// endpoints oidc: discovery + jwks (/.well-known) y authorize/token/userinfo/
// revoke/logout (/oidc). errores de token en json rfc 6749; errores de authorize
// por redirect salvo client_id/redirect_uri inválidos (página inline, nunca redirect).
import { Hono } from 'hono';
import type { Context } from 'hono';
import crypto from 'node:crypto';
import { SERVICE_NAME, SUPPORTED_SCOPES } from '../constants.js';
import { getConfig } from '../config.js';
import { getJwksJson, verifyOwnJwt } from '../services/keys.js';
import { getClient, validateRedirectUri, verifyClientSecret, type Client } from '../services/clients.js';
import {
  consumeAuthCode,
  issueAuthCode,
  issueTokens,
  revokeToken,
  rotateRefreshToken,
  userClaims,
  verifyAccessToken,
} from '../services/tokens.js';
import { clearSessionCookie, deleteSession } from '../services/session.js';
import { ErrorPage } from '../ui/pages.js';
import type { AppEnv } from '../types.js';

const PKCE_METHOD = 'S256';
// params irrecuperables (client_id/redirect_uri): página de error propia, nunca redirect
const AUTHORIZE_ERROR_TITLE = 'Solicitud de autorización inválida';

interface OAuthError {
  error: string;
  error_description?: string;
}

const oauthError = (error: string, description?: string): OAuthError =>
  description ? { error, error_description: description } : { error };

// verificación pkce (rfc 7636): challenge = base64url(sha256(verifier))
function verifyPkceS256(verifier: string, challenge: string): boolean {
  if (!verifier || !challenge) return false;
  const a = Buffer.from(crypto.createHash('sha256').update(verifier).digest('base64url'));
  const b = Buffer.from(challenge);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// autenticación de cliente para /token y /revoke: basic o client_secret_post;
// cliente público → sin secret (pkce hace de prueba de posesión)
function authenticateClient(c: Context<AppEnv>, form: Record<string, unknown>): Client | null {
  let clientId = typeof form.client_id === 'string' ? form.client_id : '';
  let secret = typeof form.client_secret === 'string' ? form.client_secret : '';
  const header = c.req.header('authorization');
  if (header?.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep < 0) return null;
      // rfc 6749 §2.3.1: las credenciales van form-urlencoded dentro del basic
      clientId = decodeURIComponent(decoded.slice(0, sep));
      secret = decodeURIComponent(decoded.slice(sep + 1));
    } catch {
      return null;
    }
  }
  if (!clientId) return null;
  const client = getClient(clientId);
  if (!client) return null;
  if (client.isPublic) return secret ? null : client;
  return verifyClientSecret(clientId, secret) ? client : null;
}

const invalidClientResponse = (c: Context<AppEnv>) => {
  c.header('WWW-Authenticate', `Basic realm="${SERVICE_NAME}"`);
  return c.json(oauthError('invalid_client', 'autenticación de cliente inválida'), 401);
};

// --- /.well-known ---

export function wellKnownRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  r.get('/openid-configuration', (c) => {
    const iss = getConfig().ISSUER_URL;
    return c.json({
      issuer: iss,
      authorization_endpoint: `${iss}/oidc/authorize`,
      token_endpoint: `${iss}/oidc/token`,
      userinfo_endpoint: `${iss}/oidc/userinfo`,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      revocation_endpoint: `${iss}/oidc/revoke`,
      end_session_endpoint: `${iss}/oidc/logout`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: SUPPORTED_SCOPES,
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: [PKCE_METHOD],
      subject_types_supported: ['public'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'nonce',
        'auth_time',
        'amr',
        'email',
        'email_verified',
        'name',
        'picture',
        'preferred_username',
      ],
    });
  });

  r.get('/jwks.json', (c) => c.json(getJwksJson()));

  return r;
}

// --- /oidc ---

export function oidcRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  r.get('/authorize', (c) => {
    const q = c.req.query();
    // client_id y redirect_uri se validan PRIMERO: si fallan no se puede
    // confiar en el destino, así que jamás se redirige (rfc 6749 §4.1.2.1)
    const client = q.client_id ? getClient(q.client_id) : null;
    if (!client) {
      return c.html(
        ErrorPage({ status: 400, title: AUTHORIZE_ERROR_TITLE, message: 'El identificador de cliente no está registrado.' }),
        400,
      );
    }
    if (!q.redirect_uri || !validateRedirectUri(client, q.redirect_uri)) {
      return c.html(
        ErrorPage({
          status: 400,
          title: AUTHORIZE_ERROR_TITLE,
          message: 'La dirección de retorno no coincide con las registradas para este cliente.',
        }),
        400,
      );
    }

    const redirectError = (error: string, description?: string) => {
      const target = new URL(q.redirect_uri);
      target.searchParams.set('error', error);
      if (description) target.searchParams.set('error_description', description);
      if (q.state) target.searchParams.set('state', q.state);
      return c.redirect(target.toString(), 302);
    };

    if (q.response_type !== 'code') {
      return redirectError('unsupported_response_type', 'solo se soporta response_type=code');
    }
    const scopes = (q.scope ?? '')
      .split(/\s+/)
      .filter((s) => (SUPPORTED_SCOPES as readonly string[]).includes(s));
    if (!scopes.includes('openid')) return redirectError('invalid_scope', 'el scope debe incluir openid');
    if (q.code_challenge_method && q.code_challenge_method !== PKCE_METHOD) {
      return redirectError('invalid_request', 'solo se soporta code_challenge_method=S256');
    }
    if (q.code_challenge && !q.code_challenge_method) {
      return redirectError('invalid_request', 'code_challenge_method requerido junto a code_challenge');
    }
    if (client.isPublic && !q.code_challenge) {
      return redirectError('invalid_request', 'pkce S256 es obligatorio para clientes públicos');
    }

    const session = c.get('session');
    const prompts = (q.prompt ?? '').split(/\s+/).filter(Boolean);
    const maxAgeS = q.max_age !== undefined ? Number(q.max_age) : NaN;
    const stale =
      session !== null && Number.isFinite(maxAgeS) && Date.now() - session.authTime > maxAgeS * 1000;

    if (prompts.includes('none') && (!session || stale)) {
      return redirectError('login_required', 'no hay sesión activa y prompt=none impide autenticar');
    }

    // reautenticación forzada: se vuelve a authorize SIN prompt=login para no
    // buclear (max_age se conserva; tras el login authTime será fresco)
    if (session && (prompts.includes('login') || stale)) {
      const returnUrl = new URL(c.req.url);
      const remaining = prompts.filter((p) => p !== 'login');
      remaining.length
        ? returnUrl.searchParams.set('prompt', remaining.join(' '))
        : returnUrl.searchParams.delete('prompt');
      return c.redirect(`/login?return_to=${encodeURIComponent(returnUrl.pathname + returnUrl.search)}&force=1`, 302);
    }

    if (!session) {
      const returnUrl = new URL(c.req.url);
      return c.redirect(`/login?return_to=${encodeURIComponent(returnUrl.pathname + returnUrl.search)}`, 302);
    }

    // v1: todos los clientes son first-party (apps propias), así que no hay
    // pantalla de consent; el code se emite directamente con la sesión activa
    const code = issueAuthCode({
      clientId: client.id,
      userId: session.user.id,
      redirectUri: q.redirect_uri,
      scope: scopes.join(' '),
      nonce: q.nonce,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge ? PKCE_METHOD : undefined,
      authTime: session.authTime,
      amr: session.amr,
    });
    const target = new URL(q.redirect_uri);
    target.searchParams.set('code', code);
    if (q.state) target.searchParams.set('state', q.state);
    return c.redirect(target.toString(), 302);
  });

  r.post('/token', async (c) => {
    c.header('Cache-Control', 'no-store');
    const form = await c.req.parseBody();
    const client = authenticateClient(c, form);
    if (!client) return invalidClientResponse(c);
    const grant = typeof form.grant_type === 'string' ? form.grant_type : '';

    if (grant === 'authorization_code') {
      const row = consumeAuthCode(typeof form.code === 'string' ? form.code : '');
      if (!row) return c.json(oauthError('invalid_grant', 'código inválido, expirado o ya usado'), 400);
      if (row.clientId !== client.id) {
        return c.json(oauthError('invalid_grant', 'el código no pertenece a este cliente'), 400);
      }
      if (row.redirectUri !== (typeof form.redirect_uri === 'string' ? form.redirect_uri : '')) {
        return c.json(oauthError('invalid_grant', 'redirect_uri no coincide con la del código'), 400);
      }
      if (row.codeChallenge) {
        const verifier = typeof form.code_verifier === 'string' ? form.code_verifier : '';
        if (!verifyPkceS256(verifier, row.codeChallenge)) {
          return c.json(oauthError('invalid_grant', 'code_verifier no satisface el code_challenge'), 400);
        }
      } else if (client.isPublic) {
        // no debería llegar aquí (authorize lo exige), cinturón y tirantes
        return c.json(oauthError('invalid_grant', 'pkce requerido para clientes públicos'), 400);
      }
      const tokens = await issueTokens({
        clientId: client.id,
        userId: row.userId,
        scope: row.scope,
        nonce: row.nonce ?? undefined,
        authTime: row.authTime.getTime(),
        amr: JSON.parse(row.amr) as string[],
      });
      return c.json(tokens);
    }

    if (grant === 'refresh_token') {
      const refresh = typeof form.refresh_token === 'string' ? form.refresh_token : '';
      const tokens = await rotateRefreshToken(refresh, client.id);
      if (!tokens) return c.json(oauthError('invalid_grant', 'refresh_token inválido, expirado o revocado'), 400);
      return c.json(tokens);
    }

    return c.json(oauthError('unsupported_grant_type', `grant_type=${grant} no soportado`), 400);
  });

  const userinfoHandler = async (c: Context<AppEnv>) => {
    // la respuesta lleva pii bajo autorización bearer: nunca cacheable (oidc §5.3.4)
    c.header('Cache-Control', 'no-store');
    const auth = c.req.header('authorization') ?? '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const info = token ? await verifyAccessToken(token) : null;
    if (!info) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return c.json(oauthError('invalid_token', 'access token inválido o expirado'), 401);
    }
    return c.json({ sub: info.userId, ...userClaims(info.userId, info.scope) });
  };
  r.get('/userinfo', userinfoHandler);
  r.post('/userinfo', userinfoHandler);

  // rfc 7009: siempre 200 aunque el token no exista (no filtrar estado)
  r.post('/revoke', async (c) => {
    const form = await c.req.parseBody();
    const client = authenticateClient(c, form);
    if (!client) return invalidClientResponse(c);
    // solo su propio token: no se permite revocar tokens de otro cliente
    revokeToken(typeof form.token === 'string' ? form.token : '', client.id);
    return c.body(null, 200);
  });

  // end_session: cierra la sesión del idp y, si la uri de retorno está
  // registrada (cliente resuelto por id_token_hint o buscando en todos), vuelve allí
  r.get('/logout', async (c) => {
    const session = c.get('session');
    if (session) deleteSession(session.token);
    clearSessionCookie(c);

    const postLogout = c.req.query('post_logout_redirect_uri');
    const state = c.req.query('state');
    if (postLogout) {
      // la uri de retorno se valida SOLO contra el cliente identificado por un
      // id_token_hint válido; sin hint no se redirige (evita usar la uri de otro
      // cliente como landing de open-redirect entre apps)
      const hint = c.req.query('id_token_hint');
      const payload = hint ? await verifyOwnJwt(hint) : null;
      const aud = typeof payload?.aud === 'string' ? payload.aud : payload?.aud?.[0];
      const hinted = aud ? getClient(aud) : null;
      if (hinted?.postLogoutRedirectUris.includes(postLogout)) {
        const target = new URL(postLogout);
        if (state) target.searchParams.set('state', state);
        return c.redirect(target.toString(), 302);
      }
    }
    return c.redirect('/login', 302);
  });

  return r;
}
