// integración con proveedores upstream (google, github, apple): url de autorización,
// intercambio de code y normalización a UpstreamProfile. el estado del round-trip
// vive en login_states (persistente, single use, limpieza perezosa).
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify, type JWTPayload, type KeyLike } from 'jose';
import { eq, lt } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { loginStates } from '../db/schema.js';
import { getConfig, type Config } from '../config.js';
import { APPLE_CLIENT_SECRET_TTL_S, LOGIN_STATE_TTL_MS } from '../constants.js';
import type { UpstreamProfile } from '../types.js';

// endpoints y scopes de cada proveedor
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
// google emite el iss con y sin esquema según el flujo; ambos son válidos
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
const GOOGLE_SCOPES = 'openid email profile';
const GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_SCOPES = 'read:user user:email';
// apple (discovery en appleid.apple.com/.well-known/openid-configuration): sin pkce,
// solo client_secret_post, y el client_secret es un jwt es256 firmado con la clave .p8
const APPLE_ISSUER = 'https://appleid.apple.com';
const APPLE_AUTH_URL = `${APPLE_ISSUER}/auth/authorize`;
const APPLE_TOKEN_URL = `${APPLE_ISSUER}/auth/token`;
const APPLE_JWKS_URL = `${APPLE_ISSUER}/auth/keys`;
const APPLE_SCOPES = 'name email';
const APPLE_KEY_ALG = 'ES256';

const STATE_BYTES = 32;
const ERROR_BODY_SLICE = 200;

interface ProviderCreds {
  clientId: string;
  // secreto estático del entorno, o generado bajo demanda (apple lo firma con su .p8)
  clientSecret: () => Promise<string>;
}

// datos del round-trip que necesita el exchange
interface ExchangeContext {
  codeVerifier: string | null;
  nonce: string;
  // apple: json con el nombre del usuario, solo en la primera autorización
  user?: string;
}

// endpoints oidc de un proveedor; el jwks lo cachea jose (no descarga hasta el primer uso)
interface OidcEndpoints {
  tokenUrl: string;
  issuer: string | string[];
  jwks: ReturnType<typeof createRemoteJWKSet>;
}

interface ProviderSpec {
  name: string;
  authUrl: string;
  scope: string;
  // oidc: response_type=code + nonce en el id_token (el state hace de nonce)
  oidc: boolean;
  pkce: boolean;
  // el callback llega por POST cross-site (response_mode=form_post), no por query
  formPost: boolean;
  // credenciales si todas están en el entorno; null si el proveedor no está configurado
  credentials: (cfg: Config) => ProviderCreds | null;
  exchange: (creds: ProviderCreds, code: string, ctx: ExchangeContext) => Promise<UpstreamProfile>;
}

const GOOGLE_OIDC: OidcEndpoints = {
  tokenUrl: GOOGLE_TOKEN_URL,
  issuer: GOOGLE_ISSUERS,
  jwks: createRemoteJWKSet(new URL(GOOGLE_JWKS_URL)),
};

const APPLE_OIDC: OidcEndpoints = {
  tokenUrl: APPLE_TOKEN_URL,
  issuer: APPLE_ISSUER,
  jwks: createRemoteJWKSet(new URL(APPLE_JWKS_URL)),
};

// par id/secret estático del entorno
const staticCreds = (clientId?: string, clientSecret?: string): ProviderCreds | null =>
  clientId && clientSecret ? { clientId, clientSecret: async () => clientSecret } : null;

// catálogo de proveedores; el orden es el de los botones del login.
// Map (no objeto literal) para que un :provider como "constructor" no resuelva nada
const PROVIDERS = new Map<string, ProviderSpec>([
  [
    'google',
    {
      name: 'Google',
      authUrl: GOOGLE_AUTH_URL,
      scope: GOOGLE_SCOPES,
      oidc: true,
      pkce: true,
      formPost: false,
      credentials: (cfg) => staticCreds(cfg.GOOGLE_CLIENT_ID, cfg.GOOGLE_CLIENT_SECRET),
      exchange: googleProfile,
    },
  ],
  [
    'github',
    {
      name: 'GitHub',
      authUrl: GITHUB_AUTH_URL,
      scope: GITHUB_SCOPES,
      oidc: false,
      pkce: false,
      formPost: false,
      credentials: (cfg) => staticCreds(cfg.GITHUB_CLIENT_ID, cfg.GITHUB_CLIENT_SECRET),
      exchange: githubProfile,
    },
  ],
  [
    'apple',
    {
      name: 'Apple',
      authUrl: APPLE_AUTH_URL,
      scope: APPLE_SCOPES,
      oidc: true,
      pkce: false,
      // pedir name/email obliga a form_post
      formPost: true,
      credentials: ({ APPLE_CLIENT_ID: clientId, APPLE_TEAM_ID: teamId, APPLE_KEY_ID: keyId, APPLE_PRIVATE_KEY: pem }) =>
        clientId && teamId && keyId && pem
          ? { clientId, clientSecret: () => appleClientSecret(clientId, teamId, keyId, pem) }
          : null,
      exchange: appleProfile,
    },
  ],
]);

const redirectUriFor = (provider: string): string => `${getConfig().ISSUER_URL}/callback/${provider}`;

// spec + credenciales del proveedor, o null si no existe o no está configurado
function resolveProvider(provider: string): { spec: ProviderSpec; creds: ProviderCreds } | null {
  const spec = PROVIDERS.get(provider);
  const creds = spec?.credentials(getConfig());
  return spec && creds ? { spec, creds } : null;
}

// proveedores activos según credenciales presentes; alimenta los botones del login
export function listProviders(): { id: string; name: string }[] {
  const cfg = getConfig();
  return [...PROVIDERS]
    .filter(([, spec]) => spec.credentials(cfg) !== null)
    .map(([id, spec]) => ({ id, name: spec.name }));
}

// arranca el round-trip: persiste el state en login_states y devuelve la url de
// autorización del proveedor junto al state (para atarlo al navegador vía cookie)
// y si el callback llegará por form_post; null si el proveedor no está configurado
export function beginUpstreamLogin(
  provider: string,
  opts: { returnTo?: string | null; linkUserId?: string | null },
): { url: string; state: string; formPost: boolean } | null {
  const resolved = resolveProvider(provider);
  if (!resolved) return null;
  const { spec, creds } = resolved;

  // limpieza perezosa de estados caducados (abandono del consent, etc.)
  getDb().delete(loginStates).where(lt(loginStates.expiresAt, new Date())).run();

  const state = randomBytes(STATE_BYTES).toString('base64url');
  const codeVerifier = spec.pkce ? randomBytes(STATE_BYTES).toString('base64url') : null;
  // login_states no tiene columna nonce: reutilizamos el state (aleatorio, single
  // use, guardado server-side) como nonce del id_token — misma garantía de frescura
  const params = new URLSearchParams({
    client_id: creds.clientId,
    redirect_uri: redirectUriFor(provider),
    scope: spec.scope,
    state,
    ...(spec.oidc && { response_type: 'code', nonce: state }),
    ...(spec.formPost && { response_mode: 'form_post' }),
    ...(codeVerifier
      ? { code_challenge: createHash('sha256').update(codeVerifier).digest('base64url'), code_challenge_method: 'S256' }
      : {}),
  });

  getDb()
    .insert(loginStates)
    .values({
      state,
      provider,
      codeVerifier,
      returnTo: opts.returnTo ?? null,
      linkUserId: opts.linkUserId ?? null,
      expiresAt: new Date(Date.now() + LOGIN_STATE_TTL_MS),
    })
    .run();

  return { url: `${spec.authUrl}?${params.toString()}`, state, formPost: spec.formPost };
}

export type UpstreamLoginResult =
  | { profile: UpstreamProfile; returnTo: string | null; linkUserId: string | null }
  | { error: string; linkUserId?: string | null };

// cierra el round-trip: consume el state (single use), intercambia el code y
// normaliza el perfil. errores en castellano listos para query string
export async function completeUpstreamLogin(
  provider: string,
  params: { code?: string; state?: string; error?: string; user?: string },
): Promise<UpstreamLoginResult> {
  const resolved = resolveProvider(provider);
  if (!resolved) return { error: 'proveedor no configurado' };
  if (!params.state) return { error: 'falta el parámetro state' };
  const { spec, creds } = resolved;

  // consume el state: la fila se borra pase lo que pase después (single use)
  const db = getDb();
  const row = db.select().from(loginStates).where(eq(loginStates.state, params.state)).get();
  if (row) db.delete(loginStates).where(eq(loginStates.state, params.state)).run();
  if (!row || row.provider !== provider || row.expiresAt.getTime() < Date.now()) {
    return { error: 'estado de autenticación inválido o caducado, inténtalo de nuevo' };
  }
  const linkUserId = row.linkUserId;

  if (params.error) return { error: `el proveedor devolvió un error: ${params.error}`, linkUserId };
  if (!params.code) return { error: 'falta el código de autorización', linkUserId };

  try {
    const profile = await spec.exchange(creds, params.code, {
      codeVerifier: row.codeVerifier,
      nonce: params.state,
      user: params.user,
    });
    return { profile, returnTo: row.returnTo, linkUserId };
  } catch (err) {
    console.error(`[upstream] fallo completando el login con ${provider}:`, err);
    return { error: `no se pudo completar el acceso con ${spec.name}`, linkUserId };
  }
}

// code flow oidc: exchange en el token endpoint + validación del id_token contra el
// jwks oficial (iss, aud y nonce). el perfil sale de los claims, sin llamada a userinfo
async function idTokenClaims(
  provider: string,
  oidc: OidcEndpoints,
  creds: ProviderCreds,
  code: string,
  ctx: ExchangeContext,
): Promise<JWTPayload & { sub: string }> {
  const res = await fetch(oidc.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: creds.clientId,
      client_secret: await creds.clientSecret(),
      redirect_uri: redirectUriFor(provider),
      ...(ctx.codeVerifier ? { code_verifier: ctx.codeVerifier } : {}),
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${provider} token: ${res.status} ${text.slice(0, ERROR_BODY_SLICE)}`);
  }
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) throw new Error(`${provider} token: respuesta sin id_token`);

  const { payload } = await jwtVerify(tokens.id_token, oidc.jwks, {
    issuer: oidc.issuer,
    audience: creds.clientId,
  });
  if (payload.nonce !== ctx.nonce) throw new Error(`${provider} id_token: nonce no coincide`);
  if (!payload.sub) throw new Error(`${provider} id_token: respuesta sin sub`);
  return { ...payload, sub: payload.sub };
}

// google: exchange con pkce; nombre y foto salen directamente de los claims
async function googleProfile(creds: ProviderCreds, code: string, ctx: ExchangeContext): Promise<UpstreamProfile> {
  const claims = await idTokenClaims('google', GOOGLE_OIDC, creds, code, ctx);
  const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : null;
  return {
    provider: 'google',
    providerAccountId: claims.sub,
    email,
    emailVerified: email !== null && claims.email_verified === true,
    name: typeof claims.name === 'string' ? claims.name : null,
    picture: typeof claims.picture === 'string' ? claims.picture : null,
  };
}

// clave .p8 importada una sola vez; el jwt se firma en cada exchange (barato y
// siempre fresco, sin gestionar la caducidad de un secreto cacheado)
let appleKey: Promise<KeyLike> | null = null;

// client_secret de apple: jwt es256 con iss=team id, sub=services id, aud=apple
async function appleClientSecret(clientId: string, teamId: string, keyId: string, pem: string): Promise<string> {
  appleKey ??= importPKCS8(pem, APPLE_KEY_ALG);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: APPLE_KEY_ALG, kid: keyId })
    .setIssuer(teamId)
    .setSubject(clientId)
    .setAudience(APPLE_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + APPLE_CLIENT_SECRET_TTL_S)
    .sign(await appleKey);
}

// apple: el email llega en el id_token de cada login (puede ser un relay privado
// @privaterelay.appleid.com); email_verified viene como string o boolean según la
// cuenta. el nombre solo llega en la primera autorización, fuera del id_token y sin
// firmar: se usa únicamente como nombre visible al dar de alta la cuenta
async function appleProfile(creds: ProviderCreds, code: string, ctx: ExchangeContext): Promise<UpstreamProfile> {
  const claims = await idTokenClaims('apple', APPLE_OIDC, creds, code, ctx);
  const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : null;
  let name: string | null = null;
  try {
    const { firstName, lastName } = (JSON.parse(ctx.user ?? '{}') as { name?: { firstName?: string; lastName?: string } })
      .name ?? {};
    name = [firstName, lastName].filter(Boolean).join(' ') || null;
  } catch {
    // user malformado: el alta cae al email como nombre
  }
  return {
    provider: 'apple',
    providerAccountId: claims.sub,
    email,
    emailVerified: email !== null && String(claims.email_verified) === 'true',
    name,
    picture: null,
  };
}

interface GithubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

// github: exchange (Accept json; devuelve 200 con {error} en fallos) + identidad por
// GET /user + email primario verificado por GET /user/emails (best-effort)
async function githubProfile(creds: ProviderCreds, code: string): Promise<UpstreamProfile> {
  const res = await fetch(GITHUB_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      client_id: creds.clientId,
      client_secret: await creds.clientSecret(),
      code,
      redirect_uri: redirectUriFor('github'),
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`github token: ${res.status} ${text.slice(0, ERROR_BODY_SLICE)}`);
  }
  const tokens = (await res.json()) as { access_token?: string; error?: string; error_description?: string };
  if (tokens.error || !tokens.access_token) {
    throw new Error(`github token: ${tokens.error ?? 'respuesta sin access_token'} ${tokens.error_description ?? ''}`.trim());
  }

  const headers = { Authorization: `Bearer ${tokens.access_token}`, Accept: 'application/vnd.github+json' };
  const userRes = await fetch(`${GITHUB_API_BASE}/user`, { headers });
  if (!userRes.ok) {
    const text = await userRes.text().catch(() => '');
    throw new Error(`github user: ${userRes.status} ${text.slice(0, ERROR_BODY_SLICE)}`);
  }
  const user = (await userRes.json()) as {
    id?: number;
    login?: string;
    name?: string | null;
    avatar_url?: string | null;
  };
  if (!user.id) throw new Error('github user: respuesta sin id');

  // /user solo expone el email si es público; el primario verificado sale de /user/emails.
  // best-effort: sin scope o sin email verificado, email=null y emailVerified=false
  const emails: GithubEmail[] = await fetch(`${GITHUB_API_BASE}/user/emails`, { headers })
    .then((r) => (r.ok ? (r.json() as Promise<GithubEmail[]>) : []))
    .catch(() => []);
  const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);

  return {
    provider: 'github',
    providerAccountId: String(user.id),
    email: primary?.email.toLowerCase() ?? null,
    emailVerified: primary !== undefined,
    name: user.name ?? user.login ?? null,
    picture: user.avatar_url ?? null,
  };
}
