// integración con proveedores upstream (google, github): url de autorización,
// intercambio de code y normalización a UpstreamProfile. el estado del round-trip
// vive en login_states (persistente, single use, limpieza perezosa).
import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { eq, lt } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { loginStates } from '../db/schema.js';
import { getConfig } from '../config.js';
import { LOGIN_STATE_TTL_MS } from '../constants.js';
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

const STATE_BYTES = 32;
const ERROR_BODY_SLICE = 200;

interface ProviderCreds {
  clientId: string;
  clientSecret: string;
}

// jwks de google, cacheado por jose entre verificaciones
let googleJwks: ReturnType<typeof createRemoteJWKSet> | null = null;

// credenciales del proveedor si está configurado en el entorno; null si no
function providerCreds(provider: string): ProviderCreds | null {
  const cfg = getConfig();
  if (provider === 'google' && cfg.GOOGLE_CLIENT_ID && cfg.GOOGLE_CLIENT_SECRET) {
    return { clientId: cfg.GOOGLE_CLIENT_ID, clientSecret: cfg.GOOGLE_CLIENT_SECRET };
  }
  if (provider === 'github' && cfg.GITHUB_CLIENT_ID && cfg.GITHUB_CLIENT_SECRET) {
    return { clientId: cfg.GITHUB_CLIENT_ID, clientSecret: cfg.GITHUB_CLIENT_SECRET };
  }
  return null;
}

const redirectUriFor = (provider: string): string => `${getConfig().ISSUER_URL}/callback/${provider}`;

// proveedores activos según credenciales presentes; alimenta los botones del login
export function listProviders(): { id: string; name: string }[] {
  return [
    { id: 'google', name: 'Google' },
    { id: 'github', name: 'GitHub' },
  ].filter((p) => providerCreds(p.id) !== null);
}

// arranca el round-trip: persiste el state en login_states y devuelve la url de
// autorización del proveedor junto al state (para atarlo al navegador vía cookie);
// null si el proveedor no está configurado
export function beginUpstreamLogin(
  provider: string,
  opts: { returnTo?: string | null; linkUserId?: string | null },
): { url: string; state: string } | null {
  const creds = providerCreds(provider);
  if (!creds) return null;

  // limpieza perezosa de estados caducados (abandono del consent, etc.)
  getDb().delete(loginStates).where(lt(loginStates.expiresAt, new Date())).run();

  const state = randomBytes(STATE_BYTES).toString('base64url');
  let url: string;
  let codeVerifier: string | null = null;

  if (provider === 'google') {
    codeVerifier = randomBytes(STATE_BYTES).toString('base64url');
    const challenge = createHash('sha256').update(codeVerifier).digest('base64url');
    // login_states no tiene columna nonce: reutilizamos el state (aleatorio, single
    // use, guardado server-side) como nonce del id_token — misma garantía de frescura
    const params = new URLSearchParams({
      client_id: creds.clientId,
      redirect_uri: redirectUriFor(provider),
      response_type: 'code',
      scope: GOOGLE_SCOPES,
      state,
      nonce: state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    url = `${GOOGLE_AUTH_URL}?${params.toString()}`;
  } else {
    const params = new URLSearchParams({
      client_id: creds.clientId,
      redirect_uri: redirectUriFor(provider),
      scope: GITHUB_SCOPES,
      state,
    });
    url = `${GITHUB_AUTH_URL}?${params.toString()}`;
  }

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

  return { url, state };
}

export type UpstreamLoginResult =
  | { profile: UpstreamProfile; returnTo: string | null; linkUserId: string | null }
  | { error: string; linkUserId?: string | null };

// cierra el round-trip: consume el state (single use), intercambia el code y
// normaliza el perfil. errores en castellano listos para query string
export async function completeUpstreamLogin(
  provider: string,
  params: { code?: string; state?: string; error?: string },
): Promise<UpstreamLoginResult> {
  const creds = providerCreds(provider);
  if (!creds) return { error: 'proveedor no configurado' };
  if (!params.state) return { error: 'falta el parámetro state' };

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
    const profile =
      provider === 'google'
        ? await googleProfile(creds, params.code, row.codeVerifier, params.state)
        : await githubProfile(creds, params.code);
    return { profile, returnTo: row.returnTo, linkUserId };
  } catch (err) {
    console.error(`[upstream] fallo completando el login con ${provider}:`, err);
    const label = provider === 'google' ? 'Google' : 'GitHub';
    return { error: `no se pudo completar el acceso con ${label}`, linkUserId };
  }
}

// google: exchange con pkce + validación del id_token contra el jwks oficial (iss,
// aud y nonce). el perfil sale entero de los claims, sin llamada extra a userinfo
async function googleProfile(
  creds: ProviderCreds,
  code: string,
  codeVerifier: string | null,
  expectedNonce: string,
): Promise<UpstreamProfile> {
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      redirect_uri: redirectUriFor('google'),
      ...(codeVerifier ? { code_verifier: codeVerifier } : {}),
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`google token: ${res.status} ${text.slice(0, ERROR_BODY_SLICE)}`);
  }
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) throw new Error('google token: respuesta sin id_token');

  googleJwks ??= createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
  const { payload } = await jwtVerify(tokens.id_token, googleJwks, {
    issuer: GOOGLE_ISSUERS,
    audience: creds.clientId,
  });
  if (payload.nonce !== expectedNonce) throw new Error('google id_token: nonce no coincide');
  if (!payload.sub) throw new Error('google id_token: respuesta sin sub');

  const email = typeof payload.email === 'string' ? payload.email.toLowerCase() : null;
  return {
    provider: 'google',
    providerAccountId: payload.sub,
    email,
    emailVerified: email !== null && payload.email_verified === true,
    name: typeof payload.name === 'string' ? payload.name : null,
    picture: typeof payload.picture === 'string' ? payload.picture : null,
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
      client_secret: creds.clientSecret,
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
