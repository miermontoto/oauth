// códigos de autorización y tokens: todo lo de larga vida se guarda hasheado
// (sha-256); el access token es un jwt stateless firmado con la clave propia.
// rotación de refresh tokens con detección de replay en cadena (modelo duckhunt).
import crypto from 'node:crypto';
import { and, eq, isNull, lt } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { authCodes, refreshTokens, users } from '../db/schema.js';
import {
  ACCESS_TOKEN_TTL_S,
  AUTH_CODE_TTL_MS,
  ID_TOKEN_TTL_S,
  REFRESH_TOKEN_TTL_MS,
} from '../constants.js';
import { signJwt, verifyOwnJwt } from './keys.js';

export const sha256hex = (s: string): string => crypto.createHash('sha256').update(s).digest('hex');

const AUTH_CODE_BYTES = 32;
const REFRESH_TOKEN_BYTES = 48;

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  id_token?: string;
  refresh_token?: string;
}

export function issueAuthCode(params: {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  authTime: number; // epoch ms
  amr: string[];
}): string {
  const code = crypto.randomBytes(AUTH_CODE_BYTES).toString('base64url');
  getDb()
    .insert(authCodes)
    .values({
      codeHash: sha256hex(code),
      clientId: params.clientId,
      userId: params.userId,
      redirectUri: params.redirectUri,
      scope: params.scope,
      nonce: params.nonce ?? null,
      codeChallenge: params.codeChallenge ?? null,
      codeChallengeMethod: params.codeChallengeMethod ?? null,
      authTime: new Date(params.authTime),
      amr: JSON.stringify(params.amr),
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS),
    })
    .run();
  return code;
}

// un solo uso: se borra siempre al leerlo; null si no existe o expiró
export function consumeAuthCode(code: string): typeof authCodes.$inferSelect | null {
  const db = getDb();
  const hash = sha256hex(code);
  const row = db.select().from(authCodes).where(eq(authCodes.codeHash, hash)).get();
  if (!row) return null;
  db.delete(authCodes).where(eq(authCodes.codeHash, hash)).run();
  return row.expiresAt.getTime() < Date.now() ? null : row;
}

// claims de identidad según scope; compartidos entre id_token y /userinfo
export function userClaims(userId: string, scope: string): Record<string, unknown> {
  const scopes = new Set(scope.split(' '));
  const row = getDb().select().from(users).where(eq(users.id, userId)).get();
  if (!row) return {};
  const claims: Record<string, unknown> = {};
  if (scopes.has('email')) {
    claims.email = row.email;
    claims.email_verified = row.emailVerified;
  }
  if (scopes.has('profile')) {
    claims.name = row.name;
    if (row.picture) claims.picture = row.picture;
    claims.preferred_username = row.email.split('@')[0];
  }
  return claims;
}

export async function issueTokens(params: {
  clientId: string;
  userId: string;
  scope: string;
  nonce?: string;
  authTime: number; // epoch ms
  amr: string[];
  // refresh token pre-generado por la rotación (para poder reclamar la fila
  // atómicamente antes de emitir); si no se pasa, se genera uno aquí
  refreshOverride?: string;
}): Promise<TokenResponse> {
  const { clientId, userId, scope } = params;
  const scopes = new Set(scope.split(' '));
  const access_token = await signJwt(
    { scope, client_id: clientId },
    { expiresInS: ACCESS_TOKEN_TTL_S, audience: clientId, subject: userId },
  );
  const res: TokenResponse = { access_token, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_S, scope };

  if (scopes.has('openid')) {
    const claims: Record<string, unknown> = {
      auth_time: Math.floor(params.authTime / 1000),
      amr: params.amr,
      ...userClaims(userId, scope),
    };
    if (params.nonce) claims.nonce = params.nonce;
    res.id_token = await signJwt(claims, { expiresInS: ID_TOKEN_TTL_S, audience: clientId, subject: userId });
  }

  if (scopes.has('offline_access')) {
    const refresh = params.refreshOverride ?? crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
    getDb()
      .insert(refreshTokens)
      .values({
        tokenHash: sha256hex(refresh),
        clientId,
        userId,
        scope,
        authTime: new Date(params.authTime),
        amr: JSON.stringify(params.amr),
        expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        createdAt: new Date(),
      })
      .run();
    res.refresh_token = refresh;
  }
  return res;
}

// revoca hacia delante toda la cadena de rotación a partir de un hash
function revokeChainForward(startHash: string): void {
  const db = getDb();
  let cursor: string | null = startHash;
  while (cursor) {
    const row = db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, cursor)).get();
    db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.tokenHash, cursor)).run();
    cursor = row?.replacedByHash ?? null;
  }
}

// rotación con detección de replay: un token ya rotado o revocado que se
// presenta de nuevo compromete la cadena entera → se revoca todo y null
export async function rotateRefreshToken(refreshToken: string, clientId: string): Promise<TokenResponse | null> {
  const db = getDb();
  const hash = sha256hex(refreshToken);
  const row = db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, hash)).get();
  if (!row || row.clientId !== clientId) return null;
  // replay real (token viejo reutilizado tras rotar o tras revocar): se compromete
  // toda la cadena hacia delante
  if (row.revokedAt || row.replacedByHash) {
    console.warn(`[tokens] replay de refresh token detectado (client=${clientId}); cadena revocada`);
    revokeChainForward(hash);
    return null;
  }
  if (row.expiresAt.getTime() < Date.now()) return null;

  // reclama la fila ANTES de emitir: el update condicional (revokedAt IS NULL AND
  // replacedByHash IS NULL) es atómico en sqlite, así que dos peticiones
  // concurrentes con el mismo token solo dejan ganar a una. el sucesor se
  // pre-genera para escribir su hash en el mismo update y no dejar ramas huérfanas
  const successor = crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
  const claim = db
    .update(refreshTokens)
    .set({ replacedByHash: sha256hex(successor) })
    .where(and(eq(refreshTokens.tokenHash, hash), isNull(refreshTokens.revokedAt), isNull(refreshTokens.replacedByHash)))
    .run();
  // la perdió una carrera: otra petición ya rotó este token. no se emite nada
  // (evita el doble gasto) y no se revoca la cadena, que el sucesor legítimo ya vive
  if (claim.changes !== 1) return null;

  return issueTokens({
    clientId,
    userId: row.userId,
    scope: row.scope,
    authTime: row.authTime.getTime(),
    amr: JSON.parse(row.amr) as string[],
    refreshOverride: successor,
  });
}

// revocación explícita vía /revoke; true si el token existía y estaba vivo.
// se exige que el token pertenezca al cliente autenticado (rfc 7009): un cliente
// no puede revocar tokens de otro
export function revokeToken(token: string, clientId: string): boolean {
  const result = getDb()
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(refreshTokens.tokenHash, sha256hex(token)),
        eq(refreshTokens.clientId, clientId),
        isNull(refreshTokens.revokedAt),
      ),
    )
    .run();
  return result.changes > 0;
}

export function revokeUserTokens(userId: string): void {
  const db = getDb();
  db.delete(authCodes).where(eq(authCodes.userId, userId)).run();
  db.update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)))
    .run();
}

export function cleanupExpiredTokens(): void {
  const now = new Date();
  const db = getDb();
  db.delete(authCodes).where(lt(authCodes.expiresAt, now)).run();
  db.delete(refreshTokens).where(lt(refreshTokens.expiresAt, now)).run();
}

// valida un access token propio; distingue de un id_token por scope+client_id
export async function verifyAccessToken(
  token: string,
): Promise<{ userId: string; clientId: string; scope: string } | null> {
  const payload = await verifyOwnJwt(token);
  if (
    !payload ||
    typeof payload.sub !== 'string' ||
    typeof payload.client_id !== 'string' ||
    typeof payload.scope !== 'string'
  ) {
    return null;
  }
  return { userId: payload.sub, clientId: payload.client_id, scope: payload.scope };
}
