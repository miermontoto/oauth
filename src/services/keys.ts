// firma es256 con jose; el par de claves se genera una vez y se persiste en
// signing_keys. las claves retiradas siguen publicándose en el jwks mientras
// pueda existir algún jwt firmado con ellas (ttl máximo de access/id token).
import {
  SignJWT,
  jwtVerify,
  generateKeyPair,
  exportJWK,
  importJWK,
  createLocalJWKSet,
  type JWK,
  type JWTPayload,
  type KeyLike,
} from 'jose';
import crypto from 'node:crypto';
import { isNull } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { signingKeys } from '../db/schema.js';
import { ACCESS_TOKEN_TTL_S, ID_TOKEN_TTL_S } from '../constants.js';
import { getConfig } from '../config.js';

const SIGNING_ALG = 'ES256';
const KID_BYTES = 8;

// clave privada activa importada, cacheada para no reimportar en cada firma
let activeKey: { kid: string; key: KeyLike } | null = null;

// genera y persiste el par p-256 si no hay clave activa; llamar en el boot
export async function ensureSigningKey(): Promise<void> {
  const db = getDb();
  const active = db.select({ kid: signingKeys.kid }).from(signingKeys).where(isNull(signingKeys.retiredAt)).get();
  if (active) return;
  const kid = crypto.randomBytes(KID_BYTES).toString('hex');
  const { publicKey, privateKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: SIGNING_ALG };
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: SIGNING_ALG, use: 'sig' };
  db.insert(signingKeys)
    .values({
      kid,
      alg: SIGNING_ALG,
      privateJwk: JSON.stringify(privateJwk),
      publicJwk: JSON.stringify(publicJwk),
      createdAt: new Date(),
    })
    .run();
  console.log(`[keys] clave de firma ${SIGNING_ALG} generada (kid=${kid})`);
}

async function getActiveKey(): Promise<{ kid: string; key: KeyLike }> {
  if (activeKey) return activeKey;
  const row = getDb().select().from(signingKeys).where(isNull(signingKeys.retiredAt)).get();
  if (!row) throw new Error('[keys] no hay clave de firma activa; ensureSigningKey() debe ejecutarse en el boot');
  const key = (await importJWK(JSON.parse(row.privateJwk) as JWK, SIGNING_ALG)) as KeyLike;
  activeKey = { kid: row.kid, key };
  return activeKey;
}

// claves públicas vigentes: la activa + retiradas cuya firma aún puede estar viva
function publicJwks(): JWK[] {
  const cutoff = Date.now() - Math.max(ACCESS_TOKEN_TTL_S, ID_TOKEN_TTL_S) * 1000;
  return getDb()
    .select()
    .from(signingKeys)
    .all()
    .filter((k) => !k.retiredAt || k.retiredAt.getTime() >= cutoff)
    .map((k) => JSON.parse(k.publicJwk) as JWK);
}

export const getJwksJson = (): { keys: object[] } => ({ keys: publicJwks() });

// metadatos de la clave activa para el panel de administración (sin material privado)
export function getActiveKeyInfo(): { kid: string; alg: string; createdAt: Date } | null {
  return (
    getDb()
      .select({ kid: signingKeys.kid, alg: signingKeys.alg, createdAt: signingKeys.createdAt })
      .from(signingKeys)
      .where(isNull(signingKeys.retiredAt))
      .get() ?? null
  );
}

export async function signJwt(
  claims: Record<string, unknown>,
  opts: { expiresInS: number; audience?: string | string[]; subject?: string },
): Promise<string> {
  const { kid, key } = await getActiveKey();
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: SIGNING_ALG, kid })
    .setIssuer(getConfig().ISSUER_URL)
    .setIssuedAt(now)
    .setExpirationTime(now + opts.expiresInS);
  if (opts.audience) jwt.setAudience(opts.audience);
  if (opts.subject) jwt.setSubject(opts.subject);
  return jwt.sign(key);
}

// verifica un jwt emitido por nosotros mismos; null si inválido o expirado
export async function verifyOwnJwt(token: string): Promise<JWTPayload | null> {
  try {
    const jwks = createLocalJWKSet({ keys: publicJwks() });
    const { payload } = await jwtVerify(token, jwks, {
      issuer: getConfig().ISSUER_URL,
      algorithms: [SIGNING_ALG],
    });
    return payload;
  } catch {
    return null;
  }
}
