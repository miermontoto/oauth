// setup de entorno para los tests de integración: fija la db sqlite temporal y
// el issuer ANTES de que cualquier módulo de src evalúe config/db (singletons).
import crypto from 'node:crypto';

const SCRATCH = '/tmp/claude-1000/-home-mier-dev-oauth/4db33465-44d2-4a9e-9372-799ff1bd4053/scratchpad';

process.env.DATABASE_PATH = `${SCRATCH}/oidc-test-${process.pid}-${Date.now()}.db`;
process.env.ISSUER_URL = 'http://localhost:3000';
process.env.NODE_ENV = 'test';

// credenciales apple de prueba: clave ec p-256 efímera; el pem viaja con \n escapados,
// como en el .env, para cubrir también el unescape de config
const appleKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
export const APPLE_CLIENT_ID = 'info.mier.id.test';
export const APPLE_TEAM_ID = 'TEAM123456';
export const APPLE_KEY_ID = 'KEY1234567';
export const APPLE_PUBLIC_KEY = appleKeys.publicKey;
process.env.APPLE_CLIENT_ID = APPLE_CLIENT_ID;
process.env.APPLE_TEAM_ID = APPLE_TEAM_ID;
process.env.APPLE_KEY_ID = APPLE_KEY_ID;
process.env.APPLE_PRIVATE_KEY = appleKeys.privateKey
  .export({ type: 'pkcs8', format: 'pem' })
  .toString()
  .replace(/\n/g, '\\n');

export const DB_PATH = process.env.DATABASE_PATH;
export const ISSUER = process.env.ISSUER_URL;

// par pkce S256: verifier aleatorio + challenge = base64url(sha256(verifier))
export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// extrae el valor de una cookie de un header set-cookie
export function cookieFrom(res: Response, name: string): string {
  const raw = res.headers.get('set-cookie') ?? '';
  const match = raw.match(new RegExp(`${name}=([^;]+)`));
  if (!match) throw new Error(`cookie ${name} no presente en la respuesta`);
  return `${name}=${match[1]}`;
}

// header basic auth para client_secret_basic (credenciales form-urlencoded, rfc 6749 §2.3.1)
export const basicAuth = (id: string, secret: string): string =>
  `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;
