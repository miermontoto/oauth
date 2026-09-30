// registro de clientes oauth (las apps propias: carreterinas, sis, duckhunt, url...).
// el secret solo existe en claro en el momento de la creación; en db va sha-256.
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { clients } from '../db/schema.js';
import { sha256hex } from './tokens.js';
import { AUTHORIZE_PATH, SUPPORTED_SCOPES } from '../constants.js';

const CLIENT_ID_BYTES = 8; // 16 hex, legible en configs
const CLIENT_SECRET_BYTES = 32;

export interface Client {
  id: string;
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  firstParty: boolean;
  isPublic: boolean; // sin secret → pkce obligatorio
}

const parseClient = (row: typeof clients.$inferSelect): Client => ({
  id: row.id,
  name: row.name,
  redirectUris: JSON.parse(row.redirectUris) as string[],
  postLogoutRedirectUris: row.postLogoutRedirectUris ? (JSON.parse(row.postLogoutRedirectUris) as string[]) : [],
  firstParty: row.firstParty,
  isPublic: row.secretHash === null,
});

export function getClient(id: string): Client | null {
  const row = getDb().select().from(clients).where(eq(clients.id, id)).get();
  return row ? parseClient(row) : null;
}

export function listClients(): Client[] {
  return getDb().select().from(clients).all().map(parseClient);
}

// el secret se devuelve una única vez; después solo existe su hash
export function createClient(params: {
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  isPublic: boolean;
}): { client: Client; secret: string | null } {
  const id = crypto.randomBytes(CLIENT_ID_BYTES).toString('hex');
  const secret = params.isPublic ? null : crypto.randomBytes(CLIENT_SECRET_BYTES).toString('hex');
  getDb()
    .insert(clients)
    .values({
      id,
      secretHash: secret ? sha256hex(secret) : null,
      name: params.name,
      redirectUris: JSON.stringify(params.redirectUris),
      postLogoutRedirectUris: params.postLogoutRedirectUris ? JSON.stringify(params.postLogoutRedirectUris) : null,
      firstParty: true, // v1: todos los clientes son apps propias
      createdAt: new Date(),
    })
    .run();
  const client = getClient(id);
  if (!client) throw new Error(`[clients] fallo al crear el cliente ${id}`);
  return { client, secret };
}

export function updateClient(
  id: string,
  params: { name?: string; redirectUris?: string[]; postLogoutRedirectUris?: string[] },
): Client | null {
  const patch: Partial<typeof clients.$inferInsert> = {};
  if (params.name !== undefined) patch.name = params.name;
  if (params.redirectUris !== undefined) patch.redirectUris = JSON.stringify(params.redirectUris);
  if (params.postLogoutRedirectUris !== undefined) {
    patch.postLogoutRedirectUris = JSON.stringify(params.postLogoutRedirectUris);
  }
  if (Object.keys(patch).length) getDb().update(clients).set(patch).where(eq(clients.id, id)).run();
  return getClient(id);
}

export function deleteClient(id: string): boolean {
  return getDb().delete(clients).where(eq(clients.id, id)).run().changes > 0;
}

export function verifyClientSecret(clientId: string, secret: string): boolean {
  const row = getDb().select({ secretHash: clients.secretHash }).from(clients).where(eq(clients.id, clientId)).get();
  if (!row?.secretHash || !secret) return false;
  // ambos son sha-256 hex (misma longitud), comparación tiempo-constante
  const a = Buffer.from(sha256hex(secret));
  const b = Buffer.from(row.secretHash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// match exacto contra las uris registradas (sin comodines ni puertos libres)
export const validateRedirectUri = (client: Client, uri: string): boolean => client.redirectUris.includes(uri);

// app que pide el acceso, leída del return_to del login cuando apunta a authorize.
// solo se describe si client_id y redirect_uri validan: nunca se muestra un destino no registrado
export interface AuthorizeRequest {
  clientName: string;
  host: string;
  scopes: string[];
  pkce: string | null;
}

export function describeAuthorizeRequest(returnTo: string | null): AuthorizeRequest | null {
  if (!returnTo?.startsWith(`${AUTHORIZE_PATH}?`)) return null;
  const q = new URLSearchParams(returnTo.slice(AUTHORIZE_PATH.length + 1));
  const client = getClient(q.get('client_id') ?? '');
  const redirectUri = q.get('redirect_uri') ?? '';
  if (!client || !validateRedirectUri(client, redirectUri) || !URL.canParse(redirectUri)) return null;
  return {
    clientName: client.name,
    host: new URL(redirectUri).host,
    scopes: (q.get('scope') ?? '').split(/\s+/).filter((s) => (SUPPORTED_SCOPES as readonly string[]).includes(s)),
    pkce: q.get('code_challenge_method'),
  };
}
