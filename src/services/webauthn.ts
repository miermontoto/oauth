// passkeys webauthn sobre @simplewebauthn/server v13. los desafíos viven en
// webauthn_challenges (un solo uso, ttl corto, limpieza perezosa al consultar);
// las credenciales en passkeys (id y publicKey en base64url, counter anti-clone).
import crypto from 'node:crypto';
import { and, eq, lt, sql } from 'drizzle-orm';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { getDb } from '../db/index.js';
import { identities, passkeys, users, webauthnChallenges } from '../db/schema.js';
import { SERVICE_NAME, WEBAUTHN_CHALLENGE_TTL_MS } from '../constants.js';
import { getConfig } from '../config.js';
import { toPublicUser } from './session.js';
import type { PublicUser } from '../types.js';

const CHALLENGE_ID_BYTES = 32;
const DEFAULT_PASSKEY_NAME = 'passkey';

// rp id = hostname del issuer; el origin esperado es el issuer completo
const rpID = (): string => new URL(getConfig().ISSUER_URL).hostname;
const expectedOrigin = (): string => new URL(getConfig().ISSUER_URL).origin;

// guarda un desafío nuevo y devuelve su id opaco (viaja al cliente y vuelve en verify)
function storeChallenge(challenge: string, kind: 'register' | 'login', userId: string | null): string {
  const id = crypto.randomBytes(CHALLENGE_ID_BYTES).toString('base64url');
  getDb()
    .insert(webauthnChallenges)
    .values({ id, challenge, userId, kind, expiresAt: new Date(Date.now() + WEBAUTHN_CHALLENGE_TTL_MS) })
    .run();
  return id;
}

// consume un desafío (un solo uso) con limpieza perezosa de los expirados
function consumeChallenge(id: string, kind: 'register' | 'login'): { challenge: string; userId: string | null } | null {
  const db = getDb();
  db.delete(webauthnChallenges).where(lt(webauthnChallenges.expiresAt, new Date())).run();
  const row = db.select().from(webauthnChallenges).where(eq(webauthnChallenges.id, id)).get();
  if (!row || row.kind !== kind) return null;
  db.delete(webauthnChallenges).where(eq(webauthnChallenges.id, id)).run();
  return { challenge: row.challenge, userId: row.userId };
}

const parseTransports = (json: string | null): AuthenticatorTransportFuture[] | undefined =>
  json ? (JSON.parse(json) as AuthenticatorTransportFuture[]) : undefined;

export async function startPasskeyRegistration(user: PublicUser): Promise<{ options: object; challengeId: string }> {
  const existing = getDb().select().from(passkeys).where(eq(passkeys.userId, user.id)).all();
  const options = await generateRegistrationOptions({
    rpName: SERVICE_NAME,
    rpID: rpID(),
    userName: user.email,
    userDisplayName: user.name,
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    excludeCredentials: existing.map((p) => ({ id: p.id, transports: parseTransports(p.transports) })),
    // uv obligatorio: la passkey es factor único de login, así que debe probar
    // presencia + verificación (pin/biometría), no solo presencia
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  return { options, challengeId: storeChallenge(options.challenge, 'register', user.id) };
}

export async function finishPasskeyRegistration(
  userId: string,
  challengeId: string,
  response: object,
  name?: string,
): Promise<boolean> {
  const stored = consumeChallenge(challengeId, 'register');
  if (!stored || stored.userId !== userId) return false;
  try {
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: response as RegistrationResponseJSON,
      expectedChallenge: stored.challenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: rpID(),
      requireUserVerification: true,
    });
    if (!verified || !registrationInfo) return false;
    const { credential } = registrationInfo;
    const res = getDb()
      .insert(passkeys)
      .values({
        id: credential.id,
        userId,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        transports: JSON.stringify(credential.transports ?? []),
        name: name?.trim() || DEFAULT_PASSKEY_NAME,
        createdAt: new Date(),
      })
      .onConflictDoNothing() // credencial ya registrada (aquí o por otro usuario)
      .run();
    return res.changes === 1;
  } catch (err) {
    console.error('[webauthn] registro de passkey fallido:', err);
    return false;
  }
}

// login usernameless: sin allowCredentials, el navegador ofrece las passkeys residentes
export async function startPasskeyLogin(): Promise<{ options: object; challengeId: string }> {
  const options = await generateAuthenticationOptions({
    rpID: rpID(),
    allowCredentials: [],
    // uv obligatorio: el login con passkey es factor único (ver registro)
    userVerification: 'required',
  });
  return { options, challengeId: storeChallenge(options.challenge, 'login', null) };
}

export async function finishPasskeyLogin(challengeId: string, response: object): Promise<PublicUser | null> {
  const stored = consumeChallenge(challengeId, 'login');
  if (!stored) return null;
  const authResponse = response as AuthenticationResponseJSON;
  const db = getDb();
  const credential = db.select().from(passkeys).where(eq(passkeys.id, authResponse.id)).get();
  if (!credential) return null;
  try {
    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: stored.challenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: rpID(),
      credential: {
        id: credential.id,
        publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')),
        counter: credential.counter,
        transports: parseTransports(credential.transports),
      },
      requireUserVerification: true,
    });
    if (!verified) return null;
    db.update(passkeys)
      .set({ counter: authenticationInfo.newCounter, lastUsedAt: new Date() })
      .where(eq(passkeys.id, credential.id))
      .run();
    const user = db.select().from(users).where(eq(users.id, credential.userId)).get();
    return user && user.isActive ? toPublicUser(user) : null;
  } catch (err) {
    console.error('[webauthn] login con passkey fallido:', err);
    return null;
  }
}

export function listPasskeys(userId: string): (typeof passkeys.$inferSelect)[] {
  return getDb().select().from(passkeys).where(eq(passkeys.userId, userId)).all();
}

export function renamePasskey(userId: string, credentialId: string, name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed) return false;
  const res = getDb()
    .update(passkeys)
    .set({ name: trimmed })
    .where(and(eq(passkeys.id, credentialId), eq(passkeys.userId, userId)))
    .run();
  return res.changes === 1;
}

// borra una passkey, NEGÁNDOSE si es el último método de acceso de la cuenta
// (sin contraseña, sin identidades sociales y sin otra passkey) — igual que unlinkIdentity
export function deletePasskey(userId: string, credentialId: string): boolean {
  const db = getDb();
  const user = db.select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, userId)).get();
  if (!user) return false;
  if (!user.passwordHash) {
    const identityCount =
      db.select({ n: sql<number>`count(*)` }).from(identities).where(eq(identities.userId, userId)).get()?.n ?? 0;
    const passkeyCount =
      db.select({ n: sql<number>`count(*)` }).from(passkeys).where(eq(passkeys.userId, userId)).get()?.n ?? 0;
    if (identityCount === 0 && passkeyCount <= 1) return false;
  }
  const res = db
    .delete(passkeys)
    .where(and(eq(passkeys.id, credentialId), eq(passkeys.userId, userId)))
    .run();
  return res.changes === 1;
}
