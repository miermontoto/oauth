// gestión de usuarios e identidades vinculadas: passwords argon2id (params de
// carreterinas), resolución de cuentas desde proveedores upstream y crud básico.
import { hash, verify } from '@node-rs/argon2';
import { and, eq, ne, sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import { getDb } from '../db/index.js';
import { identities, passkeys, users } from '../db/schema.js';
import { toPublicUser } from './session.js';
import { getConfig } from '../config.js';
import type { PublicUser, UpstreamProfile } from '../types.js';

// params argon2id (owasp; mismos que carreterinas)
const ARGON2_MEMORY_COST = 19456; // 19 MiB
const ARGON2_TIME_COST = 2;
const ARGON2_OUTPUT_LEN = 32;
const ARGON2_PARALLELISM = 1;

// hash precomputado con los mismos params: se verifica contra él cuando el email
// no existe (o no tiene password) para igualar el timing y no filtrar emails válidos
const DUMMY_HASH = '$argon2id$v=19$m=19456,t=2,p=1$DG5cNXXeQZHbKFJ4d121DQ$tPIUQTjQNbD+Ox5x4btViEmcNi0w5vASlm9QlHcVw1E';

// dominio sintético para cuentas upstream sin email
const SYNTHETIC_EMAIL_DOMAIN = 'local.invalid';

export async function hashPassword(plaintext: string): Promise<string> {
  return hash(plaintext, {
    memoryCost: ARGON2_MEMORY_COST,
    timeCost: ARGON2_TIME_COST,
    outputLen: ARGON2_OUTPUT_LEN,
    parallelism: ARGON2_PARALLELISM,
  });
}

// ---------- crud de usuarios ----------

export function findUserByEmail(email: string): typeof users.$inferSelect | null {
  return getDb().select().from(users).where(eq(users.email, email.toLowerCase().trim())).get() ?? null;
}

export function getUserById(id: string): typeof users.$inferSelect | null {
  return getDb().select().from(users).where(eq(users.id, id)).get() ?? null;
}

export function countUsers(): number {
  return getDb().select({ n: sql<number>`count(*)` }).from(users).get()?.n ?? 0;
}

export function listUsers(): (typeof users.$inferSelect)[] {
  return getDb().select().from(users).all();
}

export async function createUser(input: {
  email: string;
  password?: string;
  name: string;
  picture?: string | null;
  emailVerified?: boolean;
}): Promise<PublicUser> {
  const id = randomUUID();
  const now = new Date();
  const email = input.email.toLowerCase().trim();
  // admin por lista blanca de env; sin lista configurada, el primer usuario es
  // admin (cómodo en dev, pero en un idp público expuesto whoever registra primero
  // se haría admin, así que en prod se define ADMIN_EMAILS)
  const { adminEmails } = getConfig();
  const isAdmin = adminEmails.length > 0 ? adminEmails.includes(email) : countUsers() === 0;
  const row = {
    id,
    email,
    emailVerified: input.emailVerified ?? false,
    passwordHash: input.password ? await hashPassword(input.password) : null,
    name: input.name,
    picture: input.picture ?? null,
    isAdmin,
    isActive: true,
    createdAt: now,
    updatedAt: now,
  };
  getDb().insert(users).values(row).run();
  return toPublicUser(row);
}

// verifica email+password con timing constante: siempre se ejecuta un verify,
// contra un hash dummy si el email no existe o la cuenta no tiene password
export async function verifyCredentials(email: string, password: string): Promise<PublicUser | null> {
  const row = findUserByEmail(email);
  const ok = await verify(row?.passwordHash ?? DUMMY_HASH, password).catch(() => false);
  if (!ok || !row?.passwordHash || !row.isActive) return null;
  return toPublicUser(row);
}

export async function setPassword(userId: string, password: string): Promise<void> {
  getDb()
    .update(users)
    .set({ passwordHash: await hashPassword(password), updatedAt: new Date() })
    .where(eq(users.id, userId))
    .run();
}

export function updateProfile(userId: string, input: { name: string; picture?: string | null }): void {
  getDb()
    .update(users)
    .set({ name: input.name, ...(input.picture !== undefined && { picture: input.picture }), updatedAt: new Date() })
    .where(eq(users.id, userId))
    .run();
}

export function markEmailVerified(userId: string): void {
  getDb().update(users).set({ emailVerified: true, updatedAt: new Date() }).where(eq(users.id, userId)).run();
}

export function setUserActive(userId: string, active: boolean): void {
  getDb().update(users).set({ isActive: active, updatedAt: new Date() }).where(eq(users.id, userId)).run();
}

export function deleteUser(userId: string): void {
  getDb().delete(users).where(eq(users.id, userId)).run();
}

// ---------- identidades upstream ----------

export function findIdentity(provider: string, providerAccountId: string): typeof identities.$inferSelect | null {
  return (
    getDb()
      .select()
      .from(identities)
      .where(and(eq(identities.provider, provider), eq(identities.providerAccountId, providerAccountId)))
      .get() ?? null
  );
}

export function listIdentities(userId: string): (typeof identities.$inferSelect)[] {
  return getDb().select().from(identities).where(eq(identities.userId, userId)).all();
}

export function linkIdentity(userId: string, provider: string, providerAccountId: string, email?: string | null): void {
  getDb()
    .insert(identities)
    .values({ userId, provider, providerAccountId, email: email ?? null, createdAt: new Date() })
    .run();
}

// desvincula un proveedor, salvo que sea el último método de acceso de la cuenta
// (sin password, sin passkeys y sin otras identidades el usuario quedaría fuera)
export function unlinkIdentity(userId: string, provider: string): boolean {
  const db = getDb();
  const user = getUserById(userId);
  if (!user) return false;
  const hasPasskey = db.select({ id: passkeys.id }).from(passkeys).where(eq(passkeys.userId, userId)).get() !== undefined;
  const hasOtherIdentity =
    db
      .select({ id: identities.id })
      .from(identities)
      .where(and(eq(identities.userId, userId), ne(identities.provider, provider)))
      .get() !== undefined;
  if (!user.passwordHash && !hasPasskey && !hasOtherIdentity) return false;
  const result = db
    .delete(identities)
    .where(and(eq(identities.userId, userId), eq(identities.provider, provider)))
    .run();
  return result.changes > 0;
}

export type UpstreamResolution =
  | { user: PublicUser; created: boolean }
  // existe una cuenta con ese email pero no se puede vincular sin prueba de propiedad:
  // el usuario debe entrar con su método actual y vincular desde /account
  | { conflict: true };

// resuelve la cuenta para un perfil upstream: identidad exacta → email → alta nueva.
// la vinculación automática por email SOLO es segura si ambas partes han verificado
// la propiedad del email (evita el pre-hijacking: registrar una cuenta con el email
// ajeno, o un upstream que afirme un email sin verificar, para secuestrar la cuenta).
export async function findOrCreateFromUpstream(profile: UpstreamProfile): Promise<UpstreamResolution> {
  const identity = findIdentity(profile.provider, profile.providerAccountId);
  if (identity) {
    const row = getUserById(identity.userId);
    if (row) return { user: toPublicUser(row), created: false };
  }

  const existing = profile.email ? findUserByEmail(profile.email) : null;
  if (existing) {
    if (profile.emailVerified && existing.emailVerified) {
      linkIdentity(existing.id, profile.provider, profile.providerAccountId, profile.email);
      return { user: toPublicUser(existing), created: false };
    }
    return { conflict: true };
  }

  const email = profile.email ?? `${profile.provider}:${profile.providerAccountId}@${SYNTHETIC_EMAIL_DOMAIN}`;
  const user = await createUser({
    email,
    name: profile.name ?? email,
    picture: profile.picture,
    emailVerified: profile.email ? profile.emailVerified : false,
  });
  linkIdentity(user.id, profile.provider, profile.providerAccountId, profile.email);
  return { user, created: true };
}
