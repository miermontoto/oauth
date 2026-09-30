// sesiones de navegador del idp: servicio de @platform/auth + metadatos amr/auth_time
import { count, eq, gt } from 'drizzle-orm';
import { createSessionService, toSessionInfos, type SessionInfo } from '@platform/auth';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Context, MiddlewareHandler } from 'hono';
import { getDb } from '../db/index.js';
import { authSessions, sessionMeta, users } from '../db/schema.js';
import { SESSION_COOKIE_NAME, SESSION_TTL_MS } from '../constants.js';
import { getConfig } from '../config.js';
import type { AppEnv, CurrentSession, PublicUser } from '../types.js';

export function toPublicUser(row: typeof users.$inferSelect): PublicUser {
  return {
    id: row.id,
    email: row.email,
    emailVerified: row.emailVerified,
    name: row.name,
    picture: row.picture,
    isAdmin: row.isAdmin,
    hasPassword: row.passwordHash !== null,
  };
}

const service = createSessionService<PublicUser, string>({
  getDb: () => getDb() as never,
  table: authSessions,
  ttlMs: SESSION_TTL_MS,
  sliding: true,
  resolveUser: (userId) => {
    const row = getDb().select().from(users).where(eq(users.id, userId)).get();
    if (!row || !row.isActive) return null;
    return toPublicUser(row);
  },
});

export function createSession(userId: string, amr: string[], userAgent?: string): { token: string; expiresAt: number } {
  const session = service.createSession(userId, userAgent);
  getDb()
    .insert(sessionMeta)
    .values({ token: session.token, amr: JSON.stringify(amr), authTime: new Date() })
    .run();
  return { token: session.token, expiresAt: session.expiresAt };
}

export function validateSession(token: string): CurrentSession | null {
  const session = service.validateSession(token);
  if (!session) return null;
  const meta = getDb().select().from(sessionMeta).where(eq(sessionMeta.token, token)).get();
  return {
    token: session.token,
    user: session.user,
    amr: meta ? (JSON.parse(meta.amr) as string[]) : [],
    authTime: meta ? meta.authTime.getTime() : session.createdAt,
    expiresAt: session.expiresAt,
  };
}

export const deleteSession = (token: string): void => service.deleteSession(token);
export const cleanupExpiredSessions = (): void => service.cleanupExpiredSessions();
export const deleteOtherSessions = (userId: string, currentToken: string): number =>
  service.deleteOtherSessions(userId, currentToken);

export function listSessionInfos(userId: string, currentToken: string): SessionInfo[] {
  return toSessionInfos(service.listSessions(userId), currentToken);
}

// sesiones de navegador vigentes de todos los usuarios (resumen del panel de administración)
export function countActiveSessions(): number {
  return (
    getDb()
      .select({ n: count() })
      .from(authSessions)
      .where(gt(authSessions.expiresAt, new Date()))
      .get()?.n ?? 0
  );
}

// middleware de identidad opcional: resuelve la cookie y deja session (o null) en contexto
export const sessionMiddleware: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  c.set('session', token ? validateSession(token) : null);
  await next();
};

export function setSessionCookie(c: Context<AppEnv>, token: string, expiresAt: number): void {
  setCookie(c, SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: getConfig().isProd,
    path: '/',
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(c: Context<AppEnv>): void {
  deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
}
