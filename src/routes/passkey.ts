// api json de passkeys, montada en /passkey: registro (con sesión) y login usernameless
import { Hono } from 'hono';
import {
  finishPasskeyLogin,
  finishPasskeyRegistration,
  startPasskeyLogin,
  startPasskeyRegistration,
} from '../services/webauthn.js';
import { createSession, setSessionCookie } from '../services/session.js';
import { clientIp } from '../services/client-ip.js';
import { PASSKEY_CLIENT_JS } from '../ui/passkey-client.js';
import type { AppEnv } from '../types.js';

// rate limit sencillo en memoria por ip para el login (evita fuerza bruta de challenges)
const LOGIN_RATE_MAX = 10;
const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAP_PURGE_SIZE = 1000; // purga perezosa cuando el mapa crece demasiado
const MAX_PASSKEY_NAME = 80; // tope de longitud del nombre de la passkey
const loginHits = new Map<string, { count: number; resetAt: number }>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  if (loginHits.size > RATE_MAP_PURGE_SIZE)
    [...loginHits].filter(([, h]) => h.resetAt <= now).forEach(([key]) => loginHits.delete(key));
  const hit = loginHits.get(ip);
  if (!hit || hit.resetAt <= now) {
    loginHits.set(ip, { count: 1, resetAt: now + LOGIN_RATE_WINDOW_MS });
    return false;
  }
  hit.count += 1;
  return hit.count > LOGIN_RATE_MAX;
}

// solo acepta rutas relativas internas (evita open redirect)
const safeReturnTo = (value: unknown): string =>
  typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : '/account';

const CLIENT_JS_HEADERS = {
  'Content-Type': 'application/javascript; charset=utf-8',
  'Cache-Control': 'public, max-age=300',
};

export function passkeyRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  r.get('/client.js', (c) => c.body(PASSKEY_CLIENT_JS, 200, CLIENT_JS_HEADERS));

  r.post('/register/options', async (c) => {
    const session = c.get('session');
    if (!session) return c.json({ error: 'no autenticado' }, 401);
    return c.json(await startPasskeyRegistration(session.user));
  });

  r.post('/register/verify', async (c) => {
    const session = c.get('session');
    if (!session) return c.json({ error: 'no autenticado' }, 401);
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.challengeId !== 'string' || typeof body.response !== 'object' || body.response === null)
      return c.json({ error: 'petición inválida' }, 400);
    const ok = await finishPasskeyRegistration(
      session.user.id,
      body.challengeId,
      body.response,
      typeof body.name === 'string' ? body.name.slice(0, MAX_PASSKEY_NAME) : undefined,
    );
    return ok ? c.json({ ok: true }) : c.json({ error: 'no se pudo registrar la passkey' }, 400);
  });

  r.post('/login/options', async (c) => c.json(await startPasskeyLogin()));

  r.post('/login/verify', async (c) => {
    if (isRateLimited(clientIp(c))) return c.json({ error: 'demasiados intentos, prueba más tarde' }, 429);
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.challengeId !== 'string' || typeof body.response !== 'object' || body.response === null)
      return c.json({ error: 'petición inválida' }, 400);
    const user = await finishPasskeyLogin(body.challengeId, body.response);
    if (!user) return c.json({ error: 'passkey no válida' }, 401);
    const session = createSession(user.id, ['swk'], c.req.header('user-agent'));
    setSessionCookie(c, session.token, session.expiresAt);
    return c.json({ ok: true, returnTo: safeReturnTo(body.returnTo) });
  });

  return r;
}
