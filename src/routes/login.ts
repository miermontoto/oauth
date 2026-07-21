// rutas de autenticación de primera parte: login/signup con password, logout,
// paso mfa (totp/recovery), forgot/reset de contraseña y verificación de email.
import { Hono } from 'hono';
import { z } from 'zod';
import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { authSessions, mfaChallenges } from '../db/schema.js';
import { MFA_CHALLENGE_MAX_ATTEMPTS, MFA_CHALLENGE_TTL_MS } from '../constants.js';
import {
  clearSessionCookie,
  createSession,
  deleteSession,
  setSessionCookie,
} from '../services/session.js';
import { createUser, findUserByEmail, setPassword, verifyCredentials } from '../services/users.js';
import { consumeEmailToken, issueEmailToken, sendPasswordResetEmail } from '../services/mailer.js';
import { FORGOT_LIMIT, LOGIN_LIMIT, MFA_LIMIT, SIGNUP_LIMIT, checkRateLimit } from '../services/rate-limit.js';
import { listProviders } from '../services/upstream.js';
import { hasTotpEnabled, verifyRecoveryCode, verifyTotp } from '../services/totp.js';
import { revokeUserTokens } from '../services/tokens.js';
import { clientIp } from '../services/client-ip.js';
import { ForgotPage, LoginPage, MessagePage, MfaPage, ResetPage, SignupPage } from '../ui/pages.js';
import type { AppEnv } from '../types.js';

const MFA_CHALLENGE_ID_BYTES = 32;
const TOTP_CODE_RE = /^\d{6}$/; // lo que no sea un código totp de 6 dígitos se trata como recovery
const ERR_BAD_CREDENTIALS = 'credenciales inválidas';
const ERR_TOO_MANY = 'demasiados intentos, espera unos minutos';

// solo paths relativos same-origin: deben empezar por '/' pero no por '//'
const safeReturnTo = (raw: string | null | undefined): string =>
  raw && raw.startsWith('/') && !raw.startsWith('//') ? raw : '/account';

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1),
  return_to: z.string().optional(),
});

const signupSchema = z.object({
  name: z.string().trim().min(2, 'el nombre es muy corto').max(80),
  email: z.string().trim().toLowerCase().email('email no válido'),
  password: z.string().min(8, 'la contraseña debe tener al menos 8 caracteres').max(200),
  return_to: z.string().optional(),
});

const resetSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8, 'la contraseña debe tener al menos 8 caracteres').max(200),
});

export function loginRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  r.get('/', (c) => c.redirect(c.get('session') ? '/account' : '/login'));

  r.get('/login', (c) => {
    const returnTo = c.req.query('return_to') ?? null;
    if (c.get('session') && c.req.query('force') !== '1') return c.redirect(safeReturnTo(returnTo));
    return c.html(LoginPage({ providers: listProviders(), returnTo }));
  });

  r.post('/login', async (c) => {
    const body = await c.req.parseBody();
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) {
      return c.html(LoginPage({ providers: listProviders(), returnTo: null, error: ERR_BAD_CREDENTIALS }), 400);
    }
    const { email, password, return_to } = parsed.data;
    const returnTo = return_to ?? null;

    if (!checkRateLimit(`login:${clientIp(c)}:${email}`, LOGIN_LIMIT.max, LOGIN_LIMIT.windowMs)) {
      return c.html(LoginPage({ providers: listProviders(), returnTo, error: ERR_TOO_MANY, email }), 429);
    }

    const user = await verifyCredentials(email, password);
    // mismo mensaje exista o no el email: no filtrar cuentas válidas
    if (!user) {
      return c.html(LoginPage({ providers: listProviders(), returnTo, error: ERR_BAD_CREDENTIALS, email }), 401);
    }

    if (hasTotpEnabled(user.id)) {
      const id = randomBytes(MFA_CHALLENGE_ID_BYTES).toString('base64url');
      getDb()
        .insert(mfaChallenges)
        .values({
          id,
          userId: user.id,
          amr: JSON.stringify(['pwd']),
          returnTo,
          expiresAt: new Date(Date.now() + MFA_CHALLENGE_TTL_MS),
        })
        .run();
      return c.redirect(`/mfa?challenge=${id}`);
    }

    const session = createSession(user.id, ['pwd'], c.req.header('user-agent'));
    setSessionCookie(c, session.token, session.expiresAt);
    return c.redirect(safeReturnTo(returnTo));
  });

  r.get('/signup', (c) => c.html(SignupPage({ returnTo: c.req.query('return_to') ?? null })));

  r.post('/signup', async (c) => {
    const body = await c.req.parseBody();
    const parsed = signupSchema.safeParse(body);
    const values = {
      name: typeof body.name === 'string' ? body.name : undefined,
      email: typeof body.email === 'string' ? body.email : undefined,
    };
    if (!parsed.success) {
      const error = parsed.error.issues[0]?.message ?? 'datos no válidos';
      return c.html(SignupPage({ returnTo: null, error, values }), 400);
    }
    const { name, email, password, return_to } = parsed.data;
    const returnTo = return_to ?? null;

    if (!checkRateLimit(`signup:${clientIp(c)}`, SIGNUP_LIMIT.max, SIGNUP_LIMIT.windowMs)) {
      return c.html(SignupPage({ returnTo, error: ERR_TOO_MANY, values }), 429);
    }
    if (findUserByEmail(email)) {
      return c.html(SignupPage({ returnTo, error: 'ya existe una cuenta con ese email', values }), 409);
    }

    // sin envío de email no hay verificación por correo: la cuenta nace verificada
    const user = await createUser({ email, password, name, emailVerified: true });
    const session = createSession(user.id, ['pwd'], c.req.header('user-agent'));
    setSessionCookie(c, session.token, session.expiresAt);
    return c.redirect(safeReturnTo(returnTo));
  });

  r.post('/logout', (c) => {
    const session = c.get('session');
    if (session) deleteSession(session.token);
    clearSessionCookie(c);
    return c.redirect('/login');
  });

  r.get('/mfa', (c) => {
    const challengeId = c.req.query('challenge');
    if (!challengeId) return c.redirect('/login');
    return c.html(MfaPage({ challengeId }));
  });

  r.post('/mfa', async (c) => {
    const body = await c.req.parseBody();
    const challengeId = typeof body.challenge === 'string' ? body.challenge : '';
    const code = typeof body.code === 'string' ? body.code.trim() : '';
    if (!challengeId) return c.redirect('/login');

    if (!checkRateLimit(`mfa:${clientIp(c)}`, MFA_LIMIT.max, MFA_LIMIT.windowMs)) {
      return c.html(MfaPage({ challengeId, error: ERR_TOO_MANY }), 429);
    }

    const db = getDb();
    const row = db.select().from(mfaChallenges).where(eq(mfaChallenges.id, challengeId)).get();
    if (!row) return c.redirect('/login');
    if (row.expiresAt.getTime() <= Date.now() || row.attempts >= MFA_CHALLENGE_MAX_ATTEMPTS) {
      db.delete(mfaChallenges).where(eq(mfaChallenges.id, challengeId)).run();
      return c.redirect('/login');
    }

    const valid = TOTP_CODE_RE.test(code) ? verifyTotp(row.userId, code) : verifyRecoveryCode(row.userId, code);
    if (!valid) {
      db.update(mfaChallenges)
        .set({ attempts: row.attempts + 1 })
        .where(eq(mfaChallenges.id, challengeId))
        .run();
      return c.html(MfaPage({ challengeId, error: 'código incorrecto' }), 401);
    }

    db.delete(mfaChallenges).where(eq(mfaChallenges.id, challengeId)).run();
    const amr = [...(JSON.parse(row.amr) as string[]), 'otp', 'mfa'];
    const session = createSession(row.userId, amr, c.req.header('user-agent'));
    setSessionCookie(c, session.token, session.expiresAt);
    return c.redirect(safeReturnTo(row.returnTo));
  });

  r.get('/forgot', (c) => c.html(ForgotPage({ sent: false })));

  // anti-enumeración: siempre responde "enviado", exista o no la cuenta
  r.post('/forgot', async (c) => {
    const body = await c.req.parseBody();
    const email = typeof body.email === 'string' ? body.email.toLowerCase().trim() : '';
    if (checkRateLimit(`forgot:${clientIp(c)}`, FORGOT_LIMIT.max, FORGOT_LIMIT.windowMs)) {
      const user = email ? findUserByEmail(email) : null;
      if (user) await sendPasswordResetEmail(user.email, user.name, issueEmailToken(user.id, 'reset'));
    }
    return c.html(ForgotPage({ sent: true }));
  });

  r.get('/reset', (c) => {
    const token = c.req.query('token');
    if (!token) return c.redirect('/forgot');
    return c.html(ResetPage({ token }));
  });

  r.post('/reset', async (c) => {
    const body = await c.req.parseBody();
    const parsed = resetSchema.safeParse(body);
    if (!parsed.success) {
      const token = typeof body.token === 'string' ? body.token : '';
      if (!token) return c.redirect('/forgot');
      const error = parsed.error.issues[0]?.message ?? 'datos no válidos';
      return c.html(ResetPage({ token, error }), 400);
    }

    const userId = consumeEmailToken(parsed.data.token, 'reset');
    if (!userId) {
      return c.html(
        MessagePage({
          title: 'Enlace no válido',
          message: 'El enlace de restablecimiento ha caducado o ya se usó. Pide uno nuevo.',
          linkHref: '/forgot',
          linkText: 'Solicitar otro enlace',
        }),
        400,
      );
    }

    await setPassword(userId, parsed.data.password);
    // cambia la contraseña ⇒ fuera todas las sesiones y tokens emitidos del usuario
    getDb().delete(authSessions).where(eq(authSessions.userId, userId)).run();
    revokeUserTokens(userId);
    clearSessionCookie(c);
    return c.html(
      MessagePage({
        title: 'Contraseña actualizada',
        message: 'Tu contraseña se ha cambiado y se han cerrado todas tus sesiones.',
        linkHref: '/login',
        linkText: 'Iniciar sesión',
      }),
    );
  });

  return r;
}
