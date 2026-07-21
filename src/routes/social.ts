// login social y vinculación de identidades upstream: /login/:provider arranca el
// round-trip y /callback/:provider lo cierra (login o link según el state)
import { Hono } from 'hono';
import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { beginUpstreamLogin, completeUpstreamLogin } from '../services/upstream.js';
import { findOrCreateFromUpstream, linkIdentity } from '../services/users.js';
import { createSession, setSessionCookie } from '../services/session.js';
import { getDb } from '../db/index.js';
import { mfaChallenges } from '../db/schema.js';
import { hasTotpEnabled } from '../services/totp.js';
import { MFA_CHALLENGE_TTL_MS } from '../constants.js';
import { getConfig } from '../config.js';
import type { AppEnv } from '../types.js';

// cookie que ata el state del round-trip al navegador que lo inició (anti login-csrf)
const STATE_COOKIE = 'oauth_state';
const MFA_CHALLENGE_ID_BYTES = 32;

// solo paths relativos propios: evita open redirects vía return_to
function safeReturnTo(value: string | null | undefined): string | null {
  return value && value.startsWith('/') && !value.startsWith('//') ? value : null;
}

export function socialRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  // arranque: ?return_to=/path para volver tras el login, ?link=1 para vincular la
  // cuenta upstream al usuario de la sesión actual (desde /account)
  r.get('/login/:provider', (c) => {
    const provider = c.req.param('provider');
    const returnTo = safeReturnTo(c.req.query('return_to'));
    let linkUserId: string | null = null;
    if (c.req.query('link') === '1') {
      const session = c.get('session');
      if (!session) return c.redirect('/login', 302);
      linkUserId = session.user.id;
    }
    const started = beginUpstreamLogin(provider, { returnTo, linkUserId });
    if (!started) return c.redirect('/login?error=provider', 302);
    // ata el state al navegador: la cookie debe coincidir con el state que vuelve
    // en el callback, así un callback preparado por un atacante no cuela
    setCookie(c, STATE_COOKIE, started.state, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: getConfig().isProd,
      path: '/callback',
      maxAge: Math.floor(MFA_CHALLENGE_TTL_MS / 1000),
    });
    return c.redirect(started.url, 302);
  });

  // callback del proveedor: valida y consume el state, y despacha login o link
  r.get('/callback/:provider', async (c) => {
    const provider = c.req.param('provider');
    // binding de navegador: el state de la url debe igualar el de la cookie
    const cookieState = getCookie(c, STATE_COOKIE);
    deleteCookie(c, STATE_COOKIE, { path: '/callback' });
    const urlState = c.req.query('state');
    if (!cookieState || cookieState !== urlState) {
      return c.redirect(`/login?error=${encodeURIComponent('sesión de acceso no válida, inténtalo de nuevo')}`, 302);
    }

    const result = await completeUpstreamLogin(provider, {
      code: c.req.query('code'),
      state: urlState,
      error: c.req.query('error'),
    });

    if ('error' in result) {
      const base = result.linkUserId ? '/account' : '/login';
      return c.redirect(`${base}?error=${encodeURIComponent(result.error)}`, 302);
    }

    const { profile, returnTo, linkUserId } = result;

    // vinculación desde /account: añade la identidad sin tocar la sesión actual
    if (linkUserId) {
      try {
        linkIdentity(linkUserId, profile.provider, profile.providerAccountId, profile.email);
      } catch (err) {
        console.error('[social] fallo vinculando identidad:', err);
        return c.redirect(`/account?error=${encodeURIComponent('no se pudo vincular la cuenta')}`, 302);
      }
      return c.redirect('/account', 302);
    }

    let resolution;
    try {
      resolution = await findOrCreateFromUpstream(profile);
    } catch (err) {
      console.error('[social] fallo resolviendo el usuario del login federado:', err);
      return c.redirect(`/login?error=${encodeURIComponent('no se pudo iniciar sesión')}`, 302);
    }

    // existe una cuenta con ese email pero sin propiedad verificada por ambas partes:
    // no se vincula solo (evita el secuestro); el usuario entra con su método y vincula
    if ('conflict' in resolution) {
      return c.redirect(
        `/login?error=${encodeURIComponent('ya existe una cuenta con ese email. entra con tu método habitual y vincula el proveedor desde tu cuenta')}`,
        302,
      );
    }

    const { user } = resolution;

    // si el usuario tiene un segundo factor local, el login federado también lo exige:
    // haber comprometido el upstream no debe saltarse el mfa que el usuario activó
    if (hasTotpEnabled(user.id)) {
      const id = randomBytes(MFA_CHALLENGE_ID_BYTES).toString('base64url');
      getDb()
        .insert(mfaChallenges)
        .values({
          id,
          userId: user.id,
          amr: JSON.stringify([profile.provider]),
          returnTo: safeReturnTo(returnTo),
          expiresAt: new Date(Date.now() + MFA_CHALLENGE_TTL_MS),
        })
        .run();
      return c.redirect(`/mfa?challenge=${id}`);
    }

    const session = createSession(user.id, [profile.provider], c.req.header('user-agent'));
    setSessionCookie(c, session.token, session.expiresAt);
    return c.redirect(safeReturnTo(returnTo) ?? '/account', 302);
  });

  return r;
}
