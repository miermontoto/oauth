// rutas de gestión de cuenta del usuario autenticado (perfil, contraseña,
// totp, passkeys, identidades vinculadas y sesiones)
import { Hono } from 'hono';
import type { AppEnv } from '../types.js';
import { deleteOtherSessions, listSessionInfos } from '../services/session.js';
import {
  listIdentities,
  setPassword,
  unlinkIdentity,
  updateProfile,
  verifyCredentials,
} from '../services/users.js';
import {
  confirmTotpSetup,
  disableTotp,
  hasTotpEnabled,
  startTotpSetup,
  verifyTotp,
} from '../services/totp.js';
import { deletePasskey, listPasskeys, renamePasskey } from '../services/webauthn.js';
import { listProviders } from '../services/upstream.js';
import { revokeUserTokens } from '../services/tokens.js';
import { AccountPage, TotpRecoveryCodesPage, TotpSetupPage } from '../ui/pages.js';

// longitud mínima de contraseña (no existe en constants.ts)
const MIN_PASSWORD_LENGTH = 8;
// tope de longitud del nombre (igual que en signup); evita persistir strings enormes
const MAX_NAME_LENGTH = 80;

// url de vuelta a /account con mensaje flash en query
const flash = (kind: 'ok' | 'error', msg: string): string =>
  `/account?${kind}=${encodeURIComponent(msg)}`;

export function accountRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  // exige sesión activa; sin ella se vuelve al login con retorno a la ruta actual
  r.use('*', async (c, next) => {
    if (!c.get('session')) return c.redirect(`/login?return_to=${encodeURIComponent(c.req.path)}`);
    await next();
  });

  r.get('/', (c) => {
    const { user, token } = c.get('session')!;
    return c.html(
      AccountPage({
        user,
        identities: listIdentities(user.id),
        passkeys: listPasskeys(user.id),
        sessions: listSessionInfos(user.id, token),
        providers: listProviders(),
        totpEnabled: hasTotpEnabled(user.id),
        flash: c.req.query('ok') ?? null,
        error: c.req.query('error') ?? null,
      }),
    );
  });

  r.post('/profile', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const name = String(body.name ?? '').trim().slice(0, MAX_NAME_LENGTH);
    if (!name) return c.redirect(flash('error', 'El nombre no puede estar vacío'));
    updateProfile(user.id, { name });
    return c.redirect(flash('ok', 'Perfil actualizado'));
  });

  r.post('/password', async (c) => {
    const { user, token } = c.get('session')!;
    const body = await c.req.parseBody();
    const password = String(body.password ?? '');
    if (password.length < MIN_PASSWORD_LENGTH)
      return c.redirect(
        flash('error', `La contraseña debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres`),
      );
    // si ya hay contraseña, la actual debe ser válida antes de cambiarla
    if (user.hasPassword) {
      const current = String(body.current ?? '');
      if (!current || !(await verifyCredentials(user.email, current)))
        return c.redirect(flash('error', 'La contraseña actual no es válida'));
    }
    await setPassword(user.id, password);
    // cambiar la contraseña invalida el resto: otras sesiones y tokens emitidos
    deleteOtherSessions(user.id, token);
    revokeUserTokens(user.id);
    return c.redirect(flash('ok', 'Contraseña actualizada'));
  });

  r.get('/totp/setup', (c) => {
    const { user } = c.get('session')!;
    if (hasTotpEnabled(user.id)) return c.redirect(flash('error', 'TOTP ya está activado'));
    const { secret, otpauthUrl } = startTotpSetup(user.id);
    return c.html(TotpSetupPage({ secret, otpauthUrl, error: null }));
  });

  r.post('/totp/confirm', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const code = String(body.code ?? '').trim();
    const codes = confirmTotpSetup(user.id, code);
    if (codes) return c.html(TotpRecoveryCodesPage({ codes }));
    // el setup pendiente conserva el secreto, así que se re-renderiza con error
    const { secret, otpauthUrl } = startTotpSetup(user.id);
    return c.html(TotpSetupPage({ secret, otpauthUrl, error: 'Código incorrecto, inténtalo de nuevo' }));
  });

  r.post('/totp/disable', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const code = String(body.code ?? '').trim();
    if (!verifyTotp(user.id, code)) return c.redirect(flash('error', 'Código TOTP incorrecto'));
    disableTotp(user.id);
    return c.redirect(flash('ok', 'TOTP desactivado'));
  });

  r.post('/passkeys/rename', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const id = String(body.id ?? '');
    const name = String(body.name ?? '').trim();
    if (!id || !name) return c.redirect(flash('error', 'Datos de passkey no válidos'));
    return c.redirect(
      renamePasskey(user.id, id, name)
        ? flash('ok', 'Passkey renombrada')
        : flash('error', 'Passkey no encontrada'),
    );
  });

  r.post('/passkeys/delete', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const id = String(body.id ?? '');
    return c.redirect(
      id && deletePasskey(user.id, id)
        ? flash('ok', 'Passkey eliminada')
        : flash('error', 'Passkey no encontrada'),
    );
  });

  r.post('/identities/unlink', async (c) => {
    const { user } = c.get('session')!;
    const body = await c.req.parseBody();
    const provider = String(body.provider ?? '');
    return c.redirect(
      provider && unlinkIdentity(user.id, provider)
        ? flash('ok', 'Cuenta desvinculada')
        : flash('error', 'No puedes quitar el último método de acceso'),
    );
  });

  r.post('/sessions/logout-others', (c) => {
    const { user, token } = c.get('session')!;
    const n = deleteOtherSessions(user.id, token);
    return c.redirect(
      flash('ok', n > 0 ? `Sesiones cerradas: ${n}` : 'No había otras sesiones abiertas'),
    );
  });

  return r;
}
