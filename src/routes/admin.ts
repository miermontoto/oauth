// panel de administración: gestión de usuarios y clientes oauth registrados
import { Hono } from 'hono';
import type { AppEnv } from '../types.js';
import { deleteUser, listUsers, setUserActive } from '../services/users.js';
import { createClient, deleteClient, listClients } from '../services/clients.js';
import { AdminPage, ClientCreatedPage, ErrorPage } from '../ui/pages.js';

// url de vuelta a /admin con mensaje flash en query
const flash = (kind: 'ok' | 'error', msg: string): string =>
  `/admin?${kind}=${encodeURIComponent(msg)}`;

export function adminRoutes(): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  // exige sesión de administrador: sin sesión al login, sin permisos 403
  r.use('*', async (c, next) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login');
    if (!session.user.isAdmin)
      return c.html(
        ErrorPage({ status: 403, message: 'No tienes permisos para acceder a esta página.' }),
        403,
      );
    await next();
  });

  r.get('/', (c) =>
    c.html(
      AdminPage({
        users: listUsers(),
        clients: listClients(),
        currentUserId: c.get('session')!.user.id,
        flash: c.req.query('ok') ?? null,
        error: c.req.query('error') ?? null,
      }),
    ),
  );

  r.post('/clients', async (c) => {
    const body = await c.req.parseBody();
    const name = String(body.name ?? '').trim();
    // los textareas llegan con una uri por línea
    const splitUris = (raw: unknown): string[] =>
      String(raw ?? '')
        .split(/\r?\n/)
        .map((u) => u.trim())
        .filter(Boolean);
    const redirectUris = splitUris(body.redirect_uris);
    const postLogoutRedirectUris = splitUris(body.post_logout_redirect_uris);
    if (!name || redirectUris.length === 0)
      return c.redirect(flash('error', 'El nombre y al menos una redirect URI son obligatorios'));
    const { client, secret } = createClient({
      name,
      redirectUris,
      postLogoutRedirectUris: postLogoutRedirectUris.length ? postLogoutRedirectUris : undefined,
      isPublic: body.public === 'on',
    });
    // el secreto solo se muestra una vez, no se puede volver a recuperar
    return c.html(ClientCreatedPage({ client, secret }));
  });

  r.post('/clients/:id/delete', (c) => {
    deleteClient(c.req.param('id'));
    return c.redirect(flash('ok', 'Cliente eliminado'));
  });

  r.post('/users/:id/toggle-active', (c) => {
    const { user } = c.get('session')!;
    const id = c.req.param('id');
    if (id === user.id)
      return c.redirect(flash('error', 'No puedes desactivar tu propia cuenta'));
    const target = listUsers().find((u: { id: string }) => u.id === id);
    if (!target) return c.redirect(flash('error', 'Usuario no encontrado'));
    setUserActive(id, !target.isActive);
    return c.redirect(flash('ok', target.isActive ? 'Usuario desactivado' : 'Usuario activado'));
  });

  r.post('/users/:id/delete', (c) => {
    const { user } = c.get('session')!;
    const id = c.req.param('id');
    if (id === user.id) return c.redirect(flash('error', 'No puedes eliminar tu propia cuenta'));
    deleteUser(id);
    return c.redirect(flash('ok', 'Usuario eliminado'));
  });

  return r;
}
