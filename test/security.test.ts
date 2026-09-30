// regresiones de seguridad: cubren los fallos encontrados en la auditoría para que
// no reaparezcan (linking upstream, rotación atómica, binding de revoke, admin, xss en login).
import { DB_PATH } from './helpers.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import { ensureSigningKey } from '../src/services/keys.js';
import { closeDb } from '../src/db/index.js';
import { createClient } from '../src/services/clients.js';
import { issueTokens, rotateRefreshToken, revokeToken, sha256hex } from '../src/services/tokens.js';
import { createUser, findOrCreateFromUpstream, findIdentity } from '../src/services/users.js';
import { getDb } from '../src/db/index.js';
import { refreshTokens } from '../src/db/schema.js';
import { eq } from 'drizzle-orm';
import type { UpstreamProfile } from '../src/types.js';
import { createApp } from '../src/app.js';
import { AUTHORIZE_PATH } from '../src/constants.js';

beforeAll(async () => {
  await ensureSigningKey();
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB_PATH}${suffix}`, { force: true });
});

// emite un juego de tokens con refresh para un cliente/usuario dados
async function seedRefresh(clientId: string, userId: string): Promise<string> {
  const tokens = await issueTokens({
    clientId,
    userId,
    scope: 'openid offline_access',
    authTime: Date.now(),
    amr: ['pwd'],
  });
  return tokens.refresh_token as string;
}

describe('vinculación de identidad upstream', () => {
  it('NO auto-vincula a una cuenta existente si el email no está verificado por ambas partes', async () => {
    const existing = await createUser({ email: 'victima@example.com', password: 'x'.repeat(10), name: 'Víctima', emailVerified: true });
    // perfil upstream que afirma el email de la víctima pero SIN verificar
    const profile: UpstreamProfile = {
      provider: 'google',
      providerAccountId: 'attacker-sub-1',
      email: 'victima@example.com',
      emailVerified: false,
      name: 'Atacante',
      picture: null,
    };
    const res = await findOrCreateFromUpstream(profile);
    expect('conflict' in res).toBe(true);
    // no se creó ninguna identidad colgando de la cuenta de la víctima
    expect(findIdentity('google', 'attacker-sub-1')).toBeNull();
    expect(existing.id).toBeTruthy();
  });

  it('vincula solo cuando ambos emails están verificados', async () => {
    await createUser({ email: 'ambos@example.com', password: 'x'.repeat(10), name: 'Ambos', emailVerified: true });
    const profile: UpstreamProfile = {
      provider: 'google',
      providerAccountId: 'good-sub-1',
      email: 'ambos@example.com',
      emailVerified: true,
      name: 'Ambos',
      picture: null,
    };
    const res = await findOrCreateFromUpstream(profile);
    expect('user' in res).toBe(true);
    expect(findIdentity('google', 'good-sub-1')).not.toBeNull();
  });
});

describe('primer usuario admin sin ADMIN_EMAILS', () => {
  it('el segundo usuario del sistema no es admin', async () => {
    // en esta suite ya se han creado usuarios en beforeAll de otros describe,
    // así que este nunca es el primero → no debe ser admin
    const u = await createUser({ email: 'noadmin@example.com', password: 'x'.repeat(10), name: 'No Admin' });
    expect(u.isAdmin).toBe(false);
  });
});

describe('rotación de refresh tokens', () => {
  it('marca replacedByHash al rotar y revoca la cadena en un replay', async () => {
    const { client } = createClient({ name: 'c-rot', redirectUris: ['https://c/cb'], isPublic: true });
    const user = await createUser({ email: 'rot@example.com', password: 'x'.repeat(10), name: 'Rot' });
    const t1 = await seedRefresh(client.id, user.id);

    const rotated = await rotateRefreshToken(t1, client.id);
    expect(rotated?.refresh_token).toBeTruthy();
    const t2 = rotated!.refresh_token as string;

    // t1 quedó enlazado a t2 (cadena)
    const t1row = getDb().select().from(refreshTokens).where(eq(refreshTokens.tokenHash, sha256hex(t1))).get();
    expect(t1row?.replacedByHash).toBe(sha256hex(t2));

    // replay de t1: devuelve null y revoca TODA la cadena (t1 y t2)
    const replay = await rotateRefreshToken(t1, client.id);
    expect(replay).toBeNull();
    const t2row = getDb().select().from(refreshTokens).where(eq(refreshTokens.tokenHash, sha256hex(t2))).get();
    expect(t2row?.revokedAt).not.toBeNull();
    // y t2, ya revocado, tampoco puede rotar
    expect(await rotateRefreshToken(t2, client.id)).toBeNull();
  });

  it('un refresh token de otro cliente no rota', async () => {
    const a = createClient({ name: 'c-a', redirectUris: ['https://a/cb'], isPublic: true }).client;
    const b = createClient({ name: 'c-b', redirectUris: ['https://b/cb'], isPublic: true }).client;
    const user = await createUser({ email: 'xclient@example.com', password: 'x'.repeat(10), name: 'X' });
    const token = await seedRefresh(a.id, user.id);
    expect(await rotateRefreshToken(token, b.id)).toBeNull();
  });
});

describe('revoke con binding de cliente (rfc 7009)', () => {
  it('un cliente no puede revocar el token de otro; el dueño sí', async () => {
    const a = createClient({ name: 'r-a', redirectUris: ['https://a/cb'], isPublic: true }).client;
    const b = createClient({ name: 'r-b', redirectUris: ['https://b/cb'], isPublic: true }).client;
    const user = await createUser({ email: 'revoke@example.com', password: 'x'.repeat(10), name: 'Rev' });
    const token = await seedRefresh(a.id, user.id);

    // el cliente b no es el dueño → no revoca
    expect(revokeToken(token, b.id)).toBe(false);
    // el dueño a → revoca
    expect(revokeToken(token, a.id)).toBe(true);
    // segunda vez ya no hay nada vivo que revocar
    expect(revokeToken(token, a.id)).toBe(false);
  });
});

describe('página de login', () => {
  it('un return_to con </script> no inyecta código en el script de passkeys', async () => {
    const payload = '</script><script>alert(1)</script>';
    const html = await (await createApp().request(`/login?return_to=${encodeURIComponent(payload)}`)).text();
    expect(html).not.toContain(payload);
    // el valor solo aparece escapado dentro del data-attribute del botón
    expect(html).toContain('data-return-to="&lt;/script&gt;');
  });

  it('muestra la app que pide el acceso solo si client_id y redirect_uri están registrados', async () => {
    const client = createClient({ name: 'app-contexto', redirectUris: ['https://ctx.example.com/cb'], isPublic: true }).client;
    const authorize = (redirectUri: string): string =>
      `${AUTHORIZE_PATH}?${new URLSearchParams({ client_id: client.id, redirect_uri: redirectUri, scope: 'openid email' })}`;
    const login = async (returnTo: string): Promise<string> =>
      (await createApp().request(`/login?return_to=${encodeURIComponent(returnTo)}`)).text();

    const ok = await login(authorize('https://ctx.example.com/cb'));
    expect(ok).toContain('app-contexto');
    expect(ok).toContain('ctx.example.com');
    // un destino no registrado no se describe: nunca se enseña un host arbitrario como "destino"
    expect(await login(authorize('https://evil.example.com/cb'))).not.toContain('app-contexto');
  });
});
