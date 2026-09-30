// sign in with apple: url de autorización (form_post, nonce, sin pkce), cookie de state
// cross-site, callback por POST y client_secret jwt firmado con la clave .p8
import { APPLE_CLIENT_ID, APPLE_KEY_ID, APPLE_PUBLIC_KEY, APPLE_TEAM_ID, DB_PATH, ISSUER } from './helpers.js';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { jwtVerify } from 'jose';
import { rmSync } from 'node:fs';
import type { Hono } from 'hono';
import { createApp } from '../src/app.js';
import { ensureSigningKey } from '../src/services/keys.js';
import { closeDb } from '../src/db/index.js';
import { APPLE_CLIENT_SECRET_TTL_S } from '../src/constants.js';
import type { AppEnv } from '../src/types.js';

const APPLE_AUDIENCE = 'https://appleid.apple.com';
const STATE_COOKIE = 'oauth_state';

let app: Hono<AppEnv>;

beforeAll(async () => {
  await ensureSigningKey();
  app = createApp();
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB_PATH}${suffix}`, { force: true });
});

// arranca el round-trip y devuelve el state, la cookie que lo ata y la url de apple
async function beginApple(): Promise<{ state: string; cookie: string; url: URL; setCookie: string }> {
  const res = await app.request('/login/apple');
  expect(res.status).toBe(302);
  const url = new URL(res.headers.get('location') ?? '');
  const setCookie = res.headers.get('set-cookie') ?? '';
  const state = url.searchParams.get('state') ?? '';
  return { state, cookie: `${STATE_COOKIE}=${state}`, url, setCookie };
}

// simula el form_post de apple contra el callback
const postCallback = (fields: Record<string, string>, cookie?: string) =>
  app.request('/callback/apple', {
    method: 'POST',
    body: new URLSearchParams(fields),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie && { Cookie: cookie }) },
  });

const errorOf = (res: Response): string | null =>
  new URL(res.headers.get('location') ?? '', ISSUER).searchParams.get('error');

describe('sign in with apple', () => {
  it('muestra el botón de apple en el login cuando hay credenciales', async () => {
    const html = await (await app.request('/login')).text();
    expect(html).toContain('href="/login/apple"');
  });

  it('pide form_post con nonce=state y sin pkce, y emite la cookie de state cross-site', async () => {
    const { url, state, setCookie } = await beginApple();
    expect(`${url.origin}${url.pathname}`).toBe('https://appleid.apple.com/auth/authorize');
    expect(url.searchParams.get('client_id')).toBe(APPLE_CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe(`${ISSUER}/callback/apple`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('response_mode')).toBe('form_post');
    expect(url.searchParams.get('scope')).toBe('name email');
    expect(url.searchParams.get('nonce')).toBe(state);
    expect(url.searchParams.has('code_challenge')).toBe(false);
    // una cookie Lax no viajaría en el POST cross-site desde appleid.apple.com
    expect(setCookie).toMatch(/SameSite=None/i);
    expect(setCookie).toMatch(/Secure/i);
  });

  it('rechaza el callback POST sin la cookie que ata el state al navegador', async () => {
    const { state } = await beginApple();
    const res = await postCallback({ state, code: 'c' });
    expect(res.status).toBe(302);
    expect(errorOf(res)).toMatch(/sesión de acceso no válida/);
  });

  it('propaga el error de apple y consume el state (single use)', async () => {
    const { state, cookie } = await beginApple();
    const res = await postCallback({ state, error: 'user_cancelled_authorize' }, cookie);
    expect(errorOf(res)).toMatch(/user_cancelled_authorize/);
    const replay = await postCallback({ state, error: 'user_cancelled_authorize' }, cookie);
    expect(errorOf(replay)).toMatch(/inválido o caducado/);
  });

  it('firma el client_secret como jwt es256 de la clave .p8 y no envía code_verifier', async () => {
    let tokenBody: URLSearchParams | null = null;
    // el token endpoint de apple rechaza: basta para capturar la petición sin red
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      tokenBody = new URLSearchParams(String(init?.body));
      return new Response('{"error":"invalid_grant"}', { status: 400 });
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const { state, cookie } = await beginApple();
    const res = await postCallback({ state, code: 'apple-code' }, cookie);
    expect(errorOf(res)).toMatch(/no se pudo completar el acceso con Apple/);

    const body = tokenBody as URLSearchParams | null;
    expect(body?.get('grant_type')).toBe('authorization_code');
    expect(body?.get('code')).toBe('apple-code');
    expect(body?.get('client_id')).toBe(APPLE_CLIENT_ID);
    expect(body?.get('redirect_uri')).toBe(`${ISSUER}/callback/apple`);
    expect(body?.has('code_verifier')).toBe(false);

    const { payload, protectedHeader } = await jwtVerify(body?.get('client_secret') ?? '', APPLE_PUBLIC_KEY, {
      issuer: APPLE_TEAM_ID,
      subject: APPLE_CLIENT_ID,
      audience: APPLE_AUDIENCE,
    });
    expect(protectedHeader).toMatchObject({ alg: 'ES256', kid: APPLE_KEY_ID });
    expect((payload.exp ?? 0) - (payload.iat ?? 0)).toBe(APPLE_CLIENT_SECRET_TTL_S);
  });
});
