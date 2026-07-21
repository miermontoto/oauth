// suite de integración del flujo oidc completo: discovery, signup, authorization
// code + pkce, rotación de refresh tokens y userinfo, todo contra app.request()
import { DB_PATH, ISSUER, basicAuth, cookieFrom, pkcePair } from './helpers.js';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from 'jose';
import { rmSync } from 'node:fs';
import type { Hono } from 'hono';
import { createApp } from '../src/app.js';
import { ensureSigningKey } from '../src/services/keys.js';
import { createClient, type Client } from '../src/services/clients.js';
import { closeDb } from '../src/db/index.js';
import { SESSION_COOKIE_NAME } from '../src/constants.js';
import type { AppEnv } from '../src/types.js';

const REDIRECT_URI = 'https://app.example.com/cb';
const USER_EMAIL = 'test@example.com';
const USER_PASSWORD = 'contraseña-segura-123';

let app: Hono<AppEnv>;
let publicClient: Client;
let confidentialClient: Client;
let confidentialSecret: string;
let sessionCookie: string;
let jwks: ReturnType<typeof createLocalJWKSet>;

// intercambia code por tokens en /oidc/token (cliente público por defecto)
const postToken = (body: Record<string, string>, headers: Record<string, string> = {}) =>
  app.request('/oidc/token', { method: 'POST', body: new URLSearchParams(body), headers });

// recorre /oidc/authorize con sesión y devuelve el code + verifier pkce
async function obtainCode(client: Client, scope: string, extra: Record<string, string> = {}) {
  const { verifier, challenge } = pkcePair();
  const params = new URLSearchParams({
    client_id: client.id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope,
    state: 'estado-x',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  });
  const res = await app.request(`/oidc/authorize?${params}`, { headers: { cookie: sessionCookie } });
  expect(res.status).toBe(302);
  const target = new URL(res.headers.get('location') ?? '');
  expect(target.origin + target.pathname).toBe(REDIRECT_URI);
  expect(target.searchParams.get('state')).toBe('estado-x');
  const code = target.searchParams.get('code');
  expect(code).toBeTruthy();
  return { code: code as string, verifier };
}

beforeAll(async () => {
  await ensureSigningKey();
  app = createApp();

  publicClient = createClient({ name: 'app pública', redirectUris: [REDIRECT_URI], isPublic: true }).client;
  const conf = createClient({ name: 'app confidencial', redirectUris: [REDIRECT_URI], isPublic: false });
  confidentialClient = conf.client;
  confidentialSecret = conf.secret as string;

  // signup vía form → cookie de sesión para el resto de la suite
  const res = await app.request('/signup', {
    method: 'POST',
    body: new URLSearchParams({ name: 'Usuario Test', email: USER_EMAIL, password: USER_PASSWORD }),
  });
  expect(res.status).toBe(302);
  sessionCookie = cookieFrom(res, SESSION_COOKIE_NAME);

  const jwksRes = await app.request('/.well-known/jwks.json');
  jwks = createLocalJWKSet((await jwksRes.json()) as JSONWebKeySet);
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB_PATH}${suffix}`, { force: true });
});

describe('discovery y jwks', () => {
  it('publica la metadata openid con los endpoints del issuer', async () => {
    const res = await app.request('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    const meta = await res.json();
    expect(meta.issuer).toBe(ISSUER);
    expect(meta.authorization_endpoint).toBe(`${ISSUER}/oidc/authorize`);
    expect(meta.token_endpoint).toBe(`${ISSUER}/oidc/token`);
    expect(meta.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(meta.response_types_supported).toEqual(['code']);
    expect(meta.id_token_signing_alg_values_supported).toEqual(['ES256']);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('el jwks expone una clave EC P-256 para ES256', async () => {
    const res = await app.request('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    const { keys } = await res.json();
    expect(keys.length).toBeGreaterThan(0);
    const key = keys[0];
    expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    expect(key.kid).toBeTruthy();
    expect(key.d).toBeUndefined(); // jamás se publica la parte privada
  });
});

describe('signup y sesión', () => {
  it('la cookie de sesión da acceso a /account', async () => {
    const res = await app.request('/account', { headers: { cookie: sessionCookie } });
    expect(res.status).toBe(200);
  });
});

describe('authorization code + pkce (cliente público)', () => {
  it('emite tokens verificables con el jwks e id_token con claims de identidad', async () => {
    const { code, verifier } = await obtainCode(publicClient, 'openid email profile offline_access', {
      nonce: 'nonce-abc',
    });
    const res = await postToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: publicClient.id,
    });
    expect(res.status).toBe(200);
    const tokens = await res.json();
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.refresh_token).toBeTruthy(); // offline_access solicitado

    // access token: jwt es256 verificable contra el jwks publicado
    const { payload: at } = await jwtVerify(tokens.access_token, jwks, {
      issuer: ISSUER,
      audience: publicClient.id,
    });
    expect(at.sub).toBeTruthy();
    expect(at.scope).toBe('openid email profile offline_access');

    // id_token: misma firma, claims según scope + amr/nonce
    const { payload: idt } = await jwtVerify(tokens.id_token, jwks, {
      issuer: ISSUER,
      audience: publicClient.id,
    });
    expect(idt.sub).toBe(at.sub);
    expect(idt.email).toBe(USER_EMAIL);
    expect(idt.email_verified).toBe(true); // sin email, el alta nace verificada
    expect(idt.amr).toEqual(['pwd']);
    expect(idt.nonce).toBe('nonce-abc');
    expect(typeof idt.auth_time).toBe('number');
  });

  it('sin offline_access no se emite refresh_token', async () => {
    const { code, verifier } = await obtainCode(publicClient, 'openid email');
    const res = await postToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: publicClient.id,
    });
    expect(res.status).toBe(200);
    const tokens = await res.json();
    expect(tokens.refresh_token).toBeUndefined();
  });

  it('el code es de un solo uso: el segundo canje falla con invalid_grant', async () => {
    const { code, verifier } = await obtainCode(publicClient, 'openid');
    const body = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: publicClient.id,
    };
    expect((await postToken(body)).status).toBe(200);
    const replay = await postToken(body);
    expect(replay.status).toBe(400);
    expect((await replay.json()).error).toBe('invalid_grant');
  });

  it('un code_verifier incorrecto falla con invalid_grant', async () => {
    const { code } = await obtainCode(publicClient, 'openid');
    const res = await postToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: pkcePair().verifier, // verifier de otro par
      client_id: publicClient.id,
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_grant');
  });
});

describe('cliente confidencial (client_secret_basic)', () => {
  it('canjea el code autenticándose con basic', async () => {
    const { code, verifier } = await obtainCode(confidentialClient, 'openid email');
    const res = await postToken(
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
      { authorization: basicAuth(confidentialClient.id, confidentialSecret) },
    );
    expect(res.status).toBe(200);
    const tokens = await res.json();
    expect(decodeJwt(tokens.access_token).aud).toBe(confidentialClient.id);
  });

  it('un secret incorrecto responde 401 invalid_client', async () => {
    const { code, verifier } = await obtainCode(confidentialClient, 'openid');
    const res = await postToken(
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
      { authorization: basicAuth(confidentialClient.id, 'secret-incorrecto') },
    );
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_client');
  });
});

describe('rotación de refresh tokens', () => {
  it('rota, detecta replay y revoca la cadena entera', async () => {
    const { code, verifier } = await obtainCode(publicClient, 'openid offline_access');
    const first = await postToken({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: publicClient.id,
    });
    const rt1 = (await first.json()).refresh_token as string;

    // rotación normal: tokens nuevos con refresh nuevo
    const rotated = await postToken({ grant_type: 'refresh_token', refresh_token: rt1, client_id: publicClient.id });
    expect(rotated.status).toBe(200);
    const rt2 = (await rotated.json()).refresh_token as string;
    expect(rt2).toBeTruthy();
    expect(rt2).not.toBe(rt1);

    // replay del viejo → invalid_grant y cadena comprometida
    const replay = await postToken({ grant_type: 'refresh_token', refresh_token: rt1, client_id: publicClient.id });
    expect(replay.status).toBe(400);
    expect((await replay.json()).error).toBe('invalid_grant');

    // el sucesor también queda revocado (revocación en cadena)
    const successor = await postToken({ grant_type: 'refresh_token', refresh_token: rt2, client_id: publicClient.id });
    expect(successor.status).toBe(400);
    expect((await successor.json()).error).toBe('invalid_grant');
  });
});

describe('userinfo', () => {
  it('devuelve los claims del scope con un access token válido', async () => {
    const { code, verifier } = await obtainCode(publicClient, 'openid email profile');
    const tokens = await (
      await postToken({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
        client_id: publicClient.id,
      })
    ).json();
    const res = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(res.status).toBe(200);
    const claims = await res.json();
    expect(claims.sub).toBe(decodeJwt(tokens.access_token).sub);
    expect(claims.email).toBe(USER_EMAIL);
    expect(claims.name).toBe('Usuario Test');
    expect(claims.preferred_username).toBe(USER_EMAIL.split('@')[0]);
  });

  it('un token basura responde 401 invalid_token', async () => {
    const res = await app.request('/oidc/userinfo', { headers: { authorization: 'Bearer basura' } });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_token');
  });
});

describe('authorize sin sesión', () => {
  const baseParams = () => {
    const { challenge } = pkcePair();
    return new URLSearchParams({
      client_id: publicClient.id,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
  };

  it('redirige a /login con return_to al authorize original', async () => {
    const res = await app.request(`/oidc/authorize?${baseParams()}`);
    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location.startsWith('/login?return_to=')).toBe(true);
    const returnTo = decodeURIComponent(location.slice('/login?return_to='.length));
    expect(returnTo.startsWith('/oidc/authorize?')).toBe(true);
    expect(returnTo).toContain(`client_id=${publicClient.id}`);
  });

  it('prompt=none sin sesión redirige con error=login_required', async () => {
    const params = baseParams();
    params.set('prompt', 'none');
    params.set('state', 'estado-y');
    const res = await app.request(`/oidc/authorize?${params}`);
    expect(res.status).toBe(302);
    const target = new URL(res.headers.get('location') ?? '');
    expect(target.origin + target.pathname).toBe(REDIRECT_URI);
    expect(target.searchParams.get('error')).toBe('login_required');
    expect(target.searchParams.get('state')).toBe('estado-y');
  });
});
