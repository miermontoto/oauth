// esquema del idp: identidad central + credenciales + estado oauth/oidc.
// todos los tokens de larga vida se guardan hasheados (sha-256); los códigos
// de un solo uso también. las sesiones de navegador usan la tabla canónica
// de @platform/auth (token opaco en claro, como el resto de la plataforma).
import { index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';
import { defineSessionTableText } from '@platform/auth';

export const users = sqliteTable(
  'users',
  {
    id: text('id').primaryKey(), // uuid
    email: text('email').notNull(), // siempre lowercase
    emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
    passwordHash: text('password_hash'), // null = cuenta sin contraseña (social/passkey)
    name: text('name').notNull(),
    picture: text('picture'),
    isAdmin: integer('is_admin', { mode: 'boolean' }).notNull().default(false), // el primer usuario es admin
    isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
  },
  (t) => [uniqueIndex('idx_users_email').on(t.email)],
);

// sesión de navegador del propio idp (sso entre apps)
export const authSessions = defineSessionTableText(() => users.id);

// metadatos de autenticación de cada sesión (rfc 8176 para amr)
export const sessionMeta = sqliteTable('session_meta', {
  token: text('token')
    .primaryKey()
    .references(() => authSessions.token, { onDelete: 'cascade' }),
  amr: text('amr').notNull(), // json array: ["pwd"], ["pwd","otp"], ["swk"]...
  authTime: integer('auth_time', { mode: 'timestamp_ms' }).notNull(),
});

// cuentas vinculadas de proveedores upstream (google, github...)
export const identities = sqliteTable(
  'identities',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull(),
    providerAccountId: text('provider_account_id').notNull(),
    email: text('email'),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  },
  (t) => [
    uniqueIndex('idx_identity_provider_account').on(t.provider, t.providerAccountId),
    index('idx_identity_user').on(t.userId),
  ],
);

// totp (mfa opt-in), portado del diseño de duckhunt
export const userTotp = sqliteTable('user_totp', {
  userId: text('user_id')
    .primaryKey()
    .references(() => users.id, { onDelete: 'cascade' }),
  secret: text('secret').notNull(), // base32
  enabled: integer('enabled', { mode: 'boolean' }).notNull().default(false),
  lastStep: integer('last_step').notNull().default(0), // anti-replay
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  confirmedAt: integer('confirmed_at', { mode: 'timestamp_ms' }),
});

export const recoveryCodes = sqliteTable(
  'recovery_codes',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(), // sha-256 hex
    usedAt: integer('used_at', { mode: 'timestamp_ms' }),
  },
  (t) => [index('idx_recovery_user').on(t.userId)],
);

// desafío interino de login con mfa pendiente
export const mfaChallenges = sqliteTable('mfa_challenges', {
  id: text('id').primaryKey(), // token aleatorio
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  amr: text('amr').notNull(), // factores ya superados
  returnTo: text('return_to'),
  attempts: integer('attempts').notNull().default(0),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
});

// passkeys webauthn
export const passkeys = sqliteTable(
  'passkeys',
  {
    id: text('id').primaryKey(), // credential id, base64url
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    publicKey: text('public_key').notNull(), // base64url
    counter: integer('counter').notNull().default(0),
    transports: text('transports'), // json array
    name: text('name').notNull(),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    lastUsedAt: integer('last_used_at', { mode: 'timestamp_ms' }),
  },
  (t) => [index('idx_passkey_user').on(t.userId)],
);

export const webauthnChallenges = sqliteTable('webauthn_challenges', {
  id: text('id').primaryKey(), // token aleatorio que viaja en cookie/respuesta
  challenge: text('challenge').notNull(),
  userId: text('user_id'), // null en login usernameless
  kind: text('kind').notNull(), // 'register' | 'login'
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
});

// clientes oauth registrados (las apps: carreterinas, sis, duckhunt, url...)
export const clients = sqliteTable('clients', {
  id: text('id').primaryKey(), // client_id
  secretHash: text('secret_hash'), // sha-256 hex; null = cliente público (pkce obligatorio)
  name: text('name').notNull(),
  redirectUris: text('redirect_uris').notNull(), // json array
  postLogoutRedirectUris: text('post_logout_redirect_uris'), // json array
  firstParty: integer('first_party', { mode: 'boolean' }).notNull().default(true), // sin pantalla de consent
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
});

// códigos de autorización (un solo uso, hasheados)
export const authCodes = sqliteTable(
  'auth_codes',
  {
    codeHash: text('code_hash').primaryKey(),
    clientId: text('client_id')
      .notNull()
      .references(() => clients.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    redirectUri: text('redirect_uri').notNull(),
    scope: text('scope').notNull(),
    nonce: text('nonce'),
    codeChallenge: text('code_challenge'),
    codeChallengeMethod: text('code_challenge_method'), // solo 'S256'
    authTime: integer('auth_time', { mode: 'timestamp_ms' }).notNull(),
    amr: text('amr').notNull(), // json array
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  },
  (t) => [index('idx_code_expires').on(t.expiresAt)],
);

// refresh tokens con rotación y revocación en cadena (modelo mcp-oauth de duckhunt)
export const refreshTokens = sqliteTable(
  'refresh_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    clientId: text('client_id')
      .notNull()
      .references(() => clients.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    scope: text('scope').notNull(),
    authTime: integer('auth_time', { mode: 'timestamp_ms' }).notNull(),
    amr: text('amr').notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    revokedAt: integer('revoked_at', { mode: 'timestamp_ms' }),
    replacedByHash: text('replaced_by_hash'), // cadena de rotación para detectar replay
  },
  (t) => [index('idx_refresh_user').on(t.userId), index('idx_refresh_expires').on(t.expiresAt)],
);

// tokens de email (verificación y reset de contraseña), un solo uso, hasheados
export const emailTokens = sqliteTable(
  'email_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull(), // 'verify' | 'reset'
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
    usedAt: integer('used_at', { mode: 'timestamp_ms' }),
  },
  (t) => [index('idx_email_token_user').on(t.userId)],
);

// claves de firma jwt (es256); se genera una al primer boot y se persiste
export const signingKeys = sqliteTable('signing_keys', {
  kid: text('kid').primaryKey(),
  alg: text('alg').notNull(), // 'ES256'
  privateJwk: text('private_jwk').notNull(), // json
  publicJwk: text('public_jwk').notNull(), // json
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  retiredAt: integer('retired_at', { mode: 'timestamp_ms' }), // clave rotada: solo verifica, no firma
});

// estado del round-trip con proveedores upstream (persistente, no en memoria)
export const loginStates = sqliteTable('login_states', {
  state: text('state').primaryKey(),
  provider: text('provider').notNull(),
  codeVerifier: text('code_verifier'), // pkce hacia el upstream
  returnTo: text('return_to'),
  linkUserId: text('link_user_id'), // vinculación desde /account en vez de login
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
});
