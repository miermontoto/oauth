# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

"mier id" — personal OIDC identity provider, issuer `https://id.mier.info`. SSO for the owner's apps: carreterinas, sis, duckhunt (Node) and url (Go, verifies access tokens statelessly via JWKS).

## Stack

Hono 4 + drizzle-orm + better-sqlite3 (WAL) on Node 22, ESM, TypeScript strict. Shared `@platform/*` packages come from the `platform/` git submodule as TS source; tsup bundles them into `dist/index.js` (`noExternal`).

## Project structure

- `src/index.ts` — boot: env → db (migrations on open) → signing key → http server + periodic cleanups
- `src/app.ts` — app composition: session middleware + routers
- `src/config.ts` — zod-validated env, cached (`getConfig()`)
- `src/constants.ts` — all TTLs / cookie name / scopes; never hardcode numbers that exist here
- `src/types.ts` — shared contracts: `PublicUser`, `CurrentSession`, `AppEnv`, `UpstreamProfile`
- `src/db/` — `schema.ts` + generated `migrations/`; `getDb()` singleton with sync drizzle API (`.get()/.all()/.run()`)
- `src/services/` — `session.ts` (browser sessions + amr meta), `keys.ts` (ES256 signing key), `tokens.ts` (oauth tokens + cleanup)
- `src/routes/` — `oidc.ts` (+ `/.well-known`), `login.ts`, `social.ts`, `passkey.ts`, `account.ts`, `admin.ts`

## Key flows

- **Authorization code + PKCE (S256)**: codes are single-use, 60s TTL. All long-lived tokens and one-shot codes are stored sha-256 hashed.
- **Access token = JWT ES256** verifiable via JWKS — the Go app verifies stateless. Key generated at first boot, persisted in `signing_keys` (rotation via `retired_at`: retired keys only verify).
- **Refresh tokens**: rotation with chain revocation — `replaced_by_hash` links the chain; replay of a rotated token revokes the whole chain.
- **Browser sessions (SSO)**: `auth_session` table from `@platform/auth`, opaque token in `id_session` cookie, 30d sliding. `session_meta` adds `amr` + `auth_time`; `sessionMiddleware` puts `CurrentSession | null` in `c.get('session')`.
- **MFA**: opt-in TOTP + recovery codes; `mfa_challenges` holds the interim state between first factor and TOTP.
- **Passkeys**: webauthn (`passkeys`, `webauthn_challenges`).
- **Social login**: google/github upstream, credential-gated (a button appears only if its env pair is set); round-trip state persisted in `login_states`.

## Key commands

```bash
pnpm dev                       # tsx watch src/index.ts
pnpm build                     # tsup → dist/ + copy migrations to dist/db
pnpm start                     # node dist/index.js
pnpm db:generate               # drizzle migrations after schema changes
pnpm typecheck / pnpm test
docker compose up --build -d   # containerized deployment
```

## Environment variables

See `.env.example`. `ISSUER_URL` is mandatory in prod (the `iss` of every token). `DATABASE_PATH` defaults to `./data/oauth.db` (`/app/data/oauth.db` in docker). SMTP optional: without it, verification/reset links are logged to console. Social provider credentials optional.

## v1 decisions

- All clients are first-party → no consent screen.
- Local MFA does not apply to federated (social) login.
- Open registration; first user = admin.

## Deployment

Docker: host port 3006 → container 3000, named volume `oauth-data` at `/app/data`; tls terminated by the host's nginx-proxy → `https://id.mier.info`. Image must stay glibc (`node:22-slim`): `@node-rs/argon2` and `better-sqlite3` ship linux-x64-gnu binaries — no alpine.

## Code style

- Comments lowercase, natural Spanish (technical words in English ok). User-facing text in Spanish with proper diacritics.
- Constants over magic numbers (`src/constants.ts`).
- ESM relative imports end in `.js`; drizzle better-sqlite3 sync API (no await on db calls).
- Routers are factory functions returning `Hono<AppEnv>`.
- Minimalism and performance first; no wrapper functions; prefer logical/lambda style over loops.
