// composición de la app: middleware de sesión + routers
import { createPlatformApp } from '@platform/core-api';
import { sessionMiddleware } from './services/session.js';
import { oidcRoutes, wellKnownRoutes } from './routes/oidc.js';
import { loginRoutes } from './routes/login.js';
import { socialRoutes } from './routes/social.js';
import { passkeyRoutes } from './routes/passkey.js';
import { accountRoutes } from './routes/account.js';
import { adminRoutes } from './routes/admin.js';
import { VERSION } from './constants.js';
import type { AppEnv } from './types.js';
import type { Hono } from 'hono';

export function createApp(): Hono<AppEnv> {
  const app = createPlatformApp<AppEnv>();

  app.get('/health', (c) => c.json({ ok: true, version: VERSION }));

  app.use('*', sessionMiddleware);

  app.route('/.well-known', wellKnownRoutes());
  app.route('/oidc', oidcRoutes());
  app.route('/', loginRoutes());
  app.route('/', socialRoutes());
  app.route('/passkey', passkeyRoutes());
  app.route('/account', accountRoutes());
  app.route('/admin', adminRoutes());

  return app;
}
