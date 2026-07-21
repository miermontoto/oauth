// boot: env → db (migraciones al abrir) → clave de firma → http + limpiezas periódicas
import { loadAppEnv, startApiServer } from '@platform/core-api';

loadAppEnv(import.meta.url, { levelsUp: 1 });

const { getConfig } = await import('./config.js');
const { getDb, closeDb } = await import('./db/index.js');
const { ensureSigningKey } = await import('./services/keys.js');
const { cleanupExpiredSessions } = await import('./services/session.js');
const { cleanupExpiredTokens } = await import('./services/tokens.js');
const { createApp } = await import('./app.js');
const { SESSION_CLEANUP_INTERVAL_MS, SERVICE_NAME, VERSION } = await import('./constants.js');

const config = getConfig();
getDb(); // abre la db y aplica migraciones
await ensureSigningKey();

cleanupExpiredSessions();
cleanupExpiredTokens();
const cleanupTimer = setInterval(() => {
  cleanupExpiredSessions();
  cleanupExpiredTokens();
}, SESSION_CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

startApiServer(createApp(), {
  name: SERVICE_NAME,
  version: VERSION,
  port: config.PORT,
  afterClose: () => closeDb(),
});
