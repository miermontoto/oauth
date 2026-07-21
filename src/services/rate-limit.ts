// rate limit in-memory con ventana deslizante por clave (proceso único, sin
// persistencia: un restart resetea los contadores, aceptable para este idp).
export interface RateLimit {
  max: number;
  windowMs: number;
}

export const LOGIN_LIMIT: RateLimit = { max: 10, windowMs: 15 * 60_000 };
export const SIGNUP_LIMIT: RateLimit = { max: 5, windowMs: 60 * 60_000 };
export const MFA_LIMIT: RateLimit = { max: 10, windowMs: 15 * 60_000 };
export const FORGOT_LIMIT: RateLimit = { max: 5, windowMs: 60 * 60_000 };

interface Entry {
  hits: number[]; // timestamps de intentos dentro de la ventana
  windowMs: number; // ventana con la que se usó por última vez (para la limpieza)
}

const entries = new Map<string, Entry>();

// limpieza perezosa: cada CLEANUP_EVERY llamadas se purgan las claves sin hits vigentes
const CLEANUP_EVERY = 500;
let callsSinceCleanup = 0;

function lazyCleanup(now: number): void {
  if (++callsSinceCleanup < CLEANUP_EVERY) return;
  callsSinceCleanup = 0;
  entries.forEach((entry, key) => {
    if (entry.hits.every((t) => t <= now - entry.windowMs)) entries.delete(key);
  });
}

/** consume un intento de `key`. false ⇒ límite superado, el caller debe rechazar. */
export function checkRateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  lazyCleanup(now);
  const entry = entries.get(key) ?? { hits: [], windowMs };
  entry.hits = entry.hits.filter((t) => t > now - windowMs);
  entry.windowMs = windowMs;
  if (entry.hits.length >= max) {
    entries.set(key, entry);
    return false;
  }
  entry.hits.push(now);
  entries.set(key, entry);
  return true;
}
