// ip del cliente para rate limiting. detrás de un único proxy de confianza (nginx
// con proxy_add_x_forwarded_for) el ÚLTIMO salto de x-forwarded-for es el que
// añade el proxy con la ip real del peer; el primero lo controla el cliente y es
// falsificable, así que NUNCA se usa split(',')[0]. se prefiere x-real-ip, que el
// proxy fija y el cliente no puede forjar.
import type { Context } from 'hono';

export function clientIp(c: Context): string {
  const realIp = c.req.header('x-real-ip')?.trim();
  if (realIp) return realIp;
  const xff = c.req.header('x-forwarded-for');
  if (xff) {
    const hops = xff.split(',').map((h) => h.trim()).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }
  return 'local';
}
