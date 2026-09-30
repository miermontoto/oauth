// configuración por entorno, validada una vez al boot
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(3000),
  // url pública del emisor (iss de los tokens); en prod https://id.mier.info
  ISSUER_URL: z.string().url().default('http://localhost:3000'),
  // emails admin (coma-separados). si se define, SOLO estos son admin; si no,
  // el primer usuario registrado es admin (comodidad en dev, riesgo en prod)
  ADMIN_EMAILS: z.string().optional(),
  // smtp opcional (smtps://user:pass@host:465); sin configurar, los enlaces se loguean por consola
  SMTP_URL: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  // proveedores sociales upstream; un botón solo aparece si su par de credenciales existe
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  // apple: services id (client_id), team id, key id y pem de la clave .p8 que firma el
  // client_secret. el pem admite \n escapados para caber en una línea del .env
  APPLE_CLIENT_ID: z.string().optional(),
  APPLE_TEAM_ID: z.string().optional(),
  APPLE_KEY_ID: z.string().optional(),
  APPLE_PRIVATE_KEY: z
    .string()
    .optional()
    .transform((v) => v?.replace(/\\n/g, '\n')),
});

export type Config = z.infer<typeof envSchema> & { isProd: boolean; adminEmails: string[] };

let cached: Config | null = null;

export function getConfig(): Config {
  if (!cached) {
    const parsed = envSchema.parse(process.env);
    const adminEmails = (parsed.ADMIN_EMAILS ?? '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);
    cached = { ...parsed, isProd: parsed.NODE_ENV === 'production', adminEmails };
  }
  return cached;
}
