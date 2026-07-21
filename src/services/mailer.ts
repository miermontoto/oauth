// tokens de email (verificación / reset) y envío por smtp. los tokens se guardan
// hasheados (sha-256) y son de un solo uso; sin SMTP_URL los enlaces se loguean.
import { createHash, randomBytes } from 'node:crypto';
import nodemailer, { type Transporter } from 'nodemailer';
import { and, eq, isNull, gt } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { emailTokens } from '../db/schema.js';
import { getConfig } from '../config.js';
import { EMAIL_VERIFY_TTL_MS, PASSWORD_RESET_TTL_MS, SERVICE_NAME } from '../constants.js';

export type EmailTokenKind = 'verify' | 'reset';

const TOKEN_BYTES = 32;
const TTL_BY_KIND: Record<EmailTokenKind, number> = {
  verify: EMAIL_VERIFY_TTL_MS,
  reset: PASSWORD_RESET_TTL_MS,
};
const DEFAULT_FROM = `"${SERVICE_NAME}" <no-reply@mier.info>`;

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

// emite un token nuevo para el usuario invalidando (borrando) los previos del mismo tipo
export function issueEmailToken(userId: string, kind: EmailTokenKind): string {
  const token = randomBytes(TOKEN_BYTES).toString('base64url');
  const db = getDb();
  db.delete(emailTokens).where(and(eq(emailTokens.userId, userId), eq(emailTokens.kind, kind))).run();
  db.insert(emailTokens)
    .values({ tokenHash: sha256(token), userId, kind, expiresAt: new Date(Date.now() + TTL_BY_KIND[kind]) })
    .run();
  return token;
}

// consume un token (single use): devuelve el userId o null si no existe, expiró o ya se usó
export function consumeEmailToken(token: string, kind: EmailTokenKind): string | null {
  const tokenHash = sha256(token);
  const row = getDb()
    .select()
    .from(emailTokens)
    .where(
      and(
        eq(emailTokens.tokenHash, tokenHash),
        eq(emailTokens.kind, kind),
        isNull(emailTokens.usedAt),
        gt(emailTokens.expiresAt, new Date()),
      ),
    )
    .get();
  if (!row) return null;
  getDb().update(emailTokens).set({ usedAt: new Date() }).where(eq(emailTokens.tokenHash, tokenHash)).run();
  return row.userId;
}

// ---------- envío ----------

let transporter: Transporter | null | undefined;

// transporter perezoso: null si no hay SMTP_URL configurada (modo consola)
function getTransporter(): Transporter | null {
  if (transporter === undefined) {
    const { SMTP_URL } = getConfig();
    transporter = SMTP_URL ? nodemailer.createTransport(SMTP_URL) : null;
  }
  return transporter;
}

// envía un email o loguea el enlace si no hay smtp; un fallo de smtp no revienta
// el flujo que lo llamó (registro/reset siguen adelante), solo se loguea
async function sendMail(to: string, subject: string, text: string, link: string): Promise<void> {
  const smtp = getTransporter();
  if (!smtp) {
    console.log(`[mailer] smtp sin configurar; enlace para ${to}: ${link}`);
    return;
  }
  try {
    await smtp.sendMail({ from: getConfig().SMTP_FROM ?? DEFAULT_FROM, to, subject, text });
  } catch (err) {
    console.error(`[mailer] fallo enviando "${subject}" a ${to}:`, err);
  }
}

export async function sendVerificationEmail(to: string, name: string, token: string): Promise<void> {
  const link = `${getConfig().ISSUER_URL}/verify-email?token=${token}`;
  const text = [
    `Hola ${name},`,
    '',
    `Confirma tu dirección de correo en ${SERVICE_NAME} abriendo este enlace:`,
    link,
    '',
    'El enlace caduca en 24 horas. Si no creaste esta cuenta, ignora este mensaje.',
  ].join('\n');
  await sendMail(to, `Verifica tu email en ${SERVICE_NAME}`, text, link);
}

export async function sendPasswordResetEmail(to: string, name: string, token: string): Promise<void> {
  const link = `${getConfig().ISSUER_URL}/reset?token=${token}`;
  const text = [
    `Hola ${name},`,
    '',
    `Para restablecer tu contraseña de ${SERVICE_NAME} abre este enlace:`,
    link,
    '',
    'El enlace caduca en 1 hora. Si no pediste este cambio, ignora este mensaje.',
  ].join('\n');
  await sendMail(to, `Restablece tu contraseña de ${SERVICE_NAME}`, text, link);
}
