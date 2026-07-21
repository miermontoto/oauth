// totp (rfc 6238) sobre node:crypto, sin dependencias — portado de duckhunt.
// hmac-sha1, 6 dígitos, periodo de 30s, ventana ±1 y anti-replay por lastStep.
// los códigos de recuperación (10, formato xxxx-xxxx) se guardan como sha-256 hex.
import crypto from 'node:crypto';
import { and, eq, isNull } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { recoveryCodes, userTotp, users } from '../db/schema.js';
import { SERVICE_NAME } from '../constants.js';

// parámetros totp (rfc 6238) — compatibles con cualquier app autenticadora
const TOTP_ALGO = 'sha1';
const TOTP_DIGITS = 6;
const TOTP_PERIOD_S = 30;
const TOTP_WINDOW = 1; // pasos de tolerancia a cada lado (skew de reloj)
const TOTP_SECRET_BYTES = 20; // 160 bits

// códigos de recuperación: 10 códigos de 8 chars legibles (sin 0/1/i/l/o)
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_CHARS = 8;
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

// alfabeto base32 rfc 4648 (sin padding: el secreto totp se emite sin él)
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// codifica bytes a base32 sin padding (para el secreto del otpauth uri)
function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  // bits residuales (< 5): alinea a la izquierda y emite el último símbolo
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// decodifica base32 (tolerante: ignora espacios y padding, case-insensitive)
function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`base32 inválido: carácter '${ch}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// time-step actual (rfc 6238: floor(unix_seconds / period))
const currentStep = (): number => Math.floor(Date.now() / 1000 / TOTP_PERIOD_S);

// hotp (rfc 4226): hmac del contador de 8 bytes big-endian + truncación dinámica
function hotp(secretBytes: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  // counter < 2^53 (número seguro): parte alta y baja en dos words de 32 bit
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac(TOTP_ALGO, secretBytes).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const bin =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

// comparación tiempo-constante; longitudes distintas → false sin filtrar por timing
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// verifica un código dentro de la ventana; devuelve el time-step que casó
// (para persistirlo como anti-replay) o null. rechaza cualquier step <= after
function matchTotpStep(secret: string, code: string, after: number): number | null {
  const trimmed = code.replace(/\s/g, '');
  if (trimmed.length !== TOTP_DIGITS) return null;
  const center = currentStep();
  const secretBytes = base32Decode(secret);
  for (let step = center - TOTP_WINDOW; step <= center + TOTP_WINDOW; step++) {
    if (step <= after) continue;
    if (safeEqual(hotp(secretBytes, step), trimmed)) return step;
  }
  return null;
}

// normaliza un código de recuperación (minúsculas, sin separadores) para que el
// hash case aunque el usuario teclee con guiones/espacios/mayúsculas
const hashRecoveryCode = (code: string): string =>
  crypto
    .createHash('sha256')
    .update(code.toLowerCase().replace(/[^a-z0-9]/g, ''))
    .digest('hex');

// genera un código legible xxxx-xxxx a partir del alfabeto sin ambiguos
function generateRecoveryCode(): string {
  const chars = Array.from({ length: RECOVERY_CODE_CHARS }, () => RECOVERY_ALPHABET[crypto.randomInt(RECOVERY_ALPHABET.length)]).join('');
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

// inicia (o reinicia) la inscripción: secreto nuevo en estado pendiente (enabled=false).
// el login no exige el factor hasta confirmar con un código válido
export function startTotpSetup(userId: string): { secret: string; otpauthUrl: string } {
  const db = getDb();
  const user = db.select({ email: users.email }).from(users).where(eq(users.id, userId)).get();
  if (!user) throw new Error(`usuario ${userId} no encontrado para inscripción totp`);
  const secret = base32Encode(crypto.randomBytes(TOTP_SECRET_BYTES));
  db.insert(userTotp)
    .values({ userId, secret, enabled: false, lastStep: 0, createdAt: new Date(), confirmedAt: null })
    .onConflictDoUpdate({
      target: userTotp.userId,
      set: { secret, enabled: false, lastStep: 0, confirmedAt: null },
    })
    .run();
  const label = `${encodeURIComponent(SERVICE_NAME)}:${encodeURIComponent(user.email)}`;
  const params = new URLSearchParams({
    secret,
    issuer: SERVICE_NAME,
    algorithm: TOTP_ALGO.toUpperCase(),
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_S),
  });
  return { secret, otpauthUrl: `otpauth://totp/${label}?${params.toString()}` };
}

// confirma la inscripción: si el código es válido activa el factor y genera los
// códigos de recuperación (devueltos en claro UNA sola vez); null si no casa
export function confirmTotpSetup(userId: string, code: string): string[] | null {
  const db = getDb();
  const row = db.select().from(userTotp).where(eq(userTotp.userId, userId)).get();
  if (!row) return null;
  const step = matchTotpStep(row.secret, code, row.lastStep);
  if (step === null) return null;
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  db.transaction((tx) => {
    tx.update(userTotp)
      .set({ enabled: true, confirmedAt: new Date(), lastStep: step })
      .where(eq(userTotp.userId, userId))
      .run();
    tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId)).run();
    tx.insert(recoveryCodes)
      .values(codes.map((c) => ({ userId, codeHash: hashRecoveryCode(c), usedAt: null })))
      .run();
  });
  return codes;
}

// ¿tiene el usuario el segundo factor activo? lo consume el gate del login
export function hasTotpEnabled(userId: string): boolean {
  const row = getDb()
    .select({ userId: userTotp.userId })
    .from(userTotp)
    .where(and(eq(userTotp.userId, userId), eq(userTotp.enabled, true)))
    .get();
  return row !== undefined;
}

// verifica un código totp y persiste el step consumido (anti-replay)
export function verifyTotp(userId: string, code: string): boolean {
  const db = getDb();
  const row = db
    .select()
    .from(userTotp)
    .where(and(eq(userTotp.userId, userId), eq(userTotp.enabled, true)))
    .get();
  if (!row) return false;
  const step = matchTotpStep(row.secret, code, row.lastStep);
  if (step === null) return false;
  db.update(userTotp).set({ lastStep: step }).where(eq(userTotp.userId, userId)).run();
  return true;
}

// consume un código de recuperación: lo marca usado si casa con una fila sin usar.
// match por hash exacto (sha-256 determinista, alta entropía → timing irrelevante)
export function verifyRecoveryCode(userId: string, code: string): boolean {
  const res = getDb()
    .update(recoveryCodes)
    .set({ usedAt: new Date() })
    .where(
      and(
        eq(recoveryCodes.userId, userId),
        eq(recoveryCodes.codeHash, hashRecoveryCode(code)),
        isNull(recoveryCodes.usedAt),
      ),
    )
    .run();
  return res.changes === 1;
}

// apaga el factor: borra la fila totp y TODOS los códigos de recuperación en una
// transacción (no dejar códigos huérfanos que reactivarían un acceso al re-inscribir)
export function disableTotp(userId: string): void {
  getDb().transaction((tx) => {
    tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId)).run();
    tx.delete(userTotp).where(eq(userTotp.userId, userId)).run();
  });
}
