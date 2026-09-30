// constantes del servicio: identidad, cookies y ttls
export const SERVICE_NAME = 'mier.info';
export const VERSION = '0.1.0';

export const SESSION_COOKIE_NAME = 'id_session';
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 días, sliding
export const SESSION_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000;

// oauth/oidc
export const AUTH_CODE_TTL_MS = 60 * 1000;
export const ACCESS_TOKEN_TTL_S = 60 * 60; // jwt de 1 hora
export const ID_TOKEN_TTL_S = 60 * 60;
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

// flujos auxiliares
export const EMAIL_VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
export const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000;
export const LOGIN_STATE_TTL_MS = 10 * 60 * 1000;
// jwt client_secret de apple: se firma por exchange, basta con que viva unos minutos
export const APPLE_CLIENT_SECRET_TTL_S = 5 * 60;
export const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const MFA_CHALLENGE_MAX_ATTEMPTS = 5;
// periodo totp (rfc 6238): lo usan el verificador y la cuenta atrás del paso mfa
export const TOTP_PERIOD_S = 30;

// ruta de authorize tal y como llega en el return_to del login
export const AUTHORIZE_PATH = '/oidc/authorize';
