// contratos compartidos entre servicios y rutas
export interface PublicUser {
  id: string;
  email: string;
  emailVerified: boolean;
  name: string;
  picture: string | null;
  isAdmin: boolean;
  // true si el usuario tiene contraseña (las cuentas solo-social/passkey no)
  hasPassword: boolean;
}

// métodos de autenticación según rfc 8176
export type AmrValue = 'pwd' | 'otp' | 'swk' | 'mfa';

// sesión hidratada en el contexto de hono
export interface CurrentSession {
  token: string;
  user: PublicUser;
  amr: string[];
  authTime: number; // epoch ms
  expiresAt: number; // epoch ms
}

export type AppEnv = {
  Variables: {
    session: CurrentSession | null;
  };
};

// perfil normalizado que devuelve cualquier proveedor upstream
export interface UpstreamProfile {
  provider: string;
  providerAccountId: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  picture: string | null;
}
