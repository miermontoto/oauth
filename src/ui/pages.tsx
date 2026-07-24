// páginas del idp: solo presentación, sin estado ni acceso a db/servicios
import type { FC } from 'hono/jsx';
import type { HtmlEscapedString } from 'hono/utils/html';
import type { SessionInfo } from '@platform/auth';
import type { PublicUser } from '../types.js';
import { Layout } from './layout.js';

// fc con retorno garantizado (sin la rama null) para que c.html(Page({...})) tipe bien en los routers
type PageFC<P> = ((props: P) => HtmlEscapedString | Promise<HtmlEscapedString>) & FC<P>;

// longitud mínima de contraseña exigida en los forms (validación final en el router)
const PASSWORD_MIN_LENGTH = 8;

// tamaño de grupo al mostrar el secreto totp
const TOTP_SECRET_GROUP = 4;

// formateador único de fechas para tablas (SessionInfo trae epoch ms, el resto Date)
const dateFmt = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' });
const fmtDate = (d: Date | number): string => dateFmt.format(d);

// script del cliente webauthn, compartido por login y cuenta
const PasskeyScript: FC = () => <script src="/passkey/client.js"></script>;

// marcas monocromas (fill=currentColor → heredan el tema y se invierten al hover).
// para un proveedor sin marca conocida se cae a la inicial de su nombre.
const PROVIDER_PATHS: Record<string, string[]> = {
  github: [
    'M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58 0-.29-.01-1.05-.02-2.06-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.96 0-1.32.47-2.39 1.24-3.23-.12-.3-.54-1.53.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 016 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.23 0 4.63-2.81 5.65-5.49 5.95.43.37.81 1.1.81 2.22 0 1.61-.01 2.9-.01 3.3 0 .32.22.7.83.58A12.01 12.01 0 0024 12.5C24 5.87 18.63.5 12 .5z',
  ],
  google: [
    'M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z',
    'M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z',
    'M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z',
    'M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z',
  ],
};

const ProviderIcon: FC<{ id: string; name: string }> = ({ id, name }) => {
  const paths = PROVIDER_PATHS[id];
  if (!paths) return <span class="social-letter">{name.charAt(0).toUpperCase()}</span>;
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true">
      {paths.map((d) => (
        <path d={d} />
      ))}
    </svg>
  );
};

export const LoginPage: PageFC<{
  providers: { id: string; name: string }[];
  returnTo: string | null;
  error?: string;
  email?: string;
}> = ({ providers, returnTo, error, email }) => (
  <Layout title="Iniciar sesión">
    <h1>Iniciar sesión</h1>
    {error && <p class="error">{error}</p>}
    <form method="post" action="/login">
      {returnTo && <input type="hidden" name="return_to" value={returnTo} />}
      <label for="email">Correo electrónico</label>
      {/* autocomplete "... webauthn": el navegador ofrece las passkeys en el propio campo */}
      <input id="email" type="email" name="email" value={email ?? ''} required autofocus autocomplete="username webauthn" />
      <label for="password">Contraseña</label>
      <input id="password" type="password" name="password" required autocomplete="current-password webauthn" />
      <button type="submit">Entrar</button>
    </form>
    {providers.length > 0 && (
      <div class="social">
        <div class="social-sep">
          <span>o continúa con</span>
        </div>
        <div class="social-icons">
          {providers.map((p) => (
            <a
              class="social-btn"
              href={`/login/${p.id}${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`}
              aria-label={`Continuar con ${p.name}`}
              title={p.name}
            >
              <ProviderIcon id={p.id} name={p.name} />
            </a>
          ))}
        </div>
      </div>
    )}
    <p class="links">
      <a href="/forgot">¿Has olvidado tu contraseña?</a>
      <a href="/signup">Crear cuenta</a>
    </p>
    <PasskeyScript />
    {/* arranca el autofill de passkeys al cargar: no hace falta pulsar ningún botón */}
    <script
      dangerouslySetInnerHTML={{
        __html: `window.passkeyConditional&&window.passkeyConditional(${JSON.stringify(returnTo)});`,
      }}
    />
  </Layout>
);

// hub de servicios: la landing de id.mier.info cuando hay sesión. lista las apps
// registradas como clientes oauth; al ser sso, entrar en cualquiera es silencioso.
export const HubPage: PageFC<{
  user: PublicUser;
  services: { name: string; url: string; host: string }[];
}> = ({ user, services }) => (
  <Layout
    title="Inicio"
    wide
    actions={
      <>
        <span class="muted small">{user.email}</span>
        <a class="btn secondary sm" href="/account">
          Mi cuenta
        </a>
        <form class="inline" method="post" action="/logout">
          <button class="secondary sm">Salir</button>
        </form>
      </>
    }
  >
    <h1>Tus servicios</h1>
    {services.length === 0 ? (
      <p class="muted">Aún no hay servicios registrados. Añade clientes OAuth desde el panel de administración.</p>
    ) : (
      <div class="hub">
        {services.map((s) => (
          <a class="hub-card" href={s.url}>
            <span class="hub-badge">{s.name.charAt(0)}</span>
            <span class="hub-body">
              <span class="hub-name">{s.name}</span>
              <span class="hub-host">{s.host}</span>
            </span>
          </a>
        ))}
      </div>
    )}
  </Layout>
);

export const SignupPage: PageFC<{
  returnTo: string | null;
  error?: string;
  values?: { name?: string; email?: string };
}> = ({ returnTo, error, values }) => (
  <Layout title="Crear cuenta">
    <h1>Crear cuenta</h1>
    {error && <p class="error">{error}</p>}
    <form method="post" action="/signup">
      {returnTo && <input type="hidden" name="return_to" value={returnTo} />}
      <label for="name">Nombre</label>
      <input id="name" type="text" name="name" value={values?.name ?? ''} required autofocus />
      <label for="email">Correo electrónico</label>
      <input id="email" type="email" name="email" value={values?.email ?? ''} required autocomplete="username" />
      <label for="password">Contraseña</label>
      <input
        id="password"
        type="password"
        name="password"
        required
        minlength={PASSWORD_MIN_LENGTH}
        autocomplete="new-password"
      />
      <p class="muted small">Mínimo {PASSWORD_MIN_LENGTH} caracteres.</p>
      <button type="submit">Crear cuenta</button>
    </form>
    <p class="links">
      <a href="/login">¿Ya tienes cuenta? Inicia sesión</a>
    </p>
  </Layout>
);

export const MfaPage: PageFC<{ challengeId: string; error?: string }> = ({ challengeId, error }) => (
  <Layout title="Verificación en dos pasos">
    <h1>Verificación en dos pasos</h1>
    <p class="muted small">Introduce el código de tu aplicación de autenticación o uno de tus códigos de recuperación.</p>
    {error && <p class="error">{error}</p>}
    <form method="post" action="/mfa">
      <input type="hidden" name="challenge" value={challengeId} />
      <label for="code">Código</label>
      <input id="code" type="text" name="code" required autofocus autocomplete="one-time-code" inputmode="numeric" />
      <button type="submit">Verificar</button>
    </form>
  </Layout>
);

export const ForgotPage: PageFC<{ sent: boolean }> = ({ sent }) => (
  <Layout title="Recuperar contraseña">
    {sent ? (
      <>
        <h1>Revisa tu correo</h1>
        <p class="small">Si la dirección existe, te hemos enviado un enlace para restablecer tu contraseña.</p>
      </>
    ) : (
      <>
        <h1>Recuperar contraseña</h1>
        <form method="post" action="/forgot">
          <label for="email">Correo electrónico</label>
          <input id="email" type="email" name="email" required autofocus autocomplete="username" />
          <button type="submit">Enviar enlace</button>
        </form>
      </>
    )}
    <p class="links">
      <a href="/login">Volver a iniciar sesión</a>
    </p>
  </Layout>
);

export const ResetPage: PageFC<{ token: string; error?: string }> = ({ token, error }) => (
  <Layout title="Restablecer contraseña">
    <h1>Restablecer contraseña</h1>
    {error && <p class="error">{error}</p>}
    <form method="post" action="/reset">
      <input type="hidden" name="token" value={token} />
      <label for="password">Nueva contraseña</label>
      <input
        id="password"
        type="password"
        name="password"
        required
        minlength={PASSWORD_MIN_LENGTH}
        autofocus
        autocomplete="new-password"
      />
      <p class="muted small">Mínimo {PASSWORD_MIN_LENGTH} caracteres.</p>
      <button type="submit">Guardar contraseña</button>
    </form>
  </Layout>
);

export const MessagePage: PageFC<{ title: string; message: string; linkHref?: string; linkText?: string }> = ({
  title,
  message,
  linkHref,
  linkText,
}) => (
  <Layout title={title}>
    <h1>{title}</h1>
    <p>{message}</p>
    {linkHref && (
      <p class="links">
        <a href={linkHref}>{linkText ?? 'Continuar'}</a>
      </p>
    )}
  </Layout>
);

export const AccountPage: PageFC<{
  user: PublicUser;
  sessions: SessionInfo[];
  passkeys: { id: string; name: string; createdAt: Date; lastUsedAt: Date | null }[];
  identities: { provider: string; email: string | null }[];
  providers: { id: string; name: string }[];
  totpEnabled: boolean;
  flash?: string | null;
  error?: string | null;
}> = ({ user, sessions, passkeys, identities, providers, totpEnabled, flash, error }) => {
  const linked = new Set(identities.map((i) => i.provider));
  const unlinked = providers.filter((p) => !linked.has(p.id));
  // nombre legible del proveedor (los identities solo guardan el id)
  const providerName = (id: string): string => providers.find((p) => p.id === id)?.name ?? id;
  return (
    <Layout title="Mi cuenta" wide>
      <div class="topbar">
        <h1>Mi cuenta</h1>
        <div class="row">
          {user.isAdmin && (
            <a class="btn secondary sm" href="/admin">
              Administración
            </a>
          )}
          <form method="post" action="/logout">
            <button class="secondary sm">Cerrar sesión</button>
          </form>
        </div>
      </div>
      {error && <p class="error">{error}</p>}
      {flash && <p class="flash">{flash}</p>}

      <section class="panel">
        <h2>Perfil</h2>
        <p class="small">{user.email}</p>
        <form method="post" action="/account/profile">
          <label for="profile-name">Nombre</label>
          <input id="profile-name" type="text" name="name" value={user.name} required />
          <button class="sm">Guardar</button>
        </form>
      </section>

      <section class="panel">
        <h2>Contraseña</h2>
        <form method="post" action="/account/password">
          {user.hasPassword && (
            <>
              <label for="current-password">Contraseña actual</label>
              <input id="current-password" type="password" name="current" required autocomplete="current-password" />
            </>
          )}
          <label for="new-password">Nueva contraseña</label>
          <input
            id="new-password"
            type="password"
            name="password"
            required
            minlength={PASSWORD_MIN_LENGTH}
            autocomplete="new-password"
          />
          <button class="sm">{user.hasPassword ? 'Cambiar contraseña' : 'Establecer contraseña'}</button>
        </form>
      </section>

      <section class="panel">
        <h2>Passkeys</h2>
        {passkeys.length === 0 ? (
          <p class="muted small">No tienes ninguna passkey registrada.</p>
        ) : (
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nombre</th>
                  <th>Creada</th>
                  <th>Último uso</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {passkeys.map((pk) => (
                  <tr>
                    <td>
                      <form class="inline row" method="post" action="/account/passkeys/rename">
                        <input type="hidden" name="id" value={pk.id} />
                        <input class="compact" type="text" name="name" value={pk.name} required />
                        <button class="secondary sm">Renombrar</button>
                      </form>
                    </td>
                    <td>{fmtDate(pk.createdAt)}</td>
                    <td>{pk.lastUsedAt ? fmtDate(pk.lastUsedAt) : 'nunca'}</td>
                    <td>
                      <form class="inline" method="post" action="/account/passkeys/delete">
                        <input type="hidden" name="id" value={pk.id} />
                        <button class="danger sm">Borrar</button>
                      </form>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <button type="button" class="secondary sm" onclick="window.passkeyRegister()">
          Añadir passkey
        </button>
      </section>

      <section class="panel">
        <h2>Verificación en dos pasos</h2>
        {totpEnabled ? (
          <form method="post" action="/account/totp/disable">
            <p class="small">
              <span class="badge ok">activada</span>
            </p>
            <label for="totp-code">Código para desactivar</label>
            <input
              id="totp-code"
              class="compact"
              type="text"
              name="code"
              required
              autocomplete="one-time-code"
              inputmode="numeric"
            />
            <button class="danger sm">Desactivar</button>
          </form>
        ) : (
          <p class="small">
            No activada. <a href="/account/totp/setup">Configurar TOTP</a>
          </p>
        )}
      </section>

      <section class="panel">
        <h2>Cuentas vinculadas</h2>
        {identities.length === 0 && <p class="muted small">Ninguna cuenta vinculada.</p>}
        {identities.map((i) => (
          <p class="row small">
            <ProviderIcon id={i.provider} name={i.provider} />
            <strong>{providerName(i.provider)}</strong>
            <span class="muted">{i.email ?? 'sin email'}</span>
            <form class="inline" method="post" action="/account/identities/unlink">
              <input type="hidden" name="provider" value={i.provider} />
              <button class="danger sm">Desvincular</button>
            </form>
          </p>
        ))}
        {unlinked.length > 0 && (
          <>
            <p class="muted small">Vincular otra cuenta</p>
            <div class="social-icons start">
              {unlinked.map((p) => (
                <a
                  class="social-btn"
                  href={`/login/${p.id}?link=1`}
                  aria-label={`Vincular ${p.name}`}
                  title={`Vincular ${p.name}`}
                >
                  <ProviderIcon id={p.id} name={p.name} />
                </a>
              ))}
            </div>
          </>
        )}
      </section>

      <section class="panel">
        <h2>Sesiones</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Dispositivo</th>
                <th>Iniciada</th>
                <th>Expira</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr>
                  <td>{s.userAgent ?? 'desconocido'}</td>
                  <td>{fmtDate(s.createdAt)}</td>
                  <td>{fmtDate(s.expiresAt)}</td>
                  <td>{s.current && <span class="badge">actual</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <form method="post" action="/account/sessions/logout-others">
          <button class="secondary sm">Cerrar las demás sesiones</button>
        </form>
      </section>
      <PasskeyScript />
    </Layout>
  );
};

export const TotpSetupPage: PageFC<{ secret: string; otpauthUrl: string; error?: string | null }> = ({
  secret,
  otpauthUrl,
  error,
}) => (
  <Layout title="Configurar TOTP">
    <h1>Configurar TOTP</h1>
    <p class="small">Añade esta clave a tu aplicación de autenticación:</p>
    <code class="secret">{secret.match(new RegExp(`.{1,${TOTP_SECRET_GROUP}}`, 'g'))?.join(' ') ?? secret}</code>
    <p class="small">
      <a href={otpauthUrl}>Abrir directamente en la aplicación</a> (desde el móvil)
    </p>
    {error && <p class="error">{error}</p>}
    <form method="post" action="/account/totp/confirm">
      <label for="code">Código de verificación</label>
      <input id="code" type="text" name="code" required autofocus autocomplete="one-time-code" inputmode="numeric" />
      <button type="submit">Confirmar</button>
    </form>
    <p class="links">
      <a href="/account">Volver a mi cuenta</a>
    </p>
  </Layout>
);

export const TotpRecoveryCodesPage: PageFC<{ codes: string[] }> = ({ codes }) => (
  <Layout title="Códigos de recuperación">
    <h1>Códigos de recuperación</h1>
    <p class="small">
      Guarda estos códigos en un lugar seguro. Cada uno solo puede usarse una vez y no volverán a mostrarse.
    </p>
    <ul class="codes">
      {codes.map((code) => (
        <li>{code}</li>
      ))}
    </ul>
    <p class="links">
      <a href="/account">Volver a mi cuenta</a>
    </p>
  </Layout>
);

export const AdminPage: PageFC<{
  users: { id: string; email: string; name: string; isAdmin: boolean; isActive: boolean; createdAt: Date }[];
  clients: { id: string; name: string; redirectUris: string[]; isPublic: boolean }[];
  currentUserId?: string;
  flash?: string | null;
  error?: string | null;
}> = ({ users, clients, currentUserId, flash, error }) => (
  <Layout title="Administración" wide>
    <div class="topbar">
      <h1>Administración</h1>
      <a class="btn secondary sm" href="/account">
        Mi cuenta
      </a>
    </div>
    {error && <p class="error">{error}</p>}
    {flash && <p class="flash">{flash}</p>}

    <section class="panel">
      <h2>Usuarios</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Nombre</th>
              <th>Rol</th>
              <th>Estado</th>
              <th>Creado</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr>
                <td>{u.email}</td>
                <td>{u.name}</td>
                <td>{u.isAdmin && <span class="badge">admin</span>}</td>
                <td>{u.isActive ? <span class="badge ok">activo</span> : <span class="badge warn">inactivo</span>}</td>
                <td>{fmtDate(u.createdAt)}</td>
                <td>
                  {u.id === currentUserId ? (
                    <span class="muted small">tú</span>
                  ) : (
                    <div class="row">
                      <form class="inline" method="post" action={`/admin/users/${u.id}/toggle-active`}>
                        <button class="secondary sm">{u.isActive ? 'Desactivar' : 'Activar'}</button>
                      </form>
                      <form
                        class="inline"
                        method="post"
                        action={`/admin/users/${u.id}/delete`}
                        onsubmit="return confirm('¿Borrar este usuario? Esta acción no se puede deshacer.')"
                      >
                        <button class="danger sm">Borrar</button>
                      </form>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2>Clientes OAuth</h2>
      {clients.length === 0 ? (
        <p class="muted small">Ningún cliente registrado.</p>
      ) : (
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>client_id</th>
                <th>Nombre</th>
                <th>Redirect URIs</th>
                <th>Tipo</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {clients.map((cl) => (
                <tr>
                  <td>
                    <code>{cl.id}</code>
                  </td>
                  <td>{cl.name}</td>
                  <td>{cl.redirectUris.join(', ')}</td>
                  <td>{cl.isPublic ? <span class="badge">público</span> : <span class="badge ok">confidencial</span>}</td>
                  <td>
                    <form
                      class="inline"
                      method="post"
                      action={`/admin/clients/${cl.id}/delete`}
                      onsubmit="return confirm('¿Borrar este cliente? Sus tokens dejarán de funcionar.')"
                    >
                      <button class="danger sm">Borrar</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h3>Nuevo cliente</h3>
      <form method="post" action="/admin/clients">
        <label for="client-name">Nombre</label>
        <input id="client-name" type="text" name="name" required />
        <label for="client-uris">Redirect URIs (una por línea)</label>
        <textarea id="client-uris" name="redirect_uris" rows={3} required></textarea>
        <label for="client-logout-uris">Post-logout redirect URIs (opcional, una por línea)</label>
        <textarea id="client-logout-uris" name="post_logout_redirect_uris" rows={2}></textarea>
        <label class="check">
          <input type="checkbox" name="public" /> Cliente público (sin secreto, PKCE obligatorio)
        </label>
        <button class="sm">Crear cliente</button>
      </form>
    </section>
  </Layout>
);

export const ClientCreatedPage: PageFC<{ client: { id: string; name: string }; secret: string | null }> = ({
  client,
  secret,
}) => (
  <Layout title="Cliente creado">
    <h1>Cliente «{client.name}» creado</h1>
    <label>client_id</label>
    <p>
      <code>{client.id}</code>
    </p>
    {secret ? (
      <>
        <label>client_secret</label>
        <p>
          <code>{secret}</code>
        </p>
        <p class="error">Guarda el secreto ahora: solo se muestra una vez.</p>
      </>
    ) : (
      <p class="muted small">Cliente público: sin secreto, requiere PKCE.</p>
    )}
    <p class="links">
      <a href="/admin">Volver a administración</a>
    </p>
  </Layout>
);

export const ErrorPage: PageFC<{ status: number; message: string }> = ({ status, message }) => (
  <Layout title={`Error ${status}`}>
    <h1>Error {status}</h1>
    <p>{message}</p>
    <p class="links">
      <a href="/">Volver al inicio</a>
    </p>
  </Layout>
);
