// páginas del idp: solo presentación, sin estado ni acceso a db/servicios
import type { FC } from 'hono/jsx';
import type { HtmlEscapedString } from 'hono/utils/html';
import type { SessionInfo } from '@platform/auth';
import type { CurrentSession, PublicUser } from '../types.js';
import type { AuthorizeRequest } from '../services/clients.js';
import { AUTHORIZE_PATH, SESSION_TTL_MS, TOTP_PERIOD_S } from '../constants.js';
import { Layout } from './layout.js';
import { ServiceIcon } from './service-icon.js';

// fc con retorno garantizado (sin la rama null) para que c.html(Page({...})) tipe bien en los routers
type PageFC<P> = ((props: P) => HtmlEscapedString | Promise<HtmlEscapedString>) & FC<P>;

// longitud mínima de contraseña exigida en los forms (validación final en el router)
const PASSWORD_MIN_LENGTH = 8;

// tamaño de grupo al mostrar el secreto totp
const TOTP_SECRET_GROUP = 4;

// dígitos del código totp (campo de casillas del paso mfa y del alta)
const TOTP_DIGITS = 6;

// atajos de teclado del hub: 1-9 abren el servicio n-ésimo
const MAX_SHORTCUTS = 9;

const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_DAYS = Math.round(SESSION_TTL_MS / DAY_MS);

// radio con circunferencia 100: el stroke-dashoffset del anillo se expresa en porcentaje
const RING_RADIUS = 100 / (2 * Math.PI);

// formateador único de fechas para tablas (SessionInfo trae epoch ms, el resto Date)
const dateFmt = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' });
const fmtDate = (d: Date | number): string => dateFmt.format(d);
// solo fecha, para altas y activaciones
const dayFmt = new Intl.DateTimeFormat('es', { dateStyle: 'medium' });
const fmtDay = (d: Date | number): string => dayFmt.format(d);
// aaaa-mm-dd hh:mm, a juego con los claims del whoami
const isoFmt = new Intl.DateTimeFormat('sv-SE', { dateStyle: 'short', timeStyle: 'short' });

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

// resumen legible de un user-agent ("Firefox · Linux"). el orden importa: edge y opera se
// anuncian también como chrome, chrome como safari, e ios/android como mac os/linux
const UA_BROWSERS: [RegExp, string][] = [
  [/Edg\//, 'Edge'],
  [/OPR\//, 'Opera'],
  [/Firefox\//, 'Firefox'],
  [/Chrome\//, 'Chrome'],
  [/Safari\//, 'Safari'],
];
const UA_SYSTEMS: [RegExp, string][] = [
  [/iPhone|iPad/, 'iOS'],
  [/Android/, 'Android'],
  [/Mac OS X/, 'macOS'],
  [/Windows/, 'Windows'],
  [/CrOS/, 'ChromeOS'],
  [/Linux/, 'Linux'],
];
const MOBILE_UA_RE = /Mobile|iPhone|Android/;
const describeUa = (ua: string | null): string => {
  if (!ua) return 'Dispositivo desconocido';
  const parts = [UA_BROWSERS, UA_SYSTEMS].map((list) => list.find(([re]) => re.test(ua))?.[1]).filter(Boolean);
  return parts.length ? parts.join(' · ') : ua;
};

// script del cliente webauthn, compartido por login y cuenta
const PasskeyScript: FC = () => <script src="/passkey/client.js"></script>;

// botón de passkey + autofill al cargar. el return_to viaja en un data-attribute (escapado
// por jsx) y nunca se interpola en el script: un return_to con "</script>" no inyecta código
const PASSKEY_LOGIN_JS =
  "(function(){var b=document.getElementById('passkey-btn'),e=document.getElementById('passkey-error'),rt=b.dataset.returnTo||null;" +
  'window.passkeyConditional&&window.passkeyConditional(rt);' +
  "b.addEventListener('click',function(){e.hidden=true;window.passkeyLogin(rt,function(m){e.textContent=m;e.hidden=false})})})();";

// atajos del hub: una tecla 1-9 fuera de un campo de texto abre ese servicio
const SHORTCUTS_JS =
  "document.addEventListener('keydown',function(e){if(e.metaKey||e.ctrlKey||e.altKey||!/^[1-9]$/.test(e.key)||/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName))return;" +
  "var a=document.querySelector('a[data-key=\"'+e.key+'\"]');if(a)location.assign(a.href)});";

// cuenta atrás de la ventana totp: el periodo va alineado con epoch (rfc 6238), así que el
// navegador sabe cuándo cambia el código sin preguntar al servidor
const TOTP_COUNTDOWN_JS =
  `(function(){var p=${TOTP_PERIOD_S},s=document.getElementById('totp-left'),r=document.getElementById('totp-ring');` +
  'function t(){var l=p-Math.floor(Date.now()/1000)%p;s.textContent=l;r.style.strokeDashoffset=100-l/p*100}t();setInterval(t,1000)})();';

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
  apple: [
    'M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701',
  ],
};

const ProviderIcon: FC<{ id: string; name: string }> = ({ id, name }) => {
  const paths = PROVIDER_PATHS[id];
  if (!paths) return <span>{name.charAt(0).toUpperCase()}</span>;
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
      {paths.map((d) => (
        <path d={d} />
      ))}
    </svg>
  );
};

// iconos de trazo (currentColor) para dispositivos y acciones
const STROKE_ICONS = {
  key: 'M10.7 12.3 20 3M16 7l3 3M18 5l2 2M12 15.5a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0z',
  laptop: 'M5 5h14a1 1 0 0 1 1 1v10H4V6a1 1 0 0 1 1-1zM2 19h20',
  phone: 'M8 2.5h8a1 1 0 0 1 1 1v17a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1v-17a1 1 0 0 1 1-1zM11 18.5h2',
  arrow: 'M5 12h14M13 6l6 6-6 6',
} as const;

const Icon: FC<{ name: keyof typeof STROKE_ICONS; class?: string }> = ({ name, class: cls }) => (
  <svg
    viewBox="0 0 24 24"
    width="18"
    height="18"
    fill="none"
    stroke="currentColor"
    stroke-width="1.6"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    class={cls}
  >
    <path d={STROKE_ICONS[name]} />
  </svg>
);

// campo único de 6 dígitos con aspecto de casillas (css); se envía solo al completarse
const OtpInput: FC<{ id: string }> = ({ id }) => (
  <input
    id={id}
    class="otp"
    type="text"
    name="code"
    required
    autofocus
    inputmode="numeric"
    autocomplete="one-time-code"
    maxlength={TOTP_DIGITS}
    pattern={`\\d{${TOTP_DIGITS}}`}
    placeholder={'0'.repeat(TOTP_DIGITS)}
    oninput={`this.value.length===${TOTP_DIGITS}&&this.form.requestSubmit()`}
  />
);

const TotpCountdown: FC = () => (
  <p class="tick">
    <svg class="ring" viewBox="0 0 36 36" aria-hidden="true">
      <circle class="bg" cx="18" cy="18" r={RING_RADIUS} />
      <circle class="fg" id="totp-ring" cx="18" cy="18" r={RING_RADIUS} />
    </svg>
    <span>
      Nuevo código en <b id="totp-left">{TOTP_PERIOD_S}</b> s
    </span>
    <script dangerouslySetInnerHTML={{ __html: TOTP_COUNTDOWN_JS }} />
  </p>
);

// qué app pide el acceso: se lee del return_to cuando el login viene de authorize
const RequestContext: FC<{ request: AuthorizeRequest }> = ({ request }) => (
  <div class="ctx">
    <p>GET {AUTHORIZE_PATH}</p>
    <dl class="kv">
      <div>
        <dt>cliente</dt>
        <dd>
          <ServiceIcon host={request.host} name={request.clientName} />
          {request.clientName}
        </dd>
      </div>
      <div>
        <dt>destino</dt>
        <dd>{request.host}</dd>
      </div>
      {request.scopes.length > 0 && (
        <div>
          <dt>alcance</dt>
          <dd>{request.scopes.join(' ')}</dd>
        </div>
      )}
      {request.pkce && (
        <div>
          <dt>pkce</dt>
          <dd>{request.pkce}</dd>
        </div>
      )}
    </dl>
  </div>
);

// añade el return_to a un enlace entre páginas de auth para no perder el authorize pendiente
const withReturnTo = (path: string, returnTo: string | null): string =>
  returnTo ? `${path}?return_to=${encodeURIComponent(returnTo)}` : path;

export const LoginPage: PageFC<{
  providers: { id: string; name: string }[];
  returnTo: string | null;
  request?: AuthorizeRequest | null;
  error?: string;
  email?: string;
}> = ({ providers, returnTo, request, error, email }) => (
  <Layout title="Iniciar sesión">
    {request && <RequestContext request={request} />}
    <div class="head">
      <h1>Iniciar sesión</h1>
      {request && (
        <p>
          para continuar a <strong>{request.clientName}</strong>
        </p>
      )}
    </div>
    {error && <p class="error">{error}</p>}
    <button type="button" class="block" id="passkey-btn" data-return-to={returnTo ?? ''}>
      <Icon name="key" />
      Entrar con passkey
    </button>
    <p class="error" id="passkey-error" role="alert" hidden></p>
    <div class="sep">o con tu correo</div>
    <form class="stack" method="post" action="/login">
      {returnTo && <input type="hidden" name="return_to" value={returnTo} />}
      <div class="field">
        <label for="email">Correo electrónico</label>
        {/* autocomplete "... webauthn": el navegador ofrece las passkeys en el propio campo */}
        <input id="email" type="email" name="email" value={email ?? ''} required autofocus autocomplete="username webauthn" />
      </div>
      <div class="field">
        <label for="password">
          <span>Contraseña</span>
          <a href="/forgot">¿La has olvidado?</a>
        </label>
        <input id="password" type="password" name="password" required autocomplete="current-password webauthn" />
      </div>
      <button type="submit" class="primary block">
        Entrar
      </button>
    </form>
    {providers.length > 0 && (
      <div class="social">
        {providers.map((p) => (
          <a class="btn" href={withReturnTo(`/login/${p.id}`, returnTo)} aria-label={`Continuar con ${p.name}`}>
            <ProviderIcon id={p.id} name={p.name} />
            <span>{p.name}</span>
          </a>
        ))}
      </div>
    )}
    <p class="links">
      <span>¿No tienes cuenta?</span>
      <a href={withReturnTo('/signup', returnTo)}>Crear cuenta</a>
    </p>
    <PasskeyScript />
    {/* arranca el autofill de passkeys al cargar y conecta el botón explícito */}
    <script dangerouslySetInnerHTML={{ __html: PASSKEY_LOGIN_JS }} />
  </Layout>
);

// hub de servicios: la landing de id.mier.info cuando hay sesión. lista las apps
// registradas como clientes oauth; al ser sso, entrar en cualquiera es silencioso.
// el panel whoami enseña los claims de la sesión actual antes que la lista.
export const HubPage: PageFC<{
  session: CurrentSession;
  sessionCount: number;
  totpEnabled: boolean;
  services: { name: string; url: string; host: string }[];
}> = ({ session, sessionCount, totpEnabled, services }) => (
  <Layout title="Servicios" user={session.user} section="servicios">
    <div class="hub">
      <section class="whoami" aria-label="Tu identidad">
        <p class="cmd">
          <b>$</b> whoami
        </p>
        <p class="who">
          <strong>{session.user.name}</strong>
          <span>{session.user.email}</span>
        </p>
        <dl class="kv">
          <div>
            <dt>sub</dt>
            <dd>{session.user.id}</dd>
          </div>
          <div>
            <dt>amr</dt>
            <dd>{JSON.stringify(session.amr)}</dd>
          </div>
          <div>
            <dt>auth_time</dt>
            <dd>{isoFmt.format(session.authTime)}</dd>
          </div>
          <div>
            <dt>sesiones</dt>
            <dd>{plural(sessionCount, 'activa', 'activas')}</dd>
          </div>
          <div>
            <dt>totp</dt>
            <dd>{totpEnabled ? <span class="pill ok">activa</span> : <a href="/account#dos-pasos">sin configurar</a>}</dd>
          </div>
        </dl>
      </section>
      <section class="svcs" aria-labelledby="svcs-h">
        <div class="page-h">
          <h1 id="svcs-h">Tus servicios</h1>
          {services.length > 0 && <span class="muted small">{services.length} · sesión única</span>}
        </div>
        {services.length === 0 ? (
          <p class="muted">Aún no hay servicios registrados. Añade clientes OAuth desde el panel de administración.</p>
        ) : (
          <ul class="services">
            {services.map((s, i) => (
              <li>
                <a class="svc" href={s.url} data-key={i < MAX_SHORTCUTS ? String(i + 1) : undefined}>
                  {i < MAX_SHORTCUTS && <kbd>{i + 1}</kbd>}
                  <ServiceIcon host={s.host} name={s.name} />
                  <span class="names">
                    <span class="name">{s.name}</span>
                    <span class="host">{s.host}</span>
                  </span>
                  <Icon name="arrow" class="go" />
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
    {services.length > 0 && <script dangerouslySetInnerHTML={{ __html: SHORTCUTS_JS }} />}
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
    <form class="stack" method="post" action="/signup">
      {returnTo && <input type="hidden" name="return_to" value={returnTo} />}
      <div class="field">
        <label for="name">Nombre</label>
        <input id="name" type="text" name="name" value={values?.name ?? ''} required autofocus />
      </div>
      <div class="field">
        <label for="email">Correo electrónico</label>
        <input id="email" type="email" name="email" value={values?.email ?? ''} required autocomplete="username" />
      </div>
      <div class="field">
        <label for="password">
          <span>Contraseña</span>
          <span>Mínimo {PASSWORD_MIN_LENGTH} caracteres</span>
        </label>
        <input
          id="password"
          type="password"
          name="password"
          required
          minlength={PASSWORD_MIN_LENGTH}
          autocomplete="new-password"
        />
      </div>
      <button type="submit" class="primary block">
        Crear cuenta
      </button>
    </form>
    <p class="links">
      <span>¿Ya tienes cuenta?</span>
      <a href={withReturnTo('/login', returnTo)}>Inicia sesión</a>
    </p>
  </Layout>
);

// el mfa solo se pide tras la contraseña, así que el primer factor siempre es pwd
export const MfaPage: PageFC<{ challengeId: string; error?: string }> = ({ challengeId, error }) => (
  <Layout title="Verificación en dos pasos">
    <ol class="factors" aria-label="Factores de acceso">
      <li class="done">
        Contraseña <code>pwd</code>
      </li>
      <li class="now">
        Código TOTP <code>otp</code>
      </li>
    </ol>
    <div class="head">
      <h1>Verificación en dos pasos</h1>
      <p>Escribe el código de {TOTP_DIGITS} dígitos que muestra tu aplicación de autenticación.</p>
    </div>
    {error && <p class="error">{error}</p>}
    <form class="stack" method="post" action="/mfa">
      <input type="hidden" name="challenge" value={challengeId} />
      <label class="sr" for="code">
        Código de verificación
      </label>
      <OtpInput id="code" />
      <TotpCountdown />
      <button type="submit" class="primary block">
        Verificar
      </button>
    </form>
    <details class="alt">
      <summary>Usar un código de recuperación</summary>
      <form class="stack" method="post" action="/mfa">
        <input type="hidden" name="challenge" value={challengeId} />
        <div class="field">
          <label for="recovery">Código de recuperación</label>
          <input id="recovery" type="text" name="code" required autocomplete="off" placeholder="xxxx-xxxx" />
        </div>
        <button type="submit" class="block">
          Verificar
        </button>
      </form>
    </details>
    <p class="links">
      <a href="/login">Cancelar</a>
    </p>
  </Layout>
);

export const ForgotPage: PageFC<{ sent: boolean }> = ({ sent }) => (
  <Layout title="Recuperar contraseña">
    {sent ? (
      <div class="head">
        <h1>Revisa tu correo</h1>
        <p>Si la dirección existe, te hemos enviado un enlace para restablecer tu contraseña.</p>
      </div>
    ) : (
      <>
        <div class="head">
          <h1>Recuperar contraseña</h1>
          <p>Te enviaremos un enlace para elegir una nueva.</p>
        </div>
        <form class="stack" method="post" action="/forgot">
          <div class="field">
            <label for="email">Correo electrónico</label>
            <input id="email" type="email" name="email" required autofocus autocomplete="username" />
          </div>
          <button type="submit" class="primary block">
            Enviar enlace
          </button>
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
    <form class="stack" method="post" action="/reset">
      <input type="hidden" name="token" value={token} />
      <div class="field">
        <label for="password">
          <span>Nueva contraseña</span>
          <span>Mínimo {PASSWORD_MIN_LENGTH} caracteres</span>
        </label>
        <input
          id="password"
          type="password"
          name="password"
          required
          minlength={PASSWORD_MIN_LENGTH}
          autofocus
          autocomplete="new-password"
        />
      </div>
      <button type="submit" class="primary block">
        Guardar contraseña
      </button>
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
    <div class="head">
      <h1>{title}</h1>
      <p>{message}</p>
    </div>
    {linkHref && (
      <p class="links">
        <a href={linkHref}>{linkText ?? 'Continuar'}</a>
      </p>
    )}
  </Layout>
);

// secciones de la cuenta: ancla + etiqueta del índice lateral
const ACCOUNT_SECTIONS = [
  ['perfil', 'Perfil'],
  ['contrasena', 'Contraseña'],
  ['passkeys', 'Passkeys'],
  ['dos-pasos', 'Verificación en dos pasos'],
  ['cuentas', 'Cuentas vinculadas'],
  ['sesiones', 'Sesiones'],
] as const;

export const AccountPage: PageFC<{
  user: PublicUser;
  sessions: SessionInfo[];
  passkeys: { id: string; name: string; createdAt: Date; lastUsedAt: Date | null }[];
  identities: { provider: string; email: string | null }[];
  providers: { id: string; name: string }[];
  totp: { enabledAt: Date | null; recoveryLeft: number; recoveryTotal: number } | null;
  flash?: string | null;
  error?: string | null;
}> = ({ user, sessions, passkeys, identities, providers, totp, flash, error }) => {
  const linked = new Set(identities.map((i) => i.provider));
  const unlinked = providers.filter((p) => !linked.has(p.id));
  // nombre legible del proveedor (los identities solo guardan el id)
  const providerName = (id: string): string => providers.find((p) => p.id === id)?.name ?? id;
  return (
    <Layout title="Mi cuenta" user={user} section="cuenta">
      <h1>Mi cuenta</h1>
      {error && <p class="error">{error}</p>}
      {flash && <p class="flash">{flash}</p>}
      <div class="acct">
        <nav class="side" aria-label="Ajustes de la cuenta">
          {ACCOUNT_SECTIONS.map(([id, label]) => (
            <a href={`#${id}`}>{label}</a>
          ))}
        </nav>
        <div class="panels">
          <section class="panel" id="perfil">
            <div class="panel-h">
              <div>
                <h2>Perfil</h2>
                <p>Tu nombre y tu correo llegan a las apps en las que inicias sesión.</p>
              </div>
            </div>
            <form class="fields" method="post" action="/account/profile">
              <div class="field">
                <label for="profile-name">Nombre</label>
                <input id="profile-name" type="text" name="name" value={user.name} required />
              </div>
              <div class="field">
                <label for="profile-email">
                  <span>Correo electrónico</span>
                  {user.emailVerified ? <span class="pill ok">verificado</span> : <span class="pill">sin verificar</span>}
                </label>
                <input id="profile-email" type="email" value={user.email} readonly />
              </div>
              <button class="primary">Guardar</button>
            </form>
          </section>

          <section class="panel" id="contrasena">
            <div class="panel-h">
              <div>
                <h2>Contraseña</h2>
                <p>Al cambiarla se cierran el resto de sesiones y se revocan los tokens emitidos.</p>
              </div>
            </div>
            <form class="fields" method="post" action="/account/password">
              {user.hasPassword && (
                <div class="field">
                  <label for="current-password">Contraseña actual</label>
                  <input id="current-password" type="password" name="current" required autocomplete="current-password" />
                </div>
              )}
              <div class="field">
                <label for="new-password">Nueva contraseña</label>
                <input
                  id="new-password"
                  type="password"
                  name="password"
                  required
                  minlength={PASSWORD_MIN_LENGTH}
                  autocomplete="new-password"
                />
              </div>
              <button>{user.hasPassword ? 'Cambiar contraseña' : 'Establecer contraseña'}</button>
            </form>
          </section>

          <section class="panel" id="passkeys">
            <div class="panel-h">
              <div>
                <h2>Passkeys</h2>
                <p>Entra sin contraseña con la huella, la cara o el PIN del dispositivo.</p>
              </div>
              <button type="button" class="sm" onclick="window.passkeyRegister()">
                <Icon name="key" />
                Añadir passkey
              </button>
            </div>
            {passkeys.length === 0 ? (
              <p class="muted small">No tienes ninguna passkey registrada.</p>
            ) : (
              <div class="rows">
                {passkeys.map((pk, i) => (
                  <div class="row">
                    <span class="ico">
                      <Icon name="key" />
                    </span>
                    <div class="row-main">
                      <span class="row-t">{pk.name}</span>
                      <span class="row-s">
                        Creada {fmtDate(pk.createdAt)} ·{' '}
                        {pk.lastUsedAt ? `Último uso ${fmtDate(pk.lastUsedAt)}` : 'Nunca usada'}
                      </span>
                    </div>
                    <details class="rename">
                      <summary class="btn sm ghost">Renombrar</summary>
                      <form class="inline" method="post" action="/account/passkeys/rename">
                        <input type="hidden" name="id" value={pk.id} />
                        <label class="sr" for={`passkey-name-${i}`}>
                          Nuevo nombre
                        </label>
                        <input id={`passkey-name-${i}`} type="text" name="name" value={pk.name} required />
                        <button class="sm primary">Guardar</button>
                      </form>
                    </details>
                    <form method="post" action="/account/passkeys/delete">
                      <input type="hidden" name="id" value={pk.id} />
                      <button class="sm danger">Borrar</button>
                    </form>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section class="panel" id="dos-pasos">
            <div class="panel-h">
              <div>
                <h2>Verificación en dos pasos</h2>
                <p>
                  Código TOTP de {TOTP_DIGITS} dígitos después de la contraseña. No se pide al entrar con una passkey
                  ni con un proveedor externo.
                </p>
              </div>
              {totp ? <span class="pill ok">activada</span> : <span class="pill">desactivada</span>}
            </div>
            {totp ? (
              <div class="rows">
                <div class="row">
                  <div class="row-main">
                    <span class="row-t">Aplicación de autenticación</span>
                    <span class="row-s">{totp.enabledAt ? `Configurada el ${fmtDay(totp.enabledAt)}` : 'Configurada'}</span>
                  </div>
                  <form class="inline" method="post" action="/account/totp/disable">
                    <label class="sr" for="totp-code">
                      Código para desactivar
                    </label>
                    <input
                      id="totp-code"
                      type="text"
                      name="code"
                      required
                      placeholder="código actual"
                      autocomplete="one-time-code"
                      inputmode="numeric"
                    />
                    <button class="sm danger">Desactivar</button>
                  </form>
                </div>
                <div class="row">
                  <div class="row-main">
                    <span class="row-t">Códigos de recuperación</span>
                    <span class="row-s">
                      Quedan {totp.recoveryLeft} de {totp.recoveryTotal}. Cada uno sirve una sola vez.
                    </span>
                  </div>
                  <span class="meter" aria-hidden="true">
                    [{'#'.repeat(totp.recoveryLeft)}
                    {'.'.repeat(Math.max(totp.recoveryTotal - totp.recoveryLeft, 0))}]
                  </span>
                </div>
              </div>
            ) : (
              <p class="small">
                Añade un segundo paso al entrar con contraseña. <a href="/account/totp/setup">Configurar TOTP</a>
              </p>
            )}
          </section>

          <section class="panel" id="cuentas">
            <div class="panel-h">
              <div>
                <h2>Cuentas vinculadas</h2>
                <p>Entra con otro proveedor sin crear una cuenta nueva.</p>
              </div>
            </div>
            {identities.length === 0 && unlinked.length === 0 ? (
              <p class="muted small">No hay proveedores externos configurados.</p>
            ) : (
              <div class="rows">
                {identities.map((i) => (
                  <div class="row">
                    <span class="ico">
                      <ProviderIcon id={i.provider} name={i.provider} />
                    </span>
                    <div class="row-main">
                      <span class="row-t">{providerName(i.provider)}</span>
                      <span class="row-s">{i.email ?? 'Sin correo'}</span>
                    </div>
                    <form method="post" action="/account/identities/unlink">
                      <input type="hidden" name="provider" value={i.provider} />
                      <button class="sm danger">Desvincular</button>
                    </form>
                  </div>
                ))}
                {unlinked.map((p) => (
                  <div class="row">
                    <span class="ico">
                      <ProviderIcon id={p.id} name={p.name} />
                    </span>
                    <div class="row-main">
                      <span class="row-t">{p.name}</span>
                      <span class="row-s">Sin vincular</span>
                    </div>
                    <a class="btn sm" href={`/login/${p.id}?link=1`}>
                      Vincular
                    </a>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section class="panel" id="sesiones">
            <div class="panel-h">
              <div>
                <h2>Sesiones</h2>
                <p>Cada sesión caduca tras {SESSION_TTL_DAYS} días sin uso.</p>
              </div>
              <form method="post" action="/account/sessions/logout-others">
                <button class="sm ghost">Cerrar las demás</button>
              </form>
            </div>
            <div class="rows">
              {sessions.map((s) => (
                <div class="row">
                  <span class="ico">
                    <Icon name={s.userAgent && MOBILE_UA_RE.test(s.userAgent) ? 'phone' : 'laptop'} />
                  </span>
                  <div class="row-main">
                    <span class="row-t" title={s.userAgent ?? undefined}>
                      {describeUa(s.userAgent)}
                      {s.current && <span class="pill">esta sesión</span>}
                    </span>
                    <span class="row-s">
                      Iniciada {fmtDate(s.createdAt)} · Caduca {fmtDate(s.expiresAt)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
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
    <div class="head">
      <h1>Configurar TOTP</h1>
      <p>Añade esta clave a tu aplicación de autenticación y escribe el código que genere.</p>
    </div>
    <code class="secret">{secret.match(new RegExp(`.{1,${TOTP_SECRET_GROUP}}`, 'g'))?.join(' ') ?? secret}</code>
    <p class="small">
      <a href={otpauthUrl}>Abrir directamente en la aplicación</a> <span class="muted">(desde el móvil)</span>
    </p>
    {error && <p class="error">{error}</p>}
    <form class="stack" method="post" action="/account/totp/confirm">
      <label class="sr" for="code">
        Código de verificación
      </label>
      <OtpInput id="code" />
      <button type="submit" class="primary block">
        Confirmar
      </button>
    </form>
    <p class="links">
      <a href="/account#dos-pasos">Volver a mi cuenta</a>
    </p>
  </Layout>
);

export const TotpRecoveryCodesPage: PageFC<{ codes: string[] }> = ({ codes }) => (
  <Layout title="Códigos de recuperación">
    <div class="head">
      <h1>Códigos de recuperación</h1>
      <p>Guárdalos en un lugar seguro. Cada uno solo puede usarse una vez y no volverán a mostrarse.</p>
    </div>
    <ul class="codes">
      {codes.map((code) => (
        <li>{code}</li>
      ))}
    </ul>
    <p class="links">
      <a href="/account#dos-pasos">Volver a mi cuenta</a>
    </p>
  </Layout>
);

// host del primer redirect_uri de un cliente (icono y enlace del hub salen del mismo sitio)
const hostOf = (uri: string | undefined): string => (uri && URL.canParse(uri) ? new URL(uri).host : '');

export const AdminPage: PageFC<{
  user: PublicUser;
  users: { id: string; email: string; name: string; isAdmin: boolean; isActive: boolean; createdAt: Date }[];
  clients: { id: string; name: string; redirectUris: string[]; isPublic: boolean }[];
  activeSessions: number;
  signingKey: { kid: string; alg: string; createdAt: Date } | null;
  flash?: string | null;
  error?: string | null;
}> = ({ user, users, clients, activeSessions, signingKey, flash, error }) => {
  const inactive = users.filter((u) => !u.isActive).length;
  const publicClients = clients.filter((cl) => cl.isPublic).length;
  return (
    <Layout title="Administración" user={user} section="admin">
      <h1>Administración</h1>
      {error && <p class="error">{error}</p>}
      {flash && <p class="flash">{flash}</p>}

      <div class="stats">
        <div class="stat">
          <span>Usuarios</span>
          <strong>{users.length}</strong>
          <small>{plural(inactive, 'desactivado', 'desactivados')}</small>
        </div>
        <div class="stat">
          <span>Clientes OAuth</span>
          <strong>{clients.length}</strong>
          <small>
            {plural(clients.length - publicClients, 'confidencial', 'confidenciales')} ·{' '}
            {plural(publicClients, 'público', 'públicos')}
          </small>
        </div>
        <div class="stat">
          <span>Sesiones activas</span>
          <strong>{activeSessions}</strong>
          <small>Caducan tras {SESSION_TTL_DAYS} días sin uso</small>
        </div>
        <div class="stat">
          <span>Clave de firma</span>
          <strong>{signingKey?.alg ?? 'ninguna'}</strong>
          <small>{signingKey ? `kid ${signingKey.kid} · desde ${fmtDay(signingKey.createdAt)}` : 'Sin clave activa'}</small>
        </div>
      </div>

      <section class="panel">
        <h2>Usuarios</h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Usuario</th>
                <th>Rol</th>
                <th>Estado</th>
                <th>Alta</th>
                <th>
                  <span class="sr">Acciones</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr>
                  <td>
                    <span class="user">
                      <span>{u.name}</span>
                      <small>{u.email}</small>
                    </span>
                  </td>
                  <td>{u.isAdmin ? <span class="pill">admin</span> : <span class="muted">usuario</span>}</td>
                  <td>{u.isActive ? <span class="pill ok">activo</span> : <span class="pill bad">desactivado</span>}</td>
                  <td>{fmtDay(u.createdAt)}</td>
                  <td>
                    {u.id === user.id ? (
                      <span class="actions muted small">tú</span>
                    ) : (
                      <div class="actions">
                        <form method="post" action={`/admin/users/${u.id}/toggle-active`}>
                          <button class="sm ghost">{u.isActive ? 'Desactivar' : 'Activar'}</button>
                        </form>
                        <form
                          method="post"
                          action={`/admin/users/${u.id}/delete`}
                          onsubmit="return confirm('¿Borrar este usuario? Esta acción no se puede deshacer.')"
                        >
                          <button class="sm danger">Borrar</button>
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
        <div class="panel-h">
          <div>
            <h2>Clientes OAuth</h2>
            <p>Cada cliente aparece en Servicios con el origen de su primera redirect URI.</p>
          </div>
        </div>
        {clients.length === 0 ? (
          <p class="muted small">Ningún cliente registrado.</p>
        ) : (
          <div class="rows">
            {clients.map((cl) => (
              <div class="row">
                <ServiceIcon host={hostOf(cl.redirectUris[0])} name={cl.name} />
                <div class="row-main">
                  <span class="row-t">
                    {cl.name} <code>{cl.id}</code>
                  </span>
                  <span class="row-s">{cl.redirectUris.join(' · ')}</span>
                </div>
                {cl.isPublic ? <span class="pill">público · pkce</span> : <span class="pill">confidencial</span>}
                <form
                  method="post"
                  action={`/admin/clients/${cl.id}/delete`}
                  onsubmit="return confirm('¿Borrar este cliente? Sus tokens dejarán de funcionar.')"
                >
                  <button class="sm danger">Borrar</button>
                </form>
              </div>
            ))}
          </div>
        )}
        <h3>Nuevo cliente</h3>
        <form class="stack" method="post" action="/admin/clients">
          <div class="field">
            <label for="client-name">Nombre</label>
            <input id="client-name" type="text" name="name" required />
          </div>
          <div class="field">
            <label for="client-uris">Redirect URIs (una por línea)</label>
            <textarea id="client-uris" name="redirect_uris" rows={3} required></textarea>
          </div>
          <div class="field">
            <label for="client-logout-uris">Post-logout redirect URIs (opcional, una por línea)</label>
            <textarea id="client-logout-uris" name="post_logout_redirect_uris" rows={2}></textarea>
          </div>
          <label class="check">
            <input type="checkbox" name="public" /> Cliente público (sin secreto, PKCE obligatorio)
          </label>
          <div>
            <button class="primary">Crear cliente</button>
          </div>
        </form>
      </section>
    </Layout>
  );
};

export const ClientCreatedPage: PageFC<{ client: { id: string; name: string }; secret: string | null }> = ({
  client,
  secret,
}) => (
  <Layout title="Cliente creado">
    <h1>Cliente «{client.name}» creado</h1>
    <dl class="kv">
      <div>
        <dt>client_id</dt>
        <dd>
          <code>{client.id}</code>
        </dd>
      </div>
      {secret && (
        <div>
          <dt>client_secret</dt>
          <dd>
            <code>{secret}</code>
          </dd>
        </div>
      )}
    </dl>
    {secret ? (
      <p class="warn">Guarda el secreto ahora: solo se muestra una vez.</p>
    ) : (
      <p class="muted small">Cliente público: sin secreto, requiere PKCE.</p>
    )}
    <p class="links">
      <a href="/admin">Volver a administración</a>
    </p>
  </Layout>
);

export const ErrorPage: PageFC<{ status: number; message: string; title?: string }> = ({ status, message, title }) => (
  <Layout title={title ?? `Error ${status}`}>
    <div class="head">
      <h1>{title ?? `Error ${status}`}</h1>
      <p>{message}</p>
    </div>
    <p class="links">
      <a href="/">Volver al inicio</a>
    </p>
  </Layout>
);
