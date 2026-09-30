// layout base: documento html completo con la hoja de estilos inline y el wordmark de marca.
// estética "terminal", del linaje de url.mier.info: todo en martian mono (ancho 112.5 en títulos,
// 87.5 en datos), bordes duros, esquinas rectas y color solo para estados. oscuro por defecto;
// "papel térmico" claro cuando el sistema lo pide (prefers-color-scheme), sin toggle.
// dos shells: tarjeta centrada sobre retícula de puntos (auth) y barra con navegación (app).
import type { FC, PropsWithChildren } from 'hono/jsx';
import { html } from 'hono/html';
import { SERVICE_NAME } from '../constants.js';
import type { PublicUser } from '../types.js';
import { BrandMark } from './brand.js';
import { FONT_FACE_CSS, FONT_PRELOAD } from './fonts.js';

export type Section = 'servicios' | 'cuenta' | 'admin';

// navegación de la shell autenticada; administración solo aparece para admins
const NAV: { id: Section; href: string; label: string; adminOnly?: boolean }[] = [
  { id: 'servicios', href: '/', label: 'Servicios' },
  { id: 'cuenta', href: '/account', label: 'Cuenta' },
  { id: 'admin', href: '/admin', label: 'Administración', adminOnly: true },
];

// hoja única. tokens de color en :root (oscuro) y redefinidos para el tema claro;
// ningún componente usa colores literales
const styles = `
*,*::before,*::after{box-sizing:border-box}
${FONT_FACE_CSS}
:root{color-scheme:dark;--bg:#000;--card:#0a0a0a;--field:#151515;--fg:#f1f1f1;--muted:#8d8d8d;--line:#242424;--edge:#474747;--dot:#1d1d1d;--ok:#5bd75b;--bad:#ff6b6b}
@media (prefers-color-scheme:light){:root{color-scheme:light;--bg:#fafafa;--card:#fff;--field:#f1f1f1;--fg:#0b0b0b;--muted:#6b6b6b;--line:#e2e2e2;--edge:#b7b7b7;--dot:#d9d9d9;--ok:#1c8a3c;--bad:#c42b2b}}
[hidden]{display:none!important}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);font:400 13px/1.55 'Martian Mono',ui-monospace,'Cascadia Mono',monospace;font-stretch:87.5%;letter-spacing:-.01em;-webkit-text-size-adjust:100%}
body.auth{display:grid;place-items:center;padding:2.5rem 1rem;background-image:radial-gradient(var(--dot) 1.1px,transparent 1.3px);background-size:14px 14px}
a{color:inherit;text-underline-offset:3px}
a:hover{color:var(--muted)}
:focus-visible{outline:2px solid var(--fg);outline-offset:2px}
h1,h2,h3{margin:0;font-weight:500;font-stretch:112.5%;text-transform:lowercase;text-wrap:balance}
h1{font-size:1.5rem;line-height:1.15;letter-spacing:-.035em}
h2{font-size:.98rem;letter-spacing:-.02em}
h3{font-size:.8rem;color:var(--muted);letter-spacing:0}
p{margin:0}
code{background:var(--field);padding:.05rem .35rem;font-size:.92em;overflow-wrap:anywhere}
dl{margin:0}
dd{margin:0;min-width:0;overflow-wrap:anywhere}
summary{list-style:none;cursor:pointer}
summary::-webkit-details-marker{display:none}
.muted{color:var(--muted)}
.small{font-size:.86em}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.wordmark{display:inline-flex;align-items:center;gap:.55rem;font-weight:500;text-decoration:none;text-transform:lowercase}
.wordmark:hover{color:var(--fg)}
.wordmark svg{flex:none}
main.card{width:min(24rem,100%);display:grid;gap:1rem;padding:1.6rem;background:var(--card);border:1px solid var(--edge)}
.head{display:grid;gap:.3rem}
.head p{color:var(--muted)}
.head strong{color:var(--fg);font-weight:500}
form{margin:0}
.stack{display:grid;gap:1rem}
.field{display:grid;gap:.35rem;min-width:0}
label{display:flex;justify-content:space-between;align-items:center;gap:.5rem;font-size:.82em;color:var(--muted);text-transform:lowercase}
label a{color:var(--fg)}
input[type=text],input[type=email],input[type=password],textarea{width:100%;padding:.62rem .75rem;border:1px solid var(--edge);border-radius:0;background:var(--field);color:var(--fg);font:inherit}
input::placeholder,textarea::placeholder{color:var(--muted)}
input:focus-visible,textarea:focus-visible{outline:none;border-color:var(--fg)}
input[readonly]{color:var(--muted)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;padding:.62rem 1rem;border:1px solid var(--edge);border-radius:0;background:var(--card);color:var(--fg);font:inherit;cursor:pointer;text-decoration:none;text-transform:lowercase;white-space:nowrap}
button:hover,.btn:hover{background:var(--fg);border-color:var(--fg);color:var(--bg)}
button:active,.btn:active{transform:translateY(1px)}
button svg,.btn svg{width:1rem;height:1rem;flex:none}
.primary{background:var(--fg);border-color:var(--fg);color:var(--bg)}
.primary:hover{background:color-mix(in srgb,var(--fg) 78%,var(--bg))}
.ghost{background:transparent}
.danger{background:transparent;color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,var(--line))}
.danger:hover{background:var(--bad);border-color:var(--bad);color:var(--bg)}
.sm{padding:.36rem .7rem;font-size:.86em}
.block{width:100%}
.error,.flash,.warn{padding:.6rem .75rem;border:1px solid;font-size:.86em}
.error,.warn{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 50%,transparent);background:color-mix(in srgb,var(--bad) 8%,transparent)}
.flash{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 50%,transparent);background:color-mix(in srgb,var(--ok) 8%,transparent)}
.sep{display:flex;align-items:center;gap:.75rem;color:var(--muted);font-size:.8em;text-transform:lowercase}
.sep::before,.sep::after{content:'';flex:1;height:1px;background:var(--line)}
.links{display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem 1rem;font-size:.86em;color:var(--muted)}
.links a{color:var(--fg)}
.social{display:grid;grid-template-columns:repeat(auto-fit,minmax(6.5rem,1fr));gap:.5rem}
.ctx{display:grid;gap:.4rem;padding:.7rem .85rem;border:1px dashed var(--edge);background:var(--bg);font-size:.85em}
.ctx>p{color:var(--muted)}
.ctx>p::before{content:'› '}
.kv{display:grid;gap:.4rem}
.kv>div{display:grid;grid-template-columns:5.6rem minmax(0,1fr);gap:.75rem;align-items:baseline}
.kv dt{color:var(--muted)}
.kv dd{display:flex;flex-wrap:wrap;align-items:center;gap:.45rem}
.factors{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.35rem 1.1rem;font-size:.82em;color:var(--muted)}
.factors li::before{content:'[ ] '}
.factors .done::before{content:'[x] ';color:var(--ok)}
.factors .now{color:var(--fg)}
input.otp{--pitch:2.6ch;--cell:2.1ch;display:block;width:calc(6 * var(--pitch) + 1ch);margin-inline:auto;padding:.4rem 0 .5rem calc((var(--cell) - 1ch) / 2);border:0;background:repeating-linear-gradient(90deg,var(--edge) 0 var(--cell),transparent var(--cell) var(--pitch)) left bottom / calc(5 * var(--pitch) + var(--cell)) 2px no-repeat;font-size:1.6rem;font-stretch:100%;letter-spacing:calc(var(--pitch) - 1ch)}
input.otp:focus-visible{background-image:repeating-linear-gradient(90deg,var(--fg) 0 var(--cell),transparent var(--cell) var(--pitch))}
.tick{display:flex;align-items:center;justify-content:center;gap:.6rem;font-size:.82em;color:var(--muted)}
.tick b{color:var(--fg);font-weight:400;font-variant-numeric:tabular-nums}
.ring{width:1.4rem;height:1.4rem;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:4}
.ring .bg{stroke:var(--line)}
.ring .fg{stroke:var(--fg);stroke-dasharray:100;transition:stroke-dashoffset 1s linear}
details.alt summary{font-size:.86em;text-decoration:underline;text-underline-offset:3px}
details.alt summary::before{content:'› '}
details.alt[open] summary{margin-bottom:1rem}
body.app{display:flex;flex-direction:column}
.top{display:flex;align-items:center;flex-wrap:wrap;gap:.6rem 1.25rem;padding:.8rem clamp(1rem,3vw,1.5rem);border-bottom:1px solid var(--line)}
.top nav{display:flex;gap:.2rem;overflow-x:auto}
.top nav a{padding:.4rem .7rem;text-decoration:none;color:var(--muted);text-transform:lowercase;white-space:nowrap}
.top nav a:hover{color:var(--fg);background:var(--field)}
.top nav a[aria-current]{background:var(--fg);color:var(--bg)}
.me{margin-left:auto;display:flex;align-items:center;gap:.75rem;font-size:.86em;color:var(--muted)}
@media (max-width:44rem){.top nav{order:3;width:100%}}
@media (max-width:30rem){.me-mail{display:none}}
main.app{width:min(72rem,100%);margin-inline:auto;padding:1.75rem clamp(1rem,3vw,1.5rem) 3rem;display:grid;gap:1.25rem;align-content:start}
.page-h{display:flex;align-items:baseline;flex-wrap:wrap;gap:.5rem 1rem}
.hub{display:grid;gap:1.5rem;align-items:start}
@media (min-width:52rem){.hub{grid-template-columns:minmax(0,19rem) minmax(0,1fr)}}
.whoami{display:grid;gap:.9rem;padding:1.1rem;border:1px solid var(--edge);min-width:0}
.whoami .cmd{color:var(--muted);font-size:.86em}
.whoami .cmd b{color:var(--ok);font-weight:400}
.who{display:grid;gap:.1rem}
.who strong{font-weight:500;font-stretch:112.5%;font-size:1.15rem;letter-spacing:-.02em}
.who span{color:var(--muted)}
.svcs{display:grid;gap:.9rem;min-width:0}
.services{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}
.svc{display:flex;align-items:center;gap:1rem;padding:.8rem .6rem;border-bottom:1px solid var(--line);text-decoration:none}
.svc:hover{background:var(--fg);color:var(--bg)}
.svc:hover :is(.host,.go,kbd){color:inherit;border-color:currentColor}
.names{flex:1;display:grid;grid-template-columns:minmax(0,11rem) minmax(0,1fr);gap:.1rem 1rem;align-items:baseline;min-width:0}
@media (max-width:36rem){.names{grid-template-columns:minmax(0,1fr)}}
.names>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.name{font-weight:500}
.host{color:var(--muted);font-size:.86em}
.go{width:1.1rem;height:1.1rem;flex:none;color:var(--muted)}
kbd{font:inherit;font-size:.78em;padding:.02rem .42rem;border:1px solid var(--edge);border-bottom-width:2px;color:var(--muted)}
@media (hover:none){kbd{display:none}}
.svc-ico{width:1.75rem;height:1.75rem;flex:none;display:grid;place-items:center;text-transform:uppercase}
.svc-ico img{display:block;width:100%;height:100%;object-fit:contain}
.svc-ico.letter{border:1px solid var(--edge)}
.ctx .svc-ico{width:1rem;height:1rem;font-size:.7em}
.acct{display:grid;gap:1.25rem;align-items:start}
@media (min-width:52rem){.acct{grid-template-columns:12.5rem minmax(0,1fr)}}
.side{display:flex;gap:.15rem;overflow-x:auto;font-size:.9em}
@media (min-width:52rem){.side{flex-direction:column;position:sticky;top:1rem}.side a{white-space:normal}}
.side a{padding:.45rem .7rem;color:var(--muted);text-decoration:none;text-transform:lowercase;white-space:nowrap}
.side a:hover{color:var(--fg);background:var(--field)}
.panels{display:grid;gap:1rem;min-width:0}
.panel{display:grid;gap:.9rem;padding:1.1rem 1.25rem;border:1px solid var(--edge);background:var(--card);min-width:0;scroll-margin-top:1rem}
.panel-h{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:.75rem 1rem}
.panel-h>div{display:grid;gap:.2rem;flex:1 1 16rem;min-width:0}
.panel-h p{color:var(--muted);font-size:.86em;max-width:62ch}
.panel h3{padding-top:.9rem;border-top:1px solid var(--line)}
.panel>.stack{max-width:40rem}
.fields{display:flex;flex-wrap:wrap;align-items:flex-end;gap:.75rem}
.fields .field{flex:1 1 13rem}
.rows{display:grid}
.row{display:flex;align-items:center;flex-wrap:wrap;gap:.6rem .9rem;padding:.75rem 0;border-top:1px solid var(--line)}
.row:first-child{border-top:0;padding-top:0}
.row:last-child{padding-bottom:0}
.row-main{display:grid;gap:.1rem;flex:1 1 12rem;min-width:0}
.row-t{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;font-weight:500;overflow-wrap:anywhere}
.row-s{color:var(--muted);font-size:.83em;overflow-wrap:anywhere}
.ico{width:2.15rem;height:2.15rem;flex:none;display:grid;place-items:center;border:1px solid var(--line)}
.ico svg{width:1.1rem;height:1.1rem}
.inline{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
.inline input[type=text]{width:auto;flex:1 1 9rem;max-width:16rem;padding:.36rem .6rem}
.rename[open]{order:1;flex-basis:100%;display:grid;gap:.6rem}
.pill{display:inline-flex;align-items:center;gap:.35rem;padding:.05rem .5rem;border:1px solid var(--edge);font-size:.76em;font-weight:400;color:var(--muted);white-space:nowrap;text-transform:lowercase}
.pill.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,transparent)}
.pill.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
.pill.ok::before,.pill.bad::before{content:'';width:.42rem;height:.42rem;background:currentColor}
.meter{color:var(--ok);letter-spacing:.05em;white-space:nowrap}
.stats{display:grid;gap:.75rem;grid-template-columns:repeat(2,minmax(0,1fr))}
@media (min-width:52rem){.stats{grid-template-columns:repeat(4,minmax(0,1fr))}}
.stat{display:grid;gap:.15rem;align-content:start;padding:.9rem 1rem;border:1px solid var(--edge);background:var(--card);min-width:0}
.stat>span{color:var(--muted);font-size:.8em;text-transform:lowercase}
.stat strong{font-weight:500;font-stretch:112.5%;font-size:1.6rem;line-height:1.2;font-variant-numeric:tabular-nums}
.stat small{color:var(--muted);font-size:.78em;overflow-wrap:anywhere}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.88em}
th{text-align:left;font-weight:400;color:var(--muted);text-transform:lowercase;white-space:nowrap;padding:.5rem .9rem .5rem 0;border-bottom:1px solid var(--edge)}
td{padding:.6rem .9rem .6rem 0;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
tr:last-child td{border-bottom:0}
th:last-child,td:last-child{padding-right:0}
.user{display:grid;line-height:1.35}
.user small{color:var(--muted);font-size:.9em}
.actions{display:flex;justify-content:flex-end;gap:.35rem}
label.check{justify-content:flex-start;font-size:.88em;color:var(--fg);text-transform:none}
.check input{width:auto}
.secret{display:block;text-align:center;font-size:1.05rem;letter-spacing:.08em;padding:.7rem;border:1px solid var(--edge)}
ul.codes{list-style:none;margin:0;padding:.85rem 1rem;columns:2;font-size:.95rem;background:var(--field);border:1px solid var(--line)}
ul.codes li{padding:.15rem 0}
@media (prefers-reduced-motion:reduce){.ring .fg{transition:none}button:active,.btn:active{transform:none}}
`;

export const Layout: FC<PropsWithChildren<{ title: string; user?: PublicUser; section?: Section }>> = ({
  title,
  user,
  section,
  children,
}) => (
  <>
    {html`<!DOCTYPE html>`}
    <html lang="es">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="dark light" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="preload" href={FONT_PRELOAD} as="font" type="font/woff2" crossorigin="anonymous" />
        <title>{`${title} · ${SERVICE_NAME}`}</title>
        <style dangerouslySetInnerHTML={{ __html: styles }} />
      </head>
      {user ? (
        <body class="app">
          <header class="top">
            <a class="wordmark" href="/">
              <BrandMark size={24} />
              <span>{SERVICE_NAME}</span>
            </a>
            <nav aria-label="Secciones">
              {NAV.filter((n) => !n.adminOnly || user.isAdmin).map((n) => (
                <a href={n.href} aria-current={n.id === section ? 'page' : undefined}>
                  {n.label}
                </a>
              ))}
            </nav>
            <div class="me">
              <span class="me-mail">{user.email}</span>
              <form method="post" action="/logout">
                <button class="sm ghost">Salir</button>
              </form>
            </div>
          </header>
          <main class="app">{children}</main>
        </body>
      ) : (
        <body class="auth">
          <main class="card">
            <a class="wordmark" href="/">
              <BrandMark size={26} />
              <span>{SERVICE_NAME}</span>
            </a>
            {children}
          </main>
        </body>
      )}
    </html>
  </>
);
