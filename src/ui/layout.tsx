// layout base: documento html completo con la hoja de estilos inline y el wordmark de marca.
// estética brutalista monocroma (negro/blanco/gris) con acentos de color solo en estados,
// al estilo de url.mier.info: tipografía monoespaciada, bordes duros, esquinas rectas.
import type { Child, FC, PropsWithChildren } from 'hono/jsx';
import { html } from 'hono/html';
import { SERVICE_NAME } from '../constants.js';
import { BrandMark } from './brand.js';

// hoja única: mono (Berkeley Mono del propietario vía local(), fallback monospace),
// paleta monocroma con acentos semánticos (rojo/verde/amarillo terminal), sin radios
const styles = `
*,*::before,*::after{box-sizing:border-box}
@font-face{font-family:'Berkeley Mono';font-display:swap;src:local('Berkeley Mono')}
@font-face{font-family:'Courier Prime';font-display:swap;src:local('Courier Prime')}
:root{color-scheme:dark;--bg:#000;--fg:#fff;--muted:#999;--card:#0a0a0a;--field:#1a1a1a;--border:#333;--edge:#666;--accent:#fff;--accent-fg:#000;--danger:#ff6b6b;--danger-bg:#660000;--danger-edge:#992222;--ok:#5bd75b;--ok-bg:#006600;--ok-edge:#229922;--warn-bg:#666600;--code-bg:#141414}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;background:var(--bg);color:var(--fg);font:300 15px/1.5 'Berkeley Mono','Courier Prime',ui-monospace,'Cascadia Mono',monospace;padding:2.5rem 1rem 3rem}
body.auth{justify-content:safe center;gap:.5rem}
.brand{padding-bottom:1.4rem;text-align:center}
.brand a{display:inline-flex;flex-direction:column;align-items:center;gap:.45rem;font-weight:400;font-size:1.05rem;letter-spacing:-.02em;color:var(--fg);text-decoration:none;text-transform:lowercase}
.brand svg{display:block}
main.card{width:min(23rem,100%);background:var(--card);border:1px solid var(--edge);padding:1.9rem}
main.wide{width:min(64rem,100%)}
h1{font-size:1.2rem;margin:0 0 1.1rem;font-weight:400;letter-spacing:-.3px}
h2{font-size:1rem;margin:0 0 .75rem;font-weight:400}
h3{font-size:.78rem;margin:1.25rem 0 .5rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
p{margin:.5rem 0}
a{color:var(--fg);text-decoration:underline;text-underline-offset:2px}
a:hover{color:var(--muted)}
.muted{color:var(--muted)}
.small{font-size:.84rem}
label{display:block;font-size:.74rem;font-weight:400;color:var(--muted);margin:.9rem 0 .3rem;text-transform:lowercase;letter-spacing:.02em}
input[type=text],input[type=email],input[type=password],textarea{width:100%;padding:.6rem .7rem;border:1px solid var(--edge);border-radius:0;background:var(--field);color:var(--fg);font:inherit}
input::placeholder{color:#666}
input:focus-visible,textarea:focus-visible{outline:none;border-color:var(--fg);background:#181820}
input.compact{width:auto;max-width:9.5rem;padding:.35rem .5rem}
button,.btn{display:inline-block;margin-top:1rem;padding:.55rem .95rem;border:1px solid var(--fg);border-radius:0;background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:400;cursor:pointer;text-decoration:none;text-align:center;text-transform:lowercase}
button:hover,.btn:hover{background:#ccc;color:#000}
button:active,.btn:active{transform:translateY(1px)}
button.secondary,.btn.secondary{background:transparent;color:var(--fg);border-color:var(--edge)}
button.secondary:hover,.btn.secondary:hover{background:var(--field);color:var(--fg)}
button.danger{background:transparent;color:var(--danger);border-color:var(--danger-edge)}
button.danger:hover{background:var(--danger-bg);color:#fff}
button.sm,.btn.sm{padding:.3rem .65rem;font-size:.8rem;margin-top:.5rem}
main.card form>button{width:100%}
form{margin:0}
form.inline{display:inline}
.check{display:flex;align-items:center;gap:.5rem;font-weight:300;font-size:.88rem;color:var(--fg);text-transform:none}
.check input{width:auto}
.error{background:var(--danger-bg);color:#fff;padding:.6rem .75rem;border:1px solid var(--danger-edge);border-radius:0;font-size:.85rem}
.flash{background:var(--ok-bg);color:#fff;padding:.6rem .75rem;border:1px solid var(--ok-edge);border-radius:0;font-size:.85rem}
.links{display:flex;justify-content:space-between;gap:.75rem;flex-wrap:wrap;font-size:.85rem;margin-top:1.2rem}
.providers{display:flex;flex-direction:column;gap:.5rem;margin-top:.75rem}
.providers .btn{margin-top:0;background:transparent;color:var(--fg);border-color:var(--edge)}
.providers .btn:hover{background:var(--field)}
.social{margin-top:1.25rem}
.social-sep{display:flex;align-items:center;gap:.75rem;color:var(--muted);font-size:.74rem;text-transform:lowercase;letter-spacing:.03em}
.social-sep::before,.social-sep::after{content:'';flex:1;height:1px;background:var(--border)}
.social-icons{display:flex;justify-content:center;flex-wrap:wrap;gap:.6rem;margin-top:.9rem}
.social-icons.start{justify-content:flex-start;margin-top:.6rem}
.social-btn{display:inline-flex;align-items:center;justify-content:center;width:2.75rem;height:2.75rem;border:1px solid var(--edge);color:var(--fg);text-decoration:none;margin-top:0}
.social-btn:hover{background:var(--fg);color:var(--bg)}
.social-letter{font-weight:400;font-size:1.05rem;line-height:1}
hr.sep{border:none;border-top:1px solid var(--border);margin:1.25rem 0}
section.panel{background:var(--card);border:1px solid var(--edge);border-radius:0;padding:1.25rem 1.5rem;margin-bottom:1rem}
.hub{display:grid;grid-template-columns:repeat(auto-fill,minmax(16rem,1fr));gap:.7rem;margin-top:.25rem}
.hub-card{display:flex;align-items:center;gap:.85rem;padding:.9rem 1rem;border:1px solid var(--edge);text-decoration:none;color:var(--fg)}
.hub-card:hover{background:var(--field);border-color:var(--fg);color:var(--fg)}
.hub-badge{flex:0 0 auto;width:2.4rem;height:2.4rem;display:flex;align-items:center;justify-content:center;border:1px solid var(--edge);font-size:1.15rem;text-transform:uppercase}
.hub-badge img{display:block;object-fit:contain}
.hub-card:hover .hub-badge{border-color:var(--fg)}
.hub-body{display:flex;flex-direction:column;gap:.1rem;min-width:0}
.hub-name{font-size:.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hub-host{color:var(--muted);font-size:.78rem}
.brand-bar{width:min(64rem,100%);padding-bottom:1.4rem;margin-bottom:1.4rem;text-align:left;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.brand-bar a{flex-direction:row;gap:.5rem;font-size:1rem}
.brand-actions{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;text-transform:none}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem}
.topbar h1{margin:0}
.row{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{color:var(--muted);font-weight:400;text-align:left;white-space:nowrap;text-transform:lowercase;letter-spacing:.02em}
th,td{padding:.45rem .6rem;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:.05rem .5rem;border-radius:0;font-size:.72rem;font-weight:400;background:transparent;color:var(--muted);border:1px solid var(--edge);white-space:nowrap;text-transform:lowercase}
.badge.ok{background:var(--ok-bg);color:#fff;border-color:var(--ok-edge)}
.badge.warn{background:var(--danger-bg);color:#fff;border-color:var(--danger-edge)}
code,.mono{font-family:inherit;background:var(--code-bg);padding:.1rem .35rem;border-radius:0;font-size:.9em;word-break:break-all}
.secret{display:block;text-align:center;font-size:1.05rem;letter-spacing:.08em;padding:.7rem;border-radius:0;border:1px solid var(--edge);background:var(--code-bg)}
ul.codes{list-style:none;margin:.75rem 0;padding:.85rem 1rem;columns:2;font-family:inherit;font-size:.95rem;background:var(--code-bg);border:1px solid var(--border);border-radius:0}
ul.codes li{padding:.15rem 0}
`;

export const Layout: FC<PropsWithChildren<{ title: string; wide?: boolean; actions?: Child }>> = ({
  title,
  wide,
  actions,
  children,
}) => (
  <>
    {html`<!DOCTYPE html>`}
    <html lang="es">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <title>{`${title} · ${SERVICE_NAME}`}</title>
        <style dangerouslySetInnerHTML={{ __html: styles }} />
      </head>
      <body class={wide ? 'wide-page' : 'auth'}>
        <header class={wide ? 'brand brand-bar' : 'brand'}>
          <a href="/">
            <BrandMark size={wide ? 26 : 34} />
            <span>{SERVICE_NAME}</span>
          </a>
          {wide && actions && <div class="brand-actions">{actions}</div>}
        </header>
        <main class={wide ? 'wide' : 'card'}>{children}</main>
      </body>
    </html>
  </>
);
