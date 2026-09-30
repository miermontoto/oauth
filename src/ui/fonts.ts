// martian mono (ofl) autoalojada desde @fontsource-variable: el idp no hace peticiones a terceros.
// los ficheros "standard" traen los dos ejes (wght 100-800, wdth 75-112.5); el ancho da el
// contraste entre títulos (112.5) y datos (87.5) sin cargar más familias.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const FONT_FAMILY = 'Martian Mono';
const FONT_PACKAGE = '@fontsource-variable/martian-mono/files';
const HASH_CHARS = 8;

// latin cubre el español; latin-ext solo se descarga si la página contiene alguno de sus caracteres
const SUBSETS = [
  {
    id: 'latin',
    range:
      'U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD',
  },
  {
    id: 'latin-ext',
    range:
      'U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF',
  },
] as const;

// resolución vía node_modules: funciona igual en dev (tsx), tests y el bundle de dist
const resolve = createRequire(import.meta.url).resolve;

// ficheros leídos una vez al arrancar; la url lleva hash de contenido → cacheables sin caducidad
const fonts = SUBSETS.map(({ id, range }) => {
  const data = new Uint8Array(readFileSync(resolve(`${FONT_PACKAGE}/martian-mono-${id}-standard-normal.woff2`)));
  const hash = createHash('sha256').update(data).digest('hex').slice(0, HASH_CHARS);
  return { path: `/fonts/martian-mono-${id}.${hash}.woff2`, data, range };
});

export const FONT_FILES = new Map(fonts.map((f) => [f.path, f.data]));

// solo se precarga latin: es el que usa cualquier página en español
export const FONT_PRELOAD = fonts[0].path;

export const FONT_FACE_CSS = fonts
  .map(
    (f) =>
      `@font-face{font-family:'${FONT_FAMILY}';font-style:normal;font-display:swap;font-weight:100 800;font-stretch:75% 112.5%;src:url(${f.path}) format('woff2');unicode-range:${f.range}}`,
  )
  .join('');
