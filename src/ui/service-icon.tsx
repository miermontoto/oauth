// favicons de las apps propias, copiados de sus repositorios para servirlos sin peticiones externas.
import type { FC } from 'hono/jsx';

const SERVICE_FAVICONS = new Map([
  ...[
    // carreterinas/packages/web/static/favicon.svg
    ['carreterinas.es', `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#2D4A3E"/>
  <path d="M7 24 C 10 18, 14 22, 16 16 S 22 10, 25 8" stroke="#FAF6EE" stroke-width="2.5" fill="none" stroke-linecap="round"/>
</svg>`],
    // sis/packages/web/static/icon.svg
    ['sis.mier.info', `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="96" fill="#080a0c"/>
  <text x="256" y="296" text-anchor="middle" font-family="ui-monospace,'Fira Code','Cascadia Code',monospace" font-weight="700" font-size="180" letter-spacing="0.06em" fill="#1db954">SIS</text>
</svg>`],
    // duckhunt/packages/web/static/favicon.svg
    ['duckhunt.info', `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">
  <circle cx="8" cy="8" r="6.5" fill="none" stroke="#f0b040" stroke-width="1.5"/>
  <line x1="8" y1="0" x2="8" y2="4" stroke="#f0b040" stroke-width="1.5"/>
  <line x1="8" y1="12" x2="8" y2="16" stroke="#f0b040" stroke-width="1.5"/>
  <line x1="0" y1="8" x2="4" y2="8" stroke="#f0b040" stroke-width="1.5"/>
  <line x1="12" y1="8" x2="16" y2="8" stroke="#f0b040" stroke-width="1.5"/>
  <circle cx="8" cy="8" r="1" fill="#f0b040"/>
</svg>`],
  ].map(([host, svg]) => [host, `data:image/svg+xml,${encodeURIComponent(svg)}`] as const),
  // url/static/favicon.svg usa la misma marca que mier id
  ['url.mier.info', '/favicon.svg'],
]);

export const ServiceIcon: FC<{ host: string; name: string }> = ({ host, name }) => {
  const favicon = SERVICE_FAVICONS.get(host);
  // sin favicon conocido se cae a la inicial dentro de un recuadro
  return (
    <span class={favicon ? 'svc-ico' : 'svc-ico letter'} aria-hidden="true">
      {favicon ? <img src={favicon} width="28" height="28" alt="" /> : name.charAt(0)}
    </span>
  );
};
