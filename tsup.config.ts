import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: false,
  clean: true,
  // los paquetes @platform/* se publican como fuente ts → bundlearlos
  noExternal: [/^@platform\//],
});
