# ---- build ----
FROM node:22-slim AS build
WORKDIR /app

# pnpm via corepack, fijado a la versión del entorno de desarrollo (lockfile v9)
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@10.34.1 --activate

# dependencias de compilación para better-sqlite3 (fallback si no hay prebuild)
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# instalar dependencias (platform/ = submodule con los paquetes @platform/* en fuente ts)
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.json tsup.config.ts ./
COPY platform/ platform/
RUN pnpm install --frozen-lockfile

# compilar: tsup bundlea @platform/* en dist/index.js y el script build copia las migraciones a dist/db
COPY src/ src/
RUN pnpm build

# ---- producción ----
FROM node:22-slim AS production
WORKDIR /app

# node_modules completo del build (patrón carreterinas): @node-rs/argon2 y
# better-sqlite3 traen binarios linux-x64-gnu — NO cambiar a alpine (musl).
# los symlinks @platform/* quedan colgando pero no se resuelven en runtime (van bundleados).
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/dist dist

# directorio de datos (montado como volumen en compose)
RUN mkdir -p /app/data

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/health').then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
