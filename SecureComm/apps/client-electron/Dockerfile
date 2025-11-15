# apps/client-electron/Dockerfile

# ---------- Builder (Node + npm workspaces) ----------
FROM node:20-alpine AS builder
WORKDIR /app

# 1) Copia SOLO los manifiestos del monorepo para cachear deps
#    ¡El lockfile raíz es clave para que npm resuelva "workspace:"!
COPY package.json package-lock.json tsconfig.base.json ./

# 2) Copia los package.json de cada workspace (sin fuentes todavía)
#    Ajusta/añade más si los tuvieras
COPY packages/crypto-sdk/package.json packages/crypto-sdk/
COPY apps/client-electron/package.json apps/client-electron/

# 3) Instala dependencias en modo workspaces (determinístico)
RUN npm -v && node -v \
 && npm ci --workspaces --include-workspace-root --no-audit --no-fund

# 4) Ahora sí copia el código fuente
COPY packages/crypto-sdk/ packages/crypto-sdk/
COPY apps/client-electron/ apps/client-electron/

# 5) Build del cliente
#    Usa --workspace con la RUTA (no requiere nombre exacto del workspace)
RUN npm run --workspace apps/client-electron build

# ---------- Runtime (Nginx sirviendo estáticos del cliente) ----------
FROM nginx:1.26-alpine AS runtime
# Copia el artefacto generado por Vite (ajusta si tu build emite a otra carpeta)
COPY --from=builder /app/apps/client-electron/dist /usr/share/nginx/html
