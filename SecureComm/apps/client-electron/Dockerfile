# syntax=docker/dockerfile:1.7
FROM node:20-alpine AS builder

WORKDIR /app
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

#ARG VITE_API_BASE_URL="https://localhost/api"
#ARG VITE_WS_URL="wss://localhost/ws/secure"
ARG VITE_ROTATION_INTERVAL_MINUTES=30
#ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
#    VITE_WS_URL=$VITE_WS_URL \
ENV    VITE_ROTATION_INTERVAL_MINUTES=$VITE_ROTATION_INTERVAL_MINUTES

COPY package.json tsconfig.base.json ./
COPY packages/crypto-sdk/package.json packages/crypto-sdk/
COPY apps/client-electron/package.json apps/client-electron/

RUN npm install

COPY packages/crypto-sdk packages/crypto-sdk
COPY apps/client-electron apps/client-electron

RUN npm run --workspace @securecomm/crypto-sdk build
RUN npm run --workspace @securecomm/client-electron build

FROM nginx:1.26-alpine AS runtime

COPY --from=builder /app/apps/client-electron/dist /usr/share/nginx/html
COPY apps/client-electron/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget --spider -q http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]