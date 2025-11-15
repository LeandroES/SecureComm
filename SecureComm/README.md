# SecureComm Monorepo

SecureComm es una plataforma de mensajería end-to-end cifrada construida sobre un monorepo con workspaces de Node.js y un backend FastAPI. Esta fase inicial entrega la infraestructura base, esqueletos de servicios y contenedores listos para desarrollo.

## Estructura del repositorio

```
SecureComm/
├─ apps/
│  └─ client-electron/     # Cliente Electron + React + Vite
├─ packages/
│  └─ crypto-sdk/          # SDK criptográfico en TypeScript
├─ services/
│  └─ backend/             # Backend FastAPI
├─ infra/
│  └─ nginx/               # Configuración Nginx reverse proxy + TLS
├─ scripts/                # Utilidades locales de CI
├─ docker-compose.yml
├─ .env.example
└─ README.md
```

## Requisitos previos

- Node.js 20+
- npm 10+
- Python 3.12+
- Docker Engine 26+
- Docker Compose v2.27+

## Variables de entorno

Copia `.env.example` a `.env` y ajusta los valores según tus necesidades:

```bash
cp .env.example .env
```

## Flujo de desarrollo sin Docker

### Instalación de dependencias JavaScript

```bash
npm install
```

### Lint y pruebas del SDK y cliente

```bash
npm run lint --workspaces
npm run test --workspaces
```

### Backend (entorno virtual recomendado)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e services/backend[dev]
uvicorn securecomm_backend.main:app --reload --host 0.0.0.0 --port 8000
```

Los endpoints disponibles en esta fase:

- `GET /health` → `{ "status": "ok" }`
- `GET /version` → `{ "version": "0.1.0" }`
- `WebSocket /ws/echo` → eco autenticado mediante JWT (`token` en query o cabecera `Authorization`).

### Scripts de CI locales

```bash
./scripts/lint.sh
./scripts/test.sh
```

## Flujo con Docker y Docker Compose

### Construir imágenes

```bash
docker compose build
```

### Levantar el stack completo

```bash
docker compose up -d
```

Servicios expuestos:

- `https://localhost` → Proxy Nginx con TLS 1.3, HTTP/2 y HSTS.
- `http://localhost:8080` → Backend FastAPI (tras el proxy para pruebas locales).

### Detener y limpiar

```bash
docker compose down -v
```

## Estructura de contenedores

- **nginx**: Reverse proxy TLS 1.3 (OCSP stapling, HSTS, HTTP/2) hacia backend y cliente.
- **client**: Build estático del cliente Vite servido por Nginx.
- **backend**: FastAPI en Gunicorn + Uvicorn workers.
- **postgres**: PostgreSQL 16 con volumen persistente.
- **redis**: Redis 7 para colas y sesiones.

## Certificados TLS de desarrollo

Por defecto se espera encontrar certificados en `infra/nginx/certs/`. Para entorno local puede generarlos así:

```bash
mkdir -p infra/nginx/certs
openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout infra/nginx/certs/dev.key \
  -out infra/nginx/certs/dev.crt \
  -days 365 \
  -subj "/CN=localhost"
```

Actualiza las rutas en `infra/nginx/conf.d/default.conf` si utilizas nombres diferentes.

## Próximos pasos

Las siguientes fases incorporarán la lógica criptográfica completa (X3DH + Double Ratchet), persistencia store-and-forward y cliente funcional. Este bootstrap garantiza versiones alineadas, pipelines básicos y contenedores reproducibles.