# Guía de pruebas (Fase 1 y Fase 2)

Esta guía resume cómo validar el estado actual del monorepo: infraestructura base (Fase 1) y SDK criptográfico (Fase 2).

## Prerrequisitos
- Node.js 20+ y npm 10+
- Python 3.12+
- Docker Engine 26+ y Docker Compose v2.27+
- Copia `.env.example` a `.env` antes de iniciar servicios

## Flujo local (sin Docker)

### 1) Instalar dependencias JavaScript
```bash
npm install
```

### 2) Lint y pruebas JS/TS (SDK + cliente)
```bash
npm run lint --workspaces
npm run test --workspaces
```

### 3) Backend FastAPI
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e services/backend[dev]
ruff check services/backend/securecomm_backend
pytest services/backend/tests
```

### 4) Levantar backend para pruebas manuales
```bash
uvicorn securecomm_backend.main:app --reload --host 0.0.0.0 --port 8000
```
Visita `http://localhost:8000/health` y `http://localhost:8000/version`.

### 5) Probar WebSocket de eco (JWT requerido)
Con `wscat` (npm) u otra herramienta:
```bash
npm install -g wscat
wscat -c "ws://localhost:8000/ws/echo?token=<JWT_VALIDO>"
```
Envía un mensaje y verifica que se devuelve el eco.

## Flujo con Docker/Compose (stack completo)

### 1) Construir imágenes
```bash
docker compose build
```

### 2) Levantar servicios
```bash
docker compose up -d
```

### 3) Verificar salud
```bash
curl -k https://localhost/health
curl -k https://localhost/version
```

### 4) Probar WebSocket detrás de Nginx
```bash
wscat -c "wss://localhost/ws/echo?token=<JWT_VALIDO>" --no-check
```

### 5) Apagar y limpiar
```bash
docker compose down -v
```

## Scripts de conveniencia
Ejecuta todo el linting y tests con los scripts incluidos:
```bash
./scripts/lint.sh
./scripts/test.sh
```

## Notas
- El SDK usa libsodium-wrappers; `npm install` debe ejecutarse en Node 20+.
- Para CI en entornos sin compatibilidad con `workspace:*`, instala con una versión de npm que soporte workspaces (10+).
- Los certificados TLS de desarrollo deben residir en `infra/nginx/certs/` (ver README).