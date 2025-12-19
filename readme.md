# SecureComm Monorepo

SecureComm es una plataforma de mensajería con cifrado de extremo a extremo (E2EE) construida sobre un monorepo con workspaces de Node.js y un backend robusto en FastAPI. Esta infraestructura proporciona una base sólida con contenedores listos para desarrollo, reverse proxy seguro y herramientas de calidad de código integradas.

## Estructura del Proyecto

El repositorio está organizado de la siguiente manera:

```text
SecureComm/
├─ apps/
│  └─ client-electron/     # Cliente: React + Vite + Electron
├─ packages/
│  └─ crypto-sdk/          # SDK criptográfico en TypeScript (libsodium)
├─ services/
│  └─ backend/             # API Backend: FastAPI + PostgreSQL + Redis
├─ infra/
│  └─ nginx/               # Configuración de Reverse Proxy TLS 1.3
├─ scripts/                # Utilidades de CI locales (linting y testing)
├─ docker-compose.yml      # Orquestación de servicios
└─ package.json            # Configuración de workspaces de Node.js
```
## Requisitos Previos
Asegúrate de tener instalados los siguientes componentes:
```
Node.js: v20 o superior
npm: v10 o superior
Python: v3.12 o superior
Docker Engine: v26+ y Docker Compose v2.27+
```
## Configuración Inicial
Variables de Entorno: Copia el archivo de ejemplo y ajusta los valores según sea necesario:
```
Bash

cp .env.example .env
```
Certificados TLS (Desarrollo): Para habilitar HTTPS localmente, genera certificados autofirmados en la ruta esperada por Nginx:
```
Bash
mkdir -p infra/nginx/certs
openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout infra/nginx/certs/dev.key \
  -out infra/nginx/certs/dev.crt \
  -days 365 \
  -subj "/CN=localhost"
```
## Flujo de Desarrollo (Local)
Frontend y SDK (JavaScript/TypeScript)
Instala las dependencias y ejecuta validaciones desde la raíz:
```
Bash

npm install                     # Instala dependencias de todos los workspaces
npm run lint --workspaces       # Ejecuta el linter
npm run test --workspaces       # Ejecuta las pruebas unitarias
Backend (Python)
Se recomienda el uso de un entorno virtual:
```
```
Bash

cd services/backend
python -m venv .venv
source .venv/bin/activate       # En Windows: .venv\Scripts\activate
pip install -e .[dev]           # Instala dependencias de desarrollo
uvicorn securecomm_backend.main:app --reload --port 8000
``` 
# Flujo con Docker (Stack Completo)
Levanta todo el ecosistema (Base de datos, Redis, Backend, Frontend y Proxy) mediante Docker Compose:

## Construir y levantar:
```
Bash

docker compose build
docker compose up -d
```
## Servicios expuestos:

App/API (Nginx): https://localhost

Backend Directo: http://localhost:8080

## Limpieza:
```
Bash

docker compose down -v
```
## Pruebas y Calidad
Puedes ejecutar las validaciones globales usando los scripts incluidos:
```
Linting: ./scripts/lint.sh

Tests: ./scripts/test.sh
```
Endpoints de Verificación
```
GET /health: Estado de la API

GET /version: Versión actual (0.1.0)

WS /ws/echo: WebSocket para pruebas de eco (requiere JWT válido)
```
## Stack Tecnológico
```
Backend: FastAPI, SQLAlchemy (PostgreSQL), Redis, PyJWT.
Frontend: React, Vite, Electron.
Criptografía: libsodium-wrappers para implementación de protocolos seguros.
Infraestructura: Nginx con TLS 1.3, HSTS y HTTP/2.
```
Nota: El SDK criptográfico se encuentra en su fase inicial preparando la implementación de X3DH y Double Ratchet.