# SecureComm Project Layout

```
.
├── .env.example
├── .gitignore
├── README.md
├── apps/
│   └── client-electron/
│       ├── .dockerignore
│       ├── Dockerfile
│       ├── electron/
│       ├── index.html
│       ├── nginx.conf
│       ├── package.json
│       ├── src/
│       ├── tsconfig.json
│       ├── vite.config.ts
│       ├── vitest.config.ts
│       └── vitest.setup.ts
├── docker-compose.yml
├── eslint.config.js
├── infra/
│   └── nginx/
│       ├── certs/
│       └── conf.d/
├── package.json
├── packages/
│   └── crypto-sdk/
│       ├── package.json
│       ├── src/
│       ├── tsconfig.json
│       └── vitest.config.ts
├── scripts/
│   ├── lint.sh
│   └── test.sh
├── services/
│   └── backend/
│       ├── .dockerignore
│       ├── Dockerfile
│       ├── pyproject.toml
│       ├── securecomm_backend/
│       ├── setup.cfg
│       └── tests/
└── tsconfig.base.json
```

## Initialization Guide

Follow these steps to bootstrap the stack from a clean checkout.

### 1. Populate environment variables

```bash
cp .env.example .env
```

Review the new `.env` file and adjust secrets, passwords, and hostnames as needed.

### 2. Install local dependencies (optional for non-Docker workflows)

#### JavaScript workspaces
```bash
npm install
```

#### Python backend
```bash
cd services/backend
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]
cd ../..
```

### 3. Run quality checks locally

```bash
./scripts/lint.sh
./scripts/test.sh
```

### 4. Build and run with Docker Compose

```bash
docker compose build
docker compose up -d
```

Access the services through Nginx on `https://localhost` with the certificates provided in `infra/nginx/certs/` (self-signed for local usage).

### 5. Stop and clean up containers

```bash
docker compose down --volumes
```

Run `docker compose logs -f <service>` as needed to inspect container output.
