# Repository Guidelines

## Project Structure

This repository is a Docker Compose monorepo that ships a working AntiHub stack:

- `AntiHub/` — Next.js (TypeScript) web UI
- `AntiHub-Backend/` — FastAPI backend (Python, Alembic migrations)
- `AntiHub-plugin/` — Node.js plugin/proxy service (used by the backend)
- `AntiHook/` — Go utilities/binaries
- `docker/` — Compose helpers (e.g. DB init scripts)

Top-level deployment files live at the repo root: `docker-compose.yml`, `docker-compose.core.yml`, `deploy.sh`, `.env.example`.

## Build, Test, and Development Commands

Preferred local flow is via Docker:

```bash
cp .env.example .env
docker compose up -d
```

Use `docker-compose.core.yml` when you provide your own Postgres/Redis:

```bash
docker compose -f docker-compose.core.yml up -d
```

Module development (run inside each folder):

- Web: `cd AntiHub && pnpm install && pnpm dev` (lint: `pnpm lint`, build: `pnpm build`)
- Backend: `cd AntiHub-Backend && uv sync && uv run uvicorn app.main:app --reload`
- Plugin: `cd AntiHub-plugin && npm ci && npm run dev` / `npm start`
- Go: `cd AntiHook && go test ./... && go build ./...`

**AntiHub 对接备注：**

| 层级 | 已对接服务 | 备注 |
|------|-----------|------|
| 后端 (AntiHub-Backend) | CodexCLI | ✅ 新服务统一对接到这里 |
| 插件 (AntiHub-plugin) | Antigravity、Kiro、Qwen | ⛔ 不再新增对接 |

## Coding Style & Naming Conventions

- Keep changes scoped to the module you touch; follow existing patterns in that folder.
- TypeScript: React components in `PascalCase`, variables/functions in `camelCase`; run `pnpm lint`.
- Python: 4-space indentation; keep async routes non-blocking; migrations live in `AntiHub-Backend/alembic/`.
- Go: run `gofmt` on modified files.

Generated artifacts should not be committed (see each module’s `.gitignore`): `.next/`, `node_modules/`, `.venv/`, `__pycache__/`, and binaries in `AntiHook/`.

## Testing Guidelines

There is no single repo-wide test runner today. For changes, run a Docker smoke test (`docker compose up`) and manually verify the affected UI route / API endpoint. Use module-specific scripts/tests when present (for example `AntiHub-plugin/test/`).

## Commit & Pull Request Guidelines

Commit messages generally follow `<type>: <summary>` (common types: `feat:`, `fix:`; `!` indicates breaking changes). PRs should include: what changed, how to verify (exact commands), and screenshots for UI changes. If you add environment variables, update the relevant `*.example` files and document defaults.

