#!/usr/bin/env python3
"""Pre-provision fast, isolated Lunary environments for the 23-CVE benchmark.

Each CVE gets:
  runs/<CVE>/env/docker-compose.yml
  runs/<CVE>/INFRA.md
The app source comes read-only from bench_cache; node_modules comes from the
tmpfs prebuilt tree (/dev/shm/bacgenie-nm/<version>); Postgres data lives on tmpfs.
No docker build and no npm install at run time.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path("/hdd1/congxy/AAPaper/NewIdea/BACGenie/bacgenie")
BASE = ROOT.parent
BENCH = json.loads((ROOT / "experiment/benchmark_23.json").read_text())
SRC = BASE / "bench_cache/sources"
NM = Path("/dev/shm/bacgenie-nm")

TEMPLATE = """name: {comp}

services:
  db:
    image: postgres:15
    container_name: bacgenie-{cve_l}-db
    restart: "no"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: {pgpass}
      POSTGRES_DB: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 2s
      timeout: 3s
      retries: 60
    ports:
      - "127.0.0.1:{db_port}:5432"
    tmpfs:
      - /var/lib/postgresql/data:size=1g

  api:
    image: node:20-bookworm-slim
    container_name: bacgenie-{cve_l}-api
    restart: "no"
    depends_on:
      db:
        condition: service_healthy
    working_dir: /app
    command: ["bash", "-lc", "export PATH=/app/node_modules/.bin:$$PATH && npm -w packages/backend run migrate:db && npm -w packages/backend run start"]
    environment:
      DATABASE_URL: postgresql://postgres:{pgpass}@db:5432/postgres
      JWT_SECRET: {jwt}
      SKIP_EMAIL_VERIFY: "true"
      IS_SELF_HOSTED: "false"
      DEFAULT_PLAN: free
      PORT: "3333"
      APP_URL: http://127.0.0.1:{app_port}
      API_URL: http://127.0.0.1:{app_port}
      NODE_OPTIONS: --max-old-space-size=2048
    ports:
      - "127.0.0.1:{app_port}:3333"
    volumes:
      - {nm_tree}:/app
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:3333/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
      interval: 3s
      timeout: 5s
      retries: 80
      start_period: 60s
"""

INFRA = """# {cve} 预置靶场（请直接复用，禁止重建/重装）

- 应用：{project} {version}
- 应用源码+依赖（tmpfs，直接挂载到 /app）：`{nm_tree}`（源码来自 `{src}`）
- 宿主端口：应用 `http://127.0.0.1:{app_port}`，数据库 `127.0.0.1:{db_port}`
- compose 项目名：`{comp}`，容器 `bacgenie-{cve_l}-api` / `bacgenie-{cve_l}-db`
- 启动：`cd runs/{cve}/env && COMPOSE_PROJECT_NAME={comp} docker compose up -d --wait`
- 停止/清空：`COMPOSE_PROJECT_NAME={comp} docker compose down -v`
- **不要**执行 `docker compose build`、`npm install` 或修改 Dockerfile；本环境不需要构建。
- 漏洞入口与契约见 `runs/{cve}/01_tp.json` 与 `02_oracle_contract.json`。
"""


def main():
    cves = sys.argv[1:] or [e["cve"] for e in BENCH]
    for i, e in enumerate(BENCH):
        cve = e["cve"]
        if cve not in cves or e["project"] != "Lunary":
            continue
        ver = e["version"]
        src = SRC / f"Lunary_{ver}"
        nm_tree = NM / f"Lunary_{ver}"
        nm = nm_tree / "node_modules"
        if not src.exists() or not nm.exists():
            print(f"SKIP {cve}: missing {src} or {nm}")
            continue
        env = ROOT / "runs" / cve / "env"
        env.mkdir(parents=True, exist_ok=True)
        # Writable per-CVE source copy on tmpfs (app may write caches/logs).
        src_run = Path("/dev/shm/bacgenie-src") / cve
        if src_run.exists():
            import shutil as _sh
            _sh.rmtree(src_run)
        src_run.mkdir(parents=True, exist_ok=True)
        import shutil as _sh
        for item in src.iterdir():
            if item.name == ".git":
                continue
            dst = src_run / item.name
            if item.is_dir():
                _sh.copytree(item, dst, symlinks=True)
            else:
                _sh.copy2(item, dst)
        (src_run / "node_modules").mkdir(exist_ok=True)
        app_port = 21000 + i
        db_port = 23000 + i
        comp = "bacgenie_" + cve.lower().replace("-", "_")
        cve_l = cve.lower()
        pgpass = f"bacgenie_pg_{cve_l.replace('-', '_')}"
        jwt = f"bacgenie_jwt_{cve_l.replace('-', '_')}_fixed_secret"
        text = TEMPLATE.format(
            comp=comp, cve=cve, cve_l=cve_l, src=src, src_run=src_run, nm=nm, nm_tree=nm_tree,
            app_port=app_port, db_port=db_port, pgpass=pgpass, jwt=jwt,
        )
        (env / "docker-compose.yml").write_text(text, encoding="utf-8")
        (ROOT / "runs" / cve / "INFRA.md").write_text(
            INFRA.format(
                cve=cve, project=e["project"], version=ver, src=src, src_run=src_run, nm=nm, nm_tree=nm_tree,
                app_port=app_port, db_port=db_port, comp=comp, cve_l=cve_l,
            ),
            encoding="utf-8",
        )
        print(f"OK {cve} app={app_port} db={db_port} ver={ver}")


if __name__ == "__main__":
    main()
