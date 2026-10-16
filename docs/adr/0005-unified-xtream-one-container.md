# ADR-0005 — Unified Xtream runtime and resource-limited Canary

- **Status:** Accepted and implemented on HomeDocker (2026-10-16); historical development plan retained below
- **Date:** 2026-10-15
- **Scope:** Xtream VOD Bridge / HomeDocker (2 logical CPUs)
- **Change control:** Documentation only. This ADR authorizes no live container, Compose, nginx, secret or firewall changes.

## Post-deployment addendum (2026-10-16)

The single-worker container and canonical Compose model are now live. Canary/legacy cutover instructions below document the *design history*, not current runnable production tasks. See [production acceptance record](../release/0.6-unified-stable-gates.md) for the file-mode hotfix, nginx auth race, default-deny hardening and remaining DR obligations. The locally patched production image is not yet proven equivalent to a clean build from this commit.

## Decision

**The steady-state deployment is ONE production container, ONE Uvicorn process,
ONE ASGI application, ONE private data volume and ONE backend listener.**
The playback/API routes and the authenticated Owner/User Admin console are
two route modules of the **same process**, not independent Docker services.
"One container" must not mean two independently running Uvicorn processes
inside one container.

An additional **one-container Canary may exist temporarily for development
and release verification** (maximum 2 Xtream containers while staging).
Canary must have an explicit lifecycle: start → run bounded acceptance tests →
stop/remove its container after approval; retain its image, source and
rollback backup for future recovery. No routine four-container deployment.
Never remove or alter the currently running production services as a
side effect of implementing this ADR.

### Observed baseline (not a causation claim)

The current **running** topology has 2 production and 2 Canary containers.
During 30-second cgroup accounting, Canary Admin used approximately
12.2–14.6% of **one logical CPU**, and Canary Playback used 10.5%.
The whole host has 2 logical CPUs and reported intermittent PSI avg10 of
roughly 20–60%; these are single-window measurements, not idle-only
steady-state benchmarks. Admin workload may include healthchecks, incoming
requests, interpreter startup and framework/runtime costs.

Source review:
- `admin_ui.py` imports `app as bridge`, loading Playback code and its
  dependencies into the separate Admin Uvicorn process.
- `app.py` owns scheduled Xtream sync/bootstrap in its ASGI lifespan;
  `admin_ui.py` has separate initialization/lifespan. A merged runtime must
  initialize all stores and schedule background work **exactly once**.
- `app.py /health` computes index/episode statistics by running multiple
  SQLite queries; it is not an O(1) liveness check.
- Canary Compose healthcheck interval is currently 10s for **both** services,
  spawning an extra Python interpreter for each check. Production Compose
  checks each service every 30s. This is avoidable recurring resource work.

The above identifies candidates to profile; it does **not** prove that
healthchecks or Admin alone caused high host CPU PSI.

## Target logical topology

```text
HTTPS :18450 — existing host nginx + existing LAN/auth protection
  /a/*, /play/*            -> single Xtream ASGI server: playback API
  /admin-signin/*          -> same ASGI server: gateway/login
  /admin/*                 -> same ASGI server: protected Admin UI/API
  internal auth_request    -> same ASGI server: gate-check (nginx internal)
                                     |
                               single process
                        [FastAPI + scheduled sync]
                                     |
                            /data persistent store
```

The internal Admin ASGI mount/root-path must remain unreachable from public
routes except through reviewed nginx locations. The production root route
behavior and existing public manifest URLs MUST remain stable. Preserve
separate Owner and User permissions, CSRF Origin checks, secure cookie Path,
nonce names, and no secret leakage; **same host origin is not browser-JS
isolation**. Check gateway Referrer-Policy and mounted path matching explicitly.

Implement either an ASGI mount with correct root_path/path and lifespan
handling or a safe APIRouter refactor; use **one Uvicorn worker** initially
because multiple workers could duplicate background sync. The single parent
ASGI lifespan initializes stores and owns sync tasks exactly once. Do not
rely on FastAPI child-app lifespan automatically executing when mounted.

## Resource and cleanup contract

1. **Admin is event-driven.** No polling, sync loop, periodic cache rebuild,
   independent scheduler or second provider-client runtime solely for Admin.
   Measure its request-triggered CPU and incremental memory before claiming
   Admin is negligible.
2. Split **`/live`** (constant-time, no SQLite counts/upstream calls) from
   **`/ready`** (cheap bounded DB reachability check). Move full statistics
   currently computed by `/health` to a privileged/on-demand diagnostics
   endpoint, or preserve response compatibility via cached snapshot.
   Regressions on existing health consumers are not acceptable.
3. Healthchecks must be a **single inexpensive periodic check**, initially
   30–60 seconds with explicit timeout and bounded failures. Benchmark
   interpreter-spawn CPU before picking implementation.
4. No duplicate scheduled sync, series bootstrap, duplicated provider
   refresh, login-data migration, or hidden background timers. Canary
   disables unnecessary scheduled network work and does not duplicate live
   provider polling. Preserve JIT semantics.
5. Canary data/keys/cookies remain isolated from production. Do not share
   production SQLite write paths, tokens, browser sessions or secret
   filesystem mounts with Canary. Internal network and zero published Canary
   ports remain default unless a reviewed nginx ingress is deployed.
6. New deployment scripts MUST be fail-closed, SHA/commit-pinned,
   plan-before-apply, backup-aware and idempotent; require explicit approval
   for anything that starts/stops/recreates containers. All failed changes
   must verify rollback images, healthy state, private networking, zero new
   host ports and unchanged production container IDs.
7. Cleanup is an explicit final release phase: inventory old containers,
   stopped containers, unused images, Compose overrides, backup retention and
   orphan processes. Clean by **exact allowlisted identities only**, after
   confirmed release acceptance and rollback retention. Never run blanket
   `docker system prune`, `docker volume prune`, generic `docker compose down`,
   or indiscriminate stack removal on HomeDocker.
8. Development jobs must have bounded runtime, concurrency and temporary
   filesystem lifecycle; do not leave idle testing stacks resident. No
   provider secrets or effective Compose env output in diagnostics.

## Migration sequence (no live changes authorized)

**M0 — Freeze legacy rollout.** Preserve Stage4F files, Stage5A.2 built image
and Stage5A.3 backup/rollback design, but **do not run the two-service
Stage5A.3 `--apply`** as the desired final architecture has changed. Existing
production and Canary remain untouched pending migration plan.

**M1 — Read-only baseline.** Measure 5–15 min idle/requested CPU, RSS,
healthcheck spawn counts, DB queries and CFS throttling per container.
Measure server-wide PSI and host/daemon CPU separately. Avoid assigning
causation from 15-second top-process output.

**M2 — Offline one-process implementation.** Add unified ASGI entrypoint,
mount/restructure Admin paths and startup, split cheap liveness/diagnostics
without removing backward-compatible endpoints. Test gateway form, cookies,
session authorization, CSRF, RBAC, URL prefix and streaming. No host impact.

**M3 — One-container isolated Canary.** Build offline immutable image,
activate Canary in **one service** with zero published ports/private network,
bounded health and a defined automatic manual-cleanup procedure. Test direct
Docker-network and nginx-scratch routes; validate no provider polling
duplication. Do not expose new nginx location before LAN/WAN SNAT review.

**M4 — Benchmarks/acceptance.** Compare memory/CPU idle and loaded
conditions versus M1. Acceptance: one uvicorn worker, one scheduler, no
background Admin polling, one healthcheck process, no new published ports;
functional/security regressions zero. Establish exact idle CPU/RSS targets
using M1 measurements, rather than invented fixed percentages.

**M5 — Production cutover and cleanup.** Separate explicit approval, atomic
config/traffic migration, verified rollback, then retire the old extra
service. After successful observation window, stop/remove dormant Canary
by exact identity; keep restorable image and versioned backup.

## Non-goals / hold points

- Do not stop or modify Netdata, Homebridge, CrossWatch, AIOStreams,
  AIOMetadata, Remux, Portainer, WUD or other non-Xtream services.
- Do not assume merging containers by itself halves CPU/RSS.
- Do not run the previously approved Stage5A.3 two-container recreate;
  it was denied at CPU gate and caused no runtime changes. This ADR
  supersedes that roadmap **until a revised migration is explicitly approved**.
- Production HTTPS `:18450`, auth, externally visible APIs and legacy
  client manifests must remain working throughout migration.
