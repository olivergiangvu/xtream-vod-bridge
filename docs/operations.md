# Operations, health and Dockhand — v0.6.0

[Home](../README.md) · [Install](install.md) · [User guide](usage.md)

## Production read-only checks

```bash
sudo docker inspect xtream-vod-unified \
  --format 'STATE={{.State.Status}} HEALTH={{.State.Health.Status}} RESTARTS={{.RestartCount}} IMAGE={{.Image}}'
sudo docker inspect xtream-vod-unified \
  --format 'COMPOSE={{index .Config.Labels "com.docker.compose.project.config_files"}}'
sudo docker compose -f /opt/homedocker/stacks/xtream-vod-unified/compose.yml config -q
curl --noproxy '*' -sS -o /dev/null -w 'READY=%{http_code}\n' http://127.0.0.1:18769/ready
```

Expected image ID: `sha256:7a00ea49da7ff90bcff1823c45b183a779c5ea46424331fa397308c3ab6e1ebd`. Canonical Compose must be `/opt/homedocker/stacks/xtream-vod-unified/compose.yml`, backend bound to loopback 18769, production external SQLite volume mounted at `/data`. During 16 October 2026 acceptance it was Healthy with **0 restarts**; this is not a perpetual uptime claim.

Use `sudo docker logs --tail 50 xtream-vod-unified` locally only; **redact tokens/private URLs before sharing**. Do not enable global Uvicorn access logs that could leak signed URLs.

## Dockhand Internal stack and permissions

The operator's Dockhand **v1.0.53** screenshot confirms `xtream-vod-unified` in the Stacks table with **Source: Internal**, Status: Running, and path under `/opt/homedocker/stacks/`. This is *file-management integration*, not proof that a future one-click redeploy can read root-owned secrets.

Observed file policy on HomeDocker after the ACL repair:

| Path | Owner:group | Unix mode | Purpose |
| --- | --- | --- | --- |
| `/opt/homedocker/stacks/xtream-vod-unified/` | `root:1000` | `0750` | Dockhand (GID 1000) can browse Compose directory |
| `.../compose.yml` | `root:1000` | `0660` | Dockhand can read/edit canonical Compose |
| `.../production.env` | `root:root` | `0600` | No ordinary direct reading by Dockhand UID 1000 |

UID 1000 in the container belongs to the `dockhand` application, GID 1000; its daemon also belongs to the Docker group. Docker control is highly privileged: these Unix file modes **do not sandbox an operator with Docker socket access**. Review who can access Dockhand before permitting redeploy.

ACL warning from original incident: changing `group owner` and running `chmod 750` without checking `group::` ACL entries left effective access denied. `getfacl` showed `group::---` although `ls -l` appeared to grant access. It was resolved by setting both the ACL group entries and masks (`g::r-x,m::r-x` for directory; `g::rw-,m::rw-` for Compose), then verifying inside the Dockhand container.

**Adoption flow:** In Dockhand Stacks, choose the existing Untracked project → select existing absolute `compose.yml` → **Save only**. Do not click **Save & redeploy**, Pull/Update, or generate a second stack pointing to the same SQLite volume. After Save, the UI showed **Internal** and retained one production container. File ownership alone does not prove source-controlled lifecycle updates.

### Future Dockhand redeploy caveat

`production.env` is deliberately root-only and the Dockhand UI shows no environment variables. `env_file: ./production.env` is still required by canonical Docker Compose. A Dockhand-triggered redeploy has **not been tested** against this protected configuration; it may fail or unintentionally replace the running container. Make a point-in-time backup and test config/secrets access under controlled conditions before using any redeploy button. Avoid granting group read on all secret-bearing files just to enable a convenience feature.

## Backups and restore

Restic → rclone → OneDrive scheduling is operated outside this repository. Previously validated snapshot `4cee1ca2` passed integrity and selected restore-path reads. The local rollback archive created *after* that snapshot was **not** yet confirmed on OneDrive in the acceptance log. The operator chose to rely on the already configured scheduled backup rather than run another manual backup; verify a subsequent scheduled snapshot before claiming complete offsite archival.

Never overwrite newer SQLite with pre-cutover rollback checkpoints without accepting loss of all later writes. Full replacement-hardware DR remains untested. See [DR runbook](deployment/homedocker-v0.6.md).

## Version updates and boundaries

The GitHub Release [v0.6.0](https://github.com/olivergiangvu/xtream-vod-bridge/releases/tag/v0.6.0) is **source-only**. Neither GitHub nor Docker Hub provides a verified public v0.6.0 image corresponding to the HomeDocker pinned image SHA. Monitoring `homedocker/xtream-vod-unified:0.6.0-stable` as a locally tagged image will not discover upstream registry updates.

Do not enable blind Dockhand/WUD image pulls for this stack; use new verified image IDs and release acceptance only after rebuilding/testing separately.
