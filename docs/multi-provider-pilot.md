# v0.5 Multi-provider Router — developer candidate

**NOT for production deployment yet.** The tested HomeDocker v0.3.0 stable / v0.4 admin pilot remain the safe baselines.

## Implemented

- Add/edit/delete encrypted provider profiles in private Web UI, with passwords write-only and source labels / priority.
- Each provider has a unique immutable ID, independent Movie/Series/episode index, separate JIT cache and status.
- Supports the same numeric Xtream stream ID in two different providers without conflicts.
- Provider-specific signed v3 playback URL includes provider ID and a hidden credential revision in its HMAC. Old v2 URLs remain scoped to the legacy .env provider.
- Admin can sync each provider catalog, then activate or disable it. One provider failure does not suppress healthy providers.
- One-time encrypted import of the legacy .env provider, with opt-in hiding of legacy source from NEW stream results after an active replacement is ready. Previously signed legacy links remain valid.
- Credential URL/username/password edits require disabling provider first. Connection changes invalidate old HMAC v3 URLs, remove that provider's cached index, and require re-index.
- Hard opt-in flag XTREAM_MULTIPROVIDER_ENABLED=0 (default). When off, all existing Movie and Series operations remain unchanged.

## Production blockers / gates

1. CI and CodeQL PASS including provider ID collisions, cross-provider HMAC replay, disabled source, key permissions, rotation and original playback compatibility.
2. Runtime SSRF hardening still needed: currently public DNS is checked before outbound HTTPX requests, but DNS rebinding between validation and connection remains a risk. Pin destination IP or use audited public-IP-only connection enforcement and test it before turning this feature on for production.
3. Real-world CDN redirect behavior must be validated per provider with limited domain/IP policies. Do not copy one provider's broad public-IP downgrade rule to all without explicit approval.
4. Use scripts/provision_provider_key.py manually as root on Linux and keep the secret outside SQLite. Use optional compose.provider-vault.example.yaml to mount the pre-existing key read-only into both containers, never exposing the Docker socket.
5. Add the key to encrypted restic backup and test disaster recovery of BOTH SQLite and key; losing the key makes credentials unreadable. Back up legacy .env before any migration.
6. Admin must be served to LAN devices over verified HTTPS only, using the reviewed nginx host listener. Never bind admin HTTP directly to 0.0.0.0. No ASUS port forward.
7. Stage real multiple-provider playback using copied SQLite and keys; Movie and Series HTTP Range PASS, same IMDb across different providers, seek, media filename, quality, 429/timeouts, and source priority.
8. After pilot success, merge and deploy a pinned commit; then import current legacy .env, sync/activate it, add/sync/activate secondary provider, and only then optionally hide the legacy source.
9. Rollback is XTREAM_MULTIPROVIDER_ENABLED=0 and restart only the bridge. Avoid docker compose down -v.

**Current status:** offline implementation is not a production certification; do not enable on HomeDocker before the remaining gates are cleared.
