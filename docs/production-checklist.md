# v0.6.0 production and release checklist

This replaces the obsolete v0.1–v0.3 checklist referencing old 18767/18768 ports and a hypothetical future GitHub Release.

## Accepted on HomeDocker (2026-10-16)

- [x] Source-only GitHub v0.6.0 Release published with CI and CodeQL checks PASS.
- [x] One Unified container running, healthy, zero restarts at final check.
- [x] Canonical Compose owner set; exact immutable runtime image ID validated.
- [x] nginx HTTPS :18450 protects `/admin/` and permits signed public addon paths only; public root/API/assets denied.
- [x] Safari Owner login, System Administration, My Workspace UI and existing legacy addon/playback accepted.
- [x] Historical legacy and Canary containers removed; 22 obsolete Xtream image tags removed; SQLite retained.
- [x] Dockhand recognizes canonical stack as **Internal**, production Compose unchanged, minimum effective group ACLs verified.
- [x] Existing Restic/OneDrive snapshot `4cee1ca2` passed integrity and selected path reads.

## Open / deferred (do not mark PASS)

- [ ] Verify a **new scheduled** offsite snapshot includes post-cleanup rollback archive; no extra manual backup requested.
- [ ] Exercise full restore to different hardware; never confuse restic check with restore drill.
- [ ] New personal source → manifest → AIOStreams/player end-to-end tests for authorized Xtream and M3U providers.
- [ ] DNS rebinding/TOCTOU pinning for actual upstream connections and redirect chain (#27), plus provider CDN safety.
- [ ] Dependency/base image digest pinning, reproducibility and clean-source build equivalence to the hotfixed production image.
- [ ] Confirm Dockhand one-click *redeploy* behavior with protected root-only `production.env` on a controlled non-production test; currently Internal registration/editing only.
- [ ] Rate abuse protection and cross-client series/anime ID handling where required.

See [migration acceptance](release/0.6-unified-stable-gates.md) and [open issues](issue-triage-v0.6.md).
