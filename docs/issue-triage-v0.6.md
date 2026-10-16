# v0.6.0 GitHub issue & pull-request triage

Release baseline: [v0.6.0](https://github.com/olivergiangvu/xtream-vod-bridge/releases/tag/v0.6.0) · Original consolidation: [PR #45](https://github.com/olivergiangvu/xtream-vod-bridge/pull/45).

This document distinguishes **verified acceptance** from architecture proposals and old draft development chains. Closed does not mean every feature proposed in an old PR is shipped. Individual source branches/history are retained; old PRs can be closed *unmerged* after consolidation without rewriting the release history.

## Verified release fixes

- Single-container Unified backend; private Owner/User UI and protected Safari login; same :18450 HTTPS, legacy addon manifest and existing playback compatibility.
- Non-root JS asset file permission fix; nginx default-deny/public allowlist and session-gated Admin paths.
- Canonical Compose production ownership, local legacy/Canary cleanup, 22 obsolete image tag removals, Dockhand adoption from Untracked → Internal.
- Source CodeQL finding for legacy TLSv1/TLSv1_1 fingerprint probe fixed by TLS >=1.2 and regression test.

These are documented in [acceptance](release/0.6-unified-stable-gates.md) and [operations](operations.md).

## Still OPEN — 4 verified unresolved issues

| Issue | Why it remains open |
| --- | --- |
| [#27](https://github.com/olivergiangvu/xtream-vod-bridge/issues/27) | DNS rebind / TOCTOU safety for real TCP targets and every redirect hop not demonstrated end-to-end |
| [#19](https://github.com/olivergiangvu/xtream-vod-bridge/issues/19) | Series JIT source/tests exist, but all original *live cold-Series* performance/acceptance criteria were not demonstrated |
| [#18](https://github.com/olivergiangvu/xtream-vod-bridge/issues/18) | Grace-period pruning for transient Series list omissions not proven deployed |
| [#14](https://github.com/olivergiangvu/xtream-vod-bridge/issues/14) | AIOMetadata anime ID crosswalk, downstream player/Trakt tests pending |

## Superseded / closed as not planned

- [#22](https://github.com/olivergiangvu/xtream-vod-bridge/issues/22) requested a **separate LAN-only HTTPS admin listener**. The accepted design reuses **existing HTTPS :18450**, with gated `/admin/` and loopback app port 18769. **Closed: not planned/superseded**, not completed verbatim.
- [#1](https://github.com/olivergiangvu/xtream-vod-bridge/issues/1) was the exhaustive **v0.1.2 pre-production checklist**, including old port 18767 and provider/CDN/player/DR tests. **Closed: not planned/superseded** by the v0.6.0 migration and [current production checklist](production-checklist.md). This does **not** claim all legacy checks, new personal-provider playback, rate limiting or full new-hardware DR have passed.
- [#23](https://github.com/olivergiangvu/xtream-vod-bridge/issues/23) proposed a **system-wide provider registry with transactional global table migration**. v0.6.0 instead ships **per-user encrypted Xtream/M3U sources with scoped manifests** and retains the legacy global index. **Closed: not planned/superseded**; the global registry, global provider selection/aggregation, and migrations are **not implemented or asserted fixed**. Any renewed global-registry request needs a newly scoped proposal.

## Stale PR cleanup

Old draft PRs of v0.4/v0.5 form a dependency chain of feature branches. PR #45 consolidated them into the release. Retire those stale PRs with a concise explicit pointer to #45 and current limitations; close as unmerged rather than merging their historical commit graphs into `main` again.

The separate old 3-role proposal (Owner/Admin/Viewer) was superseded by **Admin/User**, and experimental separate :18451 Canary TLS work was retired on migration. Early multi-provider global registry PRs do not imply that global multi-provider functionality was shipped. Dependency/Dependabot PRs require separate review and must not be marked fixed solely because a stable release exists.

## Offsite DR and binary provenance

The release remains **source-only**. The known-good HomeDocker image was locally hotfixed from Canary, with no verified bytewise clean-source rebuild. Previously verified OneDrive snapshot `4cee1ca2` predates the post-cleanup legacy archives; a later successful scheduled backup has not yet been verified in this project log. No claim of completed full bare-metal restore.
