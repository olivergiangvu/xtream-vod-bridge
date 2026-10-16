# Using Xtream VOD Unified v0.6.0

[Home](../README.md) · [Install](install.md) · [Operations](operations.md)

These are the actual Admin/User UI labels observed during HomeDocker acceptance, not inferred future features.

## 1. Sign in

Open the approved HTTPS hostname at `https://YOUR_FQDN:18450/admin/`. Unauthenticated visitors should be redirected to `/admin-signin/`. Sign in with your assigned Owner/Admin or User account; never enter IPTV provider credentials into the application login form. The Owner account is the initial Admin. Logout via **Lock** to revoke the browser session.

`/admin/` must be protected by nginx auth_request. Do **not** access unprotected backend root, `/api` or `/assets` over public WAN.

## 2. My Workspace → My Sources & Addons

![Operator-provided screenshot: My Workspace, My IPTV Sources and Personal Manifests](screenshots/ui-workspace.webp)

The **My IPTV Sources** panel lets each account:
- Add a private source: display name → source type **Xtream Codes** or **M3U Playlist URL**.
- For Xtream: enter an **HTTPS** server URL, provider username and password. For M3U: use an **HTTPS** playlist URL. Use authorized providers only.
- **Test** source connectivity; **Sync VOD** to index eligible Movies/Series; optionally Edit, Disable or Delete a source. The UI may display `untested`, and connecting a provider does **not** automatically prove its stream playback works.
- Provider passwords and private M3U URLs are encrypted server-side with `SOURCE_SECRETS_KEY`, never returned in clear to browser source lists.

**Personal Manifests** panel: select one or more sources, enter addon display name, choose **Create manifest**. Copy the resulting private URL **immediately**: it is shown only once; later use **Rotate** to invalidate the old URL, and Disable/Delete to revoke access.

Do not paste manifest URLs into issues, screenshots, public browsers, or support chats; a URL is a bearer capability. To connect to AIOStreams, enter it privately as a Custom Addon and verify Movie/Series results and real byte-range playback on the authorized device.

### Status of personal playback

The UI, private source forms, RBAC and manifest lifecycle are implemented. **End-to-end new-provider manifest→real player playback was not fully demonstrated** at v0.6.0 acceptance. Test with your own provider before replacing fallback addons.

## 3. System Administration (Admin only)

![Operator-provided screenshot: Owner/System Administration and catalog counts](screenshots/ui-admin.webp)

The Owner/Admin can access:
- **User Management**: create User accounts, disable users, rotate/reset credentials. The built-in Owner stays the Admin.
- **Operations at a glance**: catalog Movie/Series/Episode counts and JIT metrics; they are instance data that change over time.
- **Refresh stats**: refresh Admin statistics without triggering a full provider catalog refresh.
- **System settings**: permitted ingestion quotas, on-demand/metadata controls where available; do not change upstream/CDN allowlists through a screenshot-driven guess.

Regular User accounts must not gain system-wide admin controls. Use encrypted restic backups for both SQLite and the matching environment secrets.

## 4. Legacy addon compatibility

Existing `/a/<token>/manifest.json` and signed `/play/*` clients were tested working after the Unified cutover; legacy AIOStreams integration remains intact. Addon priorities and sorting are managed in AIOStreams, not dictated by this bridge. Do not paste token-bearing URLs into public reports.

## 5. Troubleshooting

| Symptom | Check |
| --- | --- |
| Browser `/admin/` redirects to sign-in | Expected when not authenticated; sign in |
| UI JavaScript fails to load | Verify a *tested* image with frontend assets readable by UID 10001 |
| `/ready` not 200 | SQLite volume, permissions, one writer and app logs |
| Source Test succeeds, no streams | Run a source-specific Sync VOD; inspect provider media IDs, quotas and allowed CDN redirects; success is not guaranteed |
| Private manifest no longer works | Verify user/source enabled, manifest not rotated/deleted, and configured public origin |
| Movie works, series missing | Source episode hydration/JIT settings; matching IMDb/TMDb IDs, season/episode shape |
| Browser works but Dockhand shows Untracked | Read [Dockhand adoption](operations.md#dockhand-internal-stack-and-permissions) |

See the [operator's screenshot notes](screenshots/README.md) and [open issue register](issue-triage-v0.6.md).
