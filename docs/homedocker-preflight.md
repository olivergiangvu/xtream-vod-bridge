# HomeDocker read-only preflight

**Stage:** SSH inventory only. Do not create `.env`, forward a new port,
modify nginx, restart containers, or change AIOStreams source priority until
this review is complete.

From HomeDocker after cloning this repository:

```bash
cd /opt/xtream-vod-bridge
sudo python3 scripts/preflight_homedocker.py --port 18767
```

The script reports Docker availability, whether port `18767` is already bound
or published, basic nginx test status, an existing `/xtream-vod/` location,
and a readiness label. It performs **no writes**, and never prints Docker
environment variables, credentials, addon tokens, or playback URLs. It does not
reveal provider configuration. It only scans typical nginx `conf.d` and
`sites-enabled` locations: a negative location result **does not prove** there
are no locations in separately included configuration files.

Exit codes: `0` means no detected conflicts and prerequisites passed; `2`
means investigate first. This is not a production readiness certification.

To add a URL format check without passing credentials, use
`--public-base-url https://YOUR_DOMAIN/xtream-vod`. Do not include any addon
token or query string in this value. The script intentionally does not attempt
IPTV provider or external reachability checks.

Next steps after results are reviewed:

1. Keep existing nginx and Docker stacks untouched; choose an unused localhost
   port and validate current HTTPS routing.
2. Configure provider details **locally** in a private `.env` file, and test
   a single known movie/series with the local smoke test.
3. Confirm provider connections, redirects, streaming, and egress before
   enabling the Custom Addon in AIOStreams.
4. Only then enable Addon-first sorting and check fallback behavior.
5. Add persistent index/critical secrets to encrypted Restic→OneDrive DR and
   validate restore; keep Version Center **monitor-only**.

If the script cannot access Docker, run it as root using `sudo` as above.
Do not paste `.env`, provider URLs, `docker inspect`, or generated signed
playback links into public Issues, pull requests, or this chat.
