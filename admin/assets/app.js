'use strict';
let adminToken = '';
const $ = (id) => document.getElementById(id);
const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : '—');
const asInt = (id) => Number.parseInt($(id).value, 10);
let polling = null;

async function api(path, method = 'GET', value = undefined) {
  const response = await fetch(path, {
    method,
    cache: 'no-store',
    headers: {
      'Authorization': 'Bearer ' + adminToken,
      'Accept': 'application/json',
      ...(value === undefined ? {} : {'Content-Type': 'application/json'}),
    },
    ...(value === undefined ? {} : {body: JSON.stringify(value)}),
  });
  if (response.status === 401) throw new Error('Authentication rejected. Check ADMIN_TOKEN.');
  if (!response.ok) {
    if (response.status === 422) {
      const failure = await response.json();
      throw new Error(String(failure.detail || 'Invalid setting'));
    }
    throw new Error('Service returned HTTP ' + response.status);
  }
  return response.json();
}

function draw(data, setForm = false) {
  const health = data.bridge || {};
  const stats = health.index || {};
  const jit = health.jit || {};
  const ready = health.series_progress || {};
  const env = data.effective_env || {};
  $('bridgeState').textContent = health.status === 'ok' ? '● Bridge healthy' : '○ Bridge unavailable';
  $('bridgeState').className = 'state' + (health.status === 'ok' ? ' success' : ' warn');
  $('movies').textContent = fmt(stats.movie?.total);
  $('series').textContent = fmt(stats.series?.total);
  $('episodes').textContent = fmt(health.episodes);
  $('hits').textContent = fmt(jit.cache_hit);
  $('version').textContent = 'v' + (health.version || '?');
  $('health').textContent = health.status || 'unavailable';
  $('readySeries').textContent = fmt(ready.with_episodes);
  $('pending').textContent = fmt(ready.pending_enrichment);
  $('fetchOk').textContent = fmt(jit.fetch_ok);
  $('jitErrors').textContent = fmt((jit.fetch_failed || 0) + (jit.timeout || 0));
  $('bootstrap').textContent = String(env.bootstrap_batch ?? '—');
  $('redirect').textContent = env.redirect_mode || '—';
  $('lastCheck').textContent = 'Updated ' + new Date().toLocaleTimeString();
  if (setForm) {
    const s = data.settings || {};
    $('sourceLabel').value = s.source_label || 'IPTV VOD';
    $('onDemand').checked = s.series_on_demand === true;
    $('timeout').value = s.series_jit_timeout_seconds ?? 8;
    $('ttl').value = s.series_jit_ttl_hours ?? 6;
    $('cooldown').value = s.series_jit_retry_seconds ?? 120;
    $('variants').value = s.series_jit_max_variants ?? 8;
    $('seriesQuota').value = s.series_enrich_per_sync ?? 0;
    updatePreview();
  }
  const tbody = $('events');
  tbody.replaceChildren();
  if (!data.events?.length) {
    const row = tbody.insertRow();
    const cell = row.insertCell(); cell.colSpan = 4;
    cell.textContent = 'No events yet'; cell.className = 'muted';
  } else {
    for (const ev of data.events) {
      const row = tbody.insertRow();
      [new Date(ev.ts * 1000).toLocaleTimeString(), ev.kind + ' · ' + ev.event,
       ev.status, String(ev.duration_ms) + 'ms / ' + String(ev.amount)]
        .forEach(x => { const cell = row.insertCell(); cell.textContent = x; });
    }
  }
}

function updatePreview() {
  $('previewName').textContent = ($('sourceLabel').value.trim() || 'IPTV VOD') + ' 2160p';
}

async function refresh(setForm = false) {
  const data = await api('/api/overview');
  draw(data, setForm);
}

$('sourceLabel').addEventListener('input', updatePreview);
$('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const candidate = $('secret').value.trim();
  $('loginError').textContent = '';
  adminToken = candidate;
  try {
    await refresh(true);
    $('secret').value = '';
    $('login').hidden = true; $('main').hidden = false;
    $('refresh').hidden = false; $('logout').hidden = false;
    if (polling) clearInterval(polling);
    polling = setInterval(() => refresh(false).catch(() => {
      $('bridgeState').textContent = 'Refresh failed';
    }), 15000);
  } catch (error) {
    adminToken = '';
    $('loginError').textContent = error.message;
  }
});

$('settingsForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const fields = {
    source_label: $('sourceLabel').value.trim(),
    series_on_demand: $('onDemand').checked,
    series_jit_timeout_seconds: asInt('timeout'),
    series_jit_ttl_hours: asInt('ttl'),
    series_jit_retry_seconds: asInt('cooldown'),
    series_jit_max_variants: asInt('variants'),
    series_enrich_per_sync: asInt('seriesQuota'),
  };
  $('save').disabled = true;
  $('saveStatus').textContent = 'Saving…';
  try {
    await api('/api/settings', 'PUT', fields);
    $('saveStatus').textContent = 'Saved. New stream requests use these settings.';
    await refresh(false);
  } catch (error) {
    $('saveStatus').textContent = error.message;
  } finally {
    $('save').disabled = false;
  }
});

$('refresh').addEventListener('click', async () => {
  try { await refresh(false); } catch (error) { $('bridgeState').textContent = error.message; }
});

$('logout').addEventListener('click', () => {
  adminToken = '';
  if (polling) { clearInterval(polling); polling = null; }
  $('main').hidden = true;
  $('login').hidden = false;
  $('refresh').hidden = true; $('logout').hidden = true;
  $('bridgeState').textContent = 'Not connected';
  $('sourceLabel').value = '';
  $('loginError').textContent = '';
});
