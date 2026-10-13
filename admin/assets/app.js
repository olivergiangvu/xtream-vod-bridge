'use strict';
let adminToken = ''; // Emergency bearer auth only; never stored in browser storage.
let csrfToken = ''; // Random per-session CSRF value; held in JS memory only.
// Relative to this document: /admin/ -> /admin/api/; direct / -> /api/.
// Do not route admin API requests to the public addon /api/ root on 18450.
const adminApiRoot = new URL('api/', document.baseURI);
const $ = (id) => document.getElementById(id);
const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : '—');
const asInt = (id) => Number.parseInt($(id).value, 10);
let polling = null;
let refreshInFlight = null;

async function api(path, method = 'GET', value = undefined) {
  const suffix = path.startsWith('/api/') ? path.slice('/api/'.length) : path;
  const mutating = ['PUT', 'POST', 'PATCH', 'DELETE'].includes(method);
  const response = await fetch(new URL(suffix, adminApiRoot), {
    method,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: {
      ...(adminToken ? {'Authorization': 'Bearer ' + adminToken} : {}),
      ...(!adminToken && mutating ? {'X-CSRF-Token': csrfToken} : {}),
      'Accept': 'application/json',
      ...(value === undefined ? {} : {'Content-Type': 'application/json'}),
    },
    ...(value === undefined ? {} : {body: JSON.stringify(value)}),
  });
  // nginx redirects expired /admin/ sessions to the public sign-in gateway.
  // A redirected HTML page is not an API success response.
  if (response.redirected && new URL(response.url).pathname.startsWith('/admin-signin/')) {
    if (window.location.pathname.startsWith('/admin/')) {
      window.location.replace('/admin-signin/');
    }
    throw new Error('Session expired; opening sign-in.');
  }
  if (response.status === 401) throw new Error('Please sign in again.');
  if (!response.ok) {
    if (response.status === 422) {
      const failure = await response.json();
      throw new Error(String(failure.detail || 'Invalid setting'));
    }
    throw new Error('Service returned HTTP ' + response.status);
  }
  if (!(response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
    throw new Error('Unexpected API response (expected JSON).');
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

function refreshFeedback(message, failed = false) {
  const status = $('refreshStatus');
  status.hidden = !message;
  status.textContent = message;
  status.className = failed ? 'small notice' : 'small muted';
}

async function refresh(setForm = false) {
  // Manual clicks and the 15-second poll share the same in-flight read.
  // Neither path writes to /api/settings or overwrites unsaved form inputs.
  if (refreshInFlight) {
    if (!setForm) return refreshInFlight;
    await refreshInFlight;
  }
  const current = api('/api/overview').then(data => {
    draw(data, setForm);
    return data;
  });
  refreshInFlight = current;
  try {
    return await current;
  } finally {
    if (refreshInFlight === current) refreshInFlight = null;
  }
}

$('sourceLabel').addEventListener('input', updatePreview);
async function showDashboard() {
  await refresh(true);
  $('secret').value = '';
  $('legacySecret').value = '';
  $('login').hidden = true;
  $('main').hidden = false;
  $('refresh').hidden = false;
  $('logout').hidden = false;
  refreshFeedback('');
  if (polling) clearInterval(polling);
  polling = setInterval(() => {
    if (refreshInFlight) return;
    refresh(false).catch(error => {
      $('bridgeState').textContent = 'Stats unavailable';
      $('bridgeState').className = 'state warn';
      refreshFeedback('Auto-refresh failed: ' + error.message, true);
    });
  }, 15000);
}

$('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('loginError').textContent = '';
  adminToken = '';
  csrfToken = '';
  const password = $('secret').value;
  try {
    const response = await fetch(new URL('auth/login', adminApiRoot), {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
      body: JSON.stringify({password}),
    });
    if (response.status === 429) throw new Error('Too many attempts. Try again in 15 minutes.');
    if (response.status === 503) throw new Error('Set the Admin password on HomeDocker via SSH first.');
    if (!response.ok) throw new Error('Invalid password, or this access route is not approved.');
    const result = await response.json();
    csrfToken = result.csrf_token;
    await showDashboard();
  } catch (error) {
    $('loginError').textContent = error.message;
  } finally {
    $('secret').value = '';
  }
});

$('legacyLoginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  adminToken = $('legacySecret').value.trim();
  csrfToken = '';
  $('loginError').textContent = '';
  try {
    await showDashboard();
  } catch (error) {
    adminToken = '';
    $('loginError').textContent = error.message;
  } finally {
    $('legacySecret').value = '';
  }
});

async function restoreSession() {
  try {
    const response = await fetch(new URL('auth/session', adminApiRoot), {
      cache: 'no-store', credentials: 'same-origin',
    });
    if (!response.ok) return;
    const result = await response.json();
    $('setupHint').hidden = result.password_ready !== false;
    if (result.authenticated && result.csrf_token) {
      csrfToken = result.csrf_token;
      adminToken = '';
      await showDashboard();
    }
  } catch (_) {
    $('setupHint').hidden = false;
  }
}
restoreSession();

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
  const button = $('refresh');
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = 'Refreshing…';
  refreshFeedback('Checking latest stats…');
  try {
    await refresh(false);
    refreshFeedback('Refreshed at ' + new Date().toLocaleTimeString());
  } catch (error) {
    refreshFeedback('Refresh failed: ' + error.message, true);
  } finally {
    button.textContent = 'Refresh stats';
    button.disabled = false;
  }
});

// The nginx session gate protects all /admin/ URLs, including its JSON APIs.
// After revoking the session, never show the obsolete in-page login form there:
// login must restart at the public /admin-signin/ gateway instead.
$('logout').addEventListener('click', async () => {
  $('logout').disabled = true;
  try {
    if (!adminToken) {
      if (!csrfToken) throw new Error('Session state unavailable; reload and retry.');
      const result = await api('/api/auth/logout', 'POST');
      if (result.authenticated !== false) {
        throw new Error('Server did not confirm session revocation.');
      }
    }
    adminToken = '';
    csrfToken = '';
    if (polling) { clearInterval(polling); polling = null; }
    $('secret').value = '';
    $('legacySecret').value = '';
    $('sourceLabel').value = '';
    refreshFeedback('');
    if (window.location.pathname.startsWith('/admin/')) {
      window.location.replace('/admin-signin/');
      return;
    }
    // Retain the legacy in-page form ONLY for direct loopback/SSH admin URLs.
    $('main').hidden = true;
    $('login').hidden = false;
    $('refresh').hidden = true; $('logout').hidden = true;
    $('bridgeState').textContent = 'Not connected';
    $('loginError').textContent = '';
  } catch (error) {
    // A failed logout must not masquerade as a successfully locked session.
    $('bridgeState').textContent = 'Lock failed: ' + error.message;
    $('bridgeState').className = 'state warn';
  } finally {
    $('logout').disabled = false;
  }
});
