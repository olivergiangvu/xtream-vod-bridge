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
let privateManifest = '';
let adminIdentity = {username: '', role: ''};
let resetTarget = '';


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
  if (response.status === 401) throw new Error('Please sign in again.');
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
async function showDashboard() {
  await refresh(true);
  const session = adminToken
    ? {username: 'owner', role: 'owner'}
    : await (await fetch(new URL('auth/session', adminApiRoot), {
        cache: 'no-store', credentials: 'same-origin'
      })).json();
  adminIdentity = {username: session.username || 'owner', role: session.role || 'owner'};
  $('adminIdentity').textContent = adminIdentity.username + ' · ' + adminIdentity.role;
  $('adminUsersPanel').hidden = adminIdentity.role !== 'owner';
  const writable = adminIdentity.role !== 'viewer';
  for (const el of $('settingsForm').querySelectorAll('input,button')) el.disabled = !writable;
  if (adminIdentity.role === 'owner') await loadAdminAccounts();
  if (adminIdentity.role !== 'viewer') {
    const manifest = await api('/api/manifest');
    privateManifest = manifest.url;
    $('manifestUrl').type = 'password';
    $('manifestUrl').value = privateManifest;
    $('manifestReveal').textContent = 'Show';
    $('manifestStatus').textContent = 'Manifest ready · private addon credential';
  } else {
    privateManifest = '';
    $('manifestUrl').value = '';
    $('manifestStatus').textContent = 'Restricted to Owner/Admin accounts';
    $('manifestCopy').disabled = true;
    $('manifestReveal').disabled = true;
  }
  $('secret').value = '';
  $('legacySecret').value = '';
  $('login').hidden = true;
  $('main').hidden = false;
  $('refresh').hidden = false;
  $('logout').hidden = false;
  if (polling) clearInterval(polling);
  polling = setInterval(() => refresh(false).catch(() => {
    $('bridgeState').textContent = 'Refresh failed';
  }), 15000);
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
      body: JSON.stringify({username: $('loginUsername').value.trim().toLowerCase(), password}),
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
  try { await refresh(false); } catch (error) { $('bridgeState').textContent = error.message; }
});

$('manifestReveal').addEventListener('click', () => {
  if (!privateManifest) return;
  const field = $('manifestUrl');
  field.type = field.type === 'password' ? 'text' : 'password';
  $('manifestReveal').textContent = field.type === 'password' ? 'Show' : 'Hide';
});

$('manifestCopy').addEventListener('click', async () => {
  if (!privateManifest) return;
  try {
    await navigator.clipboard.writeText(privateManifest);
    $('manifestStatus').textContent = 'Copied. Paste directly into AIOStreams Custom Addon.';
  } catch (_) {
    const field = $('manifestUrl');
    field.type = 'text';
    field.select();
    const ok = document.execCommand('copy');
    field.type = 'password';
    $('manifestReveal').textContent = 'Show';
    $('manifestStatus').textContent = ok ? 'Copied.' : 'Clipboard denied; select and copy manually.';
  }
});

$('logout').addEventListener('click', async () => {
  if (!adminToken && csrfToken) {
    try { await api('/api/auth/logout', 'POST'); } catch (_) {}
  }
  adminToken = '';
  csrfToken = '';
  adminIdentity = {username: '', role: ''};
  $('adminIdentity').textContent = '';
  $('adminUsersPanel').hidden = true;
  privateManifest = '';
  $('manifestUrl').value = '';
  $('manifestUrl').type = 'password';
  $('manifestStatus').textContent = '';
  if (polling) { clearInterval(polling); polling = null; }
  $('main').hidden = true;
  $('login').hidden = false;
  $('refresh').hidden = true; $('logout').hidden = true;
  $('bridgeState').textContent = 'Not connected';
  $('sourceLabel').value = '';
  $('loginError').textContent = '';
});


// Owner-only human accounts, independent of Xtream provider profiles.
// All DOM content from profile names is inserted using textContent.
async function loadAdminAccounts() {
  const response = await api('/api/admin-users');
  const root = $('adminUsersList');
  root.replaceChildren();
  for (const account of response.users || []) {
    const wrap = document.createElement('div');
    wrap.className = 'admin-user-entry';
    const info = document.createElement('span');
    info.textContent = account.username + ' · ' + account.role +
      (account.enabled ? ' · active' : ' · disabled');
    wrap.append(info);
    if (account.username !== 'owner') {
      const toggle = document.createElement('button');
      toggle.className = 'ghost';
      toggle.textContent = account.enabled ? 'Disable' : 'Enable';
      toggle.type = 'button';
      toggle.addEventListener('click', async () => {
        try {
          await api('/api/admin-users/' + encodeURIComponent(account.username),
                    'PATCH', {enabled: !account.enabled});
          await loadAdminAccounts();
        } catch (e) {
          $('adminUsersMessage').textContent = e.message;
        }
      });
      wrap.append(toggle);
      const reset = document.createElement('button');
      reset.className = 'ghost';
      reset.type = 'button';
      reset.textContent = 'Reset password';
      reset.addEventListener('click', () => {
        resetTarget = account.username;
        $('resetAdminPasswordTitle').textContent = 'Reset password for ' + resetTarget;
        $('resetAdminPassword').value = '';
        $('resetAdminPasswordForm').hidden = false;
        $('resetAdminPassword').focus();
      });
      wrap.append(reset);
      const del = document.createElement('button');
      del.className = 'ghost'; del.type = 'button'; del.textContent = 'Remove';
      del.addEventListener('click', async () => {
        if (!window.confirm('Remove Admin user ' + account.username + '?')) return;
        try {
          await api('/api/admin-users/' + encodeURIComponent(account.username), 'DELETE');
          await loadAdminAccounts();
        } catch (e) {
          $('adminUsersMessage').textContent = e.message;
        }
      });
      wrap.append(del);
    }
    root.append(wrap);
  }
}

$('createAdminForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    username: $('newAdminUsername').value.trim().toLowerCase(),
    password: $('newAdminPassword').value,
    role: $('newAdminRole').value
  };
  $('adminUsersMessage').textContent = '';
  try {
    await api('/api/admin-users', 'POST', payload);
    $('createAdminForm').reset();
    $('adminUsersMessage').textContent = 'New Admin user created.';
    await loadAdminAccounts();
  } catch (e) {
    $('adminUsersMessage').textContent = e.message;
  } finally {
    $('newAdminPassword').value = '';
  }
});


$('resetAdminPasswordForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!resetTarget) return;
  try {
    await api('/api/admin-users/' + encodeURIComponent(resetTarget),
              'PATCH', {password: $('resetAdminPassword').value});
    $('adminUsersMessage').textContent = 'Password changed; prior sessions revoked.';
    resetTarget = '';
    $('resetAdminPasswordForm').hidden = true;
    await loadAdminAccounts();
  } catch (e) {
    $('adminUsersMessage').textContent = e.message;
  } finally {
    $('resetAdminPassword').value = '';
  }
});
$('cancelAdminReset').addEventListener('click', () => {
  resetTarget = '';
  $('resetAdminPassword').value = '';
  $('resetAdminPasswordForm').hidden = true;
});
