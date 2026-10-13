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
    await loadProviders();
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


// Provider manager (staged/vault-only; no playback activation in this build).
let activeProviderId = null;
let profiles = [];
let providerStreamingActivation = false;

function clearProviderForm() {
  activeProviderId = null;
  $('providerForm').reset();
  $('providerPriority').value = '100';
  $('providerPassword').value = '';
  $('providerPassword').type = 'password';
  $('showProviderPassword').textContent = 'Show';
  $('providerPassword').required = true;
  $('passwordHint').textContent = 'required for new profiles';
  $('providerFormTitle').textContent = 'Add a provider';
  $('providerSave').textContent = 'Save encrypted profile';
}

function providerText(name, text) {
  const el = document.createElement(name);
  el.textContent = text;
  return el;
}

function drawProviders() {
  const root = $('providerRows');
  root.replaceChildren();
  if (!profiles.length) {
    root.append(providerText('p', 'No encrypted provider profiles yet. Your existing .env provider continues to work independently.'));
    return;
  }
  for (const p of profiles) {
    const item = document.createElement('div');
    item.className = 'provider-entry';
    const detail = document.createElement('div');
    detail.append(providerText('strong', p.label));
    const description = providerText('div', p.base_url + ' · ' + p.username + ' · Priority ' + p.priority);
    description.className = 'small muted';
    detail.append(description);
    const badge = providerText('div', p.enabled ? 'Active · stream-ready' : 'Staged · not streaming');
    badge.className = 'small muted';
    detail.append(badge);
    const buttons = document.createElement('div');
    buttons.className = 'buttons';
    const edit = providerText('button', 'Edit');
    edit.type = 'button';
    edit.className = 'ghost';
    edit.addEventListener('click', () => {
      activeProviderId = p.id;
      $('providerLabel').value = p.label;
      $('providerUrl').value = p.base_url;
      $('providerUsername').value = p.username;
      $('providerPriority').value = p.priority;
      $('providerPassword').value = '';
      $('providerPassword').required = false;
      $('providerPassword').type = 'password';
      $('passwordHint').textContent = 'leave blank to keep saved password';
      $('providerFormTitle').textContent = 'Edit ' + p.label;
      $('providerSave').textContent = 'Save changes';
      $('providerLabel').focus();
    });
    const del = providerText('button', 'Delete');
    del.type = 'button'; del.className = 'ghost';
    del.addEventListener('click', async () => {
      if (!window.confirm('Delete staged provider profile "' + p.label + '"?')) return;
      try {
        await api('/api/providers/' + encodeURIComponent(p.id), 'DELETE');
        if (p.id === activeProviderId) clearProviderForm();
        await loadProviders();
      } catch (e) {
        $('providerSaveStatus').textContent = e.message;
      }
    });
    if (providerStreamingActivation) {
      const sync = providerText('button', 'Sync catalog');
      sync.type = 'button'; sync.className = 'ghost';
      sync.addEventListener('click', async () => {
        sync.disabled = true;
        $('providerSaveStatus').textContent = 'Indexing provider catalog…';
        try {
          const result = await api('/api/providers/' + encodeURIComponent(p.id) + '/sync', 'POST');
          $('providerSaveStatus').textContent = 'Indexed ' + (result.indexed ?? 0) + ' entries.';
          await loadProviders();
        } catch (e) {
          $('providerSaveStatus').textContent = e.message;
        } finally { sync.disabled = false; }
      });
      const activate = providerText('button', p.enabled ? 'Disable source' : 'Activate source');
      activate.type = 'button'; activate.className = 'ghost';
      activate.addEventListener('click', async () => {
        activate.disabled = true;
        try {
          await api('/api/providers/' + encodeURIComponent(p.id) + '/activation',
                    'POST', {enabled: !p.enabled});
          $('providerSaveStatus').textContent = p.enabled
            ? 'Provider disabled from new streams' : 'Provider active in new stream requests';
          await loadProviders();
        } catch (e) { $('providerSaveStatus').textContent = e.message; }
        finally { activate.disabled = false; }
      });
      buttons.append(sync, activate);
    }
    buttons.append(edit, del);
    item.append(detail, buttons);
    root.append(item);
  }
}

async function loadProviders() {
  const data = await api('/api/providers');
  const unlocked = data.key_configured === true;
  $('providerKey').textContent = unlocked ? 'Encrypted key ready' : 'Encryption key not provisioned';
  $('providerSave').disabled = !unlocked;
  if (!unlocked) {
    $('providerSaveStatus').textContent = 'Provider vault is read-only until the server key file is securely mounted.';
  }
  profiles = data.providers || [];
  providerStreamingActivation = data.streaming_activation === true;
  drawProviders();
}

$('providerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    label: $('providerLabel').value.trim(),
    base_url: $('providerUrl').value.trim(),
    username: $('providerUsername').value,
    priority: Number.parseInt($('providerPriority').value, 10),
  };
  const password = $('providerPassword').value;
  if (password || !activeProviderId) payload.password = password;
  $('providerSave').disabled = true;
  $('providerSaveStatus').textContent = 'Encrypting…';
  try {
    const isEdit = Boolean(activeProviderId);
    await api(isEdit ? '/api/providers/' + encodeURIComponent(activeProviderId) : '/api/providers',
              isEdit ? 'PATCH' : 'POST', payload);
    $('providerSaveStatus').textContent = 'Encrypted profile saved. Streaming remains disabled during migration.';
    clearProviderForm();
    await loadProviders();
  } catch (e) {
    $('providerSaveStatus').textContent = e.message;
  } finally {
    if ($('providerKey').textContent === 'Encrypted key ready') $('providerSave').disabled = false;
    $('providerPassword').value = '';
  }
});
$('providerReset').addEventListener('click', clearProviderForm);
$('showProviderPassword').addEventListener('click', () => {
  const field = $('providerPassword');
  field.type = field.type === 'password' ? 'text' : 'password';
  $('showProviderPassword').textContent = field.type === 'password' ? 'Show' : 'Hide';
});
