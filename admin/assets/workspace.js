'use strict';
/*
 * v0.5D personal workspace. No persisted browser credentials or manifest
 * tokens; no user-provided HTML insertion. API authorization/ownership live
 * exclusively on the server. Global Admin settings remain in app.js.
 */
(() => {
  const $ = id => document.getElementById(id);
  let callApi = null;
  let account = null;
  let sources = [];
  let manifests = [];
  let editingSource = null;
  let oneTimeUrl = '';
  let epoch = 0;

  const status = (id, message, error = false) => {
    const element = $(id);
    element.textContent = message;
    element.className = error ? 'small notice' : 'small muted';
  };

  const el = (tag, className, text) => {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const action = (label, handler, className = 'ghost') => {
    const button = el('button', className, label);
    button.type = 'button';
    button.addEventListener('click', async () => {
      if (button.disabled) return;
      button.disabled = true;
      try { await handler(); }
      catch (error) {
        status('sourceStatus', 'Action failed: ' + error.message, true);
      } finally { button.disabled = false; }
    });
    return button;
  };
  const failure = err => {
    if (err && err.message === 'Please sign in again.') {
      clearSensitive();
      if (location.pathname.startsWith('/admin/')) {
        location.replace('/admin-signin/');
      }
    }
    return err && err.message ? err.message : 'Service unavailable';
  };
  function clearIssuedUrl() {
    oneTimeUrl = '';
    $('issuedManifestUrl').type = 'password';
    $('issuedManifestUrl').value = '';
    $('issuedManifestPanel').hidden = true;
    $('issuedManifestReveal').textContent = 'Show';
    $('issuedManifestReveal').setAttribute('aria-pressed', 'false');
  }
  function wipeProviderFields() {
    for (const id of ['personalXtreamBase', 'personalXtreamUser',
                       'personalXtreamPassword', 'personalM3uUrl']) $(id).value = '';
  }
  function clearSensitive() {
    epoch += 1;
    oneTimeUrl = '';
    clearIssuedUrl();
    wipeProviderFields();
    $('newAccountPassword').value = '';
    $('sourceList').replaceChildren();
    $('personalManifestList').replaceChildren();
    $('manifestSourceChoices').replaceChildren();
    $('adminUserList').replaceChildren();
    sources = [];
    manifests = [];
    editingSource = null;
    callApi = null;
    account = null;
    $('usersPanel').hidden = true;
    $('accountIdentity').hidden = true;
    $('navSystem').hidden = true;
  }
  function resetSourceForm() {
    editingSource = null;
    $('personalSourceForm').reset();
    $('personalSourceName').value = '';
    $('personalSourceKind').value = 'xtream';
    $('personalSourceKind').disabled = false;
    $('replaceConfigRow').hidden = true;
    $('replaceSourceConfig').checked = false;
    $('sourceCancel').hidden = true;
    $('sourceSave').textContent = 'Add source';
    $('sourceFormTitle').textContent = 'Add a source';
    wipeProviderFields();
    updateSourceForm();
  }
  function updateSourceForm() {
    const kind = $('personalSourceKind').value;
    const replaceConfig = !editingSource || $('replaceSourceConfig').checked;
    $('xtreamFields').hidden = kind !== 'xtream' || !replaceConfig;
    $('m3uFields').hidden = kind !== 'm3u' || !replaceConfig;
    ['personalXtreamBase', 'personalXtreamUser',
     'personalXtreamPassword'].forEach(id => {
       $(id).disabled = kind !== 'xtream' || !replaceConfig;
       $(id).required = kind === 'xtream' && replaceConfig;
     });
    $('personalM3uUrl').disabled = kind !== 'm3u' || !replaceConfig;
    $('personalM3uUrl').required = kind === 'm3u' && replaceConfig;
  }
  $('personalSourceKind').addEventListener('change', () => {
    wipeProviderFields();
    updateSourceForm();
  });
  $('replaceSourceConfig').addEventListener('change', () => {
    wipeProviderFields();
    updateSourceForm();
  });
  $('sourceCancel').addEventListener('click', resetSourceForm);

  function sourceConfig() {
    if ($('personalSourceKind').value === 'xtream') return {
      base_url: $('personalXtreamBase').value.trim(),
      username: $('personalXtreamUser').value,
      password: $('personalXtreamPassword').value,
    };
    return {playlist_url: $('personalM3uUrl').value.trim()};
  }
  function startEditing(source) {
    resetSourceForm();
    editingSource = source.source_id;
    $('personalSourceKind').value = source.kind;
    $('personalSourceKind').disabled = true;
    $('personalSourceName').value = source.name;
    $('replaceConfigRow').hidden = false;
    $('sourceFormTitle').textContent = 'Edit source';
    $('sourceSave').textContent = 'Save source';
    $('sourceCancel').hidden = false;
    updateSourceForm();
    $('personalSourceName').focus();
    status('sourceStatus',
      'Provider credentials stay hidden. To change them, enable Replace and enter the full new details.');
  }

  async function refreshSources() {
    if (!callApi) return;
    const localEpoch = epoch;
    const response = await callApi('/api/my/sources');
    if (localEpoch !== epoch) return;
    sources = response.sources || [];
    renderSources();
    renderSourceChoices();
  }

  async function refreshManifests() {
    if (!callApi) return;
    const localEpoch = epoch;
    const response = await callApi('/api/my/manifests');
    if (localEpoch !== epoch) return;
    manifests = response.manifests || [];
    renderManifests();
  }

  function empty(list, message) {
    list.replaceChildren(el('p', 'small muted empty-state', message));
  }
  function renderSources() {
    const list = $('sourceList');
    list.replaceChildren();
    if (!sources.length) {
      empty(list, 'No sources yet. Add your Xtream account or M3U playlist below.');
      return;
    }
    for (const item of sources) {
      const card = el('article', 'workspace-item');
      const top = el('div', 'workspace-item-heading');
      const title = el('div');
      title.append(el('strong', '', item.name));
      title.append(el('p', 'small muted', item.kind.toUpperCase() + ' · ' +
        (item.enabled ? item.status : 'disabled') + ' · Credentials stored securely'));
      top.append(title);
      top.append(el('span', 'soft-pill', item.enabled ? 'Enabled' : 'Disabled'));
      card.append(top);
      const buttons = el('div', 'workspace-actions');
      buttons.append(action('Edit', () => startEditing(item)));
      buttons.append(action('Test', async () => {
        status('sourceStatus', 'Testing source connection…');
        try {
          const data = await callApi('/api/my/sources/' + item.source_id + '/test', 'POST');
          status('sourceStatus', 'Connection: ' + data.test.status +
            (data.test.entries === undefined ? '' : ' · Entries: ' + data.test.entries));
          await refreshSources();
        } catch (e) { status('sourceStatus', 'Test failed: ' + failure(e), true); }
      }));
      buttons.append(action('Sync VOD', async () => {
        if (!window.confirm('Sync this source now? Only provider-supplied exact IMDb/TMDb IDs are indexed.')) return;
        status('sourceStatus', 'Indexing source (manual sync)…');
        try {
          const response = await callApi('/api/my/sources/' + item.source_id + '/sync', 'POST');
          const data = response.sync || {};
          status('sourceStatus', 'Indexed: ' + (data.movies || 0) + ' movies, ' +
            (data.series || 0) + ' series, ' + (data.episodes || 0) + ' episodes.');
          await refreshSources();
        } catch (e) { status('sourceStatus', 'Sync failed: ' + failure(e), true); }
      }));
      buttons.append(action(item.enabled ? 'Disable' : 'Enable', async () => {
        try {
          await callApi('/api/my/sources/' + item.source_id, 'PATCH',
                        {enabled: !item.enabled});
          await refreshSources();
          status('sourceStatus', 'Source status updated.');
        } catch (e) { status('sourceStatus', 'Update failed: ' + failure(e), true); }
      }));
      buttons.append(action('Delete', async () => {
        if (!window.confirm('Delete this source and its indexed media? Existing manifests will no longer include it.')) return;
        try {
          await callApi('/api/my/sources/' + item.source_id, 'DELETE');
          if (editingSource === item.source_id) resetSourceForm();
          await Promise.all([refreshSources(), refreshManifests()]);
          status('sourceStatus', 'Source deleted.');
        } catch (e) { status('sourceStatus', 'Delete failed: ' + failure(e), true); }
      }));
      card.append(buttons);
      list.append(card);
    }
  }
  function renderSourceChoices() {
    const root = $('manifestSourceChoices');
    const selected = new Set(Array.from(
      root.querySelectorAll('input:checked'), node => node.value
    ));
    root.replaceChildren();
    const valid = sources.filter(source => source.enabled);
    if (!valid.length) {
      root.append(el('p', 'small muted',
        'Add and enable at least one personal source to create a manifest.'));
      $('personalManifestCreate').disabled = true;
      return;
    }
    $('personalManifestCreate').disabled = false;
    for (const source of valid) {
      const label = el('label', 'checkbox-line');
      const check = el('input');
      check.type = 'checkbox';
      check.value = source.source_id;
      check.name = 'manifestSource';
      check.checked = selected.has(source.source_id);
      label.append(check, document.createTextNode(' ' + source.name + ' · ' + source.kind));
      root.append(label);
    }
  }
  function renderManifests() {
    const root = $('personalManifestList');
    root.replaceChildren();
    if (!manifests.length) {
      empty(root, 'No manifests yet. Select your sources and create an addon.');
      return;
    }
    for (const m of manifests) {
      const card = el('article', 'workspace-item');
      const top = el('div', 'workspace-item-heading');
      const title = el('div');
      title.append(el('strong', '', m.name));
      title.append(el('p', 'small muted', (m.sources || []).length +
        ' source(s) · ' + (m.enabled ? 'Active' : 'Revoked') +
        ' · URL not stored in this browser'));
      top.append(title);
      top.append(el('span', 'soft-pill', m.enabled ? 'Active' : 'Disabled'));
      card.append(top);
      const buttons = el('div', 'workspace-actions');
      const editPanel = el('form', 'inline-reset');
      editPanel.hidden = true;
      const nameLabel = el('label', '', 'Addon name');
      const nameInput = el('input');
      nameInput.type = 'text'; nameInput.required = true; nameInput.maxLength = 64;
      nameInput.value = m.name;
      const selectionLabel = el('label', '', 'Select your enabled sources');
      const chooser = el('div', 'source-choices');
      for (const source of sources.filter(x => x.enabled)) {
        const label = el('label', 'checkbox-line');
        const check = el('input'); check.type = 'checkbox';
        check.value = source.source_id;
        check.checked = (m.sources || []).includes(source.source_id);
        label.append(check, document.createTextNode(' ' + source.name));
        chooser.append(label);
      }
      const commit = el('button', 'primary', 'Save addon');
      commit.type = 'submit';
      const dismiss = action('Cancel', () => { editPanel.hidden = true; });
      editPanel.append(nameLabel, nameInput, selectionLabel, chooser, commit, dismiss);
      editPanel.addEventListener('submit', async event => {
        event.preventDefault();
        const picked = Array.from(chooser.querySelectorAll('input:checked'), n => n.value);
        if (!picked.length) {
          status('personalManifestStatus', 'Choose at least one enabled source.', true);
          return;
        }
        commit.disabled = true;
        try {
          await callApi('/api/my/manifests/' + m.manifest_id,
                        'PATCH', {name: nameInput.value.trim(), source_ids: picked});
          await refreshManifests();
          status('personalManifestStatus', 'Manifest sources updated.');
        } catch (e) {
          status('personalManifestStatus', 'Update failed: ' + failure(e), true);
        } finally { commit.disabled = false; }
      });
      buttons.append(action('Edit sources', () => {
        editPanel.hidden = !editPanel.hidden;
        if (!editPanel.hidden) nameInput.focus();
      }));
      buttons.append(action('Rotate URL', async () => {
        if (!window.confirm('Rotate this addon URL? The previous manifest link and its playback access will stop working.')) return;
        try {
          const response = await callApi(
            '/api/my/manifests/' + m.manifest_id + '/rotate', 'POST'
          );
          showIssuedUrl(response.manifest.url, 'Rotated URL for ' + m.name);
          await refreshManifests();
        } catch (e) { status('personalManifestStatus', 'Rotate failed: ' + failure(e), true); }
      }));
      buttons.append(action(m.enabled ? 'Disable' : 'Enable', async () => {
        if (m.enabled && !window.confirm('Disable this manifest now? Its stream URLs will stop working.')) return;
        try {
          await callApi('/api/my/manifests/' + m.manifest_id, 'PATCH',
                        {enabled: !m.enabled});
          await refreshManifests();
          status('personalManifestStatus', m.enabled ? 'Manifest disabled.' : 'Manifest enabled.');
        } catch (e) { status('personalManifestStatus', 'Update failed: ' + failure(e), true); }
      }));
      buttons.append(action('Delete', async () => {
        if (!window.confirm('Permanently delete this manifest and revoke its URL?')) return;
        try {
          await callApi('/api/my/manifests/' + m.manifest_id, 'DELETE');
          await refreshManifests();
          status('personalManifestStatus', 'Manifest deleted.');
        } catch (e) { status('personalManifestStatus', 'Delete failed: ' + failure(e), true); }
      }));
      card.append(buttons, editPanel);
      root.append(card);
    }
  }
  function showIssuedUrl(url, heading) {
    if (typeof url !== 'string' || !url.startsWith('https://')) {
      throw new Error('Manifest URL was not returned by the server');
    }
    clearIssuedUrl();
    oneTimeUrl = url;
    $('issuedManifestHeading').textContent = heading;
    $('issuedManifestPanel').hidden = false;
    status('personalManifestStatus',
      'Created. Copy this private URL now; the server will not display it again.');
    $('issuedManifestCopy').focus();
  }
  $('issuedManifestCopy').addEventListener('click', async () => {
    if (!oneTimeUrl) return;
    try {
      await navigator.clipboard.writeText(oneTimeUrl);
      status('personalManifestStatus', 'Private URL copied · paste into AIOStreams.');
    } catch (_) {
      status('personalManifestStatus',
        'Clipboard unavailable. Select Show, then select and copy the URL manually.', true);
    }
  });
  $('issuedManifestReveal').addEventListener('click', () => {
    if (!oneTimeUrl) return;
    const input = $('issuedManifestUrl');
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    input.value = isHidden ? oneTimeUrl : '';
    $('issuedManifestReveal').textContent = isHidden ? 'Hide' : 'Show';
    $('issuedManifestReveal').setAttribute('aria-pressed', String(isHidden));
  });
  $('issuedManifestDismiss').addEventListener('click', () => {
    clearIssuedUrl();
    status('personalManifestStatus', 'Private URL dismissed. Rotate it if you need a new copy.');
  });

  $('personalSourceForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!callApi) return;
    const id = editingSource;
    const kind = $('personalSourceKind').value;
    const name = $('personalSourceName').value.trim();
    const payload = id
      ? {name, ...($('replaceSourceConfig').checked ? {config: sourceConfig()} : {})}
      : {name, kind, config: sourceConfig()};
    const save = $('sourceSave');
    save.disabled = true;
    status('sourceStatus', id ? 'Updating source…' : 'Saving encrypted source…');
    try {
      await callApi(id ? '/api/my/sources/' + id : '/api/my/sources',
                    id ? 'PATCH' : 'POST', payload);
      resetSourceForm();
      await refreshSources();
      status('sourceStatus', 'Source saved. Use Test, then Sync VOD to index content.');
    } catch (e) { status('sourceStatus', 'Save failed: ' + failure(e), true); }
    finally { save.disabled = false; wipeProviderFields(); }
  });
  $('personalManifestForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!callApi) return;
    const selected = Array.from(
      $('manifestSourceChoices').querySelectorAll('input:checked'),
      node => node.value
    );
    if (selected.length < 1) {
      status('personalManifestStatus', 'Choose at least one of your sources.', true);
      return;
    }
    const button = $('personalManifestCreate');
    button.disabled = true;
    status('personalManifestStatus', 'Creating private addon…');
    try {
      const response = await callApi('/api/my/manifests', 'POST',
        {name: $('personalManifestName').value.trim(), sources: selected});
      showIssuedUrl(response.manifest.url, 'New private addon URL');
      $('personalManifestName').value = '';
      await refreshManifests();
    } catch (e) { status('personalManifestStatus', 'Create failed: ' + failure(e), true); }
    finally { button.disabled = false; }
  });
  $('sourcesRefresh').addEventListener('click', () =>
    refreshSources().catch(e => status('sourceStatus', failure(e), true)));
  $('manifestsRefresh').addEventListener('click', () =>
    refreshManifests().catch(e =>
      status('personalManifestStatus', failure(e), true)));

  async function refreshUsers() {
    if (!callApi || !account || account.role !== 'admin') return;
    const localEpoch = epoch;
    const response = await callApi('/api/system/users');
    if (localEpoch !== epoch) return;
    const root = $('adminUserList');
    root.replaceChildren();
    for (const u of response.users || []) {
      const card = el('article', 'workspace-item');
      const top = el('div', 'workspace-item-heading');
      const title = el('div');
      title.append(el('strong', '', u.username));
      title.append(el('p', 'small muted',
                      u.role.toUpperCase() + (u.enabled ? ' · Enabled' : ' · Disabled')));
      top.append(title);
      card.append(top);
      if (!u.built_in) {
        const buttons = el('div', 'workspace-actions');
        buttons.append(action(u.enabled ? 'Disable User' : 'Enable User', async () => {
          if (u.enabled && !window.confirm('Disable ' + u.username + ' and revoke its sessions?')) return;
          try {
            await callApi('/api/system/users/' + encodeURIComponent(u.username),
                          'PATCH', {enabled: !u.enabled});
            await refreshUsers();
            status('adminUsersStatus', 'Account status updated.');
          } catch (e) { status('adminUsersStatus', failure(e), true); }
        }));
        const resetForm = el('form', 'inline-reset');
        resetForm.hidden = true;
        resetForm.autocomplete = 'off';
        const resetLabel = el('label', '', 'New password for ' + u.username);
        const resetInput = el('input');
        resetInput.type = 'password';
        resetInput.autocomplete = 'new-password';
        resetInput.minLength = 14;
        resetInput.maxLength = 128;
        resetInput.required = true;
        const resetSubmit = el('button', 'primary', 'Confirm reset');
        resetSubmit.type = 'submit';
        const resetCancel = action('Cancel', () => {
          resetInput.value = '';
          resetForm.hidden = true;
        });
        resetForm.append(resetLabel, resetInput, resetSubmit, resetCancel);
        resetForm.addEventListener('submit', async event => {
          event.preventDefault();
          if (!resetForm.reportValidity()) return;
          resetSubmit.disabled = true;
          try {
            await callApi('/api/system/users/' + encodeURIComponent(u.username),
                          'PATCH', {password: resetInput.value});
            status('adminUsersStatus', 'Password reset. Existing sessions revoked.');
            resetInput.value = '';
            resetForm.hidden = true;
          } catch (e) {
            status('adminUsersStatus', 'Reset failed: ' + failure(e), true);
          } finally {
            resetSubmit.disabled = false;
            resetInput.value = '';
          }
        });
        buttons.append(action('Reset password', () => {
          resetForm.hidden = !resetForm.hidden;
          if (!resetForm.hidden) resetInput.focus();
          else resetInput.value = '';
        }));
        buttons.append(action('Delete User', async () => {
          if (!window.confirm('Delete ' + u.username + '? Remove their sources first.')) return;
          try {
            await callApi('/api/system/users/' + encodeURIComponent(u.username), 'DELETE');
            await refreshUsers();
            status('adminUsersStatus', 'User removed.');
          } catch (e) { status('adminUsersStatus', failure(e), true); }
        }));
        card.append(buttons, resetForm);
      }
      root.append(card);
    }
  }
  $('adminNewUserForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!account || account.role !== 'admin') return;
    const button = $('newAccountCreate');
    button.disabled = true;
    try {
      await callApi('/api/system/users', 'POST', {
        username: $('newAccountUsername').value.trim(),
        password: $('newAccountPassword').value,
      });
      $('newAccountUsername').value = '';
      await refreshUsers();
      status('adminUsersStatus', 'User created. Share credentials securely.');
    } catch (e) { status('adminUsersStatus', 'Create failed: ' + failure(e), true); }
    finally { button.disabled = false; $('newAccountPassword').value = ''; }
  });
  $('usersRefresh').addEventListener('click', () =>
    refreshUsers().catch(e => status('adminUsersStatus', failure(e), true)));

  async function activate(session, apiCall) {
    clearSensitive();
    const localEpoch = epoch;
    account = {
      username: session.username || 'owner',
      role: session.role === 'admin' ? 'admin' : 'user',
    };
    callApi = apiCall;
    $('accountIdentity').hidden = false;
    $('accountIdentity').textContent = account.username + ' · ' + account.role;
    $('workspaceIdentity').textContent = account.username + ' · ' + account.role;
    $('navSystem').hidden = account.role !== 'admin';
    $('usersPanel').hidden = account.role !== 'admin';
    resetSourceForm();
    try {
      await Promise.all([
        refreshSources(), refreshManifests(),
        ...(account.role === 'admin' ? [refreshUsers()] : []),
      ]);
      if (epoch !== localEpoch) return;
      status('sourceStatus', 'Your private sources are ready.');
      status('personalManifestStatus', 'Your manifests are ready.');
    } catch (err) {
      if (epoch === localEpoch) {
        status('sourceStatus', 'Unable to load workspace: ' + failure(err), true);
      }
    }
  }
  window.VODWorkspace = {
    activate, refreshSources, refreshManifests,
    clearSensitive,
    isAdmin: () => account && account.role === 'admin',
  };
})();
