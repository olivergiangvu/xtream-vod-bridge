'use strict';
// No-network virtual DOM canary: run the actual browser JS with mocked DOM and
// API responses. This supplements, but does not replace, Safari HTTPS QA.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');

class Element {
  constructor(tag = 'div', id = '') {
    this.tagName = tag;
    this.id = id;
    this.children = [];
    this.handlers = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.textContent = '';
    this.type = tag === 'input' ? 'text' : undefined;
    this.attrs = {};
    this.classList = {add() {}, remove() {}, contains() {return false;}};
  }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  setAttribute(key, value) { this.attrs[key] = value; }
  removeAttribute(key) { delete this.attrs[key]; }
  append(...nodes) { this.children.push(...nodes); }
  appendChild(node) { this.children.push(node); return node; }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  focus() {}
  reset() {}
  reportValidity() { return true; }
  insertRow() {
    const row = new Element('tr');
    row.insertCell = () => {
      const cell = new Element('td');
      row.append(cell);
      return cell;
    };
    this.append(row);
    return row;
  }
  querySelectorAll(selector) {
    const items = [];
    function visit(node) {
      if (!(node instanceof Element)) return;
      if (selector === 'input:checked' &&
          node.tagName === 'input' && node.checked) items.push(node);
      for (const child of node.children) visit(child);
    }
    visit(this);
    return items;
  }
}
const step = () => new Promise(resolve => setImmediate(resolve));
function response(body, status = 200, url = 'https://canary.invalid/admin/api') {
  return {
    status, ok: status >= 200 && status < 300, redirected: false, url,
    headers: {get: () => 'application/json'},
    json: async () => body,
  };
}

async function run(role) {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element('div', id));
    return elements.get(id);
  };
  const document = {
    baseURI: 'https://canary.invalid/admin/',
    getElementById: get,
    createElement: tag => new Element(tag),
    createTextNode: text => ({textContent: text}),
  };
  let manifests = [];
  let sources = [];
  const calls = [];
  const generatedUrl = 'https://canary.invalid/a/v5_REDACTED_SAMPLE/manifest.json';
  const sourceId = 'a'.repeat(32);
  const fetch = async (url, args = {}) => {
    const pathname = new URL(url).pathname;
    const method = args.method || 'GET';
    calls.push({pathname, method, body: args.body ? JSON.parse(args.body) : null});
    if (pathname.endsWith('/auth/session')) return response({
      authenticated: true, csrf_token: 'test-csrf', username: role === 'admin' ? 'owner' : 'alice',
      role, password_ready: true,
    });
    if (pathname.endsWith('/my/sources')) {
      if (method === 'GET') return response({sources});
      if (method === 'POST') {
        const data = JSON.parse(args.body);
        sources = [{source_id: sourceId, owner: 'alice', kind: data.kind,
                    name: data.name, enabled: true, status: 'untested'}];
        return response({source: sources[0]}, 201);
      }
    }
    if (pathname.endsWith('/my/manifests')) {
      if (method === 'GET') return response({manifests});
      if (method === 'POST') {
        const data = JSON.parse(args.body);
        const obj = {manifest_id: 'b'.repeat(32), name: data.name,
                     enabled: true, sources: data.sources, url: null};
        manifests = [obj];
        return response({manifest: {...obj, url: generatedUrl, one_time_only: true}}, 201);
      }
    }
    if (pathname.endsWith('/system/users')) {
      assert.equal(role, 'admin', 'User must never fetch Admin User Management');
      return response({users: [{username: 'owner', role: 'admin',
                                enabled: true, built_in: true}]});
    }
    if (pathname.endsWith('/overview')) {
      assert.equal(role, 'admin', 'User must never fetch global overview');
      return response({
        bridge: {status: 'ok', index: {movie: {total: 0}, series: {total: 0}}},
        events: [], settings: {}, effective_env: {},
      });
    }
    if (pathname.endsWith('/manifest')) {
      assert.equal(role, 'admin', 'User must never fetch global addon manifest');
      return response({url: 'https://canary.invalid/a/legacy-secret/manifest.json'});
    }
    throw new Error('Unexpected request ' + method + ' ' + pathname);
  };
  const location = {
    pathname: '/admin/',
    replace(value) { throw new Error('Unexpected redirect ' + value); },
  };
  const context = vm.createContext({
    document, location,
    window: {location, confirm: () => true,
             prompt: () => {throw new Error('Unsafe plaintext password prompt');}},
    fetch, URL, console, navigator: {
      clipboard: {writeText: async () => {}},
    },
    setInterval: () => 1,
    clearInterval: () => {},
    Date,
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'admin/assets/workspace.js'), 'utf8'),
                  context, {filename: 'workspace.js'});
  vm.runInContext(fs.readFileSync(path.join(root, 'admin/assets/app.js'), 'utf8'),
                  context, {filename: 'app.js'});
  for (let i = 0; i < 10; ++i) await step();
  assert.equal(get('login').hidden, true);
  assert.equal(get('main').hidden, false);
  assert.equal(get('personalWorkspace').hidden, false);
  assert.equal(get('adminWorkspace').hidden, true);

  if (role === 'user') {
    assert.equal(get('navSystem').hidden, true);
    assert.equal(get('usersPanel').hidden, true);
    assert(!calls.some(c => /\/(system\/users|overview|manifest)$/.test(c.pathname)));

    get('personalSourceKind').value = 'm3u';
    get('personalSourceKind').handlers.change();
    get('personalSourceName').value = 'Synthetic Playlist';
    get('personalM3uUrl').value = 'https://example.net/media.m3u?token=TEST';
    await get('personalSourceForm').handlers.submit({preventDefault() {}});
    for (let i = 0; i < 3; ++i) await step();
    assert.equal(sources.length, 1);
    assert.equal(get('personalM3uUrl').value, '');
    const sourcePost = calls.find(c => c.pathname.endsWith('/my/sources') &&
                                     c.method === 'POST');
    assert.equal(sourcePost.body.config.playlist_url,
                 'https://example.net/media.m3u?token=TEST');
    assert(get('sourceList').children.length >= 1);

    get('personalManifestName').value = 'Private VOD';
    const choices = get('manifestSourceChoices').querySelectorAll('input:checked');
    assert.equal(choices.length, 0);
    const childLabels = get('manifestSourceChoices').children;
    assert(childLabels.length > 0);
    childLabels[0].children[0].checked = true;
    await get('personalManifestForm').handlers.submit({preventDefault() {}});
    for (let i = 0; i < 3; ++i) await step();
    assert.equal(manifests.length, 1);
    assert.equal(get('issuedManifestPanel').hidden, false);
    assert.equal(get('issuedManifestUrl').value, '',
                 'URL must not appear in DOM until explicitly revealed');
    get('issuedManifestReveal').handlers.click();
    assert.equal(get('issuedManifestUrl').value, generatedUrl);
    get('issuedManifestReveal').handlers.click();
    assert.equal(get('issuedManifestUrl').value, '');
    get('issuedManifestDismiss').handlers.click();
    assert.equal(get('issuedManifestPanel').hidden, true);
    assert.equal(get('issuedManifestUrl').value, '');
    assert(!calls.some(c => /\/(system\/users|overview|manifest)$/.test(c.pathname)));
    console.log('V05D_USER_WORKSPACE_RUNTIME=PASS');
  } else {
    assert.equal(get('navSystem').hidden, false);
    assert.equal(get('usersPanel').hidden, false);
    assert(!calls.some(c => c.pathname.endsWith('/overview')),
           'Admin personal page should not poll legacy system by default');
    get('navSystem').handlers.click();
    for (let i = 0; i < 8; ++i) await step();
    assert.equal(get('adminWorkspace').hidden, false);
    assert.equal(get('personalWorkspace').hidden, true);
    assert(calls.some(c => c.pathname.endsWith('/overview')),
           'Admin System tab should request global overview');
    assert(calls.some(c => c.pathname.endsWith('/manifest')),
           'Admin System tab should request global manifest');
    assert(calls.some(c => c.pathname.endsWith('/system/users')),
           'Admin should be able to manage User accounts');
    console.log('V05D_ADMIN_SYSTEM_RUNTIME=PASS');
  }
}

(async () => {
  await run('user');
  await run('admin');
})().catch(error => {
  console.error(error.stack);
  process.exitCode = 1;
});
