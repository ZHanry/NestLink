// Production relay metadata controls, SDK and real server/SQLite. No mocks.
'use strict';
const { prepareManagementResponseObservation } = require('./refactor-browser-response-observer.cjs');
const PANEL = '[aria-label="Relay attributes"]';
const REGION = PANEL + ' [data-node-relay-field="region"]';
const COST = PANEL + ' [data-node-relay-field="cost"]';
const READ = 'Read current attributes';
const SAVE = 'Save relay attributes';
let active = null;
function check(value, message) { if (!value) throw new Error('Relay attributes UI: ' + message); }
function matches(response, method) {
  return !!active && response.request().method() === method && new URL(response.url()).pathname === active.path;
}
function expectedFailure(response) {
  if (active && matches(response, 'PUT') && response.status() === 409) {
    active.facts.failures.push({ method: 'PUT', status: 409 });
    return true;
  }
  return false;
}
async function click(page, selector, text) {
  await page.bringToFront();
  for (const button of await page.$$(selector)) {
    if (await button.evaluate(element => element.textContent.trim()) === text) {
      await button.click(); return;
    }
  }
  throw new Error('Relay attributes UI action missing: ' + text);
}
async function network(page) {
  await click(page, '.sidebar nav button', 'Network and nodes');
  await page.waitForSelector('.content-grid .records .record', { visible: true, timeout: 8000 });
  await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
}
async function selectNode(page) {
  await page.bringToFront();
  for (const row of await page.$$('.content-grid .records .record')) {
    if (await row.$eval('strong', element => element.textContent) === active.node.name) {
      await row.click(); return;
    }
  }
  throw new Error('Owned registered relay is missing from production node list');
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
    { timeout: 8000 }, PANEL);
}
function validView(view) {
  check(view?.node_id === active.node.id && Number.isSafeInteger(view.revision) && view.revision >= 0
    && view.attributes && (view.attributes.region === null || /^[a-z0-9-]{1,32}$/.test(view.attributes.region))
    && (view.attributes.cost_weight === null || (Number.isSafeInteger(view.attributes.cost_weight)
      && view.attributes.cost_weight >= 0 && view.attributes.cost_weight <= 1000000)),
  'Actual response did not contain the matching bounded relay attributes');
  return view;
}
async function rendered(page, view) {
  await settled(page);
  const actual = await page.$eval(PANEL, element => ({
    revision: [...element.querySelectorAll('p')].map(item => item.textContent.trim()).find(text => /^revision \d+$/.test(text)),
    region: element.querySelector('[data-node-relay-field="region"]').value,
    cost: element.querySelector('[data-node-relay-field="cost"]').value,
    save_disabled: element.querySelector('button.primary').disabled,
  }));
  check(actual.revision === 'revision ' + view.revision && actual.region === (view.attributes.region ?? '')
    && actual.cost === (view.attributes.cost_weight === null ? '' : String(view.attributes.cost_weight))
    && actual.save_disabled === false, 'Rendered editor did not match the actual server JSON');
}
async function exchange(page, method, trigger, { previous = null, attributes = null, status = 200 } = {}) {
  const captured = status === 200 ? active.observers.get(page)?.expect(method + ' ' + active.path) : null;
  const pending = page.waitForResponse(response => matches(response, method), { timeout: 8000 });
  pending.catch(() => {});
  try {
    await trigger();
    const response = await pending;
    check(response.status() === status, 'Unexpected ' + method + ' HTTP status ' + response.status());
    if (previous) {
      const sent = JSON.parse(response.request().postData());
      check(sent.expected_revision === previous.revision && sent.attributes.region === attributes.region
        && sent.attributes.cost_weight === attributes.cost_weight,
      'Real update lost the prior revision or explicit unknown/zero attributes');
    }
    if (status !== 200) { await settled(page); return null; }
    const view = validView(captured ? await captured.promise : await response.json());
    await rendered(page, view);
    return view;
  } finally { captured?.cancel(); }
}
async function read(page) { return exchange(page, 'GET', () => click(page, PANEL + ' button', READ)); }
async function fill(page, region, cost) {
  await page.bringToFront();
  await page.locator(REGION).fill(region);
  await page.locator(COST).fill(cost);
  check(await page.$eval(REGION, element => element.value) === region
    && await page.$eval(COST, element => element.value) === cost, 'Real field entry did not retain the complete draft');
}
async function save(page, previous, attributes, status = 200) {
  return exchange(page, 'PUT', () => click(page, PANEL + ' button', SAVE), { previous, attributes, status });
}
async function signIn(page, ready) {
  await page.bringToFront();
  await page.goto(ready.origin, { waitUntil: 'networkidle0' });
  await page.locator('.language-selector button[lang="en"]').click();
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('#username', { visible: true });
  await page.locator('#username').fill(ready.username);
  await page.locator('#password').fill(ready.password);
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('.desktop-directory button.record', { visible: true });
}
async function leaveDuringRead(page, leave) {
  const captured = active.observers.get(page)?.expect('GET ' + active.path);
  const requested = page.waitForRequest(request => request.method() === 'GET'
    && new URL(request.url()).pathname === active.path, { timeout: 8000 });
  const pending = page.waitForResponse(response => matches(response, 'GET'), { timeout: 8000 });
  requested.catch(() => {}); pending.catch(() => {});
  let arrived = false;
  pending.then(() => { arrived = true; }, () => {});
  try {
    await click(page, PANEL + ' button', READ);
    await requested;
    await leave();
    check(!arrived, 'Lifecycle transition must precede the delayed real GET response');
    const response = await pending;
    check(response.status() === 200, 'Delayed lifecycle response was not real server success');
    return validView(captured ? await captured.promise : await response.json());
  } finally { captured?.cancel(); }
}
async function run(page, ready, report, { engine, disconnectedEvent } = {}) {
  const node = ready.relay_attributes?.node;
  check(node && typeof node.id === 'string' && /^[0-9a-f-]{36}$/.test(node.id)
    && node.name === 'Owned relay attributes node', 'A separate owned relay registration is required');
  const facts = report.relay_attributes_ui = { passed: false, failures: [], response_observers: [],
    scope: 'Production relay metadata controls through actual SDK/server/SQLite; advisory values confer no forwarding rights' };
  active = { node, path: '/api/v3/nodes/' + node.id + '/relay-attributes', facts, observers: new Map() };
  const observe = async (target, name) => {
    if (engine !== 'chrome') return;
    const evidence = {};
    facts.response_observers.push({ page: name, evidence });
    const owner = await prepareManagementResponseObservation({ page: target, origin: ready.origin, disconnectedEvent,
      facts: evidence, routes: ['GET', 'PUT'].map(method => ({ method,
        path: new RegExp('^' + active.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') })) });
    active.observers.set(target, owner);
  };
  let sibling;
  const siblingResponse = response => {
    if (active && new URL(response.url()).pathname === active.path && response.status() >= 400
        && !expectedFailure(response)) {
      report.api_failures.push({ path: active.path, status: response.status() });
    }
  };
  try {
    await observe(page, 'primary');
    facts.stage = 'default_unknown';
    await network(page);
    const initial = await exchange(page, 'GET', () => selectNode(page));
    check(initial.revision === 0 && initial.attributes.region === null && initial.attributes.cost_weight === null,
      'New relay metadata did not start with revision zero and explicit unknown values');
    facts.default_unknown_revision_zero = true;
    sibling = await page.browserContext().newPage();
    sibling.setDefaultTimeout(8000);
    sibling.on('pageerror', error => report.page_errors.push(String(error.message).slice(0, 500)));
    sibling.on('response', siblingResponse);
    await observe(sibling, 'stale-writer');
    await signIn(sibling, ready); await network(sibling);
    const stale = await exchange(sibling, 'GET', () => selectNode(sibling));
    check(stale.revision === initial.revision && stale.attributes.region === null && stale.attributes.cost_weight === null,
      'Independent stale reader did not observe the actual default state');

    facts.stage = 'save_explicit_zero';
    const attributes = { region: 'owned-cn', cost_weight: 0 };
    await fill(page, attributes.region, '0');
    const saved = await save(page, initial, attributes);
    check(saved.revision === initial.revision + 1 && saved.attributes.region === attributes.region
      && saved.attributes.cost_weight === 0, 'Saving explicit zero did not advance revision and preserve zero');
    const persisted = await read(page);
    check(persisted.revision === saved.revision && persisted.attributes.region === attributes.region
      && persisted.attributes.cost_weight === 0, 'Actual reread lost saved region or converted zero to unknown');
    facts.explicit_zero_saved = true;

    facts.stage = 'real_stale_conflict';
    const rejected = { region: 'owned-stale', cost_weight: 7 };
    await fill(sibling, rejected.region, '7');
    await save(sibling, stale, rejected, 409);
    check(await sibling.$eval(PANEL + ' button.primary', element => element.disabled)
      && await sibling.$eval(PANEL + ' [role="alert"]', element => element.textContent.trim().length > 0)
      && await sibling.$eval(PANEL, element => ![...element.querySelectorAll('p')]
        .some(item => /^revision \d+$/.test(item.textContent.trim())))
      && await sibling.$eval(REGION, element => element.value) === rejected.region
      && await sibling.$eval(COST, element => element.value) === '7',
    'Stale conflict retained a writable revision or discarded the failed draft');
    const recovered = await read(sibling);
    check(recovered.revision === saved.revision && recovered.attributes.region === attributes.region
      && recovered.attributes.cost_weight === 0, 'Conflict recovery did not read the actual committed values');
    facts.stale_conflict_requires_reread = true;

    facts.stage = 'clear_to_unknown';
    await fill(sibling, '', '');
    const cleared = await save(sibling, recovered, { region: null, cost_weight: null });
    check(cleared.revision === recovered.revision + 1 && cleared.attributes.region === null
      && cleared.attributes.cost_weight === null, 'Clearing values did not persist explicit unknown with a newer revision');
    const confirmed = await read(page);
    check(confirmed.revision === cleared.revision && confirmed.attributes.region === null
      && confirmed.attributes.cost_weight === null, 'Independent server readback lost the cleared unknown values');
    facts.unknown_clear_persisted = true; facts.revision_bound = true;

    facts.stage = 'unmount_during_read';
    const old = await leaveDuringRead(page, () => click(page, '.sidebar nav button', 'Remote desktop'));
    await page.waitForSelector('.desktop-directory button.record', { visible: true });
    check(old.revision === cleared.revision && await page.$(PANEL) === null,
      'Old real metadata response restored an unmounted editor');
    await network(page);
    check(await page.$(PANEL) === null, 'Old metadata snapshot leaked into a new node selection');
    const remounted = await exchange(page, 'GET', () => selectNode(page));
    check(remounted.revision === cleared.revision && remounted.attributes.region === null
      && remounted.attributes.cost_weight === null, 'Remounted editor did not reread persisted unknown values');
    facts.unmounted_response_ignored = true;

    facts.stage = 'logout_during_read';
    const loggedOut = await leaveDuringRead(sibling, () => click(sibling, '.sidebar-foot button', 'Sign out'));
    await sibling.waitForFunction(() => !document.querySelector('.workspace')
      && document.querySelector('.entry-panel button.primary')?.disabled === false);
    check(loggedOut.revision === cleared.revision && await sibling.$(PANEL) === null,
      'Old real metadata response restored a signed-out editor');
    facts.logout_response_ignored = true;
    await signIn(sibling, ready); await network(sibling);
    check(await sibling.$(PANEL) === null, 'Old session metadata leaked into the new session');
    const newSession = await exchange(sibling, 'GET', () => selectNode(sibling));
    check(newSession.revision === cleared.revision && newSession.attributes.region === null
      && newSession.attributes.cost_weight === null, 'New session failed to read current unknown values');
    facts.new_session_clean = true;
    check(facts.failures.length === 1 && facts.failures[0].status === 409, 'Expected exactly one real stale CAS rejection');
    facts.stage = 'complete'; facts.passed = true;
  } catch (error) {
    facts.failure_state = await page.evaluate(selector => {
      const panel = document.querySelector(selector);
      return { panel_present: !!panel, busy: panel?.getAttribute('aria-busy') ?? null,
        alert_present: !!panel?.querySelector('[role="alert"]'), save_disabled: panel?.querySelector('button.primary')?.disabled ?? null };
    }, PANEL).catch(() => ({ inspection_failed: true }));
    throw error;
  } finally {
    const closed = await Promise.allSettled([...active.observers.values()].map(owner => owner.close()));
    facts.response_observers_closed = closed.every(result => result.status === 'fulfilled');
    facts.passed &&= facts.response_observers_closed;
    if (sibling) { sibling.off('response', siblingResponse); await sibling.close(); }
    active = null;
    await click(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForSelector('.desktop-directory button.record', { visible: true });
    check(facts.response_observers_closed, 'Owned relay metadata response observer cleanup failed');
  }
}
module.exports = { run, expectedFailure };
