// Compiled production controls, SDK and real server/SQLite. No response or DOM mocks.
'use strict';
const { randomUUID } = require('node:crypto');
const { prepareManagementResponseObservation } = require('./refactor-browser-response-observer.cjs');
const PANEL = '[aria-label="Space membership"]';
const SPACE = PANEL + ' input';
const DEVICE = PANEL + ' label:nth-of-type(2) select';
const ROLE = PANEL + ' label:nth-of-type(3) select';
const ACTION = {
  read: 'Read space and devices', initialize: 'Initialize this ID (existing spaces are rejected)',
  member: 'Read membership', add: 'Enroll device for the first time (existing membership is rejected)',
  update: 'Save role or re-enroll', revoke: 'Remove device',
};
let active = null;
function check(value, message) { if (!value) throw new Error('Network membership UI: ' + message); }
function matches(response, method, pathname) {
  return response.request().method() === method && new URL(response.url()).pathname === pathname;
}
function expectedFailure(response) {
  if (!active || !active.paths.has(new URL(response.url()).pathname)) return false;
  const method = response.request().method(), status = response.status();
  if ((method === 'GET' && status === 403) || (method === 'PUT' && status === 409)) {
    active.failures.push({ method, status });
    return true;
  }
  return false;
}
async function click(page, selector, text) {
  for (const button of await page.$$(selector)) {
    if (await button.evaluate(el => el.textContent.trim()) === text) {
      await button.click(); return;
    }
  }
  throw new Error('Network membership UI action missing: ' + text);
}
async function network(page) {
  await page.bringToFront();
  await click(page, '.sidebar nav button', 'Network and nodes');
  await page.waitForSelector(PANEL, { visible: true, timeout: 8000 });
  await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
    { timeout: 8000 }, PANEL);
}
async function action(page, operation, expectedStatus = 200) {
  await page.bringToFront();
  const method = operation === 'read' || operation === 'member' ? 'GET' : operation === 'revoke' ? 'DELETE' : 'PUT';
  const pathname = operation === 'read' ? active.policy : operation === 'initialize' ? active.authority : active.member;
  const captured = expectedStatus === 200 ? active.observers.get(page)?.expect(method + ' ' + pathname) : null;
  const pending = page.waitForResponse(response => matches(response, method, pathname), { timeout: 8000 });
  try {
    await click(page, PANEL + ' button', ACTION[operation]);
    const response = await pending;
    check(response.status() === expectedStatus, operation + ' returned unexpected HTTP status ' + response.status());
    const body = expectedStatus !== 200 ? null : captured ? await captured.promise : await response.json();
    await settled(page);
    return { response, body };
  } finally { captured?.cancel(); }
}
async function readPolicy(page) { return (await action(page, 'read')).body; }
async function readMember(page) { return (await action(page, 'member')).body; }
async function chooseDevice(page, id) {
  await page.select(DEVICE, id);
  check(await page.$eval(DEVICE, el => el.value) === id, 'Registered fixture device is missing');
}
async function chooseRole(page, value) {
  await page.select(ROLE, value);
  check(await page.$eval(ROLE, el => el.value) === value, 'Role entry did not reach the real select');
}
async function mutation(page, operation, snapshot, role, expectedStatus = 200) {
  const { response, body: result } = await action(page, operation, expectedStatus);
  const body = JSON.parse(response.request().postData());
  check(body.expected_policy_revision === snapshot.revision
    && body.expected_membership_epoch === snapshot.epoch, 'Mutation did not bind the actual revision and membership epoch');
  if (operation !== 'revoke') check(body.role === role, 'Mutation lost the selected role');
  return result;
}
function snapshot(view) { return { revision: view.policy.revision, epoch: view.membership_epoch }; }
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
async function run(page, ready, report, { engine, disconnectedEvent } = {}) {
  const space = randomUUID();
  const base = '/api/v3/network/spaces/' + space;
  const facts = report.network_membership_ui = { passed: false, failures: [],
    scope: 'Production membership controls through actual SDK, server and SQLite; delayed real GET replies for lifecycle races' };
  active = { policy: base + '/policy', authority: base + '/authority',
    member: base + '/members/' + ready.host_device_id, failures: facts.failures };
  active.paths = new Set([active.policy, active.authority, active.member]);
  active.observers = new Map();
  const observe = async (target, name) => {
    if (engine !== 'chrome') return;
    const evidence = {};
    (facts.response_observers ??= []).push({ page: name, evidence });
    const owner = await prepareManagementResponseObservation({ page: target, origin: ready.origin,
      disconnectedEvent, facts: evidence,
      routes: [...active.paths].flatMap(path => ['GET', 'PUT', 'DELETE'].map(method =>
        ({ method, path: new RegExp('^' + path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') }))),
    });
    active.observers.set(target, owner);
  };
  let sibling;
  try {
    await observe(page, 'primary');
    facts.stage = 'explicit_initialization';
    await network(page);
    await page.locator(SPACE).fill(space);
    await action(page, 'read', 403);
    check(await page.$eval(PANEL + ' [role="alert"]', el => el.textContent.length > 0), 'GET403 must remain an error');
    check(await page.$(DEVICE) === null, 'GET403 inferred an initialized space');
    const initialized = (await action(page, 'initialize')).body;
    check(initialized.space_id === space && initialized.revision > 0, 'Explicit initialization did not return server policy');
    // Changing the target discards its snapshot. A second explicit zero write
    // must be rejected by the server even without inferring existence from GET.
    await page.locator(SPACE).fill(randomUUID());
    await page.locator(SPACE).fill(space);
    check(JSON.parse((await action(page, 'initialize', 409)).response.request().postData()).expected_revision === 0,
      'Repeated explicit initialization must keep revision zero and conflict');
    await readPolicy(page);
    await chooseDevice(page, ready.host_device_id);
    await chooseRole(page, 'guest');
    await action(page, 'member', 403);
    check(await page.$(DEVICE) === null, 'Missing-member GET403 supplied a writable snapshot');
    const policy = await readPolicy(page);
    check(await page.$eval(DEVICE, el => el.value) === ready.host_device_id, 'Failed read lost device draft');
    check(await page.$eval(ROLE, el => el.value) === 'guest', 'Failed read/re-read lost role draft');
    const first = await mutation(page, 'add', { revision: policy.revision, epoch: 0 }, 'guest');
    check(first.active && first.role === 'guest' && first.membership_epoch > 0, 'First enrollment did not return live membership');
    facts.forbidden_is_error = true; facts.explicit_initialization = true;
    facts.explicit_epoch_zero = true; facts.failed_read_preserves_draft = true;

    facts.stage = 'real_concurrent_conflict';
    sibling = await page.browserContext().newPage();
    await observe(sibling, 'concurrent-writer');
    sibling.setDefaultTimeout(8000);
    sibling.on('pageerror', error => report.page_errors.push(String(error.message).slice(0, 500)));
    await signIn(sibling, ready); await network(sibling);
    await sibling.locator(SPACE).fill(space);
    await readPolicy(sibling); await chooseDevice(sibling, ready.host_device_id);
    const old = await readMember(sibling);
    await chooseRole(sibling, 'admin');
    const concurrent = await mutation(sibling, 'update', snapshot(old), 'admin');
    check(concurrent.role === 'admin' && concurrent.membership_epoch > first.membership_epoch,
      'Concurrent real writer did not advance membership');
    await page.bringToFront(); await chooseRole(page, 'owner');
    await mutation(page, 'update', snapshot(first), 'owner', 409);
    check(await page.$(ROLE) === null, 'CAS conflict left a stale writable snapshot');
    check(await page.$eval(PANEL + ' [role="alert"]', el => el.textContent.length > 0), 'CAS conflict was not shown');
    await readPolicy(page);
    check(await page.$eval(ROLE, el => el.value) === 'owner', 'Policy re-read replaced failed role draft');
    const refreshed = await readMember(page);
    check(refreshed.role === 'admin', 'Conflict recovery did not read committed server role');
    check(await page.$eval(ROLE, el => el.value) === 'owner', 'Member re-read replaced failed role draft');
    const saved = await mutation(page, 'update', snapshot(refreshed), 'owner');
    check(saved.role === 'owner' && saved.active, 'Recovered write did not save retained role');
    facts.cas_conflict_preserves_draft = true; facts.reread_preserves_draft = true;
    facts.revision_epoch_bound = true;
    const revoked = await mutation(page, 'revoke', snapshot(saved));
    check(!revoked.active && revoked.membership_epoch > saved.membership_epoch, 'Remove did not revoke membership');
    const rejoined = await mutation(page, 'update', snapshot(revoked), 'owner');
    check(rejoined.active && rejoined.membership_epoch > revoked.membership_epoch, 'Re-enrollment did not advance revoked epoch');
    facts.revoke_and_reenroll = true;

    facts.stage = 'unmount_during_read';
    await sibling.bringToFront();
    let arrived = false;
    let pending = sibling.waitForResponse(r => matches(r, 'GET', active.member));
    pending.then(() => { arrived = true; });
    let requested = sibling.waitForRequest(r => r.method() === 'GET' && new URL(r.url()).pathname === active.member);
    await click(sibling, PANEL + ' button', ACTION.member); await requested;
    await click(sibling, '.sidebar nav button', 'Remote desktop');
    check(!arrived, 'Unmount must precede the delayed real member response');
    check((await pending).status() === 200, 'Old member response was not real server success');
    await sibling.waitForSelector('.desktop-directory button.record', { visible: true });
    await sibling.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
    await network(sibling);
    check(await sibling.$eval(SPACE, el => el.value) === '' && await sibling.$(DEVICE) === null,
      'Unmounted response leaked membership into a new panel');
    facts.unmounted_response_ignored = true;

    facts.stage = 'logout_during_policy_read';
    await sibling.locator(SPACE).fill(space);
    let deviceReads = 0;
    const observeDevices = request => {
      if (request.method() === 'GET' && new URL(request.url()).pathname === '/api/v3/devices') deviceReads++;
    };
    sibling.on('request', observeDevices);
    arrived = false;
    pending = sibling.waitForResponse(r => matches(r, 'GET', active.policy));
    pending.then(() => { arrived = true; });
    requested = sibling.waitForRequest(r => r.method() === 'GET' && new URL(r.url()).pathname === active.policy);
    await click(sibling, PANEL + ' button', ACTION.read); await requested;
    await click(sibling, '.sidebar-foot button', 'Sign out');
    check(!arrived, 'Logout must precede the delayed real policy response');
    check((await pending).status() === 200, 'Old policy response was not real server success');
    await sibling.waitForFunction(() => !document.querySelector('.workspace')
      && document.querySelector('.entry-panel button.primary')?.disabled === false);
    sibling.off('request', observeDevices);
    check(deviceReads === 0, 'Old policy reply started a device request after logout');
    check(await sibling.$(PANEL) === null, 'Old policy response restored signed-out UI');
    await signIn(sibling, ready); await network(sibling);
    check(await sibling.$eval(SPACE, el => el.value) === '' && await sibling.$(DEVICE) === null,
      'Old session response leaked into a new login');
    facts.logout_response_ignored = true; facts.new_session_clean = true;
    check(facts.failures.filter(f => f.method === 'GET' && f.status === 403).length === 2,
      'Expected two real forbidden reads');
    check(facts.failures.filter(f => f.method === 'PUT' && f.status === 409).length === 2,
      'Expected real duplicate-initialization and stale-write conflicts');
    facts.stage = 'complete'; facts.passed = true;
  } catch (error) {
    facts.failure_state = await page.evaluate(selector => {
      const panel = document.querySelector(selector);
      return { panel_present: !!panel, busy: panel?.getAttribute('aria-busy') ?? null,
        alert: panel?.querySelector('[role="alert"]')?.textContent.trim().slice(0, 500) ?? null,
        select_count: panel?.querySelectorAll('select').length ?? 0 };
    }, PANEL).catch(() => ({ inspection_failed: true }));
    throw error;
  } finally {
    const closed = await Promise.allSettled([...active.observers.values()].map(owner => owner.close()));
    facts.response_observers_closed = closed.every(result => result.status === 'fulfilled');
    facts.passed &&= facts.response_observers_closed;
    active = null;
    if (sibling) await sibling.close();
    await page.bringToFront();
    await click(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForSelector('.desktop-directory button.record', { visible: true });
    check(facts.response_observers_closed, 'Owned management response observer cleanup failed');
  }
}
module.exports = { run, expectedFailure };
