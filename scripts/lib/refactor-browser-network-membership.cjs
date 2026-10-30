// Compiled production controls, SDK and real server/SQLite. No response or DOM mocks.
'use strict';
const { randomUUID } = require('node:crypto');
const { prepareManagementResponseObservation } = require('./refactor-browser-response-observer.cjs');
const PANEL = '[aria-label="Space membership"]';
const SPACE = PANEL + ' input';
const DEVICE = PANEL + ' label:nth-of-type(2) select';
const ROLE = PANEL + ' label:nth-of-type(3) select';
const AUTHORITY = '[aria-label="Space authority lifecycle"]';
const AUTHORITY_ACTION = { read: 'Read authority state', rotate: 'Rotate space signing key',
  advance: 'Advance policy epoch', revoke: 'Permanently revoke space authority' };
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
  if (active?.authorityCase && response.request().method() === 'POST'
      && new URL(response.url()).pathname === active.rotate && response.status() === 409) {
    active.authorityFailures.push({ method: 'POST', status: 409 });
    return true;
  }
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
async function authorityDisabled(page, operation) {
  for (const button of await page.$$(AUTHORITY + ' button')) {
    if (await button.evaluate(element => element.textContent.trim()) === AUTHORITY_ACTION[operation]) {
      return button.evaluate(element => element.disabled);
    }
  }
  throw new Error('Network authority UI action missing: ' + operation);
}
async function authorityAction(page, operation, previous = null, status = operation === 'revoke' ? 204 : 200) {
  await page.bringToFront();
  const method = operation === 'read' ? 'GET' : operation === 'revoke' ? 'DELETE' : 'POST';
  const pathname = operation === 'rotate' ? active.rotate : operation === 'advance' ? active.advance : active.authority;
  const success = status === 200 || status === 204;
  // Every successful mutation performs a real GET before rendering its state.
  // Register that readback before the click, on the same bounded owned session.
  const captured = success ? active.observers.get(page)?.expect('GET ' + active.authority) : null;
  const readback = success ? page.waitForResponse(response => matches(response, 'GET', active.authority), { timeout: 8000 }) : null;
  const pending = page.waitForResponse(response => matches(response, method, pathname), { timeout: 8000 });
  // A click or HTTP failure may end this action before its readback exists.
  // Keep the original rejection awaitable without an unhandled late promise.
  readback?.catch(() => {}); pending.catch(() => {});
  try {
    await click(page, AUTHORITY + ' button', AUTHORITY_ACTION[operation]);
    const response = await pending;
    check(response.status() === status, 'Authority ' + operation + ' returned unexpected HTTP status ' + response.status());
    if (previous) {
      const sent = JSON.parse(response.request().postData());
      check(sent.expected_revision === previous.policy.revision && sent.expected_policy_epoch === previous.policy.policy_epoch,
        'Authority mutation did not bind the actual revision and policy epoch');
    }
    let view = null;
    if (success) {
      const confirmed = await readback;
      check(confirmed.status() === 200, 'Authority state readback did not return HTTP 200');
      view = captured ? await captured.promise : await confirmed.json();
      check(view.policy.space_id === active.space && Number.isSafeInteger(view.policy.revision) && view.policy.revision > 0
        && Number.isSafeInteger(view.policy.policy_epoch) && view.policy.policy_epoch > 0
        && Number.isSafeInteger(view.signing_generation) && view.signing_generation >= 0
        && typeof view.revoked === 'boolean' && /^[A-Za-z0-9_-]{43}$/.test(view.policy.authority_public_key),
      'Authority readback did not contain the actual bounded server state');
    }
    await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
      { timeout: 8000 }, AUTHORITY);
    if (view) {
      const rendered = await page.$eval(AUTHORITY, element => Object.fromEntries(
        [...element.querySelectorAll('[data-network-authority]')].map(item => [item.dataset.networkAuthority, item.textContent.trim()])));
      check(Number(rendered.revision) === view.policy.revision && Number(rendered.epoch) === view.policy.policy_epoch
        && Number(rendered.generation) === view.signing_generation && rendered.key === view.policy.authority_public_key
        && rendered.state === (view.revoked ? 'Permanently revoked' : 'Active'),
      'Authority controls did not render the confirmed server state');
    }
    return view;
  } finally { captured?.cancel(); }
}
async function authorityLifecycle(page, sibling, report) {
  const facts = report.network_authority_ui = { passed: false, failures: [],
    scope: 'Production authority controls, typed SDK and actual server/SQLite; two independently stale browser snapshots' };
  active.authorityFailures = facts.failures;
  active.authorityCase = true;
  // The integration runner observes the primary page's responses. This real
  // conflicting write belongs to the independently stale sibling page.
  const siblingResponse = response => {
    const pathname = new URL(response.url()).pathname;
    if (response.status() >= 400 && [active.authority, active.rotate, active.advance].includes(pathname)
        && !expectedFailure(response)) {
      report.api_failures.push({ path: pathname, status: response.status() });
    }
  };
  sibling.on('response', siblingResponse);
  try {
    facts.stage = 'read_same_space';
    await sibling.locator(SPACE).fill(active.space);
    const initial = await authorityAction(page, 'read');
    const old = await authorityAction(sibling, 'read');
    check(!initial.revoked && old.policy.revision === initial.policy.revision
      && old.policy.policy_epoch === initial.policy.policy_epoch && old.policy.authority_public_key === initial.policy.authority_public_key,
    'Concurrent authority readers did not observe the same active state');
    facts.stage = 'rotate';
    const rotated = await authorityAction(page, 'rotate', initial);
    check(!rotated.revoked && rotated.signing_generation === initial.signing_generation + 1
      && rotated.policy.revision === initial.policy.revision + 1 && rotated.policy.policy_epoch === initial.policy.policy_epoch + 1
      && rotated.policy.authority_public_key !== initial.policy.authority_public_key,
    'Rotation did not advance both epochs and replace the actual signing key');
    facts.rotation_advances_and_changes_key = true;
    facts.stage = 'stale_cas_conflict';
    await authorityAction(sibling, 'rotate', old, 409);
    check(await sibling.$(AUTHORITY + ' [data-network-authority="revision"]') === null
      && await sibling.$eval(AUTHORITY + ' [role="alert"]', element => element.textContent.trim().length > 0)
      && await authorityDisabled(sibling, 'rotate'), 'Authority conflict retained a writable stale snapshot');
    const recovered = await authorityAction(sibling, 'read');
    check(recovered.policy.revision === rotated.policy.revision && recovered.signing_generation === rotated.signing_generation
      && recovered.policy.authority_public_key === rotated.policy.authority_public_key, 'Conflict recovery did not read the committed rotation');
    facts.stale_conflict_requires_reread = true;
    facts.stage = 'advance_policy_epoch';
    const advanced = await authorityAction(sibling, 'advance', recovered);
    check(!advanced.revoked && advanced.policy.revision === rotated.policy.revision + 1
      && advanced.policy.policy_epoch === rotated.policy.policy_epoch + 1 && advanced.signing_generation === rotated.signing_generation
      && advanced.policy.authority_public_key === rotated.policy.authority_public_key,
    'Policy advance did not preserve the signing key while advancing revision and policy epoch');
    facts.policy_epoch_advances_without_key_change = true;
    facts.stage = 'permanent_revocation';
    const current = await authorityAction(page, 'read');
    check(current.policy.revision === advanced.policy.revision && current.policy.policy_epoch === advanced.policy.policy_epoch,
      'Primary authority read did not observe the actual concurrent policy advance');
    check(await authorityDisabled(page, 'revoke'), 'Permanent revocation was enabled without explicit confirmation');
    await page.locator(AUTHORITY + ' input[type="checkbox"]').click();
    check(!await authorityDisabled(page, 'revoke'), 'Explicit revocation confirmation did not enable the action');
    const terminal = await authorityAction(page, 'revoke', current);
    check(terminal.revoked && terminal.policy.revision === current.policy.revision + 1
      && terminal.policy.policy_epoch === current.policy.policy_epoch + 1 && terminal.signing_generation === current.signing_generation
      && terminal.policy.authority_public_key === current.policy.authority_public_key,
    'Permanent revocation was not confirmed by actual terminal server state');
    const reread = await authorityAction(sibling, 'read');
    check(reread.revoked && reread.policy.revision === terminal.policy.revision,
      'Independent authority read lost the permanent terminal state');
    facts.permanent_revocation_readback = true;
    for (const target of [page, sibling]) {
      for (const operation of ['rotate', 'advance', 'revoke']) {
        check(await authorityDisabled(target, operation), 'Terminal authority retained an enabled mutation');
      }
      check(await target.$eval(AUTHORITY + ' input[type="checkbox"]', element => element.disabled && !element.checked),
        'Terminal authority retained an active confirmation');
    }
    check(facts.failures.length === 1 && facts.failures[0].status === 409, 'Expected one actual stale authority conflict');
    facts.terminal_controls_disabled = true; facts.revision_epoch_bound = true;
    facts.stage = 'complete'; facts.passed = true;
  } finally {
    sibling.off('response', siblingResponse);
    active.authorityCase = false;
  }
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
async function run(page, ready, report, { engine, disconnectedEvent } = {}) {
  const space = randomUUID();
  const base = '/api/v3/network/spaces/' + space;
  const facts = report.network_membership_ui = { passed: false, failures: [],
    scope: 'Production membership controls through actual SDK, server and SQLite; delayed real GET replies for lifecycle races' };
  active = { space, policy: base + '/policy', authority: base + '/authority', rotate: base + '/authority/rotate', advance: base + '/policy/advance',
    member: base + '/members/' + ready.host_device_id, failures: facts.failures };
  active.paths = new Set([active.policy, active.authority, active.member]);
  active.observers = new Map();
  const observe = async (target, name) => {
    if (engine !== 'chrome') return;
    const evidence = {};
    (facts.response_observers ??= []).push({ page: name, evidence });
    const owner = await prepareManagementResponseObservation({ page: target, origin: ready.origin,
      disconnectedEvent, facts: evidence,
      routes: [...active.paths, active.rotate, active.advance].flatMap(path => ['GET', 'PUT', 'POST', 'DELETE'].map(method =>
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
    facts.stage = 'authority_lifecycle';
    await authorityLifecycle(page, sibling, report);
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
    if (report.network_authority_ui) report.network_authority_ui.passed &&= facts.response_observers_closed;
    active = null;
    if (sibling) await sibling.close();
    await page.bringToFront();
    await click(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForSelector('.desktop-directory button.record', { visible: true });
    check(facts.response_observers_closed, 'Owned management response observer cleanup failed');
  }
}
module.exports = { run, expectedFailure };
