// Production space controls -> typed SDK -> real server/SQLite, without mocks.
'use strict';
const { randomUUID } = require('node:crypto');
const { prepareManagementResponseObservation } = require('./refactor-browser-response-observer.cjs');
const subnetUi = require('./refactor-browser-subnet.cjs');
const wireguardUi = require('./refactor-browser-wireguard.cjs');
const PANEL = '[aria-label="Network spaces"]';
const field = name => PANEL + ' [data-space-field="' + name + '"]';
let active = null;
function check(value, message) { if (!value) throw new Error('Spaces UI: ' + message); }
function matches(response, method, pathname) {
  return response.request().method() === method && new URL(response.url()).pathname === pathname;
}
function expectedFailure(response) {
  if (!active?.base) return false;
  const pathname = new URL(response.url()).pathname;
  if (pathname !== active.base && !pathname.startsWith(active.base + '/')) return false;
  const status = response.status(), method = response.request().method();
  const allowed = (status === 409 && method === 'POST' && pathname.endsWith('/archive'))
    || (status === 403 && ((method === 'GET' && pathname === active.base)
      || (method === 'POST' && pathname.endsWith('/accept'))));
  if (allowed) active.failures.push({ method, status });
  return allowed;
}
async function click(page, selector, text, prefix = false) {
  for (const button of await page.$$(selector)) {
    if (await button.evaluate(element => element.disabled)) continue;
    const actual = await button.evaluate(element => element.textContent.trim());
    if (actual === text || (prefix && actual.startsWith(text))) { await button.click(); return; }
  }
  throw new Error('Spaces UI action missing: ' + text);
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
    { timeout: 12000 }, PANEL);
}
async function security(page) {
  await page.bringToFront();
  await click(page, '.sidebar-foot button', 'Account and security');
  await page.waitForSelector(PANEL, { visible: true, timeout: 12000 });
  await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
}
async function action(page, text, method, pathname, status = 200) {
  const captured = status === 200 || status === 201 ? active.observers.get(page)?.expect(method + ' ' + pathname, status, 12000) : null;
  const pending = page.waitForResponse(response => matches(response, method, pathname), { timeout: 12000 });
  try {
    await click(page, PANEL + ' button', text);
    const response = await pending;
    check(response.status() === status, text + ' returned unexpected status ' + response.status());
    const body = status !== 200 && status !== 201 ? null : captured ? await captured.promise : await response.json();
    await settled(page);
    return { response, body };
  } finally { captured?.cancel(); }
}
async function read(page, name) {
  const pending = page.waitForResponse(response => matches(response, 'GET', active.base), { timeout: 12000 });
  await click(page, PANEL + ' button', name + ' · ', true);
  check((await pending).status() === 200, 'Space read failed');
  await settled(page);
}
async function signIn(page, ready, username, link) {
  await page.goto(link || ready.origin, { waitUntil: 'networkidle0' });
  await page.locator('.language-selector button[lang="en"]').click();
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('#username', { visible: true });
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(ready.password);
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('.workspace', { visible: true });
  await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
}
async function run(page, ready, report, { engine, disconnectedEvent } = {}) {
  const facts = report.spaces_ui = { passed: false, failures: [], scope: 'Production account/space controls, isolated recipient browser context, real HTTP and SQLite' };
  active = { base: null, failures: facts.failures, observers: new Map() };
  const observe = async (target, name) => {
    if (engine !== 'chrome') return;
    const evidence = {};
    (facts.response_observers ??= []).push({ page: name, evidence });
    const path = /^\/api\/v3\/network\/spaces(?:\/[0-9a-f-]{36}(?:\/(?:devices|people|invitations)(?:\/[0-9a-f-]{36}(?:\/accept)?)?|\/(?:archive|audit))?)?$/;
    const owner = await prepareManagementResponseObservation({ page: target, origin: ready.origin,
      disconnectedEvent, facts: evidence,
      routes: [{ method: 'POST', path: /^\/api\/v3\/accounts$/ },
        ...['GET', 'POST', 'PUT', 'DELETE'].map(method => ({ method, path }))] });
    active.observers.set(target, owner);
  };
  const suffix = randomUUID().slice(0, 8);
  const username = 'space-ui-' + suffix, name = 'Space UI ' + suffix;
  let context;
  try {
    await observe(page, 'space-owner');
    facts.stage = 'create_recipient_account';
    await click(page, '.sidebar nav button', 'Account');
    await page.waitForSelector('#new-account', { visible: true });
    await page.waitForFunction(() => document.querySelector('#new-account')?.disabled === false);
    await page.locator('#new-account').fill(username);
    await page.locator('#new-account-password').fill(ready.password);
    let pending = page.waitForResponse(response => matches(response, 'POST', '/api/v3/accounts'));
    const accountCapture = active.observers.get(page)?.expect('POST /api/v3/accounts', 201, 12000);
    let account;
    try {
      await page.locator('.inline-create button[type="submit"]').click();
      const accountResponse = await pending;
      check(accountResponse.status() === 201, 'Recipient account was not created through UI');
      account = (accountCapture ? await accountCapture.promise : await accountResponse.json()).id;
    } finally { accountCapture?.cancel(); }
    check(typeof account === 'string', 'Recipient account ID missing');
    await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);

    facts.stage = 'create_space_and_join_device';
    await security(page);
    await page.locator(field('name')).fill(name);
    const createdResponse = await action(page, 'Create space', 'POST', '/api/v3/network/spaces', 201);
    const windowStarted = Date.now();
    const created = createdResponse.body;
    active.base = '/api/v3/network/spaces/' + created.space_id;
    await page.select(field('device'), ready.host_device_id);
    const joined = await action(page, 'Join or rejoin device', 'POST', active.base + '/devices');
    const joinBody = JSON.parse(joined.response.request().postData());
    check(joinBody.expected_revision === created.revision && joinBody.expected_membership_epoch === 0,
      'Device join did not use current revision and explicit epoch zero');
    facts.created_and_device_joined = true;

    facts.stage = 'subnet_management_lifecycle';
    await subnetUi.run(page, created.space_id, report);
    facts.stage = 'wireguard_client_management_lifecycle';
    await wireguardUi.run(page, created.space_id, report);
    await security(page);
    await action(page, 'Read my spaces', 'GET', '/api/v3/network/spaces');
    await read(page, name);

    facts.stage = 'one_use_guest_invitation';
    await page.select(field('role'), 'guest');
    await page.locator(field('target')).fill(account);
    const issued = await action(page, 'Create one-use invitation', 'POST', active.base + '/invitations', 201);
    const invitation = issued.body;
    const link = await page.$eval(field('issued'), element => element.value);
    check(link.startsWith(ready.origin + '/#space-invite=') && link.endsWith(invitation.token), 'Invitation link lost its scoped secret fragment');
    // The independent context prevents recipient sign-in from reusing the
    // deployment administrator's cookies, IndexedDB, localStorage or identity.
    context = await page.browser().createBrowserContext();
    const recipient = await context.newPage();
    await observe(recipient, 'invited-recipient');
    recipient.setDefaultTimeout(12000);
    recipient.on('pageerror', error => report.page_errors.push(String(error.message).slice(0, 500)));
    await signIn(recipient, ready, username, link);
    await recipient.waitForSelector(PANEL, { visible: true });
    check(await recipient.$eval(field('incoming'), element => element.value) === link,
      'Invitation link did not open its real acceptance controls after sign-in');
    check(await recipient.evaluate(() => location.hash) === '', 'Invitation secret remained in browser history URL');
    facts.invitation_link_opens_acceptance = true;
    const accepted = await action(recipient, 'Accept invitation', 'POST', active.base + '/invitations/' + invitation.invitation.invitation_id + '/accept');
    check(accepted.body.role === 'guest', 'Recipient did not get exact invited role');
    check(await recipient.$(field('role')) === null && await recipient.$(field('issued')) === null,
      'Guest received invitation/role management controls');
    facts.guest_isolated_context = true;
    await recipient.locator(field('incoming')).fill(link);
    await action(recipient, 'Accept invitation', 'POST', active.base + '/invitations/' + invitation.invitation.invitation_id + '/accept', 403);
    check(await recipient.$(field('device')) === null, 'Replay failure retained a writable snapshot');
    check(await recipient.$eval(field('incoming'), element => element.value) === link, 'Rejected invitation draft was lost');
    facts.invitation_single_use = true;

    facts.stage = 'conflict_and_roles';
    await page.bringToFront();
    await action(page, 'Archive space and revoke all devices and invitations', 'POST', active.base + '/archive', 409);
    check(await page.$(field('role')) === null, 'Stale revision remained writable');
    await read(page, name);
    await page.select(field('account'), account);
    await page.select(field('role'), 'member');
    const member = await action(page, 'Save role or transfer ownership', 'PUT', active.base + '/people/' + account);
    check(JSON.parse(member.response.request().postData()).role === 'member', 'Member role choice was lost');
    await recipient.bringToFront();
    await action(recipient, 'Read my spaces', 'GET', '/api/v3/network/spaces'); await read(recipient, name);
    check(await recipient.$(field('role')) === null, 'Ordinary member received role management controls');
    await page.bringToFront(); await page.select(field('role'), 'admin');
    await action(page, 'Save role or transfer ownership', 'PUT', active.base + '/people/' + account);
    await recipient.bringToFront(); await read(recipient, name);
    const allowedRoles = await recipient.$$eval(field('role') + ' option', options => options.map(option => option.value));
    check(allowedRoles.includes('member') && allowedRoles.includes('guest') && !allowedRoles.includes('admin') && !allowedRoles.includes('owner'),
      'Delegated administrator UI permits privilege escalation');
    const delegated = await action(recipient, 'Create one-use invitation', 'POST', active.base + '/invitations', 201);
    check(delegated.body.invitation.role === 'member', 'Delegated administrator failed to create member invitation');
    facts.owner_admin_member_guest = true; facts.stale_revision_rejected = true;

    facts.stage = 'revoke_and_audit';
    // Production space actions share a 30-request/60-second session budget.
    // Each UI action reads back the current listing and details, so this long
    // sequence must wait for the original window instead of raising the limit
    // or accepting 429 as a successful mutation.
    await new Promise(resolve => setTimeout(resolve, Math.max(0, 61_000 - (Date.now() - windowStarted))));
    await page.bringToFront(); await read(page, name);
    await action(page, 'Revoke invitation', 'DELETE', active.base + '/invitations/' + delegated.body.invitation.invitation_id);
    await page.select(field('account'), account);
    await action(page, 'Remove member and their space devices', 'DELETE', active.base + '/people/' + account);
    await recipient.bringToFront();
    // This control still holds the recipient's former admin snapshot. Its
    // mandatory current-space read must reject before another invitation write.
    await action(recipient, 'Create one-use invitation', 'GET', active.base, 403);
    check(await recipient.$(field('role')) === null, 'Removed account retained management state');
    await page.bringToFront();
    const audit = await action(page, 'Read latest 100 space audit entries', 'GET', active.base + '/audit');
    check(audit.body.some(entry => entry.action === 'network_space_member_removed'), 'Space audit did not record real member removal');
    await action(page, 'Remove device', 'DELETE', active.base + '/devices/' + ready.host_device_id);
    const archived = await action(page, 'Archive space and revoke all devices and invitations', 'POST', active.base + '/archive');
    check(archived.body.archived, 'Server did not archive space');
    check(await page.$(field('role')) === null, 'Archived space retained management controls');
    facts.revocation_and_audit = true; facts.archive_blocks_changes = true;

    facts.stage = 'late_reply_and_secret_cleanup';
    let arrived = false;
    pending = page.waitForResponse(response => matches(response, 'GET', active.base));
    pending.then(() => { arrived = true; });
    const requested = page.waitForRequest(request => request.method() === 'GET' && new URL(request.url()).pathname === active.base);
    await click(page, PANEL + ' button', name + ' · ', true); await requested;
    await click(page, '.sidebar nav button', 'Remote desktop');
    check(!arrived, 'Unmount did not precede delayed real space reply');
    check((await pending).status() === 200, 'Delayed space response was not real success');
    await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
    await security(page);
    check(await page.$(field('issued')) === null && await page.$(field('device')) === null,
      'Unmounted panel leaked a secret or old space snapshot into a new panel');
    facts.unmount_clears_secret_and_snapshot = true;
    facts.stage = 'complete'; facts.passed = true;
  } finally {
    const closed = await Promise.allSettled([...active.observers.values()].map(owner => owner.close()));
    facts.response_observers_closed = closed.every(result => result.status === 'fulfilled');
    facts.passed &&= facts.response_observers_closed;
    active = null;
    if (context) await context.close();
    await page.bringToFront();
    await click(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
    check(facts.response_observers_closed, 'Owned management response observer cleanup failed');
  }
}
module.exports = { run, expectedFailure };
