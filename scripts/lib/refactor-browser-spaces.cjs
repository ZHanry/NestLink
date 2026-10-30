// Production space controls -> typed SDK -> real server/SQLite, without mocks.
'use strict';
const { randomUUID } = require('node:crypto');
const PANEL = '[aria-label="Network spaces"]';
const field = name => PANEL + ' [data-space-field="' + name + '"]';
let active = null;
function check(value, message) { if (!value) throw new Error('Spaces UI: ' + message); }
function matches(response, method, pathname) {
  return response.request().method() === method && new URL(response.url()).pathname === pathname;
}
function expectedFailure(response) {
  if (!active) return false;
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
  const pending = page.waitForResponse(response => matches(response, method, pathname), { timeout: 12000 });
  await click(page, PANEL + ' button', text);
  const response = await pending;
  check(response.status() === status, text + ' returned unexpected status ' + response.status());
  await settled(page);
  return response;
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
async function run(page, ready, report) {
  const facts = report.spaces_ui = { passed: false, failures: [], scope: 'Production account/space controls, isolated recipient browser context, real HTTP and SQLite' };
  const suffix = randomUUID().slice(0, 8);
  const username = 'space-ui-' + suffix, name = 'Space UI ' + suffix;
  let context;
  try {
    facts.stage = 'create_recipient_account';
    await click(page, '.sidebar nav button', 'Account');
    await page.waitForSelector('#new-account', { visible: true });
    await page.waitForFunction(() => document.querySelector('#new-account')?.disabled === false);
    await page.locator('#new-account').fill(username);
    await page.locator('#new-account-password').fill(ready.password);
    let pending = page.waitForResponse(response => matches(response, 'POST', '/api/v3/accounts'));
    await page.locator('.inline-create button[type="submit"]').click();
    const accountResponse = await pending;
    check(accountResponse.status() === 201, 'Recipient account was not created through UI');
    const account = (await accountResponse.json()).id;
    check(typeof account === 'string', 'Recipient account ID missing');
    await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);

    facts.stage = 'create_space_and_join_device';
    await security(page);
    await page.locator(field('name')).fill(name);
    const createdResponse = await action(page, 'Create space', 'POST', '/api/v3/network/spaces', 201);
    const created = await createdResponse.json();
    active = { base: '/api/v3/network/spaces/' + created.space_id, failures: facts.failures };
    await page.select(field('device'), ready.host_device_id);
    const joined = await action(page, 'Join or rejoin device', 'POST', active.base + '/devices');
    const joinBody = JSON.parse(joined.request().postData());
    check(joinBody.expected_revision === created.revision && joinBody.expected_membership_epoch === 0,
      'Device join did not use current revision and explicit epoch zero');
    facts.created_and_device_joined = true;

    facts.stage = 'one_use_guest_invitation';
    await page.select(field('role'), 'guest');
    await page.locator(field('target')).fill(account);
    const issued = await action(page, 'Create one-use invitation', 'POST', active.base + '/invitations', 201);
    const invitation = await issued.json();
    const link = await page.$eval(field('issued'), element => element.value);
    check(link.startsWith(ready.origin + '/#space-invite=') && link.endsWith(invitation.token), 'Invitation link lost its scoped secret fragment');
    // The independent context prevents recipient sign-in from reusing the
    // deployment administrator's cookies, IndexedDB, localStorage or identity.
    context = await page.browser().createBrowserContext();
    const recipient = await context.newPage();
    recipient.setDefaultTimeout(12000);
    recipient.on('pageerror', error => report.page_errors.push(String(error.message).slice(0, 500)));
    await signIn(recipient, ready, username, link);
    await recipient.waitForSelector(PANEL, { visible: true });
    check(await recipient.$eval(field('incoming'), element => element.value) === link,
      'Invitation link did not open its real acceptance controls after sign-in');
    check(await recipient.evaluate(() => location.hash) === '', 'Invitation secret remained in browser history URL');
    facts.invitation_link_opens_acceptance = true;
    const accepted = await action(recipient, 'Accept invitation', 'POST', active.base + '/invitations/' + invitation.invitation.invitation_id + '/accept');
    check((await accepted.json()).role === 'guest', 'Recipient did not get exact invited role');
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
    check(JSON.parse(member.request().postData()).role === 'member', 'Member role choice was lost');
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
    check((await delegated.json()).invitation.role === 'member', 'Delegated administrator failed to create member invitation');
    facts.owner_admin_member_guest = true; facts.stale_revision_rejected = true;

    facts.stage = 'revoke_and_audit';
    await page.bringToFront(); await read(page, name);
    await action(page, 'Revoke invitation', 'DELETE', active.base + '/invitations/' + (await delegated.json()).invitation.invitation_id);
    await page.select(field('account'), account);
    await action(page, 'Remove member and their space devices', 'DELETE', active.base + '/people/' + account);
    await recipient.bringToFront();
    // This control still holds the recipient's former admin snapshot. Its
    // mandatory current-space read must reject before another invitation write.
    await action(recipient, 'Create one-use invitation', 'GET', active.base, 403);
    check(await recipient.$(field('role')) === null, 'Removed account retained management state');
    await page.bringToFront();
    const audit = await action(page, 'Read latest 100 space audit entries', 'GET', active.base + '/audit');
    check((await audit.json()).some(entry => entry.action === 'network_space_member_removed'), 'Space audit did not record real member removal');
    await action(page, 'Remove device', 'DELETE', active.base + '/devices/' + ready.host_device_id);
    const archived = await action(page, 'Archive space and revoke all devices and invitations', 'POST', active.base + '/archive');
    check((await archived.json()).archived, 'Server did not archive space');
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
    active = null;
    if (context) await context.close();
    await page.bringToFront();
    await click(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
  }
}
module.exports = { run, expectedFailure };
