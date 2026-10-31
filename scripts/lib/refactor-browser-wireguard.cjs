// Compiled client management with real server/SQLite authorization and delayed
// responses. This does not qualify key issuance, a kernel tunnel or a phone.
'use strict';
const { randomUUID } = require('node:crypto');
const PANEL = '[aria-label="WireGuard clients"]';
const SPACE = '[aria-label="Space membership"] input';
const field = name => PANEL + ' [data-wg-field="' + name + '"]';
let active = null;
function check(value, message) { if (!value) throw new Error('WireGuard UI: ' + message); }
function matches(response, method, pathname) {
  return response.request().method() === method && new URL(response.url()).pathname === pathname;
}
function expectedFailure(response) {
  const allowed = active && response.status() === 403 && matches(response, 'GET', active.missing);
  if (allowed) active.failures.push({ method: 'GET', status: 403 });
  return !!allowed;
}
async function button(page, text) {
  for (const candidate of await page.$$(PANEL + ' button')) {
    if (await candidate.evaluate(element => element.textContent.trim()) === text) return candidate;
  }
  throw new Error('WireGuard UI action missing: ' + text);
}
async function disabled(page, text) { return (await button(page, text)).evaluate(element => element.disabled); }
async function click(page, text) {
  const candidate = await button(page, text);
  check(!await candidate.evaluate(element => element.disabled), 'Action disabled: ' + text);
  await candidate.click();
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
    { timeout: 12000 }, PANEL);
}
async function load(page, base) {
  const pending = page.waitForResponse(response => matches(response, 'GET', base), { timeout: 12000 });
  pending.catch(() => {});
  await click(page, 'Read client space');
  check((await pending).status() === 200, 'Actual client space was not loaded');
  await settled(page);
  check(!await disabled(page, 'Verify client business'), 'Real role read did not enable verification');
}
async function run(page, spaceId, report) {
  const facts = report.wireguard_ui = { passed: false, failures: [],
    scope: 'Production client management authorization, approval and late-response fencing; issuance, kernel and mobile acceptance are separate' };
  const base = '/api/v3/network/spaces/' + spaceId;
  const missingId = randomUUID();
  active = { missing: base + '/wireguard-client-bindings/' + missingId, failures: facts.failures };
  let writes = 0, reads = 0;
  const observed = request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith(base + '/wireguard-client-bindings') && request.method() !== 'GET') writes++;
    if (path === base && request.method() === 'GET') reads++;
  };
  page.on('request', observed);
  try {
    facts.stage = 'actual_client_space';
    await page.waitForSelector(PANEL, { visible: true, timeout: 12000 });
    await page.locator(SPACE).fill(spaceId);
    check(await disabled(page, 'Verify client business') && await disabled(page, 'Read client binding'),
      'New space retained client authority');
    await load(page, base);
    check(reads === 1, 'Client load did not read its actual space');
    facts.real_client_space_loaded = true;

    facts.stage = 'explicit_draft_approval';
    const accessId = randomUUID();
    const publicKey = Buffer.alloc(32, 59).toString('base64');
    await page.locator(field('access')).fill(accessId);
    await page.locator(field('key')).fill(publicKey);
    await page.locator(field('ceiling')).fill('8192');
    for (const [name, value] of [['client', randomUUID()], ['key', Buffer.alloc(32, 60).toString('base64')],
      ['ceiling', '4096'], ['access', randomUUID()], ['binding', missingId]]) {
      await page.locator(field('approval')).click();
      check(await page.$eval(field('approval'), input => input.checked), 'Explicit approval was not recorded');
      await page.locator(field(name)).fill(value);
      check(await page.$eval(field('approval'), input => !input.checked), 'Draft edit retained approval: ' + name);
    }
    check(await disabled(page, 'Approve client key binding') && await disabled(page, 'Revoke current client'),
      'Unverified draft enabled a client mutation');
    await page.locator(field('approval')).click();
    const previous = await page.$eval(field('binding'), input => input.value);
    await click(page, 'Generate new binding ID');
    check(await page.$eval(field('binding'), input => input.value) !== previous
      && await page.$eval(field('approval'), input => !input.checked), 'New binding ID retained approval');
    facts.draft_edits_clear_approval = true;

    facts.stage = 'real_missing_binding';
    await page.locator(field('binding')).fill(missingId);
    const denied = page.waitForResponse(response => matches(response, 'GET', active.missing), { timeout: 12000 });
    denied.catch(() => {});
    await click(page, 'Read client binding');
    check((await denied).status() === 403, 'Unknown binding was not rejected by the actual server');
    await settled(page);
    check(await disabled(page, 'Read client binding') && await disabled(page, 'Verify client business')
      && await disabled(page, 'Revoke current client') && await disabled(page, 'Approve client key binding'),
      'Failed read retained writable authority');
    check(await page.$eval(PANEL + ' [role="alert"]', element => element.textContent.trim().length > 0),
      'Real binding rejection was not visible');
    facts.failed_read_clears_writable_snapshot = true;
    const draft = await page.$eval(PANEL, panel => Object.fromEntries(
      [...panel.querySelectorAll('[data-wg-field]')].filter(input => input.type !== 'checkbox')
        .map(input => [input.dataset.wgField, input.value])));
    await load(page, base);
    const reloaded = await page.$eval(PANEL, panel => Object.fromEntries(
      [...panel.querySelectorAll('[data-wg-field]')].filter(input => input.type !== 'checkbox')
        .map(input => [input.dataset.wgField, input.value])));
    check(JSON.stringify(reloaded) === JSON.stringify(draft)
      && await page.$eval(field('approval'), input => !input.checked), 'Reload lost draft or restored old approval');
    facts.failed_read_preserves_unapproved_draft = true;

    facts.stage = 'late_old_space_response';
    let arrived = false;
    const pending = page.waitForResponse(response => matches(response, 'GET', base), { timeout: 12000 });
    pending.then(() => { arrived = true; }); pending.catch(() => {});
    const requested = page.waitForRequest(request => request.method() === 'GET' && new URL(request.url()).pathname === base);
    requested.catch(() => {});
    await click(page, 'Read client space'); await requested;
    await page.locator(SPACE).fill(randomUUID());
    check(!arrived, 'Space switch did not precede delayed actual space reply');
    check((await pending).status() === 200, 'Old space reply was not an actual server success');
    await settled(page);
    check(await disabled(page, 'Verify client business') && await page.$eval(field('key'), input => input.value) === ''
      && await page.$eval(field('access'), input => input.value) === ''
      && await page.$eval(field('approval'), input => !input.checked), 'Old reply restored another space client authority');
    await page.locator(SPACE).fill(spaceId);
    check(await disabled(page, 'Read client binding'), 'Returning to an old space restored stale client authority');
    facts.late_space_reply_ignored = true;
    check(writes === 0 && facts.failures.length === 1, 'Client state exercise performed an unapproved write or unexpected failure');
    facts.no_unapproved_client_write = true;
    facts.stage = 'complete'; facts.passed = true;
  } finally { page.off('request', observed); active = null; }
}
module.exports = { run, expectedFailure };
