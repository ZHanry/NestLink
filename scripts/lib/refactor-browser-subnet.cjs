// Production subnet controls against the existing real space/SQLite fixture.
// This covers management state and races; it claims no gateway OS forwarding.
'use strict';
const { randomUUID } = require('node:crypto');
const PANEL = '[aria-label="Subnet mappings"]';
const SPACE = '[aria-label="Space membership"] input';
const field = name => PANEL + ' [data-subnet-field="' + name + '"]';
let active = null;
function check(value, message) { if (!value) throw new Error('Subnet UI: ' + message); }
function matches(response, method, pathname) {
  return response.request().method() === method && new URL(response.url()).pathname === pathname;
}
function expectedFailure(response) {
  const allowed = active && response.status() === 403 && matches(response, 'GET', active.missing);
  if (allowed) active.failures.push({ method: 'GET', status: 403 });
  return !!allowed;
}
async function click(page, selector, text) {
  for (const button of await page.$$(selector)) {
    if (await button.evaluate(element => element.textContent.trim()) === text) {
      check(!await button.evaluate(element => element.disabled), 'Action disabled: ' + text);
      await button.click(); return;
    }
  }
  throw new Error('Subnet UI action missing: ' + text);
}
async function disabled(page, text) {
  for (const button of await page.$$(PANEL + ' button')) {
    if (await button.evaluate(element => element.textContent.trim()) === text) {
      return button.evaluate(element => element.disabled);
    }
  }
  throw new Error('Subnet UI action missing: ' + text);
}
async function network(page) {
  await click(page, '.sidebar nav button', 'Network and nodes');
  await page.waitForSelector(PANEL, { visible: true, timeout: 12000 });
  await page.waitForFunction(() => document.querySelector('.refresh-button')?.disabled === false);
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false',
    { timeout: 12000 }, PANEL);
}
async function load(page, policy) {
  const pending = page.waitForResponse(response => matches(response, 'GET', policy), { timeout: 12000 });
  pending.catch(() => {});
  await click(page, PANEL + ' button', 'Read space and gateways');
  check((await pending).status() === 200, 'Original space policy was not loaded');
  await settled(page);
  await page.waitForSelector(field('export'), { visible: true, timeout: 12000 });
}
async function run(page, spaceId, report) {
  const facts = report.subnet_ui = { passed: false, failures: [],
    scope: 'Real production mapping management state and lifecycle; no mapping issuance or OS forwarding claim' };
  const base = '/api/v3/network/spaces/' + spaceId;
  const policy = base + '/policy';
  const missingId = randomUUID();
  active = { missing: base + '/subnet-mappings/' + missingId, failures: facts.failures };
  let writes = 0, detailReads = 0;
  const observed = request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith(base + '/subnet-mappings') && request.method() !== 'GET') writes++;
    if (path === base && request.method() === 'GET') detailReads++;
  };
  page.on('request', observed);
  try {
    facts.stage = 'actual_space_management_load';
    await network(page); await page.locator(SPACE).fill(spaceId);
    check(await disabled(page, 'Read and verify mapping'), 'New space supplied an unverified mapping snapshot');
    await load(page, policy);
    check(detailReads === 1, 'Load did not read the actual space role');
    facts.real_policy_and_role_loaded = true;
    facts.stage = 'draft_approval';
    const exportId = randomUUID();
    await page.locator(field('export')).fill(exportId);
    await page.locator(field('original')).fill('192.168.1.0/24');
    await page.locator(field('alias')).fill('10.210.1.0/24');
    await page.locator(field('approval')).click();
    check(await page.$eval(field('approval'), input => input.checked), 'Explicit approval was not recorded');
    await page.locator(field('alias')).fill('10.210.2.0/24');
    check(await page.$eval(field('approval'), input => !input.checked)
      && await disabled(page, 'Issue new mapping'), 'Draft edit retained prior approval');
    await page.locator(field('approval')).click();
    const previous = await page.$eval(field('id'), input => input.value);
    await click(page, PANEL + ' button', 'Generate a new mapping ID');
    check(await page.$eval(field('id'), input => input.value) !== previous
      && await page.$eval(field('approval'), input => !input.checked), 'New mapping ID retained prior approval');
    facts.draft_edits_clear_approval = true;
    facts.stage = 'real_forbidden_mapping';
    await page.locator(field('id')).fill(missingId);
    const denied = page.waitForResponse(response => matches(response, 'GET', active.missing), { timeout: 12000 });
    denied.catch(() => {});
    await click(page, PANEL + ' button', 'Read and verify mapping');
    check((await denied).status() === 403, 'Unknown mapping was not rejected by the actual server');
    await settled(page);
    check(await page.$(field('export')) === null && await disabled(page, 'Read and verify mapping')
      && await disabled(page, 'Revoke this mapping'), 'Forbidden read retained a writable revision');
    check(await page.$eval(PANEL + ' [role="alert"]', element => element.textContent.trim().length > 0),
      'Forbidden mapping read was not visible');
    facts.failed_read_clears_writable_snapshot = true;
    await load(page, policy);
    check(await page.$eval(field('export'), input => input.value) === exportId
      && await page.$eval(field('original'), input => input.value) === '192.168.1.0/24'
      && await page.$eval(field('alias'), input => input.value) === '10.210.2.0/24'
      && await page.$eval(field('approval'), input => !input.checked), 'Reload lost the draft or restored prior approval');
    facts.failed_read_preserves_unapproved_draft = true;
    facts.stage = 'space_switch_during_real_policy_read';
    const before = detailReads;
    let arrived = false;
    const pending = page.waitForResponse(response => matches(response, 'GET', policy), { timeout: 12000 });
    pending.then(() => { arrived = true; }); pending.catch(() => {});
    const requested = page.waitForRequest(request => request.method() === 'GET' && new URL(request.url()).pathname === policy);
    await click(page, PANEL + ' button', 'Read space and gateways'); await requested;
    await page.locator(SPACE).fill(randomUUID());
    check(!arrived, 'Space switch did not precede the delayed actual policy reply');
    check((await pending).status() === 200, 'Old space reply was not actual server success');
    await settled(page);
    check(detailReads === before && await page.$(field('export')) === null
      && await disabled(page, 'Read and verify mapping'), 'Old reply fetched or restored another space snapshot');
    await page.locator(SPACE).fill(spaceId);
    check(await disabled(page, 'Read and verify mapping'), 'Returning to an old space restored stale authority');
    facts.late_space_reply_ignored = true;
    check(writes === 0 && facts.failures.length === 1, 'Management state exercise performed an unapproved write');
    facts.no_unapproved_mapping_write = true;
    facts.stage = 'complete'; facts.passed = true;
  } finally {
    page.off('request', observed); active = null;
  }
}
module.exports = { run, expectedFailure };
