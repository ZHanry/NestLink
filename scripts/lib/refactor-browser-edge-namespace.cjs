// Production UI + real SDK/server namespace checks. No response or DOM mocking.
'use strict';
let active = null;
const PANEL = '[aria-label="Public service ingress"]';
const INPUTS = PANEL + ' input';
function check(value, message) { if (!value) throw new Error('Edge namespace UI: ' + message); }
function expectedFailure(response) {
  if (!active) return false;
  const pathname = new URL(response.url()).pathname;
  if (!active.paths.has(pathname)) return false;
  const method = response.request().method(), status = response.status();
  if ((method === 'GET' && status === 403) || (method === 'PUT' && (status === 409 || status === 403))) {
    active.failures.push({ method, status });
    return true;
  }
  return false;
}
async function clickText(page, selector, text) {
  const buttons = await page.$$(selector);
  for (const button of buttons) {
    if ((await button.evaluate(el => el.textContent.trim())) === text) { await button.click(); return; }
  }
  throw new Error('Edge namespace UI action missing: ' + text);
}
async function network(page) {
  await clickText(page, '.sidebar nav button', 'Network and nodes');
  await page.waitForSelector('.content-grid .records .record', { visible: true, timeout: 5000 });
}
async function node(page, name) {
  const rows = await page.$$('.content-grid .records .record');
  for (const row of rows) {
    if (await row.$eval('strong', el => el.textContent) === name) { await row.click(); return; }
  }
  throw new Error('Owned fixture edge missing: ' + name);
}
async function settled(page) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-busy') === 'false', { timeout: 8000 }, PANEL);
}
async function values(page) { return page.$$eval(INPUTS, els => els.map(el => el.value)); }
async function fill(page, fields) {
  const inputs = await page.$$(INPUTS);
  check(inputs.length === 4, 'Expected four real editor fields');
  for (let i = 0; i < fields.length; i++) {
    await page.locator(PANEL + ' label:nth-of-type(' + (i + 1) + ') input').fill(fields[i]);
  }
  check(JSON.stringify(await values(page)) === JSON.stringify(fields), 'Real editor field entry must replace each complete value');
}
async function request(page, method, text) {
  const response = page.waitForResponse(r => r.request().method() === method && active.paths.has(new URL(r.url()).pathname), { timeout: 8000 });
  await clickText(page, PANEL + ' button', text);
  await response;
  await settled(page);
}
async function save(page) { await request(page, 'PUT', 'Save public ingress'); }
async function read(page) { await request(page, 'GET', 'Read again (replace draft)'); }
async function signIn(page, ready, facts) {
  facts.stage = 'concurrent_navigation';
  await page.goto(ready.origin, { waitUntil: 'networkidle0' });
  facts.stage = 'concurrent_language';
  await page.locator('.language-selector button[lang="en"]').click();
  facts.stage = 'concurrent_trust';
  await page.locator('.entry-panel button.primary').click();
  facts.stage = 'concurrent_signin_fields';
  await page.waitForSelector('#username', { visible: true });
  await page.locator('#username').fill(ready.username);
  await page.locator('#password').fill(ready.password);
  facts.stage = 'concurrent_signin_submit';
  await page.locator('.entry-panel button.primary').click();
  facts.stage = 'concurrent_workspace';
  await page.waitForSelector('button.record', { visible: true });
}
async function run(page, ready, report) {
  const fixtures = ready.edge_namespace;
  check(fixtures?.nodes?.length === 2, 'Two owned real edge registrations are required');
  const facts = report.edge_namespace_ui = { passed: false, failures: [] };
  active = { paths: new Set(fixtures.nodes.map(n => '/api/v3/nodes/' + n.id + '/service-namespace')), failures: facts.failures };
  let sibling;
  try {
    await page.locator('.language-selector button[lang="en"]').click();
    await network(page); await node(page, fixtures.nodes[0].name); await settled(page);
    check(await page.$eval(PANEL + ' [role="alert"]', el => el.textContent.trim().length > 0), 'GET403 must remain visible as an error');
    check(await page.$eval(PANEL + ' button.primary', el => el.disabled), 'GET403 must not enable save');
    await clickText(page, PANEL + ' button', 'Initialize first configuration (revision 0)');
    check(await page.$eval(PANEL, el => el.textContent.includes('Configuration revision 0')), 'First configuration must explicitly choose revision zero');
    const first = ['services.example.test', fixtures.management_hostname, '29100, 29101', '192.0.2.1:29100'];
    const rejected = [...first]; rejected[1] = 'other.example.test';
    await fill(page, rejected); await save(page);
    check(JSON.stringify(await values(page)) === JSON.stringify(rejected), 'Failed initialization discarded draft');
    check(await page.$eval(PANEL + ' button.primary', el => el.disabled), 'Failed initialization must require re-read');
    facts.failed_initialization_preserves_draft = true;
    await read(page);
    await clickText(page, PANEL + ' button', 'Initialize first configuration (revision 0)');
    await fill(page, first); await save(page);
    check(await page.$eval(PANEL, el => el.textContent.includes('Configuration revision 1')), 'First write must return revision one');
    facts.forbidden_is_error = true; facts.explicit_revision_zero = true; facts.create_saved = true;
    // Repeated selection must retain the same real component draft.
    const draft = [...first]; draft[0] = 'draft.example.test';
    await fill(page, draft); await node(page, fixtures.nodes[0].name);
    check(JSON.stringify(await values(page)) === JSON.stringify(draft), 'Same-node selection discarded draft');
    facts.same_node_draft_preserved = true;
    await read(page);
    check(JSON.stringify(await values(page)) === JSON.stringify(first), 'Read must use the actual saved configuration');
    facts.read_saved_configuration = true;
    // A second production SDK login reads revision 1 and writes revision 2.
    sibling = await page.browserContext().newPage();
    sibling.setDefaultTimeout(8000);
    await signIn(sibling, ready, facts);
    facts.stage = 'concurrent_network';
    await network(sibling);
    facts.stage = 'concurrent_node';
    await node(sibling, fixtures.nodes[0].name); await settled(sibling);
    const second = [...first]; second[2] = '29100, 29102';
    facts.stage = 'concurrent_write';
    await fill(sibling, second); await save(sibling);
    check(await sibling.$eval(PANEL, el => el.textContent.includes('Configuration revision 2')), 'Concurrent real writer must advance revision');
    facts.stage = 'stale_primary_write';
    await fill(page, draft); await save(page);
    check(JSON.stringify(await values(page)) === JSON.stringify(draft), 'CAS conflict discarded draft');
    check(await page.$eval(PANEL + ' button.primary', el => el.disabled), 'CAS conflict must require re-read');
    check(await page.$eval(PANEL + ' [role="alert"]', el => el.textContent.trim().length > 0), 'CAS conflict must be visible');
    facts.cas_conflict_preserves_draft = true;
    facts.stage = 'conflict_readback';
    await read(page);
    check(JSON.stringify(await values(page)) === JSON.stringify(second), 'Conflict recovery must load committed revision');
    facts.conflict_recovered = true;
    // Observe an actual request, switch selection while its real HTTP response
    // is delayed by the fixture, then wait for that old response to finish.
    facts.stage = 'old_response_node_switch';
    const pendingRequest = page.waitForRequest(r => r.method() === 'GET' && new URL(r.url()).pathname === '/api/v3/nodes/' + fixtures.nodes[0].id + '/service-namespace');
    let oldResponseArrived = false;
    const pendingResponse = page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname === '/api/v3/nodes/' + fixtures.nodes[0].id + '/service-namespace');
    pendingResponse.then(() => { oldResponseArrived = true; });
    await clickText(page, PANEL + ' button', 'Read again (replace draft)');
    await pendingRequest;
    await node(page, fixtures.nodes[1].name);
    check(!oldResponseArrived, 'Node switch must precede the delayed old response');
    check((await pendingResponse).status() === 200, 'Delayed old response must contain the real saved namespace');
    await settled(page);
    check(await page.$eval('.detail-pane > h2', el => el.textContent) === fixtures.nodes[1].name, 'Selection changed after old response');
    check(await page.$eval(PANEL, el => el.textContent.includes('No configuration revision loaded')), 'Old node revision leaked to new node');
    check((await values(page)).every(v => v === ''), 'Old node configuration leaked to new node');
    facts.slow_old_response_ignored = true; facts.node_switch_clears_draft = true;
    check(facts.failures.filter(f => f.method === 'GET' && f.status === 403).length === 3, 'Expected exactly three real uninitialized namespace reads');
    check(facts.failures.filter(f => f.method === 'PUT' && f.status === 409).length === 1, 'Expected exactly one real CAS rejection');
    check(facts.failures.filter(f => f.method === 'PUT' && f.status === 403).length === 1, 'Expected exactly one real management-hostname rejection');
    facts.stage = 'complete'; facts.passed = true;
  } catch (error) {
    if (sibling) {
      facts.concurrent_failure_state = await sibling.evaluate(() => ({
        trust_present: !!document.querySelector('#trust-title'),
        signin_present: !!document.querySelector('#signin-title'),
        workspace_present: !!document.querySelector('.workspace'),
        username_present: !!document.querySelector('#username'),
        language_present: !!document.querySelector('.language-selector button[lang="en"]'),
        entry_action_disabled: document.querySelector('.entry-panel button.primary')?.disabled ?? null,
        namespace_present: !!document.querySelector('[aria-label="Public service ingress"]'),
      })).catch(() => ({ inspection_failed: true }));
    }
    // Preserve the actual panel before finally returns to the desktop page.
    // These are fixed state labels, not editor values or authentication data.
    facts.failure_state = await page.evaluate(selector => {
      const panel = document.querySelector(selector);
      return {
        panel_present: !!panel,
        aria_busy: panel?.getAttribute('aria-busy') ?? null,
        alert_present: !!panel?.querySelector('[role="alert"]'),
        alert_text: panel?.querySelector('[role="alert"]')?.textContent.trim().slice(0, 500) ?? null,
        save_disabled: panel?.querySelector('button.primary')?.disabled ?? null,
        input_count: panel?.querySelectorAll('input').length ?? 0,
      };
    }, PANEL).catch(() => ({ inspection_failed: true }));
    throw error;
  } finally {
    active = null;
    if (sibling) await sibling.close();
    await clickText(page, '.sidebar nav button', 'Remote desktop');
    await page.waitForSelector('.desktop-directory button.record', { visible: true, timeout: 5000 });
  }
}
module.exports = { run, expectedFailure };
