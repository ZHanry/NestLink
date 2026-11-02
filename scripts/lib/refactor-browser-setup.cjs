// Actual compiled onboarding controls and server readbacks; no response mocks.
'use strict';
const PANEL = 'details[aria-label="Setup guide"]';
function check(value, message) { if (!value) throw new Error('Setup guide: ' + message); }
async function clickText(page, text) {
  for (const button of await page.$$(PANEL + ' button')) {
    if (await button.evaluate(element => element.textContent.trim()) === text) {
      await button.click(); return;
    }
  }
  throw new Error('Setup action missing: ' + text);
}
async function signIn(page, ready) {
  await page.goto(ready.origin, { waitUntil: 'networkidle0' });
  await page.locator('.language-selector button[lang="en"]').click();
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('#username', { visible: true });
  await page.locator('#username').fill(ready.username);
  await page.locator('#password').fill(ready.password);
  await page.locator('.entry-panel button.primary').click();
  await page.waitForSelector('.desktop-directory button.record', { visible: true });
}
async function logoutDuringRead(page, ready, facts) {
  const sibling = await page.browserContext().newPage();
  try {
    await signIn(sibling, ready);
    await sibling.locator(PANEL + ' summary').click();
    let arrived = false, followups = 0;
    const observe = request => {
      if (request.method() === 'GET' && ['/api/v3/devices', '/api/v3/network/discovery', '/api/v3/policy'].includes(new URL(request.url()).pathname)) followups++;
    };
    sibling.on('request', observe);
    const response = sibling.waitForResponse(value => value.request().method() === 'GET'
      && new URL(value.url()).pathname === '/api/v3/auth/me');
    response.then(() => { arrived = true; });
    const requested = sibling.waitForRequest(value => value.method() === 'GET'
      && new URL(value.url()).pathname === '/api/v3/auth/me');
    await clickText(sibling, 'Read current state'); await requested;
    await sibling.locator('.sidebar-foot button:last-child').click();
    check(!arrived, 'Logout did not precede the delayed actual account read');
    check((await response).status() === 200, 'Delayed account read was not real server success');
    await sibling.waitForFunction(() => !document.querySelector('.workspace')
      && document.querySelector('.entry-panel button.primary')?.disabled === false);
    sibling.off('request', observe);
    check(followups === 0, 'A signed-out setup read started a follow-up request');
    check(await sibling.$(PANEL) === null, 'A late account reply restored signed-out controls');
    await signIn(sibling, ready);
    check(await sibling.$$eval(PANEL + ' ul li', elements => elements.length) === 0,
      'A new login retained an old setup readback');
    facts.logout_during_read_no_followup = true;
  } finally {
    await sibling.close();
  }
}
async function run(page, ready, report) {
  const facts = report.setup_guide_ui = { passed: false, modes: [], read_only: false };
  const observed = [];
  const observe = request => {
    const url = new URL(request.url());
    if (url.origin === ready.origin && /^\/api\/v3\/(auth\/me|devices|network|services|policy)(\/|$)/.test(url.pathname)) {
      observed.push({ method: request.method(), path: url.pathname });
    }
  };
  page.on('request', observe);
  try {
    await page.bringToFront();
    await page.waitForSelector(PANEL);
    await page.locator(PANEL + ' summary').click();
    check(await page.$$eval(PANEL + ' ul li', elements => elements.length) === 0,
      'An unread panel must not show passing observations');
    for (const mode of ['remote', 'private', 'public', 'network']) {
      await page.select('#setup-purpose', mode);
      check(await page.$$eval(PANEL + ' ul li', elements => elements.length) === 0,
        'Changing purpose retained another mode\'s observations');
      const start = observed.length;
      await clickText(page, 'Read current state');
      await page.waitForFunction(selector => document.querySelector(selector + ' section')?.getAttribute('aria-busy') === 'false'
        && document.querySelectorAll(selector + ' ul li').length > 0, { timeout: 10000 }, PANEL);
      const text = await page.$eval(PANEL, element => element.textContent);
      const requests = observed.slice(start);
      check(requests.some(request => request.path === '/api/v3/auth/me'), 'Account was not read from the server');
      check(requests.some(request => request.path === '/api/v3/devices'), 'Device enrollment was not read from the server');
      check(text.includes('availability and reachability require an actual session'),
        'Enrollment was presented as availability');
      if (mode === 'remote' || mode === 'network') {
        check(requests.some(request => request.path === '/api/v3/network/discovery'),
          'Discovery configuration was not actually read');
        check(text.includes('does not test UDP reachability'), 'STUN configuration was presented as reachability');
      } else {
        check(requests.some(request => request.path === '/api/v3/services'), 'Service publication was not actually read');
        check(text.includes('does not check public ingress or local target reachability'),
          'Publication records were presented as target or public reachability');
      }
      check(await page.$$eval(PANEL + ' ul li .danger', elements => elements.length) === 0,
        'A required fixture read failed');
      facts.modes.push({ mode, server_get_paths: requests.map(request => request.path), actual_readback: true });
    }
    await clickText(page, 'Open my spaces');
    await page.waitForSelector('[aria-label="Network spaces"]', { visible: true, timeout: 10000 });
    check(await page.$eval(PANEL, element => element.open), 'Navigation discarded the active guide');
    await page.select('#setup-purpose', 'remote');
    await clickText(page, 'Choose remote device');
    await page.waitForSelector('.desktop-directory button.record', { visible: true, timeout: 10000 });
    facts.existing_space_and_remote_navigation = true;
    check(observed.every(request => request.method === 'GET'), 'The setup read changed a protected resource');
    facts.read_only = true;
    await logoutDuringRead(page, ready, facts);
    await page.locator(PANEL + ' summary').click();
    facts.collapsed_after_checks = true;
    facts.passed = true;
  } catch (error) {
    facts.failure = String(error); throw error;
  } finally {
    page.off('request', observe);
  }
}
module.exports = { run };
