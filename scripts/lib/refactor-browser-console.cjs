// Production console -> SDK -> actual session service. No substituted responses.
'use strict';
function check(value, message) { if (!value) throw new Error('Console UI: ' + message); }
const devices = '[data-section="devices"]';
async function entry(page, args, report, phase) {
  const facts = report.console_ui ??= { passed: false, entry_phases: [] };
  check(await page.$('.workspace') === null && await page.$('.setup-guide') === null,
    'Authentication must not render authenticated diagnostics or workspace');
  check(!/配置向导与运行状态|Setup and current status/.test(await page.$eval('body', element => element.innerText)),
    'Legacy technical setup leaked into the entry page');
  const action = await page.$eval('.entry-panel button.primary', element => {
    const rect = element.getBoundingClientRect();
    return { count: document.querySelectorAll('.entry-panel button.primary').length,
      visible: rect.width > 0 && rect.height > 0 && rect.left >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight };
  });
  check(action.count === 1 && action.visible, 'Entry primary action must be unique and visible');
  facts.entry_phases.push(phase);
  if (phase === 'signin') await page.screenshot({ path: args.report.replace(/\.json$/, '-signin.png'), fullPage: false });
  facts.entry_is_focused = facts.entry_phases.includes('connect') && facts.entry_phases.includes('signin');
}
async function openDevices(page) {
  await page.locator(devices).click();
  await page.waitForFunction(() => document.querySelector('.login-devices')?.getAttribute('aria-busy') === 'false'
    && document.querySelector('.login-device-card .current-device'), { timeout: 12000 });
}
async function sessions(page, sibling, args, report) {
  const facts = report.console_ui;
  const expected = ['desktop', 'services', 'spaces', 'devices', 'accounts', 'network', 'nodes', 'audit'];
  check(JSON.stringify(await page.$$eval('.sidebar nav [data-section]', elements => elements.map(element => element.dataset.section))) === JSON.stringify(expected),
    'Primary and expanded administrator navigation must match the approved design');
  check(await page.$$eval('.sidebar nav details', elements => elements.length) === 0,
    'Administrator navigation must stay expanded');
  facts.navigation_matches_prototype = true;
  await openDevices(sibling);
  const siblingId = await sibling.$eval('.login-device-card:has(.current-device)', element => element.dataset.loginSession);
  check(/^[a-zA-Z0-9_-]{1,128}$/.test(siblingId), 'Actual sibling session identifier unavailable');
  await page.bringToFront();
  await openDevices(page);
  const card = '.login-device-card[data-login-session="' + siblingId + '"]';
  await page.waitForSelector(card, { visible: true });
  check(await page.$(card + ' .current-device') === null, 'Sibling must be a distinct account sign-in');
  check(await page.$$eval('.login-device-card', cards => cards.length) >= 3,
    'Real account must expose the native host and both independent browser sign-ins');
  facts.real_login_sessions = true;
  let deletes = 0;
  const path = '/api/v3/auth/sessions/' + siblingId;
  const observe = request => { if (request.method() === 'DELETE' && new URL(request.url()).pathname === path) deletes++; };
  page.on('request', observe);
  try {
    await page.locator(card + ' button').click();
    await page.waitForSelector('.task-dialog[open]', { visible: true });
    await page.locator('.confirmation-actions .secondary').click();
    check(deletes === 0 && await page.$(card), 'Cancel must preserve the actual session without a DELETE');
    facts.cancel_keeps_session = true;
    await page.locator(card + ' button').click();
    const revoked = page.waitForResponse(response => response.request().method() === 'DELETE' && new URL(response.url()).pathname === path);
    const readback = page.waitForResponse(response => response.request().method() === 'GET' && new URL(response.url()).pathname === '/api/v3/auth/me');
    await page.locator('.confirmation-actions .danger').click();
    check([200,204].includes((await revoked).status()) && (await readback).status() === 200,
      'Session revoke and account readback must both succeed on the real server');
    await page.waitForFunction(selector => !document.querySelector(selector)
      && document.querySelector('.login-devices')?.getAttribute('aria-busy') === 'false', {}, card);
    check(deletes === 1 && await page.$('.login-device-card .current-device'),
      'Exactly one other session must be revoked while the current session remains');
    facts.other_session_revoked_and_read_back = true;
    await sibling.bringToFront();
    const denied = sibling.waitForResponse(response => response.request().method() === 'GET'
      && new URL(response.url()).pathname === '/api/v3/auth/me' && response.status() === 401);
    await sibling.locator('.refresh-button').click();
    await denied;
    await sibling.waitForSelector('.entry-panel button.primary', { visible: true });
    check(await sibling.$('.workspace') === null, 'Revoked browser must lose authenticated controls');
    facts.revoked_browser_requires_signin = true;
    await page.bringToFront();
    await page.screenshot({ path: args.report.replace(/\.json$/, '-login-devices.png'), fullPage: false });
    await page.locator('[data-section="desktop"]').click();
    await page.waitForSelector('.desktop-directory button.record', { visible: true });
    facts.current_session_preserved = true;
    facts.passed = true;
  } finally { page.off('request', observe); }
}
async function pages(page, args, report) {
  const facts = report.console_ui;
  facts.pages = [];
  await page.setViewport({ width: 1440, height: 1000 });
  await page.locator('.language-selector button[lang="zh-CN"]').click();
  for (const name of ['desktop','services','spaces','devices','accounts','network','nodes','audit']) {
    await page.locator('.sidebar nav [data-section="' + name + '"]').click();
    await page.waitForFunction(name => document.querySelector('.sidebar nav [aria-current="page"]')?.dataset.section === name
      && document.querySelector('.refresh-button')?.disabled === false, {}, name);
    if (name === 'services') await page.waitForFunction(() => document.querySelector('.tunnel-records')?.getAttribute('aria-busy') === 'false');
    if (name === 'devices') await page.waitForFunction(() => document.querySelector('.login-devices')?.getAttribute('aria-busy') === 'false');
    const layout = await page.evaluate(() => ({ horizontal_overflow: document.documentElement.scrollWidth > innerWidth + 1,
      headings: document.querySelectorAll('.content > .page-head h1').length,
      sidebar_width: document.querySelector('.sidebar').getBoundingClientRect().width,
      sidebar_color: getComputedStyle(document.querySelector('.sidebar')).backgroundColor }));
    check(!layout.horizontal_overflow && layout.headings === 1 && layout.sidebar_width === 214,
      'Approved page frame is missing or overflows: ' + name);
    check(layout.sidebar_color === 'rgb(238, 235, 245)', 'Sidebar must use the approved lilac token');
    await page.screenshot({ path: args.report.replace(/\.json$/, '-console-' + name + '.png'), fullPage: false });
    facts.pages.push({ name, ...layout });
  }
  await page.locator('.language-selector button[lang="en"]').click();
  await page.locator('[data-section="desktop"]').click();
  await page.waitForSelector('.desktop-directory button.record', { visible: true });
  facts.all_pages_reviewable = true;
}
module.exports = { entry, sessions, pages };
