// Observe the compiled production UI using genuine browser actions. This helper
// proves workspace interaction and geometry only; the caller separately checks
// native media, input, signed leases and cleanup. No API or DOM state is faked.
'use strict';
const { isDeepStrictEqual } = require('node:util');

const VIEWPORTS = Object.freeze([
  { width: 1440, height: 1000 }, { width: 900, height: 800 },
  { width: 760, height: 560 }, { width: 390, height: 844 },
]);
const SESSION = Object.freeze({
  stop: '.remote-actions button.danger', close: '.remote-actions > button:last-child',
  request: '.remote-footer > button.primary', canvas: '.remote-stage',
});
const EDITOR = Object.freeze({
  save: '.service-editor .dialog-actions button.primary',
  close: '.service-editor .dialog-actions button.secondary',
});
const OPTIONS = '[aria-controls="remote-permissions"]';
const TOOLS = '[aria-controls="remote-operation-center"]';
const NAME = '.service-fields .form-section:first-child > label:first-of-type > input';
const state = new WeakMap();
function check(value, message) { if (!value) throw new Error('Workspace UI: ' + message); }
const afterPaint = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
const picturePath = (args, name) => args.report.replace(/\.json$/, '-' + name + '.png');

function assertVisibleGeometry(snapshot, keys, hitKeys = keys) {
  check(Number.isFinite(snapshot?.viewport?.width) && Number.isFinite(snapshot?.viewport?.height), 'Viewport evidence is missing');
  check(snapshot.document_width <= snapshot.viewport.width + 1, 'The document overflows horizontally');
  for (const key of keys) {
    const item = snapshot.items?.[key];
    check(item?.visible && item.count === 1, key + ' must identify one rendered element');
    const rect = item.rect;
    check(rect && ['x', 'y', 'width', 'height'].every(field => Number.isFinite(rect[field])) &&
      rect.width > 0 && rect.height > 0, key + ' has invalid bounds');
    check(rect.x >= -1 && rect.y >= -1 && rect.x + rect.width <= snapshot.viewport.width + 1 &&
      rect.y + rect.height <= snapshot.viewport.height + 1, key + ' is outside the viewport');
    if (hitKeys.includes(key)) check(item.hit === true, key + ' is covered or clipped at its center');
  }
}

function assertStable(before, after, keys) {
  check(isDeepStrictEqual(before.viewport, after.viewport), 'A stability comparison crossed viewport sizes');
  for (const key of keys) {
    check(before.items?.[key]?.rect && after.items?.[key]?.rect, key + ' stability evidence is missing');
    for (const field of ['x', 'y', 'width', 'height']) {
      const a = before.items[key].rect[field], b = after.items[key].rect[field];
      check(Number.isFinite(a) && Number.isFinite(b) && Math.abs(a - b) <= 0.5,
        key + ' moved while content or overlays changed (' + field + ')');
    }
  }
}

async function geometry(page, selectors) {
  return page.evaluate(selectors => ({
    viewport: { width: innerWidth, height: innerHeight },
    document_width: document.documentElement.scrollWidth,
    items: Object.fromEntries(Object.entries(selectors).map(([name, selector]) => {
      const elements = document.querySelectorAll(selector), element = elements[0];
      if (!element) return [name, { count: 0, visible: false }];
      const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return [name, { count: elements.length,
        visible: rect.width > 0 && rect.height > 0 && style.visibility === 'visible' && style.display !== 'none',
        rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        hit: hit === element || element.contains(hit), disabled: element.disabled === true }];
    })),
  }), selectors);
}

async function namedClick(page, selector, names) {
  await page.waitForSelector(selector, { visible: true, timeout: 5000 });
  check(await page.$eval(selector, (element, names) => names.includes(element.textContent.trim()), names),
    'The intended action changed: ' + selector);
  await page.locator(selector).setTimeout(5000).click();
}

async function toggle(page, selector, expected) {
  check(await page.$$eval(selector, buttons => buttons.length) === 1, 'An overlay toggle must be unique');
  const before = await page.$eval(selector, button => button.getAttribute('aria-expanded'));
  check(before === String(!expected), 'The overlay did not begin in the expected state');
  await page.locator(selector).setTimeout(5000).click();
  await page.waitForFunction((selector, expected) => {
    const button = document.querySelector(selector);
    const panel = document.getElementById(button?.getAttribute('aria-controls'));
    return button?.getAttribute('aria-expanded') === String(expected) &&
      (expected ? panel && !panel.hidden && panel.getBoundingClientRect().height > 0 : !panel || panel.hidden);
  }, { timeout: 5000 }, selector, expected);
  await afterPaint(page);
}

async function permissionValues(page) {
  return page.$$eval('#remote-permissions input, #remote-permissions select', elements => elements.map(element => ({
    tag: element.tagName, type: element.type, value: element.value,
    checked: element.type === 'checkbox' ? element.checked : null,
  })));
}

async function installObservation(page) {
  await page.evaluate(() => {
    if (window.__nestlinkWorkspaceUi) throw new Error('Workspace observer already installed');
    window.__nestlinkWorkspaceUi = { clicks: [] };
    document.addEventListener('click', event => {
      const button = event.target instanceof Element ? event.target.closest('button') : null;
      if (!button) return;
      const selector = ['.sidebar nav button', '.tunnel-heading > button.primary',
        '.service-editor .dialog-actions button.secondary', '.task-dialog[open] > button',
        '[aria-controls="remote-permissions"]', '[aria-controls="remote-operation-center"]',
        '.remote-actions > button:last-child', '.back-to-devices']
        .find(selector => button.matches(selector));
      if (selector && window.__nestlinkWorkspaceUi.clicks.length < 128) {
        window.__nestlinkWorkspaceUi.clicks.push({ selector, trusted: event.isTrusted });
      }
    }, true);
  });
}

async function workspaces(page, args, report) {
  check(!state.has(page), 'The workspace check cannot run twice');
  state.set(page, {});
  const facts = report.workspace_ui = { passed: false,
    scope: 'Compiled production workspace interaction and geometry; separate from real native media/input assertions',
    navigation: [], active_layouts: [], steady_layout_samples: [], screenshots: [] };
  await installObservation(page);
  // English action labels exposed a third toolbar row in the real CI page.
  // Select that language through the UI so the regression cannot disappear
  // when a runner changes its browser locale.
  await namedClick(page, '.language-selector button[lang="en"]', ['English']);
  facts.language = 'English selected through the production UI';
  const started = performance.now();
  for (const viewport of VIEWPORTS) {
    await page.setViewport(viewport);
    await afterPaint(page);
    check(await page.$eval('.sidebar nav button:nth-of-type(1)', button => button.getAttribute('aria-current')) === 'page',
      'Remote desktop must be the active workspace');
    await page.waitForSelector('.desktop-directory button.record', { visible: true, timeout: 5000 });
    await page.locator('.desktop-directory button.record').setTimeout(5000).click();
    await page.waitForFunction(() => document.querySelector('.desktop-workspace')?.classList.contains('has-selection'), { timeout: 5000 });
    await afterPaint(page);
    const desktop = await geometry(page, { connect: '.desktop-detail-actions > button.primary' });
    assertVisibleGeometry(desktop, ['connect']);
    check(!desktop.items.connect.disabled, 'The owned host must have an available connection action');
    if (viewport.width === 1440) {
      await page.screenshot({ path: picturePath(args, 'workspace'), fullPage: false });
      facts.screenshots.push('workspace');
    }
    if (viewport.width === 390) {
      await namedClick(page, '.back-to-devices', ['返回设备', 'Back to devices']);
      await page.waitForSelector('.desktop-directory button.record', { visible: true, timeout: 5000 });
      check(await page.$eval('.desktop-detail', element => getComputedStyle(element).display) === 'none',
        'Narrow back navigation must return to the device directory');
    }
    await namedClick(page, '.sidebar nav button:nth-of-type(2)', ['内网穿透', 'Tunnels']);
    await page.waitForFunction(() => document.querySelector('.sidebar nav button:nth-of-type(2)')?.getAttribute('aria-current') === 'page' &&
      document.querySelector('.tunnel-records')?.getAttribute('aria-busy') === 'false' &&
      document.querySelector('.tunnel-records .empty-state, .tunnel-record'), { timeout: 5000 });
    const tunnels = await geometry(page, { create: '.tunnel-heading > button.primary' });
    assertVisibleGeometry(tunnels, ['create']);
    await namedClick(page, '.tunnel-heading > button.primary', ['新建服务', 'New service']);
    await page.waitForSelector('.task-dialog[open] .service-editor', { visible: true, timeout: 5000 });
    const editor = await geometry(page, EDITOR);
    assertVisibleGeometry(editor, ['save', 'close']);
    if (viewport.width === 390) {
      await page.locator(NAME).setTimeout(5000).fill('Owned UI draft');
    }
    if (viewport.width === 900) {
      await page.screenshot({ path: picturePath(args, 'tunnel-editor'), fullPage: false });
      facts.screenshots.push('tunnel-editor');
    }
    const body = await page.$eval('.service-editor-body', element => {
      const rect = element.getBoundingClientRect();
      return { x: rect.x + 8, y: rect.y + rect.height / 2,
        scrollable: element.scrollHeight > element.clientHeight + 1 };
    });
    await page.mouse.move(body.x, body.y);
    await page.mouse.wheel({ deltaY: 1200 });
    await afterPaint(page);
    if (body.scrollable) await page.waitForFunction(() => document.querySelector('.service-editor-body')?.scrollTop > 0, { timeout: 3000 });
    const scrolled = await geometry(page, EDITOR);
    assertVisibleGeometry(scrolled, ['save', 'close']);
    assertStable(editor, scrolled, ['save', 'close']);
    await namedClick(page, EDITOR.close, ['关闭编辑', 'Close editor']);
    let draftPreserved = null;
    if (viewport.width === 390) {
      await page.waitForSelector('.task-dialog[open] > button.danger', { visible: true, timeout: 5000 });
      await namedClick(page, '.task-dialog[open] > button.secondary', ['继续编辑', 'Keep editing']);
      check(await page.$eval(NAME, input => input.value) === 'Owned UI draft',
        'Keep editing must preserve the actual draft');
      draftPreserved = true;
      await namedClick(page, EDITOR.close, ['关闭编辑', 'Close editor']);
      await namedClick(page, '.task-dialog[open] > button.danger', ['放弃修改', 'Discard changes']);
    }
    await page.waitForFunction(() => !document.querySelector('.task-dialog[open]'), { timeout: 5000 });
    await namedClick(page, '.sidebar nav button:nth-of-type(1)', ['远程桌面', 'Remote desktop']);
    await page.waitForFunction(() => document.querySelector('.sidebar nav button:nth-of-type(1)')?.getAttribute('aria-current') === 'page' &&
      !document.querySelector('.desktop-workspace')?.classList.contains('has-selection'), { timeout: 5000 });
    await page.waitForSelector('.desktop-directory button.record', { visible: true, timeout: 5000 });
    facts.navigation.push({ viewport, desktop, tunnels, editor, after_scroll: scrolled,
      native_body_scroll_observed: body.scrollable, draft_preserved: draftPreserved });
    check(performance.now() - started < 25000, 'Workspace interaction exceeded its original fixture budget');
  }
  await page.setViewport(VIEWPORTS[0]);
  await afterPaint(page);
  facts.navigation_elapsed_ms = Math.round(performance.now() - started);
}

async function permissions(page, report) {
  const before = await permissionValues(page);
  check(before.length === 8, 'Expected six permission checkboxes and two connection choices');
  const frame = await geometry(page, SESSION);
  assertVisibleGeometry(frame, Object.keys(SESSION), ['stop', 'close', 'request']);
  await toggle(page, OPTIONS, false);
  const hidden = await geometry(page, SESSION);
  assertStable(frame, hidden, Object.keys(SESSION));
  await toggle(page, OPTIONS, true);
  const reopened = await geometry(page, SESSION);
  assertVisibleGeometry(reopened, Object.keys(SESSION), ['stop', 'close', 'request']);
  assertStable(frame, reopened, Object.keys(SESSION));
  check(isDeepStrictEqual(before, await permissionValues(page)), 'Collapsing permissions changed the requested access');
  state.get(page).requestFrame = frame;
  report.workspace_ui.permissions = { toggled_through_ui: true, requested_values_preserved: true,
    before, initial_frame: frame, reopened_frame: reopened };
}

async function requestStarted(page, report) {
  await page.waitForFunction(selector => document.querySelector(selector)?.getAttribute('aria-expanded') === 'false' &&
    document.querySelector('#remote-permissions')?.hidden === true,
  { timeout: 5000 }, OPTIONS);
  const frame = await geometry(page, SESSION);
  assertVisibleGeometry(frame, Object.keys(SESSION), ['stop', 'close', 'request']);
  assertStable(state.get(page).requestFrame, frame, Object.keys(SESSION));
  report.workspace_ui.request_hid_options_without_moving_actions = true;
}

async function activeLayouts(page, args, report) {
  const facts = report.workspace_ui;
  const started = performance.now();
  for (const viewport of VIEWPORTS) {
    await page.setViewport(viewport);
    await afterPaint(page);
    const baseline = await geometry(page, SESSION);
    assertVisibleGeometry(baseline, Object.keys(SESSION), ['stop', 'close', 'request']);
    check(!baseline.items.stop.disabled && baseline.items.request.disabled, 'The layout check requires an active real session');
    await toggle(page, TOOLS, true);
    const drawer = await geometry(page, SESSION);
    assertVisibleGeometry(drawer, Object.keys(SESSION), ['stop', 'close', 'request']);
    assertStable(baseline, drawer, Object.keys(SESSION));
    await toggle(page, TOOLS, false);
    await toggle(page, OPTIONS, true);
    check(await page.$$eval('#remote-permissions input, #remote-permissions select', elements =>
      elements.length === 8 && elements.every(element => element.disabled)), 'An active session must freeze its granted access controls');
    const options = await geometry(page, SESSION);
    assertVisibleGeometry(options, Object.keys(SESSION), ['stop', 'close', 'request']);
    assertStable(baseline, options, Object.keys(SESSION));
    await toggle(page, OPTIONS, false);
    const restored = await geometry(page, SESSION);
    assertStable(baseline, restored, Object.keys(SESSION));
    facts.active_layouts.push({ viewport, baseline, drawer, options, restored });
    if (viewport.width === 390) {
      await page.screenshot({ path: picturePath(args, 'remote-narrow'), fullPage: false });
      facts.screenshots.push('remote-narrow');
    }
  }
  await page.setViewport(VIEWPORTS[0]);
  await afterPaint(page);
  state.get(page).steadyFrame = await geometry(page, SESSION);
  facts.active_layout_elapsed_ms = Math.round(performance.now() - started);
  check(facts.active_layout_elapsed_ms < 10000, 'Active layout actions must fit inside the first original media interval');
}

async function sampleActive(page, report) {
  const frame = await geometry(page, SESSION);
  assertVisibleGeometry(frame, Object.keys(SESSION), ['stop', 'close', 'request']);
  assertStable(state.get(page).steadyFrame, frame, Object.keys(SESSION));
  check(!frame.items.stop.disabled, 'A stable control bar must still belong to the active session');
  report.workspace_ui.steady_layout_samples.push(frame);
}

async function close(page, report) {
  const frame = await geometry(page, SESSION);
  assertVisibleGeometry(frame, Object.keys(SESSION), ['stop', 'close', 'request']);
  assertStable(state.get(page).steadyFrame, frame, Object.keys(SESSION));
  check(frame.items.stop.disabled && !frame.items.request.disabled, 'Close is checked after real session cleanup');
  await namedClick(page, SESSION.close, ['关闭', 'Close']);
  await page.waitForFunction(() => !document.querySelector('#remote-session'), { timeout: 5000 });
  const clicks = await page.evaluate(() => window.__nestlinkWorkspaceUi.clicks);
  check(clicks.length > 0 && clicks.every(event => event.trusted), 'Workspace navigation must use genuine browser clicks');
  check(clicks.some(event => event.selector === '.remote-actions > button:last-child'), 'The real Close button was not clicked');
  const facts = report.workspace_ui;
  check(isDeepStrictEqual(facts.navigation.map(item => item.viewport), VIEWPORTS) &&
    isDeepStrictEqual(facts.active_layouts.map(item => item.viewport), VIEWPORTS), 'One or more required layout sizes were skipped');
  check(facts.steady_layout_samples.length >= 3 && facts.permissions.requested_values_preserved &&
    facts.request_hid_options_without_moving_actions, 'The fixed-frame observations are incomplete');
  facts.trusted_clicks = clicks;
  facts.close_clicked_after_cleanup = true;
  facts.passed = true;
}

module.exports = { workspaces, permissions, requestStarted, activeLayouts, sampleActive, close,
  assertVisibleGeometry, assertStable, VIEWPORTS };
