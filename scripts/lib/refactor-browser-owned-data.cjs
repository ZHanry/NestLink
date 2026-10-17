// Tool-only observations and trusted UI actions against fresh owned data devices.
// No SDK replacement, permission bypass, desktop injection or user file access.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const downloadObservers = new WeakMap();
function check(value, message) { if (!value) throw new Error(message); }

function owned(ready, args) {
  const enabled = ready.owned_data?.enabled === true;
  check(enabled === (args['owned-data'] === 'true'), 'Owned data requires both the explicit fixture mode and probe opt-in');
  if (enabled) {
    const data = ready.owned_data;
    check(data.user_desktop_or_files_accessed === false && data.download.filename === 'owned-download.bin' &&
      data.upload.filename === 'owned-upload.bin' && data.expected_text === 'NestLink-G1-中文', 'Unexpected owned data descriptor');
    for (const file of [data.download, data.upload]) check(Number.isSafeInteger(file.bytes) && file.bytes > 65536 &&
      file.bytes < 4 * 1024 * 1024 && /^[a-f0-9]{64}$/.test(file.sha256), 'Invalid bounded owned file descriptor');
  }
  return enabled;
}

function ownedPaths(ready, args, tls) {
  const parent = path.resolve(path.dirname(tls.profile));
  const upload = path.resolve(args['upload-fixture'] || '');
  const downloads = path.resolve(args['download-directory'] || '');
  check(upload === path.join(parent, 'selected-upload.bin') && downloads === path.join(parent, 'received'),
    'Only exact harness-owned upload and download paths are allowed');
  check(fs.lstatSync(upload).isFile() && !fs.lstatSync(upload).isSymbolicLink() &&
    hash(fs.readFileSync(upload)) === ready.owned_data.upload.sha256, 'Selected owned upload bytes differ');
  check(fs.lstatSync(downloads).isDirectory() && !fs.lstatSync(downloads).isSymbolicLink() &&
    fs.readdirSync(downloads).length === 0, 'Browser download directory must be fresh and owned');
  return { upload, downloads };
}

async function createPage(browser, ready, args, tls) {
  if (!owned(ready, args)) return browser.newPage();
  const { downloads } = ownedPaths(ready, args, tls);
  // Both CDP and BiDi expose this public context-creation option. The Firefox
  // default context does not provide Chromium's setDownloadBehavior method.
  const context = await browser.createBrowserContext({ downloadBehavior: { policy: 'allow', downloadPath: downloads } });
  const page = await context.newPage();
  if (args.engine === 'chrome') {
    const session = await browser.target().createCDPSession();
    const observer = { session, started: [], progress: new Map() };
    session.on('Browser.downloadWillBegin', event => {
      if (observer.started.length < 4) observer.started.push({ guid: event.guid, filename: event.suggestedFilename });
    });
    session.on('Browser.downloadProgress', event => {
      if (observer.progress.size < 4 || observer.progress.has(event.guid)) observer.progress.set(event.guid, {
        state: event.state, received_bytes: event.receivedBytes, total_bytes: event.totalBytes });
    });
    // Observe actual completion before unlinking a download. An exact-sized
    // final file can exist before Chromium finishes its download bookkeeping.
    await session.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads,
      browserContextId: context.id, eventsEnabled: true });
    downloadObservers.set(page, observer);
  }
  return page;
}

async function completedDownload(page, expected) {
  const observer = downloadObservers.get(page);
  if (!observer) return null;
  const deadline = performance.now() + 10000;
  while (performance.now() < deadline) {
    if (observer.started.length === 1) {
      const started = observer.started[0];
      const progress = observer.progress.get(started.guid);
      check(started.filename === expected.filename, 'Actual browser download filename differs');
      check(progress?.state !== 'canceled', 'Actual browser download was canceled');
      if (progress?.state === 'completed') {
        check(progress.received_bytes === expected.bytes && progress.total_bytes === expected.bytes,
          'Completed browser download byte counters differ');
        return { ...started, ...progress };
      }
    }
    check(observer.started.length <= 1, 'Unexpected additional browser download');
    await sleep(25);
  }
  throw new Error('Actual browser download completion event did not arrive');
}

async function install(page, ready, args) {
  if (!owned(ready, args)) return;
  await page.evaluateOnNewDocument(() => {
    window.__ownedDataTrusted = { keydown: 0, pointerdown: 0, input: 0, untrusted: 0 };
    window.__ownedDataEvents = [];
    for (const type of ['keydown', 'pointerdown', 'input']) document.addEventListener(type, event => {
      if (!['remote-view-video', 'remote-input-text'].includes(event.target?.id)) return;
      const facts = window.__ownedDataTrusted;
      if (event.isTrusted) facts[type]++; else facts.untrusted++;
    }, true);
    for (const type of ['keydown', 'keypress', 'keyup', 'beforeinput', 'input', 'compositionstart', 'compositionend']) {
      document.addEventListener(type, event => {
        if (!['remote-view-video', 'remote-input-text'].includes(event.target?.id)) return;
        const observation = { type, target: event.target.id, trusted: event.isTrusted,
          code: event.code ?? null, key: event.key ?? null, input_type: event.inputType ?? null,
          key_code: event.keyCode ?? null, char_code: event.charCode ?? null,
          data: event.data ?? null, value_after_target_handler: event.target.value ?? null,
          path: event.composedPath().slice(0, 6).map(node => ({ tag: node.tagName ?? null, id: node.id ?? null })),
          ctrl: event.ctrlKey ?? false, alt: event.altKey ?? false, meta: event.metaKey ?? false, shift: event.shiftKey ?? false };
        if (window.__ownedDataEvents.length < 256) window.__ownedDataEvents.push({ ...observation,
          default_prevented: event.defaultPrevented });
      });
    }
  });
}

async function request(page, ready, args) {
  if (!owned(ready, args)) return;
  const labels = [
    [2, ['键盘和鼠标', 'Request keyboard and mouse control']],
    [3, ['文件下载', 'Request file downloads']],
    [4, ['文件上传', 'Request file uploads']],
  ];
  for (const [index, acceptedLabels] of labels) {
    const selector = `.remote-permissions label:nth-of-type(${index}) input`;
    check(await page.$eval(selector, input => !input.checked && !input.disabled), 'Permission must start unselected');
    const text = await page.$eval(selector, input => input.parentElement.textContent);
    check(acceptedLabels.some(label => text.includes(label)), 'Permission selector changed');
    await page.locator(selector).click();
    check(await page.$eval(selector, input => input.checked), 'Permission UI did not accept the explicit request');
  }
}

function records(args) {
  const file = path.join(path.dirname(path.resolve(args.ready)), 'input-records.jsonl');
  const raw = fs.readFileSync(file, 'utf8');
  // The actual recorder can be in the middle of writing its final line. Only
  // flushed, newline-terminated events count; malformed complete lines fail.
  const end = raw.lastIndexOf('\n');
  return end < 0 ? [] : raw.slice(0, end).split('\n').filter(Boolean).map(line => JSON.parse(line));
}
async function waitRecords(args, predicate, message) {
  const deadline = performance.now() + 10000;
  while (performance.now() < deadline) {
    const values = records(args);
    if (predicate(values)) return values;
    await sleep(25);
  }
  throw new Error(message);
}
async function privateFiles(page, expected) {
  return page.evaluate(async expected => {
    const root = await navigator.storage.getDirectory();
    let parent;
    try { parent = await root.getDirectoryHandle('nestlink-private-v15'); }
    catch (error) { if (error.name === 'NotFoundError') return []; throw error; }
    const files = [];
    for await (const [name, directory] of parent.entries()) {
      if (directory.kind !== 'directory' || !/^[0-9a-f-]{36}$/.test(name)) throw new Error('Unexpected private storage entry');
      const handle = await directory.getFileHandle('content');
      const file = await handle.getFile();
      const bytes = new Uint8Array(await file.arrayBuffer());
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
      let exact = !expected || bytes.length === expected.bytes;
      if (expected) for (let index = 0; exact && index < bytes.length; index++) exact = bytes[index] === (index * 17 + 11) % 251;
      files.push({ id: name, bytes: bytes.length, sha256: digest, actual_bytes_match_owned_pattern: exact });
    }
    return files;
  }, expected || null);
}

async function dataTransport(page) {
  return page.evaluate(async () => Promise.all((window.__nativeProbePeers || []).map(async peer => {
    const stats = await peer.getStats();
    return { sctp_state: peer.sctp?.state ?? null, maximum_message_bytes: peer.sctp?.maxMessageSize ?? null,
      channels: Array.from(stats.values()).filter(item => item.type === 'data-channel').map(item => ({
        label: item.label, state: item.state, messages_sent: item.messagesSent ?? null,
        messages_received: item.messagesReceived ?? null, bytes_sent: item.bytesSent ?? null,
        bytes_received: item.bytesReceived ?? null })) };
  })));
}

async function exercise(page, ready, args, report) {
  if (!owned(ready, args)) return;
  const data = report.owned_data = { requested: true, host_devices: 'Owned recorder and temporary private sandbox only', passed: false };
  await page.waitForFunction(() => {
    const video = document.querySelector('#remote-view-video');
    const toolbar = document.querySelector('.remote-toolbar p')?.textContent || '';
    return video?.getAttribute('tabindex') === '0' && video.classList.contains('visible') &&
      ['已连接，正在接收远程画面', 'Receiving the remote screen.'].some(label => toolbar.includes(label));
  });
  data.input_ui_binding_ready = true;
  data.transport_before = await dataTransport(page);
  check(data.transport_before.length === 1 && data.transport_before[0].sctp_state === 'connected',
    'The production peer must have one actual connected SCTP transport');
  check(records(args).every(item => item.kind === 'reset'), 'No input should be injected before a focused UI action');
  const renewalWaitStarted = performance.now();
  while (!report.renewals.length && performance.now() - renewalWaitStarted < 12000) await sleep(10);
  check(report.renewals.length > 0, 'Input must be exercised after an actual signed management renewal');
  data.input_started_after_renewal_sequence = report.renewals.at(-1).lease_sequence;
  const video = '#remote-view-video';
  const text = '#remote-input-text';
  await page.locator(video).click();
  data.input_focus_after_click = await page.evaluate(() => ({ active_element: document.activeElement?.id,
    document_focused: document.hasFocus(), trusted_events: window.__ownedDataTrusted }));
  check(data.input_focus_after_click.active_element === 'remote-view-video', 'The genuine pointer action must focus the production remote video');
  await waitRecords(args, values => values.some(item => item.kind === 'pointer' && item.button === 1 && item.down),
    'The trusted production video click did not reach the actual input recorder');
  await page.keyboard.press('a');
  await page.keyboard.down('Shift');
  await page.locator(text).click();
  await waitRecords(args, values => values.some(item => item.kind === 'release' && item.button_type === 'key' && item.code === 225),
    'The actual host did not receive release-all after video focus loss');
  await page.keyboard.up('Shift');
  // Focus-loss and text-entry are separate genuine actions. Chromium extends
  // an outer document selection on Shift-click from a captured video even in
  // stock HTML; a normal click establishes the textarea insertion caret.
  // Neither this action nor typing replaces the product's input listeners.
  await page.locator(text).click();
  data.text_entry_action = 'Trusted ordinary click after the completed Shift focus-loss action';
  data.text_focus = await page.$eval(text, element => ({ active: document.activeElement === element,
    read_only: element.readOnly, disabled: element.disabled, tag: element.tagName, parent: element.parentElement.tagName,
    maximum_length: element.maxLength, minimum_length: element.minLength, selection_start: element.selectionStart,
    selection_end: element.selectionEnd, attributes: Array.from(element.attributes, attr => [attr.name, attr.value]),
    user_modify: getComputedStyle(element).webkitUserModify, namespace: element.namespaceURI,
    document_selection: (() => { const selection = document.getSelection(); return {
      ranges: selection?.rangeCount, anchor_node: selection?.anchorNode?.nodeName,
      anchor_parent: selection?.anchorNode?.parentElement?.id, focus_node: selection?.focusNode?.nodeName,
      focus_parent: selection?.focusNode?.parentElement?.id }; })(),
    ancestors: Array.from((function* () { for (let node = element; node; node = node.parentElement) yield node; })(), node => ({
      tag: node.tagName, namespace: node.namespaceURI, inert: node.inert, editable: node.contentEditable,
      disabled: node.disabled ?? null, user_modify: getComputedStyle(node).webkitUserModify })) }));
  await page.type(text, ready.owned_data.expected_text, { delay: 5 });
  data.browser_text_events = await page.evaluate(() => window.__ownedDataEvents);
  try {
    await waitRecords(args, values => values.filter(item => item.kind === 'text').map(item => item.text).join('') === ready.owned_data.expected_text,
      'The real input channel did not deliver the exact trusted browser text');
  } catch (error) {
    // Failure-only diagnostic outside the product form. It cannot make the
    // product assertion pass, and neither replaces nor calls its input sink.
    await page.evaluate(() => {
      const diagnostic = document.createElement('textarea');
      diagnostic.id = 'owned-diagnostic-textarea';
      document.body.appendChild(diagnostic);
    });
    await page.type('#owned-diagnostic-textarea', 'Owned-diagnostic-9', { delay: 5 });
    data.failure_only_plain_textarea = await page.$eval('#owned-diagnostic-textarea', element => {
      const value = element.value;
      const user_modify = getComputedStyle(element).webkitUserModify;
      element.remove();
      return { value, user_modify, removed: !element.isConnected };
    });
    await page.$eval(text, element => {
      const diagnostic = element.cloneNode(false);
      diagnostic.id = 'owned-diagnostic-sibling';
      element.parentElement.appendChild(diagnostic);
    });
    await page.type('#owned-diagnostic-sibling', 'Sibling-diagnostic-9', { delay: 5 });
    data.failure_only_sibling_textarea = await page.$eval('#owned-diagnostic-sibling', element => {
      const result = { value: element.value, namespace: element.namespaceURI,
        user_modify: getComputedStyle(element).webkitUserModify, parent: element.parentElement.tagName };
      element.remove();
      return { ...result, removed: !element.isConnected };
    });
    const beforeRetry = records(args).filter(item => item.kind === 'text').map(item => item.text).join('');
    await page.type(text, 'Refocused-diagnostic-9', { delay: 5 });
    await sleep(500);
    const afterRetry = records(args).filter(item => item.kind === 'text').map(item => item.text).join('');
    data.failure_only_original_refocused = { native_text_before: beforeRetry, native_text_after: afterRetry,
      active_element: await page.evaluate(() => document.activeElement?.id),
      listener_changes: false };
    throw error;
  }
  data.focus_loss_release_observed = true;
  data.trusted_events = await page.evaluate(() => window.__ownedDataTrusted);
  check(data.trusted_events.keydown > 0 && data.trusted_events.pointerdown > 0 && data.trusted_events.input > 0 &&
    data.trusted_events.untrusted === 0, 'Owned input must originate from genuine browser input actions');
  const nativeInputs = records(args);
  check(nativeInputs.some(item => item.kind === 'key' && item.code === 4 && item.down) &&
    nativeInputs.some(item => item.kind === 'key' && item.code === 4 && !item.down), 'Physical A key transitions are missing');
  const pointers = nativeInputs.filter(item => item.kind === 'pointer');
  check(pointers.some(item => item.button === 1 && item.down) && pointers.every(item =>
    item.x >= 0 && item.y >= 0 && item.x < ready.capture_profile.width && item.y < ready.capture_profile.height),
    'Recorded pointer actions must stay in the actual approved video layout');

  data.stage = 'opening-data-panel';
  data.panel_before = await page.$eval('.remote-data-panel', panel => {
    const summary = panel.querySelector('summary');
    const rect = summary.getBoundingClientRect();
    const x = Math.max(0, Math.min(innerWidth - 1, rect.left + rect.width / 2));
    const y = Math.max(0, Math.min(innerHeight - 1, rect.top + rect.height / 2));
    const hit = document.elementFromPoint(x, y);
    return { open: panel.open, summary_visible: rect.width > 0 && rect.height > 0,
      rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
      hit: hit ? { tag: hit.tagName, id: hit.id, class_name: String(hit.className || '') } : null,
      hit_is_summary_or_child: hit === summary || summary.contains(hit) };
  });
  if (!data.panel_before.open) await page.locator('.remote-data-panel > summary').click({ timeout: 5000 });
  data.stage = 'waiting-for-data-readiness';
  await page.waitForFunction(() => ['连接已验证', 'Connection verified'].some(label =>
    document.querySelector('.remote-data-state')?.textContent.includes(label)));
  const approvals = '.remote-data-approvals';
  const read = 'section[aria-labelledby="remote-files-title"]';
  const write = 'section[aria-labelledby="remote-upload-title"]';
  check(await page.$$eval(`${approvals} input`, inputs => inputs.every(input => !input.checked)), 'Local data approval must default to denied');
  check(await page.$eval(`${read} button`, button => button.disabled) && await page.$eval(`${write} input[type="file"]`, input => input.disabled),
    'File operations must remain disabled before each direction is locally approved');
  data.stage = 'requesting-download-approval';
  await page.locator(`${approvals} label:nth-of-type(1) input`).click();
  check(await page.$eval(`${write} input[type="file"]`, input => input.disabled), 'Download consent must not grant uploads');
  data.stage = 'loading-download-roots';
  await page.locator(`${read} .remote-data-actions:first-of-type > button:nth-of-type(1)`).click();
  await page.waitForFunction(read => document.querySelectorAll(read + ' select option').length === 2, { timeout: 15000 }, read);
  const readRoot = await page.$eval(`${read} select`, select => select.options[1].value);
  check(await page.$eval(`${read} select`, select => select.options[1].textContent) === 'Owned download sandbox', 'Unexpected native read root');
  await page.select(`${read} select`, readRoot);
  data.stage = 'browsing-download-root';
  await page.locator(`${read} .remote-data-actions:first-of-type > button:nth-of-type(2)`).click();
  await page.waitForFunction(filename => Array.from(document.querySelectorAll('.remote-file-entry span')).some(row => row.textContent === filename), { timeout: 15000 }, ready.owned_data.download.filename);
  check(await page.$$eval('.remote-file-entry', rows => rows.length) === 1, 'Sandbox directory must expose exactly its owned source');
  await page.locator('.remote-file-entry').click();
  data.stage = 'downloading-owned-file';
  await page.locator(`${read} button.primary`).click();
  await page.waitForFunction(filename => Array.from(document.querySelectorAll('.remote-artifact')).some(row =>
    row.querySelector('strong')?.textContent === filename && ['已校验', 'Verified'].some(label =>
      row.querySelector('small')?.textContent.includes(label))), { timeout: 30000 }, ready.owned_data.download.filename);
  data.private_downloads = await privateFiles(page, ready.owned_data.download);
  check(data.private_downloads.length === 1 && data.private_downloads[0].sha256 === ready.owned_data.download.sha256 &&
    data.private_downloads[0].actual_bytes_match_owned_pattern, 'Actual OPFS download bytes differ from the owned native source');
  await page.locator('.remote-artifact button.secondary').click();
  data.browser_download_completion = await completedDownload(page, ready.owned_data.download);
  const saved = path.join(path.resolve(args['download-directory']), ready.owned_data.download.filename);
  const saveDeadline = performance.now() + 10000;
  while (performance.now() < saveDeadline) {
    if (fs.existsSync(saved) && fs.statSync(saved).size === ready.owned_data.download.bytes &&
      fs.readdirSync(path.dirname(saved)).length === 1 && hash(fs.readFileSync(saved)) === ready.owned_data.download.sha256) break;
    await sleep(25);
  }
  check(fs.existsSync(saved) && fs.lstatSync(saved).isFile() && !fs.lstatSync(saved).isSymbolicLink(), 'Actual browser Save did not finish into its owned directory');
  const savedBytes = fs.readFileSync(saved);
  data.browser_saved_file = { bytes: savedBytes.length, sha256: hash(savedBytes) };
  check(data.browser_saved_file.bytes === ready.owned_data.download.bytes && data.browser_saved_file.sha256 === ready.owned_data.download.sha256,
    'Actual browser-saved download bytes differ');
  check(fs.readdirSync(path.dirname(saved)).length === 1, 'Unexpected partial download remains');
  // The browser retains its real download until it exits. In particular,
  // Firefox can still hold a Windows file handle after exact bytes arrive.
  // cleanupAfterBrowser rechecks the same bytes and hash before removing it.
  data.owned_saved_file_pending_browser_exit = true;
  await page.locator('.remote-artifact button.danger').click();
  await page.waitForFunction(() => document.querySelectorAll('.remote-artifact').length === 0);
  check((await privateFiles(page)).length === 0, 'Actual private staging directory was not deleted');
  data.private_stage_removed = true;

  await page.locator(`${approvals} label:nth-of-type(2) input`).click();
  await page.locator(`${write} .remote-data-actions > button.secondary`).click();
  await page.waitForFunction(write => document.querySelectorAll(write + ' select option').length === 2, {}, write);
  const writeRoot = await page.$eval(`${write} select`, select => select.options[1].value);
  check(await page.$eval(`${write} select`, select => select.options[1].textContent) === 'Owned upload sandbox', 'Unexpected native receiving root');
  await page.select(`${write} select`, writeRoot);
  const chooser = await page.$(`${write} input[type="file"]`);
  check(chooser, 'Actual file selection control unavailable');
  await chooser.uploadFile(path.resolve(args['upload-fixture']));
  await page.locator(`${write} input[type="text"]`).fill(ready.owned_data.upload.filename);
  await page.locator(`${write} button.primary`).click();
  await page.waitForFunction(() => ['远端已确认文件完整接收。', 'The remote device confirmed receipt of the complete file.'].some(label =>
    document.querySelector('.remote-data-content')?.textContent.includes(label)), { timeout: 30000 });
  data.upload_acknowledged_by_actual_ui = true;
  await page.locator('.remote-data-panel > summary').click();
  await page.waitForFunction(() => !document.querySelector('.remote-data-panel')?.open &&
    Array.from(document.querySelectorAll('.remote-data-approvals input')).every(input => !input.checked));
  await page.locator('.remote-data-panel > summary').click();
  check(await page.$$eval(`${approvals} input`, inputs => inputs.every(input => !input.checked)), 'Closing the data panel must revoke every local direction');
  check(await page.$eval(`${read} button`, button => button.disabled) && await page.$eval(`${write} input[type="file"]`, input => input.disabled),
    'Revoked file controls must remain disabled after reopening');
  data.panel_close_revoked_approvals = true;
  data.transport_after = await dataTransport(page);
  check(data.transport_after.length === 1 && data.transport_after[0].sctp_state === 'connected',
    'The real SCTP transport did not remain connected after input and file transfer');
}

async function holdTerminalKey(page, ready, args, report) {
  if (!owned(ready, args)) return false;
  await page.locator('#remote-view-video').click();
  await page.keyboard.down('b');
  await waitRecords(args, values => values.some(item => item.kind === 'key' && item.code === 5 && item.down), 'Terminal held key did not reach the owned recorder');
  report.owned_data.terminal_held_key_observed = true;
  return true;
}

async function disconnect(page, ready, args, report) {
  if (!owned(ready, args)) return false;
  const before = records(args);
  const lastKeyEvent = before.findLast(item => (item.kind === 'key' && item.code === 5) ||
    (item.kind === 'release' && item.button_type === 'key' && item.code === 5));
  check(lastKeyEvent?.kind === 'key' && lastKeyEvent.down === true,
    'Terminal key was already released before the disconnect action');
  report.owned_data.pre_disconnect_input_events = before.length;
  report.owned_data.terminal_key_held_before_disconnect = true;
  // Keep the real held key focused while activating the existing Disconnect
  // handler. A programmatic button click avoids focus blur pre-releasing it;
  // authorization, transport and device cleanup stay in the product paths.
  report.owned_data.disconnect_activation = 'Existing UI button click without focus change; key input itself was trusted';
  await page.$eval('.remote-actions button.danger', button => button.click());
  await page.waitForFunction(() => window.__nativeProbePeers.every(peer => peer.connectionState === 'closed'), { timeout: 10000 });
  const nativePath = path.join(path.dirname(path.resolve(args.ready)), 'data-result.json');
  const deadline = performance.now() + 10000;
  while (!fs.existsSync(nativePath) && performance.now() < deadline) await sleep(25);
  check(fs.existsSync(nativePath), 'Native data cleanup receipt did not arrive');
  const native = JSON.parse(fs.readFileSync(nativePath, 'utf8'));
  check(native.passed && native.files_exact && native.held_buttons === 0 && native.input_device_dropped && native.owned_sandbox_removed,
    'Native input/file owners or exact uploaded bytes failed cleanup');
  check(isDeepStrictEqual(native.input_events.slice(0, before.length), before),
    'Native input history changed before disconnect cleanup');
  check(native.input_events.slice(before.length).some(item => item.kind === 'release' && item.button_type === 'key' && item.code === 5),
    'Disconnect did not release the actual terminal held key');
  await page.waitForFunction(async () => !(await navigator.locks.query()).held.some(lock => lock.name === 'nestlink-private-v15'), { timeout: 10000 });
  check((await privateFiles(page)).length === 0, 'Disconnected private files were not physically cleaned');
  report.owned_data.native_result_sha256 = hash(fs.readFileSync(nativePath));
  report.owned_data.native_uploaded_file = native.uploaded;
  report.owned_data.terminal_key_released = true;
  report.owned_data.browser_storage_lock_released = true;
  report.owned_data.passed = true;
  return true;
}

async function cleanupAfterBrowser(ready, args, report) {
  if (!owned(ready, args)) return;
  check(report.browser_closed, 'Owned saved-file cleanup requires actual browser closure');
  const tls = JSON.parse(fs.readFileSync(args.tls, 'utf8'));
  const parent = path.resolve(path.dirname(tls.profile));
  const directory = path.resolve(args['download-directory'] || '');
  check(directory === path.join(parent, 'received') && fs.lstatSync(directory).isDirectory() &&
    !fs.lstatSync(directory).isSymbolicLink(), 'Saved-file cleanup escaped the exact owned download directory');
  const entries = fs.readdirSync(directory);
  const data = report.owned_data;
  if (!data?.browser_saved_file) {
    check(entries.length === 0, 'An unverified browser download must be retained');
    return;
  }
  const expected = ready.owned_data.download;
  const saved = path.join(directory, expected.filename);
  check(entries.length === 1 && entries[0] === expected.filename && fs.lstatSync(saved).isFile() &&
    !fs.lstatSync(saved).isSymbolicLink(), 'Unexpected final browser download entry');
  const bytes = fs.readFileSync(saved);
  data.browser_saved_file_after_exit = { bytes: bytes.length, sha256: hash(bytes) };
  check(bytes.length === expected.bytes && hash(bytes) === expected.sha256,
    'Browser-exited saved-file bytes differ from the actual native source');
  fs.unlinkSync(saved);
  check(!fs.existsSync(saved) && fs.readdirSync(directory).length === 0, 'Owned browser-saved file was not physically removed');
  data.owned_saved_file_removed = true;
}

module.exports = { createPage, install, request, exercise, holdTerminalKey, disconnect, cleanupAfterBrowser };
