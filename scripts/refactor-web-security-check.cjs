// Focused production-UI check against a new, owned control deployment. No
// existing account, deployment, key, browser profile or trust store is read.
// The report deliberately excludes bodies, screenshots and exception text:
// they can contain passwords, TOTP seeds, recovery codes or access tokens.
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const argumentsMap = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!process.argv[i].startsWith('--') || !process.argv[i + 1]) throw new Error('Invalid arguments');
  argumentsMap[process.argv[i].slice(2)] = process.argv[i + 1];
}
for (const required of ['server-exe', 'production-dir', 'playwright-package', 'openssl', 'report']) {
  if (!argumentsMap[required]) throw new Error('Missing argument: --' + required);
}
if (process.platform !== 'win32') throw new Error('This probe requires Windows DPAPI');
const reportPath = path.resolve(argumentsMap.report);
const artifactsRoot = path.join(root, 'artifacts') + path.sep;
if (!reportPath.startsWith(artifactsRoot) || fs.existsSync(reportPath)) throw new Error('Report must be new and inside repository artifacts');
const productionRoot = fs.realpathSync(argumentsMap['production-dir']);
const serverSource = fs.realpathSync(argumentsMap['server-exe']);
const maximumMs = Number(argumentsMap['maximum-seconds'] || 900) * 1000;
if (!Number.isFinite(maximumMs) || maximumMs < 60_000 || maximumMs > 5_400_000) throw new Error('Maximum duration must be 60–5400 seconds');
const { chromium } = require(path.resolve(argumentsMap['playwright-package']));
const playwrightVersion = JSON.parse(fs.readFileSync(path.join(argumentsMap['playwright-package'], 'package.json'))).version;
if (playwrightVersion !== '1.64.1') throw new Error('Use reviewed playwright-core 1.64.1');
const chromePath = argumentsMap['chrome-exe'] || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
if (!fs.existsSync(chromePath) || !fs.existsSync(path.join(productionRoot, 'index.html'))) throw new Error('Missing Chrome or production entry');

const report = {
  schema_version: 1,
  scope: 'Focused development check of production Web account security and remote authorization with a real isolated control server; no media or installed-product acceptance',
  started_at_utc: new Date().toISOString(),
  maximum_seconds: maximumMs / 1000,
  cases: [],
  api_requests: [],
  direct_api_requests: [],
  tools: { node: process.version, playwright: playwrightVersion },
  cleanup: {},
};
let phase = 'setup';
let stopped = false;
let context;
let control;
let proxy;
let dropResponse = null;
let deadline;
let accessToken;
let origin;
let backendPort;
let health;
let principal;
const proxySockets = new Set();
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'nestlink-security-owned-'));
const scratchReal = fs.realpathSync(scratch);
const deploymentDir = path.join(scratch, 'deployment');
const initialPassword = crypto.randomBytes(32).toString('base64url');
const changedPassword = crypto.randomBytes(32).toString('base64url');
const remotePassword = crypto.randomBytes(24).toString('base64url');
const username = 'probe-' + crypto.randomBytes(5).toString('hex');
const hostId = crypto.randomUUID();
const hostName = 'Owned security probe host';
const hostKeys = crypto.generateKeyPairSync('ed25519');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
function failure(code) { const error = new Error(code); error.safeCode = code; return error; }
function check(condition, code) { if (!condition) throw failure(code); }
function run(executable, args, extraEnv = {}) {
  const result = spawnSync(executable, args, {
    encoding: 'utf8', timeout: 30_000, windowsHide: true,
    env: { ...process.env, ...extraEnv }, maxBuffer: 1024 * 1024,
  });
  check(!result.error && result.status === 0, 'Owned command failed: ' + path.basename(executable) + ':' + args[0]);
  return result.stdout;
}
function powershell(script, extraEnv = {}) {
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], extraEnv);
}
function siteInputs(directory) {
  const result = [];
  const visit = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      check(!entry.isSymbolicLink(), 'Static site contains a link');
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) result.push({ path: path.relative(directory, full).split(path.sep).join('/'), bytes: fs.statSync(full).size, sha256: sha256(fs.readFileSync(full)) });
    }
  };
  visit(directory);
  return result;
}
async function waitFor(predicate, code, timeout = 30_000) {
  const start = performance.now();
  while (!stopped && performance.now() - start < timeout) {
    if (await predicate()) return;
    await sleep(100);
  }
  throw failure(code);
}
async function test(name, action) {
  phase = name;
  process.stdout.write('Running focused UI case: ' + name + '\n');
  const start = performance.now();
  await action();
  report.cases.push({ case: name, status: 'passed', elapsed_ms: Math.round(performance.now() - start) });
}
function api(method, endpoint, body, authenticated = true) {
  return new Promise((resolve, reject) => {
    const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const headers = { Origin: origin };
    if (bytes) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = bytes.length; }
    if (authenticated) headers.Authorization = 'Bearer ' + accessToken;
    const request = http.request({ host: '127.0.0.1', port: backendPort, path: '/api/v3' + endpoint, method, headers, agent: false }, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > 1024 * 1024) request.destroy(new Error('Response budget'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          const raw = Buffer.concat(chunks);
          report.direct_api_requests.push({ method, path: '/api/v3' + endpoint, status: response.statusCode });
          const text = raw.toString('utf8');
          const value = raw.length ? JSON.parse(text) : null;
          // Node 20's JSON parser rounds random 63-bit security epochs. Keep
          // the exact public integer from these two flat response contracts.
          if (value && (endpoint === '/health' || endpoint === '/devices/challenge') && response.statusCode === 200) {
            const matches = [...text.matchAll(/"security_epoch"\s*:\s*([0-9]+)/g)];
            check(matches.length === 1, 'Security epoch lexical representation missing');
            value.security_epoch = BigInt(matches[0][1]);
          }
          resolve({ status: response.statusCode, value });
        } catch { reject(new Error('API response invalid')); }
      });
      response.on('error', () => reject(new Error('API response failed')));
    });
    request.setTimeout(10_000, () => request.destroy());
    request.on('error', () => reject(new Error('API transport failed')));
    request.end(bytes);
  });
}
async function requiredApi(method, endpoint, body, authenticated = true) {
  const response = await api(method, endpoint, body, authenticated);
  const code = Number.isInteger(response.value?.code) || /^[A-Z_]{1,64}$/.test(response.value?.code || '') ? response.value.code : 'none';
  check(response.status >= 200 && response.status < 300, 'API rejected owned setup: ' + method + ':' + endpoint + ':' + response.status + ':' + code);
  return response.value;
}
function varint(value) {
  let remaining = BigInt(value);
  const bytes = [];
  do {
    let next = Number(remaining & 127n);
    remaining >>= 7n;
    if (remaining) next |= 128;
    bytes.push(next);
  } while (remaining);
  return Buffer.from(bytes);
}
function protobufField(number, value) {
  if (typeof value === 'number' || typeof value === 'bigint') return Buffer.concat([varint(number << 3), varint(value)]);
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return Buffer.concat([varint((number << 3) | 2), varint(bytes.length), bytes]);
}
function signAction(challenge, action, payload) {
  const claims = Buffer.concat([
    protobufField(1, 1), protobufField(2, action), protobufField(3, challenge.deployment_id),
    protobufField(4, challenge.security_epoch), protobufField(5, principal.account_id),
    protobufField(6, hostId), protobufField(7, challenge.id),
    protobufField(8, Buffer.from(challenge.nonce, 'base64url')),
    protobufField(9, crypto.createHash('sha256').update(JSON.stringify(payload)).digest()),
    protobufField(10, challenge.expires_at_unix_ms),
  ]);
  const message = Buffer.concat([Buffer.from('NestLink/v15/device-action/v1\0'), claims]);
  const signature = crypto.sign(null, message, hostKeys.privateKey);
  check(crypto.verify(null, message, hostKeys.publicKey, signature), 'Owned signature did not verify locally');
  return signature.toString('base64url');
}
async function configurePassword(expectedRevision) {
  const challenge = await requiredApi('POST', '/devices/challenge');
  const choice = { settings: { expected_revision: expectedRevision, permissions: [1], paths: [1], expires_at_unix_ms: Date.now() + 600_000 }, password: remotePassword };
  return (await requiredApi('PUT', '/devices/' + hostId + '/remote-password', { challenge_id: challenge.id, choice, signature: signAction(challenge, 7, choice) })).revision;
}
function count(method, expression) { return report.api_requests.filter(item => item.method === method && expression.test(item.path)).length; }
function latest(method, expression) { return report.api_requests.filter(item => item.method === method && expression.test(item.path)).at(-1); }
async function remoteRevoked(id) {
  await waitFor(async () => (await requiredApi('GET', '/remote/' + id)).status === 'revoked', 'Remote request not revoked');
}
function totp(seed) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of seed) {
    const digit = alphabet.indexOf(char);
    check(digit >= 0, 'TOTP encoding');
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >> bits) & 255); }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const key = Buffer.from(bytes);
  const digest = crypto.createHmac('sha1', key).update(counter).digest();
  key.fill(0);
  const offset = digest[19] & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

async function main() {
  // Restrict the entire new scratch before any private files or profile exist.
  powershell("$ErrorActionPreference='Stop'; $p=$env:NESTLINK_OWNED_SCRATCH; $a=New-Object System.Security.AccessControl.DirectorySecurity; $a.SetAccessRuleProtection($true,$false); $s=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; $a.SetOwner($s); foreach($sid in @('S-1-3-4','S-1-5-18')){ $id=New-Object System.Security.Principal.SecurityIdentifier($sid); $r=New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $a.AddAccessRule($r) }; [IO.Directory]::SetAccessControl($p,$a)", { NESTLINK_OWNED_SCRATCH: scratch });
  report.production_inputs_before = siteInputs(productionRoot);
  report.server_input = { path: serverSource, bytes: fs.statSync(serverSource).size, sha256: sha256(fs.readFileSync(serverSource)) };
  report.script_sha256 = sha256(fs.readFileSync(__filename));
  report.chrome_sha256 = sha256(fs.readFileSync(chromePath));
  const frozenServer = path.join(scratch, 'control.exe');
  fs.copyFileSync(serverSource, frozenServer);
  check(sha256(fs.readFileSync(frozenServer)) === report.server_input.sha256, 'Server copy changed');
  const certPath = path.join(scratch, 'owned-cert.pem');
  const keyPath = path.join(scratch, 'owned-cert-key.pem');
  run(argumentsMap.openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', '/CN=NestLink owned development probe', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', keyPath, '-out', certPath]);
  const certificate = fs.readFileSync(certPath);
  const spki = new crypto.X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' });
  report.tls = { leaf_spki_sha256_base64: crypto.createHash('sha256').update(spki).digest('base64'), exception_scope: 'Owned leaf SPKI in isolated Chromium profile; no trust-store changes or global HTTPS bypass' };
  proxy = https.createServer({ cert: certificate, key: fs.readFileSync(keyPath) }, (request, response) => {
    const endpoint = new URL(request.url, origin || 'https://127.0.0.1').pathname;
    if (endpoint === '/api/v3' || endpoint.startsWith('/api/v3/')) {
      const upstream = http.request({ host: '127.0.0.1', port: backendPort, method: request.method, path: request.url, headers: request.headers, agent: false }, upstreamResponse => {
        const item = { method: request.method, path: endpoint, status: upstreamResponse.statusCode };
        report.api_requests.push(item);
        if (dropResponse && dropResponse.method === request.method && dropResponse.path.test(endpoint)) {
          const chosen = dropResponse;
          dropResponse = null;
          // Send the real backend headers and one real body byte. Losing an
          // entire response before its headers can trigger Chromium's TCP
          // retry behavior even for POST; this fault targets the UI's handling
          // of an incomplete response body after the transaction committed.
          response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
          response.flushHeaders();
          let firstByteSent = false;
          upstreamResponse.on('data', chunk => {
            if (!firstByteSent && chunk.length) { firstByteSent = true; response.write(chunk.subarray(0, 1)); }
          });
          upstreamResponse.on('end', () => {
            item.response_dropped_after_backend_completed = true;
            item.real_response_headers_and_first_byte_sent = firstByteSent;
            chosen.completed = true;
            setTimeout(() => request.socket.destroy(), 50);
          });
          return;
        }
        response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      });
      upstream.setTimeout(15_000, () => upstream.destroy());
      upstream.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
      request.on('aborted', () => upstream.destroy());
      request.pipe(upstream);
      return;
    }
    let relative;
    try { relative = decodeURIComponent(endpoint === '/' ? '/index.html' : endpoint); }
    catch { response.writeHead(400).end(); return; }
    const full = path.resolve(productionRoot, '.' + relative);
    if (!full.startsWith(productionRoot + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile() || fs.realpathSync(full) !== full) { response.writeHead(404).end(); return; }
    const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.wasm': 'application/wasm', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' }[path.extname(full)] || 'application/octet-stream';
    response.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-store' });
    fs.createReadStream(full).pipe(response);
  });
  proxy.on('connection', socket => { proxySockets.add(socket); socket.on('close', () => proxySockets.delete(socket)); });
  await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); });
  origin = 'https://127.0.0.1:' + proxy.address().port;
  const reserved = net.createServer();
  await new Promise((resolve, reject) => { reserved.once('error', reject); reserved.listen(0, '127.0.0.1', resolve); });
  backendPort = reserved.address().port;
  await new Promise(resolve => reserved.close(resolve));
  phase = 'owned-deployment-setup';
  run(frozenServer, ['init', '--directory', deploymentDir, '--management-origin', origin, '--listen', '127.0.0.1:' + backendPort]);
  const configPath = path.join(deploymentDir, 'server.toml');
  const passwordPath = path.join(deploymentDir, 'bootstrap-password');
  fs.writeFileSync(passwordPath, initialPassword, { flag: 'wx' });
  run(frozenServer, ['bootstrap', '--config', configPath, '--username', username, '--password-file', passwordPath]);
  fs.unlinkSync(passwordPath);
  phase = 'independent-new-deployment-pin';
  // Derive the public pin from this new deployment's protected key, not from
  // unauthenticated HTTP discovery. The seed crosses only a private pipe.
  const protectedSeed = Buffer.from(powershell("$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $b=[IO.File]::ReadAllBytes((Join-Path $env:NESTLINK_OWNED_DEPLOYMENT 'permit.key')); if([Text.Encoding]::ASCII.GetString($b,0,8) -ne 'NL15DP01'){throw 'key format'}; $s=[Security.Cryptography.ProtectedData]::Unprotect($b[8..($b.Length-1)],$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); try{[Console]::Write([Convert]::ToBase64String($s))}finally{[Array]::Clear($s,0,$s.Length)}", { NESTLINK_OWNED_DEPLOYMENT: deploymentDir }).trim(), 'base64');
  check(protectedSeed.length === 32, 'Protected seed length');
  const privateDer = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), protectedSeed]);
  protectedSeed.fill(0);
  const permitPublicKey = crypto.createPublicKey(crypto.createPrivateKey({ key: privateDer, type: 'pkcs8', format: 'der' })).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
  privateDer.fill(0);
  const config = fs.readFileSync(configPath, 'utf8');
  const deploymentId = /^deployment_id\s*=\s*"([^"]+)"/m.exec(config)?.[1];
  check(deploymentId, 'New deployment ID missing');
  control = spawn(frozenServer, ['control', '--config', configPath], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  control.stdout.resume();
  control.stderr.resume();
  control.on('error', () => {});
  await waitFor(async () => {
    try { const value = await api('GET', '/health', undefined, false); if (value.status === 200) { health = value.value; return true; } } catch {}
    return false;
  }, 'New control server did not start');
  check(health.deployment_id === deploymentId && health.permit_issuer === permitPublicKey, 'Independent deployment pin mismatch');
  phase = 'owned-host-and-password-setup';
  report.deployment = { deployment_id: deploymentId, permit_issuer: permitPublicKey, host_device_id: hostId, trust_pin_source: 'Only this run\'s newly created DPAPI-protected permit.key' };
  const login = await requiredApi('POST', '/auth/login', { username, password: initialPassword, factor: null }, false);
  principal = login.principal;
  accessToken = login.access_token;
  const challenge = await requiredApi('POST', '/devices/challenge');
  const device = { id: hostId, name: hostName, platform: 'windows', public_key: hostKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url'), capabilities: ['controller', 'host', 'vp8'], path_mode: 'direct_only' };
  await requiredApi('POST', '/devices', { challenge_id: challenge.id, device, signature: signAction(challenge, 1, device) });
  let passwordRevision = await configurePassword(0);
  phase = 'isolated-production-browser-start';
  context = await chromium.launchPersistentContext(path.join(scratch, 'profile'), {
    executablePath: chromePath, headless: true, locale: 'en-US', viewport: { width: 1440, height: 1000 },
    args: ['--no-first-run', '--no-default-browser-check', '--ignore-certificate-errors-spki-list=' + report.tls.leaf_spki_sha256_base64],
    timeout: 30_000,
  });
  const page = context.pages()[0] || await context.newPage();
  page.setDefaultTimeout(20_000);
  page.on('pageerror', () => { report.page_error_count = (report.page_error_count || 0) + 1; });
  report.tools.browser = context.browser()?.version() || 'unknown';
  const button = name => page.getByRole('button', { name, exact: true });
  const workspace = () => waitFor(() => page.locator('.workspace').isVisible(), 'Workspace missing');
  const idleRemote = () => waitFor(() => page.locator('#remote-session').getByRole('button', { name: 'Request connection', exact: true }).isEnabled(), 'Remote cleanup did not finish');
  await test('production-trust-and-sign-in', async () => {
    await page.goto(origin, { waitUntil: 'networkidle' });
    await button('English').click();
    await page.locator('#deployment').fill(deploymentId);
    await page.locator('#issuer').fill(permitPublicKey);
    await button('Verify and continue').click();
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(initialPassword);
    await button('Sign in').click();
    await workspace();
  });
  await test('trusted-denial-cleans-and-manual-retry-works', async () => {
    await page.getByRole('button', { name: new RegExp(hostName) }).click();
    await button('Connect in browser').click();
    await page.getByLabel('Access method', { exact: false }).selectOption('trusted_device');
    const normalCount = count('POST', /^\/api\/v3\/remote$/);
    await button('Request connection').click();
    await waitFor(() => latest('POST', /^\/api\/v3\/remote\/trusted$/)?.status === 403, 'Trusted denial missing');
    await idleRemote();
    check(count('POST', /^\/api\/v3\/remote$/) === normalCount, 'Trusted request silently fell back');
    check(!(await button('Retry cleanup').isVisible()), 'Denied request retained cleanup owner');
    await page.getByLabel('Access method', { exact: false }).selectOption('local_approval');
    await button('Request connection').click();
    await waitFor(() => count('POST', /^\/api\/v3\/remote$/) === normalCount + 1, 'Manual retry did not create request');
    await waitFor(async () => (await requiredApi('GET', '/remote')).requests.length === 1, 'Manual request not pending');
    const requestId = (await requiredApi('GET', '/remote')).requests[0].id;
    await button('Stop connection').click();
    await idleRemote();
    await remoteRevoked(requestId);
  });
  await test('remote-fullscreen-observes-enter-button-and-external-native-exit', async () => {
    await button('Fullscreen').click();
    await waitFor(() => page.evaluate(() => document.fullscreenElement?.id === 'remote-session'), 'Remote fullscreen did not enter');
    await waitFor(() => button('Exit fullscreen').isVisible(), 'Fullscreen observer did not update button');
    await button('Exit fullscreen').click();
    await waitFor(() => page.evaluate(() => !document.fullscreenElement), 'Fullscreen button did not exit');
    await waitFor(() => button('Fullscreen').isVisible(), 'Fullscreen observer did not observe button exit');
    await button('Fullscreen').click();
    await waitFor(() => page.evaluate(() => document.fullscreenElement?.id === 'remote-session'), 'Second fullscreen entry failed');
    await page.evaluate(() => document.exitFullscreen());
    await waitFor(() => button('Fullscreen').isVisible(), 'Fullscreen observer did not observe external native exit');
    report.fullscreen_validation_limit = 'Headless Chromium CDP Escape did not invoke the browser default in retained attempt10; this check uses the real external document.exitFullscreen API. Physical Escape remains installed-product acceptance.';
  });
  const requestPassword = async () => {
    await page.getByLabel('Access method', { exact: false }).selectOption('password');
    await button('Request connection').click();
    await page.locator('#remote-access-password').waitFor({ state: 'visible' });
    check((await page.locator('#remote-session').innerText()).includes('Host password revision ' + passwordRevision), 'Password revision not disclosed');
    const requests = (await requiredApi('GET', '/remote')).requests;
    check(requests.length === 1 && requests[0].permissions.length === 1 && requests[0].permissions[0] === 1, 'Unexpected request permission scope');
    return requests[0].id;
  };
  await test('changed-password-offer-never-sends-credential', async () => {
    const requestId = await requestPassword();
    const submissions = count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/);
    passwordRevision = await configurePassword(passwordRevision);
    await page.locator('#remote-access-password').fill(remotePassword);
    await button('Authorize this request only').click();
    await idleRemote();
    check(count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/) === submissions, 'Stale offer submitted password');
    await remoteRevoked(requestId);
  });
  await test('wrong-remote-password-denied-and-revoked', async () => {
    const requestId = await requestPassword();
    const submissions = count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/);
    await page.locator('#remote-access-password').fill('intentionally-wrong-owned-password');
    await button('Authorize this request only').click();
    await idleRemote();
    check(count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/) === submissions + 1, 'Unexpected password replay count');
    check(latest('POST', /^\/api\/v3\/remote\/[^/]+\/password$/)?.status === 401, 'Wrong password was not denied');
    await remoteRevoked(requestId);
  });
  await test('committed-password-authorization-with-lost-response-is-not-replayed', async () => {
    const requestId = await requestPassword();
    const submissions = count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/);
    const drop = { method: 'POST', path: new RegExp('^/api/v3/remote/' + requestId + '/password$'), completed: false };
    dropResponse = drop;
    await page.locator('#remote-access-password').fill(remotePassword);
    await button('Authorize this request only').click();
    await waitFor(() => drop.completed, 'Committed upstream response was not dropped');
    await idleRemote();
    check(latest('POST', /^\/api\/v3\/remote\/[^/]+\/password$/)?.status === 200, 'Backend did not approve real password authorization');
    check(count('POST', /^\/api\/v3\/remote\/[^/]+\/password$/) === submissions + 1, 'Unknown password outcome replayed');
    await remoteRevoked(requestId);
    await button('Close').click();
  });
  let seed;
  let recoveryCodes;
  await test('wrong-reauthentication-keeps-valid-workspace', async () => {
    await button('Account and security').click();
    await waitFor(async () => (await page.locator('.content').innerText()).includes('TOTP not enabled'), 'TOTP status missing');
    const meCount = count('GET', /^\/api\/v3\/auth\/me$/);
    await page.locator('#security-password').fill('intentionally-wrong-owned-password');
    await button('Set up TOTP').click();
    await waitFor(() => latest('POST', /^\/api\/v3\/auth\/totp$/)?.status === 401, 'Wrong reauthentication not denied');
    await waitFor(() => count('GET', /^\/api\/v3\/auth\/me$/) > meCount, 'Valid login was not rechecked');
    await workspace();
    check(await page.locator('#security-password').isVisible(), 'Wrong factor discarded security panel');
  });
  await test('real-totp-and-one-time-recovery-workflow', async () => {
    await page.locator('#security-password').fill(initialPassword);
    await button('Set up TOTP').click();
    await waitFor(async () => (await page.locator('[aria-label="One-time security information"] code').count()) === 1, 'TOTP seed missing');
    seed = await page.locator('[aria-label="One-time security information"] code').innerText();
    check(/^[A-Z2-7]{32}$/.test(seed), 'TOTP seed format');
    await page.locator('#security-totp-code').fill(totp(seed));
    await button('Confirm TOTP').click();
    await waitFor(async () => (await page.locator('[aria-label="One-time security information"] li code').count()) === 10, 'Recovery codes missing');
    recoveryCodes = await page.locator('[aria-label="One-time security information"] li code').allTextContents();
    check(new Set(recoveryCodes).size === 10, 'Recovery codes not distinct');
    await page.locator('.sidebar nav').getByRole('button', { name: 'Devices', exact: true }).click();
    await button('Account and security').click();
    check(await page.locator('[aria-label="One-time security information"] code').count() === 0, 'One-time secrets reappeared after navigation');
    await page.locator('#security-password').fill(initialPassword);
    await page.locator('#security-factor').fill(recoveryCodes[0]);
    await button('Replace recovery codes').click();
    await waitFor(async () => (await page.locator('[aria-label="One-time security information"] li code').count()) === 10, 'Replacement recovery codes missing');
    const replacement = await page.locator('[aria-label="One-time security information"] li code').allTextContents();
    check(replacement.every(code => !recoveryCodes.includes(code)), 'Recovery replacement reused old codes');
    recoveryCodes = replacement;
    await button('Saved; clear display').click();
    check(await page.locator('[aria-label="One-time security information"] code').count() === 0, 'Dismissed secrets still visible');
  });
  await test('password-change-local-confirmation-revocation-and-new-login', async () => {
    await page.locator('#security-password').fill(initialPassword);
    await page.locator('#security-factor').fill(recoveryCodes[0]);
    await page.locator('#security-new-password').fill(changedPassword);
    await page.locator('#security-confirm-password').fill('different-confirmation');
    check(!(await button('Change password and sign out').isEnabled()), 'Mismatched confirmation accepted');
    await page.locator('#security-confirm-password').fill(changedPassword);
    await button('Change password and sign out').click();
    await page.locator('#username').waitFor({ state: 'visible' });
    check(!(await page.locator('.workspace').isVisible()), 'Password change left workspace active');
    const revoked = await api('GET', '/auth/me');
    check(revoked.status === 401, 'Old API session survived password change');
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(initialPassword);
    await page.locator('#factor').fill(recoveryCodes[1]);
    const loginCount = count('POST', /^\/api\/v3\/auth\/login$/);
    await button('Sign in').click();
    await waitFor(() => count('POST', /^\/api\/v3\/auth\/login$/) === loginCount + 1, 'Old password login not attempted');
    check(latest('POST', /^\/api\/v3\/auth\/login$/)?.status === 401, 'Old password still authenticates');
    await page.locator('#password').fill(changedPassword);
    await page.locator('#factor').fill(recoveryCodes[2]);
    await button('Sign in').click();
    await workspace();
    await button('Account and security').click();
    await button('Refresh login').click();
    await waitFor(() => latest('POST', /^\/api\/v3\/auth\/refresh$/)?.status === 200, 'Refresh login failed');
    await workspace();
  });
  seed = undefined;
  recoveryCodes = undefined;
  check(!report.page_error_count, 'Production page raised runtime errors');
  report.status = 'passed';
}

(async () => {
  try {
    await Promise.race([
      main(),
      new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Probe duration exceeded')), maximumMs); }),
    ]);
  } catch (error) {
    report.status = 'failed';
    report.failure = { case: phase, error_class: error?.name || 'Error', safe_check: error?.safeCode || null };
    process.exitCode = 1;
  } finally {
    stopped = true;
    clearTimeout(deadline);
    accessToken = undefined;
    dropResponse = null;
    try { if (context) await context.close(); report.cleanup.browser_closed = true; }
    catch { report.cleanup.browser_closed = false; }
    try {
      if (control && control.exitCode === null) {
        control.kill();
        await Promise.race([new Promise(resolve => control.once('exit', resolve)), sleep(10_000)]);
      }
      report.cleanup.control_stopped = !control || control.exitCode !== null || control.signalCode !== null;
    } catch { report.cleanup.control_stopped = false; }
    try {
      for (const socket of proxySockets) socket.destroy();
      if (proxy?.listening) await new Promise(resolve => proxy.close(resolve));
      report.cleanup.https_proxy_closed = true;
    } catch { report.cleanup.https_proxy_closed = false; }
    try {
      report.production_inputs_after = siteInputs(productionRoot);
      report.production_inputs_unchanged = JSON.stringify(report.production_inputs_before) === JSON.stringify(report.production_inputs_after);
      report.server_input_unchanged = sha256(fs.readFileSync(serverSource)) === report.server_input?.sha256;
    } catch { report.production_inputs_unchanged = false; report.server_input_unchanged = false; }
    try {
      check(scratchReal.startsWith(fs.realpathSync(os.tmpdir()) + path.sep) && path.basename(scratchReal).startsWith('nestlink-security-owned-') && fs.realpathSync(scratch) === scratchReal, 'Scratch cleanup target mismatch');
      fs.rmSync(scratchReal, { recursive: true, force: false, maxRetries: 5, retryDelay: 200 });
      report.cleanup.owned_scratch_removed = !fs.existsSync(scratchReal);
    } catch { report.cleanup.owned_scratch_removed = false; }
    if (Object.values(report.cleanup).some(value => value !== true) || !report.production_inputs_unchanged || !report.server_input_unchanged) {
      report.status = 'failed'; process.exitCode = 1;
    }
    report.completed_at_utc = new Date().toISOString();
    report.failure_details_excluded = 'Exception text, API bodies, console text, screenshots and secret values are never retained';
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    process.stdout.write('Focused UI result: ' + report.status + '; retained report: ' + reportPath + '\n');
  }
})();
