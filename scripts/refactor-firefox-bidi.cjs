// Run the shared development probes in stock Firefox through WebDriver BiDi.
// This small adapter translates only probe operations; all DOM, clipboard,
// Web Locks, OPFS and RTC behavior still executes in the real browser.
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const version = '25.14.0';
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

class ProbePage {
  constructor(page) { this.page = page; }
  on(event, callback) { this.page.on(event, callback); }
  evaluate(fn, arg) { return this.page.evaluate(fn, arg); }
  addInitScript({ content }) { return this.page.evaluateOnNewDocument(content); }
  goto(url, options = {}) { return this.page.goto(url, options); }
  reload(options = {}) { return this.page.reload(options); }
  title() { return this.page.title(); }
  close() { return this.page.close(); }
  async waitForFunction(fn, arg, options = {}) {
    const handle = await this.page.waitForFunction(fn, options, arg);
    await handle.dispose();
  }
  async waitForSelector(selector, options = {}) {
    const handle = await this.page.waitForSelector(selector, {
      timeout: options.timeout,
      visible: options.state === 'visible',
      hidden: options.state === 'hidden',
    });
    if (handle) await handle.dispose();
  }
  locator(selector) {
    const page = this.page;
    return {
      count: () => page.$$eval(selector, nodes => nodes.length),
      getAttribute: name => page.$eval(selector, (node, attribute) => node.getAttribute(attribute), name),
      click: async () => {
        await page.bringToFront();
        // Puppeteer's element click uses trusted BiDi input actions. Never
        // replace this with HTMLElement.click(), which has no user activation.
        await page.click(selector);
      },
    };
  }
}

class ProbeContext {
  constructor(context) { this.context = context; this.timeout = 30_000; }
  setDefaultTimeout(timeout) { this.timeout = timeout; }
  async newPage() {
    const page = await this.context.newPage();
    page.setDefaultTimeout(this.timeout);
    return new ProbePage(page);
  }
  close() { return this.context.close(); }
}

async function launch({ headless, executablePath }) {
  const receiptPath = process.env.NESTLINK_FIREFOX_BIDI_TOOLS;
  if (!receiptPath) throw new Error('An explicit prepared stock Firefox tool receipt is required');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  if (receipt.completion !== 'prepared' || receipt.puppeteer_version !== version
      || path.resolve(receipt.binary) !== path.resolve(executablePath)
      || digest(executablePath) !== receipt.binary_sha256
      || digest(receipt.launcher_lock) !== receipt.launcher_lock_sha256
      || receipt.installer_authenticode.status !== 'Valid') {
    throw new Error('Stock Firefox tooling differs from its prepared receipt');
  }
  const packagePath = receipt.puppeteer_package;
  const manifest = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json'), 'utf8'));
  if (manifest.name !== 'puppeteer-core' || manifest.version !== version) {
    throw new Error('Stock Firefox requires the pinned BiDi launcher');
  }
  // The application tests below need real isolated storage contexts. Locale,
  // theme and reduced-motion emulation are not applied by this BiDi adapter.
  // No browser preference grants clipboard access or disables user activation.
  const launcher = await import(require('node:url').pathToFileURL(path.join(packagePath, 'lib/puppeteer/puppeteer-core.js')).href);
  const temporaryRoot = path.resolve(os.tmpdir());
  const profile = fs.mkdtempSync(path.join(temporaryRoot, 'nestlink-firefox-bidi-'));
  const browser = await launcher.default.launch({ browser: 'firefox', executablePath,
    headless, userDataDir: profile, protocol: 'webDriverBiDi' });
  const actualVersion = await browser.version();
  let closed = false;
  return {
    version: () => actualVersion,
    newContext: async () => new ProbeContext(await browser.createBrowserContext()),
    close: async () => {
      if (closed) return;
      await browser.close();
      const process = browser.process();
      if (process && process.exitCode === null && process.signalCode === null) {
        throw new Error('The owned stock Firefox process has not exited');
      }
      const target = path.resolve(profile);
      if (path.dirname(target) !== temporaryRoot || !path.basename(target).startsWith('nestlink-firefox-bidi-')) {
        throw new Error('Refuse cleanup outside the owned temporary profile');
      }
      fs.rmSync(target, { recursive: true });
      closed = true;
    },
  };
}

module.exports = { launch, version };
