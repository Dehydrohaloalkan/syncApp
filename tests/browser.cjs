// Run after `dotnet build SyncApp/SyncApp.csproj` with:
// SYNCAPP_PLAYWRIGHT=/path/to/playwright SYNCAPP_CHROMIUM_PATH=/path/to/chrome-headless-shell node tests/browser.cjs
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require(process.env.SYNCAPP_PLAYWRIGHT || 'playwright');

const root = path.resolve(__dirname, '..');
const app = path.join(root, 'SyncApp/bin/Debug/net10.0/SyncApp.dll');
const browserPath = process.env.SYNCAPP_CHROMIUM_PATH;
if (!fs.existsSync(app)) throw new Error('Build SyncApp first');
if (!browserPath || !fs.existsSync(browserPath)) throw new Error('Set SYNCAPP_CHROMIUM_PATH');

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

async function waitForHost(port) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/api/session`, response => {
          response.resume();
          response.on('end', resolve);
        }).on('error', reject);
      });
      return;
    } catch {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  throw new Error('SyncApp host did not start');
}

(async () => {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'syncapp-browser-test-'));
  const server = spawn('dotnet', [app], {
    cwd: root,
    env: { ...process.env, SYNCAPP_DATA_DIR: dataDir, SYNCAPP_PORT: String(port) },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let serverErrors = '';
  server.stderr.on('data', chunk => { serverErrors += chunk.toString(); });
  let browser;
  try {
    await waitForHost(port);
    const base = `http://127.0.0.1:${port}`;
    browser = await chromium.launch({ executablePath: browserPath, headless: true, args: ['--no-sandbox'] });
    const context = await browser.newContext();
    const page = await context.newPage();
    const pageErrors = [];
    const externalRequests = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.route('**/*', route => {
      if (!route.request().url().startsWith(base)) {
        externalRequests.push(route.request().url());
        return route.abort();
      }
      return route.continue();
    });

    await page.goto(base);
    await page.getByRole('button', { name: 'Новый проект' }).click();
    assert.equal(await page.locator('#personal-form').count(), 1);
    assert.equal(await page.locator('#work-form').count(), 1);
    const projectFormText = await page.locator('main').innerText();
    assert.doesNotMatch(projectFormText, /QR|Decimen|камера|camera/i);
    assert.equal(await page.locator('input[type="file"]').count(), 0);
    assert.equal(await page.locator('a[href*="vendor/"]').count(), 0);
    for (const legacy of ['/vendor/decimen-v0.3.0/sender.html', '/vendor/decimen-v0.3.0/receiver.html']) {
      const response = await page.request.get(base + legacy);
      assert.equal(response.status(), 404, `legacy QR resource still served: ${legacy}`);
    }
    console.log('PASS project forms use only the junk transport and QR resources are unavailable');

    assert.deepEqual(externalRequests, []);
    assert.deepEqual(pageErrors, []);
    console.log('PASS application makes no external requests or browser errors');

    const injectionPage = await context.newPage();
    const projects = [
      { id: 'work1', side: 'Work', folder: '<img src=x onerror=window.__injected=1>',
        repoPath: '<svg onload=window.__injected=1>', branch: 'main', baselineCommit: 'abc',
        baselineVerified: true, workSigningKey: null, personalSigningKey: 'public-key', workRecipient: 'age1work',
        personalRecipient: 'age1personal', applied: [], session: null,
        lastPersonalChangeId: null, lastWorkChangeId: null },
      { id: 'personal1', side: 'Personal', folder: 'Personal demo', repoPath: '/source/repo', branch: 'main',
        baselineCommit: 'def', baselineVerified: true, workRecipient: 'age1work', personalRecipient: 'age1personal',
        personalSigningKey: 'public-key', applied: [], session: null, lastPersonalChangeId: null, lastWorkChangeId: null }
    ];
    await injectionPage.route('**/api/session', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ csrf: 'test', projects })
    }));
    await injectionPage.route('**/api/projects/work1/inbox', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify([{ message: '<img src=x onerror=window.__injected=1>', sourceCommit: 'abc', changeId: 'def', previousChangeId: null }])
    }));
    let workSyncBody;
    let personalSyncBody;
    await injectionPage.route('**/api/projects/work1/sync', async route => {
      workSyncBody = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ pulledPackages: 1, preparedChanges: 0, committedFiles: 0, pushed: false }) });
    });
    await injectionPage.route('**/api/projects/personal1/sync', async route => {
      personalSyncBody = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ pulledPackages: 0, preparedChanges: 1, committedFiles: 1, pushed: true }) });
    });
    await injectionPage.route('**/api/projects/personal1/attach-work-key', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ id: 'personal1' })
    }));
    await injectionPage.goto(base);
    await injectionPage.locator('#projects button').first().click();
    await injectionPage.locator('#project-password').fill('test passphrase');
    await injectionPage.locator('#load-inbox').click();
    await injectionPage.locator('#inbox').getByText('<img src=x onerror=window.__injected=1>', { exact: true }).waitFor();
    assert.equal(await injectionPage.locator('#sync-push').count(), 0, 'Work UI exposed a push control');
    await injectionPage.locator('#sync').click();
    await injectionPage.getByText(/Загружено зашифрованных пакетов: 1/).waitFor();
    assert.equal(workSyncBody.push, false, 'Work UI requested push');
    await injectionPage.locator('#projects button').nth(1).click();
    assert.equal(await injectionPage.locator('#sync-push').count(), 1, 'Personal UI omitted explicit push control');
    await injectionPage.locator('#project-password').fill('test passphrase');
    await injectionPage.locator('#sync-push').check();
    await injectionPage.locator('#sync').click();
    await injectionPage.getByText(/отправлено: да/).waitFor();
    assert.equal(personalSyncBody.push, true, 'Personal push checkbox was not sent');
    assert.equal(await injectionPage.locator('#attach-work-key').count(), 1, 'Personal UI omitted manual age-key attachment');
    assert.equal(await injectionPage.evaluate(() => window.__injected), undefined);
    assert.equal(await injectionPage.locator('main img, #projects img').count(), 0);
    assert.equal(await injectionPage.locator('input[type="file"]').count(), 0);
    console.log('PASS Work UI is pull-only, Personal push is explicit, and untrusted metadata stays inert');
  } finally {
    if (browser) await browser.close();
    server.kill('SIGTERM');
    fs.rmSync(dataDir, { recursive: true, force: true });
    if (serverErrors && server.exitCode && server.exitCode !== 0) process.stderr.write(serverErrors);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
