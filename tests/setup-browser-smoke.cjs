// Isolated, labelled demo UI check. Synthetic setup responses; no live credentials or mutations.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8029';
const out = path.resolve(process.env.AEGIS_QA_OUTPUT || '.local/setup-qa');
const app = { app_id: 'orders-api', display_name: 'Orders API', source: { owner: 'demo', name: 'orders-api' }, access: { owner_user_ids: ['1'], deployer_user_ids_by_environment: { dev: ['1'] } }, environments: { dev: {} } };
const rid = 'setup-' + 'a'.repeat(64);
const workflowFiles = [{ path: '.github/workflows/ci.yml', content: 'name: Aegis CI\n# <img src=x onerror="window.setupXss=true">', status: 'add' }, { path: '.github/workflows/release.yml', content: 'name: Aegis release\n', status: 'add' }];
const targetFiles = [{ path: 'clusters/kind-local/bootstrap/orders-api/dev/namespace.json', content: '{"kind":"Namespace","metadata":{"name":"aegis-orders-api-dev"}}', status: 'add' }];
(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  let page;
  const errors = [];
  let phase = 'not_started', confirmations = 0, approvals = 0, allowReady = false;
  const view = () => ({ app_id: 'orders-api', setup_id: phase === 'not_started' ? null : rid, state: allowReady ? 'ready' : phase,
    pipeline_ready: ['building', 'ready'].includes(phase), target_ready: ['building', 'ready'].includes(phase), release_ready: allowReady,
    worker_online: true, workflow_files: workflowFiles, target_files: targetFiles, approval_token: 'synthetic-review', can_approve_pipeline: true, can_approve_target: true,
    pull_requests: phase === 'not_started' ? {} : Object.fromEntries(['pipeline', 'target'].map((kind, i) => [kind, { number: i + 1, url: `https://github.com/demo/setup/pull/${i + 1}`, state: phase === 'building' ? 'closed' : 'open', merged: phase === 'building', approved: phase === 'building' }])) });
  try {
    page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
    page.on('pageerror', e => errors.push(e.message));
    await page.route('**/api/v1/applications', route => route.fulfill({ json: { items: [app] } }));
    await page.route('**/api/v1/applications/orders-api/dev-setup**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('dev-setup-validations')) return route.fulfill({ json: { app_id: 'orders-api', review_token: 'synthetic-preview', worker_online: true, blockers: [], workflow_files: workflowFiles, target_files: targetFiles } });
      if (url.pathname.endsWith('/approvals')) { approvals++; phase = 'building'; return route.fulfill({ json: view() }); }
      if (url.pathname.endsWith('/dev-setups') && route.request().method() === 'POST') { confirmations++; phase = 'awaiting_review'; return route.abort('failed'); }
      return route.fulfill({ json: view() });
    });
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.evaluate(() => setupView('orders-api'));
    await page.locator('#dev-setup').waitFor({ state: 'visible' });
    await page.locator('#setup-plan').click();
    await page.locator('#setup-confirm').waitFor({ state: 'visible' });
    await page.locator('#setup-files summary').first().click();
    assert.equal(await page.locator('#setup-files img').count(), 0);
    await page.screenshot({ path: path.join(out, 'setup-review-desktop.png'), fullPage: true });
    await page.locator('#setup-confirm').click();
    await page.locator('#error').waitFor({ state: 'visible' });
    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.evaluate(() => setupView('orders-api'));
    await page.locator('#setup-approve').waitFor({ state: 'visible' });
    assert.equal(confirmations, 1);
    await page.locator('#setup-approve').click();
    await page.waitForFunction(() => document.getElementById('setup-state').textContent.includes('CI is building'));
    assert.equal(approvals, 1);
    assert.equal(await page.locator('#setup-deploy').isVisible(), false);
    allowReady = true;
    await page.locator('#setup-refresh').click();
    await page.locator('#setup-deploy').waitFor({ state: 'visible' });
    assert.match(await page.locator('#dev-setup').textContent(), /Deployment still needs your release selection and confirmation/);
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.screenshot({ path: path.join(out, 'setup-ready-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []);
    const result = { guidedSetup: 'passed', interruptedConfirmationRecovery: 'passed', logicalRequests: confirmations, realUserApprovalUI: 'passed', readyRequiresRelease: true, automaticDeployment: false, mobileFits: true, javascriptErrors: errors };
    fs.writeFileSync(path.join(out, 'browser-result.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } catch (e) {
    if (page) await page.screenshot({ path: path.join(out, 'failure.png'), fullPage: true });
    throw e;
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
