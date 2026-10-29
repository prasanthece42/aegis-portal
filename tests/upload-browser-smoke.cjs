// Local-only portal walkthrough. No GitHub credentials or deployment operations.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8028';
const sample = process.env.AEGIS_UPLOAD_SAMPLE || path.resolve('../../hello-portal.zip');
const output = path.resolve(process.env.AEGIS_QA_OUTPUT || '.local/upload-qa');
(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  let page;
  try {
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.locator('#nav-register').click();
    await page.locator('#open-upload').click();
    await page.locator('#upload').waitFor({ state: 'visible' });
    await page.locator('#upload-file').setInputFiles(sample);
    await page.locator('#inspect-upload').click();
    await page.locator('#upload-destination').waitFor({ state: 'visible' });
    assert.match(await page.locator('#upload-files').textContent(), /app\/main.py/);
    assert.match(await page.locator('#upload-detection').textContent(), /python312-web/);
    await page.locator('#upload-name').fill('hello-portal');
    await page.locator('#upload-destination button[type=submit]').click();
    await page.locator('#upload-review').waitFor({ state: 'visible' });
    await page.screenshot({ path: path.join(output, 'upload-review-desktop.png'), fullPage: true });
    // The server commits its result, then the browser loses the confirmation response.
    await page.route('**/api/v1/uploads/*/confirm', async route => {
      const response = await route.fetch();
      assert.equal(response.status(), 200);
      await route.abort('failed');
    });
    await page.locator('#create-upload').click();
    await page.locator('#error').waitFor({ state: 'visible' });
    await page.unroute('**/api/v1/uploads/*/confirm');
    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.locator('#nav-register').click();
    await page.locator('#open-upload').click();
    await page.locator('#recover-upload').click();
    await page.locator('#upload-preparation').waitFor({ state: 'visible' });
    assert.match(await page.locator('#upload-repository').textContent(), /Not registered · Not deployed/);
    const repos = await page.evaluate(async () => (await (await fetch('/api/v1/repositories')).json()).items);
    assert.equal(repos.filter(r => r.full_name === 'demo/hello-portal').length, 1);
    await page.locator('#upload-display').fill('Hello Portal');
    await page.locator('#upload-settings button[type=submit]').click();
    await page.locator('#upload-continue').waitFor({ state: 'visible' });
    assert.match(await page.locator('#upload-proposals').textContent(), /requirements-prod.txt/);
    assert.match(await page.locator('#upload-proposals').textContent(), /Portal credentials cannot install workflows/);
    await page.locator('#upload-proposals summary').first().click();
    await page.screenshot({ path: path.join(output, 'upload-preparation-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, 'Mobile upload layout overflows');
    await page.screenshot({ path: path.join(output, 'upload-preparation-mobile.png'), fullPage: true });
    await page.locator('#upload-continue').click();
    await page.locator('#registration-form').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#app-id').inputValue(), 'hello-portal');
    assert.equal(await page.locator('#display-name').inputValue(), 'Hello Portal');
    assert.equal(await page.locator('#port').inputValue(), '8000');
    assert.equal(await page.locator('#health-path').inputValue(), '/health');
    await page.locator('#validate-button').click();
    await page.locator('#review').waitFor({ state: 'visible' });
    await page.locator('#submit-registration').click();
    await page.locator('#progress').waitFor({ state: 'visible' });
    assert.match(await page.locator('#requirements').textContent(), /Awaiting review/);
    assert.equal(await page.getByRole('button', { name: 'Request deployment', exact: true }).isDisabled(), true);
    await page.screenshot({ path: path.join(output, 'upload-registration-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []);
    const result = { zipInspection: 'passed', confirmationRecovery: 'passed', logicalRepositoriesCreated: 1, pipelineReview: 'passed', registrationSettingsCarriedForward: 'passed', demoCatalogProposal: 'passed', automaticDeployment: false, mobileFits: true, javascriptErrors: errors };
    fs.writeFileSync(path.join(output, 'browser-result.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } catch (error) {
    if (page) {
      await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
      console.error({ pageErrors: errors, portalError: await page.locator('#error').textContent(), uploadState: await page.locator('#upload-state').textContent() });
    }
    throw error;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
