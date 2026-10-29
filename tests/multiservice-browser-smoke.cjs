// Local synthetic portal flow only. Never registers or deploys a live application.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:18361';
const sample = process.env.AEGIS_UPLOAD_SAMPLE || path.resolve('../../commerce-demo.zip');
const output = path.resolve('.local/multiservice-qa');
(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  try {
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.locator('#nav-register').click();
    await page.locator('#open-upload').click();
    await page.locator('#upload').waitFor({ state: 'visible' });
    await page.locator('#upload-file').setInputFiles(sample);
    await page.locator('#inspect-upload').click();
    await page.locator('#upload-destination').waitFor({ state: 'visible' });
    assert.match(await page.locator('#upload-detection').textContent(), /python312-multiservice/);
    await page.locator('#upload-name').fill('commerce-demo');
    await page.locator('#upload-destination button[type=submit]').click();
    await page.locator('#upload-review').waitFor({ state: 'visible' });
    await page.locator('#create-upload').click();
    await page.locator('#upload-preparation').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#upload-runtime-profile').inputValue(), 'python312-multiservice');
    assert.equal(await page.locator('#upload-port').inputValue(), '8080');
    assert.equal(await page.locator('#upload-stack-environment fieldset').count(), 6);
    const envSelector = 'input[data-service="catalog"][data-environment="CACHE_TTL_SECONDS"]';
    await page.locator('#upload-stack-environment ' + envSelector).fill('45');
    await page.locator('#upload-settings button[type=submit]').click();
    await page.locator('#upload-continue').waitFor({ state: 'visible' });
    assert.match(await page.locator('#upload-proposals').textContent(), /python-stack-release.yml/);
    await page.screenshot({ path: path.join(output, 'configuration-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: path.join(output, 'configuration-mobile.png'), fullPage: true });
    await page.locator('#upload-continue').click();
    await page.locator('#review').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#runtime-profile').inputValue(), 'python312-multiservice');
    assert.equal(await page.locator('#stack-environment ' + envSelector).inputValue(), '45');
    assert.match(await page.locator('#review-details').textContent(), /commerce-demo-runtime/);
    assert.match(await page.locator('#review-details').textContent(), /catalog, inventory, cart, orders, payments, notifications/);
    await page.locator('#submit-registration').click();
    await page.locator('#progress').waitFor({ state: 'visible' });
    assert.equal(await page.getByRole('button', { name: 'Request deployment', exact: true }).isDisabled(), true);
    assert.deepEqual(errors, []);
    const result = { passed: true, detectedServices: 6, environmentOverridePreserved: true,
      secretReferencesReviewed: true, stackWorkflowProposed: true, syntheticRegistration: true,
      liveRegistration: false, deployment: false, mobileFits: true, javascriptErrors: errors };
    fs.writeFileSync(path.join(output, 'browser-result.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
  } catch (e) {
    await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
    console.error({ errors, portalError: await page.locator('#error').textContent() });
    throw e;
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
