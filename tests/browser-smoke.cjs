// Optional local browser check. PLAYWRIGHT_MODULE may point to an existing installation.
const { chromium, expect } = require(process.env.PLAYWRIGHT_MODULE || '@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8010';
const output = path.resolve(process.env.AEGIS_QA_OUTPUT || '.local/qa');

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base, { waitUntil: 'networkidle' });
    await expect(page.locator('#mode-banner')).toContainText('LOCAL DEMO');
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await expect(page.locator('#applications')).toBeVisible();
    await page.getByRole('button', { name: 'Register application', exact: true }).click();
    await page.locator('#repository').selectOption('101');
    await page.locator('#display-name').fill('Orders API');
    await page.screenshot({ path: path.join(output, 'registration-desktop.png'), fullPage: true });
    await page.locator('#health-path').fill('/../admin');
    await page.getByRole('button', { name: /Validate & review/ }).click();
    await expect(page.locator('#error')).toBeVisible();
    await expect(page.locator('#error')).toContainText('health_path');
    await page.locator('#health-path').fill('/health');
    await page.getByRole('button', { name: /Validate & review/ }).click();
    await expect(page.locator('#review')).toBeVisible();
    await expect(page.locator('#review-details')).toContainText('orders-api');
    await page.screenshot({ path: path.join(output, 'registration-review.png'), fullPage: true });

    // Persist the server-side result, then lose the HTTP response: reload must recover.
    await page.route('**/api/v1/registrations', async route => {
      if (route.request().method() !== 'POST') return route.continue();
      const response = await route.fetch();
      if (response.status() !== 201) throw new Error('Expected durable registration before simulated interruption');
      await route.abort('failed');
    });
    await page.getByRole('button', { name: /Submit registration for review/ }).click();
    await expect(page.locator('#error')).toBeVisible();
    await page.unroute('**/api/v1/registrations');
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.locator('#pending-recovery')).toBeVisible();
    await page.getByRole('button', { name: 'Recover registration', exact: true }).click();
    await expect(page.locator('#progress')).toBeVisible();
    await expect(page.locator('#progress-title')).toHaveText('Orders API');
    await expect(page.locator('#requirements')).toContainText('Awaiting review');
    await expect(page.locator('#status-observed')).toContainText('Status observed:');
    await expect(page.locator('#status-observed')).not.toContainText('Invalid Date');
    await expect(page.locator('#pr-link')).toContainText('No GitHub PR was created');
    await expect(page.getByRole('button', { name: 'Request deployment', exact: true })).toBeDisabled();
    await page.screenshot({ path: path.join(output, 'registration-progress.png'), fullPage: true });
    await page.setViewportSize({ width: 375, height: 812 });
    const fits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    if (!fits) throw new Error('Mobile progress layout overflows');
    await page.screenshot({ path: path.join(output, 'registration-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Back to applications', exact: true }).click();
    await expect(page.locator('#registration-count')).toHaveText('1');
    await page.getByRole('button', { name: 'Register application', exact: true }).click();
    await expect(page.locator('#registration-form')).toBeVisible();
    if (!(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))) throw new Error('Mobile form layout overflows');
    await page.screenshot({ path: path.join(output, 'registration-form-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.locator('#sign-in')).toBeVisible();
    if (errors.length) throw new Error(JSON.stringify(errors));
    const result = { demoRegistration: 'passed', invalidHealthPath: 'rejected', lostResponseRecovery: 'passed',
      duplicateLogicalRegistrations: 1, deploymentDisabled: true, mobileFits: fits, javascriptErrors: errors };
    fs.writeFileSync(path.join(output, 'browser-result.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
