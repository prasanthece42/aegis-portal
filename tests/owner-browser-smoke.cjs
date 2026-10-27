// Optional browser QA against an isolated DEMO server only; never live credentials.
const { chromium, expect } = require(process.env.PLAYWRIGHT_MODULE || '@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8016';
const output = path.resolve(process.env.AEGIS_QA_OUTPUT || '.local/owner-qa');

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base, { waitUntil: 'networkidle' });
    await expect(page.locator('#mode-banner')).toContainText('LOCAL DEMO');
    await expect(page.locator('#nav-platform')).toBeHidden();
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await expect(page.locator('#nav-platform')).toBeVisible();
    await page.locator('#nav-platform').click();
    await expect(page.locator('#platform')).toBeVisible();
    await expect(page.locator('#owner-access')).toContainText('Explicit platform grant');
    await expect(page.locator('#platform-observed')).toContainText('DEMO');
    const data = await page.evaluate(async () => (await fetch('/api/v1/platform/overview')).json());
    // Illustrative rows exercise layout and escaping; no deployment success is invented.
    data.applications = [{ app_id: 'orders-api', display_name: 'Orders API', source: 'demo/orders-api', source_url: null, owner_user_ids: ['1'], environments: [{ environment: 'dev', namespace: 'aegis-orders-api-dev', argo_application: 'orders-api-dev', cluster_id: 'example-kind', state: 'unverified', health_observed_at: null, image_digest: 'sha256:' + 'a'.repeat(64) }] }];
    data.reviews = [{ repository: 'Platform', number: 1, title: 'Review Orders API enrollment', branch: 'main', draft: false, ci_state: 'running', url: null }];
    data.review_total = 1;
    await page.route('**/api/v1/platform/overview', route => route.fulfill({ json: data }));
    await page.locator('#refresh-platform').click();
    await expect(page.locator('#owner-summary')).toContainText('Managed applications');
    await page.screenshot({ path: path.join(output, 'owner-overview-desktop.png'), fullPage: true });
    for (const [tab, panel] of [['Reviews', 'reviews'], ['Applications', 'applications'], ['Clusters & policy', 'policy'], ['Activity', 'activity']]) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      await expect(page.locator('#owner-' + panel)).toBeVisible();
    }
    await page.getByRole('tab', { name: 'Applications', exact: true }).click();
    await expect(page.locator('#owner-application-list')).toContainText('Health not verified');
    await page.screenshot({ path: path.join(output, 'owner-applications-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 375, height: 812 });
    for (const tab of ['Overview', 'Reviews', 'Applications', 'Clusters & policy', 'Activity']) {
      await page.getByRole('tab', { name: tab, exact: true }).click();
      if (!(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))) throw new Error('Mobile owner layout overflows: ' + tab);
    }
    await page.getByRole('tab', { name: 'Overview', exact: true }).click();
    await page.screenshot({ path: path.join(output, 'owner-overview-mobile.png'), fullPage: true });
    data.reviews[0].title = '<img src=x onerror="window.__ownerXss=true">';
    await page.locator('#refresh-platform').click();
    await page.getByRole('tab', { name: 'Reviews', exact: true }).click();
    await expect(page.locator('#owner-review-list')).toContainText('<img');
    if (await page.evaluate(() => Boolean(window.__ownerXss))) throw new Error('Review title executed as HTML');
    await page.unroute('**/api/v1/platform/overview');
    await page.reload({ waitUntil: 'networkidle' });
    await expect(page.locator('#platform')).toBeVisible();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.locator('#nav-platform')).toBeHidden();
    await expect(page.locator('#sign-in')).toBeVisible();
    if (errors.length) throw new Error(JSON.stringify(errors));
    const result = { ownerNavigation: 'passed', allFiveViews: 'passed', mobileLayouts: 'passed', deepLink: 'passed', escapedReviewTitle: 'passed', hiddenAfterLogout: 'passed', javascriptErrors: errors, mode: 'isolated-demo-with-illustrative-layout-rows' };
    fs.writeFileSync(path.join(output, 'owner-browser-result.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
