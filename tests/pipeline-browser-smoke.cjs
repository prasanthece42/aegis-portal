// Isolated demo with synthetic pipeline responses; no live credentials or deployments.
const { chromium, expect } = require(process.env.PLAYWRIGHT_MODULE || '@playwright/test');
const fs = require('node:fs');
(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.goto(process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8019');
    await page.route('**/api/v1/applications', route => route.fulfill({json: {items: [{
      app_id: 'fixture-app', display_name: 'Fixture app', source: {owner: 'demo', name: 'fixture'},
      environments: {dev: {}}, access: {deployer_user_ids_by_environment: {dev: ['1']}}
    }]}}));
    let unavailable = false;
    const names = ['Validate source', 'Code quality', 'Application tests', 'Source security',
      'Dependency security', 'Build image', 'Container security', 'Publish and verify release',
      'DEV deployment verification'];
    await page.route('**/api/v1/applications/fixture-app/pipeline', route => route.fulfill(
      unavailable ? {status: 503, json: {error: {message: 'Pipeline evidence is unavailable.'}}}
      : {json: {source_commit: 'a'.repeat(40), run_id: '42', run_attempt: 2, stages:
        names.map((name, i) => ({number: i + 1, name, state: i === 3 ? 'failed' : i > 3 ? 'skipped' : 'passed',
          message: i === 3 ? '<img src=x onerror="window.pipelineXss=true">' : ''}))}}));
    await page.getByRole('button', {name: /Enter local demo/}).click();
    await page.getByRole('button', {name: 'DEV pipeline →', exact: true}).click();
    await expect(page.locator('#pipeline')).toBeVisible();
    await expect(page.locator('#pipeline-stages > li')).toHaveCount(9);
    await expect(page.locator('#pipeline-stages')).toContainText('Failed');
    await expect(page.locator('#pipeline-stages')).toContainText('Skipped');
    if (await page.evaluate(() => Boolean(window.pipelineXss))) throw new Error('Unescaped pipeline text');
    await page.setViewportSize({width: 375, height: 812});
    if (!(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))) throw new Error('Mobile overflow');
    fs.mkdirSync('.local/pipeline-qa', {recursive: true});
    await page.screenshot({path: '.local/pipeline-qa/pipeline-mobile.png', fullPage: true});
    unavailable = true;
    await page.locator('#refresh-pipeline').click();
    await expect(page.locator('#pipeline-summary')).toContainText('unavailable');
    await expect(page.locator('#pipeline-stages > li')).toHaveCount(0);
    await page.getByRole('button', {name: 'Sign out', exact: true}).click();
    await expect(page.locator('#sign-in')).toBeVisible();
    await expect(page.locator('#pipeline-stages > li')).toHaveCount(0);
    if (errors.length) throw new Error(JSON.stringify(errors));
    console.log(JSON.stringify({nineStages: 'passed', failureAndSkipped: 'passed', escaping: 'passed',
      mobile: 'passed', unavailableClearsData: 'passed', logoutClearsData: 'passed', mode: 'synthetic-demo'}));
  } finally { await browser.close(); }
})().catch(e => { console.error(e.message); process.exitCode = 1; });
