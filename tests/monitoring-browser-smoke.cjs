// Synthetic telemetry against an isolated demo; never live OAuth or deployment writes.
const { chromium, expect } = require(process.env.PLAYWRIGHT_MODULE || '@playwright/test');
const fs = require('node:fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8018');
    await expect(page.locator('#mode-banner')).toContainText('LOCAL DEMO');
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    const session = await page.evaluate(async () => (await fetch('/api/v1/session')).json());
    await page.route('**/api/v1/applications', route => route.fulfill({ json: { items: [{
      app_id: 'hello-aegis', display_name: 'Hello Aegis', environments: { dev: {}, prod: {} },
      access: { owner_user_ids: [], viewer_user_ids: [], deployer_user_ids_by_environment: { dev: [session.user_id], prod: ['another-user'] } }
    }] } }));
    const now = Math.floor(Date.now() / 1000), traceId = 'a'.repeat(32);
    const injection = '<img src=x onerror="window.telemetryXss=true">';
    let mode = 'fresh', delayed, release;
    const pending = new Promise(resolve => { release = resolve; });
    await page.route('**/observability/**', async route => {
      const url = new URL(route.request().url());
      const signal = url.pathname.split('/').at(-1);
      const common = { observed_at: new Date().toISOString() };
      if (mode === 'unavailable') return route.fulfill({ status: 503, json: { error: { message: 'Telemetry unavailable; retry safely.' } } });
      if (signal === traceId) return route.fulfill({ json: { ...common, trace_id: traceId, spans: [{ name: injection, service: 'hello-aegis', start_ns: now * 1e9, duration_ns: 1e7, error: false }] } });
      if (signal === 'metrics') {
        const selected = mode;
        if (mode === 'delayed') { delayed = true; await pending; }
        return route.fulfill({ json: { ...common, application_signal: selected, series: [
          { key: 'requests', label: selected === 'delayed' ? 'OLD RESPONSE' : 'Requests / second', points: mode === 'empty' ? [] : [[now - 30, 1], [now, 2]] }
        ] } });
      }
      if (signal === 'logs') return route.fulfill({ json: { ...common, logs: mode === 'empty' ? [] : [{ timestamp_ns: String(now * 1e9), line: injection, trace_id: traceId }] } });
      if (signal === 'alerts') return route.fulfill({ json: { ...common, alerts: mode === 'empty' ? [] : [{ name: 'HelloAegisErrors', summary: injection, state: 'firing', severity: 'warning', namespace: 'aegis-hello-aegis-dev' }] } });
      return route.fulfill({ json: { ...common, traces: mode === 'empty' ? [] : [{ trace_id: traceId, name: injection, service: 'hello-aegis', duration_ns: 1e7, span_count: 1 }] } });
    });
    await page.locator('#nav-monitoring').click();
    await expect(page.locator('#monitoring-state')).toContainText('within 90 seconds');
    await expect(page.locator('.metric-card svg path')).toHaveCount(1);
    await expect(page.locator('#monitoring-target option[value="app:hello-aegis:prod"]')).toHaveCount(0);
    await page.getByRole('tab', { name: 'Logs', exact: true }).click();
    await expect(page.locator('.log-line')).toHaveText(injection);
    await page.getByRole('button', { name: 'View trace →', exact: true }).click();
    await expect(page.locator('#trace-detail')).toBeVisible();
    await expect(page.locator('#trace-spans svg rect')).toHaveCount(1);
    await page.getByRole('tab', { name: 'Alerts', exact: true }).click();
    await expect(page.locator('#trace-detail')).toBeHidden();
    await expect(page.locator('#monitoring-content')).toContainText('firing');
    await page.getByRole('tab', { name: 'Traces', exact: true }).click();
    await expect(page.locator('#monitoring-content')).toContainText(traceId);
    mode = 'empty';
    await page.locator('#refresh-monitoring').click();
    await expect(page.locator('#monitoring-state')).toContainText('No traces observed');
    mode = 'stale';
    await page.getByRole('tab', { name: 'Metrics', exact: true }).click();
    await expect(page.locator('#monitoring-state')).toContainText('heartbeat is stale');
    mode = 'delayed';
    await page.locator('#monitoring-window').selectOption('1h');
    await expect.poll(() => delayed).toBe(true);
    mode = 'fresh';
    await page.locator('#monitoring-target').selectOption('platform:cluster');
    await expect(page.locator('#monitoring-title')).toHaveText('Cluster overview');
    await expect(page.locator('.metric-card')).toContainText('Requests / second');
    release();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('#monitoring-content')).not.toContainText('OLD RESPONSE');
    await page.getByRole('tab', { name: 'Logs', exact: true }).click();
    await expect(page.locator('#monitoring-state')).toContainText('Select an application');
    mode = 'unavailable';
    await page.locator('#monitoring-target').selectOption('app:hello-aegis:dev');
    await expect(page.locator('#monitoring-state')).toContainText('Telemetry unavailable');
    await expect(page.locator('#monitoring-observed')).toBeEmpty();
    await expect(page.locator('#monitoring-content')).toBeEmpty();
    mode = 'fresh';
    await page.locator('#refresh-monitoring').click();
    await expect(page.locator('.metric-card')).toBeVisible();
    await page.setViewportSize({ width: 375, height: 812 });
    if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Mobile overflow');
    if (await page.evaluate(() => Boolean(window.telemetryXss))) throw new Error('Telemetry executed as HTML');
    fs.mkdirSync('.local/monitoring-qa', { recursive: true });
    await page.screenshot({ path: '.local/monitoring-qa/mobile.png', fullPage: true });
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.locator('#monitoring-content')).toBeEmpty();
    await expect(page.locator('#nav-monitoring')).toBeHidden();
    if (errors.length) throw new Error(JSON.stringify(errors));
    const result = { mode: 'isolated-demo-synthetic-hello-aegis', signals: 'passed', logTraceCorrelation: 'passed', staleResponses: 'discarded', unavailable: 'visible', devOnlyTarget: 'passed', escapedTelemetry: 'passed', mobile: 'passed', logoutClearsTelemetry: 'passed', javascriptErrors: errors };
    fs.writeFileSync('.local/monitoring-qa/result.json', JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
