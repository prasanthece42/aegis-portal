// Isolated demo walkthrough. All guided workflow responses are synthetic; no live writes.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.env.AEGIS_PREVIEW_URL || 'http://127.0.0.1:8031';
const out = path.resolve(process.env.AEGIS_QA_OUTPUT || '.local/journey-qa');
const app = { app_id: 'orders-api', display_name: 'Orders API', source: { owner: 'demo', name: 'orders-api' }, access: { owner_user_ids: ['1'], deployer_user_ids_by_environment: { dev: ['1'] } }, environments: { dev: {} } };
const regId = 'reg-' + 'b'.repeat(64), setupId = 'setup-' + 'b'.repeat(64), requestId = 'req-' + 'c'.repeat(64);
const files = [{ path: '.github/workflows/ci.yml', content: 'name: CI\n# <img src=x onerror="window.journeyXss=true">', status: 'add' }];
const targetFiles = [{ path: 'clusters/dev/namespace.json', content: '{"kind":"Namespace"}', status: 'add' }];
(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  async function waitText(text) { for (let i=0; i<40; i++) { if ((await page.locator('#onboarding-message').textContent()).includes(text)) return; await new Promise(r => setTimeout(r, 100)); } throw new Error('Expected journey text: '+text); }
  async function idle() { for (let i=0; i<60; i++) { if (await page.evaluate(() => !state.busy && !state.onboarding?.loading)) return; await new Promise(r => setTimeout(r, 100)); } throw new Error('Journey stayed busy'); }
  async function advance() { await idle(); await page.clock.fastForward(30001); await new Promise(r => setTimeout(r, 100)); await idle(); }
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  let phase = 'owner_review', registrations = 0, setupConfirmations = 0, approvals = 0, deployments = 0;
  const registration = () => ({ registration_id: regId, app_id: app.app_id, display_name: app.display_name, automatic_setup: true, status_observed_at: new Date().toISOString(), requirements: [{ name: 'Catalog review', status: phase === 'owner_review' ? 'pending_review' : 'approved', actor: 'Platform owner' }], pull_request: { number: 7, url: 'https://github.com/demo/aegis-platform/pull/7' }, setup_available: phase !== 'owner_review', deployment_available: false });
  const setup = () => ({ app_id: app.app_id, setup_id: setupId, state: { owner_review: 'preparing', preparing: 'preparing', setup_approval: 'awaiting_review', building: 'building', release_review: 'ready', deploying: 'ready', healthy: 'ready' }[phase], pipeline_ready: ['building','release_review','deploying','healthy'].includes(phase), target_ready: ['building','release_review','deploying','healthy'].includes(phase), release_ready: ['release_review','deploying','healthy'].includes(phase), workflow_files: files, target_files: targetFiles, worker_online: true, can_approve_pipeline: true, can_approve_target: true, approval_token: 'synthetic-approval', pull_requests: Object.fromEntries(['pipeline','target'].map((kind, i) => [kind, { number: i+1, url: `https://github.com/demo/proposals/pull/${i+1}`, state: ['building','release_review','deploying','healthy'].includes(phase) ? 'closed' : 'open', merged: ['building','release_review','deploying','healthy'].includes(phase), approved: ['building','release_review','deploying','healthy'].includes(phase) }])) });
  const delivery = () => ({ request_id: requestId, app_id: app.app_id, environment: 'dev', release_id: '777', status: phase === 'healthy' ? 'healthy' : 'checking', security_verified: phase === 'healthy', status_observed_at: new Date().toISOString(), health_observed_at: phase === 'healthy' ? new Date().toISOString() : null });
  const journey = () => ({ app_id: app.app_id, registration_id: regId, phase, message: { owner_review: 'Waiting for platform owner approval.', preparing: 'The platform is preparing your app.', setup_approval: 'Review the generated changes.', building: 'CI is validating your app.', release_review: 'A validated release is ready.', deploying: 'Deployment is in progress.', healthy: 'Your app is healthy in DEV.' }[phase], actor: phase === 'healthy' ? 'Complete' : phase === 'release_review' ? 'You' : phase === 'setup_approval' ? 'Application and platform owners' : 'Platform', registration: registration(), setup: phase === 'owner_review' ? null : setup(), deployment: ['deploying','healthy'].includes(phase) ? delivery() : null });
  try {
    await page.route('**/api/v1/status', route => route.fulfill({ json: { mode: 'demo', version: '0.7.0', registration_enabled: true, deployment_enabled: true } }));
    await page.route('**/api/v1/applications', route => route.fulfill({ json: { items: [app] } }));
    await page.route('**/api/v1/registrations', route => route.request().method() === 'POST' ? (registrations++, assert.equal(route.request().postDataJSON().prepare_dev, true), route.fulfill({ json: registration() })) : route.fulfill({ json: { items: [] } }));
    await page.route('**/api/v1/registrations/*', route => route.fulfill({ json: registration() }));
    await page.route('**/api/v1/registration-validations*', async route => {
      assert.equal(new URL(route.request().url()).searchParams.get("guided_setup"), "true");
      const fields = route.request().postDataJSON();
      await route.fulfill({ json: { fields, source: { full_name: 'demo/orders-api', source_commit: 'a'.repeat(40) }, detection: { dockerfile_present: true }, review_token: 'synthetic-registration-review', automatic_setup: { workflow_files: files, target_files: targetFiles, blockers: [], notice: 'Review these exact proposals. Submitting authorizes preparation after catalog approval; deployment remains separate.' } } });
    });
    await page.route('**/api/v1/applications/orders-api/onboarding**', route => route.fulfill({ json: journey() }));
    await page.route('**/api/v1/applications/orders-api/dev-setup**', route => {
      if (route.request().url().endsWith('/approvals')) { approvals++; phase = 'building'; }
      else if (route.request().method() === 'POST') setupConfirmations++;
      return route.fulfill({ json: setup() });
    });
    await page.route('**/api/v1/applications/orders-api/releases**', route => route.fulfill({ json: { items: [{ release_id: '777', tag: 'release-40883905860-1', eligible: true, build_label: 'Build #1', build_number: 1, workflow_run_id: '40883905860', run_attempt: 1, source_commit: 'a'.repeat(40), published_at: '2026-10-29T12:00:00Z' }], next_page: null } }));
    await page.route('**/api/v1/deployment-validations', route => route.fulfill({ json: { fields: route.request().postDataJSON(), review_token: 'synthetic-deployment-review', context: { source_commit: 'a'.repeat(40), image_root_digest: 'sha256:' + 'a'.repeat(64), expected_desired_fingerprint: null, target: { cluster_id: 'kind-local', namespace: 'aegis-orders-api-dev' } } } }));
    await page.route('**/api/v1/deployment-requests', route => { deployments++; phase = 'deploying'; return route.fulfill({ json: delivery() }); });
    await page.route('**/api/v1/deployment-requests/*', route => route.fulfill({ json: delivery() }));
    await page.goto(base, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /Enter local demo/ }).click();
    await page.locator('#applications').waitFor({ state: 'visible' });
    await page.clock.install();
    await page.locator('#nav-register').click();
    await page.locator('#repository').selectOption('101');
    await page.locator('#validate-button').click();
    await page.locator('#registration-setup-review').waitFor({ state: 'visible' });
    await page.locator('#registration-setup-files summary').first().click();
    assert.equal(await page.locator('#registration-setup-files img').count(), 0);
    await page.screenshot({ path: path.join(out, 'combined-review-desktop.png'), fullPage: true });
    await page.locator('#submit-registration').click();
    await page.locator('#onboarding').waitFor({ state: 'visible' });
    assert.equal(registrations, 1);
    assert.match(await page.locator('#onboarding-message').textContent(), /owner approval/);
    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('#onboarding').waitFor({ state: 'visible' });
    assert.equal(registrations, 1, 'Reload must not resubmit registration');
    phase = 'setup_approval';
    await advance();
    await page.locator('#setup-approve').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#setup-confirm').isVisible(), false);
    await page.locator('#setup-approve').click();
    assert.equal(approvals, 1); assert.equal(setupConfirmations, 0);
    await advance();
    await waitText('CI is validating');
    assert.equal(deployments, 0);
    phase = 'release_review';
    await advance();
    await page.locator('#deployment').waitFor({ state: 'visible' });
    assert.match(await page.locator('#deployment-release').textContent(), /Build #1/);
    await page.locator('#deployment-release').selectOption('777');
    assert.match(await page.locator('#deployment-release-summary').textContent(), /Build #1 · Commit aaaaaaa/);
    assert.equal(await page.locator('#deployment-release-raw').isVisible(), false);
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.screenshot({ path: path.join(out, 'release-review-mobile.png'), fullPage: true });
    await page.locator('#deployment-form button[type=submit]').click();
    await page.locator('#deployment-review').waitFor({ state: 'visible' });
    assert.match(await page.locator('#deployment-review-details').textContent(), /Build #1/);
    assert.equal(deployments, 0, 'Review must not deploy');
    await page.locator('#confirm-deployment').click();
    await page.locator('#delivery-progress').waitFor({ state: 'visible' });
    assert.equal(deployments, 1);
    phase = 'healthy';
    await advance();
    await waitText('healthy in DEV');
    assert.match(await page.locator('#onboarding-actor').textContent(), /Complete/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.screenshot({ path: path.join(out, 'healthy-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []);
    const result = { guidedJourney: 'passed', combinedReview: true, extraSetupConfirmations: setupConfirmations, reloadResubmissions: 0, automaticTransitions: true, explicitDeployments: deployments, friendlyBuildLabels: true, healthyRequiresEvidence: true, mobileFits: true, javascriptErrors: errors };
    fs.writeFileSync(path.join(out, 'browser-result.json'), JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result));
  } catch (e) {
    await page.screenshot({ path: path.join(out, 'failure.png'), fullPage: true });
    console.error({ errors, portalError: await page.locator('#error').textContent(), journey: await page.locator('#onboarding-message').textContent() }); throw e;
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
