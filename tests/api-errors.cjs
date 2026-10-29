// Verify the real browser API helper handles proxy/server bodies without exposing raw HTML.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('app/static/app.js', 'utf8');
const helper = source.slice(source.indexOf('async function api('), source.indexOf('async function action('));
(async () => {
  for (const status of [500, 502, 503]) {
    const context = vm.createContext({ state: { session: null }, fetch: async () => ({ ok: false, status, json: async () => { throw new SyntaxError('Internal Server Error'); } }) });
    const call = vm.runInContext(helper + '\napi("/api/v1/uploads/test/review")', context);
    await assert.rejects(call, error => error.message.includes(`HTTP ${status}`) && error.message.includes('recovery action') && !error.message.includes('Unexpected token'));
  }
  console.log('Non-JSON server/proxy error handling passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
