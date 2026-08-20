const test = require('node:test');
const assert = require('node:assert/strict');

const express = require('../../api/node_modules/express');
const blocks = require('../../api/routes/blocks');

test('raw producer mutations are unreachable over HTTP', async t => {
  const app = express();
  app.use(express.json());
  app.use('/blocks', blocks);
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { port } = server.address();

  for (const endpoint of ['register', 'deposit', 'sync', 'post']) {
    const response = await fetch(`http://127.0.0.1:${port}/blocks/${endpoint}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attackerControlled: true }),
    });
    assert.equal(response.status, 410, endpoint);
    const body = await response.json();
    assert.equal(body.code, 'verified_pipeline_required');
  }
});
