#!/usr/bin/env node
'use strict';

const { loadConfig } = require('./src/config');
const { createServer } = require('./src/server');

async function main() {
  const config = loadConfig();
  const server = await createServer(config);
  await new Promise((resolve) => server.listen(config.port, config.host, resolve));
  const address = server.address();
  console.log(
    `Document workflow API listening on http://${address.address}:${address.port}`,
  );
  console.log('Seeded users: clerk1, clerk2, officer, senior (passwords in README)');

  const shutdown = () => {
    console.log('\nShutting down.');
    server.close(async () => {
      await server.service.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
