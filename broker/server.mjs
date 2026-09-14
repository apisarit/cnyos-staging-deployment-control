import { createProductionServer } from './core.mjs';

const { server } = await createProductionServer();
server.listen(9443, '127.0.0.1', () => process.stdout.write('CNYOS staging broker listening on loopback TLS\n'));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
