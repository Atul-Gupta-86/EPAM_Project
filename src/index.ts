import dotenv from 'dotenv';
dotenv.config();

import { initializeBackendServer } from './server.js';
import { InteractiveCLI } from './cli/cli.js';
import { logger } from './utils/logger.utils.js';

async function bootstrap() {
  try {
    // Initialize backend logical subsystem & DB
    const server = initializeBackendServer();

    // Connect CLI to backend command router
    const cli = new InteractiveCLI(server.router);

    // Handle process termination cleanly
    const cleanup = () => {
      server.shutdown();
      process.exit(0);
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);

    // If arguments were provided via CLI (e.g. "npm start -- /scan .")
    const args = process.argv.slice(2);
    if (args.length > 0) {
      const command = args.join(' ');
      await cli.runSingleCommand(command);
    } else {
      // Interactive mode
      await cli.start();
    }
  } catch (err) {
    logger.error(`Application fatal error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

bootstrap();
