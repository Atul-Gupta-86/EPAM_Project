import dotenv from 'dotenv';
dotenv.config();

import { initDatabase, type IDatabaseService } from './db/connection.js';
import { CommandController, type CommandContext } from './controller/commandController.js';
import { CommandRouter } from './router/commandRouter.js';
import { logger } from './utils/logger.utils.js';

export interface BackendServer {
  db: IDatabaseService;
  controller: CommandController;
  router: CommandRouter;
  shutdown(): void;
}

/**
 * Initializes Backend services, Database connection, and Command dispatchers
 */
export function initializeBackendServer(customCtx?: Partial<CommandContext>): BackendServer {
  try {
    // 1. Initialize DB connection
    const db = initDatabase();

    // 2. Initialize Controller
    const controller = new CommandController(customCtx);

    // 3. Initialize Router
    const router = new CommandRouter(controller);

    const shutdown = () => {
      try {
        db.close();
      } catch {
        // ignore
      }
    };

    return {
      db,
      controller,
      router,
      shutdown
    };
  } catch (err) {
    logger.error(`Failed to initialize backend services: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  }
}
