import readline from 'node:readline';
import { CommandRouter } from '../router/commandRouter.js';
import { renderNavBar } from './navbar.js';
import { logger } from '../utils/logger.utils.js';

export class InteractiveCLI {
  private router: CommandRouter;

  constructor(router?: CommandRouter) {
    this.router = router || new CommandRouter();
  }

  /**
   * Start interactive REPL loop
   */
  async start(): Promise<void> {
    console.log(renderNavBar());

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: 'security-cli > '
    });

    rl.prompt();

    for await (const line of rl) {
      const input = line.trim();
      if (input.length === 0) {
        rl.prompt();
        continue;
      }

      try {
        const result = await this.router.route(input);
        if (result.shouldQuit) {
          rl.close();
          break;
        }
      } catch (err) {
        logger.error(`An unexpected error occurred: ${err instanceof Error ? err.message : String(err)}`);
      }

      // Render fixed hintline navigation bar once after each command response
      console.log(renderNavBar());
      rl.prompt();
    }
  }

  /**
   * Run single command mode (for automation/scripting)
   */
  async runSingleCommand(commandString: string): Promise<void> {
    const result = await this.router.route(commandString);
    console.log(renderNavBar());
    if (result.shouldQuit) {
      process.exit(0);
    }
  }
}
