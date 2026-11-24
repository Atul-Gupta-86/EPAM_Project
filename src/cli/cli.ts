import readline from 'node:readline';
import pc from 'picocolors';
import { CommandRouter } from '../router/commandRouter.js';
import { renderNavBar } from './navbar.js';
import { logger } from '../utils/logger.utils.js';

export class InteractiveCLI {
  private router: CommandRouter;

  constructor(router?: CommandRouter) {
    this.router = router || new CommandRouter();
  }

  async start(): Promise<void> {
    console.log(renderNavBar());

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: pc.dim('> ')
    });

    const askCallback = (questionText: string): Promise<string> => {
      return new Promise<string>((resolve) => {
        rl.question(questionText, (answer) => {
          resolve(answer.trim());
        });
      });
    };

    rl.prompt();

    rl.on('line', async (line: string) => {
      const input = line.trim();
      if (input.length > 0) {
        try {
          const result = await this.router.route(input, askCallback);
          if (result.shouldQuit) {
            rl.close();
            process.exit(0);
          }
          console.log(renderNavBar());
        } catch (err) {
          logger.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
          console.log(renderNavBar());
        }
      }
      rl.prompt();
    });

    rl.on('close', () => {
      process.exit(0);
    });
  }

  async runSingleCommand(commandString: string): Promise<void> {
    const result = await this.router.route(commandString);
    console.log(renderNavBar());
    if (result.shouldQuit) {
      process.exit(0);
    }
  }
}
