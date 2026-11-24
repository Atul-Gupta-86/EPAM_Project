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

  /**
   * Display welcome banner
   */
  private printBanner(): void {
    console.log(pc.cyan(`
╔══════════════════════════════════════════════════════════════════════════╗
║               MULTI-TOOL SECURITY AUDIT CLI (SARIF 2.1.0)                ║
║           Aqua Trivy  •  Semgrep SAST  •  Gitleaks Secrets               ║
╚══════════════════════════════════════════════════════════════════════════╝
`));
    console.log(pc.dim('Type ') + pc.bold(pc.yellow('/help')) + pc.dim(' to list all commands or ') + pc.bold(pc.yellow('/scan <path>')) + pc.dim(' to start an audit.\n'));
  }

  /**
   * Start interactive REPL loop
   */
  async start(): Promise<void> {
    this.printBanner();
    console.log(renderNavBar());

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: pc.bold(pc.green('\nsecurity-cli > '))
    });

    rl.prompt();

    for await (const line of rl) {
      const input = line.trim();
      if (input.length > 0) {
        try {
          const result = await this.router.route(input);
          if (result.shouldQuit) {
            rl.close();
            break;
          }
        } catch (err) {
          logger.error(`An unexpected error occurred: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      // Render fixed hintline navigation bar after each response
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
