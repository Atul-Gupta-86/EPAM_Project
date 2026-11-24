import { CommandController } from '../controller/commandController.js';

/**
 * Command Router - Dispatches incoming CLI commands to the command controller
 */
export class CommandRouter {
  private controller: CommandController;

  constructor(controller?: CommandController) {
    this.controller = controller || new CommandController();
  }

  /**
   * Route command to controller handler
   */
  async route(input: string): Promise<{ shouldQuit?: boolean }> {
    return await this.controller.handleCommand(input);
  }
}
