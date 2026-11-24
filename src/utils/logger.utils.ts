import pc from 'picocolors';

export const logger = {
  info: (msg: string) => console.log(pc.cyan(`ℹ  ${msg}`)),
  success: (msg: string) => console.log(pc.green(`✔  ${msg}`)),
  warn: (msg: string) => console.log(pc.yellow(`⚠  ${msg}`)),
  error: (msg: string) => console.log(pc.red(`✖  ${msg}`)),
  banner: (msg: string) => console.log(pc.bold(pc.magenta(msg))),
  plain: (msg: string) => console.log(msg),
  divider: () => console.log(pc.dim('─'.repeat(70))),
  failedScan: () => console.log(pc.bgRed(pc.white(pc.bold('  FAILED SCAN  ')))),
};
