import pc from 'picocolors';

export const logger = {
  info: (msg: string) => console.log(pc.gray(msg)),
  success: (msg: string) => console.log(pc.dim(pc.green(msg))),
  warn: (msg: string) => console.log(pc.dim(pc.yellow(msg))),
  error: (msg: string) => console.log(pc.dim(pc.red(msg))),
  banner: (msg: string) => console.log(pc.gray(msg)),
  plain: (msg: string) => console.log(msg),
  failedScan: () => console.log(pc.dim(pc.red('FAILED SCAN')))
};
