export const logger = {
  info: (msg: string) => console.log(`[INFO] ${msg}`),
  success: (msg: string) => console.log(`[SUCCESS] ${msg}`),
  warn: (msg: string) => console.log(`[WARN] ${msg}`),
  error: (msg: string) => console.log(`[ERROR] ${msg}`),
  banner: (msg: string) => console.log(msg),
  plain: (msg: string) => console.log(msg),
  divider: () => console.log('─'.repeat(70)),
  failedScan: () => console.log(' FAILED SCAN '),
};
