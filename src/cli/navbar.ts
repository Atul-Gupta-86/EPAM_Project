import pc from 'picocolors';

export interface NavItem {
  name: string;
  command: string;
  description: string;
}

export const NAV_ITEMS: NavItem[] = [
  { name: 'help', command: '/help', description: 'Show all commands & usage' },
  { name: 'scan', command: '/scan <repo_path>', description: 'Run multi-tool vulnerability scan' },
  { name: 'tools', command: '/tools', description: 'Check security tools status' },
  { name: 'export', command: '/export [path]', description: 'Export last scan SARIF report' },
  { name: 'clear', command: '/clear', description: 'Clear screen view' },
  { name: 'result', command: '/result', description: 'Tabular summary of last scan' },
  { name: 'findings', command: '/findings', description: 'Detailed list of detected issues' },
  { name: 'quit', command: '/quit', description: 'Exit application' }
];

/**
 * Render fixed hintline navigation bar after each response
 */
export function renderNavBar(): string {
  const line = '━'.repeat(80);
  const items = NAV_ITEMS.map(item => pc.cyan(`[ ${pc.bold(item.name)} ]`)).join(' ');
  const subtitle = pc.dim('Hint: Type any command above or with "/" prefix (e.g., /scan ./my-repo, /result, /help)');

  return `\n${pc.dim(line)}\n${pc.bold(pc.yellow('NAV MENU:'))} ${items}\n${subtitle}\n${pc.dim(line)}`;
}

/**
 * Render comprehensive help menu (also shown on typo errors)
 */
export function renderHelpMenu(isTypo = false): string {
  let output = '';
  if (isTypo) {
    output += `${pc.red(pc.bold('✖ Unknown command or typo detected!'))}\n`;
    output += `${pc.yellow('Here is the list of all available commands you can run:\n')}\n`;
  } else {
    output += `${pc.bold(pc.cyan('=== Security Scanner CLI Commands ==='))}\n\n`;
  }

  for (const item of NAV_ITEMS) {
    const cmdFormatted = pc.bold(pc.green(item.command.padEnd(20)));
    output += `  ${cmdFormatted} - ${item.description}\n`;
  }

  output += `\n${pc.dim('Examples:')}\n`;
  output += `  ${pc.cyan('/scan .')}                     Scan current directory\n`;
  output += `  ${pc.cyan('/scan D:\\Projects\\my-app')}    Scan specific repository\n`;
  output += `  ${pc.cyan('/result')}                     Display scan summary table\n`;
  output += `  ${pc.cyan('/findings')}                   View all detailed vulnerabilities\n`;
  output += `  ${pc.cyan('/export ./my-reports')}        Export SARIF report\n`;
  output += `  ${pc.cyan('/tools')}                      Inspect Trivy, Semgrep, Gitleaks\n`;
  output += `  ${pc.cyan('/clear')}                      Reset display viewport\n`;
  output += `  ${pc.cyan('/quit')}                       Exit scanner\n`;

  return output;
}
