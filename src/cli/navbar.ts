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
  const items = NAV_ITEMS.map(item => `[${item.name}]`).join(' ');
  return `\nHintline: ${items}\n`;
}

/**
 * Render comprehensive help menu (also shown on typo errors)
 */
export function renderHelpMenu(isTypo = false): string {
  let output = '';
  if (isTypo) {
    output += 'Unknown command or typo detected!\n';
    output += 'Here is the list of all available commands you can run:\n\n';
  } else {
    output += '=== Security Scanner Commands ===\n\n';
  }

  for (const item of NAV_ITEMS) {
    output += `  ${item.command.padEnd(20)} - ${item.description}\n`;
  }

  output += '\nExamples:\n';
  output += '  /scan .                     Scan current directory\n';
  output += '  /scan D:\\Projects\\my-app    Scan specific repository\n';
  output += '  /result                     Display scan summary table\n';
  output += '  /findings                   View all detailed vulnerabilities\n';
  output += '  /export ./my-reports        Export SARIF report\n';
  output += '  /tools                      Inspect Trivy, Semgrep, Gitleaks\n';
  output += '  /clear                      Reset display viewport\n';
  output += '  /quit                       Exit scanner\n';

  return output;
}
