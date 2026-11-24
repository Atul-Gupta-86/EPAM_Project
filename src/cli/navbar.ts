import pc from 'picocolors';

export interface NavItem {
  name: string;
  command: string;
  description: string;
}

export const NAV_ITEMS: NavItem[] = [
  { name: 'help', command: 'help', description: 'Show all commands' },
  { name: 'scan', command: 'scan <repo_path>', description: 'Run security scan (trivy, semgrep, gitleaks)' },
  { name: 'tools', command: 'tools', description: 'Check security tools status' },
  { name: 'export', command: 'export [path]', description: 'Export last scan SARIF result' },
  { name: 'clear', command: 'clear', description: 'Clear screen' },
  { name: 'result', command: 'result', description: 'Show result of the last scan in tabular format' },
  { name: 'findings', command: 'findings', description: 'Show detailed list of findings' },
  { name: 'quit', command: 'quit', description: 'Quit from the app' }
];

/**
 * Fixed hintline navigation bar with low-contrast muted styling
 */
export function renderNavBar(): string {
  return NAV_ITEMS.map(item => `${pc.dim('[')}${pc.cyan(item.name)}${pc.dim(']')}`).join(' ');
}

/**
 * Low-contrast clean help menu
 */
export function renderHelpMenu(isTypo = false): string {
  let output = '';
  if (isTypo) {
    output += `${pc.dim(pc.red('Unknown command or typo detected.'))}\n${pc.dim('Available commands:')}\n\n`;
  } else {
    output += `${pc.dim('Commands:')}\n\n`;
  }

  for (const item of NAV_ITEMS) {
    output += `  ${pc.cyan(item.command.padEnd(20))} ${pc.dim('-')} ${pc.gray(item.description)}\n`;
  }

  return output;
}
