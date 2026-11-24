import Table from 'cli-table3';
import pc from 'picocolors';

export interface ToolSummary {
  tool: string;
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface FindingRow {
  id: number;
  tool: string;
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  message: string;
}

/**
 * Render scan summary table
 */
export function renderScanSummaryTable(summaries: ToolSummary[]): string {
  const table = new Table({
    head: [
      pc.cyan('Tool'),
      pc.cyan('Status'),
      pc.red('High'),
      pc.yellow('Medium'),
      pc.blue('Low'),
      pc.magenta('Total Issues')
    ],
    style: {
      head: [],
      border: ['grey']
    }
  });

  let totalHigh = 0;
  let totalMed = 0;
  let totalLow = 0;
  let grandTotal = 0;

  for (const s of summaries) {
    totalHigh += s.high;
    totalMed += s.medium;
    totalLow += s.low;
    grandTotal += s.total;

    const statusFormatted = s.status === 'SUCCESS' 
      ? pc.green('SUCCESS')
      : s.status === 'SKIPPED'
      ? pc.yellow('SKIPPED')
      : pc.red('FAILED');

    table.push([
      pc.bold(s.tool),
      statusFormatted,
      s.high > 0 ? pc.red(String(s.high)) : pc.dim('0'),
      s.medium > 0 ? pc.yellow(String(s.medium)) : pc.dim('0'),
      s.low > 0 ? pc.blue(String(s.low)) : pc.dim('0'),
      pc.bold(String(s.total))
    ]);
  }

  table.push([
    pc.bold('TOTAL'),
    pc.dim('—'),
    pc.red(pc.bold(String(totalHigh))),
    pc.yellow(pc.bold(String(totalMed))),
    pc.blue(pc.bold(String(totalLow))),
    pc.magenta(pc.bold(String(grandTotal)))
  ]);

  return table.toString();
}

/**
 * Render detailed findings table
 */
export function renderFindingsTable(findings: FindingRow[], limit = 25): string {
  if (findings.length === 0) {
    return pc.green('No vulnerabilities detected! Your target repository is clean.');
  }

  const table = new Table({
    head: [
      pc.cyan('#'),
      pc.cyan('Tool'),
      pc.cyan('Rule / Vuln ID'),
      pc.cyan('Severity'),
      pc.cyan('Location'),
      pc.cyan('Message')
    ],
    colWidths: [5, 12, 22, 12, 32, 45],
    wordWrap: true,
    style: {
      head: [],
      border: ['grey']
    }
  });

  const displayList = findings.slice(0, limit);
  for (const f of displayList) {
    let sevColor = pc.white;
    const sevUpper = f.severity.toUpperCase();
    if (sevUpper.includes('HIGH') || sevUpper.includes('CRITICAL') || sevUpper === 'ERROR') {
      sevColor = pc.red;
    } else if (sevUpper.includes('MEDIUM') || sevUpper.includes('WARNING')) {
      sevColor = pc.yellow;
    } else if (sevUpper.includes('LOW') || sevUpper.includes('NOTE')) {
      sevColor = pc.blue;
    }

    const shortLoc = `${f.file}:${f.line}`;
    table.push([
      String(f.id),
      f.tool,
      f.ruleId.length > 20 ? f.ruleId.slice(0, 19) + '…' : f.ruleId,
      sevColor(pc.bold(f.severity)),
      shortLoc.length > 30 ? '…' + shortLoc.slice(-29) : shortLoc,
      f.message.length > 80 ? f.message.slice(0, 77) + '…' : f.message
    ]);
  }

  let output = table.toString();
  if (findings.length > limit) {
    output += `\n${pc.dim(`Showing ${limit} of ${findings.length} findings. Use /export to view full report.`)}`;
  }
  return output;
}

/**
 * Render tool status table
 */
export function renderToolsTable(tools: { name: string; installed: boolean; path: string; version?: string }[]): string {
  const table = new Table({
    head: [pc.cyan('Security Tool'), pc.cyan('Status'), pc.cyan('Executable Path'), pc.cyan('Version')],
    style: { head: [], border: ['grey'] }
  });

  for (const t of tools) {
    table.push([
      pc.bold(t.name),
      t.installed ? pc.green('INSTALLED') : pc.red('NOT FOUND'),
      t.path || pc.dim('N/A'),
      t.version || pc.dim('N/A')
    ]);
  }

  return table.toString();
}
