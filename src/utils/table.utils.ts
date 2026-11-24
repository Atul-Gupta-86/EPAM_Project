import Table from 'cli-table3';
import pc from 'picocolors';
import { sanitizeUnicode } from './file.utils.js';

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
 * Render scan summary table in low-contrast muted colors
 */
export function renderScanSummaryTable(summaries: ToolSummary[]): string {
  const table = new Table({
    head: [
      pc.dim(pc.cyan('Tool')),
      pc.dim(pc.cyan('Status')),
      pc.dim(pc.red('High')),
      pc.dim(pc.yellow('Medium')),
      pc.dim(pc.blue('Low')),
      pc.dim(pc.cyan('Total Issues'))
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
      ? pc.dim(pc.green('SUCCESS'))
      : s.status === 'SKIPPED'
      ? pc.dim(pc.yellow('SKIPPED'))
      : pc.dim(pc.red('FAILED'));

    table.push([
      pc.gray(s.tool),
      statusFormatted,
      s.high > 0 ? pc.dim(pc.red(String(s.high))) : pc.dim('0'),
      s.medium > 0 ? pc.dim(pc.yellow(String(s.medium))) : pc.dim('0'),
      s.low > 0 ? pc.dim(pc.blue(String(s.low))) : pc.dim('0'),
      pc.gray(String(s.total))
    ]);
  }

  table.push([
    pc.dim('TOTAL'),
    pc.dim('—'),
    totalHigh > 0 ? pc.dim(pc.red(String(totalHigh))) : pc.dim('0'),
    totalMed > 0 ? pc.dim(pc.yellow(String(totalMed))) : pc.dim('0'),
    totalLow > 0 ? pc.dim(pc.blue(String(totalLow))) : pc.dim('0'),
    pc.gray(String(grandTotal))
  ]);

  return table.toString();
}

/**
 * Render detailed findings table in low-contrast muted colors
 */
export function renderFindingsTable(findings: FindingRow[], limit = 25): string {
  if (findings.length === 0) {
    return pc.gray('No vulnerabilities detected.');
  }

  const table = new Table({
    head: [
      pc.dim(pc.cyan('#')),
      pc.dim(pc.cyan('Tool')),
      pc.dim(pc.cyan('Rule / Vuln ID')),
      pc.dim(pc.cyan('Severity')),
      pc.dim(pc.cyan('Location')),
      pc.dim(pc.cyan('Message'))
    ],
    colWidths: [5, 12, 24, 12, 32, 45],
    wordWrap: true,
    style: {
      head: [],
      border: ['grey']
    }
  });

  const displayList = findings.slice(0, limit);
  for (const f of displayList) {
    let sevFormatted = pc.gray(f.severity);
    const sevUpper = f.severity.toUpperCase();
    if (sevUpper.includes('HIGH') || sevUpper.includes('CRITICAL') || sevUpper === 'ERROR') {
      sevFormatted = pc.dim(pc.red(f.severity));
    } else if (sevUpper.includes('MEDIUM') || sevUpper.includes('WARNING')) {
      sevFormatted = pc.dim(pc.yellow(f.severity));
    } else if (sevUpper.includes('LOW') || sevUpper.includes('NOTE')) {
      sevFormatted = pc.dim(pc.blue(f.severity));
    }

    const shortLoc = `${f.file}:${f.line}`;
    const cleanRuleId = sanitizeUnicode(f.ruleId);
    const cleanMsg = sanitizeUnicode(f.message);

    table.push([
      pc.dim(String(f.id)),
      pc.gray(f.tool),
      pc.gray(cleanRuleId.length > 22 ? cleanRuleId.slice(0, 21) + '…' : cleanRuleId),
      sevFormatted,
      pc.dim(shortLoc.length > 30 ? '…' + shortLoc.slice(-29) : shortLoc),
      pc.gray(cleanMsg.length > 80 ? cleanMsg.slice(0, 77) + '…' : cleanMsg)
    ]);
  }

  let output = table.toString();
  if (findings.length > limit) {
    output += `\n${pc.dim(`Showing ${limit} of ${findings.length} findings.`)}`;
  }
  return output;
}

/**
 * Render tool status table in low-contrast muted colors
 */
export function renderToolsTable(tools: { name: string; installed: boolean; path: string; version?: string }[]): string {
  const table = new Table({
    head: [
      pc.dim(pc.cyan('Security Tool')),
      pc.dim(pc.cyan('Status')),
      pc.dim(pc.cyan('Executable Path')),
      pc.dim(pc.cyan('Version'))
    ],
    style: {
      head: [],
      border: ['grey']
    }
  });

  for (const t of tools) {
    table.push([
      pc.gray(t.name),
      t.installed ? pc.dim(pc.green('INSTALLED')) : pc.dim(pc.red('NOT FOUND')),
      pc.dim(t.path || 'N/A'),
      pc.dim(t.version || 'N/A')
    ]);
  }

  return table.toString();
}
