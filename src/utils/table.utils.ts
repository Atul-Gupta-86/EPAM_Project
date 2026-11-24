import Table from 'cli-table3';

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
 * Render scan summary table in plain text
 */
export function renderScanSummaryTable(summaries: ToolSummary[]): string {
  const table = new Table({
    head: ['Tool', 'Status', 'High', 'Medium', 'Low', 'Total Issues']
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

    table.push([
      s.tool,
      s.status,
      String(s.high),
      String(s.medium),
      String(s.low),
      String(s.total)
    ]);
  }

  table.push([
    'TOTAL',
    '—',
    String(totalHigh),
    String(totalMed),
    String(totalLow),
    String(grandTotal)
  ]);

  return table.toString();
}

/**
 * Render detailed findings table in plain text
 */
export function renderFindingsTable(findings: FindingRow[], limit = 50): string {
  if (findings.length === 0) {
    return 'No vulnerabilities detected. Target repository is clean.';
  }

  const table = new Table({
    head: ['#', 'Tool', 'Rule / Vuln ID', 'Severity', 'Location', 'Message'],
    colWidths: [5, 12, 24, 12, 34, 45],
    wordWrap: true
  });

  const displayList = findings.slice(0, limit);
  for (const f of displayList) {
    const shortLoc = `${f.file}:${f.line}`;
    table.push([
      String(f.id),
      f.tool,
      f.ruleId.length > 22 ? f.ruleId.slice(0, 21) + '…' : f.ruleId,
      f.severity,
      shortLoc.length > 32 ? '…' + shortLoc.slice(-31) : shortLoc,
      f.message.length > 80 ? f.message.slice(0, 77) + '…' : f.message
    ]);
  }

  let output = table.toString();
  if (findings.length > limit) {
    output += `\nShowing ${limit} of ${findings.length} findings. Use /export to view full report.`;
  }
  return output;
}

/**
 * Render tool status table in plain text
 */
export function renderToolsTable(tools: { name: string; installed: boolean; path: string; version?: string }[]): string {
  const table = new Table({
    head: ['Security Tool', 'Status', 'Executable Path', 'Version']
  });

  for (const t of tools) {
    table.push([
      t.name,
      t.installed ? 'INSTALLED' : 'NOT FOUND',
      t.path || 'N/A',
      t.version || 'N/A'
    ]);
  }

  return table.toString();
}
