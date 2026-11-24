import path from 'node:path';
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import pc from 'picocolors';

import { getDatabase } from '../db/connection.js';
import { logger } from '../utils/logger.utils.js';
import {
  renderScanSummaryTable,
  renderFindingsTable,
  renderToolsTable,
  type ToolSummary,
  type FindingRow
} from '../utils/table.utils.js';
import {
  normalizeCommand,
  validateRepoPath,
  validateExportPath
} from '../utils/validator.utils.js';
import {
  writeJsonFile,
  readJsonFile,
  copyFileSafely,
  ensureDir
} from '../utils/file.utils.js';
import { renderHelpMenu } from '../cli/navbar.js';

import { runTrivy, type SarifReport, type ToolExecutionResult } from '../tools_execution/trivy.tool.js';
import { runSemgrep } from '../tools_execution/semgrep.tool.js';
import { runGitleaks } from '../tools_execution/gitleaks.tool.js';
import { standardizeSarif } from '../validator/sarif_standardization.js';
import { validateAndStoreNonnormalized } from '../validator/sarif_validation.js';

export interface CommandContext {
  toolsResultDir: string;
  combinedResultDir: string;
  validatorDir: string;
  nonnormalizedDir: string;
  exportsDir: string;
}

export type AskQuestionCallback = (query: string) => Promise<string>;

export class CommandController {
  private ctx: CommandContext;

  constructor(ctx?: Partial<CommandContext>) {
    this.ctx = {
      toolsResultDir: ctx?.toolsResultDir || path.resolve(process.cwd(), 'src', 'tools_result'),
      combinedResultDir: ctx?.combinedResultDir || path.resolve(process.cwd(), 'src', 'tools_result', 'combined_result'),
      validatorDir: ctx?.validatorDir || path.resolve(process.cwd(), 'src', 'validator'),
      nonnormalizedDir: ctx?.nonnormalizedDir || path.resolve(process.cwd(), 'src', 'validator', 'nonnormalized_result'),
      exportsDir: ctx?.exportsDir || path.resolve(process.cwd(), 'exports')
    };

    ensureDir(this.ctx.toolsResultDir);
    ensureDir(this.ctx.combinedResultDir);
    ensureDir(this.ctx.validatorDir);
    ensureDir(this.ctx.nonnormalizedDir);
    ensureDir(this.ctx.exportsDir);
  }

  /**
   * Main entry point for command routing
   */
  async handleCommand(input: string, askCallback?: AskQuestionCallback): Promise<{ shouldQuit?: boolean }> {
    const trimmed = input.trim();
    if (!trimmed) return {};

    const [rawCmd, ...argParts] = trimmed.split(/\s+/);
    const cmd = normalizeCommand(rawCmd);
    const args = argParts.join(' ');

    switch (cmd) {
      case 'help':
        this.handleHelp();
        return {};

      case 'scan':
        await this.handleScan(args, askCallback);
        return {};

      case 'tools':
        await this.handleTools();
        return {};

      case 'result':
        this.handleResult();
        return {};

      case 'findings':
        this.handleFindings();
        return {};

      case 'export':
        this.handleExport(args);
        return {};

      case 'clear':
        this.handleClear();
        return {};

      case 'quit':
      case 'exit':
        return { shouldQuit: true };

      default:
        // Typo or invalid command: show error and print help menu again
        console.log(renderHelpMenu(true));
        return {};
    }
  }

  handleHelp(): void {
    console.log(renderHelpMenu(false));
  }

  async handleTools(): Promise<void> {
    const checkTool = (name: string, cmd: string, verFlag = '--version') => {
      let isFileExists = false;
      try {
        if (fs.existsSync(cmd)) {
          isFileExists = true;
        }
      } catch {
        // ignore
      }

      try {
        const out = execSync(`"${cmd}" ${verFlag}`, { stdio: 'pipe', encoding: 'utf8' }).trim();
        const verLine = out.split('\n')[0]?.trim() || 'Installed';
        return { name, installed: true, path: cmd, version: verLine };
      } catch {
        if (isFileExists) {
          return { name, installed: true, path: cmd, version: 'Detected' };
        }
        return { name, installed: false, path: cmd, version: 'Not found in PATH' };
      }
    };

    const trivyCmd = process.env.TRIVY_PATH || 'trivy';
    const semgrepCmd = process.env.SEMGREP_PATH || 'semgrep';
    const gitleaksCmd = process.env.GITLEAKS_PATH || 'gitleaks';

    const toolsStatus = [
      checkTool('Trivy', trivyCmd, 'version'),
      checkTool('Semgrep', semgrepCmd, '--version'),
      checkTool('Gitleaks', gitleaksCmd, 'version')
    ];

    console.log(renderToolsTable(toolsStatus));
  }

  handleClear(): void {
    process.stdout.write('\x1b[2J\x1b[H\n'.repeat(2));
  }

  handleResult(): void {
    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');

    if (!fs.existsSync(combinedFile)) {
      logger.info('No scan results found.');
      return;
    }

    try {
      const sarif = readJsonFile<SarifReport>(combinedFile);
      const summaries = this.extractSummariesFromSarif(sarif);
      console.log(renderScanSummaryTable(summaries));
    } catch (err) {
      logger.error(`Failed to read results: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  handleFindings(): void {
    const db = getDatabase();
    const latestScan = db.getLatestScan();

    if (!latestScan) {
      logger.info('No scan records found in database.');
      return;
    }

    const findings = db.getFindings(latestScan.id);
    const rows: FindingRow[] = findings.map((f, idx) => ({
      id: idx + 1,
      tool: f.tool_name,
      ruleId: f.rule_id,
      severity: f.severity,
      file: f.file_path,
      line: f.start_line,
      message: f.message
    }));

    console.log(renderFindingsTable(rows));
  }

  handleExport(customPath?: string): void {
    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');
    const nonnormalizedFile = path.join(this.ctx.nonnormalizedDir, 'nonnormalized_result.sarif.json');

    const sourceFile = fs.existsSync(nonnormalizedFile) ? nonnormalizedFile : combinedFile;
    if (!fs.existsSync(sourceFile)) {
      logger.info('No scan result available to export.');
      return;
    }

    const { resolvedPath } = validateExportPath(customPath);
    ensureDir(resolvedPath);

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const destFile = path.extname(resolvedPath).toLowerCase() === '.json' || path.extname(resolvedPath).toLowerCase() === '.sarif'
      ? resolvedPath
      : path.join(resolvedPath, `security_scan_${timestamp}.sarif.json`);

    try {
      copyFileSafely(sourceFile, destFile);
      logger.info(`Scan result exported to: ${pc.dim(destFile)}`);
    } catch (err) {
      logger.error(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async handleScan(repoArg: string, askCallback?: AskQuestionCallback): Promise<void> {
    const validation = validateRepoPath(repoArg);
    if (!validation.valid || !validation.resolvedPath) {
      logger.error(validation.error || 'Invalid repository path');
      console.log(renderHelpMenu(true));
      return;
    }

    const targetPath = validation.resolvedPath;

    // Ask user which tools to run
    let selectedTools: string[] = ['trivy', 'semgrep', 'gitleaks'];
    if (askCallback) {
      const answer = await askCallback(pc.dim('Which tools would you like to run? [1: Trivy, 2: Semgrep, 3: Gitleaks, all: All] (default: all): '));
      const lower = answer.toLowerCase().trim();
      if (lower && lower !== 'all') {
        const picked: string[] = [];
        if (lower.includes('1') || lower.includes('trivy')) picked.push('trivy');
        if (lower.includes('2') || lower.includes('semgrep')) picked.push('semgrep');
        if (lower.includes('3') || lower.includes('gitleaks')) picked.push('gitleaks');
        if (picked.length > 0) {
          selectedTools = picked;
        }
      }
    }

    // Execute selected tools
    const executionResults: ToolExecutionResult[] = [];
    for (const toolKey of selectedTools) {
      try {
        if (toolKey === 'trivy') {
          const res = await runTrivy(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
        } else if (toolKey === 'semgrep') {
          const res = await runSemgrep(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
        } else if (toolKey === 'gitleaks') {
          const res = await runGitleaks(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
        }
      } catch (err) {
        executionResults.push({
          tool: toolKey,
          success: false,
          outputFilePath: '',
          error: err instanceof Error ? err.message : String(err)
        });
      }
    }

    // Check if scan completely failed
    const successfulRuns = executionResults.filter(r => r.success);
    if (successfulRuns.length === 0 && executionResults.length > 0) {
      logger.failedScan();
      return;
    }

    // Combine results into one SARIF document
    const combinedSarif: SarifReport = {
      $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: []
    };

    const individualFiles: string[] = [];
    for (const r of executionResults) {
      if (r.outputFilePath && fs.existsSync(r.outputFilePath)) {
        individualFiles.push(r.outputFilePath);
      }
      if (r.sarif && Array.isArray(r.sarif.runs)) {
        combinedSarif.runs.push(...r.sarif.runs);
      }
    }

    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');
    writeJsonFile(combinedFile, combinedSarif);

    // Silent Validator Pipeline (no console printing)
    const stdResult = standardizeSarif(combinedFile);
    validateAndStoreNonnormalized(
      stdResult.outputFilePath,
      individualFiles,
      this.ctx.nonnormalizedDir
    );

    // Persistence in DB
    const scanId = `scan-${Date.now()}`;
    const summaries = this.extractSummariesFromSarif(stdResult.standardizedSarif);

    let totalHigh = 0;
    let totalMed = 0;
    let totalLow = 0;
    let grandTotal = 0;

    for (const s of summaries) {
      totalHigh += s.high;
      totalMed += s.medium;
      totalLow += s.low;
      grandTotal += s.total;
    }

    const db = getDatabase();
    db.saveScan({
      id: scanId,
      target_path: targetPath,
      tools_used: selectedTools.join(','),
      timestamp: new Date().toISOString(),
      total_findings: grandTotal,
      high_count: totalHigh,
      medium_count: totalMed,
      low_count: totalLow,
      status: successfulRuns.length === selectedTools.length ? 'SUCCESS' : 'PARTIAL_SUCCESS'
    });

    const dbFindings = this.extractDbFindings(scanId, stdResult.standardizedSarif);
    db.saveFindings(dbFindings);

    // Show issue count per tool with low-contrast muted styling
    for (const s of summaries) {
      const highStr = s.high > 0 ? pc.dim(pc.red(String(s.high))) : pc.dim('0');
      const medStr = s.medium > 0 ? pc.dim(pc.yellow(String(s.medium))) : pc.dim('0');
      const lowStr = s.low > 0 ? pc.dim(pc.blue(String(s.low))) : pc.dim('0');
      console.log(`${pc.gray(s.tool)} - ${pc.dim('high')} ${highStr}, ${pc.dim('medium')} ${medStr}, ${pc.dim('low')} ${lowStr}`);
    }

    // Display standard tabular summary
    console.log(renderScanSummaryTable(summaries));
  }

  private extractSummariesFromSarif(sarif: SarifReport): ToolSummary[] {
    const map = new Map<string, { high: number; medium: number; low: number; total: number }>();

    for (const run of sarif.runs || []) {
      const toolName = run.tool?.driver?.name || 'Unknown Tool';
      if (!map.has(toolName)) {
        map.set(toolName, { high: 0, medium: 0, low: 0, total: 0 });
      }
      const counts = map.get(toolName)!;

      for (const res of run.results || []) {
        counts.total++;
        const lvl = (res.level || '').toLowerCase();
        const origLvl = String(res.properties?.originalLevel || '').toLowerCase();

        if (lvl === 'error' || origLvl === 'high' || origLvl === 'critical') {
          counts.high++;
        } else if (lvl === 'warning' || origLvl === 'medium' || origLvl === 'moderate') {
          counts.medium++;
        } else {
          counts.low++;
        }
      }
    }

    return Array.from(map.entries()).map(([tool, c]) => ({
      tool,
      status: 'SUCCESS',
      high: c.high,
      medium: c.medium,
      low: c.low,
      total: c.total
    }));
  }

  private extractDbFindings(scanId: string, sarif: SarifReport) {
    const list = [];
    for (const run of sarif.runs || []) {
      const toolName = run.tool?.driver?.name || 'Unknown';
      for (const res of run.results || []) {
        const ruleId = res.ruleId || 'N/A';
        const msg = res.message?.text || '';
        const level = (res.level || 'warning').toUpperCase();

        let file = 'unknown';
        let line = 1;
        const loc = res.locations?.[0]?.physicalLocation;
        if (loc?.artifactLocation?.uri) {
          file = loc.artifactLocation.uri;
        }
        if (loc?.region?.startLine) {
          line = loc.region.startLine;
        }

        list.push({
          scan_id: scanId,
          tool_name: toolName,
          rule_id: ruleId,
          severity: level,
          message: msg,
          file_path: file,
          start_line: line,
          raw_json: JSON.stringify(res)
        });
      }
    }
    return list;
  }
}
