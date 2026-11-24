import path from 'node:path';
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import prompts from 'prompts';
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

    // Ensure all required workspace directories exist
    ensureDir(this.ctx.toolsResultDir);
    ensureDir(this.ctx.combinedResultDir);
    ensureDir(this.ctx.validatorDir);
    ensureDir(this.ctx.nonnormalizedDir);
    ensureDir(this.ctx.exportsDir);
  }

  /**
   * Main entry point for command routing
   */
  async handleCommand(input: string): Promise<{ shouldQuit?: boolean }> {
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
        await this.handleScan(args);
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
        logger.info('Exiting Security CLI Scanner. Goodbye!');
        return { shouldQuit: true };

      default:
        // Typo or invalid command: show error and print help menu again
        console.log(renderHelpMenu(true));
        return {};
    }
  }

  /**
   * /help handler
   */
  handleHelp(): void {
    console.log(renderHelpMenu(false));
  }

  /**
   * /tools handler - Check system security tools status
   */
  async handleTools(): Promise<void> {
    logger.info('Inspecting system security scanning tools...');
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
      } catch (err: unknown) {
        if (isFileExists) {
          return { name, installed: true, path: cmd, version: 'Detected (Binary Available)' };
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

  /**
   * /clear handler - Clears the screen by sliding up terminal buffer
   */
  handleClear(): void {
    // Sliding up screen instead of hard reset, preserving user scrollback history
    process.stdout.write('\x1b[2J\x1b[H\n'.repeat(2));
    logger.banner('=== Security Scanner CLI (Console Refreshed) ===');
  }

  /**
   * /result handler - Displays last scan summary in standard tabular format
   */
  handleResult(): void {
    const db = getDatabase();
    const latestScan = db.getLatestScan();
    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');

    if (!fs.existsSync(combinedFile)) {
      logger.warn('No scan results found yet. Run "/scan <repo_path>" to perform your first audit.');
      return;
    }

    try {
      const sarif = readJsonFile<SarifReport>(combinedFile);
      const summaries = this.extractSummariesFromSarif(sarif);

      logger.banner('=== LAST SCAN RESULT (STANDARDIZED TABULAR FORMAT) ===');
      if (latestScan) {
        console.log(pc.dim(`Target: ${latestScan.target_path} | Time: ${latestScan.timestamp} | Status: ${latestScan.status}`));
      }
      console.log(renderScanSummaryTable(summaries));
    } catch (err) {
      logger.error(`Failed to read combined result file: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * /findings handler - Displays granular vulnerability findings table
   */
  handleFindings(): void {
    const db = getDatabase();
    const latestScan = db.getLatestScan();

    if (!latestScan) {
      logger.warn('No scan records found in database. Please run a scan first.');
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

    logger.banner(`=== VULNERABILITY FINDINGS (${findings.length} TOTAL) ===`);
    console.log(renderFindingsTable(rows));
  }

  /**
   * /export handler - Saves/downloads the result file of the last scan
   */
  handleExport(customPath?: string): void {
    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');
    const nonnormalizedFile = path.join(this.ctx.nonnormalizedDir, 'nonnormalized_result.sarif.json');

    const sourceFile = fs.existsSync(nonnormalizedFile) ? nonnormalizedFile : combinedFile;
    if (!fs.existsSync(sourceFile)) {
      logger.warn('No scan result available to export. Run a scan first.');
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
      logger.success(`Scan result successfully exported to: ${pc.bold(destFile)}`);
    } catch (err) {
      logger.error(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * /scan <repo_path> handler
   */
  async handleScan(repoArg: string): Promise<void> {
    // 1. Validate argument
    const validation = validateRepoPath(repoArg);
    if (!validation.valid || !validation.resolvedPath) {
      logger.error(validation.error || 'Invalid repository path');
      console.log(renderHelpMenu(true));
      return;
    }

    const targetPath = validation.resolvedPath;
    logger.info(`Target repository: ${pc.bold(targetPath)}`);

    // 2. Tool selection: Interactive if TTY, or default to all configured tools
    let selectedTools: string[] = [];
    if (process.stdin.isTTY) {
      try {
        const response = await prompts({
          type: 'multiselect',
          name: 'tools',
          message: 'Select security scanning tools to execute:',
          choices: [
            { title: 'Trivy (Vulnerability & Misconfigurations)', value: 'trivy', selected: true },
            { title: 'Semgrep (Static Code Analysis SAST)', value: 'semgrep', selected: true },
            { title: 'Gitleaks (Secrets & API Keys Detection)', value: 'gitleaks', selected: true }
          ],
          hint: '- Space to select. Return to submit',
          instructions: false
        });
        selectedTools = response.tools || [];
      } catch {
        selectedTools = ['trivy', 'semgrep', 'gitleaks'];
      }
    } else {
      selectedTools = ['trivy', 'semgrep', 'gitleaks'];
    }

    if (selectedTools.length === 0) {
      selectedTools = ['trivy', 'semgrep', 'gitleaks'];
    }

    logger.info(`Starting audit with tools: ${pc.cyan(selectedTools.join(', ').toUpperCase())}...`);

    // 3. Sequential Execution of Tools
    const executionResults: ToolExecutionResult[] = [];
    let hasFatalScanFailure = false;

    for (const toolKey of selectedTools) {
      try {
        if (toolKey === 'trivy') {
          logger.info('Executing Trivy scanner...');
          const res = await runTrivy(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
          if (!res.success && res.error) logger.warn(`Trivy notification: ${res.error}`);
        } else if (toolKey === 'semgrep') {
          logger.info('Executing Semgrep scanner...');
          const res = await runSemgrep(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
          if (!res.success && res.error) logger.warn(`Semgrep notification: ${res.error}`);
        } else if (toolKey === 'gitleaks') {
          logger.info('Executing Gitleaks scanner...');
          const res = await runGitleaks(targetPath, this.ctx.toolsResultDir);
          executionResults.push(res);
          if (!res.success && res.error) logger.warn(`Gitleaks notification: ${res.error}`);
        }
      } catch (err) {
        hasFatalScanFailure = true;
        logger.error(`Critical error running ${toolKey}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Check if scan completely failed
    const successfulRuns = executionResults.filter(r => r.success);
    if (successfulRuns.length === 0 && executionResults.length > 0) {
      logger.failedScan();
      logger.error('All selected tools failed to run successfully on the target repository.');
      return;
    }

    // 4. Combine all tool results into one SARIF document
    const combinedSarif: SarifReport = {
      $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: []
    };

    const individualFiles: string[] = [];
    for (const r of executionResults) {
      individualFiles.push(r.outputFilePath);
      if (r.sarif && Array.isArray(r.sarif.runs)) {
        combinedSarif.runs.push(...r.sarif.runs);
      }
    }

    const combinedFile = path.join(this.ctx.combinedResultDir, 'combined_result.sarif.json');
    writeJsonFile(combinedFile, combinedSarif);
    logger.success(`Combined SARIF results saved to ${combinedFile}`);

    // 5. Sequential Validation Pipeline
    // Step 5a: SARIF 2.1.0 Standardization
    logger.info('Running SARIF 2.1.0 standardization...');
    const stdResult = standardizeSarif(combinedFile);
    if (!stdResult.success) {
      logger.warn('Standardization note: mismatch detected in result counts.');
    } else {
      logger.success(`Standardization complete. ${stdResult.standardizedCount} issues preserved.`);
    }

    // Step 5b: SARIF Validation & Non-normalized storage with UTF-8 BOM
    logger.info('Running SARIF validation and UTF-8 BOM encoding...');
    const valResult = validateAndStoreNonnormalized(
      stdResult.outputFilePath,
      individualFiles,
      this.ctx.nonnormalizedDir
    );

    if (!valResult.isValidSarif) {
      logger.warn(`SARIF validation warnings: ${valResult.details.join('; ')}`);
    }
    if (valResult.hasUtf8Bom) {
      logger.success('UTF-8 BOM formatting verified successfully.');
    }
    if (valResult.zeroDataLoss) {
      logger.success('Data integrity verified: 0% data loss across all tool outputs.');
    }

    // 6. Record scan & findings in Database
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
      status: hasFatalScanFailure ? 'PARTIAL_SUCCESS' : 'SUCCESS'
    });

    // Extract individual findings to save in DB
    const dbFindings = this.extractDbFindings(scanId, stdResult.standardizedSarif);
    db.saveFindings(dbFindings);

    // 7. CLI Output - Severity Counts per Tool
    logger.banner('\n=== SCAN SUMMARY RESULTS ===');
    for (const s of summaries) {
      console.log(
        `• ${pc.bold(s.tool)} -> ${pc.red(`high: ${s.high}`)}, ${pc.yellow(`medium: ${s.medium}`)}, ${pc.blue(`low: ${s.low}`)} (Total: ${pc.magenta(s.total)})`
      );
    }

    console.log('\n' + renderScanSummaryTable(summaries));
    logger.success(`Scan completed! Results stored persistently.`);
  }

  /**
   * Helper to compute tool summaries from SARIF runs
   */
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
        } else if (lvl === 'note' || origLvl === 'low') {
          counts.low++;
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

  /**
   * Helper to extract flat finding records for database persistence
   */
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
