  import { execSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { writeJsonFile } from '../utils/file.utils.js';
import type { SarifReport, ToolExecutionResult } from './trivy.tool.js';

/**
 * Execute Semgrep scanner in SARIF format directly into the actual semgrep result file
 */
export async function runSemgrep(
  targetPath: string,
  resultDir = path.resolve(process.cwd(), 'src', 'tools_result')
): Promise<ToolExecutionResult> {
  const outputFile = path.join(resultDir, 'semgrep_result.sarif.json');
  const semgrepCmd = process.env.SEMGREP_PATH || 'semgrep';

  // Remove any legacy temp file if it exists
  const legacyTemp = path.join(resultDir, 'temp_semgrep.sarif');
  if (fs.existsSync(legacyTemp)) {
    try { fs.unlinkSync(legacyTemp); } catch { /* ignore */ }
  }

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    // Direct output to semgrep_result.sarif.json (no temp files)
    const cmd = `"${semgrepCmd}" scan --sarif --output "${outputFile}" "${targetPath}"`;

    let stderrOutput = '';
    try {
      execSync(cmd, {
        // stdin: ignore, stdout: ignore (prevents pipe deadlock from MBs of progress output), stderr: pipe (captures actual errors)
        stdio: ['ignore', 'ignore', 'pipe'],
        maxBuffer: 50 * 1024 * 1024,
        timeout: 300000 // 5 minutes timeout for large codebases
      });
    } catch (cmdErr: unknown) {
      if (cmdErr && typeof cmdErr === 'object' && 'stderr' in cmdErr) {
        stderrOutput = String((cmdErr as { stderr?: Buffer }).stderr || '').trim();
      }
    }

    // Validate that actual output file was generated and contains valid SARIF JSON
    if (fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0) {
      const content = fs.readFileSync(outputFile, 'utf8');
      const sarifData: SarifReport = JSON.parse(content);

      if (Array.isArray(sarifData?.runs)) {
        return {
          tool: 'Semgrep',
          success: true,
          sarif: sarifData,
          outputFilePath: outputFile
        };
      }
    }

    // If output file is missing or empty, throw error with captured stderr
    throw new Error(stderrOutput || 'Semgrep did not produce valid SARIF output');
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const fallbackSarif: SarifReport = {
      $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Semgrep',
              version: 'unknown',
              informationUri: 'https://github.com/semgrep/semgrep'
            }
          },
          results: []
        }
      ]
    };
    writeJsonFile(outputFile, fallbackSarif);
    return {
      tool: 'Semgrep',
      success: false,
      sarif: fallbackSarif,
      outputFilePath: outputFile,
      error: errorMsg
    };
  }
}
