import { spawnSync } from 'node:child_process';
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

  // Ensure any legacy temp file is cleaned up
  const legacyTemp = path.join(resultDir, 'temp_semgrep.sarif');
  if (fs.existsSync(legacyTemp)) {
    try { fs.unlinkSync(legacyTemp); } catch { /* ignore */ }
  }

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    // Execute semgrep using spawnSync with explicit arguments for Windows compatibility
    const semgrepArgs = ['scan', '--sarif', '--output', outputFile, targetPath];

    const result = spawnSync(semgrepCmd, semgrepArgs, {
      encoding: 'utf8',
      shell: true,
      maxBuffer: 50 * 1024 * 1024,
      timeout: 300000 // 5 minutes timeout
    });

    // Validate that actual output file was generated and contains valid SARIF JSON
    if (fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0) {
      try {
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
      } catch (parseErr) {
        throw new Error(`Failed to parse Semgrep SARIF report: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}`);
      }
    }

    // Capture exact failure details from spawnSync
    const errorDetail = result.error?.message || result.stderr || 'Semgrep did not produce a valid SARIF output file';
    throw new Error(errorDetail);
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
