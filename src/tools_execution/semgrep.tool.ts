import { execSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { writeJsonFile } from '../utils/file.utils.js';
import type { SarifReport, ToolExecutionResult } from './trivy.tool.js';

/**
 * Execute Semgrep scanner in SARIF format on the target repository
 */
export async function runSemgrep(
  targetPath: string,
  resultDir = path.resolve(process.cwd(), 'src', 'tools_result')
): Promise<ToolExecutionResult> {
  const outputFile = path.join(resultDir, 'semgrep_result.sarif.json');
  const semgrepCmd = process.env.SEMGREP_PATH || 'semgrep';

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    const tempOut = path.join(resultDir, 'temp_semgrep.sarif');
    if (fs.existsSync(tempOut)) {
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
    }

    const isOutputFileValid = (): boolean => {
      if (!fs.existsSync(tempOut) || fs.statSync(tempOut).size === 0) return false;
      try {
        const parsed = JSON.parse(fs.readFileSync(tempOut, 'utf8'));
        return Array.isArray(parsed?.runs);
      } catch {
        return false;
      }
    };

    let executed = false;

    // Strategy 1: Run with auto config (Do NOT use --metrics=off as semgrep prohibits it with auto config)
    try {
      const cmd = `"${semgrepCmd}" scan --config auto --sarif --output "${tempOut}" --quiet "${targetPath}"`;
      execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 300000 });
      executed = isOutputFileValid();
    } catch {
      // Semgrep returns exit code 1 when vulnerabilities/findings exist
      executed = isOutputFileValid();
    }

    // Strategy 2: Fallback to standard community rules (p/default)
    if (!executed) {
      try {
        const cmd = `"${semgrepCmd}" scan --config p/default --sarif --output "${tempOut}" --quiet "${targetPath}"`;
        execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 300000 });
        executed = isOutputFileValid();
      } catch {
        executed = isOutputFileValid();
      }
    }

    // Strategy 3: Fallback without explicit config flag
    if (!executed) {
      try {
        const cmd = `"${semgrepCmd}" scan --sarif --output "${tempOut}" --quiet "${targetPath}"`;
        execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 300000 });
        executed = isOutputFileValid();
      } catch {
        executed = isOutputFileValid();
      }
    }

    if (executed && fs.existsSync(tempOut)) {
      const content = fs.readFileSync(tempOut, 'utf8');
      const sarifData: SarifReport = JSON.parse(content);
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }

      writeJsonFile(outputFile, sarifData);
      return {
        tool: 'Semgrep',
        success: true,
        sarif: sarifData,
        outputFilePath: outputFile
      };
    } else {
      throw new Error('Semgrep produced no SARIF output');
    }
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
