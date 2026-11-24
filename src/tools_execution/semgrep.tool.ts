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
    // Run semgrep with sarif output and disabled metrics/version-check
    const cmd = `"${semgrepCmd}" scan --sarif --output "${tempOut}" --metrics=off --disable-version-check --quiet "${targetPath}"`;

    try {
      execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 180000 });
    } catch {
      // Retry with auto config if needed
      try {
        const fallbackCmd = `"${semgrepCmd}" scan --config auto --sarif --output "${tempOut}" --metrics=off --disable-version-check --quiet "${targetPath}"`;
        execSync(fallbackCmd, { stdio: 'pipe', encoding: 'utf8', timeout: 180000 });
      } catch (cmdErr: unknown) {
        if (!fs.existsSync(tempOut) || fs.statSync(tempOut).size === 0) {
          throw cmdErr;
        }
      }
    }

    let sarifData: SarifReport;
    if (fs.existsSync(tempOut)) {
      const content = fs.readFileSync(tempOut, 'utf8');
      sarifData = JSON.parse(content);
      fs.unlinkSync(tempOut);
    } else {
      throw new Error('Semgrep produced no SARIF output');
    }

    writeJsonFile(outputFile, sarifData);

    return {
      tool: 'Semgrep',
      success: true,
      sarif: sarifData,
      outputFilePath: outputFile
    };
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
