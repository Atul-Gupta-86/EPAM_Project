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

    // Run standard semgrep scan with --sarif output
    const cmd = `"${semgrepCmd}" scan --sarif --output "${tempOut}" "${targetPath}"`;

    try {
      execSync(cmd, {
        stdio: 'pipe',
        maxBuffer: 50 * 1024 * 1024,
        timeout: 180000
      });
    } catch {
      // Semgrep returns non-zero when vulnerabilities/findings exist, which is normal
    }

    if (fs.existsSync(tempOut) && fs.statSync(tempOut).size > 0) {
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
