import { execSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { writeJsonFile } from '../utils/file.utils.js';
import type { SarifReport, ToolExecutionResult } from './trivy.tool.js';

/**
 * Execute Gitleaks scanner in SARIF format on the target repository
 */
export async function runGitleaks(
  targetPath: string,
  resultDir = path.resolve(process.cwd(), 'src', 'tools_result')
): Promise<ToolExecutionResult> {
  const outputFile = path.join(resultDir, 'gitleaks_result.sarif.json');
  const gitleaksCmd = process.env.GITLEAKS_PATH || 'gitleaks';

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    const tempOut = path.join(resultDir, 'temp_gitleaks.sarif');
    // Gitleaks detect --source <path> --report-format sarif --report-path <file> --no-git
    const isGitRepo = fs.existsSync(path.join(targetPath, '.git'));
    const gitFlag = isGitRepo ? '' : '--no-git';
    const cmd = `"${gitleaksCmd}" detect --source "${targetPath}" --report-format sarif --report-path "${tempOut}" ${gitFlag} --exit-code 0`;

    try {
      execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 180000 });
    } catch (cmdErr: unknown) {
      if (!fs.existsSync(tempOut) || fs.statSync(tempOut).size === 0) {
        throw cmdErr;
      }
    }

    let sarifData: SarifReport;
    if (fs.existsSync(tempOut)) {
      const content = fs.readFileSync(tempOut, 'utf8');
      sarifData = JSON.parse(content);
      fs.unlinkSync(tempOut);
    } else {
      throw new Error('Gitleaks produced no SARIF output');
    }

    writeJsonFile(outputFile, sarifData);

    return {
      tool: 'Gitleaks',
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
              name: 'Gitleaks',
              version: 'unknown',
              informationUri: 'https://github.com/gitleaks/gitleaks'
            }
          },
          results: []
        }
      ]
    };
    writeJsonFile(outputFile, fallbackSarif);
    return {
      tool: 'Gitleaks',
      success: false,
      sarif: fallbackSarif,
      outputFilePath: outputFile,
      error: errorMsg
    };
  }
}
