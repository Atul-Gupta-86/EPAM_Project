import { execSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { writeJsonFile } from '../utils/file.utils.js';

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      informationUri?: string;
      rules?: Array<{
        id: string;
        name?: string;
        shortDescription?: { text: string };
        fullDescription?: { text: string };
        defaultConfiguration?: { level?: string };
        properties?: Record<string, unknown>;
      }>;
    };
  };
  results: Array<{
    ruleId: string;
    level?: string;
    message: { text: string };
    locations?: Array<{
      physicalLocation?: {
        artifactLocation?: { uri: string };
        region?: { startLine?: number; startColumn?: number };
      };
    }>;
    properties?: Record<string, unknown>;
  }>;
}

export interface SarifReport {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

export interface ToolExecutionResult {
  tool: string;
  success: boolean;
  sarif: SarifReport;
  outputFilePath: string;
  error?: string;
}

/**
 * Execute Trivy scanner in SARIF format on the target repository
 */
export async function runTrivy(
  targetPath: string,
  resultDir = path.resolve(process.cwd(), 'src', 'tools_result')
): Promise<ToolExecutionResult> {
  const outputFile = path.join(resultDir, 'trivy_result.sarif.json');
  const trivyCmd = process.env.TRIVY_PATH || 'trivy';

  try {
    // Trivy fs --format sarif --output <temp> <path>
    const tempOut = path.join(resultDir, 'temp_trivy.sarif');
    // Ensure dir exists
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    // Try executing trivy with offline/skip-db-update flags for reliability
    let cmd = `"${trivyCmd}" fs --format sarif --skip-db-update --offline-scan --output "${tempOut}" "${targetPath}"`;
    try {
      execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 180000 });
    } catch {
      // If offline scan fails due to missing DB, scan misconfigurations and secrets
      try {
        cmd = `"${trivyCmd}" fs --scanners misconfig,secret --format sarif --output "${tempOut}" "${targetPath}"`;
        execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 180000 });
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
      throw new Error('Trivy produced no SARIF output');
    }

    // Save individual tool result
    writeJsonFile(outputFile, sarifData);

    return {
      tool: 'Trivy',
      success: true,
      sarif: sarifData,
      outputFilePath: outputFile
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    // If trivy failed or not installed, create valid empty/fallback SARIF for reporting
    const fallbackSarif: SarifReport = {
      $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Trivy',
              version: 'unknown',
              informationUri: 'https://github.com/aquasecurity/trivy'
            }
          },
          results: []
        }
      ]
    };
    writeJsonFile(outputFile, fallbackSarif);
    return {
      tool: 'Trivy',
      success: false,
      sarif: fallbackSarif,
      outputFilePath: outputFile,
      error: errorMsg
    };
  }
}
