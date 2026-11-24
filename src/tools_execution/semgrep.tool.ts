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

    // Flags to prevent hanging:
    // - Output directly to file to prevent Node pipe buffer overflow/deadlock
    // - Exclude heavy directories (node_modules, .git, dist, build)
    // - Use single-threaded job execution to prevent Windows socket deadlocks
    // - Timeout after 60 seconds
    const commonExcludes = '--exclude node_modules --exclude .git --exclude dist --exclude build';
    const commonFlags = `--sarif --output "${tempOut}" --jobs 1 ${commonExcludes}`;

    let executed = false;

    // Strategy 1: Fast community security rules (p/default) - avoids registry login prompts/hangs
    try {
      const cmd = `"${semgrepCmd}" scan --config p/default ${commonFlags} "${targetPath}"`;
      execSync(cmd, { stdio: ['ignore', 'ignore', 'ignore'], timeout: 60000 });
      executed = isOutputFileValid();
    } catch {
      // Semgrep exits with 1 when findings are detected
      executed = isOutputFileValid();
    }

    // Strategy 2: Auto config fallback
    if (!executed) {
      try {
        const cmd = `"${semgrepCmd}" scan --config auto ${commonFlags} "${targetPath}"`;
        execSync(cmd, { stdio: ['ignore', 'ignore', 'ignore'], timeout: 60000 });
        executed = isOutputFileValid();
      } catch {
        executed = isOutputFileValid();
      }
    }

    // Strategy 3: Local/built-in rules fallback
    if (!executed) {
      try {
        const cmd = `"${semgrepCmd}" scan ${commonFlags} "${targetPath}"`;
        execSync(cmd, { stdio: ['ignore', 'ignore', 'ignore'], timeout: 60000 });
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
      throw new Error('Semgrep produced no SARIF output or timed out');
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
