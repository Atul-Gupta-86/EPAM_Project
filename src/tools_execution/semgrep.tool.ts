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
  const semgrepConfig = process.env.SEMGREP_CONFIG || 'p/default';

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    const tempOut = path.join(resultDir, 'temp_semgrep.sarif');
    const tempErr = path.join(resultDir, 'temp_semgrep.err');

    if (fs.existsSync(tempOut)) {
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
    }
    if (fs.existsSync(tempErr)) {
      try { fs.unlinkSync(tempErr); } catch { /* ignore */ }
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

    // Construct robust semgrep execution command
    // Exclude large vendor & build folders that cause extreme slowdowns
    const excludes = '--exclude=node_modules --exclude=.git --exclude=dist --exclude=build --exclude=vendor';
    const cmd = `"${semgrepCmd}" scan --config "${semgrepConfig}" --sarif --output "${tempOut}" --no-git ${excludes} "${targetPath}"`;

    let stderrOutput = '';
    try {
      execSync(cmd, {
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: 50 * 1024 * 1024,
        timeout: 180000 // 3 minutes timeout
      });
    } catch (err: unknown) {
      // Semgrep returns exit code 1 when findings are present; check if valid SARIF was generated
      if (err && typeof err === 'object' && 'stderr' in err) {
        stderrOutput = String((err as { stderr?: Buffer }).stderr || '').trim();
      }
    }

    if (isOutputFileValid()) {
      const content = fs.readFileSync(tempOut, 'utf8');
      const sarifData: SarifReport = JSON.parse(content);
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
      try { if (fs.existsSync(tempErr)) fs.unlinkSync(tempErr); } catch { /* ignore */ }

      writeJsonFile(outputFile, sarifData);
      return {
        tool: 'Semgrep',
        success: true,
        sarif: sarifData,
        outputFilePath: outputFile
      };
    } else {
      // Clean up empty temp file
      if (fs.existsSync(tempOut)) {
        try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
      }

      const failureReason = stderrOutput || 'Semgrep did not produce a valid SARIF output file (check network connection or rule configuration)';
      throw new Error(failureReason);
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
