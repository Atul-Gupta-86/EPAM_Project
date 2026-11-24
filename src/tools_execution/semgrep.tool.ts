import { execSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { writeJsonFile, sanitizeUnicode } from '../utils/file.utils.js';
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
  const tempOut = path.join(resultDir, 'temp_semgrep.sarif');

  const execEnv = {
    ...process.env,
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8'
  };

  try {
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }

    if (fs.existsSync(tempOut)) {
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
    }

    // Run semgrep with p/default rules in SARIF format
    const cmd = `"${semgrepCmd}" scan --config p/default --sarif --output "${tempOut}" --quiet "${targetPath}"`;

    try {
      execSync(cmd, { stdio: 'pipe', encoding: 'utf8', timeout: 300000, env: execEnv });
    } catch {
      // Fallback: try auto config if p/default fails
      try {
        const fallbackCmd = `"${semgrepCmd}" scan --config auto --sarif --output "${tempOut}" --quiet "${targetPath}"`;
        execSync(fallbackCmd, { stdio: 'pipe', encoding: 'utf8', timeout: 300000, env: execEnv });
      } catch (cmdErr: unknown) {
        if (!fs.existsSync(tempOut) || fs.statSync(tempOut).size === 0) {
          throw cmdErr;
        }
      }
    }

    if (!fs.existsSync(tempOut) || fs.statSync(tempOut).size === 0) {
      throw new Error('Semgrep produced no SARIF output');
    }

    const content = fs.readFileSync(tempOut, 'utf8');
    const sarifData: SarifReport = JSON.parse(content);
    try { fs.unlinkSync(tempOut); } catch { /* ignore */ }

    // Sanitize any unicode, emojis (such as 💎), and replacement characters from Semgrep SARIF
    if (Array.isArray(sarifData.runs)) {
      for (const run of sarifData.runs) {
        if (run.tool?.driver?.rules) {
          for (const rule of run.tool.driver.rules) {
            if (rule.shortDescription?.text) {
              rule.shortDescription.text = sanitizeUnicode(rule.shortDescription.text);
            }
            if (rule.fullDescription?.text) {
              rule.fullDescription.text = sanitizeUnicode(rule.fullDescription.text);
            }
          }
        }
        if (Array.isArray(run.results)) {
          for (const res of run.results) {
            if (res.message?.text) {
              res.message.text = sanitizeUnicode(res.message.text);
            }
            if (res.ruleId) {
              res.ruleId = sanitizeUnicode(res.ruleId);
            }
          }
        }
      }
    }

    writeJsonFile(outputFile, sarifData);

    return {
      tool: 'Semgrep',
      success: true,
      sarif: sarifData,
      outputFilePath: outputFile
    };
  } catch (err: unknown) {
    if (fs.existsSync(tempOut)) {
      try { fs.unlinkSync(tempOut); } catch { /* ignore */ }
    }
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      tool: 'Semgrep',
      success: false,
      outputFilePath: outputFile,
      error: errorMsg
    };
  }
}
