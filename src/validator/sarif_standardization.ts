import path from 'node:path';
import { readJsonFile, writeJsonFile, ensureDir, sanitizeUnicode } from '../utils/file.utils.js';
import type { SarifReport, SarifRun } from '../tools_execution/trivy.tool.js';

export interface StandardizationResult {
  success: boolean;
  standardizedSarif: SarifReport;
  originalCount: number;
  standardizedCount: number;
  outputFilePath: string;
}

/**
 * Standardize SARIF report to canonical SARIF 2.1.0 without mutating underlying vulnerability data.
 * Adheres strictly to OASIS Standard SARIF 2.1.0 and cleanses broken replacement characters.
 */
export function standardizeSarif(
  combinedSarifPath: string,
  outputPath?: string
): StandardizationResult {
  const originalSarif = readJsonFile<SarifReport>(combinedSarifPath);
  const targetOutput = outputPath || combinedSarifPath;

  let totalOriginalResults = 0;
  for (const run of originalSarif.runs || []) {
    totalOriginalResults += run.results ? run.results.length : 0;
  }

  // Canonical SARIF 2.1.0 standard wrapper
  const standardized: SarifReport = {
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: []
  };

  for (const rawRun of originalSarif.runs || []) {
    const driverName = rawRun.tool?.driver?.name || 'Unknown Tool';
    const driverVersion = rawRun.tool?.driver?.version || '1.0.0';
    const informationUri = rawRun.tool?.driver?.informationUri || 'https://oasis-open.github.io/sarif-spec/';

    const standardizedRun: SarifRun = {
      tool: {
        driver: {
          name: driverName,
          version: driverVersion,
          informationUri,
          rules: rawRun.tool?.driver?.rules ? JSON.parse(JSON.stringify(rawRun.tool.driver.rules)) : []
        }
      },
      results: []
    };

    for (const res of rawRun.results || []) {
      // Retain exact ruleId & message, cleansed of broken diamond characters
      const rawRuleId = res.ruleId || 'UNKNOWN_RULE';
      const ruleId = sanitizeUnicode(rawRuleId);

      const rawMsg = typeof res.message?.text === 'string' ? res.message.text : JSON.stringify(res.message);
      const messageText = sanitizeUnicode(rawMsg);

      // Map level compliant with SARIF 2.1.0 while preserving exact original level in properties
      let level = res.level ? String(res.level).toLowerCase() : 'warning';
      if (!['error', 'warning', 'note', 'none'].includes(level)) {
        if (level === 'critical' || level === 'high') {
          level = 'error';
        } else if (level === 'medium' || level === 'moderate') {
          level = 'warning';
        } else if (level === 'low') {
          level = 'note';
        } else {
          level = 'none';
        }
      }

      // Preserve full locations
      const locations = res.locations ? JSON.parse(JSON.stringify(res.locations)) : [
        {
          physicalLocation: {
            artifactLocation: { uri: 'unknown' },
            region: { startLine: 1, startColumn: 1 }
          }
        }
      ];

      // Deep copy existing properties and preserve original attributes intact
      const properties: Record<string, unknown> = {
        ...(res.properties ? JSON.parse(JSON.stringify(res.properties)) : {}),
        originalTool: driverName,
        originalLevel: res.level || level
      };

      standardizedRun.results.push({
        ruleId,
        level,
        message: { text: messageText },
        locations,
        properties
      });
    }

    standardized.runs.push(standardizedRun);
  }

  let totalStandardizedResults = 0;
  for (const run of standardized.runs) {
    totalStandardizedResults += run.results.length;
  }

  ensureDir(path.dirname(targetOutput));
  writeJsonFile(targetOutput, standardized);

  return {
    success: totalOriginalResults === totalStandardizedResults,
    standardizedSarif: standardized,
    originalCount: totalOriginalResults,
    standardizedCount: totalStandardizedResults,
    outputFilePath: targetOutput
  };
}
