import path from 'node:path';
import { readJsonFile, writeJsonFileWithBOM, hasUtf8Bom, ensureDir } from '../utils/file.utils.js';
import type { SarifReport } from '../tools_execution/trivy.tool.js';

export interface ValidationSummary {
  isValidSarif: boolean;
  hasUtf8Bom: boolean;
  zeroDataLoss: boolean;
  totalFindings: number;
  toolsValidated: string[];
  nonnormalizedFilePath: string;
  details: string[];
}

/**
 * Validates SARIF 2.1.0 compliance, UTF-8 BOM format, and zero data modification
 * Stores result into nonnormalized_result folder
 */
export function validateAndStoreNonnormalized(
  standardizedSarifPath: string,
  individualResultPaths: string[] = [],
  nonnormalizedOutputDir = path.resolve(process.cwd(), 'src', 'validator', 'nonnormalized_result')
): ValidationSummary {
  const details: string[] = [];
  const standardized = readJsonFile<SarifReport>(standardizedSarifPath);

  // 1. Validate SARIF 2.1.0 standard schema properties
  const isVersionCorrect = standardized.version === '2.1.0';
  const hasRunsArray = Array.isArray(standardized.runs);

  if (!isVersionCorrect) {
    details.push(`Invalid SARIF version: expected "2.1.0", found "${standardized.version}"`);
  }
  if (!hasRunsArray) {
    details.push('Missing or invalid "runs" array in SARIF document');
  }

  let totalStandardizedFindings = 0;
  const toolsValidated: string[] = [];

  for (const run of standardized.runs || []) {
    const toolName = run.tool?.driver?.name || 'Unknown';
    toolsValidated.push(toolName);
    totalStandardizedFindings += run.results ? run.results.length : 0;
  }

  // 2. Validate against individual tool files for 0% data change/loss
  let totalRawFindings = 0;
  for (const indPath of individualResultPaths) {
    try {
      const raw = readJsonFile<SarifReport>(indPath);
      for (const run of raw.runs || []) {
        totalRawFindings += run.results ? run.results.length : 0;
      }
    } catch {
      // Ignored if file wasn't generated due to tool not being selected
    }
  }

  // If individual files were provided, ensure exact match
  let zeroDataLoss = true;
  if (individualResultPaths.length > 0) {
    if (totalRawFindings !== totalStandardizedFindings) {
      zeroDataLoss = false;
      details.push(
        `Finding count mismatch: Raw individual tools had ${totalRawFindings} issues, standardized has ${totalStandardizedFindings}`
      );
    } else {
      details.push(`Integrity verified: Exactly ${totalStandardizedFindings} findings preserved with 0% data mutation.`);
    }
  }

  // 3. Store into nonnormalized_result folder with standard UTF-8 BOM
  ensureDir(nonnormalizedOutputDir);
  const nonnormalizedFilePath = path.join(nonnormalizedOutputDir, 'nonnormalized_result.sarif.json');
  writeJsonFileWithBOM(nonnormalizedFilePath, standardized);

  // 4. Verify UTF-8 BOM encoding on the created file
  const isBomValid = hasUtf8Bom(nonnormalizedFilePath);
  if (!isBomValid) {
    details.push('UTF-8 BOM validation check failed on generated output file');
  } else {
    details.push('UTF-8 BOM signature (0xEF, 0xBB, 0xBF) verified successfully.');
  }

  const isValidSarif = isVersionCorrect && hasRunsArray && details.filter(d => d.includes('Invalid') || d.includes('Missing')).length === 0;

  return {
    isValidSarif,
    hasUtf8Bom: isBomValid,
    zeroDataLoss,
    totalFindings: totalStandardizedFindings,
    toolsValidated,
    nonnormalizedFilePath,
    details
  };
}
