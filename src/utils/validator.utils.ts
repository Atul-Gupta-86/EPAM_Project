import fs from 'node:fs';
import path from 'node:path';

export const VALID_COMMANDS = [
  'help',
  'scan',
  'tools',
  'export',
  'clear',
  'result',
  'findings',
  'quit',
  'exit'
] as const;

export type ValidCommandType = typeof VALID_COMMANDS[number];

/**
 * Normalize command string, e.g., "/help" -> "help"
 */
export function normalizeCommand(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('/')) {
    return trimmed.slice(1).trim().toLowerCase();
  }
  return trimmed.toLowerCase();
}

/**
 * Check if the command verb is recognized
 */
export function isValidCommand(cmd: string): boolean {
  const normalized = normalizeCommand(cmd.split(/\s+/)[0] || '');
  return (VALID_COMMANDS as readonly string[]).includes(normalized);
}

/**
 * Validate repository/directory path existence
 */
export function validateRepoPath(targetPath: string): { valid: boolean; resolvedPath?: string; error?: string } {
  if (!targetPath || targetPath.trim() === '') {
    return { valid: false, error: 'Repository path is required. Usage: /scan <path>' };
  }

  const resolved = path.resolve(process.cwd(), targetPath.trim());
  if (!fs.existsSync(resolved)) {
    return { valid: false, error: `Directory or path does not exist: "${resolved}"` };
  }

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory() && !stat.isFile()) {
    return { valid: false, error: `Target path must be a valid directory or file: "${resolved}"` };
  }

  return { valid: true, resolvedPath: resolved };
}

/**
 * Validate export destination path
 */
export function validateExportPath(destPath?: string): { valid: boolean; resolvedPath: string } {
  if (!destPath || destPath.trim() === '') {
    const defaultDir = path.resolve(process.cwd(), 'exports');
    return { valid: true, resolvedPath: defaultDir };
  }
  const resolved = path.resolve(process.cwd(), destPath.trim());
  return { valid: true, resolvedPath: resolved };
}
