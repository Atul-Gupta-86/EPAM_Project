import fs from 'node:fs';
import path from 'node:path';

/**
 * UTF-8 BOM constant (\uFEFF)
 * Byte sequence: 0xEF, 0xBB, 0xBF
 */
export const UTF8_BOM = '\uFEFF';

/**
 * Ensure a directory exists synchronously
 */
export function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

/**
 * Write file with standard UTF-8 encoding
 */
export function writeJsonFile(filePath: string, data: unknown): void {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

/**
 * Write file with UTF-8 BOM encoding
 */
export function writeJsonFileWithBOM(filePath: string, data: unknown): void {
  ensureDir(path.dirname(filePath));
  const content = UTF8_BOM + JSON.stringify(data, null, 2);
  fs.writeFileSync(filePath, content, 'utf8');
}

/**
 * Read JSON file, stripping UTF-8 BOM if present
 */
export function readJsonFile<T = unknown>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File does not exist: ${filePath}`);
  }
  let content = fs.readFileSync(filePath, 'utf8');
  if (content.startsWith(UTF8_BOM)) {
    content = content.slice(1);
  }
  return JSON.parse(content) as T;
}

/**
 * Check if a file starts with UTF-8 BOM
 */
export function hasUtf8Bom(filePath: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  const buffer = Buffer.alloc(3);
  const fd = fs.openSync(filePath, 'r');
  try {
    fs.readSync(fd, buffer, 0, 3, 0);
    return buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Copy file safely
 */
export function copyFileSafely(src: string, dest: string): void {
  ensureDir(path.dirname(dest));
  fs.copyFileSync(src, dest);
}

/**
 * Sanitize text to remove or replace broken Unicode, replacement diamonds (\uFFFD),
 * emojis, and non-standard symbols that cause rendering issues in Windows consoles.
 */
export function sanitizeUnicode(text: string): string {
  if (!text) return '';
  return text
    // Remove the replacement character / diamond symbol (\uFFFD)
    .replace(/\uFFFD/g, '')
    // Normalize smart/curly quotes to ASCII quotes
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    // Normalize dashes and arrows
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\u2192/g, '->')
    .replace(/\u2190/g, '<-')
    // Remove emojis and miscellaneous symbols (U+1F300 to U+1FAFF, U+2600 to U+27BF)
    .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/gu, '')
    // Normalize repeated whitespace
    .replace(/\s+/g, ' ')
    .trim();
}
