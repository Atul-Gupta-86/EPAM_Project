import path from 'node:path';
import fs from 'node:fs';
import { ensureDir } from '../utils/file.utils.js';

export interface ScanRecord {
  id: string;
  target_path: string;
  tools_used: string;
  timestamp: string;
  total_findings: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  status: string;
}

export interface FindingRecord {
  id?: number;
  scan_id: string;
  tool_name: string;
  rule_id: string;
  severity: string;
  message: string;
  file_path: string;
  start_line: number;
  raw_json?: string;
}

export interface IDatabaseService {
  saveScan(scan: ScanRecord): void;
  getLatestScan(): ScanRecord | null;
  getScanById(id: string): ScanRecord | null;
  saveFindings(findings: FindingRecord[]): void;
  getFindings(scanId: string): FindingRecord[];
  close(): void;
}

/**
 * SQLite implementation using Node.js built-in DatabaseSync
 */
class SqliteDatabaseService implements IDatabaseService {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private db: any;

  constructor(dbPath: string) {
    ensureDir(path.dirname(dbPath));
    // Dynamically require node:sqlite
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { DatabaseSync } = require('node:sqlite');
    this.db = new DatabaseSync(dbPath);
    this.initTables();
  }

  private initTables(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target_path TEXT NOT NULL,
        tools_used TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        total_findings INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        medium_count INTEGER NOT NULL,
        low_count INTEGER NOT NULL,
        status TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        file_path TEXT NOT NULL,
        start_line INTEGER NOT NULL,
        raw_json TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    `);
  }

  saveScan(scan: ScanRecord): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO scans (id, target_path, tools_used, timestamp, total_findings, high_count, medium_count, low_count, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      scan.id,
      scan.target_path,
      scan.tools_used,
      scan.timestamp,
      scan.total_findings,
      scan.high_count,
      scan.medium_count,
      scan.low_count,
      scan.status
    );
  }

  getLatestScan(): ScanRecord | null {
    const stmt = this.db.prepare(`
      SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1
    `);
    const row = stmt.get();
    return (row as ScanRecord) || null;
  }

  getScanById(id: string): ScanRecord | null {
    const stmt = this.db.prepare(`
      SELECT * FROM scans WHERE id = ?
    `);
    const row = stmt.get(id);
    return (row as ScanRecord) || null;
  }

  saveFindings(findings: FindingRecord[]): void {
    if (findings.length === 0) return;
    const stmt = this.db.prepare(`
      INSERT INTO findings (scan_id, tool_name, rule_id, severity, message, file_path, start_line, raw_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const f of findings) {
      stmt.run(
        f.scan_id,
        f.tool_name,
        f.rule_id,
        f.severity,
        f.message,
        f.file_path,
        f.start_line,
        f.raw_json || ''
      );
    }
  }

  getFindings(scanId: string): FindingRecord[] {
    const stmt = this.db.prepare(`
      SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC
    `);
    return stmt.all(scanId) as FindingRecord[];
  }

  close(): void {
    if (this.db) {
      this.db.close();
    }
  }
}

/**
 * Fallback JSON store in case node:sqlite is restricted or not supported in some environment
 */
class JsonFileDatabaseService implements IDatabaseService {
  private dbPath: string;
  private scans: ScanRecord[] = [];
  private findings: FindingRecord[] = [];

  constructor(filePath: string) {
    this.dbPath = filePath.endsWith('.json') ? filePath : filePath + '.json';
    ensureDir(path.dirname(this.dbPath));
    this.load();
  }

  private load(): void {
    if (fs.existsSync(this.dbPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(this.dbPath, 'utf8'));
        this.scans = data.scans || [];
        this.findings = data.findings || [];
      } catch {
        this.scans = [];
        this.findings = [];
      }
    }
  }

  private persist(): void {
    fs.writeFileSync(this.dbPath, JSON.stringify({ scans: this.scans, findings: this.findings }, null, 2), 'utf8');
  }

  saveScan(scan: ScanRecord): void {
    const idx = this.scans.findIndex(s => s.id === scan.id);
    if (idx >= 0) {
      this.scans[idx] = scan;
    } else {
      this.scans.unshift(scan);
    }
    this.persist();
  }

  getLatestScan(): ScanRecord | null {
    return this.scans.length > 0 ? this.scans[0] : null;
  }

  getScanById(id: string): ScanRecord | null {
    return this.scans.find(s => s.id === id) || null;
  }

  saveFindings(newFindings: FindingRecord[]): void {
    this.findings.push(...newFindings);
    this.persist();
  }

  getFindings(scanId: string): FindingRecord[] {
    return this.findings.filter(f => f.scan_id === scanId);
  }

  close(): void {
    this.persist();
  }
}

let dbInstance: IDatabaseService | null = null;

export function initDatabase(dbPath?: string): IDatabaseService {
  if (dbInstance) return dbInstance;

  const targetPath = dbPath || process.env.DB_PATH || path.resolve(process.cwd(), 'data', 'security_scanner.db');
  try {
    dbInstance = new SqliteDatabaseService(targetPath);
    return dbInstance;
  } catch (err) {
    console.warn('Fallback to JSON file database service:', err);
    dbInstance = new JsonFileDatabaseService(targetPath);
    return dbInstance;
  }
}

export function getDatabase(): IDatabaseService {
  if (!dbInstance) {
    return initDatabase();
  }
  return dbInstance;
}
