# Multi-Tool Security Audit CLI (TypeScript & SARIF 2.1.0)

A robust, enterprise-grade Security Auditing CLI and Backend written in TypeScript. It coordinates security scanners (**Aqua Security Trivy**, **Semgrep SAST**, and **Gitleaks**), normalizes all findings into the OASIS SARIF 2.1.0 standard with **0% data loss**, verifies UTF-8 BOM encoding, persists results into a SQLite database, and presents consistent tabular reports via an interactive terminal frontend.

---

## 📁 Project Architecture

```
EPAM/
├── .env                                  # Environment and tool configurations
├── .gitignore                            # Git ignore definitions
├── package.json                          # Dependencies and npm scripts
├── tsconfig.json                         # TypeScript configuration
├── README.md                             # Documentation
│
└── src/
    ├── index.ts                          # Main Application Entry Point & DB bootstrap
    ├── server.ts                         # Backend logical service initialization
    │
    ├── cli/                              # Frontend CLI layer
    │   ├── cli.ts                        # Interactive Readline REPL & single-command runner
    │   └── navbar.ts                     # Fixed Hintline Navigation Bar component
    │
    ├── controller/
    │   └── commandController.ts          # Command routing, argument validation & execution
    │
    ├── router/
    │   └── commandRouter.ts              # Command dispatcher route to controller
    │
    ├── db/
    │   └── connection.ts                 # Database service (SQLite / JSON persistence)
    │
    ├── tools_execution/                  # Individual security tool runners
    │   ├── trivy.tool.ts                 # Aqua Security Trivy (Vulnerabilities/Misconfigs)
    │   ├── semgrep.tool.ts               # Semgrep SAST scanner
    │   └── gitleaks.tool.ts              # Gitleaks secrets & token detector
    │
    ├── tools_result/                     # Individual tool results
    │   ├── trivy_result.sarif.json       # Trivy individual output (SARIF)
    │   ├── semgrep_result.sarif.json     # Semgrep individual output (SARIF)
    │   ├── gitleaks_result.sarif.json    # Gitleaks individual output (SARIF)
    │   └── combined_result/              # Aggregated outputs
    │       └── combined_result.sarif.json
    │
    ├── validator/
    │   ├── sarif_standardization.ts      # Canonical SARIF 2.1.0 transformer (0% data loss)
    │   ├── sarif_validation.ts           # Schema integrity & UTF-8 BOM verifier
    │   └── nonnormalized_result/         # Final validated and BOM-encoded artifact
    │       └── nonnormalized_result.sarif.json
    │
    └── utils/
        ├── file.utils.ts                 # Safe I/O, UTF-8 BOM encoding & decoding
        ├── logger.utils.ts               # Color-coded logging utilities
        ├── table.utils.ts                # Tabular rendering (cli-table3)
        └── validator.utils.ts            # Command, argument & path verification
```

---

## 🚀 Installation & Prerequisites

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment (`.env`)
```ini
PORT=5000
NODE_ENV=development
DB_PATH=./data/security_scanner.db

# Executable paths or binary names in PATH
TRIVY_PATH=trivy
SEMGREP_PATH=semgrep
GITLEAKS_PATH=gitleaks

# Directories
TOOLS_RESULT_DIR=./src/tools_result
COMBINED_RESULT_DIR=./src/tools_result/combined_result
VALIDATOR_DIR=./src/validator
NONNORMALIZED_DIR=./src/validator/nonnormalized_result
EXPORTS_DIR=./exports
```

### 3. Build Project
```bash
npm run build
```

---

## 💻 Running the Application

### Interactive CLI Mode
```bash
npm start
```

### Single Command Execution (Scripting Mode)
```bash
npm start -- /scan ./sample_repo
npm start -- /result
npm start -- /findings
npm start -- /tools
npm start -- /export ./my-reports
npm start -- /help
```

---

## 📌 Available Commands

| Command | Description |
| :--- | :--- |
| `/help` | Displays the help menu with usage descriptions and examples. |
| `/scan <path>` | Prompts for tools selection, runs Trivy, Semgrep, and Gitleaks, standardizes & validates SARIF, and outputs severity totals. |
| `/tools` | Shows installation status, detected executable paths, and versions for all supported tools. |
| `/result` | Displays the persistent tabular summary from the latest scan stored in `combined_result.sarif.json`. |
| `/findings` | Displays a detailed table of findings (Rule ID, Severity, File Location, Message). |
| `/export [path]` | Exports the latest scan SARIF report (with UTF-8 BOM) to the system. |
| `/clear` | Smoothly slides up the terminal screen to simulate a fresh display while preserving scrollback history. |
| `/quit` | Gracefully closes database connections and exits the application. |

---

## 🛡️ SARIF 2.1.0 Standardization & Integrity Validation

1. **Standardization Pipeline (`sarif_standardization.ts`)**:
   - Converts disparate tool outputs into strict OASIS SARIF 2.1.0 format.
   - Preserves 100% of the vulnerability text, file paths, line numbers, and rule metadata.
2. **Validation Pipeline (`sarif_validation.ts`)**:
   - Validates that the number of findings matches the raw outputs exactly (0% loss guarantee).
   - Writes the file with the **UTF-8 BOM** header (`\uFEFF` / `0xEF, 0xBB, 0xBF`).
   - Persists the validated standard file into `src/validator/nonnormalized_result/nonnormalized_result.sarif.json`.

---

## 🗄️ Database Schema

The SQLite database (`data/security_scanner.db`) tracks:
- **`scans`**: `id`, `target_path`, `tools_used`, `timestamp`, `total_findings`, `high_count`, `medium_count`, `low_count`, `status`.
- **`findings`**: `id`, `scan_id`, `tool_name`, `rule_id`, `severity`, `message`, `file_path`, `start_line`, `raw_json`.
