# TerminalGuard+

Real-time secret detection middleware for MCP (Model Context Protocol) based AI workflows. Intercepts tool calls before execution and blocks commands containing credentials, API keys, passwords and other sensitive data.

## How It Works

TerminalGuard+ sits between the MCP client (e.g. Claude Desktop) and MCP servers as a transparent proxy. When an AI agent issues a tool call, the middleware:

1. Intercepts the JSON-RPC message
2. Extracts and serializes the arguments
3. Runs them through a 4-stage cascade detector
4. Blocks if a secret is found, forwards if safe

No changes to the MCP protocol or existing setup are needed.

## Cascade Architecture

| Level | Detector | Purpose |
|-------|----------|---------|
| L1 | BiLSTM | Contextual classifier. Handles ~77% of traffic with early exit. |
| L2 | SVM (TF-IDF char n-grams) | Lexical texture analysis for gray zone inputs. |
| L2.5 | Entropy + Context | Catches obfuscated/encoded secrets with high randomness. |
| L3 | Regex (~300 patterns) | **Always runs.** Safety net for known credential formats. |

Final decision: `block if regex_hit OR ml_block`

## Performance (328-sample evaluation)

| Metric | Value |
|--------|-------|
| Accuracy | 94.51% |
| Precision | 94.69% |
| Recall | 97.27% |
| F1 Score | 95.96% |
| False Negative Rate | 2.73% |
| Avg Latency | 18.76 ms |
| Critical Secret Detection | 100% |

## Project Structure

```
├── mcp_middleware.py          # MCP proxy server (main entry point for Claude Desktop)
├── command_interceptor.py     # Interactive terminal interceptor (CLI mode)
├── secret_detector.py         # Regex-based pattern matcher (L3)
├── config.yaml                # ~300 detection patterns + whitelist
├── config_manager.py          # YAML config loader
├── audit_logger.py            # Logs to MongoDB + file fallback
├── mongo_handler.py           # MongoDB connection handler
├── terminal_handler.py        # Cross-platform command execution
├── test_email_server.py       # Simulated MCP server (13 tools, 8 attack surfaces)
├── start.py                   # Starts all services
├── dashboard_api.py           # FastAPI dashboard backend
├── dashboard.js               # Dashboard frontend
├── index.html                 # Dashboard UI
├── style.css                  # Dashboard styles
├── ml/
│   ├── cascade_entropy_detector.py   # Cascade ensemble (main detection engine)
│   ├── ml_detector.py                # Logistic/SVM detector wrapper
│   ├── tf_bilstm_detector.py         # BiLSTM detector wrapper
│   ├── tf_bilstm_model.py            # BiLSTM model architecture
│   ├── tf_char_tokenizer.py          # Character-level tokenizer
│   ├── tf_dataset.py                 # Dataset loader for BiLSTM
│   ├── build_dataset.py              # Dataset generation from benchmark
│   ├── train_model.py                # Train logistic regression
│   ├── train_svm_model.py            # Train SVM
│   ├── train_tf_bilstm.py            # Train BiLSTM
│   ├── cascade_config.yaml           # Cascade thresholds config
│   └── models/                       # Trained model files (gitignored)
├── benchmark_cascade_comprehensive.py # Main benchmark script
├── benchmark_all_modes.py             # Run all 8 modes for comparison
├── benchmarkold.py                    # Test case database (328 samples)
├── benchmark_eval.py                  # Evaluation dataset generator
├── compare_results.py                 # Side-by-side comparison
└── generate_paper_figures.py          # Generate publication figures
```

## Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

For BiLSTM support:
```bash
pip install tensorflow
```

### Run as MCP Middleware (Claude Desktop)

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "terminalguard-protected-everything": {
      "command": "/path/to/venv/bin/python3",
      "args": ["/path/to/TerminalGuardPlus/mcp_middleware.py"],
      "env": {
        "MONGODB_URI": "mongodb+srv://..."
      }
    }
  }
}
```

### Run Terminal Interceptor (CLI mode)

```bash
python command_interceptor.py
```

Type commands at the `>>` prompt. Secrets get flagged with cascade level and confidence.

### Run Dashboard

```bash
export MONGODB_URI="mongodb+srv://..."
python dashboard_api.py
```

Open `http://localhost:8001/dashboard`

### Run Benchmarks

```bash
# All 8 modes comparison
python benchmark_all_modes.py

# Cascade-only with full report
python benchmark_cascade_comprehensive.py

# Generate paper figures
python generate_paper_figures.py
```

## MCP Tools Covered

The test server simulates 13 tools across 8 attack surfaces:

| Tool | Attack Surface |
|------|---------------|
| send_email | Credential leak in email body |
| send_slack_message | Token leak in chat messages |
| write_file | Secrets written to config files |
| execute_sql | Credentials in connection strings |
| deploy_service | API keys in deployment config |
| run_shell_command | Secrets in shell commands |
| http_request | API keys in headers |
| commit_and_push | Tokens in Git URLs |
| create_github_issue | Secrets in bug reports |
| store_secret | Vault operations |
| create_note | Secrets in documentation |
| read_file | Safe read operations |
| read_inbox | Safe read operations |

## Dashboard Features

- Real-time detection statistics (block rate, FP/FN rates)
- Paginated command log with human-in-the-loop annotation
- Latency metrics (avg, P50, P95, P99)
- Severity breakdown charts
- Hourly detection trends
- Cascade level distribution
- System resource monitoring

## Contributors

- **Prachi Verma** (prachi094btcsai22@igdtuw.ac.in)
- **Sanskriti Vidushi** (sanskriti114btcsai22@igdtuw.ac.in)
- **Ritesh Yaduwanshi** (riteshyaduwanshi@igdtuw.ac.in)

Department of AI and Data Sciences, IGDTUW, Delhi
