# TerminalGuard

## Project Overview

TerminalGuard is a cross-platform security tool designed to detect and prevent accidental leakage of sensitive information such as API keys, passwords, tokens, and private keys during terminal and AI tool interactions. It integrates seamlessly with system terminals and Claude Desktop MCP servers, providing real-time secret detection and blocking capabilities.

---

## Files and Their Purpose

- **command_interceptor.py**: Intercepts terminal commands, scans for secrets, warns users, and blocks unsafe commands.
- **secret_detector.py**: Contains regex patterns to detect multiple secret types and performs secret scanning.
- **audit_logger.py**: Logs all intercepted commands, their actions, and detected secrets to secure audit logs.
- **config_manager.py**: Loads secret detection configurations from an external YAML file, supports dynamic reload.
- **terminal_handler.py**: Handles cross-platform terminal command execution on Windows and macOS.
- **mcp_middleware.py**: Middleware MCP server that proxies requests between Claude Desktop and an MCP email server, intercepting and blocking secrets.
- **test_email_server.py**: A simulated MCP email server for testing TerminalGuard's middleware blocking without sending real emails.
- **config.yaml**: YAML configuration with detection patterns, whitelist commands, and audit settings.
- **audit.log**: Generated security log file with JSON records of commands and secret detections.

---

## Tasks to Do Next

- **Expand the regex library** present in `config.yaml` to cover more secret types and reduce false negatives.    //done
- **Develop a dashboard** for real-time monitoring, alert visualization, and audit log analysis.     //done
- **Work on additional use cases** beyond emails, such as file operations, database queries, cloud CLI commands, and more MCP tools integration.
//no need
---

### Key Features

- Real-time secret detection using regex patterns.
- User interactive warnings and command blocking.
- Full audit logging of all terminal and MCP interactions.
- Cross-platform compatibility (Windows/macOS).
- Middleware integration with Claude Desktop MCP servers.
- Configurable patterns and whitelist via YAML file.

---

## Contributors

- **Prachi Verma**
- **Sanskriti Vidushi**

---
