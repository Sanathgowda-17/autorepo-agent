# 🤖 AutoRepo — Autonomous 4-Agent PR Reviewer, AST Complexity Analyzer & Security Linter

**AutoRepo** is an enterprise-grade **Multi-Agent Pull Request Auditor & Static Application Security Testing (SAST) Engine** built in Python (`FastAPI`, native `ast.NodeVisitor`, and `SQLite`). Instead of passing raw code to a single naive LLM prompt, AutoRepo parses source files into deterministic **Abstract Syntax Trees (AST)** and executes a **4-Node Directed Acyclic Graph (DAG)** of specialized autonomous agents.

---

## 🏗️ 4-Agent DAG Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │   Incoming GitHub PR Diff / Webhook (HMAC)   │
                     └──────────────────────┬───────────────────────┘
                                            │
              ┌─────────────────────────────┴─────────────────────────────┐
              ▼                                                           ▼
┌───────────────────────────────────────┐   ┌───────────────────────────────────────┐
│   NODE 1: SecOps SAST Agent           │   │   NODE 2: Arch & AST Complexity Agent │
│ • Scans OWASP Top-10 & CWE signatures │   │ • Walks Python `ast.NodeVisitor` tree │
│ • Detects SQLi (CWE-89), RCE (CWE-95),│   │ • Computes McCabe Complexity (M)      │
│   Cmd Injection (CWE-78), Hardcoded   │   │ • Estimates Big-O loop nesting depth  │
│   Secrets (CWE-798), Pickle (CWE-502) │   │ • Catches N+1 DB queries inside loops │
└──────────────────┬────────────────────┘   └───────────────────┬───────────────────┘
                   │                                            │
                   └─────────────────────┬──────────────────────┘
                                         ▼
                     ┌──────────────────────────────────────┐
                     │  NODE 3: UnitTest Synthesizer Agent  │
                     │ • Extracts AST function signatures   │
                     │ • Generates runnable `pytest` suite  │
                     │   (Happy Path + CWE Regressions)     │
                     └───────────────────┬──────────────────┘
                                         ▼
                     ┌──────────────────────────────────────┐
                     │  NODE 4: Lead Critic & Patch Agent   │
                     │ • Auto-refactors vulnerable code     │
                     │   into parameterized / safe patches  │
                     │ • Computes PR Readiness Score (0-100)│
                     └──────────────────────────────────────┘
```

---

## 🔬 Core Engineering Highlights

1. **Deterministic Compiler AST Analysis (`backend/ast_engine.py`)**:
   - Uses Python's native `ast` module to walk `FunctionDef`, `AsyncFunctionDef`, `For`, `While`, `If`, and `Try` nodes.
   - Calculates **McCabe Cyclomatic Complexity** ($M = 1 + \text{branching predicates}$) per function.
   - Detects **N+1 I/O & Database Calls inside Loops**, **Mutable Default Arguments** (`def fn(cache=[])`), and **Bare `except:` Clauses**.
2. **OWASP Top-10 & CWE Static Security Linter (`backend/agent_dag.py`)**:
   - Flags `CWE-89` (SQL Injection), `CWE-798` (Hardcoded Cloud/API Credentials), `CWE-95` (`eval`/`exec` RCE), `CWE-78` (OS Command Injection), `CWE-502` (Insecure Deserialization), and `CWE-327` (Weak `MD5`/`SHA1` Hashing) with exact line numbers.
3. **Automated Patch Refactoring & Side-by-Side Diff**:
   - Rewrites string-interpolated SQL into parameterized prepared statements, replaces hardcoded secrets with `os.environ.get()`, upgrades `eval()` to `ast.literal_eval()`, and fixes mutable default arguments.
4. **Automated `pytest` Unit Test Synthesis & Sandbox Runner**:
   - Synthesizes contract tests, boundary/null-safety guards, and security regression assertions directly from parsed AST function signatures.
5. **Cryptographic GitHub Webhook Receiver (`/api/webhooks/github`)**:
   - Verifies `X-Hub-Signature-256` payloads using constant-time `hmac.compare_digest` (`HMAC-SHA256`).

---

## 🚀 Quickstart (Local Execution)

```bash
cd backend
python3 -m uvicorn app:app --host 0.0.0.0 --port 8001
```
Open **`http://localhost:8001`** in your browser.
