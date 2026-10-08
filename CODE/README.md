# Password Policy Compiler with AI Assistant & Zero-Trust Security Layer

An end-to-end Domain-Specific Language (DSL) Compiler for Password Security Policies, coupled with a Zero-Trust AI Assistant, Input/Output Safety Checks, and a Human-in-the-Loop Approval Gate.

---

## 🏛️ System Architecture

```
[ User (Natural Language) ]
            │
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│ PROPOSED: AI Assistant + Security Layer                                │
│                                                                        │
│ 1. Input Checks: Size limits, real password & secret leakage blocker   │
│ 2. AI Assistant: LLM backend (Gemini/OpenAI) + Offline Deterministic   │
│    - Plain language to policy DSL                                      │
│    - Security policy review (NIST SP 800-63B & OWASP)                  │
│    - Synthetic test-case generation (Fake passwords only)              │
│    - Compiler error & warning explainer with auto-fix                  │
│ 3. Output Checks: Strict DSL schema validator, allowed keywords only   │
│ 4. Compiler-in-the-Loop Dry-Run: C++ compiler verifies policy in memory│
│ 5. User Approval Gate: Human reviews & approves before compilation    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Approved Policy DSL)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ EXISTING: Deterministic C++ Compiler Pipeline                          │
│                                                                        │
│  [Lexer] ──► [Parser] ──► [Semantic Checker] ──► [IR & Analyzer]       │
│                                                        │               │
│                                                        ▼               │
│  [Results] ◄── [Password Validator] ◄── [Code Generator (C++)]         │
│  (Errors, Warnings, Neuro-Symbolic Evaluation)        ▲               │
│                                                        │               │
│                                      [Neuro-Symbolic Evaluator]        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **C++ Compiler:** `g++` (MinGW or GCC)
- **Node.js:** v18+ (tested with v24)

### 2. Start the Backend Server
From the `CODE` directory:
```bash
npm start
# or
node server.js
```
The server will start at: **`http://localhost:3000`**

### 3. Open the Interactive Web IDE
Open your web browser and navigate to:
```
http://localhost:3000
```

---

## 🛡️ Security Guardrails & Zero-Trust Design

1. **Input Checks:**
   - **Payload Limiter:** Caps prompts at 800 characters to prevent prompt flooding and resource exhaustion.
   - **Real Password & Secret Blocker:** Heuristic and regex engine detects high-entropy tokens, API keys (`sk-...`, `AIza...`, `ghp_...`), and patterns like `password=Secret123`. Requests containing real credentials are immediately blocked with HTTP 400.
   - **Prompt Injection Defense:** Filters delimiter attacks and system override attempts.

2. **Backend Secret Isolation:**
   - LLM API keys (`GEMINI_API_KEY`, `OPENAI_API_KEY`) stay isolated in the backend `.env` file and are never sent to the browser.
   - Works **100% offline out-of-the-box** using an intelligent deterministic rule engine if no API keys are provided.

3. **Output Checks & Compiler-in-the-Loop Verification:**
   - AI outputs are never trusted blindly.
   - Output must match strict DSL grammar (`minLength`, `maxLength`, `requireUpper`, `requireLower`, `requireDigit`, `requireSpecial`, `noSpaces`).
   - The backend runs a **dry-run** of `policy_compiler.exe` on the AI's proposal. If compilation produces errors, the proposal is blocked before the user ever sees it.

4. **Human-in-the-Loop Approval:**
   - The user must explicitly inspect the generated policy in the **Approval Modal** and click **"Approve & Send to Compiler"** before it is committed to the compiler pipeline.

---

## 🧩 The 4 AI Assistant Features

| Feature | Description | Guardrail |
| :--- | :--- | :--- |
| **1. Plain Language to Policy** | Converts plain English (e.g. *"At least 12 chars with digits and symbols, no spaces"*) into verified DSL. | Schema Whitelist + Compiler Dry-Run |
| **2. Security Policy Review** | Audits the current policy against **NIST SP 800-63B** and OWASP ASVS v4.0 guidelines. | Dry-run constraint inspection |
| **3. Synthetic Test Cases** | Generates 6 mock test cases (3 PASS, 3 FAIL) tested against the C++ Neuro-Symbolic Evaluator. | **Guaranteed Fake Passwords Only** |
| **4. Error Explainer** | Explains compiler errors (lexical, syntax, semantic typos) in educational English with one-click auto-fix. | Grounded in C++ compiler error codes |

---

## ⚙️ REST API Endpoints

- `GET /api/status`: Health check, compiler availability, active AI provider.
- `POST /api/compile`: Compiles policy DSL using `policy_compiler.exe --json`.
- `POST /api/ai/nl-to-policy`: Converts natural language to compiler-verified policy.
- `POST /api/ai/review`: Audits active policy against NIST guidelines.
- `POST /api/ai/synthetic-tests`: Generates and executes 6 synthetic mock test cases.
- `POST /api/ai/explain-error`: Diagnoses compiler errors and provides auto-fix suggestions.
- `GET /api/generated-code`: Fetches the emitted target C++ validator code.

---

## 📁 Repository Structure

```
CODE/
├── main.cpp                    # Compiler CLI & JSON output orchestrator
├── lexer.h / lexer.cpp         # Lexical analyzer with position tracking
├── token.h                     # Token data structures
├── parser.h / parser.cpp       # Recursive-descent AST parser
├── ast.h                       # AST node definitions
├── semantic.h / semantic.cpp   # Semantic validator & Levenshtein typo suggester
├── ir.h / ir.cpp               # Policy Intermediate Representation (PolicyIR)
├── ir_analyzer.h / cpp         # IR static security heuristics
├── codegen.h / codegen.cpp     # Target code generator (emits C++ validator)
├── neurosymbolic.h / cpp       # Hybrid Neuro-Symbolic strength scoring engine
├── safety_checker.js           # Input/Output Zero-Trust guardrails
├── ai_service.js               # Multi-provider AI assistant (Gemini/OpenAI/Offline)
├── server.js                   # Secure Express backend server
├── policy_compiler.html        # Interactive split-screen IDE & approval modal
├── policy_compiler.exe         # Compiled C++ binary
├── policy.txt                  # Sample policy
├── test.txt                    # Master test suite
└── .env                        # Secret environment configuration
```
