/**
 * server.js
 * 
 * Secure Backend Server for Password Policy Compiler & AI Assistant.
 * Integrates:
 * - Deterministic C++ Compiler Pipeline (Lexer, Parser, Semantic, IR, NS Evaluator, CodeGen)
 * - AI Assistant (Plain Language to Policy, Security Review, Synthetic Test Cases, Error Explainer)
 * - Strict Input and Output Safety Layers
 * - User Approval Flow
 * - Static UI Serving
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');

const SafetyChecker = require('./safety_checker');
const AiService = require('./ai_service');

const app = express();
const PORT = process.env.PORT || 3000;
const COMPILER_EXE = path.join(__dirname, 'policy_compiler.exe');

// Initialize AI Service
const aiService = new AiService(COMPILER_EXE);

// Middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50kb' })); // Payload size safety check
app.use(express.static(__dirname));

/**
 * Health & Capabilities Endpoint
 */
app.get('/api/status', (req, res) => {
  const compilerExists = fs.existsSync(COMPILER_EXE);
  res.json({
    status: 'online',
    compilerAvailable: compilerExists,
    aiProvider: aiService.getLlmProviderName(),
    hasSecretApiKey: aiService.hasLlmConfigured(),
    features: [
      'Plain Language to Policy DSL',
      'Security Policy Review & NIST Audit',
      'Synthetic Test-Case Generation (Fake Passwords Only)',
      'Compiler Error & Warning Explainer',
      'Input/Output Safety & Leakage Detection',
      'User Approval Gate',
      'Full C++ Compiler Execution'
    ]
  });
});

/**
 * CORE COMPILER ENDPOINT:
 * Runs the existing C++ Policy Compiler on an approved policy
 */
app.post('/api/compile', async (req, res) => {
  const { policyDsl, password } = req.body;

  if (!policyDsl || typeof policyDsl !== 'string') {
    return res.status(400).json({ success: false, message: 'Missing policyDsl payload' });
  }

  // Input check
  const sizeCheck = SafetyChecker.checkInputSize(policyDsl, 2000);
  if (!sizeCheck.ok) {
    return res.status(400).json({ success: false, message: sizeCheck.error });
  }

  const tempFile = path.join(__dirname, `temp_run_${Date.now()}_${Math.floor(Math.random() * 1000)}.txt`);
  try {
    await fs.promises.writeFile(tempFile, policyDsl, 'utf8');

    const args = [tempFile, '--json'];
    if (password && typeof password === 'string') {
      args.push('--password', password);
    } else {
      args.push('--check');
    }

    execFile(COMPILER_EXE, args, { timeout: 5000 }, (err, stdout, stderr) => {
      fs.unlink(tempFile, () => {});

      try {
        const result = JSON.parse(stdout.trim());
        res.json(result);
      } catch (parseErr) {
        res.status(500).json({
          success: false,
          stage: 'compiler_runtime',
          errors: [{ message: `Failed to parse compiler output: ${stdout || stderr || err?.message}` }]
        });
      }
    });
  } catch (ioErr) {
    try { await fs.promises.unlink(tempFile); } catch (_) {}
    res.status(500).json({ success: false, message: ioErr.message });
  }
});

/**
 * AI FEATURE 1: Plain Language to Policy DSL
 * Generates compiler-verified proposal with safety checks, awaiting USER APPROVAL
 */
app.post('/api/ai/nl-to-policy', async (req, res) => {
  const { prompt } = req.body;

  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ ok: false, error: 'Please enter a description of your policy rules.' });
  }

  const result = await aiService.plainLanguageToPolicy(prompt);
  if (!result.ok) {
    return res.status(400).json(result);
  }

  res.json(result);
});

/**
 * AI FEATURE 2: Security Review & NIST SP 800-63B Audit
 */
app.post('/api/ai/review', async (req, res) => {
  const { policyDsl } = req.body;

  if (!policyDsl) {
    return res.status(400).json({ ok: false, error: 'Policy DSL is empty.' });
  }

  const result = await aiService.reviewPolicySecurity(policyDsl);
  res.json(result);
});

/**
 * AI FEATURE 3: Synthetic Test Cases (Fake Passwords Only)
 */
app.post('/api/ai/synthetic-tests', async (req, res) => {
  const { policyDsl } = req.body;

  if (!policyDsl) {
    return res.status(400).json({ ok: false, error: 'Policy DSL is empty.' });
  }

  const result = await aiService.generateSyntheticTestCases(policyDsl);
  res.json(result);
});

/**
 * AI FEATURE 4: Explain Compiler Errors
 */
app.post('/api/ai/explain-error', async (req, res) => {
  const { errorData, policyDsl } = req.body;

  if (!errorData) {
    return res.status(400).json({ ok: false, error: 'No error data provided.' });
  }

  const result = await aiService.explainCompilerErrors(errorData, policyDsl || '');
  res.json(result);
});

/**
 * Read Generated Target C++ Code
 */
app.get('/api/generated-code', async (req, res) => {
  const codePath = path.join(__dirname, 'generated_validator.cpp');
  try {
    if (fs.existsSync(codePath)) {
      const code = await fs.promises.readFile(codePath, 'utf8');
      res.json({ ok: true, code });
    } else {
      res.json({ ok: false, message: 'No target code generated yet. Compile a policy first.' });
    }
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 Password Policy Compiler & AI Assistant Server Running`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`🔒 AI Provider: ${aiService.getLlmProviderName()}`);
  console.log(`🛡️  Zero-Trust Safety & Compiler Verification: ACTIVE`);
  console.log(`=======================================================`);
});
