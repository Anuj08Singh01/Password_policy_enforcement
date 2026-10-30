/**
 * safety_checker.js
 * 
 * Implements strict Input and Output Security Checks according to the Zero-Trust AI architecture.
 * - Input Checks: Payload size limiter, sensitive real-password & API secret blocker, prompt-injection sanitization.
 * - Output Checks: Strict DSL schema validation, keyword whitelist enforcement, and Compiler-in-the-Loop Dry Run verification.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { compilePolicy } = require('./compiler_engine');

const VALID_KEYWORDS = new Set([
  'minLength',
  'maxLength',
  'requireUpper',
  'requireLower',
  'requireDigit',
  'requireSpecial',
  'noSpaces'
]);

class SafetyChecker {
  /**
   * 1. INPUT CHECK: Size Limit
   */
  static checkInputSize(text, maxChars = 1000) {
    if (!text || typeof text !== 'string') {
      return { ok: true };
    }
    if (text.length > maxChars) {
      return {
        ok: false,
        error: `Input payload exceeds maximum allowed size (${text.length} > ${maxChars} chars). Request rejected to prevent prompt flooding.`
      };
    }
    return { ok: true };
  }

  /**
   * 2. INPUT CHECK: Real Password & Secret Leakage Blocker
   * Detects if the user inadvertently pasted a real password, private key, or credential.
   */
  static detectSensitiveData(text) {
    if (!text) return { ok: true };

    // Common secret patterns
    const secretPatterns = [
      { pattern: /sk-[a-zA-Z0-9]{20,}/i, name: 'OpenAI Secret Key' },
      { pattern: /AIza[0-9A-Za-z-_]{35}/, name: 'Google API Key' },
      { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub Personal Token' },
      { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
      { pattern: /bearer\s+[a-zA-Z0-9_\-\.]{20,}/i, name: 'Bearer Auth Token' },
      { pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*["']?([^\s"']{8,})["']?/i, name: 'Hardcoded Real Password' }
    ];

    for (const { pattern, name } of secretPatterns) {
      if (pattern.test(text)) {
        return {
          ok: false,
          error: `[Security Guard Triggered] Detected potential sensitive credential (${name}). Real passwords or API keys must NEVER be transmitted to AI services.`
        };
      }
    }

    // High-entropy token detection (heuristic for pasted passwords / hashes)
    const words = text.split(/\s+/);
    for (const word of words) {
      if (word.length >= 16 && /[A-Z]/.test(word) && /[a-z]/.test(word) && /[0-9]/.test(word) && /[^A-Za-z0-9]/.test(word)) {
        // Looks like a high-entropy actual password
        return {
          ok: false,
          error: `[Security Guard Triggered] Detected suspicious high-entropy string '${word.substring(0, 4)}***'. Real passwords must never be entered in the AI prompt.`
        };
      }
    }

    return { ok: true };
  }

  /**
   * 3. INPUT CHECK: Prompt Injection Defense
   */
  static sanitizePrompt(prompt) {
    if (!prompt) return '';
    // Strip control characters, keep human text
    let clean = prompt.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    // Neutralize deliberate instruction override attempts
    clean = clean.replace(/(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s+override)/gi, '[REDACTED_INJECTION_ATTEMPT]');
    return clean.trim();
  }

  /**
   * 4. OUTPUT CHECK: Strict DSL Grammar & Keyword Whitelist Enforcement
   * Verifies that the AI proposal consists ONLY of valid DSL commands and values.
   */
  static validateDslSchema(rawOutput) {
    const lines = rawOutput.split('\n');
    const validLines = [];
    const errors = [];

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      // Remove markdown code fences if AI inadvertently wrapped output
      line = line.replace(/^```[a-z]*|```$/gi, '').trim();

      if (!line) continue;
      if (line.startsWith('#')) {
        validLines.push(line);
        continue;
      }

      const parts = line.split(/\s+/);
      if (parts.length !== 2) {
        errors.push(`Line ${i + 1}: Invalid statement format '${line}'. Expected '<ruleName> <value>'`);
        continue;
      }

      const [name, value] = parts;
      if (!VALID_KEYWORDS.has(name)) {
        errors.push(`Line ${i + 1}: Unrecognized rule '${name}'. Only official DSL rules allowed.`);
        continue;
      }

      if (name === 'minLength' || name === 'maxLength') {
        if (!/^\d+$/.test(value)) {
          errors.push(`Line ${i + 1}: '${name}' requires an integer value, got '${value}'`);
          continue;
        }
      } else {
        if (value !== 'true' && value !== 'false') {
          errors.push(`Line ${i + 1}: '${name}' requires a boolean ('true' or 'false'), got '${value}'`);
          continue;
        }
      }

      validLines.push(`${name} ${value}`);
    }

    if (validLines.length === 0 && errors.length === 0) {
      return {
        ok: false,
        error: 'Output was empty or contained no valid policy rules.',
        cleanDsl: ''
      };
    }

    if (errors.length > 0) {
      return {
        ok: false,
        error: `Output grammar violations:\n${errors.join('\n')}`,
        cleanDsl: validLines.join('\n')
      };
    }

    return {
      ok: true,
      cleanDsl: validLines.join('\n')
    };
  }

  /**
   * 5. OUTPUT CHECK: Compiler-in-the-Loop Dry Run Verification
   * Executes the actual policy compiler in dry-run mode against the AI's proposal.
   */
  static async compilerDryRun(compilerExePath, dslText) {
    try {
      const res = compilePolicy(dslText);
      if (res.success) {
        return {
          verified: true,
          stage: res.stage,
          constraints: res.constraints,
          warnings: res.warnings || [],
          errors: []
        };
      } else {
        return {
          verified: false,
          stage: res.stage,
          errors: res.errors || [{ message: 'Compiler rejected policy' }]
        };
      }
    } catch (e) {
      return {
        verified: false,
        stage: 'engine',
        errors: [{ message: `Dry run execution error: ${e.message}` }]
      };
    }
  }
}

module.exports = SafetyChecker;
