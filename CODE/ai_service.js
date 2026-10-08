/**
 * ai_service.js
 * 
 * Implements the 4 AI Assistant capabilities:
 * 1. Plain Language to Policy DSL
 * 2. Policy Security Review (NIST SP 800-63B & OWASP alignment)
 * 3. Synthetic Test-Case Generation (Fake passwords only) with Compiler Execution
 * 4. Compiler Error & Warning Explainer
 * 
 * Adheres to Zero-Trust AI principles:
 * - AI output is never trusted blindly; validated through safety_checker.js & compiler dry-run.
 * - Supports Google Gemini & OpenAI API keys from environment variables (kept secret on the backend).
 * - Includes a deterministic offline heuristic assistant fallback so all 4 features work instantly out of the box!
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const SafetyChecker = require('./safety_checker');

class AiService {
  constructor(compilerExePath) {
    this.compilerExePath = compilerExePath;
    this.geminiApiKey = process.env.GEMINI_API_KEY || '';
    this.openaiApiKey = process.env.OPENAI_API_KEY || '';
  }

  /**
   * Helper: Check if external LLM API is configured
   */
  hasLlmConfigured() {
    return Boolean(this.geminiApiKey || this.openaiApiKey);
  }

  getLlmProviderName() {
    if (this.geminiApiKey) return 'Google Gemini API';
    if (this.openaiApiKey) return 'OpenAI API';
    return 'Offline Deterministic Rule Engine';
  }

  /**
   * Call external LLM (Gemini or OpenAI) with system prompt and user content
   */
  async callLlm(systemPrompt, userPrompt) {
    if (this.geminiApiKey) {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.geminiApiKey}`;
      const payload = {
        contents: [
          {
            role: 'user',
            parts: [{ text: `${systemPrompt}\n\nUser Request:\n${userPrompt}` }]
          }
        ],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 800
        }
      };

      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Gemini API error (${res.status}): ${errText}`);
      }

      const data = await res.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      return text.trim();
    }

    if (this.openaiApiKey) {
      const url = 'https://api.openai.com/v1/chat/completions';
      const payload = {
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.1,
        max_tokens: 800
      };

      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.openaiApiKey}`
        },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`OpenAI API error (${res.status}): ${errText}`);
      }

      const data = await res.json();
      return data.choices?.[0]?.message?.content?.trim() || '';
    }

    throw new Error('No LLM API key configured');
  }

  /**
   * FEATURE 1: Plain Language to Policy DSL
   * Converts conversational requirement into compiler-verified DSL for User Approval.
   */
  async plainLanguageToPolicy(userPrompt) {
    // 1. Input Safety Checks
    const sizeCheck = SafetyChecker.checkInputSize(userPrompt, 800);
    if (!sizeCheck.ok) {
      return { ok: false, error: sizeCheck.error, stage: 'input_safety' };
    }

    const secretCheck = SafetyChecker.detectSensitiveData(userPrompt);
    if (!secretCheck.ok) {
      return { ok: false, error: secretCheck.error, stage: 'input_safety' };
    }

    const cleanPrompt = SafetyChecker.sanitizePrompt(userPrompt);

    let rawDsl = '';
    let aiExplanation = '';

    if (this.hasLlmConfigured()) {
      try {
        const systemPrompt = `You are an AI assistant specialized in compiling password security policies into a Domain Specific Language (DSL).
Target DSL grammar rules:
minLength <number>
maxLength <number>
requireUpper <true|false>
requireLower <true|false>
requireDigit <true|false>
requireSpecial <true|false>
noSpaces <true|false>

Respond with ONLY the policy DSL lines, with NO markdown code blocks, NO conversational preamble, and NO extra text.
Lines starting with '#' are permitted for comments.`;

        rawDsl = await this.callLlm(systemPrompt, cleanPrompt);
        aiExplanation = `Synthesized via ${this.getLlmProviderName()} from your natural language description.`;
      } catch (llmErr) {
        console.warn('LLM call failed, falling back to offline NLP engine:', llmErr.message);
        const fb = this.heuristicPlainLanguageToDsl(cleanPrompt);
        rawDsl = fb.dsl;
        aiExplanation = fb.explanation + ' (Fallback engine activated)';
      }
    } else {
      const fb = this.heuristicPlainLanguageToDsl(cleanPrompt);
      rawDsl = fb.dsl;
      aiExplanation = fb.explanation;
    }

    // 2. Output Check: Schema & Allowed Values
    const schemaCheck = SafetyChecker.validateDslSchema(rawDsl);
    if (!schemaCheck.ok) {
      return {
        ok: false,
        error: `AI output failed grammar guardrails: ${schemaCheck.error}`,
        stage: 'output_safety',
        rawOutput: rawDsl
      };
    }

    const cleanDsl = schemaCheck.cleanDsl;

    // 3. Output Check: Compiler-in-the-Loop Dry Run
    const dryRunResult = await SafetyChecker.compilerDryRun(this.compilerExePath, cleanDsl);
    if (!dryRunResult.verified) {
      return {
        ok: false,
        error: `AI proposed policy failed compiler dry-run verification: ${dryRunResult.errors.map(e => e.message).join('; ')}`,
        stage: 'compiler_verification',
        proposedDsl: cleanDsl
      };
    }

    // 4. Return for USER APPROVAL (Zero-Trust Principle: Do not commit without user consent)
    return {
      ok: true,
      status: 'pending_user_approval',
      provider: this.getLlmProviderName(),
      proposedDsl: cleanDsl,
      explanation: aiExplanation,
      compilerVerified: true,
      constraints: dryRunResult.constraints,
      warnings: dryRunResult.warnings,
      safetyReport: {
        inputCheck: 'PASSED (Length & Secret Leakage checked)',
        grammarCheck: 'PASSED (Strict DSL Schema verified)',
        dryRunCheck: 'PASSED (C++ Compiler verified with 0 errors)'
      }
    };
  }

  /**
   * Deterministic Offline NLP Fallback for Plain Language to DSL
   */
  heuristicPlainLanguageToDsl(text) {
    const lower = text.toLowerCase();
    const rules = [];

    // Length matching: e.g. "at least 12", "min 8", "between 8 and 20"
    const betweenMatch = lower.match(/(?:between|from)\s+(\d+)\s+(?:and|to)\s+(\d+)/);
    if (betweenMatch) {
      rules.push(`minLength ${betweenMatch[1]}`);
      rules.push(`maxLength ${betweenMatch[2]}`);
    } else {
      const minMatch = lower.match(/(?:at least|minimum|min(?:imum)? of|min length of|min)\s*(\d+)/i) ||
                         lower.match(/(\d+)\s*(?:characters?|chars?)\s*(?:minimum|min|or more)/i);
      if (minMatch) {
        rules.push(`minLength ${minMatch[1]}`);
      } else if (lower.includes('short') || lower.includes('weak')) {
        rules.push('minLength 8');
      } else {
        rules.push('minLength 12');
      }

      const maxMatch = lower.match(/(?:at most|maximum|max(?:imum)? of|max length of|max|up to)\s*(\d+)/i);
      if (maxMatch) {
        rules.push(`maxLength ${maxMatch[1]}`);
      }
    }

    // Upper
    if (lower.includes('no upper') || lower.includes('forbid upper') || lower.includes('disallow upper') || lower.includes('without uppercase')) {
      rules.push('requireUpper false');
    } else if (lower.includes('upper') || lower.includes('capital')) {
      rules.push('requireUpper true');
    }

    // Lower
    if (lower.includes('no lower') || lower.includes('forbid lower') || lower.includes('disallow lower') || lower.includes('without lowercase')) {
      rules.push('requireLower false');
    } else if (lower.includes('lower') || lower.includes('small letter')) {
      rules.push('requireLower true');
    }

    // Digit
    if (lower.includes('no digit') || lower.includes('no number') || lower.includes('without digit') || lower.includes('without number')) {
      rules.push('requireDigit false');
    } else if (lower.includes('digit') || lower.includes('number') || lower.includes('numeric')) {
      rules.push('requireDigit true');
    }

    // Special
    if (lower.includes('no special') || lower.includes('no symbol') || lower.includes('without special') || lower.includes('without symbol')) {
      rules.push('requireSpecial false');
    } else if (lower.includes('special') || lower.includes('symbol') || lower.includes('punctuation')) {
      rules.push('requireSpecial true');
    }

    // Spaces
    if (/\b(?:no\s+spaces?|without\s+spaces?|disallow\s+spaces?|forbid\s+spaces?)\b/i.test(lower)) {
      rules.push('noSpaces true');
    } else if (/\b(?:allow\s+spaces?|spaces?\s+allowed|permit\s+spaces?|with\s+spaces?)\b/i.test(lower)) {
      rules.push('noSpaces false');
    }

    return {
      dsl: rules.join('\n'),
      explanation: 'Constructed by deterministic NLP rule matching your requested requirements.'
    };
  }

  /**
   * FEATURE 2: Policy Security Review & NIST SP 800-63B Audit
   */
  async reviewPolicySecurity(dslText) {
    // 1. Dry run compile to inspect parsed constraints
    const dryRun = await SafetyChecker.compilerDryRun(this.compilerExePath, dslText);
    if (!dryRun.verified) {
      return {
        ok: false,
        error: `Cannot review policy because it contains compiler errors:\n${dryRun.errors.map(e => e.message).join('\n')}`
      };
    }

    const c = dryRun.constraints;
    const findings = [];
    let securityRating = 'Moderate';
    let overallScore = 75;

    // NIST SP 800-63B Guideline checks:
    // 1. Minimum Length
    if (c.minLength === -1) {
      findings.push({
        severity: 'HIGH',
        category: 'Length Constraint',
        issue: 'No minimum length defined.',
        recommendation: 'Specify minLength of at least 8 (recommended 12+ per NIST SP 800-63B).'
      });
      overallScore -= 30;
    } else if (c.minLength < 8) {
      findings.push({
        severity: 'CRITICAL',
        category: 'Brute-force Vulnerability',
        issue: `Minimum length is only ${c.minLength}, which is vulnerable to instantaneous brute-force cracking.`,
        recommendation: 'Increase minLength to at least 8, preferably 12.'
      });
      overallScore -= 40;
    } else if (c.minLength >= 12) {
      findings.push({
        severity: 'GOOD',
        category: 'Length Strength',
        issue: `Strong minimum length of ${c.minLength} characters.`,
        recommendation: 'Meets high-security enterprise requirements.'
      });
      overallScore += 10;
    }

    // 2. Fixed Length
    if (c.minLength !== -1 && c.maxLength !== -1 && c.minLength === c.maxLength) {
      findings.push({
        severity: 'MEDIUM',
        category: 'Fixed Length Risk',
        issue: `Fixed length of ${c.minLength} characters significantly narrows the attacker's search space.`,
        recommendation: 'Allow a variable length range (e.g., minLength 12, maxLength 64).'
      });
      overallScore -= 15;
    }

    // 3. Overly Restrictive Max Length
    if (c.maxLength !== -1 && c.maxLength < 16) {
      findings.push({
        severity: 'MEDIUM',
        category: 'NIST Usability Violation',
        issue: `Maximum length of ${c.maxLength} characters discourages users from using secure multi-word passphrases.`,
        recommendation: 'NIST SP 800-63B recommends allowing passwords up to at least 64 characters.'
      });
      overallScore -= 10;
    }

    // 4. Character Set Diversity
    let classCount = 0;
    if (c.requireUpper === 1) classCount++;
    if (c.requireLower === 1) classCount++;
    if (c.requireDigit === 1) classCount++;
    if (c.requireSpecial === 1) classCount++;

    if (classCount >= 3) {
      findings.push({
        severity: 'GOOD',
        category: 'Entropy Expansion',
        issue: `Requires multiple character classes (${classCount}/4), boosting key-space entropy.`,
        recommendation: 'Maintain standard complexity requirements.'
      });
      overallScore += 10;
    } else if (classCount === 0) {
      findings.push({
        severity: 'LOW',
        category: 'Entropy Caution',
        issue: 'No specific character class requirements configured.',
        recommendation: 'Consider requiring at least digits or special characters if length is < 15.'
      });
    }

    // 5. Space Policy
    if (c.noSpaces === 1) {
      findings.push({
        severity: 'INFO',
        category: 'Passphrase Policy',
        issue: 'Spaces are forbidden.',
        recommendation: 'Allowing spaces enables memorable Diceware passphrases (e.g. "correct horse battery staple").'
      });
    }

    overallScore = Math.max(10, Math.min(100, overallScore));
    if (overallScore >= 85) securityRating = 'Strong';
    else if (overallScore >= 60) securityRating = 'Moderate';
    else securityRating = 'Weak';

    return {
      ok: true,
      rating: securityRating,
      score: overallScore,
      standards: 'NIST SP 800-63B & OWASP ASVS v4.0',
      findings,
      compilerWarnings: dryRun.warnings
    };
  }

  /**
   * FEATURE 3: Synthetic Test-Case Generation (Fake Passwords Only)
   * Generates mock passwords and runs them through the actual C++ compiler evaluator.
   */
  async generateSyntheticTestCases(dslText) {
    const dryRun = await SafetyChecker.compilerDryRun(this.compilerExePath, dslText);
    if (!dryRun.verified) {
      return {
        ok: false,
        error: `Cannot generate test cases for invalid policy:\n${dryRun.errors.map(e => e.message).join('\n')}`
      };
    }

    const c = dryRun.constraints;

    // Generate 3 synthetic PASSING and 3 synthetic FAILING candidates (Guaranteed synthetic mock strings)
    const minL = c.minLength > 0 ? c.minLength : 8;
    const maxL = c.maxLength > 0 ? c.maxLength : 24;
    const targetL = Math.min(maxL, Math.max(minL, 12));

    // Construct valid synthetic candidates
    const validCandidates = [
      {
        password: this.buildSyntheticPassword(targetL, c, 'clean'),
        description: 'Meets all policy constraints with optimal character distribution'
      },
      {
        password: this.buildSyntheticPassword(Math.min(maxL, minL + 2), c, 'minimal'),
        description: 'Boundary test: just above minimum required length'
      },
      {
        password: this.buildSyntheticPassword(Math.min(maxL, targetL + 4), c, 'diverse'),
        description: 'High entropy synthetic passphrase with symbols and numbers'
      }
    ];

    // Construct failing synthetic candidates (violating specific rules)
    const invalidCandidates = [];

    // Failing test 1: Length violation
    if (minL > 3) {
      invalidCandidates.push({
        password: 'A1!a',
        description: `Too short: length 4 is below minLength ${minL}`,
        intendedFailure: 'minLength'
      });
    } else {
      invalidCandidates.push({
        password: 'a'.repeat(maxL + 5),
        description: `Too long: exceeds maxLength ${maxL}`,
        intendedFailure: 'maxLength'
      });
    }

    // Failing test 2: Missing character class
    if (c.requireSpecial === 1) {
      invalidCandidates.push({
        password: 'AlphaNumeric99NoSymbols',
        description: 'Missing required special character (!@#$...)',
        intendedFailure: 'requireSpecial'
      });
    } else if (c.requireDigit === 1) {
      invalidCandidates.push({
        password: 'AlphaBetaNoNumbers!',
        description: 'Missing required numeric digit (0-9)',
        intendedFailure: 'requireDigit'
      });
    } else if (c.requireUpper === 1) {
      invalidCandidates.push({
        password: 'alllowercase_with_123!',
        description: 'Missing required uppercase letter (A-Z)',
        intendedFailure: 'requireUpper'
      });
    } else {
      invalidCandidates.push({
        password: 'NO_LOWERCASE_123!',
        description: 'Missing lowercase letters',
        intendedFailure: 'requireLower'
      });
    }

    // Failing test 3: Sequential / Weak Pattern / Forbidden space
    if (c.noSpaces === 1) {
      invalidCandidates.push({
        password: 'Word With Spaces 123!',
        description: 'Contains illegal whitespace characters',
        intendedFailure: 'noSpaces'
      });
    } else {
      invalidCandidates.push({
        password: 'abcdefghijklmnop1!',
        description: 'Contains predictable sequential alphabetical sequence',
        intendedFailure: 'heuristic_sequence'
      });
    }

    // Run ALL synthetic candidates through the existing C++ Policy Compiler
    const allTests = [];

    for (const item of [...validCandidates.map(v => ({ ...v, expected: 'PASS' })), ...invalidCandidates.map(iv => ({ ...iv, expected: 'FAIL' }))]) {
      const execResult = await this.evaluatePasswordWithCompiler(dslText, item.password);
      allTests.push({
        password: item.password,
        expected: item.expected,
        actualValid: execResult.isValid,
        passed: (item.expected === 'PASS' && execResult.isValid) || (item.expected === 'FAIL' && !execResult.isValid),
        score: execResult.score,
        level: execResult.level,
        description: item.description,
        reasons: execResult.reasons || []
      });
    }

    return {
      ok: true,
      syntheticGuarantee: 'All test passwords are dynamically generated synthetic mock tokens. No production passwords were used.',
      testCases: allTests
    };
  }

  buildSyntheticPassword(targetLength, c, style) {
    let uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    let lowers = 'abcdefghijkmnopqrstuvwxyz';
    let digits = '23456789';
    let specials = '@#$%^&*!?-';

    let base = [];
    if (c.requireUpper === 1) base.push(uppers[Math.floor(Math.random() * uppers.length)]);
    if (c.requireLower === 1) base.push(lowers[Math.floor(Math.random() * lowers.length)]);
    if (c.requireDigit === 1) base.push(digits[Math.floor(Math.random() * digits.length)]);
    if (c.requireSpecial === 1) base.push(specials[Math.floor(Math.random() * specials.length)]);

    // Fill remainder with varied pool
    let pool = lowers + digits;
    if (c.requireUpper !== 0) pool += uppers;
    if (c.requireSpecial !== 0) pool += specials;

    while (base.length < targetLength) {
      base.push(pool[Math.floor(Math.random() * pool.length)]);
    }

    return base.join('');
  }

  /**
   * Helper: Run a single password through policy_compiler.exe
   */
  async evaluatePasswordWithCompiler(dslText, testPassword) {
    const tempFile = path.join(__dirname, `temp_eval_${Date.now()}_${Math.floor(Math.random() * 1000)}.txt`);
    try {
      await fs.promises.writeFile(tempFile, dslText, 'utf8');

      return await new Promise((resolve) => {
        execFile(this.compilerExePath, [tempFile, '--json', '--password', testPassword], { timeout: 4000 }, (err, stdout) => {
          fs.unlink(tempFile, () => {});
          try {
            const data = JSON.parse(stdout.trim());
            if (data.evaluation) {
              resolve(data.evaluation);
            } else {
              resolve({ isValid: false, score: 0, level: 'Invalid', reasons: ['Compilation failed'] });
            }
          } catch (_) {
            resolve({ isValid: false, score: 0, level: 'Error', reasons: ['Failed to parse compiler output'] });
          }
        });
      });
    } catch (_) {
      try { await fs.promises.unlink(tempFile); } catch (_) {}
      return { isValid: false, score: 0, level: 'Error', reasons: ['Execution error'] };
    }
  }

  /**
   * FEATURE 4: Compiler Error & Warning Explainer
   * Explains compiler errors in plain English and proposes corrected code.
   */
  async explainCompilerErrors(compilerErrorData, dslText) {
    const errors = compilerErrorData.errors || [];
    const stage = compilerErrorData.stage || 'unknown';

    if (errors.length === 0) {
      return {
        ok: true,
        summary: 'No errors detected in compiler output.',
        explanation: 'The policy compiled cleanly through Lexer, Parser, Semantic Analyzer, and IR Generator.'
      };
    }

    const explanations = [];
    let suggestedFixDsl = dslText;

    for (const err of errors) {
      const msg = err.message || '';
      const line = err.line || 0;
      const col = err.col || 0;

      let explanation = '';
      let fix = '';

      if (stage === 'lexical' || msg.includes('Unexpected character')) {
        explanation = `The Lexer encountered an illegal character at line ${line}, column ${col}. Password policy DSL only accepts alphanumeric rule names, numbers, booleans, and comments starting with '#'.`;
        fix = `Remove or replace the unrecognized character on line ${line}.`;
      } else if (stage === 'syntax' || msg.includes('Expected')) {
        explanation = `The Parser encountered a grammar syntax error at line ${line}. The DSL requires each rule to have exactly two tokens: '<RuleName> <Value>' (e.g. 'minLength 8' or 'requireUpper true').`;
        fix = `Ensure every line contains both a valid keyword and its corresponding value.`;
      } else if (stage === 'semantic' && msg.includes('Did you mean')) {
        explanation = `The Semantic Analyzer detected a typo in your policy rule name at line ${line}. The compiler used Levenshtein Distance to identify the closest valid DSL keyword.`;
        fix = `Replace the misspelled rule with the suggested keyword.`;
        // Apply auto-fix for typo if suggested
        const match = msg.match(/Did you mean '([^']+)'/);
        if (match && match[1]) {
          const lines = suggestedFixDsl.split('\n');
          if (line > 0 && line <= lines.length) {
            const parts = lines[line - 1].split(/\s+/);
            if (parts.length >= 2) {
              lines[line - 1] = `${match[1]} ${parts[1]}`;
              suggestedFixDsl = lines.join('\n');
            }
          }
        }
      } else if (stage === 'semantic' && msg.includes('minLength cannot be greater than maxLength')) {
        explanation = `Logical conflict detected by the Semantic Analyzer: minLength is greater than maxLength. A password cannot simultaneously be longer than ${dslText.match(/minLength\s+(\d+)/)?.[1] || 'min'} and shorter than ${dslText.match(/maxLength\s+(\d+)/)?.[1] || 'max'}.`;
        fix = `Ensure minLength is less than or equal to maxLength.`;
      } else {
        explanation = `Compiler error during ${stage} phase: ${msg}`;
        fix = `Review line ${line} and verify the rule matches DSL specifications.`;
      }

      explanations.push({
        line,
        col,
        stage,
        originalError: msg,
        explanation,
        fix
      });
    }

    return {
      ok: true,
      stage,
      totalErrors: errors.length,
      explanations,
      hasAutoFix: suggestedFixDsl !== dslText,
      suggestedFixDsl
    };
  }
}

module.exports = AiService;
