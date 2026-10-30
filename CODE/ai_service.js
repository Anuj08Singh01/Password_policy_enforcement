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
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=${this.geminiApiKey}`;
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

    // 1. Exact length (e.g. "exactly 10 characters", "exact 10 chars", "strictly 10 characters")
    const exactMatch = lower.match(/\b(?:exactly|exact|strictly)\s+(\d+)\s*(?:characters?|chars?|letters?)?\b/i) ||
                       lower.match(/\b(\d+)\s*(?:characters?|chars?)\s*(?:exactly|exact)\b/i);

    // 2. Range (e.g. "between 8 and 20", "from 8 to 20", "8 to 20 chars", "8-20 characters")
    const rangeMatch = lower.match(/\b(?:between|from)\s+(\d+)\s+(?:and|to)\s+(\d+)\b/i) ||
                       lower.match(/\b(\d+)\s*(?:-|to)\s*(\d+)\s*(?:characters?|chars?)\b/i);

    if (exactMatch) {
      rules.push(`minLength ${exactMatch[1]}`);
      rules.push(`maxLength ${exactMatch[1]}`);
    } else if (rangeMatch) {
      rules.push(`minLength ${rangeMatch[1]}`);
      rules.push(`maxLength ${rangeMatch[2]}`);
    } else {
      // 3. Min length matching:
      // Covers:
      // - "at least 10", "minimum 10", "min 10"
      // - "must be of 10 characters", "pasword must be of 10 characters"
      // - "must be 10 characters", "should be 10 characters", "needs to be 10 characters"
      // - "10 characters long", "10 characters minimum", "10 characters", "10 chars"
      // - "length of 10", "length 10", "size 10"
      const minMatch = 
        lower.match(/(?:at\s+least|minimum|min(?:imum)?\s+(?:of|length)?|min\s*length\s*(?:of)?|min|greater\s+than\s+or\s+equal\s+to|>=)\s*(\d+)/i) ||
        lower.match(/(\d+)\s*(?:characters?|chars?|letters?)\s*(?:minimum|min|or\s+more|at\s+least|\+)/i) ||
        lower.match(/(?:must\s+be\s+of|must\s+be|should\s+be|has\s+to\s+be|have\s+to\s+be|need\s+to\s+be|needs\s+to\s+be|be\s+of|is\s+of|\bof\b|length\s+of|size\s+of|\blength\b|\bsize\b)\s*(?:at\s+least\s+)?(\d+)\s*(?:characters?|chars?|letters?)?/i) ||
        lower.match(/(?:pas+word|pass?code|pwd|token)?\s*(?:must\s+be\s+of|must\s+be|should\s+be|is)\s+(\d+)\s*(?:characters?|chars?)?/i) ||
        lower.match(/(\d+)\s*(?:characters?|chars?|letters?)\s*(?:long|in\s+length)?/i);

      if (minMatch) {
        rules.push(`minLength ${minMatch[1]}`);
      } else if (lower.includes('short') || lower.includes('weak')) {
        rules.push('minLength 8');
      } else if (lower.match(/\b(\d+)\b/)) {
        // Any standalone number in user's prompt (e.g. "password 10")
        const numMatch = lower.match(/\b(\d+)\b/);
        rules.push(`minLength ${numMatch[1]}`);
      } else {
        rules.push('minLength 8');
      }

      // 4. Max length matching:
      const maxMatch = 
        lower.match(/(?:at\s+most|maximum|max(?:imum)?\s*(?:of|length)?|max\s*length\s*(?:of)?|max|less\s+than\s+or\s+equal\s+to|<=|up\s+to|no\s+more\s+than)\s*(\d+)/i) ||
        lower.match(/(\d+)\s*(?:characters?|chars?)\s*(?:max(?:imum)?|at\s+most|or\s+less)/i);

      if (maxMatch) {
        rules.push(`maxLength ${maxMatch[1]}`);
      }
    }

    // Upper
    if (/\b(?:no\s+upper|forbid\s+upper|disallow\s+upper|without\s+upper(?:case)?|no\s+capital)\b/i.test(lower)) {
      rules.push('requireUpper false');
    } else if (/\b(?:upper|uppercase|capital|caps|large\s+letter)\b/i.test(lower)) {
      rules.push('requireUpper true');
    }

    // Lower
    if (/\b(?:no\s+lower|forbid\s+lower|disallow\s+lower|without\s+lower(?:case)?|no\s+small)\b/i.test(lower)) {
      rules.push('requireLower false');
    } else if (/\b(?:lower|lowercase|small\s+letter)\b/i.test(lower)) {
      rules.push('requireLower true');
    }

    // Digit
    if (/\b(?:no\s+digit|no\s+number|without\s+digit|without\s+number|no\s+numeric)\b/i.test(lower)) {
      rules.push('requireDigit false');
    } else if (/\b(?:digit|digits|number|numbers|numeric|integers?)\b/i.test(lower)) {
      rules.push('requireDigit true');
    }

    // Special
    if (/\b(?:no\s+special|no\s+symbol|without\s+special|without\s+symbol)\b/i.test(lower)) {
      rules.push('requireSpecial false');
    } else if (/\b(?:special|symbol|symbols|punctuation|non-alphanumeric|special\s+char)\b/i.test(lower)) {
      rules.push('requireSpecial true');
    }

    // Spaces
    if (/\b(?:no\s+spaces?|without\s+spaces?|disallow\s+spaces?|forbid\s+spaces?|space-free)\b/i.test(lower)) {
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

    // Identify active constraints explicitly configured in the compiled policy
    const activeConstraints = [];
    if (c.minLength > 0) activeConstraints.push('minLength');
    if (c.maxLength > 0) activeConstraints.push('maxLength');
    if (c.requireUpper !== -1) activeConstraints.push('requireUpper');
    if (c.requireLower !== -1) activeConstraints.push('requireLower');
    if (c.requireDigit !== -1) activeConstraints.push('requireDigit');
    if (c.requireSpecial !== -1) activeConstraints.push('requireSpecial');
    if (c.noSpaces !== -1) activeConstraints.push('noSpaces');

    // Helper: generate a password that satisfies all active constraints EXCEPT the one to violate
    const createTargetedFailure = (ruleToViolate, detailIndex = 0) => {
      let pwd = '';
      let desc = '';

      if (ruleToViolate === 'minLength') {
        if (detailIndex === 0) {
          const bLen = Math.max(1, minL - 1);
          pwd = this.buildSyntheticPassword(bLen, c, 'boundary');
          desc = `Boundary test: length ${pwd.length} is 1 character below required minLength ${minL}`;
        } else if (detailIndex === 1) {
          const sLen = Math.max(1, Math.min(4, minL - 2));
          pwd = this.buildSyntheticPassword(sLen, c, 'short');
          desc = `Too short: length ${pwd.length} is below minLength ${minL}`;
        } else {
          const vLen = Math.min(2, Math.max(1, minL - 3));
          pwd = this.buildSyntheticPassword(vLen, c, 'minimal');
          desc = `Extreme short boundary: length ${pwd.length} is well below minLength ${minL}`;
        }
      } else if (ruleToViolate === 'maxLength') {
        if (detailIndex === 0) {
          pwd = this.buildSyntheticPassword(maxL + 1, c);
          desc = `Boundary test: length ${maxL + 1} exceeds maxLength ${maxL} by 1 character`;
        } else {
          pwd = this.buildSyntheticPassword(maxL + 6, c);
          desc = `Too long: length ${maxL + 6} exceeds maxLength ${maxL}`;
        }
      } else if (ruleToViolate === 'requireUpper') {
        if (c.requireUpper === 1) {
          const raw = this.buildSyntheticPassword(targetL, { ...c, requireUpper: -1 });
          pwd = raw.toLowerCase();
          desc = 'Missing required uppercase letter (A-Z)';
        } else {
          const raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.substring(0, targetL - 1) + 'X';
          desc = 'Contains forbidden uppercase letter';
        }
      } else if (ruleToViolate === 'requireLower') {
        if (c.requireLower === 1) {
          const raw = this.buildSyntheticPassword(targetL, { ...c, requireLower: -1 });
          pwd = raw.toUpperCase();
          desc = 'Missing required lowercase letter (a-z)';
        } else {
          const raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.substring(0, targetL - 1) + 'x';
          desc = 'Contains forbidden lowercase letter';
        }
      } else if (ruleToViolate === 'requireDigit') {
        if (c.requireDigit === 1) {
          let raw = this.buildSyntheticPassword(targetL, { ...c, requireDigit: -1 });
          pwd = raw.replace(/[0-9]/g, 'a');
          desc = 'Missing required numeric digit (0-9)';
        } else {
          const raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.substring(0, targetL - 1) + '9';
          desc = 'Contains forbidden numeric digit';
        }
      } else if (ruleToViolate === 'requireSpecial') {
        if (c.requireSpecial === 1) {
          let raw = this.buildSyntheticPassword(targetL, { ...c, requireSpecial: -1 });
          pwd = raw.replace(/[^A-Za-z0-9]/g, 'A');
          desc = 'Missing required special character (!@#$...)';
        } else {
          const raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.substring(0, targetL - 1) + '!';
          desc = 'Contains forbidden special character';
        }
      } else if (ruleToViolate === 'noSpaces') {
        if (c.noSpaces === 1) {
          const raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.substring(0, 4) + ' ' + raw.substring(4);
          desc = 'Contains forbidden whitespace / space character';
        } else {
          let raw = this.buildSyntheticPassword(targetL, c);
          pwd = raw.replace(/\s/g, 'x');
          desc = 'Missing required space character';
        }
      }

      return { password: pwd, description: desc, intendedFailure: ruleToViolate };
    };

    // Construct failing synthetic candidates strictly targeting ACTIVE policy constraints
    const invalidCandidates = [];

    if (activeConstraints.length === 0) {
      invalidCandidates.push(
        { password: '', description: 'Empty password string', intendedFailure: 'empty' },
        { password: ' ', description: 'Single whitespace character', intendedFailure: 'blank' },
        { password: '1', description: 'Single character string', intendedFailure: 'short' }
      );
    } else if (activeConstraints.length === 1) {
      const singleRule = activeConstraints[0];
      invalidCandidates.push(createTargetedFailure(singleRule, 0));
      invalidCandidates.push(createTargetedFailure(singleRule, 1));
      invalidCandidates.push(createTargetedFailure(singleRule, 2));
    } else if (activeConstraints.length === 2) {
      invalidCandidates.push(createTargetedFailure(activeConstraints[0], 0));
      invalidCandidates.push(createTargetedFailure(activeConstraints[1], 0));
      invalidCandidates.push(createTargetedFailure(activeConstraints[0], 1));
    } else {
      invalidCandidates.push(createTargetedFailure(activeConstraints[0], 0));
      invalidCandidates.push(createTargetedFailure(activeConstraints[1], 0));
      invalidCandidates.push(createTargetedFailure(activeConstraints[2], 0));
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
   * Helper: Run a single password through the compiler evaluator
   */
  async evaluatePasswordWithCompiler(dslText, testPassword) {
    try {
      const { compilePolicy } = require('./compiler_engine');
      const res = compilePolicy(dslText, testPassword);
      if (res.evaluation) {
        return res.evaluation;
      }
      return { isValid: false, score: 0, level: 'Invalid', reasons: ['Compilation failed'] };
    } catch (e) {
      return { isValid: false, score: 0, level: 'Error', reasons: [e.message] };
    }
  }

  /**
   * Comprehensive Auto-Fix Engine for Password Policy DSL
   * Corrects typos, invalid values (like 'maybe'), logical conflicts (minLength > maxLength), and removes unsupported rules.
   */
  autoFixDsl(dslText) {
    if (!dslText) return dslText;
    const validKeywords = ['minLength', 'maxLength', 'requireUpper', 'requireLower', 'requireDigit', 'requireSpecial', 'noSpaces'];
    const booleanKeywords = new Set(['requireUpper', 'requireLower', 'requireDigit', 'requireSpecial', 'noSpaces']);
    const numberKeywords = new Set(['minLength', 'maxLength']);

    const levenshtein = (s1, s2) => {
      const d = Array(s1.length + 1).fill(null).map(() => Array(s2.length + 1).fill(0));
      for (let i = 0; i <= s1.length; i++) d[i][0] = i;
      for (let j = 0; j <= s2.length; j++) d[0][j] = j;
      for (let i = 1; i <= s1.length; i++) {
        for (let j = 1; j <= s2.length; j++) {
          const c = s1[i - 1].toLowerCase() === s2[j - 1].toLowerCase() ? 0 : 1;
          d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
        }
      }
      return d[s1.length][s2.length];
    };

    const lines = dslText.split('\n');
    const fixedLines = [];
    let minL = null;
    let minLineIdx = -1;
    let maxL = null;
    let maxLineIdx = -1;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const trimmed = rawLine.trim();

      // Preserve comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) {
        fixedLines.push(rawLine);
        continue;
      }

      const parts = trimmed.split(/\s+/);
      let keyword = parts[0];
      let value = parts.slice(1).join(' ');

      // 1. Check keyword or find closest Levenshtein match
      let matchedKeyword = null;
      if (validKeywords.includes(keyword)) {
        matchedKeyword = keyword;
      } else {
        let best = null;
        let minD = 4;
        for (const vk of validKeywords) {
          const dist = levenshtein(keyword, vk);
          if (dist < minD) {
            minD = dist;
            best = vk;
          }
        }
        if (best) matchedKeyword = best;
      }

      // If completely unrecognized rule (e.g. unknownRule), comment it out
      if (!matchedKeyword) {
        fixedLines.push(`# [Auto-Fix: Removed unsupported rule] ${rawLine}`);
        continue;
      }

      // 2. Validate and correct value
      let fixedValue = value;
      if (booleanKeywords.has(matchedKeyword)) {
        const vLow = value.toLowerCase().trim();
        if (['true', 'yes', 'y', '1', 'enable', 'enabled', 'maybe'].includes(vLow) || !vLow) {
          fixedValue = 'true';
        } else if (['false', 'no', 'n', '0', 'disable', 'disabled'].includes(vLow)) {
          fixedValue = 'false';
        } else {
          fixedValue = 'true';
        }
      } else if (numberKeywords.has(matchedKeyword)) {
        const numMatch = value.match(/\d+/);
        if (numMatch) {
          fixedValue = numMatch[0];
        } else {
          fixedValue = matchedKeyword === 'minLength' ? '8' : '32';
        }

        const numVal = parseInt(fixedValue, 10);
        if (matchedKeyword === 'minLength') {
          minL = numVal;
          minLineIdx = fixedLines.length;
        } else if (matchedKeyword === 'maxLength') {
          maxL = numVal;
          maxLineIdx = fixedLines.length;
        }
      }

      fixedLines.push(`${matchedKeyword} ${fixedValue}`);
    }

    // 3. Resolve logical conflict if minLength > maxLength
    if (minL !== null && maxL !== null && minL > maxL) {
      if (minLineIdx !== -1 && maxLineIdx !== -1) {
        fixedLines[minLineIdx] = `minLength ${maxL}`;
        fixedLines[maxLineIdx] = `maxLength ${minL}`;
      }
    }

    return fixedLines.join('\n');
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
    const suggestedFixDsl = this.autoFixDsl(dslText);

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
        explanation = `The Parser encountered a grammar syntax error at line ${line}. The DSL requires each rule to have exactly two tokens: '<RuleName> <Value>' (e.g. 'minLength 8' or 'requireUpper true'). Here, '${msg}' occurred.`;
        fix = `Ensure line ${line} contains a valid keyword followed by an integer or true/false boolean.`;
      } else if (stage === 'semantic' && msg.includes('Did you mean')) {
        explanation = `The Semantic Analyzer detected a typo in your policy rule name at line ${line}. The compiler used Levenshtein Distance to identify the closest valid DSL keyword.`;
        fix = `Replace the misspelled rule with the suggested keyword.`;
      } else if (stage === 'semantic' && msg.includes('minLength cannot be greater than maxLength')) {
        explanation = `Logical conflict detected by the Semantic Analyzer: minLength is greater than maxLength. A password cannot simultaneously be longer than ${dslText.match(/minLength\s+(\d+)/)?.[1] || 'min'} and shorter than ${dslText.match(/maxLength\s+(\d+)/)?.[1] || 'max'}.`;
        fix = `Ensure minLength is less than or equal to maxLength.`;
      } else {
        explanation = `Compiler diagnostic during ${stage} phase: ${msg}`;
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
      hasAutoFix: suggestedFixDsl.trim() !== dslText.trim(),
      suggestedFixDsl
    };
  }

  /**
   * FEATURE 4b: Explain Password Evaluation Failures
   */
  async explainPasswordFailure(passwordFailure, dslText) {
    const pwd = passwordFailure.password || '';
    const violations = passwordFailure.violations || passwordFailure.reasons || [];
    const constraints = passwordFailure.constraints || {};

    const items = violations.map(v => {
      let advice = 'Adjust the password to satisfy this policy constraint.';
      const vLow = v.toLowerCase();

      if (vLow.includes('minimum length') || vLow.includes('below minimum')) {
        const needed = constraints.minLength ? Math.max(1, constraints.minLength - pwd.length) : 'more';
        advice = `The password has only ${pwd.length} character(s). Add at least ${needed} more character(s) to reach the required minLength of ${constraints.minLength || 16}.`;
      } else if (vLow.includes('maximum length') || vLow.includes('exceeds')) {
        const excess = constraints.maxLength ? Math.max(1, pwd.length - constraints.maxLength) : 'excess';
        advice = `The password has ${pwd.length} characters. Remove at least ${excess} character(s) to not exceed maxLength ${constraints.maxLength}.`;
      } else if (vLow.includes('forbidden uppercase') || (vLow.includes('uppercase') && vLow.includes('forbidden'))) {
        advice = 'The password contains uppercase letters (A-Z), which are forbidden by this policy (requireUpper false). Remove or convert all capital letters to lowercase.';
      } else if (vLow.includes('uppercase') || vLow.includes('capital')) {
        advice = 'The password contains no uppercase letters (A-Z). Add at least one capital letter (requireUpper true).';
      } else if (vLow.includes('forbidden lowercase') || (vLow.includes('lowercase') && vLow.includes('forbidden'))) {
        advice = 'The password contains lowercase letters (a-z), which are forbidden by this policy (requireLower false). Remove or convert all small letters.';
      } else if (vLow.includes('lowercase') || vLow.includes('small letter')) {
        advice = 'The password contains no lowercase letters (a-z). Add at least one small letter (requireLower true).';
      } else if (vLow.includes('forbidden digit') || (vLow.includes('digit') && vLow.includes('forbidden')) || (vLow.includes('number') && vLow.includes('forbidden'))) {
        advice = 'The password contains numeric digits (0-9), which are forbidden by this policy (requireDigit false). Remove all numbers from your password.';
      } else if (vLow.includes('digit') || vLow.includes('number') || vLow.includes('numeric')) {
        advice = 'The password contains no numeric digits. Add at least one number (0-9) to satisfy requireDigit true.';
      } else if (vLow.includes('forbidden special') || (vLow.includes('special') && vLow.includes('forbidden')) || (vLow.includes('symbol') && vLow.includes('forbidden'))) {
        advice = 'The password contains special symbols (!@#$...), which are forbidden by this policy (requireSpecial false). Remove all special symbols.';
      } else if (vLow.includes('special') || vLow.includes('symbol') || vLow.includes('punctuation')) {
        advice = 'The password is missing special symbols. Add at least one symbol like !@#$%^&*() (requireSpecial true).';
      } else if (vLow.includes('missing') && vLow.includes('space')) {
        advice = 'The password is missing spaces. Add at least one whitespace character (noSpaces false).';
      } else if (vLow.includes('space') || vLow.includes('whitespace')) {
        advice = 'Whitespace characters are forbidden by this policy (noSpaces true). Remove all spaces.';
      } else if (vLow.includes('sequential')) {
        advice = 'Avoid predictable sequential patterns like "123" or "abc". Use random or varied characters.';
      } else if (vLow.includes('common')) {
        advice = 'This password matches a common dictionary password. Choose a more unique password.';
      }

      return {
        violation: v,
        advice
      };
    });

    return {
      ok: true,
      type: 'password_failure',
      passwordLength: pwd.length,
      totalViolations: violations.length,
      violations: items,
      summary: `Your password failed ${violations.length} compiled policy rule(s).`,
      generalGuidance: 'Update the password according to the suggestions above and click Evaluate again.'
    };
  }
}

module.exports = AiService;
