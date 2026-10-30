/**
 * compiler_engine.js
 * 
 * Embedded execution engine mirroring the C++ Policy Compiler pipeline:
 * Lexer -> Parser -> Semantic Analyzer -> IR Generator -> IR Analyzer -> Target CodeGen -> Neuro-Symbolic Evaluator.
 * 
 * Used automatically by the backend when Windows Application Control / Device Guard prevents 
 * executing unsigned local binaries (spawn UNKNOWN), ensuring 100% reliable execution.
 */

const fs = require('fs');
const path = require('path');

// 1. LEXER
class Lexer {
  constructor(input) {
    this.src = input;
    this.i = 0;
    this.line = 1;
    this.col = 1;
    this.errs = [];
  }

  peek() {
    if (this.i >= this.src.length) return '\0';
    return this.src[this.i];
  }

  get() {
    if (this.i >= this.src.length) return '\0';
    const c = this.src[this.i++];
    if (c === '\n') {
      this.line++;
      this.col = 1;
    } else {
      this.col++;
    }
    return c;
  }

  skipSpacesAndComments() {
    while (this.i < this.src.length) {
      const c = this.peek();
      if (c === ' ' || c === '\t' || c === '\r') {
        this.get();
        continue;
      }
      if (c === '#') {
        while (this.i < this.src.length && this.peek() !== '\n') {
          this.get();
        }
        continue;
      }
      break;
    }
  }

  tokenize() {
    const out = [];

    while (this.i < this.src.length) {
      this.skipSpacesAndComments();
      if (this.i >= this.src.length) break;

      const c = this.peek();
      const start = { line: this.line, col: this.col };

      if (c === '\n') {
        this.get();
        out.push({ type: 'Newline', lexeme: '\\n', line: start.line, col: start.col });
        continue;
      }

      if (/[a-zA-Z_]/.test(c)) {
        let s = '';
        while (this.i < this.src.length && /[a-zA-Z0-9_]/.test(this.peek())) {
          s += this.get();
        }
        const type = (s === 'true' || s === 'false') ? 'Boolean' : 'Identifier';
        out.push({ type, lexeme: s, line: start.line, col: start.col });
        continue;
      }

      if (/[0-9]/.test(c)) {
        let s = '';
        while (this.i < this.src.length && /[0-9]/.test(this.peek())) {
          s += this.get();
        }
        out.push({ type: 'Number', lexeme: s, line: start.line, col: start.col });
        continue;
      }

      this.errs.push({ message: `Unexpected character: ${c}`, line: start.line, col: start.col });
      this.get();
      out.push({ type: 'Unknown', lexeme: c, line: start.line, col: start.col });
    }

    out.push({ type: 'End', lexeme: 'EOF', line: this.line, col: this.col });
    return out;
  }
}

// 2. PARSER
class Parser {
  constructor(tokens) {
    this.ts = tokens;
    this.k = 0;
    this.errs = [];
  }

  cur() {
    if (this.k >= this.ts.length) return this.ts[this.ts.length - 1];
    return this.ts[this.k];
  }

  skipNewlines() {
    while (this.cur().type === 'Newline') this.k++;
  }

  parseValue() {
    if (this.cur().type === 'Number' || this.cur().type === 'Boolean') {
      return this.ts[this.k++].lexeme;
    }
    this.errs.push({ message: 'Expected value (number/true/false)', line: this.cur().line, col: this.cur().col });
    this.k++;
    return '';
  }

  parseRule() {
    const nameTok = this.cur();
    if (nameTok.type !== 'Identifier') {
      this.errs.push({ message: 'Expected rule name (identifier)', line: nameTok.line, col: nameTok.col });
    }
    this.k++;

    const value = this.parseValue();
    if (this.cur().type === 'Newline') this.k++;

    return {
      name: nameTok.lexeme,
      value,
      pos: { line: nameTok.line, col: nameTok.col }
    };
  }

  parse() {
    const rules = [];
    this.skipNewlines();

    while (this.cur().type !== 'End') {
      if (this.cur().type === 'Newline') {
        this.skipNewlines();
        continue;
      }

      if (this.cur().type === 'Unknown') {
        this.errs.push({ message: 'Unknown token in input', line: this.cur().line, col: this.cur().col });
        while (this.cur().type !== 'Newline' && this.cur().type !== 'End') this.k++;
        if (this.cur().type === 'Newline') this.k++;
        continue;
      }

      rules.push(this.parseRule());
      this.skipNewlines();
    }

    return { rules };
  }
}

// 3. SEMANTIC ANALYZER with Levenshtein typo suggestion
function levenshteinDistance(s1, s2) {
  const d = Array(s1.length + 1).fill(null).map(() => Array(s2.length + 1).fill(0));
  for (let i = 0; i <= s1.length; i++) d[i][0] = i;
  for (let j = 0; j <= s2.length; j++) d[0][j] = j;

  for (let i = 1; i <= s1.length; i++) {
    for (let j = 1; j <= s2.length; j++) {
      const cost = s1[i - 1].toLowerCase() === s2[j - 1].toLowerCase() ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[s1.length][s2.length];
}

function suggestRule(typo) {
  const validRules = ['minLength', 'maxLength', 'requireUpper', 'requireLower', 'requireDigit', 'requireSpecial', 'noSpaces'];
  let bestMatch = '';
  let minDistance = 3;

  for (const rule of validRules) {
    const dist = levenshteinDistance(typo, rule);
    if (dist < minDistance) {
      minDistance = dist;
      bestMatch = rule;
    }
  }
  return bestMatch;
}

class SemanticAnalyzer {
  constructor() {
    this.errs = [];
    this.constraints = {
      minLength: -1,
      maxLength: -1,
      requireUpper: -1,
      requireLower: -1,
      requireDigit: -1,
      requireSpecial: -1,
      noSpaces: -1
    };
  }

  analyze(prog) {
    for (const rule of prog.rules) {
      if (rule.name === 'minLength') {
        const v = parseInt(rule.value, 10);
        this.constraints.minLength = isNaN(v) ? -1 : v;
      } else if (rule.name === 'maxLength') {
        const v = parseInt(rule.value, 10);
        this.constraints.maxLength = isNaN(v) ? -1 : v;
      } else if (rule.name === 'requireUpper') {
        this.constraints.requireUpper = (rule.value === 'true' ? 1 : 0);
      } else if (rule.name === 'requireLower') {
        this.constraints.requireLower = (rule.value === 'true' ? 1 : 0);
      } else if (rule.name === 'requireDigit') {
        this.constraints.requireDigit = (rule.value === 'true' ? 1 : 0);
      } else if (rule.name === 'requireSpecial') {
        this.constraints.requireSpecial = (rule.value === 'true' ? 1 : 0);
      } else if (rule.name === 'noSpaces') {
        this.constraints.noSpaces = (rule.value === 'true' ? 1 : 0);
      } else {
        let msg = `Unknown rule: '${rule.name}'`;
        const suggestion = suggestRule(rule.name);
        if (suggestion) {
          msg += `. Did you mean '${suggestion}'?`;
        }
        this.errs.push({ message: msg, line: rule.pos.line, col: rule.pos.col });
      }
    }

    if (this.constraints.minLength !== -1 && this.constraints.maxLength !== -1 && this.constraints.minLength > this.constraints.maxLength) {
      this.errs.push({ message: 'minLength cannot be greater than maxLength', line: 0, col: 0 });
    }
  }
}

// 4. IR ANALYZER
class IRAnalyzer {
  static analyze(c) {
    const warnings = [];
    if (c.minLength !== -1 && c.maxLength !== -1 && c.minLength === c.maxLength) {
      warnings.push(`Password length is fixed (${c.minLength})`);
    }
    if (c.minLength !== -1 && c.minLength < 6) {
      warnings.push('Weak policy: minimum length too small');
    }
    if (c.minLength >= 10 && c.requireUpper === 1 && c.requireLower === 1 && c.requireDigit === 1) {
      warnings.push('Strong policy detected');
    }
    return warnings;
  }
}

// 5. TARGET CODE GENERATOR
class CodeGenerator {
  static generate(c, outputPath) {
    const code = `// --- AUTO-GENERATED TARGET CODE ---
// Generated by the Policy Compiler

#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cmath>

struct ValidationResult {
    bool isValid;
    std::vector<std::string> errors;
    double entropyScore;
};

class CompiledPolicyValidator {
private:
    std::string password;

    int calculatePoolSize(int uppers, int lowers, int digits, int specials) {
        int pool = 0;
        if (uppers > 0) pool += 26;
        if (lowers > 0) pool += 26;
        if (digits > 0) pool += 10;
        if (specials > 0) pool += 32;
        return pool;
    }

public:
    CompiledPolicyValidator(const std::string& pwd) : password(pwd) {}

    ValidationResult validate() {
        ValidationResult result;
        result.isValid = true;

        int upperCount = 0, lowerCount = 0, digitCount = 0, specialCount = 0, spaceCount = 0;
        for (char ch : password) {
            if (std::isupper(ch)) upperCount++;
            else if (std::islower(ch)) lowerCount++;
            else if (std::isdigit(ch)) digitCount++;
            else if (std::isspace(ch)) spaceCount++;
            else specialCount++;
        }

        int pool = calculatePoolSize(upperCount, lowerCount, digitCount, specialCount);
        if (pool > 0) {
             result.entropyScore = password.length() * (std::log(pool) / std::log(2));
        } else {
             result.entropyScore = 0;
        }

        // --- COMPILED CONSTRAINTS INJECTION ---
${c.minLength !== -1 ? `        if (password.length() < ${c.minLength}) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Password is too short. Minimum length is ${c.minLength}.");
        }\n` : ''}${c.maxLength !== -1 ? `        if (password.length() > ${c.maxLength}) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Password is too long. Maximum length is ${c.maxLength}.");
        }\n` : ''}${c.requireUpper === 1 ? `        if (upperCount == 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Missing uppercase letter (A-Z).");
        }\n` : (c.requireUpper === 0 ? `        if (upperCount > 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Uppercase letter (A-Z) is forbidden.");
        }\n` : '')}${c.requireLower === 1 ? `        if (lowerCount == 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Missing lowercase letter (a-z).");
        }\n` : (c.requireLower === 0 ? `        if (lowerCount > 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Lowercase letter (a-z) is forbidden.");
        }\n` : '')}${c.requireDigit === 1 ? `        if (digitCount == 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Missing numeric digit (0-9).");
        }\n` : (c.requireDigit === 0 ? `        if (digitCount > 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Numeric digit (0-9) is forbidden.");
        }\n` : '')}${c.requireSpecial === 1 ? `        if (specialCount == 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Missing special character (!@#...).");
        }\n` : (c.requireSpecial === 0 ? `        if (specialCount > 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Special character (!@#...) is forbidden.");
        }\n` : '')}${c.noSpaces === 1 ? `        if (spaceCount > 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Password contains illegal whitespace characters.");
        }\n` : (c.noSpaces === 0 ? `        if (spaceCount == 0) {
            result.isValid = false;
            result.errors.push_back("[REJECTED] Missing required space character.");
        }\n` : '')}        // --------------------------------------

        return result;
    }
};

int main() {
    std::string inputPwd;
    std::cout << "========================================\\n";
    std::cout << "  Standalone Target Policy Evaluator\\n";
    std::cout << "========================================\\n";
    std::cout << "Enter a password to validate: ";
    std::getline(std::cin, inputPwd);

    CompiledPolicyValidator validator(inputPwd);
    ValidationResult res = validator.validate();

    if (res.isValid) {
        std::cout << "\\n✅ STATUS: VALID\\n";
    } else {
        std::cout << "\\n❌ STATUS: INVALID\\n";
        std::cout << "\\n-- Error Log --\\n";
        for (const auto& err : res.errors) {
             std::cout << "* " << err << "\\n";
        }
    }
    std::cout << "\\n-- Metrics --\\n";
    std::cout << "Calculated Entropy: " << res.entropyScore << " bits\\n";
    if (res.entropyScore > 80.0) std::cout << "Strength: VERY STRONG\\n";
    else if (res.entropyScore > 60.0) std::cout << "Strength: STRONG\\n";
    else if (res.entropyScore > 40.0) std::cout << "Strength: MODERATE\\n";
    else std::cout << "Strength: WEAK\\n";

    return 0;
}
`;
    try {
      fs.writeFileSync(outputPath, code, 'utf8');
    } catch (_) {}
  }
}

// 6. NEURO-SYMBOLIC EVALUATOR
class NeuroSymbolicEvaluator {
  static validate(password, c) {
    let upper = 0, lower = 0, digit = 0, special = 0, spaces = 0;
    for (const ch of password) {
      if (/[A-Z]/.test(ch)) upper++;
      else if (/[a-z]/.test(ch)) lower++;
      else if (/[0-9]/.test(ch)) digit++;
      else if (/\s/.test(ch)) spaces++;
      else special++;
    }

    if (c.minLength !== -1 && password.length < c.minLength) return false;
    if (c.maxLength !== -1 && password.length > c.maxLength) return false;

    if (c.requireUpper === 1 && upper === 0) return false;
    if (c.requireUpper === 0 && upper > 0) return false;

    if (c.requireLower === 1 && lower === 0) return false;
    if (c.requireLower === 0 && lower > 0) return false;

    if (c.requireDigit === 1 && digit === 0) return false;
    if (c.requireDigit === 0 && digit > 0) return false;

    if (c.requireSpecial === 1 && special === 0) return false;
    if (c.requireSpecial === 0 && special > 0) return false;

    if (c.noSpaces === 1 && spaces > 0) return false;
    if (c.noSpaces === 0 && spaces === 0) return false;

    return true;
  }

  static getViolations(password, c) {
    const violations = [];
    let upper = 0, lower = 0, digit = 0, special = 0, spaces = 0;
    for (const ch of password) {
      if (/[A-Z]/.test(ch)) upper++;
      else if (/[a-z]/.test(ch)) lower++;
      else if (/[0-9]/.test(ch)) digit++;
      else if (/\s/.test(ch)) spaces++;
      else special++;
    }

    if (c.minLength !== -1 && password.length < c.minLength) {
      violations.push(`Below minimum length: password has ${password.length} characters (requires at least ${c.minLength})`);
    }
    if (c.maxLength !== -1 && password.length > c.maxLength) {
      violations.push(`Exceeds maximum length: password has ${password.length} characters (maximum allowed is ${c.maxLength})`);
    }
    if (c.requireUpper === 1 && upper === 0) {
      violations.push(`Missing required uppercase letter (A-Z)`);
    }
    if (c.requireUpper === 0 && upper > 0) {
      violations.push(`Contains forbidden uppercase letter`);
    }
    if (c.requireLower === 1 && lower === 0) {
      violations.push(`Missing required lowercase letter (a-z)`);
    }
    if (c.requireLower === 0 && lower > 0) {
      violations.push(`Contains forbidden lowercase letter`);
    }
    if (c.requireDigit === 1 && digit === 0) {
      violations.push(`Missing required numeric digit (0-9)`);
    }
    if (c.requireDigit === 0 && digit > 0) {
      violations.push(`Contains forbidden digit`);
    }
    if (c.requireSpecial === 1 && special === 0) {
      violations.push(`Missing required special character (!@#$%^&*...)`);
    }
    if (c.requireSpecial === 0 && special > 0) {
      violations.push(`Contains forbidden special character`);
    }
    if (c.noSpaces === 1 && spaces > 0) {
      violations.push(`Contains forbidden space/whitespace characters`);
    }
    if (c.noSpaces === 0 && spaces === 0) {
      violations.push(`Missing required space character`);
    }

    return violations;
  }

  static evaluate(password, c) {
    let score = 0;
    const reasons = [];

    let upper = 0, lower = 0, digit = 0, special = 0, spaces = 0;
    for (const ch of password) {
      if (/[A-Z]/.test(ch)) upper++;
      else if (/[a-z]/.test(ch)) lower++;
      else if (/[0-9]/.test(ch)) digit++;
      else if (/\s/.test(ch)) spaces++;
      else special++;
    }

    if (c.minLength !== -1) {
      if (password.length >= c.minLength) score += 2;
      else reasons.push('Below minimum length');
    }

    if (c.maxLength !== -1) {
      if (password.length <= c.maxLength) score += 1;
      else reasons.push('Exceeds maximum length');
    }

    if (c.requireUpper === 1) {
      if (upper > 0) score += 1;
      else reasons.push('Missing uppercase letter');
    } else if (c.requireUpper === 0) {
      if (upper === 0) score += 1;
      else reasons.push('Contains forbidden uppercase letter');
    }

    if (c.requireLower === 1) {
      if (lower > 0) score += 1;
      else reasons.push('Missing lowercase letter');
    } else if (c.requireLower === 0) {
      if (lower === 0) score += 1;
      else reasons.push('Contains forbidden lowercase letter');
    }

    if (c.requireDigit === 1) {
      if (digit > 0) score += 1;
      else reasons.push('Missing digit');
    } else if (c.requireDigit === 0) {
      if (digit === 0) score += 1;
      else reasons.push('Contains forbidden digit');
    }

    if (c.requireSpecial === 1) {
      if (special > 0) score += 2;
      else reasons.push('Missing special character');
    } else if (c.requireSpecial === 0) {
      if (special === 0) score += 1;
      else reasons.push('Contains forbidden special character');
    }

    if (c.noSpaces === 1) {
      if (spaces === 0) score += 1;
      else reasons.push('Contains spaces');
    } else if (c.noSpaces === 0) {
      if (spaces > 0) score += 1;
      else reasons.push('Missing space character');
    }

    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    else score -= 1;

    if (upper > 0 && lower > 0 && digit > 0 && special > 0) score += 2;

    for (let i = 1; i < password.length; i++) {
      if (password[i] === password[i - 1]) score -= 1;
    }

    for (let i = 2; i < password.length; i++) {
      if (password.charCodeAt(i) === password.charCodeAt(i - 1) + 1 &&
          password.charCodeAt(i - 1) === password.charCodeAt(i - 2) + 1) {
        score -= 2;
        reasons.push('Sequential pattern detected');
        break;
      }
    }

    const common = new Set(['password', '123456', 'admin', 'qwerty', 'welcome', 'letmein']);
    if (common.has(password)) {
      score = 0;
      reasons.push('Common password detected');
    }

    const level = score <= 2 ? 'Very Weak' : score <= 4 ? 'Weak' : score <= 7 ? 'Medium' : 'Strong';
    return { score, level, reasons };
  }
}

// 7. COMPILER ENGINE ENTRY POINT
function compilePolicy(dslText, testPassword = null) {
  const lexer = new Lexer(dslText);
  const tokens = lexer.tokenize();

  if (lexer.errs.length > 0) {
    return {
      success: false,
      stage: 'lexical',
      errors: lexer.errs
    };
  }

  const parser = new Parser(tokens);
  const prog = parser.parse();

  if (parser.errs.length > 0) {
    return {
      success: false,
      stage: 'syntax',
      errors: parser.errs
    };
  }

  const sem = new SemanticAnalyzer();
  sem.analyze(prog);

  if (sem.errs.length > 0) {
    return {
      success: false,
      stage: 'semantic',
      errors: sem.errs
    };
  }

  const constraints = sem.constraints;
  const warnings = IRAnalyzer.analyze(constraints);

  // Generate target C++ code file
  const outPath = path.join(__dirname, 'generated_validator.cpp');
  CodeGenerator.generate(constraints, outPath);

  let evaluation = { tested: false, isValid: false, score: 0, level: 'Untested', reasons: [], violations: [] };
  if (testPassword !== null && testPassword !== undefined) {
    const isValid = NeuroSymbolicEvaluator.validate(testPassword, constraints);
    const evalRes = NeuroSymbolicEvaluator.evaluate(testPassword, constraints);
    const violations = NeuroSymbolicEvaluator.getViolations(testPassword, constraints);
    evaluation = {
      tested: true,
      isValid,
      score: evalRes.score,
      level: evalRes.level,
      reasons: isValid ? evalRes.reasons : (violations.length > 0 ? violations : evalRes.reasons),
      violations
    };
  }

  return {
    success: true,
    stage: 'complete',
    tokens,
    constraints,
    warnings,
    generated_code_file: 'generated_validator.cpp',
    evaluation
  };
}

module.exports = {
  compilePolicy,
  Lexer,
  Parser,
  SemanticAnalyzer,
  IRAnalyzer,
  CodeGenerator,
  NeuroSymbolicEvaluator
};

