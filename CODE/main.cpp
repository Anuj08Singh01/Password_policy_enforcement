#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "lexer.h"
#include "parser.h"
#include "semantic.h"
#include "ir.h"
#include "ir_analyzer.h"
#include "neurosymbolic.h"
#include "codegen.h"

using namespace std;

static string readAll(const string& path)
{
    ifstream f(path);
    stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static string escapeJson(const string& s)
{
    ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if ((unsigned char)c < 0x20) {
            o << "\\u" << hex << setw(4) << setfill('0') << (int)(unsigned char)c;
        } else {
            o << c;
        }
    }
    return o.str();
}

static void printDiagnostic(const string& msg, const SourcePos& pos, const vector<string>& lines)
{
    // Print the error message with location
    cout << "Error at line " << pos.line << ", col " << pos.col << ": " << msg << "\n";
    
    // Print the exact line of code
    if (pos.line > 0 && pos.line <= (int)lines.size()) {
        string lineStr = lines[pos.line - 1];
        string prefix = "  " + to_string(pos.line) + " | ";
        cout << prefix << lineStr << "\n";
        
        // Print the caret pointing to the exact column
        int spaceCount = prefix.length() + pos.col - 1;
        cout << string(spaceCount, ' ') << "^~~\n";
    }
}

bool validatePassword(const string& password, const PolicyConstraints& c)
{
    int upper=0, lower=0, digit=0, special=0, spaces=0;

    for(char ch : password)
    {
        if(isupper((unsigned char)ch)) upper++;
        else if(islower((unsigned char)ch)) lower++;
        else if(isdigit((unsigned char)ch)) digit++;
        else if(isspace((unsigned char)ch)) spaces++;
        else special++;
    }

    if(c.minLength != -1 && (int)password.size() < c.minLength) return false;
    if(c.maxLength != -1 && (int)password.size() > c.maxLength) return false;

    if(c.requireUpper == 1 && upper==0) return false;
    if(c.requireUpper == 0 && upper>0) return false;

    if(c.requireLower == 1 && lower==0) return false;
    if(c.requireLower == 0 && lower>0) return false;

    if(c.requireDigit == 1 && digit==0) return false;
    if(c.requireDigit == 0 && digit>0) return false;

    if(c.requireSpecial == 1 && special==0) return false;
    if(c.requireSpecial == 0 && special>0) return false;

    if(c.noSpaces == 1 && spaces>0) return false;
    if(c.noSpaces == 0 && spaces==0) return false;

    return true;
}

int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        cout << "Usage: policy_compiler <policyfile> [--password <pwd>] [--check] [--json]\n";
        return 0;
    }

    string path = argv[1];
    bool jsonOutput = false;
    bool dryRun = false;
    string cliPassword = "";
    bool hasCliPassword = false;

    for (int i = 2; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--json") {
            jsonOutput = true;
        } else if (arg == "--check" || arg == "--dry-run") {
            dryRun = true;
        } else if (arg == "--password" && i + 1 < argc) {
            cliPassword = argv[++i];
            hasCliPassword = true;
        } else if (!arg.empty() && arg[0] != '-') {
            cliPassword = arg;
            hasCliPassword = true;
        }
    }

    ifstream chk(path);
    if(!chk)
    {
        if(jsonOutput) {
            cout << "{\"success\":false,\"stage\":\"io\",\"errors\":[{\"message\":\"Cannot open file: " 
                 << escapeJson(path) << "\",\"line\":0,\"col\":0}]}\n";
        } else {
            cout << "Error: cannot open file: " << path << "\n";
        }
        return 1;
    }

    string input = readAll(path);

    // Split input into lines for diagnostic reporting
    vector<string> sourceLines;
    {
        stringstream ss(input);
        string line;
        while(getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            sourceLines.push_back(line);
        }
    }

    // 1. LEXICAL ANALYSIS
    Lexer lex(input);
    auto tokens = lex.tokenize();

    if(!lex.errors().empty())
    {
        if(jsonOutput) {
            cout << "{\n  \"success\": false,\n  \"stage\": \"lexical\",\n  \"errors\": [\n";
            for(size_t i = 0; i < lex.errors().size(); i++) {
                const auto& e = lex.errors()[i];
                cout << "    {\"message\": \"" << escapeJson(e.message) 
                     << "\", \"line\": " << e.pos.line 
                     << ", \"col\": " << e.pos.col << "}" 
                     << (i + 1 < lex.errors().size() ? "," : "") << "\n";
            }
            cout << "  ]\n}\n";
        } else {
            cout << "\n--- LEXICAL ERRORS ---\n";
            for(const auto& e : lex.errors()) {
                printDiagnostic(e.message, e.pos, sourceLines);
                cout << "\n";
            }
        }
        return 1;
    }

    // 2. SYNTAX ANALYSIS
    Parser parser(tokens);
    ProgramNode prog = parser.parse();

    if(!parser.errors().empty())
    {
        if(jsonOutput) {
            cout << "{\n  \"success\": false,\n  \"stage\": \"syntax\",\n  \"errors\": [\n";
            for(size_t i = 0; i < parser.errors().size(); i++) {
                const auto& e = parser.errors()[i];
                cout << "    {\"message\": \"" << escapeJson(e.message) 
                     << "\", \"line\": " << e.pos.line 
                     << ", \"col\": " << e.pos.col << "}" 
                     << (i + 1 < parser.errors().size() ? "," : "") << "\n";
            }
            cout << "  ]\n}\n";
        } else {
            cout << "\n--- SYNTAX ERRORS ---\n";
            for(const auto& e : parser.errors()) {
                printDiagnostic(e.message, e.pos, sourceLines);
                cout << "\n";
            }
        }
        return 1;
    }

    // 3. SEMANTIC ANALYSIS
    SemanticAnalyzer sem;
    sem.analyze(prog);

    if(!sem.errors().empty())
    {
        if(jsonOutput) {
            cout << "{\n  \"success\": false,\n  \"stage\": \"semantic\",\n  \"errors\": [\n";
            for(size_t i = 0; i < sem.errors().size(); i++) {
                const auto& e = sem.errors()[i];
                cout << "    {\"message\": \"" << escapeJson(e.message) 
                     << "\", \"line\": " << e.pos.line 
                     << ", \"col\": " << e.pos.col << "}" 
                     << (i + 1 < sem.errors().size() ? "," : "") << "\n";
            }
            cout << "  ]\n}\n";
        } else {
            cout << "\n--- SEMANTIC ERRORS ---\n";
            for(const auto& e : sem.errors()) {
                printDiagnostic(e.message, e.pos, sourceLines);
                cout << "\n";
            }
        }
        return 1;
    }

    const auto& c = sem.getConstraints();

    // 4. IR GENERATION
    PolicyIR ir = buildIR(c);

    // 5. CODE GENERATION PHASE
    CodeGenerator::generate(c, "generated_validator.cpp");

    // 6. IR ANALYSIS
    auto warnings = IRAnalyzer::analyze(ir);

    // 7. NEURO-SYMBOLIC EVALUATION
    string password = "";
    bool didEval = false;
    bool isValid = false;
    NSResult nsResult;

    if (hasCliPassword) {
        password = cliPassword;
        didEval = true;
    } else if (!dryRun && !jsonOutput) {
        cout << "Policy Compiled Successfully!\n";
        cout << "\nFinal Policy Constraints:\n";
        cout << "  minLength      : " << c.minLength << "\n";
        cout << "  maxLength      : " << c.maxLength << "\n";
        cout << "  requireUpper   : " << (c.requireUpper ? "true" : "false") << "\n";
        cout << "  requireLower   : " << (c.requireLower ? "true" : "false") << "\n";
        cout << "  requireDigit   : " << (c.requireDigit ? "true" : "false") << "\n";
        cout << "  requireSpecial : " << (c.requireSpecial ? "true" : "false") << "\n";
        cout << "  noSpaces       : " << (c.noSpaces ? "true" : "false") << "\n";

        cout << "\nGenerating Target C++ Validation Program...\n";
        cout << "Target C++ code generated at: generated_validator.cpp\n";

        if(!warnings.empty()) {
            cout << "\nIR ANALYSIS WARNINGS:\n";
            for(const auto& w : warnings) {
                cout << "  - " << w.message << "\n";
            }
        }

        cout << "\nEnter password to evaluate: ";
        if (cin >> password) {
            didEval = true;
        }
    }

    if (didEval) {
        isValid = validatePassword(password, c);
        nsResult = NeuroSymbolicEvaluator::evaluate(password, c);
        if (!jsonOutput) {
            if(!isValid) {
                cout << "\nPassword does NOT satisfy policy rules ❌\n";
            } else {
                cout << "\nNeuro-Symbolic Password Evaluation:\n";
                cout << "  Score  : " << nsResult.score << "\n";
                cout << "  Level  : " << nsResult.level << "\n";
            }
        }
    }

    if (jsonOutput) {
        cout << "{\n";
        cout << "  \"success\": true,\n";
        cout << "  \"stage\": \"complete\",\n";
        
        // Tokens
        cout << "  \"tokens\": [\n";
        for (size_t i = 0; i < tokens.size(); i++) {
            cout << "    {\"type\": \"" << escapeJson(tokenTypeName(tokens[i].type)) 
                 << "\", \"lexeme\": \"" << escapeJson(tokens[i].lexeme) 
                 << "\", \"line\": " << tokens[i].pos.line 
                 << ", \"col\": " << tokens[i].pos.col << "}" 
                 << (i + 1 < tokens.size() ? "," : "") << "\n";
        }
        cout << "  ],\n";

        // Constraints
        cout << "  \"constraints\": {\n";
        cout << "    \"minLength\": " << c.minLength << ",\n";
        cout << "    \"maxLength\": " << c.maxLength << ",\n";
        cout << "    \"requireUpper\": " << c.requireUpper << ",\n";
        cout << "    \"requireLower\": " << c.requireLower << ",\n";
        cout << "    \"requireDigit\": " << c.requireDigit << ",\n";
        cout << "    \"requireSpecial\": " << c.requireSpecial << ",\n";
        cout << "    \"noSpaces\": " << c.noSpaces << "\n";
        cout << "  },\n";

        // Warnings
        cout << "  \"warnings\": [\n";
        for (size_t i = 0; i < warnings.size(); i++) {
            cout << "    \"" << escapeJson(warnings[i].message) << "\"" 
                 << (i + 1 < warnings.size() ? "," : "") << "\n";
        }
        cout << "  ],\n";

        cout << "  \"generated_code_file\": \"generated_validator.cpp\",\n";

        // Evaluation
        cout << "  \"evaluation\": {\n";
        cout << "    \"tested\": " << (didEval ? "true" : "false") << ",\n";
        cout << "    \"isValid\": " << (isValid ? "true" : "false") << ",\n";
        cout << "    \"score\": " << nsResult.score << ",\n";
        cout << "    \"level\": \"" << escapeJson(nsResult.level) << "\",\n";
        cout << "    \"reasons\": [\n";
        for (size_t i = 0; i < nsResult.reasons.size(); i++) {
            cout << "      \"" << escapeJson(nsResult.reasons[i]) << "\"" 
                 << (i + 1 < nsResult.reasons.size() ? "," : "") << "\n";
        }
        cout << "    ]\n";
        cout << "  }\n";
        cout << "}\n";
    }

    return 0;
}