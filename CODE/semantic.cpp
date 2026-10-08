#include "semantic.h"
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
using namespace std;

// Levenshtein Distance for Typo Correction
static int levenshteinDistance(const string& s1, const string& s2) {
    const size_t len1 = s1.size(), len2 = s2.size();
    vector<vector<int>> d(len1 + 1, vector<int>(len2 + 1));
    for(size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for(size_t j = 0; j <= len2; ++j) d[0][j] = j;

    for(size_t i = 1; i <= len1; ++i) {
        for(size_t j = 1; j <= len2; ++j) {
            int cost = (tolower(s1[i - 1]) == tolower(s2[j - 1])) ? 0 : 1;
            d[i][j] = min({ d[i - 1][j] + 1, 
                            d[i][j - 1] + 1, 
                            d[i - 1][j - 1] + cost });
        }
    }
    return d[len1][len2];
}

static string suggestRule(const string& typo) {
    vector<string> validRules = {
        "minLength", "maxLength", "requireUpper", "requireLower",
        "requireDigit", "requireSpecial", "noSpaces"
    };

    string bestMatch = "";
    int minDistance = 3; // Tolerance threshold (max 2 character edits)

    for(const auto& rule : validRules) {
        int dist = levenshteinDistance(typo, rule);
        if(dist < minDistance) {
            minDistance = dist;
            bestMatch = rule;
        }
    }
    return bestMatch;
}

void SemanticAnalyzer::analyze(const ProgramNode& prog) {

    for(const auto& rule : prog.rules) {

        if(rule.name == "minLength") {

            constraints.minLength = stoi(rule.value);
        }

        else if(rule.name == "maxLength") {

            constraints.maxLength = stoi(rule.value);
        }

        else if(rule.name == "requireUpper") {
            constraints.requireUpper = (rule.value == "true" ? 1 : 0);
        }

        else if(rule.name == "requireLower") {
            constraints.requireLower = (rule.value == "true" ? 1 : 0);
        }

        else if(rule.name == "requireDigit") {
            constraints.requireDigit = (rule.value == "true" ? 1 : 0);
        }

        else if(rule.name == "requireSpecial") {
            constraints.requireSpecial = (rule.value == "true" ? 1 : 0);
        }

        else if(rule.name == "noSpaces") {
            constraints.noSpaces = (rule.value == "true" ? 1 : 0);
        }

        else {
            string msg = "Unknown rule: '" + rule.name + "'";
            string suggestion = suggestRule(rule.name);
            if (!suggestion.empty()) {
                msg += ". Did you mean '" + suggestion + "'?";
            }
            errs.push_back({msg, rule.pos});
        }
    }

    // Logical conflict check
    if(constraints.minLength != -1 &&
       constraints.maxLength != -1 &&
       constraints.minLength > constraints.maxLength)
    {
        errs.push_back({
            "minLength cannot be greater than maxLength",
            {0,0}
        });
    }
}