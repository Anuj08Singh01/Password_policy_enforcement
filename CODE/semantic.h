#ifndef SEMANTIC_H
#define SEMANTIC_H

#include "ast.h"
#include <vector>
#include <string>

struct SemanticError {
    std::string message;
    SourcePos pos;
};

struct PolicyConstraints {
    int minLength = -1;
    int maxLength = -1;
    int requireUpper = -1;
    int requireLower = -1;
    int requireDigit = -1;
    int requireSpecial = -1;
    int noSpaces = -1;
};

class SemanticAnalyzer {
    std::vector<SemanticError> errs;
    PolicyConstraints constraints;

public:
    void analyze(const ProgramNode& prog);

    const std::vector<SemanticError>& errors() const { return errs; }
    const PolicyConstraints& getConstraints() const { return constraints; }
};

#endif