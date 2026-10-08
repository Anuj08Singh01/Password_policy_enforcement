#ifndef AST_H
#define AST_H

#include "token.h"
#include <string>
#include <vector>

struct RuleNode {
    std::string name;
    std::string value;
    SourcePos pos;
};

struct ProgramNode {
    std::vector<RuleNode> rules;
};

#endif
