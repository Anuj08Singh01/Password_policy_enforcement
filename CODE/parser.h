#ifndef PARSER_H
#define PARSER_H

#include "token.h"
#include "ast.h"
#include <vector>
#include <string>

struct ParseError {
    std::string message;
    SourcePos pos;
};

class Parser {
public:
    explicit Parser(std::vector<Token> tokens);

    ProgramNode parse();
    const std::vector<ParseError>& errors() const { return errs; }

private:
    std::vector<Token> ts;
    size_t k = 0;
    std::vector<ParseError> errs;

    const Token& cur() const;
    bool match(TokenType t);
    const Token& consume(TokenType t, const std::string& msg);
    void skipNewlines();

    RuleNode parseRule();
    std::string parseValue();
};

#endif
