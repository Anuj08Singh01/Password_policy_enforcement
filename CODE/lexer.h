#ifndef LEXER_H
#define LEXER_H

#include "token.h"
#include <string>
#include <vector>

struct LexError {
    std::string message;
    SourcePos pos;
};

class Lexer {
public:
    explicit Lexer(std::string input);

    std::vector<Token> tokenize();
    const std::vector<LexError>& errors() const { return errs; }

private:
    std::string src;
    size_t i = 0;
    SourcePos pos{1,1};
    std::vector<LexError> errs;

    char peek() const;
    char get();
    bool eof() const; // end of file

    void skipSpacesAndComments();
    Token lexIdentifierOrBool();
    Token lexNumber();
};

#endif
