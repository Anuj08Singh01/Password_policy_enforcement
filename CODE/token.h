#ifndef TOKEN_H
#define TOKEN_H

#include <string>

enum class TokenType {
    Identifier,
    Number,
    Boolean,
    Newline,
    End,
    Unknown
};

struct SourcePos {
    int line = 1;
    int col  = 1;
};

struct Token {
    TokenType type = TokenType::Unknown;
    std::string lexeme;
    SourcePos pos;
};

inline std::string tokenTypeName(TokenType t) {
    switch(t) {
        case TokenType::Identifier: return "Identifier";
        case TokenType::Number:     return "Number";
        case TokenType::Boolean:    return "Boolean";
        case TokenType::Newline:    return "Newline";
        case TokenType::End:        return "End";
        default:                    return "Unknown";
    }
}

#endif
