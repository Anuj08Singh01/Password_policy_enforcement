#include "lexer.h"
#include <cctype>

using namespace std;

Lexer::Lexer(string input) : src(move(input)) {}

char Lexer::peek() const {
    if(i >= src.size()) return '\0';
    return src[i];
}

bool Lexer::eof() const { 
    return i >= src.size();
}

char Lexer::get() {
    if(eof()) return '\0';
    char c = src[i++];

    if(c == '\n') {
        pos.line++;
        pos.col = 1;
    } else {
        pos.col++;
    }
    return c;
}

void Lexer::skipSpacesAndComments() {
    while(!eof()) {
        char c = peek();

        if(c == ' ' || c == '\t' || c == '\r') {
            get();
            continue;
        }

        // comments start with #
        if(c == '#') {
            while(!eof() && peek() != '\n') get();
            continue;
        }

        break;
    }
}

Token Lexer::lexIdentifierOrBool() {
    SourcePos start = pos;
    string s;

    while(!eof()) {
        char c = peek();
        if(isalnum((unsigned char)c) || c == '_') {
            s.push_back(get());
        } else break;
    }

    Token t;
    t.pos = start;
    t.lexeme = s;

    if(s == "true" || s == "false") 
        t.type = TokenType::Boolean;
    else 
        t.type = TokenType::Identifier;

    return t;
}

Token Lexer::lexNumber() {
    SourcePos start = pos;
    string s;

    while(!eof() && isdigit((unsigned char)peek())) {
        s.push_back(get());
    }

    Token t;
    t.type = TokenType::Number;
    t.pos = start;
    t.lexeme = s;
    return t;
}

vector<Token> Lexer::tokenize() {
    vector<Token> out;

    while(!eof()) 
    {
        skipSpacesAndComments();
        if(eof()) break;

        char c = peek();
        SourcePos start = pos;

        if(c == '\n') {
            get();
            out.push_back({TokenType::Newline, "\\n", start});
            continue;
        }

        if(isalpha((unsigned char)c) || c == '_') {
            out.push_back(lexIdentifierOrBool());
            continue;
        }

        if(isdigit((unsigned char)c)) {
            out.push_back(lexNumber());
            continue;
        }

        // Unknown character -> lexical error
        string msg = "Unexpected character: ";
        msg.push_back(c);
        errs.push_back({msg, start});
        get();
        out.push_back({TokenType::Unknown, string(1,c), start});
    }

    out.push_back({TokenType::End, "EOF", pos});
    return out;
}

