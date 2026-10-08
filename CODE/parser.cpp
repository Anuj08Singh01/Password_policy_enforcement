#include "parser.h"

using namespace std;

Parser::Parser(vector<Token> tokens) : ts(move(tokens)) {}

const Token& Parser::cur() const {
    if(k >= ts.size()) return ts.back();
    return ts[k];
}

bool Parser::match(TokenType t) {
    if(cur().type == t) { 
        k++; 
        return true; 
    }
    return false;
}

const Token& Parser::consume(TokenType t, const string& msg) {
    if(cur().type == t) 
        return ts[k++];

    errs.push_back({msg, cur().pos});
    return ts[k]; // recovery: return current
}

void Parser::skipNewlines() {
    while(cur().type == TokenType::Newline) 
        k++;
}

string Parser::parseValue() {
    if(cur().type == TokenType::Number)   
        return ts[k++].lexeme;

    if(cur().type == TokenType::Boolean)  
        return ts[k++].lexeme;

    errs.push_back({"Expected value (number/true/false)", cur().pos});
    k++; // consume something to recover
    return "";
}

RuleNode Parser::parseRule() {
    Token nameTok = consume(TokenType::Identifier, "Expected rule name (identifier)");
    string value = parseValue();

    if(cur().type == TokenType::Newline) 
        k++;

    RuleNode r;
    r.name = nameTok.lexeme;
    r.value = value;
    r.pos = nameTok.pos;
    return r;
}

ProgramNode Parser::parse() {
    ProgramNode prog;
    skipNewlines();

    while(cur().type != TokenType::End) {

        if(cur().type == TokenType::Newline) { 
            skipNewlines(); 
            continue; 
        }

        if(cur().type == TokenType::Unknown) {
            errs.push_back({"Unknown token in input", cur().pos});

            while(cur().type != TokenType::Newline && 
                  cur().type != TokenType::End) 
                k++;

            if(cur().type == TokenType::Newline) 
                k++;

            continue;
        }

        prog.rules.push_back(parseRule());
        skipNewlines();
    }

    return prog;
}

