#ifndef IR_H
#define IR_H

#include "semantic.h"

struct PolicyIR {
    int minLength = -1;
    int maxLength = -1;

    bool requireUpper = false;
    bool requireLower = false;
    bool requireDigit = false;
    bool requireSpecial = false;
    bool noSpaces = false;
};

PolicyIR buildIR(const PolicyConstraints& c);

#endif