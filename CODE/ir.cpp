#include "ir.h"

PolicyIR buildIR(const PolicyConstraints& c)
{
    PolicyIR ir;

    ir.minLength = c.minLength;
    ir.maxLength = c.maxLength;

    ir.requireUpper = c.requireUpper;
    ir.requireLower = c.requireLower;
    ir.requireDigit = c.requireDigit;
    ir.requireSpecial = c.requireSpecial;
    ir.noSpaces = c.noSpaces;

    return ir;
}