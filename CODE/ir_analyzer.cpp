#include "ir_analyzer.h"

using namespace std;

vector<IRWarning> IRAnalyzer::analyze(const PolicyIR& ir)
{
    vector<IRWarning> warnings;

    // fixed length detection
    if(ir.minLength != -1 && ir.maxLength != -1 &&
       ir.minLength == ir.maxLength)
    {
        warnings.push_back(
        {"Password length is fixed (" + 
         to_string(ir.minLength) + ")"});
    }

    // weak policy
    if(ir.minLength != -1 && ir.minLength < 6)
    {
        warnings.push_back(
        {"Weak policy: minimum length too small"});
    }

    // strong policy
    if(ir.minLength >= 10 &&
       ir.requireUpper == 1 &&
       ir.requireLower == 1 &&
       ir.requireDigit == 1)
    {
        warnings.push_back(
        {"Strong policy detected"});
    }

    return warnings;
}