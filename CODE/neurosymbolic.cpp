#include "neurosymbolic.h"
#include <cctype>
#include <set>

using namespace std;


NSResult NeuroSymbolicEvaluator::evaluate(const string& password,
                                          const PolicyConstraints& c)
{
    int score = 0;
    vector<string> reasons;

    int upper = 0, lower = 0, digit = 0, special = 0, spaces = 0;

    for(char ch : password)
    {
        if(isupper((unsigned char)ch)) upper++;
        else if(islower((unsigned char)ch)) lower++;
        else if(isdigit((unsigned char)ch)) digit++;
        else if(isspace((unsigned char)ch)) spaces++;
        else special++;
    }

    // symbolic rule satisfaction
    if(c.minLength != -1)
    {
        if((int)password.size() >= c.minLength) score += 2;
        else reasons.push_back("Below minimum length");
    }

    if(c.maxLength != -1)
    {
        if((int)password.size() <= c.maxLength) score += 1;
        else reasons.push_back("Exceeds maximum length");
    }

    if(c.requireUpper == 1)
    {
        if(upper > 0) score += 1;
        else reasons.push_back("Missing uppercase letter");
    }
    else if(c.requireUpper == 0)
    {
        if(upper == 0) score += 1;
        else reasons.push_back("Contains forbidden uppercase letter");
    }

    if(c.requireLower == 1)
    {
        if(lower > 0) score += 1;
        else reasons.push_back("Missing lowercase letter");
    }
    else if(c.requireLower == 0)
    {
        if(lower == 0) score += 1;
        else reasons.push_back("Contains forbidden lowercase letter");
    }

    if(c.requireDigit == 1)
    {
        if(digit > 0) score += 1;
        else reasons.push_back("Missing digit");
    }
    else if(c.requireDigit == 0)
    {
        if(digit == 0) score += 1;
        else reasons.push_back("Contains forbidden digit");
    }

    if(c.requireSpecial == 1)
    {
        if(special > 0) score += 2;
        else reasons.push_back("Missing special character");
    }
    else if(c.requireSpecial == 0)
    {
        if(special == 0) score += 1;
        else reasons.push_back("Contains forbidden special character");
    }

    if(c.noSpaces == 1)
    {
        if(spaces == 0) score += 1;
        else reasons.push_back("Contains spaces");
    }
    else if(c.noSpaces == 0)
    {
        if(spaces > 0) score += 1;
        else reasons.push_back("Missing space character");
    }

    // neural-inspired feature analysis
    if(password.size() >= 12) score += 2;
    else if(password.size() >= 8) score += 1;
    else score -= 1;

    if(upper > 0 && lower > 0 && digit > 0 && special > 0)
        score += 2;

    // repeated consecutive characters penalty
    for(int i=1;i<(int)password.size();i++)
    {
        if(password[i] == password[i-1])
            score -= 1;
    }

    // simple sequential pattern penalty
    for(int i=2;i<(int)password.size();i++)
    {
        if(password[i] == password[i-1] + 1 &&
           password[i-1] == password[i-2] + 1)
        {
            score -= 2;
            reasons.push_back("Sequential pattern detected");
            break;
        }
    }

    // common password detection
    set<string> common = {
        "password", "123456", "admin", "qwerty", "welcome", "letmein"
    };

    if(common.count(password))
    {
        score = 0;
        reasons.push_back("Common password detected");
    }

    string level;
    if(score <= 2) level = "Very Weak";
    else if(score <= 4) level = "Weak";
    else if(score <= 7) level = "Medium";
    else level = "Strong";

    return {score, level, reasons};
}