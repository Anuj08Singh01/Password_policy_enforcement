#ifndef IR_ANALYZER_H
#define IR_ANALYZER_H

#include "ir.h"
#include <vector>
#include <string>

struct IRWarning {
    std::string message;
};

class IRAnalyzer {
public:
    static std::vector<IRWarning> analyze(const PolicyIR& ir);
};

#endif