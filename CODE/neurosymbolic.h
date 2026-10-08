#ifndef NEURO_SYMBOLIC_H
#define NEURO_SYMBOLIC_H

#include "semantic.h"
#include <string>
#include <vector>

struct NSResult {
    int score;
    std::string level;
    std::vector<std::string> reasons;
};

class NeuroSymbolicEvaluator {
public:
    static NSResult evaluate(const std::string& password,
                             const PolicyConstraints& c);
};

#endif