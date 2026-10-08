#ifndef CODEGEN_H
#define CODEGEN_H

#include "semantic.h" // Includes PolicyConstraints
#include <string>

// The CodeGenerator takes the analyzed constraints and outputs C++ source code.
class CodeGenerator {
public:
    static void generate(const PolicyConstraints& constraints, const std::string& outputFile);
};

#endif
