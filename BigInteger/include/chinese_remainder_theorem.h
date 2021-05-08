#pragma once

#include "big_integer.h"
#include <vector>

class CRT_Solver {
public:
    ~CRT_Solver() {
        delete answer;
    }

    void add_equation(BigInteger new_a, BigInteger new_b, BigInteger new_p);

    void reset();

    BigInteger* solve();

private:
    std::vector<std::pair<BigInteger, BigInteger>> equations;
    BigInteger* answer = nullptr;
};
