//
// Created by daniilsmelskiy on 27.03.21.
//

#include <cmath>

#include "big_integer.h"
#include "crypto_algorithms.h"

#include "test_runner.h"

namespace {

    bool PrimalityTestNative(long long src) {
        if (src == 1) {
            return false;
        }
        long long r = std::sqrt(src);
        for (long long i = 2; i <= r; ++i) {
            if (src % i == 0) {
                return false;
            }
        }
        return true;
    }

};

void PrimalityTests() {
    Crypto::RandomSeedInitialization();
    /// Miller-Rabin Test check
    auto MillerRabinTest = [] () {
        const int left_bound = 1;
        const int right_bound = 1000;
        ASSERT(left_bound <= right_bound);
        for (int i = left_bound; i <= right_bound; ++i) {
            ASSERT_EQUAL(PrimalityTestNative(i), Crypto::MillerRabinTest(i));
        }
    };
    auto BPSWTest = [] () {
        const int left_bound = 1;
        const int right_bound = 1000;
        ASSERT(left_bound <= right_bound);
        for (int i = left_bound; i <= right_bound; ++i) {
            ASSERT_EQUAL(PrimalityTestNative(i), Crypto::BPSWTest(i));
        }
    };
    auto BPSWRandomTests = [] () {
        for (int i = 1; i <= 100; ++i) {
            BigInteger random_x = Crypto::GetRandomNumberLen(12);
            ASSERT_EQUAL(PrimalityTestNative(random_x.ToLong()), Crypto::BPSWTest(random_x));
        }
        for (int i = 1; i <= 100; ++i) {
            BigInteger random_x = Crypto::GetRandomNumberLen(12);
            random_x = Crypto::GetClosestPrimeNumber(random_x);
            ASSERT_EQUAL(PrimalityTestNative(random_x.ToLong()), Crypto::BPSWTest(random_x));
        }
    };

    TestRunner tr;
    RUN_TEST(tr, MillerRabinTest);
//    RUN_TEST(tr, BPSWTest);
//    RUN_TEST(tr, BPSWRandomTests);
};


int main(int argc, char* argv[]) {
    TestRunner tr;
    RUN_TEST(tr, PrimalityTests);
}