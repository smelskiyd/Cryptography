#pragma once

#include "big_integer.h"


namespace Crypto {
    void RandomSeedInitialization();

    BigInteger GetRandomNumber(const BigInteger& max_value);
    BigInteger GetRandomNumber(const BigInteger& min_value, const BigInteger& max_value);
    BigInteger GetRandomNumberLen(int len);
    BigInteger GetRandomNumberWithBitness(int bitness);

    BigInteger GetClosestPrimeNumber(const BigInteger& src);
    std::vector<BigInteger> GetRandomPrimeNumbers(const BigInteger& lhs, const BigInteger& rhs, int k = 1);
    std::vector<BigInteger> GetFirstPrimeNumbers(const BigInteger& lhs, const BigInteger& rhs, int k = 1);
    std::vector<BigInteger> GetRandomPrimeNumbersWithSomeBitness(int bitness, int k = 1);
    std::vector<BigInteger> GetFirstPrimeNumbersWithSomeBitness(int bitness, int k = 1);

    bool MillerRabinTest(const BigInteger& number);
    bool LucasSelfridgeTest(const BigInteger& number);
    bool BPSWTest(const BigInteger& number);

    void PollardRhoAlgorithm(const BigInteger& number, std::vector<BigInteger>& result,
                             int kLimit = -1);

    std::vector<std::pair<BigInteger, unsigned int>> Factorize(const BigInteger& number);

    BigInteger Phi(const BigInteger& number);
    int        Mobius(const BigInteger& number);

    int LegendreSymbol(const BigInteger& a, const BigInteger& p);
    int JacobySymbol(BigInteger a, BigInteger p);

    BigInteger CipollaAlgorithm(BigInteger n, const BigInteger& p);

    BigInteger GiantStepBabyStep(const BigInteger& a, const BigInteger& b,
                                 const BigInteger& p);
}  // namespace Crypto
