//
// Created by daniilsmelskiy on 25.03.21.
//

#include "big_integer.h"
#include "crypto_algorithms.h"

#include "test_runner.h"
#include "profile.h"

namespace {
    const std::string kBase64Symbols{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                                     "0123456789+/"};

    class BigIntegerMockup : public BigInteger {
      public :
        static BigInteger CallNativeMultiplication(const BigInteger& lhs, const BigInteger& rhs) {
            return NativeMultiplication(lhs, rhs);
        }

        static BigInteger CallKaratsubaMultiplication(const BigInteger& lhs, const BigInteger& rhs) {
            return KaratsubaMultiplication(lhs, rhs);
        }
    };
}

void TestConversions() {
    auto Construct = []() {
        ASSERT_EQUAL("321412", BigInteger(321412).ToString());
        ASSERT_EQUAL("23138219414912", BigInteger("23138219414912").ToString());
        ASSERT_EQUAL("-321482194810323", BigInteger("-321482194810323").ToString());
        ASSERT_EQUAL("0", BigInteger(-0).ToString());
    };

    auto ToInt = []() {
        ASSERT_EQUAL(328492, BigInteger(328492).ToInt());
        ASSERT_EQUAL(-423492, BigInteger(-423492).ToInt());
        ASSERT_EQUAL(0, BigInteger(0).ToInt());
        ASSERT_EQUAL(123456789, BigInteger(123456789).ToInt());
    };

    auto ToBase2 = []() {
        ASSERT_EQUAL("1000", BigInteger(8).GetBase2());
        ASSERT_EQUAL("10011101", BigInteger(157).GetBase2());
        ASSERT_EQUAL("100010110011100110100010001010011000000010000001111101011011110001101",
                     BigInteger("321031294210491201421").GetBase2());
    };

    auto FromBase2 = []() {
        ASSERT_EQUAL(BigInteger(8), BigInteger::GetFromBase2("1000"));
        ASSERT_EQUAL(BigInteger(157), BigInteger::GetFromBase2("10011101"));
        ASSERT_EQUAL(BigInteger("321031294210491201421"),
                     BigInteger::GetFromBase2("10001011001110011010001000101001100"
                                              "0000010000001111101011011110001101"));
    };

    auto ToBase64 = []() {
        ASSERT_EQUAL("IW", BigInteger(534).GetBase64());
        for (int i = 0; i < 64; ++i) {
            std::string tmp;
            tmp += kBase64Symbols[i];
            ASSERT_EQUAL(tmp, BigInteger(i).GetBase64());
        }
    };

    auto FromBase64 = []() {
        ASSERT_EQUAL(BigInteger::GetFromBase64("IW"), 534);
        for (int i = 0; i < 64; ++i) {
            std::string tmp;
            tmp += kBase64Symbols[i];
            ASSERT_EQUAL(BigInteger::GetFromBase64(tmp), i);
        }
    };

    auto ToByte = []() {
        for (int i = 0; i < (1 << 8); ++i) {
            std::string tmp;
            tmp += static_cast<char>(i);
            ASSERT_EQUAL(tmp, BigInteger(i).GetByte());
        }
    };

    auto FromByte = []() {
        for (int i = 0; i < (1 << 8); ++i) {
            std::string tmp;
            tmp += static_cast<char>(i);
            ASSERT_EQUAL(BigInteger::GetFromByte(tmp), i);
        }
    };

    TestRunner tr;
    RUN_TEST(tr, Construct);
    RUN_TEST(tr, ToInt);
    RUN_TEST(tr, ToBase2);
    RUN_TEST(tr, FromBase2);
    RUN_TEST(tr, ToBase64);
    RUN_TEST(tr, FromBase64);
    RUN_TEST(tr, ToByte);
    RUN_TEST(tr, FromByte);
}

void TestMultiplications() {
    auto NativeMultiplication = [] {
        for (int i = 0; i <= 300; ++i) {
            for (int j = 12345; j <= 23456; ++j) {
                int cur = i * j;
                auto result = BigIntegerMockup::CallNativeMultiplication(i, j);
                ASSERT_EQUAL(result, cur);
            }
        }
    };

    auto KaratsubaMultiplicationSmall = [] {
        for (int i = 1; i <= 300; ++i) {
            for (int j = 12345; j <= 23456; ++j) {
                int cur = i * j;
                auto result = BigIntegerMockup::CallKaratsubaMultiplication(i, j);
                ASSERT_EQUAL(result, cur);
            }
        }
    };

    auto KaratsubaMultiplicationBig = [] {
        for (int i = 1; i <= 100; ++i) {
            BigInteger random_a = Crypto::GetRandomNumberLen(100);
            BigInteger random_b = Crypto::GetRandomNumberLen(100);
            ASSERT_EQUAL(BigIntegerMockup::CallNativeMultiplication(random_a, random_b),
                         BigIntegerMockup::CallKaratsubaMultiplication(random_a, random_b));
        }
    };

    auto CompareMultiplicationsTime = [] {
        for (int i = 1; i <= 1; ++i) {
            BigInteger random_a = Crypto::GetRandomNumberLen(10000);
            BigInteger random_b = Crypto::GetRandomNumberLen(10000);
            std::cout << "Test #" << i << std::endl;
            {
                LOG_DURATION("Native multiplication");
                BigIntegerMockup::CallNativeMultiplication(random_a, random_b);
            }
            {
                LOG_DURATION("Karatsuba multiplication");
                BigIntegerMockup::CallKaratsubaMultiplication(random_a, random_b);
            }
        }
    };

    TestRunner tr;
    RUN_TEST(tr, NativeMultiplication);
    RUN_TEST(tr, KaratsubaMultiplicationSmall);
    RUN_TEST(tr, KaratsubaMultiplicationBig);

    RUN_TEST(tr, CompareMultiplicationsTime);
}

int main(int argc, char* argv[]) {
    TestRunner tr;
    RUN_TEST(tr, TestConversions);
    RUN_TEST(tr, TestMultiplications);
}