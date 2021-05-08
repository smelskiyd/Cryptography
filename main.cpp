#include <iostream>

#include <cmath>
#include <cassert>

#include "big_integer.h"
#include "chinese_remainder_theorem.h"
#include "crypto_algorithms.h"
#include "ElGamal.h"

void TestFactorization() {
    auto print_factor = [](const BigInteger& number) {
        auto division = Crypto::Factorize(number);
        std :: cout << "Factorization for number " << number << ": " << "{" << std::endl;
        for (const auto& number : division) {
            std :: cout << "\t" << number.first << " ^ " << number.second << std::endl;
        }
        std :: cout << "};" << std::endl;
    };
    BigInteger number;
    number = BigInteger("32756834783245234533");
    print_factor(number);
    number = BigInteger("23567237");
    print_factor(number);
    number = 24;
    print_factor(number);
    number = 104729;
    print_factor(number);
    number = 123193012;
    print_factor(number);
    number = 1000000007;
    print_factor(number);
    number = 27;
    print_factor(number);
}

void TestIsPrime() {
    auto check_prime = [](const BigInteger& number) {
        std :: cout << "Number " << number << " is ";
        std :: cout << (Crypto::MillerRabinTest(number) ? "prime" : "composite");
        std :: cout << std :: endl;
    };
    BigInteger number;
    number = BigInteger("236487681234");
    check_prime(number);
    number = 27;
    check_prime(number);
    number = 256;
    check_prime(number);
    number = 1000000007;
    check_prime(number);
    number = 541;
    check_prime(number);
    number = 104729;
    check_prime(number);
    number = 104733;
    check_prime(number);
    number = 252097800623;  // The 10,000,000,000th prime
    check_prime(number);
    number = 4;  // The 10,000,000,000th prime
    check_prime(number);
}

void TestDiscreteLog() {
    auto find_log = [](const BigInteger& a, const BigInteger& b, const BigInteger& p) {
        BigInteger result = Crypto::GiantStepBabyStep(a, b, p);
        std :: cout << "Discrete log for equation " << a << " ^ " << "x" << " mod " << p << " = "
                    << b << " is ";
        std :: cout << result << std :: endl;
        std :: cout << a << " ^ " << result << " mod " << p << " = "
                    << BigInteger::pow(a, result, p) << std :: endl;
    };

    BigInteger a = BigInteger("236487681234");
    BigInteger b = BigInteger("1784811251");
    BigInteger p = BigInteger("2341234243");
    find_log(a, b, p);
}

long long Gcd(long long x, long long y) {
    while (x > 0 && y > 0) {
        if (x >= y) x %= y;
        else y %= x;
    }
    return x + y;
}

long long EuclideanExtended(long long x, long long y) {
    if (Gcd(x, y) != 1) {
        assert(false);
    }
    std::vector<long long> r;
    r.push_back(y);
    r.push_back(x);
    while (r.back() != 1) {
        long long lhs = r[(int)r.size() - 2];
        long long rhs = r.back();
        r.push_back(lhs % rhs);
    }
    std::vector<long long> a;
    a.push_back(0);
    a.push_back(1);
    for (int i = 2; i < r.size(); ++i) {
        long long q = r[i - 2] / r[i - 1];
        long long cur = (a[i - 2] - ((a[i - 1] * q) % y) + y) % y;
        a.push_back(cur);
    }
    for (int i = 0; i < r.size(); ++i) {
        std :: cout << r[i] << " " << (i < 2 ? 0 : (r[i - 2] / r[i - 1])) << " " << a[i] << '\n';
    }
    std :: cout << (x * a.back()) % y << std :: endl;
    return a.back();
}

long long EuclideanExtended2(long long a, long long b, long long& x, long long& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    long long xx, yy;
    long long d = EuclideanExtended2(b % a, a, xx, yy);
    x = yy - (b / a) * xx;
    y = xx;
    return d;
}

int main(int argc, const char* argv[]) {
    std :: cout << (233 * 233) % 377 << std :: endl;
    {
        EuclideanExtended(233, 377);
        return 0;
    }
    {
        long long p = 11;
        long long q = 5;
        long long N = p * q;
        long long phi = (p - 1) * (q - 1);
        long long e = 7;
        {
            for (long long i = 2; i < phi && e == -1; ++i) {
                if (Gcd(i, phi) == 1 && Gcd(i, N) == 1) {
                    e = i;
                    break;
                }
            }
        }
        if (e == -1) {
            assert(false);
        }
        std:: cout << "Public key = " << e << ", " << N << std :: endl;
        long long d = EuclideanExtended(e, phi);
        std :: cout << "Private key = " << d << ", " << N << std :: endl;
        long long m = 22;
        BigInteger encoded = BigInteger::pow(m, e, N);
        std :: cout << "encoded = " << encoded << std :: endl;
        BigInteger decoded = BigInteger::pow(encoded, d, N);
        std :: cout << "decoded = " << decoded << std :: endl;
    }

    return 0;
//    TestFactorization();
//    TestIsPrime();
//    TestDiscreteLog();
    ElGamal::Emulate();
    return 0;

    // Lab 1 tests
    {
        CRT_Solver solver;
        solver.add_equation(1, 1, 2);
        solver.add_equation(1, 1, 4);
        solver.add_equation(1, 1, 8);
        if (solver.solve() == nullptr) {
            std::cout << "No solution\n";
        } else {
            std::cout << *solver.solve() << '\n';
        }
    }
    {
        CRT_Solver solver;
        solver.add_equation(1, 0, 2);
        solver.add_equation(1, 0, 4);
        if (solver.solve() == nullptr) {
            std::cout << "No solution\n";
        } else {
            std::cout << *solver.solve() << '\n';
        }
    }
    {
        {
            BigInteger x = 5212141;
            BigInteger y = 31231;
            BigInteger z = 1230;
            auto res = (x + y - z) * (z - x + x - y) / y + x * x / z - (z / y / x);
            std::cout << res << '\n';
        }
        {
            long long x = 5212141;
            long long y = 31231;
            long long z = 1230;
            auto res = (x + y - z) * (z - x + x - y) / y + x * x / z - (z / y / x);
            std::cout << res << '\n';
        }
    }
    {
        BigInteger x = 54;
        BigInteger p = 31;
        BigInteger res = BigInteger::pow(x, p);
        std :: cout << res << '\n';
    }
    {
        {
            BigInteger x = 3;
            BigInteger mod = BigInteger::pow(BigInteger(2), BigInteger(64));
            BigInteger result = BigInteger::pow(x, 200, mod);
            std :: cout << BigInteger(result) << '\n';
        }
        {
            unsigned long long x = 3;
            unsigned long long result = 1;
            for (int i = 1; i <= 200; ++i) {
                result *= x;
            }
            std :: cout << result << '\n';
        }
    }
    {
        {
            BigInteger x = 1321414351235ll;
            BigInteger y = 21416476143134ll;
            BigInteger z = 57456821654ll;
            std::cout << BigInteger::sqrt(x) << '\n';
            std::cout << BigInteger::sqrt(y) << '\n';
            std::cout << BigInteger::sqrt(z) << '\n';
        }
        {
            long double x = 1321414351235ll;
            long double y = 21416476143134ll;
            long double z = 57456821654ll;
            std::cout << std::sqrt(x) << '\n';
            std::cout << std::sqrt(y) << '\n';
            std::cout << std::sqrt(z) << '\n';
        }
    }
    {
        BigInteger result = 1;
        for (int i = 1; i <= 30; ++i) {
            result *= i;
            std :: cout << i << "! = " << result << '\n';
        }
    }
    {
        for (int i = 63; i <= 95; ++i) {
            BigInteger result = BigInteger::pow(BigInteger(2), i);
            std :: cout << "2^" << i << " = " << result << '\n';
        }
    }
    {
        BigInteger result(1);
        for (int i = 1; i <= 500; ++i) {
            BigInteger temp(2);
            result *= temp;
        }
        std :: cout << result << '\n';
    }
    {
        CRT_Solver solver;
        solver.add_equation(1, 6, 7);
        solver.add_equation(1, 8, 11);
        solver.add_equation(1, 11, 13);
        if (solver.solve() != nullptr) {
            std :: cout << *solver.solve() << '\n';
        }
    }
    return 0;
}