#include <map>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <random>
#include <sys/time.h>

#include "crypto_algorithms.h"

namespace {

    using fp2 = std::pair<BigInteger, BigInteger>;

    fp2 fp2mul(fp2 a, fp2 b, BigInteger p, BigInteger w2) {
        fp2 answer;
        BigInteger tmp1, tmp2;
     
        tmp1 = (a.first * b.first) % p;
        tmp2 = (a.second * b.second) % p;
        tmp2 = (tmp2 * w2) % p;
        answer.first = (tmp1 + tmp2) % p;
        tmp1 = (a.first * b.second) % p;
        tmp2 = (a.second * b.first) % p;
        answer.second = (tmp1 + tmp2) % p;
        
        return answer;
    }

    fp2 fp2square(fp2 a, BigInteger p, BigInteger w2) {
        return fp2mul(a, a, p, w2);
    }
     
    fp2 fp2pow(fp2 a, BigInteger n, BigInteger p, BigInteger w2) {
        fp2 ret;
     
        if (n == 0) {
            ret.first = 1;
            ret.second = 0;
            return ret;
        }
        if (n == 1) {
            return a;
        }
        if ((n % 2) == 0) {
            return fp2square(fp2pow(a, n / 2, p, w2), p, w2);
        } else {
            return fp2mul(a, fp2pow(a, n - 1, p, w2), p, w2);
        }
    }

}  // namespace

void Crypto::RandomSeedInitialization() {
//    timeval time;
  //  gettimeofday(&time, nullptr);
    //std::srand((time.tv_sec * 1000) + (time.tv_usec / 1000));
    unsigned int time_ui = static_cast<unsigned int>(time(nullptr));
    srand( time_ui );
}

BigInteger Crypto::GetRandomNumber(const BigInteger& max_value) {
    const size_t max_length = max_value.getLength();
    
    BigInteger result = 0;
    bool is_smaller = false;
    for (int i = 1; i <= max_length; ++i) {
        if (is_smaller) {
            int new_digit = rand() % 10;
            result = (result * 10) + new_digit;
        } else {
            int cur_digit = max_value.getDigitAt(i);
            int new_digit = rand() % (cur_digit + 1);
            
            result = (result * 10) + new_digit;
            is_smaller |= (new_digit < cur_digit);
        }
    }
    return result;
}

BigInteger Crypto::GetRandomNumber(const BigInteger& min_value, const BigInteger& max_value) {
    BigInteger diff = max_value - min_value + 1;
    return min_value + GetRandomNumber(diff) - 1;
}

BigInteger Crypto::GetRandomNumberLen(int len) {
    BigInteger max_limit;
    for (int i = 1; i <= len; ++i) {
        max_limit *= 10;
        max_limit += 9;
    }
    return GetRandomNumber((max_limit + 1) / 10, max_limit);
}

BigInteger Crypto::GetRandomNumberWithBitness(int bitness) {
    BigInteger lhs = BigInteger::pow(2, bitness - 1);
    BigInteger rhs = BigInteger::pow(2, bitness) - 1;
    return GetRandomNumber(lhs, rhs);
}

BigInteger Crypto::GetClosestPrimeNumber(const BigInteger& src) {
    assert(src > 0);
    if (src == 1 || src == 2) {
        return 2;
    }
    BigInteger result = src;
    if (result % 2 == 0) {
        result += 1;
    }
    while (!MillerRabinTest(result)) {
        result += 2;
    }
    return result;
}

std::vector<BigInteger> Crypto::GetRandomPrimeNumbers(const BigInteger& lhs, const BigInteger& rhs, int k) {
    std::vector<BigInteger> result;
    result.reserve(k);

    if (rhs - lhs <= 200) {
        result = GetFirstPrimeNumbers(lhs, rhs, 200);
        unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(result.begin(), result.end(), std::default_random_engine(seed));
        if (k < result.size()) {
            result.resize(k);
        }
        return result;
    }

    for (int i = 0; i < k; ++i) {
        bool found = false;
        for (int j = 0; j < 10; ++j) {
            BigInteger cur = GetRandomNumber(lhs, rhs);
            cur = GetClosestPrimeNumber(cur);
            if (cur <= rhs) {
                found = true;
                result.push_back(cur);
                break;
            }
        }
        if (!found) {
            result.shrink_to_fit();
            // TODO: Add c-error message
            break;
        }
    }
    return result;
}

std::vector<BigInteger> Crypto::GetFirstPrimeNumbers(const BigInteger& lhs, const BigInteger& rhs, int k) {
    BigInteger last = lhs;
    std::vector<BigInteger> result;
    result.reserve(k);
    for (int i = 0; i < k && last <= rhs; ++i, last += 1) {
        last = GetClosestPrimeNumber(last);
        if (last <= rhs) {
            result.push_back(last);
        }
    }
    result.shrink_to_fit();
    return result;
}

std::vector<BigInteger> Crypto::GetRandomPrimeNumbersWithSomeBitness(int bitness, int k) {
    if (bitness == 1) {
        return {};
    }
    BigInteger lhs = BigInteger::pow(2, bitness - 1);
    BigInteger rhs = BigInteger::pow(2, bitness) - 1;
    return GetRandomPrimeNumbers(lhs, rhs, k);
}

std::vector<BigInteger> Crypto::GetFirstPrimeNumbersWithSomeBitness(int bitness, int k) {
    if (bitness == 1) {
        return {};
    }
    BigInteger lhs = BigInteger::pow(2, bitness - 1);
    BigInteger rhs = BigInteger::pow(2, bitness) - 1;
    return GetFirstPrimeNumbers(lhs, rhs, k);
}

bool Crypto::MillerRabinTest(const BigInteger& number) {
    if (number == 2 || number == 3) {
        return true;
    }
    if (number < 2 || number % 2 == 0) {
        return false;
    }
    
    int degree = 0;
    BigInteger d = (number - 1);
    BigInteger q = d;
    while (d % 2 == 0) {
        ++degree;
        d /= 2;
    }

    for (int i = 0; i < std::max(10, degree); ++i) {
        BigInteger alpha = GetRandomNumber(BigInteger(2), number - 2);
        BigInteger x = BigInteger::pow(alpha, d, number);
        if (x == 1 || x == q) {
            continue;
        }
        for (int j = 1; j < degree; ++j) {
            x = (x * x) % number;
            if (x == 1) {
                return false;
            } else if (x == q) {
                break;
            }
        }

        if (x != q) {
            return false;
        }
    }
    return true;
}

bool Crypto::LucasSelfridgeTest(const BigInteger& number) {
    if (number == 2) {
        return true;
    }
    if (number < 2 || number % 2 == 0) {
        return false;
    }
    if (auto sq = BigInteger::sqrt(number); sq * sq == number) {
        return false;
    }
    BigInteger d_sign;
    for (int d = 5, sign = 1; ; d += 2, sign ^= 1) {
        if (BigInteger g = BigInteger::gcd(number, d); g > 1 && g < number) {
            return false;
        }
        d_sign = d;
        if (!sign) {
            d_sign *= -1;
        }
        if (JacobySymbol(d_sign, number) == -1) {
            break;
        }
    }
    BigInteger p = 1, q = (p - d_sign) / 4;
    BigInteger d = number + 1;
    int step = 0;
    while (d.IsEven()) {
        ++step;
        d /= 2;
    }
    BigInteger u = 1, v = p, u2m = 1, v2m = p, qm = q, qm2 = q*2, qkd = q;
    std::string d_in_bit = d.GetBase2();
    for (int i = (int)d_in_bit.size() - 2; i >= 0; --i) {
        u2m = (u2m * v2m) % number;
        v2m = (v2m * v2m) % number;
        while (v2m < qm2) {
            v2m += number;
        }
        v2m -= qm2;
        qm = (qm * qm) % number;
        qm2 = qm * 2;
        if (d_in_bit[i] == '1') {
            BigInteger t1 = (u2m * v) % number,  t2 = (v2m * u) % number,
                       t3 = (v2m * v) % number,  t4 = (((u2m * u) % number) * d_sign) % number;
            u = t1 + t2;
            if (u.IsOdd()) {
                u += number;
            }
            u = (u / 2) % number;
            v = t3 + t4;
            if (v.IsOdd()) {
                v += number;
            }
            v = (v / 2) % number;
            qkd = (qkd * qm) % number;
        }
    }
    if (u==0 || v==0) {
        return true;
    }
    BigInteger qkd2 = qkd * 2;
    for (int r = 1; r < step; ++r) {
        auto Normalize = [&number] (BigInteger& x) {
            while (x < 0) {
                x += number;
            }
            while (x >= number) {
                x -= number;
            }
        };
        v = (v * v) % number - qkd2;
        Normalize(v);
        if (v == 0) {
            return true;
        }
        if (r < step - 1) {
            qkd = (qkd * 1ll * qkd) % number;
            qkd2 = qkd * 2;
        }
    }
    return false;
}

bool Crypto::BPSWTest(const BigInteger& number) {
    if (number == 2) {
        return true;
    }
    if (number < 2 || number % 2 == 0) {
        return  false;
    }
    static std::vector<BigInteger> SmallPrimeNumbers{2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
    for (const auto& i : SmallPrimeNumbers) {
        if (number == i) {
            return true;
        }
        if (number % i == 0) {
            return false;
        }
    }
    if (!MillerRabinTest(number)) {
        return false;
    }
    return LucasSelfridgeTest(number);
}

void Crypto::PollardRhoAlgorithm(const BigInteger& number, std::vector<BigInteger>& result,
                                 const int kLimit) {
    int cur_limit = kLimit;
    
    if (number == 1) {
        return;
    }
    if (number % 2 == 0) {
        result.emplace_back(2);
        PollardRhoAlgorithm(number / 2, result);
        return;
    }
    if (MillerRabinTest(number)) {
        result.push_back(number);
        return;
    }

    while (cur_limit != 0) {
        --cur_limit;
        
        BigInteger x = GetRandomNumber(number);
        BigInteger y = x;
        BigInteger c = GetRandomNumber(number);
        BigInteger g = 1;
        BigInteger diff = 0;
        
        while (g == 1) {
            x = ((x * x) % number + c) % number;
            y = ((y * y) % number + c) % number;
            y = ((y * y) % number + c) % number;
            diff = BigInteger::abs(x - y);
            g = BigInteger::gcd(diff, number);
        }
        
        if (diff == 0) {
            continue;
        }
        
        PollardRhoAlgorithm(g, result, kLimit);
        PollardRhoAlgorithm(number / g, result, kLimit);
        break;
    }

    return;
}

std::vector<std::pair<BigInteger, unsigned int>> Crypto::Factorize(const BigInteger& number) {
    std::vector<BigInteger> partition;
    PollardRhoAlgorithm(number, partition);
    std::sort(partition.begin(), partition.end());
    
    std::vector<std::pair<BigInteger, unsigned int>> result;
    for (int l = 0; l < partition.size(); ) {
        int r = l;
        unsigned int cnt = 0;
        while (r < partition.size() && partition[l] == partition[r]) {
            ++cnt;
            ++r;
        }
        result.emplace_back(partition[l], cnt);
        l = r;
    }
    
    return result;
}

BigInteger Crypto::Phi(const BigInteger& number) {
    BigInteger result = number;
    const auto factor = Factorize(number);
    
    for (const auto& divisor : factor) {
        result -= result / divisor.first;
    }
    
    return result;
}

int Crypto::Mobius(const BigInteger& number) {
    const auto factor = Factorize(number);
    
    for (const auto& divisor : factor) {
        if (divisor.second > 1) {
            return 0;
        }
    }
    
    return ((factor.size() & 1) ? -1 : 1);
}

int Crypto::LegendreSymbol(const BigInteger& a, const BigInteger& p) {
    if (a % p == 0) {
        return 0;
    }
    
    BigInteger q = BigInteger::pow(a, (p - 1) / 2, p);
    
    return (q == 1 ? 1 : -1);
}

int Crypto::JacobySymbol(BigInteger a, BigInteger p) {
    if (p % 2 == 0) {
        std :: cout << "P has to be an odd number greater than 1.\n";
        exit(1);
    }
    if (p == 1) {
        return 1;
    }
    
    BigInteger g = BigInteger::gcd(a, p);
    if (g != 1) {
        return 0;
    }
    
    int result = 1;
    if (a < 0) {
        a *= -1;
        if (p % 4 == 3) {
            result = -1;
        }
    }
    
    do {
        int t = 0;
        while (a % 2 == 0) {
            ++t;
            a /= 2;
        }
        if (t % 2 == 1) {
            if (p % 8 == 3 || p % 8 == 5) {
                result = -result;
            }
        }
        
        if (a % 4 == 3 && p % 4 == 3) {
            result = -result;
        }
        BigInteger c = a;
        a = p % c;
        p = c;
    } while(a != 0);
    
    return result;
}

BigInteger Crypto::CipollaAlgorithm(BigInteger n, const BigInteger& p) {
    n %= p;
    
    if (p <= 2 || !MillerRabinTest(p)) {
        std :: cout << "P has to be a prime number greater than 2\n";
        return -1;
    }
    if (LegendreSymbol(n, p) != 1) {
        std :: cout << "Legendre symbol (n | p) has to be equal to 1\n";
        return -1;
    }
    
    fp2 result;
    
    while (true) {
        BigInteger w2, a;
        do {
            a = GetRandomNumber(2, p);
            w2 = a * a - n;
        } while (LegendreSymbol(w2, p) != -1);

        result.first = a;
        result.second = 1;
        result = fp2pow(result, (p + 1) / 2, p, w2);
        
        if (result.second != 0) {
            continue;
        }
        
        BigInteger x = result.first;
        BigInteger y = p - x;
                
        if ((x * x) % p == n && (y * y) % p == n) {
            break;
        }
    }
    
    return result.first;
}
    


BigInteger Crypto::GiantStepBabyStep(const BigInteger& a, const BigInteger& b,
                                     const BigInteger& p) {
    const BigInteger m = BigInteger::sqrt(p) + 1;
    auto table = std::map<BigInteger, BigInteger>{};
    
    BigInteger an = BigInteger::pow(a, m, p);
    
    for (BigInteger i = 1, cur = an; i <= m; i += 1) {
        if (!table.count(cur)) {
            table[cur] = i;
        }
        cur = (cur * an) % p;
    }
    
    for (BigInteger i = 0, cur = b; i <= m; i += 1) {
        if (table.count(cur)) {
            BigInteger ans = table[cur] * m - i;
            if (ans < p) {
                return ans;
            }
        }
        cur = (cur * a) % p;
    }
    
    return -1;
}

