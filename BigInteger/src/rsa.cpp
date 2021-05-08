//
// Created by daniilsmelskiy on 10.04.21.
//

#include <cassert>

#include "crypto_algorithms.h"
#include "chinese_remainder_theorem.h"
#include "easy/profiler.h"

#include "rsa.h"

namespace {
BigInteger GetCoprime(const BigInteger& phi) {
    BigInteger w;
    while (true) {
        if (phi.getLength() < 10) {
            w = Crypto::GetRandomNumber(2, phi - 1);
        } else {
            w = Crypto::GetRandomNumberLen(10);
        }
        while (w < phi && BigInteger::gcd(w, phi) != 1) {
            w += 1;
        }
        if (w < phi) {
            break;
        }
    }
    return w;
}

BigInteger EuclideanExtended(const BigInteger& x, const BigInteger& y) {
    if (BigInteger::gcd(x, y) != 1) {
        assert(false);
    }
    std::vector<BigInteger> r;
    r.push_back(y);
    r.push_back(x);
    while (r.back() != 1) {
        BigInteger lhs = r[(int)r.size() - 2];
        BigInteger rhs = r.back();
        r.push_back(lhs % rhs);
    }
    std::vector<BigInteger> a;
    a.emplace_back(0);
    a.emplace_back(1);
    for (int i = 2; i < r.size(); ++i) {
        BigInteger q = r[i - 2] / r[i - 1];
        BigInteger cur = (a[i - 2] - ((a[i - 1] * q) % y) + y) % y;
        a.push_back(cur);
    }

    return a.back();
}
}  // namespace

namespace RSA {

void Bob::Init(const BigInteger &p, const BigInteger &q) {
    EASY_FUNCTION();
    p_ = p;
    q_ = q;
    n_ = p_ * q_;

    /// Euler function
    /// phi_ = (p_ - 1) * (q_ - 1);

    /// Carmichael function
    phi_ = BigInteger::lcm(p_ - 1, q_ - 1);

    e_ = GetCoprime(phi_);
    d_ = EuclideanExtended(e_, phi_);
}

const BigInteger& Bob::GetModule() const {
    return n_;
}

const BigInteger& Bob::GetPhi() const {
    return phi_;
}

Key Bob::GetPublicKey() const {
    return {e_, n_};
}

Key Bob::GetPrivateKey() const {
    return {d_, n_};
}

BigInteger Bob::Decode(const BigInteger &c) {
    EASY_FUNCTION();
    BigInteger mp = BigInteger::pow(c, d_ % (p_ - 1), p_);
    BigInteger mq = BigInteger::pow(c, d_ % (q_ - 1), q_);

    CRT_Solver crt;
    crt.add_equation(1, mp, p_);
    crt.add_equation(1, mq, q_);

    const BigInteger* message = crt.solve();
    return *message;
}

void Alice::SetPublicKey(const Key &key) {
    public_key_ = key;
}

BigInteger Alice::Encode(const BigInteger &message) {
    EASY_FUNCTION();
    BigInteger c = BigInteger::pow(message, public_key_.value, public_key_.mod);
    return c;
}

std::vector<BigInteger> TextConvertor::ConvertFromText(const std::string &text, int symbol_size) {
    std::vector<BigInteger> result;
    for (int i = 0; i < text.size(); i += symbol_size) {
        BigInteger cur_symbol = 0;
        int pos = std::min(static_cast<int>(text.size()) - 1, i + symbol_size - 1);
        while (pos >= i) {
            cur_symbol *= kAlphabetSize;
            cur_symbol += ConvertToNumber(text[pos]);
            --pos;
        }
        result.push_back(cur_symbol);
    }
    return result;
}

std::string TextConvertor::ConvertToText(BigInteger symbols) {
    std::string result;
    while (symbols > 0) {
        int r = (symbols % kAlphabetSize).ToInt();
        result += ConvertToChar(r);
        symbols /= kAlphabetSize;
    }
    return result;
}

unsigned char TextConvertor::ConvertToChar(int number) {
    return static_cast<unsigned char>(number);
}

int TextConvertor::ConvertToNumber(unsigned char c) {
    return static_cast<int>(c);
}

Bob MakeBob(int len) {
    BigInteger p = Crypto::GetRandomPrimeNumbersWithSomeBitness(len, 1)[0];
    BigInteger q = Crypto::GetRandomPrimeNumbersWithSomeBitness(len, 1)[0];

    RSA::Bob bob;
    bob.Init(p, q);

    return bob;
}

BigInteger GetHash(const BigInteger& key, const BigInteger& mod, const std::string& message) {
    BigInteger result = 0;
    BigInteger step = 1;
    for (int i = 0; i < message.size(); ++i) {
        int c = static_cast<int>(message[i]) + 1;
        BigInteger cur = (key * c) % mod;
        result += cur;
        result %= mod;
    }
    return result;
}

}