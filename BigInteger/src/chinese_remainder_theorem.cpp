#include "chinese_remainder_theorem.h"

namespace {
    BigInteger gcd(const BigInteger& a, const BigInteger& b, BigInteger& x, BigInteger& y) {
        if (a == BigInteger::zero()) {
            x = BigInteger::zero();
            y = BigInteger(1);
            return b;
        }
        BigInteger xx, yy;
        BigInteger d = gcd(b % a, a, xx, yy);
        x = yy - (b / a) * xx;
        y = xx;
        return d;
    }

    BigInteger inverseMod(const BigInteger& number, const BigInteger& md) {
        if (number < BigInteger::zero() || md < BigInteger::zero()) {
            exit(1);
        }
        BigInteger x, y;
        BigInteger g = gcd(number, md, x, y);
        if (g != BigInteger(1)) {
            exit(1);
        }
        x = (x % md + md) % md;
        return x;
    }
}  // namespace

void CRT_Solver::add_equation(BigInteger new_a,
                              BigInteger new_b,
                              BigInteger new_p) {
    {
        BigInteger x, y;
        BigInteger g = gcd(new_a, new_p, x, y);
        if (new_b % g != BigInteger::zero()) {
            exit(1);
        }
        new_a /= g;
        new_b /= g;
        new_p /= g;
    }
    BigInteger b = (new_b * inverseMod(new_a, new_p)) % new_p;
    equations.emplace_back(std::make_pair(b, new_p));
    delete answer;
    answer = nullptr;
}

void CRT_Solver::reset() {
    equations.clear();
    if (answer) {
        delete answer;
    }
    answer = nullptr;
}

BigInteger* CRT_Solver::solve() {
    if (answer) {
        return answer;
    }

    const auto eq_copy = equations;

    size_t n = equations.size();

    std::vector<std::pair<BigInteger, BigInteger> > transitions;
    BigInteger total_mod(1);

    for (int i = 0; i < n; ++i) {
        BigInteger x, y;
        BigInteger g = gcd(total_mod, equations[i].second, x, y);
        total_mod *= equations[i].second;
        total_mod /= g;
    }

    for (int i = 0; i + 1 < n; ++i) {
        BigInteger p = equations[i].second;
        BigInteger b = equations[i].first;
        transitions.emplace_back(std::make_pair(p, b));
        for (int j = i + 1; j < n; ++j) {
            BigInteger pp = equations[j].second;
            BigInteger bb = equations[j].first;
            bb = (pp + bb - (b % pp)) % pp;
            {
                BigInteger x, y;
                BigInteger g = gcd(p, pp, x, y);
                if (bb % g != BigInteger::zero()) {
                    return answer = nullptr;
                }
                bb /= g;
                pp /= g;
                bb *= inverseMod(p / g, pp);
                bb %= pp;
            }
            equations[j] = std::make_pair(bb, pp);
        }
    }

    BigInteger result = equations.back().first;
    for (int i = (int)transitions.size() - 1; i >= 0; --i) {
        result = (result * transitions[i].first + transitions[i].second) % total_mod;
    }

    for (int i = 0; i < eq_copy.size(); ++i) {
        if (eq_copy[i].first != (result % eq_copy[i].second)) {
            return answer = nullptr;
        }
    }

    return answer = new BigInteger(result);
}
