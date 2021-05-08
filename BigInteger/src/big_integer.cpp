#include "big_integer.h"

#include <utility>
#include <algorithm>
#include <cassert>

// TODO: Use static_cast<> instead of C-style casts

namespace {
// True if lhs < rhs
    bool CompareTwoDigitalVectors(const std::vector<BigInteger::Digit>& lhs,
                                  const std::vector<BigInteger::Digit>& rhs) {
        if (lhs.size() < rhs.size()) return true;
        for (auto i = lhs.size(); i > 0; --i) {
            if (lhs[i - 1] != rhs[i - 1]) {
                return lhs[i - 1] < rhs[i - 1];
            }
        }
        return false;
    }

    long long DividePrefixWithBinarySearch(const BigInteger& lhs, const BigInteger& rhs) {
        int l = 0;
        int r = 9;
        while (l < r) {
            int mid = (l + r + 1) >> 1;
            if ((rhs * mid) <= lhs) {
                l = mid;
            } else {
                r = mid - 1;
            }
        }
        return l;
    }

    char ToHex(unsigned int x) {
        return (x < 10 ? char(x + '0') : char(x - 10 + 'a'));
    }

    char ToBase64(unsigned int x) {
        if (x <= 25) {
            return static_cast<char>(x + 'A');
        } else if (x <= 51) {
            return static_cast<char>(x - 26 + 'a');
        } else if (x <= 61) {
            return static_cast<char>(x - 52 + '0');
        } else if (x == 62) {
            return '+';
        } else if (x == 63) {
            return '/';
        }
        assert(false); // x > 63
    }

    unsigned int FromBase64(char x) {
        if ('A' <= x && x <= 'Z') {
            return x - 'A';
        } else if ('a' <= x && x <= 'z') {
            return x - 'a' + 26;
        } else if ('0' <= x && x <= '9') {
            return x - '0' + 52;
        } else if (x == '+') {
            return 62;
        } else if (x == '/') {
            return 63;
        }
        assert(false); // x is undefined
    }
}  // namespace

BigInteger::BigInteger(long long number) {
    if (number < 0) {
        number *= -1;
        is_positive_ = false;
    }
    if (number == 0) {
        num_ = {0};
        return;
    }

    while (number != 0) {
        num_.push_back(number % 10);
        number /= 10;
    }
    return;
}

BigInteger::BigInteger(const BigInteger& other) {
    num_ = other.num_;
    is_positive_ = other.is_positive_;
}

BigInteger::BigInteger(BigInteger&& other) noexcept {
    num_ = std::move(other.num_);
    is_positive_ = other.is_positive_;
}

BigInteger::BigInteger(const std::string& number) {
    std::string tmp = number;
    if (!tmp.empty() && tmp[0] == '-') {
        is_positive_ = false;
        tmp.erase(tmp.begin());
    }
    assert(tmp.size() > 0);
    
    std::vector<Digit> digits;
    digits.reserve(tmp.size());
    std::reverse(tmp.begin(), tmp.end());
    for (int i = 0; i < tmp.size(); ++i) {
        char c = tmp[i];
        assert('0' <= c && c <= '9');
        Digit d = c - '0';
        digits.emplace_back(d);
    }
    
    num_ = digits;
    validate();
}

BigInteger BigInteger::buildByDigitalVector(const std::vector<Digit>& number) {
    if (number.empty()) return BigInteger(0);
    return BigInteger(number);
}

BigInteger BigInteger::zero() {
    static BigInteger result(0);
    return result;
}

const std::vector<BigInteger::Digit>& BigInteger::data() const {
    return num_;
}

bool BigInteger::IsPositive() const {
    return is_positive_;
}

size_t BigInteger::getLength() const {
    return num_.size();
}

bool BigInteger::IsEven() const {
    return !(num_[0] & 1);
}

bool BigInteger::IsOdd() const {
    return (num_[0] & 1);
}

BigInteger::Digit BigInteger::getDigitAt(int pos) const {
    assert(pos > 0 && pos <= getLength());
    return num_[getLength() - pos];
}

bool BigInteger::operator == (long long other) const {
    return *this == BigInteger(other);
}

bool BigInteger::operator == (const BigInteger& other) const {
    return num_ == other.num_ && is_positive_ == other.is_positive_;
}

bool BigInteger::operator != (long long other) const {
    return !(*this == other);
}

bool BigInteger::operator != (const BigInteger& other) const {
    return !(*this == other);
}

bool BigInteger::operator < (const BigInteger& other) const {
    if (IsPositive() != other.IsPositive()) {
        return other.IsPositive();
    }

    const auto unsigned_compare = compareUnsignedNumbers(num_, other.num_);
    if (IsPositive()) {
        return unsigned_compare == CompareSign::LESS;
    } else {
        return unsigned_compare == CompareSign::GREATER;
    }
}

bool BigInteger::operator <= (const BigInteger& other) const {
    if (IsPositive() != other.IsPositive()) {
        return other.IsPositive();
    }

    const auto unsigned_compare = compareUnsignedNumbers(num_, other.num_);
    if (unsigned_compare == CompareSign::EQUAL) {
        return true;
    }
    if (IsPositive()) {
        return unsigned_compare == CompareSign::LESS;
    } else {
        return unsigned_compare == CompareSign::GREATER;
    }
}

bool BigInteger::operator > (const BigInteger& other) const {
    if (IsPositive() != other.IsPositive()) {
        return IsPositive();
    }

    const auto unsigned_compare = compareUnsignedNumbers(num_, other.num_);
    if (IsPositive()) {
        return unsigned_compare == CompareSign::GREATER;
    } else {
        return unsigned_compare == CompareSign::LESS;
    }
}

bool BigInteger::operator >= (const BigInteger& other) const {
    if (IsPositive() != other.IsPositive()) {
        return IsPositive();
    }

    const auto unsigned_compare = compareUnsignedNumbers(num_, other.num_);
    if (unsigned_compare == CompareSign::EQUAL) {
        return true;
    }
    if (IsPositive()) {
        return unsigned_compare == CompareSign::GREATER;
    } else {
        return unsigned_compare == CompareSign::LESS;
    }
}

BigInteger& BigInteger::operator = (long long other) {
    *this = BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator = (const BigInteger& other) {
    num_ = other.num_;
    is_positive_ = other.is_positive_;
    return *this;
}

BigInteger& BigInteger::operator = (BigInteger&& other) noexcept {
    num_ = std::move(other.num_);
    is_positive_ = other.is_positive_;
    return *this;
}



BigInteger BigInteger::operator + (long long other) const {
    return (*this) + BigInteger(other);
}

BigInteger BigInteger::operator + (const BigInteger& other) const {
    BigInteger result;

    if (IsPositive() == other.IsPositive()) {
        result.num_ = getUnsignedSum(num_, other.num_);
        result.is_positive_ = IsPositive();
        result.validate();
        return result;
    }

    auto unsigned_compare = compareUnsignedNumbers(num_, other.num_);
    if (unsigned_compare != CompareSign::LESS) {
        result.is_positive_ = is_positive_;
        result.num_ = getUnsignedDiff(num_, other.num_);
    } else {
        result.is_positive_ = !is_positive_;
        result.num_ = getUnsignedDiff(other.num_, num_);
    }
    result.validate();
    return result;
}

BigInteger& BigInteger::operator += (long long other) {
    *this = *this + BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator += (const BigInteger& other) {
    *this = *this + other;
    return *this;
}

BigInteger BigInteger::operator - (long long other) const {
    return *this - BigInteger(other);
}

BigInteger BigInteger::operator - (BigInteger other) const {
    other.is_positive_ ^= 1;
    return (*this) + other;
}

BigInteger& BigInteger::operator -= (long long other) {
    *this = *this - BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator -= (const BigInteger& other) {
    *this = *this - other;
    return *this;
}

// TODO: Optimize multiplication on small-numbers
BigInteger BigInteger::operator * (long long other) const {
    return (*this) * BigInteger(other);
}

BigInteger BigInteger::operator * (const BigInteger& other) const {
    return KaratsubaMultiplication(*this, other);
}

BigInteger& BigInteger::operator *= (long long other) {
    *this *= BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator *= (const BigInteger& other) {
    *this = *this * other;
    return *this;
}

BigInteger BigInteger::operator / (long long other) const {
    return *this / BigInteger(other);
}

BigInteger BigInteger::operator / (const BigInteger& other) const {
    if (other == zero()) {
        exit(1);
    }
    DivisionResult division_result = getUnsignedDivision(*this, other);
    BigInteger result = buildByDigitalVector(division_result.quotient);

    if (IsPositive() == other.IsPositive()) {
        result.is_positive_ = true;
    } else {
        result.is_positive_ = false;
    }
    result.validate();

    return result;
}

BigInteger& BigInteger::operator /= (long long other) {
    *this = *this / BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator /= (const BigInteger& other) {
    *this = *this / other;
    return *this;
}

BigInteger BigInteger::operator % (long long other) const {
    return *this % BigInteger(other);
}

BigInteger BigInteger::operator % (const BigInteger& other) const {
    if (other == zero()) {
        exit(1);
    }

    DivisionResult division_result = getUnsignedDivision(*this, other);

    BigInteger result;
    result = buildByDigitalVector(division_result.remainder);
    result.is_positive_ = IsPositive();
    result.validate();
    return result;
}

BigInteger& BigInteger::operator %= (long long other) {
    *this = *this % BigInteger(other);
    return *this;
}

BigInteger& BigInteger::operator %= (const BigInteger& other) {
    *this = *this % other;
    return *this;
}

BigInteger BigInteger::pow(const BigInteger& number, const BigInteger& power) {
    if (power == zero()) {
        return BigInteger(1);
    }
    if (power.num_[0] & 1) {
        return pow(number, power - 1) * number;
    }
    BigInteger w = pow(number, power / 2);
    return w * w;
}

BigInteger BigInteger::pow(const BigInteger& number, const BigInteger& power,
                          const BigInteger& module) {
    if (power == zero()) {
        return mod(BigInteger(1), module);
    }
    if (power.getDigitAt(power.getLength()) & 1) {
        return mod(pow(number, power - 1, module) * number, module);
    }
    BigInteger w = pow(number, power / 2, module);
    return mod(w * w, module);
}


void BigInteger::validateSign() {
    if (num_.size() == 1 && num_.at(0) == 0) {
        is_positive_ = true;
    }
}

void BigInteger::validate() {
    while (num_.size() > 1 && num_.back() == 0) {
        num_.pop_back();
    }
    validateSign();
}

BigInteger::CompareSign BigInteger::compareUnsignedNumbers(
        const std::vector<BigInteger::Digit>& lhs,
        const std::vector<BigInteger::Digit>& rhs) {
    if (lhs.size() != rhs.size()) {
        return (lhs.size() < rhs.size() ? CompareSign::LESS
                                        : CompareSign::GREATER);
    }
    for (long long pos = (long long)lhs.size() - 1; pos >= 0; --pos) {
        if (lhs[pos] != rhs[pos]) {
            return (lhs[pos] < rhs[pos] ? CompareSign::LESS
                                        : CompareSign::GREATER);
        }
    }
    return CompareSign::EQUAL;
}

std::vector<BigInteger::Digit> BigInteger::getUnsignedSum(const std::vector<Digit>& lhs,
                                              const std::vector<Digit>& rhs) {
    auto max_length = std::max(lhs.size(), rhs.size());
    std::vector<Digit> sum(max_length + 1, 0);

    long long d = 0;
    for (long long i = 0; i < max_length; ++i) {
        long long c = (i < lhs.size() ? lhs[i] : 0) + (i < rhs.size() ? rhs[i] : 0) + d;
        sum[i] = c % 10;
        d = c > 9 ? 1 : 0;
    }
    if (d) sum.back() = 1;
    else sum.pop_back();

    return sum;
}

std::vector<BigInteger::Digit> BigInteger::getUnsignedDiff(const std::vector<Digit>& lhs,
                                               const std::vector<Digit>& rhs) {
    if (lhs.size() < rhs.size()) {
        exit(1);
    }

    std::vector<Digit> diff(lhs.size(), 0);
    long long d = 0;
    for (long long i = 0; i < lhs.size(); ++i) {
        long long c = (lhs[i] - d - (i < rhs.size() ? rhs[i] : 0));
        if (c >= 0) {
            d = 0;
            diff[i] = c;
        } else {
            d = 1;
            diff[i] = 10 + c;
        }
    }

    if (d != 0) {
        exit(1);
    }
    return diff;
}

BigInteger::DivisionResult BigInteger::getUnsignedDivision(BigInteger lhs,
                                                           BigInteger rhs) {
    BigInteger::DivisionResult result;

    if (lhs.num_.size() < rhs.num_.size()) {
        result.quotient = {0};
        result.remainder = lhs.num_;
        return result;
    }

    lhs.is_positive_ = true;
    rhs.is_positive_ = true;
    const long long kLen((long long)rhs.num_.size());

    std::vector<Digit> quotient((long long)lhs.num_.size() - kLen + 1, 0);
    while (rhs <= lhs) {
        long long cur_len = kLen;

        std::vector<Digit> prefix;
        prefix.reserve(cur_len);
        for (long long i = cur_len; i > 0; --i) {
            prefix.push_back(lhs.num_[(long long)lhs.num_.size() - i]);
        }

        BigInteger c = buildByDigitalVector(prefix);
        if (rhs > c) {
            ++cur_len;
            prefix.insert(prefix.begin(), lhs.num_[(long long)lhs.num_.size() - cur_len]);
            c = buildByDigitalVector(prefix);
        }

        long long k = DividePrefixWithBinarySearch(c, rhs);
        quotient[(long long)lhs.num_.size() - cur_len] = k;
        c -= rhs * k;

        for (long long i = cur_len; i > 0; --i) {
            lhs.num_[(long long)lhs.num_.size() - i] = 0;
        }
        for (long long i = 0; i < c.num_.size(); ++i) {
            lhs.num_[(long long)lhs.num_.size() - cur_len + i] = c.num_[i];
        }
        lhs.validate();
    }

    result.quotient = quotient;
    result.remainder = lhs.num_;
    return result;
}

BigInteger BigInteger::NativeMultiplication(const BigInteger& lhs, const BigInteger& rhs) {
    // TODO: Optimize multiplication on small numbers
    std::vector<Digit> mult(lhs.num_.size() + rhs.num_.size(), 0);
    for (long long i = 0; i < lhs.num_.size(); ++i) {
        for (long long j = 0, d = 0; j < rhs.num_.size() || d != 0; ++j) {
            long long cur = (long long)lhs.num_[i] * (long long)(j < rhs.num_.size() ? rhs.num_[j] : 0)
                            + (long long)mult[i + j] + d;
            mult[i + j] = cur % 10;
            d = cur / 10;
        }
    }
    BigInteger result;
    result.num_ = mult;
    result.is_positive_ = (lhs.IsPositive() == rhs.IsPositive() ? true : false);
    result.validate();
    return result;
}

BigInteger BigInteger::KaratsubaMultiplication(const BigInteger& lhs, const BigInteger& rhs) {
    if (lhs == BigInteger::zero() || rhs == BigInteger::zero()) {
        return BigInteger::zero();
    }

    if (std::min(lhs.getLength(), rhs.getLength()) <= 100) {
        return NativeMultiplication(lhs, rhs);
    }

    // TODO: Multiple by integer (not BigInteger), when one of numbers is small
    struct NumberDivision {
        BigInteger lhs, rhs;
        bool sign;
    };
    auto GetDivision = [](const BigInteger& number, int rhs_len) {
        NumberDivision result;
        result.sign = number.IsPositive();

        int len = number.getLength();
        if (len <= rhs_len) {
            result.lhs = BigInteger::zero();
            result.rhs = number;
            return result;
        }

        std::vector<Digit> rhs_part;
        rhs_part.reserve(rhs_len);
        for (int i = 0; i < rhs_len; ++i) {
            rhs_part.push_back(number.num_[i]);
        }
        result.rhs = BigInteger(rhs_part);

        std::vector<Digit> lhs_part;
        lhs_part.reserve(len - rhs_len);
        for (int i = rhs_len; i < len; ++i) {
            lhs_part.push_back(number.num_[i]);
        }
        result.lhs = BigInteger(lhs_part);

        return result;
    };

    int base_length = std::max(lhs.getLength(), rhs.getLength()) / 2;

    if (base_length <= 1) {
        return NativeMultiplication(lhs, rhs);
    }

    NumberDivision lhs_div = GetDivision(lhs, base_length),
                   rhs_div = GetDivision(rhs, base_length);

    /// Main algorithm
    /// A = A0 + A1 * Base ^ M
    /// B = B0 + B1 * Base ^ M
    /// A * B = (A0 + A1 * Base ^ M) * (B0 + B1 * Base ^ M)
    /// A * B = (A0 * B0) + (A0 * B1 + A1 * B0) * (Base ^ M) + (A1 * B1) * (Base ^ 2M)
    /// A0 * B1 + A1 * B0 = (A0 + A1) * (B0 + B1) - A0 * B0 - A1 * B1
    /// C0 = A0 * B0
    /// C1 = A1 * B1
    /// C2 = A0 * B1 + A1 * B0 = (A0 + A1) * (B0 + B1) - C0 - C1
    /// A * B = C0 + C2 * Base ^ M + C1 * Base ^ 2M
    BigInteger C0 = KaratsubaMultiplication(lhs_div.rhs, rhs_div.rhs);
    BigInteger C1 = KaratsubaMultiplication(lhs_div.lhs, rhs_div.lhs);
    BigInteger C2 = KaratsubaMultiplication(lhs_div.lhs + lhs_div.rhs, rhs_div.lhs + rhs_div.rhs) - C0 - C1;

    int result_len = std::max(std::max(C0.getLength(), C2.getLength() + base_length),
                              C1.getLength() + 2 * base_length);
    std::vector<int> result(result_len, 0);

    auto AddTo = [](std::vector<int>& result, std::vector<Digit>& number, int starting_pos) {
        assert(result.size() >= number.size() + starting_pos);
        for (int i = 0; i < number.size(); ++i) {
            result[starting_pos + i] += static_cast<int>(number[i]);
        }
    };
    AddTo(result, C0.num_, 0);
    AddTo(result, C2.num_, base_length);
    AddTo(result, C1.num_, 2 * base_length);

    std::vector<Digit> byte_result;
    byte_result.reserve(result.size());
    int d = 0;
    for (int i = 0; i < result.size() || d; ++i) {
        int cur = (i < result.size() ? result[i] : 0) + d;
        byte_result.push_back(cur % 10);
        d = cur / 10;
    }

    BigInteger big_int_result{byte_result};
    big_int_result.is_positive_ = (lhs.IsPositive() == rhs.IsPositive());
    return big_int_result;
}

std::ostream& operator << (std::ostream& fout, const BigInteger& number) {
    if (!number.IsPositive()) {
        fout << "-";
    }
    for (int i = (int)number.data().size() - 1; i >= 0; --i) {
        int digit = static_cast<int>(number.data()[i]);
        fout << digit;
    }
    return fout;
}

BigInteger BigInteger::abs(BigInteger number) {
    number.is_positive_ = true;
    return number;
}

BigInteger BigInteger::sqrt(const BigInteger& number) {
    if (number == BigInteger::zero()) {
        return number;
    }
    long long len = ((long long)number.num_.size() + 1) / 2;
    std::vector<Digit> result(len, 0);
    for (long long i = len - 1; i >= 0; --i) {
        Digit l = 0;
        Digit r = 9;
        while (l < r) {
            Digit mid = (l + r + 1) / 2;
            result[i] = mid;
            BigInteger w(result);
            if ((w * w) <= number) l = mid;
            else r = mid - 1;
        }
        result[i] = l;
    }
    BigInteger w(result);
    w.validate();
    return w;
}

BigInteger BigInteger::mod(const BigInteger& lhs, const BigInteger& rhs) {
    if (rhs == zero()) {
        exit(1);
    }
    if (lhs == zero()) {
        return zero();
    }
    BigInteger floorDiv = lhs / rhs;
    if (lhs.IsPositive() != rhs.IsPositive()) {
        if (lhs % rhs != zero()) {
            floorDiv = floorDiv - 1;
        }
    }
    BigInteger result = lhs - (rhs * floorDiv);
    return result;
}

BigInteger BigInteger::gcd(BigInteger lhs, BigInteger rhs) {
    lhs.is_positive_ = true;
    rhs.is_positive_ = true;
    while (lhs > 0 && rhs > 0) {
        if (lhs > rhs) {
            lhs = mod(lhs, rhs);
        } else {
            rhs = mod(rhs, lhs);
        }
    }
    return lhs + rhs;
}

BigInteger BigInteger::lcm(const BigInteger &lhs, const BigInteger &rhs) {
    assert(lhs > 0);
    assert(rhs > 0);
    return (lhs * rhs) / gcd(lhs, rhs);
}

int BigInteger::ToInt() const {
    int result = 0;
    for (int i = (int)num_.size(); i > 0; --i) {
        result *= 10;
        result += num_[i - 1];
    }
    if (!IsPositive()) {
        result *= -1;
    }
    return result;
}

long long BigInteger::ToLong() const {
    long long result = 0;
    for (int i = (int)num_.size(); i > 0; --i) {
        result *= 10;
        result += num_[i - 1];
    }
    if (!IsPositive()) {
        result *= -1;
    }
    return result;
}

std::string BigInteger::ToString() const {
    std::string result;
    if (!IsPositive()) {
        result += "-";
    }
    for (int i = (int)num_.size(); i > 0; --i) {
        result += static_cast<char>('0' + num_[i - 1]);
    }
    return result;
}

std::string BigInteger::GetBase2() const {
    BigInteger tmp = *this;
    if (!tmp.IsPositive()) {
        tmp.is_positive_ = true;
    }
    std::string result;
    while (tmp > 0) {
        auto r = tmp % 2;
        result += (r == 0 ? '0' : '1');
        tmp /= 2;
    }
    std::reverse(result.begin(), result.end());
    if (result.empty()) {
        result = "0";
    }
    return result;
}

std::string BigInteger::GetHex() const {
    BigInteger tmp = *this;
    if (!tmp.IsPositive()) {
        tmp.is_positive_ = true;
    }
    std::string result;
    while (tmp > 0) {
        auto r = tmp % 16;
        result += ToHex(r.ToInt());
        tmp /= 16;
    }
    std::reverse(result.begin(), result.end());
    if (result.empty()) {
        result += ToHex(0);
    }
    return result;
}

std::string BigInteger::GetBase64() const {
    BigInteger tmp = *this;
    if (!tmp.IsPositive()) {
        tmp.is_positive_ = true;
    }
    std::string result;
    while (tmp > 0) {
        auto r = tmp % 64;
        result += ToBase64(r.ToInt());
        tmp /= 64;
    }
    std::reverse(result.begin(), result.end());
    if (result.empty()) {
        result += ToBase64(0);
    }
    return result;
}

std::string BigInteger::GetByte() const {
    BigInteger tmp = *this;
    if (!tmp.IsPositive()) {
        tmp.is_positive_ = true;
    }

    std::string result;
    while (tmp > 0) {
        auto r = tmp % 256;
        result += static_cast<unsigned char>(r.ToInt());
        tmp /= 256;
    }
    std::reverse(result.begin(), result.end());

    if (result.empty()) {
        result += static_cast<unsigned char>(0);
    }
    return result;
}

BigInteger BigInteger::GetFromBase2(const std::string& src) {
    BigInteger result = 0;
    for (auto c : src) {
        result *= 2;
        result += c - '0';
    }
    return result;
}

BigInteger BigInteger::GetFromBase64(const std::string& src) {
    BigInteger result = 0;
    for (auto c : src) {
        result *= 64;
        result += FromBase64(c);
    }
    return result;
}

BigInteger BigInteger::GetFromByte(const std::string& src) {
    BigInteger result = 0;
    for (unsigned char c : src) {
        result *= 256;
        result += static_cast<int>(c);
    }
    return result;
}
