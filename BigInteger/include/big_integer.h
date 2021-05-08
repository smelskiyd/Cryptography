#pragma once

#include <string>
#include <vector>
#include <iostream>

class BigInteger {
  public:
    using Digit = unsigned char;

    BigInteger() : BigInteger(0) {}
    BigInteger(const BigInteger& other);
    BigInteger(BigInteger&& other) noexcept;
    BigInteger(long long number);
    BigInteger(const std::string& number);

    /// 1 <= pos <= number_length
    Digit getDigitAt(int pos) const;

    static BigInteger zero();
    const std::vector<Digit>& data() const;
    size_t getLength() const;

    bool IsPositive() const;
    bool IsEven() const;
    bool IsOdd() const;

    int ToInt() const;
    long long ToLong() const;
    std::string ToString() const;
    std::string GetBase2() const;
    std::string GetHex() const;
    std::string GetBase64() const;
    std::string GetByte() const;

    bool operator == (long long other) const;
    bool operator == (const BigInteger& other) const;
    bool operator != (long long other) const;
    bool operator != (const BigInteger& other) const;
    bool operator <  (const BigInteger& other) const;
    bool operator <= (const BigInteger& other) const;
    bool operator >  (const BigInteger& other) const;
    bool operator >= (const BigInteger& other) const;

    BigInteger& operator = (long long other);
    BigInteger& operator = (const BigInteger& other);
    BigInteger& operator = (BigInteger&& other) noexcept;

    BigInteger  operator + (long long other) const;
    BigInteger  operator + (const BigInteger& other) const;
    BigInteger& operator += (long long other);
    BigInteger& operator += (const BigInteger& other);

    BigInteger  operator - (long long other) const;
    BigInteger  operator - (BigInteger other) const;
    BigInteger& operator -= (long long other);
    BigInteger& operator -= (const BigInteger& other);

    BigInteger  operator * (long long other) const;
    BigInteger  operator * (const BigInteger& other) const;
    BigInteger& operator *= (long long other);
    BigInteger& operator *= (const BigInteger& other);

    BigInteger  operator / (long long other) const;
    BigInteger  operator / (const BigInteger& other) const;
    BigInteger& operator /= (long long other);
    BigInteger& operator /= (const BigInteger& other);

    /// Remainder: works like remainder for integral types in C++
    /// [a / b] * b + a % b = a
    BigInteger  operator % (long long other) const;
    BigInteger  operator % (const BigInteger& other) const;
    BigInteger& operator %= (long long other);
    BigInteger& operator %= (const BigInteger& other);

    static BigInteger pow(const BigInteger& number, const BigInteger& power);
    static BigInteger pow(const BigInteger& number, const BigInteger& power,
                         const BigInteger& md);

    static BigInteger sqrt(const BigInteger& number);

    static BigInteger abs(BigInteger number);

    static BigInteger mod(const BigInteger& lhs, const BigInteger& rhs);

    static BigInteger gcd(BigInteger lhs, BigInteger rhs);
    static BigInteger lcm(const BigInteger& lhs, const BigInteger& rhs);

    static BigInteger GetFromBase2(const std::string& src);
    static BigInteger GetFromBase64(const std::string& src);
    static BigInteger GetFromByte(const std::string& src);

protected:
    struct DivisionResult {
        std::vector<Digit> quotient;
        std::vector<Digit> remainder;
    };

    enum class CompareSign {
        LESS = -1,
        EQUAL = 0,
        GREATER = 1
    };

    BigInteger(const std::vector<Digit>& number) : num_(number) { validate(); }
    static BigInteger buildByDigitalVector(const std::vector<Digit>& number);

    static CompareSign compareUnsignedNumbers(const std::vector<Digit>& lhs,
                                              const std::vector<Digit>& rhs);
    static std::vector<Digit> getUnsignedSum(const std::vector<Digit>& lhs,
                                             const std::vector<Digit>& rhs);
    /// REQUIREMENT: LHS has to be not less than RHS
    static std::vector<Digit> getUnsignedDiff(const std::vector<Digit>& lhs,
                                              const std::vector<Digit>& rhs);
    /// REQUIREMENT: RHS can't be equal to zero
    static DivisionResult getUnsignedDivision(BigInteger lhs,
                                              BigInteger rhs);
    static BigInteger NativeMultiplication(const BigInteger& lhs, const BigInteger& rhs);
    static BigInteger KaratsubaMultiplication(const BigInteger& lhs, const BigInteger& rhs);

    void validateSign();
    void validate();

    std::vector<Digit> num_;
    bool is_positive_{true};
};

std::ostream& operator << (std::ostream& fout, const BigInteger& number);
