#include "ElGamal.h"

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

namespace Operators {
    BigInteger mod(BigInteger x, const BigInteger& md) {
        return ((x % md) + md) % md;
    }

    BigInteger sum(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& md) {
        return mod(lhs + rhs, md);
    }

    BigInteger diff(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& md) {
        return mod(lhs - rhs, md);
    }

    BigInteger mult(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& md) {
        return mod(lhs * rhs, md);
    }

    BigInteger div(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& md) {
        BigInteger q = inverseMod(rhs, md);
        return mult(lhs, q, md);
    }
}  // namespace Operators

namespace ElGamal {

using namespace Operators;

Point G = Point{parseHexadecimal("09487239995A5EE76B55F9C2F098"),
                parseHexadecimal("A89CE5AF8724C0A23E0E0FF77500")};
Point O = Point{-1, -1};
BigInteger A = parseHexadecimal("DB7C2ABF62E35E668076BEAD2088");
BigInteger B = parseHexadecimal("659EF8BA043916EEDE8911702B22");
BigInteger p = parseHexadecimal("DB7C2ABF62E35E668076BEAD208B");
BigInteger N = parseHexadecimal("DB7C2ABF62E35E7628DFAC6561C5");

bool Point::operator == (const Point& rhs) const {
    return (x == rhs.x) && (y == rhs.y);
}

bool Point::operator != (const Point& r) const {
    return !(*this == r);
}

Point Point::operator + (const Point& rhs) const {
    if (*this == O) {
        return rhs;
    }
    if (rhs == O) {
        return *this;
    }

    if (*this != rhs && x == rhs.x) {
        return O;
    }
    if(*this == rhs && y == 0) {
        return O;
    }

    BigInteger a;
    BigInteger b;
    if (*this != rhs) {
        a = div(diff(rhs.y, y, p), diff(rhs.x, x, p), p);
        b = div(diff(mult(y, rhs.x, p),
                     mult(rhs.y, x, p), p),
                diff(rhs.x, x, p), p);
    } else {
        a = div(sum(mult(3, mult(x, x, p), p), A, p),
                sum(y, y, p), p);
        b = div(sum(sum(mod(mult(mult(x, x, p), x, p) * -1, p),
                        mult(A, x, p), p),
                    mult(2, B, p), p),
                sum(y, y, p), p);
    }

    return Point{diff(diff(mult(a, a, p), x, p), rhs.x, p), diff(sum(mod(BigInteger::pow(a, 3, p) * -1, p), mult(a, sum(x, rhs.x, p), p), p), b, p)};
}

Point Point::operator * (const BigInteger& step) const {
    if (step == 0) {
        return O;
    }
    Point res;
    if ((step % 2) == BigInteger::zero()) {
        res = (*this) * (step / 2);
        res = res + res;
    } else {
        res = ((*this) * (step - 1)) + (*this);
    }
    return res;
}

std::ostream& operator << (std::ostream& os, const Point& a) {
    os << "(" << a.x << ", " << a.y << ")";
    return os;
}

static BigInteger parseHexadecimal(const std::string& hex) {
    const auto l = hex.size();
    BigInteger res = 0;
    for (auto i = 0; i < l; ++i) {
        res *= 16;
        if ('0' <= hex[i] && hex[i] <= '9') {
            res += hex[i] - '0';
        }
        else if ('A' <= hex[i] && hex[i] <= 'F') {
            res += (hex[i] - 'A') + 10;
        }
        else if ('a' <= hex[i] && hex[i] <= 'z') {
            res += (hex[i] - 'a') + 10;
        }
        else {
            printf("Wrong letter %c in hexadecimal format\n", hex[i]);
            exit(1);
        }
    }
    return res;
}

Bob::Bob() {
//    k = Crypto::GetRandomNumber(1, N - 1);
    k = 0;
    while (k == 0) {
        k = Crypto::GetRandomNumber(1, 99) % N;
    }
    Y = G * k;
}

Point Bob::decode(const std::pair<Point, Point>& code) {
    Point s = code.first * k;
    s.y *= -1;
    return s+code.second;
}

std::pair<Point, Point> encode(const Point& M, const Point& key) {
//    BigInteger r = Crypto::GetRandomNumber(1, N - 1);
    BigInteger r = 0;
    while (r == 0) {
        r = Crypto::GetRandomNumber(1, 99) % N;
    }
    Point d = key * r;
    Point g = G * r;
    Point h = M + d;
    return std::make_pair(g, h);
}

void Emulate() {
    std :: cout << "El-Gamal\n";
    std :: cout << "Point to encode: ";
    Point M = G * 10;
    std :: cout << M << '\n';
    Bob b;
    std :: cout << "Key: ";
    std :: cout << b.Y << '\n';
    std::pair<Point, Point> code = encode(M, b.Y);
    std :: cout << "Encoded value: " << code.first << ' ' << code.second << '\n';
    std :: cout << "Decoded: ";
    std :: cout << b.decode(code) << std :: endl;
}

}  // namespace ElGamal
