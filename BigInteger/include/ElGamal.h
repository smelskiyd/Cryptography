#pragma once

#include "big_integer.h"
#include "crypto_algorithms.h"


namespace ElGamal {

struct Point {
    BigInteger x;
    BigInteger y;
    
    bool operator == (const Point& rhs) const;
    bool operator != (const Point& r) const;
    
    Point operator + (const Point& rhs) const;
    Point operator * (const BigInteger& step) const;
    
    friend std::ostream& operator << (std::ostream& os, const Point& a);
};

static BigInteger parseHexadecimal(const std::string& hex);

class Bob {
private:
    BigInteger k;

public:
    Bob();

    Point decode(const std::pair<Point, Point>& code);

    Point Y;
};

std::pair<Point, Point> encode(const Point& M, const Point& key);

void Emulate();

}  // namespace ElGamal
