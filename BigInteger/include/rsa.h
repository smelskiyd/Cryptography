//
// Created by daniilsmelskiy on 10.04.21.
//

#pragma once

#include "big_integer.h"

namespace RSA {

struct Key {
    BigInteger value;
    BigInteger mod;
};

class Bob {
  public:
    void Init(const BigInteger& p, const BigInteger& q);

    const BigInteger& GetModule() const;
    const BigInteger& GetPhi() const;
    Key GetPublicKey() const;
    Key GetPrivateKey() const;

    BigInteger Decode(const BigInteger& c);

  private:
    BigInteger p_, q_;
    BigInteger n_;
    BigInteger phi_;
    BigInteger e_;
    BigInteger d_;
};

class Alice {
  public:
    void SetPublicKey(const Key& key);
    BigInteger Encode(const BigInteger& message);

  private:
    Key public_key_;
};

class TextConvertor {
  public:
    static const int kAlphabetSize = 256;

    static std::vector<BigInteger> ConvertFromText(const std::string& text, int symbol_size);
    static std::string ConvertToText(BigInteger symbols);

  private:
    static unsigned char ConvertToChar(int number);
    static int ConvertToNumber(unsigned char c);
};

Bob MakeBob(int len);
BigInteger GetHash(const BigInteger& key, const BigInteger& mod, const std::string& message);

}  // namespace RSA