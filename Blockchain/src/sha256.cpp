//
// Created by daniilsmelskiy on 07.05.21.
//

#include "sha256.h"

#include <algorithm>
#include <cassert>

using namespace SHA256;

namespace {
const unsigned int keys[64] =
        {0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
         0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
         0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
         0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
         0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
         0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
         0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
         0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
         0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
         0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
         0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
         0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
         0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
         0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
         0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
         0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

std::vector<Byte> ConvertToByte(const std::string& message) {
    std::vector<Byte> result;
    result.reserve(message.size());

    std::transform(message.begin(), message.end(), std::back_inserter(result), [](char c) {
        return static_cast<Byte>(c);
    });

    return result;
}

std::vector<Byte> PrepareMessage(const std::string& message) {
    std::vector<Byte> result{ConvertToByte(message)};
    result.push_back((1u << 7u));

    int size = static_cast<int>(result.size()) + 8;
    size = (size + 63) / 64;
    size = (size * 64);
    result.resize(size, 0);

    size_t message_length = message.size();
    for (int i = 0; i < 8; ++i) {
        Byte cur = message_length % 256;
        result[static_cast<int>(result.size()) - 1 - i] = cur;

        message_length /= 256;
    }

    assert((result.size()) % 64 == 0);

    return result;
}

unsigned int RightRotate(unsigned int number, unsigned int k) {
    unsigned int last_digits = number & ((1u << k) - 1);

    return ((number >> k) | (last_digits << (32 - k)));
}

std::vector<unsigned int> Compress(const std::vector<unsigned int>& q, std::vector<unsigned int>& hash) {
    std::vector<unsigned int> result = hash;

    for (int i = 0; i < 64; ++i) {
        unsigned int s1 = ((RightRotate(result[4], 6) ^ RightRotate(result[4], 11)) ^ RightRotate(result[4], 25));
        unsigned int ch = ((result[4] & result[5]) ^ ((!result[4]) & result[6]));
        unsigned int temp1 = result[7] + s1 + ch + keys[i] + q[i];
        unsigned int s0 = ((RightRotate(result[0], 2) ^ RightRotate(result[0], 13)) ^ RightRotate(result[0], 22));
        unsigned int maj = (((result[0] & result[1]) ^ (result[0] & result[2])) ^ (result[1] & result[2]));
        unsigned int temp2 = s0 + maj;

        for (int j = 7; j > 0; --j) {
            result[j] = result[j - 1];
        }

        result[0] = temp1 + temp2;
        result[4] += temp1;
    }

    return result;
}

void EncodeBlock(const std::vector<Byte>& message, int l, int r,
                 std::vector<unsigned int>& hash) {
    assert((r - l) == 64);
    std::vector<unsigned int> q;
    q.reserve(64);

    for (int i = l; i < r; i += 4) {
        unsigned int cur = 0;
        for (int j = 3; j >= 0; --j) {
            cur ^= message[i + j];
            if (j) {
                cur <<= 8u;
            }
        }

        q.push_back(cur);
    }

    for (int i = 0; i < 48; ++i) {
        q.push_back(0u);
    }

    assert(q.size() == 64);

    for (int i = 16; i < 64; ++i) {
        unsigned int s0 = ((RightRotate(q[i - 15], 7) ^ RightRotate(q[i - 15], 18)) ^ (q[i - 15] >> 3u));
        unsigned int s1 = ((RightRotate(q[i - 2], 17) ^ RightRotate(q[i - 2], 19)) ^ (q[i - 2] >> 10u));

        q[i] = q[i - 16] + s0 + q[i - 7] + s1;
    }

    const auto compressed_numbers = Compress(q, hash);
    assert(compressed_numbers.size() == hash.size());

    for (int i = 0; i < hash.size(); ++i) {
        hash[i] += compressed_numbers[i];
    }
}

}  // namespace

std::vector<unsigned int> SHA256::GetHash(const std::string& input_message) {
    std::vector<Byte> byte_message = PrepareMessage(input_message);

    std::vector<unsigned int> hash{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    for (int i = 0; i < byte_message.size(); i += kBlockSize) {
        EncodeBlock(byte_message, i, i + kBlockSize, hash);
    }

    return hash;
}

std::vector<unsigned int> SHA256::GetHash(const BigInteger& number) {
    return GetHash(number.GetByte());
}

BigInteger SHA256::ConvertToBigInteger(const std::vector<unsigned int>& hash) {
    BigInteger result = 0;

    for (auto value : hash) {
        BigInteger number(value);

        result *= (1ll << 32ll);
        result += number;
    }

    return result;
}

std::string SHA256::ConvertToString(const BigInteger& hash) {
    std::string result = hash.GetBase2();
    std::reverse(result.begin(), result.end());

    assert(result.size() <= 256);

    while (result.size() < 256) {
        result += "0";
    }

    std::reverse(result.begin(), result.end());
    return result;
}

std::string SHA256::ConvertToString(const std::vector<unsigned int>& hash) {
    BigInteger number = ConvertToBigInteger(hash);

    return ConvertToString(number);
}