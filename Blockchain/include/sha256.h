//
// Created by daniilsmelskiy on 07.05.21.
//

#pragma once

#include <string>
#include <vector>

#include "big_integer.h"

namespace SHA256 {

using Byte = unsigned char;

constexpr int kBlockSize = 64;

/// Return 256-bit hash value
std::vector<unsigned int> GetHash(const std::string& input_message);
std::vector<unsigned int> GetHash(const BigInteger& number);

/// Constructs an integer from its parts
BigInteger  ConvertToBigInteger(const std::vector<unsigned int>& hash);
std::string ConvertToString(const BigInteger& hash);
std::string ConvertToString(const std::vector<unsigned int>& hash);

}