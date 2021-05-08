//
// Created by daniilsmelskiy on 07.05.21.
//

#pragma once

#include "big_integer.h"

class MerkleTree {
  public:
    MerkleTree() = default;
    explicit MerkleTree(const std::vector<BigInteger>& numbers);

    BigInteger GetRootHash() const;

  private:
    void BuildTree(const std::vector<BigInteger>& numbers);
    void CountNode(int id);

    std::vector<BigInteger> nodes_;
    int n_{}, tree_size_{};
};