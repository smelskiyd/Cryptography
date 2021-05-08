//
// Created by daniilsmelskiy on 07.05.21.
//

#include "merkle_tree.h"

#include "sha256.h"

namespace {
BigInteger GetHash(const BigInteger& number) {
    BigInteger first_hash = SHA256::ConvertToBigInteger(SHA256::GetHash(number));
    BigInteger second_hash = SHA256::ConvertToBigInteger(SHA256::GetHash(first_hash));

    return second_hash;
}
}  // namespace

MerkleTree::MerkleTree(const std::vector<BigInteger>& numbers) : n_(numbers.size()) {
    BuildTree(numbers);
}

BigInteger MerkleTree::GetRootHash() const {
    return nodes_[0];
}

void MerkleTree::CountNode(int id) {
    if (id + id < tree_size_ + n_) {
        BigInteger sum = nodes_[id + id];

        if (id + id + 1 < tree_size_ + n_) {
            sum += nodes_[id + id + 1];
        }

        nodes_[id] = GetHash(sum);
    } else {
        nodes_[id] = 0;
    }
}

void MerkleTree::BuildTree(const std::vector<BigInteger>& numbers) {
    tree_size_ = 1;
    while (tree_size_ < n_) {
        tree_size_ += tree_size_;
    }

    nodes_.resize(tree_size_ + n_, 0);
    for (int i = 0; i < n_; ++i) {
        nodes_[tree_size_ + i] = GetHash(numbers[i]);
    }

    for (int i = tree_size_ - 1; i >= 0; --i) {
        CountNode(i);
    }
}
