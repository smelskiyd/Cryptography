//
// Created by daniilsmelskiy on 07.05.21.
//

#pragma once

#include "big_integer.h"
#include "merkle_tree.h"
#include "json.h"

namespace Blockchain {

struct Transaction {
    int from, to;
    int value;

    Transaction() = default;
    Transaction(int from, int to, int value);
    explicit Transaction(const Json::Node& node);

    Json::Node ToJson() const;

    BigInteger GetHash() const;
};

class Block {
  public:
    Block() = default;
    explicit Block(const Json::Node& node);

    void SetTransactions(const std::vector<Transaction>& transactions);
    void SetHeight(int height);
    void SetVersion(int version);
    void SetNonce(const BigInteger& nonce);
    void SetMerkleRoot(const BigInteger& merkle_root);
    void SetPreviousBlockHash(const BigInteger& previous_block_hash);
    void SetBlockHash(const BigInteger& block_hash);
    void SetDifficulty(int difficulty);

    const std::vector<Transaction>& GetTransactions() const;
    int   GetHeight() const;
    int   GetVersion() const;
    int   GetDifficulty() const;
    const BigInteger& GetNonce();
    const BigInteger& GetMerkleRoot();
    const BigInteger& GetPreviousBlockHash() const;
    const BigInteger& GetBlockHash();

    Json::Node ToJson();

    bool Validate();

  private:
    std::string FindBlockHashWithoutNonce();
    BigInteger FindTotalBlockHash();
    MerkleTree BuildMerkleTree();

    bool ValidateHashWithNonce(const BigInteger& nonce) const;
    BigInteger RunMining();

    BigInteger previous_block_hash_;

    int height_{};
    int version_{0};
    std::optional<BigInteger> merkle_root_;

    std::optional<BigInteger> nonce_;

    std::optional<BigInteger> block_hash_;
    std::optional<MerkleTree> merkle_tree_;
    std::vector<Transaction> transactions_;

    int difficulty_{4};
};

class BlockChain {
  public:
    void Load(const Json::Document& document);
    void Save(std::ostream& output);

    void AddNewBlock(const std::vector<Transaction>& transactions);

    bool Validate();

    int GetSize() const;
    Block& GetBlock(int height);

  private:
    const int kDefaultVersion{0};
    const int kDefaultDifficulty{8};

    std::vector<Block> blocks_;
};

}