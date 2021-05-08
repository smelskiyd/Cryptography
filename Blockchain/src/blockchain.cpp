//
// Created by daniilsmelskiy on 07.05.21.
//

#include <cassert>
#include <algorithm>

#include "blockchain.h"
#include "sha256.h"

using namespace Blockchain;

namespace {
BigInteger GetHash(const BigInteger& number) {
    return SHA256::ConvertToBigInteger(SHA256::GetHash(number));
}
}  // namespace

Transaction::Transaction(int from, int to, int value) : from(from), to(to), value(value) {
}

Transaction::Transaction(const Json::Node& node) {
    auto as_object = node.AsMap();

    from = as_object["from"].AsInt();
    to = as_object["to"].AsInt();
    value = as_object["value"].AsInt();
}

Json::Node Transaction::ToJson() const {
    std::map<std::string, Json::Node> object;

    object.insert({"from", from});
    object.insert({"to", to});
    object.insert({"value", value});

    return object;
}

BigInteger Transaction::GetHash() const {
    std::string str;

    str += std::to_string(from);
    str += std::to_string(to);
    str += std::to_string(value);

    return SHA256::ConvertToBigInteger(SHA256::GetHash(str));
}

Block::Block(const Json::Node& node) {
    auto as_object = node.AsMap();

    auto has_value = [](const std::map<std::string, Json::Node>& dict, const std::string& key) {
        return dict.find(key) != dict.end();
    };

    auto get_value = [has_value] (std::map<std::string, Json::Node>& dict, const std::string& key,
                                  bool required = true) {
        if (!has_value(dict, key) && required) {
            printf("Error: Input block doesn't have a field '%s'", key.c_str());
            exit(1);
        }
        return dict[key];
    };

    SetHeight(get_value(as_object, "height").AsInt());
    SetVersion(get_value(as_object, "version").AsInt());
    SetNonce(get_value(as_object, "nonce").AsString());
    SetMerkleRoot(get_value(as_object, "merkle_root").AsString());
    SetPreviousBlockHash(get_value(as_object, "previous_block_hash").AsString());
    SetBlockHash(get_value(as_object, "block_hash").AsString());
    SetDifficulty(get_value(as_object, "difficulty").AsInt());

    const auto transactions_json = get_value(as_object, "transactions").AsArray();
    std::vector<Transaction> transactions;
    transactions.reserve(transactions_json.size());

    std::transform(transactions_json.begin(), transactions_json.end(), std::back_inserter(transactions),
                   [] (const Json::Node& json_transaction) {
        return Transaction(json_transaction);
    });

    SetTransactions(transactions);
}

void Block::SetTransactions(const std::vector<Transaction>& transactions) {
    transactions_ = transactions;
}

void Block::SetHeight(int height) {
    height_ = height;
}

void Block::SetVersion(int version) {
    version_ = version;
}

void Block::SetNonce(const BigInteger& nonce) {
    nonce_ = nonce;
}

void Block::SetMerkleRoot(const BigInteger& merkle_root) {
    merkle_root_ = merkle_root;
}

void Block::SetPreviousBlockHash(const BigInteger& previous_block_hash) {
    previous_block_hash_ = previous_block_hash;
}

void Block::SetBlockHash(const BigInteger& block_hash) {
    block_hash_ = block_hash;
}

void Block::SetDifficulty(int difficulty) {
    assert(difficulty <= 256);
    difficulty_ = difficulty;
}

const std::vector<Transaction>& Block::GetTransactions() const {
    return transactions_;
}

int Block::GetHeight() const {
    return height_;
}

int Block::GetVersion() const {
    return version_;
}

const BigInteger& Block::GetNonce() {
    if (!nonce_.has_value()) {
        nonce_ = RunMining();
    }

    return *nonce_;
}

const BigInteger& Block::GetMerkleRoot() {
    if (!merkle_root_) {
        merkle_tree_ = BuildMerkleTree();
        merkle_root_ = merkle_tree_->GetRootHash();
    }

    return *merkle_root_;
}

const BigInteger& Block::GetPreviousBlockHash() const {
    return previous_block_hash_;
}

const BigInteger& Block::GetBlockHash() {
    if (!block_hash_) {
        block_hash_ = FindTotalBlockHash();
    }

    return *block_hash_;
}

int Block::GetDifficulty() const {
    return difficulty_;
}

MerkleTree Block::BuildMerkleTree() {
    std::vector<BigInteger> transactions_hash;
    transactions_hash.reserve(transactions_.size());

    for (const auto& transaction : transactions_) {
        transactions_hash.push_back(transaction.GetHash());
    }

    return MerkleTree(transactions_hash);
}

std::string Block::FindBlockHashWithoutNonce() {
    std::vector<BigInteger> elements = {
            GetPreviousBlockHash(),
            GetHash(height_),
            GetHash(version_),
            GetMerkleRoot()
    };

    std::string temp;
    for (const auto& element : elements) {
        temp += element.ToString();
    }

    return temp;
}

BigInteger Block::FindTotalBlockHash() {
    std::string temp = FindBlockHashWithoutNonce();
    temp += GetHash(GetNonce()).ToString();

    return SHA256::ConvertToBigInteger(SHA256::GetHash(temp));
}

bool Block::ValidateHashWithNonce(const BigInteger& hash) const {
    auto str = SHA256::ConvertToString(hash);

    for (int j = 0; j < difficulty_; ++j) {
        if (str[j] != '0') {
            return false;
        }
    }

    return true;
}

BigInteger Block::RunMining() {
    std::string partial_hash = FindBlockHashWithoutNonce();

    for (BigInteger i = 0; ; i += 1) {
        std::string temp = partial_hash + GetHash(i).ToString();

        auto block_hash = SHA256::ConvertToBigInteger(SHA256::GetHash(temp));

        if (ValidateHashWithNonce(block_hash)) {
            return i;
        }
    }
}

Json::Node Block::ToJson() {
    std::map<std::string, Json::Node> json_root;

    json_root.insert({"height", GetHeight()});
    json_root.insert({"version", GetVersion()});
    json_root.insert({"nonce", GetNonce().ToString()});
    json_root.insert({"merkle_root", GetMerkleRoot().ToString()});
    json_root.insert({"previous_block_hash", GetPreviousBlockHash().ToString()});
    json_root.insert({"block_hash", GetBlockHash().ToString()});
    json_root.insert({"difficulty", GetDifficulty()});

    std::vector<Json::Node> transactions_json;
    transactions_json.reserve(transactions_.size());

    std::transform(transactions_.begin(), transactions_.end(), std::back_inserter(transactions_json),
                   [] (const Transaction& transaction) {
                       return transaction.ToJson();
                   });

    json_root.insert({"transactions", transactions_json});

    return json_root;
}

bool Block::Validate() {
    MerkleTree tmp_merkle_tree = BuildMerkleTree();

    if (tmp_merkle_tree.GetRootHash() != GetMerkleRoot()) {
        printf("Warning: Merkle root value is not correct!\n");
        return false;
    }

    if (!ValidateHashWithNonce(GetBlockHash())) {
        printf("Warning: Nonce is not correct!\n");
        return false;
    }

    if (!(GetBlockHash() == FindTotalBlockHash())) {
        printf("Warning: Block hash is not correct!\n");
        return false;
    }

    return true;
}

void BlockChain::Load(const Json::Document& document) {
    const auto as_array = document.GetRoot().AsArray();
    blocks_.reserve(as_array.size());

    for (const auto& block : as_array) {
        blocks_.emplace_back(block);
    }
}

void BlockChain::Save(std::ostream& output) {
    std::vector<Json::Node> array_root;
    array_root.reserve(blocks_.size());

    for (auto& block : blocks_) {
        array_root.emplace_back(block.ToJson());
    }

    Json::Node json_root(array_root);

    output << json_root;
}

void BlockChain::AddNewBlock(const std::vector<Transaction>& transactions) {
    Block& block = blocks_.emplace_back();
    block.SetTransactions(transactions);
    block.SetVersion(kDefaultVersion);
    block.SetDifficulty(kDefaultDifficulty);

    int height = GetSize();
    block.SetHeight(height);
    if (height > 1) {
        block.SetPreviousBlockHash(GetBlock(height - 1).GetBlockHash());
    }

    std::stringstream sstr;
    sstr << block.ToJson();

    printf("Added new block with following parameters: \n%s\n\n\n", sstr.str().c_str());
}

int BlockChain::GetSize() const {
    return static_cast<int>(blocks_.size());
}

Block& BlockChain::GetBlock(int height) {
    assert(0 < height && height <= GetSize());

    return blocks_[height - 1];
}

bool BlockChain::Validate() {
    for (int i = 0; i < blocks_.size(); ++i) {
        if (!blocks_[i].Validate()) {
            return false;
        }

        if (i && !(blocks_[i].GetPreviousBlockHash() == blocks_[i - 1].GetBlockHash())) {
            printf("Warning: Previous block hash isn't correct!\n");
            return false;
        }
    }

    return true;
}