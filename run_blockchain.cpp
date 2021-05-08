//
// Created by daniilsmelskiy on 07.05.21.
//

#include <string>
#include <iostream>
#include <random>
#include <cmath>

#include "blockchain.h"

using namespace Blockchain;

constexpr int kInitValue{100000};

struct User {
    int id{0};
    int amount{0};

    User() = default;
    User(int id, int amount) : id(id), amount(amount) {}
};

struct UserStats {
    int total{kInitValue};
    int min{kInitValue};
    int max{kInitValue};
};

void UpdateStats(std::map<int, UserStats>& stats, int user, int value) {
    stats[user].total += value;
    if (stats[user].total > stats[user].max) {
        stats[user].max = stats[user].total;
    }

    if (stats[user].total < stats[user].min) {
        stats[user].min = stats[user].total;
    }
}

std::vector<Transaction> GenerateTransactions(std::vector<User>& users, int output_size) {
    std::vector<Transaction> result;

    int n = users.size();

    for (int i = 0; i < output_size; ++i) {
        int x = std::abs(rand()) % n;
        int y = std::abs(rand()) % n;

        if (x != y) {
            int num = rand();
            int den = RAND_MAX;

            double percent = static_cast<double>(num) / static_cast<double>(den);
            int value = users[x].amount * percent;

            result.emplace_back(x, y, value);

            users[x].amount -= value;
            users[y].amount += value;
        }
    }

    return result;
}

std::vector<User> GenerateUsers(int n) {
    std::vector<User> users;
    users.reserve(n);

    for (int i = 0; i < n; ++i) {
        users.emplace_back(i, kInitValue);
    }

    return users;
}

void RunInitialEmulation(const std::string& file_name) {
    std::vector<User> users = GenerateUsers(20);

    BlockChain blockchain;

    for (int i = 0; i < 5; ++i) {
        auto transactions = GenerateTransactions(users, 5);

        blockchain.AddNewBlock(transactions);
    }

    if (!blockchain.Validate()) {
        printf("Error: Blockchain has wrong data.\n");
        exit(1);
    } else {
        printf("Everything is correct. Saving blockchain to file...\n");
    }

    std::ofstream output(file_name);
    if (!output.is_open()) {
        printf("Failed to open output file!\n");
        exit(1);
    }

    blockchain.Save(output);
    output.close();

    printf("Blockchain is successfully saved.\n");
}

void InitBlockchainFromFile(const std::string& filename) {
    std::ifstream input(filename);
    if (!input.is_open()) {
        printf("Failed to open file.\n");
        exit(1);
    }

    Json::Document document = Json::Load(input);

    BlockChain blockchain;
    blockchain.Load(document);

    if (!blockchain.Validate()) {
        printf("Error: Some data in blockchain isn't valid.\n");
        exit(1);
    } else {
        printf("Everything is correct. Blockchain is ready.\n");
    }

    std::map<int, UserStats> amount;
    for (int i = 0; i < blockchain.GetSize(); ++i) {
        for (const auto& transaction : blockchain.GetBlock(i + 1).GetTransactions()) {
            UpdateStats(amount, transaction.from, -transaction.value);
            UpdateStats(amount, transaction.to  ,  transaction.value);
        }
    }

    printf("Found %d users among all transactions\n", static_cast<int>(amount.size()));
    int total = 0;
    for (auto it : amount) {
        printf("User %d has %d coins. Min: %d, max: %d.\n", it.first, it.second.total, it.second.min, it.second.max);
        total += it.second.total;
    }

    printf("Total amount of money in blockchain: %d\n", total);
}

int main(int argc, char* argv[]) {
//    RunInitialEmulation("/home/daniilsmelskiy/working-directory/tmp_projects/CryptoLabs/out/blockchain_test2");
    InitBlockchainFromFile("/home/daniilsmelskiy/working-directory/tmp_projects/CryptoLabs/out/blockchain_test2");
}