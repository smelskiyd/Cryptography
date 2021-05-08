//
// Created by daniilsmelskiy on 10.04.21.
//

#include "big_integer.h"
#include "crypto_algorithms.h"
#include "rsa.h"

#include "test_runner.h"
#include "profile.h"
#include "easy/profiler.h"

namespace {
    std::string GenMessage(int len) {
        std::string some_text;
        for (int i = 0; i < len; ++i) {
            some_text += static_cast<unsigned char>((rand() % 255) + 1);
        }
        return some_text;
    }

    int GetSymbolLimit(BigInteger limit, int alphabet) {
        int result = 0;
        while (limit > 0) {
            ++result;
            limit /= alphabet;
        }
        return result - 1;
    }
}

void SampleTest() {
    const int kLen = 64;
    Crypto::RandomSeedInitialization();

    RSA::Bob bob = RSA::MakeBob(kLen);

    RSA::Alice alice;
    alice.SetPublicKey(bob.GetPublicKey());

    for (int i = 0; i < 1; ++i) {
        BigInteger message = Crypto::GetRandomNumberWithBitness(kLen);
        BigInteger c = alice.Encode(message);
        BigInteger m = bob.Decode(c);
        ASSERT_EQUAL(message, m);
    }
}

void TextConvertationTest() {
    Crypto::RandomSeedInitialization();
    std::string some_text = GenMessage(10000);

    std::vector<BigInteger> conversion = RSA::TextConvertor::ConvertFromText(some_text, 10);

    std::string result;
    for (const auto& item : conversion) {
        result += RSA::TextConvertor::ConvertToText(item);
    }
    ASSERT_EQUAL(some_text, result);
}

void TextMessageTest() {
    Crypto::RandomSeedInitialization();
    std::string message = GenMessage(1000);

    {
        RSA::Bob bob_message = RSA::MakeBob(64);

        RSA::Alice alice_message;
        alice_message.SetPublicKey(bob_message.GetPublicKey());

        int symbol_size = GetSymbolLimit(bob_message.GetModule(), RSA::TextConvertor::kAlphabetSize);
        auto text_symbols = RSA::TextConvertor::ConvertFromText(message, symbol_size);

        std::vector<BigInteger> encoded;
        encoded.reserve(text_symbols.size());
        for (const auto &symbol : text_symbols) {
            encoded.push_back(alice_message.Encode(symbol));
        }

        std::string result_text;
        for (const auto &item : encoded) {
            result_text += RSA::TextConvertor::ConvertToText(bob_message.Decode(item));
        }

        ASSERT_EQUAL(message, result_text);
    }
    {
        RSA::Bob alice_signature = RSA::MakeBob(64);

        RSA::Alice bob_signature;
        bob_signature.SetPublicKey(alice_signature.GetPublicKey());

        BigInteger key = Crypto::GetClosestPrimeNumber(Crypto::GetRandomNumberLen(3));
        BigInteger mod = Crypto::GetClosestPrimeNumber(Crypto::GetRandomNumberLen(12));
        BigInteger hash = RSA::GetHash(key, mod, message);
        BigInteger encoded = alice_signature.Decode(hash);

        BigInteger decoded = bob_signature.Encode(encoded);
        ASSERT_EQUAL(hash, decoded);
    }
}

int main(int argc, char* argv[]) {
    EASY_PROFILER_ENABLE;

    TestRunner tr;
    RUN_TEST(tr, SampleTest);
    RUN_TEST(tr, TextConvertationTest);
    RUN_TEST(tr, TextMessageTest);

//    profiler::dumpBlocksToFile("/home/daniilsmelskiy/working-directory/tmp_projects/CryptoLabs/out/rsa_measure.prof");
}