//
// Created by daniilsmelskiy on 24.04.21.
//

#include <chrono>

#include "client.h"
#include "big_integer.h"
#include "crypto_algorithms.h"

#include "AES.h"
#include "SHA256.h"

using namespace std::chrono_literals;

#define DEFAULT_PORT 8888

static std::chrono::steady_clock::duration kWaitDuration{5s};

int n, my_pos;
std::vector<std::string> users;

struct DiffieHellman {
    BigInteger p, g;
    BigInteger my_public_key;
    BigInteger private_key;
    std::string private_key_byte;
} diffie_hellman;

void GetInitInfo(Client& client) {
    ChatMessage message = client.wait_for_all_connections();

    auto users_list = message.get_field("users")->AsArray();
    n = users_list.size();
    for (int i = 0; i < users_list.size(); ++i) {
        users.push_back(users_list[i].AsString());
        printf("%d-th user is: %s\n", i, users_list[i].AsString().c_str());
        if (users_list[i].AsString() == client.get_name()) {
            my_pos = i;
        }
    }

    diffie_hellman.p = BigInteger(message.get_field("p")->AsString());
    diffie_hellman.g = BigInteger(message.get_field("g")->AsString());
    printf("p = %s\ng = %s\n", diffie_hellman.p.ToString().c_str(), diffie_hellman.g.ToString().c_str());
}

void InitializePrivateKey(Client& client) {
    diffie_hellman.my_public_key = Crypto::GetRandomNumberLen(15);
    printf("My public key: %s\n", diffie_hellman.my_public_key.ToString().c_str());

    int next = (my_pos + 1) % n;
    for (int i = 0; i < n; ++i) {
        if (i == my_pos) {
            /// I am first
            BigInteger w = BigInteger::pow(diffie_hellman.g, diffie_hellman.my_public_key, diffie_hellman.p);
            ChatMessage message;
            message.add_field("to", users[next]);
            message.add_field("value", w.ToString());
            client.send_message(message);
        } else if (my_pos == (i + n - 1) % n) {
            /// I am last
            ChatMessage message = client.receive_message();
            diffie_hellman.private_key = BigInteger::pow(BigInteger(message.get_field("value")->AsString()),
                                                         diffie_hellman.my_public_key, diffie_hellman.p);
            diffie_hellman.private_key_byte = diffie_hellman.private_key.GetByte();
            while (diffie_hellman.private_key_byte.size() < 32) {
                diffie_hellman.private_key_byte.insert(diffie_hellman.private_key_byte.begin(), '0');
            }
        } else {
            ChatMessage message = client.receive_message();
            BigInteger w = message.get_field("value")->AsString();
            w = BigInteger::pow(w, diffie_hellman.my_public_key, diffie_hellman.p);

            ChatMessage new_message;
            new_message.add_field("to", users[next]);
            new_message.add_field("value", w.ToString());

            client.send_message(new_message);
        }
    }

    printf("My private key is: %s\n", diffie_hellman.private_key.ToString().c_str());
}

std::string DecryptMessage(std::string text, int length) {
    unsigned char* text_data = reinterpret_cast<unsigned char*>(text.data());
    unsigned char* key_data = reinterpret_cast<unsigned char*>(diffie_hellman.private_key_byte.data());

    AES aes;
    unsigned char* decoded = aes.Decrypt(text_data, text.size(), key_data);

    char* decoded_char = reinterpret_cast<char*>(decoded);
    std::string result(decoded_char, decoded_char + length);
    return result;
}

void ReceiveDecodedMessage(Client& client) {
    ChatMessage message = client.receive_message();
    std::string from = message.get_field("from")->AsString();
    std::string encrypted_text = message.get_field("message")->AsString();
    std::string decrypted_text = DecryptMessage(encrypted_text, message.get_field("length")->AsInt());

    SHA256 sha256;
    auto hash = sha256.hash(decrypted_text);
    if (std::to_string(*hash) != message.get_field("hash")->AsString()) {
        printf("Hash isn't equal.\n");
        exit(1);
    } else {
        printf("Hash is equal\n");
    }

    printf("New message from user %s: %s\n", from.c_str(), decrypted_text.c_str());
    fflush(stdout);
}

std::string EncodeMessage(std::string text) {
    unsigned char* text_data = reinterpret_cast<unsigned char*>(text.data());
    unsigned char* key_data = reinterpret_cast<unsigned char*>(diffie_hellman.private_key_byte.data());

    unsigned int out_len;
    AES aes;
    unsigned char* encoded = aes.Encrypt(text_data, text.size(), key_data, out_len);

    char* encoded_char = reinterpret_cast<char*>(encoded);
    std::string result(encoded_char, encoded_char + out_len);

    return result;
}

void SendEncodedMessage(Client& client, const std::string& receiver, const std::string& text) {
    ChatMessage message;
    message.add_field("to", receiver);

    message.add_field("message", EncodeMessage(text));
    message.add_field("length", Json::Node(static_cast<int>(text.size())));

    SHA256 sha256;
    auto hash = sha256.hash(text);
    message.add_field("hash", std::to_string(*hash));

    client.send_message(message);

    printf("Message is successfully sent\n");
}

void StartChatting(Client& client) {
    std::chrono::steady_clock::time_point last_tp = std::chrono::steady_clock::now() - kWaitDuration;

    while (true) {
        while (client.has_any_messages()) {
            printf("Server has some messages\n");
            fflush(stdout);

            ReceiveDecodedMessage(client);
        }

        std::chrono::steady_clock::time_point cur_tp = std::chrono::steady_clock::now();
        if (cur_tp - last_tp > kWaitDuration) {
            printf("Print some message or # to stop chatting: \n");

            std::string input_text;
            getline(std::cin, input_text);

            if (input_text.empty()) {
                last_tp = std::chrono::steady_clock::now();
                continue;
            }
            if (input_text == "#") {
                break;
            }

            printf("Who would you like to send this message?\n");

            std::string receiver_name;
            while (receiver_name.empty()) {
                getline(std::cin, receiver_name);
            }

            SendEncodedMessage(client, receiver_name, input_text);
            last_tp = std::chrono::steady_clock::now();
        }
    }
}

int main() {
    Crypto::RandomSeedInitialization();

    Client client;
    client.run(DEFAULT_PORT);

    GetInitInfo(client);
    InitializePrivateKey(client);

    StartChatting(client);
}