//
// Created by daniilsmelskiy on 24.04.21.
//

#include <arpa/inet.h>
#include <sys/types.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cmath>
#include <algorithm>

#include "chat_message.h"
#include "crypto_algorithms.h"

#include "server.h"

namespace {
    constexpr int kDefaultBufferSize{1025};

    void ExitWithError(const char* error_message, int exit_status = EXIT_FAILURE) {
        perror(error_message);
        exit(exit_status);
    }

    int CreateMasterSocket() {
        int master_socket = socket(AF_INET , SOCK_STREAM , 0);
        return master_socket;
    }

    void CreateSocketAddress(struct sockaddr_in* address, int port) {
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = INADDR_ANY;
        address->sin_port = htons(port);
    }

    int EnableMultipleConnections(int master_socket) {
        int opt = true;
        return setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    }

    int BindMasterSocket(int master_socket, sockaddr_in* address) {
        return bind(master_socket, (struct sockaddr*)address, sizeof(*address));
    }

    int ListenMasterSocket(int master_socket, int limit_of_connetions = 1) {
        return listen(master_socket, limit_of_connetions);
    }

    int AcceptNewConnection(int master_socket, struct sockaddr_in* address, int* address_len) {
        return accept(master_socket, (struct sockaddr*)address, (socklen_t*)address_len);
    }

    void SendTo(int socket_descriptor, const char* const message, int message_length, int flags = 0) {
        if (send(socket_descriptor, message, message_length, flags) != message_length) {
            ExitWithError("Failed to send message");
        }
    }

    void SendTo(int socket_descriptor, const std::string& message) {
        if (send(socket_descriptor, message.data(), message.size(), 0) != message.size()) {
            ExitWithError("Failed to send message");
        }
    }

    int ReceiveFrom(int socket_descriptor, char* message) {
        int len = recv(socket_descriptor, message, kDefaultBufferSize - 1, 0);
        if (len < 0) {
            ExitWithError("Failed to receive data from user");
        }

        return len;
    }

    int ReceiveFrom(int socket_descriptor, char* message, int length, int flags = 0) {
        int len = recv(socket_descriptor, message, length, flags);
        if (len != length) {
            ExitWithError("Failed to receive enough data from user");
        }

        return len;
    }

    int TryReceiveFrom(int socket_descriptor, char* message, int length, int flags = 0) {
        return recv(socket_descriptor, message, length, flags);
    }

    std::pair<BigInteger, BigInteger> GetPGForDiffieHellman(int p_length) {
        Crypto::RandomSeedInitialization();
        BigInteger p;
        while (true) {
            p = Crypto::GetClosestPrimeNumber(Crypto::GetRandomNumberWithBitness(p_length));
            BigInteger tmp = (p - 1) / 2;
            if (Crypto::MillerRabinTest(tmp)) {
                break;
            }
        }

        BigInteger g = Crypto::GetRandomNumber(2, p - 1);

        return {p, g};
    }

}  // namespace


void Server::init(int port) {
    if ((master_socket = CreateMasterSocket()) == 0) {
        ExitWithError("Failed to create Master socket");
    }

    if (EnableMultipleConnections(master_socket) < 0) {
        ExitWithError("Failed to enable multiple connections");
    }

    CreateSocketAddress(&address, port);

    if (BindMasterSocket(master_socket, &address) < 0) {
        ExitWithError("Bind Master socket failed");
    }

    printf("Listening port %d\n", port);
}

void Server::start_listen(int limit_of_connections) const {
    if (ListenMasterSocket(master_socket, limit_of_connections) < 0) {
        ExitWithError("Failed to start listen connections");
    }
}

int Server::initialize_fd_set(fd_set* read_fds) {
    FD_ZERO(read_fds);

    FD_SET(master_socket, read_fds);
    int max_sd = master_socket;

    for (const auto& client : clients) {
        FD_SET(client.socket_fd, read_fds);
        max_sd = std::max(max_sd, client.socket_fd);
    }

    return max_sd;
}

void Server::add_new_connection() {
    int new_socket;
    if ((new_socket = AcceptNewConnection(master_socket, &address, &address_len)) < 0) {
        ExitWithError("Accepting error");
        return;
    }

    printf("New connection accepted, socket fd is %d, ip is: %s, port: %d\n",
           new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    {   /// Welcome message
        ChatMessage message;
        message.add_field("from", Json::Node(std::string("server")));
        const std::string hello_message{"Hello from server! You are successfully connected!\n"
                                        "Please send a message with your name."};
        message.add_field("message", Json::Node(hello_message));

        send_message_to(new_socket, message);
        puts("Welcome message sent successfully");
    }
    {   /// Receive user name
        auto message = receive_message_from(new_socket);
        auto name_field = message->get_field("name");
        if (!name_field) {
            ExitWithError("Client-machine must send a message with name.");
        }
        std::string name = name_field->AsString();

        add_new_client(ClientData{name, new_socket});
    }

    if (clients.size() == kNumberOfUsers) {
        /// All users are connected
        printf("All %d users are connected.\n", static_cast<int>(clients.size()));

        std::vector<Json::Node> users_list;
        for (const auto& client: clients) {
            users_list.emplace_back(client.name);
        }

        ChatMessage message;
        message.add_field("from", std::string("server"));
        message.add_field("users", users_list);
        message.add_field("message", std::string("All users are connected."));

        const auto p_g = GetPGForDiffieHellman(32);
        message.add_field("p", p_g.first.ToString());
        message.add_field("g", p_g.second.ToString());

        for (const auto& client: clients) {
            send_message_to(client.socket_fd, message);
        }

        printf("All users are informed that all users are ready to chat.\n");
    }
}

bool Server::check_connection(ClientData client, fd_set* read_fds) {
    int socket_fd = client.socket_fd;

    if (FD_ISSET(socket_fd, read_fds)) {
        auto message = receive_message_from(socket_fd);
        if (!message) {
            getpeername(socket_fd, reinterpret_cast<sockaddr*>(&address), reinterpret_cast<socklen_t*>(&address_len));

            printf("Host disconnected, ip %s, port %d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            remove_client(client);

            return false;
        } else {
            process_message_from(client, *message);
        }
    }

    return true;
}

[[noreturn]]
void Server::run(int port, int limit_of_connections) {
    init(port);
    start_listen(limit_of_connections);

    address_len = sizeof(address);
    puts("Waiting for connections ...");

    fd_set read_fds;

    while (true) {
        int max_sd = initialize_fd_set(&read_fds);

        int activity = select(max_sd + 1, &read_fds, nullptr, nullptr, nullptr);

        if ((activity < 0) && (errno != EINTR)) {
            printf("Select error\n");
        }

        if (FD_ISSET(master_socket, &read_fds)) {
            add_new_connection();
        }

        for (int i = 0; i < clients.size(); ++i) {
            if (!check_connection(clients[i], &read_fds)) {
                --i;
            }
        }
    }
}

void Server::add_new_client(const ClientData& client_data) {
    clients.push_back(client_data);
    sd_by_name.insert({client_data.name, client_data.socket_fd});
    printf("New client with name \'%s\' was successfully added to the network with socked id = %d\n",
           client_data.name.c_str(), client_data.socket_fd);
}

void Server::remove_client(const ClientData& client_data) {
    close(client_data.socket_fd);
    clients.erase(std::find(clients.begin(), clients.end(), client_data));
    sd_by_name.erase(sd_by_name.find(client_data.name));

    printf("Client with name \'%s\', at port %d, was successfully disconnected\n",
           client_data.name.c_str(), client_data.socket_fd);
}

void Server::send_message_to(int socket_descriptor, const ChatMessage& message) const {
    SendTo(socket_descriptor, message.get_ready_message());
}

std::optional<ChatMessage> Server::receive_message_from(int socket_fd) {
    int len = TryReceiveFrom(socket_fd, buffer, kDefaultMessageLength);
    if (len == 0) {
        return std::nullopt;
    }
    if (len != kDefaultMessageLength) {
        ExitWithError("Failed to read message length");
    }
    buffer[len] = '\0';
    int message_length = std::atoi(buffer);

    len = ReceiveFrom(socket_fd, buffer, message_length);
    if (len != message_length) {
        ExitWithError("Failed to read message");
    }

    return ChatMessage(std::string(buffer, buffer + len));
}

void Server::process_message_from(const ClientData& client, ChatMessage message) {
    printf("Server received new message from user %s\n", client.name.c_str());
    printf("Message = %s\n", message.get_json_message().c_str());
    if (auto field_to = message.get_field("to"); field_to.has_value()) {
        std::string to = field_to->AsString();
        if (to == "server") {

        } else {
            message.remove_field("to");
            message.add_field("from", client.name);

            printf("Sending message to user %s\n", to.c_str());
            send_message_to(sd_by_name[to], message);
            printf("Message was successfully sent\n");
            fflush(stdout);
        }
    }
}