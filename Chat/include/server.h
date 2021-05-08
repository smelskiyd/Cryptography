//
// Created by daniilsmelskiy on 24.04.21.
//
#pragma once

#include <vector>
#include <arpa/inet.h>

#include "chat_message.h"

class Server {
  public:
    [[noreturn]]
    void run(int port, int limit_of_connections = 1);

  private:
    static constexpr int kDefaultBufferSize{1025};
    static constexpr int kNumberOfUsers{3};

    struct ClientData {
        bool operator == (const ClientData& rhs) const {
            return name == rhs.name && socket_fd == rhs.socket_fd;
        }

        std::string name;
        int socket_fd;
    };

    void init(int port);
    void start_listen(int limit_of_connections) const;
    int  initialize_fd_set(fd_set* read_fds);

    void add_new_connection();
    bool check_connection(ClientData client, fd_set* read_fds);

    void send_message_to(int socket_fd, const ChatMessage& message) const;
    std::optional<ChatMessage> receive_message_from(int socket_fd);
    void process_message_from(const ClientData& client, ChatMessage message);

    void add_new_client(const ClientData& client_data);
    void remove_client(const ClientData& client_name);

    int master_socket;
    sockaddr_in address;
    int address_len{sizeof(address)};

    std::vector<ClientData> clients;
    std::map<std::string, int> sd_by_name;

    char buffer[kDefaultBufferSize];
};