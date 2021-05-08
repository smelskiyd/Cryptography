//
// Created by daniilsmelskiy on 24.04.21.
//
#pragma once

#include <unistd.h>
#include <arpa/inet.h>
#include <string>

#include "chat_message.h"

class Client {
  public:
    Client() = default;
    ~Client() {
        close(socket_fd);
    }

    void run(int port);
    ChatMessage wait_for_all_connections();
    bool has_any_messages();

    void send(const char* const message, int length) const;
    void send(const std::string& message) const;

    std::string receive();
    std::string receive(int length);

    ChatMessage receive_message();
    void        send_message(const ChatMessage& message) const;

    const std::string& get_name() const;

  private:
    static constexpr int kDefaultBufferSize{1025};

    void init(int port);
    void connect_to_server();

    int socket_fd;
    sockaddr_in server_addr;

    char buffer[kDefaultBufferSize];

    std::string name;
};