//
// Created by daniilsmelskiy on 24.04.21.
//
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>

#include "client.h"

namespace {
void ExitWithError(const char* error_message, int exit_status = EXIT_FAILURE) {
    perror(error_message);
    exit(exit_status);
}

void CreateSocketAddress(struct sockaddr_in* address, int port) {
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = INADDR_ANY;
    address->sin_port = htons(port);
}

int ReadFromServer(int socket_fd, char* buffer, int length, int flags = 0) {
    int len = recv(socket_fd, buffer, length, flags);
    if (len < 0) {
        ExitWithError("Failed to read data from server.");
    }
    buffer[len] = '\0';
    return len;
}

void SendToServer(int socket_fd, const char* const buffer, int length, int flags = 0) {
    if (send(socket_fd, buffer, length, flags) != length) {
        ExitWithError("Failed to send message to server");
    }
}
}  // namespace

void Client::init(int port) {
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        ExitWithError("Socket creation failed");
    } else {
        printf("Socket successfully created\n");
    }

    CreateSocketAddress(&server_addr, port);
}

void Client::connect_to_server() {
    if (connect(socket_fd,  reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
        ExitWithError("Connection with the server failed");
    } else {
        printf("Successfully connected to the server\n");
    }
}

void Client::run(int port) {
    init(port);
    connect_to_server();

    {    /// Get first connection message
        ChatMessage hello_message_from_server = receive_message();
        printf("Received message from server: %s\n", hello_message_from_server.get_json_message().c_str());
    }
    {
        std::cout << "Print your name: " << std::endl;
        std::cin >> name;

        ChatMessage message;
        message.add_field("to", std::string("server"));
        message.add_field("name", name);

        send_message(message);
    }
}

ChatMessage Client::wait_for_all_connections() {
    ChatMessage message = receive_message();
    return message;
}

bool Client::has_any_messages() {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(socket_fd, &read_fds);

    struct timeval tv = {0, 0};
    int activity = select(socket_fd + 1, &read_fds, nullptr, nullptr, &tv);

    if ((activity < 0) && (errno != EINTR)) {
        ExitWithError("Select error");
    }

    return activity > 0;
}

void Client::send(const char *const message, int length) const {
    SendToServer(socket_fd, message, length);
}

void Client::send(const std::string& message) const {
    SendToServer(socket_fd, message.data(), message.size());
}

std::string Client::receive() {
    int len = ReadFromServer(socket_fd, buffer, kDefaultBufferSize - 1);

    std::string result(buffer, buffer + len);
    return result;
}

std::string Client::receive(int length) {
    int len = ReadFromServer(socket_fd, buffer, length);
    if (len != length) {
        ExitWithError("Failed to receive enough data from server");
    }

    std::string result(buffer, buffer + len);
    return result;
}

ChatMessage Client::receive_message() {
    int len = ReadFromServer(socket_fd, buffer, kDefaultMessageLength);
    if (len != kDefaultMessageLength) {
        ExitWithError("Failed to read message length");
    }
    buffer[len] = '\0';
    int message_length = std::atoi(buffer);

    len = ReadFromServer(socket_fd, buffer, message_length);
    if (len != message_length) {
        ExitWithError("Failed to read message");
    }

    return ChatMessage(std::string(buffer, buffer + len));
}

void Client::send_message(const ChatMessage& message) const {
    send(message.get_ready_message());
}

const std::string& Client::get_name() const {
    return name;
}
