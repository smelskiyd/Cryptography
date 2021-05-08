//
// Created by daniilsmelskiy on 25.04.21.
//

#pragma once

#include <optional>

#include "json.h"

static constexpr int kDefaultMessageLength{4};

class ChatMessage {
  public:
    ChatMessage() = default;
    ChatMessage(const std::string& str_data);

    void reset();

    void add_field(const std::string& field_name, const char* const value);
    void add_field(const std::string& field_name, const Json::Node& node);
    void add_field(const std::string& field_name, Json::Node&& node);

    std::string get_ready_message() const;
    std::string get_json_message() const;

    Json::Node get_json_root() const;

    std::optional<Json::Node> get_field(const std::string& field_name) const;
    void remove_field(const std::string& field_name);

  private:
    static std::string parse_data_length(int data_length, int output_length);

    std::map<std::string, Json::Node> data;
};