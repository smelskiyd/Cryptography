//
// Created by daniilsmelskiy on 25.04.21.
//

#include "chat_message.h"

ChatMessage::ChatMessage(const std::string& str_data) {
    std::stringstream sstr;
    sstr << str_data;
    Json::Document doc = Json::Load(sstr);
    data = doc.GetRoot().AsMap();
}

void ChatMessage::reset() {
    data.clear();
}

void ChatMessage::add_field(const std::string &field_name, const char* const value) {
    data.insert({field_name, Json::Node(std::string(value))});
}

void ChatMessage::add_field(const std::string& field_name, const Json::Node& node) {
    data.insert({field_name, node});
}

void ChatMessage::add_field(const std::string& field_name, Json::Node&& node) {
    data.insert({field_name, std::move(node)});
}

std::string ChatMessage::get_ready_message() const {
    Json::Node root(data);
    std::ostringstream sstr;
    sstr << root;

    std::string result;
    result += parse_data_length(sstr.str().size(), kDefaultMessageLength);

    result += sstr.str();

    return result;
}

std::string ChatMessage::get_json_message() const {
    Json::Node root(data);
    std::ostringstream sstr;
    sstr << root;

    return sstr.str();
}

Json::Node ChatMessage::get_json_root() const {
    Json::Node root(data);
    return root;
}

std::optional<Json::Node> ChatMessage::get_field(const std::string& field_name) const {
    if (data.find(field_name) != data.end()) {
        return data.at(field_name);
    }
    return std::nullopt;
}

void ChatMessage::remove_field(const std::string& field_name) {
    data.erase(data.find(field_name));
}

std::string ChatMessage::parse_data_length(int data_length, int output_length) {
    std::string result = std::to_string(data_length);
    while (result.size() < output_length) {
        result.insert(result.begin(), '0');
    }
    return result;
}
