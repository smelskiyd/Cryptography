#pragma once

#include <map>
#include <string>
#include <variant>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>

namespace Json {
class Node : public std::variant<std::vector<Node>,
                                 std::map<std::string, Node>,
                                 int,
                                 double,
                                 bool,
                                 std::string> {
  public:
    using variant::variant;

    const auto& AsArray() const {
        return std::get<std::vector<Node>>(*this);
    }
    const auto& AsMap() const {
        return std::get<std::map<std::string, Node>>(*this);
    }
    bool AsBool() const {
        return std::get<bool>(*this);
    }
    int AsInt() const {
        return std::get<int>(*this);
    }
    double AsDouble() const {
        return std::get<double>(*this);
    }
    const auto& AsString() const {
        return std::get<std::string>(*this);
    }
};

class Document {
  public:
    explicit Document(Node root);

    const Node& GetRoot() const;

  private:
    Node root;
};

Document Load(std::istream& input);
}  // namespace Json

inline std::ostream& operator << (std::ostream& out, const Json::Node& node) {
    using Json::Node;

    if (std::holds_alternative<int>(node)) {
        out << std::get<int>(node);
    } else if (std::holds_alternative<double>(node)) {
        out << std::setprecision(10) << std::get<double>(node);
    } else if (std::holds_alternative<std::string>(node)) {
        std::string str = std::get<std::string>(node);
        std::string formatted_str;
        for (auto c : str) {
            if (c == '\\') {
                formatted_str += '\\';
                formatted_str += '\\';
            } else if (c == '"') {
                formatted_str += '\"';
            } else {
                formatted_str += c;
            }
        }
        out << "\"" << formatted_str << "\"";
    } else if (std::holds_alternative<std::vector<Node>>(node)) {
        const std::vector<Node>& v = node.AsArray();
        out << "[";
        bool is_first = true;
        for (int i = 0; i < v.size(); ++i) {
            if (!is_first) out << ",\n";
            else out << "\n";
            is_first = false;
            out << v[i];
        }
        out << "\n]";
    } else if (std::holds_alternative<std::map<std::string, Node>>(node)) {
        const std::map<std::string, Node>& m = node.AsMap();
        out << "{";
        bool is_first = true;
        for (const auto& item : m) {
            if (!is_first) out << ",\n";
            else out << "\n";
            is_first = false;
            out << "\"" << item.first << "\": " << item.second;
        }
        out << "\n}";
    }
    return out;
}
