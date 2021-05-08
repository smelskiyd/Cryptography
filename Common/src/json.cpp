#include "json.h"

namespace {
    bool IsDigit(char c) {
        return ('0' <= c && c <= '9');
    }
}

namespace Json {
Document::Document(Node root) : root(move(root)) {
}

const Node& Document::GetRoot() const {
    return root;
}

Node LoadNode(std::istream& input);

Node LoadArray(std::istream& input) {
    std::vector<Node> result;

    for (char c; input >> c && c != ']'; ) {
        if (c != ',') {
            input.putback(c);
        }
        result.push_back(LoadNode(input));
    }

    return Node(std::move(result));
}

Node LoadDouble(std::istream& input, bool is_positive = true) {
    double result = 0.;
    bool read_real = false;
    while (true) {
        char c = input.peek();
        if (!IsDigit(c) && c != '.') break;
        if (c == '.') {
            read_real = true;
            input.get();
            break;
        }
        result *= 10;
        result += input.get() - '0';
    }
    if (read_real) {
        double degree = 1;
        while (IsDigit(input.peek())) {
            degree /= 10.;
            result += degree * (double)(input.get() - '0');
        }
    }

    if (!is_positive) result *= -1.;

    if (!read_real) {
        return Node((int)result);
    }
    return Node((double)result);
}

Node LoadBool(std::istream& input) {
    std::string field;
    while (islower(input.peek())) {
        field += input.get();
    }
    return (field == "false" ? Node((bool)false) : Node((bool)true));
}

Node LoadString(std::istream& input) {
    std::string line;
    char c;
    bool previous_is_slash = false;
    while (input.get(c)) {
        if (c == '\\') {
            if (previous_is_slash) {
                line += '\\';
                previous_is_slash = false;
            } else {
                previous_is_slash = true;
            }
        } else if (c == '"') {
            if (previous_is_slash) {
                line += '"';
                previous_is_slash = false;
            } else {
                break;
            }
        } else {
            previous_is_slash = false;
            line += c;
        }
    }
    return Node(move(line));
}

Node LoadDict(std::istream& input) {
    std::map<std::string, Node> result;

    for (char c; input >> c && c != '}'; ) {
        if (c == ',') {
            input >> c;
        }

        std::string key = LoadString(input).AsString();
        input >> c;
        result.emplace(move(key), LoadNode(input));
    }

    return Node(move(result));
}

Node LoadNode(std::istream& input) {
    char c;
    input >> c;
    if (c == '[') {
        return LoadArray(input);
    } else if (c == '{') {
        return LoadDict(input);
    } else if (c == '"') {
        return LoadString(input);
    } else if (IsDigit(c)) {
        input.putback(c);
        return LoadDouble(input);
    } else if (c == '-') {
        return LoadDouble(input, false);
    } else {
        input.putback(c);
        return LoadBool(input);
    }
}

Document Load(std::istream& input) {
    return Document{LoadNode(input)};
}
}  // namespace Json
