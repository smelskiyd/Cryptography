//
// Created by daniilsmelskiy on 24.04.21.
//

#include "server.h"

#define DEFAULT_PORT 8888

int main(int argc , char* argv[]) {
    Server server;
    server.run(DEFAULT_PORT, 3);
}
