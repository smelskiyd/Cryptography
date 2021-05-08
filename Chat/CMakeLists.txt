set(SOURCES
        include/client.h        src/client.cpp
        include/server.h        src/server.cpp
        include/chat_message.h  src/chat_message.cpp
        include/AES.h           src/AES.cpp
        include/SHA256.h        src/SHA256.cpp)

add_library(Chat STATIC ${SOURCES})
target_include_directories(Chat PUBLIC include)
target_link_libraries(Chat DevUtils)
