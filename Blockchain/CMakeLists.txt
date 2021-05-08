set(SOURCES
        include/merkle_tree.h   src/merkle_tree.cpp
        include/sha256.h        src/sha256.cpp
        include/blockchain.h    src/blockchain.cpp)

add_library(Blockchain STATIC ${SOURCES})
target_include_directories(Blockchain PUBLIC include)
target_link_libraries(Blockchain BigInteger DevUtils)
