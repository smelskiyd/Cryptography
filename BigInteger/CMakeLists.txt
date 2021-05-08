set(SOURCES
        include/big_integer.h                src/big_integer.cpp
        include/chinese_remainder_theorem.h  src/chinese_remainder_theorem.cpp
        include/crypto_algorithms.h          src/crypto_algorithms.cpp
        include/ElGamal.h                    src/ElGamal.cpp
        include/rsa.h src/rsa.cpp)

add_library(BigInteger STATIC ${SOURCES})
target_include_directories(BigInteger PUBLIC include)
