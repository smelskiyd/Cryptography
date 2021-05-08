cmake_minimum_required(VERSION 3.17)
project(CryptoLabs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Og")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libasan -fsanitize=address -fno-omit-frame-pointer")

##### Profiler #####
add_subdirectory(3d-party)
add_compile_definitions(RINGRT_PROFILE BUILD_WITH_EASY_PROFILER)
include_directories(3d-party/easy_profiler/easy_profiler_converter/include)
include_directories(3d-party/easy_profiler/easy_profiler_core/include)

##### Crypto libs #####
add_subdirectory(BigInteger)
add_subdirectory(Common)

set(CryptoLibs BigInteger DevUtils easy_profiler)

add_executable(CryptoLabs       main.cpp)
add_executable(common_tests     tests/common_tests.cpp)
add_executable(algorithms_tests tests/algorithms_tests.cpp)
add_executable(rsa_tests        tests/rsa_tests.cpp)

target_link_libraries(CryptoLabs        ${CryptoLibs})
target_link_libraries(common_tests      ${CryptoLibs})
target_link_libraries(algorithms_tests  ${CryptoLibs})
target_link_libraries(rsa_tests         ${CryptoLibs})

##### Chat #####
add_subdirectory(Chat)

target_link_libraries(Chat ${CryptoLibs})

set(ChatLibs ${CryptoLibs} Chat)

add_executable(run_server run_server.cpp)
add_executable(run_client run_client.cpp)

target_link_libraries(run_server ${ChatLibs})
target_link_libraries(run_client ${ChatLibs})

##### Blockchain #####
add_subdirectory(Blockchain)

target_link_libraries(Blockchain ${CryptoLibs})

set(BlockchainLibs ${CryptoLibs} Blockchain)

add_executable(run_blockchain run_blockchain.cpp)
target_link_libraries(run_blockchain ${BlockchainLibs})
