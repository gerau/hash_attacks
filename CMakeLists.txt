cmake_minimum_required(VERSION 3.19)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -fopenmp ")
set(CMAKE_CXX_FLAGS_DEBUG "-g -ggdb3 -pg")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(hash_attacks)
find_package(OpenSSL)
message(${OPENSSL_CRYPTO_LIBRARY})

add_executable(main main.cpp)

add_subdirectory(src)

target_link_libraries(main attacks)
