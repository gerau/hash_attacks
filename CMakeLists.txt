cmake_minimum_required(VERSION 3.19)
set(CMAKE_CXX_STANDARD 17)
project(hash_attacks)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL)
message(${OPENSSL_CRYPTO_LIBRARY})

add_executable(main main.cpp)

add_subdirectory(src)

target_link_libraries(main attacks)
