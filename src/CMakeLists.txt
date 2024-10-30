add_library(attacks attacks.cpp)

target_include_directories(attacks PUBLIC ${CMAKE_SOURCE_DIR}/include)

set(OPENSSL_USE_STATIC_LIBS TRUE)

target_link_libraries(attacks PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
