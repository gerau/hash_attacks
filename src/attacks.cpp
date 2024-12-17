#include "attacks.hpp"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <omp.h> // OpenMP for parallelism
#include <openssl/evp.h>
#include <random>

#include <set>
#include <string>

std::string addNumberToEnd(std::string message, int number)
{
    return message + std::to_string(number);
}

bool compareHashes(const unsigned char* first_hash, const unsigned char* second_hash, int number_of_bytes)
{
    for (int i = 1; i <= number_of_bytes; i++) {
        if (first_hash[28 - i] != second_hash[28 - i]) {
            return false;
        }
    }
    return true;
}

std::string changeRandomLetter(std::string message)
{
    std::random_device device;
    std::mt19937 rand(device());
    int position = rand() % message.length();
    int letter = rand() % (END_OF_ALPHABET - START_OF_ALPHABET) + START_OF_ALPHABET;

    std::string new_message = message;
    while (new_message.at(position) == (char)letter) {
        letter = rand() % (END_OF_ALPHABET - START_OF_ALPHABET) + START_OF_ALPHABET;
    }
    new_message[position] = (char)letter;
    return new_message;
}

void printMessageWithHash(std::string message, unsigned char* hash, int bytes, int width)
{
    std::cout << "message = \033[32m" << std::left << std::setw(width + 10) << message << std::setw(10) << std::right << "\033[0mhash = ";
    for (int i = 0; i < 28 - bytes; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << "\033[31m";
    for (int i = 28 - bytes; i < 28; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << "\033[0m" << std::setfill(' ') << std::endl;
}

int firstPreimageAttack(std::string message, bool verbose)
{
    unsigned char original_hash[28] {};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha224();
    EVP_DigestInit(mdctx, md);
    EVP_DigestUpdate(mdctx, message.data(), message.length());
    EVP_DigestFinal(mdctx, original_hash, 0);

    std::string new_message = "";
    bool is_found = false;
    int iteration = 0;
    unsigned char new_hash[28] {};

    while (!is_found) {
        iteration++;
        new_message = addNumberToEnd(message, iteration);

        EVP_DigestInit(mdctx, md);
        EVP_DigestUpdate(mdctx, new_message.data(), new_message.length());
        EVP_DigestFinal(mdctx, new_hash, 0);

        is_found = compareHashes(original_hash, new_hash, 2);
        if (iteration < 30 && verbose) {
            printMessageWithHash(new_message, new_hash, 2, message.length());
        }
    }
    if (verbose) {
        std::cout << "\n\033[36mfounded preimage: \033[0m\n";
        printMessageWithHash(new_message, new_hash, 2, message.length());
        std::cout << "\n\033[36moriginal message: \033[0m\n";
        printMessageWithHash(message, original_hash, 2, message.length());
        std::cout << "\n";
    }
    return iteration;
}

int secondPreimageAttack(std::string message, bool verbose)
{
    unsigned char original_hash[28] {};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha224();
    EVP_DigestInit(mdctx, md);
    EVP_DigestUpdate(mdctx, message.data(), message.length());
    EVP_DigestFinal(mdctx, original_hash, 0);

    std::string new_message = message;
    bool is_found = false;
    int iteration = 0;
    unsigned char new_hash[28] {};

    while (!is_found) {
        iteration++;
        new_message = changeRandomLetter(new_message);

        EVP_DigestInit(mdctx, md);
        EVP_DigestUpdate(mdctx, new_message.data(), new_message.length());
        EVP_DigestFinal(mdctx, new_hash, 0);

        is_found = compareHashes(original_hash, new_hash, 2);
        if (iteration < 30 && verbose) {
            printMessageWithHash(new_message, new_hash, 2, message.length());
        }
    }
    if (verbose) {
        std::cout << "\n\033[36mfounded preimage: \033[0m\n";
        printMessageWithHash(new_message, new_hash, 2, message.length());
        std::cout << "\n\033[36moriginal message: \033[0m\n";
        printMessageWithHash(message, original_hash, 2, message.length());
    }
    return iteration;
}

int firstBirthdayAttack(std::string message, bool verbose)
{
    std::map<uint32_t, std::string> sigma;
    unsigned char hash[28] {};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha224();
    EVP_DigestInit(mdctx, md);
    EVP_DigestUpdate(mdctx, message.data(), message.length());
    EVP_DigestFinal(mdctx, hash, 0);

    uint32_t short_hash = (uint32_t)hash[0] + ((uint32_t)hash[1] << 8) + ((uint32_t)hash[2] << 16) + ((uint32_t)hash[3] << 24);
    sigma.insert({ short_hash, message });
    std::string new_message = "";
    bool is_found = false;
    int iteration = 0;

    unsigned char new_hash[28] {};
    while (!is_found) {
        iteration++;
        new_message = addNumberToEnd(message, iteration);

        EVP_DigestInit(mdctx, md);
        EVP_DigestUpdate(mdctx, new_message.data(), new_message.length());
        EVP_DigestFinal(mdctx, new_hash, 0);

        short_hash = (uint32_t)new_hash[27] + ((uint32_t)new_hash[26] << 8) + ((uint32_t)new_hash[25] << 16) + ((uint32_t)new_hash[24] << 24);
        if (iteration < 30 && verbose) {
            printMessageWithHash(new_message, new_hash, 4, message.length());
        }
        if (sigma.count(short_hash)) {
            is_found = true;

            EVP_DigestInit(mdctx, md);
            EVP_DigestUpdate(mdctx, sigma.at(short_hash).data(), sigma.at(short_hash).length());
            EVP_DigestFinal(mdctx, hash, 0);

            break;
        }
        sigma.insert({ short_hash, new_message });
    }
    if (verbose) {
        std::cout << "\n\033[36mfounded collision: \033[0m\n";
        printMessageWithHash(new_message, new_hash, 4, message.length());
        printMessageWithHash(sigma.at(short_hash), hash, 4, message.length());
    }
    return iteration;
}

int secondBirthdayAttack(std::string message, bool verbose)
{
    std::map<uint32_t, std::string> sigma;
    unsigned char hash[28] {};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha224();
    EVP_DigestInit(mdctx, md);
    EVP_DigestUpdate(mdctx, message.data(), message.length());
    EVP_DigestFinal(mdctx, hash, 0);

    uint32_t short_hash = (uint32_t)hash[0] + ((uint32_t)hash[1] << 8) + ((uint32_t)hash[2] << 16) + ((uint32_t)hash[3] << 24);
    sigma.insert({ short_hash, message });
    std::string new_message = message;
    bool is_found = false;
    int iteration = 0;

    unsigned char new_hash[28] {};
    while (!is_found) {
        iteration++;
        new_message = changeRandomLetter(new_message);

        EVP_DigestInit(mdctx, md);
        EVP_DigestUpdate(mdctx, new_message.data(), new_message.length());
        EVP_DigestFinal(mdctx, new_hash, 0);

        short_hash = (uint32_t)new_hash[27] + ((uint32_t)new_hash[26] << 8) + ((uint32_t)new_hash[25] << 16) + ((uint32_t)new_hash[24] << 24);
        if (iteration < 30 && verbose) {
            printMessageWithHash(new_message, new_hash, 4, message.length());
        }
        if (sigma.count(short_hash) && sigma.at(short_hash) != new_message) {
            is_found = true;

            EVP_DigestInit(mdctx, md);
            EVP_DigestUpdate(mdctx, sigma.at(short_hash).data(), sigma.at(short_hash).length());
            EVP_DigestFinal(mdctx, hash, 0);

            break;
        }
        sigma.insert({ short_hash, new_message });
    }
    if (verbose) {
        std::cout << "\n\033[36mfounded collision: \033[0m\n";
        printMessageWithHash(new_message, new_hash, 4, message.length());
        printMessageWithHash(sigma.at(short_hash), hash, 4, message.length());
    }
    return iteration;
}

unsigned char* generateRandomBytes(int number_of_bytes)
{
    unsigned char* result = new unsigned char[number_of_bytes];
    std::random_device rd;
    std::mt19937 rng(rd());

    for (int i = 0; i < number_of_bytes; i++) {
        result[i] = (unsigned char)(rng() & 0xff);
    }
    return result;
}

unsigned char** generateKRandomBytes(int k, int number_of_bytes)
{
    unsigned char** result = new unsigned char*[k];
    std::set<unsigned long> tags;
    for (int i = 0; i < k; i++) {
        result[i] = new unsigned char[number_of_bytes];
    }
    std::random_device rd;
    std::mt19937 rng(rd());
    auto r = rng();
    unsigned long mask = (1ul << (number_of_bytes * 8)) - 1;
    for (int i = 0; i < k; i++) {
        r = r & mask;
        while (tags.find(r) != tags.end()) {
            r++;
            r &= mask;
        }
        tags.insert(r);
        for (int j = 0; j < number_of_bytes; j++) {
            result[i][j] = (unsigned char)(r & 0xff);
            r >>= 8;
        }
        r = rng();
    }
    return result;
}

void printArray(const unsigned char* x, int size)
{
    for (int i = 0; i < size; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)x[i];
    }
    std::cout << std::endl;
}

inline void redundancyFunction(const unsigned char* x, const unsigned char* r, unsigned char* result)
{
    std::memcpy(result, r, 16 - N_BYTES);
    std::memcpy(result + 16 - N_BYTES, x, N_BYTES);
}

unsigned int calculateTag(unsigned char* x)
{
    unsigned int result = 0;
    for (int i = 0; i < N_BYTES; i++) {
        result += (unsigned int)(x[i]) << (N - 8 * i - 8);
    }
    return result;
}

TableRecord* computeTable(int k, int l, const unsigned char* r)
{
    TableRecord* table = new TableRecord[k];
    unsigned char** precomputed_x = generateKRandomBytes(k, N_BYTES);

    const EVP_MD* md = EVP_sha224();
#pragma omp parallel for
    for (int i = 0; i < k; i++) {
        unsigned char* first = precomputed_x[i];
        unsigned char* second = new unsigned char[N_BYTES];
        EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
        unsigned char R[16];
        unsigned char hash[28];
        std::memcpy(second, first, N_BYTES);

        for (int j = 0; j < l; j++) {
            redundancyFunction(second, r, R);

            EVP_DigestInit_ex(mdctx, md, 0);
            EVP_DigestUpdate(mdctx, R, 16);
            EVP_DigestFinal_ex(mdctx, hash, 0);

            std::memcpy(second, hash + (28 - N_BYTES), N_BYTES);
        }
        table[i] = { first, calculateTag(second) };
        EVP_MD_CTX_destroy(mdctx);
    }
    return table;
}

unsigned char* SHA_224(unsigned char* message, int size)
{
    const EVP_MD* md = EVP_sha224();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    unsigned char* hash = new unsigned char[28];
    EVP_DigestInit_ex(mdctx, md, 0);
    EVP_DigestUpdate(mdctx, message, size);
    EVP_DigestFinal_ex(mdctx, hash, 0);
    return hash;
}

bool compareTableRecords(TableRecord a, TableRecord b)
{
    return a.x_L < b.x_L;
}

unsigned char* HellmanAttack(int k, int l, const unsigned char* h, TableRecord* records, const unsigned char* r)
{
    unsigned char y[N_BYTES];
    std::memcpy(y, h + (28 - N_BYTES), N_BYTES);
    std::sort(records, records + k, compareTableRecords);

    int j = -1;
    const EVP_MD* md = EVP_sha224();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    unsigned char R[16];
    unsigned char hash[28];
    TableRecord y_tag;
    y_tag.x_L = calculateTag(y);
    for (int i = 0; i < l; i++) {
        if (std::binary_search(records, records + k, y_tag, compareTableRecords)) {
            auto founded_index = std::lower_bound(records, records + k, y_tag, compareTableRecords);
            assert(y_tag.x_L == founded_index->x_L);
            y_tag = *founded_index;
            j = i;
            break;
        }
        redundancyFunction(y, r, R);
        EVP_DigestInit_ex(mdctx, md, 0);
        EVP_DigestUpdate(mdctx, R, 16);
        EVP_DigestFinal_ex(mdctx, hash, 0);
        std::memcpy(y, hash + (28 - N_BYTES), N_BYTES);
        y_tag.x_L = calculateTag(y);
    }
    if (j == -1) {
        return nullptr;
    }
    unsigned char x[N_BYTES];
    std::memcpy(x, y_tag.x_0, N_BYTES);
    for (int i = 0; i < l - j - 1; i++) {

        redundancyFunction(x, r, R);
        EVP_DigestInit_ex(mdctx, md, 0);
        EVP_DigestUpdate(mdctx, R, 16);
        EVP_DigestFinal_ex(mdctx, hash, 0);
        std::memcpy(x, hash + (28 - N_BYTES), N_BYTES);
    }
    unsigned char* result = new unsigned char[16];
    redundancyFunction(x, r, result);
    // auto result_hash = SHA_224(result, 16);
    // if (!compareHashes(result_hash, h, N_BYTES)) {
    //     return nullptr;
    // }
    return result;
}
