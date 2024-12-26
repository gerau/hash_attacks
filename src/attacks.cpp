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
#include <omp.h>
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
    std::copy(r, r + (16 - N_BYTES), result);
    std::copy(x, x + N_BYTES, result + (16 - N_BYTES));
}

unsigned int calculateTag(unsigned char* x)
{
    unsigned int result = 0;
    for (int i = 0; i < N_BYTES; i++) {
        result += (unsigned int)(x[i]) << (N - 8 * i - 8);
    }
    return result;
}

bool compareTableRecords(TableRecord a, TableRecord b)
{
    return a.x_L < b.x_L;
}

TableRecord* computeTable(int k, int l, const unsigned char* r)
{

    TableRecord* table = new TableRecord[k];
    unsigned char** precomputed_x = generateKRandomBytes(k, N_BYTES);
#pragma omp parallel shared(precomputed_x, table)
    {
        const EVP_MD* md = EVP_sha224();
        int thread_id = omp_get_thread_num();
        EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
        unsigned char R[16];
        unsigned char hash[28];
        double percent = 0;
#pragma omp for
        for (int i = 0; i < k; i++) {
            if (thread_id == 0) {
                if (((double)i / k) * 100 * 8 - percent > 0.01) {
                    percent = ((double)i / k) * 100 * 8;
                    std::cout << "\rprogress of generating table: " << std::setw(5) << std::setprecision(2) << percent << "%"
                              << std::flush;
                };
            }
            unsigned char* first = precomputed_x[i];
            redundancyFunction(first, r, R);
            for (int j = 0; j < l; j++) {
                EVP_DigestInit_ex(mdctx, md, 0);
                EVP_DigestUpdate(mdctx, R, 16);
                EVP_DigestFinal_ex(mdctx, hash, 0);
                std::copy(hash + 28 - N_BYTES, hash + 28, R + 16 - N_BYTES);
            }
            table[i] = { first, calculateTag(hash + 28 - N_BYTES) };
        }
        std::cout << "                                                                \r" << std::flush;
        EVP_MD_CTX_destroy(mdctx);
    }
    std::sort(table, table + k, compareTableRecords);

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

unsigned char* HellmanAttack(int k, int l, const unsigned char* h, const TableRecord* records, const unsigned char* r)
{
    unsigned char y[N_BYTES];
    std::memcpy(y, h + (28 - N_BYTES), N_BYTES);

    const EVP_MD* md = EVP_sha224();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    unsigned char* R = new unsigned char[16];

    unsigned char* P = new unsigned char[16];
    unsigned char hash[28];

    TableRecord y_tag;
    y_tag.x_L = calculateTag(y);

    redundancyFunction(y, r, R);
    redundancyFunction(y, r, P);

    for (int i = 0; i < l; i++) {
        if (std::binary_search(records, records + k, y_tag, compareTableRecords)) {
            auto founded_index = std::lower_bound(records, records + k, y_tag, compareTableRecords);
            while ((founded_index->x_L == y_tag.x_L) && (founded_index != records + k + 1)) {
                std::memcpy(P + 16 - N_BYTES, founded_index->x_0, N_BYTES);
                for (int j = 0; j < l - i - 1; j++) {
                    EVP_DigestInit_ex(mdctx, md, 0);
                    EVP_DigestUpdate(mdctx, P, 16);
                    EVP_DigestFinal_ex(mdctx, hash, 0);
                    std::copy(hash + 28 - N_BYTES, hash + 28, P + 16 - N_BYTES);
                }
                EVP_DigestInit_ex(mdctx, md, 0);
                EVP_DigestUpdate(mdctx, P, 16);
                EVP_DigestFinal_ex(mdctx, hash, 0);
                if (compareHashes(hash, h, N_BYTES)) {
                    return P;
                }
                founded_index++;
            }
        }
        EVP_DigestInit_ex(mdctx, md, 0);
        EVP_DigestUpdate(mdctx, R, 16);
        EVP_DigestFinal_ex(mdctx, hash, 0);
        std::copy(hash + 28 - N_BYTES, hash + 28, R + 16 - N_BYTES);
        y_tag.x_L = calculateTag(R + 16 - N_BYTES);
    }
    return nullptr;
}

// no abstraction, maximum optimization

unsigned char* HellmanAttackMultipleTables(int k, int l, const unsigned char* h, TableRecord** tables, unsigned char** r)
{
    unsigned char y[N_BYTES];

    const EVP_MD* md = EVP_sha224();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();

    unsigned char x[N_BYTES];
    unsigned char* R = new unsigned char[16];
    unsigned char* P = new unsigned char[16];
    unsigned char hash[28];

    for (int t = 0; t < k; t++) {
        std::memcpy(y, h + (28 - N_BYTES), N_BYTES);
        TableRecord y_tag;
        y_tag.x_L = calculateTag(y);

        redundancyFunction(y, r[t], R);
        for (int i = 0; i < l; i++) {
            if (std::binary_search(tables[t], tables[t] + k, y_tag, compareTableRecords)) {
                auto founded_index = std::lower_bound(tables[t], tables[t] + k, y_tag, compareTableRecords);
                while ((founded_index->x_L == y_tag.x_L) && (founded_index != tables[t] + k + 1)) {

                    std::memcpy(P + 16 - N_BYTES, founded_index->x_0, N_BYTES);
                    std::memcpy(x, founded_index->x_0, N_BYTES);
                    for (int j = 0; j < l - i; j++) {
                        EVP_DigestInit_ex(mdctx, md, 0);
                        EVP_DigestUpdate(mdctx, P, 16);
                        EVP_DigestFinal_ex(mdctx, hash, 0);
                        std::copy(hash + 28 - N_BYTES, hash + 28, P + 16 - N_BYTES);
                    }
                    if (compareHashes(hash, h, N_BYTES)) {
                        return P;
                    }
                    founded_index++;
                }
            }
            EVP_DigestInit_ex(mdctx, md, 0);
            EVP_DigestUpdate(mdctx, R, 16);
            EVP_DigestFinal_ex(mdctx, hash, 0);
            std::copy(hash + 28 - N_BYTES, hash + 28, R + 16 - N_BYTES);
            y_tag.x_L = calculateTag(y);
        }
    }
    return nullptr;
}
