#include "attacks.hpp"
#include <cassert>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <openssl/evp.h>
#include <string>

std::string addNumberToEnd(std::string message, int number)
{
    return message + std::to_string(number);
}

std::string changeRandomLetter(std::string message)
{
    std::random_device device;
    std::mt19937 rand(device());
    int position = rand() % message.length();
    int letter = rand() % (END_OF_ALPHABET - START_OF_ALPHABET) + START_OF_ALPHABET;

    std::string new_message = message;
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

        for (int i = 1; i <= 2; i++) {
            if (original_hash[28 - i] != new_hash[28 - i]) {
                break;
            }
            if (i == 2) {
                is_found = true;
            }
        }
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
    std::cout << "\n";
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

        for (int i = 1; i <= 2; i++) {
            if (original_hash[28 - i] != new_hash[28 - i]) {
                break;
            }
            if (i == 2) {
                is_found = true;
            }
        }
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
