#include <attacks.hpp>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <isa-l_crypto.h>
#include <omp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <ratio>
#include <set>

const std::string DEFAULT = "\033[0m";

const std::string PURPLE = "\033[35m";

const std::string my_name[3] {
    "herashchenko",
    "volodymyr",
    "sergiyovich"
};
std::string generateRandomLetters(int number_of_letters)
{
    std::string result;
    std::random_device device;
    std::mt19937 rand(device());
    for (int i = 0; i < number_of_letters; i++) {
        result += (char)(rand() % (END_OF_ALPHABET - START_OF_ALPHABET) + START_OF_ALPHABET);
    }
    return result;
}

std::string generateRandomMessage(int min, int max)
{
    std::string random_message = "";

    for (int i = 0; i < 3; i++) {
        random_message += generateRandomLetters(rand() % (max - min) + min);
        random_message += my_name[i];
    }
    random_message += generateRandomLetters(rand() % (max - min) + min);
    return random_message;
}

void testAttacks()
{
    int iterations = 0;
    iterations = firstPreimageAttack(generateRandomMessage(2, 5));
    std::cout << std::dec << "\nfirst preimage attack, iterations = " << iterations << "\n\n";

    iterations = secondPreimageAttack(generateRandomMessage(2, 5));
    std::cout << std::dec << "\nsecond preimage attack, iterations = " << iterations << "\n\n";

    iterations = firstBirthdayAttack(generateRandomMessage(2, 5));
    std::cout << std::dec << "\nfirst birthday attack, iterations = " << iterations << "\n\n";

    iterations = secondBirthdayAttack(generateRandomMessage(2, 5));
    std::cout << std::dec << "\nsecond birthday attack, iterations = " << iterations << "\n\n";
}

void runHellman()
{
    // int ks[] = {
    //     1 << 10,
    //     1 << 12,
    //     1 << 14
    //
    // };
    // int ls[] = {
    //     1 << 5,
    //     1 << 6,
    //     1 << 7
    //
    // };

    int ks[] = {
        // 1 << 20,
        // 1 << 22,
        1 << 24

    };
    int ls[] = {
        // 1 << 10,
        // 1 << 11,
        1 << 12,

    };

    int attempts = 10000;

    for (auto k : ks) {
        for (auto l : ls) {
            std::streamsize prev_precision = std::cout.precision();
            auto r = generateRandomBytes(16 - N_BYTES);
            std::cout << "=========================================" << '\n';
            std::cout << "attack for parameters k = " << k << " and l = " << l << '\n';
            auto start { std::chrono::steady_clock::now() };
            auto s = computeTable(k, l, r);
            auto end { std::chrono::steady_clock::now() };
            std::chrono::duration<double> elapsed_seconds { end - start };
            std::cout.precision(prev_precision);

            std::cout << "time taken for table generation = " << elapsed_seconds.count() << "s\n";
            start = std::chrono::steady_clock::now();
            std::set<uint32_t> set_xL;
            for (int i = 0; i < k; i++) {
                set_xL.insert(s[i].x_L);
            }
            std::cout << "generated table for attack!\n"
                      << '\n';
            std::cout << "table unique elements of x_L = " << set_xL.size() << "; percentage: " << (double)set_xL.size() / (double)k * 100 << "%" << '\n';

            int failure = 0;

#pragma omp parallel reduction(+ : failure)
            {
                double percent = 0;
                int thread_id = omp_get_thread_num();

#pragma omp for
                for (int i = 0; i < attempts; i++) {
                    unsigned char* message = generateRandomBytes(32);
                    auto hash = SHA_224(message, 32);

                    auto collision = HellmanAttack(k, l, hash, s, r);

                    if (thread_id == 0) {
                        if (((double)i / attempts) * 100 * 8 - percent > 0.01) {
                            percent = ((double)i / attempts) * 100 * 8;
                            std::cout << "\rprogress of attack: " << std::setw(5) << std::setprecision(2) << percent << "%"
                                      << std::flush;
                        };
                    }

                    if (collision == nullptr) {
                        failure++;
                        continue;
                    }
                }
            }

            std::cout << "\r                                                                \n"
                      << std::flush;
            std::cout.precision(prev_precision);
            std::cout << "attacks ended!\n";
            end = std::chrono::steady_clock::now();
            elapsed_seconds = end - start;
            std::cout << "time taken for attack = " << elapsed_seconds.count() << "s\n";

            std::cout << "number of successful attempts = " << std::dec << attempts - failure << " from " << attempts << " attempts\n";

            std::cout << "percentage of successful attempts = " << PURPLE << (double)(attempts - failure) / (double)attempts * 100 << DEFAULT << "%\n\n";
            delete[] s;
        }
    }
}

void runMultipleHellman()
{
    int ks[] = {
        1 << 10,
        1 << 12,
        1 << 14

    };
    int ls[] = {
        1 << 5,
        1 << 6,
        1 << 7

    };

    // int ks[] = {
    //     1 << 20,
    //     1 << 22,
    //     1 << 22
    //
    // };
    // int ls[] = {
    //     1 << 10,
    //     1 << 11,
    //     1 << 12,
    //
    // };

    int attempts = 10000;

    for (auto k : ks) {
        for (auto l : ls) {
            std::streamsize prev_precision = std::cout.precision();

            unsigned char** rs = new unsigned char*[k];
            TableRecord** tables = new TableRecord*[k];

            for (int i = 0; i < k; i++) {
                auto r = generateRandomBytes(16 - N_BYTES);
                auto s = computeTable(k, l, r);
                tables[i] = s;
                rs[i] = r;
            }
            std::cout << "=========================================" << '\n';
            std::cout << "attack for parameters k = " << k << " and l = " << l << '\n';
            auto start { std::chrono::steady_clock::now() };

            std::cout.precision(prev_precision);

            start = std::chrono::steady_clock::now();

            int failure = 0;

#pragma omp parallel reduction(+ : failure)
            {
                double percent = 0;
                int thread_id = omp_get_thread_num();

#pragma omp for
                for (int i = 0; i < attempts; i++) {
                    unsigned char* message = generateRandomBytes(32);
                    auto hash = SHA_224(message, 32);

                    auto collision = HellmanAttackMultipleTables(k, l, hash, tables, rs);

                    if (thread_id == 0) {
                        if (((double)i / attempts) * 100 * 8 - percent > 0.01) {
                            percent = ((double)i / attempts) * 100 * 8;
                            std::cout << "\rprogress of attack: " << std::setw(5) << std::setprecision(2) << percent << "%"
                                      << std::flush;
                        };
                    }

                    if (collision == nullptr) {
                        failure++;
                        continue;
                    }
                }
            }

            std::cout << "\r                                                                \n"
                      << std::flush;
            std::cout.precision(prev_precision);
            std::cout << "attacks ended!\n";
            auto end = std::chrono::steady_clock::now();
            auto elapsed_seconds = end - start;
            std::cout << "time taken for attack = " << elapsed_seconds.count() << "s\n";

            std::cout << "number of successful attempts = " << std::dec << attempts - failure << " from " << attempts << " attempts\n";

            std::cout << "percentage of successful attempts = " << PURPLE << (double)(attempts - failure) / (double)attempts * 100 << DEFAULT << "%\n\n";
            delete[] rs;
            delete[] tables;
        }
    }
}

int main(int argc, char** argv)
{

    runHellman();
    // runMultipleHellmsan();
    /*
        int k = 1 << 20;
        int l = 1 << 10;
        auto r = generateRandomBytes(16 - N_BYTES);
        std::cout << "=========================================" << '\n';
        std::cout << "attack for parameters k = " << 1 << 14 << " and l = " << 1 << 7 << '\n';
        auto start { std::chrono::steady_clock::now() };
        auto s = computeTable(k, l, r);
        auto end { std::chrono::steady_clock::now() };
        std::chrono::duration<double> elapsed_seconds { end - start };

        std::cout << "r = ";
        printArray(r, 16 - N_BYTES);
        unsigned char* message = generateRandomBytes(32);

        auto hash = SHA_224(message, 32);

        auto collision = HellmanAttack(k, l, hash, s, r);
        int attempt = 1;
        while (collision == nullptr) {
            std::cout << "attack failed :( \n";
            message = generateRandomBytes(32);
            hash = SHA_224(message, 32);

            collision = HellmanAttack(k, l, hash, s, r);
            attempt++;
        }
        std::cout << "message = ";
        printArray(message, 32);
        std::cout << "hash  = ";
        printArray(hash, 28);
        std::cout << "found collision on iteration: " << attempt << '\n';*/
}
