#include <attacks.hpp>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>

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

int main(int argc, char** argv)
{
    testAttacks();

    int number_of_test = 100;
    if (argc >= 2) {
        number_of_test = std::stoi(argv[1]);
    }
    std::fstream test_file("results.csv");

    if (!test_file) {
        std::cout << "File with results not found, creating new...\n";
        test_file.open("results.csv", std::fstream::out | std::fstream::app | std::fstream::ate);
        test_file << "first preimage,second preimage,first birthday,second birthday\n";
    } else {
        test_file.open("results.csv", std::fstream::out | std::fstream::app | std::fstream::ate);
    }

    std::cout << "Starting testing with " << number_of_test << " iterations:\n";
    int percent = 0;
    auto start { std::chrono::steady_clock::now() };

    std::cout << "progress: " << std::setw(4) << percent << "%";
    for (int i = 1; i <= number_of_test; i++) {
        test_file << firstPreimageAttack(generateRandomMessage(3, 6), false) << ",";
        test_file << secondPreimageAttack(generateRandomMessage(3, 6), false) << ",";
        test_file << firstBirthdayAttack(generateRandomMessage(3, 6), false) << ",";
        test_file << secondBirthdayAttack(generateRandomMessage(3, 6), false) << "\n";

        if (((double)i / number_of_test) * 100 > percent) {
            percent = ((double)i / number_of_test) * 100;
            std::cout << "\rprogress: " << std::setw(4) << percent << "%"
                      << std::flush;
        }
    }
    std::cout << "\rprogress: " << std::setw(4) << percent << "%\n";
    auto end { std::chrono::steady_clock::now() };
    std::chrono::duration<double> elapsed_seconds { end - start };
    std::cout << "seconds elapsed for test: \033[35m" << elapsed_seconds.count() << "s\033[0m\n";
    test_file.close();
    return 0;
}
