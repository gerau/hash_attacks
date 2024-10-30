#include <attacks.hpp>
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

int main(int argc, char** argv)
{
    firstPreimageAttack(generateRandomMessage(2, 5));
    secondPreimageAttack(generateRandomMessage(2, 5));
}
