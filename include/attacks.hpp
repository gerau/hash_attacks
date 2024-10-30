#pragma once
#include <random>
#include <string>
const char START_OF_ALPHABET = 33;
const char END_OF_ALPHABET = 126;

std::string addNumberToEnd(std::string message, int number);
std::string changeRandomLetter(std::string message);

int firstPreimageAttack(std::string message, bool verbose = true);
int secondPreimageAttack(std::string message, bool verbose = true);

int firstBirthdayAttack(std::string message, bool verbose = true);
int secondBirthdayAttack(std::string message, bool verbose = true);
