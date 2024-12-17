#pragma once
#include <random>
#include <string>
const char START_OF_ALPHABET = 33;
const char END_OF_ALPHABET = 126;

const int N = 16;
const int N_BYTES = N / 8;

std::string addNumberToEnd(std::string message, int number);
std::string changeRandomLetter(std::string message);

int firstPreimageAttack(std::string message, bool verbose = true);
int secondPreimageAttack(std::string message, bool verbose = true);

int firstBirthdayAttack(std::string message, bool verbose = true);
int secondBirthdayAttack(std::string message, bool verbose = true);

inline void redundancyFunction(const unsigned char* x, const unsigned char* r, unsigned char* result);

struct TableRecord {
    unsigned char* x_0;
    unsigned int x_L;
};

unsigned char* generateRandomBytes(int number_of_bytes);

unsigned char* SHA_224(unsigned char* message, int size);
unsigned int calculateTag(unsigned char* x);

void printArray(const unsigned char* x, int size);
TableRecord* computeTable(int k, int l, const unsigned char* r);

unsigned char* HellmanAttack(int k, int l, const unsigned char* h, TableRecord* records, const unsigned char* r);
