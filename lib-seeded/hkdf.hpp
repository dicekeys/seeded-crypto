#pragma once

#include "sodium-buffer.hpp"

SodiumBuffer hkdfBlake2b(const unsigned char* keyPtr, size_t keyLength, SodiumBuffer info, size_t outputSize);
