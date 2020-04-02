#pragma once

#include <string>
#include <vector>

std::string toHexStr(const std::vector<unsigned char> bytes);
std::vector<unsigned char> hexStrToByteVector(const std::string hexStr);