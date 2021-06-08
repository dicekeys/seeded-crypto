#pragma once

#include <string>
#include "ByteBuffer.hpp"
#include "../convert.hpp"

const std::string fiveDashes = "-----";

const std::string hex64Blocks(const std::vector<unsigned char> &data) {
    const std::string hex = toHexStr(data);
    std::string result;
    for (size_t index = 0; index < hex.size(); index += 64) {
        if (index > 0) {
            result += "\n"
        }
        result += hex.substr(index, 64);
    }
    return result;
}

const std::string PEM(const std::string type, ByteBuffer data) {
    const std::string hex = "fixme";
    return fiveDashes + "BEGIN " + type + fiveDashes + "\n" +
        hex64Blocks(data.byteVector) + "\n"
        fiveDashes + "END " + type + fiveDashes + "\n";
}
