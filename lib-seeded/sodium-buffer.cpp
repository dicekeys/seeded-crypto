#include <sodium.h>
#include <memory.h>
#include <vector>
#include <stdexcept>
#include "sodium-buffer.hpp"
#include "sodium-initializer.hpp"
#include "convert.hpp"

/*
Wrap sodium_malloc to ensure that memory is allocated on an 8-byte boundary
by allocating extra bytes if necessary.

Per the sodium_malloc documentation: https://libsodium.gitbook.io/doc/memory_management
    "The returned address will not be aligned if the allocation size is not a multiple of the required alignment.
    For this reason, sodium_malloc() should not be used with packed or variable-length structures, unless the size
    given to sodium_malloc() is rounded up in order to ensure proper alignment."
*/
void* sodium_malloc_aligned(size_t length) {
    ensureSodiumInitialized();
    const size_t lengthMod8 = length % 8;
    const size_t lengthExtendedToEnsure64BitAlignment =
        length + lengthMod8 + ( (lengthMod8 == 0) ? 0 : 8 );
    return sodium_malloc(lengthExtendedToEnsure64BitAlignment);
}

SodiumBuffer::SodiumBuffer(size_t length, const unsigned char* bufferData):
    length(length),
    data((unsigned char*) sodium_malloc_aligned(length))
{
    if (bufferData != NULL) {
        memcpy(data, bufferData, length);
    }
};

SodiumBuffer::SodiumBuffer(const SodiumBuffer &other) :
    SodiumBuffer(other.length, other.data) {}

SodiumBuffer::SodiumBuffer(const std::vector<unsigned char> &bufferData) :
    SodiumBuffer(bufferData.size(), bufferData.data()) {}


SodiumBuffer::~SodiumBuffer() {
    sodium_free(data);
}

const std::vector<unsigned char> SodiumBuffer::toVector() const {
    std::vector<unsigned char> v(length);
    memcpy(v.data(), data, length);
    return v;
}

const std::string SodiumBuffer::toHexString() const {
    constexpr char hexDigits[] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

  std::string hexString(length * 2, ' ');
  for (int i = 0; i < length; i++) {
    unsigned char b = data[i];
    hexString[2 * i] = hexDigits[b >> 4];
    hexString[2 * i + 1] = hexDigits[b & 0xf];
  }
  return hexString;
}

SodiumBuffer SodiumBuffer::fromHexString(const std::string hexStr) {
    if (hexStr.length() >= 2 && hexStr[1] == 'x' && hexStr[0] == '0') {
        // Ignore prefix '0x'
        return hexStrToByteVector(hexStr.substr(2));
    }
    if (hexStr.length() % 2 == 1) {
        throw std::invalid_argument("Invalid hex string length");
    }
    SodiumBuffer buffer(hexStr.length() / 2);
    for (size_t i = 0; i < buffer.length; i++) {
        buffer.data[i] = (parseHexChar(hexStr[2 * i]) << 4) | parseHexChar(hexStr[2 * i + 1]);
    }
    return buffer;
}
