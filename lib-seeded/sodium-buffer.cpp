#include "sodium-buffer.hpp"
#include "sodium-initializer.hpp"
#include <sodium.h>
#include <memory.h>
#include <vector>

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

