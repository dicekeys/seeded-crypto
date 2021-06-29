#pragma once

#include <string>
#include <vector>
#include "../sodium-buffer.hpp"

typedef unsigned char ubyte;

/**
 * https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.txt
 * 
 *  3.1.  Scalar Numbers
 *
 *  Scalar numbers are unsigned and are always stored in big-endian
 *  format.  Using n[k] to refer to the kth octet being interpreted, the
 *  value of a two-octet scalar is ((n[0] << 8) + n[1]).  The value of a
 *  four-octet scalar is ((n[0] << 24) + (n[1] << 16) + (n[2] << 8) +
 *  n[3]).
 */

class ByteBuffer {
  public:
    std::vector<ubyte> byteVector;

    ByteBuffer(const std::vector<ubyte> &_byteVector);
    ByteBuffer(const SodiumBuffer &sodiumBuffer);
    ByteBuffer(size_t length, const unsigned char* data);
    ByteBuffer(size_t length);
    ByteBuffer();

    static ByteBuffer fromHex(const std::string &hex);
    static ByteBuffer concat(const ByteBuffer &firstPart, const ByteBuffer &secondPart);
    std::string toHex() const;

    const ByteBuffer SHA1() const;
    const ByteBuffer SHA2_256() const;

    uint32_t size() const;
    ubyte* data() const;

    ByteBuffer slice(size_t start, size_t count) const;

    void writeByte(ubyte byte);

    void write16Bits(uint16_t value);
    void write32Bits(uint32_t value);

    void append(const std::vector<ubyte> &value, size_t skipBytes = 0);
    void append(const SodiumBuffer &value, size_t skipBytes = 0);
    void append(size_t numBytes, const ubyte* data);
    void append(const ByteBuffer &value, size_t skipBytes = 0);
    void append(const std::string &str);
};

