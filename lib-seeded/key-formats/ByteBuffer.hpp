#pragma once

#include <string>
#include <vector>
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
    std::vector<uint8_t> byteVector;

    ByteBuffer(const std::vector<uint8_t> &_byteVector);
    ByteBuffer(size_t length, const unsigned char * data);
    ByteBuffer();

    uint32_t size() const;

    void writeByte(uint8_t byte);

    void write16Bits(uint16_t value);
    void write32Bits(uint32_t value);
  
    void append(const std::vector<uint8_t> &value, size_t skipBytes = 0);
    void append(size_t numBytes, const uint8_t* data);
    void append(const ByteBuffer &value, size_t skipBytes = 0);
    void append(const std::string str);

    ByteBuffer slice(size_t start, size_t count) const;
};

