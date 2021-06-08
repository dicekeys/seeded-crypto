#pragma once

#include <vector>
#include <string>

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

    ByteBuffer(const std::vector<uint8_t> &_byteVector) {
      byteVector = _byteVector;
    }

    ByteBuffer() { 
    }

    uint32_t size() const { return byteVector.size(); };

    void writeByte(uint8_t byte) {
      byteVector.push_back(byte);
    };

    void write16Bits(uint16_t value) {
      uint8_t high = (value >> 8) & 0xff;
      uint8_t low = value & 0xff;
      writeByte(high);
      writeByte(low);
    };

    void write32Bits(uint32_t value) {
      uint16_t high = (value >> 16) & 0xffff;
      uint16_t low = value & 0xffff;
      write16Bits(high);
      write16Bits(low);
    };
  
    void append(std::vector<uint8_t> &value, size_t skipBytes = 0) {
      auto start = value.begin();
      if (skipBytes > 0) {
        std::advance(start, skipBytes);
      }
      byteVector.insert( byteVector.end(), start, value.end() );
    };

    void append(ByteBuffer &value, size_t skipBytes = 0) {
      append(value.byteVector, skipBytes);
    };
};

