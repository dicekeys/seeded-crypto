#include "ByteBuffer.hpp"
#include "../convert.hpp"

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

ByteBuffer::ByteBuffer(const std::vector<uint8_t> &_byteVector) {
    byteVector = _byteVector;
}

ByteBuffer::ByteBuffer(const SodiumBuffer &sodiumBuffer) {
    byteVector.assign(sodiumBuffer.data, sodiumBuffer.data + sodiumBuffer.length);
}

ByteBuffer::ByteBuffer(size_t length, const unsigned char * data) {
    byteVector.assign(data, data + length);
}

ByteBuffer ByteBuffer::fromHex(const std::string& hex) {
  return ByteBuffer(hexStrToByteVector(hex));
}
std::string ByteBuffer::toHex() const {
  return toHexStr(byteVector);
}


ByteBuffer::ByteBuffer() = default;

uint32_t ByteBuffer::size() const { return uint32_t(byteVector.size()); }

void ByteBuffer::writeByte(uint8_t byte) {
    byteVector.push_back(byte);
}

void ByteBuffer::write16Bits(uint16_t value) {
    uint8_t high = uint8_t(value >> 8u) & uint8_t(0xff);
    uint8_t low = value & uint8_t(0xff);
    writeByte(high);
    writeByte(low);
}

void ByteBuffer::write32Bits(uint32_t value) {
    uint16_t high = uint16_t(value >> 16u) & uint16_t(0xffff);
    uint16_t low = uint16_t(value) & uint16_t(0xffff);
    write16Bits(high);
    write16Bits(low);
}

void ByteBuffer::append(const SodiumBuffer &value, size_t skipBytes) {
    byteVector.insert( byteVector.end(), value.data + skipBytes, value.data + (value.length - skipBytes) );
}
void ByteBuffer::append(const std::vector<uint8_t> &value, size_t skipBytes) {
    auto start = value.begin();
    if (skipBytes > 0) {
        std::advance(start, skipBytes);
    }
    byteVector.insert( byteVector.end(), start, value.end() );
}

void ByteBuffer::append(size_t numBytes, const uint8_t* data) {
    byteVector.insert( byteVector.end(), data, data + numBytes );
}

void ByteBuffer::append(const ByteBuffer &value, size_t skipBytes) {
    append(value.byteVector, skipBytes);
}

void ByteBuffer::append(const std::string &str) {
    byteVector.insert( byteVector.end(), str.begin(), str.end() );
}

ByteBuffer ByteBuffer::slice(size_t start, size_t count) const {
    return ByteBuffer(count, byteVector.data() + start);
}
