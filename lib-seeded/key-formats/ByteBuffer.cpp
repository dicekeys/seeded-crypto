#include "ByteBuffer.hpp"
#include "../convert.hpp"
#include "SHA1.hpp"

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

ByteBuffer::ByteBuffer(const std::vector<ubyte> &_byteVector) {
    byteVector = _byteVector;
}

ByteBuffer::ByteBuffer(const SodiumBuffer &sodiumBuffer) {
    byteVector.assign(sodiumBuffer.data, sodiumBuffer.data + sodiumBuffer.length);
}

ByteBuffer::ByteBuffer(size_t length, const unsigned char * data) {
    byteVector.assign(data, data + length);
}

ByteBuffer::ByteBuffer(size_t length) {
  byteVector.assign(length, 0);
}

ByteBuffer ByteBuffer::fromHex(const std::string& hex) {
  return ByteBuffer(hexStrToByteVector(hex));
}
std::string ByteBuffer::toHex() const {
  return toHexStr(byteVector);
}

const ByteBuffer ByteBuffer::SHA1() const {
  sha1 hash = sha1();
  hash.add(byteVector.data(), byteVector.size());
  hash.finalize();
  ByteBuffer hashBuffer;
  // Write a word at a time to ensure the hash has the correct byte ordering.
  for (uint32_t word = 0; word < 5; word++) {
    hashBuffer.write32Bits(hash.state[word]);
  }
  return hashBuffer;
}

const ByteBuffer ByteBuffer::SHA2_256() const {
  ByteBuffer sha256Hash(crypto_hash_sha256_BYTES);
  crypto_hash_sha256(sha256Hash.data(), byteVector.data(), byteVector.size());
  return sha256Hash;
}

ByteBuffer::ByteBuffer() = default;

uint32_t ByteBuffer::size() const { return uint32_t(byteVector.size()); }
ubyte* ByteBuffer::data() const { return (ubyte*)byteVector.data(); }

void ByteBuffer::writeByte(ubyte byte) {
    byteVector.push_back(byte);
}

void ByteBuffer::write16Bits(uint16_t value) {
    ubyte high = ubyte(value >> 8u) & ubyte(0xff);
    ubyte low = value & ubyte(0xff);
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
void ByteBuffer::append(const std::vector<ubyte> &value, size_t skipBytes) {
    auto start = value.begin();
    if (skipBytes > 0) {
        std::advance(start, skipBytes);
    }
    byteVector.insert( byteVector.end(), start, value.end() );
}

void ByteBuffer::append(size_t numBytes, const ubyte* data) {
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

ByteBuffer ByteBuffer::concat(const ByteBuffer &firstPart, const ByteBuffer &secondPart) {
    ByteBuffer result(firstPart);
    result.append(secondPart);
    return result;
}
