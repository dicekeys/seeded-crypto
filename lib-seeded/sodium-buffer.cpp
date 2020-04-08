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
        length + ( (lengthMod8 == 0) ? 0 : (8 - lengthMod8) );
    return sodium_malloc(lengthExtendedToEnsure64BitAlignment);
}

SodiumBuffer::SodiumBuffer(size_t _length, const unsigned char* bufferData):
    length(_length),
    data((unsigned char*) sodium_malloc_aligned(_length))
{
    if (bufferData != NULL && _length > 0) {
        memcpy(data, bufferData, _length);
    }
};

SodiumBuffer::SodiumBuffer(const std::string str) : SodiumBuffer(
  str.size(),
  (const unsigned char*)str.data())
{}


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

const std::string SodiumBuffer::toUtf8String() const {
  return std::string((const char*)data, (const size_t)length);
}

const std::string SodiumBuffer::toHexString() const {
    constexpr char hexDigits[] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

  std::string hexString(length * 2, ' ');
  for (size_t i = 0; i < length; i++) {
    unsigned char b = data[i];
    hexString[2 * i] = hexDigits[b >> 4];
    hexString[2 * i + 1] = hexDigits[b & 0xf];
  }
  return hexString;
}

SodiumBuffer SodiumBuffer::fromHexString(const std::string& hexStr) {
    if (hexStr.length() >= 2 && hexStr[1] == 'x' && hexStr[0] == '0') {
        // Ignore prefix '0x'
        return SodiumBuffer::fromHexString(hexStr.substr(2));
    }
    else {
      if (hexStr.length() % 2 == 1) {
        throw std::invalid_argument("Invalid hex string length");
      }
      SodiumBuffer buffer(hexStr.length() / 2);
      for (size_t i = 0; i < buffer.length; i++) {
        buffer.data[i] = (parseHexChar(hexStr[2 * i]) << 4) | parseHexChar(hexStr[2 * i + 1]);
      }
      return buffer;
    }
}

// const SodiumBuffer SodiumBuffer::pushField(const SodiumBuffer &bufferToPrepend) const {
//   size_t newBufferLength = 4 + bufferToPrepend.length + length;
//   if (newBufferLength > 0xffffffff || newBufferLength <= (length + 4)) {
//       // This new buffer is so big it would overflow a 4-byte word length.
//       // Throw an exception and limit sizes to 4GB rather than risk overflow vulns
//       throw std::invalid_argument("Attempt to create buffer that exceeds limits");
//   }
//   SodiumBuffer bufferWithNewFieldPrepended = SodiumBuffer(newBufferLength);
//   unsigned char* writePtr = bufferWithNewFieldPrepended.data;
//   // Write four-big endian bytes encoding the length of the prepended field,
//   // advancing the writePtr
//   *(writePtr++) = (bufferToPrepend.length >> 24) & 0xff;
//   *(writePtr++) = (bufferToPrepend.length >> 16) & 0xff;
//   *(writePtr++) = (bufferToPrepend.length >> 8) & 0xff;
//   *(writePtr++) = (bufferToPrepend.length) & 0xff;
//   // Write the prepended field and advance the writePtr.
//   memcpy(writePtr, bufferToPrepend.data, bufferToPrepend.length);
//   writePtr += bufferToPrepend.length;
//   // Write the data from this buffer at the end of the new buffer
//   memcpy(bufferWithNewFieldPrepended.data + 4 + bufferToPrepend.length, data, length);
//   return bufferWithNewFieldPrepended;
// }

// SodiumBufferSerializationIterator SodiumBuffer::getSerializationIterator() const {
//     return SodiumBufferSerializationIterator(this);
// }

// SodiumBufferSerializationIterator::SodiumBufferSerializationIterator(
//     const SodiumBuffer* _buffer
// ) : buffer(_buffer), bytesConsumed(0) {}

// const SodiumBuffer SodiumBufferSerializationIterator::popRemainder() {
//     const unsigned char* remainingDataPtr = buffer->data + bytesConsumed;
//     const size_t bytesRemaining = buffer->length - bytesConsumed;
//     bytesConsumed = buffer->length;
//     return SodiumBuffer(bytesRemaining, remainingDataPtr);
// }

// const bool SodiumBufferSerializationIterator::noFieldsRemain() const {
//     return (buffer->length - bytesConsumed) <= 4;
// }

// const bool SodiumBufferSerializationIterator::noDataRemain() const {
//   return (buffer->length - bytesConsumed) <= 0;
// }

const SodiumBuffer SodiumBuffer::combineFixedLengthList(
    const std::vector<const SodiumBuffer*>& sodiumBufferPtrs
) {
  size_t buffersToWrite = sodiumBufferPtrs.size();
  size_t bufferLengthNeeded = 0;
    // Calculate the length needed to serialize the record
    for (int i = 0; i < buffersToWrite; i++) {
        const SodiumBuffer* sodiumBufferPtr = sodiumBufferPtrs[i];
        if (i < buffersToWrite - 1) {
          // allocate space for 4-byte size
          bufferLengthNeeded += 4;
        }
        if (sodiumBufferPtr != NULL) {
            // allocate space for buffer
            if (sodiumBufferPtr->length > (size_t)0xffffffff) {
              throw std::invalid_argument("Cannot serialize buffers of size >= 4GB");
            }
            bufferLengthNeeded += sodiumBufferPtr->length;
        }
    }
    SodiumBuffer bufferEncodingAFixedLengthListOfOtherBuffers =
        SodiumBuffer(bufferLengthNeeded);
    unsigned char* writePtr = bufferEncodingAFixedLengthListOfOtherBuffers.data;

    for (int i = 0; i < buffersToWrite; i++) {
        const SodiumBuffer* sodiumBufferPtr = sodiumBufferPtrs[i];
        size_t thisItemsLength = sodiumBufferPtr ? sodiumBufferPtr->length : 0;
        if (i < buffersToWrite - 1) {
            // For all buffers except the last, write a four-byte big-endian
            // length field which tells us how many more bytes to read
            // before the next item starts.
            *(writePtr++) = (thisItemsLength >> 24) & 0xff;
            *(writePtr++) = (thisItemsLength >> 16) & 0xff;
            *(writePtr++) = (thisItemsLength >> 8) & 0xff;
            *(writePtr++) = (thisItemsLength) & 0xff;
        }
        if (thisItemsLength > 0) {
            // Write the contents of this item
            memcpy(writePtr, sodiumBufferPtr->data, thisItemsLength);
            writePtr += thisItemsLength;
        }
    }
    return bufferEncodingAFixedLengthListOfOtherBuffers;
}

const std::vector<SodiumBuffer> SodiumBuffer::splitFixedLengthList(
    int itemCount
) const {
  std::vector<SodiumBuffer> fixedLengthListOfBuffers(0);
    size_t bytesRemaining = length;
    unsigned char* readPtr = data;

    for (int i = 0; i < itemCount; i++) {
        size_t itemLength;
        if (i == itemCount -1) {
            // The last item in the list consumed however many bytes are remaining
            itemLength = bytesRemaining;            
        } else {
            // Parse the 4-byte field length to determine the length of this item in bytes
            if (bytesRemaining < 4) {
              throw std::invalid_argument("Not enough bytes in buffer for field length");
            }
            itemLength = 
                (size_t(*(readPtr)) << 24) +
                (size_t(*(readPtr + 1)) << 16) +
                (size_t(*(readPtr + 2)) << 8) +
                (size_t(*(readPtr + 3)));
            readPtr += 4;
            bytesRemaining -= 4;
            if (itemLength > bytesRemaining) {
                throw std::invalid_argument("Field length is longer than remaining bytes in buffer");
            }
        }
        // Copy the contents of this item into a SodiumBuffer.
        fixedLengthListOfBuffers.push_back(SodiumBuffer(itemLength, readPtr));
        readPtr += itemLength;
        bytesRemaining -= itemLength;
    }
    return fixedLengthListOfBuffers;
};

