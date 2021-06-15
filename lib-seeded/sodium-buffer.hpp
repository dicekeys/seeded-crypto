#pragma once

#include "sodium-initializer.hpp"
#include "sodium.h"
#include <memory.h>
#include <vector>
#include <string>

// class SodiumBufferSerializationIterator;

/**
 * @brief A byte array containing a length and a pointer to memory (the data field),
 * which ensures data is erased (replaced with zeros) before the memory it occupies
 * is released for re-use by other objects.
 * 
 * Built on top of sodium_malloc and sodium_free from LibSodium.
 * 
 * Note: while this class exists to serve a security function, in that it
 * provides memory that will be erased before re-use, it does not serve
 * all security functions.  Specifically, it cannot:
 *   1. guarantee if or when the object will be de-allocated an memory erased
 *   2. and it does not provide any bounds-checked operations.
 *      (though that feature should be on the to-do list.)
 * 
 * @ingroup BuildingBlocks
 */
class SodiumBuffer {
public:
  /**
   * @brief A pointer to the buffer of bytes
   *
   */
  unsigned char* data;
  /**
   * @brief The length of the buffer.
   *
   */
  const size_t length;

  /**
   * @brief Construct a new SodiumBuffer by specifying its length
   * and optionally specifying a pointer to a buffer of that length
   * or greater.
   *
   * @param length The number of bytes to allocate to the buffer
   * @param bufferData An optional pointer to data to copy, which
   * must be at least length bytes long.
   */
  SodiumBuffer(size_t length = 0, const unsigned char* bufferData = NULL);

  /**
   * @brief Construct a SodiumBuffer by copying the length and data
   * of an array of bytes.
   */
  SodiumBuffer(const std::vector<unsigned char>& bufferData);

  /**
   * @brief Construct a new SodiumBuffer by copying another SodiumBuffer.
   *
   * @param other
   */
  SodiumBuffer(const SodiumBuffer& other);

  /**
    * Construct a buffer that stores a string
    */
  SodiumBuffer(const std::string str);

  /**
   * @brief Create a new SodiumBuffer that stored a fixed-length array
   * of other $n$ other sodium buffers.
   * 
   * Each of the first $n_-1$ buffers is preceded by a four-byte big-endian
   * length field. The length of the final field is the number of bytes
   * remaining in the resulting SodiumBuffer (it is implicit since
   * SodiumBuffer objects track their total length).
   * 
   * @param buffers A vector of pointers to SodiumBuffer objects.
   * You may pass null pointers which will create fields of zero bytes in length.
   * (They will be de-serialized as zero-length SodiumBuffer objects).
   * 
   * This is handy for serializing objects with a fixed set of members that
   * can be serialized into SodiumBuffer objects (e.g. byte arrays & strings).
   */
  static const SodiumBuffer combineFixedLengthList(
    const std::vector<const SodiumBuffer*>& buffers
  );

  /**
   * @brief Deserialize a fixed-length list of SodiumBuffers that had
   * been serialized to a single buffer via a call to the static
   * combineFixedLengthList method.
   * 
   * The result is a vector of SodiumBuffers.
   * 
   * @param count The number of buffers in the list that was combined
   * to form this SodiumBuffer
   * @return const std::vector<SodiumBuffer> The list of SodiumBuffer objects
   * that were combined into a list when this SodiumBuffer was constructed
   * via combineFixedLengthList.
   */
  const std::vector<SodiumBuffer> splitFixedLengthList(
      int count
  ) const;

  /**
   * @brief Create a SodiumBuffer from a string of hex digits.
   * 
   * @param hexStr A string of hex digits, optionally preceeded by
   * the two-character hex-string signifier "0x".
   *
   * @return SodiumBuffer A buffer of bytes reconstituted from hexStr
   */
  static SodiumBuffer fromHexString(const std::string& hexStr);

  /**
   * @brief Destroy the SodiumBuffer object, freeing and zero-ing
   * the buffer.
   */
  ~SodiumBuffer();

  /**
   * @brief Copy the buffer into a byte vector, which by nature of being
   * a standard library class will be stored in a region of memory
   * that is *not* guaranteed to be erased when the object is destroyed.
   * 
   * @return const std::vector<unsigned char> A copy of the data in the SodiumBuffer
   */
  const std::vector<unsigned char> toVector() const;

  /**
 * @brief If the data in the buffer represents a UTF8-format string, reconstitute
 * the data back into a UTF8 std::string.  Note that the result will be in a
 * region of memory that is *not* guaranteed to be erased when the object is destroyed.
 */
  const std::string toUtf8String() const;

  /**
   * @brief Convert the data in the buffer to a lowercase hex string, which
   * by nature of being stored in a string will be in a region of memory
   * that is *not* guaranteed to be erased when the object is destroyed.
   * 
   * @return const std::vector<unsigned char> A copy of the data in the SodiumBuffer
   */
  const std::string toHexString() const;

  /**
   * Get a serialization iterator that allows serialized messages to be
   * deconstructed by popping fields out of a buffer.
   */
  //SodiumBufferSerializationIterator getSerializationIterator() const;
};
