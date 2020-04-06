#pragma once

#include "sodium-initializer.hpp"
#include "sodium.h"
#include <memory.h>
#include <vector>
#include <string>

/**
 * @brief A buffer class which uses memory that is erased
 * before the memory is released for re-use by other objects.
 * 
 * Built on top of sodium_malloc and sodium_free from LibSodium.
 * 
 * Note: while this class exists to serve a security function, in that it
 * provides memory that will be erased before re-use, it does not serve
 * all security functions.  Specifically, it cannot:
 *   1. guarantee if or when the object will be de-allocated an memory erased
 *   2. and it does not provide any bounds-checked operations.
 *      (though that feature should be on the to-do list.)
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
  SodiumBuffer(size_t length, const unsigned char* bufferData = NULL);

  /**
   * @brief Construct a SodiumBuffer by copying the length and data
   * of an array of bytes.
   */
  SodiumBuffer(const std::vector<unsigned char> &bufferData);

  /**
   * @brief Construct a new SodiumBuffer by copying another SodiumBuffer.
   * 
   * @param other 
   */
  SodiumBuffer(const SodiumBuffer &other);

  /**
   * @brief Create a SodiumBuffer from a string of hex digits.
   * 
   * @param hexStr A string of hex digits, optionally preceeded by
   * the two-character hex-string signifier "0x".
   *
   * @return SodiumBuffer A buffer of bytes reconstituted from hexStr
   */
  static SodiumBuffer fromHexString(const std::string hexStr);

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
   * @brief Conver the data in the buffer to a lowercase hex string, which
   * by nature of being stored in a string will be in a region of memory
   * that is *not* guaranteed to be erased when the object is destroyed.
   * 
   * @return const std::vector<unsigned char> A copy of the data in the SodiumBuffer
   */
  const std::string toHexString() const;
};
