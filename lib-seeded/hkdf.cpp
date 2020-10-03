#include "sodium.h"
#include "sodium-buffer.hpp"

#include "hkdf.hpp"
// https://tools.ietf.org/html/rfc5869, with Blake2 in 32 byte block mode
SodiumBuffer hkdfBlake2b(const unsigned char* keyPtr, size_t keyLength, SodiumBuffer info, size_t outputSize) {
  static const size_t blockSize = 32;

  // Section 2.2
  // PRK = HMAC-Hash(salt, IKM)
  static const unsigned char zero_bytes_for_salt[blockSize] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  SodiumBuffer PRK(blockSize);
  crypto_generichash_blake2b(
    (unsigned char*)PRK.data, PRK.length,
    keyPtr, keyLength,
    zero_bytes_for_salt, blockSize);

  const size_t blockAlignedSize = ((outputSize + blockSize - 1) / blockSize ) * blockSize;
  SodiumBuffer resultBlocks(blockAlignedSize);
  SodiumBuffer blakeHashState(crypto_generichash_blake2b_statebytes());
  unsigned char counterByte = 1;  
  // T(0) = empty string (zero length)
  // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
  // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
  // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
  // T(i) = HMAC-Hash(PRK, T(i-1) | info | (i % 256) )
  for (size_t bytesGenerated = 0; bytesGenerated < resultBlocks.length; bytesGenerated += blockSize) {
    crypto_generichash_blake2b_init(
      static_cast<crypto_generichash_blake2b_state*>((void*)blakeHashState.data),
      PRK.data, PRK.length,
      blockSize
    );
    // T(i-1)
    if (bytesGenerated == 0) {
      // T(1-1) == T(0) == empty string (zero length), as there is no previous block
    } else {
      // T(i-1) for i > 1 is the previous block
      crypto_generichash_blake2b_update(
        static_cast<crypto_generichash_blake2b_state*>((void*)blakeHashState.data),
        resultBlocks.data + bytesGenerated - blockSize, blockSize
      );
    }
    // | info
    crypto_generichash_blake2b_update(
      static_cast<crypto_generichash_blake2b_state*>((void*)blakeHashState.data),
      info.data, info.length
    );
    // | (i % 256)
    crypto_generichash_blake2b_update(
      static_cast<crypto_generichash_blake2b_state*>((void*)blakeHashState.data),
      &counterByte, 1
    );
    counterByte++;
    crypto_generichash_blake2b_final(
      static_cast<crypto_generichash_blake2b_state*>((void*)blakeHashState.data),
      resultBlocks.data + bytesGenerated, blockSize
    );
  }

  if (outputSize < resultBlocks.length) {
    // If the caller requested fewer bytes than we generated, truncate to the requested length
    SodiumBuffer trimmedResult(outputSize);
    memcpy(trimmedResult.data, resultBlocks.data, trimmedResult.length);
    return trimmedResult;
  } else {
    return resultBlocks;
  }
  
}
