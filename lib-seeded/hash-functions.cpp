#include <stdexcept>
#include "hash-functions.hpp"

SodiumBuffer HashFunction::hash(
		SodiumBuffer message,
		unsigned long long hash_length_in_bytes
	) const {
    return hash(message.data, message.length, hash_length_in_bytes);
  }

MemoryHardHashFunction::MemoryHardHashFunction(
		unsigned long long _opslimit,
		unsigned long long _memlimit
	) : opslimit(_opslimit), memlimit(_memlimit) {}

HashFunctionBlake2b::HashFunctionBlake2b() :
  FixedOutputLengthHashFunction(crypto_generichash_BYTES)
{}

void HashFunctionBlake2b::hash_block(
		void* hash_output,
		const void* message,
		unsigned long long message_length
	) const {
  const int nonZeroHashResultMeansOutOfMemoryError =  crypto_generichash(
    (unsigned char*)hash_output, crypto_generichash_BYTES,
    (const unsigned char*)message, message_length,
    NULL, 0);
  if (nonZeroHashResultMeansOutOfMemoryError != 0) {
    throw std::bad_alloc();
  }

}

HashFunctionSHA256::HashFunctionSHA256() :
  FixedOutputLengthHashFunction(crypto_hash_sha256_BYTES)
{}

void HashFunctionSHA256::hash_block(
  void* hash_output,
  const void* message,
  unsigned long long message_length
) const {
  const int nonZeroHashResultMeansOutOfMemoryError = 
    crypto_hash_sha256((unsigned char*)hash_output, (const unsigned char*)message, message_length);
  if (nonZeroHashResultMeansOutOfMemoryError != 0) {
    throw std::bad_alloc();
  }
}

SodiumBuffer FixedOutputLengthHashFunction::hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const {
		if (hash_length_in_bytes < block_size_in_bytes) {
			// When exactly one block is needed, just call hash_block
			SodiumBuffer block(block_size_in_bytes);
			hash_block(block.data, message, message_length);
			SodiumBuffer result(hash_length_in_bytes);
			memcpy_s(result.data, result.length, block.data, block.length);
			return result;
		} else if (hash_length_in_bytes == block_size_in_bytes) {
			// When less than a block of bytes is needed, generate one block
			// and copy only those bytes needed.
			SodiumBuffer result(block_size_in_bytes);
			hash_block(result.data, message, message_length);
			return result;
		} else {
			// When more than one block of bytes is needed, generate a hash h1
			// and then for blocks i=0...n, generate h2=(h1 + i).  Truncate
			// the last block if needed.
			SodiumBuffer result(hash_length_in_bytes), h1(block_size_in_bytes);
			unsigned long long bytes_written = 0;
			hash_block(h1.data, message, message_length);
			while (bytes_written + block_size_in_bytes <= result.length) {
				// There's at least one more full block of data to write
				// append the hash of h1
				hash_block(result.data + bytes_written, h1.data, h1.length);
				bytes_written += block_size_in_bytes;

				// increment h1
				for (int i=block_size_in_bytes-1; i > 0; i--) {
					if (++(h1.data[i]) != 0) {
						// only increment the more-significant byte in big-endian memory
						// order (the previous byte) if this byte overflowed from 255 to 0.
						// otherwise, leave the increment loop.
						break;
					}
				}
			}
			if (bytes_written < result.length) {
				// A partial block still needs to be written.  Put it in a buffer h2 and then write
				// out the number of bytes needed.
				SodiumBuffer h2(block_size_in_bytes);
				hash_block(h2.data, h1.data, h1.length);
				memcpy_s(result.data + bytes_written, result.length - bytes_written, h2.data, h2.length);
			}
		}
	}

HashFunctionArgon2id::HashFunctionArgon2id(
  unsigned long long _opslimit,
  unsigned long long _memlimit
) : MemoryHardHashFunction(_opslimit, _memlimit) {}

	
SodiumBuffer HashFunctionArgon2id::hash(
  const void* message,
  unsigned long long message_length,
  unsigned long long hash_length_in_bytes
) const {
  if (
    hash_length_in_bytes < crypto_pwhash_argon2id_BYTES_MIN ||
    hash_length_in_bytes > crypto_pwhash_argon2id_BYTES_MAX
  ) {
    throw std::invalid_argument("Invalid hash length");
  }

  // Argon2id requires a 16-byte salt.
  // Since this is only used with messages that are already salted,
  // we use a salt of 16 zero bytes.
  static const unsigned char zero_bytes_for_salt[crypto_pwhash_argon2id_SALTBYTES] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  SodiumBuffer result(hash_length_in_bytes);
  const int nonZeroHashResultMeansOutOfMemoryError = crypto_pwhash(
    result.data,
		result.length,
    (const char*)message,
		message_length,
    zero_bytes_for_salt,
    opslimit,
    memlimit,
    crypto_pwhash_ALG_ARGON2ID13
  );
  if (nonZeroHashResultMeansOutOfMemoryError != 0) {
    throw std::bad_alloc();
  }
  return result;
};

HashFunctionScrypt::HashFunctionScrypt(
  unsigned long long _opslimit,
  unsigned long long _memlimit
) : MemoryHardHashFunction(_opslimit, _memlimit)  {}
	
SodiumBuffer HashFunctionScrypt::hash(
  const void* message,
  unsigned long long message_length,
  unsigned long long hash_length_in_bytes
) const {
  if( hash_length_in_bytes < crypto_pwhash_BYTES_MIN ||
      hash_length_in_bytes > crypto_pwhash_BYTES_MIN) {
    throw std::invalid_argument("Invalid hash length");
  }
  // Scrypt requires a 32-byte salt.
  // Since this is only used with messages that are already salted,
  // we use a salt of 32 zero bytes.
  static const unsigned char zero_bytes_for_salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES] =
    {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
  SodiumBuffer result(hash_length_in_bytes);
  const int nonZeroHashResultMeansOutOfMemoryError = crypto_pwhash_scryptsalsa208sha256(
    result.data,
		result.length,
    (const char*)message,
		message_length,
    zero_bytes_for_salt,
    opslimit,
    memlimit
  );
  if (nonZeroHashResultMeansOutOfMemoryError != 0) {
    throw std::bad_alloc();
  }
  return result;
};
