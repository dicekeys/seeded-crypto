#pragma once

#include <vector>
#include <sodium.h>
#include "sodium-buffer.hpp"

/**
 * @brief An abstract hash function implementation used to derive keys
 * 
 * @ingroup BuildingBlocks
 */
class HashFunction {
	public:
	/**
	 * @brief Destroy the Hash Function object
	 * 
	 */
	virtual ~HashFunction() {}

	/**
	 * @brief The hash implementation
	 * 
	 * @param message The byte array to hash
	 * @param message_length The length of the byte array to hash
	 * @param hash_length_in_bytes The length of hash that should be generated
	 * @return SodiumBuffer 
	 */
	virtual SodiumBuffer hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const = 0;

	/**
	 * @brief The hash implementation
	 * 
	 * @param message The data to hash
	 * @param hash_length_in_bytes The length of hash that should be generated
	 * @return SodiumBuffer 
	 */
	SodiumBuffer hash(
		SodiumBuffer message,
		unsigned long long hash_length_in_bytes
	) const;

};

class FixedOutputLengthHashFunction: public HashFunction {
	public:
	const unsigned long long block_size_in_bytes;
	
	FixedOutputLengthHashFunction(unsigned long long _block_size_in_bytes) : block_size_in_bytes(_block_size_in_bytes) {}

	void virtual hash_block(
		void* output_ptr,
		const void* message,
		unsigned long long message_length
	) const = 0;

	 SodiumBuffer hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const;
};


class HashFunctionBlake2b : public FixedOutputLengthHashFunction {
public:
	HashFunctionBlake2b();

	void hash_block(
		void* hash_output,
		const void* message,
		unsigned long long message_length
	) const;
};

class HashFunctionSHA256 : public FixedOutputLengthHashFunction {
public:
	HashFunctionSHA256();
	
	void hash_block(
		void* hash_output,
		const void* message,
		unsigned long long message_length
	) const;
};

class MemoryHardHashFunction: public HashFunction {
	protected:
		unsigned long long opslimit;
		unsigned long long memlimit;

	MemoryHardHashFunction(
		unsigned long long _opslimit,
		unsigned long long _memlimit
	);
};


class HashFunctionArgon2id : public MemoryHardHashFunction {

public:
	HashFunctionArgon2id(
		unsigned long long _opslimit,
		unsigned long long _memlimit
	);

	SodiumBuffer hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const;
};

class HashFunctionScrypt : public MemoryHardHashFunction {
public:
	HashFunctionScrypt(
		unsigned long long _opslimit,
		unsigned long long _memlimit
	);
	
	SodiumBuffer hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const;
};
