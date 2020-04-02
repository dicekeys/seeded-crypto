#pragma once

#include <vector>
#include <sodium.h>
#include "sodium-buffer.hpp"

class HashFunction {
	public:
	virtual ~HashFunction() {}

	virtual SodiumBuffer hash(
		const void* message,
		unsigned long long message_length,
		unsigned long long hash_length_in_bytes
	) const = 0;

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
