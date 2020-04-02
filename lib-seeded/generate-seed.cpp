#include "generate-seed.hpp"

// We call this function to generate and write the key into memory so that the
// class instance can treat the key as a constant.
const SodiumBuffer generateSeed(
  const std::string& seedString,
  const std::string& keyDerivationOptionsJson,
  const KeyDerivationOptionsJson::KeyType keyTypeRequired,
  const size_t keyLengthInBytesRequired
) {
  const KeyDerivationOptions keyDerivationOptions(keyDerivationOptionsJson, keyTypeRequired);
  // Ensure that the purpose in the key derivation options matches
  // the actual purpose
  if (
    keyTypeRequired != KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_ &&
    keyTypeRequired != keyDerivationOptions.keyType  
  ) {
    throw InvalidKeyDerivationOptionValueException( (
      "Key generation options must have keyType " + std::to_string(keyTypeRequired)
    ).c_str() );
  }

  size_t keyLengthInBytes = keyLengthInBytesRequired > 0 ?
    keyLengthInBytesRequired : keyDerivationOptions.keyLengthInBytes;
  if (keyLengthInBytes != keyDerivationOptions.keyLengthInBytes) {
    throw InvalidKeyDerivationOptionValueException( (
      "Key length in bytes for this keyType should be " + std::to_string(keyLengthInBytes) +
       " but keyLengthInBytes field was set to " + std::to_string(keyDerivationOptions.keyLengthInBytes)
      ).c_str()
    );
  }

  // Create a hash preimage that is the seed string, followed by a null
  // terminator, followed by the keyDerivationOptionsJson string.
  //   <seedString> + '\0' <keyDerivationOptionsJson>
  SodiumBuffer preimage(
    // length of the seed string
    seedString.length() +
    // 1 character for a null char between the two strings
    1 +
    // length of the json string specifying the key generation options
    keyDerivationOptions.keyDerivationOptionsJson.length()
  );

  // Copy the seed string into the preimage
  memcpy(
    preimage.data,
    seedString.c_str(),
    seedString.length()
  );
  // copy the null terminator between strings into the preimage
  preimage.data[seedString.length()] = '0';
  // copy the key derivation options into the preimage
  memcpy(
    preimage.data + seedString.length() + 1,
    keyDerivationOptions.keyDerivationOptionsJson.c_str(),
    keyDerivationOptions.keyDerivationOptionsJson.length()
  );

  // Hash the preimage to create the seed
  SodiumBuffer derivedKey =
    keyDerivationOptions.hashFunctionImplemenation->hash(
        preimage.data,
        preimage.length,
        keyLengthInBytes
    );

  return derivedKey;
}