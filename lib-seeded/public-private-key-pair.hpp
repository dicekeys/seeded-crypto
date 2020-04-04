#pragma once

#include "sodium-buffer.hpp"
#include "public-key.hpp"

class PublicPrivateKeyPair {
public:
  const SodiumBuffer secretKey;
  const std::vector<unsigned char> publicKeyBytes;
  const std::string keyDerivationOptionsJson;

  PublicPrivateKeyPair(
    const SodiumBuffer secretKey,
    const std::vector<unsigned char> publicKeyBytes,
    const std::string keyDerivationOptionsJson
  );

  PublicPrivateKeyPair(
    const SodiumBuffer& seedBuffer,
    const std::string& keyDerivationOptionsJson
  );

  PublicPrivateKeyPair(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  PublicPrivateKeyPair(const std::string &publicPrivateKeyPairAsJson);

  PublicPrivateKeyPair(
    const PublicPrivateKeyPair& other
  );

  const PublicKey getPublicKey() const;

  const SodiumBuffer unseal(
    const unsigned char* ciphertext,
    const size_t ciphertextLength,
    const std::string &postDecryptionInstructionsJson
  ) const;

  const SodiumBuffer unseal(
    const std::vector<unsigned char> &ciphertext,
    const std::string& postDecryptionInstructionsJson = ""
  ) const;

  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;

};
