#pragma once

#include "public-key.hpp"

class PublicPrivateKeyPair {
protected:
  const SodiumBuffer secretKey;
  const std::vector<unsigned char> publicKeyBytes;
  const std::string keyDerivationOptionsJson;

public:
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

};
