#pragma once

#include "sodium-buffer.hpp"
#include "signature-verification-key.hpp"

class SigningKey {
protected:
  const SodiumBuffer signingKey;
  const std::string keyDerivationOptionsJson;

public:
  SigningKey(
    const SigningKey& other
  );

  SigningKey(
    const SodiumBuffer &signingKey,
    const std::string &KeyDerivationOptionsJson
  );

  SigningKey(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  const SignatureVerificationKey getSignatureVerificationKey() const;

  const std::vector<unsigned char> generateSignature(
    const unsigned char* message,
    const size_t messageLength
  ) const;

  const std::vector<unsigned char> generateSignature(
    const std::vector<unsigned char> &message
  ) const;

};
