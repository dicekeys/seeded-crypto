#pragma once

#include "sodium-buffer.hpp"
#include "signature-verification-key.hpp"

class SigningKey {
protected:
  std::vector<unsigned char> signatureVerificationKeyBytes;

public:
  const SodiumBuffer signingKeyBytes;
  const std::string keyDerivationOptionsJson;

  SigningKey(
    const SigningKey& other
  );

  SigningKey(
    const SodiumBuffer &signingKey,
    const std::string &KeyDerivationOptionsJson
  );

  SigningKey(
    const SodiumBuffer &signingKey,
    const std::vector<unsigned char> &signatureVerificationKey,
    const std::string &keyDerivationOptionsJson
  );

  SigningKey(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  SigningKey(
    const std::string& signingKeyAsJson
  );

  const std::vector<unsigned char> getSignatureVerificationKeyBytes();

  const SignatureVerificationKey getSignatureVerificationKey();

  const std::vector<unsigned char> generateSignature(
    const unsigned char* message,
    const size_t messageLength
  ) const;

  const std::vector<unsigned char> generateSignature(
    const std::vector<unsigned char> &message
  ) const;

  const std::string toJson(
    bool minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater = true,
    int indent = -1,
    const char indent_char = ' '
  ) const;


};
