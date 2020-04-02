#pragma once

#include <cassert>
#include <sodium.h>
#include <vector>
#include <string>

#include "sodium-buffer.hpp"

class SignatureVerificationKey {
public:
  const std::vector<unsigned char> verificationKeyBytes;
  const std::string keyDerivationOptionsJson;
 
  SignatureVerificationKey(
    const std::vector<unsigned char> &keyBytes,
    const std::string &keyDerivationOptionsJson
  );

  SignatureVerificationKey(const std::string &keyAsJson);

  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;


private:
  static bool verify(
    const unsigned char* signatureVerificationKey,
    const unsigned char* message,
    const size_t messageLength,
    const unsigned char* signature
  );

public:
  static bool verify(
    const unsigned char* signatureVerificationKey,
    const size_t signatureVerificationKeyLength,
    const unsigned char* message,
    const size_t messageLength,
    const unsigned char* signature,
    const size_t signatureLength
  );

  static bool verify(
    const std::vector<unsigned char>& signatureVerificationKey,
    const unsigned char* message,
    const size_t messageLength,
    const std::vector<unsigned char>& signature
  );

  bool verify(
    const unsigned char* message,
    const size_t messageLength,
    const std::vector<unsigned char>& signature
  ) const;

  bool verify(
    const std::vector<unsigned char>& message,
    const std::vector<unsigned char>& signature
  ) const;

  bool verify(
    const SodiumBuffer& message,
    const std::vector<unsigned char>& signature
  ) const;


  const std::vector<unsigned char> getKeyBytes() const;

  const std::string getKeyBytesAsHexDigits() const;

  const std::string getKeyDerivationOptionsJson() const {
    return keyDerivationOptionsJson; 
  }

  
  protected:
    static SignatureVerificationKey create(const std::string &signatureVerificationKeyAsJson);
};

