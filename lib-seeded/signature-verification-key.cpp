#include "github-com-nlohmann-json/json.hpp"
#include "signature-verification-key.hpp"
#include "exceptions.hpp"
#include "convert.hpp"
#include <stdexcept>

namespace SignatureVerificationKeyJsonFieldName {
  const std::string verificationKeyBytesAsHexDigits = "keyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

SignatureVerificationKey::SignatureVerificationKey(
    const std::vector<unsigned char> &_verificationKeyBytes,
    const std::string &_keyDerivationOptionsJson
  ) : verificationKeyBytes(_verificationKeyBytes), keyDerivationOptionsJson(_keyDerivationOptionsJson) {
    if (verificationKeyBytes.size() != crypto_sign_PUBLICKEYBYTES) {
      throw std::invalid_argument("Invalid key size exception");
    }
  }

SignatureVerificationKey createFrommJson(const std::string& signatureVerificationKeyAsJson) {
  try {
     nlohmann::json jsonObject = nlohmann::json::parse(signatureVerificationKeyAsJson);
     const std::string verificationKeyBytesAsHexDigits = jsonObject.value<std::string>(
       SignatureVerificationKeyJsonFieldName::verificationKeyBytesAsHexDigits, "");
     const std::vector<unsigned char> verificationKeyBytes = hexStrToByteVector(verificationKeyBytesAsHexDigits);
     const std::string keyDerivationOptionsJson = jsonObject.value<std::string>(
       SignatureVerificationKeyJsonFieldName::keyDerivationOptionsJson, ""
       );
     return SignatureVerificationKey(verificationKeyBytes, keyDerivationOptionsJson);
  } catch (std::exception e) {
    throw JsonParsingException(e.what());
  }
}

SignatureVerificationKey::SignatureVerificationKey(const std::string &verificationKeyAsJson) :
 SignatureVerificationKey(createFrommJson(verificationKeyAsJson)) {}


const std::string SignatureVerificationKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SignatureVerificationKeyJsonFieldName::verificationKeyBytesAsHexDigits] =
    getKeyBytesAsHexDigits();
  asJson[SignatureVerificationKeyJsonFieldName::keyDerivationOptionsJson] =
    keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
}

const std::vector<unsigned char> SignatureVerificationKey::getKeyBytes(
) const {
  return verificationKeyBytes;
}

const std::string SignatureVerificationKey::getKeyBytesAsHexDigits(
) const {
  return toHexStr(verificationKeyBytes);
}

bool SignatureVerificationKey::verify(
  const unsigned char* signatureVerificationKey,
  const unsigned char* message,
  const size_t messageLength,
  const unsigned char* signature
) {
  return crypto_sign_verify_detached(signature, message, messageLength, signatureVerificationKey) == 0;
}

bool SignatureVerificationKey::verify(
  const unsigned char* signatureVerificationKey,
  const size_t signatureVerificationKeyLength,
  const unsigned char* message,
  const size_t messageLength,
  const unsigned char* signature,
  const size_t signatureLength
) {
  if (signatureVerificationKeyLength != crypto_sign_PUBLICKEYBYTES) {
    throw std::invalid_argument("Invalid signature-verification key size");
  }
  if (signatureLength != crypto_sign_BYTES) {
    throw std::invalid_argument("Invalid signature size");
  }
  return crypto_sign_verify_detached(signature, message, messageLength, signatureVerificationKey) == 0;
}

bool SignatureVerificationKey::verify(
  const std::vector<unsigned char>& signatureVerificationKey,
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char>& signature
) {
  return verify(
    signatureVerificationKey.data(), signatureVerificationKey.size(),
    message, messageLength,
    signature.data(), signature.size()
  );
}

bool SignatureVerificationKey::verify(
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char>& signature
) const {
  return verify(verificationKeyBytes, message, messageLength, signature);
}

bool SignatureVerificationKey::verify(
  const std::vector<unsigned char>& message,
  const std::vector<unsigned char>& signature
) const {
  return verify(verificationKeyBytes, message.data(), message.size(), signature);
}

bool SignatureVerificationKey::verify(
  const SodiumBuffer& message,
  const std::vector<unsigned char>& signature
) const {
  return verify(verificationKeyBytes, message.data, message.length, signature);
}