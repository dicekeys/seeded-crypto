#include "github-com-nlohmann-json/json.hpp"
#include "signature-verification-key.hpp"
#include "exceptions.hpp"
#include "convert.hpp"
#include <stdexcept>

namespace SignatureVerificationKeyJsonFieldName {
  const std::string keyBytes = "keyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

SignatureVerificationKey::SignatureVerificationKey(
    const std::vector<unsigned char> &_verificationKeyBytes,
    const std::string &_keyDerivationOptionsJson
  ) : signatureVerificationKeyBytes(_verificationKeyBytes), keyDerivationOptionsJson(_keyDerivationOptionsJson) {
    if (signatureVerificationKeyBytes.size() != crypto_sign_PUBLICKEYBYTES) {
      throw std::invalid_argument("Invalid key size exception");
    }
  }

SignatureVerificationKey SignatureVerificationKey::fromJson(const std::string& signatureVerificationKeyAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(signatureVerificationKeyAsJson);
    return SignatureVerificationKey(
      hexStrToByteVector(jsonObject.value<std::string>(
        SignatureVerificationKeyJsonFieldName::keyBytes, "")),
      jsonObject.value<std::string>(
        SignatureVerificationKeyJsonFieldName::keyDerivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

// SignatureVerificationKey::SignatureVerificationKey(const std::string &verificationKeyAsJson) :
//  SignatureVerificationKey(createFrommJson(verificationKeyAsJson)) {}


const std::string SignatureVerificationKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SignatureVerificationKeyJsonFieldName::keyBytes] =
    toHexStr(getKeyBytes());
  asJson[SignatureVerificationKeyJsonFieldName::keyDerivationOptionsJson] =
    keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
}

const std::vector<unsigned char> SignatureVerificationKey::getKeyBytes(
) const {
  return signatureVerificationKeyBytes;
}

const std::string SignatureVerificationKey::getKeyBytesAsHexDigits(
) const {
  return toHexStr(signatureVerificationKeyBytes);
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
    throw KeyLengthException("Invalid signature-verification key size");
  }
  if (signatureLength != crypto_sign_BYTES) {
    return false;
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
  return verify(signatureVerificationKeyBytes, message, messageLength, signature);
}

bool SignatureVerificationKey::verify(
  const std::vector<unsigned char>& message,
  const std::vector<unsigned char>& signature
) const {
  return verify(signatureVerificationKeyBytes, message.data(), message.size(), signature);
}

bool SignatureVerificationKey::verify(
  const SodiumBuffer& message,
  const std::vector<unsigned char>& signature
) const {
  return verify(signatureVerificationKeyBytes, message.data, message.length, signature);
}


const SodiumBuffer SignatureVerificationKey::toSerializedBinaryForm() const {
  SodiumBuffer _signatureVerificationKeyBytes(signatureVerificationKeyBytes);
  SodiumBuffer _keyDerivationOptionsJson(keyDerivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &_signatureVerificationKeyBytes,
    &_keyDerivationOptionsJson
  });
}

SignatureVerificationKey SignatureVerificationKey::fromSerializedBinaryForm(
  SodiumBuffer serializedBinaryForm
) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return SignatureVerificationKey(
    fields[0].toVector(), fields[1].toUtf8String()
  );
}
