#include "signing-key.hpp"
#include "key-derivation-options.hpp"
#include "sodium-buffer.hpp"
#include "generate-seed.hpp"
#include "convert.hpp"

SigningKey::SigningKey(
  const SodiumBuffer& _signingKey,
  const std::string& _keyDerivationOptionsJson
) :
  keyDerivationOptionsJson(_keyDerivationOptionsJson),
  signingKeyBytes(_signingKey),
  signatureVerificationKeyBytes(0)
  {}

SigningKey::SigningKey(
  const SodiumBuffer &_signingKey,
  const std::vector<unsigned char> &_signatureVerificationKey,
  const std::string &_keyDerivationOptionsJson
) :
  keyDerivationOptionsJson(_keyDerivationOptionsJson),
  signingKeyBytes(_signingKey),
  signatureVerificationKeyBytes(_signatureVerificationKey) {
}

SigningKey::SigningKey(
  const SigningKey& other
) :
  keyDerivationOptionsJson(other.keyDerivationOptionsJson),
  signingKeyBytes(other.signingKeyBytes),
  signatureVerificationKeyBytes(other.signatureVerificationKeyBytes)
  {}


namespace SigningKeyJsonField {
  const std::string signatureVerificationKeyBytes = "signatureVerificationKeyBytes";
  const std::string signingKeyBytes = "signingKeyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

SigningKey constructSigningKeyFromJson(
  const std::string& signingKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(signingKeyAsJson);
    return SigningKey(
      SodiumBuffer::fromHexString(jsonObject.value(SigningKeyJsonField::signingKeyBytes, "")),
      hexStrToByteVector(jsonObject.value(SigningKeyJsonField::signatureVerificationKeyBytes, "")),
      jsonObject.value(SigningKeyJsonField::keyDerivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }

}

SigningKey::SigningKey(
  const std::string& signingKeyAsJson
) : SigningKey( constructSigningKeyFromJson(signingKeyAsJson)) {}

SigningKey::SigningKey(
  const std::string& seedString,
  const std::string& _keyDerivationOptionsJson
) :
  signingKeyBytes(crypto_sign_SECRETKEYBYTES),
  signatureVerificationKeyBytes(crypto_sign_PUBLICKEYBYTES),
  keyDerivationOptionsJson(_keyDerivationOptionsJson)
{
  // Turn the seed string into a seed of the appropriate length
  SodiumBuffer seed = generateSeed(
    seedString,
    keyDerivationOptionsJson,
    KeyDerivationOptionsJson::KeyType::Signing,
    crypto_sign_SEEDBYTES
  );
  // We're not going to keep the signature-verification key, but the sodium API requires we provide a buffer for it.
  crypto_sign_seed_keypair(signatureVerificationKeyBytes.data(), signingKeyBytes.data, seed.data);
}


const std::vector<unsigned char> SigningKey::getSignatureVerificationKeyBytes() {
  if (signatureVerificationKeyBytes.size() == 0) {
    signatureVerificationKeyBytes.resize(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_ed25519_sk_to_pk(signatureVerificationKeyBytes.data(), signingKeyBytes.data);
  }
  return signatureVerificationKeyBytes;
}

const SignatureVerificationKey SigningKey::getSignatureVerificationKey() const {
  std::vector<unsigned char> pk(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(pk.data(), signingKeyBytes.data);
  return SignatureVerificationKey(pk, keyDerivationOptionsJson);
}


const std::vector<unsigned char> SigningKey::generateSignature(
  const unsigned char* message,
  const size_t messageLength
) const {
  std::vector<unsigned char> signature(crypto_sign_BYTES);
  unsigned long long siglen_p;
  crypto_sign_detached(signature.data(), &siglen_p, message, messageLength, signingKeyBytes.data);
  return signature;
}

const std::vector<unsigned char> SigningKey::generateSignature(
  const std::vector<unsigned char>& message
) const {
  return generateSignature(message.data(), message.size());
}

const std::string SigningKey::toJson(
  bool minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater,
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SigningKeyJsonField::signingKeyBytes] = signingKeyBytes.toHexString();
  if (!minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater) {
    asJson[SigningKeyJsonField::signatureVerificationKeyBytes] =
      toHexStr(signatureVerificationKeyBytes);
  }
  asJson[SigningKeyJsonField::keyDerivationOptionsJson] = keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
};