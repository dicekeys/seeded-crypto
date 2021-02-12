#include "signing-key.hpp"
#include "derivation-options.hpp"
#include "sodium-buffer.hpp"
#include "convert.hpp"
#include "exceptions.hpp"

SigningKey::SigningKey(
  const SodiumBuffer& _signingKeyBytes,
  const std::string& _derivationOptionsJson
) :
  derivationOptionsJson(_derivationOptionsJson),
  signingKeyBytes(_signingKeyBytes),
  signatureVerificationKeyBytes(0)
{
  if (signatureVerificationKeyBytes.size() > 0 &&
      signatureVerificationKeyBytes.size() != crypto_sign_PUBLICKEYBYTES
  ) {
    throw InvalidDerivationOptionValueException("Invalid signature-verification key size");
  }
  if (signingKeyBytes.length != crypto_sign_SECRETKEYBYTES) {
    throw InvalidDerivationOptionValueException("Invalid signing key size");
  }
}

SigningKey::SigningKey(
  const SodiumBuffer &_signingKey,
  const std::vector<unsigned char> &_signatureVerificationKey,
  const std::string& _derivationOptionsJson
) :
  derivationOptionsJson(_derivationOptionsJson),
  signingKeyBytes(_signingKey),
  signatureVerificationKeyBytes(_signatureVerificationKey) {
}

SigningKey::SigningKey(
  const SigningKey& other
) :
  derivationOptionsJson(other.derivationOptionsJson),
  signingKeyBytes(other.signingKeyBytes),
  signatureVerificationKeyBytes(other.signatureVerificationKeyBytes)
  {}


namespace SigningKeyJsonField {
  const std::string signatureVerificationKeyBytes = "signatureVerificationKeyBytes";
  const std::string signingKeyBytes = "signingKeyBytes";
  const std::string derivationOptionsJson = "recipeJson";
}

SigningKey SigningKey::fromJson(
  const std::string& signingKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(signingKeyAsJson);
    return SigningKey(
      SodiumBuffer::fromHexString(jsonObject.at(SigningKeyJsonField::signingKeyBytes)),
      hexStrToByteVector(jsonObject.value(SigningKeyJsonField::signatureVerificationKeyBytes, "")),
      jsonObject.value(SigningKeyJsonField::derivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }

}

SigningKey::SigningKey(
  const std::string& _seedString,
  const std::string& _derivationOptionsJson
) : SigningKey(deriveFromSeed(_seedString, _derivationOptionsJson)) {}


SigningKey SigningKey::deriveFromSeed(
  const std::string& _seedString,
  const std::string& _derivationOptionsJson
) {
  // Turn the seed string into a seed of the appropriate length
  SodiumBuffer seed = DerivationOptions::derivePrimarySecret(
    _seedString,
    _derivationOptionsJson,
    DerivationOptionsJson::type::SigningKey,
    crypto_sign_SEEDBYTES
  );
  // Dervive a key pair from the seed
  SodiumBuffer signingKeyBytes(crypto_sign_SECRETKEYBYTES);
  std::vector<unsigned char> signatureVerificationKeyBytes(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_seed_keypair(signatureVerificationKeyBytes.data(), signingKeyBytes.data, seed.data);
  return SigningKey(signingKeyBytes, signatureVerificationKeyBytes, _derivationOptionsJson);
}



const std::vector<unsigned char> SigningKey::getSignatureVerificationKeyBytes() {
  if (signatureVerificationKeyBytes.size() == 0) {
    signatureVerificationKeyBytes.resize(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_ed25519_sk_to_pk(signatureVerificationKeyBytes.data(), signingKeyBytes.data);
  }
  return signatureVerificationKeyBytes;
}

const SignatureVerificationKey SigningKey::getSignatureVerificationKey() {
  return SignatureVerificationKey(getSignatureVerificationKeyBytes(), derivationOptionsJson);
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
  if (signatureVerificationKeyBytes.size() > 0 &&
      !minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater) {
    asJson[SigningKeyJsonField::signatureVerificationKeyBytes] =
      toHexStr(signatureVerificationKeyBytes);
  }
  asJson[SigningKeyJsonField::derivationOptionsJson] = derivationOptionsJson;
  return asJson.dump(indent, indent_char);
};

const SodiumBuffer SigningKey::toSerializedBinaryForm(
  bool minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater
) const {
  SodiumBuffer _signatureVerificationKeyBytes(signatureVerificationKeyBytes);
  SodiumBuffer _derivationOptionsJson(derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &signingKeyBytes,
    minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater ?
    NULL : &_signatureVerificationKeyBytes,
    &_derivationOptionsJson
  });
}

SigningKey SigningKey::fromSerializedBinaryForm(
  const SodiumBuffer &serializedBinaryForm
) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return SigningKey(
    fields[0], fields[1].toVector(), fields[2].toUtf8String()
  );
}

