#include "signing-key.hpp"
#include "key-derivation-options.hpp"
#include "sodium-buffer.hpp"
#include "generate-seed.hpp"

SigningKey::SigningKey(
  const SodiumBuffer& _signingKey,
  const std::string& _keyDerivationOptionsJson
) :
  keyDerivationOptionsJson(_keyDerivationOptionsJson),
  signingKey(_signingKey)
  {}

SigningKey::SigningKey(
  const SigningKey& other
) :
  keyDerivationOptionsJson(other.keyDerivationOptionsJson),
  signingKey(other.signingKey)
  {}

SigningKey::SigningKey(
  const std::string& seedString,
  const std::string& _keyDerivationOptionsJson
) : signingKey(crypto_sign_SECRETKEYBYTES), keyDerivationOptionsJson(_keyDerivationOptionsJson) {
  // Turn the seed string into a seed of the appropriate length
  SodiumBuffer seed = generateSeed(seedString, keyDerivationOptionsJson, KeyDerivationOptionsJson::KeyType::Signing, crypto_sign_SEEDBYTES);
  // We're not going to keep the signature-verification key, but the sodium API requires we provide a buffer for it.
  std::vector<unsigned char> signatureVerificationKeyBytes(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_seed_keypair(signatureVerificationKeyBytes.data(), signingKey.data, seed.data);
}

const SignatureVerificationKey SigningKey::getSignatureVerificationKey() const {
  std::vector<unsigned char> pk(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(pk.data(), signingKey.data);
  return SignatureVerificationKey(pk, keyDerivationOptionsJson);
}


const std::vector<unsigned char> SigningKey::generateSignature(
  const unsigned char* message,
  const size_t messageLength
) const {
  std::vector<unsigned char> signature(crypto_sign_BYTES);
  unsigned long long siglen_p;
  crypto_sign_detached(signature.data(), &siglen_p, message, messageLength, signingKey.data);
  return signature;
}

const std::vector<unsigned char> SigningKey::generateSignature(
  const std::vector<unsigned char>& message
) const {
  return generateSignature(message.data(), message.size());
}
