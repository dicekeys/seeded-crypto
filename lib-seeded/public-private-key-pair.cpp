#include "public-private-key-pair.hpp"
#include "crypto_box_seal_salted.h"
#include "key-derivation-options.hpp"
#include "generate-seed.hpp"

PublicPrivateKeyPair::PublicPrivateKeyPair(
    const SodiumBuffer _secretKey,
    const std::vector<unsigned char> _publicKeyBytes,
    const std::string _keyDerivationOptionsJson
  ) :
    secretKey(_secretKey),
    publicKeyBytes(_publicKeyBytes),
    keyDerivationOptionsJson(_keyDerivationOptionsJson)
    {}


PublicPrivateKeyPair::PublicPrivateKeyPair(
  const SodiumBuffer &seedBuffer,
  const std::string &_keyDerivationOptionsJson
) : keyDerivationOptionsJson(_keyDerivationOptionsJson), publicKeyBytes(crypto_box_PUBLICKEYBYTES), secretKey(crypto_box_SECRETKEYBYTES) {
  if (seedBuffer.length < crypto_box_SEEDBYTES){
    throw std::invalid_argument("Insufficient seed length");
  }
  crypto_box_seed_keypair((unsigned char *) publicKeyBytes.data(), secretKey.data, seedBuffer.data);
}

  PublicPrivateKeyPair::PublicPrivateKeyPair(
    const std::string& _seedString,
    const std::string& _keyDerivationOptionsJson
  ) : PublicPrivateKeyPair(
      generateSeed(_seedString, _keyDerivationOptionsJson, KeyDerivationOptionsJson::KeyType::Public, crypto_box_SEEDBYTES),
      _keyDerivationOptionsJson
  ) {}

PublicPrivateKeyPair::PublicPrivateKeyPair(
  const PublicPrivateKeyPair &other
):
  publicKeyBytes(other.publicKeyBytes), 
  keyDerivationOptionsJson(other.keyDerivationOptionsJson),
  secretKey(other.secretKey)
  {}

const SodiumBuffer PublicPrivateKeyPair::unseal(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string &postDecryptionInstructionsJson
) const {
  if (ciphertextLength <= crypto_box_SEALBYTES) {
    throw std::invalid_argument("Invalid message length");
  }
  SodiumBuffer plaintext(ciphertextLength -crypto_box_SEALBYTES);

  const int result = crypto_box_salted_seal_open(
    plaintext.data,
    ciphertext,
    ciphertextLength,
    publicKeyBytes.data(),
    secretKey.data,
    postDecryptionInstructionsJson.c_str(),
    postDecryptionInstructionsJson.length()
  );
  if (result != 0) {
    throw CryptographicVerificationFailure("Public/Private unseal failed: the private key doesn't match the public key used to seal the message, the post-decryption instructions do not match those used to seal the message, or the ciphertext was modified/corrupted.");
  }
  return plaintext;
}

const SodiumBuffer PublicPrivateKeyPair::unseal(
  const std::vector<unsigned char> &ciphertext,
  const std::string& postDecryptionInstructionsJson
) const {
  return unseal(ciphertext.data(), ciphertext.size(), postDecryptionInstructionsJson
  );
};

const PublicKey PublicPrivateKeyPair::getPublicKey() const {
  return PublicKey(publicKeyBytes, keyDerivationOptionsJson);
}