#include "github-com-nlohmann-json/json.hpp"
#include "private-key.hpp"
#include "crypto_box_seal_salted.h"
#include "key-derivation-options.hpp"
#include "generate-seed.hpp"
#include "convert.hpp"

PrivateKey::PrivateKey(
    const SodiumBuffer _privateKeyBytes,
    const std::vector<unsigned char> _publicKeyBytes,
    const std::string _keyDerivationOptionsJson
  ) :
    privateKeyBytes(_privateKeyBytes),
    publicKeyBytes(_publicKeyBytes),
    keyDerivationOptionsJson(_keyDerivationOptionsJson)
    {
    if (publicKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidKeyDerivationOptionValueException("Invalid public key size");
    }
    if (privateKeyBytes.length != crypto_box_SECRETKEYBYTES) {
      throw InvalidKeyDerivationOptionValueException("Invalid private key size for public/private key pair");
    }
  }

PrivateKey::PrivateKey(
  const SodiumBuffer &seedBuffer,
  const std::string &_keyDerivationOptionsJson
) : keyDerivationOptionsJson(_keyDerivationOptionsJson), publicKeyBytes(crypto_box_PUBLICKEYBYTES), privateKeyBytes(crypto_box_SECRETKEYBYTES) {
  if (seedBuffer.length < crypto_box_SEEDBYTES){
    throw std::invalid_argument("Insufficient seed length");
  }
  crypto_box_seed_keypair((unsigned char *) publicKeyBytes.data(), privateKeyBytes.data, seedBuffer.data);
}

  PrivateKey::PrivateKey(
    const std::string& _seedString,
    const std::string& _keyDerivationOptionsJson
  ) : PrivateKey(
      generateSeed(_seedString, _keyDerivationOptionsJson, KeyDerivationOptionsJson::KeyType::Public, crypto_box_SEEDBYTES),
      _keyDerivationOptionsJson
  ) {}

PrivateKey::PrivateKey(
  const PrivateKey &other
):
  publicKeyBytes(other.publicKeyBytes), 
  keyDerivationOptionsJson(other.keyDerivationOptionsJson),
  privateKeyBytes(other.privateKeyBytes)
  {}

const SodiumBuffer PrivateKey::unseal(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string &postDecryptionInstructionsJson
) const {
  if (ciphertextLength <= crypto_box_SEALBYTES) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: Invalid message length");
  }
  SodiumBuffer plaintext(ciphertextLength -crypto_box_SEALBYTES);

  const int result = crypto_box_salted_seal_open(
    plaintext.data,
    ciphertext,
    ciphertextLength,
    publicKeyBytes.data(),
    privateKeyBytes.data,
    postDecryptionInstructionsJson.c_str(),
    postDecryptionInstructionsJson.length()
  );
  if (result != 0) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: the private key doesn't match the public key used to seal the message, the post-decryption instructions do not match those used to seal the message, or the ciphertext was modified/corrupted.");
  }
  return plaintext;
}

const SodiumBuffer PrivateKey::unseal(
  const std::vector<unsigned char> &ciphertext,
  const std::string& postDecryptionInstructionsJson
) const {
  return unseal(ciphertext.data(), ciphertext.size(), postDecryptionInstructionsJson
  );
};

const PublicKey PrivateKey::getPublicKey() const {
  return PublicKey(publicKeyBytes, keyDerivationOptionsJson);
}


/////
//  JSON
////
namespace PrivateKeyJsonField {
  const std::string publicKeyBytes = "publicKeyBytes";
  const std::string privateKeyBytes = "privateKeyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

PrivateKey PrivateKey::fromJson(
  const std::string &PrivateKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(PrivateKeyAsJson);
    return PrivateKey(
      SodiumBuffer::fromHexString(jsonObject.at(PrivateKeyJsonField::privateKeyBytes)),
      hexStrToByteVector(jsonObject.at(PrivateKeyJsonField::publicKeyBytes)),
      jsonObject.value(PrivateKeyJsonField::keyDerivationOptionsJson, ""));
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

// PrivateKey::PrivateKey(const std::string &privateKeyAsJson) :
//   PrivateKey(constructPrivateKeyFromJson(privateKeyAsJson)) {}

const std::string PrivateKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[PrivateKeyJsonField::privateKeyBytes] = privateKeyBytes.toHexString();
  asJson[PrivateKeyJsonField::publicKeyBytes] = toHexStr(publicKeyBytes);
  asJson[PrivateKeyJsonField::keyDerivationOptionsJson] = keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const SodiumBuffer PrivateKey::toSerializedBinaryForm() const {
  SodiumBuffer keyDerivationOptionsJsonBuffer = SodiumBuffer(keyDerivationOptionsJson);
  SodiumBuffer _publicKeyBytes(publicKeyBytes);
  SodiumBuffer _keyDerivationOptionsJson(keyDerivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &privateKeyBytes,
    &_publicKeyBytes,
    &_keyDerivationOptionsJson
  });
}

PrivateKey PrivateKey::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return PrivateKey(fields[0], fields[1].toVector(), fields[2].toUtf8String());
}
