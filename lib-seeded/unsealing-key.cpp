#include "github-com-nlohmann-json/json.hpp"
#include "unsealing-key.hpp"
#include "crypto_box_seal_salted.h"
#include "derivation-options.hpp"
#include "convert.hpp"
#include "exceptions.hpp"

UnsealingKey::UnsealingKey(
    const SodiumBuffer _UnsealingKeyBytes,
    const std::vector<unsigned char> _SealingKeyBytes,
    const std::string _derivationOptionsJson
  ) :
    UnsealingKeyBytes(_UnsealingKeyBytes),
    SealingKeyBytes(_SealingKeyBytes),
    derivationOptionsJson(_derivationOptionsJson)
    {
    if (SealingKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidDerivationOptionValueException("Invalid public key size");
    }
    if (UnsealingKeyBytes.length != crypto_box_SECRETKEYBYTES) {
      throw InvalidDerivationOptionValueException("Invalid private key size for public/private key pair");
    }
  }

UnsealingKey::UnsealingKey(
  const SodiumBuffer &seedBuffer,
  const std::string& _derivationOptionsJson
) : derivationOptionsJson(_derivationOptionsJson), SealingKeyBytes(crypto_box_PUBLICKEYBYTES), UnsealingKeyBytes(crypto_box_SECRETKEYBYTES) {
  if (seedBuffer.length < crypto_box_SEEDBYTES){
    throw std::invalid_argument("Insufficient seed length");
  }
  crypto_box_seed_keypair((unsigned char *) SealingKeyBytes.data(), UnsealingKeyBytes.data, seedBuffer.data);
}

  UnsealingKey::UnsealingKey(
    const std::string& _seedString,
    const std::string& _derivationOptionsJson
  ) : UnsealingKey(
      DerivationOptions::deriveMasterSecret(_seedString, _derivationOptionsJson, DerivationOptionsJson::type::UnsealingKey, crypto_box_SEEDBYTES),
      _derivationOptionsJson
  ) {}

UnsealingKey::UnsealingKey(
  const UnsealingKey &other
):
  SealingKeyBytes(other.SealingKeyBytes), 
  derivationOptionsJson(other.derivationOptionsJson),
  UnsealingKeyBytes(other.UnsealingKeyBytes)
  {}

const SodiumBuffer UnsealingKey::unseal(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string& postDecryptionInstructions
) const {
  if (ciphertextLength <= crypto_box_SEALBYTES) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: Invalid message length");
  }
  SodiumBuffer plaintext(ciphertextLength -crypto_box_SEALBYTES);

  const int result = crypto_box_salted_seal_open(
    plaintext.data,
    ciphertext,
    ciphertextLength,
    SealingKeyBytes.data(),
    UnsealingKeyBytes.data,
    postDecryptionInstructions.c_str(),
    postDecryptionInstructions.length()
  );
  if (result != 0) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: the private key doesn't match the public key used to seal the message, the post-decryption instructions do not match those used to seal the message, or the ciphertext was modified/corrupted.");
  }
  return plaintext;
}

const SodiumBuffer UnsealingKey::unseal(
  const std::vector<unsigned char> &ciphertext,
  const std::string& postDecryptionInstructions
) const {
  return unseal(ciphertext.data(), ciphertext.size(), postDecryptionInstructions
  );
};

const SodiumBuffer UnsealingKey::unseal(
  const PackagedSealedMessage &packagedSealedMessage
) const {
  return unseal(packagedSealedMessage.ciphertext, packagedSealedMessage.postDecryptionInstructions);
}

const SealingKey UnsealingKey::getSealingKey() const {
  return SealingKey(SealingKeyBytes, derivationOptionsJson);
}


/////
//  JSON
////
namespace UnsealingKeyJsonField {
  const std::string SealingKeyBytes = "SealingKeyBytes";
  const std::string UnsealingKeyBytes = "UnsealingKeyBytes";
  const std::string derivationOptionsJson = "derivationOptionsJson";
}

UnsealingKey UnsealingKey::fromJson(
  const std::string& UnsealingKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(UnsealingKeyAsJson);
    return UnsealingKey(
      SodiumBuffer::fromHexString(jsonObject.at(UnsealingKeyJsonField::UnsealingKeyBytes)),
      hexStrToByteVector(jsonObject.at(UnsealingKeyJsonField::SealingKeyBytes)),
      jsonObject.value(UnsealingKeyJsonField::derivationOptionsJson, ""));
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string UnsealingKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[UnsealingKeyJsonField::UnsealingKeyBytes] = UnsealingKeyBytes.toHexString();
  asJson[UnsealingKeyJsonField::SealingKeyBytes] = toHexStr(SealingKeyBytes);
  asJson[UnsealingKeyJsonField::derivationOptionsJson] = derivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const SodiumBuffer UnsealingKey::toSerializedBinaryForm() const {
  SodiumBuffer derivationOptionsJsonBuffer = SodiumBuffer(derivationOptionsJson);
  SodiumBuffer _SealingKeyBytes(SealingKeyBytes);
  SodiumBuffer _derivationOptionsJson(derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &UnsealingKeyBytes,
    &_SealingKeyBytes,
    &_derivationOptionsJson
  });
}

UnsealingKey UnsealingKey::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return UnsealingKey(fields[0], fields[1].toVector(), fields[2].toUtf8String());
}
