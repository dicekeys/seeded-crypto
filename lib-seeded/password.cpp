#include "password.hpp"
#include "derivation-options.hpp"
#include "exceptions.hpp"
#include "word-lists.hpp"
#include <algorithm>    // std::min
#include <sstream> 

Password::Password(
  const SodiumBuffer& _secretBytes,
  const std::string& _derivationOptionsJson
) : secretBytes(_secretBytes), derivationOptionsJson(_derivationOptionsJson) {}

Password::Password(
  const std::string& seedString,
  const std::string& _derivationOptionsJson
) : secretBytes(
  DerivationOptions::derivePrimarySecret(
    seedString,
    _derivationOptionsJson,
    DerivationOptionsJson::type::Password
  )), derivationOptionsJson(_derivationOptionsJson) {}

Password Password::deriveFromSeed(
  const std::string& seedString,
  const std::string& derivationOptionsJson
) {
  return Password(
    DerivationOptions::derivePrimarySecret(
      seedString,
      derivationOptionsJson,
      DerivationOptionsJson::type::Password
    ),
    derivationOptionsJson
  );
}

Password::Password(const Password &other) : Password(other.secretBytes, other.derivationOptionsJson) {}

// JSON field names
namespace PasswordJsonFields {
  static const std::string secretBytes = "secretBytes";
  static const std::string derivationOptionsJson = "derivationOptionsJson";
}

Password Password::fromJson(const std::string& secretAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(secretAsJson);
    auto kdo = jsonObject.value<std::string>(PasswordJsonFields::derivationOptionsJson, "");
    return Password(
      SodiumBuffer::fromHexString(jsonObject.at(PasswordJsonFields::secretBytes)),
      jsonObject.value<std::string>(PasswordJsonFields::derivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string
Password::toJson(
  int indent,
const char indent_char
) const {
  nlohmann::json asJson;
  asJson[PasswordJsonFields::secretBytes] = secretBytes.toHexString();
  if (derivationOptionsJson.size() > 0) {
    asJson[PasswordJsonFields::derivationOptionsJson] = derivationOptionsJson;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Password::toSerializedBinaryForm() const {
  SodiumBuffer _derivationOptionsJson(derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &secretBytes,
    &_derivationOptionsJson
  });
}

Password Password::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Password(fields[0], fields[1].toUtf8String());
}

// add format
const std::string Password::password() const {
  const char* const delim = "-";

  const auto strings = asWordVector();
  std::ostringstream joined;
  joined << strings.size();
  for (std::string word : strings) {
    // Ascii uppercase the first character of the word
    const char firstCharUppercase = word[0] + ('A' - 'a');
    joined << "-" << firstCharUppercase << word.substr(1);
  }
  return joined.str();
}

const std::vector<std::string> Password::asWordVector() const {
  std::vector<std::string> wordsGenerated;

  const auto derivationOptions = new DerivationOptions(
    derivationOptionsJson,
    DerivationOptionsJson::type::Password
  );

  const auto wordList = getWordList(derivationOptions->wordList);

  // FUTURE -- this code needs to be fixed if we're ever using word lists that are not powers of 2.
  // Likely use a BIGINT library for those cases (and, to maintain backwards compat, only those cases)
  // const unsigned int bitsPerWord =
  //   derivationOptions->wordList == DerivationOptionsJson::WordList::EN_512_words_5_chars_max_ed_4_20200917 ? 9 :
  //   derivationOptions->wordList == DerivationOptionsJson::WordList::EN_1024_words_6_chars_max_ed_4_20200917 ? 10 : 9;

  unsigned int wordsNeeded = derivationOptions->lengthInWords;
  unsigned int bytesConsumed = 0;
  unsigned char currentByte = 0;
  unsigned int bitsLeftInByte = 0;
//  unsigned int bitsNeededForIndexIntoWordList = bitsPerWord;
  unsigned int indexIntoWordList = 0;

  for (size_t byteIndexOfSecret = 0; byteIndexOfSecret < secretBytes.length; byteIndexOfSecret += BytesPerWordOfPassword) {
    uint64_t hashBytesAsBigEndianNumber = 0;
    // read 64 bit unsigned in big endian format
    for (size_t byteIndexOfULong = 0; byteIndexOfULong < BytesPerWordOfPassword; byteIndexOfULong++) {
      hashBytesAsBigEndianNumber |=
        ((uint64_t) secretBytes.data[byteIndexOfSecret + byteIndexOfULong])
        << (BytesPerWordOfPassword * (BytesPerWordOfPassword - (1 +  byteIndexOfULong)));
    }
    wordsGenerated.push_back(wordList[hashBytesAsBigEndianNumber % wordList.size()]);
  }
  return wordsGenerated;
}

