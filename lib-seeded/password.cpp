#include "password.hpp"
#include "derivation-options.hpp"
#include "exceptions.hpp"
#include "word-lists.hpp"
#include <algorithm>    // std::min
#include <sstream> 

const std::vector<std::string> parseOrGetWordList(
  const DerivationOptions& derivationOptions,
  const std::string& wordListAsSingleString
) {
  if (wordListAsSingleString.length() <= 2) {
    return getWordList(derivationOptions.wordList);
  }

  // Parse the word list
  std::vector<std::string> wordList;
  size_t wordStart = 0;
  while (wordStart < wordListAsSingleString.length()) {
    // Find the next word start by locating the next letter
    while (wordStart < wordListAsSingleString.length() && !isalpha(wordListAsSingleString[wordStart])) {
       wordStart++;
    }
    if (wordStart < wordListAsSingleString.length()) {
      size_t wordLength = 1;
      while (wordStart + wordLength < wordListAsSingleString.length() && isalpha(wordListAsSingleString[wordStart + wordLength])) {
        wordLength++;
      }
      wordList.push_back(wordListAsSingleString.substr(wordStart, wordLength));
      wordStart += wordLength;
    }
  }
  return wordList;
}


const std::vector<std::string> asWordVector(
  const DerivationOptions& derivationOptions,
  const SodiumBuffer& secretBytes,
  const std::string& wordListAsSingleString = ""
) {
  const std::vector<std::string> wordList = parseOrGetWordList(derivationOptions, wordListAsSingleString);
  std::vector<std::string> wordsGenerated;

  unsigned int wordsNeeded = derivationOptions.lengthInWords;
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


// add format
const std::string derivePassword(
  const DerivationOptions& derivationOptions,
  const SodiumBuffer& secretBytes,
  const std::string& wordListAsSingleString = ""
) {
  const char* const delim = "-";

  const std::vector<std::string> words = asWordVector(derivationOptions, secretBytes, wordListAsSingleString);

  std::ostringstream joined;
  joined << words.size();
  if (words.size() > 0)  {
    // capitalize the first word
    joined  << delim << std::string(1, toupper(words[0][0])) << words[0].substr(1);;
  }
  // Add the rest of the words.
  for (size_t wordIndex = 1; wordIndex < words.size(); wordIndex++) {
    joined << delim << words[wordIndex];
  }
  return joined.str();
}

const std::string derivePassword(
  const std::string& derivationOptionsJson,
  const std::string& seedString,
  const std::string& wordListAsSingleString = ""
) {
 const DerivationOptions derivationOptions(derivationOptionsJson, DerivationOptionsJson::type::Password);
 const SodiumBuffer secretBytes = derivationOptions.derivePrimarySecret(
    seedString,
    DerivationOptionsJson::type::Password
  );
  return derivePassword(derivationOptions, secretBytes, wordListAsSingleString);
}


Password::Password(
  const std::string& _password,
  const std::string& _derivationOptionsJson
) : password(_password), derivationOptionsJson(_derivationOptionsJson) {}

// Password::Password(
//   const std::string& seedString,
//   const std::string& _derivationOptionsJson,
//   const std::string& wordListAsSingleString
// ) : password(derivePassword(seedString, _derivationOptionsJson, wordListAsSingleString)),
//   derivationOptionsJson(_derivationOptionsJson) {}

Password Password::deriveFromSeed(
  const std::string& seedString,
  const std::string& derivationOptionsJson,
  const std::string& wordListAsSingleString
) {
  return Password(
    derivePassword(
      derivationOptionsJson,
      seedString,
      wordListAsSingleString
    ),
    derivationOptionsJson
  );
}

Password::Password(const Password &other) : Password(other.password, other.derivationOptionsJson) {}

// JSON field names
namespace PasswordJsonFields {
  static const std::string password = "password";
  static const std::string derivationOptionsJson = "derivationOptionsJson";
}

Password Password::fromJson(const std::string& secretAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(secretAsJson);
    auto kdo = jsonObject.value<std::string>(PasswordJsonFields::derivationOptionsJson, "");
    return Password(
      jsonObject.value<std::string>(PasswordJsonFields::password, ""),
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
  asJson[PasswordJsonFields::password] = this->password;
  if (derivationOptionsJson.size() > 0) {
    asJson[PasswordJsonFields::derivationOptionsJson] = derivationOptionsJson;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Password::toSerializedBinaryForm() const {
  SodiumBuffer _password(this->password);
  SodiumBuffer _derivationOptionsJson(this->derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &_password,
    &_derivationOptionsJson
  });
}

Password Password::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Password(fields[0].toUtf8String(), fields[1].toUtf8String());
}


