#include "password.hpp"
#include "derivation-options.hpp"
#include "exceptions.hpp"
#include "./externally-generated/derivation-parameters.hpp"
#include "externally-generated/word-lists/EN_512_words_5_chars_max_ed_4_20200917.hpp"
#include "externally-generated/word-lists/EN_1024_words_6_chars_max_ed_4_20200917.hpp"
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

  const auto wordList =
    derivationOptions->wordList == DerivationOptionsJson::WordList::EN_512_words_5_chars_max_ed_4_20200917 ?
    EN_512_words_5_chars_max_ed_4_20200917 :
    derivationOptions->wordList == DerivationOptionsJson::WordList::EN_1024_words_6_chars_max_ed_4_20200917 ?
    EN_1024_words_6_chars_max_ed_4_20200917 :
    // default
    EN_512_words_5_chars_max_ed_4_20200917;

  const unsigned int bitsPerWord =
    derivationOptions->wordList == DerivationOptionsJson::WordList::EN_512_words_5_chars_max_ed_4_20200917 ? 9 :
    derivationOptions->wordList == DerivationOptionsJson::WordList::EN_1024_words_6_chars_max_ed_4_20200917 ? 10 : 9;

  unsigned int wordsNeeded = derivationOptions->lengthInWords;
  unsigned int bytesConsumed = 0;
  unsigned char currentByte = 0;
  unsigned int bitsLeftInByte = 0;
  unsigned int bitsNeededForIndexIntoWordList = bitsPerWord;
  unsigned int indexIntoWordList = 0;

  while (wordsNeeded > 0) {

    if (bitsLeftInByte == 0) {
      // We're out of bits to read from in the current byte
      // Fetch the next byte

      if (bytesConsumed >= secretBytes.length) {
        // We're out of bytes to fetch
        break;
      }
      // The byte we were copying over into words is empty. Grab another.
      currentByte = secretBytes.data[bytesConsumed++];
      bitsLeftInByte = 8;
    }
    const auto numBitsToCopy = std::min(bitsLeftInByte, bitsNeededForIndexIntoWordList);
    // If we're only copying part of the byte, copy high-order bits and
    // shift the remaining bits to the right.  (Shift any bits that
    const unsigned int bitsToCopy = (currentByte >> (bitsLeftInByte - numBitsToCopy));
    bitsLeftInByte -= numBitsToCopy;
    currentByte = currentByte & (0xff >> (8 - bitsLeftInByte));
    // shift any value already in the word index left of the bits to copy in
    // so that the numBitsToCopy bits on the right will be 0
    indexIntoWordList = (indexIntoWordList << numBitsToCopy);
    // Add the copied bits into the low-order bits of the word index.
    indexIntoWordList += bitsToCopy;
    // We now need that many fewer bits to complete the word index
    bitsNeededForIndexIntoWordList -= numBitsToCopy;
    // See if we've completed a word
    if (bitsNeededForIndexIntoWordList == 0) {
      // We've completed a word.  Push it onto the completed list of words
      wordsGenerated.push_back(wordList[indexIntoWordList]);
      wordsNeeded--;
      // Start a new word index, which is empty, needs bitsPerWordsBits
      indexIntoWordList = 0;
      bitsNeededForIndexIntoWordList = bitsPerWord;
    }
  }
  if (bitsNeededForIndexIntoWordList < bitsPerWord && wordsNeeded > 0) {
    // We were in the middle of generating a word when we ran out of bits.
    // We still had enough bits to add a word, so we'll use it.
    wordsGenerated.push_back(wordList[indexIntoWordList]);
  }

  return wordsGenerated;
}

