#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include "lib-seeded.hpp"
#include "../lib-seeded/convert.hpp"


const std::string orderedTestKey = "A1tB2rC3bD4lE5tF6bG1tH1tI1tJ1tK1tL1tM1tN1tO1tP1tR1tS1tT1tU1tV1tW1tX1tY1tZ1t";
std::string defaultTestPublicKeyDerivationOptionsJson = R"KGO({
	"keyType": "Public",
	"additionalSalt": "1"
})KGO";
std::string defaultTestSymmetricKeyDerivationOptionsJson = R"KGO({
	"keyType": "Symmetric",
	"additionalSalt": "1"
})KGO";
std::string defaultTestSigningKeyDerivationOptionsJson = R"KGO({
	"keyType": "Signing",
	"additionalSalt": "1"
})KGO";


TEST(Seed, FidoUseCase) {
	std::string kdo = R"KDO({
	"keyType": "Seed",
	"hashFunction": "Argon2id",
	"keyLengthInBytes": 96
})KDO";
	Seed seed(
		orderedTestKey,
		kdo
	);
	const std::string seedAsHex = toHexStr(seed.seedBytes.toVector());
	ASSERT_EQ(
		seedAsHex,
		"6a7c4bf1355de9689f1c7148c304eda43d5b92dabdf00d83b488ed1d3f054f55a7ff32bf05c2a8e030aa66780f983b989b29d376498a1100865c0ebc095c1982b3079645ad9329f80248a69880c74c9bf087ef39ccbbc0cd1cdf587f8a79c6a5"
	);
}

const std::string fastSeedJsonKeyDerivationOptions = R"KDO({
	"keyType": "Seed",
	"hashFunction": "SHA256",
	"keyLengthInBytes": 96
})KDO";
TEST(Seed, ConvertsToJsonAndBack) {
	Seed seed(orderedTestKey, fastSeedJsonKeyDerivationOptions);
	
	const auto serialized = seed.toJson(1, '\t');
	const auto replica = Seed(serialized);
	ASSERT_EQ(replica.keyDerivationOptionsJson, seed.keyDerivationOptionsJson);
	ASSERT_STREQ(replica.seedBytes.toHexString().c_str(), seed.seedBytes.toHexString().c_str());
}

TEST(Seed, ConvertsToSerializedFormAndBack) {
	Seed seed(orderedTestKey, fastSeedJsonKeyDerivationOptions);
	
	const auto serialized = seed.toSerializedBinaryForm();
	const auto replica = Seed::fromSerializedBinaryForm(serialized);
	ASSERT_EQ(replica.keyDerivationOptionsJson, seed.keyDerivationOptionsJson);
	ASSERT_STREQ(replica.seedBytes.toHexString().c_str(), seed.seedBytes.toHexString().c_str());
}

TEST(Seed, fromJsonWithoutKeyDerivationOptions) {
	Seed seed(R"JSON({
	"seedBytes": "0xffFE"
})JSON");

	ASSERT_EQ(seed.seedBytes.length, 2);
	ASSERT_EQ(seed.seedBytes.data[0], 0xff);
	ASSERT_EQ(seed.seedBytes.data[1], 0xfe);
	ASSERT_EQ(seed.keyDerivationOptionsJson.length(), 0);
}


TEST(PostDecryptionInstructions, ThowsOnInvalidJson) {
	ASSERT_ANY_THROW(
		PostDecryptionInstructions("badjson")
	);
}

TEST(PostDecryptionInstructions, Handles0LengthJsonObject) {
	ASSERT_STREQ(
		PostDecryptionInstructions("").userMustAcknowledgeThisMessage.c_str(),
		""
	);
}

TEST(PostDecryptionInstructions, HandlesEmptyJsonObject) {
	ASSERT_STREQ(
		PostDecryptionInstructions("{}").userMustAcknowledgeThisMessage.c_str(),
		""
	);
}

TEST(PublicKey, GetsPublicKey) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);
	const PublicKey testPublicKey = testPrivateKey.getPublicKey();

	ASSERT_EQ(testPublicKey.getPublicKeyBytes().size(), 32);
}

TEST(PublicKey, GetsPublicKeyFromEmptyOptions) {
	const PrivateKey testPrivateKey(orderedTestKey, "{}");
	const PublicKey testPublicKey = testPrivateKey.getPublicKey();

	ASSERT_EQ(toHexStr(testPublicKey.getPublicKeyBytes()).length(), 64);
}


TEST(PrivateKey, ConvertsToJsonAndBack) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);

	const std::string json = testPrivateKey.toJson(1, '\t');
	const PrivateKey replica(json);
	ASSERT_EQ(replica.keyDerivationOptionsJson, defaultTestPublicKeyDerivationOptionsJson);
	ASSERT_EQ(toHexStr(replica.publicKeyBytes), toHexStr(testPrivateKey.publicKeyBytes));
	ASSERT_EQ(replica.privateKeyBytes.toHexString(), testPrivateKey.privateKeyBytes.toHexString());
}


TEST(PrivateKey, ConvertsToSerializedFormAndBack) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);

	auto serialized = testPrivateKey.toSerializedBinaryForm();
	const PrivateKey replica = PrivateKey::fromSerializedBinaryForm(serialized);
	ASSERT_EQ(replica.keyDerivationOptionsJson, defaultTestPublicKeyDerivationOptionsJson);
	ASSERT_EQ(toHexStr(replica.publicKeyBytes), toHexStr(testPrivateKey.publicKeyBytes));
	ASSERT_EQ(replica.privateKeyBytes.toHexString(), testPrivateKey.privateKeyBytes.toHexString());
}



TEST(PublicKey, ConvertsToJsonAndBack) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);
	const PublicKey testPublicKey = testPrivateKey.getPublicKey();
	
	const std::string json = testPublicKey.toJson(1, '\t');
	const PublicKey replica(json);
	ASSERT_EQ(replica.getKeyDerivationOptionsJson(), defaultTestPublicKeyDerivationOptionsJson);
	ASSERT_EQ(toHexStr(replica.getPublicKeyBytes()), toHexStr(testPublicKey.getPublicKeyBytes()));
}


TEST(PublicKey, ConvertsToSerializedFormAndBack) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);
	const PublicKey testPublicKey = testPrivateKey.getPublicKey();
	
	const auto serialized = testPublicKey.toSerializedBinaryForm();
	const PublicKey replica = PublicKey::fromSerializedBinaryForm(serialized);
	ASSERT_EQ(replica.getKeyDerivationOptionsJson(), defaultTestPublicKeyDerivationOptionsJson);
	ASSERT_EQ(toHexStr(replica.getPublicKeyBytes()), toHexStr(testPublicKey.getPublicKeyBytes()));
}


TEST(PublicKey, EncryptsAndDecrypts) {
	const PrivateKey testPrivateKey(orderedTestKey, defaultTestPublicKeyDerivationOptionsJson);
	const PublicKey testPublicKey = testPrivateKey.getPublicKey();

	const std::vector<unsigned char> messageVector = { 'y', 'o', 't', 'o' };
	const std::string postDecryptionInstructionsJson = "{}";
	SodiumBuffer messageBuffer(messageVector);
	const auto sealedMessage = testPublicKey.seal(messageBuffer, postDecryptionInstructionsJson);
	const auto unsealedMessage = testPrivateKey.unseal(sealedMessage, postDecryptionInstructionsJson);
	const auto unsealedPlaintext = unsealedMessage.toVector();
	ASSERT_EQ(messageVector, unsealedPlaintext);
}


TEST(SigningKey, GetsSigningKey) {
	SigningKey testSigningKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);
	const SignatureVerificationKey testSignatureVerificationKey = testSigningKey.getSignatureVerificationKey();

	ASSERT_EQ(testSignatureVerificationKey.getKeyBytesAsHexDigits().length(), 64);
}

TEST(SigningKey, GetsSigningKeyFromEmptyOptions) {
	SigningKey testSigningKey(orderedTestKey, "{}");
	const SignatureVerificationKey testSignatureVerificationKey = testSigningKey.getSignatureVerificationKey();

	ASSERT_EQ(testSignatureVerificationKey.getKeyBytesAsHexDigits().length(), 64);
}

TEST(SigningKey, ConvertsToJsonAndBack) {
	SigningKey testKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);

	const std::string json = testKey.toJson(true, 1, '\t');
	SigningKey gpk2(json);
	ASSERT_EQ(gpk2.keyDerivationOptionsJson, defaultTestSigningKeyDerivationOptionsJson);
	ASSERT_STREQ(gpk2.signingKeyBytes.toHexString().c_str(), testKey.signingKeyBytes.toHexString().c_str());
	ASSERT_STREQ(toHexStr(gpk2.getSignatureVerificationKeyBytes()).c_str(), toHexStr(testKey.getSignatureVerificationKeyBytes()).c_str());
}


TEST(SigningKey, ConvertsToSerializedFormAndBack) {
	SigningKey testKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);

	auto comactSerializedBinaryForm = testKey.toSerializedBinaryForm(true);
	auto compactCopy = SigningKey::fromSerializedBinaryForm(comactSerializedBinaryForm);
	ASSERT_EQ(compactCopy.keyDerivationOptionsJson, testKey.keyDerivationOptionsJson);
	ASSERT_STREQ(toHexStr(compactCopy.getSignatureVerificationKeyBytes()).c_str(), toHexStr(testKey.getSignatureVerificationKeyBytes()).c_str());
	ASSERT_STREQ(compactCopy.signingKeyBytes.toHexString().c_str(), testKey.signingKeyBytes.toHexString().c_str());

	auto fullSerializedBinaryForm = testKey.toSerializedBinaryForm(false);
	auto fullCopy = SigningKey::fromSerializedBinaryForm(fullSerializedBinaryForm);
	ASSERT_EQ(fullCopy.keyDerivationOptionsJson, testKey.keyDerivationOptionsJson);
	ASSERT_STREQ(toHexStr(fullCopy.getSignatureVerificationKeyBytes()).c_str(), toHexStr(testKey.getSignatureVerificationKeyBytes()).c_str());
	ASSERT_STREQ(fullCopy.signingKeyBytes.toHexString().c_str(), testKey.signingKeyBytes.toHexString().c_str());

}

TEST(SignatureVerificationKey, ConvertsToJsonAndBack) {
	SigningKey testSigningKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);
	const SignatureVerificationKey testSignatureVerificationKey = testSigningKey.getSignatureVerificationKey();

	const std::string gpkJson = testSignatureVerificationKey.toJson(1, '\t');
	const SignatureVerificationKey gpk2(gpkJson);
	ASSERT_EQ(gpk2.getKeyDerivationOptionsJson(), defaultTestSigningKeyDerivationOptionsJson);
	ASSERT_STREQ(gpk2.getKeyBytesAsHexDigits().c_str(), testSignatureVerificationKey.getKeyBytesAsHexDigits().c_str());
}

TEST(SignatureVerificationKey, ConvertsToSerializedFormAndBack) {
	SigningKey testSigningKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);
	const SignatureVerificationKey testSignatureVerificationKey = testSigningKey.getSignatureVerificationKey();

	const auto serialized = testSignatureVerificationKey.toSerializedBinaryForm();
	const SignatureVerificationKey replica = SignatureVerificationKey::fromSerializedBinaryForm(serialized);
	ASSERT_EQ(replica.getKeyDerivationOptionsJson(), defaultTestSigningKeyDerivationOptionsJson);
	ASSERT_STREQ(replica.getKeyBytesAsHexDigits().c_str(), testSignatureVerificationKey.getKeyBytesAsHexDigits().c_str());
}

TEST(SigningKey, Verification) {
	SigningKey testSigningKey(orderedTestKey, defaultTestSigningKeyDerivationOptionsJson);
	const SignatureVerificationKey testSignatureVerificationKey = testSigningKey.getSignatureVerificationKey();

	const std::vector<unsigned char> messageVector = { 'y', 'o', 't', 'o' };
	const auto signature = testSigningKey.generateSignature(messageVector);
	const auto shouldVerifyAsTrue = testSignatureVerificationKey.verify(messageVector, signature);
	ASSERT_TRUE(shouldVerifyAsTrue);
	const std::vector<unsigned char> invalidMessageVector = { 'y', 'o', 'l', 'o' };
	const auto shouldVerifyAsFalse = testSignatureVerificationKey.verify(invalidMessageVector, signature);
	ASSERT_FALSE(shouldVerifyAsFalse);
}


TEST(SymmetricKey, EncryptsAndDecryptsWithoutPostDecryptionInstructions) {
	const SymmetricKey testSymmetricKey(orderedTestKey, defaultTestSymmetricKeyDerivationOptionsJson);

	const std::vector<unsigned char> messageVector = { 'y', 'o', 't', 'o' };
	const std::string postDecryptionInstructionsJson = {};
	SodiumBuffer messageBuffer(messageVector);
	const auto sealedMessage = testSymmetricKey.seal(messageBuffer);
	const auto unsealedMessage = testSymmetricKey.unseal(sealedMessage);
	const auto unsealedPlaintext = unsealedMessage.toVector();
	ASSERT_EQ(messageVector, unsealedPlaintext);
}



TEST(SymmetricKey, ConvertsToSerializedFormAndBack) {
	const SymmetricKey testKey(orderedTestKey, defaultTestSymmetricKeyDerivationOptionsJson);

	const auto serializedBinaryForm = testKey.toSerializedBinaryForm();
	const auto copy = SymmetricKey::fromSerializedBinaryForm(serializedBinaryForm);
	ASSERT_EQ(copy.keyDerivationOptionsJson, defaultTestSymmetricKeyDerivationOptionsJson);
	ASSERT_STREQ(copy.keyBytes.toHexString().c_str(), testKey.keyBytes.toHexString().c_str());
}

TEST(SymmetricKey, ConvertsToJsonAndBack) {
	const SymmetricKey testKey(orderedTestKey, defaultTestSymmetricKeyDerivationOptionsJson);

	const std::string json = testKey.toJson(1, '\t');
	const SymmetricKey gpk2(json);
	ASSERT_EQ(gpk2.keyDerivationOptionsJson, defaultTestSymmetricKeyDerivationOptionsJson);
	ASSERT_STREQ(gpk2.keyBytes.toHexString().c_str(), testKey.keyBytes.toHexString().c_str());
}

TEST(SymmetricKey, EncryptsAndDecrypts) {
	const SymmetricKey testSymmetricKey(orderedTestKey, defaultTestSymmetricKeyDerivationOptionsJson);

	const std::vector<unsigned char> messageVector = { 'y', 'o', 't', 'o' };
	const std::string postDecryptionInstructionsJson = "{\"userMustAcknowledgeThisMessage\": \"yoto mofo\"}";
	SodiumBuffer messageBuffer(messageVector);
	
	const auto sealedMessage = testSymmetricKey.seal(messageBuffer, postDecryptionInstructionsJson);
	const auto unsealedMessage = testSymmetricKey.unseal(sealedMessage, postDecryptionInstructionsJson);
	const std::vector<unsigned char> unsealedPlaintext = unsealedMessage.toVector();
	ASSERT_EQ(messageVector, unsealedPlaintext);
}


TEST(SymmetricKey, EncrypsUsingMessageAndDecrypts) {
	const SymmetricKey testSymmetricKey(orderedTestKey, defaultTestSymmetricKeyDerivationOptionsJson);
	
	const std::vector<unsigned char> messageVector = { 'y', 'o', 't', 'o' };
	const std::string postDecryptionInstructionsJson = "{\"userMustAcknowledgeThisMessage\": \"yoto mofo\"}";
	SodiumBuffer messageBuffer(messageVector);

	const auto sealedMessage = testSymmetricKey.seal(messageBuffer, postDecryptionInstructionsJson);
	const auto unsealedMessage = testSymmetricKey.unseal(sealedMessage, postDecryptionInstructionsJson);

	const std::vector<unsigned char> unsealedPlaintext = unsealedMessage.toVector();
	ASSERT_EQ(messageVector, unsealedPlaintext);
}

