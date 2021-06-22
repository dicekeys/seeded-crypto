#include "gtest/gtest.h"
#include <string>
#include "../lib-seeded/lib-seeded.hpp"
#include "../lib-seeded/convert.hpp"
#include "../lib-seeded/key-formats/OpenPgpPacket.hpp"
#include "../lib-seeded/key-formats/ByteBuffer.hpp"
#include "../lib-seeded/key-formats/UserPacket.hpp"
#include "../lib-seeded/key-formats/PublicKeyPacket.hpp"
#include "../lib-seeded/key-formats/SecretKeyPacket.hpp"
#include "../lib-seeded/key-formats/SignaturePacket.hpp"
#include "../lib-seeded/key-formats/OpenSshKey.hpp"
#include "../lib-seeded/key-formats/OpenPgpKey.hpp"
#include "../lib-seeded/key-formats/PEM.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#ifdef __APPLE__
namespace fs = std::__fs::filesystem;
#else
namespace fs = std::filesystem;
#endif



struct TestVector {
	ubyte version;
	std::string privateKeyHex;
	std::string publicKeyHex;
	uint32_t timestamp;

	std::string name;
	std::string email;

	std::string fingerprintHex;
	std::string publicPacketHex;
	std::string secretPacketHex;
	std::string userIdPacketHex;
	std::string signaturePacketHex;
};

std::vector<TestVector> testCases = {
	{
		VERSION_4,
		"58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF",
   	"71F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E8",
		0x60844560u,
		"DK_USER_1",
		"dkuser1@dicekeys.org",
		"FBE62AB5DC8C41B12C06F37E85B7A357B0E9FFD8",
		"9833046084456016092B06010401DA470F0101074071F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E8",
		"9458046084456016092B06010401DA470F0101074071F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E80000FF58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF135C",
		"B420444B5F555345525F31203C646B757365723140646963656B6579732E6F72673E",
		"8890041316080038162104FBE62AB5DC8C41B12C06F37E85B7A357B0E9FFD8050260844560021B01050B0908070206150A09080B020416020301021E01021780000A091085B7A357B0E9FFD865EB0100C5A77D28D9623C74B493A7A5E72ABF24F34C4E133DA85E314C6105B06A4E26AF0100A6EC13920C8023FC0444705D4F32A55B977EC147BE3B6B68F112601A52B6730A"
	}, {
		VERSION_4,
		"F741CC9AC284484A9282152E36CDEE239EBA572F5C258979C9657AA3F7E95EBC",
		"207E2C90C6F41BCC055CD939DF50575E9BD77F1BFAAD6F85BE1058FFB6AEDBDF",
		0x6084459bu,
		"DK_USER_2",
		"dkuser2____@dicekeys.com",
		"4F98C213FCBBBD97004A4473E99D26BEB59B3C9A",
		"9833046084459B16092B06010401DA470F01010740207E2C90C6F41BCC055CD939DF50575E9BD77F1BFAAD6F85BE1058FFB6AEDBDF",
		"9458046084459B16092B06010401DA470F01010740207E2C90C6F41BCC055CD939DF50575E9BD77F1BFAAD6F85BE1058FFB6AEDBDF000100F741CC9AC284484A9282152E36CDEE239EBA572F5C258979C9657AA3F7E95EBC1088",
		"B424444B5F555345525F32203C646B75736572325F5F5F5F40646963656B6579732E636F6D3E",
		"88900413160800381621044F98C213FCBBBD97004A4473E99D26BEB59B3C9A05026084459B021B01050B0908070206150A09080B020416020301021E01021780000A0910E99D26BEB59B3C9A485400FE298973EBB860EF016F581FAD2C80226C05056C3B6B6710B7AD20BE06DE22F7820100EE4FC5C1C204F897FACF9CF4973C052C7E703EE658F97C5CAEF99C09CE27E700"
	}
};


void wrapTest(const std::string& toEncode, const std::string& toCheckAgainstEncodedValue) {
	const auto encoded = wrapKeyAsMpiFormat(ByteBuffer::fromHex(toEncode));
	auto encodedHex = toUpper(encoded.toHex());
	ASSERT_STRCASEEQ(encodedHex.c_str(), toCheckAgainstEncodedValue.c_str());
}

TEST(KeyFormats, SignaturHashPreImage) {
	const auto& testCase = testCases[0];
	const auto publicKey = ByteBuffer::fromHex(testCase.publicKeyHex);
	const auto privateKeyBytes = ByteBuffer::fromHex(testCase.privateKeyHex);
	const UserPacket userPacket(testCase.name, testCase.email);
//	const auto userIdPacketBody = createUserPacketBody(createUserIdPacketContent(testCase.name, testCase.email));
	EdDsaKeyConfiguration configuration;
	configuration.version = testCase.version;
	configuration.preferredSymmetricAlgorithms = {9,8,7,2};
	configuration.preferredHashAlgorithms = {0x0a, 0x09, 0x08, 0x0b, 0x02};
	configuration.preferredCompressionAlgorithms = {2,3,1};

	const EdDsaPublicPacket publicPacket(publicKey, testCase.timestamp, configuration);
	const SecretKeyPacket secretPacket(publicPacket, privateKeyBytes, testCase.timestamp);

	const auto sk = SigningKey(SodiumBuffer(privateKeyBytes.byteVector), "");
	const SignaturePacket signaturePacket(sk, userPacket, secretPacket, publicPacket, testCase.timestamp);
//		ByteBuffer packetBody = createSignaturePacketBodyIncludedInHash(publicPacket.fingerprint, testCase.timestamp);

	// Calculate the SHA256-bit hash of the packet before appending the
	// unhashed subpackets (which, as the name implies, shouldn't be hashed).
	ASSERT_STRCASEEQ(toUpper(signaturePacket.signatureHashPreImage.toHex()).c_str(),
		"990033046084456016092B06010401DA470F0101074071F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E8B400000020444B5F555345525F31203C646B757365723140646963656B6579732E6F72673E041316080038162104FBE62AB5DC8C41B12C06F37E85B7A357B0E9FFD8050260844560021B01050B0908070206150A09080B020416020301021E0102178004FF0000003E"
	);
}

TEST(KeyFormats, PacketFunctions) {
	for (const auto& testCase : testCases) {
		const auto privateKeyBytes = ByteBuffer::fromHex(testCase.privateKeyHex);
		const auto sk = SigningKey(SodiumBuffer(privateKeyBytes.byteVector), "");

		const UserPacket userPacket(testCase.name, testCase.email);
		ASSERT_STRCASEEQ(userPacket.encode().toHex().c_str(), testCase.userIdPacketHex.c_str());

		EdDsaKeyConfiguration configuration;
		configuration.version = testCase.version;
		configuration.preferredSymmetricAlgorithms = {9,8,7,2};
		configuration.preferredHashAlgorithms = {0x0a, 0x09, 0x08, 0x0b, 0x02};
		configuration.preferredCompressionAlgorithms = {2,3,1};

		EdDsaPublicPacket publicPacket(ByteBuffer::fromHex(testCase.publicKeyHex), testCase.timestamp, configuration);
		ByteBuffer encodedPublicPacket = publicPacket.encode();
		ASSERT_STRCASEEQ(encodedPublicPacket.toHex().c_str(), testCase.publicPacketHex.c_str());
		ASSERT_STRCASEEQ(publicPacket.fingerprint.toHex().c_str(), testCase.fingerprintHex.c_str());

		SecretKeyPacket secretPacket(publicPacket, privateKeyBytes, testCase.timestamp);
		ASSERT_STRCASEEQ(secretPacket.encode().toHex().c_str(), testCase.secretPacketHex.c_str());

		const SignaturePacket signaturePacket(sk, userPacket, secretPacket, publicPacket, testCase.timestamp);
		ASSERT_STRCASEEQ(signaturePacket.encode().toHex().c_str(), testCase.signaturePacketHex.c_str());

		const std::string testResultsDirectoryPath = "./test-results";
		fs::create_directories(testResultsDirectoryPath);
		const std::string keyFileName = testResultsDirectoryPath + "/PrivateKey-" + toHexStr(publicPacket.keyId.byteVector) + ".pem";
		std::ofstream privateKeyFile(keyFileName);
		ByteBuffer out;
    out.append(secretPacket.encode());
    out.append(userPacket.encode());
    out.append(signaturePacket.encode());
    const std::string pemData = PEM("PGP PRIVATE KEY BLOCK", out);
		privateKeyFile << pemData;
	}
}

TEST(KeyFormats, PacketFunctionV5) {
	for (const auto& testCase : testCases) {
		const auto privateKeyBytes = ByteBuffer::fromHex(testCase.privateKeyHex);
		const auto sk = SigningKey(SodiumBuffer(privateKeyBytes.byteVector), "");

		const UserPacket userPacket(testCase.name, testCase.email);
		ASSERT_STRCASEEQ(userPacket.encode().toHex().c_str(), testCase.userIdPacketHex.c_str());

		EdDsaKeyConfiguration configuration;
		configuration.version = VERSION_5;
		EdDsaPublicPacket publicPacket(ByteBuffer::fromHex(testCase.publicKeyHex), testCase.timestamp, configuration);
		ByteBuffer encodedPublicPacket = publicPacket.encode();

		SecretKeyPacket secretPacket(publicPacket, privateKeyBytes, testCase.timestamp);

		const SignaturePacket signaturePacket(sk, userPacket, secretPacket, publicPacket, testCase.timestamp);

		const std::string testResultsDirectoryPath = "./test-results";
		fs::create_directories(testResultsDirectoryPath);
		const std::string keyFileName = testResultsDirectoryPath + "/PrivateKeyV5-" + toHexStr(publicPacket.keyId.byteVector) + ".pem";
		std::ofstream privateKeyFile(keyFileName);
		ByteBuffer out;
    out.append(secretPacket.encode());
    out.append(userPacket.encode());
    out.append(signaturePacket.encode());
    const std::string pemData = PEM("PGP PRIVATE KEY BLOCK", out);
		privateKeyFile << pemData;
	}
}

TEST(KeyFormats, SigningKeyConstructor) {
	for (const auto& testCase : testCases) {
		SigningKey signingKey(SodiumBuffer(ByteBuffer::fromHex(testCase.privateKeyHex).byteVector), "");

		const ByteBuffer privateKey = ByteBuffer(signingKey.getSeedBytes());
		const ByteBuffer publicKey = ByteBuffer(signingKey.getSignatureVerificationKeyBytes());

		ASSERT_STRCASEEQ(privateKey.toHex().c_str(), testCase.privateKeyHex.c_str());
		ASSERT_STRCASEEQ(publicKey.toHex().c_str(), testCase.publicKeyHex.c_str());
	}
}


TEST(KeyFormats, OpenPGP) {
	const auto& testCase = testCases[0];
		EdDsaKeyConfiguration configuration;
		configuration.version = testCase.version;
		configuration.preferredSymmetricAlgorithms = {9,8,7,2};
		configuration.preferredHashAlgorithms = {0x0a, 0x09, 0x08, 0x0b, 0x02};
		configuration.preferredCompressionAlgorithms = {2,3,1};

	const SigningKey signingKey(SodiumBuffer(ByteBuffer::fromHex(testCase.privateKeyHex).byteVector), "{\"bogusRecipeWhichWillBeIgnored\": true}");

	ASSERT_STRCASEEQ(toHexStr(signingKey.getSeedBytes().toVector()).c_str(), testCase.privateKeyHex.c_str());
	ASSERT_STRCASEEQ(toHexStr(signingKey.getSignatureVerificationKeyBytes()).c_str(), testCase.publicKeyHex.c_str());
	const std::string pem = generateOpenPgpKey(signingKey, createUserIdPacketContent(testCase.name, testCase.email), testCase.timestamp, configuration);

	std::string expectedKeyBlock = "\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlFgEYIRFYBYJKwYBBAHaRw8BAQdAcfBjFSWhELKmBG1MHc8KK4uM2d7x53PbQIFl\np0ei4+gAAP9Yy6hJbqvD1Y+EwDREjvHB+VycZYLgBsK7IFtw61jVzxNctCBES19V\nU0VSXzEgPGRrdXNlcjFAZGljZWtleXMub3JnPoiQBBMWCAA4FiEE++YqtdyMQbEs\nBvN+hbejV7Dp/9gFAmCERWACGwEFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQ\nhbejV7Dp/9hl6wEAxad9KNliPHS0k6el5yq/JPNMThM9qF4xTGEFsGpOJq8BAKbs\nE5IMgCP8BERwXU8ypVuXfsFHvjtraPESYBpStnMK\n=lFgEYIRFYBYJKwYBBAHaRw8BAQdAcfBjFSWhELKmBG1MHc8KK4uM2d7x53PbQIFlp0ei4+gAAP9Yy6hJbqvD1Y+EwDREjvHB+VycZYLgBsK7IFtw61jVzxNctCBES19VU0VSXzEgPGRrdXNlcjFAZGljZWtleXMub3JnPoiQBBMWCAA4FiEE++YqtdyMQbEsBvN+hbejV7Dp/9gFAmCERWACGwEFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQhbejV7Dp/9hl6wEAxad9KNliPHS0k6el5yq/JPNMThM9qF4xTGEFsGpOJq8BAKbsE5IMgCP8BERwXU8ypVuXfsFHvjtraPESYBpStnMK\n-----END PGP PRIVATE KEY BLOCK-----\n";
	
		ASSERT_STREQ(pem.c_str(), expectedKeyBlock.c_str());
}

TEST(KeyFormats, WrapKey) {
	wrapTest(
		"00",
		"0000"
	);

	wrapTest(
		"01",
		"000101"
	);

	wrapTest(
		"FF",
		"0008FF"
	);

	wrapTest(
		"01FF",
		"000901FF"
	);

	wrapTest(
		"0000000000",
		"0000"
	);

	wrapTest(
		"58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF",
		"00FF58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF"
	);

	wrapTest(
		"F741CC9AC284484A9282152E36CDEE239EBA572F5C258979C9657AA3F7E95EBC",
		"0100F741CC9AC284484A9282152E36CDEE239EBA572F5C258979C9657AA3F7E95EBC"
	);
}


TEST(OpenSSH, PublicKey) {
	const auto privateKey = ByteBuffer::fromHex("05AD7768A6BF76BACF11CD6E958685C2921A2D0A1F7B3313CB66FA71382FCF41");
	const auto publicKey = ByteBuffer::fromHex("C953742F5D7A26111D868FBBAD228C9C180524FD1743891A2796D49F4735FD3D");

	SigningKey sk(SodiumBuffer(privateKey.byteVector), "");
	SignatureVerificationKey svk = sk.getSignatureVerificationKey();

	const auto openSSHKey = getOpenSSHPublicKeyEd25519(svk);
	ASSERT_STREQ(
		openSSHKey.c_str(),
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlTdC9deiYRHYaPu60ijJwYBST9F0OJGieW1J9HNf09 DiceKeys"
	);
}

TEST(OpenSSH, PrivateKey) {
	const auto privateKey = ByteBuffer::fromHex("05AD7768A6BF76BACF11CD6E958685C2921A2D0A1F7B3313CB66FA71382FCF41");
	SigningKey sk(SodiumBuffer(privateKey.byteVector), "");
	const uint32_t checksum = 0x103D60C3;
	const auto pk = getOpenSSHPrivateKeyEd25519(sk, "DiceKeys", checksum);
	const auto pkBase64 = base64Encode(pk.byteVector);
	ASSERT_STREQ(
		pkBase64.c_str(),
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDJU3QvXXomER2Gj7utIoycGAUk/RdDiRonltSfRzX9PQAAAJAQPWDDED1gwwAAAAtzc2gtZWQyNTUxOQAAACDJU3QvXXomER2Gj7utIoycGAUk/RdDiRonltSfRzX9PQAAAEAFrXdopr92us8RzW6VhoXCkhotCh97MxPLZvpxOC/PQclTdC9deiYRHYaPu60ijJwYBST9F0OJGieW1J9HNf09AAAACERpY2VLZXlzAQIDBAU="
	);
}
