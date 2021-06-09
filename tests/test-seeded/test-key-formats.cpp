#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include "../lib-seeded/key-formats/Packet.hpp"
#include "../lib-seeded/key-formats/ByteBuffer.hpp"
#include "../lib-seeded/key-formats/UserPacket.hpp"
#include "../lib-seeded/key-formats/PublicKeyPacket.hpp"
#include "../lib-seeded/key-formats/SecretKeyPacket.hpp"
#include "../lib-seeded/key-formats/SignaturePacket.hpp"
#include "../lib-seeded/lib-seeded.hpp"
#include "../lib-seeded/convert.hpp"

std::string toUpper (const std::string& a) {
	std::string upper = a;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	return upper;
}

void wrapTest(const std::string& toEncode, const std::string& toCheckAgainstEncodedValue) {
	const auto encoded = wrapKeyWithLengthPrefixAndTrim(ByteBuffer::fromHex(toEncode));
	auto encodedHex = toUpper(encoded.toHex());
	ASSERT_STRCASEEQ(encodedHex.c_str(), toCheckAgainstEncodedValue.c_str());
}

TEST(KeyFormats, PacketFunctions) {
	const std::string privateKeyHex = "58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF";
	const std::string publicKeyHex = "71F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E8";
	uint32_t timestamp = 0x60844560u;

	const std::string name = "DK_USER_1";
	const std::string email = "dkuser1@dicekeys.org";
	const std::string userIdPacketBinary = "B420444B5F555345525F31203C646B757365723140646963656B6579732E6F72673E";
	const auto userIdPacket = createUserPacket(name, email);
	const auto userIdPacketHex = userIdPacket.toHex();
	ASSERT_STRCASEEQ(userIdPacketHex.c_str(), userIdPacketBinary.c_str());

	const std::string fingerprintHex = "FBE62AB5DC8C41B12C06F37E85B7A357B0E9FFD8";
	const std::string publicPacketBinary = "9833046084456016092B06010401DA470F0101074071F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E8";
	ByteBuffer publicKeyPacket = createPublicPacket(ByteBuffer::fromHex(publicKeyHex), timestamp);
	ASSERT_STRCASEEQ(publicKeyPacket.toHex().c_str(), publicPacketBinary.c_str());
	ByteBuffer fingerprint = getPublicKeyFingerprint(publicKeyPacket);
	ASSERT_STRCASEEQ(fingerprint.toHex().c_str(), fingerprintHex.c_str());

	const std::string secretPacketBinary = "9458046084456016092B06010401DA470F0101074071F0631525A110B2A6046D4C1DCF0A2B8B8CD9DEF1E773DB408165A747A2E3E80000FF58CBA8496EABC3D58F84C034448EF1C1F95C9C6582E006C2BB205B70EB58D5CF135C";
	ByteBuffer secretPacket = createSecretPacket(ByteBuffer::fromHex(privateKeyHex), ByteBuffer::fromHex(publicKeyHex), timestamp);
	ASSERT_STRCASEEQ(secretPacket.toHex().c_str(), secretPacketBinary.c_str());
	
	const std::string signaturePacketBinary = "8890041316080038162104FBE62AB5DC8C41B12C06F37E85B7A357B0E9FFD8050260844560021B01050B0908070206150A09080B020416020301021E01021780000A091085B7A357B0E9FFD865EB0100C5A77D28D9623C74B493A7A5E72ABF24F34C4E133DA85E314C6105B06A4E26AF0100A6EC13920C8023FC0444705D4F32A55B977EC147BE3B6B68F112601A52B6730A";
	ByteBuffer signaturePacket = createSignaturePacket(ByteBuffer::fromHex(privateKeyHex), ByteBuffer::fromHex(publicKeyHex), userIdPacket, timestamp);
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
