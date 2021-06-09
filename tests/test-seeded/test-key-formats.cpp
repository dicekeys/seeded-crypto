#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include "../lib-seeded/key-formats/Packet.hpp"
#include "../lib-seeded/key-formats/ByteBuffer.hpp"
#include "../lib-seeded/lib-seeded.hpp"
#include "../lib-seeded/convert.hpp"

void wrapTest(const std::string& toEncode, const std::string& toCheckAgainstEncodedValue) {
	const auto encoded = wrapKeyWithLengthPrefixAndTrim(ByteBuffer::fromHex(toEncode));
	auto encodedHex = encoded.toHex();
	// Compare in upper-case
	std::transform(encodedHex.begin(), encodedHex.end(), encodedHex.begin(), ::toupper);
	ASSERT_EQ(encodedHex, toCheckAgainstEncodedValue);
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
