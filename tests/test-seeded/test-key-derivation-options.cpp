#include "gtest/gtest.h"
#include "lib-seeded.hpp"


TEST(KeyDerivationOptions, GeneratesDefaults) {
	KeyDerivationOptions kgo = KeyDerivationOptions(R"KGO({
	"keyType": "Public"	
})KGO",
	KeyDerivationOptionsJson::KeyType::Public
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"keyType": "Public"
})KGO"
	);
}


TEST(KeyDerivationOptions, FidoUseCase) {
	KeyDerivationOptions kgo = KeyDerivationOptions(R"KGO({
	"keyType": "Seed",
	"keyLengthInBytes": 96,
	"hashFunction": "Argon2id",
	"restrictions": {
		"androidPackagePrefixesAllowed": ["com.dicekeys.fido"]
	}
})KGO",
	KeyDerivationOptionsJson::KeyType::Seed
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"hashFunction": "Argon2id",
	"hashFunctionIterations": 2,
	"hashFunctionMemoryLimit": 67108864,
	"keyLengthInBytes": 96,
	"keyType": "Seed"
})KGO"
);
}
/*
,
	"restrictions": {
		"androidPackagePrefixesAllowed": [
			"com.dicekeys.fido"
		],
		"urlPrefixesAllowed": []
	}
*/

TEST(KeyDerivationOptions, InitsWithClientPrefixes) {
	KeyDerivationOptions kgo = KeyDerivationOptions(R"KGO({
	"keyType": "Public",
	"restrictToClientApplicationsIdPrefixes": ["com.dicekeys.client", "com.dicekeys.another"]
})KGO",
	KeyDerivationOptionsJson::KeyType::Public
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"keyType": "Public"
})KGO"
);
}
