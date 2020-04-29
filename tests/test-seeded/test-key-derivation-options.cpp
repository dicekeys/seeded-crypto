#include "gtest/gtest.h"
#include "lib-seeded.hpp"


TEST(KeyDerivationOptions, GeneratesDefaults) {
	KeyDerivationOptions kgo = KeyDerivationOptions(R"KGO({
	"type": "Public"	
})KGO",
	KeyDerivationOptionsJson::type::Public
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"type": "Public"
})KGO"
	);
}


TEST(KeyDerivationOptions, FidoUseCase) {
	KeyDerivationOptions kgo = KeyDerivationOptions(R"KGO({
	"type": "Secret",
	"lengthInBytes": 96,
	"hashFunction": "Argon2id",
	"restrictions": {
		"androidPackagePrefixesAllowed": ["com.dicekeys.fido"]
	}
})KGO",
	KeyDerivationOptionsJson::type::Secret
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"hashFunction": "Argon2id",
	"hashFunctionMemoryLimitInBytes": 67108864,
	"hashFunctionMemoryPasses": 2,
	"lengthInBytes": 96,
	"type": "Secret"
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
	"type": "Public",
	"restrictToClientApplicationsIdPrefixes": ["com.dicekeys.client", "com.dicekeys.another"]
})KGO",
	KeyDerivationOptionsJson::type::Public
);
	ASSERT_EQ(
		kgo.keyDerivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"type": "Public"
})KGO"
);
}
