#include "gtest/gtest.h"
#include "lib-seeded.hpp"


TEST(DerivationOptions, GeneratesDefaults) {
	DerivationOptions kgo = DerivationOptions(R"KGO({
	"type": "UnsealingKey"	
})KGO",
	DerivationOptionsJson::type::UnsealingKey
);
	ASSERT_EQ(
		kgo.derivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"type": "UnsealingKey"
})KGO"
	);
}


TEST(DerivationOptions, derivesPrimarySecrets) {
	const SodiumBuffer seed = DerivationOptions::derivePrimarySecret(
		"Avocado",
		R"KGO({"lengthInBytes": 64})KGO",
		DerivationOptionsJson::type::Secret
	);
	ASSERT_EQ(seed.length, 64);
}


TEST(DerivationOptions, FidoUseCase) {
	DerivationOptions kgo = DerivationOptions(R"KGO({
	"type": "Secret",
	"lengthInBytes": 96,
	"hashFunction": "Argon2id",
	"restrictions": {
		"androidPackagePrefixesAllowed": ["com.dicekeys.fido"]
	}
})KGO",
	DerivationOptionsJson::type::Secret
);
	ASSERT_EQ(
		kgo.derivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
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

TEST(DerivationOptions, InitsWithClientPrefixes) {
	DerivationOptions kgo = DerivationOptions(R"KGO({
	"type": "UnsealingKey",
	"restrictToClientApplicationsIdPrefixes": ["com.dicekeys.client", "com.dicekeys.another"]
})KGO",
	DerivationOptionsJson::type::UnsealingKey
);
	ASSERT_EQ(
		kgo.derivationOptionsJsonWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "SHA256",
	"type": "UnsealingKey"
})KGO"
);
}
