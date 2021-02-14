#include "gtest/gtest.h"
#include "lib-seeded.hpp"


TEST(Recipe, GeneratesDefaults) {
	Recipe kgo = Recipe(R"KGO({
	"type": "UnsealingKey"	
})KGO",
	RecipeJson::type::UnsealingKey
);
	ASSERT_EQ(
		kgo.recipeWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "BLAKE2b",
	"type": "UnsealingKey"
})KGO"
	);
}


TEST(Recipe, derivesPrimarySecrets) {
	const SodiumBuffer seed = Recipe::derivePrimarySecret(
		"Avocado",
		R"KGO({"lengthInBytes": 64})KGO",
		RecipeJson::type::Secret
	);
	ASSERT_EQ(seed.length, 64);
}


TEST(Recipe, FidoUseCase) {
	Recipe kgo = Recipe(R"KGO({
	"type": "Secret",
	"lengthInBytes": 96,
	"hashFunction": "Argon2id",
	"restrictions": {
		"androidPackagePrefixesAllowed": ["com.dicekeys.fido"]
	}
})KGO",
	RecipeJson::type::Secret
);
	ASSERT_EQ(
		kgo.recipeWithAllOptionalParametersSpecified(1, '\t'),
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

TEST(Recipe, InitsWithClientPrefixes) {
	Recipe kgo = Recipe(R"KGO({
	"type": "UnsealingKey",
	"restrictToClientApplicationsIdPrefixes": ["com.dicekeys.client", "com.dicekeys.another"]
})KGO",
	RecipeJson::type::UnsealingKey
);
	ASSERT_EQ(
		kgo.recipeWithAllOptionalParametersSpecified(1, '\t'),
		R"KGO({
	"algorithm": "X25519",
	"hashFunction": "BLAKE2b",
	"type": "UnsealingKey"
})KGO"
);
}
