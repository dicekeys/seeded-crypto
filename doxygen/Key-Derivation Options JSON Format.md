Key-Derivation Options JSON format {#key_derivation_options_format}
================

This JSON-format for an object specifies how seeds and keys should be derived.
Its value must be either a valid JSON object specification, enclosed in braces ("{}"), or an empty string.

All fields are optional and have defaults specified, and so an empty object "{}" will indicate that he defaults for all fields should be used.
Any empty string ("") is treated the same as an empty object ("{}).

## Fields Specified by this Library

The following fields are used by the seeded-crypto C++ library.

#### keyType

Specify whether this JSON object should be used to construct an
@ref Seed, @ref SymmetricKey, @ref PrivateKey, or @ref SigningKey.

```
"keyType"?:
    // For constructing a Seed object
    "Seed" |
    // For constructing a SymmetricKey object
    "Symmetric" |
    // For constructing a PrivateKey object, from which a corresponding PublicKey can be instantiated
    "Public" |
    // For constructing a SigningKey object, from which a SignatureVerificationKey can be instantiated
    "Signing"
```

If not provided, the keyType is inferred from the type of object being constructed.

If you attempt to construct an object of one `keyType` when the the `"keyType"` field specifies
a different `keyType`, the constructor will treat it as an exception.

#### algorithm

Specify the specific algorithm to use.

```
"algorithm"?: 
    // valid only for "keyType": "Symmetric"
    "XSalsa20Poly1305" | // the current default for SymmetricKey
    // valid only for "keyType": "Public"
    "X25519" |           // the current default for PrivateKey
    // valid only for "keyType": Signing
    "Ed25519"            // the current default for SigningKey
```

The `algorithm` field should never be set for `"keyType": "Seed"`.

#### keyLengthInBytes
```
"keyLengthInBytes"?: number // e.g. "keyLengthInBytes": 32
```

Set this value when using `"KeyType": "Seed"` to set the size of the seed to be derived (in bytes, as the name implies). If set for other `keyType`s, it must
match the keyLengthInBytes of that algorithm (32 bytes for the current algorithms).

If this library is extended to support `algorithm` values with multiple key-length
options, this field can be used to specify which length varient of the algorithm to
use.

#### hashFunction
```
"hashFunction"?: "BLAKE2b" | "SHA256" | "Argon2id" | "Scrypt"
```

Specifies the hash function used to derive the key.  If "Argoin2id" or "Scrypt" are used, you can specify the memory limit and ops (iterations) via
```
"hashFunctionMemoryLimit": number // default 67108864
"hashFunctionIterations": number // default 2
```

For example:
```
{
    "keyType": "Seed",
    "keyLengthInBytes": 96,
    "hashFunction": "Argon2id",
    "hashFunctionMemoryLimit": 67108864,
    "hashFunctionIterations": 4
}
```

## Extension fields

In addition to the fields specified by this library, this format can be extended to support additional fields.  This library will ignore those fields when processing the JSON format, but since those fields are part of the JSON string, they will be part of the seed used to derive the output.  No matter how small the change to the JSON string, whether the insertion of a new field or the insertion of a white-space character, will cause an entirely different key to be derived.

So, for example, an arbitrary salt could be extended when deriving a SymmetricKey as illustred by this key-derivation options JSON string:
```
{
    "keyType": "SymmetricKey",
    "SaltWithThePhoneNumberForJenny": 8675309
}
```

The following extension field is used by DiceKeys, but not parsed or processed by this specific library.


#### restrictions

The DiceKeys app will restrict access to derived seeds or keys to so that only those apps that are specifically allowed can obtain or use them.

```
    "restrictions: {
        "androidPackagePrefixesAllowed": string[],
        "urlPrefixesAllowed": string[]
    }
```

For example:
```
{
    "keyType": "Seed",
    "restrictions": {
        "androidPackagePrefixesAllowed": [
            "org.dicekeys.apps.fido",
            "com.dicekeys.apps.fido"
        ],
        "urlPrefixesAllowed": [
            "https://dicekeys.org/app/fido",
            "https://dicekeys.com/app/fido"
        ]
    }
}
```

#### excludeOrientationOfFaces

When using a DiceKey as a seed, the default seed string will be a 75-character string consisting of triples for each die in canonoical order:
 * The uppercase letter on the die
 * The digit on the die
 * The orientation relative to the top of the square in canonical form

If  `excludeOrientationOfFaces` is set to `true` set to true, the orientation character (the third member of each triple) will be excluded
resulting in a 50-character seed.
The advantage of this settig is that, should a user manually transcribe the contents of a DiceKey, incorrectly record and orientation,
and not verify that the copy is correct, the mistake will not prevent them from correctly re-deriving the seed for this key in the future.

```
    "excludeOrientationOfFaces"?: true | false // default false
```