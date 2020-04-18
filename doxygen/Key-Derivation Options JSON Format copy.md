# Key-Derivation Options JSON Format {#key_derivation_options_format}

This JSON-format is used to specify how a key should be derived from a seed string.

When the Seeded Cryptography Library derives a key from a seed string, the key-derivations
options JSON string is used to salt the key derivation process.
Thus, any change to this string no matter how tiny, even if just ordering or white space,
will cause the library to derive a different key than for any other pair of
seed strings and key-derivation options JSON string.

The value of a key-derivation options JSON string must be either a valid JSON object specification,
which is a set of fields enclosed in curly braces ("{}") per the JSON format,
or an empty string.

This specification defines default values for all fields, which are applied if a field is absent,
and so a key-derviation options JSON string that is itself an empty string ("") or empty object ("{}")
will use the default values for all fields.
For example, If you are specifying derivation options for a SymmetricKey operation and pass an empty string,
the `"keyType"` field will be inferred to be `Symmetric` and the `"algorithm"` will be the default
algorithm for symmetric key cryptography (`XSalsa20Poly1305`).

This specification breaks fields into three types:

*Universal fields* are used by the Seeded Cryptography Library directly to derive keys.
They are generalizable to any type of seed string, not just the DiceKeys use case
for which the library was created.

The Seeded Cryptogpraphy Library is oblivious to other fields, but since they are part of the
JSON string any changes to them will cause the library to derive a different key.

*DiceKeys Hardware fields* apply to keys seeded with a DiceKeys.

*DiceKeys API fields* apply to keys generated through the DiceKeys API, which
calls uses the DiceKeys app to generate keys and often to perform cryptographic
operations. The DiceKeys app protects the keys so that other applications are not
able to see the raw DiceKey, and these options specify which applications are
allowed to generate keys and what they are allowed to do with them.

The extensibility of underlying JSON format and the obliviousness of this
library to non-universal fields allows other libraries to build
on top of it without having to change this library.
Any key-derivation options fields added will be ignored by this
library for all purposes beyond salting the keys generated.

Since any JSON object field outside the spec can be attached, one could, for example, use a
field to salt the derivation of a SymmetricKey like so:
```TypeScript
{
    "keyType": "SymmetricKey",
    "SaltWithThePhoneNumberForJenny": 8675309
}
```



@anchor key_derivation_options_universal_fields
### Universal Fields used by the Seeded Cryptography Library

The following fields are inspected and used by the seeded-crypto C++ library.

#### keyType

Specify whether this JSON object should be used to construct an
@ref Seed, @ref SymmetricKey, @ref PrivateKey, or @ref SigningKey.

```TypeScript
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

```TypeScript
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
```TypeScript
"keyLengthInBytes"?: number // e.g. "keyLengthInBytes": 32
```

Set this value when using `"KeyType": "Seed"` to set the size of the seed to be derived (in bytes, as the name implies). If set for other `keyType`s, it must
match the keyLengthInBytes of that algorithm (32 bytes for the current algorithms).

If this library is extended to support `algorithm` values with multiple key-length
options, this field can be used to specify which length varient of the algorithm to
use.

#### hashFunction
```TypeScript
"hashFunction"?: "BLAKE2b" | "SHA256" | "Argon2id" | "Scrypt" // default "SHA256"
```

Specifies the hash function used to derive the key.  If `"Argoin2id"` or `"Scrypt"` are used, you can specify the memory limit and ops (iterations) via
two additional fields, which are ignored for  `"BLAKE2b"` and `"SHA256"`.
```
"hashFunctionMemoryLimit": number // default 67108864
"hashFunctionIterations": number // default 2, has no effect if algorithm is "BLAKE2b" | "SHA256" 
```


For example:
```TypeScript
{
    "keyType": "Seed",
    "keyLengthInBytes": 96,
    "hashFunction": "Argon2id",
    "hashFunctionMemoryLimit": 67108864,
    "hashFunctionIterations": 4
}
```

##### Hash defaults and recommendations

The default hash function is `SHA256` as this library was designed for DiceKeys,
which are sufficiently random seeds (~196 bits) so as not to require
brute-force prevention with a costly key-derivation function like `Scrypt`
or `Argon2id`.  The default ensures that keys can be re-derived cheaply
on just about any hardware platform.

Applcations that need a more expensive key derivation to protect against
brute-forcing of the key-derivation algorithm will want to use
`Scrypt` if and only if keys will always be derived on hardware where
no untrusted code will run during the derivation process.
If keys may sometimes be derived on hardware shared with untrusted code,
even if that code is sanboxed, we recommend using `Argon2id`.

We purposely chose _not_ to support multiple iterations of `BLAKE2b` or `SHA256`
via the `hashFunctionIterations` field, as applications that want to increase the
cost of key derviation to prevent brute forcing should use `Argon2id` or `Scrypt`.

### DiceKeys Hardware Fields

This Seeded Cryptography Library is oblivious to these fields, but they are documented
here to keep the specification from being split into too many locations.

#### excludeOrientationOfFaces

When using a DiceKey as a seed, the default seed string will be a 75-character string consisting of triples for each die in canonoical order:
 * The uppercase letter on the die
 * The digit on the die
 * The orientation relative to the top of the square in canonical form

If  `excludeOrientationOfFaces` is set to `true` set to true, the orientation character (the third member of each triple) will be excluded
resulting in a 50-character seed.
This option exists because orientations may be harder for users to copy correctly than letters and digits are.
With this option on, should a user choose to manually copy the contents of a DiceKey and make an error
in copying an orientation, that error will not prevent them from re-deriving the specified key or seed.

```
    "excludeOrientationOfFaces"?: true | false // default false
```

### DiceKeys API Fields

These fields specify who may generate keys and what they may do with them once generated.

#### clientMayRetrieveKey

Set `"clientMayRetrieveKey"?: true` to allow the client application to retrieve the
PrivateKey (`"keyType": "Public"`),
SigningKey (`"KeyType": "Signing"`), or
SymmetricKey (`"keyType": "Symmetric"`)
subject to any restrictions specified in the `"restrictions"` field.

```
    "clientMayRetrieveKey"?: true | false // default false
```

This allows client apps to derive keys that they can use
private/signing/symmetric keys even when the seed is not present
for re-derivation, but still have a key that is recoverable with
the seed should it become necessary.

#### restrictions

The DiceKeys app will restrict access to derived seeds or keys to so that only those apps that are specifically allowed can obtain or use them.

```TypeScript
    "restrictions"?: {
        "androidPackagePrefixesAllowed"?: string[],
        "urlPrefixesAllowed"?: string[]
    }
```

For example:
```TypeScript
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

If the `"restrictions"` field is set, but the object it is set to does not contain an
`"androidPackagePrefixesAllowed"` field, the API will forbid Android applications from
generating the key.
If the `"restrictions"` field is set, but the object it is set to does not contain a
`"urlPrefixesAllowed"` field, the API will forbid iOS and other applications that
rely on this field to generate the key.

The API will terminate prefixes set via "`androidPackagePrefixesAllowed`" with dots, and
and terminate client package IDs with dots, to prevent extension attacks.  In other words,
if you set the prefix `com.example`, the API will treat it as `com.example.`, so that
another party cannot register `com.exampleattacker` to match the `com.eaxmple` prefix.
