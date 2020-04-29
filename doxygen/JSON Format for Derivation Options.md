# JSON Format for Derivation Options {#derivation_options_format}

This JSON-format is used to specify how secrets (Secret), keys (SymmetricKey) and key pairs (UnsealingKey & SealingKey, SigningKey & SignatureVerificationKey) should be derived from a seed string.

For example, the following is a valid Derivation Options JSON string used to generate a SymmetricKey, using the `Argon2id` to derive the key bytes from a seed string:

```TypeScript
{
    "type": "SymmetricKey",
    "hashFunction": "Argon2id"
}
```

The value of a derivation options JSON string must be either a valid JSON object specification,
which is a set of fields enclosed in curly braces ("{}") per the JSON format,
or an empty string.

This specification defines default values for _all_ fields, these defaults are used when a field is absent, and so a derivation options JSON string that is itself an empty string ("") or empty object ("{}") will use defaults for all field values.
For example, If you are deriving a SymmetricKey and pass the empty string,
the `"type"` will be inferred to be `Symmetric`, the `"hashFunction"` to be `SHA256`, and the `"algorithm"` will be the default
algorithm for symmetric key cryptography: `XSalsa20Poly1305`.

The Seeded Cryptography Library uses a hash function to derive keys and secrets, and the input to that hash function includes both the seed string _and_ the JSON string you provide with the derivation options.  In cryptographic terms, this means the JSON string with your derivation options is used to _salt_ the hash function.
Thus, _any_ change to this Derivation Options JSON string, even if just ordering or white space, will cause a different key or secret to be derived.

Any fields in your JSON object that are not in this specification have no effect other than to change the input to the hash function and thus the derived key or secret.
This allows other libraries to extend the spec without making changes to how this
library derives keys and secrets. Those using the library can also embed arbitrary
fields into the JSON object as they see fit. For example, the second field in
the object specified by the following JSON string is not processed by the library,
but since the entire string is passed to the hash function used to derive the key it ensure a different key will be derived than if the field were absent:

```TypeScript
{
    "type": "SymmetricKey",
    "aRandomNumericSaltNotInTheSpec": 1299486243
}
```

#### How this specification is organized
This specification separates the JSON object fields into three categories:

*Universal fields* are used by the Seeded Cryptography Library directly to derive secrets and key seeds. These are generalizable to any type of seed string, not just the DiceKeys use case for which we created this library.

The Seeded Cryptogpraphy Library is oblivious to other fields, but since they are part of the
JSON string any changes to them will cause the library to derive a different key.

*DiceKeys Hardware fields* apply to keys seeded with a DiceKeys.

*DiceKeys API fields* apply to keys generated through the DiceKeys API, which
calls uses the DiceKeys app to generate keys and often to perform cryptographic
operations. The DiceKeys app protects the keys so that other applications are not
able to see the raw DiceKey, and these options specify which applications are
allowed to generate keys and what they are allowed to do with them.


@anchor derivation_options_universal_fields
### Universal Fields used by the Seeded Cryptography Library

The following fields are inspected and used by the seeded-crypto C++ library.

#### type

Specify whether this JSON object should be used to construct a
@ref Secret, @ref SymmetricKey, @ref UnsealingKey, or @ref SigningKey.

```TypeScript
"type"?:
    // For constructing a raw Secret
    "Secret" |
    // For constructing a SymmetricKey
    "SymmetricKey" |
    // For constructing an UnsealingKey, from which a corresponding SealingKey can be instantiated
    "UnsealingKey" |
    // For constructing a SigningKey, from which a SignatureVerificationKey can be instantiated
    "SigningKey"
```

Instead of a generic Public and Private asymmetric key, we support separate key pairs for sealing (encrypting and integrity-protecting) messages, SealingKey & UnsealingKey, and for digital signatures, the SigningKey & SignatureVerificationKey. The `type` for an asymmetric key pair is the type of the private key, as you can obtain a public SignatureVerificationKey from the private SigningKey, and you can obtain the public SealingKey from the private UnsealingKey.

If this field is not provided, the type is inferred from the type of object being constructed.

If you attempt to construct an object of one `type` when the `"type"` field specifies
a different `type`, the constructor will throw an @ref InvalidDerivationOptionValueException.

#### algorithm

Specify the specific algorithm to use.

```TypeScript
"algorithm"?: 
    // valid only for "type": "SymmetricKey"
    "XSalsa20Poly1305" | // the default for SymmetricKey
    // valid only for "type": "UnsealingKey"
    "X25519" |           // the default for UnsealingKey
    // valid only for "type": "SigningKey"
    "Ed25519"            // the default for SigningKey
```

The `algorithm` field should never be set when `"type": "Secret"`.

#### lengthInBytes
```TypeScript
"lengthInBytes"?: number // e.g. "lengthInBytes": 32
```

Use this field `"type": "Secret"` to set the size of the secret to be derived
(in bytes, as the name implies). If set for other derived object `type`, it must
the value assigned must match the lengthInBytes of that algorithm
(32 bytes for the algorithms currently supported).

If this library is extended to support `algorithm` values with multiple key-length
options, this field will be used to specify which length varient of the algorithm to
use.

#### hashFunction

The `hashFunction` field specifies the hash function to used to derive key seeds and secrets. The default is `"SHA256"`.

```TypeScript
"hashFunction"?: "BLAKE2b" | "SHA256" | "Argon2id" | "Scrypt"
```

`Argon2id` and `Scrypt` are hash functions designed to require not just computation, but also memory, in order to thwart hardware brute force attacks.[^1] (The `Argon2id` parameter maps to algorithm `crypto_pwhash_ALG_ARGON2ID13` in libsodium with the salt set to a block of zero bytes, and `Scrypt` maps to algorithm `crypto_pwhash_scryptsalsa208sha256` in libsodium, also with zero bytes for the salt.) When using these two hash functions, you can also specify the memory limit and the number of passes to make through memory.

[^1] X

```TypeScript
"hashFunctionMemoryLimitInBytes": number // default 67108864
"hashFunctionMemoryPasses": number // default 2
```

The `hashFunctionMemoryLimitInBytes` field is the amount of memory that `Argoin2id` or `Scrypt` will be required to iterate (pass) through
in order to compute the correct output,
and `hashFunctionMemoryPasses` is the number of passes it will need
to make through that memory to do so.

For example:
```TypeScript
{
    "type": "Secret",
    "lengthInBytes": 96,
    "hashFunction": "Argon2id",
    "hashFunctionMemoryLimitInBytes": 67108864,
    "hashFunctionMemoryPasses": 4
}
```

As the name implies, the `hashFunctionMemoryLimitInBytes` field is specified in bytes. It should be a multiple of 1,024, must be at least 8,192 and no greater than 2^31 (2,147,483,648).  The default is 67,108,864.
This field maps to the [`memlimit` parameter in libsodium](https://libsodium.gitbook.io/doc/password_hashing/default_phf).

The `hashFunctionMemoryPasses` must be at least 1, no greater than 2^32-1 (4,294,967,295), and is set to 2 memory passes by default. Since this parameter determines the number of passes the hash function will make through the memory region specified by `hashFunctionMemoryLimitInBytes`, and results in hashing an
amount of memory equal to the product of these two parameters,
the computational cost on the order of the product of
`hashFunctionMemoryPasses` times `hashFunctionMemoryLimitInBytes`.
(The `hashFunctionMemoryPasses` field maps to the poorly-documented `opslimit` in `libsodium`. An examination of the `libsodium` source shows that opslimit is assigned to a parameter named `t_cost`, which in turn is assigned to `instance.passes` on line 56 of [argon2.c](https://github.com/jedisct1/libsodium/blob/7214dff083638604cd48e5c9ffc5704460192794/src/libsodium/crypto_pwhash/argon2/argon2.c).)


`BLAKE2b` and `SHA256` are single-iteration functions and so, when using them, the
`hashFunctionMemoryLimitInBytes` and `hashFunctionMemoryPasses` fields must
not be set.

##### Hash defaults and recommendations

The default hash function is `SHA256` as this library was designed for DiceKeys,
which are random and rawn from such a large number of possible values (~2^196)
to make `Scrypt` and `Argon2id` unncessary.
This default ensures that keys can be re-derived cheaply
on just about any hardware platform.

Applcations that need a more expensive key derivation to protect against
brute-forcing of the derivation algorithm will want to use
`Scrypt` if _and only if_ keys will _always_ be derived on hardware where
no untrusted code will run during the derivation process.
If keys may sometimes be derived on hardware shared with untrusted code,
even if that code is sanboxed, we recommend using `Argon2id`.

We purposely chose _not_ to support multiple iterations of `BLAKE2b` or `SHA256`
via the `hashFunctionMemoryPasses` field, as applications that want to increase the
cost of key derviation to prevent brute forcing should use `Argon2id` or `Scrypt`.

##### Preimage construction

The input, or `preimage`, to the key derivation function is the concatenation of
- the seed (UTF8 encoded if no encoding to a binary array is specified)),
- a null-termination character ('\0') for the seed,
- the type (`Symmetric`, `Public`, `Signing`, or `Secret`) of the key being derived,
    UTF8 encoded and not null terminated, and
- the derivation options JSON string, UTF8 encoded and not null terminated.

Including the `type` of the key (or secret) being derived in the preimage may seem unnecessary, since there is a `type` field in the JSON format.  It is important to include the type of the key or secret actually being derived because the `type` field is optional in the JSON format. If we were not to include it, two keys of different types derived from the same JSON specification could have the same preimage.


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
in copying an orientation, that error will not prevent them from re-deriving the specified key or secret.

```
    "excludeOrientationOfFaces"?: true | false // default false
```

### DiceKeys API Fields

These fields specify who may generate keys and what they may do with them once generated.

#### clientMayRetrieveKey

Set `"clientMayRetrieveKey"?: true` to allow the client application to retrieve the
UnsealingKey (`"type": "UnsealingKey"`),
SigningKey (`"type": "SigningKey"`), or
SymmetricKey (`"type": "SymmetricKey"`)
subject to any restrictions specified in the `"restrictions"` field.

```
    "clientMayRetrieveKey"?: true | false // default false
```

This allows client apps to derive keys that they can use
private/signing/symmetric keys even when the seed is not present
for re-derivation, but still have a key that is recoverable with
the seed should it become necessary.

#### restrictions

The DiceKeys app will restrict access to derived keys or secrets to so that only those apps that are specifically allowed can obtain or use them.

```TypeScript
    "restrictions"?: {
        "androidPackagePrefixesAllowed"?: string[],
        "urlPrefixesAllowed"?: string[]
    }
```

For example:
```TypeScript
{
    "type": "Secret",
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
if you set the prefix `com.example`, the API will test if `com.example.` is a prefix
of the string composed by concatenating a period onto your client application's package name.
So, if an attacker registers the package name `com.exampleattacker`, they will not be
able to match the `com.eaxmple` prefix.
