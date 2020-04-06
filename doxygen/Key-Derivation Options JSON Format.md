Key-Derivation Options JSON format {#key_derivation_options_format}
================

All fields are optional with sensible defaults, and if the empty string is used all default values will be used..

If not any empty string, must specify a JSON object by starting with "{" and ending with "}".

In addition to specified fields, it is legal to add arbitrary fields to the JSON object specified by the string. Since the full string is used to salt key derivation, you can change the derived key by adding fields of the names of your choosing. For exaple, the following string is a legal set of keyDerivationOptions
```
{
    "keyType": "Seed",
    "SaltWithThePhoneNumberForJenny": 8675309
}
```

#### keyType

```
"keyType"?:
    "Seed" |      // A new seed derived from the secret seed and the key-derivation options
    "Symmetric" | // A symmetric key that can be used to seal and unseal data
    "Public" |    // A public/private key pair
    "Signing" |   // A signing/verification key pair
```

If not provided, the keyType is inferred from the type of object being constructed.

#### alorrithm

```
"algorithm"?: 
    // valid only for "keyType": "Symmetric"
    "XSalsa20Poly1305" |
    // valid only for "keyType": "Public"
    "X25519" |
    // valid only for "keyType": Signing
    "Ed25519"
```

For future use for specifying a type of Symmetric, Public/Private, or Signing/Verification algorithm. The current implementations are
the defaults:

#### keyLengthInBytes
```
"keyLengthInBytes"?: number // e.g. "keyLengthInBytes": 32
```

Specify the length of a key or seed. Currently used only for "KeyType": "Seed", but may be used in the future for algorithms that support multiple key lengths.

#### hashFunction
```
"hashFunction"?: "BLAKE2b" | "SHA256" | "Argon2id" | "Scrypt"
```
Specifies the hash function used to derive the key.  If "Argoin2id" or "Scrypt" are used, you can specify the memory limit and ops (iterations) via
```
"hashFunctionMemoryLimit": number // default 67108864
"hashFunctionIterations": number // default 2
```

### restrictions

If set, this should contain an object which specifies which Android packages and URLs (for iOS and web apps) are allowed to use the key.

```
"restrictions"?: {
    "androidPackagePrefixesAllowed"?: string[]
    "urlPrefixesAllowed"?: string[]
}
```


