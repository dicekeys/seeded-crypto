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
the `"type"` will be inferred to be `Symmetric`, the `"hashFunction"` to be `BLAKE2b`, and the `"algorithm"` will be the default
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

The Seeded Cryptography Library is oblivious to other fields, but since they are part of the
JSON string any changes to them will cause the library to derive a different key.

*DiceKeys Hardware fields* apply to keys seeded with a DiceKeys.

*Authentication and Authorization Requirements* apply to keys generated through
the DiceKeys API, which calls uses the DiceKeys app to generate keys and often
to perform cryptographic operations. The DiceKeys app protects the keys so
that other applications are not
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
    // For constructing a password
    "Password" |
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

The `algorithm` field should never be set when `"type": "Secret"` or `"type": "Password"`.

#### lengthInBytes
```TypeScript
"lengthInBytes"?: number // e.g. "lengthInBytes": 32
```

Use this field when `"type": "Secret"` to set the size of the secret to be derived
(in bytes, as the name implies). If set for other derived object `type`, it must
the value assigned must match the lengthInBytes of that algorithm
(32 bytes for the algorithms currently supported).

If this library is extended to support `algorithm` values with multiple key-length
options, this field will be used to specify which length variant of the algorithm to
use.

#### lengthInBits
```TypeScript
"lengthInBits"?: number
```

Use this field when `"type": "Password` to set the required minimum bit strength of the
password.  For example, if using a 512 word list (9 bits) and setting this value to
95, an 11-word password (99 bit) password will be generated.

If neither this field nor `lengthInWords` is set, the default lengthInBits for a password
will be 128.

#### lengthInWords
```TypeScript
"lengthInWords"?: number
```

Use this field when `"type": "Password` to set the required minimum number of words
from a word list to join together to form a password.

#### wordList
```TypeScript
"wordList"?:  "EN_512_words_5_chars_max_ed_4_20200917" | "EN_1024_words_6_chars_max_ed_4_20200917"

```

Use this field when `"type": "Password` to set the word list to be used to create
a password from the binary secret.
Defaults to `"EN_512_words_5_chars_max_ed_4_20200917"`, a 512-word list of words of max length 5 characters
all of which are at least an edit distance of four from every other word on the list.

#### hashFunction

The `hashFunction` field specifies the hash function to used to derive key seeds and secrets. The default is `"BLAKE2b"`.

```TypeScript
"hashFunction"?: "BLAKE2b" | "Argon2id"
```

`Argon2id` is a hash function designed to require not just computation, but also memory, in order to thwart hardware brute force attacks.[^1].  To derive secrets, the password parameter is set to the seed and the salt parameter is set to the concatenation of the type string ("Password", "Secret", "SymmetricKey", "UnsealingKey" or "SigningKey") followed by the derivation options JSON string. No null terminators or other separators are used.  The implementation uses the `argon2id_hash_raw` function internal to libsodium. with  When using `Argon2id`, you can also specify the memory limit and the number of passes to make through memory.

`BLAKE2b` applies the BLAKE2b hash function as the building block for HKDF function ([RFC5869](https://tools.ietf.org/html/rfc5869)) to allow for arbitrary-length outputs.  We set the HKDF input keying material (`IKM` parameter) to the seed string and the `info` parameter set to the concatenation of the type string ("Password", "Secret", "SymmetricKey", "UnsealingKey" or "SigningKey") followed by the derivation options JSON string.  We using BLAKE2b with a 32-byte output block as the underlying HMAC. The implementation uses the `crypto_generichash_blake2b` series of functions in libsodium) function with a 32 byte block and 32 0s for the `salt` used when deriving the `PRK` (see Step 1 in Section 2.2 of the [HKDF spec](https://tools.ietf.org/html/rfc5869)).

```TypeScript
"hashFunctionMemoryLimitInBytes": number // default 67108864
"hashFunctionMemoryPasses": number // default 2
```

The `hashFunctionMemoryLimitInBytes` field is the amount of memory that `Argon2id` will be required to iterate (pass) through
in order to compute the correct output (it will be rounded down to the nearest kilobyte),
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
the computational cost is on the order of the product of
`hashFunctionMemoryPasses` times `hashFunctionMemoryLimitInBytes`.
(The `hashFunctionMemoryPasses` field maps to the poorly-documented `opslimit` in `libsodium`. An examination of the source shows that opslimit is assigned to a parameter named `t_cost`, which in turn is assigned to `instance.passes` on line 56 of [argon2.c](https://github.com/jedisct1/libsodium/blob/7214dff083638604cd48e5c9ffc5704460192794/src/libsodium/crypto_pwhash/argon2/argon2.c).)


Since `BLAKE2b` is a single-iteration function, the
`hashFunctionMemoryLimitInBytes` and `hashFunctionMemoryPasses` fields must
not be set when it is used.

##### Hash defaults and recommendations

The default hash function is `BLAKE2b` as this library was designed for DiceKeys,
which are random and drawn from such a large number of possible values (~2^196)
to make `Argon2id` unnecessary.
This default ensures that keys can be re-derived cheaply
on just about any hardware platform.

Applications that need a more expensive key derivation to protect against
brute-forcing of the derivation algorithm will want to use `Argon2id`.

We purposely chose _not_ to support multiple iterations of `BLAKE2b`
via the `hashFunctionMemoryPasses` field, as applications that want to increase the
cost of key derivation to prevent brute forcing should use `Argon2id`.

### DiceKeys Hardware Fields

This Seeded Cryptography Library is oblivious to these fields, but they are documented
here to keep the specification from being split into too many locations.

#### excludeOrientationOfFaces

When using a DiceKey as a seed, the default seed string will be a 75-character string consisting of triples for each die in canonical order:
 1 The uppercase letter on the die
 2 The digit on the die
 3 The orientation relative to the top of the square in canonical form

If `excludeOrientationOfFaces` is set to `true`, the orientation character (the third member of each triple) will be
set to "?" before the canonical form is determined
(the choice of the top left corner that results in the human readable
form earliest in the sort order) and "?" will be the third character
in each triple.

This option exists because orientations may be harder for users to copy correctly than letters and digits are.
With this option on, should a user choose to manually copy the contents of a DiceKey and make an error
in copying an orientation, that error will not prevent them from re-deriving the specified key or secret.

```
    "excludeOrientationOfFaces"?: true | false // default false
```

### Authentication and Authorization Requirements

These fields specify who may generate keys and what they may do with them once generated.

#### allow

The most universal form of identifying apps and services is via components of [URL](https://en.wikipedia.org/wiki/URL)s: origins and paths.
The web, iOS, and Android all provide a means for one app to contact another website or on-device application by issuing an HTTPS request to a resource identified via an HTTPS URL, which will fail unless the operating system or browser is able to authenticate the recipient.
For intra-browser communication between web-apps, communication via postMessage provides authentication via origins.
Thus, the default way to restrict the use of a derived key or secret is via these web standards using the `allow` field.


```TypeScript
    "allow"?: {"host": string, "paths"?: string[]}[]
```

A request is allowed if any of the entries in the array matches the host and one of the paths from an entry in the list.

The specification uses hosts and not origins as the scheme must always be "https://".
Unless a custom port is in use, the host field is the same as the hostname (e.g. "example.com").
If the host field starts with "*.", then any subdomain will match, as will the domain that
follows the "*." prefix.  So, "*.example.com" is satisfied by both "sub.example.com" and "example.com."

For URL-based APIs (those where messages are passed via page loads, as opposed to postMessage requests),
the path of the URL to which the response will be sent must match one of the paths in the `paths` field.  Path specifications may end in "*", in which case
the path must start with the prefix before the "*".  For example, "https://example.com/iamgroot" satisfies path "/iam\*".
All paths must start with a "/" per web specifications, but if you forget to include the "/" the validator will assume you intended to include it.  If you do not specify a `paths` field, the default of `["/--derived-secret-api--/*"]`.

If the `allow` clause is not satisfied, the DiceKeys app must not send the response (unless it is allowed by `androidPackagePrefixesAllowed`, below).

Example:

```TypeScript
    "allow": [
        {"host": "dicekeys.org", "paths": ["/app/fido*"]},
        {"host": "dicekeys.com", "paths": ["/app/fido*"]}
    ]
```

By default, this field is unset and any client may use the key (though the seal operation supports UnsealingInstructions that include `allow`, protecting against data being unsealed and read by unauthorized clients.)

Alas, issuing a request via an HTTPS url only allows the client to authenticate the server. Operating systems like iOS do not provide support for the DiceKeys app receiving a request to authenticate the client. Rather, the app can only ensure that the response is sent to one of the authorized URLs. Attackers, and other clients that are not authorized, can issue requests and have keys, unsealed messages, or other data sent to the prefixes you authorize. The apps and services you offer at those prefixes must be written to throw out responses to requests that they did not issue, and do so without leaking any data to attackers.

Our DiceKeys client APIs generate 128-bit random request ID using APIs designed for cryptographic randomness, and throw out responses for requests from IDs that they did not issue, and so are designed to protect against such attacks. Further, operations performed by the DiceKeys app in response to API requests do not have side effects, beyond causing the user to load in their DiceKey if needed and respond to requests.

#### requireAuthenticationHandshake
To harden your app against unauthorized client requests, you can set the `requireAuthenticationHandshake` field.
```TypeScript
  "requireAuthenticationHandshake"?: boolean
```

Since the default is false, the only reason to include this field in your derivation options is to set it to true.

```TypeScript
  "requireAuthenticationHandshake": true
```

When set, clients will need to issue a handshake request to the API, and receive an authorization token (a random shared secret), before issuing other requests where the URL at which they received the token starts with one of the authorized prefixes. The DiceKeys app will map the authorization token to that URL and, when requests include that token, validate that the URL associated with the token has a valid prefix. The DiceKeys app will continue to validate that responses are also sent to a valid prefix. 

#### androidPackagePrefixesAllowed

While the Android platform supports issuing requests and receiving responses via URLs, the platform has better support for authentication via application package names. Specifically, an application receiving an explicit intent issued to its package receives an OS-validated package name of the client.  Authenticating clients via packages does not require a handshake, is faster, and potentially more secure.

If `androidPackagePrefixesAllowed` is set to a list of package prefixes, clients may contact the DiceKeys app on Android without going through the URL interface, need not have a URL on the `allow` list, and need not use a handshake even if `requireAuthenticationHandshake` is set to true.  If this value is set, `allow` should always be set, even if to an empty list.


```TypeScript
    "androidPackagePrefixesAllowed"?: string[],
```

For example:
```TypeScript
{
    "type": "Secret",
    "androidPackagePrefixesAllowed": [
        "org.dicekeys.apps.fido",
        "com.dicekeys.apps.fido"
    ],
    "allow": [
        {"host": "dicekeys.org", "paths": ["/app/fido"]},
        {"host": "dicekeys.com", "paths": ["/app/fido"]}
    ]
}
```

The API will terminate prefixes set via "`androidPackagePrefixesAllowed`" with dots, and
and terminate client package IDs with dots, to prevent extension attacks.  In other words,
if you set the prefix `com.example`, the API will test if `com.example.` is a prefix
of the string composed by concatenating a period onto your client application's package name.
So, if an attacker registers the package name `com.exampleattacker`, they will not be
able to match the `com.example` prefix.

```TypeScript
{
    "requireUsersConsent": {
        "question": "Do you want use \"8fsd8pweDmqed\" as your SpoonerMail account password and remove your current password?",
        "actionButtonLabels": {
            "allow": "Make my password \"8fsd8pweDmqed\"",
            "deny": "No" 
        }
    }
}
```

#### clientMayRetrieveKey

By default, the DiceKeys app will forbid clients from retrieving a
SigningKey, SymmetricKey, or UnsealingKey
even when all authentication restrictions (e.g., `allow`) are met.

To derive keys that an authorized client will be permitted to retrieve, use the `clientMayRetrieveKey` field.

```TypeScript
    "clientMayRetrieveKey"?: boolean
```

Since the default is false, it is primarily used as follows:

```TypeScript
    "clientMayRetrieveKey": true
```

Clients can use this field to generate keys that they can get a copy of,
use for any purpose they want without having to interact with the DiceKeys API or app,
yet which they can ask the DiceKeys app to recover for them should the key be lost.
For example, an end-to-end encrypted app could generate a key pair it uses for
communication and storage, keep the key locally, but ask the DiceKeys app to re-derive
it if the user is recovering their data on a new device.
