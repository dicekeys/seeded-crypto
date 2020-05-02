# Introduction {#introduction}

This Seeded Cryptography Library was written to support the DiceKeys project.

It is an _object oriented_ cryptographic library, with keys
(SymmetricKey, UnsealingKey & SealingKey, SigningKey & SignatureVerificationKey)
as first-class objects,
and cryptographic operations implemented as methods on those keys.
It also supports a derived Secret class, into which
cryptographic-strength secrets can be derived and shared with
clients that want to implement their own operations.

```cpp
const SymmetricKey(...);
const std::string plaintext("Wait long enough, and grilled cheese becomes its own spoonerism.");
const auto sealed_message = sk.seal(plaintext);
```

All keys and secrets are derived from _seed_ strings, using options specified in
the @ref derivation_options_format. This is different from most other libraries,
where keys are generated using a random number generator. You can still create
keys using the random number generator with this library, but you would do so
by having the generator create a random seed string.

```cpp
const UnsealingKey private_key(
    // The seed string. Hopefully better than Randall Munroe's
    "valid equine capacitor paperclip wrong bovine ground luxury",
    // Since the seed is still a bit short, use a memory-hard
    // derivation function to derive the key, not just a simple hash.
    "{hashFunction=\"Argon2id\"}"
);
```

Like [LibSodium](https://libsodium.gitbook.io/doc/), the cryptogrpahic library
on which the Seeded Cryptography Library it built, this library is opnionated.
It offers a small number of safe options to direct users to good choices, rather
than offering a wide variety with some potentially-dangerous choices.
For example, instead of _encrypt_ and
_decrypt_ operations, the library supports only _seal_ and _unseal_.
The difference is that sealing a message always attaches a message authentication code (MAC)
to the ciphertext, and unsealing always ensures that the ciphertext has not been modified
by checking the MAC.
The seal operation also packages the ciphertext along with the derivation options
needed to derive the key needed to unseal the message from the seed.

When sealing data, you can also attach a string that must be known
to anyone unsealing the message.  This is separate from the key and is
included in plaintext in PackagedSealedMessage returned by the seal operation.
You can use it, for example, to attach
instructions about how such messages should be treated when unsealing.
Those instructions are not public, and not encrypted. For example:

```cpp
const SymmetricKey sk(...);
const std::string plaintext("Wait long enough, and grilled cheese becomes its own spoonerism.")
const std::string unsealing_instructions(
    "Unsealed messages should be shared only with those who like wordplay."
);
const auto sealed_message = sk.seal(plaintext, unsealing_instructions);
```

All keys and mesage packages in this library can be easily serialized into
either JSON format or a binary format, and deserialized,
freeing those using the library from having to implement their own
serialization methods.

```cpp
const auto public_key = SealingKey.fromJson(SealingKeyAsJson);
const SodiumBuffer public_key_as_binary = public_key.toSerializedBinaryForm();
const SealingKey copy_of_public_key = SealingKey.fromSerializedBinaryForm(public_key_as_binary);
```

