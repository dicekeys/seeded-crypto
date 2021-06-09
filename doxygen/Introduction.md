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
const SymmetricKey sk(...);
const std::string plaintext("Wait long enough, and grilled cheese becomes its own spoonerism.");
const auto sealed_message = sk.seal(plaintext);
```

All keys and secrets are derived from _seed_ strings, using options specified in
the @ref recipe_format. This is different from most other libraries,
where keys are generated using a random number generator. You can still create
keys using the random number generator with this library, but you would do so
by having the generator create a random seed string.

```cpp
const UnsealingKey private_key = UnsealingKey::deriveFromSeed(
    // The seed string. Hopefully better than Randall Munroe's
    "valid equine capacitor paperclip wrong bovine ground luxury",
    // Since the seed is still a bit short, use a memory-hard
    // derivation function to derive the key, not just a simple hash.
    "{hashFunction:\"Argon2id\"}"
);
```

Like [LibSodium](https://libsodium.gitbook.io/doc/), the cryptographic library
on which the Seeded Cryptography Library is built, this library is opinionated.
It offers a small number of safe options to direct users to good choices, rather
than offering a wide variety with some potentially-dangerous choices.
For example, instead of _encrypt_ and
_decrypt_ operations, the library supports only _seal_ and _unseal_.
The difference is that sealing a message always attaches a message authentication code (MAC)
to the ciphertext, and unsealing always ensures that the ciphertext has not been modified
by checking the MAC.
The seal operation also packages the ciphertext along with the recipe
needed to derive the key needed to unseal the message from the seed.

When sealing data, you can also attach a string that must be known
to anyone unsealing the message.  This is separate from the key and is
included in plaintext in PackagedSealedMessage returned by the seal operation.
You can use it, for example, to attach
instructions about how such messages should be treated when unsealing.
Those instructions are public, and not encrypted. For example:

```cpp
const SymmetricKey sk(...);
const std::string plaintext("Wait long enough, and grilled cheese becomes its own spoonerism.")
const std::string unsealing_instructions(
    "Unsealed messages should be shared only with those who like wordplay."
);
const auto sealed_message = sk.seal(plaintext, unsealing_instructions);
```

All keys and packaged messages in this library can be easily serialized into
either JSON format or a binary format, and deserialized,
freeing those using the library from having to implement their own
serialization methods.

```cpp
const auto public_key = SealingKey.fromJson(SealingKeyAsJson);
const SodiumBuffer public_key_as_binary = public_key.toSerializedBinaryForm();
const SealingKey copy_of_public_key = SealingKey.fromSerializedBinaryForm(public_key_as_binary);
```

## Seeding with DiceKeys

DiceKeys are converted into strings by generating a three-character ASCII/UTF8 triple for each die:

  - An uppercase letter: '`A`'-'`Z`' excluding '`Q`'
  - An digit: '`1`'-'`6`' (not to be confused for )
  - A lowercase orientation letter:
      - '`t`' if the top of the die as read faces the *t*op of box (it is upright)
      - '`r`' if the top of the die as read faces the *r*ight side of box, or 90 degrees clockwise from upright
      - '`b`' if the top of the die as read faces the *b*ottom of box, or 180 degrees clockwise from upright
      - '`l`' if the top of the die as read faces the *l*eft side of box, or 270 degrees clockwise from upright.

    This convention matches the naming conventions of CSS boxes (e.g. `margin-[top|left|bottom|right]`), rectangles in the browser Document Object Model (DOM), and forms the pronounceable acronym `trbl` which lends itself to the memory mnemonic of "[right here in river city.](https://en.wikipedia.org/wiki/Ya_Got_Trouble)"

The three-character triples are concatenated English reading order, starting at the top left and proceeding across the row, and then down each row until reaching the bottom right.  A DiceKey with 25 dice will yield a 75-character string.

The DiceKey itself may be read in one of four possible orientations, and changing the orientation at which a DiceKey is read should not change the secrets it generates.
Thus, the seed string should represent a _canonical_ orientation of the key.

While DiceKeys hardware with a hinged lid may seemingly have a predefined canonical top that might be detectable to a machine vision algorithm, not all DiceKeys hardware will have a canonical top.  For example, a DiceKey made from stickers (STICKIES) are squares and have no defined top.

Thus, the canonical top left of a DiceKey is the one that produces a string that representation with the earliest sort order.
One cannot simply assume that a corner die alone will be sufficient to indicate sort order (e.g., assuming that a corner with `A1` must be the top left), because a DiceKey could have more than one `A`.  (DiceKeys are currently packaged with 25 unique dice, but users should be allowed to two sets together when generating two DiceKeys and still expect the software to function reliably.)
Rather, to determine the correct seed string algorithmically, generate all four possible string representations of the DiceKey and take the earliest in sort order.
