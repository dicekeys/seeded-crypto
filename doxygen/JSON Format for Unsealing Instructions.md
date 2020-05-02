# JSON Format for Unsealing Instructions {#unsealing_instructions_format}

The SealingKey.seal and SymmetricKey.seal operations support a an optional _unsealingInstructions_ string parameter.
If the parameter is provided when a message is sealed, the same value must be present when the _unseal_
operation is called.  The field is stored in plaintext (unencrypted) in the _unsealingInstructions_
field of the PackagedSealedMessage returned by the _seal_ operation. (If the field is not provided, it is treated
as an empty string.)

The Seeded Cryptography Library is agnostic to the format and value of this string, so long as
the same string is used both during sealing and unsealing.

However, since it's format mirrors @ref derivation_options_format, and the DiceKeys API Fields
are currently documented here, we currently document the JSON format for Unsealing Instructions
fields below.

### DiceKeys API Fields

The fields provide instructions the DiceKeys app about when unsealed data
may be released to a client application.

#### restrictions

This field mirrors the field in @ref derivation_options_format, restricting the set
of parties allowed to see an unsealed message.

```TypeScript
    "restrictions"?: {
        "androidPackagePrefixesAllowed"?: string[],
        "urlPrefixesAllowed"?: string[]
    }
```

#### requireUsersConsent

If set, the DiceKeys app should display the message to the user before allowing
the unsealed message to be returned to the requesting client app.
The message should be in the user's native language.

```TypeScript
    "requireUsersConsent"?: {
        "question": String,
        "actionButtonLabels": {
            "allow": String,
            "decline": String 
        }
    }
```

For example
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