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

### Authentication and authorization requirements

The unsealing instructions support require authentication requirements via the
`urlPrefixesAllowed`, `requireAuthenticationHandshake`, and `androidPackagePrefixesAllowed` fields
from the derivation options format.

#### requireUsersConsent

Yyou can instruct the DiceKeys app to display a consent question to the user
before unsealing the message and returning it to the client app.
The message should be in the client's preferred language at time of sealing.

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