# JSON Format for Unsealing Instructions {#unsealing_instructions_format}

The SealingKey.seal and SymmetricKey.seal operations support an optional _unsealingInstructions_ string parameter.
If the parameter is provided when a message is sealed, the same value must be present when the _unseal_
operation is called.  The field is stored in plaintext (unencrypted) in the _unsealingInstructions_
field of the PackagedSealedMessage returned by the _seal_ operation. (If the field is not provided, it is treated
as an empty string.)

The Seeded Cryptography Library is agnostic to the format and value of this string, so long as
the same string is used both during sealing and unsealing.

However, since it's format mirrors @ref recipe_format, and the DiceKeys API Fields
are currently documented here, we currently document the JSON format for Unsealing Instructions
fields below.

### Authentication and authorization requirements

The unsealing instructions support require authentication requirements via the
`allow`, `requireAuthenticationHandshake`, and `androidPackagePrefixesAllowed` fields
from the recipe format.
<!-- 
#### requireUsersConsent

You can instruct the DiceKeys app to display a consent question to the user
before unsealing the message and returning it to the client app.
You specify the `question`, the text for the button that will `allow` the data
to be unsealed, and the text for the button that will `deny` the client access
to the unsealed data.
The language of the warning is chosen by the sealer of the message, which should use
it's best knowledge about the language of the user at the time of sealing.

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
``` -->
