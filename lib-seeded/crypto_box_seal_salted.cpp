/************************************
 * This started as a small modification to crypto_box_seal.c
 * in libsodium to allow a salt to be added to public-key
 * sealed boxes so that DiceKeys can support messages that
 * require processing of post-decryption instructions.
 * 
 * However, Stuart couldn't help but add lots of documentation.
 */
#include <string.h>
#include "sodium.h"
#include "crypto_box_seal_salted.h"

/**
 * Generate a nonce to use for sealing a message sent
 * from the holder of one curve22519 public key to the
 * keyhold of another curve22519 public key, with an optiona
 * salt.  If no salt is present, set salt_length to 0.
 **/
void _crypto_box_seal_nonce_salted(
  unsigned char *output_nonce,
  const unsigned char *senders_public_key, const unsigned char *recipients_public_key,
  const char* salt,
  const size_t salt_length
) {
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
    crypto_generichash_update(&st, senders_public_key, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_update(&st, recipients_public_key, crypto_box_PUBLICKEYBYTES);
    if (salt_length > 0) {
      crypto_generichash_update(&st, (const unsigned char*) salt, salt_length);
    }
    crypto_generichash_final(&st, output_nonce, crypto_box_NONCEBYTES);
}

/**
 * Seal a message so that it can only be
 * opened/authenticated a recipient who holds the
 * private key corresponding to
 * recipients_curve22519_public_key.
 * Use a salt to generate the nonce so that
 * the message will only be decrypted if the same
 * salt is provided.
 * 
 * The output ciphertext buffer should be of size
 * message_length + crypto_box_SEALBYTES
 */
int
crypto_box_salted_seal(
  unsigned char *output_ciphertext,
  const unsigned char *message,
  unsigned long long message_length,
  const unsigned char *recipients_curve22519_public_key,
  const char* salt,
  const size_t salt_length  
)
{
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char epk[crypto_box_PUBLICKEYBYTES];
    unsigned char esk[crypto_box_SECRETKEYBYTES];
    int           ret;

    // generate an ephemeral public/private key pair
    if (crypto_box_keypair(epk, esk) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    memcpy(output_ciphertext, epk, crypto_box_PUBLICKEYBYTES);
    _crypto_box_seal_nonce_salted(nonce, epk, recipients_curve22519_public_key, salt, salt_length);
    ret = crypto_box_easy(output_ciphertext + crypto_box_PUBLICKEYBYTES,
                          message, message_length,
                          nonce, recipients_curve22519_public_key, esk);
    sodium_memzero(esk, sizeof esk);
    sodium_memzero(epk, sizeof epk);
    sodium_memzero(nonce, sizeof nonce);

    return ret;
}

int
crypto_box_salted_seal_open(
  unsigned char *m, const unsigned char *c,
  unsigned long long clen,
  const unsigned char *pk, const unsigned char *sk,
  const char* salt, const size_t salt_length
)
{
    unsigned char nonce[crypto_box_NONCEBYTES];

    if (clen < crypto_box_SEALBYTES) {
        return -1;
    }
    _crypto_box_seal_nonce_salted(nonce, c, pk, salt, salt_length);

    // COMPILER_ASSERT(crypto_box_PUBLICKEYBYTES < crypto_box_SEALBYTES);
    return crypto_box_open_easy(m, c + crypto_box_PUBLICKEYBYTES,
                                clen - crypto_box_PUBLICKEYBYTES,
                                nonce, c, sk);
}

