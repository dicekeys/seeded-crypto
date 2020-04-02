/************************************
 * This is a small modification to crypto_box_seal.c in libsodium to
 * allow a salt to be added to public-key sealed boxes so that
 * DiceKeys can support messages that require processing of
 * post-decryption instructions
 */

int crypto_box_salted_seal(
  unsigned char* c, const unsigned char* m,
  unsigned long long mlen, const unsigned char* pk,
  const char* salt,
  const size_t salt_length
);

int
crypto_box_salted_seal_open(
  unsigned char* m, const unsigned char* c,
  unsigned long long clen,
  const unsigned char* pk, const unsigned char* sk,
  const char* salt, const size_t salt_length
);
