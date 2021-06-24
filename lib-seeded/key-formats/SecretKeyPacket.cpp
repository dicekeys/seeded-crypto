#include "OpenPgpPacket.hpp"
#include "SecretKeyPacket.hpp"
 extern "C" {
  #include "rijndael-alg-fst.h"
 }
 
ByteBuffer aes128(const ByteBuffer& key, ByteBuffer &plaintextBlock) {
  const int keySizeInBits = 128;
  const int nRoundsIf128BitKey = 10;
  u32 rk[/*4*(Nr + 1)*/ (4 * (nRoundsIf128BitKey +1))];
  rijndaelKeySetupEnc(rk, key.data(), keySizeInBits);
  ByteBuffer ciphertextBlock(16);
  rijndaelEncrypt(rk, nRoundsIf128BitKey, plaintextBlock.data(), (ubyte*) ciphertextBlock.data());
  return ciphertextBlock;
}

const ByteBuffer calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey) {
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.5.3
  // 5.5.3.  Secret-Key Packet Formats
  // ...
  // * If the string-to-key usage octet is zero or 255, then a two-octet
  //   checksum of the plaintext of the algorithm-specific portion (sum
  //   of all octets, mod 65536)...
  uint16_t checksum = 0;
  for (size_t i = 0; i < wrappedSecretKey.byteVector.size(); i ++) {
    // arithmetic on two-byte unsigned shorts is already mod 65536
    // so we don't have to perform the mod operation
    const ubyte byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  ByteBuffer checksumBuffer;
  checksumBuffer.write16Bits(checksum);
  return checksumBuffer;
}

const ByteBuffer openPgpStyleCfpAes128Sha256(
  const ByteBuffer &plaintext,
  const std::string passphrase
) {
  const size_t blockSize = 16;
  const ByteBuffer sha256OfPassphrase = ByteBuffer(passphrase).SHA2_256();

  // |    3.7.1.1.  Simple S2K
  // |    Simple S2K hashes the passphrase to produce the session key.  ... 
  // |    If the hash size is greater than the session key
  // |    size, the high-order (leftmost) octets of the hash are used as the
  // |    key.
  ByteBuffer aes128BitKey = sha256OfPassphrase.slice(0, blockSize);

  // |    OpenPGP does symmetric encryption using a variant of Cipher Feedback
  // |    mode (CFB mode).  This section describes the procedure it uses in
  // |    detail.  This mode is what is used for Symmetrically Encrypted Data
  // |    Packets; the mechanism used for encrypting secret-key material is
  // |    similar, and is described in the sections above.
  // |
  // |    In the description below, the value BS is the block size in octets of
  // |    the cipher.  Most ciphers have a block size of 8 octets.  The AES and
  // |    Twofish have a block size of 16 octets.  Also note that the
  // |    description below assumes that the IV and CFB arrays start with an
  // |    index of 1 (unlike the C language, which assumes arrays start with a
  // |    zero index).
  // |
  // |    OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
  // |    prefixes the plaintext with BS+2 octets of random data, such that
  // |    octets BS+1 and BS+2 match octets BS-1 and BS.  It does a CFB
  // |    resynchronization after encrypting those BS+2 octets.
  // |
  // |    Thus, for ... an algorithm with a block size of 16 octets
  // |    (128 bits), the IV is 18 octets long, and octets 17 and 18 replicate
  // |    octets 15 and 16.  Those extra two octets are an easy check for a
  // |    correct key.

  // Since we won't necessarily have a reliable random number generator in WebAssembly,
  // we'll use the second half of the hash for which the first half was used for the key
  ByteBuffer prefixForPlaintext = sha256OfPassphrase.slice(blockSize, blockSize);
  // Since the prefix used bytes 16-31 of the hash, replicating octets 15 and 16
  // can be done by replicating bytes 30 and 31 of the hash.
  prefixForPlaintext.append(sha256OfPassphrase.slice((2 * blockSize) - 2, 2));
  ByteBuffer ciphertext;
  // |    Step by step, here is the procedure:
  // |
  // |    1.   The feedback register (FR) is set to the IV, which is all zeros.
  ByteBuffer feedbackRegister(blockSize);
  // |
  // |    2.   FR is encrypted to produce FRE (FR Encrypted).  This is the
  // |         encryption of an all-zero value.
  ByteBuffer feedbackRegisterEncrypted = aes128(aes128BitKey, feedbackRegister);
  // |
  // |    3.   FRE is xored with the first BS octets of random data prefixed to
  // |         the plaintext to produce C[1] through C[BS], the first BS octets
  // |         of ciphertext.
  for (int byte = 0; byte < blockSize; byte++) {
    ciphertext.writeByte(feedbackRegisterEncrypted.byteVector[byte] ^ prefixForPlaintext.byteVector[byte]);
  }
  // |
  // |    4.   FR is loaded with C[1] through C[BS].
  feedbackRegister = ciphertext.slice(ciphertext.size() - blockSize, blockSize);
  // |
  // |    5.   FR is encrypted to produce FRE, the encryption of the first BS
  // |         octets of ciphertext.
  feedbackRegisterEncrypted = aes128(aes128BitKey, feedbackRegister);
  // |
  // |    6.   The left two octets of FRE get xored with the next two octets of
  // |         data that were prefixed to the plaintext.  This produces C[BS+1]
  // |         and C[BS+2], the next two octets of ciphertext.
  for (int byte = 0; byte < 2; byte++) {
    ciphertext.writeByte(feedbackRegisterEncrypted.byteVector[byte] ^ prefixForPlaintext.byteVector[(blockSize-2) + byte]);
  }

  // |    7.   (The resynchronization step) FR is loaded with C[3] through
  // |         C[BS+2].
  // (Dang! This standard seems unnecessarily convoluted.)
  size_t indexIntoPlaintext = 0;
  while (indexIntoPlaintext < plaintext.size()) {
    feedbackRegister = ciphertext.slice(ciphertext.size() - blockSize, blockSize);
  // |
  // |    8.   FR is encrypted to produce FRE.
    aes128(aes128BitKey, feedbackRegister);
  // |
  // |    9.   FRE is xored with the first BS octets of the given plaintext,
  // |         now that we have finished encrypting the BS+2 octets of prefixed
  // |         data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
  // |         octets of ciphertext.
    for (int byte = 0; byte < blockSize && indexIntoPlaintext < plaintext.size(); byte++) {
      ciphertext.writeByte(feedbackRegister.byteVector[byte] ^ plaintext.byteVector[indexIntoPlaintext++]);
    }
  }
  // |
  // |    10.  FR is loaded with C[BS+3] to C[BS + (BS+2)]
  // |
  // |    11.  FR is encrypted to produce FRE.
  // |
  // |    12.  FRE is xored with the next BS octets of plaintext, to produce
  // |         the next BS octets of ciphertext.  These are loaded into FR, and
  // |         the process is repeated until the plaintext is used up.
  return ciphertext;
}


const ByteBuffer createSecretKeyPacketBody(
  const ByteBuffer& secretKey,
  const PublicKeyPacket& publicKeyPacket,
  uint32_t timestamp,
  const std::string &passphrase = ""
) {
  ByteBuffer packetBody;
  const KeyConfiguration& keyConfiguration = publicKeyPacket.keyConfiguration;
// 5.5.1.3.  Secret-Key Packet (Tag 5)
//
//    A Secret-Key packet contains all the information that is found in a
//    Public-Key packet, including the public-key material, but also
//    includes the secret-key material after all the public-key fields.
  packetBody.append(publicKeyPacket.body);
  // 5.5.3.  Secret-Key Packet Formats

  // |    The Secret-Key and Secret-Subkey packets contain all the data of the
  // |    Public-Key and Public-Subkey packets, with additional algorithm-
  // |    specific secret-key data appended, usually in encrypted form.
  // |
  // |    The packet contains:
  // |
  // |    *  A Public-Key or Public-Subkey packet, as described above.

  // |  *  One octet indicating string-to-key usage conventions.  Zero
  // |     indicates that the secret-key data is not encrypted. 255 or 254
  // |     indicates that a string-to-key specifier is being given.  Any
  // |     other value is a symmetric-key encryption algorithm identifier.  A
  // |     version 5 packet MUST NOT use the value 255.
  const bool encrypt = passphrase.size() > 0;
  packetBody.writeByte(encrypt ? SECRET_KEY_ENCRYPTION_ON : SECRET_KEY_ENCRYPTION_OFF);

  if (keyConfiguration.version == VERSION_5) {
    // |  *  Only for a version 5 packet, a one-octet scalar octet count of the
    // |    next 4 optional fields.
    packetBody.writeByte(encrypt ? 4 : 0);
  }

  if (encrypt) { // if to be encrypted
    // |  *  [Optional] If string-to-key usage octet was 255 or 254, a one-
    // |     octet symmetric encryption algorithm.
    packetBody.writeByte(keyConfiguration.keyEncryptionAlgorithm);
    // |  *  [Optional] If string-to-key usage octet was 255 or q, a string-
    // |     to-key specifier.  The length of the string-to-key specifier is
    // |     implied by its type, as described above.

    // |         3.7.1.1.  Simple S2K

    // |        This directly hashes the string to produce the key data.  See below
    // |        for how this hashing is done.

    // |          Octet 0:        0x00
    // |          Octet 1:        hash algorithm
    packetBody.writeByte(0);
    packetBody.writeByte(keyConfiguration.keyEncryptionHashAlgorithm);

    // |  *  [Optional] If secret data is encrypted (string-to-key usage octet
    // |     not zero), an Initial Vector (IV) of the same length as the
    // |     cipher's block size.
    packetBody.append(ByteBuffer(16));
  }

  // Append the actual secret key material, in MPI format as specified above
  ByteBuffer wrappedSecretKey = wrapKeyAsMpiFormat(secretKey);
  ByteBuffer keyDataOptionallyEncrypted = encrypt ?
      // |      If the string-to-key usage octet was
      // |      254, then a 20-octet SHA-1 hash of the plaintext of the algorithm-
      // |      specific portion.  This checksum or hash is encrypted together
      // |      with the algorithm-specific fields (if string-to-key usage octet
      // |      is not zero).  Note that for all other values, a two-octet
      // |      checksum is required.
    openPgpStyleCfpAes128Sha256(ByteBuffer::concat(wrappedSecretKey, wrappedSecretKey.SHA1()), passphrase) :
      // |  5.5.3.  Secret-Key Packet Formats
      // |  ...
      // |   *  If the string-to-key usage octet is zero or 255, then a two-octet
      // |      checksum of the plaintext of the algorithm-specific portion (sum
      // |      of all octets, mod 65536).  ...
    ByteBuffer::concat(wrappedSecretKey, calculateCheckSumOfWrappedSecretKey(wrappedSecretKey));

  if (keyConfiguration.version == VERSION_5) {
    // |  *  Only for a version 5 packet, a four-octet scalar octet count for
    // |     the following secret key material.  This includes the encrypted
    // |     SHA-1 hash or AEAD tag if the string-to-key usage octet is 254 or
    // |     253.
    packetBody.write32Bits(keyDataOptionallyEncrypted.size());
  }

  packetBody.append(keyDataOptionallyEncrypted);
  return packetBody;
}

SecretKeyPacket::SecretKeyPacket(
  const PublicKeyPacket& publicKeyPacket,
  const ByteBuffer& _secretKey,
  uint32_t _timestamp,
  const std::string &passphrase
) : OpenPgpPacket(PTAG_SECRET),
  secretKey(_secretKey),
  timestamp(_timestamp),
  body(createSecretKeyPacketBody(secretKey, publicKeyPacket, timestamp, passphrase))
  {}

const ByteBuffer& SecretKeyPacket::getBody() const { return body; };


