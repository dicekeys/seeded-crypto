#pragma once
#include <vector>
#include "ByteBuffer.hpp"


const ubyte VERSION_4 = 0x04;
const ubyte VERSION_5 = 0x05;


const uint8_t ALGORITHM_HASH_SHA_256 = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]


const ubyte ALGORITHM_EC_DH = 0x12; // RFC4880-bis-10 - Section 9.1 - 18 (0x12) - ECDH [RFC8032]
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-9.2
const std::vector<ubyte> ALGORITHM_EC_DH_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID

const ubyte ALGORITHM_ED_DSA = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
const std::vector<ubyte> ALGORITHM_ED_DSA_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID


//  7 | AES with 128-bit key [AES]            |
const ubyte SYMMETRIC_ALGORITHM_AES_KEY_128 = 0x07;
//  8 | AES with 192-bit key                  |
const ubyte SYMMETRIC_ALGORITHM_AES_KEY_192 = 0x08;
//  9 | AES with 256-bit key                  |
const ubyte SYMMETRIC_ALGORITHM_AES_KEY_256 = 0x09;


// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-03#section-9.5
// 9.5.  Hash Algorithms
//
//        +============+================================+=============+
//        |         ID | Algorithm                      | Text Name   |
//        +============+================================+=============+
//        |          1 | MD5 [HAC]                      | "MD5"       |
// Homie don't play broken hash algorithms that date back to the era of
// "In Living Color". Even "Doogie Houser MD" aged better than MD5.
//        +------------+--------------------------------+-------------+
//        |          2 | SHA-1 [FIPS180]                | "SHA1"      |
// You'd use a hash algorithm that dates back to the era of
// "Wayne's World"? Sha right? No, Sha wrong.
//        +------------+--------------------------------+-------------+
//        |          3 | RIPE-MD/160 [HAC]              | "RIPEMD160" |
// 24 years after HAC, this no longer seems so RIPE.
//        +------------+--------------------------------+-------------+
//        |          4 | Reserved                       |             |
// After the first three on this list, I also have many reservations
// before we continue.
//        +------------+--------------------------------+-------------+
//        |          5 | Reserved                       |             |
//        +------------+--------------------------------+-------------+
//        |          6 | Reserved                       |             |
//        +------------+--------------------------------+-------------+
//        |          7 | Reserved                       |             |
//        +------------+--------------------------------+-------------+
//        |          8 | SHA2-256 [FIPS180]             | "SHA256"    |
const ubyte HASH_ALGORITHM_SHA2_256 = 8;
//        +------------+--------------------------------+-------------+
//        |          9 | SHA2-384 [FIPS180]             | "SHA384"    |
const ubyte HASH_ALGORITHM_SHA2_384 = 9;
//        +------------+--------------------------------+-------------+
//        |         10 | SHA2-512 [FIPS180]             | "SHA512"    |
const ubyte HASH_ALGORITHM_SHA2_512 = 10;
//        +------------+--------------------------------+-------------+
//        |         11 | SHA2-224 [FIPS180]             | "SHA224"    |
const ubyte HASH_ALGORITHM_SHA2_224 = 11;
//        +------------+--------------------------------+-------------+
//        |         12 | SHA3-256 [FIPS202]             | "SHA3-256"  |
const ubyte HASH_ALGORITHM_SHA3_256 = 12;
//        +------------+--------------------------------+-------------+
//        |         13 | Reserved                       |             |
//        +------------+--------------------------------+-------------+
//        |         14 | SHA3-512 [FIPS202]             | "SHA3-512"  |
const ubyte HASH_ALGORITHM_SHA3_512 = 14;


// 5.2.3.21.  Key Flags

//    (N octets of flags)

//    This subpacket contains a list of binary flags that hold information
//    about a key.  It is a string of octets, and an implementation MUST
//    NOT assume a fixed size.  This is so it can grow over time.  If a
//    list is shorter than an implementation expects, the unstated flags
//    are considered to be zero.  The defined flags are as follows:

//    First octet:

//         +======+=================================================+
//         | flag | definition                                      |
//         +======+=================================================+
//         | 0x01 | This key may be used to certify other keys.     |
const ubyte KEY_FLAG_OCTET1_CERTIFY_OTHER_KEYS = 0x01;
//         +------+-------------------------------------------------+
//         | 0x02 | This key may be used to sign data.              |
const ubyte KEY_FLAG_OCTET1_SIGN_DATA = 0x02;
//         +------+-------------------------------------------------+
//         | 0x04 | This key may be used to encrypt communications. |
const ubyte KEY_FLAG_OCTET1_ENCRYPT_COMMUNICATIONS = 0x04;
//         +------+-------------------------------------------------+
//         | 0x08 | This key may be used to encrypt storage.        |
const ubyte KEY_FLAG_OCTET1_ENCRYPT_STORAGE = 0x08;
//         +------+-------------------------------------------------+
//         | 0x10 | The private component of this key may have been |
//         |      | split by a secret-sharing mechanism.            |
const ubyte KEY_FLAG_OCTET1_PRIVATE_KEY_SPLIT_VIA_SECRET_SHARING = 0x10;
//         +------+-------------------------------------------------+
//         | 0x20 | This key may be used for authentication.        |
const ubyte KEY_FLAG_OCTET1_MAY_BE_USED_FOR_AUTHENTICATION = 0x20;
//         +------+-------------------------------------------------+
//         | 0x80 | The private component of this key may be in the |
//         |      | possession of more than one person.             |
const ubyte KEY_FLAG_OCTET1_MAY_BE_IN_POSSESSION_OF_MORE_THAN_ONE_PERSON = 0x80;
//         +------+-------------------------------------------------+

// |       +======+==========================+
// |       | flag | definition               |
// |       +======+==========================+
// |       | 0x04 | Reserved (ADSK).         |
// |       +------+--------------------------+
// |       | 0x08 | Reserved (timestamping). |
// |       +------+--------------------------+

// | 5.2.3.24.  Features
// |       +=========+============================================+
// |       | feature | definition                                 |
// |       +=========+============================================+
// |       | 0x01    | Modification Detection (packets 18 and 19) |
const ubyte FEATURE_MODIFICATION_DETECTION = 0X01;
// |       +---------+--------------------------------------------+
// |       | 0x02    | Reserved (AEAD Data & v5 SKESK)            |
// |       +---------+--------------------------------------------+
// |       | 0x04    | Version 5 Public-Key Packet format and     |
// |       |         | corresponding new fingerprint format       |
const ubyte FEATURE_V5_PUBLIC_KEY_PACKET_AND_FINGERPRINT_FORMAT = 0X04;
// |       +---------+--------------------------------------------+


const ubyte S2K_SPECIFIER_SIMPLE = 0;
const ubyte S2K_SPECIFIER_SALTED = 1;
const ubyte S2K_SPECIFIER_ITERATED_AND_SALTED = 3;

class KeyConfiguration {
public:
  // The public key algorithm
  ubyte algorithm;
  // The public key curve
  std::vector<ubyte> curve;
  // The key/signature packet version (4 is widely supported in 2021, 5 is emerging)
  ubyte version = VERSION_5;


  // The symmetric key encryption algorithm used for encrypting secret keys.
  // We're currently only supporting AES_128, but this is here as a const
  // to show the path to adding other options in the future.
  const ubyte keyEncryptionAlgorithm = SYMMETRIC_ALGORITHM_AES_KEY_128;

  // The hash algorithm used to turn a passphrase into a key for encrypting
  // private keys.
  // We're currently only supporting SHA2_256, but this is in KeyConfiguration
  // as a const so that the path to supporting other options later is more clear.
  const ubyte keyEncryptionHashAlgorithm = HASH_ALGORITHM_SHA2_256;

  std::vector<ubyte> keyFlags = {
    ( 
      KEY_FLAG_OCTET1_CERTIFY_OTHER_KEYS |
      KEY_FLAG_OCTET1_MAY_BE_USED_FOR_AUTHENTICATION |
      KEY_FLAG_OCTET1_ENCRYPT_COMMUNICATIONS |
      KEY_FLAG_OCTET1_ENCRYPT_STORAGE
    )
    // default does not include second octet, leaving all flags 0
  };
  std::vector<ubyte> preferredSymmetricAlgorithms = {
    SYMMETRIC_ALGORITHM_AES_KEY_256,
    SYMMETRIC_ALGORITHM_AES_KEY_192,
    SYMMETRIC_ALGORITHM_AES_KEY_128
  };
  std::vector<ubyte> preferredHashAlgorithms = {
    HASH_ALGORITHM_SHA2_512,
    HASH_ALGORITHM_SHA2_384,
    HASH_ALGORITHM_SHA2_256
  };
  std::vector<ubyte> preferredCompressionAlgorithms = {
    0x03, // BZip2 (0x3)
    0x02, // ZLIB (0x2)
    0x01  // ZIP (0x1)
  };
  std::vector<ubyte> features = {
    FEATURE_MODIFICATION_DETECTION, // Modification detection (0x1),
    FEATURE_V5_PUBLIC_KEY_PACKET_AND_FINGERPRINT_FORMAT
  };
  std::vector<ubyte> keyServerPreferences = {
    0x80 // No-modify (0x80)
  };
};

class EdDsaKeyConfiguration : public KeyConfiguration {
public:
  EdDsaKeyConfiguration() {
    algorithm = ALGORITHM_ED_DSA;
    curve = ALGORITHM_ED_DSA_CURVE_OID_25519;
  }
};

class EcDhKeyConfiguration : public KeyConfiguration {
public:
  EcDhKeyConfiguration() {
    algorithm = ALGORITHM_EC_DH;
    curve = ALGORITHM_EC_DH_CURVE_OID_25519;
  }
};

