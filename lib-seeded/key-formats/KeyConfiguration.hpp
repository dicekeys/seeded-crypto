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



class KeyConfiguration {
public:
  ubyte algorithm;
  std::vector<ubyte> curve;
  ubyte version = VERSION_5;
  std::vector<ubyte> keyFlags = {
    0x01 // Certify (0x1)
  };
  std::vector<ubyte> preferredSymmetricAlgorithms = {
    0x09, // AES with 256-bit key (0x9)
    0x08, // AES with 192-bit key (0x8)
    0x07  // AES with 128-bit key (0x7)
  };
  std::vector<ubyte> preferredHashAlgorithms = {
    0x0a, // SHA512 (0xa)
    0x09, // SHA384 (0x9)
    0x08  // SHA256 (0x8)
  };
  std::vector<ubyte> preferredCompressionAlgorithms = {
    0x03, // BZip2 (0x3)
    0x02, // ZLIB (0x2)
    0x01  // ZIP (0x1)
  };
  std::vector<ubyte> features = {
    0x01 // Modification detection (0x1)
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

