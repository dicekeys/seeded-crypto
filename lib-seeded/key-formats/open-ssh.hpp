/*
object OpenPgpHelper {

    fun generateOpenPgpKey(privateKey: ByteArray, name: String, email: String, timestamp: UInt): String {
        val out = ByteStreams.newDataOutput()
        // val timestamp = 1577836800u // 2020-01-01 00:00:00
        val secretPacket = SecretPacket(privateKey, timestamp)
        val userPacket = UserIdPacket(name, email)
        val signaturePacket = SignaturePacket(privateKey, timestamp, userPacket)

        out.write(secretPacket.toByteArray())
        out.write(userPacket.toByteArray())
        out.write(signaturePacket.toByteArray())

        val base64 = BaseEncoding.base64().encode(out.toByteArray())

        return PemHelper.block("PGP PRIVATE KEY BLOCK", base64)
    }
} 
*/
#include <vector>
#include <string>


//  Unencrypted Multiprecision Integers
class Mpi {

  Mpi(std::vector<uint8_t> value) {

  }
    val size : UShort by lazy {
        value.bitLength().toUShort()
    }

    fun toByteArray(): ByteArray{
        val body = ByteStreams.newDataOutput()
        body.writeShort(size.toInt())
        if(size > 0u) {
            body.write(value.toByteArray().let {
                // BigInteger representation always have a sign bit. This is not a problem as we only
                // handle positive numbers. The only edge case is when we use eg. all 8 bits of a byte
                // to represent a positive number. BigInteger will have to store (8 number bits + 1 sign bits)
                // 1 byte fits the number representation and it will need to consume one more zero byte in our case
                // to represent the sign positive bit.
                // In that case it's safe to remove the first byte if it's 0
                if(it[0] == 0.toByte()){
                    return@let it.takeLast(it.size - 1).toByteArray()
                }
                it
            })
        }
        return body.toByteArray()
    }

    companion object{
        fun fromHex(hex: String): Mpi {
            return Mpi(BigInteger(hex, 16))
        }

        fun fromByteArray(byteArray: ByteArray): Mpi {
            return Mpi(BigInteger(1, byteArray))
        }
    }
}

/**
 * https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.txt
 * 
 *  3.1.  Scalar Numbers
 *
 *  Scalar numbers are unsigned and are always stored in big-endian
 *  format.  Using n[k] to refer to the kth octet being interpreted, the
 *  value of a two-octet scalar is ((n[0] << 8) + n[1]).  The value of a
 *  four-octet scalar is ((n[0] << 24) + (n[1] << 16) + (n[2] << 8) +
 *  n[3]).
 */


class Packet {
  // RFC4880 - Section 4
  // Explanation: https://under-the-hood.sequoia-pgp.org/packet-structure/
  virtual uint8_t pTag(); // Also known as CTB (Cipher Type Byte)
  std::vector<uint8_t> body();

  virtual std::vector<uint8_t> hash(digest: MessageDigest);

  const std::vector<uint8_t> toByteArray() {
    std::vector<uint8_t> out;
    out.push_back(pTag());
    // RFC2440 Section 4.2.2
    // Hardcoded as a byte, it should be variable based on PTag but it's ok for our use case
    const auto bodyVector = body();
    out.push_back(bodyVector.size());
    out.insert(out.end(), bodyVector.begin(), bodyVector.end() );
    return out;
  }

public:
  static const uint8_t Version = 0x04;
  static const uint8_t Sha256Algorithm = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]
  static const uint8_t Ed25519Algorithm = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
  static const std::vector<uint8_t> Ed25519CurveOid() { return std::vector<uint8_t>({0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}); } // RFC4880-bis-10 - Section 9.2.  ECC Curve OID
};

class ByteBuffer {
  public:
    std::vector<uint8_t> buffer;

    void writeByte(uint8_t byte) {
      buffer.push_back(byte);
    };

    void write16Bits(uint16_t value) {
      uint8_t high = (value >> 8) & 0xff;
      uint8_t low = value & 0xff;
      writeByte(high);
      writeByte(low);
    };

    void write32Bits(uint32_t value) {
      uint16_t high = (value >> 16) & 0xffff;
      uint16_t low = value & 0xffff;
      write16Bits(high);
      write16Bits(low);
    };
  
    void writeByteVector(std::vector<uint8_t>  value) {
      buffer.insert( buffer.end(), value.begin(), value.end() );
    };

}

class PublicPacket: Packet {
  std::vector<u_int8_t> publicKey;
  uint32_t timestamp;
  PublicPacket(std::vector<u_int8_t> _publicKey, uint32_t _timestamp) {
    publicKey = _publicKey;
    timestamp = _timestamp;
  };

  uint8_t pTag() { return 0x98; }

  std::vector<u_int8_t> body() {
    ByteBuffer out;

    // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format

    out.writeByte(Version);
    out.writeByte(Packet::Version)
    out.write32Bits(timestamp.toInt())
    out.writeByte(Packet::Ed25519Algorithm)
    out.writeByte(Packet::Ed25519CurveOid.size)
    out.writeByteVector(Packet::Ed25519CurveOid())

    // 0x40 indicate compressed format
    // val taggedPublicKey = byteArrayOf(0x40) + publicKey
    out.write(Mpi.fromByteArray(taggedPublicKey).toByteArray())

    return body;
  }


};
/*
class PublicPacket(private val publicKey: ByteArray, private val timestamp: UInt): Packet() {

    override val pTag: Int
        get() = 0x98

    override val body: ByteArray by lazy {
        val body = ByteStreams.newDataOutput()

        // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format
        // 0x40 indicate compressed format
        val taggedPublicKey = byteArrayOf(0x40) + publicKey

        body.write(Version)
        body.writeInt(timestamp.toInt())
        body.write(Ed25519Algorithm)
        body.write(Ed25519CurveOid.size)
        body.write(Ed25519CurveOid)

        body.write(Mpi.fromByteArray(taggedPublicKey).toByteArray())

        body.toByteArray()
    }

    // A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
    // followed by the two-octet packet length, followed by the entire
    // Public-Key packet starting with the version field.  The Key ID is the
    // low-order 64 bits of the fingerprint.
    fun fingerprint(): ByteArray {
        val out = ByteStreams.newDataOutput()

        // SHA-1 must not be used when collisions could lead to security failures
        // It is used here as hash for keyIds where collisions are acceptable, and only
        // because it is required for compatibility with RFC2440 (11.2) where no
        // alternative is available.
        val digest: MessageDigest = MessageDigest.getInstance("SHA-1")

        out.writeByte(0x99)
        out.writeShort(body.size)
        out.write(body)

        digest.update(out.toByteArray())

        return digest.digest()
    }

    fun keyId(): ByteArray = fingerprint().takeLast(8).toByteArray()


    override fun hash(digest: MessageDigest) {
        val buffer = ByteStreams.newDataOutput()
        buffer.writeByte(0x99)
        buffer.writeShort(body.size) // 2-bytes
        buffer.write(body)

        digest.update(buffer.toByteArray())
    */


const std::string generateOpenPgpKey(u_int8_t privateKey[], std::string name, std::string email, uint32_t timestamp) {
  std::vector<u_int8_t> out;
  std::vector<u_int8_t> secretPacket = getSecretPacket(privateKey, timestamp);
  std::vector<u_int8_t> userPacket = getUserIdPacket(name, email);
  std::vector<u_int8_t> signaturePacket = signaturePacket(privateKey, timestamp, userPacket);
  out.insert( out.end(), secretPacket.begin(), secretPacket.end() );
  out.insert( out.end(), userPacket.begin(), userPacket.end() );
  out.insert( out.end(), signaturePacket.begin(), signaturePacket.end() );
}