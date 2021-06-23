#include "OpenSshKey.hpp"
#include "../convert.hpp"
#include "asciiArmor.hpp"
#include <sodium.h>

class PgpByteBuffer : public ByteBuffer {
public:
    void appendDataWithLengthPrefix(const ByteBuffer &rawBuffer) {
        write32Bits(rawBuffer.size());
        append(rawBuffer);
    }

    void appendDataWithLengthPrefix(const std::string &rawString) {
        write32Bits(uint32_t(rawString.size()));
        append(rawString);
    }

    void appendPublicKeyEd25519(const ByteBuffer &publicKey) {
        appendDataWithLengthPrefix("ssh-ed25519");
        appendDataWithLengthPrefix(publicKey);
    }

    void appendPrivateKeyEd25519(
            const SigningKey &signingKey,
            const std::string &comment,
            uint32_t checksum = get32RandomBits()
    ) {
        // Checksum is a random number and is used only to validate that the key when successfully decrypted.
        // This method allow you to provide a checksum in order to validate the unit tests
        write32Bits(checksum);
        write32Bits(checksum);
        appendPublicKeyEd25519(signingKey.getSignatureVerificationKeyBytes());

        // scalar, point # Private Key part + Public Key part (AGAIN)
        ByteBuffer privateKeyConcatenatedWithPublicKey;
        privateKeyConcatenatedWithPublicKey.append(signingKey.getSeedBytes());
        privateKeyConcatenatedWithPublicKey.append(signingKey.getSignatureVerificationKeyBytes());
        appendDataWithLengthPrefix(privateKeyConcatenatedWithPublicKey);

        // Comment
        appendDataWithLengthPrefix(comment);

        const int blockSize = 8; // for unencrypted is 8

        const ubyte paddingBytesNeeded = (blockSize - (size() % blockSize)) % blockSize;
        for (ubyte i = 1; i <= paddingBytesNeeded; i++) {
            writeByte(i);
        }
    }
};

const std::string getOpenSSHPublicKeyEd25519(const SignatureVerificationKey &publicKey) {
    PgpByteBuffer out;
    out.appendPublicKeyEd25519(publicKey.getKeyBytes());
    return "ssh-ed25519 " + base64Encode(out.byteVector) + " DiceKeys";
}

const ByteBuffer getOpenSSHPrivateKeyEd25519(
        const SigningKey &signingKey,
        const std::string comment,
        uint32_t checksum
) {
    PgpByteBuffer out;
    out.append("openssh-key-v1");
    out.writeByte(0); // null byte
    ByteBuffer publicKey(signingKey.getSignatureVerificationKeyBytes());

    out.appendDataWithLengthPrefix("none"); // CipherName
    out.appendDataWithLengthPrefix("none"); // KdfName
    out.appendDataWithLengthPrefix(""); // KdfName
    out.write32Bits(1); // NumKeys

    {
        PgpByteBuffer pubKeyBuffer;
        pubKeyBuffer.appendPublicKeyEd25519(publicKey);
        out.appendDataWithLengthPrefix(pubKeyBuffer);
    } {
        PgpByteBuffer privateKeyBuffer;
        privateKeyBuffer.appendPrivateKeyEd25519(signingKey, comment, checksum);
        out.appendDataWithLengthPrefix(privateKeyBuffer);
    }
    return out;
}

const std::string getOpenSshPemPrivateKeyEd25519(
  const SigningKey& signingKey,
  const std::string comment,
  uint32_t checksum
) {
  return asciiArmor("OPENSSH PRIVATE KEY", getOpenSSHPrivateKeyEd25519(signingKey, comment, checksum));
}
