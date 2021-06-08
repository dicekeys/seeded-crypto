#include <random>
#include "ByteBuffer.hpp"
#include "../convert.hpp"

uint32_t get32RandomBits () {
    std::random_device rd;     // only used once to initialise (seed) engine
    std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
    std::uniform_int_distribution<uint32_t> uni(0, 0xffffffff); // guaranteed unbiased
    return uni(rng);
}


class PgpByteBuffer : public ByteBuffer {
public:
    void appendDataWithLengthPrefix(const ByteBuffer &rawBuffer) {
        write32Bits(rawBuffer.size());
        append(rawBuffer);
    }

    void appendDataWithLengthPrefix(const std::string &rawString) {
        write32Bits(rawString.size());
        append(rawString);
    }

    void appendPublicKeyEd25519(const ByteBuffer &publicKey) {
        appendDataWithLengthPrefix("ssh-ed25519");
        appendDataWithLengthPrefix(publicKey);
    }

    void appendPrivateKeyEd25519(
            const ByteBuffer &privateKey,
            const ByteBuffer &publicKey,
            const std::string &comment,
            uint32_t checksum = get32RandomBits()
    ) {
        // Checksum is a random number and is used only to validate that the key when successfully decrypted.
        // This method allow you to provide a checksum in order to validate the unit tests
        write32Bits(checksum);
        write32Bits(checksum);
        appendPublicKeyEd25519(publicKey);

        // scalar, point # Private Key part + Public Key part (AGAIN)
        ByteBuffer privateKeyConcatenatedWithPublicKey;
        privateKeyConcatenatedWithPublicKey.append(privateKey);
        privateKeyConcatenatedWithPublicKey.append(publicKey);
        appendDataWithLengthPrefix(privateKeyConcatenatedWithPublicKey);

        // Comment
        appendDataWithLengthPrefix(comment);

        const int blockSize = 8; // for unencrypted is 8

        const uint8_t paddingBytesNeeded = (blockSize - (size() % blockSize)) % blockSize;
        for (uint8_t i = 1; i <= paddingBytesNeeded; i++) {
            writeByte(i);
        }
    }

};



std::string createAuthorizedPublicKeyEd25519(const ByteBuffer &publicKey) {
    PgpByteBuffer out;
    out.appendPublicKeyEd25519(publicKey);
    return "ssh-ed25519 " + toHexStr(out.byteVector) + " DiceKeys";
}

std::string createPrivateKeyEd25519(
        const ByteBuffer &privateKey,
        const ByteBuffer &publicKey,
        const std::string comment,
        uint32_t checksum = get32RandomBits()
) {
    // FIXME
    //const privateKeyEd255119 = Ed25519PrivateKeyParameters(privateKey, 0)
    //val publicKey = privateKeyEd255119.generatePublicKey().encoded

    PgpByteBuffer out;
    out.append("openssh-key-v1");
    out.writeByte(0); // null byte

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
        privateKeyBuffer.appendPrivateKeyEd25519(privateKey, publicKey, comment, checksum);
        out.appendDataWithLengthPrefix(privateKeyBuffer);
    }
}
