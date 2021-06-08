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

//
//const std::string generateOpenPgpKey(u_int8_t privateKey[], std::string name, std::string email, uint32_t timestamp) {
//  std::vector<u_int8_t> out;
//  std::vector<u_int8_t> secretPacket = getSecretPacket(privateKey, timestamp);
//  std::vector<u_int8_t> userPacket = getUserIdPacket(name, email);
//  std::vector<u_int8_t> signaturePacket = signaturePacket(privateKey, timestamp, userPacket);
//  out.insert( out.end(), secretPacket.begin(), secretPacket.end() );
//  out.insert( out.end(), userPacket.begin(), userPacket.end() );
//  out.insert( out.end(), signaturePacket.begin(), signaturePacket.end() );
//}