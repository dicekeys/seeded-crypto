#include "UserPacket.hpp"
#include "Packet.hpp"

const ByteBuffer createUserPacket(const std::string &userName, const std::string &email) {
    ByteBuffer packetBody;
    // FIXME -- encoding or validation needed?
    std::string userNameAndEmail = userName + " <" + email + ">";
    std::vector<uint8_t> userNameAndEmailByteVector(userNameAndEmail.begin(), userNameAndEmail.end());
    packetBody.append(userNameAndEmailByteVector);
    return createPacket(pTagUserIdPacket, packetBody);
}