#pragma once

#include "ByteBuffer.hpp"

const ByteBuffer createUserPacketBody(const std::string& userName, const std::string& email);
const ByteBuffer createUserPacketHashPreimage(const ByteBuffer& userIdPacketBody);
const ByteBuffer createUserPacket(const ByteBuffer& userPacketBody);
const ByteBuffer createUserPacket(const std::string& userName, const std::string& email);
