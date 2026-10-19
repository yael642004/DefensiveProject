#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// CryptoPP Headers
#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#pragma pack(push, 1)
struct RequestHeader {
    unsigned char clientId[16];
    unsigned char version;
    unsigned short code;
    unsigned int payloadSize;
};

struct ResponseHeader {
    unsigned char version;
    unsigned short code;
    unsigned int payloadSize;
};
#pragma pack(pop)

const int PROTOCOL_VERSION = 3;
const int PORT = 1234;
const std::string HOST = "127.0.0.1";