#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "KeePassFile.h"

TEST_CASE("File Header", "Header") {
    KeePassFile kpFile("../libkeepass/db_samples/kp_1.kdbx"); // Password is "kppass"
    REQUIRE(kpFile.formatVersion() == FormatVersion::KDBX_2);
    REQUIRE((kpFile.fileVersion().major == 3 && kpFile.fileVersion().minor == 1));
    REQUIRE(kpFile.isPayloadCompressed() == true);
    REQUIRE(kpFile.masterSeed().size() == 32);
    REQUIRE(kpFile.headerSize() == 222);
}
