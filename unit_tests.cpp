#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "KeePassFile.h"
#include "KeePassFileSettings.h"

TEST_CASE("Retrieve file settings", "Setttings") {
    KeePassFile kpFile("../libkeepass/db_samples/kp_1.kdbx"); // Password is "kppass"
    KeePassFileSettings settings = kpFile.getSettingsFromFile();
    REQUIRE(settings.formatVersion() == FormatVersion::KDBX_2);
    REQUIRE((settings.fileVersion().major == 3 && settings.fileVersion().minor == 1));
    REQUIRE(settings.isPayloadCompressed() == true);
    REQUIRE(settings.masterSeed().size() == 32);
    REQUIRE(settings.innerRandStreamId() == InnerStreamEncryption::SALSA20);
}
