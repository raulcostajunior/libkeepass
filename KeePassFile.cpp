#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "KeePassFile.h"
#include "KeePassFileException.h"
#include "KeePassFileSettings.h"

using namespace std;

/* --- Magic bytes in the keepass file header --- */
const uint8_t signature_1_magic[] = {0x03, 0xD9, 0xA2, 0x9A};
const uint8_t signature_2_KP_1 = 0x65;
const uint8_t signature_2_KP_2_PreRelease = 0x66;
const uint8_t signature_2_KP_2 = 0x67;

const uint16_t kMaxHeaderBufferSize = 16384;


KeePassFile::KeePassFile(string path): _filePath(path) {
}


KeePassFile::~KeePassFile() {
    if (_ifstream.is_open()) {
        _ifstream.close();
    }
}


KeePassFileSettings KeePassFile::getSettingsFromFile() {
    KeePassFileSettings settings;
    uint16_t headerSize;
    readHeader(settings, headerSize);
    return settings;
}


void KeePassFile::readHeader(KeePassFileSettings& settings, uint16_t& headerSize) {
    char readBuff[kMaxHeaderBufferSize];

    headerSize = 0;
    _ifstream.open(_filePath, ios::in | ios::binary);

    if (!_ifstream.is_open()) {
        throw KeePassFileException(string("File not found: '") + _filePath + "'.");
    }

    _ifstream.read(readBuff, 4);
    headerSize += _ifstream.gcount();

    if (static_cast<uint8_t>(readBuff[0]) != signature_1_magic[0] ||
        static_cast<uint8_t>(readBuff[1]) != signature_1_magic[1] ||
        static_cast<uint8_t>(readBuff[2]) != signature_1_magic[2] ||
        static_cast<uint8_t>(readBuff[3]) != signature_1_magic[3])
    {
        _ifstream.close();
        throw KeePassFileException("Invalid file format: file magic number mismatch.");
    }

    _ifstream.read(readBuff, 1);
    headerSize += _ifstream.gcount();
    // Skips remaining 3 bytes - the fifth byte alone indicates the file format version.
    _ifstream.ignore(3);
    headerSize += _ifstream.gcount();

    switch (static_cast<uint8_t>(readBuff[0]))
    {
    case signature_2_KP_1:
        settings._keepassSpecVersion = FormatVersion::KDB_1;
        break;

    case signature_2_KP_2:
    case signature_2_KP_2_PreRelease:
        settings._keepassSpecVersion = FormatVersion::KDBX_2;
        break;

    default:
        settings._keepassSpecVersion = FormatVersion::UNKNOWN;
        _ifstream.close();
        throw KeePassFileException("Unknown keepass file version.");
    }

    _ifstream.read(readBuff, 2);
    headerSize += _ifstream.gcount();
    settings._fileVersion.minor = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);
    _ifstream.read(readBuff, 2);
    headerSize += _ifstream.gcount();
    settings._fileVersion.major = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);

    // Decode the dynamic header
    uint8_t currEntryType;
    do {
        _ifstream.read(readBuff, 1);
        headerSize += _ifstream.gcount();
        currEntryType = static_cast<uint8_t>(readBuff[0]);
        _ifstream.read(readBuff, 2);
        headerSize += _ifstream.gcount();
        uint16_t entrySize = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);
        _ifstream.read(readBuff, entrySize);
        headerSize += _ifstream.gcount();

        try {
            processHeaderField(static_cast<HeaderEntryType>(currEntryType), entrySize, readBuff, settings);
        }
        catch (KeePassFileException &) {
            _ifstream.close();
            throw;
        }
    }
    while (currEntryType != static_cast<uint8_t>(HeaderEntryType::END));

    _ifstream.close();
}


void KeePassFile::processHeaderField(HeaderEntryType entryType, uint16_t entrySize,
                                     const char *entryData, KeePassFileSettings& settings)
{
    switch (entryType)
    {
    case HeaderEntryType::END: // Nothing to do here - at least for now END doesn´t change the internal state of the object.
        break;
    case HeaderEntryType::COMMENT: // Just ignores the comment for now;
        break;
    case HeaderEntryType::CIPHER_ID:
        // There's just one algorithm supported for outer encryption, AES256.
        // This field is plainly ignored for now.
        break;
    case HeaderEntryType::COMPRESSION_FLAGS:
    {
        uint16_t flagValue = static_cast<uint8_t>(entryData[0]) + 10 * static_cast<uint8_t>(entryData[1]);
        settings._isPayloadCompressed = flagValue; // 0 is not compressed; 1 is gziped.
        break;
    }
    case HeaderEntryType::MASTER_SEED:
    {
        settings._masterSeed.clear();
        for (uint16_t i = 0; i < entrySize; i++)
        {
            settings._masterSeed.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::ENCRYPTION_IV:
    {
        settings._encryptionIV.clear();
        for (uint16_t i = 0; i < entrySize; i++)
        {
            settings._encryptionIV.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::TRANSFORM_SEED:
    {
        settings._transformSeed.clear();
        for (uint16_t i = 0; i < entrySize; i++)
        {
            settings._transformSeed.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::TRANSFORM_ROUNDS:
    {
        settings._transformRounds = static_cast<uint8_t>(entryData[0]) + 10 * static_cast<uint8_t>(entryData[1]);
        break;
    }
    case HeaderEntryType::STREAM_START_BYTES:
    {
        settings._streamStartBytes.clear();
        for (uint16_t i = 0; i < entrySize; i++)
        {
            settings._streamStartBytes.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::PROTECTED_STREAM_KEY:
    {
        settings._protectedStreamBytes.clear();
        for (uint16_t i = 0; i < entrySize; i++)
        {
            settings._protectedStreamBytes.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::INNER_RANDOM_STREAM_ID:
    {
        uint8_t idValue = static_cast<uint8_t>(entryData[0]) + 10 * static_cast<uint8_t>(entryData[1]);
        switch (idValue) {
        case 0:
            settings._innerRandStreamId = InnerStreamEncryption::NONE;
            break;
        case 1:
            settings._innerRandStreamId = InnerStreamEncryption::ARC4_VARIANT;
            break;
        case 2:
            settings._innerRandStreamId = InnerStreamEncryption::SALSA20;
            break;
        default:
            throw KeePassFileException("Invalid file format: unrecognized inner stream encryption specification.");
        }
    }
    }
}

