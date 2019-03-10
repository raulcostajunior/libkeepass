#include "KeePassFileException.h"
#include "KeePassFile.h"

#include <algorithm>
#include <iostream>

using namespace std;

/* --- Magic bytes in the keepass file header --- */

const uint8_t signature_1_magic[] = {0x03, 0xD9, 0xA2, 0x9A};
const uint8_t signature_2_KP_1 = 0x65;
const uint8_t signature_2_KP_2_PreRelease = 0x66;
const uint8_t signature_2_KP_2 = 0x67;

const uint16_t kMaxHeaderBufferSize = 16384;


KeePassFile::KeePassFile(string path) :
        _filePath(path),
        _keepassSpecVersion(FormatVersion::UNKNOWN) {
    readHeader();
}


KeePassFile::~KeePassFile() {
    if (_ifstream.is_open()) {
        _ifstream.close();
    }
}


const FormatVersion& KeePassFile::formatVersion() const {
    return _keepassSpecVersion;
}


const FileVersion& KeePassFile::fileVersion() const {
    return _fileVersion;
}


bool KeePassFile::isPayloadCompressed() const {
    return _isPayloadCompressed;
}


const vector<uint8_t>& KeePassFile::masterSeed() const {
    return _masterSeed;
}


void KeePassFile::processHeaderField(HeaderEntryType entryType, uint16_t entrySize, const char* entryData)
{
    switch (entryType) {
    case HeaderEntryType::END:
        // Nothing to do here - at least for now END doesn´t change the internal state of the object.
        break;
    case HeaderEntryType::COMMENT:
        // Just ignores the comment for now;
        break;
    case HeaderEntryType::CIPHER_ID:
        // There's just one algorithm supported for outer encryption, AES256.
        // This field is plainly ignored for now.
        break;
    case HeaderEntryType::COMPRESSION_FLAGS: {
        uint16_t flagValue = static_cast<uint8_t>(entryData[0]) + 10*static_cast<uint8_t>(entryData[1]);
        _isPayloadCompressed = flagValue; // 0 is not compressed; 1 is gziped.
        break;
    }
    case HeaderEntryType::MASTER_SEED: {
        _masterSeed.clear();
        for (uint16_t i = 0; i < entrySize; i++) {
            _masterSeed.push_back(static_cast<uint8_t>(entryData[i]));
        }
        break;
    }
    case HeaderEntryType::ENCRYPTION_IV:
    case HeaderEntryType::TRANSFORM_SEED:
    case HeaderEntryType::TRANSFORM_ROUNDS:
    case HeaderEntryType::STREAM_START_BYTES:
    case HeaderEntryType::PROTECTED_STREAM_KEY:
    case HeaderEntryType::INNER_RANDOM_STREAM_ID:
       // TODO: handle all these remaining types
        break;
    }
}


void KeePassFile::readHeader() {
    char readBuff[kMaxHeaderBufferSize];

    _ifstream.open(_filePath, ios::in | ios::binary);

    if (!_ifstream.is_open()) {
        throw KeePassFileException(string("File not found: '") + _filePath + "'.");
    }

    _ifstream.read(readBuff, 4);

    if (static_cast<uint8_t>(readBuff[0]) != signature_1_magic[0] ||
        static_cast<uint8_t>(readBuff[1]) != signature_1_magic[1] ||
        static_cast<uint8_t>(readBuff[2]) != signature_1_magic[2] ||
        static_cast<uint8_t>(readBuff[3]) != signature_1_magic[3])
    {
        _ifstream.close();
        throw KeePassFileException("Invalid file format: file magic number mismatch.");
    }

    _ifstream.read(readBuff, 1);
    // Skips remaining 3 bytes - the fifth byte alone indicates the file format version.
    _ifstream.ignore(3);

    switch (static_cast<uint8_t>(readBuff[0]))
    {
    case signature_2_KP_1:
        _keepassSpecVersion = FormatVersion::KDB_1;
        break;

    case signature_2_KP_2:
    case signature_2_KP_2_PreRelease:
        _keepassSpecVersion = FormatVersion::KDBX_2;
        break;

    default:
        _keepassSpecVersion = FormatVersion::UNKNOWN;
        _ifstream.close();
        throw KeePassFileException("Unknown keepass file version.");
    }

    _ifstream.read(readBuff, 2);
    _fileVersion.minor = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);
    _ifstream.read(readBuff, 2);
    _fileVersion.major = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);

    // Decode the dynamic header
    uint8_t currEntryType;
    do {
        _ifstream.read(readBuff, 1);
        currEntryType = static_cast<uint8_t>(readBuff[0]);
        _ifstream.read(readBuff, 2);
        uint16_t entrySize = static_cast<uint8_t>(readBuff[0]) + 10*static_cast<uint8_t>(readBuff[1]);
        _ifstream.read(readBuff, entrySize);

        processHeaderField(static_cast<HeaderEntryType>(currEntryType), entrySize, readBuff);
    }
    while (currEntryType != static_cast<uint8_t>(HeaderEntryType::END));

    _ifstream.close();
}
