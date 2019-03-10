#include "KeePassFileException.h"
#include "KeePassFile.h"

using namespace std;

// TODO: refactor the reads into util functions like "uint32_t readDwordLE(istream&)"

/* --- Magic bytes in the keepass file header --- */

const uint8_t signature_1_magic[] = {0x03, 0xD9, 0xA2, 0x9A};
const uint8_t signature_2_KP_1 = 0x65;
const uint8_t signature_2_KP_2_PreRelease = 0x66;
const uint8_t signature_2_KP_2 = 0x67;


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


void KeePassFile::readHeader() {
    _ifstream.open(_filePath, ios::in | ios::binary);

    if (!_ifstream.is_open()) {
        throw KeePassFileException(string("File not found: '") + _filePath + "'.");
    }

    char signature1[4];
    _ifstream.read(signature1, 4);

    if (static_cast<uint8_t>(signature1[0]) != signature_1_magic[0] ||
        static_cast<uint8_t>(signature1[1]) != signature_1_magic[1] ||
        static_cast<uint8_t>(signature1[2]) != signature_1_magic[2] ||
        static_cast<uint8_t>(signature1[3]) != signature_1_magic[3])
    {
        _ifstream.close();
        throw KeePassFileException("Invalid file format: file magic number mismatch.");
    }

    char signature2;
    _ifstream.read(&signature2, 1);
    // Skips remaining 3 bytes - the fifth byte alone indicates the file format version.
    _ifstream.ignore(3);

    switch (static_cast<uint8_t>(signature2))
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

    char wordBuff[2];
    _ifstream.read(wordBuff, 2);
    _fileVersion.minor = static_cast<uint8_t>(wordBuff[0]) + 10*static_cast<uint8_t>(wordBuff[1]);
    _ifstream.read(wordBuff, 2);
    _fileVersion.major = static_cast<uint8_t>(wordBuff[0]) + 10*static_cast<uint8_t>(wordBuff[1]);

    _ifstream.close();
}
