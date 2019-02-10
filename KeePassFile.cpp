#include <cstdint>
#include <fstream>

#include "KeePassFile.h"

using namespace std;

/* ---  KeepassFileException members --- */

KeepassFileException::KeepassFileException(const string msg): m_msg(msg) {

}

const char* KeepassFileException::what() const noexcept {
    return m_msg.c_str();
}


/* --- Magic bytes in the keepass file header --- */

const uint8_t signature_1_magic[] = {0x03, 0xD9, 0xA2, 0x9A};
const uint8_t signature_2_KP_1 = 0x65;
const uint8_t signature_2_KP_2_PreRelease = 0x66;
const uint8_t signature_2_KP_2 = 0x67;


/* --- KeepassFile members --- */

KeepassFile::KeepassFile(string path) : m_filePath(path),
    m_version(KeepassVersion::UNKNOWN)
{
    readHeader();
}


KeepassVersion KeepassFile::version() const
{
    return m_version;
}


void KeepassFile::readHeader()
{
    ifstream kpFile(m_filePath, ios::in|ios::binary);

    if (!kpFile.is_open()) {
        throw KeepassFileException(string("File not found: '") + m_filePath + "'.");
    }

    char signature1[4];
    kpFile.read(signature1, 4);

    if (static_cast<uint8_t>(signature1[0]) != signature_1_magic[0] ||
        static_cast<uint8_t>(signature1[1]) != signature_1_magic[1] ||
        static_cast<uint8_t>(signature1[2]) != signature_1_magic[2] ||
        static_cast<uint8_t>(signature1[3]) != signature_1_magic[3])
    {
        kpFile.close();
        throw KeepassFileException("Invalid file format: file magic number mismatch.");
    }

    char signature2;
    kpFile.read(&signature2, 1);
    // Skips remaining 3 bytes - the fifth byte alone indicates the file version.
    kpFile.ignore(3);

    switch (static_cast<uint8_t>(signature2))
    {

    case signature_2_KP_1:
        m_version = KeepassVersion::KDB_1;
        break;

    case signature_2_KP_2:
    case signature_2_KP_2_PreRelease:
        m_version = KeepassVersion::KDBX_2;
        break;

    default:
        m_version = KeepassVersion::UNKNOWN;
        kpFile.close();
        throw KeepassFileException("Unknown keepass file version.");
    }

    kpFile.close();
}
