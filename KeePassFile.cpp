#include <cstdint>

#include "KeePassFileException.h"
#include "KeePassFile.h"

using namespace std;

/* --- Magic bytes in the keepass file header --- */

const uint8_t signature_1_magic[] = {0x03, 0xD9, 0xA2, 0x9A};
const uint8_t signature_2_KP_1 = 0x65;
const uint8_t signature_2_KP_2_PreRelease = 0x66;
const uint8_t signature_2_KP_2 = 0x67;


KeePassFile::KeePassFile(string path) :
    m_filePath(path),
    m_version(KeePassVersion::UNKNOWN) {

    readHeader();
}


KeePassFile::~KeePassFile() {
    if (m_ifstream.is_open()) {
        m_ifstream.close();
    }
}


KeePassVersion KeePassFile::version() const
{
    return m_version;
}


void KeePassFile::readHeader()
{
    m_ifstream.open(m_filePath, ios::in | ios::binary);

    if (!m_ifstream.is_open()) {
        throw KeePassFileException(string("File not found: '") + m_filePath + "'.");
    }

    char signature1[4];
    m_ifstream.read(signature1, 4);

    if (static_cast<uint8_t>(signature1[0]) != signature_1_magic[0] ||
        static_cast<uint8_t>(signature1[1]) != signature_1_magic[1] ||
        static_cast<uint8_t>(signature1[2]) != signature_1_magic[2] ||
        static_cast<uint8_t>(signature1[3]) != signature_1_magic[3])
    {
        m_ifstream.close();
        throw KeePassFileException("Invalid file format: file magic number mismatch.");
    }

    char signature2;
    m_ifstream.read(&signature2, 1);
    // Skips remaining 3 bytes - the fifth byte alone indicates the file format version.
    m_ifstream.ignore(3);

    switch (static_cast<uint8_t>(signature2))
    {

    case signature_2_KP_1:
        m_version = KeePassVersion::KDB_1;
        break;

    case signature_2_KP_2:
    case signature_2_KP_2_PreRelease:
        m_version = KeePassVersion::KDBX_2;
        break;

    default:
        m_version = KeePassVersion::UNKNOWN;
        m_ifstream.close();
        throw KeePassFileException("Unknown keepass file version.");
    }

    m_ifstream.close();
}
