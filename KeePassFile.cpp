#include <cstdint>
#include <fstream>

#include "KeePassFile.h"

using namespace std;

const uint32_t signature_1_magic = 0x9AA2D903;
const uint32_t signature_2_KP_1 = 0xB54BFB65;
const uint32_t signature_2_KP_2_Beta = 0xB54BFB66;
const uint32_t signature_2_KP_2 = 0xB54BFB67;

/*
.kdb and .kdbx file formats’ header first have 2 fields of 4 bytes each that are the file signatures (cf KdbxFile.cs of Keepass2 source code).

File Signature 1 (the first field) will always have a value of 0x9AA2D903 .

File Signature 2 (the second field) can have (for now) 3 different value, each value indicating the file format/version :

for .kdb files (KeePass 1.x file format) : 0xB54BFB65 ,
for kdbx file of KeePass 2.x pre-release (alpha & beta) : 0xB54BFB66 ,
for kdbx file of KeePass post-release : 0xB54BFB67 .
After these 2 fields, .kdb and .kdbx differ totally :
   .kdb has fixed number of fields taking a fixed number of bytes in its header, while .kdbx has a TLV list of fields in its header.
 */

KeePassFile::KeePassFile(string path) : m_filePath(path),
                                        m_version(KeepassVersion::UNKNOWN)
{

    readHeader();
}

KeepassVersion KeePassFile::version() const
{
    return m_version;
}

void KeePassFile::readHeader()
{

    ifstream kpFile(m_filePath, ios::binary);

    uint32_t signature1;
    kpFile >> signature1;

    if (signature1 != signature_1_magic)
    {
        // TODO: throw a std::exception
        throw "Invalid file format";
    }

    uint32_t signature2;
    kpFile >> signature2;

    // TODO: throw std::exception in case of an unknown format
    switch (signature2)
    {

    case signature_2_KP_1:
        m_version = KeepassVersion::KDB_1;
        break;

    case signature_2_KP_2:
    case signature_2_KP_2_Beta:
        m_version = KeepassVersion::KDBX_2;
        break;

    default:
        m_version = KeepassVersion::UNKNOWN;
    }
}
