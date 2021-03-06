#ifndef KEYPASSFILESETTINGS_H
#define KEYPASSFILESETTINGS_H

#include <cstdint>
#include <vector>

enum class FormatVersion: uint8_t {
    UNKNOWN, KDB_1, KDBX_2, KDBX_3, KDBX_4
};

enum class HeaderEntryType: uint8_t {
    END, COMMENT, CIPHER_ID, COMPRESSION_FLAGS, MASTER_SEED,
    TRANSFORM_SEED, TRANSFORM_ROUNDS, ENCRYPTION_IV,
    PROTECTED_STREAM_KEY, STREAM_START_BYTES, INNER_RANDOM_STREAM_ID
};

enum class InnerStreamEncryption: uint8_t {
    NONE, ARC4_VARIANT, SALSA20
};

struct FileVersion {
    uint16_t minor;
    uint16_t major;
};


class KeePassFileSettings
{
    friend class KeePassFile;

public:

    const FormatVersion& formatVersion() const;

    const FileVersion& fileVersion() const;

    bool isPayloadCompressed() const;

    const std::vector<uint8_t>& masterSeed() const;

    const std::vector<uint8_t>& encryptionIV() const;

    const std::vector<uint8_t>& transformSeed() const;

    const uint16_t& transformRounds() const;

    const std::vector<uint8_t>& protectedStreamBytes() const;

    const std::vector<uint8_t>& streamStartBytes() const;

    const InnerStreamEncryption& innerRandStreamId() const;

private:

    FormatVersion _keepassSpecVersion = FormatVersion::UNKNOWN;

    FileVersion _fileVersion;

    bool _isPayloadCompressed; // When true, the payload is Gziped.

    std::vector<std::uint8_t> _masterSeed;

    std::vector<std::uint8_t> _encryptionIV;

    std::vector<std::uint8_t> _transformSeed;

    uint16_t _transformRounds;

    std::vector<std::uint8_t> _protectedStreamBytes;

    std::vector<std::uint8_t> _streamStartBytes;

    InnerStreamEncryption _innerRandStreamId = InnerStreamEncryption::NONE;
};

#endif // KEYPASSFILESETTINGS_H
