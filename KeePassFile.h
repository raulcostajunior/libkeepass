#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

enum class FormatVersion: uint8_t {
    UNKNOWN, KDB_1, KDBX_2, KDBX_3, KDBX_4
};

enum class HeaderEntryType: uint8_t {
    END, COMMENT, CIPHER_ID, COMPRESSION_FLAGS, MASTER_SEED,
    TRANSFORM_SEED, TRANSFORM_ROUNDS, ENCRYPTION_IV,
    PROTECTED_STREAM_KEY, STREAM_START_BYTES, INNER_RANDOM_STREAM_ID
};

struct FileVersion {
    uint16_t minor;
    uint16_t major;
};


class KeePassFile
{
 public:

   KeePassFile(std::string path);
   virtual ~KeePassFile();

   const FormatVersion& formatVersion() const;
   const FileVersion& fileVersion() const;
   bool isPayloadCompressed() const;
   const std::vector<uint8_t>& masterSeed() const;

 private:

   void readHeader();
   void processHeaderField(HeaderEntryType entryType, uint16_t entrySize, const char* entryData);

   std::string _filePath;
   std::ifstream _ifstream;

   /* Information contained in file header */
   FormatVersion _keepassSpecVersion;
   FileVersion _fileVersion;
   bool _isPayloadCompressed; // When true, the payload is Gziped.
   std::vector<std::uint8_t> _masterSeed;
};


#endif

