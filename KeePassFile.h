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

enum class InnerStreamEncryption: uint8_t {
    NONE, ARC4_VARIANT, SALSA20
};

struct FileVersion {
    uint16_t minor;
    uint16_t major;
};

// TODO: Add a move ctor so that getPayloadBlocks can transfer ownership of the blocks.
/// A block of data in the cyphered payload area of the file.
struct PayloadBlock {
    uint16_t blockId;
    uint8_t dataHash[32];
    uint16_t blockSize;
    // The block data after first decryption; can still be
    // gzipped and have internal values cyphered by the
    // algorithm specified in the file header's field
    // InnerStreamEncryption.
    std::vector<uint8_t> blockData;
    // The block data after being gunziped and having its
    // internal protected values decyphered - will be equal
    // to blockData when the payload is not compressed and
    // no cypher is used for storing internal protected
    // values. Block plain data is expected to be in XML
    // format. Any text enconding for the XML formatted
    // data should be handled by client code that will
    // receive the PayloadBlock.
    std::vector<uint8_t> blockPlainData;
};


class KeePassFile
{
 public:

   KeePassFile(std::string path);
   virtual ~KeePassFile();

   // TODO: change to return a nested class FileInfo: const KeePassFile::FileInfo& getFileInfo
   // FileInfo will have all the file header fields as members. An instance of FileInfo
   // will be kept by the class and will be completely refreshed each time the get method is
   // activated.
   void readHeader();
   // TODO: make sure that the PayloadBlock move constructor will be used upon returning the blocks to the caller
   // (vector has a move ctor which, hopefully, will be used at return time).
   std::vector<PayloadBlock> getPayloadBlocks(std::string password);

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
   const uint16_t& headerSize() const;

 private:

   void processHeaderField(HeaderEntryType entryType, uint16_t entrySize, const char* entryData);

   std::string _filePath;
   std::ifstream _ifstream;

   /* Information contained in file header */
   FormatVersion _keepassSpecVersion;
   FileVersion _fileVersion;
   bool _isPayloadCompressed; // When true, the payload is Gziped.
   std::vector<std::uint8_t> _masterSeed;
   std::vector<std::uint8_t> _encryptionIV;
   std::vector<std::uint8_t> _transformSeed;
   uint16_t _transformRounds;
   std::vector<std::uint8_t> _protectedStreamBytes;
   std::vector<std::uint8_t> _streamStartBytes;
   InnerStreamEncryption _innerRandStreamId;

   uint16_t _headerSize;
};


#endif

