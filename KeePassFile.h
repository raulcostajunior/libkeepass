#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "KeePassFileSettings.h"

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

   KeePassFileSettings getSettingsFromFile();

   // TODO: make sure that the PayloadBlock move constructor will be used upon returning the blocks to the caller
   // (vector has a move ctor which, hopefully, will be used at return time).
   std::vector<PayloadBlock> getPayloadBlocks(std::string password);

 private:

   void readHeader(KeePassFileSettings& settings, uint16_t& headerSize);

   void processHeaderField(HeaderEntryType entryType, uint16_t entrySize,
                           const char* entryData, KeePassFileSettings& settings);

   std::string _filePath;
   std::ifstream _ifstream;

};


#endif

