#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <exception>
#include <fstream>
#include <string>

enum class KeePassVersion: unsigned short {
    UNKNOWN = 0, KDB_1, KDBX_2, KDBX_3, KDBX_4
};


class KeePassFile
{

 public:

   KeePassFile(std::string path);

   virtual ~KeePassFile();

   KeePassVersion version() const;

 private:

   void readHeader();

   std::string m_filePath;
   std::ifstream m_ifstream;

   KeePassVersion m_version;

};


#endif

