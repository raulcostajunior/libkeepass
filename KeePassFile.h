#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <string>

using std::string;

enum class KeepassVersion: unsigned short {
    UNKNOWN = 0, KDB_1, KDBX_2, KDBX_3, KDBX_4
};


class KeePassFile
{

 public:

   KeePassFile(string path);

   KeepassVersion version() const;

 private:

   void readHeader();

   string m_filePath;

   KeepassVersion m_version;

};



#endif

