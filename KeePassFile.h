#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <string>

using std::string; 

class KeePassFile
{
 public:
   KeePassFile(string path);

   struct Header;

   /**
    * Returns the header of the keepass file. 
    */
   Header header() const;

 private:
   string m_filePath;
};

struct KeePassFile::Header {

};
#endif

