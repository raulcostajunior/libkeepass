#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <string>

class KeePassFile
{
 public:
   KeePassFile(std::string path);

 private:
   std::string _file_path;
};

#endif

