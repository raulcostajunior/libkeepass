#ifndef KEE_PASS_FILE_H
#define KEE_PASS_FILE_H

#include <exception>
#include <string>

enum class KeepassVersion: unsigned short {
    UNKNOWN = 0, KDB_1, KDBX_2, KDBX_3, KDBX_4
};


class KeepassFileException: public std::exception {

public:

    KeepassFileException(std::string msg);

    virtual const char* what() const noexcept;

private:

    std::string m_msg;

};


class KeepassFile
{

 public:

   KeepassFile(std::string path);

   KeepassVersion version() const;

 private:

   void readHeader();

   std::string m_filePath;

   KeepassVersion m_version;

};



#endif

