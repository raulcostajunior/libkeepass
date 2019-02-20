#ifndef KEEPASSFILEEXCEPTION_H
#define KEEPASSFILEEXCEPTION_H

#include <exception>
#include <string>

class KeePassFileException: public std::exception {

public:
    KeePassFileException(std::string msg);

    virtual const char* what() const noexcept;

private:

    std::string m_msg;
};

#endif // KEEPASSFILEEXCEPTION_H
