#include "KeePassFileException.h"


KeePassFileException::KeePassFileException(std::string msg): m_msg(msg) {
}

const char * KeePassFileException::what() const noexcept {
    return m_msg.c_str();
}
