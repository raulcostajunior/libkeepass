# libkeepass
A C++ library for reading and writing safe password files in the Keepass format (`*.kbdx`).

Further information on the KeePass file format can be found at https://github.com/lgg/awesome-keepass#docs-and-articles.

`libkeepass` depends on the `CryptoPP` cryptography library (https://www.cryptopp.com). The `cmake` find module for `CryptoPP` (https://bitbucket.org/sergiu/cryptopp-cmake) has been embeeded into this project.

For MacOS, `CryptoPP` can be installed with `brew install Cryptopp`. 
