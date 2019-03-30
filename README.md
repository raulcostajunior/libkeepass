# libkeepass
A C++ library for reading and writing safe password files in the Keepass format (`*.kbdx`).

Further information on the KeePass file format can be found at https://github.com/lgg/awesome-keepass#docs-and-articles.

`libkeepass` depends on the `CryptoPP` cryptography library (https://www.cryptopp.com). The `cmake` find module for `CryptoPP` (https://bitbucket.org/sergiu/cryptopp-cmake) has been embeeded into this project.

For MacOS, `CryptoPP` can be installed with `brew install Cryptopp`. 

For a brew installation of CryptoPP, `FindCryptoPP.cmake` depends on the environment variable `CRYPTOPP_ROOT_DIR` being set or passed to `cmake` via `-D` command line option. 

At the time of writing, `CRYPTO_ROOT_DIR` should point to `/usr/local/Cellar/cryptopp/8.1.0` for a default installation of `CryptoPP` via `brew`.

