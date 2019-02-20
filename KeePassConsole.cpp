#include <cstdlib>
#include <iostream>

#include "KeePassFile.h"
#include "KeePassFileException.h"

using namespace std;

int main() {

    try {
        KeePassFile kpFile("../libkeepass/db_samples/kp_1.kdbx"); // Password is "kppass"
        cout << "Keepass file version: " << static_cast<unsigned short>(kpFile.version()) << endl;
    }
    catch (KeePassFileException& e) {
        cout << "Error reading file: " << e.what() << endl;
    }

    return EXIT_SUCCESS;
}
