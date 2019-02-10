#include <cstdlib>
#include <iostream>

#include "KeePassFile.h"

using namespace std;

int main() {

    try {
        KeepassFile kpFile("kp_1.kdbx");
        cout << "Keepass file version: " << static_cast<unsigned short>(kpFile.version()) << endl;
    }
    catch (KeepassFileException& e) {
        cout << "Error reading file: " << e.what() << endl;
    }

    return EXIT_SUCCESS;
}
