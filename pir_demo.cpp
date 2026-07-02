#include <iostream>
#include "libsimplepir.h"

int main() {
    std::cout << "=== Demo PIR SimplePIR ===" << std::endl;

    GlobalInitPIR();
    PIRServerSetup(1, 8);
    PIRClientQuery(3);
    PIRServerAnswer(1);
    PIRClientExtract();

    std::cout << "Demo PIR terminee" << std::endl;
    return 0;
}
