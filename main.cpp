#include <iostream>
#include "packetcapture.h"

int main()
{
    try
    {
        Packetcapture *MySniffer = new Packetcapture();
        return EXIT_SUCCESS;
    } catch(...)
    {
        std::cout << "[Packetcapture] - Error" << std::endl;
        return EXIT_FAILURE;
    }
}