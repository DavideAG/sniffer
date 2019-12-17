#include "packetcapture.h"

pcap_if_t* Packetcapture::showInterfaces(int& numberOfInterfaces)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    numberOfInterfaces=0;
    if (pcap_findalldevs(&interfaces,error) == -1)
    {
        std::cout << error << std::endl;
        throw "[Packetcapture] - Error in pcap findall devs\n";   
    }

    std::cout << "the interfaces present on the system are:" << std::endl; 
    for (temp=interfaces; temp; temp=temp->next)
    {
        std::cout << numberOfInterfaces++ << " : " << temp->name << std::endl;
    }
    --numberOfInterfaces;
    return interfaces;
}

void Packetcapture::selectInterface()
{
    int i = -1, j = 0;
    pcap_if_t* interfaces = showInterfaces(j), *temp;
    std::cout << std::endl << "Select an interface: ";
    std::cin >> i;
    
    if (i > j || i < 0)
    {
        std::cout << "[Packetcapture] - Bad value at selectInterface" << std::endl;
        throw "Bad value";
    }
    
    for (temp=interfaces, j=0; j<i; temp=temp->next, j++) {}

    this->adapter = new std::string(std::move(temp->name));
}

void Packetcapture::attachInterface()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    snaplen = 6000;     //<----------------- ***add this to user input!
    handle = pcap_open_live(adapter[0].c_str(), snaplen, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        std::cout << "[Packetcapture] - Error at attachInterface - " << errbuf << std::endl;
        throw "pcap_open_live error";
    }

    std::cout << "attached to " << adapter[0] << std::endl;
}

Packetcapture::Packetcapture()
{
    selectInterface();
    attachInterface();
}