#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

class Packetcapture
{
    public:
    Packetcapture();

    private:
    std::string *adapter = nullptr;
    pcap_t *handle = nullptr;
    int snaplen;

    pcap_if_t* showInterfaces(int& numberOfInterfaces);
    void selectInterface();
    void attachInterface();

};