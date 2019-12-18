#include <sstream>
#include "packetcapture.h"
#include <arpa/inet.h>
#include "netinet/ether.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"

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

    std::cout << "attached to " << adapter[0] << std::endl << std::endl;
}


void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    std::stringstream out;

    /* layer 2 parsing */
    struct ether_header *ethernet;
    ethernet = (struct ether_header *) pkt_data;
    if (sizeof(*ethernet) > header->caplen)
        return;

    const struct ether_addr *__addr_dst = (const struct ether_addr *) &ethernet->ether_dhost;
    const struct ether_addr *__addr_src = (const struct ether_addr *) &ethernet->ether_shost;
    
    /* layer 3 parsing */
    struct ip *ip;
    ip = (struct ip *) pkt_data + sizeof(*ethernet);
    unsigned int iph_len = ip->ip_hl * 4;
    if (sizeof(*ethernet) + iph_len > header->caplen)
        return;

    
    out << header->ts.tv_sec << ":" << header->ts.tv_usec << "  " << ether_ntoa(__addr_src) << " -> " <<  ether_ntoa(__addr_dst) << "  ";
    out << inet_ntoa(ip->ip_src) << " -> " << inet_ntoa(ip->ip_dst);
    
    std::cout << out.str() << std::endl;
}


Packetcapture::Packetcapture()
{
    selectInterface();
    attachInterface();

    //applyFilter()   //TODO: actually no filters are used

    pcap_loop(handle, 0, dispatcher_handler, nullptr);

    pcap_close(handle);

}