#include <sstream>
#include <string>
#include <arpa/inet.h>
#include "packetcapture.h"
#include "netinet/ether.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"

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
    if (ntohs(ethernet->ether_type) != ETH_P_IP)
        return;

    struct ip *ip;
    ip = (struct ip *) (pkt_data + sizeof(*ethernet));
    unsigned int iph_len = ip->ip_hl * 4;
    if (sizeof(*ethernet) + iph_len > header->caplen)
        return;

    /* layer 4 parsing */
    std::string protocol;
    struct tcphdr *tcp = nullptr;
    struct udphdr *udp = nullptr;
    uint16_t sport = 0, dport = 0;
    bool is_get_or_post = false;
    std::string uri;
    if (uint64_t(ip->ip_p) == IPPROTO_TCP)  /* TCP packet */
    {
        protocol = "TCP";
        tcp = (struct tcphdr *)(pkt_data + sizeof(*ethernet) + iph_len);
        
        if (sizeof(*ethernet) + iph_len + sizeof(tcp) > header->caplen)
            return;
        
        sport = tcp->source;
        dport = tcp->dest;

        if (ntohs(dport) == 80)
        {
            std::string http((char *)(pkt_data + sizeof(*ethernet) + iph_len + sizeof(*tcp)));
            if ((http.find("GET") != std::string::npos) || (http.find("POST") != std::string::npos))
            {              
                is_get_or_post = true;
                size_t host_pos = http.find("Host: ");
                
                if (host_pos == std::string::npos)
                {
                    std::cout << "[Packetcapture] - Error at dispatcher_handler - " << "Error - no 'Host: ' found" << std::endl;
                    throw "Error - no 'Host: ' found";
                }

                uri = std::string((const char *)(http.c_str() + host_pos + 6));     /* afther 'Host: ' */
                uri = uri.substr(0, uri.find("\n"));
            }
        }
    }
    else if (uint(ip->ip_p) == IPPROTO_UDP) /* UDP packet */
    {
        protocol = "UDP";
        udp = (struct udphdr *)(pkt_data + sizeof(*ethernet) + iph_len);

        if (sizeof(*ethernet) + iph_len + sizeof(udp) > header->caplen)
            return;

        sport = udp->source;
        dport = udp->dest;
    }
    else                                    /* no TCP or UDP packet */
        return;
    

    /* output */
    out << header->ts.tv_sec << ":" << header->ts.tv_usec << " \t" << ether_ntoa(__addr_src) << " -> " <<  ether_ntoa(__addr_dst) << " \t";
    out << inet_ntoa(ip->ip_src) << " -> " << inet_ntoa(ip->ip_dst) << "\t\t";
    out << protocol << "\t" << ntohs(sport) << " -> " << ntohs(dport) << "\t";
    if (is_get_or_post)
        out << uri;
    
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