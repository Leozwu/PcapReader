#include <iostream>
#include <pcap.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "messages.h"
using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main()
{
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // open capture file for offline processing
    descr = pcap_open_offline("test.pcap", errbuf);
    if (descr == NULL)
    {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0)
    {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    cout << "capture finished" << endl;
    return 0;
}

int mcount =0;

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    //  const struct tcphdr* tcpHeader;
    const struct udphdr *udpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    string dataStr = "";

    ethernetHeader = (struct ether_header *)packet;
    mcount++; // for break point counter
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_VLAN)  // vlan 0x8100
    {
        // filter 802.1Q vlan tag : 4 bytes
        ipHeader = (struct ip *)(packet + sizeof(struct ether_header) + 4); //  vlan tag
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_UDP)
        {
            udpHeader = (udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + 4);
            sourcePort = ntohs(udpHeader->source);
            destPort = ntohs(udpHeader->dest);

            data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 4);
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 4);

            // starting debug code for gdb--------------
            ENXTPacket* phdr = (ENXTPacket*) data;
            ENXTFrame* pframe = (ENXTFrame*) (data + sizeof(ENXTPacket));
            ENXTSBEMsg* psbe = (ENXTSBEMsg*) (data + sizeof(ENXTPacket) + sizeof(ENXTFrame));
            
            // force convert to different type for GDB
            standing * pstanding =(standing*) (data + sizeof(ENXTPacket));
            contract * pcontract =(contract*) (data + sizeof(ENXTPacket));
            outright * poutright =(outright*) (data + sizeof(ENXTPacket));

            uint64_t l = (phdr->psn);
            uint16_t mt = (psbe->tempid);

            if (mt >0){
                cout<<"No="<<mcount<<"\tdatalen="<<dataLength<<"\tpsn="<<l<<"\tchannelid="<<phdr->channelid<<"\tframelen="<<pframe->frame<<"\ttmpid="<<mt<<endl;
            }
        }
    }
}
