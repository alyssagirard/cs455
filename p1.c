/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Jed Miller & Alyssa Girard
    File Name:          p1.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-------------------------------------------------------------------------*/
void usage(char *cmd)
{
    printf("Usage: %s PCAP_file_Name\n" , cmd);
}

/*-------------------------------------------------------------------------*/

int main( int argc  , char *argv[] )
{
    char        *pcapIn ;
    pcap_hdr_t   pcapHdr ;
    packetHdr_t  pktHdr  ;
    uint8_t      ethFrame[MAXFRAMESZ] ;

    // Convinient pointers to specific parts of the data
    etherHdr_t  *frameHdrPtr = (etherHdr_t  *) ethFrame ;
    arpMsg_t    *arpBody  = (arpMsg_t *)  (ethFrame + sizeof(etherHdr_t));
    ipv4Hdr_t   *ipv4Body = (ipv4Hdr_t *) (ethFrame + sizeof(etherHdr_t));

    
    if ( argc < 2 )
    {
        usage( argv[0] ) ;
        exit ( EXIT_FAILURE ) ;
    }

    pcapIn = argv[1] ;
    printf("\nProcessing PCAP file '%s'\n\n" , pcapIn ) ;

    // Read the global header of the pcapInput file
    // By calling readPCAPhdr().
    // If error occured, call errorExit("Failed to read global header from the PCAP file " )
    if (readPCAPhdr(pcapIn, &pcapHdr) == -1 )
    {
        errorExit("Failed to read global header from the PCAP file " );
    }


    // Print the global header of the pcap filer
    // using printPCAPhdr()
    printPCAPhdr(&pcapHdr);

    // Print labels before any packets are printed
    puts("") ;
    printf("%6s %14s %6s / %6s %-20s %-20s %8s %s\n" ,
           "PktNum" , "Time Stamp" , "OrgLen" , "Captrd"  , 
           "Source" , "Destination" , "Protocol" , "info");

    // Read one packet at a time
    int i = 1;
    while ( getNextPacket(&pktHdr, &ethFrame[0]) )
    {
        printf("     %d       ", i);
        // Use packetMetaDataPrint() to print the packet header data; 
        printPacketMetaData(&pktHdr);
        //          Time is printed relative to the 1st packet's time
        // Use packetPrint( ) to print the actual content of the packet starting at the
        // ethernet level and up
        printPacket(frameHdrPtr);

        // Print the protocol
        /* 46<=eth_type<=1500 ? Payload Len : Protocol */
        switch (ntohs(frameHdrPtr->eth_type))
        {
        case PROTO_ARP:
            printARPinfo(arpBody);
            break;

        case PROTO_IPv4:
            printIPinfo(ipv4Body);
            break;
        
        default:
            printf("UNKNOWN_PROTOCOL: %d", frameHdrPtr->eth_type);
            break;
        }
        // if protocol is arp, then run printarpinfo
        // if protocol is icmp, then run printicmp
        // if protocol is tcp or udp, print ipinfo?

        puts("");       
        i++;
    }
    
    printf("\nReached end of PCAP file '%s'\n" , pcapIn ) ;
    cleanUp() ;    
}

