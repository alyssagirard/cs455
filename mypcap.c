/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Jed Miller & Alyssa Girard
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

// Custom utilities
char *ipHeaderToStr(const ipv4Hdr_t *ip_header , char *headerStr);

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double      baseTime ;  // capturing time (in seconds ) of the very 1st packet in this file
bool        baseTimeSet = false ;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
uint32_t swapbytes_32( uint32_t to_swap ) 
{
    return ((to_swap>> 24) & 0x000000FF) |
          ((to_swap >> 8)  & 0x0000FF00) |
          ((to_swap << 8)  & 0x00FF0000) |
          ((to_swap << 24) & 0xFF000000);
}

/*-------------------------------------------------------------------------*/
uint16_t swapbytes_16( uint16_t to_swap ) 
{
    return (to_swap >> 8) | (to_swap << 8);
}

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
    if (fname == NULL || p == NULL) 
    {
        return -1;
    }

    // Open the file
    pcapInput = fopen(fname, "r");
    

    // Read the file header
    if (fread(p, sizeof(pcap_hdr_t), 1, pcapInput) != 1) {
        return -1;
    }

    // Check the magic number
    // 
    // This checks the two cases to find the timestamp format. It also checks them in reverse to
    // see if the file was writen using a different endianess than the current machine 
    // reading the file
    #define MICROSEC_MAGIC_NUMBER 0xA1B2C3D4
    #define NANOSEC_MAGIC_NUMBER 0xA1B23C4D

    switch (p->magic_number)
    {
    // Host ordered
    case MICROSEC_MAGIC_NUMBER:
        microSec = true;
        bytesOK = true;
        break;
    case NANOSEC_MAGIC_NUMBER:
        microSec = false;
        bytesOK = true;
        break;
    // Reverse order
    case __builtin_bswap32(MICROSEC_MAGIC_NUMBER):
        microSec = true;
        bytesOK = false;
        break;
    case __builtin_bswap32(NANOSEC_MAGIC_NUMBER):        
        microSec = false;
        bytesOK = false;
        break;
    default:
        return -1;
    }

    // Fix the header if the endianess is wrong
    if (! bytesOK) {
        p->version_major = __builtin_bswap16(p->version_major);
        p->version_minor = __builtin_bswap16(p->version_minor);
        p->thiszone      = __builtin_bswap32(p->thiszone);
        p->sigfigs       = __builtin_bswap32(p->sigfigs);
        p->snaplen       = __builtin_bswap32(p->snaplen);
        p->network       = __builtin_bswap32(p->network);
    }
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"                           , p->magic_number );    
    
    printf("major version %u\n"                           , p->version_major );    

    printf("minor version %u\n"                           , p->version_minor );    

    printf("GMT to local correction %d seconds\n"                           , p->thiszone );    

    printf("accuracy of timestamps %u\n"                           , p->sigfigs );    

    printf("Cut-off max length of captured packets %u\n"                           , p->snaplen );    

    printf("data link type %u\n"                           , p->network );    
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    if (p == NULL || ethFrame == NULL) {
        return false;
    }

    if(fread(p, sizeof(packetHdr_t), 1, pcapInput) != 1) {
        return false;
    }

    // Check if bytes need to be reordered to match endianess
    if( ! bytesOK )   
    {
        p->ts_sec   = __builtin_bswap32(p->ts_sec);
        p->ts_usec  = __builtin_bswap32(p->ts_usec);
        p->incl_len = __builtin_bswap32(p->incl_len);
        p->orig_len = __builtin_bswap32(p->orig_len);
    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    if (fread(ethFrame, p->incl_len, 1, pcapInput) != 1) {
        return false;
    }

    // Set the baseTime if it isn't set
    if (! baseTimeSet) {
        baseTimeSet = true;

        if (microSec) {
            // Microseconds
            baseTime = (p->ts_sec * 1.0) + (p->ts_usec * 0.000001);
        } else {
            // Nanoseconds
            baseTime = (p->ts_sec * 1.0) + (p->ts_usec * 0.000000001);
        }
    }
    
    return true ;
}


/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p  )
{
    double time;
    // time stamp
    if (!microSec) 
    { // if in nanoseconds
        time = p->ts_sec + (p->ts_usec / 1000000000.0);
        time = time - baseTime;
    } else 
    { // if in microseconds
        time = p->ts_sec + (p->ts_usec / 1000000.0);
        time = time - baseTime; 
    }

    printf("%.6f     ", time);
    // OrgLen
    printf("%d /     ", p->orig_len);

    // Captrd
    printf("%d ", p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */ 

void printPacket( const etherHdr_t *frPtr )
{
    // print Source/Destination MAC addresses

    // Source
    char source[18];
    macToStr(frPtr->eth_srcMAC, source);
    printf("%s    ", source);

    // Dest
    char dest[18];
    macToStr(frPtr->eth_dstMAC, dest);
    printf("%s    ", dest);
}

void printARPinfo( const arpMsg_t *m ) 
{
    printf("ARP      ");

    char senderIp[16];
    char destinationIp[16];
    char senderMac[18];

    switch (ntohs(m->arp_oper))
    {
    case ARPREQUEST:
        printf("Who has %s ? Tell %s",
            ipToStr(m->arp_tpa, destinationIp),
            ipToStr(m->arp_spa, senderIp)
        );
        break;
    case ARPREPLY:
        printf("%s is at %s",
            ipToStr(m->arp_spa, senderIp),
            macToStr(m->arp_sha, senderMac)
        );
        break;
    default:
        printf("ARP_ERROR");
        break;
    }
}

void printIPinfo ( const ipv4Hdr_t *ipHeader )
{
    char srcStr[MAXIPv4ADDRLEN];
    char dstStr[MAXIPv4ADDRLEN];

    ipToStr(ipHeader->ip_srcIP, srcStr);
    printf("%s    ", srcStr);

    ipToStr(ipHeader->ip_dstIP, dstStr);
    printf("%s    ", dstStr);

    char ip_header_buffer[64];
    switch (ipHeader->ip_proto)
    {
    case PROTO_ICMP:
        printf("ICMP     ");


        // char ip_header_buffer[64];
        printf("%s ",
            ipHeaderToStr(ipHeader, ip_header_buffer)
        );


        // Take the start of ip header, add the header length, cast to ICMP header
        icmpHdr_t *icmp_header = (icmpHdr_t*)((uint8_t*)ipHeader + (ipHeader->ip_verHlen & 0x0F) * 4);

        // These two lines select a pointer into the array, cast it to a number, and then adjust for network ordering
        uint16_t sequence_number = ntohs(*(uint16_t*)&icmp_header->icmp_line2[2]);
        uint16_t id_number = ntohs(*(uint16_t*)&icmp_header->icmp_line2);

        printf("ICMP_HDR{ %-12s :id= %d, seq=%5d} ",
            // TODO: Error check other types?
            icmp_header->icmp_type == ICMP_ECHO_REQUEST ? "Echo Request" : "Echo Reply",
            id_number,
            sequence_number
        );

        uint8_t icmp_hlen_bytes = (ipHeader->ip_verHlen & 0x0F) * 4;

        uint16_t icmp_total_len = ntohs(ipHeader->ip_totLen);

        uint16_t icmp_payload_len = icmp_total_len - icmp_hlen_bytes;

        uint16_t icmp_data_len = icmp_payload_len - sizeof(icmp_header);

        printf("AppData=   %d", icmp_data_len);


        break;
    case PROTO_TCP:
        printf("TCP      ");

        printf("%s ",
            ipHeaderToStr(ipHeader, ip_header_buffer)
        );
        // TO FIX
        

        uint8_t tcp_hlen_bytes = (ipHeader->ip_verHlen & 0x0F) * 4;

        uint16_t tcp_total_len = ntohs(ipHeader->ip_totLen);

        uint16_t tcp_payload_len = tcp_total_len - tcp_hlen_bytes;

        printf("AppData=   %d", tcp_payload_len);

        break;

    case PROTO_UDP:
        printf("UDP      ");

        printf("%s ",
            ipHeaderToStr(ipHeader, ip_header_buffer)
        );

        // TO FIX

        uint8_t udp_hlen_bytes = (ipHeader->ip_verHlen & 0x0F) * 4;

        uint16_t udp_total_len = ntohs(ipHeader->ip_totLen);

        uint16_t udp_payload_len = udp_total_len - udp_hlen_bytes - 8;

        printf("AppData=   %d", udp_payload_len);
        

        // hlen_bytes = (ipHeader->ip_verHlen & 0x0F) * 4;

        // // Subtract from ethernet header size
        // payload_len = p->incl_len - sizeof(etherHdr_t) - hlen_bytes;
        
        // data_len = payload_len - 8;

        // printf("AppData=   %d", data_len);

        break;
    
    default:
        printf("UNKNOWN_PROTOCOL");
        break;
    }

    return;
}

unsigned printICMPinfo( const icmpHdr_t * )
{
    return 1;
}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
char *ipToStr( const IPv4addr ip , char *ipStr  )
{
    sprintf(ipStr, "%u.%u.%u.%u", ip.byte[0], ip.byte[1], ip.byte[2], ip.byte[3]);
    return ipStr;
}

/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}

/* headerStr needs to be at least 39 bytes long */
char *ipHeaderToStr(const ipv4Hdr_t *ip_header , char *headerStr)
{
    int ip_header_len = (ip_header->ip_verHlen & 0x0F) * 4;

    sprintf(headerStr, "IP_HDR{ Len=%d incl. %d options bytes}",
        ip_header_len,
        ip_header_len - 20
    );

    return headerStr;
}