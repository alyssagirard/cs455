/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Alyssa Girard
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

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
	// Always check for incoming NULL pointers
    if (fname == NULL)
    {
        printf("fname is null\n");
        return -1;
    }

    if (p == NULL)
    {
        printf("p is null\n");
        return -1;
    }

    size_t mnum_read;
    size_t v_ma;
    size_t v_mi;
    size_t tz;
    size_t sf;
    size_t sl;
    size_t nw;


	// Successfully open the input 'fname'
    pcapInput = fopen(fname, "rb");
    if (pcapInput == NULL) 
    {
        printf("PCAP input is null\n");
        return -1;
    }

    //read input into the global header
    mnum_read = fread(&p->magic_number, sizeof(p->magic_number), 1, pcapInput);
    if (mnum_read != 1){
        return -1;
    } 

    v_ma = fread(&p->version_major, sizeof(p->version_major), 1, pcapInput);
    if (v_ma != 1) {
        return -1;
    } 
    v_mi = fread(&p->version_minor, sizeof(p->version_minor), 1, pcapInput);
    if (v_mi != 1) {
        return -1;
    } 

    tz = fread(&p->thiszone, sizeof(p->thiszone), 1, pcapInput);
    if (tz != 1) {
        return -1;
    } 

    sf = fread(&p->sigfigs, sizeof(p->sigfigs), 1, pcapInput);
    if (sf != 1) {
        return -1;
    } 

    sl = fread(&p->snaplen, sizeof(p->snaplen), 1, pcapInput);
    if (sl != 1) {
        return -1;
    } 

    nw = fread(&p->network, sizeof(p->network), 1, pcapInput);
    if (nw != 1) {
        return -1;
    } 

    // Determine the capturer's byte ordering
    // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second 
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.

    // AKA Properly set the global flags: bytesOK  and   microSec
    // printf("p->magic_number: %x\n", p->magic_number);

    if (p->magic_number == 0xa1b2c3d4){
        //microseconds,little endian
        bytesOK = true;
        microSec = true;

    }else if (p->magic_number == 0xd4c3b2a1){
        //microsecondss, big endian
        bytesOK = false;
        microSec = true;

    }else if (p->magic_number == 0xa1b23c4d) {
        // nanoseconds, little endian
        bytesOK = true;
        microSec = false;
    } else if(p->magic_number == 0x4d3cb2a1) {
        //nanoseconds, swapped
        bytesOK = false;
        microSec = false;

    } else {
        printf("Unrecognized magic number\n");
        return -1;
    }

    if( ! bytesOK )
    {
        // reorder the bytes of the fields in this packet header
        p->version_major = swapbytes_16(p->version_major);
        p->version_minor = swapbytes_16(p->version_minor);
        p->thiszone = swapbytes_32(p->thiszone);
        p->sigfigs = swapbytes_32(p->sigfigs);
        p->snaplen = swapbytes_32(p->snaplen);
        p->network = swapbytes_32(p->network);
    }

    return 0;
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
    // Check for incoming NULL pointers
    if (p == NULL)
    {
        printf("p is null\n");
        return false;
    }

    if (ethFrame == NULL)
    {
        printf("ethframe is null\n");
        return false;
    }

    
    size_t tssec;
    size_t tsusec;
    size_t ilen;
    size_t olen;


    // Read the header of the next packet in the PCAP file

    tssec = fread(&p->ts_sec, sizeof(p->ts_sec), 1, pcapInput);
    if (tssec != 1) 
    {
        return false;
    }

    tsusec = fread(&p->ts_usec, sizeof(p->ts_usec), 1, pcapInput);
    if (tsusec != 1) 
    {
        return false;
    }

    ilen = fread(&p->incl_len, sizeof(p->incl_len), 1, pcapInput);
    if (ilen != 1) 
    {
        return false;
    }

    olen = fread(&p->orig_len, sizeof(p->orig_len), 1, pcapInput);
    if (olen != 1) 
    {
        return false;
    }

    // Did the capturer use a different 
    // byte-ordering than mine (as determined by the magic number)?
    if( ! bytesOK )   // TODO
    {
        // reorder the bytes of the fields in this packet header
        p->ts_sec = swapbytes_32(p->ts_sec);
        p->ts_usec = swapbytes_32(p->ts_usec);
        p->incl_len = swapbytes_32(p->incl_len);
        p->orig_len = swapbytes_32(p->orig_len);
        
    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    fread(ethFrame, 1, p->incl_len, pcapInput);
    if (p->incl_len > MAXFRAMESZ) 
    {
        return false;
    }

    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
    if (!baseTimeSet) 
    {
        if (!microSec) 
        { // if in nanoseconds
            baseTime = (p->ts_usec / 1000000000.0) + p->ts_sec;
            baseTimeSet = true;
        } else 
        { // If in microseconds
            baseTime = (p->ts_usec / 1000000.0) + p->ts_sec;
            baseTimeSet = true;
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


    // Prot
    // printf("%u", frPtr->eth_type);


}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
    return buf;
}