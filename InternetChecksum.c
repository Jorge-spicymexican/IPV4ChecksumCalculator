/* Copyright (C) 2022 MOSE
 *
 * All Rights Reserved
 * You may not use, distribute or modify this code without the
 * express written permission of MSOE
 *
 * Contact Info
 * Jorge Jurado-Farica
 * 608-312-5950
 * jurado-garciaj@msoe.edu
 *
 */

#include "InternetChecksum.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

//function prototypes
//Prototypes functions
void RequestingInfo_First_32Bits(IPHeader_TYPE* HeaderData);
void RequestingInfo_Second_32Bits(IPHeader_TYPE* HeaderData);
void RequestingInfo_Third_32Bits(IPHeader_TYPE* HeaderData);
void Requesting_Source_IP_Address(IPHeader_TYPE* HeaderData);
void Requesting_Destination_IP_Address(IPHeader_TYPE* HeaderData);
void Getting_Options( IPHeader_TYPE* HeaderData);
void IPCHECK(IPHeader_TYPE* HeaderData);
char PrintIP4Header(IPHeader_TYPE* HeaderData);
unsigned int ip_to_int (const char * ip);
unsigned short* SetupIPHeader(IPHeader_TYPE* HeaderData);
void IPHeaderInBytes(unsigned short* uacharIP);
char WithinBounds( int Value, int LowerBound, int UpperBound);

/* Convert the character string in "ip" into an unsigned integer.
   This assumes that an unsigned integer contains at least 32 bits.
*/
unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;
    start = ip;
    
    /// for throught the ip data and check if its 0.0.0.0 send in 0.

    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return INVALID;
            }
        }
        if (n >= 256) {
            return INVALID;
        }
        v *= 256;
        v += n;
    }
    return v;
}

//code for functions
//Prototypes functions
void RequestingInfo_First_32Bits(IPHeader_TYPE* HeaderData)
{
    unsigned char cUserIHL;
    unsigned char ucUserDSCP;
    unsigned char ucUserECN;
    unsigned short usUserLength;

    //introudction
    printf("Please enter your values as integers, THANKS!\n");

    // Entering Internet Header Length
    printf("Enter the Internet Header Length (IHL): ");
    scanf("%d", &cUserIHL);
    printf("IHL entered: %d\n", cUserIHL);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(cUserIHL, IHL_MIN, IHL_MAX) == -1 )
    {
        printf("Entered IHL Value is out of bounds, setting IHL to min: 5\n");
        cUserIHL = 5;
    }

    HeaderData->ucIHL = cUserIHL;


    // Getting the DSCP value of the IPv4 header format
    printf("Enter the Differentiated Services Code Point (DSCP): ");
    scanf("%d", &ucUserDSCP);
    printf("DSCP entered: %d\n", ucUserDSCP);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(ucUserDSCP, DSCP_MIN, DSCP_MAX) == -1 )
    {
        printf("Entered DSCP Value is out of bounds, setting DSCP to min: 0\n");
        ucUserDSCP = 0;
    }

    HeaderData->usDSCHP = ucUserDSCP;


    // Getting the ECN value of the IPv4 header format
    // Possible Values are 00, 10, 01, 11
    printf("Enter the ECN (Possible Values 0-3): ");
    scanf("%d", &ucUserECN);
    printf("ECN entered: %d\n", ucUserECN);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(ucUserECN, ECN_MIN, ECN_MAX) == -1 ) //outside of founds
    {
        printf("Entered ECN Value is out of bounds, setting ECN to min: 0\n");
        ucUserECN = 0;
    }

    HeaderData->ucECN = ucUserECN;

    // Getting the Total Length values of the IPv4 header format
    // this indicates the entir sixe of the IP packet max size is 65,535 bytes
    printf("Enter the Entire Size of the IP Packet in bytes (Possible Values 0-65,535): ");
    scanf("%d", &usUserLength);
    printf("IP Packet Size entered: %d\n", usUserLength);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(usUserLength, TOTAL_LENGTH_MIN, TOTAL_LENGTH_MAX) == -1 ) //outside of founds
    {
        printf("Entered Length of IP packet Value is out of bounds, setting Size of packet to 10\n");
        usUserLength = 10;
    }

    // storing the values into the struct
    HeaderData->cVersion = 4;
    HeaderData->usTotal_Length = usUserLength;
    HeaderData->usHeader_Checksum = 0;

    return;
}


// functions for requesting 4-8 Octets of the IPv4 Header
void RequestingInfo_Second_32Bits(IPHeader_TYPE* HeaderData)
{
    unsigned short usID;
    unsigned char FlagString;
    unsigned short usOffset;

    //introudction
    printf("Please enter your values in base 10 format, THANKS!\n");

    printf("Enter the Identification Number only Positive Value: ");
    scanf("%d", &usID);
    printf("ID entered: %d\n", usID);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(usID, ID_MIN, ID_MAX) == -1 )
    {
        printf("Entered ID Value is out of bounds, setting ID to 40 \n");
        usID = 40;
    }
    // setting up the structure with this information
    HeaderData->usIdentification = usID;

    // selecting Fragement flags
    printf("Please entery your Flag Value\n");
    scanf("%d", &FlagString);
    printf("Entered Value: %d\n", FlagString);

    HeaderData->ucFlags = FlagString;


    //setting fragmeent offset
    // this sepcifies the position of the fragment in the orginal
    // fragement IP packet
    printf("Enter the Fragement Offset only Positive Value: ");
    scanf("%d", &usOffset);
    printf("Offset entered: %d\n", usOffset);
    //check if the cUserIHL is witin our bounds
    if( WithinBounds(usOffset, FRAGEMENT_OFFSET_MIN, FRAGEMENT_OFFSET_MAX) == -1 )
    {
        printf("Entered Fragement Offset Value is out of bounds, setting Fragement offset to 0 \n");
        usOffset = 0;
    }

    HeaderData->usFragment_Offset = usOffset;
    return;
}


// Getting the Time to live and protcol values.
void RequestingInfo_Third_32Bits(IPHeader_TYPE* HeaderData)
{
    // setting up octions as all zeros.
    // initalizing all the first to zero
    HeaderData->Options_0 = 0;
    HeaderData->Options_1 = 0;
    HeaderData->Options_2 = 0;
    HeaderData->Options_3 = 0;

    unsigned char ucTimetoLive;
    unsigned char ucProtcol;

    // allow the user to put in the time to live
    printf("Please select your Time to Live value, (0-256): ");
    scanf("%d", &ucTimetoLive);
    printf("Time to Live entered: %d\n", ucTimetoLive);
    //check if the value is witin our bounds
    if( WithinBounds(ucTimetoLive, TIME_TO_LIVE_MIN, TIME_TO_LIVE_MAX) == -1 )
    {
        printf("Entered Time to live Value is out of bounds, setting value to 1 \n");
        ucTimetoLive = 1;
    }
    //go ahead and set the values now
    HeaderData->ucTime_To_Live = ucTimetoLive;


    printf("Please select your Protocol,");
    scanf("%d", &ucProtcol);
    printf("Protocol entered: %d\n", ucProtcol);
    //check if the value is witin our bounds
    if( WithinBounds(ucProtcol, PROTOCOL_MIN, PROTOCOL_MAX) == -1 )
    {
        printf("Entered Protocol Value Value is out of bounds, setting valuue to Ethernet (143)\n");
        ucProtcol = 143;
    }
    HeaderData->ucProtcol = ucProtcol;

    return;
}

// getting the source IP address
void Requesting_Source_IP_Address(IPHeader_TYPE* HeaderData)
{
    /*
    In order to do this setup I will have to allocate memory for this string
    in my code using calloc and malloc.
    */
    char *SourceIPAddress; //pointer to a charcter 
    SourceIPAddress = (char*)malloc(sizeof(char)*4);

    printf("Please Enter your Source IP Address in QUAD format MAX: '255.255.255.255'\n");
    scanf("%s", SourceIPAddress);

    // error checking for a valid IP address
    // error checking formula for validating a good IP address
    unsigned long int integer = ip_to_int(SourceIPAddress);

    printf("Intger value received\n");

    if (integer == INVALID)
    {
        printf ("'%s' is not a valid IP address.\n", SourceIPAddress);
    }
    else
    {
        printf ("'%s' is %d.\n", SourceIPAddress, integer);
    }

    HeaderData->acSourceIPAddress = integer;
    free(SourceIPAddress);
    return;
}


// getting the destination IP Address
void Requesting_Destination_IP_Address(IPHeader_TYPE* HeaderData)
{
    char* DestinationIPAddress;
    DestinationIPAddress = (char*)malloc(sizeof(char)*4);
    printf("Please Enter your Destination IP Address in QUAD format MAX: '255.255.255.255'\n");
    scanf("%s", DestinationIPAddress);

    // error checking formula for validating a good IP address
    unsigned long int IPAddress_int = ip_to_int(DestinationIPAddress);

    if (IPAddress_int == INVALID)
    {
        printf ("'%s' is not a valid IP address.\n", DestinationIPAddress);
    }
    else
    {
        printf ("'%s' is %u.\n", DestinationIPAddress, IPAddress_int);
    }

    HeaderData->acDestinationIPAddress = IPAddress_int;
    free(DestinationIPAddress);
    return;
}


// setting up options
void Getting_Options( IPHeader_TYPE* HeaderData)
{

    // getting the options of the system
    unsigned short Options_number = HeaderData->ucIHL - 5;
    unsigned int Option;
    printf("Number of Options to be inserted: %d\n", Options_number);

    for( int i = 0; i < Options_number; i++)
    {
        // go there the printing function and insert the value into your array
        printf("Option[%d] : Please enter your 32 Bit Value (0-4,294,967,295):", i);
        scanf("%d", &Option);
        printf("Entered Valued: %d\n", Option);

        // sitting up the switch case statment for the flow control
        switch(i)
        {
            case 0:
            //write code
            HeaderData->Options_0 = Option;
            break;

            case 1:
            //write code
            HeaderData->Options_1 = Option;
            break;

            case 2:
            //write code
            HeaderData->Options_2 = Option;
            break;

            case 3:
            //write code
            HeaderData->Options_3 = Option;
            break;

        }
    }

}


// prints IP header data before calculating checksum
char PrintIP4Header(IPHeader_TYPE* HeaderData)
{
    //printf from start to finish
    printf("==========IP Header before CheckSum Calculation========\n");
    printf("================ 0 - 31 Bits ========================\n");
    printf("Version: %u\n", HeaderData->cVersion);
    printf("IHL: %u\n", HeaderData->ucIHL);
    printf("DSCHP: %u\n", HeaderData->usDSCHP);
    printf("ECN: %u\n", HeaderData->ucECN);
    printf("Total Length: %u\n", HeaderData->usTotal_Length);

    printf("=====================================================\n");
    printf("=============== 32 - 63 Bits ========================\n");
    printf("Identification: %u\n", HeaderData->usIdentification);
    printf("Flags (1-ONE/0-OFF): %u\n", HeaderData->ucFlags);
    printf("Flag Offset: %u\n", HeaderData->usFragment_Offset);

    printf("=====================================================\n");
    printf("=============== 64 - 95 Bits ========================\n");
    printf("Time out Counter: %u\n", HeaderData->ucTime_To_Live);
    printf("Protocol: %u\n", HeaderData->ucProtcol);
    printf("Inital CheckSum: %u\n", HeaderData->usHeader_Checksum);

    printf("=====================================================\n");
    printf("=============== 96 - 159 Bits =======================\n");
    printf("Source IP Address: %u\n", HeaderData->acSourceIPAddress);
    printf("Destination IP Address: %u\n", HeaderData->acDestinationIPAddress);

    printf("=====================================================\n");
    printf("============== Options( If IHL > 5) =================\n");
    printf("=============== 160 - 288 Bits ======================\n");
    printf("Option_0: %u\n", HeaderData->Options_0);
    printf("Option_1: %u\n", HeaderData->Options_1);
    printf("Option_2: %u\n", HeaderData->Options_2);
    printf("Option_3: %u\n", HeaderData->Options_3);

    return 0;
}


// Calculates IPv4 checksum and stores into the IP Header struct
void IPCHECK(IPHeader_TYPE* HeaderData)
{

    //unsigned short *uacharIP;
    //uacharIP = SetupIPHeader(HeaderData);
    unsigned short uacharIP[18];

    //uacharIP = malloc(sizeof(short)*17); //created a variable in main memory

    // first created values into an array of bytes
    uacharIP[0] = (HeaderData->cVersion << 12) + (HeaderData->ucIHL << 8) +
                           (HeaderData->usDSCHP << 2) + (HeaderData->ucECN);
    uacharIP[1] = (HeaderData->usTotal_Length);
    uacharIP[2] = (HeaderData->usIdentification);

    //adding frags offset and fragment bit 
    uacharIP[3] = (HeaderData->ucFlags << 13) + (HeaderData->usFragment_Offset);

    uacharIP[4] = (HeaderData->ucTime_To_Live << 8) + (HeaderData->ucProtcol);
    uacharIP[5] = HeaderData->usHeader_Checksum;

    //calculating source IP Address shifting the data 
    uacharIP[6] = HeaderData->acSourceIPAddress >> 16;  //option 0 upper byte
    uacharIP[7] = HeaderData->acSourceIPAddress & 0xFFFF;  //option 0 lower byte

    //destination IP Address
    uacharIP[8] = HeaderData->acDestinationIPAddress >> 16;  //option 0 upper byte
    uacharIP[9] = HeaderData->acDestinationIPAddress & 0xFFFF;  //option 0 lower byte


    if( HeaderData-> ucIHL > 5 )
    {
        //options configuration
        uacharIP[10] = HeaderData->Options_0 >> 16;  //option 0 upper byte
        uacharIP[11] = HeaderData->Options_0 & 0xFFFF;  //option 0 lower byte

        uacharIP[12] = HeaderData->Options_1 >> 16; //option 1 upper byte
        uacharIP[13] = HeaderData->Options_1 & 0xFFFF; //option 1 lower byte

        uacharIP[14] = HeaderData->Options_2 >> 16;  //option 2 upper byte
        uacharIP[15] = HeaderData->Options_2 & 0xFFFF;  //option 2 lower byte

        uacharIP[16] = HeaderData->Options_3 >> 16; //option 3 upper byte
        uacharIP[17] = HeaderData->Options_3 & 0xFFFF; //option 3 lower byte
    }
    else
    {
                //options configuration
        uacharIP[10] = 0;  //option 0 upper byte
        uacharIP[11] = 0;  //option 0 lower byte

        uacharIP[12] = 0; //option 1 upper byte
        uacharIP[13] = 0; //option 1 lower byte

        uacharIP[14] = 0;  //option 2 upper byte
        uacharIP[15] = 0;  //option 2 lower byte

        uacharIP[16] = 0; //option 3 upper byte
        uacharIP[17] = 0; //option 3 lower byte
    }
    

    printf("Information for uacharIP[0]: %16x\n", uacharIP[0]);
    printf("Information for uacharIP[1]: %16x\n", uacharIP[1]);
    printf("Information for uacharIP[2]: %16x\n", uacharIP[2]);
    printf("Information for uacharIP[3]: %16x\n", uacharIP[3]);
    printf("Information for uacharIP[4]: %16x\n", uacharIP[4]);
    printf("Information for uacharIP[5]: %16x\n", uacharIP[5]);
    printf("Information for uacharIP[6]: %16x\n", uacharIP[6]);
    printf("Information for uacharIP[7]: %16x\n", uacharIP[7]);
    printf("Information for uacharIP[8]: %16x\n", uacharIP[8]);
    printf("Information for uacharIP[9]: %16x\n", uacharIP[9]);
    printf("Information for uacharIP[10]: %16x\n", uacharIP[10]);
    printf("Information for uacharIP[11]: %16x\n", uacharIP[11]);
    printf("Information for uacharIP[12]: %16x\n", uacharIP[12]);
    printf("Information for uacharIP[13]: %16x\n", uacharIP[13]);
    printf("Information for uacharIP[14]: %16x\n", uacharIP[14]);
    printf("Information for uacharIP[15]: %16x\n", uacharIP[15]);
    printf("Information for uacharIP[16]: %16x\n", uacharIP[16]);
    printf("Information for uacharIP[17]: %16x\n", uacharIP[17]);

    //loop araound uachar IP to verify the correct bit formation

    printf("Length of Byte array: %d\n", NELEMS(uacharIP) );

    // afterwards do xor or decimal arthmetic to get the values.
    // if the sume of bits is greater than 0xFFFF carry that value and insert it as
    // as a leading carry.
    unsigned long int acc=0;
    // Handle complete 16-bit blocks.
    for (int i=0;i+1<NELEMS(uacharIP); i+=1)
    {
        //printf("%d \n", uacharIP[i]);

        static unsigned short PreviousVal = 0;
        printf("PreviousVal:   %16x\n", PreviousVal);
        printf("Current Value: %16x\n", uacharIP[i] );
        //printf("Previous Added Values:  %16x\n", acc);
        acc = PreviousVal + uacharIP[i]; //in the begging it will be zero
        printf("Added Value:   %16x\n", acc);
        printf("=================================\n");

        if (acc>0xffff) {
            acc-=0xffff;
        }


        PreviousVal = acc;
    }

    printf("Output of checksum calculation before inversion: %16x\n", acc);
    // insert the checksum in the Header Data
    HeaderData->usHeader_Checksum = (unsigned short)(~acc);

    //free(uacharIP);

    return;
}


// setups the array of bytes to be processed by the checksum formula
unsigned short* SetupIPHeader(IPHeader_TYPE* HeaderData)
{
    /*
    static unsigned short uacharIP[17];

    //uacharIP = malloc(sizeof(short)*17); //created a variable in main memory

    // first created values into an array of bytes
    uacharIP[0] = (HeaderData->cVersion << 12) + (HeaderData->ucIHL << 8) +
                           (HeaderData->usDSCHP << 2) + (HeaderData->ucECN);
    uacharIP[1] = (HeaderData->usTotal_Length);
    uacharIP[2] = (HeaderData->usIdentification);
    uacharIP[3] = (HeaderData->ucTime_To_Live << 8) + (HeaderData->ucProtcol);
    uacharIP[4] = HeaderData->usHeader_Checksum;

    //calculating source IP Address shifting the data 
    uacharIP[5] = HeaderData->acSourceIPAddress >> 16;  //option 0 upper byte
    uacharIP[6] = HeaderData->acSourceIPAddress & 0xFFFF;  //option 0 lower byte

    //destination IP Address
    uacharIP[7] = HeaderData->acDestinationIPAddress >> 16;  //option 0 upper byte
    uacharIP[8] = HeaderData->acDestinationIPAddress & 0xFFFF;  //option 0 lower byte


    if( HeaderData-> ucIHL > 5 )
    {
        //options configuration
        uacharIP[9] = HeaderData->Options_0 >> 16;  //option 0 upper byte
        uacharIP[10] = HeaderData->Options_0 & 0xFFFF;  //option 0 lower byte

        uacharIP[11] = HeaderData->Options_1 >> 16; //option 1 upper byte
        uacharIP[12] = HeaderData->Options_1 & 0xFFFF; //option 1 lower byte

        uacharIP[13] = HeaderData->Options_2 >> 16;  //option 2 upper byte
        uacharIP[14] = HeaderData->Options_2 & 0xFFFF;  //option 2 lower byte

        uacharIP[15] = HeaderData->Options_3 >> 16; //option 3 upper byte
        uacharIP[16] = HeaderData->Options_3 & 0xFFFF; //option 3 lower byte
    }
    else
    {
                //options configuration
        uacharIP[9] = 0;  //option 0 upper byte
        uacharIP[10] = 0;  //option 0 lower byte

        uacharIP[11] = 0; //option 1 upper byte
        uacharIP[12] = 0; //option 1 lower byte

        uacharIP[13] = 0;  //option 2 upper byte
        uacharIP[14] = 0;  //option 2 lower byte

        uacharIP[15] = 0; //option 3 upper byte
        uacharIP[16] = 0; //option 3 lower byte
    }
    

    printf("Information for uacharIP[0]: %u\n", uacharIP[0]);
    printf("Information for uacharIP[1]: %u\n", uacharIP[1]);
    printf("Information for uacharIP[2]: %u\n", uacharIP[2]);
    printf("Information for uacharIP[3]: %u\n", uacharIP[3]);
    printf("Information for uacharIP[4]: %u\n", uacharIP[4]);
    printf("Information for uacharIP[5]: %u\n", uacharIP[5]);
    printf("Information for uacharIP[6]: %u\n", uacharIP[6]);
    printf("Information for uacharIP[7]: %u\n", uacharIP[7]);
    printf("Information for uacharIP[8]: %u\n", uacharIP[8]);
    printf("Information for uacharIP[9]: %u\n", uacharIP[9]);
    printf("Information for uacharIP[10]: %u\n", uacharIP[10]);
    printf("Information for uacharIP[11]: %u\n", uacharIP[11]);
    printf("Information for uacharIP[12]: %u\n", uacharIP[12]);
    printf("Information for uacharIP[13]: %u\n", uacharIP[13]);
    printf("Information for uacharIP[14]: %u\n", uacharIP[14]);
    printf("Information for uacharIP[15]: %u\n", uacharIP[15]);
    printf("Information for uacharIP[16]: %u\n", uacharIP[16]);

    return uacharIP;
    */
}


void IPHeaderInBytes(unsigned short* uacharIP)
{
    printf("IP Header in bytes\n");
    //printing IP Header in form of bytes
    for( int i=0; i < NELEMS(uacharIP); i++ )
    {
        printf("Byte[%d]: %X \n", i, uacharIP[i] );
    }

    printf("IP Header has been finalized\n");
}


/*
This function checks if the value is within a selected bound.
Returns -1 if out of bounds and zero if not
*/
char WithinBounds( int iValue, int iLowerBound, int iUpperBound)
{

    if( iValue >= iLowerBound && iValue <= iUpperBound )
    {
        return 0;
    }
    else
    {
        return -1;
    }
}
