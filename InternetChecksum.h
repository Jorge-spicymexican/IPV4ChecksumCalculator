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

// These gaurd headers will protect our code from courption
// and save them for us.

#ifndef INTERNETCHECKSUM_H
#define INTERNETCHECKSUM_H

#define IHL_MIN 5
#define IHL_MAX 9
#define DSCP_MIN 0
#define DSCP_MAX 46
#define ECN_MIN 0
#define ECN_MAX 3
#define TOTAL_LENGTH_MIN 0
#define TOTAL_LENGTH_MAX 65535
#define FLAG_DONT_FRAGMENT 0
#define FLAG_FRAGMENT 1
#define ID_MIN 0
#define ID_MAX 65535
#define FRAGEMENT_OFFSET_MIN 0
#define FRAGEMENT_OFFSET_MAX 8191
#define TIME_TO_LIVE_MIN 0
#define TIME_TO_LIVE_MAX 255
#define PROTOCOL_MIN 0
#define PROTOCOL_MAX 255
#define BYTES_LENGTH 65535
#define INVALID -1
#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

//typedefs
typedef struct
{
    // First 32 bits of data
	char cVersion;
	unsigned char ucIHL;
	unsigned short usDSCHP;
	unsigned char ucECN;
	unsigned short usTotal_Length;

    // second 32 bits of data
	unsigned short usIdentification;
	unsigned char ucFlags;
	unsigned short usFragment_Offset;

    // third 32 bits of data
	unsigned char ucTime_To_Live;
	unsigned char ucProtcol;
	unsigned short usHeader_Checksum;

	unsigned long int acSourceIPAddress;
	unsigned long int acDestinationIPAddress;

    unsigned long int Options_0;
    unsigned long int Options_1;
    unsigned long int Options_2;
    unsigned long int Options_3;
}
IPHeader_TYPE;

//Prototypes functions
void RequestingInfo_First_32Bits(IPHeader_TYPE* HeaderData);
void RequestingInfo_Second_32Bits(IPHeader_TYPE* HeaderData);
void RequestingInfo_Third_32Bits(IPHeader_TYPE* HeaderData);
void Requesting_Source_IP_Address(IPHeader_TYPE* HeaderData);
void Requesting_Destination_IP_Address(IPHeader_TYPE* HeaderData);
void Getting_Options(IPHeader_TYPE* HeaderData);
void IPCHECK(IPHeader_TYPE* HeaderData);
char PrintIP4Header(IPHeader_TYPE* HeaderData);

#endif /* INTERNETCHECKSUM_H */
