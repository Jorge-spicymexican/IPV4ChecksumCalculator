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

#include <stdio.h>
#include <stdlib.h>
#include "InternetChecksum.h"
#include <memory.h>

#define YES 1
#define NO  0
#define FUNCTIONAL_TEST NO
IPHeader_TYPE sIPV4;

int main(void){

if( FUNCTIONAL_TEST )
{
    //go ahead and fille in the structure with information
    printf("Configuring IP Header...\n");
    // IP Header in Hex is:
    //first 32 bits
    sIPV4.cVersion = 4;
    sIPV4.ucIHL = 5;
    sIPV4.usDSCHP = 0;
    sIPV4.ucECN = 0;
    sIPV4.usTotal_Length = 28;

    //second 32 bits
    sIPV4.usIdentification = 0;
    sIPV4.ucFlags = 0;
    sIPV4.usFragment_Offset = 0;

    //third 32 bits
    sIPV4.ucTime_To_Live = 1;
    sIPV4.ucProtcol = 2;
    sIPV4.usHeader_Checksum = 0;


    sIPV4.Options_0 = 0;
    sIPV4.Options_1 = 0;
    sIPV4.Options_2 = 0;
    sIPV4.Options_3 = 0;

}
else
{
    sIPV4.cVersion = 4;
    sIPV4.ucIHL = 0;
    sIPV4.usDSCHP = 0;
    sIPV4.ucECN = 0;
    sIPV4.usTotal_Length = 0;

    //second 32 bits
    sIPV4.usIdentification = 0;
    sIPV4.ucFlags = 0;
    sIPV4.usFragment_Offset = 0;

    //third 32 bits
    sIPV4.ucTime_To_Live = 0;
    sIPV4.ucProtcol = 0;
    sIPV4.usHeader_Checksum = 0;


    sIPV4.Options_0 = 0;
    sIPV4.Options_1 = 0;
    sIPV4.Options_2 = 0;
    sIPV4.Options_3 = 0;

    RequestingInfo_First_32Bits(&sIPV4);  // the first 4 Octets have been configured

    RequestingInfo_Second_32Bits(&sIPV4); // the second 4 Octets configuration

    // Getting the Time to live and protcol values.
    RequestingInfo_Third_32Bits(&sIPV4);


}
       
    
// see if we need options for this file
if( sIPV4.ucIHL > 5)
{
    //run the option functions
    Getting_Options(&sIPV4);
}

//source IP Address
//run the source IP function
Requesting_Source_IP_Address(&sIPV4);

//run the destination IP function
Requesting_Destination_IP_Address(&sIPV4);

printf("\n\n");
printf("Calculting IP Checksum\n\n");
// Calculating IP Checksum
IPCHECK(&sIPV4);

printf("\n\n");
// printing IP4Header
PrintIP4Header(&sIPV4);

} //end main