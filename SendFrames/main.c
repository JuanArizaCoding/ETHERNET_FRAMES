#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#define MIN_BYTES_DATA 46 //In bytes
#define MAX_BYTES_DATA 1500 //In bytes
#define ETHERNET_FRAME 1514 //1518-4=1514 bytes (cheksum not used)
#define MESSAGE_INIT_FRAME 14

char*getEthernet();
int checkData(u_char*,u_char*);
void sendInformation(char*);

int main()
{
    char*interfaz=getEthernet();
    if(interfaz!=NULL){
          sendInformation(interfaz);
    }else{
        printf("No valid interface");
        return -1;
    }

    return 0;
}

char*getEthernet(){
    pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	int selectedDevice;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return NULL;
	}

	/* Print the list */
	for(d= alldevs; d != NULL; d= d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return NULL;
	}

    printf("Seleccione una opcion: ");
    scanf("%d",&selectedDevice);
    fflush(stdin);
    /* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return NULL;
	}

    i=0;
    for(d= alldevs; d != NULL; d= d->next){
        i++;
        if(i==selectedDevice){
            return d->name;
        }
    }
	/* We don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	return NULL;
}

int checkData(u_char*message,u_char*packet){
    int bound = MESSAGE_INIT_FRAME; //We start to write on byte 14

    if(strlen(message) >= MAX_BYTES_DATA) {
        for(int i = 0; i < MAX_BYTES_DATA; i++) {
            packet[bound] = message[i];
            bound++;
        }
    }else if(strlen(message) < MIN_BYTES_DATA) {
        for(int i = 0; i < MIN_BYTES_DATA; i++) {
            if(i < strlen(message)) {
                packet[bound] = message[i];
            }else {
                packet[bound] = 0;
            }
            bound++;
        }
    }else {
        for(int i = 0; i < strlen(message); i++) {
            packet[bound] = message[i];
            bound++;
        }
    }

    return bound;
}



void sendInformation(char* interfaz) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[ETHERNET_FRAME];

    int i;

    /* Open the adapter */
    if ((fp = pcap_open_live(interfaz,        // name of the device
                             65536,            // portion of the packet to capture. It doesn't matter in this case
                             1,                // promiscuous mode (nonzero means promiscuous)
                             1000,            // read timeout
                             errbuf            // error buffer
                             )) == NULL){
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", interfaz);
    }



    /* Supposing to be on ethernet, set mac destination to broadcast mac (ff:ff:ff:ff:ff:ff),

     we use strtol to convert HEX number into a decimal number*/

    packet[0]=strtol("FF", NULL, 16);
    packet[1]=strtol("FF", NULL, 16);
    packet[2]=strtol("FF", NULL, 16);
    packet[3]=strtol("FF", NULL, 16);
    packet[4]=strtol("FF", NULL, 16);
    packet[5]=strtol("FF", NULL, 16);

    /* set mac source to our mac ("2C-3B-70-4E-00-47), we use strtol to convert HEX

     number into a decimal number*/

    packet[6]=strtol("2C", NULL, 16);
    packet[7]=strtol("3B", NULL, 16);
    packet[8]=strtol("70", NULL, 16);
    packet[9]=strtol("4E", NULL, 16);
    packet[10]=strtol("00", NULL, 16);
    packet[11]=strtol("47", NULL, 16);

    /* set ethertypè to 0x2223, which is indicated into the work sheet */

    packet[12]=strtol("22", NULL, 16);
    packet[13]=strtol("23", NULL, 16);

    /* Fill the rest of the packet */

    u_char* message = (u_char*)malloc(MAX_BYTES_DATA * sizeof(u_char));
    printf("Introduzca el mensaje que desea mandar: \n");
    fgets(message, MAX_BYTES_DATA, stdin);
    message[strlen(message)-1] = '\0';

    //We get the message

    int finalPacketSize = checkData(message, packet);

    /* Send down the packet */

    pcap_sendpacket(fp,                     // Adapter
                    packet,            // buffer with the packet
                    finalPacketSize);      // size

    printf("Packet sended!\n");

    free(message);
    pcap_close(fp);
}
