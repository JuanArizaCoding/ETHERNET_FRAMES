#include <stdio.h>
#include <stdlib.h>
#include"pcap.h"

#define MESSAGE_INIT_FRAME 14

char* getEthernet(void);
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packetData);



int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Abrir el dispositivo seleccionado
    handle = pcap_open_live(getEthernet(), 65536, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("Error al abrir la interfaz seleccionada: %s\n", errbuf);
        return 1;
    }
    // Capturar y procesar las tramas
    pcap_loop(handle, 0, packetHandler, NULL);

    // Liberar la memoria
    pcap_close(handle);
    return 0;
}



char* getEthernet() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    int selectedDevice = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return NULL;
    }

    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next){
        printf("%d. %s", ++i, d->name);

        if (d->description)
            printf(" (%s)\n", d->description);

        else
            printf(" (No description available)\n");
    }

    if (i == 0){
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return NULL;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* Retrieve again the device list from the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        return NULL;
    }

    printf("Seleccione el numero de interfez que desea: ");
    scanf("%d", &selectedDevice);
    fflush(stdin);
    i = 0;

    for(d= alldevs; d != NULL; d= d->next){
        i++;
        if(selectedDevice == i) {
            return d->name;
        }
    }

    return NULL;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {

    // Check if destination mac is broadcast
    if (packetData[0] == 0xff &&
        packetData[1] == 0xff &&
        packetData[2] == 0xff &&
        packetData[3] == 0xff &&
        packetData[4] == 0xff &&
        packetData[5] == 0xff) {

        // Check if Ethertype is 0x2223
        if (packetData[12] == 0x22 &&
            packetData[13] == 0x23) {

            // Show the message received in the packet and show the MAC of the transmiter
            int i;
            printf("\nMensaje recibido por el usuario %x:%x:%x:%x:%x:%x\n",
                   packetData[6],
                   packetData[7],
                   packetData[8],
                   packetData[9],
                   packetData[10],
                   packetData[11]);

            for (i = MESSAGE_INIT_FRAME; i < pkthdr->len; i++) {
                printf("%c", packetData[i]);
            }
            printf("\n");
        }
    }
}
