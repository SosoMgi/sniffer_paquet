
#include "utile.h"

extern pcap_t* handle;
extern struct options options;

void callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
        const u_char* packet) 
{ 
    (void) arg;
    unsigned int i=0; 
    static int count=0; 
 
    printf("Packet Count: %d\n", ++count);    /* Number of Packets */
    printf("Recieved Packet Size: %d\n", pkthdr->len);    /* Length of header */
    printf("Payload:\n");                     /* And now the data */
    for(i=0;i<pkthdr->len;i++) { 
        if(isprint(packet[i]))                /* Check if the packet data is printable */
            printf("%c ",packet[i]);          /* Print it */
        else
            printf(" . ");          /* If not print a . */
        if((i%16==0 && i!=0) || i==pkthdr->len-1) 
            printf("\n"); 
    }
}




//________________________________________________________________________



// affichage de l'aide si besoin
void usage() {
	printf("Utilisation : ./sniffer\n\t[-i <interface>\n\t-o <fichier>\n\t-f <filtre BPF>]\n");
}


void capture(bpf_u_int32 netp) {

    struct bpf_program fp;
   

    if (pcap_compile (handle, &fp, options.filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(EXIT_FAILURE);
    }

    /* set the filter */
    if(pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "Error setting filter\n");
        exit(EXIT_FAILURE);
    } 
 

   /* loop for callback function */
   if(pcap_loop(handle, 0, callback, NULL) < 0)
    {
         fprintf(stderr, "Error in pcap_loop\n");
         exit(EXIT_FAILURE);
    }
}


//________________________________________________________________________



void online()
{
// name of the device in the first arg
    char errbuff[PCAP_ERRBUF_SIZE];
    int devs;
    pcap_if_t *alldevsp;
    // const u_char *packet; 
    //struct bpf_program fp;        /* hold compiled program */
     bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
    

    //Device where we sniff
    devs = pcap_findalldevs(&alldevsp, errbuff);
    if(devs == -1)
    {
        fprintf(stderr, "device unknown: %s\n", errbuff);
        exit(EXIT_FAILURE);
    }
    printf("Device: %s\n", alldevsp->name);


    /* Get the network address and mask */
    pcap_lookupnet(alldevsp->name, &netp, &maskp, errbuff); 

    printf("%s\n", pcap_lib_version());

	
    // fragment of code for open the device stored in dev
    handle = pcap_open_live(alldevsp->name, BUFSIZ, 1, 1000, errbuff);
    if (handle == NULL)
    {
        fprintf(stderr, "Can't open the device %s: %sn", alldevsp->name, errbuff);
        exit(EXIT_FAILURE);
    }

    pcap_set_timeout(handle, 1000);

	int status;
	if ((status = pcap_activate(handle)) < 0)
    {
        pcap_perror(handle, "pcap activate error");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    capture(netp);
}





//________________________________________________________________________


void offline()
{
    // name of the device in the first arg
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    int devs;
    // const u_char *packet; 
    //struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
    

    //Device where we sniff
    devs = pcap_findalldevs(&alldevsp, errbuff);
    if(devs == -1)
    {
        fprintf(stderr, "device unknown: %s\n", errbuff);
        exit(EXIT_FAILURE);
    }
    printf("Device: %s\n", alldevsp->name);

    /* Get the network address and mask */
    pcap_lookupnet(alldevsp->name, &netp, &maskp, errbuff);

    // fragment of code for open the device stored in dev
    if((handle = pcap_open_offline(alldevsp->name, errbuff)) == NULL)
    {
        fprintf(stderr, "Can't open the device %s: %sn", alldevsp->name, errbuff);
        exit(EXIT_FAILURE);
    }

    capture(netp);

}