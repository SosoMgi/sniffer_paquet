#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include "parser/protocol.h"




// gestion des paquets tcp

// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|          Source Port          |        Destination Port       |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                        Sequence Number                        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                     Acknowledgment Number                     |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//| Offset|  Res. |     Flags     |             Window            |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|            Checksum           |         Urgent Pointer        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                    Options                    |    Padding    |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


void parse_tcp(const unsigned char *packet, uint16_t size) 
{
	struct tcphdr *tcp = (struct tcphdr *)packet;
	uint16_t source = ntohs(tcp>source),
             dest = ntohs(tcp->dest),
			 doff = tcp->doff;
    int  tcp_size= tcp->th_off*4;

    void (*next_layer)(const unsigned char *, uint16_t) = NULL;

    title("TCP");
	printf("\t\tSource port: %d\n", ntohs(tcp->th_sport)); // port source (première case)
    next_protocole(tcp->th_dport, next_layer);

    

    printf("\t\tDestination port: %d\n", dest); // port destination (deuxième case)
    next_protocole(tcp->th_dport, next_layer);


    //affiche les infos suivantes de l'en-tête TCP
	printf("\t\tSequence number: %d (0x%04x)\n", ntohl(tcp->th_seq), ntohl(tcp->th_seq));
	printf("\t\tAcknowledgment number: %d\n", ntohl(tcp->th_ack));
	printf("\t\tHeader length: %d bytes\n", tcp_size);

	printf("\t\tFlags: 0x%02x\n", tcp->th_flags);


    //affiche les flags de l'en-tête TCP
    if (tcp->fin)
        printf("\t\t\tFIN\n");
    if (tcp->syn)
        printf("\t\t\tSYN\n");
    if (tcp->rst)
        printf("\t\t\tRST\n");
    if (tcp->psh)
        printf("\t\t\tPSH\n");
    if (tcp->ack)
        printf("\t\t\tACK\n");
    if (tcp->urg)
        printf("\t\t\tURG\n");

    //affiche les infos suivantes de l'en-tête TCP
    printf("\t\tWindow size: %d\n", ntohs(tcp->th_win));
    printf("\t\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
    printf("\t\tUrgent pointer: %d\n", ntohs(tcp->th_urp));

    if(next_layer != NULL && (size - tcp_size) > 0)
		(*next_layer)(packet + tcp_size, size - tcp_size); // appel de la couche supérieure (ex: HTTP)
    

	
    

}