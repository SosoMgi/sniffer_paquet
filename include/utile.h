#ifndef UTILE_H
#define UTILE_H

#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <ctype.h>
#include <unistd.h>
#include "options.h"

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void capture(bpf_u_int32 netp);

void usage();

void offline();

void online();

#endif