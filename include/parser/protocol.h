#ifndef PROTOCOL_H
#define PROTOCOL_H

#define HTTP 80
#define SMTP 25
#define TELNET 23
#define FTP 21
#define POP2 109
#define POP3 110
#define IMAP 143
#define IMAP_SSL 993

#include <stdint.h>


void parse_ethernet(const unsigned char *packet);
void parse_arp(const unsigned char *packet);
void parse_ip(const unsigned char *packet);
void parse_ipv6(const unsigned char *packet);
void parse_tcp(const unsigned char *packet, uint16_t size);
void parse_udp(const unsigned char *packet);
void parse_bootp(const unsigned char *packet);
void parse_dhcp(const unsigned char *packet);
void parse_dns(const unsigned char *packet);
void parse_smtp(const unsigned char *packet, uint16_t size);
void parse_telnet(const unsigned char *packet, uint16_t size);
void parse_pop(const unsigned char *packet, uint16_t size);
void parse_http(const unsigned char *packet, uint16_t size);
void parse_ftp(const unsigned char *packet, uint16_t size);
void parse_imap(const unsigned char *packet, uint16_t size);
void parse_imap_ssl(const unsigned char *packet, uint16_t size);
void parse_pop2(const unsigned char *packet, uint16_t size);
void parse_pop3(const unsigned char *packet, uint16_t size);

void title(char* s);
void next_protocole(uint16_t port, void (*next_layer)(const unsigned char *, uint16_t));
#endif