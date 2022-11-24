#include "utile.h"
#include "parser/protocol.h"
#include "options.h"



void title (char* s)
{
    printf("\033[1m");
	printf("\t\t▭▭▭ %s ▭▭▭\n", s);
	printf("\033[0m");
}

void next_protocole(uint16_t port, void (*next_layer)(const unsigned char *, uint16_t))
{
    next_layer = NULL;

    switch (port)
    {
        case HTTP:
            next_layer = parse_http;
            break;
     /*   case SMTP:
            next_layer = parse_smtp;
            break;
        case TELNET:
            next_layer = parse_telnet;
            break;
        case FTP:
            next_layer = parse_ftp;
            break;
        case POP2:
            next_layer = parse_pop2;
            break;
        case POP3:
            next_layer = parse_pop3;
            break;
        case IMAP:
            next_layer = parse_imap;
            break;
        case IMAP_SSL:
            next_layer = parse_imap_ssl;
            break;  */
        default:
            next_layer = NULL;
            break;
    }
}

void parse_http(const unsigned char *packet, uint16_t size)
{
    title("HTTP");
    (void) packet;
    (void) size;
}