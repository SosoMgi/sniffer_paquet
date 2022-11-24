#include "utile.h"
#include <signal.h>



static enum LEVEL max_verbosity = 0;

#define CHK_VERB() if(verbosity != max_verbosity) return;

pcap_t* handle;

struct options options;;

// gère le signal d'arrêt du programme (CTRL + C)
static void signal_handler(int signo) {
    (void) signo;
    pcap_breakloop(handle); // on arrête tout, car demandé
}




int main (int argc, char *argv[])
{
    char c;

    
    options.type = NONE;
    options.verbosity = COMPLETE;
    options.filter = NULL;


    // gère la reception d'un signal
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        printf("An error occurred while setting a signal handler.\n");
        return -1;
    }


    while ((c = getopt (argc, argv, "i:o:f:v")) != -1)
    {
        switch (c) 
        {
            case 'i': // interface
                options.type = ONLINE;
                options.name=optarg;
                break;
            case 'o': // fichier 
                options.type = OFFLINE;
                options.name=optarg;
                break;
            case 'f': // filtre
                options.filter=optarg;
                break;
            case 'v': // verbosity
                options.verbosity=atoi(optarg);
                if(options.verbosity<1 || options.verbosity>3)
                {
                    fprintf(stderr, "Verbosity must be between 1 and 3\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }


    max_verbosity = options.verbosity;

    if(options.type == ONLINE) {online();}
    else if (options.type == OFFLINE) {offline();}
    else
    {
        usage();
        exit(EXIT_FAILURE);
    }

    return 0;
     
}



