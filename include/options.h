#ifndef OPTIONS_H
#define OPTIONS_H

#include <pcap.h>


#define RED "\033[0;31m"
#define BOLD_RED "\033[1;31m"
#define GREEN "\033[0;32m"
#define BOLD_GREEN "\033[1;32m"
#define YELLOW "\033[0;33m"
#define BOLD_YELLOW "\033[01;33m"
#define BLUE "\033[0;34m"
#define BOLD_BLUE "\033[1;34m"
#define MAGENTA "\033[0;35m"
#define BOLD_MAGENTA "\033[1;35m"
#define CYAN "\033[0;36m"
#define BOLD_CYAN "\033[1;36m"
#define RESET "\033[0m"

#define BEGIN_LOG(verb)      \
	do {                     \
		set_verbosity(verb); \
	} while (0)
#define END_LOG() \
	do {          \
	} while (0)

enum LEVEL { CONCISE = 1, SYNTH = 2, COMPLETE = 3 };


struct options {
	enum TYPE { NONE, ONLINE, OFFLINE } type;
	char *name;
	char *filter;
	int verbosity;
	pcap_if_t alldevs;
};

#endif