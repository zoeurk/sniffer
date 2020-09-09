#include <stdlib.h>

#include <argp.h>

#include <netdb.h>

#include "others.h"

const char 			*argp_program_version = "sniffer-1.0";
const char 			*argp_program_bug_address = "zoeurk@gmail.com";

struct output		myoutput = {0, {'\0'}, 0, 0, 0, 0 ,0, 0, 0, 0, 0,
						"\0","\0","\0", "\0", "\0", "\0", "\0",
						0, 0, NULL, NULL, {{0,0,0,0,0,0}},
						NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
				};
//struct tcp_packet	tcp_packet = {0, 0, NULL};
int 			s;
unsigned long int 	captured = 0, statsrecv = 0, statsdrops = 0, selected = 0;
void 			*check = NULL;
char			___flags___[7] = "FSRPAUE",
				*ip4flags[3]={ NULL, "DF", "MF" };
char 			buffer[65535];
char 			doc[] = "Simple sniffer TCP/IP";
struct argp_option	options[] = {
						{"interface", 'i', "inteface", 0, "interface utilisée", 0 },
						{"flags", 'f', "opt1:arg;opt2:arg2[;...]", 0, "options de filtre", 0},
						{"noresolv", 'R', 0,  0, "ne faire de resolution de nom", 0},
						{"nolinklayer",'L', 0, 0, "pas afficher address mac", 0 },
						{"noaddress",'A', 0, 0, "ne pas afficher l'ip et les informations relatives(ex: hostname)", 0},
						{"notransport", 'T', 0 , 0, "ne pas afficher les infos relative à la couche transport (ex: checksum)",0},
						{"noheader", 'H', 0, 0, "ne pas afficher les entetes ip", 0},						
						{"nooptions", 'O', 0, 0, "ne pas afficher les options IP", 0},
						{"nodata", 'd', 0, 0, "pas afficher les datas", 0 },
						{"nohexa", 'D', 0, 0, "pas afficher les datas au format hexadecimal", 0},
						{"count_captured", 'c', "x", 0, "s'arreter après avoir capture un certain nombre de packet analysé", 0},
						{"count_received",'r', "x", 0, "s'arreter après avoir capture un certain nombre de packet recu", 0},
						{"count_selected",'C', "x", 0, "s'arreter après avoir capture un certain nombre de packet selectionné par les filtres", 0},
						{"verbose", 'v', 0, 0, "mode verbeux (port 53 et 123)", 0},
						{0}
				};
struct arguments		args = { NULL, 0, 0, 0, 0, NULL };
//struct data_split 		s_data = {0,0,0,0,NULL,NULL};
struct  data_split *s_data = NULL;
//struct  b z = { 0 };

