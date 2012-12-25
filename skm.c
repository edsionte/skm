#include <stdio.h>
#include <termios.h>
#include <term.h>
#include <curses.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "skm.h"
#include "tcp_show.h" 
#include "udp_show.h"
#include "raw_show.h"
#include "process.h"

#define DEFAULT_FLUSH_TIME 2 

static struct termios initial_settings, new_settings;
static int peek_character = -1;

//print the info
int showmem = 0;
int showext = 0;
int showproc = 0;
int showtcpinfo = 0;
int showipv4 = 0;
int showipv6 = 0;

int delay_time = DEFAULT_FLUSH_TIME;

//filter
int fstate = 0;
int fsrc = 0;
int fdst = 0;
int fsport = 0;
int fdport = 0;
struct skm_filter f;
int port_op = 0;

int kcmd = 0;

//screen
int screen_width = 0;
int screen_length = 0;

void eprint(int line, int err_no, char *str)
{
	printf("Error%d in line %d:%s() with %s\n", errno, line, str, strerror(errno));
}

void init_keyboard()
{
	tcgetattr(0, &initial_settings);
	tcgetattr(0, &new_settings);
	new_settings.c_lflag &= ~ICANON;
	new_settings.c_lflag &= ~ECHO;
	new_settings.c_lflag &= ~ISIG;
	new_settings.c_cc[VMIN] = 0;
	new_settings.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &initial_settings);
}

void close_keyboard()
{
	tcsetattr(0, TCSANOW, &initial_settings);
}

int kbhit()
{
	char ch;
	int nread;

	if(peek_character != -1)
		return 1;
	new_settings.c_cc[VMIN]=0;
	tcsetattr(0, TCSANOW, &new_settings);
	nread = read(0, &ch, 1);
	new_settings.c_cc[VMIN]=1;
	tcsetattr(0, TCSANOW, &new_settings);

	if(nread == 1) {
		peek_character = ch;
		return 1;
	}
	return 0;
}

int readch()
{
	char ch;

	if(peek_character != -1) {
		ch = peek_character;
		peek_character = -1;
		return ch;
	}
	read(0, &ch, 1);
	return ch;
}   

void port_op_help()
{
	printf("\tWhere OP can be one of the following:\n");
	printf("\t== or eq : Equal to port\n");
	printf("\t>= or ge : Greater than or equal to port\n");
	printf("\t>  or lt : Greater than to port\n");
	printf("\t<= or le : Less than or equal to port\n");
	printf("\t<  or gt : Less than to port\n");
	printf("\t!= or ne : Not equal to port\n");
}

int op_to_int(char *op)
{
	if (strcmp(op, "==") == 0 || strcmp(op, "eq") == 0)
		return SKM_EQ;
	else if (strcmp(op, ">=") == 0 || strcmp(op, "ge") == 0)
		return SKM_GE;
	else if (strcmp(op, ">") == 0 || strcmp(op, "gt") == 0)
		return SKM_GT;
	else if (strcmp(op, "<=") == 0 || strcmp(op, "le") == 0)
		return SKM_LE;
	else if (strcmp(op, "<") == 0 || strcmp(op, "lt") == 0)
		return SKM_LT;
	else if (strcmp(op, "!=") == 0 || strcmp(op, "ne") == 0)
		return SKM_NE;
	else {
		port_op_help();
		return 0;
	}
}

void tcp_state_help()
{
	printf("\tfilter ==> SKM_STATE\n");
	printf("\testab  ==> SKM_ESTABLISHED\n");
	printf("\tsyn-sent  ==> SKM_SYN_SENT\n");
	printf("\tsyn-recv  ==> SKM_SYN_RECV\n");
	printf("\tfin-wait-1  ==> SKM_FIN_WAIT1\n");
	printf("\tfin-wait-2  ==> SKM_FIN_WAIT2\n");
	printf("\ttime-wait  ==> SKM_TIME_WAIT\n");
	printf("\tclose  ==> SKM_CLOSE\n");
	printf("\tclose-wait  ==> SKM_CLOSE_WAIT\n");
	printf("\tlast-ack  ==> SKM_LAST_ACK\n");
	printf("\tlisten  ==> SKM_LISTEN\n");
	printf("\tclosing  ==> SKM_CLOSING\n");
}

int state_to_int(char *state)
{
	if (strcmp(state, "estab") == 0) 
		return SKM_ESTABLISHED;
	else if (strcmp(state, "syn-sent") == 0)
		return SKM_SYN_SENT;
	else if (strcmp(state, "syn-recv") == 0)
		return SKM_SYN_RECV;
	else if (strcmp(state, "fin-wait-1") == 0)
		return SKM_FIN_WAIT1;
	else if (strcmp(state, "fin-wait-2") == 0)
		return SKM_FIN_WAIT2;
	else if (strcmp(state, "time-wait") == 0)
		return SKM_TIME_WAIT;
	else if (strcmp(state, "close") == 0)
		return SKM_CLOSE;
	else if (strcmp(state, "close-wait") == 0)
		return SKM_CLOSE_WAIT;
	else if (strcmp(state, "last-ack") == 0)
		return SKM_LAST_ACK;
	else if (strcmp(state, "listen") == 0)
		return SKM_LISTEN;
	else if (strcmp(state, "closing") == 0)
		return SKM_CLOSING;
	else {
		tcp_state_help();
		return 0;
	}
}

//option:-h 
void print_help()
{
	printf("This is help info \n");
}

//option:-v
void print_version()
{
	printf("This is version info\n");
}

//show socket info by specific protocol
void socket_show(int opt_state, int kb_state, int kcmd, int idx)
{
	if (opt_state & (1 << OPT_TCP)) {
		tcp_show(opt_state, kb_state, kcmd, idx);
	} else if (opt_state & (1 << OPT_UDP)) {
		udp_show(opt_state, kb_state, kcmd, idx);
	} else if (opt_state & (1 << OPT_RAW)) {
		raw_show(opt_state, kb_state, kcmd, idx);
	} else { 
		printf("other ..\n");	
	}
}

int main(int argc, char **argv)
{
	char myname[10] = {'\0'};
	int kb_ch = 0;
	int opt_ch = 0;
	int idx = 1;
	int opt_state = 0;
	int kb_state = 0; 

	//clear the screen
	printf("\033[2J");

	//get the name
	strncpy(myname, argv[0] + 2, strlen(argv[0]) - 2);

	if (argc <= 1) {
		opt_state |= (1 << OPT_TCP);
	}

	get_screensize();

	//check the options
	int time;
	while ((opt_ch = getopt(argc, argv, "tuwd:46mepdhv")) != -1) {
		switch (opt_ch) {
			case 't':
				opt_state |= (1 << OPT_TCP);
				break;	
			case 'u':
				opt_state |= (1 << OPT_UDP);
				break;	
			case 'w':
				opt_state |= (1 << OPT_RAW);
				break;
			case 'd':
				delay_time = atoi(optarg); 
				break;	
			case '4':
				opt_state |= (1 << OPT_IPV4);
				break;	
			case '6':
				opt_state |= (1 << OPT_IPV6);
				break;	
			case 'm':
				opt_state |= (1 << OPT_MEM);
				break;	
			case 'e':
				opt_state |= (1 << OPT_EXT);
				break;	
			case 'p':
				opt_state |= (1 << OPT_PROC);
				user_ent_hash_build();	
				break;	
			case 'i':
				opt_state |= (1 << OPT_TCPINFO);
				break;
			case 'h':
				print_help();
				exit(0);	
			case 'v':
				print_version();
				exit(0);
			default:
				printf("Usage: %s [options]\n", myname);
				return -1;
		}//switch()
	}//while

	argc -= optind;
	argv += optind;
	
	//check the filter
	while (argc > 0) {
		if (strcmp(*argv, "state") == 0) {
			fstate = 1;
			f.state = state_to_int(*(++argv));
			if (f.state == 0 || --argc <= 0)
				goto opt_error;
		} else if (strcmp(*argv, "src") == 0) {
			fsrc = 1;
			memset(f.src, IP_MAX_LEN, 0);
			strcpy(f.src, *(++argv));
			if (--argc <= 0)
				goto opt_error;
		} else if (strcmp(*argv, "dst") == 0) {
			fdst = 1;
			memset(f.dst, IP_MAX_LEN, 0);
			strcpy(f.dst, *(++argv));
			if (--argc <= 0)
				goto opt_error;
		} else if (strcmp(*argv, "sport") == 0) {
			fsport = 1;
			port_op = op_to_int(*(++argv));
			if (port_op == 0 || --argc <= 0)
				goto opt_error;
			f.sport = atoi(*(++argv));
			if (--argc <= 0)
				goto opt_error;
		} else if (strcmp(*argv, "dport") == 0) {
			fdport = 1;
			port_op = op_to_int(*(++argv));
			if (port_op == 0 || --argc <= 0)
				goto opt_error;
			f.dport = atoi(*(++argv));
			if (--argc <= 0)
				goto opt_error;
		} else {
opt_error:		
			print_help();
			return -1;
		}

		argc--;
		argv++;
	}

	if (!(opt_state & (1 << OPT_UDP)) && !(opt_state & (1 << OPT_RAW))) {
		opt_state |= (1 << OPT_TCP);
	}

	init_keyboard();
	//the main frame
	while(1) {

		printf("\033[s");
		if(kbhit()) {
			kb_ch = readch();
			switch (kb_ch) {
				case 'q':
					goto leave;
				case 'p':
					kb_state |= (1 << KB_SPORT);
					kcmd = KB_SPORT;
					break;
				case 'P':
					kb_state |= (1 << KB_DPORT);
					kcmd = KB_DPORT;
					break;
				case 'R':
					kb_state |= (1 << KB_RECV);
					kcmd = KB_RECV;
					break;
				case 'S':
					kb_state |= (1 << KB_SENT);
					kcmd = KB_SENT;
					break;
				case '0':
					kcmd = 0;
					break;
			}//swtich
		}
		//show info
		socket_show(opt_state, kb_state, kcmd, idx);
		idx++;
		//delay
		sleep(delay_time);

	}//while
	printf("\033[u");

leave:
	close_keyboard();
	//make the cursor jump to screen bottom
	printf("\033[%d;1H", screen_length);
	exit(0);
}

