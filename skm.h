#ifndef __MY_SKM_H
#define __MY_SKM_H

#define BOTTOM_INFO_LINE 5

//the skm's options 
enum SKM_OPT {
	OPT_TCP = 1,
	OPT_UDP,
	OPT_RAW,
	OPT_IPV4,
	OPT_IPV6,
	OPT_MEM,
	OPT_EXT,
	OPT_PROC,
	OPT_TCPINFO,
	OPT_HELP,
	OPT_VERSION,
	OPT_MAX
};

enum SKM_KB {
	KB_SPORT = 1,
	KB_DPORT,
	KB_RECV,
	KB_SENT,
	KB_MAX
};

enum SKM_TCP_STATE {
	SKM_ESTABLISHED = 1,
	SKM_SYN_SENT,
	SKM_SYN_RECV,
	SKM_FIN_WAIT1,
	SKM_FIN_WAIT2,
	SKM_TIME_WAIT,
	SKM_CLOSE,
	SKM_CLOSE_WAIT,
	SKM_LAST_ACK,
	SKM_LISTEN,
	SKM_CLOSING,
	SKM_STATE_MAX
};

enum SKM_OP {
	SKM_EQ = 1,	//==
	SKM_GE,		//>=
	SKM_GT,		//>
	SKM_LE,		//<=
	SKM_LT,		//<	
	SKM_NE,		//!=
	SKM_OP_MAX
};

#define IP_MAX_LEN 40
struct skm_filter {
	int state;
	char src[IP_MAX_LEN];
	char dst[IP_MAX_LEN];
	int sport;
	int dport;	
};

void eprint(int line, int err_no, char *str);
#endif
