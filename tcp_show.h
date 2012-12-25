#ifndef __MY_TCP_SHOW_H
#define __MY_TCP_SHOW_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>

#include "rbtree.h"

struct sk_req {
	struct nlmsghdr nlh;
	struct inet_diag_req r;
};

struct tcpinfo_node {
	struct rb_node rb;
	struct nlmsghdr *h;
	struct inet_diag_msg *pkg; 

};

/*
struct tcpinfo_node {
	struct rb_node rb;
	int state;
	int rqueue;
	int wqueue;
	int dport;
	int sport;
	char src_ip[IP_MAX_LEN];
	char dst_ip[IP_MAX_LEN];
	char info[IP_MAX_LEN];
};
*/

int tcp_show(int opt_state, int kb_state, int kcmd, int idx); 
int tcp_show_sock(struct nlmsghdr *h, void *arg);

#endif
