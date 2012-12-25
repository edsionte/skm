#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h> //fcntl
#include <errno.h>
#include <string.h>
#include <asm/types.h> //NLMSG_OK()
#include <sys/socket.h> //
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/inet_diag.h>
#include <netinet/tcp.h> //TCP_LISTEN and so on
#include <linux/rtnetlink.h>

#include "skm.h"
#include "tcp_show.h"
#include "process.h"
#include "screen.h"

extern int showmem;
extern int showext;
extern int showtcpinfo;
extern int showproc;
extern int showipv4;
extern int showipv6;

extern int delay_time;

extern int fstate;
extern int fsrc;
extern int fdst;
extern int fsport;
extern int fdport;
extern struct skm_filter f;
extern int port_op;

extern int kcmd;

extern int screen_length;
extern int screen_width;

void get_tcp_state(int state, int x, int y);

void print_headline(int line)
{
	printf("\033[%d;1H\033[KState\033[%d;10H\033[KRecv-Q\033[%d;20H\033[KSend-Q\
			\033[%d;30H\033[KLocal Address:Port\033[%d;50H\033[KPeer Address:Port\n",\
			line, line, line, line, line);

}

void get_state_num(int state, int state_num[]) 
{
	switch (state) {
		case TCP_ESTABLISHED:
			state_num[0]++;
			break;
		case TCP_CLOSE:
			state_num[1]++;
			break;
		case TCP_LISTEN:
			state_num[2]++;
			break;
	}
}

void print_summary(int tcp_num, int ipv4_num, int state_num[])
{
	printf("\033[1;1H\033[KTCP:total:%d ip:%d ipv6:%d (estab %d closed %d listen %d)\n",\
			tcp_num, ipv4_num, tcp_num - ipv4_num,\
			state_num[0], state_num[1], state_num[2]);

	printf("\033[%d;1H\033[K===========================================================\n", BOTTOM_INFO_LINE - 1);
}

//print the detail info of a rbtree node
void __tcpinfo_tree_print(struct tcpinfo_node *node, int line)
{
	struct inet_diag_msg *pkg = NULL;
	struct nlmsghdr *h = NULL;
	char src_ip[IP_MAX_LEN];
	char dst_ip[IP_MAX_LEN];
	int sport;
	int dport;

	pkg = node->pkg;
	h = node->h;

	if (pkg == NULL || h == NULL) {
		printf("in print_tcp_tree(): pkg or h is null.\n");
		exit(1);
	}

	memset(src_ip, 0, sizeof(src_ip));
	memset(dst_ip, 0, sizeof(dst_ip));
	inet_ntop(AF_INET, pkg->id.idiag_src, src_ip, IP_MAX_LEN);
	inet_ntop(AF_INET, pkg->id.idiag_dst, dst_ip, IP_MAX_LEN);
	sport = ntohs(pkg->id.idiag_sport);
	dport = ntohs(pkg->id.idiag_dport);

	get_tcp_state(pkg->idiag_state, line, 1);
	printf("\033[%d;10H\033[K%d", line, pkg->idiag_rqueue);
	printf("\033[%d;20H\033[K%d", line, pkg->idiag_wqueue);
	printf("\033[%d;30H\033[K%s:%d  ", line, src_ip, sport);
	printf("\033[%d;50H\033[K%s:%d  ", line, dst_ip, dport);

	tcp_show_sock(h, NULL);
}

//traverse the rbtree
int tcpinfo_tree_print(struct rb_root *tcpinfo_tree, int line)
{
	struct rb_node *pos = NULL;

	for (pos = rb_first(tcpinfo_tree); pos; pos = rb_next(pos)) {
		struct tcpinfo_node *node = NULL;
		node = container_of(pos, struct tcpinfo_node, rb);
		__tcpinfo_tree_print(node, line);
		line++;
	}
	return 0;
}

int tcpinfo_tree_destroy(struct rb_root *tcpinfo_tree)
{
	struct rb_node *pos = NULL;
	struct rb_node *next = NULL;
	//int i= 0;

	for (pos = rb_first(tcpinfo_tree); pos; pos = next) {
		struct tcpinfo_node *node = NULL;

		next = rb_next(pos);
		rb_erase(pos, tcpinfo_tree);
		node = container_of(pos, struct tcpinfo_node, rb);
		free(node);
		//i++;
	}
	return 0;
}


int tcpinfo_tree_compare(struct inet_diag_msg *msg, struct inet_diag_msg *cur)
{
	int sport, cur_sport;
	int dport, cur_dport;

	switch (kcmd) {
		case KB_SPORT:
			sport = ntohs(msg->id.idiag_sport);
			cur_sport = ntohs(cur->id.idiag_sport);
			return (sport <= cur_sport ? 1 : 0);
		case KB_DPORT:
			dport = ntohs(msg->id.idiag_dport);
			cur_dport = ntohs(cur->id.idiag_dport);
			return (dport <= cur_dport ? 1 : 0);
		case KB_RECV:
			return (msg->idiag_rqueue <= cur->idiag_rqueue ? 1 : 0);
		case KB_SENT:
			return (msg->idiag_wqueue <= cur->idiag_wqueue ? 1 : 0);
	}

	return 0;
}

//insert a node to the rbtree
int tcpinfo_tree_insert(struct rb_root *tcpinfo_tree, struct tcpinfo_node *node)
{
	struct rb_node **cur_rb = NULL;
	struct rb_node *parent = NULL;

	cur_rb = &(tcpinfo_tree->rb_node);

	//search the inserting position
	while (*cur_rb) {
		struct tcpinfo_node *cur = NULL;
		cur = container_of(*cur_rb, struct tcpinfo_node, rb);

		parent = *cur_rb;
		if (tcpinfo_tree_compare(node->pkg, cur->pkg) == 1) {
			//node <= cur
			cur_rb = &((*cur_rb)->rb_left);
		} else {
			//node > cur
			cur_rb = &((*cur_rb)->rb_right);
		}
	}

	//add a new code and rebalance rbtree
	rb_link_node(&(node->rb), parent, cur_rb);
	rb_insert_color(&(node->rb), tcpinfo_tree);

	return 0;
}

//filter a port by the @Op
int filter_port(int op, int f_port, int port) {
	switch (op) {
		case SKM_EQ:
			if (port == f_port)
				return 1;
			break;
		case SKM_GE:
			if (port >= f_port)
				return 1;
			break;
		case SKM_GT:
			if (port > f_port)
				return 1;
			break;
		case SKM_LE:
			if (port <= f_port)
				return 1;
			break;
		case SKM_LT:
			if (port < f_port)
				return 1;
			break;
		case SKM_NE:
			if (port != f_port)
				return 1;
			break;
	}

	return 0;
}

//print the state of the socket
void get_tcp_state(int state, int x, int y)
{
	char s[16] = {'\0'};

	switch (state) {
		case TCP_ESTABLISHED:
			strcpy(s, "ESTAB");
			break;
		case TCP_SYN_SENT:
			strcpy(s, "SYN_SENT");
			break;
		case TCP_SYN_RECV:
			strcpy(s, "SYN_RECV");
			break;
		case TCP_FIN_WAIT1:
			strcpy(s, "FIN_WAIT1");
			break;
		case TCP_FIN_WAIT2:
			strcpy(s, "FIN_WAIT2");
			break;
		case TCP_TIME_WAIT:
			strcpy(s, "TIME_WAIT");
			break;
		case TCP_CLOSE:
			strcpy(s, "CLOSE");
			break;
		case TCP_CLOSE_WAIT:
			strcpy(s, "CLOSE_WAIT");
			break;
		case TCP_LAST_ACK:
			strcpy(s, "LAST_ACK");
			break;
		case TCP_LISTEN:
			strcpy(s,"LISTEN");
			break;
		case TCP_CLOSING:
			strcpy(s, "CLOSEING");
			break;
		default:
			strcpy(s, "UNKNOW");
			break;
	}//switch
	printf("\033[%d;%dH\033[K%s ", x, y, s);
}


/*
int ssfilter_bytecompile(struct ssfilter *f, char **bytecode)
{
	switch (f->type) {
		case SSF_S_AUTO:
			{
				if (!(*bytecode=malloc(4))) abort();
				((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
				return 4;
			}
		case SSF_DCOND:
		case SSF_SCOND:
			{
				struct aafilter *a = (void*)f->pred;
				struct aafilter *b;
				char *ptr;
				int  code = (f->type == SSF_DCOND ? INET_DIAG_BC_D_COND : INET_DIAG_BC_S_COND);
				int len = 0;

				for (b=a; b; b=b->next) {
					len += 4 + sizeof(struct inet_diag_hostcond);
					if (a->addr.family == AF_INET6)
						len += 16;
					else
						len += 4;
					if (b->next)
						len += 4;
				}
				if (!(ptr = malloc(len))) abort();
				*bytecode = ptr;
				for (b=a; b; b=b->next) {
					struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)ptr;
					int alen = (a->addr.family == AF_INET6 ? 16 : 4);
					int oplen = alen + 4 + sizeof(struct inet_diag_hostcond);
					struct inet_diag_hostcond *cond = (struct inet_diag_hostcond*)(ptr+4);

					*op = (struct inet_diag_bc_op){ code, oplen, oplen+4 };
					cond->family = a->addr.family;
					cond->port = a->port;
					cond->prefix_len = a->addr.bitlen;
					memcpy(cond->addr, a->addr.data, alen);
					ptr += oplen;
					if (b->next) {
						op = (struct inet_diag_bc_op *)ptr;
						*op = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, len - (ptr-*bytecode)};
						ptr += 4;
					}
				}
				return ptr - *bytecode;
			}
		case SSF_D_GE:
			{
				struct aafilter *x = (void*)f->pred;
				if (!(*bytecode=malloc(8))) abort();
				((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_GE, 8, 12 };
				((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
				return 8;
			}
		case SSF_D_LE:
			{
				struct aafilter *x = (void*)f->pred;
				if (!(*bytecode=malloc(8))) abort();
				((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_LE, 8, 12 };
				((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
				return 8;
			}
		case SSF_S_GE:
			{
				struct aafilter *x = (void*)f->pred;
				if (!(*bytecode=malloc(8))) abort();
				((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_GE, 8, 12 };
				((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
				return 8;
			}
		case SSF_S_LE:
			{
				struct aafilter *x = (void*)f->pred;
				if (!(*bytecode=malloc(8))) abort();
				((struct inet_diag_bc_op*)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_LE, 8, 12 };
				((struct inet_diag_bc_op*)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
				return 8;
			}

		case SSF_AND:
			{
				char *a1, *a2, *a, l1, l2;
				l1 = ssfilter_bytecompile(f->pred, &a1);
				l2 = ssfilter_bytecompile(f->post, &a2);
				if (!(a = malloc(l1+l2))) abort();
				memcpy(a, a1, l1);
				memcpy(a+l1, a2, l2);
				free(a1); free(a2);
				ssfilter_patch(a, l1, l2);
				*bytecode = a;
				return l1+l2;
			}
		case SSF_OR:
			{
				char *a1, *a2, *a, l1, l2;
				l1 = ssfilter_bytecompile(f->pred, &a1);
				l2 = ssfilter_bytecompile(f->post, &a2);
				if (!(a = malloc(l1+l2+4))) abort();
				memcpy(a, a1, l1);
				memcpy(a+l1+4, a2, l2);
				free(a1); free(a2);
				*(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, l2+4 };
				*bytecode = a;
				return l1+l2+4;
			}
		case SSF_NOT:
			{
				char *a1, *a, l1;
				l1 = ssfilter_bytecompile(f->pred, &a1);
				if (!(a = malloc(l1+4))) abort();
				memcpy(a, a1, l1);
				free(a1);
				*(struct inet_diag_bc_op*)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, 8 };
				*bytecode = a;
				return l1+4;
			}
		default:
			abort();
	}
}
*/

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}   
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

//show the detail info
void tcp_show_info(struct nlmsghdr *nlh, struct inet_diag_msg *r)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	char b1[64];
	double rtt = 0;

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr*)(r+1),
			nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (showmem && tb[INET_DIAG_MEMINFO]) {
		printf("showmme..\n");
		struct inet_diag_meminfo *minfo
			= RTA_DATA(tb[INET_DIAG_MEMINFO]);
		printf(" mem:(r%u,w%u,f%u,t%u)",
				minfo->idiag_rmem,
				minfo->idiag_wmem,
				minfo->idiag_fmem,
				minfo->idiag_tmem);
	}
/*
	if (showtcpinfo && tb[INET_DIAG_INFO]) {
		struct tcp_info *info;
		int len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);
		if (len < sizeof(*info)) {
			info = alloca(sizeof(*info));
			memset(info, 0, sizeof(*info));
			memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
		} else
			info = RTA_DATA(tb[INET_DIAG_INFO]);
		if (show_options) {
			if (info->tcpi_options & TCPI_OPT_TIMESTAMPS)
				printf(" ts");
			if (info->tcpi_options & TCPI_OPT_SACK)
				printf(" sack");
			if (info->tcpi_options & TCPI_OPT_ECN)
				printf(" ecn");
			if (info->tcpi_options & TCPI_OPT_ECN_SEEN)
				printf(" ecnseen");
		}

		if (tb[INET_DIAG_CONG])
			printf(" %s", (char *) RTA_DATA(tb[INET_DIAG_CONG]));

		if (info->tcpi_options & TCPI_OPT_WSCALE)
			printf(" wscale:%d,%d", info->tcpi_snd_wscale,
					info->tcpi_rcv_wscale);
		if (info->tcpi_rto && info->tcpi_rto != 3000000)
			printf(" rto:%g", (double)info->tcpi_rto/1000);
		if (info->tcpi_rtt)
			printf(" rtt:%g/%g", (double)info->tcpi_rtt/1000,
					(double)info->tcpi_rttvar/1000);
		if (info->tcpi_ato)
			printf(" ato:%g", (double)info->tcpi_ato/1000);
		if (info->tcpi_snd_cwnd != 2)
			printf(" cwnd:%d", info->tcpi_snd_cwnd);
		if (info->tcpi_snd_ssthresh < 0xFFFF)
			printf(" ssthresh:%d", info->tcpi_snd_ssthresh);
		rtt = (double) info->tcpi_rtt;
		if (tb[INET_DIAG_VEGASINFO]) {
			const struct tcpvegas_info *vinfo
				= RTA_DATA(tb[INET_DIAG_VEGASINFO]);

			if (vinfo->tcpv_enabled &&
					vinfo->tcpv_rtt && vinfo->tcpv_rtt != 0x7fffffff)
				rtt =  vinfo->tcpv_rtt;
		}

		if (rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
			printf(" send %sbps",
					sprint_bw(b1, (double) info->tcpi_snd_cwnd *
						(double) info->tcpi_snd_mss * 8000000.
						/ rtt));
		}

		if (info->tcpi_rcv_rtt)
			printf(" rcv_rtt:%g", (double) info->tcpi_rcv_rtt/1000);
		if (info->tcpi_rcv_space)
			printf(" rcv_space:%d", info->tcpi_rcv_space);
	}
	*/

}

//show the other info 
int tcp_show_sock(struct nlmsghdr *h, void *arg)
{
	struct inet_diag_msg *r = NLMSG_DATA(h);

	if (showmem || showtcpinfo) {
		tcp_show_info(h, r);
	}

	if (showext) {
		printf(" (ino:%u)", r->idiag_inode);
		printf(" (sk:");
		if (r->id.idiag_cookie[1] != 0)
			printf("%08x", r->id.idiag_cookie[1]);
		printf("%08x)", r->id.idiag_cookie[0]);

	}

	if (showproc) {
		char ubuf[4096];
		if (find_users(r->idiag_inode, ubuf, sizeof(ubuf)) > 0)
			printf(" users:(%s)", ubuf);
	}

	return 0;
}

int tcp_show(int opt_state, int kb_opt, int kcmd, int idx)
{
	int fd;
	struct sk_req req;
	struct sockaddr_nl src_addr, dst_addr;
	struct msghdr msg;
	char buf[8192];
	char src_ip[IP_MAX_LEN];
	char dst_ip[IP_MAX_LEN];
	int sport;
	int dport;
	//	char *bc = NULL;
	//	int bclen = 0;
	//	struct rtattr rta;
	//	struct iovec iov[3];
	struct iovec iov;

	//print the summary info
	int tcp_num = 0;
	int ipv4_num = 0;
	int state_num[3] = {0};

	//option:-m
	if (opt_state & (1 << OPT_MEM))	{
		showmem = 1;
		req.r.idiag_ext |= (1 << (INET_DIAG_MEMINFO));
	}

	//option:-e  
	if (opt_state & (1 << OPT_EXT)) {
		showext = 1;
	}

	//option:-p
	if (opt_state & (1 << OPT_PROC)) {
		showproc = 1;
	}

	//option:-i
	if (opt_state & (1 << OPT_TCPINFO)) {
		showtcpinfo = 1;
		//set the flag
	}

	//option:-4
	if (opt_state & (1 << OPT_IPV4)) {
		showipv4 = 1;	
	}

	//option:-6
	if (opt_state & (1 << OPT_IPV6)) {
		showipv6 = 1;
	}

	//create the netink socket
	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0) {
		eprint(__LINE__, errno, "socket");
		return -1;
	}

	//init the msg
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH | NLM_F_ROOT;
	req.nlh.nlmsg_pid = 0;

	memset(&req.r, 0, sizeof(req.r));
	req.r.idiag_family = AF_INET;
	req.r.idiag_states = ((1 << TCP_CLOSING + 1) - 1); //states to dump

	//send msg to kernel
	iov.iov_base = &req;
	iov.iov_len = sizeof(req);

	//	iov[0].iov_base = &req;
	//	iov[0].iov_len = sizeof(req);
	/*
	   if (showmem) {
	//	bclen = ssfilter_bytecompile(f->f, &bc);

	if (!(bc=malloc(4))) abort();
	((struct inet_diag_bc_op*)bc)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
	//	                 return 4;

	bclen = 4;
	rta.rta_type = INET_DIAG_REQ_BYTECODE;
	rta.rta_len = RTA_LENGTH(bclen);
	iov[1] = (struct iovec){ &rta, sizeof(rta) };
	iov[2] = (struct iovec){ bc, bclen };
	req.nlh.nlmsg_len += RTA_LENGTH(bclen);
	}
	*/

	//init the dst address
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = 0;
	dst_addr.nl_groups = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dst_addr;
	msg.msg_namelen = sizeof(dst_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	//	msg.msg_iov = iov;
	//	msg.msg_iovlen = (showmem == 1) ? 3: 1;

	//send @msg to kernel
	if (sendmsg(fd, &msg, 0) < 0) {
		eprint(__LINE__, errno, "sendmsg");
		return -1;
	}

	//recv msg from kernel
	memset(buf, 0 ,sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	/*
	   iov[0] = (struct iovec){
	   .iov_base = buf,
	   .iov_len = sizeof(buf)
	   };
	   */
	int line = BOTTOM_INFO_LINE;
	struct rb_root tcpinfo_tree = RB_ROOT;

	print_headline(line);
	line++;

	//while1
	while (1) {
		int status;
		struct nlmsghdr *h;

		//		msg = (struct msghdr) {
		//			(void *)&dst_addr, sizeof(dst_addr),
		//				&iov, 1, NULL, 0, 0
		//		};
		/*
		   msg = (struct msghdr) {
		   (void *)&dst_addr, sizeof(dst_addr),
		   iov, 1, NULL, 0, 0
		   };
		   */

		msg = (struct msghdr) {
			(void *)&dst_addr, sizeof(dst_addr),
				&iov, 1, NULL, 0, 0
		};
		//length of recv data
		status = recvmsg(fd, &msg, 0);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			//	return -1;	
			eprint(__LINE__, errno, "recvmsg");
			continue;
			//	return -1; 
		}

		if (status == 0) {
			printf("EOF on netlink\n");
			close(fd);
			return 0;
		}

		h = (struct nlmsghdr *)buf;
		//decide the cursor
		//		printf("\033[%d;1H\033[KTime:%d*%ds\n", screen_length - 1, idx, delay_time);

		//while2
		while (NLMSG_OK(h, status)) {
			struct inet_diag_msg *pkg = NULL;

			//recv over
			if (h->nlmsg_type == NLMSG_DONE) {
				close(fd);
				goto info_print;
				//return 0;

			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err;
				err = (struct nlmsgerr*)NLMSG_DATA(h);
				fprintf(stderr, "%d Error %d:%s\n", __LINE__, -(err->error), strerror(-(err->error)));
				close(fd);
				return 0;
			}

			pkg = (struct inet_diag_msg *)NLMSG_DATA(h);

			//get the num of tcp
			tcp_num++;
			//get the num of specific state
			get_state_num(pkg->idiag_state, state_num);

			//filter the ipv6	
			if (pkg->idiag_family == AF_INET6 && showipv4 == 1 && showipv6 == 0) {
				h = NLMSG_NEXT(h, status);
				continue;
			}

			//filter the ipv4
			if (pkg->idiag_family == AF_INET) {
				//get the num of ipv4 socket
				ipv4_num++;
				if (showipv4 == 0 && showipv6 == 1) {

					h = NLMSG_NEXT(h, status);
					continue;
				}
			}

			//filter the state
			if (fstate == 1 && pkg->idiag_state != f.state) {
				h = NLMSG_NEXT(h, status);
				continue;
			}
			//get the ip addr of current entry
			memset(src_ip, 0, sizeof(src_ip));
			memset(dst_ip, 0, sizeof(dst_ip));
			inet_ntop(AF_INET, pkg->id.idiag_src, src_ip, IP_MAX_LEN);
			inet_ntop(AF_INET, pkg->id.idiag_dst, dst_ip, IP_MAX_LEN);
			sport = ntohs(pkg->id.idiag_sport);
			dport = ntohs(pkg->id.idiag_dport);

			//filter the srcaddr
			if (fsrc == 1 && strcmp(src_ip, f.src) != 0) {
				h = NLMSG_NEXT(h, status);
				continue;
			}
			//filter the dstaddr
			if (fdst == 1 && strcmp(dst_ip, f.dst) != 0) {
				h = NLMSG_NEXT(h, status);
				continue;
			}

			//filter the sport
			if (fsport == 1 && filter_port(port_op, f.sport, sport) == 0) {
				h = NLMSG_NEXT(h, status);
				continue;
			}

			//filter the dport
			if (fdport == 1 && filter_port(port_op, f.dport, dport) != 1) {
				h = NLMSG_NEXT(h, status);
				continue;
			}

			if (kcmd == 0) {
				//output the info directly when user don't click the key cmd
				get_tcp_state(pkg->idiag_state, line, 1);
				printf("\033[%d;10H\033[K%d", line, pkg->idiag_rqueue);
				printf("\033[%d;20H\033[K%d", line, pkg->idiag_wqueue);
				printf("\033[%d;30H\033[K%s:%d  ", line, src_ip, sport);
				printf("\033[%d;50H\033[K%s:%d  ", line, dst_ip, dport);

				tcp_show_sock(h, NULL);
				line++;
			} else {
				//insert the current dentry to rbtree
				struct tcpinfo_node *node = malloc(sizeof(struct tcpinfo_node));

				if (node == NULL) {
					eprint(__LINE__, errno, "malloc");
				}

				node->h = h;
				node->pkg = pkg;

				tcpinfo_tree_insert(&tcpinfo_tree, node);
			}

			h = NLMSG_NEXT(h, status);

		}//while2
	}//while1

info_print:

	//print the summary info
	print_summary(tcp_num, ipv4_num, state_num);

	//if user click the key, then print the sorting info
	if (kcmd != 0) {
		//print the rbtree
		line = BOTTOM_INFO_LINE;
		print_headline(line);
		tcpinfo_tree_print(&tcpinfo_tree, ++line);
		//destroy the rbtree
		tcpinfo_tree_destroy(&tcpinfo_tree);
	}
	//print the time info
	printf("\033[%d;1H\033[KTime:%d*%d=%ds\n", screen_length - 1, idx, delay_time, idx * delay_time);

	close(fd);
	return 0;
}

