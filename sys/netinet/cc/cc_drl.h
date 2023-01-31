#ifndef CC_DRL_H_
#define CC_DRL_H_

#define CC_DRL_MAX_QUEUE 10000

struct pkt {
	u_int		cwnd;
	int		smoothed_rtt;
	int		cong_events;

	u_int		laddr;
	u_int		lport;
};

#endif