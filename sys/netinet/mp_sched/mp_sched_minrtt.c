/*
* Copyright (c) 2023 Brenton Fleming <bkfl@deakin.edu.au>
*
* This software is developed by Brenton Fleming for the Deakin University
* Network Lab.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <sys/types.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_var.h>
#include <netinet/mp_sched/mp_sched.h>
#include <netinet/mp_sched/mp_sched_module.h>

struct minrtt {
	uint32_t flags;
	
};

static MALLOC_DEFINE(M_MINRTT, "minRTT data", "Per connection minRTT data.");

static int	minrtt_mod_init(void);
static int	minrtt_cb_init(struct mp_sched_var *mpschedv);
static void	minrtt_cb_destroy(struct mp_sched_var *mpschedv);
static struct sf_handle * minrtt_get_subflow(struct mp_sched_var *mpschedv);

struct mp_sched_algo minrtt_mp_sched_algo = {
	.name = "minrtt",
	.cb_init = minrtt_cb_init,
	.cb_destroy = minrtt_cb_destroy,
	.get_subflow = minrtt_get_subflow,
};

static int
minrtt_cb_init(struct mp_sched_var *mpschedv)
{
	struct minrtt *minrtt_data = NULL;

	minrtt_data = malloc(sizeof(struct minrtt), M_MINRTT, M_NOWAIT|M_ZERO);
	if (minrtt_data == NULL)
		return (ENOMEM);

	minrtt_data->flags = 0;
	
	mpschedv->mp_sched_data = minrtt_data;

	return (0);
}

static void
minrtt_cb_destroy(struct mp_sched_var *mpschedv)
{
	free(mpschedv->mp_sched_data, M_MINRTT);
}

static struct sf_handle *
minrtt_get_subflow(struct mp_sched_var *mpschedv)
{
	struct minrtt *minrtt_data;
	struct mpcb *mp;
	struct sf_handle *sf_next = NULL;
	struct sf_handle *sf_min = NULL;
	struct inpcb *inp;
	struct tcpcb *tp;
	int awnd;
	int sf_min_rtt;
	int sf_min_awnd;
		
	minrtt_data = mpschedv->mp_sched_data;
	mp = mpschedv->mp;
	
	TAILQ_FOREACH (sf_next, &mp->sf_list, next_sf_handle) {
		/* Check sub-flow is established and not closing */
		if (sf_next->sf_flags & (SFHS_MPENDED | SFHS_MPESTABLISHED))
			continue;
			
		inp = sotoinpcb(sf_next->sf_so);
		tp = intotcpcb(inp);
		
		INP_WLOCK(inp);
		if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
			sf_next->sf_flags |= SFHS_MPENDED;
		
			if (tp->t_sf_state & SFS_MP_DISCONNECTED)
				mp_schedule_tasks(mp, MP_SCHEDCLOSE);
		
			INP_WUNLOCK(inp);
			continue;
		}
		
		if ((tp->t_state < TCPS_ESTABLISHED) || tp->t_rxtshift) {
			INP_WUNLOCK(inp);
			continue;
		}
		
		/* Compute the amount of data in flight */
		if (V_tcp_do_rfc6675_pipe)
			awnd = tcp_compute_pipe(tp);
		else
			awnd = tp->snd_max - tp->snd_una;
		
		/* Check if sub-flow has capacity in CWND */
		if (((int)tp->snd_cwnd - awnd) > 0) {
			/* If first available sub-flow, set as current min_rtt */
			if (sf_min == NULL) {
				sf_min = sf_next;
				sf_min_rtt = tp->t_srtt;
				sf_min_awnd = awnd;
			}
			else {
				/* minRTT will prioritize the path with the lowest RTT, but also prevent paths sitting idle. */
				if (sf_min_awnd == 0 && awnd > 0) {
					INP_WUNLOCK(inp);
					continue;
				}
				else if ((awnd == 0 && sf_min_awnd > 0) || (tp->t_srtt < sf_min_rtt)) {
					sf_min = sf_next;
					sf_min_rtt = tp->t_srtt;
					sf_min_awnd = awnd;
				}
			}
		}
		
		INP_WUNLOCK(inp);
	}
	
	/* XXXBKF: If no available sf found, just return the first
	 * Need to introduce a wait function here in future */
	if (sf_min == NULL) {
		sf_min = TAILQ_FIRST(&mp->sf_list);
	}
	
	return sf_min;
}

DECLARE_MP_SCHED_MODULE(minrtt, &minrtt_mp_sched_algo);
MODULE_VERSION(minrtt, 1);
