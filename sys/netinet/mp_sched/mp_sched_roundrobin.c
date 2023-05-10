/*
* Copyright (c) 2023 Brenton Fleming <bkfl@deakin.edu.au>
* Copyright (c) 2013-2015 Swinburne University of Technology, Melbourne, Australia.
* All rights reserved.
*
* This software is developed by Brenton Fleming for the Deakin University
* Network Lab. It is based software developed at the Centre for Advanced Internet
* Architectures, Swinburne University of Technology, by Nigel Williams and
* Lawrence Stewart, made possible in part by a gift from the FreeBSD
* Foundation and The Cisco University Research Program Fund, a corporate
* advised fund of Silicon Valley Community Foundation.
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

struct roundrobin {
	struct sf_handle *last_sf_selected;
	uint32_t flags;
	
};

static MALLOC_DEFINE(M_ROUNDROBIN, "RoundRobin data", "Per connection RoundRobin data.");

static int	roundrobin_mod_init(void);
static int	roundrobin_cb_init(struct mp_sched_var *mpschedv);
static void	roundrobin_cb_destroy(struct mp_sched_var *mpschedv);
static struct sf_handle * roundrobin_get_subflow(struct mp_sched_var *mpschedv);

struct mp_sched_algo roundrobin_mp_sched_algo = {
	.name = "roundrobin",
	.cb_init = roundrobin_cb_init,
	.cb_destroy = roundrobin_cb_destroy,
	.get_subflow = roundrobin_get_subflow,
};

static int
roundrobin_cb_init(struct mp_sched_var *mpschedv)
{
	struct roundrobin *roundrobin_data = NULL;

	roundrobin_data = malloc(sizeof(struct roundrobin), M_ROUNDROBIN, M_NOWAIT|M_ZERO);
	if (roundrobin_data == NULL)
		return (ENOMEM);

	roundrobin_data->last_sf_selected = NULL;
	roundrobin_data->flags = 0;
	
	mpschedv->mp_sched_data = roundrobin_data;

	return (0);
}

static void
roundrobin_cb_destroy(struct mp_sched_var *mpschedv)
{
	free(mpschedv->mp_sched_data, M_ROUNDROBIN);
}

static struct sf_handle *
roundrobin_get_subflow(struct mp_sched_var *mpschedv)
{
	struct roundrobin *roundrobin_data;
	struct mpcb *mp;
	struct sf_handle *sf_index;
	struct sf_handle *sf_next = NULL;
	struct inpcb *inp;
	struct tcpcb *tp;
	
	roundrobin_data = mpschedv->mp_sched_data;
	mp = mpschedv->mp;
	
	/* The last subflow used for output */
	sf_index = roundrobin_data->last_sf_selected;

	/* want to start from the "next" subflow after our
	 * previously used subflow. */
	if (sf_index)
		sf_next = TAILQ_NEXT(sf_index, next_sf_handle);

	/* will start from the start of list */
	if (sf_next == NULL)
		sf_index = sf_next = TAILQ_FIRST(&mp->sf_list);

again:
	TAILQ_FOREACH_FROM (sf_next, &mp->sf_list, next_sf_handle) {
		if (sf_next->sf_flags & (SFHS_MPENDED | SFHS_MPESTABLISHED))
			continue;

		/* XXXNJW: some cases can drop through without an inp.
		 * need to investigate why. */

		/* Rather than subflow-level checks, should in the future rely
		 * only on sfh flags. If there is some problem with the PCB
		 * the calling function can try again. */
		inp = sotoinpcb(sf_next->sf_so);
		tp = intotcpcb(inp);
		
		INP_WLOCK(inp);
		if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
			sf_next->sf_flags |= SFHS_MPENDED;

			/* XXXNJW: this just sneaked in for now to catch
			 * flows that have (for example) been reset. Must
			 * find a better solution for this. */
			if (tp->t_sf_state & SFS_MP_DISCONNECTED)
				mp_schedule_tasks(mp, MP_SCHEDCLOSE);

			INP_WUNLOCK(inp);
			continue;
		}
		
		if ((tp->t_state < TCPS_ESTABLISHED) || tp->t_rxtshift) {
			INP_WUNLOCK(inp);
			continue;
		}

		INP_WUNLOCK(inp);
		break;
	}

	if ((sf_next == NULL) && (sf_index != TAILQ_FIRST(&mp->sf_list))) {
		sf_index = TAILQ_FIRST(&mp->sf_list);
		goto again;
	}

	roundrobin_data->last_sf_selected = sf_next;
	return sf_next;
}

DECLARE_MP_SCHED_MODULE(roundrobin, &roundrobin_mp_sched_algo);
MODULE_VERSION(roundrobin, 1);
