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
#include <sys/lock.h>
#include <sys/sema.h>

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
#include <netinet/mp_sched/mp_sched_dqn.h>

struct state_head state_queue = STAILQ_HEAD_INITIALIZER(state_queue);
struct rwlock state_queue_lock;

VNET_DEFINE(struct proc *, mp_sched_dqn_proc_ptr) = NULL;

static MALLOC_DEFINE(M_DQN, "DQN scheduler data", "Per connection DQN scheduler data.");
static MALLOC_DEFINE(M_STATE, "DQN State data", "State data for transfer to DQN agent.");

static int	dqn_mod_init(void);
static int	dqn_mod_destroy(void);
static int	dqn_cb_init(struct mp_sched_var *mpschedv);
static void	dqn_cb_destroy(struct mp_sched_var *mpschedv);
static struct sf_handle * dqn_get_subflow(struct mp_sched_var *mpschedv);

struct mp_sched_algo dqn_mp_sched_algo = {
	.name = "dqn",
	.mod_init = dqn_mod_init,
	.mod_destroy = dqn_mod_destroy,
	.cb_init = dqn_cb_init,
	.cb_destroy = dqn_cb_destroy,
	.get_subflow = dqn_get_subflow,
};

static int dqn_mod_init(void)
{
	STATE_QUEUE_LOCK_INIT();
	STAILQ_INIT(&state_queue);
	
	return (0);
}

static int dqn_mod_destroy(void)
{
	struct state *se;
	
	/* Free any remaining entries in state queue */
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		STAILQ_REMOVE_HEAD(&state_queue, entries);
		free(se, M_STATE);
	}
	STATE_QUEUE_WUNLOCK();
	STATE_QUEUE_LOCK_DESTROY();
	
	return (0);
}

static int
dqn_cb_init(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data = NULL;
	
	dqn_data = malloc(sizeof(struct dqn), M_DQN, M_NOWAIT|M_ZERO);
	
	if (dqn_data == NULL)
		return (ENOMEM);
	
	dqn_data->fb_mpschedv.mp = mpschedv->mp;
	dqn_data->fb_algo = &roundrobin_mp_sched_algo;
	if (dqn_data->fb_algo->cb_init != NULL)
		dqn_data->fb_algo->cb_init(&dqn_data->fb_mpschedv);
	dqn_data->flags = 0;
	
	mpschedv->mp_sched_data = dqn_data;
	
	sema_init(&dqn_data->sema, 0, "DQN scheduler signaling");
	
	return (0);
}

static void
dqn_cb_destroy(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data;
	
	dqn_data = mpschedv->mp_sched_data;
	
	if (dqn_data->fb_algo->cb_destroy != NULL)
		dqn_data->fb_algo->cb_destroy(&dqn_data->fb_mpschedv);
	
	sema_destroy(&dqn_data->sema);
	
	free(mpschedv->mp_sched_data, M_DQN);
}

static struct sf_handle *
dqn_get_subflow(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data;
	struct mpcb *mp;
	struct state *se;
	struct sf_handle *sf;
	struct inpcb *inp;
	struct tcpcb *tp;
	
	dqn_data = mpschedv->mp_sched_data;
	mp = mpschedv->mp;
	
	if (DQN_PROC() == NULL)
		goto fallback;
	
	se = malloc(sizeof(struct state), M_STATE, M_NOWAIT|M_ZERO);
	if (se == NULL)
		goto fallback;
	
	se->mpcb_ptr = mp;
	se->sema_ptr = &dqn_data->sema;
	se->sent = FALSE;
	se->sf_select = -1;
	
	sf = TAILQ_FIRST(&mp->sf_list);
	if (sf == NULL) {
		free(se, M_STATE);
		goto fallback;
	}
	
	inp = sotoinpcb(sf->sf_so);
	tp = intotcpcb(inp);
	se->sf1_ptr = sf;
	se->sf1_awnd = V_tcp_do_rfc6675_pipe ? tcp_compute_pipe(tp) : tp->snd_max - tp->snd_una;
	se->sf1_cwnd = (int)tp->snd_cwnd;
	se->sf1_rtt = tp->t_srtt;
	
	sf = TAILQ_NEXT(sf, next_sf_handle);
	if (sf == NULL) {
		free(se, M_STATE);
		goto fallback;
	}
	
	inp = sotoinpcb(sf->sf_so);
	tp = intotcpcb(inp);
	se->sf2_ptr = sf;
	se->sf2_awnd = V_tcp_do_rfc6675_pipe ? tcp_compute_pipe(tp) : tp->snd_max - tp->snd_una;
	se->sf2_cwnd = (int)tp->snd_cwnd;
	se->sf2_rtt = tp->t_srtt;
	
	STATE_QUEUE_WLOCK();
	STAILQ_INSERT_TAIL(&state_queue, se, entries);
	STATE_QUEUE_WUNLOCK();

	kern_psignal(DQN_PROC(), SIGUSR1);
	sema_timedwait(se->sema_ptr, SEM_WAIT_TIMEOUT);
	
	STATE_QUEUE_WLOCK();
	STAILQ_REMOVE(&state_queue, se, state, entries);
	STATE_QUEUE_WUNLOCK();
	
	/* Process response, sf_select will be -1 if DQN agent did not handle in time */
	if (se->sf_select == 1) {
		sf = se->sf1_ptr;
		free(se, M_STATE);
		return sf;
	}
	else if (se->sf_select == 2) {
		sf = se->sf2_ptr;
		free(se, M_STATE);
		return sf;
	}
	else {
		free(se, M_STATE);
		goto fallback;
	}
	
fallback:
	/* Fallback to RoundRobin if no DQN PID registered */
	if (dqn_data->fb_algo->get_subflow != NULL)
		return dqn_data->fb_algo->get_subflow(&dqn_data->fb_mpschedv);
	else
		return TAILQ_FIRST(&mp->sf_list);
}


int
sys_mp_sched_dqn_set_proc(struct thread *td, struct mp_sched_dqn_set_proc_args *uap)
{
	DQN_PROC() = td->td_proc;
	printf("%s: pid %d registered as dqn handler\n", __func__, DQN_PROC()->p_pid);
	
	return (0);
}


int
sys_mp_sched_dqn_clear_proc(struct thread *td, struct mp_sched_dqn_clear_proc_args *uap)
{
	DQN_PROC() = NULL;
	printf("%s: dqn handler cleared\n", __func__);
	
	return (0);
}

int
sys_mp_sched_dqn_get_state(struct thread *td, struct mp_sched_dqn_get_state_args *uap)
{
	struct state *se = NULL;
	
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		if (!se->sent) {
			se->sent = TRUE;
			break;
		}
	}
	STATE_QUEUE_WUNLOCK();
	
	if (se == NULL) {
		td->td_retval[0] = -1;
		return (0);
	}
	
	copyout((void *)se->mpcb_ptr, uap->mpcb_ptr, sizeof(uintptr_t));
	copyout(&se->sf1_awnd, uap->sf1_awnd, sizeof(int));
	copyout(&se->sf1_cwnd, uap->sf1_cwnd, sizeof(int));
	copyout(&se->sf1_rtt, uap->sf1_rtt, sizeof(int));
	copyout(&se->sf2_awnd, uap->sf1_awnd, sizeof(int));
	copyout(&se->sf2_cwnd, uap->sf2_cwnd, sizeof(int));
	copyout(&se->sf2_rtt, uap->sf2_rtt, sizeof(int));
	
	return (0);
}

int
sys_mp_sched_dqn_select_subflow(struct thread *td, struct mp_sched_dqn_select_subflow_args *uap)
{
	struct state *se = NULL;
	
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		if ((uintptr_t)se->mpcb_ptr == uap->mpcb_ptr) {
			break;
		}
	}
	STATE_QUEUE_WUNLOCK();
	
	if (se == NULL) {
		td->td_retval[0] = -1;
		return (0);
	}
	
	se->sf_select = uap->sf_select;
	sema_post(se->sema_ptr);
	
	return (0);
}

DECLARE_MP_SCHED_MODULE(dqn, &dqn_mp_sched_algo);
MODULE_VERSION(dqn, 1);
