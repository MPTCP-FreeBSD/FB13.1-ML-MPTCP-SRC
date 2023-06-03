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
#include <netinet/mptcp_pcb.h>
#include <netinet/mp_sched/mp_sched.h>
#include <netinet/mp_sched/mp_sched_module.h>
#include <netinet/mp_sched/mp_sched_dqn.h>

struct state_head state_queue = STAILQ_HEAD_INITIALIZER(state_queue);
struct rwlock state_queue_lock;

VNET_DEFINE(struct proc *, mp_sched_dqn_proc_ptr) = NULL;
VNET_DEFINE(uint32_t, mp_sched_dqn_ref_ctr) = 0;

static MALLOC_DEFINE(M_DQN, "DQN scheduler data", "Per connection DQN scheduler data.");
static MALLOC_DEFINE(M_STATE_ENTRY, "DQN State data", "State data for transfer to DQN agent.");

static int	dqn_mod_init(void);
static int	dqn_mod_destroy(void);
static int	dqn_cb_init(struct mp_sched_var *mpschedv);
static void	dqn_cb_destroy(struct mp_sched_var *mpschedv);
static struct sf_handle * dqn_get_subflow(struct mp_sched_var *mpschedv);

static struct sf_handle * validate_subflow(struct sf_handle *sf, struct dqn * dqn_data, struct mpcb *mp);
static int calculate_gput_wma(int32_t sf1_gput_hist[HIST_SIZE], int32_t sf2_gput_hist[HIST_SIZE]);

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
    /* Init state queue and lock */
	STATE_QUEUE_LOCK_INIT();
	STAILQ_INIT(&state_queue);
	
	return (0);
}

static int dqn_mod_destroy(void)
{
	struct state_entry *se = NULL;
	
	/* Free all remaining entries in state queue */
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		STAILQ_REMOVE_HEAD(&state_queue, entries);
		free(se, M_STATE_ENTRY);
	}
	STATE_QUEUE_WUNLOCK();
	
	/* Cleanup state queue lock */
	STATE_QUEUE_LOCK_DESTROY();
	
	return (0);
}

static int
dqn_cb_init(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data = NULL;
	
	/* Allocate memory, return error if failed */
	dqn_data = malloc(sizeof(struct dqn), M_DQN, M_NOWAIT|M_ZERO);
	if (dqn_data == NULL)
		return (ENOMEM);
	
	/* Assign RoundRobin as fallback scheduler and init */
	dqn_data->fb_mpschedv.mp = mpschedv->mp;
	dqn_data->fb_algo = &roundrobin_mp_sched_algo;
	if (dqn_data->fb_algo->cb_init != NULL)
		dqn_data->fb_algo->cb_init(&dqn_data->fb_mpschedv);
	
	/* Assign dqn_data to mpcb */
	mpschedv->mp_sched_data = dqn_data;
	
	return (0);
}

static void
dqn_cb_destroy(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data = NULL;
	
	dqn_data = mpschedv->mp_sched_data;
	
	/* Call destroy on fallback algorithm */
	if (dqn_data->fb_algo->cb_destroy != NULL)
		dqn_data->fb_algo->cb_destroy(&dqn_data->fb_mpschedv);
	
	/* Remove mpcb reference and free memory */
	mpschedv->mp_sched_data = NULL;
	free(dqn_data, M_DQN);
}

static struct sf_handle *
dqn_get_subflow(struct mp_sched_var *mpschedv)
{
	struct dqn *dqn_data = NULL;
	struct mpcb *mp = NULL;
	
	struct state_entry *se = NULL;
	
	struct sf_handle *sf = NULL;
	struct sf_handle *sf1 = NULL;
	struct sf_handle *sf2 = NULL;
	
	struct inpcb *inp;
	struct tcpcb *tp;
	
	dqn_data = mpschedv->mp_sched_data;
	mp = mpschedv->mp;
	
	/* Fallback to RoundRobin if no user process registered as handler */
	if (DQN_PROC() == NULL)
		goto fallback;
	
	/* Allocate state memory, fallback to RoundRobin on failure */
	se = malloc(sizeof(struct state_entry), M_STATE_ENTRY, M_NOWAIT|M_ZERO);
	if (se == NULL)
		goto fallback;
	
	/* Init state entry values */
	se->ref = DQN_REF_NEXT();
	sema_init(&se->se_sema, 0, "se_sema");
	se->action = -1;
	se->last_action = dqn_data->last_action;
	
	/* Shuffle goodput history by 1 element */
	memmove(&dqn_data->sf1_gput_hist[1], &dqn_data->sf1_gput_hist[0], sizeof(int32_t)*(HIST_SIZE - 1));
	memmove(&dqn_data->sf2_gput_hist[1], &dqn_data->sf2_gput_hist[0], sizeof(int32_t)*(HIST_SIZE - 1));
	
	/* Get subflow 1 from mpcb */
	sf = TAILQ_FIRST(&mp->sf_list);
	if (sf == NULL) {
		goto out;
	}
	
	/* Process subflow 1 */
	sf1 = validate_subflow(sf, dqn_data, mp);
	if (sf1 == NULL) {
		goto out;
	}
	
	inp = sotoinpcb(sf->sf_so);
	tp = intotcpcb(inp);
	
	/* Populate subflow 1 state */
    se->sf1_state.pipe = V_tcp_do_rfc6675_pipe ? tcp_compute_pipe(tp) : tp->snd_max - tp->snd_una;
    se->sf1_state.wnd = tp->snd_cwnd < tp->snd_wnd ? (int)tp->snd_cwnd : tp->snd_wnd;
    se->sf1_state.srtt = tp->t_srtt;
    se->sf1_state.rttvar = tp->t_rttvar;
    dqn_data->sf1_gput_hist[0] = tp->t_stats_gput_prev;
	memcpy(&se->sf1_last_state, &dqn_data->sf1_last_state, sizeof(struct state));
	memcpy(&dqn_data->sf1_last_state, &se->sf1_state, sizeof(struct state));
	
	/* Get subflow 2 from mpcb */
	sf = TAILQ_NEXT(sf, next_sf_handle);
	if (sf == NULL) {
		sf = sf1;
		goto out;
	}
	
	/* Process subflow 2 */
	sf2 = validate_subflow(sf, dqn_data, mp);
	if (sf2 == NULL) {
		sf = sf1;
		goto out;
	}
	
	inp = sotoinpcb(sf->sf_so);
	tp = intotcpcb(inp);
	
	/* Populate subflow 1 state */
    se->sf2_state.pipe = V_tcp_do_rfc6675_pipe ? tcp_compute_pipe(tp) : tp->snd_max - tp->snd_una;
    se->sf2_state.wnd = tp->snd_cwnd < tp->snd_wnd ? (int)tp->snd_cwnd : tp->snd_wnd;
    se->sf2_state.srtt = tp->t_srtt;
    se->sf2_state.rttvar = tp->t_rttvar;
    dqn_data->sf2_gput_hist[0] = tp->t_stats_gput_prev;
	memcpy(&se->sf2_last_state, &dqn_data->sf2_last_state, sizeof(struct state));
	memcpy(&dqn_data->sf2_last_state, &se->sf2_state, sizeof(struct state));
	
	/* Calculate goodput weighted moving average */
	se->total_gput_wma = calculate_gput_wma(dqn_data->sf1_gput_hist, dqn_data->sf2_gput_hist);
	
	/* Queue state entry for handling by DQN agent */
	STATE_QUEUE_WLOCK();
	STAILQ_INSERT_TAIL(&state_queue, se, entries);
	STATE_QUEUE_WUNLOCK();
	
	kern_psignal(DQN_PROC(), SIGUSR1);
	
	MPP_UNLOCK(mp->mp_mppcb);
	if (sema_timedwait(&se->se_sema, DQN_TIMEOUT) == 0) {
		dqn_data->last_action = se->action;
	}
	else {
		printf("%s: Timeout waiting for DQN agent response, ref = %d.\n", __func__, se->ref);
		if (DQN_PROC() != NULL) {
  			kern_psignal(DQN_PROC(), SIGKILL);
  			DQN_PROC() = NULL;
		}
	}
	MPP_LOCK(mp->mp_mppcb);
	
	/* Remove state entry from queue */
	STATE_QUEUE_WLOCK();
	STAILQ_REMOVE(&state_queue, se, state_entry, entries);
	STATE_QUEUE_WUNLOCK();
	
	/* Process response */
    switch (se->action) {
    case 0:
        sf = sf1;
        goto out;
        break;
    case 1:
        sf = sf2;
        goto out;
        break;
    default:
        sf = NULL;
        goto fallback;
        break;
    }    
	
fallback:
	/* Fallback to RoundRobin if no DQN PID registered */
	if (dqn_data->fb_algo->get_subflow != NULL)
		sf = dqn_data->fb_algo->get_subflow(&dqn_data->fb_mpschedv);
	else
		sf =  TAILQ_FIRST(&mp->sf_list);
	
out:
	/* Cleanup memory and return selection */
	if (se != NULL) {
		sema_destroy(&se->se_sema);	 
		free(se, M_STATE_ENTRY);
	}
		
	return sf;
}

static struct sf_handle *
validate_subflow(struct sf_handle *sf, struct dqn *dqn_data, struct mpcb *mp)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	
	inp = sotoinpcb(sf->sf_so);
	tp = intotcpcb(inp);
	
	INP_WLOCK(inp);
	
	/* Check subflow is available for transmission */
	if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
		sf->sf_flags |= SFHS_MPENDED;
	
		if (tp->t_sf_state & SFS_MP_DISCONNECTED)
			mp_schedule_tasks(mp, MP_SCHEDCLOSE);
	
		INP_WUNLOCK(inp);
		return NULL;
	}
	
	if ((tp->t_state < TCPS_ESTABLISHED) || tp->t_rxtshift) {
		INP_WUNLOCK(inp);
		return NULL;
	}

	INP_WUNLOCK(inp);
	
	return sf;
}

static int
calculate_gput_wma(int32_t sf1_gput_hist[HIST_SIZE], int32_t sf2_gput_hist[HIST_SIZE])
{
	int count = 0;
	int sf1_total = 0;
	int sf2_total = 0;
	
	for (int i = 0; i < HIST_SIZE; i++) {
		count += HIST_SIZE - i;
		sf1_total += sf1_gput_hist[i] * (HIST_SIZE - i);
		sf2_total += sf2_gput_hist[i] * (HIST_SIZE - i);
	}
	
	return ((sf1_total + sf2_total) / count);
}

int
sys_mp_sched_dqn_set_proc(struct thread *td, struct mp_sched_dqn_set_proc_args *uap)
{
    /* Register calling process as DQN handler */
	DQN_PROC() = td->td_proc;
	printf("MP_SCHED_DQN: PID %d registered as handler.\n", DQN_PROC()->p_pid);
	
	return (0);
}


int
sys_mp_sched_dqn_clear_proc(struct thread *td, struct mp_sched_dqn_clear_proc_args *uap)
{
    /* Clear DQN handler process */
	DQN_PROC() = NULL;
	return (0);
}

int
sys_mp_sched_dqn_get_state(struct thread *td, struct mp_sched_dqn_get_state_args *uap)
{
	struct state_entry *se = NULL;
	
	/* Find next state entry to be sent */
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		if (se->sent == FALSE) {
            /* Set sent flag */
            se->sent = TRUE;
            
            /* Copy values from kernel to userland */
			copyout(&se->ref, uap->ref, sizeof(uint32_t));
			copyout(&se->last_action, uap->last_action, sizeof(int));
			copyout(&se->sf1_last_state, uap->sf1_last_state, sizeof(struct state));
			copyout(&se->sf2_last_state, uap->sf2_last_state, sizeof(struct state));
			copyout(&se->sf1_state, uap->sf1_state, sizeof(struct state));
			copyout(&se->sf2_state, uap->sf2_state, sizeof(struct state));
			copyout(&se->total_gput_wma, uap->total_gput_wma, sizeof(int));
			
			break;
		}
	}
	STATE_QUEUE_WUNLOCK();
	
	/* No state entry found for sending */
	if (se == NULL) {
		td->td_retval[0] = -1;
		return (0);
	}
	
	return (0);
}

int
sys_mp_sched_dqn_select_subflow(struct thread *td, struct mp_sched_dqn_select_subflow_args *uap)
{
	struct state_entry *se = NULL;
	
	/* Find state entry based on ref */
	STATE_QUEUE_WLOCK();
	STAILQ_FOREACH(se, &state_queue, entries) {
		if (se->ref == uap->ref) {
			se->action = uap->action;
			sema_post(&se->se_sema);
			break;
		}
	}
	STATE_QUEUE_WUNLOCK();
	
	/* No matching state entry found */
	if (se == NULL) {
		printf("%s: no state entry found for ref = %d", __func__, uap->ref);
		td->td_retval[0] = -1;
		return (0);
	}

	return (0);
}

DECLARE_MP_SCHED_MODULE(dqn, &dqn_mp_sched_algo);
MODULE_VERSION(dqn, 1);
