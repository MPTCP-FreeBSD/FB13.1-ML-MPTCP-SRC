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

#ifndef _NETINET_MP_SCHED_DQN_H_
#define _NETINET_MP_SCHED_DQN_H_

#define DQN_TIMEOUT 500

/* Global vars */
extern STAILQ_HEAD(state_head, state_entry) state_queue;

/* Per-netstack bits. */
VNET_DECLARE(struct proc *, mp_sched_dqn_proc_ptr);
#define	V_mp_sched_dqn_proc_ptr VNET(mp_sched_dqn_proc_ptr)

VNET_DECLARE(uint32_t, mp_sched_dqn_ref_ctr);
#define	V_mp_sched_dqn_ref_ctr VNET(mp_sched_dqn_ref_ctr)

/* Structure for DQN state information */
struct state {
    int awnd;
    int cwnd;
    int swnd;
    int rtt;
    int rttvar;
};

/* State entry structure for queuing and DQN agent coordination */
struct state_entry {
    /* Reference number for lookup */
    uint32_t ref;
    
    /* Coordination with DQN handler */
    int action;
    int prev_action;
    bool sent;
    struct sema se_sema;
    
    /* Subflow 1 metrics */
    struct state sf1_prev_state;
    struct state sf1_state;
    
    /* Subflow 2 metrics */
    struct state sf2_prev_state;
    struct state sf2_state;
    
    STAILQ_ENTRY(state_entry) entries;
};

/* Algorithm-specific data */
struct dqn {
	/* Structures for fallback algorithm */
	struct mp_sched_algo *fb_algo;
	struct mp_sched_var fb_mpschedv;

	/* Previous state metrics for subflows */
	struct state sf1_prev_state;
	struct state sf2_prev_state;
	int prev_action;
};

/* Macro to obtain the DQN proc pointer */
#define	DQN_PROC()	V_mp_sched_dqn_proc_ptr

/* Macro to obtain the next DQN reference number */
#define	DQN_REF_NEXT()	V_mp_sched_dqn_ref_ctr++;

extern struct rwlock state_queue_lock;
#define	STATE_QUEUE_LOCK_INIT()		rw_init(&state_queue_lock, "state_queue")
#define	STATE_QUEUE_LOCK_DESTROY()	rw_destroy(&state_queue_lock)
#define	STATE_QUEUE_RLOCK()			rw_rlock(&state_queue_lock)
#define	STATE_QUEUE_RUNLOCK()		rw_runlock(&state_queue_lock)
#define	STATE_QUEUE_WLOCK()			rw_wlock(&state_queue_lock)
#define	STATE_QUEUE_WUNLOCK()		rw_wunlock(&state_queue_lock)
#define	STATE_QUEUE_LOCK_ASSERT()	rw_assert(&state_queue_lock, RA_LOCKED)

#endif /* _NETINET_MP_SCHED_DQN_H_ */
