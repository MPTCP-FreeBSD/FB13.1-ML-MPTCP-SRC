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
#define HIST_SIZE 3

/* Global vars */
extern STAILQ_HEAD(state_head, state_entry) state_queue;

/* Per-netstack bits. */
VNET_DECLARE(struct proc *, mp_sched_dqn_proc_ptr);
#define	V_mp_sched_dqn_proc_ptr VNET(mp_sched_dqn_proc_ptr)

VNET_DECLARE(uint32_t, mp_sched_dqn_ref_ctr);
#define	V_mp_sched_dqn_ref_ctr VNET(mp_sched_dqn_ref_ctr)

/* Structure for DQN state information */
struct state {
    int pipe;      /* Unacknowledged bytes in flight */
    uint32_t wnd;  /* Window size - min of cwnd and swnd */
    int srtt;      /* Smoothed round trip time */
    int rttvar;    /* Variance in round trip time */
};

/* State entry structure for queuing and DQN agent coordination */
struct state_entry {
    uint32_t ref;         /* Reference number for lookup */
    bool sent;            /* Flag for sent to DQN agent */
    struct sema se_sema;  /* Semaphore for response signaling */
    int action;          /* Action selected by agent */
    int last_action;     /* Last action taken by agent */
    struct state sf1_last_state;  /* Subflow 1 last state */
	struct state sf2_last_state;  /* Subflow 2 last state */
	struct state sf1_state;       /* Subflow 1 current state */
    struct state sf2_state;	      /* Subflow 2 current state */
    int total_gput_wma;           /* Sum of subflow 1 and subflow 2 goodput weighted moving average */
    
    STAILQ_ENTRY(state_entry) entries;
};

/* Algorithm-specific data */
struct dqn {
	struct mp_sched_algo *fb_algo;    /* Pointer to fallback algorithm */
	struct mp_sched_var fb_mpschedv;  /* Data for fallback algorithm */
    int last_action;                 /* Last action taken by agent */
    struct state sf1_last_state;      /* Subflow 1 last state */
	struct state sf2_last_state;      /* Subflow 2 last state */
	int32_t sf1_gput_hist[HIST_SIZE];  /* Subflow 1 historical goodput data */
	int32_t sf2_gput_hist[HIST_SIZE];  /* Subflow 1 historical goodput data */
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
