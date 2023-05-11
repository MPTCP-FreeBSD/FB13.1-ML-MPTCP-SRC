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

#define SEM_WAIT_TIMEOUT 500000

/* Global vars */
extern STAILQ_HEAD(state_head, state) state_queue;

/* Per-netstack bits. */
VNET_DECLARE(struct proc *, mp_sched_dqn_proc_ptr);
#define	V_mp_sched_dqn_proc_ptr VNET(mp_sched_dqn_proc_ptr)

/* Algorithm-specific data */
struct dqn {
	/* Structures for fallback algorithm */
	struct mp_sched_algo *fb_algo;
	struct mp_sched_var fb_mpschedv;
	
	struct sema sema;
	
	uint32_t flags;
	
};

/* State structure for queuing and copy to user */
struct state {
    struct mpcb	*mpcb_ptr;
    struct sema *sema_ptr;
    int sf_select;
    bool sent;
    
    struct sf_handle *sf1_ptr;
    int	sf1_awnd;
    int sf1_cwnd;
    int	sf1_rtt;
    
    struct sf_handle *sf2_ptr;
    int	sf2_awnd;
    int	sf2_cwnd;
    int	sf2_rtt;
    
    STAILQ_ENTRY(state) entries;
};

/* Macro to obtain the DQN proc pointer */
#define	DQN_PROC()	V_mp_sched_dqn_proc_ptr

extern struct rwlock state_queue_lock;
#define	STATE_QUEUE_LOCK_INIT()		rw_init(&state_queue_lock, "state_queue")
#define	STATE_QUEUE_LOCK_DESTROY()	rw_destroy(&state_queue_lock)
#define	STATE_QUEUE_RLOCK()			rw_rlock(&state_queue_lock)
#define	STATE_QUEUE_RUNLOCK()		rw_runlock(&state_queue_lock)
#define	STATE_QUEUE_WLOCK()			rw_wlock(&state_queue_lock)
#define	STATE_QUEUE_WUNLOCK()		rw_wunlock(&state_queue_lock)
#define	STATE_QUEUE_LOCK_ASSERT()	rw_assert(&state_queue_lock, RA_LOCKED)

#endif /* _NETINET_MP_SCHED_DQN_H_ */
