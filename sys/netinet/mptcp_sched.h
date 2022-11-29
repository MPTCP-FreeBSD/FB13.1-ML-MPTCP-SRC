/*-
 * Copyright (c) 2013-2015
 * Swinburne University of Technology, Melbourne, Australia.
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Nigel Williams,
 * made possible in part by a gift from the FreeBSD Foundation and The
 * Cisco University Research Program Fund, a corporate advised fund of
 * Silicon Valley Community Foundation.
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

#ifndef MPTCP_SCHED_H_
#define MPTCP_SCHED_H_

#include <netinet/tcp.h>
#include <netinet/mptcp_var.h>

/* Global scheduler vars. */
extern STAILQ_HEAD(sched_head, sched_algo) sched_list;
extern struct sched_disc roundrobin_sched_algo;

/* Per-netstack bits. */
VNET_DECLARE(struct sched_algo *, default_sched_ptr);
#define	V_default_sched_ptr VNET(default_sched_ptr)

/* Define the new net.inet.tcp.mptcp.sched sysctl tree. */
SYSCTL_DECL(_net_inet_tcp_mptcp_sched);

/* Scheduler housekeeping functions. */
int	sched_register_algo(struct sched_algo *add_sched_algo);
int	sched_deregister_algo(struct sched_algo *remove_sched_algo);

/*
 * Struct holding data to be passed from the tcpcb to the scheduling algorithm
 */
struct sched_var {
	void        *sched_data; /* Per-connection private sched algorithm data. */
	uint32_t    flags; /* Flags for sched_var (see below) */
	struct mpcb *mp;
	struct tcpcb *tcp; /* TCP control block of calling subflow */
	struct tcpcb *sched_tp; /* The pcb selected by algorithm */
};

/* sched_var flags */
// Any flags relevant to _all_ schedulers should be defined here

/*
 * Structure to hold data and function pointers that together represent a
 * packet scheduling discipline.
 */
struct sched_algo {
	char	name[MPTCP_SA_NAME_MAX];

	/* Init global module state on kldload. */
	int	(*mod_init)(void);

	/* Cleanup global module state on kldunload. */
	int	(*mod_destroy)(void);

	/* Init scheduler state for a new control block. */
	int	(*cb_init)(struct sched_var *sched);

	/* Cleanup scheduler state for a terminating control block. */
	void	(*cb_destroy)(struct sched_var *sv);

	/* Init variables for a newly established connection. */
	void	(*conn_init)(struct sched_var *sv);

	/* Called on writing new data to socket buffer (tcp_usr_send) */
	void	(*sched_usr_send)(struct sched_var *sv, uint16_t type);

	/* Called on execution of scheduler task */
	void	(*sched_task)(struct sched_var *sv, uint16_t type);

	STAILQ_ENTRY (sched_algo) entries;
};

/* Macro to obtain the sched algo's struct ptr. */
#define	SCHED_ALGO(mp)	((mp)->sched_algo)

/* Macro to obtain the sched algo's data ptr. */
#define	SCHED_DATA(mp)	((mp)->sched_v->sched_data)

/* Macro to obtain the system default Scheduler algo's struct ptr. */
#define	SCHED_DEFAULT() V_default_sched_ptr

extern struct rwlock sched_list_lock;
#define	SCHED_LIST_LOCK_INIT()	    rw_init(&sched_list_lock, "sched_list")
#define	SCHED_LIST_LOCK_DESTROY()	rw_destroy(&sched_list_lock)
#define	SCHED_LIST_RLOCK()		    rw_rlock(&sched_list_lock)
#define	SCHED_LIST_RUNLOCK()	    rw_runlock(&sched_list_lock)
#define	SCHED_LIST_WLOCK()		    rw_wlock(&sched_list_lock)
#define	SCHED_LIST_WUNLOCK()	    rw_wunlock(&sched_list_lock)
#define	SCHED_LIST_LOCK_ASSERT()	rw_assert(&sched_list_lock, RA_LOCKED)

#endif /* MPTCP_SCHED_H_ */