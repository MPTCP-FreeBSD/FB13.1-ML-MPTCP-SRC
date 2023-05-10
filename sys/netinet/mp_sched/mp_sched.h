/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2023 Brenton Fleming <bkfl@deakin.edu.au>
 * Copyright (c) 2007-2008 Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software is developed by Brenton Fleming for the Deakin University
 * Network Lab. It is based software developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET_MP_SCHED_H_
#define _NETINET_MP_SCHED_H_

#ifdef _KERNEL

/* Global MP scheduler vars. */
extern STAILQ_HEAD(mp_sched_head, mp_sched_algo) mp_sched_list;
extern struct mp_sched_algo roundrobin_mp_sched_algo;

/* Per-netstack bits. */
VNET_DECLARE(struct mp_sched_algo *, default_mp_sched_ptr);
#define	V_default_mp_sched_ptr VNET(default_mp_sched_ptr)

/* Define the new net.inet.tcp.mptcp.scheduler sysctl tree. */
SYSCTL_DECL(_net_inet_tcp_mptcp_scheduler);

/* MP scheduler housekeeping functions. */
int	mp_sched_register_algo(struct mp_sched_algo *add_mp_sched);
int	mp_sched_deregister_algo(struct mp_sched_algo *remove_mp_sched);

/* Structure to hold data for the MP scheduler algorithm */
struct mp_sched_var {
	void		*mp_sched_data; /* Per-connection private scheduler algorithm data. */
  	struct mpcb *mp;			/* Pointer to multipath control block */
};

/*
 * Structure to hold data and function pointers that together represent a
 * multipath scheduler algorithm.
 */
struct mp_sched_algo {
	char	name[MPTCP_SA_NAME_MAX];

	/* Init global module state on kldload. */
	int	(*mod_init)(void);

	/* Cleanup global module state on kldunload. */
	int	(*mod_destroy)(void);

	/* Init MP scheduler state for a new control block. */
	int	(*cb_init)(struct mp_sched_var *mpschedv);

	/* Cleanup MP scheduler state for a terminating control block. */
	void	(*cb_destroy)(struct mp_sched_var *mpschedv);

    /* Request sub-flow selection for transmission */
    struct sf_handle *	(*get_subflow)(struct mp_sched_var *mpschedv);

	/* Called on receipt of a data ack. */
	void	(*dack_received)(struct mp_sched_var *mpschedv);

	STAILQ_ENTRY (mp_sched_algo) entries;
};

/* Macro to obtain the MP scheduler algo's struct ptr. */
#define	MP_SCHED_ALGO(mp)	((mp)->mp_sched_algo)

/* Macro to obtain the MP scheduler algo's var ptr. */
#define	MP_SCHED_VAR(mp)	((mp)->mpschedv)

/* Macro to obtain the MP scheduler algo's data ptr. */
#define	MP_SCHED_DATA(mp)	((mp)->mpschedv->mp_sched_data)

/* Macro to obtain the system default MP scheduler algo's struct ptr. */
#define	MP_SCHED_DEFAULT()	V_default_mp_sched_ptr

extern struct rwlock mp_sched_list_lock;
#define	MP_SCHED_LIST_LOCK_INIT()		rw_init(&mp_sched_list_lock, "mp_sched_list")
#define	MP_SCHED_LIST_LOCK_DESTROY()	rw_destroy(&mp_sched_list_lock)
#define	MP_SCHED_LIST_RLOCK()			rw_rlock(&mp_sched_list_lock)
#define	MP_SCHED_LIST_RUNLOCK()			rw_runlock(&mp_sched_list_lock)
#define	MP_SCHED_LIST_WLOCK()			rw_wlock(&mp_sched_list_lock)
#define	MP_SCHED_LIST_WUNLOCK()			rw_wunlock(&mp_sched_list_lock)
#define	MP_SCHED_LIST_LOCK_ASSERT()		rw_assert(&mp_sched_list_lock, RA_LOCKED)

#define MP_SCHED_ALGOOPT_LIMIT			2048

#endif /* _KERNEL */
#endif /* _NETINET_MP_SCHED_H_ */
