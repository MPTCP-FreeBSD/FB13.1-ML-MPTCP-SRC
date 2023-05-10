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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_var.h>

#include <netinet/mp_sched/mp_sched.h>

#include <netinet/mp_sched/mp_sched_module.h>

/*
 * List of available MP scheduler algorithms on the current system. First element
 * is used as the system default MP scheduler algorithm.
 */
struct mp_sched_head mp_sched_list = STAILQ_HEAD_INITIALIZER(mp_sched_list);

/* Protects the mp_sched_list TAILQ. */
struct rwlock mp_sched_list_lock;

VNET_DEFINE(struct mp_sched_algo *, default_mp_sched_ptr) = &roundrobin_mp_sched_algo;

/*
 * Sysctl handler to show and change the default MP scheduler algorithm.
 */
static int
mp_sched_default_algo(SYSCTL_HANDLER_ARGS)
{
	char default_mp_sched[MPTCP_SA_NAME_MAX];
	struct mp_sched_algo *funcs;
	int error;

	/* Get the current default: */
	MP_SCHED_LIST_RLOCK();
	strlcpy(default_mp_sched, MP_SCHED_DEFAULT()->name, sizeof(default_mp_sched));
	MP_SCHED_LIST_RUNLOCK();

	error = sysctl_handle_string(oidp, default_mp_sched, sizeof(default_mp_sched), req);

	/* Check for error or no change */
	if (error != 0 || req->newptr == NULL)
		goto done;

	error = ESRCH;

	/* Find algo with specified name and set it to default. */
	MP_SCHED_LIST_RLOCK();
	STAILQ_FOREACH(funcs, &mp_sched_list, entries) {
		if (strncmp(default_mp_sched, funcs->name, sizeof(default_mp_sched)))
			continue;
		V_default_mp_sched_ptr = funcs;
		error = 0;
		break;
	}
	MP_SCHED_LIST_RUNLOCK();
done:
	return (error);
}

/*
 * Sysctl handler to display the list of available MP scheduler algorithms.
 */
static int
mp_sched_list_available(SYSCTL_HANDLER_ARGS)
{
	struct mp_sched_algo *algo;
	struct sbuf *s;
	int err, first, nalgos;

	err = nalgos = 0;
	first = 1;

	MP_SCHED_LIST_RLOCK();
	STAILQ_FOREACH(algo, &mp_sched_list, entries) {
		nalgos++;
	}
	MP_SCHED_LIST_RUNLOCK();

	s = sbuf_new(NULL, NULL, nalgos * MPTCP_SA_NAME_MAX, SBUF_FIXEDLEN);

	if (s == NULL)
		return (ENOMEM);

	/*
	 * It is theoretically possible for the MP scheduler list to have grown 
	 * in size since the call to sbuf_new() and therefore for the sbuf to be 
	 * too small. If this were to happen (incredibly unlikely), the sbuf will
	 * reach an overflow condition, sbuf_printf() will return an error and
	 * the sysctl will fail gracefully.
	 */
	MP_SCHED_LIST_RLOCK();
	STAILQ_FOREACH(algo, &mp_sched_list, entries) {
		err = sbuf_printf(s, first ? "%s" : ", %s", algo->name);
		if (err) {
			/* Sbuf overflow condition. */
			err = EOVERFLOW;
			break;
		}
		first = 0;
	}
	MP_SCHED_LIST_RUNLOCK();

	if (!err) {
		sbuf_finish(s);
		err = sysctl_handle_string(oidp, sbuf_data(s), 0, req);
	}

	sbuf_delete(s);
	return (err);
}

/*
 * Reset the default MP scheduler algo to RoundRobin for any netstack which is using the algo
 * that is about to go away as its default.
 */
static void
mp_sched_checkreset_default(struct mp_sched_algo *remove_mp_sched)
{
	VNET_ITERATOR_DECL(vnet_iter);

	MP_SCHED_LIST_LOCK_ASSERT();

	VNET_LIST_RLOCK_NOSLEEP();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);
		if (strncmp(MP_SCHED_DEFAULT()->name, remove_mp_sched->name,
		    MPTCP_SA_NAME_MAX) == 0)
			V_default_mp_sched_ptr = &roundrobin_mp_sched_algo;
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK_NOSLEEP();
}

/*
 * Initialise MP scheduler subsystem on system boot.
 */
static void
mp_sched_init(void)
{
	MP_SCHED_LIST_LOCK_INIT();
	STAILQ_INIT(&mp_sched_list);
}

/*
 * Returns non-zero on success, 0 on failure.
 */
int
mp_sched_deregister_algo(struct mp_sched_algo *remove_mp_sched)
{
	struct mp_sched_algo *funcs, *tmpfuncs;
	int err;

	err = ENOENT;

	/* Never allow roundrobin to be deregistered. */
	if (&roundrobin_mp_sched_algo == remove_mp_sched)
		return (EPERM);

	/* Remove algo from mp_sched_list so that new connections can't use it. */
	MP_SCHED_LIST_WLOCK();
	STAILQ_FOREACH_SAFE(funcs, &mp_sched_list, entries, tmpfuncs) {
		if (funcs == remove_mp_sched) {
			mp_sched_checkreset_default(remove_mp_sched);
			STAILQ_REMOVE(&mp_sched_list, funcs, mp_sched_algo, entries);
			err = 0;
			break;
		}
	}
	MP_SCHED_LIST_WUNLOCK();

	if (!err)
		mptcp_schedalgounload(remove_mp_sched);

	return (err);
}

/*
 * Returns 0 on success, non-zero on failure.
 */
int
mp_sched_register_algo(struct mp_sched_algo *add_mp_sched)
{
	struct mp_sched_algo *funcs;
	int err;

	err = 0;

	/*
	 * Iterate over list of registered MP scheduler algorithms and make sure
	 * we're not trying to add a duplicate.
	 */
	MP_SCHED_LIST_WLOCK();
	STAILQ_FOREACH(funcs, &mp_sched_list, entries) {
		if (funcs == add_mp_sched || strncmp(funcs->name, add_mp_sched->name,
		    MPTCP_SA_NAME_MAX) == 0)
			err = EEXIST;
	}

	if (!err)
		STAILQ_INSERT_TAIL(&mp_sched_list, add_mp_sched, entries);

	MP_SCHED_LIST_WUNLOCK();

	return (err);
}

/*
 * Handles kld related events. Returns 0 on success, non-zero on failure.
 */
int
mp_sched_modevent(module_t mod, int event_type, void *data)
{
	struct mp_sched_algo *algo;
	int err;

	err = 0;
	algo = (struct mp_sched_algo *)data;

	switch(event_type) {
	case MOD_LOAD:
		if (algo->mod_init != NULL)
			err = algo->mod_init();
		if (!err)
			err = mp_sched_register_algo(algo);
		break;

	case MOD_QUIESCE:
	case MOD_SHUTDOWN:
	case MOD_UNLOAD:
		err = mp_sched_deregister_algo(algo);
		if (!err && algo->mod_destroy != NULL)
			algo->mod_destroy();
		if (err == ENOENT)
			err = 0;
		break;

	default:
		err = EINVAL;
		break;
	}

	return (err);
}

SYSINIT(mp_sched, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_FIRST, mp_sched_init, NULL);

/* Declare sysctl tree and populate it. */
SYSCTL_NODE(_net_inet_tcp_mptcp, OID_AUTO, scheduler, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "MPTCP scheduler related settings");

SYSCTL_PROC(_net_inet_tcp_mptcp_scheduler, OID_AUTO, algorithm,
    CTLFLAG_VNET | CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, 0, mp_sched_default_algo, "A",
    "Default MPTCP scheduler algorithm");

SYSCTL_PROC(_net_inet_tcp_mptcp_scheduler, OID_AUTO, available,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, 0, mp_sched_list_available, "A",
    "List available MPTCP scheduler algorithms");
