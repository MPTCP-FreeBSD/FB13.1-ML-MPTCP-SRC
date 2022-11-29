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

#include <sys/cdefs.h>
#ifndef MPTCP_DTRACE_DEFINE_H_
#define MPTCP_DTRACE_DEFINE_H_

#include "opt_kdtrace.h"
#include <sys/kernel.h>
#include <sys/sdt.h>

SDT_PROVIDER_DEFINE(mptcp);

/* Allocated a new mppcb */
SDT_PROBE_DEFINE1(mptcp, session, mpp_pcballoc, mppcb_alloc,
	"uintptr_t");    /* Pointer to mppcb struct allocated */

/* Released a mppcb */
SDT_PROBE_DEFINE1(mptcp, session, mpp_pcbrele, mppcb_release,
	"uintptr_t");    /* Pointer to mppcb struct to be released */

/* Attached MP transport block */
SDT_PROBE_DEFINE1(mptcp, session, mp_attach, mpcb_attached,
	"uintptr_t");    /* Pointer to mpcb struct attached to mppcb */

/* Discard MP transport block */
SDT_PROBE_DEFINE1(mptcp, session, mp_discardcb, entry,
	"uintptr_t");    /* Pointer to mpcb struct to be discarded */

/* MP session transitions to M_ESTABLISHED */
SDT_PROBE_DEFINE5(mptcp, session, mp_init_established, estab_info,
    "uint64_t",		/* Initial data-sequence send */
    "uint64_t",		/* Initial data-sequence receive */
    "uintptr_t",	/* The pointer to the struct mpcb */
    "uint32_t",	    /* Local mp session token */
    "uint32_t");	/* Remote mp session token */

/* Setting socket options */
SDT_PROBE_DEFINE3(mptcp, session, mp_setopt, entry,
	"uintptr_t",    /* Pointer to mpcb struct */
	"int_t",    /* Protocol level */
	"int_t");	/* Option value */

/* Getting socket options */
SDT_PROBE_DEFINE3(mptcp, session, mp_getopt, entry,
	"uintptr_t",    /* Pointer to mpcb struct */
	"int_t",    /* Protocol level */
	"int_t");	/* Option value */

/* Generation of local key */
SDT_PROBE_DEFINE2(mptcp, session, mp_process_subflow_event, connected,
	"uintptr_t",    /* Pointer to mpcb struct */
	"uintptr_t");   /* Pointer to tcbcb struct */

/* Generation of local key */
SDT_PROBE_DEFINE2(mptcp, session, mp_process_local_key, new_key,
    "uint32_t",		/* Local session token */
    "uint64_t");	/* Local key */

/* Remote key and foreign host session token */
SDT_PROBE_DEFINE2(mptcp, session, mp_process_remote_key, new_key,
    "uint32_t",		/* Foreign host session token */
    "uint64_t");	/* Remote key */

SDT_PROBE_DEFINE1(mptcp, session, tcp_detach, entry,
		"uintptr_t");   /* Pointer to struct socket */


#endif /* MPTCP_DTRACE_DEFINE_H_ */