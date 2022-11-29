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
#ifndef MPTCP_DTRACE_DECLARE_H_
#define MPTCP_DTRACE_DECLARE_H_

#include "opt_kdtrace.h"
#include <sys/kernel.h>
#include <sys/sdt.h>

/* Declare the MPTCP provider */
SDT_PROVIDER_DECLARE(mptcp);

/* Allocated a MPPCB */
SDT_PROBE_DECLARE(mptcp, session, mpp_pcballoc, mppcb_alloc);

/* Released a MPPCB */
SDT_PROBE_DECLARE(mptcp, session, mpp_pcbrele, mppcb_release);

/* Attached a MPCB */
SDT_PROBE_DECLARE(mptcp, session, mp_attach, mpcb_attached);

/* Discard a MPCB */
SDT_PROBE_DECLARE(mptcp, session, mp_discardcb, entry);

/* Info on connection becoming established */
SDT_PROBE_DECLARE(mptcp, session, mp_init_established, estab_info);

/* Setting options at the subflow level. */
SDT_PROBE_DECLARE(mptcp, session, mp_setopt, entry);

/* Getting options at the subflow level. */
SDT_PROBE_DECLARE(mptcp, session, mp_getopt, entry);

/* Setting options at the subflow level. */
SDT_PROBE_DECLARE(mptcp, session, mp_process_subflow_event, connected);

/* Local session key and token */
SDT_PROBE_DECLARE(mptcp, session, mp_process_local_key, new_key);

/* Foreign Host session key and token */
SDT_PROBE_DECLARE(mptcp, session, mp_process_remote_key, new_key);

/* Detach tcpcb from socket */
SDT_PROBE_DECLARE(mptcp, session, tcp_detach, entry);


#endif /* MPTCP_DTRACE_DECLARE_H_ */