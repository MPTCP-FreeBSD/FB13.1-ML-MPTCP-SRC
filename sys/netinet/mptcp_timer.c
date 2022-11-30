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
__FBSDID("$FreeBSD$");

#include "opt_compat.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#include "opt_tcpdebug.h"

#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/sbuf.h>
#include <sys/jail.h>

#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>

/* XXXNJW: too many header dependencies with mptcp_var.h? (i.e. need to pull in
 * in.h etc etc to compile. */
#include <netinet/in.h>

#include <sys/sockbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/vnet.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp_pcb.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_timer.h>


int	mp_backoff[MPT_MAXRXTSHIFT + 1] = {1, 1, 1, 1};


void
mp_timer_activate(struct mpcb *mp, int timer_type, u_int delta)
{
	struct callout *t_callout;
	void *f_callout;
	int cpu = curcpu;   /* XXNJW: look into cpuid stuff */

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	switch (timer_type) {
		case MPT_REXMT:
			t_callout = &mp->mp_timers->mpt_rexmt;
			f_callout = mp_timer_rexmt;
			break;
		case MPT_TIMEOUT:
			printf("%s: mp %p activate timeout\n", __func__, mp);
			t_callout = &mp->mp_timers->mpt_timeout;
			f_callout = mp_timer_timeout;
			break;
		default:
			panic("bad timer_type");
		}
	if (delta == 0) {
		callout_stop(t_callout);
	} else {
		callout_reset_on(t_callout, delta, f_callout, mp, cpu);
	}
}

int
mp_timer_active(struct mpcb *mp, int timer_type)
{
	struct callout *t_callout;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	switch (timer_type) {
	    case MPT_REXMT:
		    t_callout = &mp->mp_timers->mpt_rexmt;
		    break;
		case MPT_TIMEOUT:
			t_callout = &mp->mp_timers->mpt_timeout;
			break;
		default:
			panic("bad timer_type");
		}
	return callout_active(t_callout);
}

void
mp_timer_rexmt(void * xmp)
{
    struct mppcb *mpp;
    struct mpcb *mp = xmp;

    /* XXXNJW should be concerned about races with discard? */
	if (mp == NULL) {
		return;
	}

	mpp = mp->mp_mppcb;
    MPP_LOCK(mpp);

	printf("%s: rxtshift %d, snd_nxt %u snd_una %u\n", __func__,
	    mp->mp_rxtshift, (uint32_t) mp->ds_snd_nxt,
	    (uint32_t) mp->ds_snd_una);

	if (callout_pending(&mp->mp_timers->mpt_rexmt) ||
		!callout_active(&mp->mp_timers->mpt_rexmt))
        goto out;

	callout_deactivate(&mp->mp_timers->mpt_rexmt);
	if ((mpp->mpp_flags & MPP_DROPPED) != 0)
		goto out;

    /* Reached max data-level RTOs, drop the connection. */
	if (++mp->mp_rxtshift > MPT_MAXRXTSHIFT) {
		printf("%s: rxtshift %d reset subflows\n", __func__, mp->mp_rxtshift);
		mp->mp_rxtshift = MPT_MAXRXTSHIFT;
		mp_reset_all_subflows(mp);
		(void) mp_drop(mp, ETIMEDOUT);
		KASSERT(mp != NULL, ("%s: MP is NULL\n", __func__));
		goto out;
	}

    /* update the timer */
    mp->mp_rxtcur = MPTCPTV_RTOBASE * mp_backoff[mp->mp_rxtshift];
    mp->ds_snd_nxt = mp->ds_snd_una;

    printf("%s: mp_rxtcur %d ticks\n", __func__, mp->mp_rxtcur);

    (void) mp_output(mp);

    // mp_output now returns locked
//    CURVNET_RESTORE();
//    return;

out:
    MPP_UNLOCK(mpp);
}


/* XXXNJW: timeout only set when we have no subflows (i.e.
 * all have detached.) Thus in this case we can call mp_close
 * */
void
mp_timer_timeout(void * xmp)
{
    struct mppcb *mpp;
    struct mpcb *mp = xmp;
    struct socket *so;

    printf("%s: mp %p\n", __func__, mp);

    /* XXXNJW should be concerned about races with discard? */
    if (mp == NULL) {
		return;
	}

    mpp = mp->mp_mppcb;
    MPP_LOCK(mpp);

	if (callout_pending(&mp->mp_timers->mpt_timeout) ||
		!callout_active(&mp->mp_timers->mpt_timeout))
        goto out;

	callout_deactivate(&mp->mp_timers->mpt_timeout);

	mpp_pcbdrop(mpp);

	/* Arrive here at end of timewait, or timed out. */
	if (mpp->mpp_flags & MPP_TIMEWAIT) {
		/* XXXNJW: what if we still have subflow cnt > 0 at this point? */
		mp->mp_state = MPS_M_CLOSED;
		so = mpp->mpp_socket;
		if (so != NULL) {
			/* XXXNJW: expect to have socket reference if the socket
			 * still exists at the end of timewait. */
			if (mpp->mpp_flags & MPP_SOCKREF) {
				mpp->mpp_flags &= ~MPP_SOCKREF;
				MPP_UNLOCK(mpp);
				ACCEPT_LOCK();
				SOCK_LOCK(so);
				KASSERT(so->so_state & SS_PROTOREF,
					("tcp_twclose: INP_SOCKREF && !SS_PROTOREF"));
				so->so_state &= ~SS_PROTOREF;
				sofree(so);
				return;
			} else {
				/* should not be any cases where something else has a
				 * reference to the socket? */
				printf("%s: ended timewait with socket, no hard ref\n",
				    __func__);
			}
		} else {
			/* The socket has been already cleaned-up for us, free mp, mpp */
			mp_discardcb(mp);
			mp = NULL;
			mpp_pcbfree(mpp);
			mpp = NULL;
		}
	} else {
		mp = mp_drop(mp, ETIMEDOUT);
	}
out:
    if (mp != NULL)
	    MPP_UNLOCK(mpp);
}