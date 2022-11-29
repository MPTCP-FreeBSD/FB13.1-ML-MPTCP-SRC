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
#include <sys/refcount.h>
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
#include <netinet/mptcp_dtrace_define.h>

static VNET_DEFINE(uma_zone_t, mppcb_zone);
#define	V_mppcb_zone			VNET(mppcb_zone)

/*
 * Allocate a PCB and associate it with the socket.
 * On success return with the PCB locked.
 */
int
mpp_pcballoc(struct socket *so)
{
	struct mppcb *mpp;

	mpp = uma_zalloc(V_mppcb_zone, M_NOWAIT | M_ZERO);
	if (mpp == NULL)
		return (ENOBUFS);
	mpp->mpp_socket = so;
	mpp->mpp_cred = crhold(so->so_cred);
	mpp->mpp_fibnum = so->so_fibnum;
	so->so_pcb = (caddr_t)mpp;
	refcount_init(&mpp->mpp_refcount, 1);

	MPP_LOCK_INIT(mpp);
	MPP_LOCK(mpp);

	SDT_PROBE1(mptcp, session, mpp_pcballoc, mppcb_alloc, mpp);

	return (0);
}

int
mpp_getsockaddr(struct socket *so, struct sockaddr **nam)
{
	struct mppcb *mpp;
	uint32_t addr;
	in_port_t port;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mpp_getsockaddr: mp == NULL"));

	MPP_LOCK(mpp);
	port = mpp->mpp_lport;
	addr = mpp->mpp_laddr;
	MPP_UNLOCK(mpp);

	*nam = in_sockaddr(port, (struct in_addr*) &addr);
	return 0;
}


/* should have a primary inp if this function is called. */
int
mpp_getpeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct mppcb *mpp;
	struct mpcb *mp;
	struct sf_handle *sfh;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("in_getpeeraddr: inp == NULL"));
	MPP_LOCK(mpp);

    mp = mpptompcb(mpp);
    KASSERT(mp != NULL, ("in_getsockaddr: mp == NULL"));

    /* XXXNJW: Just using the first subflow for now */
    sfh = TAILQ_FIRST(&mp->sf_list);
    KASSERT(sfh->sf_so != NULL, ("in_getpeeraddr: sf_so == NULL"));

  	MPP_UNLOCK(mpp);

	/* not good, but temporary */
    (*(sfh->sf_so)->so_proto->pr_usrreqs->pru_peeraddr)(sfh->sf_so, nam);

	return 0;
}


/*
 * mpp_pcbdetach() is responsible for dissociating a socket from an mppcb.
 * With established MPTCP connections, the mppcb may significantly outlive
 * the socket, in which case mpp_pcbfree() is deferred.
 */
void
mpp_pcbdetach(struct mppcb *mpp)
{
	KASSERT(mpp->mpp_socket != NULL, ("%s: mpp_socket == NULL", __func__));

	mpp->mpp_socket->so_pcb = NULL;
	mpp->mpp_socket = NULL;
}

void
mpp_pcbdrop(struct mppcb *mpp)
{
	MPP_LOCK_ASSERT(mpp);
	mpp->mpp_flags |= MPP_DROPPED;
}

void
mpp_pcbfree(struct mppcb *mpp)
{
	KASSERT(mpp->mpp_socket == NULL, ("%s: mpp_socket != NULL", __func__));

	MPP_LOCK_ASSERT(mpp);

	if (!mpp_pcbrele(mpp))
	    MPP_UNLOCK(mpp);
}

/* XXXNJW - comment to reflect what happens in the case of
 * an mppcb refcount (much the same as with an inpcb count,
 * but there are some odd uses of the refcount in the code
 * currently (see tcp_do_segement and goto mp_input within) */
void
mpp_pcbref(struct mppcb *mpp)
{
	KASSERT(mpp->mpp_refcount > 0, ("%s: refcount 0", __func__));
	refcount_acquire(&mpp->mpp_refcount);
}

/* XXXNJW: This is a workaround to allow tcp_do_segment
 * to release a reference on the mpp without already
 * holding the MPP_LOCK. Currently tcp_do_segment bumps
 * the refcount on the mpp to prevent a use-after-free
 * error on connection closes where pru_close and tcp
 * shutdown race with one another. */
void
mpp_pcbrele_unlocked(struct mppcb *mpp)
{
	MPP_LOCK(mpp);
	if(!mpp_pcbrele(mpp))
		MPP_UNLOCK(mpp);
	return;
}

int
mpp_pcbrele(struct mppcb *mpp)
{
	KASSERT(mpp->mpp_refcount > 0, ("%s: refcount 0", __func__));
	MPP_LOCK_ASSERT(mpp);
	if (refcount_release(&mpp->mpp_refcount) == 0)
		return (0);

	SDT_PROBE1(mptcp, session, mpp_pcbrele, mppcb_release, mpp);
	printf("%s: %p\n", __func__, mpp);

	/* released last reference to mpp */
	crfree(mpp->mpp_cred);

	MPP_UNLOCK(mpp);
	MPP_LOCK_DESTROY(mpp); // XXX: to change
	uma_zfree(V_mppcb_zone, mpp);

    return (1);
}

void
mpp_init(void) {
	V_mppcb_zone = uma_zcreate("mppcb", sizeof(struct mppcb),
					NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(V_mppcb_zone, maxsockets);
}