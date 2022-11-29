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

#ifndef MPTCP_PCB_H_
#define MPTCP_PCB_H_

#define mpptompcb(mpp)	(mpp)->mpp_mpcb

/* XXXNJW Should define an mpp conninfo struct for fibnum, ports */

/*
 * Multi-path Protocol Control Block.
 *
 * Replacement of the INET PCB (inpcb), used in standard TCP/SOCK_STREAM
 * sockets. The inpcb is still used on each of the subflow sockets.
 */
struct mppcb {
	struct socket *mpp_socket;	/* pointer to socket of master subflow */
	struct mpcb *mpp_mpcb;		 /* per-protocol control block (mptcp only) */
    struct mtx mppcb_mutex;	 /* mutex for the protocol control block */
    struct	ucred	*mpp_cred;	/* cache of socket cred */
    u_int16_t mpp_flags;      /* Connection flags (TIMEWAIT, DROPPED)*/
	uint8_t	mpp_status;		 /* Connection status _UNUSED_ */
	u_int mpp_refcount;          /* refcount */

	/* To move to a 'conninfo'-type struct */
    int mpp_fibnum;
    in_port_t mpp_lport;
    in_port_t mpp_fport;
    uint32_t mpp_laddr;
    uint32_t mpp_faddr;
};


/* MP Flags (mp_flags) */
#define MPP_TIMEWAIT		0x0001	/* MP state machine time-wait */
#define MPP_DROPPED		0x0002	/* protocol dropped */
#define MPP_SOCKREF		0X0004	/* Strong socket reference */

/* Mutex for the MPCB */
#define MPP_LOCK_INIT(mpp) mtx_init(&mpp->mppcb_mutex, "mppcb", NULL, MTX_DEF)
#define MPP_LOCK_DESTROY(mpp) mtx_destroy(&mpp->mppcb_mutex)
#define MPP_LOCK(mpp)      mtx_lock(&mpp->mppcb_mutex)
#define MPP_LOCKED(mpp)   mtx_owned(&(mpp)->mppcb_mutex)
#define MPP_UNLOCK(mpp)	   mtx_unlock(&mpp->mppcb_mutex)
#define	MPP_LOCK_ASSERT(mpp) mtx_assert(&mpp->mppcb_mutex, MA_OWNED)

int mpp_pcballoc(struct socket *);
int mpp_getsockaddr(struct socket *so, struct sockaddr **nam);
int mpp_getpeeraddr(struct socket *so, struct sockaddr **nam);
int	mpp_pcbrele(struct mppcb *mpp);
void mpp_pcbrele_unlocked(struct mppcb *mpp);
void mpp_pcbdetach(struct mppcb *);
void mpp_pcbdrop(struct mppcb *);
void mpp_pcbfree(struct mppcb *);
void mpp_pcbref(struct mppcb *mpp);

#endif /* MPTCP_PCB_H_ */