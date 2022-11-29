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
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/hhook.h>
#include <sys/kernel.h>
#include <sys/khelp.h>
#include <sys/kdb.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/sbuf.h>
#include <sys/taskqueue.h>
#include <sys/jail.h>

#ifdef INET6
#include <sys/domain.h>
#endif
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/refcount.h>
#include <sys/sockbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/random.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_usrreq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_syncache.h>

#include <netinet/mptcp.h>
#include <netinet/mptcp_timer.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_pcb.h>

#include <machine/in_cksum.h>
#include <machine/stdarg.h>



int
mp_reass(struct mpcb *mp, struct mbuf *m)
{
	struct mbuf *mq, *mpre;
	struct socket *so = mp->mp_mppcb->mpp_socket;
	int flags = 0, wakeup = 0, todrop;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	M_ASSERTPKTHDR(m);
    KASSERT(m_tag_locate(m, PACKET_COOKIE_MPTCP, PACKET_TAG_DSN, NULL) != NULL,
        ("%s: no dsn tag on segment\n", __func__));

//	printf("%s: packetlen %d\n", __func__, m->m_pkthdr.len);
//    printf("%s: ds_rcv_nxt: %u mdsn %u\n", __func__,
//        (uint32_t) mp->ds_rcv_nxt, (uint32_t) M_MPTCPDSN(m));
//    printf("%s: ds_rcv_nxt: %ju mdsn %ju\n", __func__,
//		mp->ds_rcv_nxt, M_MPTCPDSN(m));
    if (M_MPTCPDSNFLAGS(m) & MP_DFIN)
		printf("%s: inserting dfin seg %u ds_rcv_nxt: %u\n",__func__,
		    (uint32_t) mp->ds_rcv_nxt, (uint32_t) M_MPTCPDSN(m));

    /* Trim overlapping at data level, or drop if duplicate */
    todrop = mp->ds_rcv_nxt - M_MPTCPDSN(m);
    if (todrop > 0) {
//    	printf("%s: dup segment %u len %d todrop %d \n", __func__,
//    		(uint32_t) M_MPTCPDSN(m), m->m_pkthdr.len, todrop);
    	/* Partially duplicated segment. Trim until
		 * we reach the new data. Otherwise a complete
		 * duplicate that can be freed. goto present
		 * to read in any queued data. */
    	if (todrop < m->m_pkthdr.len) {
			M_MPTCPDSN(m) += todrop;
			m_adj(m, todrop);
		} else {
			m_freem(m);
			if (mp->mp_segq)
			    goto present;
			else
				return (0);
		}
    }

	/*
	 * Find a segment which begins after this one does.
     * XXX: adjust for dealing with DSNs
	 */
	mpre = NULL;
	for (mq = mp->mp_segq; mq != NULL; mq = mq->m_nextpkt) {
//		printf("%s: mqdsn %lu mdsn %lu\n", __func__,
//		    M_MPTCPDSN(mq), M_MPTCPDSN(m));
		if (DSEQ_GT((uint64_t)M_MPTCPDSN(mq), (uint64_t)M_MPTCPDSN(m)))
			break;
		mpre = mq;
//		printf("%s: mpre set, dsn %u\n", __func__, (uint32_t) M_MPTCPDSN(mq));
	}

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
     *
     * XXX: in this case dealing with DSNs rather than TCP SEQs.
     * So previous_dsn + previous_len compared with the DSN on
     * the passed in mbuf.
     *
     * After adjustment we change the DSN on the mbuf tag. Note
     * that the
	 */
	if (mpre != NULL) {
		int i;

		/* conversion to int (in i) handles seq wraparound */
		i = M_MPTCPDSN(mpre) + mpre->m_pkthdr.len - M_MPTCPDSN(m);
		if (i > 0) {
			if (i >= m->m_pkthdr.len) {
				m_freem(m);
				/*
				 * Try to present any queued data
				 * at the left window edge to the user.
				 * This is needed after the 3-WHS
				 * completes.
				 */
				goto present;	/* ??? */
			}
			m_adj(m, i);
			M_MPTCPDSN(m) += i;
		}
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (mq) {
		struct mbuf *nq;
		int i;

		i = (M_MPTCPDSN(m) + m->m_pkthdr.len) - M_MPTCPDSN(mq);
		if (i <= 0)
			break;
		if (i < mq->m_pkthdr.len) {
			M_MPTCPDSN(mq) += i;
			m_adj(mq, i);
			mp->mp_segqlen -= i;
			break;
		}

		nq = mq->m_nextpkt;
		mp->mp_segqlen -= mq->m_pkthdr.len;
		m_freem(mq);
		if (mpre)
			mpre->m_nextpkt = nq;
		else
			mp->mp_segq = nq;
		mq = nq;
	}

	/*
	 * Insert the new (data-level) segment queue entry into place.
	 */
	if (mpre) {
		m->m_nextpkt = mpre->m_nextpkt;
		mpre->m_nextpkt = m;
	} else {
		mq = mp->mp_segq;
		mp->mp_segq = m;
		m->m_nextpkt = mq;
	}
	mp->mp_segqlen += m->m_pkthdr.len;

present:

    /* XXXNJW: check to see if first segment is in order.
     * if so, schedule mp_input, which will append the
     * data to the buffer. */
	mq = mp->mp_segq;
//    printf("%s: present, got %ju, rcv_nxt %ju\n", __func__,
//		M_MPTCPDSN(mq), mp->ds_rcv_nxt);

	SOCKBUF_LOCK(&so->so_rcv);
	while ((mq = mp->mp_segq) != NULL &&
		M_MPTCPDSN(mq) == mp->ds_rcv_nxt) {

		mp->mp_segq = mq->m_nextpkt;
		mp->ds_rcv_nxt += mq->m_pkthdr.len;
		mp->mp_segqlen -= mq->m_pkthdr.len;

//		printf("%s: rcv_nst now %ju\n", __func__, mp->ds_rcv_nxt);

		/* XXXNJW: temp way to handle receipt of DFIN. Need to +1
		 * ds_rcv_nxt as generally it is increased by segment length
		 * rather than the dss_len (also currently the dss len isn't
		 * included in the mtag) */
		flags = M_MPTCPDSNFLAGS(mq) & MP_DFIN;

		if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
			m_freem(mq);
		else {
			mq->m_nextpkt = NULL;
			sbappendstream_locked(&so->so_rcv, mq, 0);
			wakeup = 1;
		}
	}

	if (wakeup) {
		mp->mp_flags |= MPF_ACKNOW;
		sorwakeup_locked(so);
	} else
		SOCKBUF_UNLOCK(&so->so_rcv);

	return (flags);

}