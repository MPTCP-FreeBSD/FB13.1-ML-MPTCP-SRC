/*-
 * Copyright (c) 2012-2015
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

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/limits.h>
#include <sys/endian.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/queue.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/proc.h>
#include <sys/jail.h>

#ifdef DDB
#include <ddb/ddb.h>
#endif

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_usrreq.h>
#include <netinet/tcpip.h>

#include <netinet/cc/cc.h>

#include <netinet/mptcp.h>
#include <netinet/mptcp_pcb.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_timer.h>
#include <netinet/mptcp_dtrace_declare.h>

static int mp_attach(struct socket *so);
static void mp_usrclosed(struct mpcb *mp);
static void mp_disconnect(struct mpcb *mp);
static int mp_usr_accept(struct socket *so, struct sockaddr **nam);
static void mp_usr_detach(struct socket *so);
static int mp_subflow_setopt(struct mpcb *mp, struct sockopt *sopt);
static int mp_setopt(struct mpcb *mp, struct sockopt *sopt);
static int mp_getopt(struct mpcb *mp, struct sockopt *sopt);

/*
 * When creating an MPTCP socket, now make a new mpp and mp only. A new
 * (inp,tp,gso) subflow will be created if we issue a connect. If creating a
 * LISTEN socket, then the call the mp_usr_listen will allocate a subflow
 */
static int
mp_usr_attach(struct socket *so, int proto, struct thread *td)
{
    struct mppcb *mpp;
    int error = 0;

    printf("%s: so - %p\n", __func__, so);

    mpp = sotomppcb(so);
	KASSERT(mpp == NULL, ("%s: mpp != NULL", __func__));

    /* This will init the mpcb */
    error = mp_attach(so);
    if (error)
        goto out;

    /* XXXNJW: temp subflow protosw for testing */
    sf_protosw = *so->so_proto;
    sf_protosw.pr_usrreqs = &tcp_usrreqs;
    sf_protosw.pr_ctloutput = tcp_ctloutput;

out:
    return error;
}

/*
 * Initiate a connection. Will need to create and insert a new subflow, then
 * can call tcp_usr_connect on the new subflow to actually send the SYN.
 * tcp_output() attached an MP_CAPABLE to the outgoing SYN segment.
 */
static int
mp_usr_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct mppcb *mpp = NULL;
	struct mpcb *mp = NULL;
	struct socket *sf_so = NULL;
	struct inpcb *inp = NULL;
	int error = 0;

	printf("%s so - %p\n", __func__, so);

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mp_usr_connect: mpp == NULL"));
	MPP_LOCK(mpp);
	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		error = EINVAL;
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp_usr_connect: mp == NULL"));

	if (mp->mp_state > MPS_M_CLOSED) {
		error = EINVAL;
		goto out;
	}

	/* creates a subflow ghost socket, inheriting state from the primary
	 * socket (similar to sonewconn). */
	error = mp_create_subflow_socket(so, &sf_so);
	if (error)
        goto out;

	KASSERT(sf_so != NULL, ("%s: subflow socket NULL", __func__));

	soisconnecting(so);

	/* attach tcpcb and inpcb to the subflow socket */
	error = tcp_attach(sf_so);
	if (error)
        goto out;

	/* Insert the new sufblow pcbs and gso into sf_list */
	error = mp_insert_subflow(mp, sf_so);
    if (error)
    	goto out;

    /* Initiate a connection from the new subflow socket. */
    error = (*(sf_so)->so_proto->pr_usrreqs->pru_connect)(sf_so, nam, td);

	/* XXXNJW: a temporary way to store the default ports used
	 * in this connection. */
    inp = sotoinpcb(sf_so);
out:
    MPP_UNLOCK(mpp);
	return (error);

}

static int
mp_usr_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct mppcb *mpp;
	struct mpcb *mp;
    int error = 0;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mp_usr_bind: mpp NULL"));

	MPP_LOCK(mpp);
	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		error = EINVAL;
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp_usr_bind: mp NULL"));

	if (mp->mp_state > MPS_M_CLOSED) {
		error = EINVAL;
		goto out;
	}

	INP_INFO_WLOCK(&V_tcbinfo);

	/* need to call tcp_usr_bind outside of the MPP lock */
	error = mp_bind_attach(so, mp, nam, td);
	if (error) {
		INP_INFO_WUNLOCK(&V_tcbinfo);
        goto out;
	}
	KASSERT(mp->m_cb_ref.inp != NULL, ("mp_usr_bind: listen inp NULL"));

	INP_INFO_WUNLOCK(&V_tcbinfo);

out:
	MPP_UNLOCK(mpp);
	return (error);
}

/* The bind call should have caused a tcpcb to be
 * allocated, so just need to check if tp exists and
 * call tcp_usr_listen, which should set things
 * up appropriately. */
static int
mp_usr_listen(struct socket *so, int backlog, struct thread *td)
{
	struct mppcb *mpp;
	struct mpcb *mp;
    struct inpcb *inp = NULL;
    struct tcpcb *tp;
	int error = 0;

    mpp = sotomppcb(so);
    KASSERT(mpp != NULL, ("mp_usr_listen: mpp == NULL"));
    MPP_LOCK(mpp);

    printf("%s: so - %p\n", __func__, so);

    mp = mpptompcb(mpp);
    KASSERT(mp != NULL, ("mp_usr_listen: mp == NULL"));

    mp->mp_passive = 1;
    inp = mp->m_cb_ref.inp;

    KASSERT(inp != NULL, ("mp_usr_listen: inp == NULL"));
    INP_WLOCK(inp);

    if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = EINVAL;
		INP_WUNLOCK(inp);
		goto out;
	}
	tp = intotcpcb(inp);

	SOCK_LOCK(so);
	INP_HASH_WLOCK(&V_tcbinfo);
	if (error == 0 && inp->inp_lport == 0)
		error = in_pcbbind(inp, (struct sockaddr *)0, td->td_ucred);
	INP_HASH_WUNLOCK(&V_tcbinfo);
	if (error == 0) {
		tcp_state_change(tp, TCPS_LISTEN);
		solisten_proto(so, backlog);
	}
	SOCK_UNLOCK(so);
	INP_WUNLOCK(inp);

out:
	MPP_UNLOCK(mpp);
	return error;
}

static int
mp_attach(struct socket *so)
{
	struct mppcb *mpp;
    struct mpcb *mp;
	int error = 0;

    /* Allocate the socket buffers. Note that for now
     * when creating the ghost socket for subflows,
     * they will use these sockbufs (but won't for
     * example call sbflush). */
    if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, V_tcp_sendspace, V_tcp_recvspace);
		if (error)
			goto out;
	}

    /* Disable for now, but should be okay to re-enable
     * at a later point. */
	so->so_rcv.sb_flags &= ~SB_AUTOSIZE;
	so->so_snd.sb_flags &= ~SB_AUTOSIZE;

	/* mpp is locked on return */
	error = mpp_pcballoc(so);
	if (error)
		goto out;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL", __func__));

    error = mp_newmpcb(mpp);
	if (error) {
		MPP_UNLOCK(mpp);
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("%s: mp == NULL", __func__));
	mp->mp_state = MPS_M_CLOSED;

	SDT_PROBE1(mptcp, session, mp_attach, mpcb_attached, mp);

	MPP_UNLOCK(mpp);
out:
	return (error);
}


/*
 * Mark the connection as being incapable of further output.
 */
static int
mp_usr_shutdown(struct socket *so)
{
	struct mppcb *mpp = NULL;
	struct mpcb *mp = NULL;
	struct sf_handle *sfh;
	int error = 0;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mpp == NULL"));
    MPP_LOCK(mpp);

    printf("%s: so - %p\n", __func__, so);

	/* Has the primary inpcb of the connection been
	 * previously closed? */
	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}

	socantsendmore(so);

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp == NULL"));

	/* MP-sessions should go through the MPTCP shutdown
	 * states before closing the subflows */
	if (mp->mp_connected) {
		mp_usrclosed(mp);
		/* Unless we were already >= M_FIN_WAIT_2, will
		 * need to send a DFIN to the foreign host. mp_output
		 * unlocks mp, mpp */
		if (!(mpp->mpp_flags & MPP_DROPPED))
			error = mp_output(mp);
	} else if (mp->subflow_cnt > 0) {
		KASSERT(mp->subflow_cnt == 1, ("%s: multiple subflows on non-mptcp "
			"connection\n", __func__));
		/* XXXNJW: Just using the first subflow for now */
		sfh = TAILQ_FIRST(&mp->sf_list);
		KASSERT(sfh->sf_so != NULL, ("%s: sf_so == NULL", __func__));
		printf("%s: shutdown subflow socket %p\n", __func__, sfh->sf_so);
		(*(sfh->sf_so)->so_proto->pr_usrreqs->pru_shutdown)(sfh->sf_so);
	}

out:
	MPP_UNLOCK(mpp);
	return (error);
}

static int
mp_usr_disconnect(struct socket *so)
{
	struct mppcb *mpp;
	struct mpcb *mp = NULL;
	struct sf_handle *sfh;
	int error = 0;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mp_usr_disconnect: mpp == NULL"));

	MPP_LOCK(mpp);

	printf("%s: so - %p\n", __func__, so);

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp_usr_disconnect: mp == NULL"));

	/* (1) A mp_connected session should go through the
	 * multipath shutdown states, which involves sending
	 * a D-FIN and so forth. An MP connection that was
	 * never connected, and never had and subflows will
	 * drop straight through here (as there is nothing to
	 * disconnect). mp_usr_close will cause mp_close to
	 * be called later.
	 * (2) If a MPTCP connection was never established, but
	 * we have subflows, mark the socket as disconnecting
	 * and call pru_disconnect on the subflows now. */
	if (mp->mp_connected) {
		mp_disconnect(mp);
	} else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);

		if (mp->subflow_cnt == 0) {
			/* Will drop the mppcb, but not free any control blocks */
			mp = mp_close(mp);
			KASSERT(mp != NULL, ("mp_disconnect: mp_close() returned NULL"));
		} else {
			/* XXXNJW: Just using the first subflow for now */
			sfh = TAILQ_FIRST(&mp->sf_list);
			if (!(sfh->sf_flags & (SFHS_MPENDED|SFHS_DISCONNECTING))) {
				KASSERT(sfh->sf_so != NULL, ("%s: sf_so == NULL", __func__));
				printf("%s: disconnect subflow socket %p\n", __func__, sfh->sf_so);
				sfh->sf_flags |= SFHS_DISCONNECTING;
				error = (*(sfh->sf_so)->so_proto->pr_usrreqs->pru_disconnect)
					(sfh->sf_so);
			}
		}
	}

out:
    MPP_UNLOCK(mpp);
	return (error);
}

/* XXXNJW: Try to keep mp_disconnect relevant only
 * at MP level. I.e. for connections that reached
 * mp_connected. Other cases should not come through
 * here (e.g. still connecting, infinite mapped) . */
static void
mp_disconnect(struct mpcb *mp)
{
	printf("%s\n", __func__);

	struct mppcb *mpp = mp->mp_mppcb;
	struct socket *so = mpp->mpp_socket;

	MPP_LOCK_ASSERT(mpp);

	if (mp->subflow_cnt == 0) {
		/* If there are no subflows, should close everything
		 * now mp won't return as NULL, as socket won't be
		 * freed  */
		printf("%s: subflow cnt == 0\n", __func__);
		mp = mp_close(mp);
		KASSERT(mp != NULL, ("mp_disconnect: mp_close() returned NULL"));
	} else {
		printf("%s: set mp->socket disconnecting. sf_cnt %d\n", __func__,
		    mp->subflow_cnt);
		/* The session has subflows and reached a connected state */
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		/* We have an active MPTCP session, therefore need to
		 * go through MPTCP shutdown states */
		mp_usrclosed(mp);
		if (!(mpp->mpp_flags & MPP_DROPPED))
		    mp_output(mp);
	}
}

static void
mp_usr_close(struct socket *so)
{
	struct mppcb *mpp = NULL;
	struct mpcb *mp = NULL;
    struct sf_handle *sfh = NULL;
    struct socket *sf_so;
    struct inpcb *sf_inp;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL\n", __func__));
	MPP_LOCK(mpp);

	printf("%s: so - %p\n", __func__, so);

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("%s: mp == NULL\n", __func__));

	/* If an MPTCP connection was established at some point, */
	if (mp->mp_connected) {
		if (!(mpp->mpp_flags & MPP_TIMEWAIT) &&
			!(mpp->mpp_flags & MPP_DROPPED))
			mp_disconnect(mp);

		if (!(mpp->mpp_flags & MPP_TIMEWAIT) &&
			!(mpp->mpp_flags & MPP_DROPPED)) {
			SOCK_LOCK(so);
			so->so_state |= SS_PROTOREF;
			SOCK_UNLOCK(so);
			mpp->mpp_flags |= MPP_SOCKREF;
		}
	} else if (mp->subflow_cnt == 1) {
		/* Might need to wait on tcp to close before freeing,
		 * so take strong reference (prevents sofree from
		 * detaching the mppcb). Must always wait on subflows to
		 * free themselves before we can free the MP-layer
		 * control blocks (as subflows still dereference the
		 * mpcb) */
		if (!(mpp->mpp_flags & MPP_TIMEWAIT) &&
			!(mpp->mpp_flags & MPP_DROPPED)) {
			SOCK_LOCK(so);
			so->so_state |= SS_PROTOREF;
			SOCK_UNLOCK(so);
			mpp->mpp_flags |= MPP_SOCKREF;
		}

		/* Initiate a close on the subflow socket. The subflow
		 * will notify the mp-layer when it discards the tcpcb.
		 * Call sorele after. If the subflow is already DROPPED,
		 * then subflow will be detached and freed. Otherwise
		 * will be freed at the end of time-wait or on entering
		 * tcp_close.
		 *
		 * XXXNJW: temp, just grab the first sublfow as this
		 * should be the only one we have. */
		sfh = TAILQ_FIRST(&mp->sf_list);
		if (sfh->sf_so != NULL) {
			sf_so = sfh->sf_so;
			KASSERT(sf_so != NULL, ("%s: sf so == NULL", __func__));

			sf_inp = sotoinpcb(sf_so);
			KASSERT(sf_inp != NULL, ("%s: inp == NULL", __func__));

			(*sf_so->so_proto->pr_usrreqs->pru_close)(sf_so);

			/* If SS_PROTOREF is not held, should be okay to free
			 * the subflow socket here. Otherwise the subflow socket
			 * is freed once the subflow has finished using it (e.g.
			 * it might still be in the process of disconnecting at
			 * this point). */
			if (!(sf_so->so_state & SS_PROTOREF)) {
				printf("%s: free and release subflow socket\n", __func__);

				/* XXXNJW: temp. To make sure that the mp-layer
				 * doesn't try to access this subflow after this
				 * point. */
				sfh->sf_flags |= SFHS_MPENDED;
				sfh->sf_so = NULL;

				/* sofree on the subflow socket */
				mp_subflow_release_socket(sf_so);

				/* Decrement subflow count. this will result in a
				 * call to mp_close (as we only have a single sublow
				 * in non mp_connected sessions. */
				KASSERT(mp != NULL, ("%s: mp NULL\n", __func__));
				if (mp_detach_subflow_locked(mp))
					return;
			}
		}

	} else if (!(mp->mp_connected) && (mp->subflow_cnt == 0)) {
		printf("%s: subflow already detached\n", __func__);
		if ((mp = mp_close(mp)) == NULL)
		    return;
	}

	MPP_UNLOCK(mpp);
}

static void
mp_usrclosed(struct mpcb *mp)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);

	switch (mp->mp_state) {
	    /* The closed case will be handled earlier than here. */
		case MPS_M_CLOSED:
			printf("%s: already in state CLOSED\n", __func__);
			if(mp->subflow_cnt == 0)
			    mp = mp_close(mp);
			KASSERT(mp != NULL,
			    ("mp_usrclosed: mp_close() returned NULL"));
			break;
		case MPS_M_ESTABLISHED:
			mp->mp_state = MPS_M_FIN_WAIT_1;
			break;
		case MPS_M_CLOSE_WAIT:
			mp->mp_state = MPS_M_LAST_ACK;
			break;
	}

	if (mp->mp_state >= MPS_M_FIN_WAIT_2) {
		printf("%s: >= FW2\n", __func__);
		soisdisconnected(mp->mp_mppcb->mpp_socket);

		/* Prevent the connection hanging in FIN_WAIT_2
		 * indefinitely. Since we call 'close_all_subflows'
		 * when we move to M_FW2, it is possible for the
		 * subflows to all go through shutdown without
		 * sending a DFIN back to US. */
		if (mp->mp_state == MPS_M_FIN_WAIT_2) {
		    // start a timeout. base this on a longer 'idle'
			// period (in case the other side still plans on
			// sending)? just using the hard-coded timer for now
			if (!mp_timer_active(mp, MPT_TIMEOUT))
				mp_timer_activate(mp, MPT_TIMEOUT, MPTCPTV_TIMEOUT);
		}
	}

}

static void
mp_usr_abort(struct socket *so)
{
	struct mppcb *mpp = NULL;
	struct mpcb *mp = NULL;

	printf("%s: not implemented, stopping\n", __func__);
	kdb_break();

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mp_usr_abort: mpp == NULL"));

	MPP_LOCK(mpp);
	KASSERT(mpp->mpp_socket != NULL,
	    ("mp_usr_abort: mp_socket == NULL"));

	if (!(mpp->mpp_flags & MPP_TIMEWAIT) &&
	    !(mpp->mpp_flags & MPP_DROPPED)) {
		mp = mpptompcb(mpp);
		KASSERT(mp != NULL, ("mp_usr_abort: mp == NULL"));
//		mp_drop(mp, ECONNABORTED);
	}
	if (!(mpp->mpp_flags & MPP_DROPPED)) {
		SOCK_LOCK(so);
		so->so_state |= SS_PROTOREF;
		SOCK_UNLOCK(so);
		mpp->mpp_flags |= MPP_SOCKREF;
	}

	MPP_UNLOCK(mpp);
}

/* XXXNJW temporary - just pulls the first subflow
 * and sends */
static int
mp_usr_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	int mp_outflags = 0, error = 0;
	struct mppcb *mpp = NULL;
	struct mpcb *mp = NULL;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL\n", __func__));
	MPP_LOCK(mpp);

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		if (control)
			m_freem(control);
		if (m)
			m_freem(m);
		error = ECONNRESET;
		goto out;
	}

	/* TCP doesn't do control messages (rights, creds, etc) */
	if (control) {
		if (control->m_len) {
			m_freem(control);
			if (m)
				m_freem(m);
			error = EINVAL;
			goto out;
		}
		m_freem(control);	/* empty control, just free it */
	}

	/* no OOB for the moment */
	if (flags & PRUS_OOB) {
		if (m)
			m_freem(m);
		error = EINVAL;
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp_usr_send: mp == NULL"));

	if (nam && !mp->mp_connected) {
		panic("mp_usr_send: transport not yet connected\n");
	}

	/* no flags for now. */
	sbappendstream(&so->so_snd, m, 0);
	if (flags & PRUS_EOF) {
		printf("%s: got PRUS_EOF\n", __func__);
		/*
		 * Close the send side of the connection after
		 * the data is sent.
		 */
		socantsendmore(so);
		mp_usrclosed(mp);
	}
	if (!(mpp->mpp_flags & MPP_DROPPED)) {
		if (flags & PRUS_MORETOCOME)
			mp_outflags |= PRUS_MORETOCOME;

		/* mp_output _no longer_ unlocks */
		if (mp->mp_connected)
		    error = mp_output(mp);
		else
			error = mp_standard_output(mp);
	}

out:
	MPP_UNLOCK(mpp);
	return error;
}

/* XXXNJW temporary Should really just be tested
 * for a valid connection then calling mp_output() */
static int
mp_usr_rcvd(struct socket *so, int flags)
{
	struct mppcb *mpp;
	struct mpcb *mp;
	int error = 0;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL\n", __func__));
	MPP_LOCK(mpp);

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("%s: mp == NULL\n", __func__));

	if (mp->mp_connected)
        error = mp_output(mp);
	else
		error = mp_standard_output(mp);

out:
	MPP_UNLOCK(mpp);
	return error;
}

static int
mp_usr_accept(struct socket *so, struct sockaddr **nam)
{
	struct mppcb *mpp;
	struct mpcb *mp;
	struct sf_handle *sf;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct in_addr addr;
	int error = 0;
	in_port_t port = 0;

	if (so->so_state & SS_ISDISCONNECTED)
		return (ECONNABORTED);

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL", __func__));
	MPP_LOCK(mpp);

	INP_INFO_RLOCK(&V_tcbinfo);

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("%s: mp == NULL", __func__));

	/* XXXNJW: Temp while testing */
	sf = TAILQ_FIRST(&mp->sf_list);
	inp = sotoinpcb(sf->sf_so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));

	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		error = ECONNABORTED;
		goto out;
	}
	tp = intotcpcb(inp);

	/*
	 * We inline in_getpeeraddr and COMMON_END here,
	 * so that we can copy the data of interest and
	 * defer the malloc until after we release the lock.
	 */
	port = inp->inp_fport;
	addr = inp->inp_faddr;

out:
	INP_WUNLOCK(inp);
	INP_INFO_RUNLOCK(&V_tcbinfo);
	MPP_UNLOCK(mpp);

	if (error == 0)
		*nam = in_sockaddr(port, &addr);
	return error;
}

/* XXXNJW temp for testing. Will free any proto blocks
 * associated with the MPTCP socket. There is no MP
 * session time-wait; so this occurs after the tcp
 * subflow time-wait period (if active closer).
 * NB: The MP_LOCK isn't acquired here either. */
static void
mp_usr_detach(struct socket *so)
{
	printf("%s: so %p\n", __func__, so);

	struct mppcb *mpp;
	struct mpcb *mp;
	struct inpcb *inp = NULL;
	struct tcpcb *tp = NULL;

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("mp_usr_detach: mpp NULL"));
    MPP_LOCK(mpp);

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("mp_usr_detach: mp NULL"));

	KASSERT(mpp->mpp_socket != NULL,
	    ("mp_usr_detach: mpp_socket == NULL"));
	KASSERT(so->so_pcb == mpp, ("mp_detach: so_pcb != mpp"));
	KASSERT(mpp->mpp_socket == so, ("mp_detach: mpp_socket != so"));

	/* If there is a listen tp, should discard it */
	if ((inp = mp->m_cb_ref.inp)) {
		INP_INFO_WLOCK(&V_tcbinfo);
		INP_WLOCK(inp);
		tp = intotcpcb(inp);
		KASSERT(tp != NULL, ("%s: tp NULL\n", __func__));
		tcp_discardcb(tp);
		inp->inp_socket = NULL;
		in_pcbfree(inp);
		INP_INFO_WUNLOCK(&V_tcbinfo);
	}

	if (mp->mp_connected) {
		if (mpp->mpp_flags & MPP_TIMEWAIT) {
			/* 1 - M_TIMEWAIT state has been discarded
			 * 2 - Still in TIMEWAIT */
			if (mpp->mpp_flags & MPP_DROPPED) {
				mp_discardcb(mp);
				mpp_pcbdetach(mpp);
				mpp_pcbfree(mpp);
			} else {
				mpp_pcbdetach(mpp);
				MPP_UNLOCK(mpp);
			}
		} else {
			if ((mpp->mpp_flags & MPP_DROPPED) ||
				(mp->mp_state == MPS_M_CLOSED)) {
				mp_discardcb(mp);
				mpp_pcbdetach(mpp);
				mpp_pcbfree(mpp);
			} else {
				printf("%s: detached an mpp that is not "
					"MPP_DROPPED or MPS_M_CLOSED\n", __func__);
				mpp_pcbdetach(mpp);
				MPP_UNLOCK(mpp);
			}
		}
	} else {
		if ((mpp->mpp_flags & MPP_DROPPED) ||
			(mp->mp_state == MPS_M_CLOSED)) {
			mp_discardcb(mp);
			mpp_pcbdetach(mpp);
			mpp_pcbfree(mpp);
		} else {
			/* This case shouldn't happen */
			printf("%s: detached an mp session not MPP_DROPPED or "
				  "MPS_M_CLOSED\n", __func__);
			mpp_pcbdetach(mpp);
			MPP_UNLOCK(mpp);
		}
	}


}

static int
mp_usr_rcvoob(struct socket *so, struct mbuf *m, int flags)
{
	int error = 0;
//	struct inpcb *inp;
//	struct mpcb *mp = NULL;
//	struct sf_handle *sf = NULL;
//
//
//	inp = sotoinpcb(so);
//	KASSERT(inp != NULL, ("%s: inp == NULL\n", __func__));
//	INP_WLOCK(inp);
//	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
//		error = ECONNRESET;
//		INP_WUNLOCK(inp);
//		goto out;
//	}
//
//	mp = intompcb(inp);
//	KASSERT(mp != NULL, ("%s: mp == NULL\n", __func__));
//	mp_pcbref(mp);
//	INP_WUNLOCK(inp);
//
//	sf = TAILQ_FIRST(&mp->sf_list);
//	KASSERT(sf != NULL, ("%s: sf NULL\n", __func__));
//	error = tcp_usr_rcvoob(sf->sf_so, m, flags);
//
//out:
	return error;
}

struct protosw sf_protosw;

#ifdef INET
struct pr_usrreqs mptcp_usrreqs = {
	.pru_abort =		mp_usr_abort,
	.pru_accept =		mp_usr_accept,
	.pru_attach =		mp_usr_attach,
	.pru_bind =	        mp_usr_bind,
	.pru_connect =		mp_usr_connect,
	.pru_control =		in_control,
	.pru_detach =		mp_usr_detach,
	.pru_disconnect =	mp_usr_disconnect,
	.pru_listen =		mp_usr_listen,
	.pru_peeraddr =		mpp_getpeeraddr,
	.pru_rcvd =         mp_usr_rcvd,
	.pru_rcvoob =		mp_usr_rcvoob,
	.pru_send =	        mp_usr_send,
	.pru_shutdown =		mp_usr_shutdown,
	.pru_sockaddr =		mpp_getsockaddr,
	//.pru_sosetlabel =	in_pcbsosetlabel,
	.pru_close =		mp_usr_close,
	.pru_sosend = sosend_generic,
	.pru_soreceive = soreceive_generic,
};
#endif /* INET */

/* XXNJW: Currently just go through all the subflows
 * and set the same sock opt. These settings also need
 * to propagate to new subflows being added later.
 *
 * sosetopt will set options on the mppcb socket before
 * we get here. IPPROTO_IP options, or socket options
 * that might modify an inpcb (e.g. SO_SETFIB) will not
 * be set on the mppcb. So basically at this point
 * socket-level stuff has been already set, and we just
 * filter and propagate options to the subflows (at levels
 * socket, inpcb, tcpcb).
 */
int
mp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct mppcb *mpp;
	struct mpcb *mp;
	int error = 0;

	if (sopt->sopt_level != SOL_SOCKET && sopt->sopt_level != IPPROTO_TCP
		    && sopt->sopt_level != IPPROTO_IP)
		return(EINVAL);

	mpp = sotomppcb(so);
	KASSERT(mpp != NULL, ("%s: mpp == NULL", __func__));
	MPP_LOCK(mpp);

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		MPP_UNLOCK(mpp);
		return (ECONNRESET);
	}

	mp = mpptompcb(mpp);
	KASSERT(mp != NULL, ("%s: mp == NULL", __func__));

	switch (sopt->sopt_dir) {
		case SOPT_SET:
			error = mp_setopt(mp, sopt);
			break;
		case SOPT_GET:
			error = mp_getopt(mp, sopt);
			break;
		default:
			break;
	}

	MPP_UNLOCK(mpp);

	return error;
}

/* Sits between mp_ctloutput and sosetopt of the
 * subflows. Here we filter the options to a subset
 * that has relevance at the subflow level.
 *
 * XXXNJW: currently a very small subset of Socket/TCP/IP
 * options are supported. This can/should expand in
 * the future. */
static int
mp_setopt(struct mpcb *mp, struct sockopt *sopt)
{
    int error = 0, optval;
    struct mp_sopt *m_sopt = NULL;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

	SDT_PROBE3(mptcp, session, mp_setopt, entry, mp,
	    sopt->sopt_level, sopt->sopt_name);

    /* (1) Might need to apply options to subflow
     * sockets. Only some options should be applied.
     * XXXNJW: Should also store what options have been
     * set, so that new subflows can inherit these on
     * creation.
     * (2) IP options.
     * (3) TCP options. */
    if (sopt->sopt_level == SOL_SOCKET) {
    	switch(sopt->sopt_name) {
		/* XXXNJW: For now just pass on this subset of
		 * options to subflow socket */
    	case SO_DEBUG:
    	case SO_KEEPALIVE:
    	case SO_LINGER:
    	/* The following make changes in the inpcb (via
    	 * ip_ctloutput) */
    	case SO_REUSEADDR:
		case SO_REUSEPORT:
		case SO_SETFIB:
    	    break;

		default:
			error = ENOPROTOOPT;
			goto out;
		}
    } else if (sopt->sopt_level == IPPROTO_IP) {
    	switch(sopt->sopt_name) {
		/* XXXNJW: just a minimal set of IP options allowed
		 * through for the moment */
		case IP_OPTIONS:
		case IP_TOS:
		case IP_TTL:
		case IP_MINTTL:
			break;
    	default:
    		error = ENOPROTOOPT;
    		goto out;
    	}
    } else { /* IPPROTO_TCP */
    	switch(sopt->sopt_name) {
		/* XXXNJW: For now pass on this subset of options
		 * to the subflow tcpcb */
		case TCP_NODELAY:
		case TCP_NOPUSH:
		case TCP_MAXSEG:
		case TCP_CONGESTION:
		case TCP_KEEPIDLE:
		case TCP_KEEPINTVL:
		case TCP_KEEPINIT:
		case TCP_KEEPCNT:
			break;
		default:
			error = ENOPROTOOPT;
			goto out;
		}
    }

    if ((error = sooptcopyin(sopt, &optval, sizeof (optval),
        sizeof (optval))) != 0)
    	goto out;

    /* If this is the first time setting this option, create
     * and insert (into mp session list) a new mp_sopt */
    if ((m_sopt = mp_locate_mp_sopt(mp, sopt)) == NULL)
    	m_sopt = mp_alloc_mp_sopt();

    if (m_sopt == NULL) {
		error = ENOBUFS;
		goto out;
	} else {
		/* Populate/refresh option so that it can be applied
		 * to new subflows when they are created. */
    	m_sopt->sopt_level = sopt->sopt_level;
    	m_sopt->sopt_name = sopt->sopt_name;
    	m_sopt->sopt_val = optval;
    }

    /* Apply the option on all the currently existing subflows */
   	error = mp_subflow_setopt(mp, sopt);

out:
	return error;
}

/* XXXNJW: For now just pulling the options that have
 * been set on the first subflow (assuming a subflow
 * has been created). TODO: keep track of what options
 * have been set (or maybe some defaults) and return
 * these. */
static int
mp_getopt(struct mpcb *mp, struct sockopt *sopt)
{
    int error = 0;
    struct sf_handle *sf;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    SDT_PROBE3(mptcp, session, mp_getopt, entry, mp,
    	sopt->sopt_level, sopt->sopt_name);

	/* We have either IP or TCP level options here (as
	 * socket level are processed in sogetopt).
	 *
	 * Need to filter according to the options that we
	 * have, and then return the values that are stored
	 * in mp->mpsopt_list. */

    /* Only return a subset TCP or IP options, as we don't
     * allow setting of all the typical TCP socket opts (for now)*/

    switch (sopt->sopt_level) {
    case IPPROTO_IP:
        switch (sopt->sopt_name) {
		case IP_OPTIONS:
		case IP_TOS:
		case IP_TTL:
		case IP_MINTTL:
			break;
		default:
			error = ENOPROTOOPT;
			goto out;
		}
        break;
	case IPPROTO_TCP:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
		case TCP_MAXSEG:
		case TCP_NOPUSH:
		case TCP_CONGESTION:
			break;
		default:
			error = ENOPROTOOPT;
			goto out;
		}
		break;
	default:
		error = ENOPROTOOPT;
		goto out;
    }
    /* XXXNJW: should base this off of what we have in
     * mpsopt_list, but since all subflows have the same
     * options for now, just  */
    if (mp->subflow_cnt) {
		sf = TAILQ_FIRST(&mp->sf_list);
		if (sf != NULL) {
			error = sogetopt(sf->sf_so, sopt);
		}
	} else
		sopt->sopt_valsize = 0;

out:
	return error;
}


/* Itereate through the subflows and call sosetopt. May
 * need to filter options as it might be incorrect to
 * set options on some subflows, depending on their
 * current state. */
static int
mp_subflow_setopt(struct mpcb *mp, struct sockopt *sopt)
{
    int error = 0;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* XXXNJW: Once the options have been filtered,
     * iterate through and set on all subflows.
     *
     * Options must be protocol-specific (i.e. TCP)
     * and also subflow-relevant */

    /* XXNJW: From here on should be applying option
     * to subflows */
    if (mp->subflow_cnt) {
		struct sf_handle *sf;
		/* Iterate here */
		sf = TAILQ_FIRST(&mp->sf_list);
		if (sf != NULL) {
			printf("%s: set opt level %d name %d on sf %p\n", __func__,
				sopt->sopt_level, sopt->sopt_name, sototcpcb(sf->sf_so));
			error = sosetopt(sf->sf_so, sopt);
		}

		/* Also store a copy of the currently applied
		 * socket options, so newly created subflows can
		 * apply these also. */
    }
    return error;
}
