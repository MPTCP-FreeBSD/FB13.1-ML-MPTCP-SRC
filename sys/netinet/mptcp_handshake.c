/*-
 * Copyright (c) 2013-2015
 * Swinburne University of Technology, Melbourne, Australia.
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Nigel Williams,
 * made possible in part by a gift from The FreeBSD Foundation.
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
#include <sys/sockbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/random.h>

/* for SCTP auth functions */
#include <crypto/sha1.h>

/* for checking interface status */
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_usrreq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_syncache.h>

#include <netinet/mptcp.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_pcb.h>
#include <netinet/mptcp_dtrace_declare.h>

/* for SCTP auth functions */
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_auth.h>
#include <netinet/sctp_constants.h>

#include <machine/in_cksum.h>
#include <machine/stdarg.h>

static void mp_instoklist(struct mpcb *mp);

void
mp_init_established(struct mpcb *mp)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);

	/* we know the other end is mp enabled */
	if (mp->mp_state < MPS_M_ESTABLISHED) {
		mp->mp_state = MPS_M_ESTABLISHED;

		printf("%s: mp %p is established\n", __func__, mp);

		/* mp_connected checked by mp_usrreqs when shutting down connection */
		mp->mp_connected = 1;

		/* XXXNJW: why not use mp_sendseqinit? */
		mp->ds_map_max = mp->ds_snd_una = mp->ds_snd_max = mp->ds_map_min =
			mp->ds_snd_nxt = mp->ds_idsn + 1;
		mp->ds_rcv_nxt = mp->ds_idsr + 1;

		/* XXXNJW: temp way of inserting tokens into mp-hashlist */
		mp_instoklist(mp);

		SDT_PROBE(mptcp, session, mp_init_established, estab_info,
			mp->ds_idsn, mp->ds_idsr, mp, mp->local_token, mp->remote_token);
	}

}

void
mp_syncache_process_local_key(struct syncache *sc)
{
	uint8_t digest[20];
	sc->sc_local_key = mp_generate_local_key();
	mp_do_sha_hash(digest, (uint8_t*) &sc->sc_local_key,
		 sizeof(sc->sc_local_key));
	sc->sc_ds_iss = mp_new_idsn(digest);
	sc->sc_ds_iss = htobe64(sc->sc_ds_iss);
	sc->sc_mp_local_token = mp_get_token(digest);
	printf("%s: local token: %u\n", __func__,
	    sc->sc_mp_local_token);
}

void
mp_syncache_process_remote_key(struct syncache *sc, uint64_t remote_key)
{
	uint8_t digest[20];
	sc->sc_remote_key = remote_key;
	mp_do_sha_hash(digest, (uint8_t*) &sc->sc_remote_key,
		 sizeof(sc->sc_remote_key));
	sc->sc_ds_irs = mp_new_idsn(digest);
	sc->sc_ds_irs = htobe64(sc->sc_ds_irs);
	sc->sc_mp_remote_token = mp_get_token(digest);
}

void
mp_process_local_key(struct mp_connection *mp_conn, uint64_t local_key)
{
	uint8_t digest[20];
	char buf[256];

	mp_do_sha_hash(digest, (uint8_t*) &local_key, sizeof(local_key));

	mp_conn->ds_idss = mp_new_idsn(digest);
	mp_conn->local_key = local_key;

	/* As linux does this, we need to do it for interop */
	mp_conn->ds_idss = htobe64(mp_conn->ds_idss);
	mp_conn->local_token = mp_get_token(digest);

	btohex(buf, sizeof(buf), digest, sizeof(digest), BTOHEX_MSBLTOR);
	mp_debug(MPSESSION, 4, 0, "SHA1(local_key) = 0x%s\n", buf);

	SDT_PROBE2(mptcp, session, mp_process_local_key, new_key,
		mp_conn->local_token, mp_conn->local_key);
}

void
mp_process_remote_key(struct mp_connection *mp_conn, uint64_t remote_key)
{
	uint8_t digest[20];
	char buf[256];

	mp_do_sha_hash(digest, (uint8_t*) &remote_key, sizeof(remote_key));

	mp_conn->ds_idrs = mp_new_idsn(digest);
	mp_conn->remote_key = remote_key;

	mp_conn->ds_idrs = htobe64(mp_conn->ds_idrs);
	mp_conn->remote_token = mp_get_token(digest);

	mp_debug(MPSESSION, 4, 0, "%s: idrs: %ju : %u\n", __func__,
		(uintmax_t)mp_conn->ds_idrs, (uint32_t)mp_conn->ds_idrs);

	/* debug output from hash */
	btohex(buf, sizeof(buf), digest, sizeof(digest), BTOHEX_MSBLTOR);
//	mp_debug(MPSESSION, 4, 0, "SHA1(remote_key) = 0x%s\n", buf);
//	mp_debug(MPSESSION, 4, 0, "remote idsn = %u\n", (uint32_t)mp_conn->ds_idrs);

	SDT_PROBE2(mptcp, session, mp_process_remote_key, new_key,
		mp_conn->remote_token, mp_conn->remote_key);
}


/*
 * Based on syncache_respond. Used to send a SYN/ACK on receipt of MP_JOIN,
 * as the syncache is not used for JOIN connections. Perhaps a syncache-like
 * cache of mp_joins would be appropriate?
 */
int
mp_join_respond(struct socket *so, struct tcpcb *tp, struct in_conninfo *inc)
{
	struct ip *ip = NULL;
	struct mbuf *m;
	struct tcphdr *th;
	struct tcpopt to;
	int optlen, error = 0;	/* Make compiler happy */
	int win, wscale = 0;

	u_int16_t hlen, tlen, mssopt;
	hlen =	sizeof(struct ip);
	tlen = hlen + sizeof(struct tcphdr);

	KASSERT((tp->t_sf_flags & SFF_GOT_JOIN_SYN),
	    ("%s: didn't get a join SYN\n", __func__));

	win = sbspace(&so->so_rcv);
	win = imax(win, 0);
	win = imin(win, TCP_MAXWIN);

	tp->rcv_wnd = win;

	if (V_tcp_do_rfc1323) {
		if (tp->t_flags & TF_RCVD_SCALE) {
			/*
			 * Pick the smallest possible scaling factor that
			 * will still allow us to scale up to sb_max, aka
			 * kern.ipc.maxsockbuf.
			 *
			 * We do this because there are broken firewalls that
			 * will corrupt the window scale option, leading to
			 * the other endpoint believing that our advertised
			 * window is unscaled.  At scale factors larger than
			 * 5 the unscaled window will drop below 1500 bytes,
			 * leading to serious problems when traversing these
			 * broken firewalls.
			 *
			 * With the default maxsockbuf of 256K, a scale factor
			 * of 3 will be chosen by this algorithm.  Those who
			 * choose a larger maxsockbuf should watch out
			 * for the compatiblity problems mentioned above.
			 *
			 * RFC1323: The Window field in a SYN (i.e., a <SYN>
			 * or <SYN,ACK>) segment itself is never scaled.
			 */
			while (wscale < TCP_MAX_WINSHIFT &&
				(TCP_MAXWIN << wscale) < sb_max)
				wscale++;
		}
	}

	/* Determine MSS we advertize to other end of connection. */
	mssopt = tcp_mssopt(inc);
	if (to.to_mss)
		mssopt = max( min(to.to_mss, mssopt), V_tcp_minmss);

	/* Create the IP+TCP header from scratch. */
	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return (ENOBUFS);
	m->m_data += max_linkhdr;
	m->m_len = tlen;
	m->m_pkthdr.len = tlen;
	m->m_pkthdr.rcvif = NULL;

	ip = mtod(m, struct ip *);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_len = htons(tlen);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_sum = 0;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src = inc->inc_laddr;
	ip->ip_dst = inc->inc_faddr;
	ip->ip_ttl = tp->t_inpcb->inp_ip_ttl;
	ip->ip_tos = tp->t_inpcb->inp_ip_tos;

	/*
	 * See if we should do MTU discovery.  Route lookups are
	 * expensive, so we will only unset the DF bit if:
	 *
	 *	1) path_mtu_discovery is disabled
	 *	2) the SCF_UNREACH flag has been set
	 */
	if (V_path_mtu_discovery && tp->t_rxtshift < 3 + 1)
        ip->ip_off |= htons(IP_DF);

	th = (struct tcphdr *)(ip + 1);
	th->th_sport = inc->inc_lport;
	th->th_dport = inc->inc_fport;

	th->th_seq = htonl(tp->iss);
	th->th_ack = htonl(tp->irs + 1);
	th->th_off = sizeof(struct tcphdr) >> 2;
	th->th_x2 = 0;
	th->th_flags = TH_SYN|TH_ACK;
	th->th_win = htons(win);
	th->th_urp = 0;

	// should also check that we got an ECN flag in the SYN
	if (V_tcp_do_ecn) {
		th->th_flags |= TH_ECE;
		TCPSTAT_INC(tcps_ecn_shs);
	}

	/* Tack on the TCP options. */
	if ((tp->t_flags & TF_NOOPT) == 0) {
		to.to_flags = 0;

		to.to_mss = mssopt;
		to.to_flags = TOF_MSS;
		if (tp->t_flags & TF_RCVD_SCALE) {
			to.to_wscale = wscale;
			to.to_flags |= TOF_SCALE;
		}
		if (tp->t_flags & TF_RCVD_TSTMP) {
			to.to_tsval = tcp_ts_getticks();
			to.to_tsecr = tp->ts_recent;
			to.to_flags |= TOF_TS;
		}
		if (tp->t_flags & TF_SACK_PERMIT)
			to.to_flags |= TOF_SACKPERM;

		/* The MP_JOIN option */
		to.to_mopts.mpo_flags = 0;
		to.to_flags |= TOF_MPTCP;
		to.to_mopts.mpo_flags |= MPOF_JOIN_SYN;
		to.to_mopts.to_mpoptlen = MPTCP_SUBLEN_MP_JOIN_SYNACK;
		to.to_mopts.snd_rnd = tp->t_mp_conn.local_rand;

		/* copy keys to calculate HMAC */
		to.to_mopts.remote_key = tp->t_mp_conn.remote_key;
		to.to_mopts.local_key = tp->t_mp_conn.local_key;

        /* XXXNJW: actually not calculating or validating the hmacs for the
         * moment*/

		optlen = tcp_addoptions(&to, (u_char *)(th + 1));

		/* Adjust headers by option size. */
		th->th_off = (sizeof(struct tcphdr) + optlen) >> 2;
		m->m_len += optlen;
		m->m_pkthdr.len += optlen;

		ip->ip_len = htons(ntohs(ip->ip_len) + optlen);

	} else
		return 1;  // if NOOPT set, can't actually proceed as we need
	             // options in order to send the mp_join...

	M_SETFIB(m, inc->inc_fibnum);
	m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);

	m->m_pkthdr.csum_flags = CSUM_TCP;
	th->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		htons(tlen + optlen - hlen + IPPROTO_TCP));

	error = ip_output(m, tp->t_inpcb->inp_options, NULL, 0, NULL, tp->t_inpcb);
	INP_WUNLOCK(tp->t_inpcb);

	return (error);

}

/* XXXNJW: temp
 * The token info struct ties a mpcb to session tokens, so that the
 * mpcb can be located via a session token. In the case where we
 * don't have memory to allocate this struct, just continue on. The
 * result will be that MP_JOINs from addresses that have not been
 * explicitly added will not associate with the session. */
static void
mp_instoklist(struct mpcb *mp)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);

	struct mpcb_tokinfo *tokeninfo;
	tokeninfo = malloc(sizeof(struct mpcb_tokinfo), M_MPTOKINFO, M_NOWAIT);
	if (tokeninfo != NULL) {
		tokeninfo->mpti_pcb = mp;
		tokeninfo->mpti_local_token = mp->local_token;
		tokeninfo->mpti_remote_token = mp->remote_token;

		MPTOK_INFO_WLOCK(&mp_tokinfo_list);
		SLIST_INSERT_HEAD(&mp_tokinfo_list.mpti_listhead, tokeninfo,
			mpti_entry);
		MPTOK_INFO_WUNLOCK(&mp_tokinfo_list);
	}
}

void
mp_remtoklist(uint32_t local_token)
{
	struct mpcb_tokinfo *tokeninfo;

	MPTOK_INFO_WLOCK(&mp_tokinfo_list);
	SLIST_FOREACH(tokeninfo, &mp_tokinfo_list.mpti_listhead, mpti_entry) {
		if (tokeninfo->mpti_local_token == local_token) {
			printf("%s: free token\n", __func__);
			SLIST_REMOVE(&mp_tokinfo_list.mpti_listhead,
			    tokeninfo, mpcb_tokinfo, mpti_entry);
			free(tokeninfo, M_MPTOKINFO);
		}
	}
	MPTOK_INFO_WUNLOCK(&mp_tokinfo_list);
}

/* Find and return locked mpcb for a given token */
struct mpcb*
mp_locate_mpcb(uint32_t token)
{
    struct mpcb *mp = NULL;
    struct mpcb_tokinfo *tokeninfo;

    MPTOK_INFO_WLOCK(&mp_tokinfo_list);
	SLIST_FOREACH(tokeninfo, &mp_tokinfo_list.mpti_listhead, mpti_entry) {
		if (tokeninfo->mpti_local_token == token) {
			mp = tokeninfo->mpti_pcb;
			KASSERT(mp != NULL, ("%s: mp NULL\n", __func__));
			break;
		}
	}
	MPTOK_INFO_WUNLOCK(&mp_tokinfo_list);

	if (mp)
		MPP_LOCK(mp->mp_mppcb);

	return(mp);
}

/*
 * Some basic random number/hashing functions that should
 * be okay for initial release
 *
 * XXXNJW: Need a more secure method?
 */
u_int64_t
mp_generate_local_key(void)
{
       u_int64_t key = arc4random();
       key = key << 32;
       key += arc4random();
       return key;
}

/*
 * Digest is for a 20 byte SHA1, key is the session key created
 * when the mpcb was created
 */
uint32_t
mp_do_sha_hash(uint8_t *digest, uint8_t *key, uint64_t key_length) {

       SHA1_CTX context;

       if ((key == NULL) || (key_length == 0)) {
              return (0);
       }

       SHA1Init(&context);
       SHA1Update(&context, key, key_length);
       SHA1Final(digest, &context);

       return key_length;
}

// XXXNJW: turn these into Macros
/*
 * Take a digest and return a token. Linux_compat
 * changes the offset into the digest.
 */
uint32_t
mp_get_token(uint8_t *digest) {
//	if(!linux_compat)
//		return (*((uint32_t *) (digest + 16)));
//	else
		return (*((uint32_t *) (digest)));
}

/*
 * Take a digest and return the idsn. Linux_compat
 * changes the offset into the digest.
 */

uint64_t
mp_new_idsn(uint8_t *digest) {
//	if(!linux_compat)
//		return (*((uint64_t *) (digest)));
//	else
		return (*((uint64_t *) (digest+12)));
}

/*
 * HMAC for used when completing mp_join handshake.
 * We use the hmac functions implemented in sctp_auth.c
 */
uint32_t
mp_get_hmac(uint8_t *digest, uint64_t local_key, uint64_t remote_key,
		uint32_t local_rand, uint32_t remote_rand) {
	/*
	* Set up the hmac key
	*/
	uint8_t key[16];
	uint32_t keylen = sizeof(local_key) + sizeof(remote_key);

	bcopy(&local_key, key, sizeof(local_key));
	bcopy(&remote_key, key + 8, sizeof(remote_key));

	/*
	* Set up the hmac msg
	*/
	uint64_t hmac_msg;
	hmac_msg = (uint64_t)local_rand << 32;
	hmac_msg |= remote_rand;

	/*
	 * Do the hashing. 0x0001 is the type for sha1
	 */
	uint32_t hmac_len = sctp_hmac(0x0001, key, keylen,
	    (uint8_t *) &hmac_msg, sizeof(hmac_msg), digest);

	return(hmac_len);
}

/*
 * Debugging function for printing a sequence of bytes
 */
void
btohex(char *buf, uint32_t buf_len, uint8_t *bytes, int32_t bytes_len, int32_t flags)
{
	struct sbuf out;
	int32_t i;

	i = bytes_len - 1;
	sbuf_new(&out, buf, buf_len, 0);

	while (i >= 0) {
		if (flags & BTOHEX_MSBRTOL)
			sbuf_printf(&out, "%0x", *(bytes + bytes_len - i - 1));
		else
			sbuf_printf(&out, "%0x", *(bytes + i));
		i--;
	}

	sbuf_finish(&out);
}