/*-
 * Copyright (c) 2013-2015
 * Swinburne University of Technology, Melbourne, Australia.
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Nigel Williams and
 * Lawrence Stewart, made possible in part by a gift from the FreeBSD
 * Foundation and The Cisco University Research Program Fund, a corporate
 * advised fund of Silicon Valley Community Foundation.
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
#include <netinet/mptcp_pcb.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_timer.h>
#include <netinet/mptcp_dtrace_declare.h>

/* for SCTP auth functions */
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_auth.h>
#include <netinet/sctp_constants.h>

#include <machine/in_cksum.h>
#include <machine/stdarg.h>


/* Declare sysctl tree and populate it. */
SYSCTL_NODE(_net_inet_tcp, OID_AUTO, mptcp, CTLFLAG_RW, NULL,
    "Mulitpath TCP related settings");

VNET_DEFINE(int, max_subflows) = 8;
#define	V_mptcp_max_subflows	VNET(mptcp_max_subflows);
SYSCTL_INT(_net_inet_tcp_mptcp, OID_AUTO, max_subflows,
	CTLFLAG_RW, &VNET_NAME(max_subflows), 0,
    "Maximum number of subflows per Multipath TCP Connection");

VNET_DEFINE(int, single_packet_maps) = 1;
#define	V_mptcp_single_packet_maps	VNET(mptcp_single_packet_maps);
SYSCTL_INT(_net_inet_tcp_mptcp, OID_AUTO, single_packet_maps,
    CTLFLAG_RW, &VNET_NAME(single_packet_maps), 0,
    "DSN Maps cover a single packet only");

VNET_DECLARE(int, nomptimewait);
#define	V_nomptimewait  VNET(nomptimewait)
VNET_DEFINE(int, nomptimewait) = 1;
SYSCTL_INT(_net_inet_tcp_mptcp, OID_AUTO, nomptimewait,
	CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(nomptimewait), 0,
    "Do not use the timeout timer when entering MPTCP TIME WAIT");

VNET_DECLARE(int, mptimerlength);
#define	V_mptimerlength  VNET(mptimerlength)
VNET_DEFINE(int, mptimerlength) = 0;
SYSCTL_INT(_net_inet_tcp_mptcp, OID_AUTO, mptimerlength,
	CTLFLAG_VNET | CTLFLAG_RW, &VNET_NAME(mptimerlength), 0,
    "MPTCP timeout interval length");


VNET_DEFINE_STATIC(uma_zone_t, mpcb_zone);
#define	V_mpcb_zone			VNET(mpcb_zone)

//static VNET_DEFINE(uma_zone_t, mpsopt_zone);
//#define V_mpsopt_zone VNET(mpsopt_zone)

#define mp_timeout() V_mptimerlength ? V_mptimerlength*hz : MPTCPTV_TIMEOUT

#define M_MPTCPDSN(m) \
    (((struct dsn_tag *)(m_tag_locate(m, PACKET_COOKIE_MPTCP, \
    PACKET_TAG_DSN, NULL)))->dsn)

#define M_MPTCPDSNFLAGS(m) \
    (((struct dsn_tag *)(m_tag_locate(m, PACKET_COOKIE_MPTCP, \
    PACKET_TAG_DSN, NULL)))->dss_flags)

MALLOC_DEFINE(M_REASSLISTHEAD, "reasshead", "Head of reass queue list");

struct debug_class {
	char class[32];
	int verbosity;
	int loglevelexclusive;
};

struct mpcb_mem {
	struct	mpcb		mpcb;
};

uint32_t mp_active_debug_classes;

struct debug_class debug_classes[] = {
		{.class = "MPSESSION"},
		{.class = "DSMAP"},
		{.class = "SBSTATUS"},
		{.class = "REASS"}
};

#define	N_DEBUGCLASSES (sizeof(debug_classes)/sizeof(struct debug_class))

MALLOC_DEFINE(M_SFHANDLE, "sfhandle",
     "Handle containing subflow information: inp, tcp, gso");
MALLOC_DEFINE(M_MPTOKINFO, "mptokeninfo",
     "MP sessions and their (local, remote) tokens");
MALLOC_DEFINE(M_MPTIMERS, "mptimers",
     "Timer callouts for MP sessions");
MALLOC_DEFINE(M_MPSOPT, "mpsopt",
     "Record of socket options on MP connection");

static int mp_subflow_detached(struct mpcb *mp, int count);
static int mp_close_subflow(struct mpcb *mp);
static int mp_detached_last_subflow(struct mpcb *mp);
static void mp_process_subflow_event(struct mpcb *mp, struct tcpcb *tp);
static void mp_set_default_address(struct mpcb *mp, struct inpcb *inp);
static void mp_set_connection_info(struct mpcb *mp, struct tcpcb *tp);
static void mp_sf_connected(struct mpcb *mp, struct tcpcb *tp);
static int  mp_join_learned(struct mpcb *mp, struct socket *so);
static int  mp_join_from_advertised(struct mpcb *mp, struct socket *so);
static int mp_join_do_connect(struct socket *so, void* laddr, void* faddr,
	u_int16_t lport, u_int16_t fport);
static void	mp_update_recwin(struct mpcb *mp);
static int  mp_do_output(struct socket *so, struct mpcb *mp,
	struct sf_handle *sf, int flags);
static void mp_input(struct mpcb *mp, struct socket *so);
static void mp_standard_input_ack(struct mpcb *mp, struct socket *so);
static int mp_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct mpcb *mp, int tlen);
static void mp_dooptions(struct tcpopt *to, u_char *cp, int cnt);
static void mp_twstart(struct mpcb *mp);

static struct sf_handle * mp_get_subflow(struct mpcb *mp);
static struct ds_map* mp_get_map(struct mpcb *mp, int length);
static uint64_t mp_dsn32to64(uint64_t ds_val, uint64_t dseq);
static uint64_t mp_ack32to64(uint64_t dack_val, uint64_t dseq);

static void mp_reass_flush(struct mpcb *mp);


/* XXXNJW: TEMP PATH MANAGEMENT */
/* keeping track of addresses added via sysctl:
 * net.inet.tcp.mptcp.mp_addresses. Though we start at '1' as the 'master'
 * address is included by default.
 */
int mp_address_count = 1;
struct sockaddr_storage mp_usable_addresses[MAX_ADDRS];

/* Initialise extern variables that store addresses */
struct sockaddr_storage mp_path_manager[MAX_ADDRS];
/* --- */

struct mp_sessions mp_tokinfo_list;

#define MSBIT_CHECK 0x80000000


void
mp_debug(uint32_t log_class, int msg_verbosity, uint32_t flags, char * fmt, ...) {
	va_list ap;
	int effective_verbosity, i, loglevelexclusive;

	effective_verbosity = 0;

	if (log_class & mp_active_debug_classes) {
	// calculate shift index (index of class into array)
		i = 0;
		loglevelexclusive = 0;
		while(log_class >= 1) {
			if (log_class & 0x1) {
				effective_verbosity = max(debug_classes[i].verbosity, effective_verbosity);
				loglevelexclusive += debug_classes[i].loglevelexclusive;
			}
			log_class >>= 1;
			i++;
		}

		if	((loglevelexclusive && msg_verbosity == effective_verbosity) ||
				(!loglevelexclusive && msg_verbosity <= effective_verbosity)) {
			va_start(ap, fmt);
			vprintf(fmt, ap);
			va_end(ap);
		}
	}
}

/*
 * Sysctl handler to show and change addito subflow addresses
 */
static int
mp_addresses(SYSCTL_HANDLER_ARGS)
{
	char *straddr;
	struct sbuf *s;
	void *addr;
	char inet_buf[64];
	int error, i, ret;

	error = 0;

	if (req->newptr == NULL) {
		s = sbuf_new_for_sysctl(NULL, NULL, 300, req);
		if (s == NULL)
			return (ENOMEM);

		/* Start at i = 1 as the 'master' address is always included
		 * by default */
		for (i = 1; i < mp_address_count; i++) {
			switch (mp_usable_addresses[i].ss_family) {
				case AF_INET:
					addr = &((struct sockaddr_in *)
					    &mp_usable_addresses[i])->sin_addr;
					break;
				case AF_INET6:
					addr = &((struct sockaddr_in6 *)
					    &mp_usable_addresses[i])->sin6_addr;
					break;
				default:
					return (EINVAL);
			}

			inet_ntop(mp_usable_addresses[i].ss_family, addr, inet_buf,
			    mp_usable_addresses[i].ss_len);
			sbuf_cat(s, inet_buf);
			if (i < (mp_address_count - 1))
				sbuf_cat(s, " ");
		}

		error = sbuf_finish(s);
		sbuf_delete(s);
	} else {
		i = 1;
		while ((straddr = strsep((const char **)&req->newptr, " "))
			!= NULL && i < MAX_ADDRS && !error) {
			ret = inet_pton(AF_INET6, straddr,
			    &((struct sockaddr_in6 *)&mp_usable_addresses[i])->sin6_addr);
			if (ret == 1) {
				mp_usable_addresses[i].ss_family = AF_INET6;
				mp_usable_addresses[i].ss_len = sizeof(struct sockaddr_in6);
			} else if (ret == 0) {
				ret = inet_pton(AF_INET, straddr,
				&((struct sockaddr_in *)&mp_usable_addresses[i])->sin_addr);
				if (ret == 1) {
					mp_usable_addresses[i].ss_family = AF_INET;
					mp_usable_addresses[i].ss_len = sizeof(struct sockaddr_in);
				}
			}

			/* If there was no valid address, ret will be < 1. */
			if (ret < 1) {
				char *zero = "0";
				mp_address_count = 1;
				if (strcmp(straddr, zero) == 0)
					return(0);
				error = EINVAL;
			}
			i++;
		}

		if (!error) {
			if (i == mp_address_count)
				error = E2BIG; // most likely addresses exceeded MAX_ADDRS
			else
				mp_address_count = i;
		}
	}

	return (error);
}

/*
 * Sysctl handler for setting debug output levels for mp
 */
static int
mp_debug_sysctl_handler(SYSCTL_HANDLER_ARGS)
{
	struct sbuf *s;
	int error, i;

	error = 0;

	if (req->newptr == NULL) {
		s = sbuf_new_for_sysctl(NULL, NULL, 300, req);
		if (s == NULL)
			return (ENOMEM);

		for(i = 0; i < N_DEBUGCLASSES; i++) {
				if (i > 0)
					sbuf_putc(s, ',');
				sbuf_printf(s, "%s:%c%d", debug_classes[i].class,
					debug_classes[i].loglevelexclusive ? '=' : '*',
					debug_classes[i].verbosity);
		}

		error = sbuf_finish(s);
		sbuf_delete(s);
	} else {
		char *class, *pair;

		while ((pair = strsep(((const char **)&req->newptr), ",")) != NULL) {
			class = strsep(&pair, ":");
			for(i = 0; i < N_DEBUGCLASSES; i++) {
				if (strcmp(class, debug_classes[i].class) == 0
					|| strcmp(class, "ALL") == 0) {
					if (pair[0] == '=') {
						debug_classes[i].loglevelexclusive = 1;
						pair++;
					} else {
						if (pair[0] == '*')
							pair++;
						debug_classes[i].loglevelexclusive = 0;
					}
					debug_classes[i].verbosity = strtol(pair, NULL, 10);
					if (debug_classes[i].verbosity == 0)
						mp_active_debug_classes &= ~(1<<i);
					else
						mp_active_debug_classes |= 1<<i;
				}
			}
		}
	}

	return (error);
}

/*
 * Parse MP options and place in tcpopt->to_mopts.
 */
static void
mp_dooptions(struct tcpopt *to, u_char *cp, int cnt)
{
	int opt, optlen;
	uint8_t subtype;

	to->to_mopts.mpo_flags = 0;
	to->to_flags = 0;
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
		case TCPOPT_MPTCP:
			bcopy((char *)cp + 2,
					(char *)&subtype, sizeof(subtype));
			if (optlen > MAX_MP_OPLEN)
				continue;
			mp_dosubtypes(to, subtype, cp, opt, optlen, 0);
			break;
		default:
			continue;
		}
	}
}

void
mp_dosubtypes(struct tcpopt *to, uint8_t subtype, u_char *cp, int opt,
	int optlen, int flags) {
	int byte_offset;
	struct mp_capable mcap;
	struct mp_join mjoin;

	subtype = subtype >> 4;

	switch(subtype)
	{
	case MPTCP_SUBTYPE_MP_CAPABLE:
	{
		/* XXXNJW:
		 * have to check that the 's' bit is set
		 * also should check for the dss csum bit (for now just ignore it...)
		 */
		if (optlen != MPTCP_SUBLEN_MP_CAPABLE_SYN &&
				optlen != MPTCP_SUBLEN_MP_CAPABLE_ACK) {
			break;
		}

		/* indicate we have mptcp options present */
		to->to_flags |= TOF_MPTCP;
		to->to_mopts.mpo_flags |= MPOF_MP_CAPABLE;

		if ((flags & TO_SYN) &&
				(optlen == MPTCP_SUBLEN_MP_CAPABLE_SYN)) {

				bcopy((char *)cp,(char *)&mcap,
						sizeof(struct mp_capable));

				/* using checksums? */
				if (mcap.flags & USE_CSUM) {
					to->to_mopts.mpo_flags |= MPOF_USE_CSUM;
				}

				/* need to save the incoming key */
				bcopy((char *)cp + MP_REMOTE_KEY_OFFSET,
						(char *)&to->to_mopts.remote_key,
						sizeof(to->to_mopts.remote_key));
		}

		if (optlen == MPTCP_SUBLEN_MP_CAPABLE_ACK) {
			/* do some validation here */

			/* XXXNJW: put in a flag that tells a passive opener to go
			 * directly into MPTCP mode (rather than wait around in
			 * INFINITE_MAP mode for a couple of packets. This is read
			 * during syncache_expand, and causes mp_init_established to
			 * be called (while we already hole the MP_LOCK). */
			to->to_mopts.mpo_flags |= MPOF_CAPABLE_ACK;
		}
		break;
	}
	case MPTCP_SUBTYPE_DSS:
	{
			byte_offset = 0;
			uint8_t	dss_flags;

			to->to_flags |= TOF_MPTCP;
			to->to_mopts.mpo_flags |= MPOF_DSS;
			bcopy((char *)cp + MP_DSS_FLAGS_OFFSET,(char *)&dss_flags,
							sizeof(uint8_t));

			/* Data-FIN present */
			if (dss_flags & FIN_PRESENT)
				to->to_mopts.mpo_flags |= MPOF_DATA_FIN;

			/* Data-ACK present */
			if (dss_flags & ACK_PRESENT) {
				// set flag that we have an ACK
				to->to_mopts.mpo_flags |= MPOF_DATA_ACK;

				/* Is 64-bit Data ACK present */
				if (dss_flags & ACK_64_PRESENT) {
					to->to_mopts.mpo_flags |= MPOF_ACK64;
					// grabbing whole 64-bits
					bcopy((char *)cp + MP_DATA_ACK64_OFFSET,
						(char *)&to->to_mopts.data_ack_num,
						sizeof(to->to_mopts.data_ack_num));
					to->to_mopts.data_ack_num =
							be64toh(to->to_mopts.data_ack_num);
					// offset the presence of 64-bit ACK
					byte_offset += 8;
				} else {
					uint32_t short_data_ack;
					bcopy((char *)cp + MP_DATA_ACK_OFFSET,
						(char *)&short_data_ack,
						sizeof(short_data_ack));
					to->to_mopts.data_ack_num = ntohl(short_data_ack);
					byte_offset += 4; // offset the presence of 32-bit ACK
				}
			}

			/* DSN, SSN, length and csum present */
			if (dss_flags & MAP_PRESENT) {
				/* flag the new DSN Mapping for this subflow */
				to->to_mopts.mpo_flags |= MPOF_DSN_MAP;

				/* Is DSN 8 octets */
				if (dss_flags & DSN_64) {
					bcopy((char *)cp + MP_DSN_OFFSET + byte_offset,
						(char *)&to->to_mopts.data_seq_num,
						sizeof(to->to_mopts.data_seq_num));
					to->to_mopts.data_seq_num =
					    be64toh(to->to_mopts.data_seq_num);
					byte_offset += 4;
					to->to_mopts.mpo_flags |= MPOF_DSN64;
				} else {
					uint32_t short_dsn;
					bcopy((char *)cp + MP_DSN_OFFSET + byte_offset,
						(char *)&short_dsn,
						sizeof(short_dsn));
					to->to_mopts.data_seq_num = (uint64_t) ntohl(short_dsn);
				}

				/* subflow sequence number */
				bcopy((char *)cp + MP_SUB_SEQN_OFFSET + byte_offset,
					(char *)&to->to_mopts.sub_seq_num,
					sizeof(to->to_mopts.sub_seq_num));
				to->to_mopts.sub_seq_num = ntohl(to->to_mopts.sub_seq_num);

				/* Data-level length */
				bcopy((char *)cp + MP_DATA_LEN_OFFSET + byte_offset,
					(char *)&to->to_mopts.dss_data_len,
					sizeof(to->to_mopts.dss_data_len));
				to->to_mopts.dss_data_len = ntohs(to->to_mopts.dss_data_len);

				/*
				 * XXXNJW: need to check if using csums
				 * should do this by checking the length of the option
				 * at the start and keeping track along the way....
				 */

				 /* checksum */
//					bcopy((char *)cp + MP_CSUM_OFFSET + byte_offset,
//						(char *)&to->to_mopts.dss_csum,
//						sizeof(to->to_mopts.dss_csum));
//					to->to_mopts.dss_csum = ntohs(to->to_mopts.dss_csum);
			}
			break;
	}
	case MPTCP_SUBTYPE_MP_JOIN:
	{
		if (optlen != MPTCP_SUBLEN_MP_JOIN_SYN &&
			optlen != MPTCP_SUBLEN_MP_JOIN_SYNACK &&
			optlen != MPTCP_SUBLEN_MP_JOIN_ACK) {
			break;
		}

		to->to_flags |= TOF_MPTCP;
		to->to_mopts.optlen = optlen;

		switch (optlen)
		{
		case MPTCP_SUBLEN_MP_JOIN_SYN:
			to->to_flags |= TOF_MPTCP;

			/* copy address id */
			bcopy((char *)cp + 3,
					(char *)&to->to_mopts.addr_id,
					sizeof(to->to_mopts.addr_id));

			/* is this a backup path */
			if (subtype & IS_BACKUP) {
				to->to_mopts.mpo_flags |= MPOF_BACKUP_PATH;
			}

			/* save the local_token */
			bcopy((char *)cp + MP_RCV_TOKEN_OFFSET,
					(char *)&to->to_mopts.rcv_token,
					sizeof(to->to_mopts.rcv_token));
			to->to_mopts.rcv_token = ntohl(to->to_mopts.rcv_token);

			/* save the senders random number */
			bcopy((char *)cp + MP_SND_RND_OFFSET,
					(char *)&to->to_mopts.snd_rnd,
					sizeof(to->to_mopts.snd_rnd));
			to->to_mopts.mpo_flags |= MPOF_JOIN_SYN;
			break;
		case MPTCP_SUBLEN_MP_JOIN_SYNACK:
			to->to_flags |= TOF_MPTCP;

			/* copy option 'header' into struct */
			bcopy((char *)cp,(char *)&mjoin,
				sizeof(struct mp_join));
			/* is this a backup path */
			if (mjoin.sub_flags & IS_BACKUP) {
				to->to_mopts.mpo_flags |= MPOF_BACKUP_PATH;
			}
			/* save remote truncate MAC */
			bcopy((char *)cp + MP_SND_MAC_OFFSET,
			    (char *)&to->to_mopts.snd_trc_mac,
			    sizeof(to->to_mopts.snd_trc_mac));

			/* save the senders random number */
			bcopy((char *)cp + MP_SND_RND_SYNACK_OFFSET,
			    (char *)&to->to_mopts.snd_rnd,
			    sizeof(to->to_mopts.snd_rnd));

			to->to_mopts.mpo_flags |= MPOF_JOIN_SYNACK;
			break;
		case MPTCP_SUBLEN_MP_JOIN_ACK:
			to->to_flags |= TOF_MPTCP;

			/* just take a pointer to the hmac. We can copy the bytes in
			 * syncache_expand_subflow as the memory will still be valid */
			to->to_mopts.snd_mac = (char *)cp + MP_SND_MAC_OFFSET;

			to->to_mopts.mpo_flags |= MPOF_JOIN_ACK;
			to->to_mopts.mpo_flags |= MPOF_NEED_ACK;
			break;
		}
		break;
	}
	case MPTCP_SUBTYPE_ADD_ADDR:
	{
		/* not using the port number field for now */
		if (optlen != MPTCP_SUBLEN_ADD_ADDRV4 &&
		    optlen != MPTCP_SUBLEN_ADD_ADDRV6)
				break;

		void * addr = NULL;
		int addr_len = 0;
		to->to_flags |= TOF_MPTCP;

		switch (optlen)
		{
		case MPTCP_SUBLEN_ADD_ADDRV4:
			to->to_mopts.mpo_flags |= MPOF_ADD_ADDR_V4;
			addr = &((struct sockaddr_in *)
					&to->to_mopts.new_addr)->sin_addr.s_addr;
			addr_len = 4;
			/* Copy address ID */
			break;
		case MPTCP_SUBLEN_ADD_ADDRV6:
			to->to_mopts.mpo_flags |= MPOF_ADD_ADDR_V6;
			/* Copy INET address */
			addr = &((struct sockaddr_in6 *)
					&to->to_mopts.new_addr)->sin6_addr.__u6_addr;
			addr_len = 16;
			break;
		}
		/* Copy INET address */
		bcopy((char *)cp + MP_ADD_ADDR_OFFSET, addr,
		    addr_len);

		char buf[128];
		inet_ntop(AF_INET, &(((struct in_addr *) addr)->s_addr), buf, sizeof(buf));
		mp_debug(MPSESSION, 4, 0, "option add_addr %s\n", buf);

		/* Copy address ID */
		bcopy((char *)cp + MP_ADDID_OFFSET,
		    (char *)&to->to_mopts.addr_id,
		    sizeof(to->to_mopts.addr_id));
		break;
	}
	case MPTCP_SUBTYPE_REMOVE_ADDR:
	{
		to->to_flags |= TOF_MPTCP;
		break;
	}
	case MPTCP_SUBTYPE_MP_PRIO:
	{
		to->to_flags |= TOF_MPTCP;
		break;
	}
	case MPTCP_SUBTYPE_MP_FAIL:
	{
		to->to_flags |= TOF_MPTCP;
		break;
	}
	case MPTCP_SUBTYPE_MP_FASTCLOSE:
	{
		if (optlen != MPTCP_SUBTYPELEN_MP_FASTCLOSE)
			break;

		to->to_flags |= TOF_MPTCP;
		to->to_mopts.mpo_flags |= MPOF_FASTCLOSE;

		bcopy((char *)cp + MP_FAIL_KEY_OFFSET,
			(char *)&to->to_mopts.local_key,
			sizeof(&to->to_mopts.local_key));
		break;
	}
	} /* end of switch */
}

void
mp_syncache_newmpcb(struct mpcb *mp, struct syncache *sc)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);

//    mp->ds_idsn = sc->sc_ds_iss;
//    mp->ds_idsr = sc->sc_ds_irs;

    /* XXXNJW: if we know we are going to have an MP connection, should
     * use the data-level accounting here. */
    mp->ds_rcv_nxt = sc->sc_irs + 1;
    mp->ds_snd_una = mp->ds_map_max = mp->ds_map_min = mp->ds_snd_nxt =
        sc->sc_iss + 1;

//    mp->local_key = sc->sc_local_key;
//    mp->remote_key = sc->sc_remote_key;
//    mp->local_token = sc->sc_mp_local_token;
//    mp->remote_token = sc->sc_mp_remote_token;

	/* Connected is set when a subflow is connected, whether MPTCP or
	 * standard TCP */
	mp->mp_connected = 0;

	/* created through syncache, therefore came from a listening socket */
//	mp->mp_passive = 1;

    printf("%s: ds_idsn: %u ds_idsr: %u ds_rcv_nxt %u ds_map_max: %u ds_snd_una %u max %u\n",
         __func__, (uint32_t) mp->ds_idsn, (uint32_t) mp->ds_idsr,
         (uint32_t) mp->ds_rcv_nxt, (uint32_t) mp->ds_map_max,
         (uint32_t) mp->ds_snd_una, (uint32_t) mp->ds_snd_max);
}

int
mp_newmpcb(struct mppcb *mpp)
{
	struct mpcb_mem *mpm;
	struct mpcb *mp;
	int error = 0;

	mpm = uma_zalloc(V_mpcb_zone, M_NOWAIT | M_ZERO);
	if (mpm == NULL)
		return (ENOBUFS);

	mp = &mpm->mpcb;  // XXXNJW: don't really need to init via mpm

	/* Pointer to the multipath protocol control block */
	mp->mp_mppcb = mpp;

	/* tp is set only when we have a LISTEN tp */
	mp->m_cb_ref.mp = mp;
	mp->m_cb_ref.inp = NULL;

	/* Not an mptcp session to start. Mark as '1' once MP established */
	mp->mp_session = 0;

	/* Connected is set when a subflow is connected, whether MPTCP or
	 * standard TCP */
	mp->mp_connected = 0;

	/* This will be changed to '1' if mp_usr_listen() is called. */
	mp->mp_passive = 0;

	/* Init list of subflow tpcbs */
	TAILQ_INIT(&mp->sf_list);

	/* List of socket options */
	TAILQ_INIT(&mp->mp_sopt_list);

	/* Per-mpcb task queue */
//	mp->mp_tq = taskqueue_create("mp_taskq", M_NOWAIT,
//		taskqueue_thread_enqueue, &mp->mp_tq);
//	taskqueue_start_threads(&mp->mp_tq, 1, PI_NET, "mp %p taskq", &mp);

	/* Init task queue handlers
	 * XXXNJW: Some of these tasks are temporary and should be removed at some
	 * point (e.g. datascheduler_task_handler used to kick tcp_output of
	 * subflows while a proper packet scheduler is missing */

	/*  */
	TASK_INIT(&mp->subflow_event_task, 0, mp_subflow_event_task_handler,
	    mp->mp_mppcb);

	/* Perform rexmits when d-level RTO fires */
//	TASK_INIT(&mp->rexmit_task, 0, mp_rexmit_task_handler, mp->mp_mppcb);

    /* XXXNJW: temp, should get rid of this task at some point. */
	TASK_INIT(&mp->subflow_close_task, 0, mp_close_subflow_task_handler,
	    mp->mp_mppcb);

	/* A subflow has removed itself from it's socket */
	TASK_INIT(&mp->subflow_detached_task, 0, mp_subflow_detached_task_handler,
	    mp->mp_mppcb);

	/* Drop acked data, send new data */
	TASK_INIT(&mp->mp_output_task, 0, mp_output_task_handler, mp->mp_mppcb);

	/* Append to rcv buffer, process mp-level signals */
	TASK_INIT(&mp->mp_input_task, 0, mp_input_task_handler, mp->mp_mppcb);

	/* Asynchronous sending of MP_JOINs */
	TASK_INIT(&mp->join_task, 0, mp_join_task_handler, mp->mp_mppcb);

	/* Set the default scheduler for the connection */
//	SCHED_ALGO(mp) = &sched_roundrobin;

	/* mp-level timers */
	mp->mp_timers = malloc(sizeof(struct mptcp_timer), M_MPTIMERS, M_NOWAIT);

	callout_init(&mp->mp_timers->mpt_rexmt, CALLOUT_MPSAFE);
	callout_init(&mp->mp_timers->mpt_timeout, CALLOUT_MPSAFE);

	/* Zero the added address count - this increments when we receive
	 * add_addr from the remote host */
	mp->mp_added_address_count = 0;

	/* Number of addresses available to this mp at creation time. Value may
	 * differ from the global address count due to e.g. an interface not being
	 * available at this time. */
	mp->mp_conn_address_count = mp_address_count;

	/*
	 * Set the masks. We clear bits as ADD_ADDRs and JOINS are sent
	 * for each of the subflows.
	 */
	uint32_t bitmask = 0xffffffff;
	mp->mp_advaddr_mask = ~(bitmask << mp->mp_conn_address_count);

	/* Don't want to advertise the 'primary' address so mask out now */
	mp->mp_advaddr_mask &= ~1;
	mp->mp_advjoin_mask = mp->mp_advaddr_mask;

	/* Update the advertise address mask and count of addresses available to
	 * the session */
	mp_update_available_addresses(mp);

	/* reference from the MPPCB */
	mpp->mpp_mpcb = mp;

	return (error);
}

struct mpcb *
mp_drop(struct mpcb *mp, int error)
{
	struct socket *so = mp->mp_mppcb->mpp_socket;

	printf("%s: mp %p\n", __func__, mp);

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	if (mp->mp_state >= MPS_M_ESTABLISHED)
		mp->mp_state = MPS_M_CLOSED;

	so->so_error = error;
	return (mp_close(mp));
}

/*
 * A hacky work around to create a new inpcb, tcpcb pair and ascociate them
 * with the primary socket.
 *
 * XXXNJW: Need to revisit how the listen side of things works, so this code
 * will change.
 */
int
mp_bind_attach(struct socket *so, struct mpcb *mp,
    struct sockaddr *nam, struct thread *td) {
	struct inpcb *inp;
    struct tcpcb *tp;
    int error;

    MPP_LOCK_ASSERT(mp->mp_mppcb);
    INP_INFO_WLOCK_ASSERT(&V_tcbinfo);

	/* inpcb and tcpcb required for listen */
	error = in_pcballoc(so, &V_tcbinfo);
	if (error) {
		return (error);
	}
	inp = sotoinpcb(so);
	inp->inp_vflag |= INP_IPV4;
	tp = tcp_newtcpcb(inp);
	if (tp == NULL) {
		in_pcbdetach(inp);
		in_pcbfree(inp);
		return (ENOBUFS);
	}
	tp->t_state = TCPS_CLOSED;
	tp->t_mpcb = mp;
	tp->t_sf_flags |= SFF_LISTENTCPCB;
	mp->m_cb_ref.inp = inp;
	INP_WUNLOCK(inp);

	error = tcp_usr_bind(so, nam, td);

	/* Set the socket pcb back to the mppcb */
	so->so_pcb = (caddr_t) mp->mp_mppcb;
	so->so_snd.sb_flags &= ~SB_AUTOSIZE;
	so->so_rcv.sb_flags &= ~SB_AUTOSIZE;;

	return (error);
}

int
mp_create_subflow_socket(struct socket *so, struct socket **sf_gso)
{
	int error = 0;

	/* Allocate subflow gsock */
	if ((error = mp_alloc_subflow_socket(so, sf_gso)))
		goto out;
	KASSERT(*sf_gso != NULL, ("mp_usr_connect: sf_gso NULL"));

	/* XXXNJW: temp protosw struct that allows ghost sockets to use
	 * tcp_usrreqs */
	(*sf_gso)->so_proto = &sf_protosw;

out:
   return error;
}

/* XXXNJW: add some validation here, perhaps */
int
mp_connect_subflow(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	return tcp_usr_connect(so, nam, td);
}

/* Only called for standard TCP connections to
 * process ACKs. */
static void
mp_standard_input_ack(struct mpcb *mp, struct socket *so)
{
//	struct tcpcb *tp;
	struct inpcb *inp;
	struct sf_handle *sf = TAILQ_FIRST(&mp->sf_list);
//	int need_output = 0;
//    uint32_t acknum;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	if (sf->sf_flags & SFHS_MPENDED)
		return;

    inp = sotoinpcb(sf->sf_so);
	KASSERT(inp != NULL, ("%s: inp == NULL mp %p ", __func__, mp));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
		INP_WUNLOCK(inp);
		return;
	}
	INP_WUNLOCK(inp);

	mp_do_output(so, mp, sf, 0);

    return;
}

/* mp_input does the "present" portion of mp_reass (i.e.
 * sbappendstream). This includes calling wakeup on the
 * recv buffer.
 *
 * Also process any data-level signalling, such as DFIN
 * or DFIN-ACK (can we actually do this here?) *for now
 * keep processing DFIN-ACK as a subflow event.
 */
static void
mp_input(struct mpcb *mp, struct socket *so)
{
    int off, tlen = 0;
    struct tcphdr *th = NULL;
    struct ip *ip = NULL;
    struct m_tag *mtag;
    struct dsn_tag *dtag;
    struct mbuf *m;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* process each segment independently */
    while ((m = mp->mp_input_segq) != NULL) {
    	th = NULL;
		mtag = NULL;
    	mp->mp_input_segq = m->m_nextpkt;

    	/* XXXNJW: A mbuf with a m_tag has length but no header.
    	 * A mbuf with a tcp header will not have any length (beyond
    	 * that of the header) */
    	mtag = m_tag_locate(m, PACKET_COOKIE_MPTCP, PACKET_TAG_DSN, NULL);
        if (mtag) {
            tlen = m->m_pkthdr.len;
            dtag = (struct dsn_tag *) mtag;

            if (dtag->dss_flags & MPD_DSN32) {
            	dtag->dsn = mp_dsn32to64(dtag->dsn, mp->ds_rcv_nxt);
			}
        } else {
            ip = mtod(m, struct ip *);
		    th = (struct tcphdr *)((caddr_t)ip + sizeof(struct ip));

            /* Only expect that DACK, other mp signal segments
             * will arrive with tcphdrs. In this case tlen will
             * be the length of the headers, and adjusting tlen
             * back by offset will result on a tlen of 0.
             *
             * Hence it's probably not nessesary to bother with
             * setting tlen here, or even testing if the offset
             * exceeds the length of the header (would have been
             * checked in tcp_input anyway). */
		    tlen = ntohs(ip->ip_len) - sizeof(struct ip);
            off = th->th_off << 2;
	        if (off < sizeof (struct tcphdr) || off > tlen) {
	            m_free(m);
                continue;
            }
            tlen -= off;
        }

    	/* mp_do_segment consumes the mbuf, returns MPP_LOCKED if
    	 * return is 1, otherwise MPP is unlocked. mbuf consumed
    	 * prior to return */
    	mp_do_segment(m, th, so, mp, tlen);
    }
}

static int
mp_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct mpcb *mp, int tlen)
{
	int need_output = 0;
	int flags = 0;
    struct tcpopt to;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* parse options if we have a tcp hdr. We only ever process
     * options in these mbufs - there should never be data */
	if (th) {
		mp_dooptions(&to, (u_char *)(th + 1),
			(th->th_off << 2) - sizeof(struct tcphdr));

		/*
		 * Processing ADD_ADDR options. This will add the new remote address
		 * to the path manager, making it available for this mp connection.
		 * Usually a server might advertise additional addresses that a client
		 * can connect to (though a client may advertise a new address and then
		 * connect _from_ that address).
		 */
		if (to.to_mopts.mpo_flags & (MPOF_ADD_ADDR_V4 | MPOF_ADD_ADDR_V6)) {
			/* insert into list of usable addresses at index AddrID */
			/* store the in_addr in the sockaddr_storage */
            printf("%s: got new addr\n", __func__);

			bcopy(&to.to_mopts.new_addr,
				&mp->mp_added_addresses[to.to_mopts.addr_id],
				sizeof(struct sockaddr_storage));

			mp->mp_added_addresses[to.to_mopts.addr_id].ss_family =
				AF_INET;
			mp->mp_added_addresses[to.to_mopts.addr_id].ss_len =
				sizeof(struct sockaddr_in);

			char buf[128];
			inet_ntop(AF_INET, &(((struct sockaddr_in *)
				&mp->mp_added_addresses[to.to_mopts.addr_id])->sin_addr.s_addr),
				buf, sizeof(buf));
			mp_debug(MPSESSION, 4, 0, "added address %s\n", buf);

			inet_ntop(AF_INET, &(((struct sockaddr_in *)
				&to.to_mopts.new_addr)->sin_addr.s_addr),
				buf, sizeof(buf));
			mp_debug(MPSESSION, 4, 0, "got address %s\n", buf);
			printf("%s: got address %s\n", __func__, buf);

			/* XXXNJW: TEMP - Need to implement improved path management */
			/* update address count and mask */
			mp->mp_lrnedjoin_mask |=
				(1 << (mp->mp_added_address_count));
			mp->mp_added_address_count += 1;
		}

    	if (to.to_mopts.mpo_flags & MPOF_DATA_ACK) {
    		to.to_mopts.data_ack_num =
    			mp_ack32to64(to.to_mopts.data_ack_num, mp->ds_snd_una);

    		if (to.to_mopts.data_ack_num > mp->ds_snd_una) {
    		    if (mp_data_ack(mp, to.to_mopts.data_ack_num))
    			    need_output = 1;

				/* Process DFIN-ACK */
				if(mp->mp_flags & MPF_SENTDFIN) {

	//				printf("%s: process dfin-ack dack %u una %u snd_max %u equal %d\n",
	//					__func__, (uint32_t)to.to_mopts.data_ack_num,
	//					(uint32_t) mp->ds_snd_una, (uint32_t) mp->ds_snd_max,
	//					(mp->ds_snd_una == mp->ds_snd_max) ? 1 : 0);
	//				printf("%s: 64-bit ack %ju una %ju snd_max %ju snd_nxt %ju\n",
	//						__func__, to.to_mopts.data_ack_num, mp->ds_snd_una,
	//						mp->ds_snd_max, mp->ds_snd_nxt);

					if (mp->ds_snd_una == mp->ds_snd_max) {
						switch (mp->mp_state) {
						case MPS_M_FIN_WAIT_1:
							if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
								soisdisconnected(so);
							mp->mp_state = MPS_M_FIN_WAIT_2;
							mp_close_all_subflows(mp);
							goto drop;
						case MPS_M_CLOSING:
							mp_twstart(mp);
							mp_close_all_subflows(mp);
							goto drop;
						case MPS_M_LAST_ACK:
							mp->mp_mppcb->mpp_flags |= MPP_DROPPED;
							mp->mp_state = MPS_M_CLOSED;
							mp_close_all_subflows(mp);
							goto drop;
						}
						printf("%s: dfin is acked, state now %d needoutput %d\n",
							__func__, mp->mp_state, need_output);
					}
				}
    		} // else this is an out-of-date DACK.
    	}

    	/* No longer needed */
		m_free(m);

	} else if (th == NULL) {
        /* These are pure data segments with a DSN tag. Any MPTCP
         * header options will be processed in the block above.
         * (this means that we enqueue two mbufs for a segment
         * with data + MPTCP signalling). */

		flags = mp_reass(mp, m);

		/* XXXNJW: always D-ack for now. */
		mp->mp_flags |= MPF_ACKNOW;

		/* Process DFIN on segment */
		if (flags & MP_DFIN) {
			/* A DFIN on a segment with no length, need to bump rcv_nxt
			 * XXXNJW: would still need to bump the rcv_nxt, even if
			 * there was data? */
			if (MPS_HAVERCVDFIN(mp->mp_state) == 0) {
				printf("%s: first dfin, state %d\n", __func__, mp->mp_state);
				// XXXNJW: need to take care of half-syncd connections
				// that get a DFIN? (we won't even attempt to process
				// these in the current code, as MPS would be < ESTAB

				socantrcvmore(so);
				mp->ds_rcv_nxt++;
				need_output = 1;
			}
			switch (mp->mp_state) {
			case MPS_M_ESTABLISHED:
				mp->mp_state = MPS_M_CLOSE_WAIT;
				break;

			case MPS_M_FIN_WAIT_1:
				mp->mp_state = MPS_M_CLOSING;
				break;

			case MPS_M_FIN_WAIT_2:
				mp_twstart(mp);
				break;
			}
			printf("%s: DFIN, set state %d need_output %d\n",
				__func__, mp->mp_state, need_output);
		}
	} else /* No signaling, no data to deliver */
		goto drop;

	/* XXXNJW: modified to call mp_output per-segment (as required)
	 * This is an expensive thing to do, so delaying DACKs here and
	 * coalescing contiguous data-level segments prior to calling
	 * mp_do_segment needs to be implemented. */
	if (need_output)
		mp_output(mp);

	return 0;
drop:
	m_freem(m);
    return 0;
}

/* Standard TCP flows */
int mp_standard_output(struct mpcb *mp)
{
    int error = 0;
    struct socket *so = mp->mp_mppcb->mpp_socket;
    struct sf_handle *sf = TAILQ_FIRST(&mp->sf_list);

    KASSERT(sf != NULL, ("%s sf == NULL\n", __func__));
    MPP_LOCK_ASSERT(mp->mp_mppcb);
    error = mp_do_output(so, mp, sf, 0);

    return error;
}

/* Multipath TCP flows */
int mp_output(struct mpcb *mp)
{
	struct socket *so = mp->mp_mppcb->mpp_socket;
	struct sf_handle *sf = NULL;
    int flags = 0, error = 0;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	/* how might we get into this situation? */
	if (mp->mp_state == MPS_M_CLOSED) {
		printf("%s mp_output mp %p, state MPS_CLOSED so %p\n", __func__,
		    mp, so);
		//mp_disconnect_all_subflows(mp);
		goto out;
	}

	if (mp->mp_state >= MPS_M_ESTABLISHED)
		flags = mp_outflags[mp->mp_state];

	/* If we've sent a DFIN already, and ds_snd_nxt isn't ds_snd_una, then
	 * this isn't a rexmit and we should unset the flag.
	 * XXXNJW:
	 */
	if ((flags & MP_DFIN) &&
	   ((mp->mp_flags & MPF_SENTDFIN) && !(mp->ds_snd_nxt == mp->ds_snd_una)))
        flags &= ~MP_DFIN;

	/* XXXNJW: Prevent adding another byte for the DFIN. Seems to be
	 * a rexmit case for the DFIN. when is this condition met? a rexmit
	 * would not equal ds_snd_max? */
	if ((flags & MP_DFIN) && (mp->mp_flags & MPF_SENTDFIN) &&
	    mp->ds_snd_nxt == mp->ds_snd_max) {
		mp->ds_snd_nxt--;
	}

	if (mp->mp_flags & MPF_ACKNOW) {
		mp->mp_flags &= ~MPF_ACKNOW;
		flags |= MP_DACK;
	}

	if (mp->mp_state > MPS_M_ESTABLISHED)
		printf("%s: mp %p in state %d flags %d\n",
		    __func__, mp, mp->mp_state, flags);

	/* Temporary address management (advertising, scheduling joins..) */
	if (mp->mp_state == MPS_M_ESTABLISHED) {
		/* Are there local addresses that should be advertised to the remote
		 * host? */
		if (mp->mp_advaddr_mask)
			flags |= MP_ADV_ADDR;

	    /* XXXNJW: basic joining logic. Schedule join task if:
		 * - Are an active opener (client) and have no addresses to advertise
		 * - Have not yet issued MP_JOINs to addresses we have advertised OR
		 *   have learned about via ADD_ADDR
		 */
		if (!mp->mp_passive && (mp->mp_advaddr_mask == 0) &&
		    ((mp->mp_advjoin_mask) || (mp->mp_lrnedjoin_mask))) {
			mp_schedule_tasks(mp, MP_SCHEDJOIN);
		}
	}

	/* XXXNJW: Reset the flags if there is a reason */

	/* XXXNJW: There may be some instances where we do not want to send
	 * anything further. In that case we do not do subflow selection and
	 * should return (unlocked?) */

	/* NB: the length is being overridden to be all unmapped chars. should
	 * however ensure that we don't append more than what the subflow can
	 * fit in the send buffer */

	/* XXXNJW: Temp while testing */
	/* Select a subflow. A scheduler hook would go here. The scheduler should
	 * return with a locked inp */
	sf = mp_get_subflow(mp);

	if (mp->mp_state > MPS_M_ESTABLISHED)
		printf("%s: selected tp %p\n",__func__, sotoinpcb(sf->sf_so)->inp_ppcb);

	/* No subflow was available to send data (e.g. all disconnected) */
	if (sf == NULL && mp->mp_state == MPS_M_ESTABLISHED) {
		/* start rexmit timer to try again later */
		if (!mp_timer_active(mp, MPT_REXMT))
			mp_timer_activate(mp, MPT_REXMT, mp->mp_rxtcur);
		goto out;
	} else if (sf == NULL && mp->mp_state >= MPS_M_ESTABLISHED) {
	    /* If we are disconnecting and no longer have any subflows to
	     * send data on, might as well close now. */

		/* Since we can't send anything, start a protocol disconnect on
		 * all the subflows, ignoring the data level shutdown. The mpcb
		 * will be freed once the subflows are disconnected. */
		mp_close_all_subflows(mp);
		goto out;
	}

	KASSERT(sf != NULL, ("%s: Subflow handle NULL\n", __func__));
	error = mp_do_output(so, mp, sf, flags);

out:
    return (error);

}

/* XXXNJW: should deal with errors from the sending subflow (though we
 * don't want to propagate these back to the socket) */
static int
mp_do_output(struct socket *so, struct mpcb *mp, struct sf_handle *sf,
    int flags)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	struct ds_map *map;
    struct mbuf *m_mapped, *mb;
    int error = 0;
    int moff, off, map_length = 0;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	/* Interlock the subflow inp to ensure the inp doesn't
	 * disappear when we drop the MP_LOCK. */
	inp = sotoinpcb(sf->sf_so);
	KASSERT(inp != NULL, ("%s: inp == NULL mp %p so %p sfh %p", __func__, mp,
	    so, sf));

	/* A temporary thing while trying to figure out a race condition */
	if (!mp->mp_connected) {
		INP_WLOCK(inp);
		if ((inp->inp_flags & INP_DROPPED) || (inp->inp_flags & INP_TIMEWAIT)) {
			printf("%s: inp dropped mid-send\n", __func__);
			INP_WUNLOCK(inp);
			goto unlock;
		}
		tp = intotcpcb(inp);
		uint32_t acknum = tp->last_ack_processed = tp->snd_una;
		INP_WUNLOCK(inp);

		if (acknum > mp->ds_snd_una)
		    mp_data_ack(mp, acknum);
	}

	SOCKBUF_LOCK(&so->so_snd);

	/* What we send next depends on whether we are retransmitting
	 * or sending new data. check the state of the mp and set the
	 * "send next" according to this (either snd_max for new, or
	 * snd_una for a rexmit).
	 *
	 * How much should we transmit initially? as there aren't any
	 * mappings at the data level. just a few segments?
	 */

	/* XXXNJW temp fix for disconnected MP flows that still have a
	 * byte in the send buffer (but no sb_mb for some reason...)
	 * need to figure out why one byte would be in there when the
	 * buffer has no sb_mb.
	 *
	 * This is a little different from the -len issue that occurs
	 * in standard TCP once a FIN has been sent (but not acked,
	 * i.e. snd_nxt is '1' greater than snd_una), as in this case
	 * there actually appears to be a single byte in so_snd.
	 *
	 * NB: the "MPS_ESTABLISHED" check is the fix.*/
	if (!mp->mp_connected || mp->mp_state >= MPS_M_ESTABLISHED) {
        off = mp->ds_snd_nxt - mp->ds_snd_una;
        map_length = sbavail(&so->so_snd) - off;

        if (map_length < 0) {
			printf("%s: sb_avail %d map_len %d off %d\n", __func__,
				sbavail(&so->so_snd), map_length, off);
			printf("%s: ds_snd_una %u ds_snd_nxt %u\n",
					__func__, (uint32_t) mp->ds_snd_una,
					(uint32_t) mp->ds_snd_nxt);
			printf("%s: ds_snd_max %u\n", __func__, (uint32_t) mp->ds_snd_max);
		}

        /* XXXNJW: If we have mapped new data from the sb, then we don't
         * want to include a DFIN. This restricts us to only putting a
         * DFIN on an empty DSS. But it also means that DFINs won't be
         * put onto rexmits, for example. */
        if ((flags & MP_DFIN) && map_length) {
			printf("%s: avail %d map_length %d ds_snd_una %u ds_snd_nxt %u\n",
				__func__, sbavail(&so->so_snd),	map_length,
				(uint32_t) mp->ds_snd_una, (uint32_t) mp->ds_snd_nxt);
            flags &= ~MP_DFIN;
        }
	}

	/* Ensure that SENTDFIN set? (just while debugging?) */
	if (map_length < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be < 0. In transmit case
	     * snd_nxt == snd_una so off is '0'
		 */
		map_length = 0;
	}

	KASSERT(map_length >= 0, ("%s: offset < 0\n", __func__));

	/* In retransmit case, let's send half of the outstanding data. */
	if (DSEQ_LT(mp->ds_snd_nxt, mp->ds_snd_max) &&
	    !((mp->mp_flags & MPF_SENTDFIN))) {
		printf("%s: retransmitting from %u, shift %d maplen %d\n", __func__,
		    (uint32_t)mp->ds_snd_una, mp->mp_rxtshift, map_length);
	}

	/* XXNJW: Possible to get calls that don't have any new data
	 * to send, and no signaling is required. */
	if (!map_length && !flags) {
		SOCKBUF_UNLOCK(&so->so_snd);
		goto unlock;
	}

    if (map_length) {
    	if (flags & MP_DFIN)
    	    flags &= ~MP_DFIN;

		map = mp_get_map(mp, map_length);
		if (!map) {
			error = ENOBUFS;
			SOCKBUF_UNLOCK(&so->so_snd);
			goto unlock;
		}

		/*
		 * Start the m_copym function from the closest mbuf
		 * to the offset in the socket buffer chain.
		 */
		mb = sbsndptr(&so->so_snd, off, map_length, &moff);

		/* copy the mapped data from the data-level send buffer to a new mbuf
		 * chain */
		m_mapped = m_copym(mb, moff, map_length, M_NOWAIT);
		if (m_mapped == NULL) {
			/* XXXNJW Need to remember the map that we've allocated, so that
			 * when we try again that map is copied and transmitted first
			 * OR should just free the map now, and a new map can be alloc'd
			 * on the next call through (as ds_snd_nxt will not have been
			 * incremented). */
			error = ENOBUFS;
			SOCKBUF_UNLOCK(&so->so_snd);
			goto unlock;
	    }

		SOCKBUF_UNLOCK(&so->so_snd);

		mp->ds_snd_nxt += map_length;

		/* XXXNJW: advance snd_nxt */
		if (flags & MP_DFIN) {
		    mp->mp_flags |= MPF_SENTDFIN;
		    mp->ds_snd_nxt++;
		}

		/* Increment ds_snd_max if we've mapped new data
		 * and are about to send */
		if (DSEQ_GT(mp->ds_snd_nxt, mp->ds_snd_max))
			mp->ds_snd_max = mp->ds_snd_nxt;

		if (mp->mp_connected && !mp_timer_active(mp, MPT_REXMT))
			mp_timer_activate(mp, MPT_REXMT, mp->mp_rxtcur);

		/* XXXNJW - the state on an inp might have changed since
		 * it was nominated for output. need a suitable way to handle
		 * this case as at this point we've already mapped and
		 * accounted for the data we are going to send. (though the
		 * rexmit timer will eventually fire if we return at this
		 * point */
		INP_WLOCK(inp);
		if ((inp->inp_flags & INP_DROPPED) || (inp->inp_flags & INP_TIMEWAIT)) {
			printf("%s: inp dropped mid-send\n", __func__);
			INP_WUNLOCK(inp);
			goto unlock;
		}

		tp = intotcpcb(inp);
		tp->t_mp_conn.ds_ack_num = mp->ds_rcv_nxt;
		tp->t_mp_conn.ds_snd_nxt = mp->ds_snd_nxt; // XXX: ??

		struct ds_map *previous_map;
		previous_map = TAILQ_LAST(&tp->t_send_maps.dsmap_list, dsmapq_head);
		if (previous_map)
			map->sf_seq_start = previous_map->sf_seq_start
			    + previous_map->ds_map_len;
		else
			map->sf_seq_start = tp->snd_nxt;

		/* XXXNJW: TODO If there is ds-level overlap, should trim the
		 * retransmit map to save sending the same data twice. */

		/* Insert the allocated map at the tail. Maps will always have
		 * increasing sf_seq_start, and will not overlap in subflow sequence
		 * space */
		map->sf_tp = tp;
		TAILQ_INSERT_TAIL(&tp->t_send_maps.dsmap_list, map, sf_ds_map_next);

		/* Append to the mapped data to the subflow */
		sbappendstream(&inp->inp_socket->so_snd, m_mapped, 0);

		/* The map mbuf pointers are not useful now */
		/* XXXNJW: perhaps keeping a reference to the first mbuf might be useful? */
		map->mbuf_start = m_mapped;
		map->mbuf_offset = 0;

		/* start the ds-level timer here */
	} else {
		/* XXXNJW: advance snd_nxt */
		if (flags & MP_DFIN) {
			mp->mp_flags |= MPF_SENTDFIN;
			mp->ds_snd_nxt++;
		}

		if (DSEQ_GT(mp->ds_snd_nxt, mp->ds_snd_max))
			mp->ds_snd_max = mp->ds_snd_nxt;

		SOCKBUF_UNLOCK(&so->so_snd);

		INP_WLOCK(inp);
		if ((inp->inp_flags & INP_DROPPED) || (inp->inp_flags & INP_TIMEWAIT)) {
			printf("%s: inp dropped mid-send\n", __func__);
			/* if we are trying to send DFIN for the first time */
			if ((flags & MP_DFIN) && (mp->mp_flags & MPF_SENTDFIN))
				mp->mp_flags &= ~MPF_SENTDFIN;
			INP_WUNLOCK(inp);
			goto unlock;
		}

		tp = intotcpcb(inp);
		tp->t_mp_conn.ds_ack_num = mp->ds_rcv_nxt;
		tp->t_mp_conn.ds_snd_nxt = mp->ds_snd_nxt; // XXX: ??

//		MPP_UNLOCK(mp->mp_mppcb);

		/* If we are only sending MPTCP signaling, need to force
		 * the subflow to send a packet. */
		if (flags)
		    tp->t_flags |= TF_ACKNOW;

	}

	/* Flags passed to the subflow.
	 * XXXNJW: There are additional SFFs to could set in here */
    if (flags & MP_ADV_ADDR)
    	tp->t_sf_flags |= SFF_SEND_ADD_ADDR;
    if (flags & MP_DACK)
		tp->t_sf_flags |= SFF_NEED_DACK;
	if (flags & MP_DFIN)
		tp->t_sf_flags |= SFF_NEED_DFIN;

	/* call output if there is data to send, or we need to send control info */
	if(map_length || flags)
	    error = tcp_output(tp);

	INP_WUNLOCK(inp);
//	return error;

unlock:
//	MPP_UNLOCK(mp->mp_mppcb);
	return error;

}

/* XXXNJW: temporary round robin scheduler. just using the link field in the
 * subflow handle so select subflows in order of insertion. When we get to
 * the end just select the first subflow.
 *
 * Might need to call into this distinguishing between whether we need to
 * send data, or just MP-level signaling. In the case of signaling it is
 * possible to use subflows that are in any state other than < EST or TW
 * (in the TW case, inp will be set as INP_DROPPED)
 * */
static struct sf_handle *
mp_get_subflow(struct mpcb *mp)
{
	struct sf_handle *sf_index = NULL;
	struct sf_handle *sf_next = NULL;
    struct inpcb *inp;
    struct tcpcb *tp;

	/* The last subflow used for output */
	sf_index = mp->mp_temp_sched.last_sf_selected;

	/* want to start from the "next" subflow after our
	 * previously used subflow. */
	if (sf_index)
		sf_next = TAILQ_NEXT(sf_index, next_sf_handle);

	/* will start from the start of list */
	if (sf_next == NULL)
		sf_index = sf_next = TAILQ_FIRST(&mp->sf_list);

again:
	TAILQ_FOREACH_FROM(sf_next, &mp->sf_list, next_sf_handle) {
		if (sf_next->sf_flags & (SFHS_MPENDED | SFHS_MPESTABLISHED))
			continue;

		/* XXXNJW: some cases can drop through without an inp.
		 * need to investigate why. */

		/* Rather than subflow-level checks, should in the future rely
		 * only on sfh flags. If there is some problem with the PCB
		 * the calling function can try again. */
		inp = sotoinpcb(sf_next->sf_so);
		INP_WLOCK(inp);
		if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
			sf_next->sf_flags |= SFHS_MPENDED;

			/* XXXNJW: this just sneaked in for now to catch
			 * flows that have (for example) been reset. Must
			 * find a better solution for this. */
			if (tp->t_sf_state & SFS_MP_DISCONNECTED)
				mp_schedule_tasks(mp, MP_SCHEDCLOSE);

			INP_WUNLOCK(inp);
			continue;
		}
		tp = intotcpcb(inp);
		if ((tp->t_state < TCPS_ESTABLISHED) || tp->t_rxtshift) {
			INP_WUNLOCK(inp);
			continue;
		}

		INP_WUNLOCK(inp);
		break;
	}

	if ((sf_next == NULL) && (sf_index != TAILQ_FIRST(&mp->sf_list))) {
		sf_index = TAILQ_FIRST(&mp->sf_list);
		goto again;
	}

	mp->mp_temp_sched.last_sf_selected = sf_next;
	return sf_next;
}

/*
 * Free everything. locks, lists etc etc
 */
void
mp_discardcb(struct mpcb *mp)
{
	/* Release any ds_maps that remain */
    struct mppcb *mpp = mp->mp_mppcb;

    MPP_LOCK_ASSERT(mpp);

    SDT_PROBE1(mptcp, session, mp_discardcb, entry, mp);
    printf("%s: %p\n", __func__, mp);


	/* Release any subflow handles. */
	mp_sf_flush(mp);
	/* Release any recorded socket options */
	mp_mpsopt_flush(mp);
	/* Release any segments remaining in the reass queue */
    mp_reass_flush(mp);

	/* Release mpti entry */
//	/mp_remtoklist(mp->local_token);

//	taskqueue_drain(mp->mp_tq, &mp->rexmit_task);
//	taskqueue_drain(mp->mp_tq, &mp->data_task);
//	taskqueue_drain(mp->mp_tq, &mp->sf_mgmt_task);
//	taskqueue_free(mp->mp_tq);

    /* XXXNJW: again, a hack to cancel enqueued tasks
     * now that the mpcb is discarded. */

    u_int pend = 0;
	taskqueue_cancel(taskqueue_swi, &mp->subflow_event_task, &pend);

	taskqueue_cancel(taskqueue_swi, &mp->subflow_detached_task, &pend);
	if (pend) {
	    printf("%s: subflow_detached_task was pending", __func__);
	    pend = 0;
	}

	taskqueue_cancel(taskqueue_swi, &mp->subflow_close_task, &pend);
	if (pend) {
		printf("%s: subflow_close_task was pending", __func__);
		pend = 0;
	}

	taskqueue_cancel(taskqueue_swi, &mp->mp_output_task, &pend);
	taskqueue_cancel(taskqueue_swi, &mp->mp_input_task, &pend);
	taskqueue_cancel(taskqueue_swi, &mp->join_task, &pend);

	callout_stop(&mp->mp_timers->mpt_rexmt);
	callout_stop(&mp->mp_timers->mpt_timeout);
	free(mp->mp_timers, M_MPTIMERS);

	mpp->mpp_mpcb = NULL;
	uma_zfree(V_mpcb_zone, mp);
}

/*
 * Return the common rcv window. The window is updated when soreceive is called
 * and is attached to the subsequent outgoing DACK that signifies that data
 * has been read by the application.
 */
uint32_t
mp_get_recwin(struct mpcb *mp) {
	mp_update_recwin(mp);
	return mp->ds_rcv_wnd;
}

static void
mp_update_recwin(struct mpcb *mp) {
	mp->ds_rcv_wnd = sbspace(&mp->mp_mppcb->mpp_socket->so_rcv);
}

void
mp_update_sndwin(struct mpcb *mp, uint16_t win) {
	MPP_LOCK_ASSERT(mp->mp_mppcb);
	mp->ds_snd_wnd = win;
}

/* Try to locate an existing entry for a socket option that
 * is being set. If we can't find an entry, then this is the
 * first time we have seen this option. */
struct mp_sopt*
mp_locate_mp_sopt(struct mpcb *mp, struct sockopt *sopt)
{
	 struct mp_sopt *m_sopt = NULL;

	 MPP_LOCK_ASSERT(mp->mp_mppcb);

	 TAILQ_FOREACH(m_sopt, &mp->mp_sopt_list, next_mp_sopt) {
		   if (m_sopt->sopt_level == sopt->sopt_level &&
			   m_sopt->sopt_name == sopt->sopt_name)
				  break;
	 }

     return m_sopt;
}

struct mp_sopt*
mp_alloc_mp_sopt(void)
{
    struct mp_sopt *mpsopt;
//    mpsopt = uma_zalloc(mpsopt_zone, M_NOWAIT | M_ZERO);
    mpsopt = malloc(sizeof(struct mptcp_timer), M_MPSOPT, M_NOWAIT);
    return mpsopt;
}

void
mp_schedule_tasks(struct mpcb *mp, int task_flags)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);

	if ((task_flags & MP_SCHEDINPUT)) {
		if (mp->mp_input_pending == 0) {
			mp->mp_input_pending = 1;
			mpp_pcbref(mp->mp_mppcb);
			taskqueue_enqueue(taskqueue_swi, &mp->mp_input_task);
		}
	}

	if ((task_flags & MP_SCHEDEVENT)) {
		if(mp->mp_event_pending == 0) {
			mp->mp_event_pending = 1;
			mpp_pcbref(mp->mp_mppcb);
			taskqueue_enqueue(taskqueue_swi, &mp->subflow_event_task);
		}
	}

	if ((task_flags & MP_SCHEDJOIN)) {
		printf("%s: enqueue subflow join\n", __func__);
		if (mp->mp_join_pending == 0) {
			mp->mp_join_pending = 1;
			mpp_pcbref(mp->mp_mppcb);
			taskqueue_enqueue(taskqueue_swi, &mp->join_task);
		}
	}

//	if ((task_flags & MP_SCHEDCLOSE)) {
//		if (mp->mp_sf_close_pending == 0) {
//			mp->mp_sf_close_pending = 1;
//			mpp_pcbref(mp->mp_mppcb);
//			taskqueue_enqueue(taskqueue_swi, &mp->subflow_close_task);
//		}
//	}

}

/* XXXNJW: Previously were done asynchronously but were running
 * into race conditions with taking mpp_pcbref and the two pending
 * flags. So now just run them in this thread while we have the MPP
 * anyway. */
int
mp_do_task_now(struct mpcb *mp, int task_flags)
{
	int unlocked = 0;

	if ((task_flags & MP_SCHEDCLOSE))
		mp_close_subflow(mp);

	if ((task_flags & MP_SCHEDDETACH))
		 unlocked = mp_subflow_detached(mp, 1);

	return unlocked;
}

/* An event has occurred on a subflow that the mp-layer should handle.
 * If we haven't enqueued the task, do so now otherwise just set the
 * event flags. */
void
mp_enqueue_subflow_event(struct tcpcb *tp, u_int16_t event_flag)
{
	INP_WLOCK_ASSERT(tp->t_inpcb);

//	tp->t_event_flags |= event_flag;
//	if(tp->t_event_pending == 0) {
//		tp->t_event_pending = 1;
//		taskqueue_enqueue(taskqueue_swi, &tp->t_mpcb->subflow_event_task);
//		if (atomic_cmpset_int(&tp->t_mpcb->mp_sf_event_pending, 0, 1))
//			mpp_pcbref(tp->t_mpcb->mp_mppcb);
//	}
}

//void
//mp_enqueue_event(struct mpcb *mp, u_int16_t event_flag)
//{
//	MPP_LOCK_ASSERT(mp->mp_mppcb);
//
//	mp->mp_event_flags |= event_flag;
//	taskqueue_enqueue(taskqueue_swi, &mp->mp_event_task);
//	if (atomic_cmpset_int(&mp->mp_sf_event_pending, 0, 1))
//		mpp_pcbref(mp->mp_mppcb);
//
//}

static void
mp_sf_connected(struct mpcb *mp, struct tcpcb *tp)
{
	struct socket *so;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	so = mp->mp_mppcb->mpp_socket;
	KASSERT(so != NULL, ("%s: so NULL\n", __func__));

	/* Set the primary socket as connected */
	if (so->so_state & SS_ISCONNECTING) {
		printf("%s: set primary socket %p connected\n", __func__, so);

		/* Init the sequence numbers based on the subflow that
		 * just connected, if MP is not established at this point.
		 * The connection will commence using subflow sequence
		 * space. */
		if (!mp->mp_connected) {
            mp_sendseqinit(mp,tp);
		    mp_rcvseqinit(mp, tp);
		}

		soisconnected(so);
	}

}


void
mp_input_task_handler(void *context, int pending)
{
	struct mpcb *mp;
	struct mppcb *mpp;
	struct socket *so;

	mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));

	MPP_LOCK(mpp);

	if (mpp_pcbrele(mpp)) {
		printf("%s: mpp freed, return\n", __func__);
		return;
	}

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));

	mp->mp_input_pending = 0;

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED)) {
		goto out;
	}

	so = mpp->mpp_socket;
	KASSERT(so != NULL, ("%s: so from context was NULL\n", __func__));

//	/* mp_input unlocks MPP */
	if (mp->mp_input_segq)
		mp_input(mp, so);
	else if (!mp->mp_connected)
		mp_standard_input_ack(mp, so);

out:
	MPP_UNLOCK(mpp);
}


/* Drop from the primary send buffer here under MPP_LOCK to ensure stability
 * when assigning new maps/data to subflows. (accounting is adjusted on
 * the subflow input path) */
void
mp_output_task_handler(void *context, int pending)
{

	struct mpcb *mp;
	struct mppcb *mpp;
    struct socket *so;

    mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));

	MPP_LOCK(mpp);

	if (mpp->mpp_refcount < 2)
	    printf("%s: mpp ref count %d\n", __func__, mpp->mpp_refcount);

	if (mpp_pcbrele(mpp)) {
		printf("%s: so %p mpp %p mp %p\n", __func__, mpp->mpp_socket, mpp,
			mpp->mpp_mpcb);
		return;
	}

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));

	mp->mp_output_pending = 0;

	so = mpp->mpp_socket;
	KASSERT(so != NULL, ("%s: so from context was NULL\n", __func__));

	/* XXXNJW: probably should peek at any errors */
	if (mp->mp_connected)
	    mp_output(mp);
	else
		mp_standard_output(mp);

	MPP_UNLOCK(mpp);
}

void
mp_subflow_event_task_handler(void *context, int pending)
{
	struct mppcb *mpp;
	struct mpcb *mp;
	struct sf_handle *sfhandle;
	struct inpcb *inp;
	struct tcpcb *tp;

	mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));

	MPP_LOCK(mpp);

	if (mpp->mpp_refcount < 2)
	    printf("%s: mpp ref count %d\n", __func__, mpp->mpp_refcount);

	if (mpp_pcbrele(mpp)) {
		printf("%s: so %p mpp %p mp %p\n", __func__, mpp->mpp_socket, mpp,
			mpp->mpp_mpcb);
		return;
	}

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));

	mp->mp_sf_event_pending = 0;

	TAILQ_FOREACH(sfhandle, &mp->sf_list, next_sf_handle) {
		if (sfhandle->sf_flags & SFHS_MPENDED)
		    continue;

		inp = sotoinpcb(sfhandle->sf_so);
		KASSERT(inp != NULL, ("%s: inp NULL\n", __func__));
		INP_WLOCK(inp);

		if (inp->inp_flags & INP_TIMEWAIT) {
			INP_WUNLOCK(inp);
			continue;
		}

		tp = intotcpcb(inp);
		if (tp->t_event_pending == 0) {
			INP_WUNLOCK(inp);
			continue;
		}

		tp->t_event_pending = 0;
		mp_process_subflow_event(mp, tp);
		INP_WUNLOCK(inp);
	}

	MPP_UNLOCK(mpp);
}

void
mp_join_task_handler(void *context, int pending)
{
	struct mpcb *mp;
	struct mppcb *mpp;
    struct socket *so;

	mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));

	MPP_LOCK(mpp);

	if (mpp->mpp_refcount < 2)
	    printf("%s: mpp ref count %d\n", __func__, mpp->mpp_refcount);

	if (mpp_pcbrele(mpp)) {
		printf("%s: so %p mpp %p mp %p\n", __func__, mpp->mpp_socket, mpp,
			mpp->mpp_mpcb);
		return;
	}

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));

	mp->mp_join_pending = 0;

	if (mpp->mpp_flags & (MPP_TIMEWAIT | MPP_DROPPED))
		goto unlock_return;

	if (mp->subflow_cnt == MAX_SUBFLOWS || mp->mp_state < MPS_M_ESTABLISHED)
		goto unlock_return;

	so = mp->mp_mppcb->mpp_socket;
	if (!(so->so_state & SS_ISCONNECTED))
		goto unlock_return;

	/* Addresses remain to join from */
	if (mp->mp_advjoin_mask)
		mp_join_from_advertised(mp, so);

	/* Learned addresses remain to join to */
	if (mp->mp_lrnedjoin_mask)
		mp_join_learned(mp, so);

unlock_return:
	MPP_UNLOCK(mp->mp_mppcb);

}

static int
mp_join_from_advertised(struct mpcb *mp, struct socket *so)
{
	struct inpcb *inp;
	void *laddr = NULL, *faddr = NULL;
	u_int16_t lport, fport;
	int error = 0;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	/* Have advertised addresses that we have not yet tried to the
	 * default foreign interface from from. */
	char buf[128];
	if (mp->mp_advjoin_mask) {
		/* try connect to default foreign address */
		lport = mp->mp_mppcb->mpp_lport;
		fport = mp->mp_mppcb->mpp_fport;
		faddr = &((struct sockaddr_in *)
			&mp->mp_foreign_address)->sin_addr.s_addr;

		inet_ntop(AF_INET, faddr, buf, sizeof(buf));
		printf("%s: faddr now %s:%d\n", __func__, buf, fport);

		int i;
		for (i = 1; i < mp->mp_conn_address_count; i++) {
			printf("%s: conn addr count %d\n", __func__, i);

			/* continue if this index has sent join already */
			if (!(mp->mp_advjoin_mask & (1 << i)))
				continue;

			/* Set the local address */
			if (mp_usable_addresses[i].ss_family == AF_INET) {
				laddr = &((struct sockaddr_in *)
					&mp_usable_addresses[i])->sin_addr.s_addr;
			}

			/* Do not send any more joins from this local address */
			mp->mp_advjoin_mask &= ~(1 << i);

			/* Check for existing 5-tuple. Do not want to issue a
			 * join across an existing address pair. */
			inp = in_pcblookup(&V_tcbinfo, *((struct in_addr *)faddr),
				fport, *((struct in_addr *)faddr), lport, INPLOOKUP_WLOCKPCB,
				NULL);

			if (inp) {
				INP_WUNLOCK(inp);
				printf("%s: abort joining existing tuple\n", __func__);
				continue;
			}

			error = mp_join_do_connect(so, laddr, faddr, lport, fport);
			if (error)
			    break;
		}
	}

    return error;
}


/*
 * Find the next address to send a JOIN for, then
 * assign this to addr and use when connecting the new
 * subflow.
 *
 * XXXNJW: mostly for demo purposes
 */
static int
mp_join_learned(struct mpcb *mp, struct socket *so)
{
	struct inpcb *inp;
	int error = 0, found_foreign = 0;
	void *laddr = NULL, *faddr = NULL;
	u_int16_t lport, fport;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* find the first learned address that we haven't tried joining.
	 * If we have learned about any remote addresses, attempt to connect
	 * to these. Otherwise return. */
	char buf[128];

	if (mp->mp_lrnedjoin_mask) {
		int i;
		for (i = 0; i < mp->mp_added_address_count; i++) {
			printf("%s: learned addr count %d\n", __func__, i);
			inet_ntop(AF_INET, &(((struct sockaddr_in *)
				&mp->mp_added_addresses[i])->sin_addr.s_addr),
				buf, sizeof(buf));
			printf("%s: current address %s\n", __func__, buf);
			printf("%s: learned mask %u\n", __func__, mp->mp_lrnedjoin_mask);

			/* continue if this index has sent join already */
			if (!(mp->mp_lrnedjoin_mask & (1 << i)))
				continue;

			if (mp->mp_added_addresses[i].ss_family == AF_INET) {
				faddr = &((struct sockaddr_in *)
					&mp->mp_added_addresses[i])->sin_addr.s_addr;
			}
			found_foreign = 1;

			inet_ntop(AF_INET, faddr, buf, sizeof(buf));
				printf("%s: faddr now %s\n", __func__, buf);

			/* Do not send any more joins to this added address. */
			mp->mp_lrnedjoin_mask &= ~(1 << i);
			break;
		}

	}

	if (found_foreign == 0)
       goto out;

	lport = mp->mp_mppcb->mpp_lport;
	fport = mp->mp_mppcb->mpp_fport;

	/* try connect from default interface first */
	laddr = &((struct sockaddr_in *)
		&mp->mp_default_address)->sin_addr.s_addr;

	inet_ntop(AF_INET, laddr, buf, sizeof(buf));
	printf("%s: laddr now %s\n", __func__, buf);

	error = mp_join_do_connect(so, laddr, faddr, lport, fport);
	if (error)
		return error;

	/* Want to issue a connect from each of the local addresses
	 * that are available */
	int i;
	for (i = 1; i < mp->mp_conn_address_count; i++) {
		printf("%s: conn addr count %d\n", __func__, i);

		/* Set the local address */
		if (mp_usable_addresses[i].ss_family == AF_INET) {
			laddr = &((struct sockaddr_in *)
				&mp_usable_addresses[i])->sin_addr.s_addr;
		}

		if (mp_is_addr_default((struct sockaddr_in *)laddr, mp))
			continue;

		inet_ntop(AF_INET, laddr, buf, sizeof(buf));
		printf("%s: laddr now %s\n", __func__, buf);

		/* Check for existing 5-tuple. Do not want to issue a
		 * join across an existing address pair. */
		inp = in_pcblookup(&V_tcbinfo, *((struct in_addr *)faddr),
			fport, *((struct in_addr *)faddr), lport, INPLOOKUP_WLOCKPCB, NULL);

		if (inp) {
			INP_WUNLOCK(inp);
			printf("%s: abort joining existing tuple\n", __func__);
			continue;
		}

		// now have the src and dst addresses, create a new socket and send
		// the join.
		if (mp_join_do_connect(so, laddr, faddr, lport, fport))
			break;
	}

out:
    return error;
}

static int
mp_join_do_connect(struct socket *so, void* laddr, void* faddr,
	u_int16_t lport, u_int16_t fport)
{
	int error = 0;
	struct socket *sf_so;
	struct mppcb *mpp;
    struct inpcb *inp;
    struct tcpcb *tp;
	struct sockaddr nam;

    mpp = sotomppcb(so);

	/* creates a subflow ghost socket, inheriting state from the primary
	 * socket (similar to sonewconn). */
    error = mp_create_subflow_socket(so, &sf_so);
    if (error)
    	goto out;

    /* Populate nam with foreign address details */
	bcopy(faddr, &(((struct sockaddr_in *) &nam)->sin_addr.s_addr),
		sizeof(struct in_addr));
	((struct sockaddr_in *) &nam)->sin_port = fport;
	nam.sa_len = sizeof(struct sockaddr_in);
	nam.sa_family = AF_INET;

	/* attach tcpcb and inpcb to the subflow socket */
	error = tcp_attach(sf_so);
	if (error)
		goto out;

	printf("%s: attached new subflow\n", __func__);

	/* XXXNJW: Some setup of the inpcb. this is very hacky and must be
	 * redone (for demo only) */
	inp = sotoinpcb(sf_so);
	INP_WLOCK(inp);

	tp = intotcpcb(inp);
	tp->t_mp_conn.remote_token = mpp->mpp_mpcb->remote_token;
	tp->t_mp_conn.local_token = mpp->mpp_mpcb->local_token;

	inp->inp_lport = lport;
	bcopy(laddr, &inp->inp_laddr, sizeof(struct in_addr));

	INP_HASH_WLOCK(&V_tcbinfo);
	error = in_pcbinshash(inp);
	INP_HASH_WUNLOCK(&V_tcbinfo);

	INP_WUNLOCK(inp);
	if (error)
		kdb_break();

	/* Insert the new sufblow pcbs and gso into sf_list */
	error = mp_insert_subflow(mpp->mpp_mpcb, sf_so);
	if (error)
		goto out;

	/* Initiate a connection from the new subflow socket. */
	error = (*(sf_so)->so_proto->pr_usrreqs->pru_connect)(sf_so, &nam,
		curthread);
	if (error)
		kdb_break();

out:
    return error;
}

/* Called from mp_output (rather than the drop_task_handler) */
void
mp_drop_task(struct mpcb *mp, int acked)
{
	struct socket *so;
	struct mbuf *mfree;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	so = mp->mp_mppcb->mpp_socket;
	KASSERT(so != NULL, ("%s: so from context was NULL\n", __func__));

	SOCKBUF_LOCK(&so->so_snd);
	if (acked > sbavail(&so->so_snd)) {
		//mp->snd_wnd -= sbavail(&so->so_snd);
		/* Our dfin has been acked in this case. */
		mfree = sbcut_locked(&so->so_snd,
		    (int)sbavail(&so->so_snd));
	} else {
		mfree = sbcut_locked(&so->so_snd, acked);
		//mp->snd_wnd -= acked;
	}

	/* NB: sowwakeup_locked() does an implicit unlock. */
	sowwakeup_locked(so);
	m_freem(mfree);
	return;
}

static void
mp_process_subflow_event(struct mpcb *mp, struct tcpcb *tp)
{
	if (tp->t_event_flags & SFE_MPESTABLISHED) {
		tp->t_event_flags &= ~SFE_MPESTABLISHED;

		/* The sequence numbers negotiated for MP connection */
		mp->ds_idsn = tp->t_mp_conn.ds_idss;
		mp->ds_idsr = tp->t_mp_conn.ds_idrs;

		/* XXXNJW: a temp way to store some info for mp_joins */
		mp_set_default_address(mp, tp->t_inpcb);
		mp_set_connection_info(mp, tp);

		/* Can now set the MP connection as established. */
		mp_init_established(mp);
	}

	if (tp->t_event_flags & SFE_CONNECTED) {
		tp->t_event_flags &= ~SFE_CONNECTED;
		mp_sf_connected(mp, tp);
		printf("%s: subflow %p on mp %p\n", __func__, tp, mp);
		SDT_PROBE2(mptcp, session, mp_process_subflow_event, connected,
			mp, tp);
	}
}

/* During connection setup these values are held by mp_connection
 * struct in the initial connecting subflow. Now store the tokens
 * at the mp-level for use in JOINs, mpti struct */
static void
mp_set_connection_info(struct mpcb *mp, struct tcpcb *tp)
{
    mp->remote_key = tp->t_mp_conn.remote_key;
    mp->remote_token = tp->t_mp_conn.remote_token;
    mp->local_key = tp->t_mp_conn.local_key;
    mp->local_token = tp->t_mp_conn.local_token;
}

static void
mp_set_default_address(struct mpcb *mp, struct inpcb *inp)
{
	void * addr = NULL;
	int addr_len = 0;

	/* Default local and foreign ports for the connection */
	mp->mp_mppcb->mpp_lport = inp->inp_lport;
	mp->mp_mppcb->mpp_fport = inp->inp_fport;

	/* Hard-coded for IPv4 for now */
	addr_len = 4;
	addr = &((struct sockaddr_in *) &mp->mp_default_address)->sin_addr.s_addr;
	bcopy(&inp->inp_laddr.s_addr, addr, addr_len);
	mp->mp_default_address.ss_family = AF_INET;
	mp->mp_default_address.ss_len = sizeof(struct sockaddr_in);

	/* Default foreign address */
	addr = &((struct sockaddr_in *) &mp->mp_foreign_address)->sin_addr.s_addr;
	bcopy(&inp->inp_faddr.s_addr, addr, addr_len);
	mp->mp_foreign_address.ss_family = AF_INET;
	mp->mp_foreign_address.ss_len = sizeof(struct sockaddr_in);

}

/* XXXNJW: A temp way to clean out subflows.
 * Sort of a garbage collection for subflows that
 * have been tcp_closed but were never freed (due
 * to pru_close not being called by waiting
 * thread). */
void
mp_close_subflow_task_handler(void *context, int pending)
{
	struct mpcb *mp;
	struct mppcb *mpp;

	mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));

	MPP_LOCK(mpp);
	if (mpp_pcbrele(mpp)) {
		printf("%s: so %p mpp %p mp %p\n", __func__, mpp->mpp_socket, mpp,
			mpp->mpp_mpcb);
		return;
	}

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));

	mp->mp_sf_close_pending = 0;
	mp_close_subflow(mp);

	MPP_UNLOCK(mp->mp_mppcb);
}

/* XXNJW: called under MPP locks. This is currently used
 * only in cases where a subflow is not able to free itself
 * (i.e. doesn't go through a disconnect, taking SS_PROTOREF).
 * It is a temporary solution - need to go through and think
 * about the closing states of subflows in more depth.
 *
 * The inp is already dropped, socket should be disconnected.
 * SS_PROTOREF and INP_SOCKREF should not be set in this case,
 * as we want sorele to ultimately call detach and free. */
static int
mp_close_subflow(struct mpcb *mp)
{
	struct sf_handle *sfhandle;
	struct inpcb *inp;
    struct socket *so;

    TAILQ_FOREACH(sfhandle, &mp->sf_list, next_sf_handle) {
		if (sfhandle->sf_flags & SFHS_MPENDED)
			continue;

		so = sfhandle->sf_so;
		KASSERT(so != NULL, ("%s: so == NULL", __func__));

		inp = sotoinpcb(so);

		/* As we've got mutltiple subflows closing, and aren't
		 * freeing the handles (and not always setting ended
		 * on the handle...) a cheap hack to stop panics */
		if (inp == NULL) {
			sfhandle->sf_flags |= SFHS_MPENDED;
			continue;
		}

//		KASSERT(inp != NULL, ("%s: inp NULL\n", __func__));

		INP_WLOCK(inp);

//		printf("%s: inp flags %d\n", __func__, inp->inp_flags);
//		printf("%s: sfh flags %d\n", __func__, sfhandle->sf_flags);

		/* Timewait subflows will dealloc themselves when
		 * the timer expires */
		if (inp->inp_flags & INP_TIMEWAIT) {
			INP_WUNLOCK(inp);
			continue;
		}

		/* Only interested in subflows that can be freed now. */
		if (!(inp->inp_flags & INP_DROPPED)) {
			INP_WUNLOCK(inp);
			continue;
		}

		/* XXXNJW: temp - to make sure we don't try to dereference the
		 * inp from this point onwards.
		 *
		 * The inp won't be available after this. */
		sfhandle->sf_flags |= SFHS_MPENDED;
		sfhandle->sf_so = NULL;

		/* also remove this sfhandle from the list and free? */

		/* soisdisconnected should have been called if we
		 * are calling a close from here? */
	//	KASSERT(so->so_state == SS_ISDISCONNECTED,
	//		("%s: socket !disconnected\n", __func__));
		printf("%s: so_state %d\n", __func__, so->so_state);
		INP_WUNLOCK(inp);

		/* need to remove, close subflow.
		 * XXXNJW:*/
		(*so->so_proto->pr_usrreqs->pru_close)(so);
		if (!(so->so_state & SS_PROTOREF)) {
			printf("%s: free and release subflow socket\n", __func__);
			sfhandle->sf_so = NULL;

			/* sofree on the subflow socket */
			mp_subflow_release_socket(so);

			/* Decrement subflow count. this will result in a
			 * call to mp_close (as we only have a single sublow
			 * in non mp_connected sessions. */
			KASSERT(mp != NULL, ("%s: mp NULL\n", __func__));
			if (mp_detach_subflow_locked(mp))
				return 1;
		}
	}

    return 0;
}





//static void
//mp_close_subflow(struct inpcb *inp)
//{
//	struct socket *so;
//
//
//	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
//
//	so = inp->inp_socket;
//	KASSERT(so != NULL, ("%s: so == NULL", __func__));
//
//	/* soisdisconnected should have been called if we
//	 * are calling a close from here? */
////	KASSERT(so->so_state == SS_ISDISCONNECTED,
////		("%s: socket !disconnected\n", __func__));
//    printf("%s: so_state %d\n", __func__, so->so_state);
//
//	INP_WUNLOCK(inp);
//
//	/* need to remove, close subflow. */
//	(*so->so_proto->pr_usrreqs->pru_close)(so);
//	mp_subflow_release_socket(so);
//}


//static void
//mp_process_event(struct mpcb *mp)
//{
//	mp->mp_sf_event_pending = 0;
//
//}

//void
//mp_trigger_rexmit(struct mpcb *mp) {
//	mpp_pcbref(mp->mp_mppcb);
//	taskqueue_enqueue(taskqueue_swi, &mp->rexmit_task);
////	if (atomic_cmpset_int(&mp->mp_rexmit_pending, 0, 1))
////		mpp_pcbref(mp->mp_mppcb);
//}


///*
// * Find the first subflow that isn't in subflow-level rexmit and do data-level
// * rexmit on this flow (just call tcp_output, the ds_map code worries about
// * XXXNJW: or perhaps whichever subflow has cwnd > 1MSS?
// */
//void
//mp_rexmit_task_handler(void *context, int pending)
//{
//	struct mpcb *mp;
//	struct mppcb *mpp;
//	struct sf_handle *sfhandle;
//    struct inpcb *inp;
//    struct tcpcb *tp;
//
//	mpp = (struct mppcb *)context;
//	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));
//
//	mp = mpp->mpp_mpcb;
//	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));
//
//	MPP_LOCK(mpp);
//	if (mpp_pcbrele(mpp))
//		kdb_break();
//
//	mp->mp_rexmit_pending = 0;
//
//	TAILQ_FOREACH(sfhandle, &mp->sf_list, next_sf_handle) {
//		inp = sotoinpcb(sfhandle->sf_so);
//		KASSERT(inp != NULL, ("%s: inp NULL\n", __func__));
//		INP_WLOCK(inp);
//
//		tp = intotcpcb(inp);
//		if (!(inp->inp_flags & INP_DROPPED) && tp->t_rxtshift == 0
//		    && tp->t_state == TCPS_ESTABLISHED) {
//			break;
//		}
//		INP_WUNLOCK(inp);
//	}
//	MPP_UNLOCK(mpp);
//
//	if (sfhandle != NULL) {
//		tcp_output(tp);
//		INP_WUNLOCK(inp);
//	}
//
//	if (tp == NULL)
//		mp_debug(MPSESSION, 1, 0, "%s: all subflows in rexmit\n", __func__);
//}


/*
 * Move ds_snd_una forward and schedule drop of bytes acked. if ack'ing
 * past snd_max, then this is an ACK of a DFIN, so we can begin to close
 * all the subflows, and the connection.
 *
 * If the send window is partially ACKd, then we reset the data-level RTO
 * timer. If the window is fully ACKd, the timer is stopped.
 *
 */
int
mp_data_ack(struct mpcb *mp, uint64_t data_ack_num) {
    struct socket *so = mp->mp_mppcb->mpp_socket;
    struct mbuf *mfree;
    int acked = 0, needoutput = 0;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    mp_debug(MPSESSION, 4, 0, "processing DACK %ju (%u), ds-una is %ju\n",
			data_ack_num, (uint32_t)data_ack_num, mp->ds_snd_una);

//    printf("%s: dack %ju una %ju max %ju\n", __func__, data_ack_num,
//        mp->ds_snd_una, mp->ds_snd_max);

    acked = data_ack_num - mp->ds_snd_una;
    if(acked) {
    	/* XXXNJW: Update mp_rxtcur to base value. Not taking into
    	 * account SRTT of the subflows etc. Also need a less silly
    	 * method of setting these values (i.e. put them in a macro
    	 * or something. */
    	mp->mp_rxtshift = 0;
    	mp->mp_rxtcur = MPTCPTV_RTOBASE;

    	/* Check for DFIN being acked in mp_drop_task */
    	//mp_drop_task(mp, acked);

    	if (data_ack_num == mp->ds_snd_max)
    		needoutput = 1;

//    	printf("%s: acked %d\n", __func__, acked);

    	SOCKBUF_LOCK(&so->so_snd);
		if (acked > sbavail(&so->so_snd)) {
			/* Our dfin has been acked in this case. */
			printf("%s: finisacked %ju snd_nxt %ju snd_una %ju\n", __func__,
			    data_ack_num, mp->ds_snd_nxt, mp->ds_snd_una);
			printf("%s: finisacked %u snd_nxt %u snd_una %u\n", __func__,
				(uint32_t)data_ack_num, (uint32_t)mp->ds_snd_nxt,
				(uint32_t)mp->ds_snd_una);
			printf("%s: acked %d\n", __func__, acked);

			//mp->snd_wnd -= sbavail(&so->so_snd);
			mfree = sbcut_locked(&so->so_snd,
				(int)sbavail(&so->so_snd));
		} else {
			mfree = sbcut_locked(&so->so_snd, acked);
			//mp->snd_wnd -= acked;
		}

		/* NB: sowwakeup_locked() does an implicit unlock. */
		sowwakeup_locked(so);
		m_freem(mfree);

    	mp->ds_snd_una = data_ack_num;
    	if (DSEQ_LT(mp->ds_snd_nxt, mp->ds_snd_una))
    		mp->ds_snd_nxt = mp->ds_snd_una;

    }

    /* MP-level rexmit timer */
    if (mp->mp_connected) {
		if (data_ack_num == mp->ds_snd_max) {
			if (mp_timer_active(mp, MPT_REXMT))
				mp_timer_activate(mp, MPT_REXMT, 0);
		} else if (DSEQ_LT(data_ack_num, mp->ds_snd_max)) {
				mp_timer_activate(mp, MPT_REXMT, mp->mp_rxtcur);
		} else {/* if (!in persist)? */ }
    }

    return (needoutput);
}



//static void
//mp_rcvd_dfin_ack(struct mpcb *mp)
//{
//	printf("%s: entered with state %d\n", __func__, mp->mp_state);
//
//	struct socket *so = mp->mp_mppcb->mpp_socket;
//    int do_output = 0;
//
//	MPP_LOCK_ASSERT(mp->mp_mppcb);
//
//    switch (mp->mp_state) {
//	case MPS_M_FIN_WAIT_1:
//		if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
//			soisdisconnected(so);
//		mp->mp_state = MPS_M_FIN_WAIT_2;
//		break;
//
//	case MPS_M_CLOSING:
//		mp->mp_state = MPS_M_TIME_WAIT;
//		do_output = 1;
//		break;
//
//	case MPS_M_LAST_ACK:
//		mp->mp_state = MPS_M_CLOSED;
//		do_output = 1;
//	}
//
//    /* Moving to time_wait or closed should trigger close
//     * on all subflows */
//    if (do_output) {
//    	mpp_pcbref(mp->mp_mppcb);
//        taskqueue_enqueue(taskqueue_swi, &mp->mp_output_task);
//    }
//
//    printf("%s: exit with state %d\n", __func__, mp->mp_state);
//}

//static void
//mp_rcvd_dfin(struct mpcb *mp)
//{
//	printf("%s: entered with state %d\n", __func__, mp->mp_state);
//
//	MPP_LOCK_ASSERT(mp->mp_mppcb);
//
//    struct socket *so = mp->mp_mppcb->mpp_socket;
//    int need_output = 0;
//    socantrcvmore(so);
//
//	switch (mp->mp_state) {
//	case MPS_M_ESTABLISHED:
//		mp->mp_state = MPS_M_CLOSE_WAIT;
//		break;
//
//	case MPS_M_FIN_WAIT_1:
//		mp->mp_state = MPS_M_CLOSING;
////		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
////			soisdisconnected(so);
////			mp_disconnect_all_subflows(mp); // let mp_output/usrreq do this?
////            /* Some kind of FW2 timer so we don't wait
////             * around in FW2 for a dfin ack? */
////		} else /* Should send a data-ack of the DFIN we've got */
//			need_output = 1;
//		break;
//
//	case MPS_M_FIN_WAIT_2:
//		mp->mp_state = MPS_M_TIME_WAIT;
//		/* Moving to time_wait should trigger close on all subflow.
//		 * For now this is done by calling into mp_output, where
//		 * we check the mp_state and call a disconnect. */
//		need_output = 1;
//		break;
//	}
//
//	/* Schedule calling of mp_output if we need to respond to
//	 * this */
////	if (need_output && mp->output_task_pending == 0) {
////		atomic_add_int(&mp->output_task_pending, 1);
//	if (need_output) {
//		mpp_pcbref(mp->mp_mppcb);
//		taskqueue_enqueue(taskqueue_swi, &mp->mp_output_task);
//	}
////	}
//
//    printf("%s: exit with state %d\n", __func__, mp->mp_state);
//}



/*
 * Accesses socket buffer on behalf on a subflow and returns a mapping
 * into the send buffer than the subflow will transmit from.
 *
 * XXXNJW: currently restricted to returning a map of size 1420 (this allows
 * space for header and options to be added while staying under the typical
 * ethernet MSS)
 */
static struct ds_map*
mp_get_map(struct mpcb *mp, int length) {
	struct ds_map *map = NULL;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* XXXNJW removed the code searching for maps that need rexmit. need
     * to put back in later, or maybe rethink how retransmission work (maybe
     * just make a new map altogether? though this will mess up the reference
     * counting and freeing the socket buffer) */
	if(length) {
		map = malloc(sizeof(struct ds_map), M_DSSMAP, M_NOWAIT|M_ZERO);
		if (map) {
			map->ds_map_start = mp->ds_snd_nxt;
			map->ds_map_len = map->ds_map_remain = length;
		}
	}

	return(map);
}


struct ds_map *
mp_find_dsmap(struct tcpcb *tp, tcp_seq	seqnum)
{
	struct ds_map *map = NULL;
	tcp_seq sf_seq_end;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	/* If there aren't any maps, return */
	if(TAILQ_EMPTY(&tp->t_send_maps.dsmap_list))
		return NULL;

	/* Performing wrap detection on map lookups based on sequence number.
	 * If (sf_seq_end = sf_start + length) wraps, sf_seq_end will be less
	 * than sf_seq_start. We detect this with: seqnum <= sf_seq_end (seqnum
	 * is in map) && sf_seq_end < map->sf_seq_start
	 */
	TAILQ_FOREACH(map, &tp->t_send_maps.dsmap_list, sf_ds_map_next) {
		sf_seq_end =  map->sf_seq_start + map->ds_map_len;// - 1;

		/* reached end of this map list, return a NULL map, as mp_output
		 * should be allocating new maps for this subflow */
		if (seqnum == sf_seq_end)
			continue;

		/* match the first map which covers the passed-in sequence num.
		 * includes checks for wrapped maps. */
		if ((seqnum >= map->sf_seq_start && sf_seq_end > map->sf_seq_start
			&& seqnum < sf_seq_end) ||
			(sf_seq_end < map->sf_seq_start && seqnum < map->sf_seq_start
			&& seqnum < sf_seq_end) ||
			(sf_seq_end < map->sf_seq_start && seqnum >= map->sf_seq_start
			&& seqnum <= UINT_MAX)) {
				mp_debug(DSMAP, 4, 0, "%s  sequence num: %u"
					"starts at %u, ends %u\n", __func__,
					seqnum, map->sf_seq_start, sf_seq_end);
				break;
		}
	}

	return (map);
}


/*
 * Attempt to close a MP control block, marking it as dropped, and freeing
 * the socket if we hold the only reference.
 */
struct mpcb *
mp_close(struct mpcb *mp)
{
	printf("%s: entered\n", __func__);

	struct mppcb *mpp = mp->mp_mppcb;
	struct socket *so;

	MPP_LOCK_ASSERT(mpp);

	mpp_pcbdrop(mpp);
	so = mpp->mpp_socket;
	KASSERT(so != NULL, ("%s: mpp_socket NULL\n", __func__));

	soisdisconnected(so);

	/* Would expect MPP_SOCKREF to be set in all cases except for
	 * a usr_close on an un-synchronised connection. */
	if (mpp->mpp_flags & MPP_SOCKREF) {
		KASSERT(so->so_state & SS_PROTOREF,
		    ("mp_close: !SS_PROTOREF"));
		mpp->mpp_flags &= ~MPP_SOCKREF;
		MPP_UNLOCK(mpp);
		SOCK_LOCK(so);
		so->so_state &= ~SS_PROTOREF;
		printf("%s: call sofree\n", __func__);
		sofree(so);
		return (NULL);
	}
	return (mp);
}

/* XXXNJW: Temp, to improve */
void
mp_close_all_subflows(struct mpcb *mp)
{
	struct sf_handle *sf_h = NULL;
	struct socket *so;
	int error = 0;
	MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* XXXNJW: temp hack
     * The sf handles are freed when the mpcb is released. The count is
     * decremented when the subflow is detached from the subflow socket.
     * This is a bit of a messy copy of soclose, without the processing
     * for sockets with state SO_ACCEPTCONN */
	TAILQ_FOREACH(sf_h, &mp->sf_list, next_sf_handle) {
		if((sf_h->sf_flags & (SFHS_MPENDED | SFHS_DISCONNECTING)) == 0) {
			so = sf_h->sf_so;
			KASSERT(so != NULL, ("%s: subflow so NULL\n", __func__));
			printf("%s: disconnecting subflow tp %p\n", __func__,
			    sototcpcb(sf_h->sf_so));
		    error = sodisconnect(sf_h->sf_so);
            if (error == 0) {
            	(*so->so_proto->pr_usrreqs->pru_close)(sf_h->sf_so);
            	SOCK_LOCK(sf_h->sf_so);
            	sorele(sf_h->sf_so);
            }
		    sf_h->sf_flags |= SFHS_DISCONNECTING;
		}
	}
}

void
mp_reset_all_subflows(struct mpcb *mp)
{
	printf("%s\n", __func__);

	struct sf_handle *sf_h = NULL;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct socket *so;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	INP_INFO_WLOCK(&V_tcbinfo);

	/* XXXNJW: temp hack
	 * The sf handles are freed when the mpcb is released. The count is
	 * decremented when the subflow is detached from the subflow socket.
	 * This is a bit of a messy copy of soclose, without the processing
	 * for sockets with state SO_ACCEPTCONN */
	TAILQ_FOREACH(sf_h, &mp->sf_list, next_sf_handle) {
		printf("%s: sf_flags %d\n", __func__, sf_h->sf_flags);
		if((sf_h->sf_flags & SFHS_MPENDED) == 0) {
			so = sf_h->sf_so;
			KASSERT(so != NULL, ("%s: subflow so NULL\n", __func__));
			printf("%s: RST subflow at handle %p\n", __func__, sf_h);
			inp = sotoinpcb(sf_h->sf_so);
			INP_WLOCK(inp);

			if (inp->inp_flags & INP_DROPPED) { /* already dropped */
				INP_WUNLOCK(inp);
				continue;
			}

			tp = intotcpcb(inp);
			tp->t_sf_flags = 0; /* No DACKs, etc to be added */
			tp->t_sf_state = SFS_MP_DISCONNECTED;
			tp = tcp_drop(tp, tp->t_softerror ?
		        tp->t_softerror : ETIMEDOUT); /* Sends RST, calls tcp_close */

			/* tp should not be NULL in here, as INP_SOCKREF is not set.
			 * The INP and subflow socket will be freed from the call to
			 * soclose. */
			KASSERT(tp != NULL, ("%s: tp null after tcp_drop\n", __func__));
			if (tp != NULL)
			    INP_WUNLOCK(inp);

			sf_h->sf_flags |= SFHS_MPENDED;
		}
	}
	INP_INFO_WUNLOCK(&V_tcbinfo);

}

void
mp_subflow_freehandle(struct mpcb *mp, struct sf_handle *sf)
{
	printf("%s\n", __func__);

	MPP_LOCK_ASSERT(mp->mp_mppcb);
	/* remove subflows with NULL tps */
	TAILQ_REMOVE(&mp->sf_list, sf, next_sf_handle);
	free(sf, M_SFHANDLE);
}

void
mp_subflow_release_socket(struct socket *so)
{
	SOCK_LOCK(so);
	sorele(so);
}

void
mp_subflow_detached_task_handler(void *context, int pending)
{
	struct mppcb *mpp;
    struct mpcb *mp;

	mpp = (struct mppcb *)context;
	KASSERT(mpp != NULL, ("%s: mpp from context was NULL\n", __func__));
	MPP_LOCK(mpp);

	printf("%s: mpp_locked. pending %d\n", __func__, pending);

	mp = mpp->mpp_mpcb;
	KASSERT(mp != NULL, ("%s: mp from context was NULL\n", __func__));
    mp->mp_sf_detach_pending = 0;

	if (mpp->mpp_refcount < 2)
	    printf("%s: mpp ref count %d\n", __func__, mpp->mpp_refcount);

	if (mpp_pcbrele(mpp)) {
		printf("%s: so %p mpp %p mp %p\n", __func__, mpp->mpp_socket, mpp,
			mpp->mpp_mpcb);
		return;
	}

    mp_subflow_detached(mpp->mpp_mpcb, pending);

}

int
mp_detach_subflow_locked(struct mpcb *mp)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);
	printf("%s: entered\n", __func__);
	return mp_subflow_detached(mp, 1);
}

/* XXXNJW: tcp_discardcb has been called, so remove the subflow from the list
 * as it is not longer useful. A time_wait subflow will remove itself and does
 * not need access to the mpcb.
 *
 * Currently cleans up any NULL tp blocks.
 * Since this is done asynchronously, is it possible the memory pointed to by
 * the tp could be assigned to a new tp in the meantime? */
static int
mp_subflow_detached(struct mpcb *mp, int count)
{
    int unlocked = 0;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    printf("%s: mp %p sf cnt %d\n", __func__, mp, mp->subflow_cnt);
	KASSERT(count <= mp->subflow_cnt,
	    ("%s: detach count exceeds subflow count\n", __func__));

	for (int i = 0; i < count; i++) {
		KASSERT(mp->subflow_cnt > 0, ("%s: subflow count < 0\n", __func__));
		if (--mp->subflow_cnt == 0) {
			/* Returns > 0 if the mp has been freed */
			unlocked = mp_detached_last_subflow(mp);
		}
	}

	return unlocked;
}

static int
mp_detached_last_subflow(struct mpcb *mp)
{
	int unlocked = 0;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	// need to think about half-synchronised connections,
	// regular tcp connections and so forth.

	/* If the mp-level is already disconnected, or never
	 * connected we can just close and free the PCBs now.
	 * Otherwise start a timer in case a subflow re-appears. */
	if (mp->mp_mppcb->mpp_flags & MPP_TIMEWAIT) {
        /* Wait for timewait to end before closing. */
		printf("%s: last subflow, in M_TW mpp %p\n",
		    __func__, mp->mp_mppcb);
		if (!mp_timer_active(mp, MPT_TIMEOUT))
			mp_timer_activate(mp, MPT_TIMEOUT, mp_timeout());
    } else if (mp->mp_state == MPS_M_CLOSED) {
    	printf("%s: last subflow, in M_CLOSED mpp %p\n",
    	    __func__, mp->mp_mppcb);
    	/* Unlike TW case, there should be a socket still
    	 * attached to the mpp at this point, so should
    	 * be okay to call mp_close */
		if (!mp_close(mp))
			unlocked = 1;
	} else if (!mp_timer_active(mp, MPT_TIMEOUT))
	    mp_timer_activate(mp, MPT_TIMEOUT, mp_timeout());

	printf("%s: unlocked %d\n", __func__, unlocked);
	return unlocked;
}

/* Just remove all the subflow handles that might have been allocated.
 * XXXNJW: Should really make sure all the subflows have been dropped and
 * dealloced so that there aren't any left floating around with state. */
void
mp_sf_flush(struct mpcb *mp)
{
	struct sf_handle *sf;
	while ((sf = TAILQ_FIRST(&mp->sf_list)) != NULL) {
		TAILQ_REMOVE(&mp->sf_list, sf, next_sf_handle);
		free(sf, M_SFHANDLE);
	}
}

/* XXXNJW: currently not freeing any recorded options during a
 * connection, and are just removing them all at the end. */
void
mp_mpsopt_flush(struct mpcb *mp)
{
	struct mp_sopt *mpsopt;
	while ((mpsopt = TAILQ_FIRST(&mp->mp_sopt_list)) != NULL) {
		TAILQ_REMOVE(&mp->mp_sopt_list, mpsopt, next_mp_sopt);
		free(mpsopt, M_MPSOPT);
	}
}


/* This is not actually allocating a proper "socket", Just want the struct
 * to be initialised and then copy some state from the actual MP socket. The
 * subflows will use/set flags as needed to track their own state. Eventually
 * don't want to allocate an entire socket.
 */
struct socket *
mp_allocghostsocket(struct socket *so) {
	struct socket *sf_gso = NULL;

	KASSERT(so != NULL, ("mp_allocghostsocket: so == NULL"));

	sf_gso = gsoalloc(so->so_vnet);
	if (sf_gso == NULL)
		return (NULL);

	knlist_init_mtx(&sf_gso->so_rcv.sb_sel.si_note, SOCKBUF_MTX(&sf_gso->so_rcv));
	knlist_init_mtx(&sf_gso->so_snd.sb_sel.si_note, SOCKBUF_MTX(&sf_gso->so_snd));

	/* Inherit state from the connection socket (though don't set so_head) */
	sf_gso->so_head = NULL;
	sf_gso->so_options = so->so_options &~ SO_ACCEPTCONN;
	sf_gso->so_state = so->so_state;
	sf_gso->so_linger = so->so_linger;
	sf_gso->so_state = so->so_state | SS_NOFDREF;
	sf_gso->so_fibnum = so->so_fibnum;
	sf_gso->so_cred = crhold(so->so_cred);
    sf_gso->so_count = 1;

	/* A protosw struct for subflows.
	 * Subflows can use standard tcp proto hooks (e.g. tcp_usr_detach).
	 * Need to do this in a nicer way. */
	sf_gso->so_proto = &sf_protosw;

	return sf_gso;
}

void
mp_sftimewait(struct socket *sf_gso)
{
//	struct inpcb *sf_inp;
//	struct inpcb *inp;
//	struct mpcb *mp;
////	struct socket *so;
//
//	SOCK_LOCK_ASSERT(sf_gso);
//	sf_inp = sotoinpcb(sf_gso);
//	KASSERT(sf_inp != NULL, ("%s: inp NULL\n", __func__));
//
//	mp = intompcb(sf_inp);
//	KASSERT(mp != NULL, ("%s: mp NULL\n", __func__));
//
//	inp = mp->mp_inpcb;
//	INP_WLOCK(inp);
//	inp->inp_flags |= INP_TIMEWAIT;
//	INP_WUNLOCK(inp);
}


int
mp_create_subflow_implicit(struct mpcb *mp, struct socket *so, struct ip *ip,
	struct tcphdr *th)
{
	int error;
	struct socket *sf_so;
    struct inpcb *inp;
    struct tcpcb *tp;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

    /* creates a subflow ghost socket, inheriting state from the primary
	 * socket (similar to sonewconn). */
	error = mp_create_subflow_socket(so, &sf_so);
	if (error)
        goto out;

	KASSERT(sf_so != NULL, ("%s: subflow socket NULL", __func__));
	sf_so->so_state &= (SS_NOFDREF | SS_NBIO | SS_ASYNC);

	/* attach tcpcb and inpcb to the subflow socket */
	error = tcp_attach(sf_so);
	if (error)
		goto out;

    inp = sotoinpcb(sf_so);
    KASSERT(inp != NULL, ("%s: subflow inp NULL", __func__));
    INP_WLOCK(inp);

    inp->inp_lport = th->th_dport;
    inp->inp_fport = th->th_sport;
    inp->inp_faddr.s_addr = ip->ip_src.s_addr;
    inp->inp_laddr.s_addr = ip->ip_dst.s_addr;

    INP_HASH_WLOCK(&V_tcbinfo);
    in_pcbinshash(inp);
    INP_HASH_WUNLOCK(&V_tcbinfo);

    tp = intotcpcb(inp);

	SOCK_LOCK(sf_so);
	error = solisten_proto_check(sf_so);
	if (error == 0) {
		tp->t_state = TCPS_LISTEN;
		solisten_proto(sf_so, 2);
	}
	SOCK_UNLOCK(sf_so);

	if (error) {
		printf("%s: error %d subflow socket state %d\n", __func__, error,
		    sf_so->so_state);
		kdb_break();
	}

    soisconnecting(sf_so);
	tp->t_sf_flags |= SFF_PASSIVE_JOIN;
	tp->iss = tcp_new_isn(tp);
    tp->irs = th->th_seq;
    tp->t_mp_conn.local_key = mp->local_key;
    tp->t_mp_conn.remote_key = mp->remote_key;
    INP_WUNLOCK(inp);

	/* Insert the new sufblow pcbs and gso into sf_list (takes MP_LOCK) */
	error = mp_insert_subflow(mp, sf_so);
out:
   MPP_UNLOCK(mp->mp_mppcb);
   return error;
}


/*
 * Add a subflow to the provided mp connection. Allocate a new sunflow handle
 * (tp, inp, g_so) and insert into the list of subflows.
 */
int
mp_insert_subflow(struct mpcb *mp, struct socket *sf_so)
{
	struct sf_handle *new_sf = NULL;
    struct tcpcb *tp;
    int error = 0;

    MPP_LOCK_ASSERT(mp->mp_mppcb);

	new_sf = malloc(sizeof(struct sf_handle), M_SFHANDLE, M_NOWAIT);
	if (new_sf == NULL) {
		error = ENOMEM;
        goto out;
	}

	new_sf->sf_so = sf_so;
	new_sf->sf_flags = 0;
	tp = intotcpcb(sotoinpcb(sf_so));

	/* Set the mpcb pointer */
	tp->t_mpcb = mp;

	TAILQ_INSERT_TAIL(&mp->sf_list, new_sf, next_sf_handle);
	if (mp->subflow_cnt == 0) {
		tp->t_sf_flags |= SFF_FIRSTSUBFLOW;
		tp->t_sf_flags |= SFF_INFINITEMAP;
		tp->t_sf_flags |= SFF_SEND_MPCAPABLE;
	}
	tp->t_addrid = mp->subflow_cnt++;

out:
	return (error);
}

int
mp_attach_subflow(struct socket *so)
{
	 return tcp_attach(so);
}


/* Append the just received mbuf to the queue of segments
 * to be processed by mp_input. Don't need to allocate
 * anything. Assumes that there is at least one packet
 * in the list, inserts at the end. */
void
mp_appendpkt(struct mbuf *mb, struct mbuf *m_ptr)
{
    struct mbuf *mq;

    KASSERT(mb != NULL, ("%s: mbuf NULL\n", __func__));

    mq = mb;
    while (mq->m_nextpkt) {
	    mq = mq->m_nextpkt;
    }
    mq->m_nextpkt = m_ptr;

    return;
}

void
mp_mbuf_enqueue(struct mpcb *mp, struct mbuf *m)
{
	MPP_LOCK_ASSERT(mp->mp_mppcb);
    KASSERT(mp != NULL, ("%s: mp NULL", __func__));
    KASSERT(m != NULL, ("%s: m NULL", __func__));

	if (mp->mp_input_segq == NULL)
		mp->mp_input_segq = m;
	else
		mp_appendpkt(mp->mp_input_segq, m);


}

void
mp_reass_flush(struct mpcb *mp)
{
	struct mbuf *m;

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	while ((m = mp->mp_segq) != NULL) {
		mp->mp_segq = m->m_nextpkt;
		mp->mp_segqlen -= m->m_pkthdr.len;
		m_freem(m);
	}

	KASSERT((mp->mp_segqlen == 0),
	    ("MPTCP reass queue %p length is %d instead of 0 after flush.",
	    mp, mp->mp_segqlen));
}


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

/*
 * Go through the process of creating a subflow - inpcb, tcpcb and a ghost
 * socket.
 */
int
mp_alloc_subflow_socket(struct socket *so, struct socket **gso)
{
	struct socket *sf_gso = NULL;
	int error = 0;

	/* create the ghost socket */
	sf_gso = mp_allocghostsocket(so);
	if (sf_gso == NULL) {
    	error = ENOMEM;
		goto out;
    }

	*gso = sf_gso;

out:
	return (error);
}


/* XXXNJW: to re-think */
static void
mp_twstart(struct mpcb *mp)
{
    struct socket *so;
    struct mppcb *mpp;
    int acknow;

    printf("%s: mp %p\n", __func__, mp);

    mpp = mp->mp_mppcb;
    MPP_LOCK_ASSERT(mpp);

    so = mpp->mpp_socket;
    soisdisconnected(so);

//	if (V_nomptimewait) {
//        mp->mp_state = MPS_M_CLOSED;
//        mp = mp_close(mp);
//        if (mp != NULL)
//            MPP_UNLOCK(mp->mp_mppcb);
//		return;
//	}

    // Maybe, so that we can call a free on the socket/mppcb
    // without the mppcb going away?
    // mpp_pcbref(mpp);

	acknow = mp->mp_flags & MPF_ACKNOW;
    mp->mp_state = MPS_M_TIME_WAIT;
    mpp->mpp_flags |= MPP_TIMEWAIT;
    mp_timer_activate(mp, MPT_TIMEOUT, mp_timeout());

//    if (acknow)
//		mp_twrespond(tw, TH_ACK);

     // should we try to free the socket?

}

/* XXXNJW: Some flaky sequence number wrap detection
 * Once we OR in the upper bits, if the previous DSN
 * is larger than the data_seq_num, then data_seq_num
 * has wrapped. Thus need to increment the upper 32 to
 * factor in the wrap.
 */
static uint64_t
mp_dsn32to64(uint64_t ds_val, uint64_t dseq)
{
	ds_val = (((dseq) & 0xFFFFFFFF00000000) | (uint32_t) ds_val);

	/* does this dsn wrap */

	/* If old dseq is greater than the new dsn, and the MSBs
	 * of new dsn are 0, and the MSBs of old dseq are 1, then
	 * the new dsn wraps (lower 32-bits). increment the 33rd
	 * bit by 1. */
	if ((uint32_t)dseq > (uint32_t)ds_val
		&& ((uint32_t)ds_val & 0xC0000000) == 0
		&& ((uint32_t)dseq & 0xC0000000) == 0xC0000000) {
		mp_debug(MPSESSION, 4, 0, "%s: detected wrap on lower 32 "
			"of ds_rcv_nxt %ju: %u, dsn map start %ju : %u\n",
			__func__, dseq, (uint32_t)dseq,
			ds_val, (uint32_t)ds_val);
		ds_val += ((uint64_t) 1 << 32);
	}

	return ds_val;
}

/* XXXNJW: More flaky sequence number wrap detection,
 * This time when converting D-ACKs to 64-bit.
 */
static uint64_t
mp_ack32to64(uint64_t dack_val, uint64_t dseq)
{
//	printf("%s: dack_val: %u dsnd_una %u\n", (uint32_t)dack_val,
//		(uint32_t)dseq);
//	printf("%s: dack_val: %ju dsnd_una %ju\n", dack_val, dseq);
	dack_val = ((dseq & 0xFFFFFFFF00000000) | (uint32_t) dack_val);
//	printf("%s: dack_val: %ju dsnd_una %ju\n", dack_val, dseq);

	/* DACK is positive and has wrapped on the lower 32
	 * DACK is a duplicate after una has wrapped on the
	 * lower 32. */
	if ((uint32_t)dseq > (uint32_t)dack_val
		&& ((uint32_t)dack_val & 0xC0000000) == 0
		&& ((uint32_t)dseq & 0xC0000000) == 0xC0000000) {
		mp_debug(MPSESSION, 4, 0, "%s: detected wrap on lower 32 "
			"of ds_rcv_nxt %ju: %u, dsn map start %ju : %u\n",
			__func__, dseq, (uint32_t)dseq,
			dack_val, (uint32_t)dack_val);
		dack_val += ((uint64_t) 1 << 32);
	} else if ((uint32_t)dseq < (uint32_t)dack_val
			&& ((uint32_t)dseq & 0xC0000000) == 0
			&& ((uint32_t)dack_val & 0xC0000000) == 0xC0000000) {
		dack_val -= ((uint64_t) 1 << 32);
	}

//	printf("%s: dack_val: %ju dsnd_una %ju\n", dack_val, dseq);
	return dack_val;
}

/* If we are attempting to use an interface, need to make sure that it is up.
 * this is more important for things like sending ADD_ADDRs on interfaces that
 * aren't up (this can happen if the sysctl is configured to use an address,
 * and that address happens to be down/non existent */
int
mp_is_if_up(struct sockaddr *l_addr) {
	struct ifaddr *ifa = NULL;

	ifa = ifa_ifwithaddr(l_addr);
	if (!ifa)
		return 0;

	return (ifa->ifa_ifp->if_flags & IFF_UP);
}

/* If the added address is being used in the master_tp (i.e. is default route)
 * we do not want to be advertising this (it will eventually try to bind the
 * same address and port as the master tp, causing problems) */
int
mp_is_addr_default(struct sockaddr_in *l_addr, struct mpcb *mp) {
	void *addr;
	char inet_buf[64];

	MPP_LOCK_ASSERT(mp->mp_mppcb);

	addr = &l_addr->sin_addr;
	inet_ntop(AF_INET, addr, inet_buf, mp_usable_addresses[0].ss_len);
	mp_debug(MPSESSION, 1, 0, "%s: Comparing added address %s ", __func__,
	    inet_buf);

	addr = &((struct sockaddr_in *) &mp_usable_addresses[0])->sin_addr;
	inet_ntop(AF_INET, addr, inet_buf, mp_usable_addresses[0].ss_len);
	mp_debug(MPSESSION, 1, 0, "with default %s\n", inet_buf);

	/* is the passed-in interface the same as the default interface  */
	if (l_addr->sin_addr.s_addr ==
	    ((struct sockaddr_in *) &mp->mp_default_address)->sin_addr.s_addr)  {
		mp_debug(MPSESSION, 1, 0, "%s: mp_addresses entry same as master_tp "
		    "addr\n", __func__);
		return 1;
	}

	mp_debug(MPSESSION, 1, 0, "%s: mp_addresses entry not same as master_tp "
	    "addr\n", __func__);
	return 0;
}

void
mp_update_available_addresses(struct mpcb *mp) {
	struct mp_add address;
	int new_address_count = mp->mp_conn_address_count;
	int i;

	address.length = address.sub_ipver = 0;

	/* Loop through available addresses. If the interface is down then it
	 * is not included in this connection. If the interface is the same as the
	 * default interface of the connection, it is not included. */
	for (i = 1; i < mp->mp_conn_address_count; i++) {
		if (!mp_is_if_up((struct sockaddr *) &mp_usable_addresses[i]) ||
			mp_is_addr_default((struct sockaddr_in *) &mp_usable_addresses[i],
			mp)) {
			mp->mp_advaddr_mask &= ~(1 << i);
			new_address_count--;
		}
		mp->mp_conn_address_count = new_address_count;
	}

}


void
mp_init(void)
{
	V_mpcb_zone = uma_zcreate("mpcb", sizeof(struct mpcb_mem),
				    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(V_mpcb_zone, maxsockets);

//	V_mpcb_zone = uma_zcreate("mpsopt", sizeof(struct mp_sopt),
//				    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
//	uma_zone_set_max(V_mpcb_zone, maxsockets);

	MPTOK_INFO_LOCK_INIT(&mp_tokinfo_list, "mp_tok list lock"); /* XXXNJW: temp list */
    SLIST_INIT(&mp_tokinfo_list.mpti_listhead);
}

void
mp_destroy(void) {
	MPTOK_INFO_LOCK_DESTROY(&mp_tokinfo_list);
//	uma_zdestroy(V_mpsopt_zone);
	uma_zdestroy(V_mpcb_zone);
}

SYSCTL_PROC(_net_inet_tcp_mptcp, OID_AUTO, mp_addresses, CTLTYPE_STRING|CTLFLAG_RW,
    NULL, 0, mp_addresses, "A", "extra addresses to be used in Multipath TCP connections");

SYSCTL_PROC(_net_inet_tcp_mptcp, OID_AUTO, mp_debug, CTLTYPE_STRING|CTLFLAG_RW,
    NULL, 0, mp_debug_sysctl_handler, "A", "Enable debugging output for mptcp");