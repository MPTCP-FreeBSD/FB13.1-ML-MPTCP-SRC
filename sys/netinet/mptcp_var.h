/*-
 * Copyright (c) 2012-2015
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

#ifndef MPTCP_VAR_H_
#define MPTCP_VAR_H_

#include <netinet/in.h>
#include <netinet/mptcp_types.h>

#define MAX_SUBFLOWS 8
#define MAX_ADDRS 	8
#define MAX_SUBFLOW_REXMIT    3

#define	BTOHEX_MSBLTOR	0x01
#define	BTOHEX_MSBRTOL	0x02


/* Is mptcp enabled? Determines whether MP_CAPABLE is put into outgoing SYNs,
 * or responded to if we receive a SYN + MP_CAPABLE */
//VNET_DECLARE(int, tcp_do_mptcp);
//#define	V_tcp_do_mptcp	VNET(tcp_do_mptcp)

/* for malloc'ing list heads */
MALLOC_DECLARE(M_REASSLISTHEAD);

/*
 * Globally accessible index of addresses that can be
 * used for mp_enabled connections. set via a sysctl.
 * mp_address_advertised is a bitmask that records whether
 * an address has been advertised.
 *
 * Initialised in mptcp_subr.c
 */
extern int mp_address_count;
extern struct sockaddr_storage mp_usable_addresses[MAX_ADDRS];

struct syncache;
struct ip;

/* User-protocol handle */
extern struct pr_usrreqs mptcp_usrreqs;

/* XXXNJW: A temp struct used to map mpcbs to mp session tokens. */
extern struct mp_sessions mp_tokinfo_list;

/* XXXNJW: A temp protosw that is used when creating subflows (allows them to
 * use standard TCP pr_usrreqs) */
extern struct protosw sf_protosw;


/* control output (set socket options) */
int mp_ctloutput(struct socket *, struct sockopt *);

#define sotomppcb(so) ((struct mppcb *)(so)->so_pcb)

/* Macros to initialize mptcp sequence numbers for
 * send and receive from initial tcp send and receive
 * sequence numbers. Used by the first subflow only,
 * as we operate in infinite mapped mode until mptcp
 * session is fully established.
 */
#define	mp_rcvseqinit(mp,tp) \
	(mp)->ds_rcv_nxt = (tp)->irs + 1

#define	mp_sendseqinit(mp,tp) \
	(mp)->ds_snd_una = (mp)->ds_snd_nxt = (mp)->ds_map_max = \
	    (mp)->ds_map_min = (tp)->iss + 1

#define M_MAXSFREXMIT() \
	V_mpsubflowrexmits ? V_mpsubflowrexmits : MAX_SUBFLOW_REXMIT


/* MPTCP Subflow handle.
 *
 * Accessed under the SF_LIST_RLOCK and SF_LIST_WLOCK and protected by the
 * INP_WLOCK (from the subflow INET PCB).
 * XXXNJW: Is this a sensible way to do it?
 */
struct sf_handle {
	TAILQ_ENTRY(sf_handle) next_sf_handle;
	struct socket *sf_so; /* subflow socket */
    struct protosw *sf_protosw;	 /* use standard TCP protosw for subflows */
    int    sf_flags;    /* subflow state flags */
};

struct mp_sched {
	struct sf_handle *last_sf_selected;
};

/* Struct to hold socket options for the connection */
struct mp_sopt {
       TAILQ_ENTRY(mp_sopt) next_mp_sopt;
       int sopt_level; /* option level (IPPROTO_TCP/SOL_SOCKET) */
       int sopt_name; /* option name */
       int sopt_val;  /* option value */
};

struct mp_addr_v4 {
	uint32_t token;
	in_port_t in_port;
	uint8_t pos_mask;
	uint8_t	id;
	uint8_t is_backup:1;
	struct	in_addr in_addr;
};

struct mp_path_map {
	struct mp_addr_v4 *local_address;
	struct mp_addr_v4 *remote_address;
};

TAILQ_HEAD(sf_send_head, sfsendmap_qent);

/* XXXNJW: temp. list of mpcb-token structs */
SLIST_HEAD(mpti_listhead, mpcb_tokinfo);

/*
 * Multi-path Control Block.
 *
 * Protected by MP_LOCK (m) and the MP_INNER_LOCK (i).
 *
 * Fields protected by the inner lock can be accessed outside of (m). The (m)
 * lock should not be taken while holding the (i) lock, but the (i) lock can
 * be taken while holding the (m) lock.
 *
 * XXXNJW: There is a bunch of path management stuff in here that needs to be
 * moved elsewhere.
 */
struct mpcb {
	struct mppcb *mp_mppcb;     /* (m) back pointer to multipath pcb */
	struct multi_cb m_cb_ref;   /* (m) pointer to self and a "listen" INP */
	uint8_t	mp_connected:1,     /* (m) did session ever connect? */
			mp_session:1,       /* (i) is this a mptcp session? */
			mp_passive:1,       /* (i) passive opener */
			csum_enabled:1;	    /* (i) using csum with data segments */
	int	mp_state;               /* state of mptcp connection */
	u_int mp_flags;             /* (i) mpcb session-related flags*/
	u_int16_t mp_event_flags;   /* E.g. mp-signaling events */

	struct taskqueue *mp_tq;	/* per-mp private task queue */
	struct sched_algo *sched_algo; /* scheduling algorithm to use */

    /* Subflows */
	TAILQ_HEAD(sf_handle_head, sf_handle) sf_list; /* (m) List of sf handles */
	int mp_conn_address_count; /* number of addresses available to session */
	int subflow_cnt;			/* (i) total number of subflows */

	/* TCP socket options */
	TAILQ_HEAD(mp_sopt_head, mp_sopt) mp_sopt_list; /* (m) List of socket options */


	struct mbuf *mp_input_segq; /* List of segments to process in mp_input */
	struct mbuf *mp_segq;       /* reass list of data-level segments */
	int mp_segqlen;             /* bytes in m_segq */

	u_int	t_rcvtime;		    /* inactivity time */
	u_int	t_starttime;		/* time connection was established */

	/* Data-level retransmits */
	struct mptcp_timer *mp_timers;	/* All the MPTCP timers in one struct */
	int mp_rxtcur;				   /* Current data-level RTO in ticks */
    int mp_rxtshift;               /* log(2) of rexmt exp. backoff */

	/* tokens, seq nums, windows */
	uint32_t local_token; 	/* local token for mptcp connection */
	uint32_t remote_token;  /* (i) token generated by remote host */
	uint64_t local_key; 	/* (i) 64-bit key sent by this host */
	uint64_t remote_key; 	/* (i) 64-bit key from remote host */

	uint64_t ds_idsn;		/* (i) data seq initial data seq number */
	uint64_t ds_snd_una;	/* (i) oldest unacknowledged seq, data space */
	uint64_t ds_snd_max;	/* (i) max send seq num, data space */
    uint64_t ds_snd_nxt;    /* (i) next sqn to send */

	uint64_t ds_map_max;	/* (i) Seq num of next byte to be mapped to a SF */
	uint64_t ds_map_min;	/* (i) Lowest seq no. currently in a map (may be below UNA) */
	uint32_t ds_snd_wnd;	/* (i) current send window */

	uint64_t ds_idsr;		/* (i) Initial data sequence receive */
	uint64_t ds_rcv_nxt;	/* (i) next expected data seq number */
	uint64_t ds_last_rcvd;	/* the last received ds seq number */
	uint32_t ds_rcv_wnd;	/* (i*) Receive window to be advertised by sub-flows */
	uint64_t ds_last_dack_sent; /* Last sent data-level ACK */

	/* CC stuff. To go elsewhere */
	uint64_t alpha;			/* alpha value for congestion control */
	uint64_t total_cwnd;	/* total cwnd of all subflows */

	/*
	 * The "path manager" of sorts, just an array of addresses
	 * that have been received via add_addr options.
	 * The address ID is just the index into the array.
	 * XXXNJW: This cannot be used for interop, as we cannot
	 * guarantee a mapping between address IDs and the array indexes
	 *
     * *NB: To be removed from the mpcb
	 * Initialised in mptcp_subr.c
	 */
	struct  mp_addr_v4	loc_addrs[MAX_ADDRS]; /* local addresses available to this connection */
	uint8_t	laddr_mask;				/* mask of address entries in loc_addrs */
	struct  mp_addr_v4	rem_addrs[MAX_ADDRS]; /* remote addresses available to this connection */
	uint8_t	raddr_mask;				/* mask of address entries in rem_addrs*/

	uint8_t l_addr_index_cnt; /* number of entries in local address table */
	uint8_t r_addr_index_cnt; /* number of entries in local address table */
	uint8_t path_cnt;		/* number of entries in local address table */
	int output_task_pending; /* is a drop task already enqueued */

	int mp_added_address_count;	/* added (via add_addr) subflows */
	struct sockaddr_storage mp_added_addresses[MAX_ADDRS];
	struct sockaddr_storage mp_default_address; /* Default interface for conn */
	struct sockaddr_storage mp_foreign_address; /* Default interface for conn */

	struct sockaddr_storage mp_path_manager[MAX_ADDRS];
	uint32_t mp_advaddr_mask; /* Mask for ADD_ADDRs sent */
	uint32_t mp_advjoin_mask; /* Mask for MP_JOINs sent from advertised addrs */
	uint32_t mp_lrnedjoin_mask; /* Mask for MP_JOINs sent to learned addrs */

	/*
	 * Various async tasks. Used when a task can be performed later, or when
	 * using a different thread simplifies locking.
	 *
	 * XXXNJW: still using the SWI task queue. Want a queue per MPTCP
	 * connection, and probably a single generic task handler rather than
	 * specific handlers.
	 */
	int mp_event_pending;
	int mp_join_pending;
	struct task mp_event_task; /* Receive Dfin, ack of Dfin etc. */

	struct task subflow_event_task; /* Subflows connecting, disconnecting etc. */
	struct task subflow_detached_task; /* subflow called tp_discardpcb */
    struct task mp_output_task; /* sbdrop, mapping new data */
    struct task mp_input_task;  /* sbappend, d-level signalling */
	struct task	join_task;	/* For enqueuing aysnc joins */
	struct task subflow_close_task; /* XXXNJW: to ensure subflows usr_close */
	//	struct task	rexmit_task;	/* For enqueuing data-level rexmits */

	int mp_input_pending;      /* Is an input task already pending */
	int mp_output_pending;     /* Is an output task already pending */
	int mp_sf_event_pending;   /* Is a sf event task already pending */
	int mp_sf_close_pending;   /* Is a sf close task already pending */
    int mp_sf_detach_pending;  /* Is a sf detach task already pending */

	struct mp_sched mp_temp_sched;
};


/*
 * A basic, temporary implementation of a list that maps mpcb's to tokens.
 * This is used to take in incoming join and map the token to an appropriate
 * mpcb.
 *
 * the mpti list, and rwlock, are initialised in mp_init(). an mpcb_tokinfo is
 * created with each mpcb and inserted into the list at connection established
 */
struct mpcb_tokinfo {
	SLIST_ENTRY(mpcb_tokinfo) mpti_entry;
    struct mpcb *mpti_pcb;
    uint32_t mpti_local_token;
    uint32_t mpti_remote_token;
};

struct mp_sessions {
	struct rwlock		 mpti_lock;
	struct mpti_listhead mpti_listhead;
};

/* MP closing state machine */
#define MP_NSTATES 	10			/* Number of MP state machine states */
#define	MPS_M_CLOSED		0	/* closed */
#define	MPS_M_ESTABLISHED	1	/* MP session established */
#define	MPS_M_FIN_WAIT_1	2	/* Sent a D-FIN (active close) */
#define	MPS_M_FIN_WAIT_2	3   /* D-FIN was ACKED (active close) */
#define MPS_M_CLOSING		4	/* Simultaneous close */
#define MPS_M_CLOSE_WAIT	5   /* Received a D-FIN (passive close) */
#define MPS_M_LAST_ACK		6   /* Sent a D-FIN (passive close) */
#define MPS_M_TIME_WAIT		7   /* Acked D-FIN (active close) */

/* For mp_flags */
#define MPF_ACKNOW   0x01
#define MPF_SENTDFIN 0x02

/* Flags for mp_output, dss_flags (on mtag) */
#define	MP_DFIN	    0x01
#define	MP_DACK	    0x02
#define MP_ADV_ADDR 0x04

#define MPD_DSN32   0x10
#define MPD_DSN64   0x20

static u_char	mp_outflags[MP_NSTATES] = {
	0,                  /* 0, MPS_M_CLOSED */
	0,		            /* 1, MPS_ESTABLISHED */
	MP_DFIN,            /* 2, MPS_M_FIN_WAIT_1 */
	MP_DACK,            /* 3, MPS_M_FIN_WAIT_2 */
	MP_DACK,            /* 4, MPS_M_CLOSING */
	MP_DACK,            /* 5, MPS_M_CLOSE_WAIT */
	MP_DFIN,            /* 6, MPS_M_LAST_ACK */
	MP_DACK,            /* 7, MPS_M_TIME_WAIT */
	0,
};

/* States for sf_handle->sf_state */
/* XXXNJW: actually these should be flags that the MP layer looks at when
 * dealing with sf_handles, not something the subflow has an awareness of.
 * E.g. SFS_CLOSING is okay, SFS_SENTCAPABLE,INFINITE_MAP should be in a tp
 * control block field. */
#define SFHS_BOUNDSUBFLOW	0x0001  /* Bound, primarily for listen sockets */
#define SFHS_MPESTABLISHED  0x0002  /* Subflow is using MPTCP */
#define SFHS_DISCONNECTING  0x0004  /* Commenced protocol disconnect */
#define SFHS_MPENDED        0x0010  /* No longer capable of using MPTCP */

/* Subflow events flags for tp->t_event_flags. Used to determine what to do
 * when mp->subflow_event_task_handler runs. */
#define SFE_CONNECTED        0x0001
#define SFE_MPESTABLISHED    0x0002
#define SFE_DISCONNECTING    0x0004
#define SFE_DISCONNECTED     0x0008
#define SFE_RCVDDFIN         0x0010
#define SFE_RCVDDFINACK      0x0020
#define SFE_RCVDRST          0x0040

/* M-Level events. keep consistent with the subflow events? */
#define MPE_RCVDDFIN         0x0010

/* XXXNJW: flags set in tcp_input to signal event to be enqueued
 * at mp-level */
#define MP_SCHEDINPUT  0x01
#define MP_SCHEDCLOSE  0x02
#define MP_SCHEDEVENT  0x04
#define MP_SCHEDDETACH 0x08
#define MP_SCHEDJOIN   0x10

/* Subflow flags for for tp->sf_flags . Used to signal input/output behaviours
 * (such as whether to add certain options etc) */
#define SFF_GOT_SYNACK		0x00000001
#define SFF_GOT_JOIN_SYN	0x00000002
#define SFF_GOT_JOIN_SYNACK	0x00000004
#define SFF_GOT_JOIN_ACK	0x00000008
#define	SFF_DATA_WAIT		0x00000010
#define	SFF_NEED_DACK		0x00000020
#define	SFF_NEED_DFIN		0x00000040
#define SFF_SEND_ADD_ADDR 	0x00000080
#define SFF_SEND_WAIT		0x00000100
#define SFF_SEND_MPCAPABLE  0x00000200  /* Should add MP_CAPABLE to outgoing */
#define SFF_SENT_MPCAPABLE	0x00000400	/* Advertised as MP_CAPABLE */
#define SFF_INFINITEMAP		0x00000800  /* Using infinite map */
#define SFF_FIRSTSUBFLOW	0x00001000  /* First subflow created */
#define SFF_LISTENTCPCB    	0x00002000  /* sf is used to accept connections */
#define SFF_PASSIVE_JOIN    0x00004000

/* States for t_sf_state.  */
#define SFS_MP_CONNECTING    0x0001
#define SFS_MP_ENABLED       0x0002
#define SFS_MP_DISCONNECTING 0x0004
#define SFS_MP_DISCONNECTED  0x0008

/* offsets for mptcp option parsing */
#define MP_DSS_FLAGS_OFFSET	3
#define MP_REMOTE_KEY_OFFSET	4
#define MP_DATA_ACK_OFFSET 	4
#define MP_DATA_ACK64_OFFSET	4
#define MP_DSN_OFFSET		4
#define MP_SUB_SEQN_OFFSET	8
#define MP_DATA_LEN_OFFSET	12
#define MP_CSUM_OFFSET	1	4
#define MP_RCV_TOKEN_OFFSET	4
#define MP_SND_RND_OFFSET	8
#define MP_SND_MAC_OFFSET	4
#define MP_SND_RND_SYNACK_OFFSET	12
#define MP_FAIL_KEY_OFFSET	4
#define MP_ADD_ADDR_OFFSET	4
#define MP_ADDID_OFFSET		3
#define MP_TOKEN_OFFSET	0
#define MP_IDSN_OFFSET	12

/* MPTCP signaling options */
#define MPOF_CAPABLE_SYN	0x0001
#define MPOF_CAPABLE_SYNACK	0x0002
#define MPOF_CAPABLE_ACK	0x0004
#define MPOF_MP_CAPABLE	0x0008
#define MPOF_DSS		0x0010
#define MPOF_DSN_MAP	0x0020
#define MPOF_DATA_ACK	0x0040
#define MPOF_ADD_ADDR	0x0080
#define MPOF_ADD_ADDR_V4	0x0100
#define MPOF_MP_JOIN	0x0200
#define MPOF_MP_RST		0x0400
#define MPOF_REMOVE_ADDR	0x0800
#define MPOF_MP_PRIO	0x1000
#define MPOF_USE_CSUM	0x2000
#define MPOF_DSN64		0x4000
#define MPOF_ACK64		0x8000
#define MPOF_NEED_ACK	0x00010000
#define MPOF_JOIN_SYN	0x00020000
#define	MPOF_JOIN_ACK	0x00040000
#define	MPOF_JOIN_SYNACK	0x00080000
#define MPOF_BACKUP_PATH	0x00100000
#define	MPOF_DATA_FIN	0x00200000
#define MPOF_ADD_ADDR_V6	0x00400000
#define MPOF_MP_FAIL	0x00800000
#define MPOF_FASTCLOSE	0x01000000
#define	MPOF_MAXOPT		0x02000000


/* Bit Mask for D-FIN flag */
#define MP_SET_DATA_FIN	0x20

/* MPTCP status flags */
#define MP_INIT 0
#define CSUM_ENABLED 1

/* mbuf tag defines */
#define PACKET_TAG_DSN 10
#define PACKET_COOKIE_MPTCP 34216894
#define DSN_TAG_LEN  9

/* DS Map flags */
#define MAPF_IS_SENT	0x00000001 /* Sent all data from map */
#define MAPF_IS_ACKED	0x00000002 /* All data in map is acknowledged */
#define MAPF_IS_DUP		0x00000004 /* Duplicate map, already acked at ds-level */
#define MAPF_IS_REXMIT	0x00000008 /* Is a rexmit of a previously sent map */

#define SB_NUMMAPPED(mp) 		\
	((mp)->ds_map_max - (mp)->ds_map_min)
#define	TCPS_SUBFLOWCLOSING(s)	((s) == TCPS_CLOSE_WAIT)
#define	intompcb(ip)	(((struct tcpcb *)(ip)->inp_ppcb)->t_mpcb)
#define	MPS_HAVERCVDFIN(s)	((s) >= MPS_M_CLOSING)
#define MPS_ENDED(s) ((s) == MPS_M_TIME_WAIT || (s) == MPS_M_CLOSED)

/* XXXNJW: mallocs to be removed */
MALLOC_DECLARE(M_SFHANDLE); /* Type for subflow handle */
MALLOC_DECLARE(M_MPTOKINFO); /* Type for subflow handle */
MALLOC_DECLARE(M_MPTIMERS); /* mp_timers struct */
MALLOC_DECLARE(M_MPSOPT);   /* mp_sopt struct */


/*
 * MP Options.
 */

/* MP_CAPABLE option */
struct mp_capable {
	uint8_t kind;		/* option kind */
	uint8_t length;		/* length of option */
	uint8_t ver_sub;	/* MPTCP version */
	uint8_t flags;	/* MPTCP subtype */

#define	USE_SHA1	1	/* Bit 1 */
#define	USE_CSUM	128	/* Bit 8 */
};

/* DSS option */
struct mp_dss {
	uint8_t kind;
	uint8_t length;
	uint8_t	subtype;
	uint8_t dss_flags;

#define ACK_PRESENT	0x0001
#define ACK_64_PRESENT	0x0002
#define MAP_PRESENT	0x0004
#define DSN_64	0x0008
#define FIN_PRESENT	0x0010
};

/* MP_JOIN option flags */
struct mp_join {
	uint8_t kind;
	uint8_t length;
	uint8_t	sub_flags;
	uint8_t addr_id;

/* masks for bits 16-31 of dss option */
#define IS_BACKUP	0x01
};

/* MP_ADD option */
struct mp_add {
	uint8_t kind;
	uint8_t length;
	uint8_t	sub_ipver;
	uint8_t addr_id;

#define IS_IPV4	1
};

struct dsn_tag {
    struct m_tag tag;
    uint64_t dsn;
    uint8_t  dss_flags;
};

struct dss_psdhead {
	uint64_t dsn;
	uint32_t ssn;
	u_short	len;
	u_short	pad;
};

typedef struct mptcp_key {
	uint32_t keylen;
	uint8_t key[];
} mptcp_key_t;


/*
 * LOCK MACROS used for:
 * MP Token Info list
 */

#define MP_LOCK_INIT(mp) 	mtx_init(&mp->mpcb_mutex, "mpcb", NULL, MTX_DEF)
#define MP_LOCK_DESTROY(mp) 	mtx_destroy(&mp->mpcb_mutex)
#define MP_LOCK(mp)		mtx_lock(&mp->mpcb_mutex)
#define MP_UNLOCK(mp)	mtx_unlock(&mp->mpcb_mutex)
#define	MP_LOCK_ASSERT(mp)	mtx_assert(&mp->mpcb_mutex, MA_OWNED)
#define MP_UNLOCK_ASSERT(mp) mtx_assert(&mp->mpcb_mutex, MA_UNLOCKED)

/* XXXNJW: Locks for the mp-token list. The list will be replaced with
 * more substatial at a later time. */
#define MPTOK_INFO_LOCK_INIT(mpti, d) \
	rw_init_flags(&(mpti)->mpti_lock, (d), RW_RECURSE)
#define MPTOK_INFO_LOCK_DESTROY(mpti)  rw_destroy(&(mpti)->mpti_lock)
#define MPTOK_INFO_RLOCK(mpti)	rw_rlock(&(mpti)->mpti_lock)
#define MPTOK_INFO_WLOCK(mpti)	rw_wlock(&(mpti)->mpti_lock)
#define MPTOK_INFO_RUNLOCK(mpti)	rw_runlock(&(mpti)->mpti_lock)
#define MPTOK_INFO_WUNLOCK(mpti)	rw_wunlock(&(mpti)->mpti_lock)
#define	MPTOK_INFO_LOCK_ASSERT(mp)	rw_assert(&(mpti)->mpti_lock, RA_WLOCKED)

/* 64-bit DSN comparisons */
#define	DSEQ_LT(a,b)	((int64_t)((a)-(b)) < 0)
#define	DSEQ_LEQ(a,b)	((int64_t)((a)-(b)) <= 0)
#define	DSEQ_GT(a,b)	((int64_t)((a)-(b)) > 0)
#define	DSEQ_GEQ(a,b)	((int64_t)((a)-(b)) >= 0)

#define	DSEQ_MIN(a, b)	((SEQ_LT(a, b)) ? (a) : (b))
#define	DSEQ_MAX(a, b)	((SEQ_GT(a, b)) ? (a) : (b))

/* MP-related debug output */
/*
 * Keep these defines in sync with debug_class struct in mptcp_subr.c
	{.class = "MPSESSION"},
	{.class = "DSMAP"}
*/
#define MPSESSION 	0x00000001
#define DSMAP 		0x00000002
#define SBSTATUS 	0x00000004
#define REASS		0x00000008

/* MPTCP systcl identifiers */
#define	MPTCPCTL_MAXSUBFLOWS	1	/* Maximum subflows allowed */
#define	MPTCPCTL_SINGLEPKTMAPS	2	/* put DSS map on each packet */
#define MPTCPCTL_NOTIMEWAIT     3   /* Don't use timeout on M_TIME_WAIT */

VNET_DECLARE(int, max_subflows);
VNET_DECLARE(int, single_packet_maps);


void mpp_init(void);
void mp_init(void);
void mp_destroy(void);
int  mp_newmpcb(struct mppcb *mpp);
void mp_syncache_newmpcb(struct mpcb *mp, struct syncache *sc);
void mp_discardcb(struct mpcb *mp);
struct mpcb*
     mp_close(struct mpcb *mp);
struct mpcb*
     mp_drop(struct mpcb *mp, int error);
void mp_sf_flush(struct mpcb *mp);
void mp_mpsopt_flush(struct mpcb *mp);
struct mp_sopt*
     mp_alloc_mp_sopt(void);
int mp_bind_attach(struct socket *so, struct mpcb *mp,
	struct sockaddr *nam, struct thread *td);
void mp_appendpkt(struct mbuf *mb, struct mbuf *m_ptr);
void mp_mbuf_enqueue(struct mpcb *mp, struct mbuf *m);
void mp_dosubtypes(struct tcpopt *to, uint8_t subtype, u_char *cp,
	int opt, int optlen, int flags);

/* Debugging stuff */
void mp_debug(uint32_t log_class, int msg_verbosity,
    uint32_t flags, char * fmt, ...);
void	btohex(char *buf, uint32_t buf_len, uint8_t *bytes,
    int32_t bytes_len, int32_t flags);

/* */
int	    mp_output(struct mpcb *mp);
int     mp_standard_output(struct mpcb *mp); /* Standard TCP connections */
int     mp_reass(struct mpcb *mp, struct mbuf *m);

void	ds_reass_init(struct mpcb *m);
void	mp_order_segment_list(struct tcpcb *tp, struct sockbuf *sb);
uint64_t mp_generate_local_key(void);
uint32_t mp_do_hashing(struct mpcb *mp);
uint32_t mp_do_sha_hash(uint8_t *digest, uint8_t *key, uint64_t key_length);
uint32_t mp_get_token(uint8_t *digest);
uint64_t mp_new_idsn(uint8_t *digest);
u_short  mp_dss_cksum(struct dss_psdhead);
uint32_t mp_get_hmac (uint8_t *digest, uint64_t local_key, uint64_t remote_key,
			uint32_t local_rand, uint32_t remote_rand);
uint32_t
		mp_get_token(uint8_t *digest);

void	mp_update_map(struct mpcb *mp);
void	mp_add_local_addr(struct mpcb *mp,
    struct in_addr *inp_local_addr, in_port_t lport, uint8_t address_id);
void	mp_add_remote_addr(struct mpcb *mp, struct in_addr *inp_remote_addr,
    in_port_t rport, uint8_t address_id);
void	mp_remove_remote_addr(struct mpcb *mp, uint8_t address_id);
void 	mp_process_local_key(struct mp_connection *mp_conn, uint64_t local_key);
void 	mp_process_remote_key(struct mp_connection *mp_conn, uint64_t remote_key);
void 	mp_state_change(struct mpcb *mp, int state);
void    mp_syncache_process_local_key(struct syncache *sc);
void    mp_syncache_process_remote_key(struct syncache *sc,
            uint64_t remote_key);
struct mpcb*
        mp_locate_mpcb(uint32_t token);

void mp_remtoklist(uint32_t local_token); /* free mpti entry */

/* Managing Subflows */
struct socket *
        mp_allocghostsocket(struct socket *so);
void    mp_close_all_subflows(struct mpcb *mp);
void    mp_reset_all_subflows(struct mpcb *mp);
int     mp_alloc_subflow_socket(struct socket *so, struct socket **gso);
int     mp_insert_subflow(struct mpcb *mp, struct socket *sf_so);
void    mp_enqueue_event(struct mpcb *mp, u_int16_t event_flag);
void    mp_enqueue_subflow_event(struct tcpcb *tp, u_int16_t event_flag);
void    mp_subflow_freehandle(struct mpcb *mp, struct sf_handle *sf);
void    mp_subflow_release_socket(struct socket *so);
int     mp_attach_subflow(struct socket *so);
int     mp_create_subflow_implicit(struct mpcb *mp, struct socket *so,
    struct ip *ip, struct tcphdr *th);
int     mp_join_respond(struct socket *so, struct tcpcb *tp,
    struct in_conninfo *inc);
int  	mp_connect_subflow(struct socket *so, struct sockaddr *nam,
		    struct thread *td);
int     mp_create_subflow_socket(struct socket *so, struct socket **sf_gso);
void    mp_close_subflow_task_handler(void *context, int pending);
void    mp_sftimewait(struct socket *sf_gso);

/* Socket options */
int    mp_ctloutput(struct socket *so, struct sockopt *sopt);
struct mp_sopt* mp_locate_mp_sopt(struct mpcb *mp, struct sockopt *sopt);

/* Interface management */
int    mp_is_if_up(struct sockaddr *l_addr);
int    mp_is_addr_default(struct sockaddr_in *l_addr, struct mpcb *mp);
void   mp_update_available_addresses(struct mpcb *mp);

/* tcp_output related */
uint32_t
		mp_get_recwin(struct mpcb *mp);
void	mp_update_sndwin(struct mpcb *mp, uint16_t win);

struct ds_map *
		mp_find_dsmap(struct tcpcb *tp, tcp_seq	seqnum);

/* tcp_input related */
int  mp_data_ack(struct mpcb *mp, uint64_t data_ack_num);
void mp_drop_from_sendbuffer_locked(struct mpcb *mp, int acked,
    struct ds_map *map);
void mp_drop_from_sendbuffer(struct mpcb *mp, int acked, struct ds_map *map);
void mp_deferred_sbdrop(struct mpcb *mp, int acked);
void mp_init_established(struct mpcb *mp);
void mp_set_ds_map(struct mpcb *mp, uint64_t ds_num);
int  mp_do_task_now(struct mpcb *mp, int task_flags);

/* Functions for task queue */
void mp_schedule_tasks(struct mpcb *mp, int task_flags);
void mp_join_task_handler(void *context, int pending);
void mp_subflow_event_task_handler(void *context, int pending);
void mp_subflow_detached_task_handler(void *context, int pending);
void mp_output_task_handler(void *context, int pending);
void mp_input_task_handler(void *context, int pending);
void mp_drop_task(struct mpcb *mp, int acked);
int mp_detach_subflow_locked(struct mpcb *mp);
/* data_level rexmit */
void    mp_trigger_rexmit(struct mpcb *mp);
//void    mp_queue_data_rexmit_unlocked(struct mpcb *mp);
void    mp_queue_data_rexmit_unlocked(struct tcpcb *tp);

#endif /* MPTCP_VAR_H_ */