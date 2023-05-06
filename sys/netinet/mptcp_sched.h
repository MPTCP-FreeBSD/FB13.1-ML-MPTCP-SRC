#ifndef MPTCP_SCHED_H_
#define MPTCP_SCHED_H_

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

struct sf_handle *mp_get_subflow(struct mpcb *mp);
struct sf_handle *mp_sched_rr(struct mpcb *mp);
struct sf_handle *mp_sched_minRTT(struct mpcb *mp);

#endif /* MPTCP_SCHED_H_ */
