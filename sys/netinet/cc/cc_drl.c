#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <sys/types.h>

#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_module.h>

#define MAX_QUEUE_SIZE 10000

struct pkt {
	u_int		cwnd;
	int			smoothed_rtt;
	int			cong_events;

	u_int		laddr;
	u_int		lport;
};

struct pkt_node {
	struct pkt	pkt;

	STAILQ_ENTRY(pkt_node)	nodes;
};

struct ccv_node {
	struct cc_var 	*ccv;

	LIST_ENTRY(ccv_node)	nodes;
};

struct drl {
	u_int 		cwnd;
	u_int 		cwnd_prev;

	u_int		laddr;
	u_int		lport;
	struct ccv_node	*ccv_node;
};


STAILQ_HEAD(pkthead, pkt_node) pkt_queue = STAILQ_HEAD_INITIALIZER(pkt_queue);
static struct 	mtx pkt_queue_mtx;
static int	pkt_queue_size = 0;

LIST_HEAD(ccvhead, ccv_node) ccv_list = LIST_HEAD_INITIALIZER(ccv_list);
static struct 	mtx ccv_list_mtx;


static MALLOC_DEFINE(M_DRL, "DRL Data", "Per connection data required for the DRL algorithm");
static MALLOC_DEFINE(M_DRL_PKT_NODE, "DRL pkt_node", "DRL pkt_node struct");
static MALLOC_DEFINE(M_DRL_CCV_NODE, "DRL ccv_node", "DRL ccv_node struct");
static MALLOC_DEFINE(M_DRL_PKT_BUFFER, "DRL pkt buffer", "DRL pkt buffer");


static int	drl_mod_init(void);
static int	drl_cb_init(struct cc_var *ccv);
static void	drl_cb_destroy(struct cc_var *ccv);
static void	drl_ack_received(struct cc_var *ccv, uint16_t type);
static void	drl_cong_signal(struct cc_var *ccv, uint32_t type);
static void	drl_post_recovery(struct cc_var *ccv);
static void	drl_after_idle(struct cc_var *ccv);


struct cc_algo drl_cc_algo = {
	.name = "drl",
	.mod_init = drl_mod_init,
	.cb_init = drl_cb_init,
	.cb_destroy = drl_cb_destroy,
	.ack_received = drl_ack_received,
	.cong_signal = drl_cong_signal,
	.after_idle = drl_after_idle
};

static int
drl_mod_init(void) {
	// Initialise module mutexes
	mtx_init(&pkt_queue_mtx, "cc_drl_pkt_queue_mtx", NULL, MTX_DEF);
	mtx_init(&ccv_list_mtx, "cc_drl_ccv_list_mtx", NULL, MTX_DEF);

	return 0;
}

static int
drl_cb_init(struct cc_var *ccv)
{
	struct drl *drl_data;
	struct ccv_node *cn;

	// Allocate local cc data
	drl_data = malloc(sizeof(struct drl), M_DRL, M_NOWAIT|M_ZERO);
	if (drl_data == NULL)
		return (ENOMEM);

	// Initialise local cc data
	drl_data->cwnd = 0;
	drl_data->cwnd_prev = 0;
	drl_data->laddr = 0;
	drl_data->lport = 0;

	// Assign local cc data to ccv
	ccv->cc_data = drl_data;

	// Allocate and populate struct for ccv lookup
	cn = malloc(sizeof(struct ccv_node), M_DRL_CCV_NODE, M_NOWAIT|M_ZERO);
	cn->ccv = ccv;
	
	// Add ccv lookup to list
	mtx_lock(&ccv_list_mtx);
	LIST_INSERT_HEAD(&ccv_list, cn, nodes);
	mtx_unlock(&ccv_list_mtx);

	// Assign back pointer to ccv node
	drl_data->ccv_node = cn;

	return (0);
}

static void
drl_cb_destroy(struct cc_var *ccv)
{
	struct drl *drl_data;
	
	drl_data = ccv->cc_data;

	// Remove ccv from lookup list
	mtx_lock(&ccv_list_mtx);
	LIST_REMOVE(drl_data->ccv_node, nodes);
	mtx_unlock(&ccv_list_mtx);

	// Free local cc memory
	free(drl_data, M_DRL);
}

static void
drl_ack_received(struct cc_var *ccv, uint16_t type)
{
	struct drl *drl_data;
	struct pkt_node *pn;

	drl_data = ccv->cc_data;

	// Allocate and populate struct for tcp stats
	pn = malloc(sizeof(struct pkt_node), M_DRL_PKT_NODE, M_NOWAIT|M_ZERO);
	pn->pkt.cwnd = CCV(ccv, snd_cwnd);
	pn->pkt.smoothed_rtt = CCV(ccv, t_srtt);
	pn->pkt.cong_events = 0;
	pn->pkt.laddr = drl_data->laddr = CCV(ccv, t_inpcb)->inp_laddr.s_addr;
	pn->pkt.lport = drl_data->lport = CCV(ccv, t_inpcb)->inp_lport;

	// Push tcp stats to drl agent for processing
	mtx_lock(&pkt_queue_mtx);
	if (pkt_queue_size >= MAX_QUEUE_SIZE)
	{
		STAILQ_REMOVE_HEAD(&pkt_queue, nodes);
		pkt_queue_size--;
	}
	STAILQ_INSERT_TAIL(&pkt_queue, pn, nodes);
	pkt_queue_size++;
	mtx_unlock(&pkt_queue_mtx);

	// Update tcpcb send_cwnd with latest from drl agent
	if (drl_data->cwnd > 0)
		CCV(ccv, snd_cwnd) = drl_data->cwnd;
}

static void
drl_cong_signal(struct cc_var *ccv, uint32_t type)
{
	struct drl *drl_data;
	struct pkt_node *pn;

	drl_data = ccv->cc_data;

	// Allocate and populate struct for tcp stats
	pn = malloc(sizeof(struct pkt_node), M_DRL_PKT_NODE, M_NOWAIT|M_ZERO);
	pn->pkt.cwnd = CCV(ccv, snd_cwnd);
	pn->pkt.smoothed_rtt = CCV(ccv, t_srtt);
	pn->pkt.cong_events = 1;
	pn->pkt.laddr = drl_data->laddr = CCV(ccv, t_inpcb)->inp_laddr.s_addr;
	pn->pkt.lport = drl_data->lport = CCV(ccv, t_inpcb)->inp_lport;
	
	// Push tcp stats to drl agent for processing
	mtx_lock(&pkt_queue_mtx);
	if (pkt_queue_size >= MAX_QUEUE_SIZE)
	{
		STAILQ_REMOVE_HEAD(&pkt_queue, nodes);
		pkt_queue_size--;
	}
	STAILQ_INSERT_TAIL(&pkt_queue, pn, nodes);
	pkt_queue_size++;
	mtx_unlock(&pkt_queue_mtx);

	// Update cwnd with latest from drl agent
	if (drl_data->cwnd > 0)
		CCV(ccv, snd_cwnd) = drl_data->cwnd;
}

static void
drl_after_idle(struct cc_var *ccv)
{
	uint32_t rw;
	struct drl *drl_data;

	drl_data = ccv->cc_data;

	// Reset congestion window, as per RFC5681 Section 4.1.
	rw = tcp_compute_initwnd(tcp_maxseg(ccv->ccvc.tcp));
	CCV(ccv, snd_cwnd) = drl_data->cwnd = drl_data->cwnd_prev = min(rw, CCV(ccv, snd_cwnd));

	// Store local address and port
	if (drl_data->laddr == 0)
		drl_data->laddr = CCV(ccv, t_inpcb)->inp_laddr.s_addr;
	if (drl_data->lport == 0)
		drl_data->lport = CCV(ccv, t_inpcb)->inp_lport;
}

int
sys_drl_update_cwnd(struct thread *td, struct drl_update_cwnd_args *uap)
{
	struct drl *drl_data;
	struct ccv_node *cn;

	// Find cc_var from laddr and lport
	mtx_lock(&ccv_list_mtx);
	LIST_FOREACH(cn, &ccv_list, nodes) {
			drl_data = cn->ccv->cc_data;
			if (drl_data->laddr == uap->laddr && drl_data->lport == uap->lport)
			{
				// Update cwnd
				drl_data->cwnd_prev = drl_data->cwnd;
				drl_data->cwnd = uap->cwnd;

				mtx_unlock(&ccv_list_mtx);
				return 0;
			}
		}

	mtx_unlock(&ccv_list_mtx);
	return 0;
}

int
sys_drl_get_buffer(struct thread *td, struct drl_get_buffer_args *uap)
{
	STAILQ_HEAD(pkthead, pkt_node) tmp_q = STAILQ_HEAD_INITIALIZER(tmp_q);
	struct pkt_node *pn;

	struct pkt *pb;
	int size;
	int idx = 0;

	// Return error if pkt queue is empty
	if (pkt_queue_size == 0)
	{
		td->td_retval[0] = -1;
		return 0;
	}

	// Copy pkt queue to temp queue, allowing the main queue to continue receiving events
	mtx_lock(&pkt_queue_mtx);
	STAILQ_CONCAT(&tmp_q, &pkt_queue);
	size = pkt_queue_size;
	pkt_queue_size = 0;
	mtx_unlock(&pkt_queue_mtx);

	// Allocate and populate pkt buffer
	pb = malloc(sizeof(struct pkt) * size, M_DRL_PKT_BUFFER, M_NOWAIT|M_ZERO);
	STAILQ_FOREACH(pn, &tmp_q, nodes) {
			pb[idx].cwnd = pn->pkt.cwnd;
			pb[idx].smoothed_rtt = pn->pkt.smoothed_rtt;
			pb[idx].cong_events = pn->pkt.cong_events;
			pb[idx].laddr = pn->pkt.laddr;
			pb[idx].lport = pn->pkt.lport;
			STAILQ_REMOVE_HEAD(&tmp_q, nodes);
			free(pn, M_DRL_PKT_NODE);
			idx++;
		}

	// Copy buffer to user space
	copyout(pb, uap->data, sizeof(struct pkt) * size);
	copyout(&size, uap->size, sizeof(int));

	// Free kernel memory
	free(pb, M_DRL_PKT_BUFFER);

	return 0;
}

DECLARE_CC_MODULE(drl, &drl_cc_algo);
MODULE_VERSION(drl, 1);
