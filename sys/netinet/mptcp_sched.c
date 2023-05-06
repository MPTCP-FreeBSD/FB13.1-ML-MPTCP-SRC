#include <netinet/mptcp_sched.h>

/* XXXBKF: temporary implementation of scheduler selection */
struct sf_handle *
mp_get_subflow(struct mpcb *mp)
{
	return mp_sched_minRTT(mp);
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
struct sf_handle *
mp_sched_rr(struct mpcb *mp)
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
	TAILQ_FOREACH_FROM (sf_next, &mp->sf_list, next_sf_handle) {
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

struct sf_handle *
mp_sched_minRTT(struct mpcb *mp)
{
	struct sf_handle *sf_min = NULL;
	struct sf_handle *sf_next = NULL;
	struct inpcb *inp;
	struct tcpcb *tp;
	int min_rtt;
		
	TAILQ_FOREACH (sf_next, &mp->sf_list, next_sf_handle) {
		if (sf_next->sf_flags & (SFHS_MPENDED | SFHS_MPESTABLISHED))
			continue;
		
		inp = sotoinpcb(sf_next->sf_so);
		tp = intotcpcb(inp);
		
		INP_WLOCK(inp);
		
		if (inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT)) {
			sf_next->sf_flags |= SFHS_MPENDED;
		
			if (tp->t_sf_state & SFS_MP_DISCONNECTED)
				mp_schedule_tasks(mp, MP_SCHEDCLOSE);
		
			INP_WUNLOCK(inp);
			continue;
		}
		
		if ((tp->t_state < TCPS_ESTABLISHED) || tp->t_rxtshift) {
			INP_WUNLOCK(inp);
			continue;
		}
		
		/* Check if sub-flow has capacity in CWND */
		if (tcp_compute_pipe(tp) - tp->snd_cwnd > 0) {
			/* If first available sub-flow, set as current min_rtt */
			if (sf_min == NULL) {
				sf_min = sf_next;
				min_rtt = tp->t_srtt;
			}
			else {
				/* Check if rtt is less than current min_rtt */
				if (tp->t_srtt < min_rtt) {
					sf_min = sf_next;
					min_rtt = tp->t_srtt;
				}
			}
		}
		
		INP_WUNLOCK(inp);
	}
	
	/* XXXBKF: If no available sf found, just return the first
	 * Need to introduce a wait function here in future */
	if (sf_min == NULL)
		sf_min = TAILQ_FIRST(&mp->sf_list);
	
	return sf_min;
}
