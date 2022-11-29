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

#ifndef MPTCP_TIMER_H_
#define MPTCP_TIMER_H_

#define	MPTCPTV_RTOBASE	(4*hz) /* Initial RTO length (arbitrary number) */
#define MPTCPTV_TIMEOUT (30*hz) /* Once MPTCP session enters timewait */
#define MPTCPTV_TIMEOUTCNT 2   /* Just a default multiplier for timeout */

#define	MPT_MAXRXTSHIFT	3 /* Max retransmits (arbitrary number) */

struct mpcb;

struct mptcp_timer {
	struct	callout mpt_rexmt;	    /* retransmit timer */
	struct	callout mpt_timeout;   /* timewait */
};
#define MPT_REXMT    0x01
#define MPT_TIMEOUT 0x02

void	mp_timer_init(void);
void    mp_timer_activate(struct mpcb *mp, int timer_type, u_int delta);
int     mp_timer_active(struct mpcb *mp, int timer_type);
void	mp_timer_rexmt(void *xmp);
void	mp_timer_timeout(void *xmp);

#endif /* MPTCP_TIMER_H_ */