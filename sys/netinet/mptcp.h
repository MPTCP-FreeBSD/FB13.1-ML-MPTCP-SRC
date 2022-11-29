/*-
 * Copyright (c) 2012-2015
 * 	Swinburne University of Technology, Melbourne, Australia.
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

/*
 * mptcp.h
 *
 *  Created on: 15/05/2012
 *      Author: nwilliams
 */

#ifndef MPTCP_H_
#define MPTCP_H_


#include <sys/cdefs.h>

#define MPTCP_64BIT_KEY 8

typedef	u_int64_t mptcp_seq;

/* MPTCP subtypes */
#define	MPTCP_SUBTYPE_MP_CAPABLE	0
#define		MPTCP_SUBLEN_MP_CAPABLE_SYN	12
#define		MPTCP_SUBLEN_MP_CAPABLE_ACK	20

#define MPTCP_SUBTYPE_MP_JOIN		1
#define		MPTCP_SUBLEN_MP_JOIN_SYN	12
#define		MPTCP_SUBLEN_MP_JOIN_SYNACK	16		// should be 16, but run out of option space
#define		MPTCP_SUBLEN_MP_JOIN_ACK	24		// should be 24, but run out of option space

#define MPTCP_SUBTYPE_DSS			2
#define		MPTCP_SUBLEN_DSS_DATA_ACK	XX
#define		MPTCP_SUBLEN_DSS_DATA_DSN	XX

#define MPTCP_SUBTYPE_ADD_ADDR		3
#define 	MPTCP_SUBLEN_ADD_ADDRV4		8
#define 	MPTCP_SUBLEN_ADD_ADDRV6		20

#define MPTCP_SUBTYPE_REMOVE_ADDR	4
#define 	MPTCP_SUBLEN_REMOVE_ADDR	4

#define MPTCP_SUBTYPE_MP_PRIO		5

#define MPTCP_SUBTYPE_MP_FAIL		6
#define		MPTCP_SUBTYPELEN_MP_FAIL	12

#define MPTCP_SUBTYPE_MP_FASTCLOSE	7
#define 	MPTCP_SUBTYPELEN_MP_FASTCLOSE 12

#define	MAX_MP_OPLEN	28

/* mptcp errors */

#define EMAXSUBFLOWSREACHED 01
#define ENOMPCB	02
#define	ENOTCPCB 03

/* mptcp funcs */


#define	MPTCP_SA_NAME_MAX	16	/* max scheduler discipline name length */

#endif /* MPTCP_H_ */