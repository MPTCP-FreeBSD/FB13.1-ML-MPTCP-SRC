/*
 * tcp_usrreq.h
 *
 *  Created on: 02/10/2014
 *      Author: nwilliams
 */

#ifndef TCP_USRREQ_H_
#define TCP_USRREQ_H_

/* Called from tcp_usr_* and mp_usr_* functions */
int	tcp_attach(struct socket *so);
int	tcp_connect(struct tcpcb *, struct sockaddr *, struct thread *td);

/* Called from mp_usrreq */
int		tcp_usr_attach(struct socket *so, int proto, struct thread *td);
int		tcp_usr_bind(struct socket *so, struct sockaddr *nam,
		    struct thread *td);
void	tcp_usr_detach(struct socket *so);
int		tcp_usr_listen(struct socket *so, int backlog, struct thread *td);
int		tcp_usr_connect(struct socket *so, struct sockaddr *nam,
			struct thread *td);
int		tcp_usr_disconnect(struct socket *so);
int		tcp_usr_accept(struct socket *so, struct sockaddr **nam);
int		tcp_usr_shutdown(struct socket *so);
int		tcp_usr_rcvd(struct socket *so, int flags);
int		tcp_usr_rcvoob(struct socket *so, struct mbuf *m, int flags);
int		tcp_usr_send(struct socket *so, int flags, struct mbuf *m,
			struct sockaddr *nam, struct mbuf *control, struct thread *td);
void	tcp_usr_abort(struct socket *so);
void 	tcp_usr_close(struct socket *so);

/* TEMP: Only used for initial testing */
void tcp_usrclosed(struct tcpcb *tp);

#endif /* TCP_USRREQ_H_ */