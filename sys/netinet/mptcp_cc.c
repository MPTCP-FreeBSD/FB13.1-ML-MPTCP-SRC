#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>

#include <sys/types.h>
#include <sys/systm.h>

static int _cwnd = 0;

int sys_set_cwnd(struct thread *td, struct set_cwnd_args *uap)
{
	_cwnd = uap->cwnd;
	return 0;
}

int sys_get_cwnd(struct thread *td, struct get_cwnd_args *uap)
{
	td->td_retval[0] = _cwnd;
	return 0;
}