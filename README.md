MPTCP FreeBSD Source:
---------------
Multipath TCP (MPTCP) has been implemented and evaluated using the modular approach known as ModCC in FreeBSD. This research builds a foundation for developing an experimental platform and implementing MPTCP protocol stacks in FreeBSD-13 to plug machine learning (ML) models. Several independent and interoperable implementations are essential for the Internet Engineering Task Force (IETF) recognition of emerging ML-based MPTCP algorithms. We implement MPTCP under FreeBSD-13 and make them publicly available as dynamically pluggable user and kernel modules for testing and experimentation by the wider network and the Internet community. In particular, we redesign MPTCP over FreeBSD and implement enhanced ModCC in v13.1. In addition, we develop and implement a new kernel module CC-DRL to handle two system calls: i) drl_get_buffer to marshal data from the kernel to ML models in the user space and ii) drl_update_cwnd to marshal data from the ML models to the kernel space. CC-DRL operates in parallel with ModCC. We present new insights and concise descriptions of MPTCP implementation challenges to assist other parallel initiatives to develop compatible MPTCP stacks.

Source Roadmap:
---------------
```
bin		System/user commands.

cddl		Various commands and libraries under the Common Development
		and Distribution License.

contrib		Packages contributed by 3rd parties.

crypto		Cryptography stuff (see crypto/README).

etc		Template files for /etc.

gnu		Commands and libraries under the GNU General Public License
		(GPL) or Lesser General Public License (LGPL).  Please see
		gnu/COPYING* for more information.

include		System include files.

kerberos5	Kerberos5 (Heimdal) package.

lib		System libraries.

libexec		System daemons.

release		Release building Makefile & associated tools.

rescue		Build system for statically linked /rescue utilities.

sbin		System commands.

secure		Cryptographic libraries and commands.

share		Shared resources.

stand		Boot loader sources.

sys		Kernel sources.

sys/<arch>/conf Kernel configuration files. GENERIC is the configuration
		used in release builds. NOTES contains documentation of
		all possible entries.

tests		Regression tests which can be run by Kyua.  See tests/README
		for additional information.

tools		Utilities for regression testing and miscellaneous tasks.

usr.bin		User commands.

usr.sbin	System administration commands.
```

For information on synchronizing your source tree with one or more of
the FreeBSD Project's development branches, please see:

  https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/current-stable.html
