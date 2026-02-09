// SPDX-License-Identifier: GPL-2.0-or-later
/* Router advertisement
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_SOCKOPT_H
#define _ZEBRA_SOCKOPT_H

#include "sockunion.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int setsockopt_so_recvbuf(int sock, int size);
extern int setsockopt_so_sendbuf(const int sock, int size);
extern int getsockopt_so_sendbuf(const int sock);
extern int getsockopt_so_recvbuf(const int sock);

extern int setsockopt_ipv6_pktinfo(int sock, int val);
extern int setsockopt_ipv6_multicast_hops(int sock, int val);
extern int setsockopt_ipv6_unicast_hops(int sock, int val);
extern int setsockopt_ipv6_hoplimit(int sock, int val);
extern int setsockopt_ipv6_multicast_loop(int sock, int val);
extern int setsockopt_ipv6_tclass(int sock, int tclass);

#define SOPT_SIZE_CMSG_PKTINFO_IPV6() (sizeof(struct in6_pktinfo));

/*
 * Size defines for control messages used to get ifindex.  We define
 * values for each method, and define a macro that can be used by code
 * that is unaware of which method is in use.
 * These values are without any alignment needed (see CMSG_SPACE in RFC3542).
 */
#if defined(IP_PKTINFO)
/* Linux in_pktinfo. */
#define SOPT_SIZE_CMSG_PKTINFO_IPV4()  (CMSG_SPACE(sizeof(struct in_pktinfo)))
/* XXX This should perhaps be defined even if IP_PKTINFO is not. */
#define SOPT_SIZE_CMSG_PKTINFO(af)                                             \
  ((af == AF_INET) ? SOPT_SIZE_CMSG_PKTINFO_IPV4() \
                   : SOPT_SIZE_CMSG_PKTINFO_IPV6()
#endif /* IP_PKTINFO */

#if defined(IP_RECVIF)
/* BSD/Solaris */

#define SOPT_SIZE_CMSG_RECVIF_IPV4()	(sizeof(struct sockaddr_dl))
#endif /* IP_RECVIF */

/* SOPT_SIZE_CMSG_IFINDEX_IPV4 - portable type */
#if defined(SOPT_SIZE_CMSG_PKTINFO)
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() SOPT_SIZE_CMSG_PKTINFO_IPV4()
#elif defined(SOPT_SIZE_CMSG_RECVIF_IPV4)
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() SOPT_SIZE_CMSG_RECVIF_IPV4()
#else  /* Nothing available */
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() (sizeof(char *))
#endif /* SOPT_SIZE_CMSG_IFINDEX_IPV4 */

#define SOPT_SIZE_CMSG_IFINDEX(af)                                             \
  (((af) == AF_INET) : SOPT_SIZE_CMSG_IFINDEX_IPV4() \
                    ? SOPT_SIZE_CMSG_PKTINFO_IPV6())

/*
 * If not defined then define the value for `TCP_MD5SIG_MAXKEYLEN`. This seems
 * to be unavailable for NetBSD 8, FreeBSD 11 and FreeBSD 12.
 *
 * The value below was copied from `linux/tcp.h` from the Linux kernel headers.
 */
#ifndef TCP_MD5SIG_MAXKEYLEN
#define TCP_MD5SIG_MAXKEYLEN 80
#endif

extern int setsockopt_ipv4_multicast_if(int sock, struct in_addr if_addr,
					ifindex_t ifindex);
extern int setsockopt_ipv4_multicast(int sock, int optname,
				     struct in_addr if_addr,
				     unsigned int mcast_addr,
				     ifindex_t ifindex);
extern int setsockopt_ipv4_multicast_loop(int sock, uint8_t val);

extern int setsockopt_ipv4_tos(int sock, int tos);

/* Ask for, and get, ifindex, by whatever method is supported. */
extern int setsockopt_ifindex(int af, int sock, ifindex_t val);
extern ifindex_t getsockopt_ifindex(int af, struct msghdr *msgh);

/* swab the fields in iph between the host order and system order expected
 * for IP_HDRINCL.
 */
extern void sockopt_iphdrincl_swab_htosys(struct ip *iph);
extern void sockopt_iphdrincl_swab_systoh(struct ip *iph);

extern int sockopt_tcp_rtt(int sock);

/*
 * TCP MD5 signature option. This option allows TCP MD5 to be enabled on
 * addresses.
 *
 * sock
 *    Socket to enable option on.
 *
 * su
 *    Sockunion specifying address to enable option on.
 *
 * password
 *    MD5 auth password
 */
extern int sockopt_tcp_signature(int sock, union sockunion *su,
				 const char *password);

/*
 * Extended TCP MD5 signature option. This option allows TCP MD5 to be enabled
 * on prefixes.
 *
 * sock
 *    Socket to enable option on.
 *
 * su
 *    Sockunion specifying address (or prefix) to enable option on.
 *
 * prefixlen
 *    0    - su is an address; fall back to non-extended mode
 *    Else - su is a prefix; prefixlen is the mask length
 *
 * password
 *    MD5 auth password
 */
extern int sockopt_tcp_signature_ext(int sock, union sockunion *su,
				     uint16_t prefixlen, const char *password);

/*
 * set TCP max segment size. This option allows user to configure
 * max segment size for TCP session
 *
 * sock
 *    Socket to enable option on.
 *
 * tcp_maxseg
 *    value used for TCP segment size negotiation during SYN
 */
extern int sockopt_tcp_mss_set(int sock, int tcp_maxseg);

/*
 * get TCP max segment size. This option allows user to get
 * the segment size for TCP session
 *
 * sock
 *    Socket to get max segement size.
 */
extern int sockopt_tcp_mss_get(int sock);

/*
 * Configure TCP keepalive for a given socket
 *
 * sock
 *   Socket to enable keepalive option on.
 *
 * keepalive_idle
 *   number of seconds a connection needs to be idle
 *   before sending out keep-alive proves
 *
 * keepalive_intvl
 *   number of seconds between TCP keep-alive probes
 *
 * keepalive_probes
 *   max number of probers to send before giving up
 *   and killing tcp connection
 */
extern int setsockopt_tcp_keepalive(int sock, uint16_t keepalive_idle,
				    uint16_t keepalive_intvl,
				    uint16_t keepalive_probes);

/*
 * Set IP_TRANSPARENT option to socket
 *
 * sock
 *    Socket to enable option on.
 */
extern void sockopt_ip_transparent(int sock);

/*
 * TCP-AO (TCP Authentication Option, RFC 5925) key and API.
 * When HAVE_DECL_TCP_AO_ADD_KEY is set, the following can be used to
 * configure TCP-AO keys on a socket for a given peer address/prefix.
 */
#define TCP_AO_MAXKEYLEN 80

enum tcp_ao_algorithm {
	TCP_AO_ALG_HMAC_SHA1 = 0,
	TCP_AO_ALG_CMAC_AES128,
	TCP_AO_ALG_MAX
};

struct frr_tcp_ao_key {
	uint8_t send_id;
	uint8_t recv_id;
	const uint8_t *key;
	uint16_t keylen;
	enum tcp_ao_algorithm algorithm;
	int preference; /* -1 deprecated, 0 normal, 1 preferred */
};

/*
 * Add TCP-AO keys to a socket for the given peer address/prefix.
 * keys[] has nkeys entries. current_key_idx and rnext_key_idx are
 * indices into keys[] for the current and next keys (use -1 for none).
 * Returns 0 on success, -1 on error, -2 if TCP-AO is not supported.
 */
extern int sockopt_tcp_ao_add_keys(int sock, union sockunion *su,
				  uint16_t prefixlen,
				  const struct frr_tcp_ao_key *keys, int nkeys,
				  int current_key_idx, int rnext_key_idx);

/*
 * Remove TCP-AO keys from a socket for the given peer address/prefix.
 * keys[] has nkeys entries (only send_id and recv_id are used per key).
 * Returns 0 on success, -1 on error, -2 if TCP-AO is not supported.
 */
extern int sockopt_tcp_ao_del_keys(int sock, union sockunion *su,
				  uint16_t prefixlen,
				  const struct frr_tcp_ao_key *keys, int nkeys);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_SOCKOPT_H */
