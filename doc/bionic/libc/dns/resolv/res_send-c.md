Response:
The user wants a summary of the functionality of the provided C source code file `res_send.c`. This file is part of Android's Bionic libc and deals with sending DNS queries and receiving responses.

Here's a breakdown of the steps to generate the summary:

1. **Identify the core purpose:** The filename and initial comments indicate this file handles sending DNS requests.
2. **Analyze the key functions:** Look for functions that perform the main operations. `res_nsend`, `send_vc`, and `send_dg` are likely candidates.
3. **Understand the underlying mechanisms:** The code uses sockets (both UDP and TCP) to communicate with DNS servers.
4. **Note the retry and timeout logic:** The code includes mechanisms to retry queries and handle timeouts.
5. **Recognize the caching interaction:** The code checks a DNS cache before sending requests.
6. **Consider the role of `res_state`:** This structure holds the resolver configuration and state.
7. **Summarize the different paths:**  The code has separate paths for UDP and TCP communication.
8. **Mention the error handling:** The code needs to handle network errors and DNS response errors.
9. **Highlight Android-specific aspects:** Although the base code is from NetBSD, the presence of `#ifdef ANDROID_CHANGES` suggests Android-specific customizations.
10. **Combine the observations into a concise summary.**
这是 `bionic/libc/dns/resolv/res_send.c` 源代码文件的第一部分，其主要功能可以归纳为：

**核心功能：发送 DNS 查询并接收响应。**

具体来说，该文件实现了以下关键功能：

1. **发送 DNS 查询报文:**
   - 封装 DNS 查询信息到数据包中。
   - 支持通过 UDP (datagram) 或 TCP (virtual circuit) 两种方式发送查询。
   - 根据配置（`statp->options` 中的 `RES_USEVC` 和查询报文大小）选择合适的传输协议。

2. **处理 DNS 服务器地址:**
   - 管理和轮询配置的 DNS 服务器列表 (`statp->nsaddr_list`)。
   - 支持通过 `RES_ROTATE` 选项轮换使用的 DNS 服务器，以实现负载均衡。
   - 维护内部的 DNS 服务器地址缓存 (`EXT(statp).ext->nsaddrs`)，并在配置更改时更新。

3. **实现查询重试机制:**
   - 根据 `statp->retry` 配置，在没有收到响应或发生错误时重试查询。

4. **处理超时:**
   - 为 DNS 查询设置超时时间，避免无限等待。
   - 超时时间根据配置 (`params->base_timeout_msec` 或旧的计算方式) 和 DNS 服务器索引动态调整。

5. **集成 DNS 缓存:**
   - 在发送查询前先查找本地 DNS 缓存 (`_resolv_cache_lookup`)，如果找到匹配的记录则直接返回缓存结果。
   - 如果缓存中没有找到，并且查询成功，则将响应添加到缓存 (`_resolv_cache_add`)。
   - 如果查询失败，则通知缓存查询失败 (`_resolv_cache_query_failed`)。

6. **实现 TCP 连接管理:**
   - 建立和维护与 DNS 服务器的 TCP 连接 (`send_vc`)。
   - 处理 TCP 连接的建立、数据发送、数据接收以及连接重置等情况。
   - 支持通过 `connect_with_timeout` 函数设置连接超时。

7. **实现 UDP 通信:**
   - 通过 UDP 数据报发送和接收 DNS 查询和响应 (`send_dg`)。
   - 支持通过 `retrying_poll` 函数等待 UDP 响应，并处理超时。

8. **处理查询和响应 Hook 函数:**
   - 提供了 `qhook` (query hook) 和 `rhook` (response hook) 机制，允许用户在查询发送前和响应接收后执行自定义操作。

9. **统计信息收集:**
   - 收集 DNS 查询的统计信息，例如请求发送时间、响应码、延迟等，并更新到缓存统计信息中。

10. **源端口随机化 (Android 特性):**
    - 在建立 UDP 或 TCP 连接时，尝试绑定到一个随机的本地端口，提高安全性。

**与 Android 功能的关系举例：**

- **网络连接:** 当 Android 应用需要解析域名时（例如，访问一个网站），它会通过 Bionic libc 的 DNS 解析函数发起请求。`res_send.c` 中的代码负责将这个请求发送到配置的 DNS 服务器。
- **应用层 DNS 查询:**  无论是使用 Java 的 `InetAddress.getByName()` 还是 NDK 的 `getaddrinfo`，最终都会调用到 Bionic libc 的 DNS 解析相关函数，从而使用到 `res_send.c` 中的功能。
- **热点连接:** Android 设备连接到 Wi-Fi 热点时，可能会通过 DHCP 获取 DNS 服务器地址。这些地址会被传递给 Bionic libc 的 DNS 解析器，然后被 `res_send.c` 使用。

**总结来说，`res_send.c` 是 Android 系统中负责将 DNS 查询发送到 DNS 服务器并接收响应的核心模块，是网络通信的基础组成部分。**

在接下来的第 2 部分中，很可能会包含 `send_dg` 函数的剩余部分，以及错误处理、调试输出等相关的代码。

### 提示词
```
这是目录为bionic/libc/dns/resolv/res_send.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*	$NetBSD: res_send.c,v 1.9 2006/01/24 17:41:25 christos Exp $	*/

/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#ifdef notdef
static const char sccsid[] = "@(#)res_send.c	8.1 (Berkeley) 6/4/93";
static const char rcsid[] = "Id: res_send.c,v 1.5.2.2.4.5 2004/08/10 02:19:56 marka Exp";
#else
__RCSID("$NetBSD: res_send.c,v 1.9 2006/01/24 17:41:25 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * Send query to name server and wait for reply.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#ifdef ANDROID_CHANGES
#include "resolv_netid.h"
#include "resolv_private.h"
#include "private/android_filesystem_config.h"
#else
#include <resolv.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/eventlib.h>

#include <resolv_cache.h>

#include <async_safe/log.h>

#ifndef DE_CONST
#define DE_CONST(c,v)   v = ((c) ? \
    strchr((const void *)(c), *(const char *)(const void *)(c)) : NULL)
#endif

/* Options.  Leave them on. */
#ifndef DEBUG
#define DEBUG
#endif
#include "res_debug.h"
#include "res_private.h"
#include "resolv_stats.h"

#define EXT(res) ((res)->_u._ext)
#define DBG 0

/* Forward. */

static int		get_salen __P((const struct sockaddr *));
static struct sockaddr * get_nsaddr __P((res_state, size_t));
static int		send_vc(res_state, struct __res_params *params, const u_char *, int,
				u_char *, int, int *, int, time_t *, int *, int *);
static int		send_dg(res_state, struct __res_params *params, const u_char *, int,
				u_char *, int, int *, int, int *, int *, time_t *, int *, int *);
static void		Aerror(const res_state, FILE *, const char *, int,
			       const struct sockaddr *, int);
static void		Perror(const res_state, FILE *, const char *, int);
static int		sock_eq(struct sockaddr *, struct sockaddr *);
void res_pquery(const res_state, const u_char *, int, FILE *);
static int connect_with_timeout(int sock, const struct sockaddr *nsap,
			socklen_t salen, const struct timespec timeout);
static int retrying_poll(const int sock, short events, const struct timespec* finish);

/* BIONIC-BEGIN: implement source port randomization */
typedef union {
    struct sockaddr      sa;
    struct sockaddr_in   sin;
    struct sockaddr_in6  sin6;
} _sockaddr_union;

static int
random_bind( int  s, int  family )
{
    _sockaddr_union  u;
    int              j;
    socklen_t        slen;

    /* clear all, this also sets the IP4/6 address to 'any' */
    memset( &u, 0, sizeof u );

    switch (family) {
        case AF_INET:
            u.sin.sin_family = family;
            slen             = sizeof u.sin;
            break;
        case AF_INET6:
            u.sin6.sin6_family = family;
            slen               = sizeof u.sin6;
            break;
        default:
            errno = EPROTO;
            return -1;
    }

    /* first try to bind to a random source port a few times */
    for (j = 0; j < 10; j++) {
        /* find a random port between 1025 .. 65534 */
        int  port = 1025 + (res_randomid() % (65535-1025));
        if (family == AF_INET)
            u.sin.sin_port = htons(port);
        else
            u.sin6.sin6_port = htons(port);

        if ( !bind( s, &u.sa, slen ) )
            return 0;
    }

    /* nothing after 10 tries, our network table is probably busy */
    /* let the system decide which port is best */
    if (family == AF_INET)
        u.sin.sin_port = 0;
    else
        u.sin6.sin6_port = 0;

    return bind( s, &u.sa, slen );
}
/* BIONIC-END */

static const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;

/* Public. */

/* int
 * res_isourserver(ina)
 *	looks up "ina" in _res.ns_addr_list[]
 * returns:
 *	0  : not found
 *	>0 : found
 * author:
 *	paul vixie, 29may94
 */
__LIBC_HIDDEN__ int
res_ourserver_p(const res_state statp, const struct sockaddr *sa) {
	const struct sockaddr_in *inp, *srv;
	const struct sockaddr_in6 *in6p, *srv6;
	int ns;

	switch (sa->sa_family) {
	case AF_INET:
		inp = (const struct sockaddr_in *)(const void *)sa;
		for (ns = 0;  ns < statp->nscount;  ns++) {
			srv = (struct sockaddr_in *)(void *)get_nsaddr(statp, (size_t)ns);
			if (srv->sin_family == inp->sin_family &&
			    srv->sin_port == inp->sin_port &&
			    (srv->sin_addr.s_addr == INADDR_ANY ||
			     srv->sin_addr.s_addr == inp->sin_addr.s_addr))
				return (1);
		}
		break;
	case AF_INET6:
		if (EXT(statp).ext == NULL)
			break;
		in6p = (const struct sockaddr_in6 *)(const void *)sa;
		for (ns = 0;  ns < statp->nscount;  ns++) {
			srv6 = (struct sockaddr_in6 *)(void *)get_nsaddr(statp, (size_t)ns);
			if (srv6->sin6_family == in6p->sin6_family &&
			    srv6->sin6_port == in6p->sin6_port &&
#ifdef HAVE_SIN6_SCOPE_ID
			    (srv6->sin6_scope_id == 0 ||
			     srv6->sin6_scope_id == in6p->sin6_scope_id) &&
#endif
			    (IN6_IS_ADDR_UNSPECIFIED(&srv6->sin6_addr) ||
			     IN6_ARE_ADDR_EQUAL(&srv6->sin6_addr, &in6p->sin6_addr)))
				return (1);
		}
		break;
	default:
		break;
	}
	return (0);
}

/* int
 * res_nameinquery(name, type, class, buf, eom)
 *	look for (name,type,class) in the query section of packet (buf,eom)
 * requires:
 *	buf + HFIXEDSZ <= eom
 * returns:
 *	-1 : format error
 *	0  : not found
 *	>0 : found
 * author:
 *	paul vixie, 29may94
 */
int
res_nameinquery(const char *name, int type, int class,
		const u_char *buf, const u_char *eom)
{
	const u_char *cp = buf + HFIXEDSZ;
	int qdcount = ntohs(((const HEADER*)(const void *)buf)->qdcount);

	while (qdcount-- > 0) {
		char tname[MAXDNAME+1];
		int n, ttype, tclass;

		n = dn_expand(buf, eom, cp, tname, sizeof tname);
		if (n < 0)
			return (-1);
		cp += n;
		if (cp + 2 * INT16SZ > eom)
			return (-1);
		ttype = ns_get16(cp); cp += INT16SZ;
		tclass = ns_get16(cp); cp += INT16SZ;
		if (ttype == type && tclass == class &&
		    ns_samename(tname, name) == 1)
			return (1);
	}
	return (0);
}

/* int
 * res_queriesmatch(buf1, eom1, buf2, eom2)
 *	is there a 1:1 mapping of (name,type,class)
 *	in (buf1,eom1) and (buf2,eom2)?
 * returns:
 *	-1 : format error
 *	0  : not a 1:1 mapping
 *	>0 : is a 1:1 mapping
 * author:
 *	paul vixie, 29may94
 */
int
res_queriesmatch(const u_char *buf1, const u_char *eom1,
		 const u_char *buf2, const u_char *eom2)
{
	const u_char *cp = buf1 + HFIXEDSZ;
	int qdcount = ntohs(((const HEADER*)(const void *)buf1)->qdcount);

	if (buf1 + HFIXEDSZ > eom1 || buf2 + HFIXEDSZ > eom2)
		return (-1);

	/*
	 * Only header section present in replies to
	 * dynamic update packets.
	 */
	if ((((const HEADER *)(const void *)buf1)->opcode == ns_o_update) &&
	    (((const HEADER *)(const void *)buf2)->opcode == ns_o_update))
		return (1);

	if (qdcount != ntohs(((const HEADER*)(const void *)buf2)->qdcount))
		return (0);
	while (qdcount-- > 0) {
		char tname[MAXDNAME+1];
		int n, ttype, tclass;

		n = dn_expand(buf1, eom1, cp, tname, sizeof tname);
		if (n < 0)
			return (-1);
		cp += n;
		if (cp + 2 * INT16SZ > eom1)
			return (-1);
		ttype = ns_get16(cp);	cp += INT16SZ;
		tclass = ns_get16(cp); cp += INT16SZ;
		if (!res_nameinquery(tname, ttype, tclass, buf2, eom2))
			return (0);
	}
	return (1);
}

int
res_nsend(res_state statp,
	  const u_char *buf, int buflen, u_char *ans, int anssiz)
{
	int gotsomewhere, terrno, try, v_circuit, resplen, ns, n;
	char abuf[NI_MAXHOST];
	ResolvCacheStatus     cache_status = RESOLV_CACHE_UNSUPPORTED;

	if (anssiz < HFIXEDSZ) {
		errno = EINVAL;
		return (-1);
	}
	DprintQ((statp->options & RES_DEBUG) || (statp->pfcode & RES_PRF_QUERY),
		(stdout, ";; res_send()\n"), buf, buflen);
	v_circuit = (statp->options & RES_USEVC) || buflen > PACKETSZ;
	gotsomewhere = 0;
	terrno = ETIMEDOUT;

	int  anslen = 0;
	cache_status = _resolv_cache_lookup(
			statp->netid, buf, buflen,
			ans, anssiz, &anslen);

	if (cache_status == RESOLV_CACHE_FOUND) {
		return anslen;
	} else if (cache_status != RESOLV_CACHE_UNSUPPORTED) {
		// had a cache miss for a known network, so populate the thread private
		// data so the normal resolve path can do its thing
		_resolv_populate_res_for_net(statp);
	}
	if (statp->nscount == 0) {
		// We have no nameservers configured, so there's no point trying.
		// Tell the cache the query failed, or any retries and anyone else asking the same
		// question will block for PENDING_REQUEST_TIMEOUT seconds instead of failing fast.
		_resolv_cache_query_failed(statp->netid, buf, buflen);
		errno = ESRCH;
		return (-1);
	}

	/*
	 * If the ns_addr_list in the resolver context has changed, then
	 * invalidate our cached copy and the associated timing data.
	 */
	if (EXT(statp).nscount != 0) {
		int needclose = 0;
		struct sockaddr_storage peer;
		socklen_t peerlen;

		if (EXT(statp).nscount != statp->nscount) {
			needclose++;
		} else {
			for (ns = 0; ns < statp->nscount; ns++) {
				if (statp->nsaddr_list[ns].sin_family &&
				    !sock_eq((struct sockaddr *)(void *)&statp->nsaddr_list[ns],
					     (struct sockaddr *)(void *)&EXT(statp).ext->nsaddrs[ns])) {
					needclose++;
					break;
				}

				if (EXT(statp).nssocks[ns] == -1)
					continue;
				peerlen = sizeof(peer);
				if (getpeername(EXT(statp).nssocks[ns],
				    (struct sockaddr *)(void *)&peer, &peerlen) < 0) {
					needclose++;
					break;
				}
				if (!sock_eq((struct sockaddr *)(void *)&peer,
				    get_nsaddr(statp, (size_t)ns))) {
					needclose++;
					break;
				}
			}
		}
		if (needclose) {
			res_nclose(statp);
			EXT(statp).nscount = 0;
		}
	}

	/*
	 * Maybe initialize our private copy of the ns_addr_list.
	 */
	if (EXT(statp).nscount == 0) {
		for (ns = 0; ns < statp->nscount; ns++) {
			EXT(statp).nstimes[ns] = RES_MAXTIME;
			EXT(statp).nssocks[ns] = -1;
			if (!statp->nsaddr_list[ns].sin_family)
				continue;
			EXT(statp).ext->nsaddrs[ns].sin =
				 statp->nsaddr_list[ns];
		}
		EXT(statp).nscount = statp->nscount;
	}

	/*
	 * Some resolvers want to even out the load on their nameservers.
	 * Note that RES_BLAST overrides RES_ROTATE.
	 */
	if ((statp->options & RES_ROTATE) != 0U &&
	    (statp->options & RES_BLAST) == 0U) {
		union res_sockaddr_union inu;
		struct sockaddr_in ina;
		int lastns = statp->nscount - 1;
		int fd;
		u_int16_t nstime;

		if (EXT(statp).ext != NULL)
			inu = EXT(statp).ext->nsaddrs[0];
		ina = statp->nsaddr_list[0];
		fd = EXT(statp).nssocks[0];
		nstime = EXT(statp).nstimes[0];
		for (ns = 0; ns < lastns; ns++) {
			if (EXT(statp).ext != NULL)
				EXT(statp).ext->nsaddrs[ns] =
					EXT(statp).ext->nsaddrs[ns + 1];
			statp->nsaddr_list[ns] = statp->nsaddr_list[ns + 1];
			EXT(statp).nssocks[ns] = EXT(statp).nssocks[ns + 1];
			EXT(statp).nstimes[ns] = EXT(statp).nstimes[ns + 1];
		}
		if (EXT(statp).ext != NULL)
			EXT(statp).ext->nsaddrs[lastns] = inu;
		statp->nsaddr_list[lastns] = ina;
		EXT(statp).nssocks[lastns] = fd;
		EXT(statp).nstimes[lastns] = nstime;
	}

	/*
	 * Send request, RETRY times, or until successful.
	 */
	for (try = 0; try < statp->retry; try++) {
	    struct __res_stats stats[MAXNS];
	    struct __res_params params;
	    int revision_id = _resolv_cache_get_resolver_stats(statp->netid, &params, stats);
	    bool usable_servers[MAXNS];
	    android_net_res_stats_get_usable_servers(&params, stats, statp->nscount,
		    usable_servers);

	    for (ns = 0; ns < statp->nscount; ns++) {
		if (!usable_servers[ns]) continue;
		struct sockaddr *nsap;
		int nsaplen;
		time_t now = 0;
		int rcode = RCODE_INTERNAL_ERROR;
		int delay = 0;
		nsap = get_nsaddr(statp, (size_t)ns);
		nsaplen = get_salen(nsap);
		statp->_flags &= ~RES_F_LASTMASK;
		statp->_flags |= (ns << RES_F_LASTSHIFT);

 same_ns:
		if (statp->qhook) {
			int done = 0, loops = 0;

			do {
				res_sendhookact act;

				act = (*statp->qhook)(&nsap, &buf, &buflen,
						      ans, anssiz, &resplen);
				switch (act) {
				case res_goahead:
					done = 1;
					break;
				case res_nextns:
					res_nclose(statp);
					goto next_ns;
				case res_done:
					if (cache_status == RESOLV_CACHE_NOTFOUND) {
						_resolv_cache_add(statp->netid, buf, buflen,
								ans, resplen);
					}
					return (resplen);
				case res_modified:
					/* give the hook another try */
					if (++loops < 42) /*doug adams*/
						break;
					/*FALLTHROUGH*/
				case res_error:
					/*FALLTHROUGH*/
				default:
					goto fail;
				}
			} while (!done);
		}

		Dprint(((statp->options & RES_DEBUG) &&
			getnameinfo(nsap, (socklen_t)nsaplen, abuf, sizeof(abuf),
				NULL, 0, niflags) == 0),
				(stdout, ";; Querying server (# %d) address = %s\n",
				ns + 1, abuf));


		if (v_circuit) {
			/* Use VC; at most one attempt per server. */
			try = statp->retry;

			n = send_vc(statp, &params, buf, buflen, ans, anssiz, &terrno,
				    ns, &now, &rcode, &delay);

			/*
			 * Only record stats the first time we try a query. This ensures that
			 * queries that deterministically fail (e.g., a name that always returns
			 * SERVFAIL or times out) do not unduly affect the stats.
			 */
			if (try == 0) {
				struct __res_sample sample;
				_res_stats_set_sample(&sample, now, rcode, delay);
				_resolv_cache_add_resolver_stats_sample(statp->netid, revision_id,
					ns, &sample, params.max_samples);
			}

			if (DBG) {
				async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
					"used send_vc %d\n", n);
			}

			if (n < 0)
				goto fail;
			if (n == 0)
				goto next_ns;
			resplen = n;
		} else {
			/* Use datagrams. */
			if (DBG) {
				async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "using send_dg\n");
			}

			n = send_dg(statp, &params, buf, buflen, ans, anssiz, &terrno,
				    ns, &v_circuit, &gotsomewhere, &now, &rcode, &delay);

			/* Only record stats the first time we try a query. See above. */
			if (try == 0) {
				struct __res_sample sample;
				_res_stats_set_sample(&sample, now, rcode, delay);
				_resolv_cache_add_resolver_stats_sample(statp->netid, revision_id,
					ns, &sample, params.max_samples);
			}

			if (DBG) {
				async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "used send_dg %d\n",n);
			}

			if (n < 0)
				goto fail;
			if (n == 0)
				goto next_ns;
			if (DBG) {
				async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "time=%ld\n",
						  time(NULL));
			}
			if (v_circuit)
				goto same_ns;
			resplen = n;
		}

		Dprint((statp->options & RES_DEBUG) ||
		       ((statp->pfcode & RES_PRF_REPLY) &&
			(statp->pfcode & RES_PRF_HEAD1)),
		       (stdout, ";; got answer:\n"));

		DprintQ((statp->options & RES_DEBUG) ||
			(statp->pfcode & RES_PRF_REPLY),
			(stdout, "%s", ""),
			ans, (resplen > anssiz) ? anssiz : resplen);

		if (cache_status == RESOLV_CACHE_NOTFOUND) {
		    _resolv_cache_add(statp->netid, buf, buflen,
				      ans, resplen);
		}
		/*
		 * If we have temporarily opened a virtual circuit,
		 * or if we haven't been asked to keep a socket open,
		 * close the socket.
		 */
		if ((v_circuit && (statp->options & RES_USEVC) == 0U) ||
		    (statp->options & RES_STAYOPEN) == 0U) {
			res_nclose(statp);
		}
		if (statp->rhook) {
			int done = 0, loops = 0;

			do {
				res_sendhookact act;

				act = (*statp->rhook)(nsap, buf, buflen,
						      ans, anssiz, &resplen);
				switch (act) {
				case res_goahead:
				case res_done:
					done = 1;
					break;
				case res_nextns:
					res_nclose(statp);
					goto next_ns;
				case res_modified:
					/* give the hook another try */
					if (++loops < 42) /*doug adams*/
						break;
					/*FALLTHROUGH*/
				case res_error:
					/*FALLTHROUGH*/
				default:
					goto fail;
				}
			} while (!done);

		}
		return (resplen);
 next_ns: ;
	   } /*foreach ns*/
	} /*foreach retry*/
	res_nclose(statp);
	if (!v_circuit) {
		if (!gotsomewhere)
			errno = ECONNREFUSED;	/* no nameservers found */
		else
			errno = ETIMEDOUT;	/* no answer obtained */
	} else
		errno = terrno;

	_resolv_cache_query_failed(statp->netid, buf, buflen);

	return (-1);
 fail:

	_resolv_cache_query_failed(statp->netid, buf, buflen);
	res_nclose(statp);
	return (-1);
}

/* Private */

static int
get_salen(const struct sockaddr *sa)
{

#ifdef HAVE_SA_LEN
	/* There are people do not set sa_len.  Be forgiving to them. */
	if (sa->sa_len)
		return (sa->sa_len);
#endif

	if (sa->sa_family == AF_INET)
		return (sizeof(struct sockaddr_in));
	else if (sa->sa_family == AF_INET6)
		return (sizeof(struct sockaddr_in6));
	else
		return (0);	/* unknown, die on connect */
}

/*
 * pick appropriate nsaddr_list for use.  see res_init() for initialization.
 */
static struct sockaddr *
get_nsaddr(res_state statp, size_t n)
{

	if (!statp->nsaddr_list[n].sin_family && EXT(statp).ext) {
		/*
		 * - EXT(statp).ext->nsaddrs[n] holds an address that is larger
		 *   than struct sockaddr, and
		 * - user code did not update statp->nsaddr_list[n].
		 */
		return (struct sockaddr *)(void *)&EXT(statp).ext->nsaddrs[n];
	} else {
		/*
		 * - user code updated statp->nsaddr_list[n], or
		 * - statp->nsaddr_list[n] has the same content as
		 *   EXT(statp).ext->nsaddrs[n].
		 */
		return (struct sockaddr *)(void *)&statp->nsaddr_list[n];
	}
}

static struct timespec get_timeout(const res_state statp, const struct __res_params* params, const int ns)
{
	int msec;
	if (params->base_timeout_msec != 0) {
		// TODO: scale the timeout by retry attempt and maybe number of servers
		msec = params->base_timeout_msec;
	} else {
		// Legacy algorithm which scales the timeout by nameserver number.
		// For instance, with 4 nameservers: 5s, 2.5s, 5s, 10s
		// This has no effect with 1 or 2 nameservers
		msec = (statp->retrans * 1000) << ns;
		if (ns > 0) {
			msec /= statp->nscount;
		}
		if (msec < 1000) {
			msec = 1000;  // Use at least 100ms
		}
	}
	if (DBG) {
		async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "using timeout of %d msec\n", msec);
	}

	struct timespec result;
	result.tv_sec = msec / 1000;
	result.tv_nsec = (msec % 1000) * 1000000;
	return result;
}

static int
send_vc(res_state statp, struct __res_params* params,
	const u_char *buf, int buflen, u_char *ans, int anssiz,
	int *terrno, int ns, time_t* at, int* rcode, int* delay)
{
	*at = time(NULL);
	*rcode = RCODE_INTERNAL_ERROR;
	*delay = 0;
	const HEADER *hp = (const HEADER *)(const void *)buf;
	HEADER *anhp = (HEADER *)(void *)ans;
	struct sockaddr *nsap;
	int nsaplen;
	int truncating, connreset, resplen, n;
	struct iovec iov[2];
	u_short len;
	u_char *cp;
	void *tmp;

	if (DBG) {
		async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "using send_vc\n");
	}

	nsap = get_nsaddr(statp, (size_t)ns);
	nsaplen = get_salen(nsap);

	connreset = 0;
 same_ns:
	truncating = 0;

	struct timespec now = evNowTime();

	/* Are we still talking to whom we want to talk to? */
	if (statp->_vcsock >= 0 && (statp->_flags & RES_F_VC) != 0) {
		struct sockaddr_storage peer;
		socklen_t size = sizeof peer;
		unsigned old_mark;
		socklen_t mark_size = sizeof(old_mark);
		if (getpeername(statp->_vcsock,
				(struct sockaddr *)(void *)&peer, &size) < 0 ||
		    !sock_eq((struct sockaddr *)(void *)&peer, nsap) ||
			getsockopt(statp->_vcsock, SOL_SOCKET, SO_MARK, &old_mark, &mark_size) < 0 ||
			old_mark != statp->_mark) {
			res_nclose(statp);
			statp->_flags &= ~RES_F_VC;
		}
	}

	if (statp->_vcsock < 0 || (statp->_flags & RES_F_VC) == 0) {
		if (statp->_vcsock >= 0)
			res_nclose(statp);

		statp->_vcsock = socket(nsap->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (statp->_vcsock < 0) {
			switch (errno) {
			case EPROTONOSUPPORT:
#ifdef EPFNOSUPPORT
			case EPFNOSUPPORT:
#endif
			case EAFNOSUPPORT:
				Perror(statp, stderr, "socket(vc)", errno);
				return (0);
			default:
				*terrno = errno;
				Perror(statp, stderr, "socket(vc)", errno);
				return (-1);
			}
		}
		fchown(statp->_vcsock, AID_DNS, -1);
		if (statp->_mark != MARK_UNSET) {
			if (setsockopt(statp->_vcsock, SOL_SOCKET,
				    SO_MARK, &statp->_mark, sizeof(statp->_mark)) < 0) {
				*terrno = errno;
				Perror(statp, stderr, "setsockopt", errno);
				return -1;
			}
		}
		errno = 0;
		if (random_bind(statp->_vcsock,nsap->sa_family) < 0) {
			*terrno = errno;
			Aerror(statp, stderr, "bind/vc", errno, nsap,
			    nsaplen);
			res_nclose(statp);
			return (0);
		}
		if (connect_with_timeout(statp->_vcsock, nsap, (socklen_t)nsaplen,
				get_timeout(statp, params, ns)) < 0) {
			*terrno = errno;
			Aerror(statp, stderr, "connect/vc", errno, nsap,
			    nsaplen);
			res_nclose(statp);
			/*
			 * The way connect_with_timeout() is implemented prevents us from reliably
			 * determining whether this was really a timeout or e.g. ECONNREFUSED. Since
			 * currently both cases are handled in the same way, there is no need to
			 * change this (yet). If we ever need to reliably distinguish between these
			 * cases, both connect_with_timeout() and retrying_poll() need to be
			 * modified, though.
			 */
			*rcode = RCODE_TIMEOUT;
			return (0);
		}
		statp->_flags |= RES_F_VC;
	}

	/*
	 * Send length & message
	 */
	ns_put16((u_short)buflen, (u_char*)(void *)&len);
	iov[0] = evConsIovec(&len, INT16SZ);
	DE_CONST(buf, tmp);
	iov[1] = evConsIovec(tmp, (size_t)buflen);
	if (writev(statp->_vcsock, iov, 2) != (INT16SZ + buflen)) {
		*terrno = errno;
		Perror(statp, stderr, "write failed", errno);
		res_nclose(statp);
		return (0);
	}
	/*
	 * Receive length & response
	 */
 read_len:
	cp = ans;
	len = INT16SZ;
	while ((n = read(statp->_vcsock, (char *)cp, (size_t)len)) > 0) {
		cp += n;
		if ((len -= n) == 0)
			break;
	}
	if (n <= 0) {
		*terrno = errno;
		Perror(statp, stderr, "read failed", errno);
		res_nclose(statp);
		/*
		 * A long running process might get its TCP
		 * connection reset if the remote server was
		 * restarted.  Requery the server instead of
		 * trying a new one.  When there is only one
		 * server, this means that a query might work
		 * instead of failing.  We only allow one reset
		 * per query to prevent looping.
		 */
		if (*terrno == ECONNRESET && !connreset) {
			connreset = 1;
			res_nclose(statp);
			goto same_ns;
		}
		res_nclose(statp);
		return (0);
	}
	resplen = ns_get16(ans);
	if (resplen > anssiz) {
		Dprint(statp->options & RES_DEBUG,
		       (stdout, ";; response truncated\n")
		       );
		truncating = 1;
		len = anssiz;
	} else
		len = resplen;
	if (len < HFIXEDSZ) {
		/*
		 * Undersized message.
		 */
		Dprint(statp->options & RES_DEBUG,
		       (stdout, ";; undersized: %d\n", len));
		*terrno = EMSGSIZE;
		res_nclose(statp);
		return (0);
	}
	cp = ans;
	while (len != 0 && (n = read(statp->_vcsock, (char *)cp, (size_t)len)) > 0){
		cp += n;
		len -= n;
	}
	if (n <= 0) {
		*terrno = errno;
		Perror(statp, stderr, "read(vc)", errno);
		res_nclose(statp);
		return (0);
	}

	if (truncating) {
		/*
		 * Flush rest of answer so connection stays in synch.
		 */
		anhp->tc = 1;
		len = resplen - anssiz;
		while (len != 0) {
			char junk[PACKETSZ];

			n = read(statp->_vcsock, junk,
				 (len > sizeof junk) ? sizeof junk : len);
			if (n > 0)
				len -= n;
			else
				break;
		}
		// return size should never exceed container size
		resplen = anssiz;
	}
	/*
	 * If the calling applicating has bailed out of
	 * a previous call and failed to arrange to have
	 * the circuit closed or the server has got
	 * itself confused, then drop the packet and
	 * wait for the correct one.
	 */
	if (hp->id != anhp->id) {
		DprintQ((statp->options & RES_DEBUG) ||
			(statp->pfcode & RES_PRF_REPLY),
			(stdout, ";; old answer (unexpected):\n"),
			ans, resplen);
		goto read_len;
	}

	/*
	 * All is well, or the error is fatal.  Signal that the
	 * next nameserver ought not be tried.
	 */
	if (resplen > 0) {
	    struct timespec done = evNowTime();
	    *delay = _res_stats_calculate_rtt(&done, &now);
	    *rcode = anhp->rcode;
	}
	return (resplen);
}

/* return -1 on error (errno set), 0 on success */
static int
connect_with_timeout(int sock, const struct sockaddr *nsap, socklen_t salen,
	const struct timespec timeout)
{
	int res, origflags;

	origflags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, origflags | O_NONBLOCK);

	res = __connect(sock, nsap, salen);
	if (res < 0 && errno != EINPROGRESS) {
		res = -1;
		goto done;
	}
	if (res != 0) {
		struct timespec now = evNowTime();
		struct timespec finish = evAddTime(now, timeout);
		if (DBG) {
			async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "  %d send_vc\n", sock);
		}

		res = retrying_poll(sock, POLLIN | POLLOUT, &finish);
		if (res <= 0) {
			res = -1;
		}
	}
done:
	fcntl(sock, F_SETFL, origflags);
	if (DBG) {
		async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
			"  %d connect_with_const timeout returning %d\n", sock, res);
	}
	return res;
}

static int
retrying_poll(const int sock, const short events, const struct timespec* finish) {
	struct timespec now, timeout;

retry:
	if (DBG) {
		async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "  %d retrying_poll\n", sock);
	}

	now = evNowTime();
	if (evCmpTime(*finish, now) > 0)
		timeout = evSubTime(*finish, now);
	else
		timeout = evConsTime(0L, 0L);
	struct pollfd fds = { .fd = sock, .events = events };
	int n = ppoll(&fds, 1, &timeout, /*sigmask=*/NULL);
	if (n == 0) {
		if (DBG) {
			async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
				"  %d retrying_poll timeout\n", sock);
		}
		errno = ETIMEDOUT;
		return 0;
	}
	if (n < 0) {
		if (errno == EINTR)
			goto retry;
		if (DBG) {
			async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
				"  %d retrying_poll got error %d\n",sock, n);
		}
		return n;
	}
	if (fds.revents & (POLLIN | POLLOUT | POLLERR)) {
		int error;
		socklen_t len = sizeof(error);
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
			errno = error;
			if (DBG) {
				async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
					"  %d retrying_poll dot error2 %d\n", sock, errno);
			}

			return -1;
		}
	}
	if (DBG) {
		async_safe_format_log(ANDROID_LOG_DEBUG, "libc",
			"  %d retrying_poll returning %d\n",sock, n);
	}

	return n;
}

static int
send_dg(res_state statp, struct __res_params* params,
	const u_char *buf, int buflen, u_char *ans, int anssiz,
	int *terrno, int ns, int *v_circuit, int *gotsomewhere,
	time_t *at, int *rcode, int* delay)
{
	*at = time(NULL);
	*rcode = RCODE_INTERNAL_ERROR;
	*delay = 0;
	const HEADER *hp = (const HEADER *)(const void *)buf;
	HEADER *anhp = (HEADER *)(void *)ans;
	const struct sockaddr *nsap;
	int nsaplen;
	struct timespec now, timeout, finish, done;
	struct sockaddr_storage from;
	socklen_t fromlen;
	int resplen, n, s;

	nsap = get_nsaddr(statp, (size_t)ns);
	nsaplen = get_salen(nsap);
	if (EXT(statp).nssocks[ns] == -1) {
		EXT(statp).nssocks[ns] = socket(nsap->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (EXT(statp).nssocks[ns] < 0) {
			switch (errno) {
			case EPROTONOSUPPORT:
#ifdef EPFNOSUPPORT
			case EPFNOSUPPORT:
#endif
			case EAFNOSUPPORT:
				Perror(statp, stderr, "socket(dg)", errno);
				return (0);
			default:
				*terrno = errno;
				Perror(statp, stderr, "socket(dg)", errno);
				return (-1);
			}
		}

		fchown(EXT(statp).nssocks[ns], AID_DNS, -1);
		if (statp->_mark != MARK_UNSET) {
			if (setsockopt(EXT(statp).nssocks[ns], SOL_SOCKET,
					SO_MARK, &(statp->_mark), sizeof(statp->_mark)) < 0) {
				res_nclose(statp);
				return -1;
			}
		}
#ifndef CANNOT_CONNECT_DGRAM
		/*
		 * On a 4.3BSD+ machine (client and server,
		 * actually), sending to a nameserver datagram
		 * port with no nameserver will cause an
		 * ICMP port unreachable message to be returned.
		 * If our datagram socket is "connected" to the
		 * server, we get an ECONNREFUSED error on the next
		 * socket operation, and select returns if the
		 * error message is received.  We can thus detect
		 * the absence of a nameserver without timing out.
		 */
		if (random_bind(EXT(statp).nssocks[ns], nsap->sa_family) < 0) {
			Aerror(statp, stderr, "bind(dg)", errno, nsap,
			    nsaplen);
			res_nclose(statp);
			return (0);
		}
		if (__connect(EXT(statp).nssocks[ns], nsap, (socklen_t)nsaplen) < 0) {
			Aerror(statp, stderr, "connect(dg)", errno, nsap,
			    nsaplen);
			res_nclose(statp);
			return (0);
		}
#endif /* !CANNOT_CONNECT_DGRAM */
		Dprint(statp->options & RES_DEBUG,
		       (stdout, ";; new DG socket\n"))

	}
	s = EXT(statp).nssocks[ns];
#ifndef CANNOT_CONNECT_DGRAM
	if (send(s, (const char*)buf, (size_t)buflen, 0) != buflen) {
		Perror(statp, stderr, "send", errno);
		res_nclose(statp);
		return (0);
	}
#else /* !CANNOT_CONNECT_DGRAM */
	if (sendto(s, (const char*)buf, buflen, 0, nsap, nsaplen) != buflen)
	{
		Aerror(statp, stderr, "sendto", errno, nsap, nsaplen);
		res_nclose(statp);
		return (0);
	}
#endif /* !CANNOT_CONNECT_DGRAM */

	/*
	 * Wait for reply.
	 */
	timeout = get_timeout(statp, params, ns);
	now = evNowTime();
	finish = evAddTime(now, timeout);
retry:
	n = retrying_poll(s, POLLIN, &finish);

	if (n == 0) {
		*rcode = RCODE_TIMEOUT;
		Dprint(statp->options & RES_DEBUG, (stdout, ";; timeout\n"));
		*gotsomewhere = 1;
		return (0);
	}
	if (n < 0) {
		Perror(statp, st
```