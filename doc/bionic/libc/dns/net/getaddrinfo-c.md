Response:
Let's break down the thought process for analyzing the `getaddrinfo.c` code and generating the detailed response.

**1. Understanding the Request:**

The core request is to understand the functionality of `getaddrinfo.c`, how it relates to Android, how its constituent functions are implemented, its interaction with the dynamic linker, potential usage errors, and how it's invoked by Android frameworks/NDK. The request specifically asks for a summary in this first part.

**2. Initial Reading and Keyword Identification:**

The first step is to quickly scan the code and identify key concepts and function names. Keywords that jump out are:

* `getaddrinfo` (the central function)
* `freeaddrinfo`
* `hints` (the `addrinfo` structure guiding the lookup)
* `res` (the resulting linked list of `addrinfo` structures)
* `hostname`, `servname` (inputs to `getaddrinfo`)
* `PF_INET`, `PF_INET6`, `PF_UNSPEC` (address families)
* `SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_RAW` (socket types)
* `IPPROTO_TCP`, `IPPROTO_UDP` (protocols)
* `DNS`, `/etc/hosts` (name resolution sources)
* `nsswitch.h` (Name Service Switch)
* `android_getaddrinfo_proxy` (Android-specific proxy mechanism)
* `NetdClientDispatch.h` (interaction with the `netd` daemon)
* `dynamic linker` (mentioned in the prompt)
* `libc` functions (like `malloc`, `free`, `strdup`, `memcpy`, `socket`, `close`, etc.)
* `errno`, `EAI_*` (error handling)

**3. High-Level Functionality Identification:**

Based on the keywords and the overall structure, it's clear that `getaddrinfo` is about resolving hostnames and service names into network addresses. It takes hints to filter the results and returns a linked list of `addrinfo` structures, each containing address information.

**4. Categorizing Functionality:**

To structure the detailed explanation, it's helpful to categorize the functions within the file:

* **Core `getaddrinfo` logic:**  `getaddrinfo`, `android_getaddrinfofornet`, `android_getaddrinfofornetcontext` (wrappers with network namespace support).
* **Result creation and management:** `get_ai`, `freeaddrinfo`.
* **Hostname processing:** `explore_fqdn` (DNS lookup), `explore_null` (NULL hostname handling), `explore_numeric` (numeric IP address), `explore_numeric_scope` (scoped IPv6 addresses).
* **Service name processing:** `get_port`, `get_portmatch`, `str2number`.
* **Helper functions:** `find_afd` (address family data), `ip6_str2scopeid` (IPv6 scope ID conversion), `get_canonname`.
* **Android-specific proxy:** `android_getaddrinfo_proxy`.
* **Name Service Switch:** Interactions with `nsswitch.h`, `_files_getaddrinfo`, `_dns_getaddrinfo`.
* **Connectivity Checks (for `AI_ADDRCONFIG`):** `_have_ipv6`, `_have_ipv4`.

**5. Detailed Function Analysis (Example: `getaddrinfo` itself):**

For a core function like `getaddrinfo`, the analysis would involve:

* **Purpose:**  The main entry point for address resolution.
* **Inputs:** `hostname`, `servname`, `hints`.
* **Outputs:**  A linked list of `addrinfo` structures via the `res` pointer.
* **Core Logic:**
    * Handles NULL hostname/servname.
    * Processes `hints` and validates them.
    * Iterates through `explore` table (defining possible socket type/protocol combinations).
    * Calls different "explore" functions based on hostname type (FQDN, numeric, NULL).
    * If FQDN, uses Name Service Switch (`nsdispatch`).
    * Potentially uses the Android proxy (`android_getaddrinfo_proxy`).
    * Handles errors and memory management.
* **Android Relevance:**  The `android_getaddrinfofornet` and `android_getaddrinfofornetcontext` wrappers demonstrate Android's network namespace support. The proxy function is a significant Android addition.

**6. Dynamic Linker Considerations:**

This requires understanding how `getaddrinfo` might depend on other libraries. Key points are:

* **Dependencies:**  It likely depends on `libc.so` itself (standard C library functions) and potentially libraries involved in DNS resolution (though the provided code seems to integrate some of this). The `NetdClientDispatch` suggests interaction with a separate daemon, potentially through an interface defined in a shared library.
* **SO Layout Sample:**  A basic layout would show `libc.so` containing `getaddrinfo`, and potentially another `libnetd_client.so` (or similar name) for the proxy interaction.
* **Linking Process:**  The dynamic linker resolves symbols like `getaddrinfo` and functions in `NetdClientDispatch` at runtime.

**7. Error Scenarios:**

Think about common mistakes developers make when using `getaddrinfo`:

* Passing invalid `hints`.
* Providing neither hostname nor service name.
* Incorrectly handling the returned linked list (memory leaks).
* Not checking the return value for errors.
* Trying to resolve non-existent hostnames.

**8. Framework/NDK Invocation and Frida Hooking:**

* **Framework:**  High-level Android APIs (e.g., `java.net.InetAddress`) eventually call down to native code, including `getaddrinfo`.
* **NDK:**  NDK developers can directly call `getaddrinfo` from their C/C++ code.
* **Frida Hooking:**  Identify the function signature of `getaddrinfo` (or its Android-specific variants) and use Frida's scripting capabilities to intercept calls, inspect arguments, and potentially modify behavior.

**9. Structuring the Response:**

Organize the information logically, starting with a high-level summary, then delving into details for each aspect of the request. Use headings and bullet points for clarity. Provide code examples where relevant (like Frida hooks).

**10. Refinement and Review:**

After drafting the response, review it for accuracy, completeness, and clarity. Ensure that the language is precise and easy to understand. Double-check any assumptions or inferences. For instance, initially, I might overemphasize direct DNS library linking, but a closer look reveals that `getaddrinfo.c` integrates some DNS logic and also uses the Android proxy. The refinement process involves adjusting the focus accordingly.

By following this systematic approach, breaking down the problem into smaller, manageable parts, and iteratively refining the analysis, it's possible to generate a comprehensive and accurate explanation of the `getaddrinfo.c` code.
## bionic/libc/dns/net/getaddrinfo.c 功能归纳 (第 1 部分)

根据提供的源代码片段，`bionic/libc/dns/net/getaddrinfo.c` 文件的主要功能可以归纳为：

**核心功能：将主机名和服务名解析为网络地址信息。**

更具体地说，这个文件实现了 `getaddrinfo` 函数及其相关的辅助功能，用于执行以下任务：

1. **接收主机名 (`hostname`) 和/或服务名 (`servname`) 作为输入。**  主机名可以是域名、IP 地址字符串或 NULL。服务名可以是端口号字符串或服务名称字符串。
2. **接收可选的 `addrinfo` 结构体指针 (`hints`)，用于提供关于期望的地址类型、协议族、套接字类型等信息。** 这允许调用者过滤和控制返回的地址信息。
3. **返回一个指向 `addrinfo` 结构体链表的指针 (`res`)，其中包含了解析后的网络地址信息。** 每个 `addrinfo` 结构体包含一个网络地址 (`ai_addr`) 和其他相关信息，例如地址族 (`ai_family`)、套接字类型 (`ai_socktype`) 和协议 (`ai_protocol`)。
4. **支持多种地址族 (Address Family)，包括 IPv4 (`PF_INET`) 和 IPv6 (`PF_INET6`)。**  也支持 `PF_UNSPEC`，表示可以接受任何地址族。
5. **支持多种套接字类型 (Socket Type)，例如流式套接字 (`SOCK_STREAM`) 和数据报套接字 (`SOCK_DGRAM`)。**
6. **支持多种协议 (Protocol)，例如 TCP (`IPPROTO_TCP`) 和 UDP (`IPPROTO_UDP`)。**
7. **处理各种类型的主机名输入：**
    * **完全限定域名 (FQDN)：**  通过 DNS 查询进行解析。
    * **数字 IP 地址字符串：**  直接转换为二进制地址。
    * **NULL 主机名：**  根据 `hints` 中的 `AI_PASSIVE` 标志，返回通配地址 (0.0.0.0 或 ::) 或回环地址 (127.0.0.1 或 ::1)。
8. **处理服务名输入：**
    * **数字端口号字符串：**  直接转换为端口号。
    * **服务名称字符串：**  通过查询系统服务数据库（例如 `/etc/services`）进行解析。
9. **提供 `freeaddrinfo` 函数用于释放 `getaddrinfo` 分配的 `addrinfo` 结构体链表的内存。**
10. **实现对 `hints` 标志的支持，例如 `AI_PASSIVE`、`AI_CANONNAME`、`AI_NUMERICHOST` 等，以控制解析行为。**
11. **实现与 Android 特性的集成，例如网络命名空间 (network namespace) 和 `netd` 守护进程的交互。**
12. **在 Android 中，提供了一个代理机制 (`android_getaddrinfo_proxy`)，用于将 `getaddrinfo` 请求转发到 `netd` 守护进程进行处理。** 这通常用于跨网络命名空间进行 DNS 解析。
13. **使用 Name Service Switch (NSS) 机制，允许配置不同的解析源，例如本地文件 (`/etc/hosts`) 和 DNS 服务器。**
14. **实现 `AI_ADDRCONFIG` 标志的支持，根据系统是否配置了 IPv4 或 IPv6 地址来过滤返回的地址信息。** （尽管代码注释中提到 bionic 当前不支持 `getifaddrs`，所以使用了检查网络连通性的方法作为替代）。

**与 Android 功能的关系举例说明：**

* **网络连接:**  Android 应用程序需要知道服务器的 IP 地址才能建立网络连接。`getaddrinfo` 是实现这一功能的关键。例如，当一个 Android 应用尝试连接到 `www.google.com` 时，系统会调用 `getaddrinfo` 来获取 `www.google.com` 对应的 IP 地址。
* **网络服务发现:**  某些 Android 应用可能需要发现局域网内的服务。`getaddrinfo` 可以用于解析 Bonjour 或 mDNS 等服务发现协议中返回的主机名。
* **网络权限控制:**  Android 的网络权限模型可能会影响 `getaddrinfo` 的行为。例如，没有网络权限的应用可能无法解析某些主机名。
* **VPN 和网络命名空间:**  Android 支持 VPN 连接和网络命名空间。`getaddrinfo` 需要能够感知当前的网络命名空间，以便进行正确的地址解析。 `android_getaddrinfofornet` 和 `android_getaddrinfofornetcontext` 函数就是为支持网络命名空间而设计的。
* **DNS 解析器配置:**  Android 系统允许用户配置 DNS 服务器。`getaddrinfo` 使用这些配置来执行 DNS 查询。

总而言之，`bionic/libc/dns/net/getaddrinfo.c` 是 Android 系统中网络地址解析的核心组件，它为应用程序提供了将人类可读的主机名和服务名转换为计算机可用的网络地址的能力，是构建网络应用程序的基础。

### 提示词
```
这是目录为bionic/libc/dns/net/getaddrinfo.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: getaddrinfo.c,v 1.82 2006/03/25 12:09:40 rpaulo Exp $	*/
/*	$KAME: getaddrinfo.c,v 1.29 2000/08/31 17:26:57 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Issues to be discussed:
 * - Thread safe-ness must be checked.
 * - Return values.  There are nonstandard return values defined and used
 *   in the source code.  This is because RFC2553 is silent about which error
 *   code must be returned for which situation.
 * - IPv4 classful (shortened) form.  RFC2553 is silent about it.  XNET 5.2
 *   says to use inet_aton() to convert IPv4 numeric to binary (alows
 *   classful form as a result).
 *   current code - disallow classful form for IPv4 (due to use of inet_pton).
 * - freeaddrinfo(NULL).  RFC2553 is silent about it.  XNET 5.2 says it is
 *   invalid.
 *   current code - SEGV on freeaddrinfo(NULL)
 * Note:
 * - We use getipnodebyname() just for thread-safeness.  There's no intent
 *   to let it do PF_UNSPEC (actually we never pass PF_UNSPEC to
 *   getipnodebyname().
 * - The code filters out AFs that are not supported by the kernel,
 *   when globbing NULL hostname (to loopback, or wildcard).  Is it the right
 *   thing to do?  What is the relationship with post-RFC2553 AI_ADDRCONFIG
 *   in ai_flags?
 * - (post-2553) semantics of AI_ADDRCONFIG itself is too vague.
 *   (1) what should we do against numeric hostname (2) what should we do
 *   against NULL hostname (3) what is AI_ADDRCONFIG itself.  AF not ready?
 *   non-loopback address configured?  global address configured?
 * - To avoid search order issue, we have a big amount of code duplicate
 *   from gethnamaddr.c and some other places.  The issues that there's no
 *   lower layer function to lookup "IPv4 or IPv6" record.  Calling
 *   gethostbyname2 from getaddrinfo will end up in wrong search order, as
 *   follows:
 *	- The code makes use of following calls when asked to resolver with
 *	  ai_family  = PF_UNSPEC:
 *		getipnodebyname(host, AF_INET6);
 *		getipnodebyname(host, AF_INET);
 *	  This will result in the following queries if the node is configure to
 *	  prefer /etc/hosts than DNS:
 *		lookup /etc/hosts for IPv6 address
 *		lookup DNS for IPv6 address
 *		lookup /etc/hosts for IPv4 address
 *		lookup DNS for IPv4 address
 *	  which may not meet people's requirement.
 *	  The right thing to happen is to have underlying layer which does
 *	  PF_UNSPEC lookup (lookup both) and return chain of addrinfos.
 *	  This would result in a bit of code duplicate with _dns_ghbyname() and
 *	  friends.
 */

#include <fcntl.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include "NetdClientDispatch.h"
#include "resolv_cache.h"
#include "resolv_netid.h"
#include "resolv_private.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <syslog.h>
#include <stdarg.h>
#include "nsswitch.h"
#include "private/bionic_defs.h"

typedef union sockaddr_union {
    struct sockaddr     generic;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
} sockaddr_union;

#define SUCCESS 0
#define ANY 0
#define YES 1
#define NO  0

static const char in_addrany[] = { 0, 0, 0, 0 };
static const char in_loopback[] = { 127, 0, 0, 1 };
#ifdef INET6
static const char in6_addrany[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const char in6_loopback[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};
#endif

#if defined(__ANDROID__)
// This should be synchronized to ResponseCode.h
static const int DnsProxyQueryResult = 222;
#endif

static const struct afd {
	int a_af;
	int a_addrlen;
	int a_socklen;
	int a_off;
	const char *a_addrany;
	const char *a_loopback;
	int a_scoped;
} afdl [] = {
#ifdef INET6
	{PF_INET6, sizeof(struct in6_addr),
	 sizeof(struct sockaddr_in6),
	 offsetof(struct sockaddr_in6, sin6_addr),
	 in6_addrany, in6_loopback, 1},
#endif
	{PF_INET, sizeof(struct in_addr),
	 sizeof(struct sockaddr_in),
	 offsetof(struct sockaddr_in, sin_addr),
	 in_addrany, in_loopback, 0},
	{0, 0, 0, 0, NULL, NULL, 0},
};

struct explore {
	int e_af;
	int e_socktype;
	int e_protocol;
	const char *e_protostr;
	int e_wild;
#define WILD_AF(ex)		((ex)->e_wild & 0x01)
#define WILD_SOCKTYPE(ex)	((ex)->e_wild & 0x02)
#define WILD_PROTOCOL(ex)	((ex)->e_wild & 0x04)
};

static const struct explore explore[] = {
#if 0
	{ PF_LOCAL, 0, ANY, ANY, NULL, 0x01 },
#endif
#ifdef INET6
	{ PF_INET6, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_INET6, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_INET6, SOCK_RAW, ANY, NULL, 0x05 },
#endif
	{ PF_INET, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_INET, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_INET, SOCK_RAW, ANY, NULL, 0x05 },
	{ PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, "udp", 0x07 },
	{ PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, "tcp", 0x07 },
	{ PF_UNSPEC, SOCK_RAW, ANY, NULL, 0x05 },
	{ -1, 0, 0, NULL, 0 },
};

#ifdef INET6
#define PTON_MAX	16
#else
#define PTON_MAX	4
#endif

static const ns_src default_dns_files[] = {
	{ NSSRC_FILES, 	NS_SUCCESS },
	{ NSSRC_DNS, 	NS_SUCCESS },
	{ 0, 0 }
};

#define MAXPACKET	(8*1024)

typedef union {
	HEADER hdr;
	u_char buf[MAXPACKET];
} querybuf;

struct res_target {
	struct res_target *next;
	const char *name;	/* domain name */
	int qclass, qtype;	/* class and type of query */
	u_char *answer;		/* buffer to put answer */
	int anslen;		/* size of answer buffer */
	int n;			/* result length */
};

static int str2number(const char *);
static int explore_fqdn(const struct addrinfo *, const char *,
	const char *, struct addrinfo **, const struct android_net_context *);
static int explore_null(const struct addrinfo *,
	const char *, struct addrinfo **);
static int explore_numeric(const struct addrinfo *, const char *,
	const char *, struct addrinfo **, const char *);
static int explore_numeric_scope(const struct addrinfo *, const char *,
	const char *, struct addrinfo **);
static int get_canonname(const struct addrinfo *,
	struct addrinfo *, const char *);
static struct addrinfo *get_ai(const struct addrinfo *,
	const struct afd *, const char *);
static int get_portmatch(const struct addrinfo *, const char *);
static int get_port(const struct addrinfo *, const char *, int);
static const struct afd *find_afd(int);
#ifdef INET6
static int ip6_str2scopeid(char *, struct sockaddr_in6 *, u_int32_t *);
#endif

static struct addrinfo *getanswer(const querybuf *, int, const char *, int,
	const struct addrinfo *);
static int _dns_getaddrinfo(void *, void *, va_list);
static void _sethtent(FILE **);
static void _endhtent(FILE **);
static struct addrinfo *_gethtent(FILE **, const char *,
    const struct addrinfo *);
static int _files_getaddrinfo(void *, void *, va_list);
static int _find_src_addr(const struct sockaddr *, struct sockaddr *, unsigned , uid_t);

static int res_queryN(const char *, struct res_target *, res_state);
static int res_searchN(const char *, struct res_target *, res_state);
static int res_querydomainN(const char *, const char *,
	struct res_target *, res_state);

static const char * const ai_errlist[] = {
	"Success",
	"Address family for hostname not supported",	/* EAI_ADDRFAMILY */
	"Temporary failure in name resolution",		/* EAI_AGAIN      */
	"Invalid value for ai_flags",		       	/* EAI_BADFLAGS   */
	"Non-recoverable failure in name resolution", 	/* EAI_FAIL       */
	"ai_family not supported",			/* EAI_FAMILY     */
	"Memory allocation failure", 			/* EAI_MEMORY     */
	"No address associated with hostname", 		/* EAI_NODATA     */
	"hostname nor servname provided, or not known",	/* EAI_NONAME     */
	"servname not supported for ai_socktype",	/* EAI_SERVICE    */
	"ai_socktype not supported", 			/* EAI_SOCKTYPE   */
	"System error returned in errno", 		/* EAI_SYSTEM     */
	"Invalid value for hints",			/* EAI_BADHINTS	  */
	"Resolved protocol is unknown",			/* EAI_PROTOCOL   */
	"Argument buffer overflow",			/* EAI_OVERFLOW   */
	"Unknown error", 				/* EAI_MAX        */
};

/* XXX macros that make external reference is BAD. */

#define GET_AI(ai, afd, addr) 					\
do { 								\
	/* external reference: pai, error, and label free */ 	\
	(ai) = get_ai(pai, (afd), (addr)); 			\
	if ((ai) == NULL) { 					\
		error = EAI_MEMORY; 				\
		goto free; 					\
	} 							\
} while (/*CONSTCOND*/0)

#define GET_PORT(ai, serv) 					\
do { 								\
	/* external reference: error and label free */ 		\
	error = get_port((ai), (serv), 0); 			\
	if (error != 0) 					\
		goto free; 					\
} while (/*CONSTCOND*/0)

#define GET_CANONNAME(ai, str) 					\
do { 								\
	/* external reference: pai, error and label free */ 	\
	error = get_canonname(pai, (ai), (str)); 		\
	if (error != 0) 					\
		goto free; 					\
} while (/*CONSTCOND*/0)

#define ERR(err) 						\
do { 								\
	/* external reference: error, and label bad */ 		\
	error = (err); 						\
	goto bad; 						\
	/*NOTREACHED*/ 						\
} while (/*CONSTCOND*/0)

#define MATCH_FAMILY(x, y, w) 						\
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == PF_UNSPEC || 	\
	    (y) == PF_UNSPEC)))
#define MATCH(x, y, w) 							\
	((x) == (y) || (/*CONSTCOND*/(w) && ((x) == ANY || (y) == ANY)))

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
const char *
gai_strerror(int ecode)
{
	if (ecode < 0 || ecode > EAI_MAX)
		ecode = EAI_MAX;
	return ai_errlist[ecode];
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

#if defined(__BIONIC__)
	if (ai == NULL) return;
#else
	_DIAGASSERT(ai != NULL);
#endif

	do {
		next = ai->ai_next;
		if (ai->ai_canonname)
			free(ai->ai_canonname);
		/* no need to free(ai->ai_addr) */
		free(ai);
		ai = next;
	} while (ai);
}

static int
str2number(const char *p)
{
	char *ep;
	unsigned long v;

	assert(p != NULL);

	if (*p == '\0')
		return -1;
	ep = NULL;
	errno = 0;
	v = strtoul(p, &ep, 10);
	if (errno == 0 && ep && *ep == '\0' && v <= UINT_MAX)
		return v;
	else
		return -1;
}

/*
 * The following functions determine whether IPv4 or IPv6 connectivity is
 * available in order to implement AI_ADDRCONFIG.
 *
 * Strictly speaking, AI_ADDRCONFIG should not look at whether connectivity is
 * available, but whether addresses of the specified family are "configured
 * on the local system". However, bionic doesn't currently support getifaddrs,
 * so checking for connectivity is the next best thing.
 */
static int
_have_ipv6(unsigned mark, uid_t uid) {
	static const struct sockaddr_in6 sin6_test = {
		.sin6_family = AF_INET6,
		.sin6_addr.s6_addr = {  // 2000::
			0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		};
	sockaddr_union addr = { .in6 = sin6_test };
	return _find_src_addr(&addr.generic, NULL, mark, uid) == 1;
}

static int
_have_ipv4(unsigned mark, uid_t uid) {
	static const struct sockaddr_in sin_test = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = __constant_htonl(0x08080808L)  // 8.8.8.8
	};
	sockaddr_union addr = { .in = sin_test };
	return _find_src_addr(&addr.generic, NULL, mark, uid) == 1;
}

bool readBE32(FILE* fp, int32_t* result) {
  int32_t tmp;
  if (fread(&tmp, sizeof(tmp), 1, fp) != 1) {
    return false;
  }
  *result = ntohl(tmp);
  return true;
}

#if defined(__ANDROID__)
// Returns 0 on success, else returns on error.
static int
android_getaddrinfo_proxy(
    const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res, unsigned netid)
{
	int success = 0;

	// Clear this at start, as we use its non-NULLness later (in the
	// error path) to decide if we have to free up any memory we
	// allocated in the process (before failing).
	*res = NULL;

	// Bogus things we can't serialize.  Don't use the proxy.  These will fail - let them.
	if ((hostname != NULL &&
	     strcspn(hostname, " \n\r\t^'\"") != strlen(hostname)) ||
	    (servname != NULL &&
	     strcspn(servname, " \n\r\t^'\"") != strlen(servname))) {
		return EAI_NODATA;
	}

	FILE* proxy = fdopen(__netdClientDispatch.dnsOpenProxy(), "r+");
	if (proxy == NULL) {
		return EAI_SYSTEM;
	}
	netid = __netdClientDispatch.netIdForResolv(netid);

	// Send the request.
	if (fprintf(proxy, "getaddrinfo %s %s %d %d %d %d %u",
		    hostname == NULL ? "^" : hostname,
		    servname == NULL ? "^" : servname,
		    hints == NULL ? -1 : hints->ai_flags,
		    hints == NULL ? -1 : hints->ai_family,
		    hints == NULL ? -1 : hints->ai_socktype,
		    hints == NULL ? -1 : hints->ai_protocol,
		    netid) < 0) {
		goto exit;
	}
	// literal NULL byte at end, required by FrameworkListener
	if (fputc(0, proxy) == EOF ||
	    fflush(proxy) != 0) {
		goto exit;
	}

	char buf[4];
	// read result code for gethostbyaddr
	if (fread(buf, 1, sizeof(buf), proxy) != sizeof(buf)) {
		goto exit;
	}

	int result_code = (int)strtol(buf, NULL, 10);
	// verify the code itself
	if (result_code != DnsProxyQueryResult) {
		fread(buf, 1, sizeof(buf), proxy);
		goto exit;
	}

	struct addrinfo* ai = NULL;
	struct addrinfo** nextres = res;
	while (1) {
		int32_t have_more;
		if (!readBE32(proxy, &have_more)) {
			break;
		}
		if (have_more == 0) {
			success = 1;
			break;
		}

		ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_storage));
		if (ai == NULL) {
			break;
		}
		ai->ai_addr = (struct sockaddr*)(ai + 1);

		// struct addrinfo {
		//	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
		//	int	ai_family;	/* PF_xxx */
		//	int	ai_socktype;	/* SOCK_xxx */
		//	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
		//	socklen_t ai_addrlen;	/* length of ai_addr */
		//	char	*ai_canonname;	/* canonical name for hostname */
		//	struct	sockaddr *ai_addr;	/* binary address */
		//	struct	addrinfo *ai_next;	/* next structure in linked list */
		// };

		// Read the struct piece by piece because we might be a 32-bit process
		// talking to a 64-bit netd.
		int32_t addr_len;
		bool success =
				readBE32(proxy, &ai->ai_flags) &&
				readBE32(proxy, &ai->ai_family) &&
				readBE32(proxy, &ai->ai_socktype) &&
				readBE32(proxy, &ai->ai_protocol) &&
				readBE32(proxy, &addr_len);
		if (!success) {
			break;
		}

		// Set ai_addrlen and read the ai_addr data.
		ai->ai_addrlen = addr_len;
		if (addr_len != 0) {
			if ((size_t) addr_len > sizeof(struct sockaddr_storage)) {
				// Bogus; too big.
				break;
			}
			if (fread(ai->ai_addr, addr_len, 1, proxy) != 1) {
				break;
			}
		}

		// The string for ai_cannonname.
		int32_t name_len;
		if (!readBE32(proxy, &name_len)) {
			break;
		}
		if (name_len != 0) {
			ai->ai_canonname = (char*) malloc(name_len);
			if (fread(ai->ai_canonname, name_len, 1, proxy) != 1) {
				break;
			}
			if (ai->ai_canonname[name_len - 1] != '\0') {
				// The proxy should be returning this
				// NULL-terminated.
				break;
			}
		}

		*nextres = ai;
		nextres = &ai->ai_next;
		ai = NULL;
	}

	if (ai != NULL) {
		// Clean up partially-built addrinfo that we never ended up
		// attaching to the response.
		freeaddrinfo(ai);
	}
exit:
	if (proxy != NULL) {
		fclose(proxy);
	}

	if (success) {
		return 0;
	}

	// Proxy failed;
	// clean up memory we might've allocated.
	if (*res) {
		freeaddrinfo(*res);
		*res = NULL;
	}
	return EAI_NODATA;
}
#endif

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int
getaddrinfo(const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	return android_getaddrinfofornet(hostname, servname, hints, NETID_UNSET, MARK_UNSET, res);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int
android_getaddrinfofornet(const char *hostname, const char *servname,
    const struct addrinfo *hints, unsigned netid, unsigned mark, struct addrinfo **res)
{
	struct android_net_context netcontext = {
		.app_netid = netid,
		.app_mark = mark,
		.dns_netid = netid,
		.dns_mark = mark,
		.uid = NET_CONTEXT_INVALID_UID,
        };
	return android_getaddrinfofornetcontext(hostname, servname, hints, &netcontext, res);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int
android_getaddrinfofornetcontext(const char *hostname, const char *servname,
    const struct addrinfo *hints, const struct android_net_context *netcontext,
    struct addrinfo **res)
{
	struct addrinfo sentinel;
	struct addrinfo *cur;
	int error = 0;
	struct addrinfo ai;
	struct addrinfo ai0;
	struct addrinfo *pai;
	const struct explore *ex;

	/* hostname is allowed to be NULL */
	/* servname is allowed to be NULL */
	/* hints is allowed to be NULL */
	assert(res != NULL);
	assert(netcontext != NULL);
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;
	pai = &ai;
	pai->ai_flags = 0;
	pai->ai_family = PF_UNSPEC;
	pai->ai_socktype = ANY;
	pai->ai_protocol = ANY;
	pai->ai_addrlen = 0;
	pai->ai_canonname = NULL;
	pai->ai_addr = NULL;
	pai->ai_next = NULL;

	if (hostname == NULL && servname == NULL)
		return EAI_NONAME;
	if (hints) {
		/* error check for hints */
		if (hints->ai_addrlen || hints->ai_canonname ||
		    hints->ai_addr || hints->ai_next)
			ERR(EAI_BADHINTS); /* xxx */
		if (hints->ai_flags & ~AI_MASK)
			ERR(EAI_BADFLAGS);
		switch (hints->ai_family) {
		case PF_UNSPEC:
		case PF_INET:
#ifdef INET6
		case PF_INET6:
#endif
			break;
		default:
			ERR(EAI_FAMILY);
		}
		memcpy(pai, hints, sizeof(*pai));

		/*
		 * if both socktype/protocol are specified, check if they
		 * are meaningful combination.
		 */
		if (pai->ai_socktype != ANY && pai->ai_protocol != ANY) {
			for (ex = explore; ex->e_af >= 0; ex++) {
				if (pai->ai_family != ex->e_af)
					continue;
				if (ex->e_socktype == ANY)
					continue;
				if (ex->e_protocol == ANY)
					continue;
				if (pai->ai_socktype == ex->e_socktype
				 && pai->ai_protocol != ex->e_protocol) {
					ERR(EAI_BADHINTS);
				}
			}
		}
	}

	/*
	 * check for special cases.  (1) numeric servname is disallowed if
	 * socktype/protocol are left unspecified. (2) servname is disallowed
	 * for raw and other inet{,6} sockets.
	 */
	if (MATCH_FAMILY(pai->ai_family, PF_INET, 1)
#ifdef PF_INET6
	 || MATCH_FAMILY(pai->ai_family, PF_INET6, 1)
#endif
	    ) {
		ai0 = *pai;	/* backup *pai */

		if (pai->ai_family == PF_UNSPEC) {
#ifdef PF_INET6
			pai->ai_family = PF_INET6;
#else
			pai->ai_family = PF_INET;
#endif
		}
		error = get_portmatch(pai, servname);
		if (error)
			ERR(error);

		*pai = ai0;
	}

	ai0 = *pai;

	/* NULL hostname, or numeric hostname */
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		/* PF_UNSPEC entries are prepared for DNS queries only */
		if (ex->e_af == PF_UNSPEC)
			continue;

		if (!MATCH_FAMILY(pai->ai_family, ex->e_af, WILD_AF(ex)))
			continue;
		if (!MATCH(pai->ai_socktype, ex->e_socktype, WILD_SOCKTYPE(ex)))
			continue;
		if (!MATCH(pai->ai_protocol, ex->e_protocol, WILD_PROTOCOL(ex)))
			continue;

		if (pai->ai_family == PF_UNSPEC)
			pai->ai_family = ex->e_af;
		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		if (hostname == NULL)
			error = explore_null(pai, servname, &cur->ai_next);
		else
			error = explore_numeric_scope(pai, hostname, servname,
			    &cur->ai_next);

		if (error)
			goto free;

		while (cur->ai_next)
			cur = cur->ai_next;
	}

	/*
	 * XXX
	 * If numeric representation of AF1 can be interpreted as FQDN
	 * representation of AF2, we need to think again about the code below.
	 */
	if (sentinel.ai_next)
		goto good;

	if (hostname == NULL)
		ERR(EAI_NODATA);
	if (pai->ai_flags & AI_NUMERICHOST)
		ERR(EAI_NONAME);

#if defined(__ANDROID__)
	int gai_error = android_getaddrinfo_proxy(
		hostname, servname, hints, res, netcontext->app_netid);
	if (gai_error != EAI_SYSTEM) {
		return gai_error;
	}
#endif

	/*
	 * hostname as alphabetical name.
	 * we would like to prefer AF_INET6 than AF_INET, so we'll make a
	 * outer loop by AFs.
	 */
	for (ex = explore; ex->e_af >= 0; ex++) {
		*pai = ai0;

		/* require exact match for family field */
		if (pai->ai_family != ex->e_af)
			continue;

		if (!MATCH(pai->ai_socktype, ex->e_socktype,
				WILD_SOCKTYPE(ex))) {
			continue;
		}
		if (!MATCH(pai->ai_protocol, ex->e_protocol,
				WILD_PROTOCOL(ex))) {
			continue;
		}

		if (pai->ai_socktype == ANY && ex->e_socktype != ANY)
			pai->ai_socktype = ex->e_socktype;
		if (pai->ai_protocol == ANY && ex->e_protocol != ANY)
			pai->ai_protocol = ex->e_protocol;

		error = explore_fqdn(
			pai, hostname, servname, &cur->ai_next, netcontext);

		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}

	/* XXX */
	if (sentinel.ai_next)
		error = 0;

	if (error)
		goto free;
	if (error == 0) {
		if (sentinel.ai_next) {
 good:
			*res = sentinel.ai_next;
			return SUCCESS;
		} else
			error = EAI_FAIL;
	}
 free:
 bad:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	*res = NULL;
	return error;
}

/*
 * FQDN hostname, DNS lookup
 */
static int
explore_fqdn(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res,
    const struct android_net_context *netcontext)
{
	struct addrinfo *result;
	struct addrinfo *cur;
	int error = 0;
	static const ns_dtab dtab[] = {
		NS_FILES_CB(_files_getaddrinfo, NULL)
		{ NSSRC_DNS, _dns_getaddrinfo, NULL },	/* force -DHESIOD */
		NS_NIS_CB(_yp_getaddrinfo, NULL)
		{ 0, 0, 0 }
	};

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	result = NULL;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	switch (nsdispatch(&result, dtab, NSDB_HOSTS, "getaddrinfo",
			default_dns_files, hostname, pai, netcontext)) {
	case NS_TRYAGAIN:
		error = EAI_AGAIN;
		goto free;
	case NS_UNAVAIL:
		error = EAI_FAIL;
		goto free;
	case NS_NOTFOUND:
		error = EAI_NODATA;
		goto free;
	case NS_SUCCESS:
		error = 0;
		for (cur = result; cur; cur = cur->ai_next) {
			GET_PORT(cur, servname);
			/* canonname should be filled already */
		}
		break;
	}

	*res = result;

	return 0;

free:
	if (result)
		freeaddrinfo(result);
	return error;
}

/*
 * hostname == NULL.
 * passive socket -> anyaddr (0.0.0.0 or ::)
 * non-passive socket -> localhost (127.0.0.1 or ::1)
 */
static int
explore_null(const struct addrinfo *pai, const char *servname,
    struct addrinfo **res)
{
	int s;
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;

	assert(pai != NULL);
	/* servname may be NULL */
	assert(res != NULL);

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * filter out AFs that are not supported by the kernel
	 * XXX errno?
	 */
	s = socket(pai->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0) {
		if (errno != EMFILE)
			return 0;
	} else
		close(s);

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (pai->ai_flags & AI_PASSIVE) {
		GET_AI(cur->ai_next, afd, afd->a_addrany);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "anyaddr");
		 */
		GET_PORT(cur->ai_next, servname);
	} else {
		GET_AI(cur->ai_next, afd, afd->a_loopback);
		/* xxx meaningless?
		 * GET_CANONNAME(cur->ai_next, "localhost");
		 */
		GET_PORT(cur->ai_next, servname);
	}
	cur = cur->ai_next;

	*res = sentinel.ai_next;
	return 0;

free:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * numeric hostname
 */
static int
explore_numeric(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res, const char *canonname)
{
	const struct afd *afd;
	struct addrinfo *cur;
	struct addrinfo sentinel;
	int error;
	char pton[PTON_MAX];

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	*res = NULL;
	sentinel.ai_next = NULL;
	cur = &sentinel;

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	switch (afd->a_af) {
#if 0 /*X/Open spec*/
	case AF_INET:
		if (inet_aton(hostname, (struct in_addr *)pton) == 1) {
			if (pai->ai_family == afd->a_af ||
			    pai->ai_family == PF_UNSPEC /*?*/) {
				GET_AI(cur->ai_next, afd, pton);
				GET_PORT(cur->ai_next, servname);
				if ((pai->ai_flags & AI_CANONNAME)) {
					/*
					 * Set the numeric address itself as
					 * the canonical name, based on a
					 * clarification in rfc2553bis-03.
					 */
					GET_CANONNAME(cur->ai_next, canonname);
				}
				while (cur && cur->ai_next)
					cur = cur->ai_next;
			} else
				ERR(EAI_FAMILY);	/*xxx*/
		}
		break;
#endif
	default:
		if (inet_pton(afd->a_af, hostname, pton) == 1) {
			if (pai->ai_family == afd->a_af ||
			    pai->ai_family == PF_UNSPEC /*?*/) {
				GET_AI(cur->ai_next, afd, pton);
				GET_PORT(cur->ai_next, servname);
				if ((pai->ai_flags & AI_CANONNAME)) {
					/*
					 * Set the numeric address itself as
					 * the canonical name, based on a
					 * clarification in rfc2553bis-03.
					 */
					GET_CANONNAME(cur->ai_next, canonname);
				}
				while (cur->ai_next)
					cur = cur->ai_next;
			} else
				ERR(EAI_FAMILY);	/*xxx*/
		}
		break;
	}

	*res = sentinel.ai_next;
	return 0;

free:
bad:
	if (sentinel.ai_next)
		freeaddrinfo(sentinel.ai_next);
	return error;
}

/*
 * numeric hostname with scope
 */
static int
explore_numeric_scope(const struct addrinfo *pai, const char *hostname,
    const char *servname, struct addrinfo **res)
{
#if !defined(SCOPE_DELIMITER) || !defined(INET6)
	return explore_numeric(pai, hostname, servname, res, hostname);
#else
	const struct afd *afd;
	struct addrinfo *cur;
	int error;
	char *cp, *hostname2 = NULL, *scope, *addr;
	struct sockaddr_in6 *sin6;

	assert(pai != NULL);
	/* hostname may be NULL */
	/* servname may be NULL */
	assert(res != NULL);

	/*
	 * if the servname does not match socktype/protocol, ignore it.
	 */
	if (get_portmatch(pai, servname) != 0)
		return 0;

	afd = find_afd(pai->ai_family);
	if (afd == NULL)
		return 0;

	if (!afd->a_scoped)
		return explore_numeric(pai, hostname, servname, res, hostname);

	cp = strchr(hostname, SCOPE_DELIMITER);
	if (cp == NULL)
		return explore_numeric(pai, hostname, servname, res, hostname);

	/*
	 * Handle special case of <scoped_address><delimiter><scope id>
	 */
	hostname2 = strdup(hostname);
	if (hostname2 == NULL)
		return EAI_MEMORY;
	/* terminate at the delimiter */
	hostname2[cp - hostname] = '\0';
	addr = hostname2;
	scope = cp + 1;

	error = explore_numeric(pai, addr, servname, res, hostname);
	if (error == 0) {
		u_int32_t scopeid;

		for (cur = *res; cur; cur = cur->ai_next) {
			if (cur->ai_family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)(void *)cur->ai_addr;
			if (ip6_str2scopeid(scope, sin6, &scopeid) == -1) {
				free(hostname2);
				return(EAI_NODATA); /* XXX: is return OK? */
			}
			sin6->sin6_scope_id = scopeid;
		}
	}

	free(hostname2);

	return error;
#endif
}

static int
get_canonname(const struct addrinfo *pai, struct addrinfo *ai, const char *str)
{

	assert(pai != NULL);
	assert(ai != NULL);
	assert(str != NULL);

	if ((pai->ai_flags & AI_CANONNAME) != 0) {
		ai->ai_canonname = strdup(str);
		if (ai->ai_canonname == NULL)
			return EAI_MEMORY;
	}
	return 0;
}

static struct addrinfo *
get_ai(const struct addrinfo *pai, const struct afd *afd, const char *addr)
{
	char *p;
	struct addrinfo *ai;

	assert(pai != NULL);
	assert(afd != NULL);
	assert(addr != NULL);

	ai = (struct addrinfo *)malloc(sizeof(struct addrinfo)
		+ (afd->a_socklen));
	if (ai == NULL)
		return NULL;

	memcpy(ai, pai, sizeof(struct addrinfo));
	ai->ai_addr = (struct sockaddr *)(void *)(ai + 1);
	memset(ai->ai_addr, 0, (size_t)afd->a_socklen);

#ifdef HAVE_SA_LEN
	ai->ai_addr->sa_len = afd->a_socklen;
#endif

	ai->ai_addrlen = afd->a_socklen;
#if defined (__alpha__) || (defined(__i386__) && defined(_LP64)) || defined(__sparc64__)
	ai->__ai_pad0 = 0;
#endif
	ai->ai_addr->sa_family = ai->ai_family = afd->a_af;
	p = (char *)(void *)(ai->ai_addr);
	memcpy(p + afd->a_off, addr, (size_t)afd->a_addrlen);
	return ai;
}

static int
get_portmatch(const struct addrinfo *ai, const char *servname)
{

	assert(ai != NULL);
	/* servname may be NULL */

	return get_port(ai, servname, 1);
}

static int
get_port(const struct addrinfo *ai, const char *servname, int matchonly)
{
	const char *proto;
	struct servent *sp;
	int port;
	int allownumeric;

	assert(ai != NULL);
	/* servname may be NULL */

	if (servname == NULL)
		return 0;
	switch (ai->ai_family) {
	case AF_INET:
#ifdef AF_INET6
	case AF_INET6:
#endif
		break;
	default:
		return 0;
	}

	switch (ai->ai_socktype) {
	case SOCK_RAW:
		return EAI_SERVICE;
	case SOCK_DGRAM:
	case SOCK_STREAM:
		allownumeric = 1;
		break;
	case ANY:
#if 1  /* ANDROID-SPECIFIC CHANGE TO MATCH GLIBC */
		allownumeric = 1;
#else
		allownumeric = 0;
#endif
		break;
	default:
		return EAI_SOCKTYPE;
	}

	port = str2number(servname);
	if (port >= 0) {
		if (!allownumeric)
			return EAI_SERVICE;
		if (port < 0 || port > 65535)
			return EAI_SERVICE;
		port = htons(port);
	} else {
		if (ai->ai_flags & AI_NUMERICSERV)
			return EAI_NONAME;

		switch (ai->ai_socktype) {
		case SOCK_DGRAM:
			proto = "udp";
			break;
		case SOCK_STREAM:
			proto = "tcp";
			break;
		default:
			proto = NULL;
			break;
		}

		if ((sp = getservbyname(servname, proto)) == NULL)
			return EAI_SERVICE;
		port = sp->s_port;
	}

	if (!matchonly) {
		switch (ai->ai_family) {
		case AF_INET:
			((struct sockaddr_in *)(void *)
			    ai->ai_addr)->sin_port = port;
			break;
#ifdef INET6
		case AF_INET6:
			((struct sockaddr_in6 *)(void *)
			    ai->ai_addr)->sin6_port = port;
			break;
#endif
		}
	}

	return 0;
}

static const struct afd *
find_afd(int af)
{
	const struct afd *afd;

	if (af == PF_UNSPEC)
		return NULL;
	for (afd = afdl; afd->a_af; afd++) {
		if (afd->a_af == af)
			return afd;
	}
	return NULL;
}

#ifdef INET6
/* convert a string to a scope identifier. XXX: IPv6 specific */
static int
ip6_str2scopeid(char *scope, struct sockaddr_in6 *sin6, u_int32_t *scopeid)
{
	u_long lscopeid;
	struct in6_addr *a6;
	char *ep;

	assert(scope != NULL);
	assert(sin6 != NULL);
	assert(scopeid != NULL);

	a6 = &sin6->sin6_addr;

	/* empty scopeid portion is invalid */
	if (*scope == '\0')
		return -1;

	if (IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6)) {
		/*
		 * We currently assume a one-to-one mapping between links
		 * and interfaces, so we simply use interface indices for
		 * like-local scopes.
		 */
		*scopeid = if_nametoindex(scope);
		if (*scopeid == 0)
			goto trynumeric;
		return 0;
	}

	/* still unclear about literal, allow numeric only - placeholder */
	if (IN6_IS_ADDR_SITELOCAL(a6) || IN6_IS_ADDR_MC_SITELOCAL(a6))
		goto trynumeric;
	if (IN6_IS_ADDR_MC_ORGLOCAL(a6))
		goto trynumeric;
	else
		goto trynumeric;	/* global */

	/* try to convert to a numeric id as a last resort */
  trynumeric:
	errno = 0;
	lscopeid = strtoul(scope, &ep, 10);
	*scopeid = (u_int32_t)(lscopeid & 0xffffffffUL);
	if (errno == 0 && ep && *ep == '\0' && *scope
```