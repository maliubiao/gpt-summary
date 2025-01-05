Response:
The user wants a summary of the functionalities of the provided C source code file `bionic/libc/dns/net/gethnamaddr.c`. This file is part of Android's Bionic libc and deals with hostname and address resolution.

Here's a breakdown of how to address the request:

1. **Identify Core Functionality:** The file's name and the functions within it (like `gethostbyname`, `gethostbyaddr`) clearly indicate its purpose: resolving hostnames to IP addresses and vice-versa.

2. **Analyze Key Functions:** Go through each function and understand its role in the resolution process. Note the variations like `gethostbyname`, `gethostbyname2`, and the `android_gethostbynamefornet*` variants which indicate network context awareness.

3. **Highlight Android-Specific Aspects:** Pay close attention to functions prefixed with `android_`, as these are specifically designed for the Android environment, likely involving network namespace or context management.

4. **Explain libc Function Implementations:**  For standard libc functions, the focus should be on their general operation related to DNS resolution. For Bionic-specific internal functions, provide a high-level explanation of their role.

5. **Address Dynamic Linking:** Look for any signs of interaction with the dynamic linker. In this code, there isn't explicit dynamic linking happening *within* this file. The dynamic linker's role is primarily in loading the shared library containing these functions.

6. **Consider Logic and Assumptions:**  For functions like `_yp_hostent`, infer the logic based on the code's flow and variable names. Hypothesize inputs and outputs based on their purpose.

7. **Identify Potential Errors:** Think about common mistakes developers might make when using these functions, like providing incorrect address lengths or forgetting to handle error conditions.

8. **Trace Android Framework Interaction:**  Consider how high-level Android frameworks or the NDK might call into these functions. Think about the layers involved in a network request.

9. **Provide Frida Hook Examples:**  Demonstrate how to use Frida to intercept and inspect the execution of these functions, which is crucial for debugging.

10. **Structure the Response:** Organize the information logically, starting with a general summary and then delving into specifics for each requirement.

**Self-Correction during thought process:**

* **Initial thought:** Focus heavily on DNS protocol details. **Correction:** The code deals with *resolving* names, not the low-level DNS protocol itself. The focus should be on the libc API and how it interacts with the underlying resolver.
* **Initial thought:** Assume explicit calls to dynamic linker functions within this file. **Correction:** This file likely gets loaded by the dynamic linker, but doesn't contain explicit `dlopen` or similar calls. The explanation needs to focus on the linker's role in making this code available.
* **Initial thought:** Overcomplicate the Frida examples. **Correction:** Keep the Frida snippets concise and focused on demonstrating interception and parameter inspection.

By following these steps and making necessary corrections, a comprehensive and accurate answer can be generated.
这是 `bionic/libc/dns/net/gethnamaddr.c` 源代码文件的第二部分，主要包含以下功能：

**1. 处理 Yellow Pages (YP/NIS) 数据源的 hostname 和 IP 地址查询:**

* **`_yp_hostent(char *line, int af, struct getnamaddr *info)`:**  这是一个静态函数，用于解析从 YP/NIS 服务返回的一行主机信息数据。它将字符串形式的 IP 地址、主机名和别名解析并填充到 `hostent` 结构体中。
    * **功能:**  解析 YP/NIS 返回的主机信息字符串。
    * **实现:**
        1. 它首先解析 IP 地址，使用 `inet_pton` 将字符串形式的 IP 地址转换为网络字节序的二进制 IP 地址，并存储在 `host_addrs` 数组中。
        2. 然后，它解析主机名，并将其存储到 `hp->h_name`。
        3. 接着，它解析主机别名，并将它们存储到 `hp->h_aliases` 数组中。
        4. 最后，它将解析出的 IP 地址、主机名和别名复制到 `info->buf` 指向的缓冲区中，并更新 `hostent` 结构体的相应字段。
    * **与 Android 功能的关系:** 在某些使用 YP/NIS 的网络环境中，Android 设备可能需要从 YP/NIS 服务器获取主机信息。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入 `line`:** "192.168.1.10 host1 alias1 alias2\n"
        * **假设 `af`:** `AF_INET`
        * **预期输出 `hp` 的内容:**
            * `hp->h_name`: "host1"
            * `hp->h_addrtype`: `AF_INET`
            * `hp->h_length`: 4
            * `hp->h_addr_list[0]`: 包含 IP 地址 192.168.1.10 的二进制表示
            * `hp->h_aliases[0]`: "alias1"
            * `hp->h_aliases[1]`: "alias2"
    * **用户或编程常见的使用错误:**  如果在非 YP/NIS 环境下调用此函数，或者 YP/NIS 服务器返回的数据格式不正确，会导致解析错误。

* **`_yp_gethtbyaddr(void *rv, void *cb_data, va_list ap)`:**  这是一个静态函数，用于通过 IP 地址在 YP/NIS 服务中查找主机信息。
    * **功能:**  通过 IP 地址查询 YP/NIS 服务获取主机信息。
    * **实现:**
        1. 它首先检查 YP/NIS 域名是否已配置。
        2. 然后，它使用 `inet_ntop` 将二进制 IP 地址转换为字符串形式。
        3. 根据地址族 (`af`) 选择相应的 YP/NIS 映射表 (`hosts.byaddr` 或 `ipnodes.byaddr`)。
        4. 调用 `yp_match` 函数在 YP/NIS 服务中查找匹配的记录。
        5. 如果找到匹配的记录，则调用 `_yp_hostent` 解析返回的数据。
    * **与 Android 功能的关系:**  在配置了 YP/NIS 客户端的 Android 设备上，此函数用于实现 `gethostbyaddr` 功能。
    * **链接处理过程:**  此函数依赖于 `libnsl.so` 中提供的 YP/NIS 相关函数 (例如 `yp_match`). 动态链接器会将此文件链接到 `libnsl.so`，以便调用这些函数。
    * **假设输入与输出:**
        * **假设输入 IP 地址:** 192.168.1.10 (二进制形式)
        * **假设 `af`:** `AF_INET`
        * **假设 YP/NIS 服务器上 `hosts.byaddr` 包含 "192.168.1.10 host1 alias1"**
        * **预期输出:**  成功找到主机信息，并将信息填充到 `info->hp` 指向的 `hostent` 结构体中，返回 `NS_SUCCESS`。

* **`_yp_gethtbyname(void *rv, void *cb_data, va_list ap)`:**  这是一个静态函数，用于通过主机名在 YP/NIS 服务中查找主机信息。
    * **功能:**  通过主机名查询 YP/NIS 服务获取主机信息。
    * **实现:**
        1. 它首先检查 YP/NIS 域名是否已配置。
        2. 根据地址族 (`af`) 选择相应的 YP/NIS 映射表 (`hosts.byname` 或 `ipnodes.byname`)。
        3. 调用 `yp_match` 函数在 YP/NIS 服务中查找匹配的记录。
        4. 如果找到匹配的记录，则调用 `_yp_hostent` 解析返回的数据。
    * **与 Android 功能的关系:**  在配置了 YP/NIS 客户端的 Android 设备上，此函数用于实现 `gethostbyname` 功能。
    * **链接处理过程:**  与 `_yp_gethtbyaddr` 类似，依赖于 `libnsl.so` 中提供的 YP/NIS 相关函数。
    * **假设输入与输出:**
        * **假设输入主机名:** "host1"
        * **假设 `af`:** `AF_INET`
        * **假设 YP/NIS 服务器上 `hosts.byname` 包含 "host1 192.168.1.10 alias1"**
        * **预期输出:**  成功找到主机信息，并将信息填充到 `info->hp` 指向的 `hostent` 结构体中，返回 `NS_SUCCESS`。

**2. 提供非可重入版本的 `gethostbyname` 和 `gethostbyname2` 函数:**

* **`gethostbyname(const char *name)`:**  这是 `gethostbyname_r` 的非可重入版本。它使用静态的 `res_state` 结构体。
    * **功能:**  通过主机名获取主机信息 (IPv4)。
    * **实现:** 它调用可重入版本 `gethostbyname_r`，并使用静态的 `res_state` 结构体和缓冲区。
    * **与 Android 功能的关系:**  提供标准的 `gethostbyname` 函数，供不需要线程安全的应用程序使用。
    * **用户或编程常见的使用错误:**  在多线程环境中使用此函数可能导致线程安全问题，应优先使用 `gethostbyname_r`。

* **`gethostbyname2(const char *name, int af)`:** 这是 `gethostbyname2_r` 的非可重入版本。它使用静态的 `res_state` 结构体。
    * **功能:**  通过主机名和地址族获取主机信息 (IPv4 或 IPv6)。
    * **实现:** 它调用可重入版本 `gethostbyname2_r`，并使用静态的 `res_state` 结构体和缓冲区。
    * **与 Android 功能的关系:**  提供标准的 `gethostbyname2` 函数，供不需要线程安全的应用程序使用，并允许指定地址族。
    * **用户或编程常见的使用错误:**  与 `gethostbyname` 类似，在多线程环境中使用可能导致线程安全问题，应优先使用 `gethostbyname2_r`。

**3. 提供 Android 特定的 `gethostbynamefornet` 和 `gethostbyaddrfornet` 函数，允许指定网络 ID:**

* **`android_gethostbynamefornet(const char *name, int af, unsigned netid, unsigned mark)`:**  允许应用程序指定网络 ID 进行主机名查询。
    * **功能:**  在指定的网络上通过主机名获取主机信息。
    * **实现:** 它创建一个 `android_net_context` 结构体，包含指定的 `netid` 和 `mark`，然后调用 `android_gethostbynamefornetcontext`。
    * **与 Android 功能的关系:**  允许应用程序在特定的网络命名空间中执行 DNS 查询，这对于支持网络隔离的 Android 系统非常重要。例如，VPN 应用可以使用此功能在 VPN 网络接口上进行 DNS 查询。

* **`android_gethostbynamefornetcontext(const char *name, int af, const struct android_net_context *netcontext)`:**  实际执行带网络上下文的主机名查询。
    * **功能:**  在给定的网络上下文中通过主机名获取主机信息。
    * **实现:** 它获取 `res_state`，然后调用内部函数 `gethostbyname_internal` 执行查询。
    * **与 Android 功能的关系:**  是 `android_gethostbynamefornet` 的核心实现，处理网络上下文相关的逻辑。

* **`android_gethostbyaddrfornet(const void *addr, socklen_t len, int af, unsigned netid, unsigned mark)`:** 允许应用程序指定网络 ID 进行 IP 地址反向查询。
    * **功能:**  在指定的网络上通过 IP 地址获取主机信息。
    * **实现:** 它创建一个 `android_net_context` 结构体，包含指定的 `netid` 和 `mark`，然后调用 `android_gethostbyaddrfornetcontext`。
    * **与 Android 功能的关系:**  允许应用程序在特定的网络命名空间中执行反向 DNS 查询。

* **`android_gethostbyaddrfornetcontext(const void *addr, socklen_t len, int af, const struct android_net_context *netcontext)`:** 实际执行带网络上下文的 IP 地址反向查询。
    * **功能:**  在给定的网络上下文中通过 IP 地址获取主机信息。
    * **实现:** 它调用 `android_gethostbyaddrfornetcontext_proxy`。
    * **与 Android 功能的关系:** 是 `android_gethostbyaddrfornet` 的核心实现，处理网络上下文相关的逻辑。

* **`android_gethostbyaddrfornetcontext_proxy(const void* addr, socklen_t len, int af, const struct android_net_context *netcontext)`:**  一个代理函数，用于获取静态的 `res_state` 并调用内部实现。
    * **功能:**  作为 `android_gethostbyaddrfornetcontext` 的代理，获取必要的资源。
    * **实现:** 它获取静态的 `res_state`，然后调用 `android_gethostbyaddrfornetcontext_proxy_internal`。

* **`android_gethostbyaddrfornetcontext_proxy_internal(...)`:**  实际执行带网络上下文的 IP 地址反向查询的内部实现。 (代码未在此部分展示，但可以推断其功能)。

**4. 提供非可重入版本的 `gethostbyaddr` 函数，并调用带网络上下文的版本:**

* **`gethostbyaddr(const void *addr, socklen_t len, int af)`:**  这是 `gethostbyaddr_r` 的非可重入版本，它使用默认的网络上下文。
    * **功能:**  通过 IP 地址获取主机信息 (使用默认网络)。
    * **实现:** 它调用 `android_gethostbyaddrfornetcontext_proxy` 并传递一个未设置的网络上下文 (`NETCONTEXT_UNSET`)。
    * **与 Android 功能的关系:** 提供标准的 `gethostbyaddr` 函数，供不需要线程安全和网络上下文控制的应用程序使用。
    * **用户或编程常见的使用错误:** 在需要指定网络接口或在多线程环境中使用时可能不适用。

**5. 提供非可重入版本的 `gethostent` 函数，用于从 hosts 文件中读取主机信息:**

* **`gethostent(void)`:**  这是 `gethostent_r` 的非可重入版本。
    * **功能:**  从本地的 `hosts` 文件中读取下一个主机信息条目。
    * **实现:** 它首先检查是否已打开 `hosts` 文件，如果没有则调用 `sethostent_r` 打开。然后调用 `netbsd_gethostent_r` 读取一行并解析。
    * **与 Android 功能的关系:**  允许应用程序从本地 `hosts` 文件中获取主机信息，这在没有 DNS 服务器或者需要覆盖 DNS 解析时很有用。
    * **用户或编程常见的使用错误:**  在多线程环境中使用可能导致线程安全问题，应优先使用 `gethostent_r`。忘记调用 `endhostent` 关闭文件句柄可能导致资源泄漏。

**Android Framework or NDK 如何一步步到达这里:**

1. **应用程序 (Java/Kotlin 或 Native):** 应用程序需要解析主机名或查找与 IP 地址关联的主机名。
2. **NDK (Native 开发):**  Native 代码可以直接调用 `gethostbyname`, `gethostbyaddr` 或 Android 特定的 `android_gethostbynamefornet`, `android_gethostbyaddrfornet` 函数。
3. **Android Framework (Java/Kotlin):**
    * **`java.net.InetAddress.getByName(String host)`:**  当 Java 代码调用此方法时，Android Framework 会通过 JNI 调用到 Bionic libc 中的 `getaddrinfo` 函数 (此文件未包含 `getaddrinfo` 的实现，但它是相关的)。
    * **`java.net.InetAddress.getByAddress(byte[] addr)`:**  类似地，此方法会通过 JNI 调用到 Bionic libc 中相关的地址查找函数。
4. **Bionic libc (`gethnamaddr.c`):**
    * 如果调用的是 `gethostbyname` 或 `gethostbyname2`，会调用此文件中的相应函数。
    * 如果调用的是 `gethostbyaddr`, 会调用此文件中的相应函数。
    * 如果调用的是 `android_gethostbynamefornet` 或 `android_gethostbyaddrfornet`，会调用此文件中的 Android 特定版本。
5. **DNS 解析或其他数据源:**  这些函数会根据配置 (`/etc/hosts`, DNS 服务器, YP/NIS 等) 查询主机信息。对于 DNS 查询，通常会涉及到 `res_state` 结构体和 `resolv.conf` 配置文件。

**Frida Hook 示例调试这些步骤:**

以下是一些使用 Frida Hook 调试 `gethostbyname` 和 `android_gethostbynamefornet` 的示例：

```javascript
// Hook gethostbyname
Interceptor.attach(Module.findExportByName("libc.so", "gethostbyname"), {
  onEnter: function(args) {
    console.log("gethostbyname called with hostname:", Memory.readUtf8String(args[0]));
  },
  onLeave: function(retval) {
    if (retval.isNull()) {
      console.log("gethostbyname failed");
    } else {
      const hostent = ptr(retval);
      console.log("gethostbyname returned hostent struct at:", hostent);
      const h_name = Memory.readUtf8String(Memory.readPointer(hostent));
      console.log("h_name:", h_name);
      // 可以进一步读取 h_addr_list 等字段
    }
  }
});

// Hook android_gethostbynamefornet
Interceptor.attach(Module.findExportByName("libc.so", "android_gethostbynamefornet"), {
  onEnter: function(args) {
    const hostname = Memory.readUtf8String(args[0]);
    const af = args[1].toInt32();
    const netid = args[2].toInt32();
    const mark = args[3].toInt32();
    console.log("android_gethostbynamefornet called with:");
    console.log("  hostname:", hostname);
    console.log("  af:", af);
    console.log("  netid:", netid);
    console.log("  mark:", mark);
  },
  onLeave: function(retval) {
    if (retval.isNull()) {
      console.log("android_gethostbynamefornet failed");
    } else {
      const hostent = ptr(retval);
      console.log("android_gethostbynamefornet returned hostent struct at:", hostent);
      // 读取 hostent 结构体内容
    }
  }
});
```

**归纳一下 `gethnamaddr.c` (第2部分) 的功能:**

总而言之，`bionic/libc/dns/net/gethnamaddr.c` 的第二部分主要负责以下功能：

1. **处理来自 Yellow Pages (YP/NIS) 的主机名和 IP 地址查询请求。**
2. **提供非可重入版本的 `gethostbyname`, `gethostbyname2`, `gethostbyaddr`, 和 `gethostent` 函数，方便简单的单线程应用程序使用。**
3. **提供 Android 特定的、允许指定网络 ID 的 `android_gethostbynamefornet` 和 `android_gethostbyaddrfornet` 函数，以支持 Android 系统中的网络隔离和多网络环境。**

这部分代码是 Android Bionic libc 中网络功能的重要组成部分，它使得应用程序能够解析主机名和执行反向 IP 地址查找，并考虑了 Android 平台的特定需求，如网络命名空间。

Prompt: 
```
这是目录为bionic/libc/dns/net/gethnamaddr.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
en + NS_IN6ADDRSZ > info->buflen)
			goto nospc;
		map_v4v6_address(bf, bf);
		hp->h_addrtype = AF_INET6;
		hp->h_length = NS_IN6ADDRSZ;
	}

	__res_put_state(res);
	*info->he = NETDB_SUCCESS;
	return NS_SUCCESS;
nospc:
	errno = ENOSPC;
	*info->he = NETDB_INTERNAL;
	return NS_UNAVAIL;
}

#ifdef YP
/*ARGSUSED*/
static struct hostent *
_yp_hostent(char *line, int af, struct getnamaddr *info)
{
	struct in6_addr host_addrs[MAXADDRS];
	char **aliases;
	size_t maxaliases;
	char *p = line;
	char *cp, **q, *ptr;
	size_t len, anum, i;
	int addrok;
	int more;
	size_t naddrs;
	struct hostent *hp = info->hp;

	_DIAGASSERT(line != NULL);

	hp->h_name = NULL;
	hp->h_addrtype = af;
	switch (af) {
	case AF_INET:
		hp->h_length = NS_INADDRSZ;
		break;
	case AF_INET6:
		hp->h_length = NS_IN6ADDRSZ;
		break;
	default:
		return NULL;
	}
	setup(aliases, maxaliases);
	naddrs = 0;
	q = aliases;

nextline:
	/* check for host_addrs overflow */
	if (naddrs >= __arraycount(host_addrs))
		goto done;

	more = 0;
	cp = strpbrk(p, " \t");
	if (cp == NULL)
		goto done;
	*cp++ = '\0';

	/* p has should have an address */
	addrok = inet_pton(af, p, &host_addrs[naddrs]);
	if (addrok != 1) {
		/* skip to the next line */
		while (cp && *cp) {
			if (*cp == '\n') {
				cp++;
				goto nextline;
			}
			cp++;
		}
		goto done;
	}
	naddrs++;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	p = cp;
	cp = strpbrk(p, " \t\n");
	if (cp != NULL) {
		if (*cp == '\n')
			more = 1;
		*cp++ = '\0';
	}
	if (!hp->h_name)
		hp->h_name = p;
	else if (strcmp(hp->h_name, p) == 0)
		;
	else
		addalias(q, p, aliases, maxaliases);
	p = cp;
	if (more)
		goto nextline;

	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (*cp == '\n') {
			cp++;
			goto nextline;
		}
		addalias(q, cp, aliases, maxaliases);
		cp = strpbrk(cp, " \t");
		if (cp != NULL)
			*cp++ = '\0';
	}

done:
	if (hp->h_name == NULL) {
		free(aliases);
		return NULL;
	}

	ptr = info->buf;
	len = info->buflen;

	anum = (size_t)(q - aliases);
	HENT_ARRAY(hp->h_addr_list, naddrs, ptr, len);
	HENT_ARRAY(hp->h_aliases, anum, ptr, len);

	for (i = 0; i < naddrs; i++)
		HENT_COPY(hp->h_addr_list[i], &host_addrs[i], hp->h_length,
		    ptr, len);
	hp->h_addr_list[naddrs] = NULL;

	HENT_SCOPY(hp->h_name, hp->h_name, ptr, len);

	for (i = 0; i < anum; i++)
		HENT_SCOPY(hp->h_aliases[i], aliases[i], ptr, len);
	hp->h_aliases[anum] = NULL;
	free(aliases);

	return hp;
nospc:
	free(aliases);
	*info->he = NETDB_INTERNAL;
	errno = ENOSPC;
	return NULL;
}

/*ARGSUSED*/
int
_yp_gethtbyaddr(void *rv, void *cb_data, va_list ap)
{
	struct hostent *hp = NULL;
	char *ypcurrent;
	int ypcurrentlen, r;
	char name[INET6_ADDRSTRLEN];	/* XXX enough? */
	const unsigned char *uaddr;
	int af;
	const char *map;
	struct getnamaddr *info = rv;

	_DIAGASSERT(rv != NULL);

	uaddr = va_arg(ap, unsigned char *);
	/* NOSTRICT skip len */(void)va_arg(ap, int);
	af = va_arg(ap, int);

	if (!__ypdomain) {
		if (_yp_check(&__ypdomain) == 0)
			return NS_UNAVAIL;
	}
	/*
	 * XXX unfortunately, we cannot support IPv6 extended scoped address
	 * notation here.  gethostbyaddr() is not scope-aware.  too bad.
	 */
	if (inet_ntop(af, uaddr, name, (socklen_t)sizeof(name)) == NULL)
		return NS_UNAVAIL;
	switch (af) {
	case AF_INET:
		map = "hosts.byaddr";
		break;
	default:
		map = "ipnodes.byaddr";
		break;
	}
	ypcurrent = NULL;
	r = yp_match(__ypdomain, map, name,
		(int)strlen(name), &ypcurrent, &ypcurrentlen);
	if (r == 0)
		hp = _yp_hostent(ypcurrent, af, info);
	else
		hp = NULL;
	free(ypcurrent);
	if (hp == NULL) {
		*info->he = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	}
	return NS_SUCCESS;
}

/*ARGSUSED*/
int
_yp_gethtbyname(void *rv, void *cb_data, va_list ap)
{
	struct hostent *hp;
	char *ypcurrent;
	int ypcurrentlen, r;
	const char *name;
	int af;
	const char *map;
	struct getnamaddr *info = rv;

	_DIAGASSERT(rv != NULL);

	name = va_arg(ap, char *);
	/* NOSTRICT skip string len */(void)va_arg(ap, int);
	af = va_arg(ap, int);

	if (!__ypdomain) {
		if (_yp_check(&__ypdomain) == 0)
			return NS_UNAVAIL;
	}
	switch (af) {
	case AF_INET:
		map = "hosts.byname";
		break;
	default:
		map = "ipnodes.byname";
		break;
	}
	ypcurrent = NULL;
	r = yp_match(__ypdomain, map, name,
		(int)strlen(name), &ypcurrent, &ypcurrentlen);
	if (r == 0)
		hp = _yp_hostent(ypcurrent, af, info);
	else
		hp = NULL;
	free(ypcurrent);
	if (hp == NULL) {
		*info->he = HOST_NOT_FOUND;
		return NS_NOTFOUND;
	}
	return NS_SUCCESS;
}
#endif

/*
 * Non-reentrant versions.
 */

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
struct hostent *
gethostbyname(const char *name)
{
	struct hostent *result = NULL;
	struct res_static* rs = __res_get_static();

	gethostbyname_r(name, &rs->host, rs->hostbuf, sizeof(rs->hostbuf), &result, &h_errno);
	return result;
}

struct hostent *
gethostbyname2(const char *name, int af)
{
	struct hostent *result = NULL;
	struct res_static* rs = __res_get_static();

	gethostbyname2_r(name, af, &rs->host, rs->hostbuf, sizeof(rs->hostbuf), &result, &h_errno);
	return result;
}

// android_gethostby*fornet can be called in two different contexts.
//  - In the proxy client context (proxy != NULL), |netid| is |app_netid|.
//  - In the proxy listener context (proxy == NULL), |netid| is |dns_netid|.
// The netcontext is constructed before checking which context we are in.
// Therefore, we have to populate both fields, and rely on the downstream code to check whether
// |proxy == NULL|, and use that info to query the field that matches the caller's intent.
static struct android_net_context make_context(unsigned netid, unsigned mark) {
	struct android_net_context netcontext = NETCONTEXT_UNSET;
	netcontext.app_netid = netid;
	netcontext.app_mark = mark;
	netcontext.dns_netid = netid;
	netcontext.dns_mark = mark;
	return netcontext;
}

struct hostent *
android_gethostbynamefornet(const char *name, int af, unsigned netid, unsigned mark)
{
	const struct android_net_context netcontext = make_context(netid, mark);
	return android_gethostbynamefornetcontext(name, af, &netcontext);
}

struct hostent *
android_gethostbynamefornetcontext(const char *name, int af,
	const struct android_net_context *netcontext)
{
	struct hostent *hp;
	res_state res = __res_get_state();
	if (res == NULL)
		return NULL;
	struct res_static* rs = __res_get_static();
	hp = gethostbyname_internal(name, af, res, &rs->host, rs->hostbuf, sizeof(rs->hostbuf),
	                            &h_errno, netcontext);
	__res_put_state(res);
	return hp;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
struct hostent *
gethostbyaddr(const void *addr, socklen_t len, int af)
{
	return android_gethostbyaddrfornetcontext_proxy(addr, len, af, &NETCONTEXT_UNSET);
}

struct hostent *
android_gethostbyaddrfornet(const void *addr, socklen_t len, int af, unsigned netid, unsigned mark)
{
	const struct android_net_context netcontext = make_context(netid, mark);
	return android_gethostbyaddrfornetcontext(addr, len, af, &netcontext);
}

struct hostent *
android_gethostbyaddrfornetcontext(const void *addr, socklen_t len, int af,
	const struct android_net_context *netcontext)
{
	return android_gethostbyaddrfornetcontext_proxy(addr, len, af, netcontext);
}

__LIBC_HIDDEN__ struct hostent*
android_gethostbyaddrfornetcontext_proxy(const void* addr, socklen_t len, int af,
                                  const struct android_net_context *netcontext)
{
	struct res_static* rs = __res_get_static();
	return android_gethostbyaddrfornetcontext_proxy_internal(addr, len, af, &rs->host, rs->hostbuf,
                                                    sizeof(rs->hostbuf), &h_errno, netcontext);
}

struct hostent *
gethostent(void)
{
  struct res_static* rs = __res_get_static();
	if (!rs->hostf) {
	  sethostent_r(&rs->hostf);
	  if (!rs->hostf) {
	    h_errno = NETDB_INTERNAL;
	    return NULL;
	  }
	}
	memset(&rs->host, 0, sizeof(rs->host));
	return netbsd_gethostent_r(rs->hostf, &rs->host, rs->hostbuf, sizeof(rs->hostbuf), &h_errno);
}

"""


```