Response:
The user wants a summary of the functionality of the provided C code file `bionic/libc/dns/net/getaddrinfo.c`. This file is part of Android's Bionic library and is responsible for the `getaddrinfo` function.

Here's a breakdown of the tasks:

1. **Identify the core functionality:**  The primary purpose is to resolve hostnames to IP addresses.
2. **Explain each libc function:** This involves detailing the implementation of functions like `getanswer`, `_get_scope`, `_get_label`, `_get_precedence`, `_common_prefix_len`, `_rfc6724_compare`, `_find_src_addr`, `_rfc6724_sort`, `_dns_getaddrinfo`, `_files_getaddrinfo`, `res_queryN`, `res_searchN`, and `res_querydomainN`.
3. **Illustrate Android-specific aspects:** Explain how this code interacts with Android's networking stack, potentially mentioning `netd`, network namespaces, and the use of `SO_MARK`.
4. **Address dynamic linking:** Since this is part of `libc`, explain how it's linked and accessed by other processes. Provide a simplified `so` layout.
5. **Provide logical reasoning:** For complex functions, give hypothetical inputs and expected outputs.
6. **Highlight common user errors:**  Explain typical mistakes developers might make when using `getaddrinfo`.
7. **Trace the call path:** Describe how the Android framework or NDK calls into this code, offering a Frida hook example.
8. **Summarize the overall functionality:**  Provide a concise conclusion about the file's role.

**Mental Sandbox:**

*   **Core `getaddrinfo` logic:**  It likely involves checking a local hosts file, then querying DNS servers. The code seems to implement RFC 6724 for address sorting.
*   **`libc` functions:**  Need to analyze the implementation details of each function. Some deal with DNS parsing (`getanswer`), others with address preference (`_rfc6724_compare`, `_rfc6724_sort`).
*   **Android specifics:** The code mentions `netcontext`, `app_mark`, and `uid`, which are clearly Android extensions for network management and security. The use of `socket` with `SOCK_DGRAM` and `connect` to determine the source address is interesting.
*   **Dynamic linking:** `libc.so` is a fundamental library, so all applications implicitly link against it. The dynamic linker (`linker`) handles the loading and symbol resolution.
*   **Frida hook:** A hook on `getaddrinfo` or related functions like `_dns_getaddrinfo` would be useful to observe the behavior.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果它与android的功能有关系，请做出对应的举例说明: Yes
3. 详细解释每一个libc函数的功能是如何实现的: Yes
4. 对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程: Yes
5. 如果做了逻辑推理，请给出假设输入与输出: Yes
6. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
7. 说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤: Yes
8. 用中文回复: Yes
9. 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Strategizing complete.** I will now proceed with generating the response based on the analysis above. I will structure the response logically, starting with the overall functionality and then delving into the details of each aspect. The Frida hook example will focus on a function like `_dns_getaddrinfo` to capture the DNS query process.
这是 `bionic/libc/dns/net/getaddrinfo.c` 源代码文件的第二部分，它主要负责实现 `getaddrinfo` 函数中与 DNS 查询和本地文件查询相关的逻辑，以及对查询结果进行排序的功能。

**归纳一下它的功能：**

本代码文件的核心功能是作为 `getaddrinfo` 函数的一部分，负责：

1. **执行 DNS 查询:**  当 `getaddrinfo` 需要通过 DNS 解析主机名时，此部分代码会构造 DNS 查询报文，发送到配置的 DNS 服务器，并解析返回的 DNS 响应。
2. **处理本地 hosts 文件查询:**  当系统配置为先查询本地 `hosts` 文件时，此部分代码会读取并解析 `/etc/hosts` 文件，查找与目标主机名匹配的 IP 地址。
3. **合并和过滤查询结果:**  从 DNS 服务器和本地 `hosts` 文件获取的 IP 地址会被合并到一个链表中。
4. **根据 RFC 6724 排序地址:**  实现了 RFC 6724 中定义的源地址选择算法，对获取到的 IP 地址进行排序，以选择最优的连接目标地址。
5. **管理 DNS 查询状态:**  使用 `res_state` 结构体管理 DNS 查询的状态信息，例如已尝试的 DNS 服务器、查询选项等。

**与 Android 功能的关系举例说明：**

*   **网络连接:** 当 Android 应用需要连接到网络上的某个主机时（例如打开网页、连接服务器），它会调用 `getaddrinfo` 函数来解析主机名。本文件中的代码负责执行实际的 DNS 查询，将主机名转换为 IP 地址，这是建立网络连接的基础。
*   **网络策略和权限:** Android 的网络策略和权限管理会影响 DNS 查询。例如，应用可能被限制只能通过特定的网络接口进行连接。代码中可以看到 `netcontext` 结构体的使用，它包含了应用的 `mark` 和 `uid`，这些信息会被传递到 DNS 查询过程中，以便应用网络策略。
*   **VPN 和代理:** 当设备连接到 VPN 或使用了代理时，DNS 查询的路径可能会发生变化。此文件中的代码会根据当前的网络配置，将 DNS 查询发送到正确的 DNS 服务器。

**详细解释每一个 libc 函数的功能是如何实现的：**

*   **`getanswer(const querybuf *answer, int anslen, const char *qname, int qtype, const struct addrinfo *pai)`:**
    *   **功能:** 解析 DNS 服务器返回的响应报文，提取出 IP 地址和其他相关信息。
    *   **实现:**
        1. 接收 DNS 响应报文 (`answer`)，响应长度 (`anslen`)，原始查询的主机名 (`qname`)，查询类型 (`qtype`) 和原始的 `addrinfo` 结构体 (`pai`) 作为输入。
        2. 解析 DNS 报文头部，获取应答记录的数量 (`ancount`)。
        3. 遍历每个应答记录，根据记录类型 (`type`) 提取出 IP 地址（A 记录对应 IPv4，AAAA 记录对应 IPv6）。
        4. 处理 CNAME 记录，如果遇到 CNAME 记录，会继续查询 CNAME 指向的真实主机名。
        5. 将解析出的 IP 地址信息填充到新的 `addrinfo` 结构体中，并将其添加到链表中。
        6. `BOUNDED_INCR` 和 `BOUNDS_CHECK` 宏用于进行边界检查，防止解析过程中读取越界。
*   **`_get_scope(const struct sockaddr *addr)`:**
    *   **功能:**  根据 IP 地址判断其作用域（例如，链路本地、站点本地、全局等）。这是 RFC 6724 地址排序算法的一部分。
    *   **实现:**
        1. 接收一个 `sockaddr` 结构体指针，该结构体包含了 IP 地址信息。
        2. 根据地址族 (`sa_family`) 判断是 IPv4 还是 IPv6 地址。
        3. 对于 IPv6 地址，根据地址前缀判断其作用域（例如，环回地址、链路本地地址、组播地址等）。
        4. 对于 IPv4 地址，根据地址范围判断其作用域（例如，环回地址、自动配置地址等）。
*   **`_get_label(const struct sockaddr *addr)`:**
    *   **功能:**  根据 IP 地址获取其标签，用于 RFC 6724 地址排序。
    *   **实现:**
        1. 接收一个 `sockaddr` 结构体指针。
        2. 根据地址族和地址前缀，返回一个表示地址标签的整数值。不同的标签代表不同的地址类型（例如，环回地址、IPv4 映射地址、6to4 地址等）。
*   **`_get_precedence(const struct sockaddr *addr)`:**
    *   **功能:**  根据 IP 地址获取其优先级，用于 RFC 6724 地址排序。
    *   **实现:**
        1. 接收一个 `sockaddr` 结构体指针。
        2. 根据地址族和地址前缀，返回一个表示地址优先级的整数值。
*   **`_common_prefix_len(const struct in6_addr *a1, const struct in6_addr *a2)`:**
    *   **功能:**  计算两个 IPv6 地址之间相同前缀的长度（位数）。
    *   **实现:**
        1. 接收两个 `in6_addr` 结构体指针。
        2. 逐字节比较两个 IPv6 地址，直到找到不同的字节。
        3. 在不同的字节中，逐位比较，找到第一个不同的位，并返回相同前缀的长度。
*   **`_rfc6724_compare(const void *ptr1, const void* ptr2)`:**
    *   **功能:**  比较两个 `addrinfo_sort_elem` 结构体，用于 RFC 6724 地址排序。
    *   **实现:**
        1. 接收两个指向 `addrinfo_sort_elem` 结构体的指针。
        2. 按照 RFC 6724 的规则，依次比较两个地址的可用性、作用域匹配度、是否废弃、是否为本地地址、标签匹配度、优先级、传输协议、作用域大小、最长前缀匹配等。
        3. 返回一个负数、零或正数，表示第一个地址小于、等于或大于第二个地址。
*   **`_find_src_addr(const struct sockaddr *addr, struct sockaddr *src_addr, unsigned mark, uid_t uid)`:**
    *   **功能:**  尝试找到用于连接到目标地址的源 IP 地址。
    *   **实现:**
        1. 创建一个 UDP 套接字。
        2. 如果指定了 `mark` 和 `uid`，则设置套接字的 `SO_MARK` 选项并修改套接字的所有者。
        3. 调用 `connect` 函数连接到目标地址。即使是 UDP 套接字，`connect` 也不会真正建立连接，而是用于绑定本地地址。
        4. 调用 `getsockname` 获取本地绑定的地址，即为源 IP 地址。
        5. 关闭套接字。
*   **`_rfc6724_sort(struct addrinfo *list_sentinel, unsigned mark, uid_t uid)`:**
    *   **功能:**  对 `addrinfo` 链表按照 RFC 6724 规则进行排序。
    *   **实现:**
        1. 将链表转换为 `addrinfo_sort_elem` 数组，每个元素包含一个 `addrinfo` 结构体指针、源地址信息和原始顺序。
        2. 调用 `_find_src_addr` 函数为每个目标地址找到合适的源地址。
        3. 使用 `qsort` 函数和 `_rfc6724_compare` 函数对数组进行排序。
        4. 将排序后的数组重新组织成链表。
*   **`_dns_getaddrinfo(void *rv, void *cb_data, va_list ap)`:**
    *   **功能:**  执行 DNS 查询，获取主机名的 IP 地址。
    *   **实现:**
        1. 从 `va_list` 中获取主机名 (`name`)，`addrinfo` 提示结构体 (`pai`) 和网络上下文信息 (`netcontext`)。
        2. 根据 `pai` 中的地址族信息，构造相应的 DNS 查询报文（A 记录查询 IPv4，AAAA 记录查询 IPv6）。如果 `ai_family` 是 `AF_UNSPEC`，则优先查询 IPv6，如果失败再查询 IPv4。
        3. 调用 `res_searchN` 函数执行 DNS 查询。
        4. 调用 `getanswer` 函数解析 DNS 响应，并将结果添加到 `addrinfo` 链表中。
        5. 调用 `_rfc6724_sort` 函数对结果进行排序。
        6. 将排序后的 `addrinfo` 链表存储到 `rv` 指向的内存。
*   **`_sethtent(FILE **hostf)`:**
    *   **功能:**  打开或重置用于读取 `/etc/hosts` 文件的文件指针。
    *   **实现:**
        1. 如果文件指针 `*hostf` 为空，则打开 `/etc/hosts` 文件，并将其文件指针赋值给 `*hostf`。
        2. 如果文件指针 `*hostf` 不为空，则使用 `rewind` 函数将文件指针移动到文件开头。
*   **`_endhtent(FILE **hostf)`:**
    *   **功能:**  关闭用于读取 `/etc/hosts` 文件的文件指针。
    *   **实现:**
        1. 如果文件指针 `*hostf` 不为空，则使用 `fclose` 函数关闭文件，并将 `*hostf` 设置为空。
*   **`_gethtent(FILE **hostf, const char *name, const struct addrinfo *pai)`:**
    *   **功能:**  从 `/etc/hosts` 文件中读取一行，并查找与指定主机名匹配的 IP 地址。
    *   **实现:**
        1. 如果文件指针 `*hostf` 为空，则调用 `_sethtent` 打开文件。
        2. 使用 `fgets` 函数读取文件中的一行。
        3. 忽略以 `#` 开头的注释行。
        4. 解析该行，提取出 IP 地址和主机名列表。
        5. 比较主机名列表中的每个主机名与目标主机名 (`name`)，如果匹配，则使用 `getaddrinfo` 函数解析 IP 地址字符串，并将其添加到 `addrinfo` 链表中。
*   **`_files_getaddrinfo(void *rv, void *cb_data, va_list ap)`:**
    *   **功能:**  通过读取本地 `/etc/hosts` 文件获取主机名的 IP 地址。
    *   **实现:**
        1. 从 `va_list` 中获取主机名 (`name`) 和 `addrinfo` 提示结构体 (`pai`)。
        2. 调用 `_sethtent` 打开 `/etc/hosts` 文件。
        3. 循环调用 `_gethtent` 函数，逐行读取并查找匹配的 IP 地址。
        4. 将找到的 IP 地址添加到 `addrinfo` 链表中。
        5. 调用 `_endhtent` 关闭文件。
        6. 将 `addrinfo` 链表存储到 `rv` 指向的内存。
*   **`res_queryN(const char *name, struct res_target *target, res_state res)`:**
    *   **功能:**  构造 DNS 查询报文，发送到 DNS 服务器，并接收响应。
    *   **实现:**
        1. 接收主机名 (`name`)，目标结构体 (`target`) 和 DNS 状态信息 (`res`)。
        2. 循环遍历 `target` 链表中的每个目标（例如，IPv4 和 IPv6 查询）。
        3. 调用 `res_nmkquery` 函数构造 DNS 查询报文。
        4. 调用 `res_nsend` 函数发送查询报文并接收响应。
        5. 检查响应报文的返回码和应答记录数量，判断查询是否成功。
        6. 如果启用了 EDNS0，并且查询失败，可能会尝试禁用 EDNS0 后重试。
*   **`res_searchN(const char *name, struct res_target *target, res_state res)`:**
    *   **功能:**  根据配置的搜索域列表，尝试进行 DNS 查询，直到找到答案或所有搜索域都尝试完毕。
    *   **实现:**
        1. 接收主机名 (`name`)，目标结构体 (`target`) 和 DNS 状态信息 (`res`)。
        2. 如果主机名中没有点号，并且启用了 `RES_DEFNAMES` 选项，则尝试添加默认域名进行查询。
        3. 如果主机名中有点号，但没有尾部的点号，并且启用了 `RES_DNSRCH` 选项，则遍历配置的搜索域列表，依次尝试将搜索域添加到主机名后进行查询。
        4. 调用 `res_querydomainN` 函数执行实际的查询。
        5. 根据查询结果的返回码 (`h_errno`)，判断是否继续搜索下一个域。
        6. 最后，如果之前没有尝试过直接查询原始主机名，则进行一次尝试。
*   **`res_querydomainN(const char *name, const char *domain, struct res_target *target, res_state res)`:**
    *   **功能:**  对指定的主机名和域名进行 DNS 查询。
    *   **实现:**
        1. 接收主机名 (`name`)，域名 (`domain`)，目标结构体 (`target`) 和 DNS 状态信息 (`res`)。
        2. 如果 `domain` 为空，则检查 `name` 是否有尾部的点号，如果有则移除。
        3. 如果 `domain` 不为空，则将 `name` 和 `domain` 拼接成完整的域名。
        4. 调用 `res_queryN` 函数执行实际的查询。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`getaddrinfo` 函数及其相关的代码位于 `libc.so` 中。

**`libc.so` 布局样本（简化）：**

```
libc.so:
    ...
    .text:  # 代码段
        getaddrinfo:  # getaddrinfo 函数入口
            ...
            call    _dns_getaddrinfo  # 调用 _dns_getaddrinfo
            call    _files_getaddrinfo # 调用 _files_getaddrinfo
            ...
        _dns_getaddrinfo:
            ...
            call    res_searchN
            ...
        res_searchN:
            ...
            call    res_queryN
            ...
        res_queryN:
            ...
            ; 调用其他 libc 中的网络相关函数，例如 socket, sendto, recvfrom 等
            ...
        _files_getaddrinfo:
            ...
            call    _sethtent
            call    _gethtent
            call    _endhtent
            ...
    .data:  # 数据段
        ...
    .bss:   # 未初始化数据段
        ...
    .dynamic: # 动态链接信息
        NEEDED libcutils.so  # 依赖的库
        SONAME libc.so
        ...
    .symtab: # 符号表
        getaddrinfo
        _dns_getaddrinfo
        res_searchN
        res_queryN
        _files_getaddrinfo
        ...
    .strtab: # 字符串表
        ...
```

**链接的处理过程：**

1. **编译时链接:** 当应用程序或共享库链接到 `libc` 时，链接器 (ld) 会在 `libc.so` 的符号表 (`.symtab`) 中查找 `getaddrinfo` 等函数的符号。
2. **运行时链接:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** 动态链接器会解析应用程序中对 `getaddrinfo` 等符号的引用，将其指向 `libc.so` 中对应的函数地址。这是通过查找 `libc.so` 的符号表完成的。
4. **延迟绑定 (可选):** 为了优化启动性能，符号的解析可能采用延迟绑定的方式。只有在第一次调用 `getaddrinfo` 时，动态链接器才会真正解析其地址。

**逻辑推理，给出假设输入与输出：**

**假设输入：**

*   `getaddrinfo("www.google.com", NULL, NULL, &res)` 被调用。
*   系统配置为先查询 DNS 服务器。
*   DNS 服务器返回 `www.google.com` 的 IPv4 地址为 `142.250.180.142` 和 IPv6 地址为 `2404:6800:4007:81b::200e`。

**预期输出：**

`res` 指向的 `addrinfo` 链表可能包含两个元素（顺序可能因 RFC 6724 排序而异）：

*   第一个 `addrinfo` 结构体包含以下信息：
    *   `ai_family`: `AF_INET`
    *   `ai_addr`: 指向 `sockaddr_in` 结构体，其 `sin_addr.s_addr` 为 `142.250.180.142` 的网络字节序。
*   第二个 `addrinfo` 结构体包含以下信息：
    *   `ai_family`: `AF_INET6`
    *   `ai_addr`: 指向 `sockaddr_in6` 结构体，其 `sin6_addr` 为 `2404:6800:4007:81b::200e`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **未检查 `getaddrinfo` 的返回值:** `getaddrinfo` 返回 0 表示成功，非 0 表示出错。开发者需要检查返回值并使用 `gai_strerror` 获取错误信息。
    ```c
    struct addrinfo *res;
    int error = getaddrinfo("invalid_hostname", NULL, NULL, &res);
    if (error != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error));
        // 缺少错误处理
    }
    ```
2. **泄露 `addrinfo` 链表:** `getaddrinfo` 成功时会分配内存用于存储 `addrinfo` 链表，使用完毕后需要调用 `freeaddrinfo` 释放内存。
    ```c
    struct addrinfo *res;
    getaddrinfo("www.example.com", "80", NULL, &res);
    // ... 使用 res
    // 缺少 freeaddrinfo(res);
    ```
3. **`hints` 结构体使用不当:**  `hints` 结构体用于指导 `getaddrinfo` 的行为。例如，如果只想要 IPv4 地址，应该设置 `hints.ai_family = AF_INET`。设置不当可能导致无法获取期望的地址类型。
    ```c
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // 忘记设置 ai_family
    getaddrinfo("www.example.com", "80", &hints, &res);
    ```
4. **假设地址族:**  不要假设 `addrinfo` 链表中返回的地址族，应该遍历链表并根据 `ai_family` 处理不同类型的地址。
    ```c
    struct addrinfo *res, *p;
    getaddrinfo("www.example.com", "80", NULL, &res);
    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)p->ai_addr; // 假设是 IPv4
        // ...
    }
    freeaddrinfo(res);
    ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

1. **Android Framework/NDK 调用:**
    *   **Java Framework:** Android Framework 中的 Java 代码（例如，`java.net.InetAddress.getAllByName()` 或 `java.net.Socket` 构造函数）最终会通过 JNI 调用到 Native 代码。
    *   **NDK:** 使用 NDK 开发的应用可以直接调用 C/C++ 标准库函数，包括 `getaddrinfo`。

2. **JNI 调用:** Framework 中的 Java 方法会调用到 `libjavacrypto.so`、`libnativehelper.so` 或其他相关库中的 JNI 函数。

3. **Native 函数调用:** JNI 函数会调用到 Bionic 库中的 `getaddrinfo` 函数，该函数位于 `libc.so` 中。

4. **`getaddrinfo` 内部流程:** `getaddrinfo` 函数内部会根据配置和参数，调用 `_dns_getaddrinfo`（进行 DNS 查询）和 `_files_getaddrinfo`（查询本地 hosts 文件）。

**Frida Hook 示例：**

可以使用 Frida Hook `_dns_getaddrinfo` 函数来观察 DNS 查询过程。

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_dns_getaddrinfo"), {
    onEnter: function(args) {
        const name = Memory.readUtf8String(args[0]);
        console.log("[*] _dns_getaddrinfo called with name: " + name);
    },
    onLeave: function(retval) {
        console.log("[*] _dns_getaddrinfo returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print("[*] Script loaded, waiting for _dns_getaddrinfo calls...")
sys.stdin.read()
session.detach()
```

**使用方法：**

1. 安装 Frida 和 Python 的 Frida 模块。
2. 将 `your.app.package` 替换为你要调试的 Android 应用的包名。
3. 运行 Python 脚本。
4. 在 Android 设备上运行目标应用，并执行触发 `getaddrinfo` 调用的操作（例如，访问一个网址）。
5. Frida 会 Hook `_dns_getaddrinfo` 函数，并打印出传入的主机名。

这个 Frida 示例可以帮助你验证 Android 应用是如何调用到 `_dns_getaddrinfo` 的，并可以观察传递给该函数的主机名。你可以进一步 Hook 其他相关函数，例如 `res_searchN` 或 `res_queryN`，以更深入地了解 DNS 查询的细节。

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
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
id == lscopeid)
		return 0;
	else
		return -1;
}
#endif

/* code duplicate with gethnamaddr.c */

static const char AskedForGot[] =
	"gethostby*.getanswer: asked for \"%s\", got \"%s\"";

#define BOUNDED_INCR(x) \
	do { \
		BOUNDS_CHECK(cp, x); \
		cp += (x); \
	} while (/*CONSTCOND*/0)

#define BOUNDS_CHECK(ptr, count) \
	do { \
		if (eom - (ptr) < (count)) { h_errno = NO_RECOVERY; return NULL; } \
	} while (/*CONSTCOND*/0)

static struct addrinfo *
getanswer(const querybuf *answer, int anslen, const char *qname, int qtype,
    const struct addrinfo *pai)
{
	struct addrinfo sentinel, *cur;
	struct addrinfo ai;
	const struct afd *afd;
	char *canonname;
	const HEADER *hp;
	const u_char *cp;
	int n;
	const u_char *eom;
	char *bp, *ep;
	int type, class, ancount, qdcount;
	int haveanswer, had_error;
	char tbuf[MAXDNAME];
	int (*name_ok) (const char *);
	char hostbuf[8*1024];

	assert(answer != NULL);
	assert(qname != NULL);
	assert(pai != NULL);

	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	canonname = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
	case T_ANY:	/*use T_ANY only for T_A/T_AAAA lookup*/
		name_ok = res_hnok;
		break;
	default:
		return NULL;	/* XXX should be abort(); */
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof hostbuf;
	cp = answer->buf;
	BOUNDED_INCR(HFIXEDSZ);
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	BOUNDED_INCR(n + QFIXEDSZ);
	if (qtype == T_A || qtype == T_AAAA || qtype == T_ANY) {
		/* res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		if (n >= MAXHOSTNAMELEN) {
			h_errno = NO_RECOVERY;
			return (NULL);
		}
		canonname = bp;
		bp += n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = canonname;
	}
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		BOUNDS_CHECK(cp, 3 * INT16SZ + INT32SZ);
		type = _getshort(cp);
 		cp += INT16SZ;			/* type */
		class = _getshort(cp);
 		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		BOUNDS_CHECK(cp, n);
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA || qtype == T_ANY) &&
		    type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf, sizeof tbuf);
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > ep - bp || n >= MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			strlcpy(bp, tbuf, (size_t)(ep - bp));
			canonname = bp;
			bp += n;
			continue;
		}
		if (qtype == T_ANY) {
			if (!(type == T_A || type == T_AAAA)) {
				cp += n;
				continue;
			}
		} else if (type != qtype) {
			if (type != T_KEY && type != T_SIG)
				syslog(LOG_NOTICE|LOG_AUTH,
	       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				       qname, p_class(C_IN), p_type(qtype),
				       p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_A:
		case T_AAAA:
			if (strcasecmp(canonname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
				       AskedForGot, canonname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			if (type == T_A && n != INADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA && n != IN6ADDRSZ) {
				cp += n;
				continue;
			}
			if (type == T_AAAA) {
				struct in6_addr in6;
				memcpy(&in6, cp, IN6ADDRSZ);
				if (IN6_IS_ADDR_V4MAPPED(&in6)) {
					cp += n;
					continue;
				}
			}
			if (!haveanswer) {
				int nn;

				canonname = bp;
				nn = strlen(bp) + 1;	/* for the \0 */
				bp += nn;
			}

			/* don't overwrite pai */
			ai = *pai;
			ai.ai_family = (type == T_A) ? AF_INET : AF_INET6;
			afd = find_afd(ai.ai_family);
			if (afd == NULL) {
				cp += n;
				continue;
			}
			cur->ai_next = get_ai(&ai, afd, (const char *)cp);
			if (cur->ai_next == NULL)
				had_error++;
			while (cur && cur->ai_next)
				cur = cur->ai_next;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		if (!canonname)
			(void)get_canonname(pai, sentinel.ai_next, qname);
		else
			(void)get_canonname(pai, sentinel.ai_next, canonname);
		h_errno = NETDB_SUCCESS;
		return sentinel.ai_next;
	}

	h_errno = NO_RECOVERY;
	return NULL;
}

struct addrinfo_sort_elem {
	struct addrinfo *ai;
	int has_src_addr;
	sockaddr_union src_addr;
	int original_order;
};

/*ARGSUSED*/
static int
_get_scope(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
			return IPV6_ADDR_MC_SCOPE(&addr6->sin6_addr);
		} else if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
			   IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
			/*
			 * RFC 4291 section 2.5.3 says loopback is to be treated as having
			 * link-local scope.
			 */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		} else if (IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr)) {
			return IPV6_ADDR_SCOPE_SITELOCAL;
		} else {
			return IPV6_ADDR_SCOPE_GLOBAL;
		}
	} else if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
		unsigned long int na = ntohl(addr4->sin_addr.s_addr);

		if (IN_LOOPBACK(na) ||                          /* 127.0.0.0/8 */
		    (na & 0xffff0000) == 0xa9fe0000) {          /* 169.254.0.0/16 */
			return IPV6_ADDR_SCOPE_LINKLOCAL;
		} else {
			/*
			 * RFC 6724 section 3.2. Other IPv4 addresses, including private addresses
			 * and shared addresses (100.64.0.0/10), are assigned global scope.
			 */
			return IPV6_ADDR_SCOPE_GLOBAL;
		}
	} else {
		/*
		 * This should never happen.
		 * Return a scope with low priority as a last resort.
		 */
		return IPV6_ADDR_SCOPE_NODELOCAL;
	}
}

/* These macros are modelled after the ones in <netinet/in6.h>. */

/* RFC 4380, section 2.6 */
#define IN6_IS_ADDR_TEREDO(a)	 \
	((*(const uint32_t *)(const void *)(&(a)->s6_addr[0]) == ntohl(0x20010000)))

/* RFC 3056, section 2. */
#define IN6_IS_ADDR_6TO4(a)	 \
	(((a)->s6_addr[0] == 0x20) && ((a)->s6_addr[1] == 0x02))

/* 6bone testing address area (3ffe::/16), deprecated in RFC 3701. */
#define IN6_IS_ADDR_6BONE(a)      \
	(((a)->s6_addr[0] == 0x3f) && ((a)->s6_addr[1] == 0xfe))

/*
 * Get the label for a given IPv4/IPv6 address.
 * RFC 6724, section 2.1.
 */

/*ARGSUSED*/
static int
_get_label(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return 4;
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;
		if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) {
			return 0;
		} else if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
			return 4;
		} else if (IN6_IS_ADDR_6TO4(&addr6->sin6_addr)) {
			return 2;
		} else if (IN6_IS_ADDR_TEREDO(&addr6->sin6_addr)) {
			return 5;
		} else if (IN6_IS_ADDR_ULA(&addr6->sin6_addr)) {
			return 13;
		} else if (IN6_IS_ADDR_V4COMPAT(&addr6->sin6_addr)) {
			return 3;
		} else if (IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr)) {
			return 11;
		} else if (IN6_IS_ADDR_6BONE(&addr6->sin6_addr)) {
			return 12;
		} else {
			/* All other IPv6 addresses, including global unicast addresses. */
			return 1;
		}
	} else {
		/*
		 * This should never happen.
		 * Return a semi-random label as a last resort.
		 */
		return 1;
	}
}

/*
 * Get the precedence for a given IPv4/IPv6 address.
 * RFC 6724, section 2.1.
 */

/*ARGSUSED*/
static int
_get_precedence(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return 35;
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr)) {
			return 50;
		} else if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
			return 35;
		} else if (IN6_IS_ADDR_6TO4(&addr6->sin6_addr)) {
			return 30;
		} else if (IN6_IS_ADDR_TEREDO(&addr6->sin6_addr)) {
			return 5;
		} else if (IN6_IS_ADDR_ULA(&addr6->sin6_addr)) {
			return 3;
		} else if (IN6_IS_ADDR_V4COMPAT(&addr6->sin6_addr) ||
		           IN6_IS_ADDR_SITELOCAL(&addr6->sin6_addr) ||
		           IN6_IS_ADDR_6BONE(&addr6->sin6_addr)) {
			return 1;
		} else {
			/* All other IPv6 addresses, including global unicast addresses. */
			return 40;
		}
	} else {
		return 1;
	}
}

/*
 * Find number of matching initial bits between the two addresses a1 and a2.
 */

/*ARGSUSED*/
static int
_common_prefix_len(const struct in6_addr *a1, const struct in6_addr *a2)
{
	const char *p1 = (const char *)a1;
	const char *p2 = (const char *)a2;
	unsigned i;

	for (i = 0; i < sizeof(*a1); ++i) {
		int x, j;

		if (p1[i] == p2[i]) {
			continue;
		}
		x = p1[i] ^ p2[i];
		for (j = 0; j < CHAR_BIT; ++j) {
			if (x & (1 << (CHAR_BIT - 1))) {
				return i * CHAR_BIT + j;
			}
			x <<= 1;
		}
	}
	return sizeof(*a1) * CHAR_BIT;
}

/*
 * Compare two source/destination address pairs.
 * RFC 6724, section 6.
 */

/*ARGSUSED*/
static int
_rfc6724_compare(const void *ptr1, const void* ptr2)
{
	const struct addrinfo_sort_elem *a1 = (const struct addrinfo_sort_elem *)ptr1;
	const struct addrinfo_sort_elem *a2 = (const struct addrinfo_sort_elem *)ptr2;
	int scope_src1, scope_dst1, scope_match1;
	int scope_src2, scope_dst2, scope_match2;
	int label_src1, label_dst1, label_match1;
	int label_src2, label_dst2, label_match2;
	int precedence1, precedence2;
	int prefixlen1, prefixlen2;

	/* Rule 1: Avoid unusable destinations. */
	if (a1->has_src_addr != a2->has_src_addr) {
		return a2->has_src_addr - a1->has_src_addr;
	}

	/* Rule 2: Prefer matching scope. */
	scope_src1 = _get_scope(&a1->src_addr.generic);
	scope_dst1 = _get_scope(a1->ai->ai_addr);
	scope_match1 = (scope_src1 == scope_dst1);

	scope_src2 = _get_scope(&a2->src_addr.generic);
	scope_dst2 = _get_scope(a2->ai->ai_addr);
	scope_match2 = (scope_src2 == scope_dst2);

	if (scope_match1 != scope_match2) {
		return scope_match2 - scope_match1;
	}

	/*
	 * Rule 3: Avoid deprecated addresses.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/*
	 * Rule 4: Prefer home addresses.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/* Rule 5: Prefer matching label. */
	label_src1 = _get_label(&a1->src_addr.generic);
	label_dst1 = _get_label(a1->ai->ai_addr);
	label_match1 = (label_src1 == label_dst1);

	label_src2 = _get_label(&a2->src_addr.generic);
	label_dst2 = _get_label(a2->ai->ai_addr);
	label_match2 = (label_src2 == label_dst2);

	if (label_match1 != label_match2) {
		return label_match2 - label_match1;
	}

	/* Rule 6: Prefer higher precedence. */
	precedence1 = _get_precedence(a1->ai->ai_addr);
	precedence2 = _get_precedence(a2->ai->ai_addr);
	if (precedence1 != precedence2) {
		return precedence2 - precedence1;
	}

	/*
	 * Rule 7: Prefer native transport.
	 * TODO(sesse): We don't currently have a good way of finding this.
	 */

	/* Rule 8: Prefer smaller scope. */
	if (scope_dst1 != scope_dst2) {
		return scope_dst1 - scope_dst2;
	}

	/*
	 * Rule 9: Use longest matching prefix.
         * We implement this for IPv6 only, as the rules in RFC 6724 don't seem
         * to work very well directly applied to IPv4. (glibc uses information from
         * the routing table for a custom IPv4 implementation here.)
	 */
	if (a1->has_src_addr && a1->ai->ai_addr->sa_family == AF_INET6 &&
	    a2->has_src_addr && a2->ai->ai_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a1_src = &a1->src_addr.in6;
		const struct sockaddr_in6 *a1_dst = (const struct sockaddr_in6 *)a1->ai->ai_addr;
		const struct sockaddr_in6 *a2_src = &a2->src_addr.in6;
		const struct sockaddr_in6 *a2_dst = (const struct sockaddr_in6 *)a2->ai->ai_addr;
		prefixlen1 = _common_prefix_len(&a1_src->sin6_addr, &a1_dst->sin6_addr);
		prefixlen2 = _common_prefix_len(&a2_src->sin6_addr, &a2_dst->sin6_addr);
		if (prefixlen1 != prefixlen2) {
			return prefixlen2 - prefixlen1;
		}
	}

	/*
	 * Rule 10: Leave the order unchanged.
	 * We need this since qsort() is not necessarily stable.
	 */
	return a1->original_order - a2->original_order;
}

/*
 * Find the source address that will be used if trying to connect to the given
 * address. src_addr must be large enough to hold a struct sockaddr_in6.
 *
 * Returns 1 if a source address was found, 0 if the address is unreachable,
 * and -1 if a fatal error occurred. If 0 or -1, the contents of src_addr are
 * undefined.
 */

/*ARGSUSED*/
static int
_find_src_addr(const struct sockaddr *addr, struct sockaddr *src_addr, unsigned mark, uid_t uid)
{
	int sock;
	int ret;
	socklen_t len;

	switch (addr->sa_family) {
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		/* No known usable source address for non-INET families. */
		return 0;
	}

	sock = socket(addr->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sock == -1) {
		if (errno == EAFNOSUPPORT) {
			return 0;
		} else {
			return -1;
		}
	}
	if (mark != MARK_UNSET && setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
		close(sock);
		return 0;
	}
	if (uid > 0 && uid != NET_CONTEXT_INVALID_UID && fchown(sock, uid, (gid_t)-1) < 0) {
		close(sock);
		return 0;
	}
	do {
		ret = __connect(sock, addr, len);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		close(sock);
		return 0;
	}

	if (src_addr && getsockname(sock, src_addr, &len) == -1) {
		close(sock);
		return -1;
	}
	close(sock);
	return 1;
}

/*
 * Sort the linked list starting at sentinel->ai_next in RFC6724 order.
 * Will leave the list unchanged if an error occurs.
 */

/*ARGSUSED*/
static void
_rfc6724_sort(struct addrinfo *list_sentinel, unsigned mark, uid_t uid)
{
	struct addrinfo *cur;
	int nelem = 0, i;
	struct addrinfo_sort_elem *elems;

	cur = list_sentinel->ai_next;
	while (cur) {
		++nelem;
		cur = cur->ai_next;
	}

	elems = (struct addrinfo_sort_elem *)malloc(nelem * sizeof(struct addrinfo_sort_elem));
	if (elems == NULL) {
		goto error;
	}

	/*
	 * Convert the linked list to an array that also contains the candidate
	 * source address for each destination address.
	 */
	for (i = 0, cur = list_sentinel->ai_next; i < nelem; ++i, cur = cur->ai_next) {
		int has_src_addr;
		assert(cur != NULL);
		elems[i].ai = cur;
		elems[i].original_order = i;

		has_src_addr = _find_src_addr(cur->ai_addr, &elems[i].src_addr.generic, mark, uid);
		if (has_src_addr == -1) {
			goto error;
		}
		elems[i].has_src_addr = has_src_addr;
	}

	/* Sort the addresses, and rearrange the linked list so it matches the sorted order. */
	qsort((void *)elems, nelem, sizeof(struct addrinfo_sort_elem), _rfc6724_compare);

	list_sentinel->ai_next = elems[0].ai;
	for (i = 0; i < nelem - 1; ++i) {
		elems[i].ai->ai_next = elems[i + 1].ai;
	}
	elems[nelem - 1].ai->ai_next = NULL;

error:
	free(elems);
}

/*ARGSUSED*/
static int
_dns_getaddrinfo(void *rv, void	*cb_data, va_list ap)
{
	struct addrinfo *ai;
	querybuf *buf, *buf2;
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct res_target q, q2;
	res_state res;
	const struct android_net_context *netcontext;

	name = va_arg(ap, char *);
	pai = va_arg(ap, const struct addrinfo *);
	netcontext = va_arg(ap, const struct android_net_context *);
	//fprintf(stderr, "_dns_getaddrinfo() name = '%s'\n", name);

	memset(&q, 0, sizeof(q));
	memset(&q2, 0, sizeof(q2));
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	buf = malloc(sizeof(*buf));
	if (buf == NULL) {
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}
	buf2 = malloc(sizeof(*buf2));
	if (buf2 == NULL) {
		free(buf);
		h_errno = NETDB_INTERNAL;
		return NS_NOTFOUND;
	}

	switch (pai->ai_family) {
	case AF_UNSPEC:
		/* prefer IPv6 */
		q.name = name;
		q.qclass = C_IN;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		int query_ipv6 = 1, query_ipv4 = 1;
		if (pai->ai_flags & AI_ADDRCONFIG) {
			query_ipv6 = _have_ipv6(netcontext->app_mark, netcontext->uid);
			query_ipv4 = _have_ipv4(netcontext->app_mark, netcontext->uid);
		}
		if (query_ipv6) {
			q.qtype = T_AAAA;
			if (query_ipv4) {
				q.next = &q2;
				q2.name = name;
				q2.qclass = C_IN;
				q2.qtype = T_A;
				q2.answer = buf2->buf;
				q2.anslen = sizeof(buf2->buf);
			}
		} else if (query_ipv4) {
			q.qtype = T_A;
		} else {
			free(buf);
			free(buf2);
			return NS_NOTFOUND;
		}
		break;
	case AF_INET:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_A;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	case AF_INET6:
		q.name = name;
		q.qclass = C_IN;
		q.qtype = T_AAAA;
		q.answer = buf->buf;
		q.anslen = sizeof(buf->buf);
		break;
	default:
		free(buf);
		free(buf2);
		return NS_UNAVAIL;
	}

	res = __res_get_state();
	if (res == NULL) {
		free(buf);
		free(buf2);
		return NS_NOTFOUND;
	}

	/* this just sets our netid val in the thread private data so we don't have to
	 * modify the api's all the way down to res_send.c's res_nsend.  We could
	 * fully populate the thread private data here, but if we get down there
	 * and have a cache hit that would be wasted, so we do the rest there on miss
	 */
	res_setnetcontext(res, netcontext);
	if (res_searchN(name, &q, res) < 0) {
		__res_put_state(res);
		free(buf);
		free(buf2);
		return NS_NOTFOUND;
	}
	ai = getanswer(buf, q.n, q.name, q.qtype, pai);
	if (ai) {
		cur->ai_next = ai;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	if (q.next) {
		ai = getanswer(buf2, q2.n, q2.name, q2.qtype, pai);
		if (ai)
			cur->ai_next = ai;
	}
	free(buf);
	free(buf2);
	if (sentinel.ai_next == NULL) {
		__res_put_state(res);
		switch (h_errno) {
		case HOST_NOT_FOUND:
			return NS_NOTFOUND;
		case TRY_AGAIN:
			return NS_TRYAGAIN;
		default:
			return NS_UNAVAIL;
		}
	}

	_rfc6724_sort(&sentinel, netcontext->app_mark, netcontext->uid);

	__res_put_state(res);

	*((struct addrinfo **)rv) = sentinel.ai_next;
	return NS_SUCCESS;
}

static void
_sethtent(FILE **hostf)
{

	if (!*hostf)
		*hostf = fopen(_PATH_HOSTS, "re");
	else
		rewind(*hostf);
}

static void
_endhtent(FILE **hostf)
{

	if (*hostf) {
		(void) fclose(*hostf);
		*hostf = NULL;
	}
}

static struct addrinfo *
_gethtent(FILE **hostf, const char *name, const struct addrinfo *pai)
{
	char *p;
	char *cp, *tname, *cname;
	struct addrinfo hints, *res0, *res;
	int error;
	const char *addr;
	char hostbuf[8*1024];

//	fprintf(stderr, "_gethtent() name = '%s'\n", name);
	assert(name != NULL);
	assert(pai != NULL);

	if (!*hostf && !(*hostf = fopen(_PATH_HOSTS, "re")))
		return (NULL);
 again:
	if (!(p = fgets(hostbuf, sizeof hostbuf, *hostf)))
		return (NULL);
	if (*p == '#')
		goto again;
	if (!(cp = strpbrk(p, "#\n")))
		goto again;
	*cp = '\0';
	if (!(cp = strpbrk(p, " \t")))
		goto again;
	*cp++ = '\0';
	addr = p;
	/* if this is not something we're looking for, skip it. */
	cname = NULL;
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (!cname)
			cname = cp;
		tname = cp;
		if ((cp = strpbrk(cp, " \t")) != NULL)
			*cp++ = '\0';
//		fprintf(stderr, "\ttname = '%s'", tname);
		if (strcasecmp(name, tname) == 0)
			goto found;
	}
	goto again;

found:
	hints = *pai;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(addr, NULL, &hints, &res0);
	if (error)
		goto again;
	for (res = res0; res; res = res->ai_next) {
		/* cover it up */
		res->ai_flags = pai->ai_flags;

		if (pai->ai_flags & AI_CANONNAME) {
			if (get_canonname(pai, res, cname) != 0) {
				freeaddrinfo(res0);
				goto again;
			}
		}
	}
	return res0;
}

/*ARGSUSED*/
static int
_files_getaddrinfo(void *rv, void *cb_data, va_list ap)
{
	const char *name;
	const struct addrinfo *pai;
	struct addrinfo sentinel, *cur;
	struct addrinfo *p;
	FILE *hostf = NULL;

	name = va_arg(ap, char *);
	pai = va_arg(ap, struct addrinfo *);

//	fprintf(stderr, "_files_getaddrinfo() name = '%s'\n", name);
	memset(&sentinel, 0, sizeof(sentinel));
	cur = &sentinel;

	_sethtent(&hostf);
	while ((p = _gethtent(&hostf, name, pai)) != NULL) {
		cur->ai_next = p;
		while (cur && cur->ai_next)
			cur = cur->ai_next;
	}
	_endhtent(&hostf);

	*((struct addrinfo **)rv) = sentinel.ai_next;
	if (sentinel.ai_next == NULL)
		return NS_NOTFOUND;
	return NS_SUCCESS;
}

/* resolver logic */

/*
 * Formulate a normal query, send, and await answer.
 * Returned answer is placed in supplied buffer "answer".
 * Perform preliminary check of answer, returning success only
 * if no error is indicated and the answer count is nonzero.
 * Return the size of the response on success, -1 on error.
 * Error number is left in h_errno.
 *
 * Caller must parse answer and determine whether it answers the question.
 */
static int
res_queryN(const char *name, /* domain name */ struct res_target *target,
    res_state res)
{
	u_char buf[MAXPACKET];
	HEADER *hp;
	int n;
	struct res_target *t;
	int rcode;
	int ancount;

	assert(name != NULL);
	/* XXX: target may be NULL??? */

	rcode = NOERROR;
	ancount = 0;

	for (t = target; t; t = t->next) {
		int class, type;
		u_char *answer;
		int anslen;
		u_int oflags;

		hp = (HEADER *)(void *)t->answer;
		oflags = res->_flags;

again:
		hp->rcode = NOERROR;	/* default */

		/* make it easier... */
		class = t->qclass;
		type = t->qtype;
		answer = t->answer;
		anslen = t->anslen;
#ifdef DEBUG
		if (res->options & RES_DEBUG)
			printf(";; res_nquery(%s, %d, %d)\n", name, class, type);
#endif

		n = res_nmkquery(res, QUERY, name, class, type, NULL, 0, NULL,
		    buf, sizeof(buf));
#ifdef RES_USE_EDNS0
		if (n > 0 && (res->_flags & RES_F_EDNS0ERR) == 0 &&
		    (res->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0)
			n = res_nopt(res, n, buf, sizeof(buf), anslen);
#endif
		if (n <= 0) {
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; res_nquery: mkquery failed\n");
#endif
			h_errno = NO_RECOVERY;
			return n;
		}
		n = res_nsend(res, buf, n, answer, anslen);
#if 0
		if (n < 0) {
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; res_query: send error\n");
#endif
			h_errno = TRY_AGAIN;
			return n;
		}
#endif

		if (n < 0 || hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
			rcode = hp->rcode;	/* record most recent error */
#ifdef RES_USE_EDNS0
			/* if the query choked with EDNS0, retry without EDNS0 */
			if ((res->options & (RES_USE_EDNS0|RES_USE_DNSSEC)) != 0 &&
			    ((oflags ^ res->_flags) & RES_F_EDNS0ERR) != 0) {
				res->_flags |= RES_F_EDNS0ERR;
#ifdef DEBUG
				if (res->options & RES_DEBUG)
					printf(";; res_nquery: retry without EDNS0\n");
#endif
				goto again;
			}
#endif
#ifdef DEBUG
			if (res->options & RES_DEBUG)
				printf(";; rcode = %u, ancount=%u\n", hp->rcode,
				    ntohs(hp->ancount));
#endif
			continue;
		}

		ancount += ntohs(hp->ancount);

		t->n = n;
	}

	if (ancount == 0) {
		switch (rcode) {
		case NXDOMAIN:
			h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			h_errno = NO_RECOVERY;
			break;
		}
		return -1;
	}
	return ancount;
}

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
static int
res_searchN(const char *name, struct res_target *target, res_state res)
{
	const char *cp, * const *domain;
	HEADER *hp;
	u_int dots;
	int trailing_dot, ret, saved_herrno;
	int got_nodata = 0, got_servfail = 0, tried_as_is = 0;

	assert(name != NULL);
	assert(target != NULL);

	hp = (HEADER *)(void *)target->answer;	/*XXX*/

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');
	trailing_dot = 0;
	if (cp > name && *--cp == '.')
		trailing_dot++;


        //fprintf(stderr, "res_searchN() name = '%s'\n", name);

	/*
	 * if there aren't any dots, it could be a user-level alias
	 */
	if (!dots && (cp = __hostalias(name)) != NULL) {
		ret = res_queryN(cp, target, res);
		return ret;
	}

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	if (dots >= res->ndots) {
		ret = res_querydomainN(name, NULL, target, res);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		tried_as_is++;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	if ((!dots && (res->options & RES_DEFNAMES)) ||
	    (dots && !trailing_dot && (res->options & RES_DNSRCH))) {
		int done = 0;

		/* Unfortunately we need to set stuff up before
		 * the domain stuff is tried.  Will have a better
		 * fix after thread pools are used.
		 */
		_resolv_populate_res_for_net(res);

		for (domain = (const char * const *)res->dnsrch;
		   *domain && !done;
		   domain++) {

			ret = res_querydomainN(name, *domain, target, res);
			if (ret > 0)
				return ret;

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return -1;
			}

			switch (h_errno) {
			case NO_DATA:
				got_nodata++;
				/* FALLTHROUGH */
			case HOST_NOT_FOUND:
				/* keep trying */
				break;
			case TRY_AGAIN:
				if (hp->rcode == SERVFAIL) {
					/* try next search element, if any */
					got_servfail++;
					break;
				}
				/* FALLTHROUGH */
			default:
				/* anything else implies that we're done */
				done++;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			if (!(res->options & RES_DNSRCH))
			        done++;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!tried_as_is) {
		ret = res_querydomainN(name, NULL, target, res);
		if (ret > 0)
			return ret;
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (got_nodata)
		h_errno = NO_DATA;
	else if (got_servfail)
		h_errno = TRY_AGAIN;
	return -1;
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static int
res_querydomainN(const char *name, const char *domain,
    struct res_target *target, res_state res)
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	assert(name != NULL);
	/* XXX: target may be NULL??? */

#ifdef DEBUG
	if (res->options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s)\n",
			name, domain?domain:"<Nil>");
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + 1 + d + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return res_queryN(longname, target, res);
}
```