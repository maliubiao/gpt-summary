Response:
Let's break down the thought process for answering the user's request about the `nfnetlink.h` header file.

**1. Understanding the Core Request:**

The user provided a header file and asked for:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it relate to Android?
* **libc Function Details:** Explain the libc functions (specifically).
* **Dynamic Linker:** Discuss its role and provide examples.
* **Logic Inference:** Show input/output examples.
* **Common Errors:** Identify potential user mistakes.
* **Android Framework/NDK Path:** Trace how this file is reached.
* **Frida Hooking:** Provide a debugging example.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_NFNETLINK_H` and `#define _UAPI_NFNETLINK_H`:**  Standard include guard to prevent multiple inclusions. Not a core functionality, but important for compilation.
* **`#include <linux/types.h>` and `#include <linux/netfilter/nfnetlink_compat.h>`:**  Includes other kernel header files. This immediately tells me the file deals with low-level networking, specifically Netfilter. The `uapi` directory reinforces this – it's an interface between user-space and kernel-space.
* **`enum nfnetlink_groups`:** Defines constants related to Netfilter events. The names (CONNTRACK, NFTABLES, ACCT, NFTRACE) are strong hints about its purpose.
* **`struct nfgenmsg`:** A structure containing fields related to Netfilter messages (family, version, resource ID).
* **`#define` macros:**  Various macros for manipulating Netfilter message types and subsystems. These are key for understanding how messages are structured.

**3. Addressing Each Request Point Systematically:**

* **Functionality:** Based on the keywords and structure, I can deduce that this file defines the user-space API for interacting with the kernel's Netfilter subsystem. It specifies the message types and groups used for communication.

* **Android Relevance:**  Android uses the Linux kernel, so Netfilter is part of its networking stack. Firewalls, connection tracking, and network address translation (NAT) are all potential uses. Specifically, connection tracking is mentioned explicitly in the enums. I need to connect this to concrete Android features like internet sharing, VPNs, and potentially even app-level firewalls.

* **libc Function Details:**  This is a trick question!  This header file *defines types and constants*, not functions. The *implementation* of sending and receiving these Netfilter messages will reside in libc functions (like `socket`, `sendto`, `recvfrom`), but *this file itself doesn't contain function definitions*. It's crucial to point this out to avoid misleading the user.

* **Dynamic Linker:**  Header files are processed during compilation, not at runtime by the dynamic linker. Therefore, the dynamic linker isn't directly involved with *this file*. However, the *code that uses these definitions* will be linked, and I can give a general explanation of how shared libraries work in Android and how the linker resolves symbols. Providing a sample `so` layout and linking process steps is helpful.

* **Logic Inference:**  I need to construct a plausible scenario. Sending a message to subscribe to connection tracking events seems like a good example. I need to define a hypothetical input (an integer representing the desired group) and the expected output (a constant representing that group).

* **Common Errors:** Users might misuse the constants (e.g., using the wrong group ID), or misunderstand the message structure. Trying to use these definitions directly without understanding the underlying Netlink protocol is another potential error.

* **Android Framework/NDK Path:** This requires tracing the interaction from a higher level. I start with a potential use case (network monitoring), then link it to Android Framework APIs (like `NetworkStatsManager`), and then down to the NDK (using sockets). Finally, I connect it to the kernel Netfilter through system calls.

* **Frida Hooking:**  I need to target the system calls involved in sending/receiving Netfilter messages. `sendto` is a likely candidate. The Frida script should demonstrate how to intercept this call and inspect the arguments, specifically the `addr` structure which contains the Netlink information.

**4. Structuring the Answer:**

I need to organize the information clearly, addressing each point in the user's request. Using headings and bullet points will improve readability. It's important to be precise in my terminology and avoid making assumptions. Specifically, I need to be careful when discussing "libc functions" since this file doesn't define them directly.

**5. Refinement and Review:**

Before submitting the answer, I'd review it to ensure:

* **Accuracy:**  Is the information correct?
* **Completeness:** Have I addressed all aspects of the request?
* **Clarity:** Is the language easy to understand?
* **Examples:** Are the examples helpful and illustrative?
* **Code Formatting:** Is the Frida script correctly formatted?

By following this structured thought process, I can generate a comprehensive and accurate answer that meets the user's needs. The key is to break down the problem, analyze the input carefully, and connect the low-level details of the header file to the broader context of Android and networking.
这个C头文件 `bionic/libc/kernel/uapi/linux/netfilter/nfnetlink.h` 定义了用户空间程序与Linux内核Netfilter框架通信时使用的常量、枚举和数据结构。Netfilter是Linux内核中用于网络包过滤、连接跟踪和网络地址转换（NAT）的子系统。`nfnetlink` 是 Netfilter 提供的一种基于 Netlink 协议的接口，允许用户空间程序与 Netfilter 模块进行交互。

**功能列举:**

1. **定义 Netfilter 事件组 (nfnetlink_groups):**
   -  `NFNLGRP_CONNTRACK_NEW`, `NFNLGRP_CONNTRACK_UPDATE`, `NFNLGRP_CONNTRACK_DESTROY`:  定义了连接跟踪（Connection Tracking）模块产生的事件，例如新连接的建立、连接状态的更新和连接的销毁。
   -  `NFNLGRP_CONNTRACK_EXP_NEW`, `NFNLGRP_CONNTRACK_EXP_UPDATE`, `NFNLGRP_CONNTRACK_EXP_DESTROY`: 定义了连接跟踪预期（Connection Tracking Expectation）模块产生的事件。连接跟踪预期用于处理诸如 FTP 数据连接等需要动态创建连接的情况。
   -  `NFNLGRP_NFTABLES`:  定义了与 `nftables` 子系统相关的事件。`nftables` 是 Netfilter 的后继者，提供更灵活和强大的包过滤框架。
   -  `NFNLGRP_ACCT_QUOTA`: 定义了与网络计费和配额相关的事件。
   -  `NFNLGRP_NFTRACE`: 定义了与 Netfilter 包跟踪相关的事件，用于调试网络包的流向和处理。

2. **定义通用 Netfilter 消息头 (nfgenmsg):**
   - `nfgen_family`:  指示地址族，通常是 `AF_INET` 或 `AF_INET6`。
   - `version`: Netfilter 协议版本，通常是 `NFNETLINK_V0` (定义为 0)。
   - `res_id`:  保留字段，通常为 0。

3. **定义 Netfilter 子系统 ID 和消息类型相关的宏:**
   - `NFNL_SUBSYS_ID(x)`:  从一个值中提取 Netfilter 子系统 ID。
   - `NFNL_MSG_TYPE(x)`:  从一个值中提取 Netfilter 消息类型。
   - 定义了一系列 Netfilter 子系统 ID，例如 `NFNL_SUBSYS_CTNETLINK` (连接跟踪), `NFNL_SUBSYS_NFTABLES` (nftables) 等。

4. **定义批量消息相关的常量:**
   - `NFNL_MSG_BATCH_BEGIN`, `NFNL_MSG_BATCH_END`:  用于指示一批 Netfilter 消息的开始和结束。
   - `enum nfnl_batch_attributes`: 定义了批量消息的属性，例如 `NFNL_BATCH_GENID` (生成 ID)。

**与 Android 功能的关系及举例:**

Android 使用 Linux 内核，因此也使用了 Netfilter 框架来实现其网络功能。`nfnetlink.h` 中定义的常量和结构体是 Android 系统中与网络相关的核心组件进行交互的基础。

* **连接跟踪 (Connection Tracking):**
    - **功能:** Android 系统利用连接跟踪来管理网络连接的状态，例如 NAT (网络地址转换) 功能就需要跟踪连接信息。
    - **举例:** 当你的 Android 设备作为热点共享网络时，Netfilter 的连接跟踪模块会跟踪通过热点的连接，以便正确地将数据包路由到相应的设备。`NFNLGRP_CONNTRACK_NEW`, `NFNLGRP_CONNTRACK_UPDATE` 和 `NFNLGRP_CONNTRACK_DESTROY` 等事件组允许用户空间的监控程序（例如网络管理应用）接收有关连接状态变化的通知。

* **防火墙 (Firewall):**
    - **功能:** Android 的防火墙功能（例如允许或阻止特定应用的联网）通常基于 Netfilter 或其继任者 `nftables` 实现。
    - **举例:** Android 系统可以使用 Netfilter 或 `nftables` 规则来阻止某个应用访问特定的网络端口或地址。`NFNLGRP_NFTABLES` 事件组允许用户空间的管理工具监控和配置 `nftables` 规则。

* **网络监控和统计:**
    - **功能:** Android 系统需要监控网络流量和连接状态，以便进行流量统计、网络性能分析等。
    - **举例:** Android 的网络统计服务可能会监听 `NFNLGRP_CONNTRACK_NEW` 和 `NFNLGRP_CONNTRACK_DESTROY` 事件来跟踪活动的网络连接，从而计算应用的流量使用情况。

* **VPN (虚拟私人网络):**
    - **功能:** VPN 连接的建立和管理也可能涉及到与 Netfilter 的交互，例如设置路由规则、进行数据包的加密和解密等。
    - **举例:**  当一个 VPN 连接建立时，Android 系统可能会使用 Netfilter 来将通过 VPN 接口的数据包路由到 VPN 服务器，并可能更新连接跟踪信息以确保 VPN 连接的正确性。

**libc 函数的功能实现:**

这个头文件本身**不包含 libc 函数的实现**。它只是定义了常量、枚举和结构体。用户空间程序需要使用 libc 提供的网络相关的系统调用和函数来与 Netfilter 进行交互。常见的 libc 函数包括：

* **`socket()`:**  用于创建 Netlink 套接字，以便与内核的 Netfilter 模块通信。需要指定地址族为 `AF_NETLINK`，协议为 `NETLINK_NETFILTER`。
* **`bind()`:**  将 Netlink 套接字绑定到特定的 Netlink 组 ID，以便接收特定类型的 Netfilter 事件通知。可以使用 `nl_addr` 结构体来指定组 ID。
* **`sendto()`:**  用于向内核的 Netfilter 模块发送消息，例如添加或删除防火墙规则，或请求连接跟踪信息。
* **`recvfrom()`:**  用于从内核的 Netfilter 模块接收消息，例如接收连接状态变化的通知或 `nftables` 事件。
* **`close()`:**  关闭 Netlink 套接字。

这些 libc 函数的实现细节涉及到操作系统内核的网络协议栈和系统调用处理。例如，`sendto()` 会将用户空间的数据复制到内核空间，然后内核的网络协议栈会根据指定的协议（Netlink）和目标地址（Netfilter 模块）来处理该数据。`recvfrom()` 的过程则相反，内核将数据发送到用户空间的缓冲区。

**涉及 dynamic linker 的功能:**

这个头文件本身**不直接涉及 dynamic linker 的功能**。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库，并解析和链接符号。

虽然这个头文件不直接参与链接过程，但使用它的代码（例如网络相关的库或应用）会被链接到 libc 或其他包含网络功能的共享库。

**so 布局样本:**

假设有一个名为 `libnetfilter_client.so` 的共享库，它使用了 `nfnetlink.h` 中定义的常量和结构体来与 Netfilter 交互。

```
libnetfilter_client.so:
    .text         # 代码段
        - 函数1 使用了 nfnetlink.h 中的定义
        - 函数2
        ...
    .rodata       # 只读数据段
        - 包含 nfnetlink.h 中定义的常量
    .data         # 可读写数据段
    .bss          # 未初始化数据段
    .dynamic      # 动态链接信息
        - NEEDED libc.so
        ...
    .symtab       # 符号表
        - 包含 libnetfilter_client.so 导出的符号
        - 包含 libnetfilter_client.so 导入的符号 (例如来自 libc.so)
    .strtab       # 字符串表
```

**链接的处理过程:**

1. **编译时:** 当编译 `libnetfilter_client.so` 的源代码时，编译器会处理 `#include <linux/netfilter/nfnetlink.h>` 指令，并使用其中定义的常量和结构体。编译器会生成目标文件，其中包含对外部符号的引用，例如 libc 中的 `socket`、`bind` 等函数。

2. **链接时:**  链接器（`ld` 或 `lld`）将 `libnetfilter_client.so` 的目标文件与其他必要的库（例如 `libc.so`) 链接在一起。链接器会解析符号引用，将 `libnetfilter_client.so` 中对 `socket` 的调用链接到 `libc.so` 中 `socket` 函数的实现。动态链接信息 (`.dynamic` 段) 会记录 `libnetfilter_client.so` 依赖于 `libc.so`。

3. **运行时:** 当一个应用加载 `libnetfilter_client.so` 时，Android 的动态链接器会执行以下步骤：
    - 加载 `libnetfilter_client.so` 到内存。
    - 检查 `libnetfilter_client.so` 的依赖项，例如 `libc.so`。
    - 如果依赖项尚未加载，则加载它们。
    - **重定位:** 动态链接器会修改 `libnetfilter_client.so` 中的代码和数据，以使用正确的内存地址。这包括解析对共享库中函数的调用和对全局变量的访问。例如，对 `socket` 函数的调用会被重定向到 `libc.so` 中 `socket` 函数的实际地址。
    - 完成链接后，应用就可以调用 `libnetfilter_client.so` 中定义的函数，这些函数会使用 `nfnetlink.h` 中定义的常量和结构体与 Netfilter 交互。

**逻辑推理、假设输入与输出:**

假设用户空间程序想要订阅 `NFNLGRP_CONNTRACK_NEW` 事件组。

**假设输入:**  一个整数，代表要订阅的 Netlink 组 ID。在这个例子中，假设 `NFNLGRP_CONNTRACK_NEW` 的枚举值为 1。

**逻辑推理:**
1. 程序创建一个 Netlink 套接字。
2. 程序构造一个 Netlink 地址结构体，设置地址族为 `AF_NETLINK`，并设置 `nl_groups` 字段为 `(1 << NFNLGRP_CONNTRACK_NEW)`，表示订阅 `NFNLGRP_CONNTRACK_NEW` 组。
3. 程序调用 `bind()` 函数，将套接字绑定到该地址结构体。

**预期输出:**  如果 `bind()` 调用成功，程序将能够接收到内核发送的属于 `NFNLGRP_CONNTRACK_NEW` 事件组的 Netlink 消息。接收到的消息将包含有关新建立的连接的信息。

**用户或编程常见的使用错误:**

1. **使用错误的 Netlink 组 ID:**  如果程序尝试绑定到不存在或错误的 Netlink 组 ID，`bind()` 调用可能会失败，或者程序可能无法接收到预期的事件。例如，拼写错误或使用了已被废弃的组 ID。

2. **未正确处理 Netlink 消息格式:**  Netlink 消息包含头部和有效负载。用户程序需要正确解析接收到的消息，包括 Netlink 头部和 Netfilter 相关的消息头部 (如 `nfgenmsg`)，以及后续的属性。如果解析错误，可能会导致程序崩溃或产生错误的理解。

3. **权限不足:** 某些 Netfilter 操作可能需要 root 权限或特定的 capabilities。如果用户程序没有足够的权限，尝试执行这些操作（例如修改防火墙规则）将会失败。

4. **忘记绑定到组:**  如果程序创建了 Netlink 套接字但没有调用 `bind()` 绑定到特定的 Netfilter 组，它将无法接收到任何 Netfilter 事件通知。

5. **错误的套接字类型或协议:**  必须使用 `AF_NETLINK` 地址族和 `NETLINK_NETFILTER` 协议来创建与 Netfilter 通信的套接字。使用错误的类型或协议会导致连接失败。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java/Kotlin):**
   - 例如，Android 的 `ConnectivityManager` 或 `NetworkStatsManager` 等系统服务可能需要获取网络连接信息或监控网络状态。
   - 这些服务可能会调用底层的 Native 代码（C/C++），通常是通过 JNI (Java Native Interface)。

2. **NDK (Native Development Kit) 或 Native Libraries:**
   - 在 Native 代码中，开发者可以使用标准的 POSIX 网络 API，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`。
   - 要与 Netfilter 交互，Native 代码需要包含 `<linux/netfilter/nfnetlink.h>` 头文件，以使用其中定义的常量和结构体。
   - Native 代码会创建 Netlink 套接字，并使用 `nfnetlink.h` 中定义的组 ID 来订阅特定的 Netfilter 事件。

3. **System Calls:**
   - 当 Native 代码调用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等函数时，这些调用最终会触发 Linux 内核的系统调用。
   - 例如，`socket()` 会触发 `socket()` 系统调用，`bind()` 会触发 `bind()` 系统调用。

4. **Kernel Netfilter Subsystem:**
   - 内核接收到来自用户空间的 Netlink 消息后，会根据消息的类型和内容将其路由到相应的 Netfilter 模块，例如连接跟踪模块或 `nftables` 模块。
   - 当 Netfilter 模块产生事件时（例如新连接建立），它会构建一个 Netlink 消息，并发送到已订阅该事件组的 Netlink 套接字。

**Frida Hook 示例调试步骤:**

假设我们想要 Hook 一个使用 `nfnetlink.h` 的 Native 函数，该函数订阅了连接跟踪的新连接事件。

**C/C++ 代码示例 (假设在某个 Native 库中):**

```c++
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int subscribe_conntrack_events() {
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = (1 << NFNLGRP_CONNTRACK_NEW); // 订阅新连接事件

    if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    printf("Successfully subscribed to conntrack new events.\n");
    return sock_fd;
}
```

**Frida Hook 脚本示例:**

```javascript
// 假设目标进程已经运行，并且加载了包含 subscribe_conntrack_events 函数的库
const libName = "your_native_library.so"; // 替换为你的 Native 库名称
const subscribeFunc = "subscribe_conntrack_events";

// 获取函数的地址
const subscribeAddress = Module.findExportByName(libName, subscribeFunc);

if (subscribeAddress) {
    console.log(`Found ${subscribeFunc} at ${subscribeAddress}`);

    // Hook socket 函数
    Interceptor.attach(Module.findExportByName(null, "socket"), {
        onEnter: function (args) {
            const domain = args[0].toInt32();
            const type = args[1].toInt32();
            const protocol = args[2].toInt32();
            console.log(`[socket] domain: ${domain}, type: ${type}, protocol: ${protocol}`);
        },
        onLeave: function (retval) {
            console.log(`[socket] returned: ${retval}`);
        }
    });

    // Hook bind 函数
    Interceptor.attach(Module.findExportByName(null, "bind"), {
        onEnter: function (args) {
            const sockfd = args[0].toInt32();
            const addrPtr = args[1];
            const addrlen = args[2].toInt32();

            if (addrlen >= Process.pointerSize * 2) {
                const family = addrPtr.readU16();
                const groups = addrPtr.add(Process.pointerSize).readU32();
                console.log(`[bind] sockfd: ${sockfd}, family: ${family}, groups: ${groups}`);
            } else {
                console.log(`[bind] sockfd: ${sockfd}, addrlen: ${addrlen}`);
            }
        },
        onLeave: function (retval) {
            console.log(`[bind] returned: ${retval}`);
        }
    });

    // 执行目标函数 (如果需要)
    // RPC.call(subscribeFunc); // 假设你已经设置了 RPC

} else {
    console.error(`Could not find ${subscribeFunc} in ${libName}`);
}
```

**调试步骤:**

1. **确定目标进程和库:** 找到包含你想要调试的 Native 函数的进程和共享库的名称。
2. **编写 Frida 脚本:**  使用 `Module.findExportByName` 找到 `socket` 和 `bind` 函数的地址，并使用 `Interceptor.attach` 来 Hook 这些函数。
3. **Hook `socket`:** 在 `socket` 的 `onEnter` 中打印其参数，例如地址族、套接字类型和协议，以确认是否创建了 Netlink 套接字 (`AF_NETLINK`, `NETLINK_NETFILTER`)。
4. **Hook `bind`:** 在 `bind` 的 `onEnter` 中打印其参数，特别是 `addr` 结构体中的地址族 (`nl_family`) 和组 ID (`nl_groups`)，以确认程序是否正确地绑定到了 `NFNLGRP_CONNTRACK_NEW` 组。
5. **运行 Frida 脚本:** 使用 Frida 连接到目标进程并运行脚本。
6. **观察输出:**  查看 Frida 的输出，分析 `socket` 和 `bind` 函数的调用情况，确认参数是否正确。如果 `bind` 成功返回 0，则表示订阅成功。

通过这种方式，你可以使用 Frida 动态地分析 Native 代码与 Netfilter 的交互，理解其如何使用 `nfnetlink.h` 中定义的常量和结构体。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/nfnetlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_NFNETLINK_H
#define _UAPI_NFNETLINK_H
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_compat.h>
enum nfnetlink_groups {
  NFNLGRP_NONE,
#define NFNLGRP_NONE NFNLGRP_NONE
  NFNLGRP_CONNTRACK_NEW,
#define NFNLGRP_CONNTRACK_NEW NFNLGRP_CONNTRACK_NEW
  NFNLGRP_CONNTRACK_UPDATE,
#define NFNLGRP_CONNTRACK_UPDATE NFNLGRP_CONNTRACK_UPDATE
  NFNLGRP_CONNTRACK_DESTROY,
#define NFNLGRP_CONNTRACK_DESTROY NFNLGRP_CONNTRACK_DESTROY
  NFNLGRP_CONNTRACK_EXP_NEW,
#define NFNLGRP_CONNTRACK_EXP_NEW NFNLGRP_CONNTRACK_EXP_NEW
  NFNLGRP_CONNTRACK_EXP_UPDATE,
#define NFNLGRP_CONNTRACK_EXP_UPDATE NFNLGRP_CONNTRACK_EXP_UPDATE
  NFNLGRP_CONNTRACK_EXP_DESTROY,
#define NFNLGRP_CONNTRACK_EXP_DESTROY NFNLGRP_CONNTRACK_EXP_DESTROY
  NFNLGRP_NFTABLES,
#define NFNLGRP_NFTABLES NFNLGRP_NFTABLES
  NFNLGRP_ACCT_QUOTA,
#define NFNLGRP_ACCT_QUOTA NFNLGRP_ACCT_QUOTA
  NFNLGRP_NFTRACE,
#define NFNLGRP_NFTRACE NFNLGRP_NFTRACE
  __NFNLGRP_MAX,
};
#define NFNLGRP_MAX (__NFNLGRP_MAX - 1)
struct nfgenmsg {
  __u8 nfgen_family;
  __u8 version;
  __be16 res_id;
};
#define NFNETLINK_V0 0
#define NFNL_SUBSYS_ID(x) ((x & 0xff00) >> 8)
#define NFNL_MSG_TYPE(x) (x & 0x00ff)
#define NFNL_SUBSYS_NONE 0
#define NFNL_SUBSYS_CTNETLINK 1
#define NFNL_SUBSYS_CTNETLINK_EXP 2
#define NFNL_SUBSYS_QUEUE 3
#define NFNL_SUBSYS_ULOG 4
#define NFNL_SUBSYS_OSF 5
#define NFNL_SUBSYS_IPSET 6
#define NFNL_SUBSYS_ACCT 7
#define NFNL_SUBSYS_CTNETLINK_TIMEOUT 8
#define NFNL_SUBSYS_CTHELPER 9
#define NFNL_SUBSYS_NFTABLES 10
#define NFNL_SUBSYS_NFT_COMPAT 11
#define NFNL_SUBSYS_HOOK 12
#define NFNL_SUBSYS_COUNT 13
#define NFNL_MSG_BATCH_BEGIN NLMSG_MIN_TYPE
#define NFNL_MSG_BATCH_END NLMSG_MIN_TYPE + 1
enum nfnl_batch_attributes {
  NFNL_BATCH_UNSPEC,
  NFNL_BATCH_GENID,
  __NFNL_BATCH_MAX
};
#define NFNL_BATCH_MAX (__NFNL_BATCH_MAX - 1)
#endif

"""

```