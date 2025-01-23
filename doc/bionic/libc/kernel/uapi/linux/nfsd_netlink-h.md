Response:
Let's break down the thought process for analyzing this C header file and answering the request.

**1. Understanding the Context:**

The first step is to recognize the context: the file is located within the Android Bionic library, specifically under `bionic/libc/kernel/uapi/linux/`. The `uapi` directory signifies "user-space API," meaning this file defines interfaces for user-space programs to interact with the Linux kernel. The filename `nfsd_netlink.h` strongly suggests it's related to the Network File System daemon (nfsd) and uses the netlink socket interface for communication.

**2. Identifying Key Elements:**

Next, I scanned the file for the core components:

* **Header Guards:** `#ifndef _UAPI_LINUX_NFSD_NETLINK_H` and `#define _UAPI_LINUX_NFSD_NETLINK_H` are standard header guards to prevent multiple inclusions.
* **Macros:** `#define NFSD_FAMILY_NAME "nfsd"` and `#define NFSD_FAMILY_VERSION 1` define constants related to the Netlink family.
* **Enums:** The majority of the file consists of `enum` definitions. These are named constants, likely representing attributes and commands for the nfsd netlink interface.

**3. Inferring Functionality from Enums:**

The names of the enums and their members provide significant clues about the file's purpose:

* **`NFSD_A_RPC_STATUS_*`:**  Clearly related to reporting the status of RPC (Remote Procedure Call) operations within the NFS server. The members describe specific attributes of an RPC call, like transaction ID (XID), flags, program, version, procedure, service time, and source/destination addresses/ports.
* **`NFSD_A_SERVER_*`:**  Deals with server-wide settings, such as the number of server threads, grace time, lease time, and scope.
* **`NFSD_A_VERSION_*`:**  Relates to the NFS protocol version being used.
* **`NFSD_A_SERVER_PROTO_VERSION`:**  Likely a specific attribute for a server protocol version.
* **`NFSD_A_SOCK_*` and `NFSD_A_SERVER_SOCK_ADDR`:**  Concerned with socket addresses and transport names for listeners.
* **`NFSD_A_POOL_MODE_*`:**  Suggests configuration related to thread pools within the NFS server.
* **`NFSD_CMD_*`:**  These are commands that can be sent through the netlink socket to the nfsd. They correspond to getting and setting the attributes defined in the other enums (e.g., getting RPC status, setting the number of threads).

**4. Connecting to Android:**

Given this understanding, I considered how this relates to Android. NFS is a standard network file sharing protocol. While not a core Android feature used by typical apps, it *is* used in some enterprise scenarios or custom Android setups where devices might need to act as NFS servers or clients. Therefore, this file provides the interface for managing the NFS server *if* it's running on an Android device.

**5. Addressing Specific Request Points:**

* **Functionality:**  List the inferred functionalities based on the enum names.
* **Android Relevance:** Explain that it's used for NFS server management on Android, although not a core feature for most users.
* **libc Function Explanation:** Recognize that this file is *declarative*. It defines constants; it doesn't contain actual libc function *implementations*. The *use* of these constants would occur in libc functions related to netlink socket communication. It's crucial to clarify this distinction.
* **Dynamic Linker:**  Again, this file doesn't directly involve the dynamic linker. It defines constants that a program might use, but the linking process happens at a different stage when the program using these constants is built. Therefore, no SO layout or linking process explanation is directly applicable *to this file itself*. However, it's important to mention that programs *using* these definitions will be linked against libc.
* **Logic Reasoning/Assumptions:** Provide examples of how the constants might be used in a hypothetical scenario of querying RPC status.
* **User/Programming Errors:** Suggest potential errors related to misinterpreting or incorrectly using these constants when interacting with the netlink socket.
* **Android Framework/NDK Path:**  Describe how a hypothetical Android component (either in the framework or using the NDK) might interact with the kernel through system calls that eventually lead to the nfsd netlink interface.
* **Frida Hook:**  Provide a basic Frida example targeting a hypothetical function that sends netlink messages related to NFS.

**6. Structuring the Answer:**

Organize the information logically, addressing each point of the request clearly and concisely. Use headings and bullet points to improve readability. Emphasize the key distinction between *defining* constants and *implementing* functionality.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this file contains the actual *implementation* of some NFS-related functionality.
* **Correction:**  Realized the `uapi` location and the structure of the file indicate it's an interface definition, not implementation. The actual implementation resides in the kernel.
* **Initial thought:**  Focus heavily on specific libc functions.
* **Correction:**  Shifted focus to explaining *how* libc functions (like those dealing with netlink sockets) would *use* these definitions, rather than dissecting the implementation of unrelated libc functions.
* **Initial thought:**  Overcomplicate the dynamic linker explanation.
* **Correction:**  Simplified the explanation by stating that while this file itself doesn't involve the dynamic linker directly, programs using these definitions will be linked against libc.

By following this structured thought process, anticipating potential misunderstandings, and correcting initial assumptions, I arrived at the comprehensive and accurate answer provided previously.
这是一个定义了与Linux内核中NFSD (NFS Server Daemon) 子系统通过 Netlink 接口进行通信的常量和枚举的头文件。它属于Android Bionic库的一部分，但其核心是与Linux内核的接口定义，而不是Bionic自身的功能实现。

**它的功能:**

这个头文件定义了以下内容，用于用户空间程序（如nfsd进程的管理工具）与内核中的nfsd进行通信：

1. **Netlink Family 名称和版本:**
   - `NFSD_FAMILY_NAME "nfsd"`: 定义了 Netlink 协议族的名称，用于识别 nfsd 的 Netlink 通信。
   - `NFSD_FAMILY_VERSION 1`: 定义了该 Netlink 协议族的版本号。

2. **RPC 状态属性 (NFSD_A_RPC_STATUS_*)**:  定义了用于查询和报告 NFS RPC (Remote Procedure Call) 调用状态的属性 ID。这些属性可以用来获取关于特定 RPC 调用的详细信息，例如：
   - `NFSD_A_RPC_STATUS_XID`: RPC 事务 ID。
   - `NFSD_A_RPC_STATUS_FLAGS`: RPC 标志。
   - `NFSD_A_RPC_STATUS_PROG`: RPC 调用的程序号。
   - `NFSD_A_RPC_STATUS_VERSION`: RPC 调用的版本号。
   - `NFSD_A_RPC_STATUS_PROC`: RPC 调用的过程号。
   - `NFSD_A_RPC_STATUS_SERVICE_TIME`: RPC 调用的服务时间。
   - 源地址和端口 (`NFSD_A_RPC_STATUS_SADDR4`, `NFSD_A_RPC_STATUS_DADDR4`, `NFSD_A_RPC_STATUS_SADDR6`, `NFSD_A_RPC_STATUS_DPORT`, `NFSD_A_RPC_STATUS_SPORT`)。
   - `NFSD_A_RPC_STATUS_COMPOUND_OPS`: 复合操作的数量。

3. **服务器属性 (NFSD_A_SERVER_*)**: 定义了用于管理 NFS 服务器全局设置的属性 ID，例如：
   - `NFSD_A_SERVER_THREADS`: 服务器线程数。
   - `NFSD_A_SERVER_GRACETIME`: 服务器的宽限期。
   - `NFSD_A_SERVER_LEASETIME`: 服务器的租约时间。
   - `NFSD_A_SERVER_SCOPE`: 服务器的作用域。

4. **版本属性 (NFSD_A_VERSION_*)**: 定义了用于管理支持的 NFS 协议版本的属性 ID，例如：
   - `NFSD_A_VERSION_MAJOR`: 主版本号。
   - `NFSD_A_VERSION_MINOR`: 次版本号。
   - `NFSD_A_VERSION_ENABLED`: 版本是否启用。

5. **服务器协议版本属性 (NFSD_A_SERVER_PROTO_VERSION)**:  定义了服务器协议版本的属性 ID。

6. **套接字属性 (NFSD_A_SOCK_*, NFSD_A_SERVER_SOCK_ADDR)**: 定义了用于管理监听套接字的属性 ID，例如：
   - `NFSD_A_SOCK_ADDR`: 套接字地址。
   - `NFSD_A_SOCK_TRANSPORT_NAME`: 传输协议名称。

7. **线程池模式属性 (NFSD_A_POOL_MODE_*)**: 定义了用于管理服务器线程池模式的属性 ID，例如：
   - `NFSD_A_POOL_MODE_MODE`: 线程池模式。
   - `NFSD_A_POOL_MODE_NPOOLS`: 线程池数量。

8. **Netlink 命令 (NFSD_CMD_*)**: 定义了可以通过 Netlink 发送给 nfsd 的命令 ID，用于查询和设置服务器的各种属性，例如：
   - `NFSD_CMD_RPC_STATUS_GET`: 获取 RPC 状态。
   - `NFSD_CMD_THREADS_SET`, `NFSD_CMD_THREADS_GET`: 设置和获取服务器线程数。
   - `NFSD_CMD_VERSION_SET`, `NFSD_CMD_VERSION_GET`: 设置和获取支持的 NFS 版本。
   - `NFSD_CMD_LISTENER_SET`, `NFSD_CMD_LISTENER_GET`: 设置和获取监听器。
   - `NFSD_CMD_POOL_MODE_SET`, `NFSD_CMD_POOL_MODE_GET`: 设置和获取线程池模式。

**与 Android 功能的关系及举例说明:**

虽然 NFS 不是 Android 核心用户空间功能，但在以下场景中可能相关：

* **Android 作为 NFS 服务器:**  某些定制的 Android 系统或企业级应用可能会让 Android 设备充当 NFS 服务器，供其他设备挂载文件系统。在这种情况下，这个头文件中定义的常量会被用来管理 Android 设备上的 NFS 服务器进程 (nfsd)。
* **Android 管理 NFS 服务器:**  一些工具可能运行在 Android 系统上，用于监控或管理网络中的 NFS 服务器。这些工具可能会使用 Netlink 与远程的 NFS 服务器进行通信，虽然这个头文件定义的是本地 nfsd 的接口，但理解 Netlink 的工作方式是通用的。

**举例说明:**

假设一个 Android 系统配置为 NFS 服务器。一个系统应用需要获取当前 NFS 服务器的线程数。它可能会执行以下步骤（简化描述）：

1. **创建 Netlink 套接字:** 使用 `socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC)` 创建一个 Netlink 套接字。
2. **构建 Netlink 消息:**  构建一个 Netlink 消息，其中包含：
   - `nlmsghdr`:  Netlink 消息头，指定协议族为 `NF_NETLINK`（通用 Netlink），命令为 `NFSD_CMD_THREADS_GET`。
   - `genlmsghdr`: 通用 Netlink 消息头，指定家族名称为 `"nfsd"` (通过 `NFSD_FAMILY_NAME` 宏)。
3. **发送消息:** 使用 `sendto` 系统调用将 Netlink 消息发送到内核。
4. **接收消息:** 使用 `recvfrom` 系统调用接收来自内核的 Netlink 响应消息。
5. **解析消息:**  解析响应消息，其中包含 `NFSD_A_SERVER_THREADS` 属性及其对应的值。

**libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了一些常量和枚举。libc 函数会使用这些常量来构造和解析与内核 nfsd 子系统通信的 Netlink 消息。

例如，以下是一些可能使用到这些常量的 libc 函数（或其封装函数）：

* **`socket()`:**  用于创建 Netlink 套接字 (`AF_NETLINK`, `NETLINK_GENERIC`)。
* **`bind()`:**  将 Netlink 套接字绑定到特定的端口或组 (虽然对于客户端 Netlink 通信通常不需要显式绑定)。
* **`sendto()`:**  用于发送 Netlink 消息到内核。发送消息时，需要根据这个头文件中定义的常量来设置消息头和属性。
* **`recvfrom()`:** 用于接收来自内核的 Netlink 消息。接收到消息后，需要根据这个头文件中定义的常量来解析消息中的属性。
* **Netlink 辅助库函数:** Android Bionic 或其他库可能会提供一些封装了 Netlink 通信的辅助函数，这些函数内部会使用到这些常量。例如，可能存在一个 `nfsd_get_server_threads()` 函数，它会内部构造并发送一个 `NFSD_CMD_THREADS_GET` 命令，并解析返回的 `NFSD_A_SERVER_THREADS` 属性。

**详细解释 libc 函数的实现:**

由于这个头文件不包含 libc 函数的实现，因此无法直接解释其实现。不过，可以简要描述与 Netlink 通信相关的 libc 函数的通用实现思路：

* **`socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC)`:**  这个系统调用会陷入内核，内核创建一个 Netlink 套接字的数据结构，并返回一个文件描述符给用户空间。`AF_NETLINK` 指明了地址族为 Netlink，`SOCK_DGRAM` 指明了使用无连接的数据报协议，`NETLINK_GENERIC` 指明了使用通用 Netlink 协议族。
* **`sendto()`:**  这个系统调用会将用户空间提供的 Netlink 消息数据拷贝到内核空间，然后内核根据消息头中的信息将消息路由到对应的 Netlink 协议处理模块 (在本例中是 nfsd 的 Netlink 接口)。
* **`recvfrom()`:**  这个系统调用会阻塞调用线程，直到内核接收到匹配的 Netlink 消息。一旦接收到消息，内核将其拷贝到用户空间提供的缓冲区，并返回接收到的字节数。

**涉及 dynamic linker 的功能:**

这个头文件**不直接涉及 dynamic linker 的功能**。它定义的是内核接口，在编译时会被包含到使用它的源代码中。dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是在程序运行时加载共享库并解析符号依赖。

然而，如果一个用户空间的程序使用了这些常量并通过 libc 函数与内核的 nfsd 通信，那么该程序会链接到 libc.so。在程序启动时，dynamic linker 会加载 libc.so，并解析程序中对 libc 函数的符号引用。

**so 布局样本:**

libc.so 是一个庞大的共享库，包含大量的函数。与 Netlink 通信相关的函数可能会位于 libc.so 的网络或 socket 相关的部分。一个简化的 libc.so 布局样本可能如下所示：

```
libc.so:
    .text         # 代码段
        socket@plt
        bind@plt
        sendto@plt
        recvfrom@plt
        ... 其他函数 ...
    .rodata       # 只读数据段
        ... 字符串常量 ...
    .data         # 数据段
        ... 全局变量 ...
    .bss          # 未初始化数据段
    .symtab       # 符号表
        socket
        bind
        sendto
        recvfrom
        ... 其他符号 ...
    .strtab       # 字符串表
```

**链接的处理过程:**

1. **编译时:**  当编译使用这个头文件的源代码时，编译器会识别对 libc 函数的调用（例如 `socket`, `sendto`）。这些函数的地址在编译时是未知的。
2. **链接时:**  静态链接器会将目标文件链接在一起，生成可执行文件或共享库。它会在符号表中记录对外部符号（如 libc 函数）的引用。
3. **运行时:**  当程序启动时，dynamic linker 会执行以下步骤：
   - 加载程序本身。
   - 检查程序的依赖关系，发现需要加载 libc.so。
   - 加载 libc.so 到内存中的某个地址。
   - 解析程序的重定位表，将程序中对 libc 函数的引用地址更新为 libc.so 中对应函数的实际地址。这通常通过 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 机制实现。

**假设输入与输出 (逻辑推理):**

假设一个程序尝试获取 NFS 服务器的线程数。

**假设输入:**

* Netlink 套接字已创建并连接到内核。
* 构建的 Netlink 消息包含以下内容：
    - `nlmsghdr.nlmsg_len`:  消息长度。
    - `nlmsghdr.nlmsg_type`:  `RTM_NEWLINK` (或其他相关类型，取决于具体实现)。
    - `nlmsghdr.nlmsg_flags`:  `NLM_F_REQUEST`。
    - `nlmsghdr.nlmsg_seq`:  消息序列号。
    - `nlmsghdr.nlmsg_pid`:  发送进程的 PID。
    - `genlmsghdr.cmd`: `NFSD_CMD_THREADS_GET`.
    - `genlmsghdr.version`: `NFSD_FAMILY_VERSION`.
    - 可能包含其他属性，例如指定要查询的服务器实例（如果存在多个）。

**假设输出:**

内核会返回一个 Netlink 消息，包含以下内容：

* `nlmsghdr`:  表示一个响应消息。
* `genlmsghdr`:  表示对 `NFSD_CMD_THREADS_GET` 命令的响应。
* 一个或多个 `nlattr` 结构，其中一个的 `nla_type` 为 `NFSD_A_SERVER_THREADS`，`nla_data` 包含服务器线程数的整数值。

**用户或编程常见的使用错误:**

* **错误的 Netlink 消息结构:**  未能正确设置 `nlmsghdr` 和 `genlmsghdr` 的字段，例如错误的命令 ID 或协议族版本。
* **错误的属性类型:**  在请求或响应中使用了错误的 `nla_type` 值，导致内核无法识别或返回错误的数据。
* **缺少必要的权限:**  某些 Netlink 操作可能需要 root 权限才能执行。
* **未处理错误:**  `sendto` 和 `recvfrom` 等系统调用可能会失败，程序需要检查返回值并处理错误情况。
* **缓冲区溢出:**  在接收 Netlink 消息时，如果没有足够大的缓冲区来存储内核返回的数据，可能导致缓冲区溢出。
* **阻塞:**  如果在没有数据可接收的情况下调用 `recvfrom`，程序会阻塞。需要使用非阻塞 I/O 或 `select`/`poll` 等机制来避免无限期阻塞。
* **误解属性值的含义:**  未能正确解析 Netlink 消息中返回的属性值，例如假设它是特定的数据类型或范围。

**Android Framework 或 NDK 如何到达这里:**

1. **Framework 或 NDK 组件的需求:**  Android Framework 的一个系统服务或者使用 NDK 开发的应用，如果需要管理或监控本地的 NFS 服务器，就需要与内核的 nfsd 子系统进行通信。
2. **NDK 调用 (如果使用 NDK):**  如果使用 NDK，开发者可以直接使用标准的 POSIX socket API (例如 `socket`, `bind`, `sendto`, `recvfrom`) 来创建和操作 Netlink 套接字。
3. **Framework 调用 (如果使用 Framework):**  Android Framework 可能会提供一些更高级的 API 来管理系统服务，这些 API 内部会使用 Binder IPC 与系统服务通信。系统服务可能会使用底层的 Netlink 接口。例如，一个负责管理网络相关功能的系统服务可能会使用 Netlink 与内核交互。
4. **系统调用:**  无论是 NDK 直接调用还是 Framework 间接调用，最终都会通过系统调用 (例如 `socket`, `sendto`, `recvfrom`) 进入内核。
5. **内核 Netlink 子系统:**  内核的 Netlink 子系统接收到来自用户空间的 Netlink 消息后，会根据消息头中的协议族信息将其路由到对应的 Netlink 协议处理模块，在本例中是 nfsd 的 Netlink 接口。
6. **nfsd Netlink 接口:**  nfsd 的 Netlink 接口处理接收到的消息，执行相应的操作（例如获取服务器线程数），并将结果通过 Netlink 消息返回给用户空间。

**Frida Hook 示例调试步骤:**

假设我们想 hook 一个使用 Netlink 与 nfsd 通信的程序，例如一个名为 `nfsd_control` 的工具。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[->] {message['payload']}")
    elif message['type'] == 'receive':
        print(f"[<-] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

def main():
    package_name = "com.example.nfsdcontrol" # 替换为实际的包名或进程名
    try:
        session = frida.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process '{package_name}' not found. Attaching to spawn.")
        session = frida.attach(package_name, spawn=True)
        session.resume()

    script_code = """
    const sendtoPtr = Module.findExportByName(null, "sendto");
    const recvfromPtr = Module.findExportByName(null, "recvfrom");

    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter: function(args) {
                const sockfd = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                const flags = args[3].toInt32();
                const addr = args[4];
                const addrlen = args[5] ? args[5].toInt32() : 0;

                // 检查是否是 Netlink 套接字
                const addrFamilyPtr = addr.readPointer();
                if (addrFamilyPtr && addrFamilyPtr.toInt32() === 16) { // AF_NETLINK = 16
                    const message = hexdump(buf, { length: len, ansi: true });
                    send({ type: 'send', payload: message });
                }
            }
        });
    } else {
        console.error("sendto not found");
    }

    if (recvfromPtr) {
        Interceptor.attach(recvfromPtr, {
            onEnter: function(args) {
                this.buf = args[1]; // 保存接收缓冲区指针
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() > 0) {
                    const sockfd = ptr(this.buf).readU32(); // 获取套接字描述符
                    const message = hexdump(this.buf, { length: retval.toInt32(), ansi: true });
                    send({ type: 'receive', payload: message });
                }
            }
        });
    } else {
        console.error("recvfrom not found");
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 调试步骤:**

1. **保存代码:** 将上述 Python 代码保存为 `frida_nfsd_hook.py`。
2. **找到目标进程:** 确定与 NFS 控制相关的进程名称或包名。
3. **运行 Frida 脚本:**  在终端中运行 `frida -UF -l frida_nfsd_hook.py` (如果已知应用包名) 或 `frida -n <进程名> -l frida_nfsd_hook.py` (如果已知进程名)。
4. **观察输出:**  Frida 脚本会 hook `sendto` 和 `recvfrom` 函数，并尝试识别 Netlink 套接字的调用。当程序发送或接收 Netlink 消息时，脚本会打印出消息的 hexdump。
5. **分析输出:**  分析 hexdump 输出，可以查看发送的命令 ID (`NFSD_CMD_*`) 和接收到的属性类型 (`NFSD_A_*`)，从而理解程序与内核 nfsd 的交互过程。
6. **修改脚本:**  可以根据需要修改 Frida 脚本，例如添加过滤条件只关注特定的命令或属性，或者修改消息内容进行更深入的调试。

这个 Frida 示例提供了一个基本的框架，可以根据具体的调试需求进行扩展，例如可以 hook 封装 Netlink 通信的更高级别的库函数，或者修改 Netlink 消息的内容来测试内核的行为。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/nfsd_netlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_NFSD_NETLINK_H
#define _UAPI_LINUX_NFSD_NETLINK_H
#define NFSD_FAMILY_NAME "nfsd"
#define NFSD_FAMILY_VERSION 1
enum {
  NFSD_A_RPC_STATUS_XID = 1,
  NFSD_A_RPC_STATUS_FLAGS,
  NFSD_A_RPC_STATUS_PROG,
  NFSD_A_RPC_STATUS_VERSION,
  NFSD_A_RPC_STATUS_PROC,
  NFSD_A_RPC_STATUS_SERVICE_TIME,
  NFSD_A_RPC_STATUS_PAD,
  NFSD_A_RPC_STATUS_SADDR4,
  NFSD_A_RPC_STATUS_DADDR4,
  NFSD_A_RPC_STATUS_SADDR6,
  NFSD_A_RPC_STATUS_DADDR6,
  NFSD_A_RPC_STATUS_SPORT,
  NFSD_A_RPC_STATUS_DPORT,
  NFSD_A_RPC_STATUS_COMPOUND_OPS,
  __NFSD_A_RPC_STATUS_MAX,
  NFSD_A_RPC_STATUS_MAX = (__NFSD_A_RPC_STATUS_MAX - 1)
};
enum {
  NFSD_A_SERVER_THREADS = 1,
  NFSD_A_SERVER_GRACETIME,
  NFSD_A_SERVER_LEASETIME,
  NFSD_A_SERVER_SCOPE,
  __NFSD_A_SERVER_MAX,
  NFSD_A_SERVER_MAX = (__NFSD_A_SERVER_MAX - 1)
};
enum {
  NFSD_A_VERSION_MAJOR = 1,
  NFSD_A_VERSION_MINOR,
  NFSD_A_VERSION_ENABLED,
  __NFSD_A_VERSION_MAX,
  NFSD_A_VERSION_MAX = (__NFSD_A_VERSION_MAX - 1)
};
enum {
  NFSD_A_SERVER_PROTO_VERSION = 1,
  __NFSD_A_SERVER_PROTO_MAX,
  NFSD_A_SERVER_PROTO_MAX = (__NFSD_A_SERVER_PROTO_MAX - 1)
};
enum {
  NFSD_A_SOCK_ADDR = 1,
  NFSD_A_SOCK_TRANSPORT_NAME,
  __NFSD_A_SOCK_MAX,
  NFSD_A_SOCK_MAX = (__NFSD_A_SOCK_MAX - 1)
};
enum {
  NFSD_A_SERVER_SOCK_ADDR = 1,
  __NFSD_A_SERVER_SOCK_MAX,
  NFSD_A_SERVER_SOCK_MAX = (__NFSD_A_SERVER_SOCK_MAX - 1)
};
enum {
  NFSD_A_POOL_MODE_MODE = 1,
  NFSD_A_POOL_MODE_NPOOLS,
  __NFSD_A_POOL_MODE_MAX,
  NFSD_A_POOL_MODE_MAX = (__NFSD_A_POOL_MODE_MAX - 1)
};
enum {
  NFSD_CMD_RPC_STATUS_GET = 1,
  NFSD_CMD_THREADS_SET,
  NFSD_CMD_THREADS_GET,
  NFSD_CMD_VERSION_SET,
  NFSD_CMD_VERSION_GET,
  NFSD_CMD_LISTENER_SET,
  NFSD_CMD_LISTENER_GET,
  NFSD_CMD_POOL_MODE_SET,
  NFSD_CMD_POOL_MODE_GET,
  __NFSD_CMD_MAX,
  NFSD_CMD_MAX = (__NFSD_CMD_MAX - 1)
};
#endif
```