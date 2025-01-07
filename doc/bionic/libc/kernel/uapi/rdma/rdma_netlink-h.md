Response:
Thinking Process to Answer the RDMA Netlink Header Question:

1. **Understand the Core Purpose:** The file is `rdma_netlink.h`. Keywords: "rdma" (Remote Direct Memory Access) and "netlink". This immediately suggests it's about RDMA functionality exposed through the Linux Netlink socket interface. The path `bionic/libc/kernel/uapi/` indicates it's a user-space API definition used by the Android C library to interact with the kernel.

2. **High-Level Functionality Identification (Scan for Enums and Defines):**  Quickly scan the file for `enum` and `#define`. These define the core vocabulary and constants. Group them conceptually:
    * **Client Types:** `RDMA_NL_IWCM`, `RDMA_NL_LS`, `RDMA_NL_NLDEV`. These seem like different RDMA subsystems.
    * **Groups:** `RDMA_NL_GROUP_IWPM`, `RDMA_NL_GROUP_LS`, `RDMA_NL_GROUP_NOTIFY`. These are likely Netlink multicast groups for different notification types.
    * **Macros for Type Encoding/Decoding:** `RDMA_NL_GET_CLIENT`, `RDMA_NL_GET_OP`, `RDMA_NL_GET_TYPE`. Indicates a way to structure messages.
    * **IWPM (Infiniband Workload Partition Manager) Specifics:** A large block of `IWPM_...` enums (operations, NLA attributes). This suggests a key focus of this file.
    * **LS (Link Service) Specifics:** `RDMA_NL_LS_OP_...`, `LS_NLA_TYPE_...`, `rdma_ls_resolve_header`. Another major RDMA component.
    * **NLDEV (Netlink Device) Specifics:** `rdma_nldev_command`, `rdma_nldev_attr`, `rdma_nldev_print_type`. Likely for managing RDMA devices.
    * **Other Enums:** `RDMA_NODE_...`, `rdma_nl_counter_mode`, etc. These represent specific RDMA concepts.

3. **Connect to Android:**  RDMA is about high-performance networking and direct memory access. Think about where this might be relevant in Android:
    * **High-Performance Computing/Servers:**  Android isn't primarily a server OS, but some Android devices *could* act in such roles or interface with server infrastructure.
    * **Specialized Hardware:** Some Android devices might have RDMA-capable network interfaces for specific purposes.
    * **Virtualization/Containers:**  RDMA could be used within a virtualized or containerized Android environment.

4. **libc Function Explanation - Acknowledge Limitation:**  The *header file* itself doesn't *implement* libc functions. It *defines* constants and structures used by libc functions when interacting with the kernel RDMA subsystem. Focus on the *purpose* of these definitions for libc.

5. **Dynamic Linker:** This header file doesn't directly involve the dynamic linker. It's a *kernel* API definition. The dynamic linker is involved in loading *user-space* libraries. Note this distinction. If an Android application *used* an RDMA library (which might use these definitions), then the dynamic linker would be involved in loading that library.

6. **Logical Reasoning (Relatively Limited Here):** The structure of the enums and macros suggests a typical request-response pattern using Netlink, where messages are categorized by client and operation. The NLA attributes suggest a way to encode structured data within Netlink messages.

7. **Common User Errors:**  Focus on general Netlink usage errors and potential RDMA-specific errors based on the defined operations:
    * Incorrectly encoding/decoding Netlink messages.
    * Using incorrect operation codes or attribute types.
    * Not handling errors reported by the kernel.
    * Issues with permissions or device access.

8. **Android Framework/NDK Path:**  Trace how an application might end up using these definitions:
    * **NDK:**  An NDK library could directly interact with the Linux kernel via Netlink and use these definitions.
    * **Framework (More Likely Indirect):** The Android Framework itself might have system services or HALs (Hardware Abstraction Layers) that use RDMA. Application code would then indirectly use these services through higher-level APIs.

9. **Frida Hook Example:**  Focus on hooking the `sendto` or `recvfrom` system calls with the `NETLINK_RDMA` family to intercept the raw Netlink messages. This allows inspection of the actual data being exchanged.

10. **Structure and Language:** Organize the answer logically with clear headings. Use precise language, explaining technical terms like Netlink and NLA. Provide concrete examples where possible. Maintain a helpful and informative tone.

Self-Correction/Refinement during the process:

* **Initial thought:**  Maybe this file defines some libc wrapper functions for RDMA. **Correction:** Realized it's a *header file*, so it primarily defines *data structures and constants* used by those functions (likely in another part of `bionic`).
* **Initial thought:**  Focus heavily on the dynamic linker. **Correction:** Recognized that this header file is more about the kernel interface, and the dynamic linker's involvement is indirect (loading libraries that *use* this interface).
* **Ensuring clarity:** Double-checked explanations of Netlink and NLA to ensure they are easy to understand for someone who might not be familiar with these concepts.

By following these steps, the comprehensive and accurate answer provided earlier can be constructed.


这个文件 `bionic/libc/kernel/uapi/rdma/rdma_netlink.h` 定义了用于与 Linux 内核 RDMA (Remote Direct Memory Access) 子系统进行通信的 Netlink 接口的用户空间 API。由于它位于 `bionic/libc/kernel/uapi/` 目录下，它是由 Android 的 C 库 (bionic) 提供的，用于在用户空间程序和内核之间传递关于 RDMA 的信息。

**功能列举:**

该文件定义了以下核心功能，用于通过 Netlink 套接字与内核中的 RDMA 子系统交互：

1. **定义了不同的 RDMA Netlink 客户端类型 (`RDMA_NL_IWCM`, `RDMA_NL_LS`, `RDMA_NL_NLDEV`):**  这些枚举值代表了不同的 RDMA 相关的功能模块或者客户端，例如：
   - `RDMA_NL_IWCM`:  可能与 InfiniBand Workload Partition Manager 相关。
   - `RDMA_NL_LS`:  可能与 RDMA Link Service 相关，用于发现和管理 RDMA 网络拓扑。
   - `RDMA_NL_NLDEV`:  用于管理 RDMA 设备。

2. **定义了 Netlink 组 (`RDMA_NL_GROUP_IWPM`, `RDMA_NL_GROUP_LS`, `RDMA_NL_GROUP_NOTIFY`):**  这些定义了 Netlink 多播组，用户空间程序可以加入这些组来接收来自内核的特定 RDMA 事件通知。

3. **定义了用于构造和解析 Netlink 消息类型的宏 (`RDMA_NL_GET_CLIENT`, `RDMA_NL_GET_OP`, `RDMA_NL_GET_TYPE`):** 这些宏帮助用户空间程序构建正确的 Netlink 消息头，以便内核能够识别消息的来源和目的操作。

4. **定义了与 InfiniBand Workload Partition Manager (IWPM) 相关的常量和枚举:**
   - **操作码 (`RDMA_NL_IWPM_REG_PID`, `RDMA_NL_IWPM_ADD_MAPPING`, 等等):**  定义了可以执行的各种 IWPM 操作，例如注册进程 ID、添加/查询/移除地址映射、获取远程信息等。
   - **Netlink 属性 (NLA) (`IWPM_NLA_REG_PID_UNSPEC`, `IWPM_NLA_MANAGE_ADDR`, 等等):**  定义了用于在 Netlink 消息中携带数据的属性类型，例如进程 ID、地址、标志等。

5. **定义了与 RDMA Link Service (LS) 相关的常量和结构体:**
   - **操作码 (`RDMA_NL_LS_OP_RESOLVE`, `RDMA_NL_LS_OP_SET_TIMEOUT`, 等等):**  定义了可以执行的 LS 操作，例如解析路径、设置超时时间等。
   - **Netlink 属性 (`LS_NLA_TYPE_PATH_RECORD`, `LS_NLA_TYPE_TIMEOUT`, 等等):**  定义了用于在 LS Netlink 消息中携带数据的属性类型，例如路径记录、超时时间、GID 等。
   - **结构体 (`rdma_ls_resolve_header`, `rdma_ls_ip_resolve_header`):**  定义了与特定 LS 操作相关的消息头结构。

6. **定义了与 RDMA 设备管理 (NLDEV) 相关的常量和枚举:**
   - **命令 (`rdma_nldev_command`):**  定义了可以执行的 RDMA 设备管理命令，例如获取/设置设备信息、创建/删除链接、获取资源信息等。
   - **属性 (`rdma_nldev_attr`):**  定义了用于在 NLDEV Netlink 消息中携带数据的属性类型，涵盖了设备索引、名称、固件版本、端口状态、资源信息（如 QP、CQ、MR 等）等各种设备属性。
   - **其他枚举 (`rdma_nldev_print_type`, `rdma_nl_counter_mode`, 等等):**  定义了用于格式化输出、控制计数器模式等的选项。

**与 Android 功能的关系及举例说明:**

RDMA 是一种高性能的网络技术，通常用于数据中心和高性能计算环境。虽然 Android 主要面向移动设备，但在某些特定场景下，RDMA 也可能与 Android 功能相关：

* **Android Things 或嵌入式设备:**  如果 Android 被用在需要高性能网络通信的嵌入式设备上（例如，与服务器集群交互的设备），那么 RDMA 技术可能会被使用。
* **数据中心应用 (理论上):**  虽然不常见，但如果 Android 设备被用作数据中心基础设施的一部分（例如，轻量级计算节点），RDMA 可能用于节点间的高速互联。
* **虚拟化环境:**  在 Android 虚拟机 (例如，运行在服务器上的 Android 实例) 中，RDMA 可能被用于客户机操作系统与宿主机之间，或者客户机操作系统之间的通信。

**举例说明 (假设场景):**

假设一个 Android Things 设备连接到一个支持 RDMA 的服务器集群，该设备需要通过 RDMA 与服务器进行高速数据传输。在这种情况下，Android 应用程序可能会使用 NDK 编写，并使用 `rdma_netlink.h` 中定义的常量和结构体来构建 Netlink 消息，以便：

1. **使用 `RDMA_NL_NLDEV` 客户端和相关的命令和属性:**  查询 RDMA 设备的信息，例如设备名称、端口状态等。例如，发送一个 `RDMA_NLDEV_CMD_GET` 命令，并使用 `RDMA_NLDEV_ATTR_DEV_NAME` 属性来获取 RDMA 设备的名称。

2. **使用 `RDMA_NL_LS` 客户端和相关的操作和属性:**  发现网络中的其他 RDMA 节点。例如，发送一个 `RDMA_NL_LS_OP_RESOLVE` 命令，并使用 `LS_NLA_TYPE_DGID` 属性指定目标节点的 GID (Global Identifier)。

3. **使用 `RDMA_NL_IWCM` 客户端和相关的操作和属性:**  如果涉及到 workload partitioning，可能需要注册进程 ID，添加地址映射等。

**libc 函数的实现解释:**

`rdma_netlink.h` 本身是一个头文件，它**不包含** libc 函数的实现。它定义了常量、枚举和结构体，这些会被 libc 中与 Netlink 套接字交互的函数使用。

与 Netlink 交互的常见 libc 函数包括：

* **`socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA)`:**  创建一个 Netlink 套接字，用于与内核的 RDMA 子系统通信。`NETLINK_RDMA` 是一个协议族常量，用于指定与 RDMA 相关的 Netlink 协议。
* **`bind(sockfd, (struct sockaddr *)&addr, sizeof(addr))`:**  将 Netlink 套接字绑定到一个地址。对于用户空间程序，通常需要指定进程 ID 作为 Netlink 地址的一部分。
* **`sendto(sockfd, buf, len, flags, (struct sockaddr *)&dest_addr, sizeof(dest_addr))`:**  通过 Netlink 套接字发送消息到内核或另一个 Netlink 套接字。`buf` 包含根据 `rdma_netlink.h` 中定义的结构体和常量构建的 Netlink 消息。
* **`recvfrom(sockfd, buf, len, flags, (struct sockaddr *)&src_addr, &addrlen))`:**  从 Netlink 套接字接收消息。接收到的消息需要根据 `rdma_netlink.h` 中定义的结构体和常量进行解析。

**这些 libc 函数的实现位于 bionic 的源代码中，例如 `bionic/libc/net/` 或 `bionic/libc/syscalls/` 目录下。** 它们的实现涉及到：

1. **系统调用:**  这些 libc 函数最终会调用相应的 Linux 系统调用，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`。
2. **错误处理:**  libc 函数会处理系统调用返回的错误，并设置 `errno` 变量。
3. **数据结构操作:**  libc 函数会操作与套接字相关的内核数据结构。
4. **地址结构处理:**  libc 函数会处理 `sockaddr_nl` 结构体，用于指定 Netlink 通信的源地址和目标地址。

**涉及 dynamic linker 的功能:**

`rdma_netlink.h` 本身**不直接涉及** dynamic linker 的功能。它是一个内核 API 的头文件。

Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载和链接共享库 (`.so` 文件)。如果一个 Android 应用程序或库需要使用 RDMA 功能，它可能会链接到一个提供 RDMA 相关功能的共享库。

**so 布局样本 (假设):**

假设存在一个名为 `librdma_client.so` 的共享库，它封装了与 RDMA 子系统交互的功能。其布局可能如下：

```
librdma_client.so:
    .text:  // 代码段，包含 RDMA 客户端的逻辑，例如创建 Netlink 套接字、发送/接收消息等
        rdma_connect()
        rdma_send_data()
        rdma_receive_data()
        // ... 其他 RDMA 相关函数 ...

    .rodata: // 只读数据段，可能包含一些常量

    .data:   // 可读写数据段，可能包含一些全局变量

    .dynamic: // 动态链接信息，包含依赖关系、符号表等

    .symtab:  // 符号表，列出库中定义的符号 (函数名、变量名等)

    .strtab:  // 字符串表，存储符号名称

    .rel.dyn: // 动态重定位表

    .rel.plt: // PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程:**

1. **编译时:**  当应用程序或另一个共享库链接到 `librdma_client.so` 时，编译器会将对 `librdma_client.so` 中符号的引用记录下来。

2. **加载时 (Dynamic Linker 的工作):**
   - 当应用程序启动时，或者在运行时需要加载 `librdma_client.so` 时，dynamic linker 会被调用。
   - Dynamic linker 会读取 `librdma_client.so` 的 `.dynamic` 段，获取其依赖关系 (如果它依赖于其他共享库)。
   - Dynamic linker 会加载 `librdma_client.so` 及其依赖项到内存中。
   - **符号解析和重定位:** Dynamic linker 会解析应用程序或其他库中对 `librdma_client.so` 中符号的引用，并更新相应的地址。例如，如果应用程序调用了 `rdma_connect()` 函数，dynamic linker 会将该调用指令的目标地址修改为 `rdma_connect()` 函数在内存中的实际地址。PLT 和 GOT (Global Offset Table) 用于实现延迟绑定，提高加载性能。

**逻辑推理 (假设输入与输出):**

假设一个用户空间程序想要获取本地 RDMA 设备的名称。

**假设输入:**

- Netlink 套接字已创建并绑定。
- 构建的 Netlink 消息包含：
    - `nl_family`: `AF_NETLINK`
    - `nl_pid`:  发送进程的 ID
    - `nl_groups`: 0
    - 消息头指示 `RDMA_NL_NLDEV` 客户端和 `RDMA_NLDEV_CMD_GET` 操作。
    - Netlink 属性包含 `RDMA_NLDEV_ATTR_DEV_INDEX` 和期望获取的设备索引 (例如 0)。

**预期输出:**

- 内核会回复一个 Netlink 消息，包含：
    - 相同的 `nl_family` 和 `nl_pid`。
    - 消息头指示 `RDMA_NL_NLDEV` 客户端和相应的响应操作。
    - Netlink 属性包含：
        - `RDMA_NLDEV_ATTR_DEV_INDEX`:  请求的设备索引 (0)。
        - `RDMA_NLDEV_ATTR_DEV_NAME`:  对应设备的名称 (例如 "mlx5_0")。

**用户或编程常见的使用错误:**

1. **Netlink 消息构造错误:**
   - **错误的头部:**  例如，使用了错误的客户端类型或操作码。
   - **错误的属性类型或顺序:**  Netlink 属性需要按照规定的格式和顺序添加。
   - **缺少必要的属性:**  某些操作可能需要特定的属性才能成功。
   - **属性数据长度错误:**  属性数据的长度必须与实际数据匹配。
   ```c
   // 错误示例：忘记设置 NLA 头部长度
   struct nlattr *nla = (struct nlattr *)NLMSG_TAIL(nlh);
   nla->nla_type = RDMA_NLDEV_ATTR_DEV_INDEX;
   // 缺少 nla->nla_len 的设置
   ```

2. **Netlink 套接字操作错误:**
   - **忘记绑定套接字:**  在发送消息之前，需要将 Netlink 套接字绑定到本地地址。
   - **目标地址错误:**  发送消息时，需要指定正确的目标 Netlink 地址 (通常是内核的 0)。
   - **权限问题:**  某些 RDMA 操作可能需要 root 权限。

3. **错误处理不足:**
   - **未检查 `sendto` 和 `recvfrom` 的返回值:**  这些函数可能会返回错误，例如连接失败或超时。
   - **未正确解析内核返回的错误消息:**  内核可能会通过 Netlink 消息返回错误代码，用户程序需要能够解析并处理这些错误。

4. **RDMA 概念理解不足:**
   - **错误地使用 RDMA 操作:**  例如，在没有正确建立连接的情况下尝试发送数据。
   - **不了解 RDMA 资源的生命周期:**  例如，在资源释放后尝试访问。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**  一个使用 C/C++ 进行 Android 开发的开发者，如果需要与 RDMA 硬件交互，可能会使用 NDK。
2. **系统服务 (Framework):**  Android Framework 中可能存在一些系统服务，负责管理或监控底层的硬件资源，包括 RDMA 设备。这些服务可能会使用底层的 Netlink 接口与内核通信。
3. **硬件抽象层 (HAL):**  Android 的 HAL 层介于 Framework 和硬件驱动之间。如果 Android 设备支持 RDMA，可能会有一个 RDMA HAL 模块，该模块会使用 Netlink 与内核 RDMA 驱动进行通信。

**步骤示例 (NDK 使用场景):**

1. **应用程序通过 JNI 调用 NDK 代码。**
2. **NDK 代码创建一个 Netlink 套接字，协议族为 `AF_NETLINK`，协议为 `NETLINK_RDMA`。**
   ```c
   int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA);
   ```
3. **NDK 代码构建一个 Netlink 消息，包含 `rdma_netlink.h` 中定义的常量和结构体。**
   ```c
   struct sockaddr_nl src_addr, dest_addr;
   struct nlmsghdr *nlh;
   struct iovec iov;
   struct msghdr msg;
   char *nl_buf;

   // ... 初始化地址结构 ...

   nlh = (struct nlmsghdr *)nl_buf;
   nlh->nlmsg_len = NLMSG_LENGTH(RTM_GENERIC); // 假设使用通用消息类型
   nlh->nlmsg_type = RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET);
   nlh->nlmsg_flags = NLM_REQUEST | NLM_F_ACK;
   nlh->nlmsg_seq = msg_seq++;
   nlh->nlmsg_pid = getpid();

   // 添加 Netlink 属性 (例如，获取设备名称)
   struct nlattr *nla = NLMSG_TAIL(nlh);
   nla->nla_type = RDMA_NLDEV_ATTR_DEV_INDEX;
   nla->nla_len = NLA_LENGTH(sizeof(int));
   int dev_index = 0;
   memcpy(NLA_DATA(nla), &dev_index, sizeof(dev_index));
   nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len);

   // ... 设置 iov 和 msg ...
   ```
4. **NDK 代码使用 `sendto` 系统调用发送 Netlink 消息。**
   ```c
   sendto(sock, &msg, 0);
   ```
5. **NDK 代码使用 `recvfrom` 系统调用接收内核的响应。**
   ```c
   recvfrom(sock, &msg, 0, &src_addr, &addr_len);
   ```
6. **NDK 代码解析接收到的 Netlink 消息，提取 RDMA 设备信息。**

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `sendto` 和 `recvfrom` 系统调用，并过滤 `AF_NETLINK` 和 `NETLINK_RDMA` 相关的调用，以查看应用程序和内核之间交换的原始 Netlink 消息。

**Frida Hook 脚本示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

session = frida.attach('目标进程') # 将 '目标进程' 替换为目标应用程序的包名或进程 ID

script_code = """
Interceptor.attach(Module.findExportByName(null, "sendto"), {
    onEnter: function(args) {
        const sockfd = args[0].toInt32();
        const buff = args[1];
        const len = args[2].toInt32();
        const dest_addr = ptr(args[4]);
        const addrlen = args[5].toInt32();

        const sa_family = dest_addr.readU16();
        if (sa_family === 16) { // AF_NETLINK = 16
            const nl_family = dest_addr.add(2).readU16();
            if (nl_family === 25) { // NETLINK_RDMA = 25
                console.log("[Sendto] sockfd:", sockfd, "len:", len);
                console.log("Netlink Header:");
                const nlmsghdr = buff.readByteArray(16); // 读取 Netlink 消息头
                console.log(hexdump(nlmsghdr, { ansi: true }));
            }
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
    onEnter: function(args) {
        this.sockfd = args[0].toInt32();
        this.buff = args[1];
        this.len = args[2].toInt32();
        this.src_addr = ptr(args[4]);
        this.addrlen = ptr(args[5]);
    },
    onLeave: function(retval) {
        if (retval.toInt32() > 0) {
            const sa_family = this.src_addr.readU16();
            if (sa_family === 16) { // AF_NETLINK = 16
                const nl_family = this.src_addr.add(2).readU16();
                if (nl_family === 25) { // NETLINK_RDMA = 25
                    console.log("[Recvfrom] sockfd:", this.sockfd, "len:", retval.toInt32());
                    console.log("Netlink Header:");
                    const nlmsghdr = this.buff.readByteArray(16); // 读取 Netlink 消息头
                    console.log(hexdump(nlmsghdr, { ansi: true }));
                }
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. 将上述 Python 代码保存为 `rdma_hook.py`。
2. 找到目标 Android 进程的包名或进程 ID。
3. 运行 Frida 脚本：`frida -U -f <目标包名> -l rdma_hook.py` 或 `frida -U <目标进程ID> -l rdma_hook.py`。
4. 执行目标应用程序中与 RDMA 交互的操作。
5. Frida 会打印出 `sendto` 和 `recvfrom` 系统调用中与 `AF_NETLINK` 和 `NETLINK_RDMA` 相关的消息，包括 Netlink 消息头的内容，可以进一步分析消息类型、标志和数据。

通过这种方式，可以详细观察 Android 应用程序如何使用 `rdma_netlink.h` 中定义的接口与内核 RDMA 子系统进行通信。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/rdma_netlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_RDMA_NETLINK_H
#define _UAPI_RDMA_NETLINK_H
#include <linux/types.h>
enum {
  RDMA_NL_IWCM = 2,
  RDMA_NL_RSVD,
  RDMA_NL_LS,
  RDMA_NL_NLDEV,
  RDMA_NL_NUM_CLIENTS
};
enum {
  RDMA_NL_GROUP_IWPM = 2,
  RDMA_NL_GROUP_LS,
  RDMA_NL_GROUP_NOTIFY,
  RDMA_NL_NUM_GROUPS
};
#define RDMA_NL_GET_CLIENT(type) ((type & (((1 << 6) - 1) << 10)) >> 10)
#define RDMA_NL_GET_OP(type) (type & ((1 << 10) - 1))
#define RDMA_NL_GET_TYPE(client,op) ((client << 10) + op)
#define IWPM_UABI_VERSION_MIN 3
#define IWPM_UABI_VERSION 4
enum {
  IWPM_FLAGS_NO_PORT_MAP = (1 << 0),
};
enum {
  RDMA_NL_IWPM_REG_PID = 0,
  RDMA_NL_IWPM_ADD_MAPPING,
  RDMA_NL_IWPM_QUERY_MAPPING,
  RDMA_NL_IWPM_REMOVE_MAPPING,
  RDMA_NL_IWPM_REMOTE_INFO,
  RDMA_NL_IWPM_HANDLE_ERR,
  RDMA_NL_IWPM_MAPINFO,
  RDMA_NL_IWPM_MAPINFO_NUM,
  RDMA_NL_IWPM_HELLO,
  RDMA_NL_IWPM_NUM_OPS
};
enum {
  IWPM_NLA_REG_PID_UNSPEC = 0,
  IWPM_NLA_REG_PID_SEQ,
  IWPM_NLA_REG_IF_NAME,
  IWPM_NLA_REG_IBDEV_NAME,
  IWPM_NLA_REG_ULIB_NAME,
  IWPM_NLA_REG_PID_MAX
};
enum {
  IWPM_NLA_RREG_PID_UNSPEC = 0,
  IWPM_NLA_RREG_PID_SEQ,
  IWPM_NLA_RREG_IBDEV_NAME,
  IWPM_NLA_RREG_ULIB_NAME,
  IWPM_NLA_RREG_ULIB_VER,
  IWPM_NLA_RREG_PID_ERR,
  IWPM_NLA_RREG_PID_MAX
};
enum {
  IWPM_NLA_MANAGE_MAPPING_UNSPEC = 0,
  IWPM_NLA_MANAGE_MAPPING_SEQ,
  IWPM_NLA_MANAGE_ADDR,
  IWPM_NLA_MANAGE_FLAGS,
  IWPM_NLA_MANAGE_MAPPING_MAX
};
enum {
  IWPM_NLA_RMANAGE_MAPPING_UNSPEC = 0,
  IWPM_NLA_RMANAGE_MAPPING_SEQ,
  IWPM_NLA_RMANAGE_ADDR,
  IWPM_NLA_RMANAGE_MAPPED_LOC_ADDR,
  IWPM_NLA_MANAGE_MAPPED_LOC_ADDR = IWPM_NLA_RMANAGE_MAPPED_LOC_ADDR,
  IWPM_NLA_RMANAGE_MAPPING_ERR,
  IWPM_NLA_RMANAGE_MAPPING_MAX
};
#define IWPM_NLA_MAPINFO_SEND_MAX 3
#define IWPM_NLA_REMOVE_MAPPING_MAX 3
enum {
  IWPM_NLA_QUERY_MAPPING_UNSPEC = 0,
  IWPM_NLA_QUERY_MAPPING_SEQ,
  IWPM_NLA_QUERY_LOCAL_ADDR,
  IWPM_NLA_QUERY_REMOTE_ADDR,
  IWPM_NLA_QUERY_FLAGS,
  IWPM_NLA_QUERY_MAPPING_MAX,
};
enum {
  IWPM_NLA_RQUERY_MAPPING_UNSPEC = 0,
  IWPM_NLA_RQUERY_MAPPING_SEQ,
  IWPM_NLA_RQUERY_LOCAL_ADDR,
  IWPM_NLA_RQUERY_REMOTE_ADDR,
  IWPM_NLA_RQUERY_MAPPED_LOC_ADDR,
  IWPM_NLA_RQUERY_MAPPED_REM_ADDR,
  IWPM_NLA_RQUERY_MAPPING_ERR,
  IWPM_NLA_RQUERY_MAPPING_MAX
};
enum {
  IWPM_NLA_MAPINFO_REQ_UNSPEC = 0,
  IWPM_NLA_MAPINFO_ULIB_NAME,
  IWPM_NLA_MAPINFO_ULIB_VER,
  IWPM_NLA_MAPINFO_REQ_MAX
};
enum {
  IWPM_NLA_MAPINFO_UNSPEC = 0,
  IWPM_NLA_MAPINFO_LOCAL_ADDR,
  IWPM_NLA_MAPINFO_MAPPED_ADDR,
  IWPM_NLA_MAPINFO_FLAGS,
  IWPM_NLA_MAPINFO_MAX
};
enum {
  IWPM_NLA_MAPINFO_NUM_UNSPEC = 0,
  IWPM_NLA_MAPINFO_SEQ,
  IWPM_NLA_MAPINFO_SEND_NUM,
  IWPM_NLA_MAPINFO_ACK_NUM,
  IWPM_NLA_MAPINFO_NUM_MAX
};
enum {
  IWPM_NLA_ERR_UNSPEC = 0,
  IWPM_NLA_ERR_SEQ,
  IWPM_NLA_ERR_CODE,
  IWPM_NLA_ERR_MAX
};
enum {
  IWPM_NLA_HELLO_UNSPEC = 0,
  IWPM_NLA_HELLO_ABI_VERSION,
  IWPM_NLA_HELLO_MAX
};
enum {
  RDMA_NODE_IB_CA = 1,
  RDMA_NODE_IB_SWITCH,
  RDMA_NODE_IB_ROUTER,
  RDMA_NODE_RNIC,
  RDMA_NODE_USNIC,
  RDMA_NODE_USNIC_UDP,
  RDMA_NODE_UNSPECIFIED,
};
enum {
  RDMA_NL_LS_OP_RESOLVE = 0,
  RDMA_NL_LS_OP_SET_TIMEOUT,
  RDMA_NL_LS_OP_IP_RESOLVE,
  RDMA_NL_LS_NUM_OPS
};
#define RDMA_NL_LS_F_ERR 0x0100
enum {
  LS_RESOLVE_PATH_USE_ALL = 0,
  LS_RESOLVE_PATH_USE_UNIDIRECTIONAL,
  LS_RESOLVE_PATH_USE_GMP,
  LS_RESOLVE_PATH_USE_MAX
};
#define LS_DEVICE_NAME_MAX 64
struct rdma_ls_resolve_header {
  __u8 device_name[LS_DEVICE_NAME_MAX];
  __u8 port_num;
  __u8 path_use;
};
struct rdma_ls_ip_resolve_header {
  __u32 ifindex;
};
#define RDMA_NLA_F_MANDATORY (1 << 13)
#define RDMA_NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER | RDMA_NLA_F_MANDATORY))
enum {
  LS_NLA_TYPE_UNSPEC = 0,
  LS_NLA_TYPE_PATH_RECORD,
  LS_NLA_TYPE_TIMEOUT,
  LS_NLA_TYPE_SERVICE_ID,
  LS_NLA_TYPE_DGID,
  LS_NLA_TYPE_SGID,
  LS_NLA_TYPE_TCLASS,
  LS_NLA_TYPE_PKEY,
  LS_NLA_TYPE_QOS_CLASS,
  LS_NLA_TYPE_IPV4,
  LS_NLA_TYPE_IPV6,
  LS_NLA_TYPE_MAX
};
struct rdma_nla_ls_gid {
  __u8 gid[16];
};
enum rdma_nldev_command {
  RDMA_NLDEV_CMD_UNSPEC,
  RDMA_NLDEV_CMD_GET,
  RDMA_NLDEV_CMD_SET,
  RDMA_NLDEV_CMD_NEWLINK,
  RDMA_NLDEV_CMD_DELLINK,
  RDMA_NLDEV_CMD_PORT_GET,
  RDMA_NLDEV_CMD_SYS_GET,
  RDMA_NLDEV_CMD_SYS_SET,
  RDMA_NLDEV_CMD_RES_GET = 9,
  RDMA_NLDEV_CMD_RES_QP_GET,
  RDMA_NLDEV_CMD_RES_CM_ID_GET,
  RDMA_NLDEV_CMD_RES_CQ_GET,
  RDMA_NLDEV_CMD_RES_MR_GET,
  RDMA_NLDEV_CMD_RES_PD_GET,
  RDMA_NLDEV_CMD_GET_CHARDEV,
  RDMA_NLDEV_CMD_STAT_SET,
  RDMA_NLDEV_CMD_STAT_GET,
  RDMA_NLDEV_CMD_STAT_DEL,
  RDMA_NLDEV_CMD_RES_QP_GET_RAW,
  RDMA_NLDEV_CMD_RES_CQ_GET_RAW,
  RDMA_NLDEV_CMD_RES_MR_GET_RAW,
  RDMA_NLDEV_CMD_RES_CTX_GET,
  RDMA_NLDEV_CMD_RES_SRQ_GET,
  RDMA_NLDEV_CMD_STAT_GET_STATUS,
  RDMA_NLDEV_CMD_RES_SRQ_GET_RAW,
  RDMA_NLDEV_CMD_NEWDEV,
  RDMA_NLDEV_CMD_DELDEV,
  RDMA_NLDEV_CMD_MONITOR,
  RDMA_NLDEV_NUM_OPS
};
enum rdma_nldev_print_type {
  RDMA_NLDEV_PRINT_TYPE_UNSPEC,
  RDMA_NLDEV_PRINT_TYPE_HEX,
};
enum rdma_nldev_attr {
  RDMA_NLDEV_ATTR_UNSPEC,
  RDMA_NLDEV_ATTR_PAD = RDMA_NLDEV_ATTR_UNSPEC,
  RDMA_NLDEV_ATTR_DEV_INDEX,
  RDMA_NLDEV_ATTR_DEV_NAME,
  RDMA_NLDEV_ATTR_PORT_INDEX,
  RDMA_NLDEV_ATTR_CAP_FLAGS,
  RDMA_NLDEV_ATTR_FW_VERSION,
  RDMA_NLDEV_ATTR_NODE_GUID,
  RDMA_NLDEV_ATTR_SYS_IMAGE_GUID,
  RDMA_NLDEV_ATTR_SUBNET_PREFIX,
  RDMA_NLDEV_ATTR_LID,
  RDMA_NLDEV_ATTR_SM_LID,
  RDMA_NLDEV_ATTR_LMC,
  RDMA_NLDEV_ATTR_PORT_STATE,
  RDMA_NLDEV_ATTR_PORT_PHYS_STATE,
  RDMA_NLDEV_ATTR_DEV_NODE_TYPE,
  RDMA_NLDEV_ATTR_RES_SUMMARY,
  RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY,
  RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME,
  RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR,
  RDMA_NLDEV_ATTR_RES_QP,
  RDMA_NLDEV_ATTR_RES_QP_ENTRY,
  RDMA_NLDEV_ATTR_RES_LQPN,
  RDMA_NLDEV_ATTR_RES_RQPN,
  RDMA_NLDEV_ATTR_RES_RQ_PSN,
  RDMA_NLDEV_ATTR_RES_SQ_PSN,
  RDMA_NLDEV_ATTR_RES_PATH_MIG_STATE,
  RDMA_NLDEV_ATTR_RES_TYPE,
  RDMA_NLDEV_ATTR_RES_STATE,
  RDMA_NLDEV_ATTR_RES_PID,
  RDMA_NLDEV_ATTR_RES_KERN_NAME,
  RDMA_NLDEV_ATTR_RES_CM_ID,
  RDMA_NLDEV_ATTR_RES_CM_ID_ENTRY,
  RDMA_NLDEV_ATTR_RES_PS,
  RDMA_NLDEV_ATTR_RES_SRC_ADDR,
  RDMA_NLDEV_ATTR_RES_DST_ADDR,
  RDMA_NLDEV_ATTR_RES_CQ,
  RDMA_NLDEV_ATTR_RES_CQ_ENTRY,
  RDMA_NLDEV_ATTR_RES_CQE,
  RDMA_NLDEV_ATTR_RES_USECNT,
  RDMA_NLDEV_ATTR_RES_POLL_CTX,
  RDMA_NLDEV_ATTR_RES_MR,
  RDMA_NLDEV_ATTR_RES_MR_ENTRY,
  RDMA_NLDEV_ATTR_RES_RKEY,
  RDMA_NLDEV_ATTR_RES_LKEY,
  RDMA_NLDEV_ATTR_RES_IOVA,
  RDMA_NLDEV_ATTR_RES_MRLEN,
  RDMA_NLDEV_ATTR_RES_PD,
  RDMA_NLDEV_ATTR_RES_PD_ENTRY,
  RDMA_NLDEV_ATTR_RES_LOCAL_DMA_LKEY,
  RDMA_NLDEV_ATTR_RES_UNSAFE_GLOBAL_RKEY,
  RDMA_NLDEV_ATTR_NDEV_INDEX,
  RDMA_NLDEV_ATTR_NDEV_NAME,
  RDMA_NLDEV_ATTR_DRIVER,
  RDMA_NLDEV_ATTR_DRIVER_ENTRY,
  RDMA_NLDEV_ATTR_DRIVER_STRING,
  RDMA_NLDEV_ATTR_DRIVER_PRINT_TYPE,
  RDMA_NLDEV_ATTR_DRIVER_S32,
  RDMA_NLDEV_ATTR_DRIVER_U32,
  RDMA_NLDEV_ATTR_DRIVER_S64,
  RDMA_NLDEV_ATTR_DRIVER_U64,
  RDMA_NLDEV_ATTR_RES_PDN,
  RDMA_NLDEV_ATTR_RES_CQN,
  RDMA_NLDEV_ATTR_RES_MRN,
  RDMA_NLDEV_ATTR_RES_CM_IDN,
  RDMA_NLDEV_ATTR_RES_CTXN,
  RDMA_NLDEV_ATTR_LINK_TYPE,
  RDMA_NLDEV_SYS_ATTR_NETNS_MODE,
  RDMA_NLDEV_ATTR_DEV_PROTOCOL,
  RDMA_NLDEV_NET_NS_FD,
  RDMA_NLDEV_ATTR_CHARDEV_TYPE,
  RDMA_NLDEV_ATTR_CHARDEV_NAME,
  RDMA_NLDEV_ATTR_CHARDEV_ABI,
  RDMA_NLDEV_ATTR_CHARDEV,
  RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID,
  RDMA_NLDEV_ATTR_STAT_MODE,
  RDMA_NLDEV_ATTR_STAT_RES,
  RDMA_NLDEV_ATTR_STAT_AUTO_MODE_MASK,
  RDMA_NLDEV_ATTR_STAT_COUNTER,
  RDMA_NLDEV_ATTR_STAT_COUNTER_ENTRY,
  RDMA_NLDEV_ATTR_STAT_COUNTER_ID,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTERS,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE,
  RDMA_NLDEV_ATTR_DEV_DIM,
  RDMA_NLDEV_ATTR_RES_RAW,
  RDMA_NLDEV_ATTR_RES_CTX,
  RDMA_NLDEV_ATTR_RES_CTX_ENTRY,
  RDMA_NLDEV_ATTR_RES_SRQ,
  RDMA_NLDEV_ATTR_RES_SRQ_ENTRY,
  RDMA_NLDEV_ATTR_RES_SRQN,
  RDMA_NLDEV_ATTR_MIN_RANGE,
  RDMA_NLDEV_ATTR_MAX_RANGE,
  RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTER_INDEX,
  RDMA_NLDEV_ATTR_STAT_HWCOUNTER_DYNAMIC,
  RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE,
  RDMA_NLDEV_ATTR_DRIVER_DETAILS,
  RDMA_NLDEV_ATTR_RES_SUBTYPE,
  RDMA_NLDEV_ATTR_DEV_TYPE,
  RDMA_NLDEV_ATTR_PARENT_NAME,
  RDMA_NLDEV_ATTR_NAME_ASSIGN_TYPE,
  RDMA_NLDEV_ATTR_EVENT_TYPE,
  RDMA_NLDEV_SYS_ATTR_MONITOR_MODE,
  RDMA_NLDEV_ATTR_MAX
};
enum rdma_nl_counter_mode {
  RDMA_COUNTER_MODE_NONE,
  RDMA_COUNTER_MODE_AUTO,
  RDMA_COUNTER_MODE_MANUAL,
  RDMA_COUNTER_MODE_MAX,
};
enum rdma_nl_counter_mask {
  RDMA_COUNTER_MASK_QP_TYPE = 1,
  RDMA_COUNTER_MASK_PID = 1 << 1,
};
enum rdma_nl_dev_type {
  RDMA_DEVICE_TYPE_SMI = 1,
};
enum rdma_nl_name_assign_type {
  RDMA_NAME_ASSIGN_TYPE_UNKNOWN = 0,
  RDMA_NAME_ASSIGN_TYPE_USER = 1,
};
enum rdma_nl_notify_event_type {
  RDMA_REGISTER_EVENT,
  RDMA_UNREGISTER_EVENT,
  RDMA_NETDEV_ATTACH_EVENT,
  RDMA_NETDEV_DETACH_EVENT,
};
#endif

"""

```