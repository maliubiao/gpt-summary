Response:
Let's break down the thought process for answering the request about the `smc.h` header file.

**1. Initial Understanding of the Request:**

The core request is to analyze the provided C header file (`smc.h`) and explain its purpose, relation to Android, function implementations, dynamic linking aspects, common errors, and how Android reaches this code. The context provided is that this file belongs to Android's Bionic library, specifically under the kernel UAPI.

**2. Identifying Key Areas of the Header File:**

Scanning the header file immediately reveals several key structural elements:

* **Includes Guard:** `#ifndef _UAPI_LINUX_SMC_H_` prevents multiple inclusions. This is standard practice in C/C++.
* **Enums:**  Numerous `enum` definitions are present (e.g., `SMC_PNETID_UNSPEC`, `SMC_NETLINK_GET_SYS_INFO`, `SMC_NLA_SYS_VER`). These are likely defining constants used for different aspects of the SMC (Shared Memory Communications) functionality.
* **Defines:** Several `#define` directives exist (e.g., `SMCR_GENL_FAMILY_NAME`, `SMC_PCI_ID_STR_LEN`). These are likely string literals and constants.

**3. Connecting to the Context (Bionic and Android):**

The path `bionic/libc/kernel/uapi/linux/smc.handroid` strongly suggests this file is related to interacting with the Linux kernel's SMC subsystem from Android's userspace. The "uapi" indicates "user API," meaning it defines the interface seen by userspace applications.

**4. Deciphering the Enums and Defines (Deductive Reasoning):**

* **`SMC_PNETID` Enums:** These seem to relate to identifying network interfaces or ports associated with SMC. The `GET`, `ADD`, `DEL`, `FLUSH` suggests operations on a list of these identifiers. "PNETID" likely stands for "Physical Network ID."
* **`SMC_GENL_FAMILY_NAME` & `SMC_GENL_FAMILY_VERSION`:** The presence of "GENL" hints at Netlink, a kernel mechanism for communication between the kernel and userspace. These defines likely identify a specific Netlink family used by SMC.
* **`SMC_NETLINK_GET_*` Enums:**  These strongly indicate different types of information or actions that can be requested from the kernel's SMC subsystem via Netlink. "LGR" and "DEV" likely refer to logical groups and devices, respectively. "SMCR" and "SMCD" are probably specific SMC components or roles. "UEID" and "SEID" are likely some form of identifiers related to SMC connections or endpoints.
* **`SMC_NLA_*` Enums:** The "NLA" likely stands for "Netlink Attribute." These enums define the types of data that can be exchanged in the Netlink messages related to SMC. Breaking down the suffixes (e.g., `_SYS`, `_LGR`, `_LINK`) helps categorize the attributes.

**5. Formulating the Functional Description:**

Based on the enums and defines, a high-level understanding of the file's purpose emerges:

* Defining constants for interacting with the Linux kernel's Shared Memory Communications (SMC) subsystem.
* Using the Netlink protocol for communication.
* Providing mechanisms to query system information, manage logical groups, links, devices, and collect statistics related to SMC.
* Handling identifiers (UEID, SEID) and limitations (HS_LIMITATION).

**6. Connecting to Android Functionality:**

SMC is a performance optimization for network communication. Android, being a mobile operating system, benefits from such optimizations. Examples of potential Android usage include:

* **Faster inter-process communication (IPC):** If Android uses SMC for certain IPC mechanisms, this header file would be relevant.
* **Optimized network connections:**  Applications using network sockets could potentially benefit from underlying SMC support.

**7. Addressing Libc Function Implementation (Important Clarification):**

The header file itself *doesn't implement* libc functions. It *defines constants* that might be used by libc functions or other userspace tools to interact with the kernel. This is a crucial distinction. The question incorrectly assumed the header file contains function implementations. The answer needs to correct this misconception.

**8. Dynamic Linker Aspects:**

Since this is a header file, it doesn't directly involve the dynamic linker. However,  if code *using* these definitions were part of a shared library, the standard dynamic linking processes would apply. A simple example of a hypothetical `libsmc_user.so` was constructed to illustrate this. The explanation focused on the standard SO layout and the linker's role in resolving symbols.

**9. Logical Reasoning (Assumptions and Outputs):**

For the Netlink interactions,  it's possible to hypothesize how data might be structured in a Netlink message based on the defined attributes. For example, when requesting system info (`SMC_NETLINK_GET_SYS_INFO`), the kernel might respond with a Netlink message containing attributes defined by `SMC_NLA_SYS_*`.

**10. Common Usage Errors:**

Focusing on incorrect usage of the defined constants or incorrect handling of Netlink messages are good examples of common errors.

**11. Android Framework/NDK and Frida Hooking:**

This part requires tracing how an Android application might eventually trigger code that uses these definitions. The pathway likely involves:

* **Application using sockets:**  Standard Java/Kotlin networking APIs.
* **Android Framework:**  The framework interacts with the kernel on behalf of the application.
* **NDK (Optional):** Native code using socket APIs.
* **Bionic Libc:**  The underlying C library implements the socket functions.
* **Kernel System Calls:**  Libc functions make system calls, potentially involving SMC-related calls.
* **Netlink:** The kernel SMC subsystem uses Netlink to communicate status or receive commands.

The Frida hook example focuses on hooking a likely system call related to Netlink (`sendto` with `AF_NETLINK`).

**12. Review and Refinement:**

After drafting the initial response, it's important to review for clarity, accuracy, and completeness. Ensure the distinction between header file definitions and function implementations is clear. Check that the explanations are easy to understand and the examples are relevant. For instance, initially, the explanation of libc functions might have been misleading, so it was corrected to emphasize that the header *defines*, not *implements*.

This iterative thought process, combining direct analysis of the code with contextual knowledge of Android and the Linux kernel, allows for a comprehensive and accurate answer to the complex request.
这个C头文件 `smc.h` 定义了与 Linux 内核中的共享内存通信 (Shared Memory Communications - SMC) 子系统交互的用户空间 API。它不是一个实际的源代码文件，而是一个头文件，用于定义常量、枚举和宏，这些在用户空间程序与内核 SMC 模块进行通信时使用。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它是 Android Bionic C 库的一部分，用于定义用户空间程序可以直接使用的内核接口。

**功能列举:**

这个头文件主要定义了以下几个方面的功能：

1. **SMC 网络 ID (PNETID) 管理:**
   - 定义了 `SMC_PNETID_*` 枚举，用于标识不同类型的物理网络接口，如未指定、名称、以太网名称、IB 名称、IB 端口。
   - 定义了 `SMC_PNETID_GET`, `SMC_PNETID_ADD`, `SMC_PNETID_DEL`, `SMC_PNETID_FLUSH` 等常量，用于指定对 PNETID 执行的操作类型（获取、添加、删除、刷新）。

2. **SMC Netlink 通信:**
   - 定义了与 SMC 相关的 Generic Netlink 家族名称和版本：`SMCR_GENL_FAMILY_NAME`, `SMCR_GENL_FAMILY_VERSION`, `SMC_GENL_FAMILY_NAME`, `SMC_GENL_FAMILY_VERSION`。Netlink 是一种 Linux 内核与用户空间进程通信的方式。
   - 定义了各种 Netlink 操作码（`SMC_NETLINK_GET_*`, `SMC_NETLINK_DUMP_*`, `SMC_NETLINK_ADD_*`, `SMC_NETLINK_REMOVE_*`, `SMC_NETLINK_ENABLE_*`, `SMC_NETLINK_DISABLE_*`），用于请求内核 SMC 子系统的不同信息或执行不同的操作，例如获取系统信息、获取逻辑组/链路信息、获取设备信息、获取统计信息、管理唯一端点 ID (UEID) 和共享端点 ID (SEID)、管理握手限制等。

3. **SMC Netlink 属性 (NLA):**
   - 定义了大量的 `SMC_NLA_*` 枚举，用于表示通过 Netlink 消息传递的各种属性。这些属性描述了 SMC 的各种状态、配置和统计信息，例如系统版本、逻辑组 ID、链路 ID、设备信息、统计数据、反馈统计、EID 表项、SEID 状态、握手限制状态等。

**与 Android 功能的关系及举例:**

SMC 是 Linux 内核中的一种网络协议优化技术，旨在通过 RDMA (Remote Direct Memory Access) 提供高性能的进程间或机器间通信。在 Android 中，如果内核启用了 SMC 支持，并且某些系统服务或应用使用了基于套接字的通信，那么底层可能会利用 SMC 来提升性能。

**举例:**

假设 Android 系统中的一个组件需要与另一个组件进行高性能的 socket 通信。如果这两个组件运行在支持 RDMA 的硬件上，并且内核的 SMC 模块已加载，那么它们之间的 socket 连接可能会自动协商并使用 SMC 作为底层传输协议。这可以显著减少 CPU 开销并提高数据传输效率。

虽然这个头文件本身不直接体现 Android Framework 或 NDK 的功能，但它定义了与内核交互的接口，这些接口可能会被底层的网络库或系统服务所使用。

**libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现**。它仅仅定义了常量和枚举，用于指导如何与内核的 SMC 子系统进行交互。实际的 libc 函数，例如用于创建套接字或发送/接收数据的函数 (`socket`, `sendto`, `recvfrom` 等)，其实现位于 Bionic libc 的其他源文件中。

当用户空间程序想要与内核的 SMC 子系统交互时，它通常会使用 `socket` 系统调用创建一个 `AF_NETLINK` 类型的套接字，并指定相应的 Netlink 家族 (如 `NETLINK_GENERIC`)。然后，程序会构造包含特定 Netlink 消息头的消息，其中会使用到这个头文件中定义的常量（如 `SMC_GENL_FAMILY_NAME` 和各种 `SMC_NETLINK_*` 操作码和 `SMC_NLA_*` 属性）。这些消息通过 `sendto` 系统调用发送到内核。内核的 SMC 模块会处理这些消息，并可能通过 Netlink 返回响应。

**dynamic linker 的功能及 SO 布局样本和链接处理过程:**

这个头文件本身与 dynamic linker 没有直接关系。Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 的主要职责是加载共享库 (SO 文件) 到进程的内存空间，并解析和绑定符号引用。

如果有一个使用了 `smc.h` 中定义的常量的用户空间程序或共享库，那么在编译和链接该程序/库时，编译器会使用这些定义。但在运行时，dynamic linker 不会直接处理这个头文件。

**SO 布局样本 (假设有一个使用了 SMC 接口的共享库 `libsmc_user.so`):**

```
libsmc_user.so:
  .text      # 代码段
    # ... 使用了 smc.h 中定义的常量的代码 ...
  .rodata    # 只读数据段
    # ... 可能包含一些字符串常量 ...
  .data      # 可读写数据段
    # ... 全局变量等 ...
  .bss       # 未初始化数据段
  .dynsym    # 动态符号表
    # ... 可能包含与 Netlink 相关的函数符号 ...
  .dynstr    # 动态字符串表
  .rel.dyn   # 动态重定位表 (用于数据)
  .rel.plt   # 动态重定位表 (用于过程链接表)
```

**链接的处理过程:**

1. **编译时:** 当编译 `libsmc_user.c` (假设) 时，编译器会读取 `smc.h`，并将其中定义的常量嵌入到生成的 `.o` 文件中。
2. **链接时:** 当链接器创建 `libsmc_user.so` 时，它会将各个 `.o` 文件合并，并处理符号引用。如果 `libsmc_user.so` 需要调用其他共享库（例如，处理 Netlink 通信的库），链接器会记录这些依赖关系和需要解析的外部符号。
3. **运行时:** 当 Android 系统加载一个使用了 `libsmc_user.so` 的进程时，dynamic linker 会：
   - 加载 `libsmc_user.so` 到内存中的某个地址。
   - 解析 `libsmc_user.so` 的依赖关系，并加载所需的其他共享库。
   - 遍历 `libsmc_user.so` 的重定位表 (`.rel.dyn` 和 `.rel.plt`)，根据加载地址更新代码和数据中的地址引用，确保函数调用和数据访问指向正确的内存位置。

**逻辑推理、假设输入与输出:**

由于 `smc.h` 主要是定义常量，而不是实现逻辑，直接进行逻辑推理的场景不多。但是，我们可以假设一个用户空间程序想要获取系统 SMC 信息。

**假设输入:**

1. 用户程序创建一个 `AF_NETLINK` 类型的套接字。
2. 用户程序构造一个 Netlink 消息，设置 `nlh->nlmsg_type = SMC_GENL_FAMILY_ID` (假设已通过 `genl_ctrl_resolve` 获取到 SMC generic netlink 家族 ID)。
3. 用户程序设置 `gnlh->cmd = SMC_NETLINK_GET_SYS_INFO`。
4. 用户程序通过 `sendto` 发送该消息到内核。

**假设输出:**

内核的 SMC 模块收到请求后，会构造一个 Netlink 响应消息，其中包含以下可能的 Netlink 属性 (基于 `smc.h` 中的定义)：

- `SMC_NLA_SYS_VER`: SMC 内核模块的版本。
- `SMC_NLA_SYS_REL`: SMC 内核模块的发布版本。
- `SMC_NLA_SYS_IS_ISM_V2`: 指示是否支持 ISM v2 的标志。
- `SMC_NLA_SYS_LOCAL_HOST`: 本地主机名。
- `SMC_NLA_SYS_SEID`: 系统范围的 SEID。
- `SMC_NLA_SYS_IS_SMCR_V2`: 指示是否支持 SMCR v2 的标志。

用户程序收到响应后，需要解析 Netlink 消息，提取这些属性的值。

**用户或编程常见的使用错误:**

1. **使用错误的 Netlink 家族 ID 或操作码:**  如果程序使用了错误的 `SMC_GENL_FAMILY_NAME` 或 `SMC_NETLINK_*` 常量，内核可能无法识别请求，或者返回错误。
2. **构造错误的 Netlink 消息结构:**  Netlink 消息的构造需要遵循特定的格式，包括消息头、Generic Netlink 头和属性。如果消息结构不正确，内核可能无法正确解析。
3. **忘记处理 Netlink 消息的长度:**  Netlink 消息的长度信息很重要，用于确定消息的边界和正确解析属性。
4. **错误地解释 Netlink 属性:**  理解每个 `SMC_NLA_*` 属性的含义和数据类型至关重要。错误的解释会导致程序行为异常。
5. **权限问题:** 与内核交互可能需要特定的权限。如果用户程序没有足够的权限发送 Netlink 消息或执行特定的 SMC 操作，会遇到权限错误。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

1. **Android 应用程序发起网络请求或使用需要高性能通信的组件。** 比如，一个使用 Socket 进行网络通信的应用。
2. **Android Framework 的网络层处理请求。**  Java 层面的 `java.net.Socket` 或 `java.nio` 包下的类最终会调用到 Native 层的实现。
3. **NDK 可能直接使用 Socket API。**  Native 代码可以使用 `socket()`, `connect()`, `send()`, `recv()` 等 POSIX 标准的 Socket API。
4. **Bionic libc 提供 Socket API 的实现。** 这些 API 的实现位于 Bionic libc 中，最终会通过系统调用与内核交互。
5. **内核的 Socket 实现可能会使用 SMC。** 如果内核配置了 SMC 支持，并且连接的双方满足 SMC 的条件（例如，在支持 RDMA 的硬件上），内核可能会协商使用 SMC 作为底层的传输协议。
6. **用户空间程序通过 Netlink 与 SMC 子系统交互 (不常见于普通应用的网络请求，更多用于系统服务或特定的性能监控工具)。**  如果需要直接管理或监控 SMC，用户空间程序会使用 `AF_NETLINK` 套接字，并构造包含 `smc.h` 中定义的常量的 Netlink 消息。

**Frida Hook 示例:**

假设我们想查看是否有进程尝试获取 SMC 系统信息，我们可以 hook `sendto` 系统调用，并过滤 `AF_NETLINK` 类型的套接字，然后检查发送的消息内容是否包含与 SMC 相关的 Netlink 命令。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['pid'], message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(['/system/bin/app_process64'], stdio='inherit')
    if not pid:
        device.resume(session.pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
            onEnter: function(args) {
                var sockfd = args[0].toInt32();
                var buf = ptr(args[1]);
                var len = args[2].toInt32();
                var dest_addr = ptr(args[3]);

                var sa_family = dest_addr.readU16();
                if (sa_family === 16) { // AF_NETLINK
                    var nlmsg_type = buf.readU16();
                    if (nlmsg_type >= 0x10 && nlmsg_type <= 0x1F) { // 假设 SMC Generic Netlink 的范围
                        console.log("Detected sendto to AF_NETLINK socket:", sockfd);
                        console.log("Message Type:", nlmsg_type);
                        // 可以进一步解析 Netlink 消息头和属性
                    }
                }
            },
            onLeave: function(retval) {
                // console.log("sendto returned:", retval);
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    print("[*] Running, press Ctrl+C to stop")
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print("Process not found")
except KeyboardInterrupt:
    print("Stopping script")

```

**Frida Hook 说明:**

1. **连接到设备或进程:** 使用 `frida.get_usb_device()` 获取 USB 设备，并根据提供的 PID 或 spawn 新进程来 attach 到目标进程。
2. **创建 Frida Script:** 使用 JavaScript 代码创建一个 Frida Script。
3. **Hook `sendto`:** 使用 `Interceptor.attach` hook `libc.so` 中的 `sendto` 函数。
4. **检查 `sa_family`:** 在 `onEnter` 中，读取 `dest_addr` 参数的前两个字节，判断是否为 `AF_NETLINK` (值为 16)。
5. **检查 `nlmsg_type`:** 如果是 `AF_NETLINK`，读取发送缓冲区 `buf` 的前两个字节，这通常是 Netlink 消息头的 `nlmsg_type` 字段。这里假设 SMC Generic Netlink 消息类型的范围，你需要根据实际情况调整。
6. **打印信息:** 打印检测到的 `AF_NETLINK` 套接字和消息类型。你可以进一步解析 Netlink 消息来查看具体的操作码和属性。
7. **加载和运行 Script:** 使用 `script.load()` 加载脚本，并进入运行状态。

通过这个 Frida Hook，你可以观察到哪些进程正在使用 Netlink 与内核通信，并初步判断是否涉及到 SMC 子系统。要更精确地分析 SMC 相关的 Netlink 消息，你需要深入了解 Netlink 消息的结构和 SMC 的 Netlink 协议。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/smc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_SMC_H_
#define _UAPI_LINUX_SMC_H_
enum {
  SMC_PNETID_UNSPEC,
  SMC_PNETID_NAME,
  SMC_PNETID_ETHNAME,
  SMC_PNETID_IBNAME,
  SMC_PNETID_IBPORT,
  __SMC_PNETID_MAX,
  SMC_PNETID_MAX = __SMC_PNETID_MAX - 1
};
enum {
  SMC_PNETID_GET = 1,
  SMC_PNETID_ADD,
  SMC_PNETID_DEL,
  SMC_PNETID_FLUSH
};
#define SMCR_GENL_FAMILY_NAME "SMC_PNETID"
#define SMCR_GENL_FAMILY_VERSION 1
#define SMC_GENL_FAMILY_NAME "SMC_GEN_NETLINK"
#define SMC_GENL_FAMILY_VERSION 1
#define SMC_PCI_ID_STR_LEN 16
#define SMC_MAX_HOSTNAME_LEN 32
#define SMC_MAX_UEID 4
#define SMC_MAX_EID_LEN 32
enum {
  SMC_NETLINK_GET_SYS_INFO = 1,
  SMC_NETLINK_GET_LGR_SMCR,
  SMC_NETLINK_GET_LINK_SMCR,
  SMC_NETLINK_GET_LGR_SMCD,
  SMC_NETLINK_GET_DEV_SMCD,
  SMC_NETLINK_GET_DEV_SMCR,
  SMC_NETLINK_GET_STATS,
  SMC_NETLINK_GET_FBACK_STATS,
  SMC_NETLINK_DUMP_UEID,
  SMC_NETLINK_ADD_UEID,
  SMC_NETLINK_REMOVE_UEID,
  SMC_NETLINK_FLUSH_UEID,
  SMC_NETLINK_DUMP_SEID,
  SMC_NETLINK_ENABLE_SEID,
  SMC_NETLINK_DISABLE_SEID,
  SMC_NETLINK_DUMP_HS_LIMITATION,
  SMC_NETLINK_ENABLE_HS_LIMITATION,
  SMC_NETLINK_DISABLE_HS_LIMITATION,
};
enum {
  SMC_GEN_UNSPEC,
  SMC_GEN_SYS_INFO,
  SMC_GEN_LGR_SMCR,
  SMC_GEN_LINK_SMCR,
  SMC_GEN_LGR_SMCD,
  SMC_GEN_DEV_SMCD,
  SMC_GEN_DEV_SMCR,
  SMC_GEN_STATS,
  SMC_GEN_FBACK_STATS,
  __SMC_GEN_MAX,
  SMC_GEN_MAX = __SMC_GEN_MAX - 1
};
enum {
  SMC_NLA_SYS_UNSPEC,
  SMC_NLA_SYS_VER,
  SMC_NLA_SYS_REL,
  SMC_NLA_SYS_IS_ISM_V2,
  SMC_NLA_SYS_LOCAL_HOST,
  SMC_NLA_SYS_SEID,
  SMC_NLA_SYS_IS_SMCR_V2,
  __SMC_NLA_SYS_MAX,
  SMC_NLA_SYS_MAX = __SMC_NLA_SYS_MAX - 1
};
enum {
  SMC_NLA_LGR_V2_VER,
  SMC_NLA_LGR_V2_REL,
  SMC_NLA_LGR_V2_OS,
  SMC_NLA_LGR_V2_NEG_EID,
  SMC_NLA_LGR_V2_PEER_HOST,
  __SMC_NLA_LGR_V2_MAX,
  SMC_NLA_LGR_V2_MAX = __SMC_NLA_LGR_V2_MAX - 1
};
enum {
  SMC_NLA_LGR_R_V2_UNSPEC,
  SMC_NLA_LGR_R_V2_DIRECT,
  SMC_NLA_LGR_R_V2_MAX_CONNS,
  SMC_NLA_LGR_R_V2_MAX_LINKS,
  __SMC_NLA_LGR_R_V2_MAX,
  SMC_NLA_LGR_R_V2_MAX = __SMC_NLA_LGR_R_V2_MAX - 1
};
enum {
  SMC_NLA_LGR_R_UNSPEC,
  SMC_NLA_LGR_R_ID,
  SMC_NLA_LGR_R_ROLE,
  SMC_NLA_LGR_R_TYPE,
  SMC_NLA_LGR_R_PNETID,
  SMC_NLA_LGR_R_VLAN_ID,
  SMC_NLA_LGR_R_CONNS_NUM,
  SMC_NLA_LGR_R_V2_COMMON,
  SMC_NLA_LGR_R_V2,
  SMC_NLA_LGR_R_NET_COOKIE,
  SMC_NLA_LGR_R_PAD,
  SMC_NLA_LGR_R_BUF_TYPE,
  SMC_NLA_LGR_R_SNDBUF_ALLOC,
  SMC_NLA_LGR_R_RMB_ALLOC,
  __SMC_NLA_LGR_R_MAX,
  SMC_NLA_LGR_R_MAX = __SMC_NLA_LGR_R_MAX - 1
};
enum {
  SMC_NLA_LINK_UNSPEC,
  SMC_NLA_LINK_ID,
  SMC_NLA_LINK_IB_DEV,
  SMC_NLA_LINK_IB_PORT,
  SMC_NLA_LINK_GID,
  SMC_NLA_LINK_PEER_GID,
  SMC_NLA_LINK_CONN_CNT,
  SMC_NLA_LINK_NET_DEV,
  SMC_NLA_LINK_UID,
  SMC_NLA_LINK_PEER_UID,
  SMC_NLA_LINK_STATE,
  __SMC_NLA_LINK_MAX,
  SMC_NLA_LINK_MAX = __SMC_NLA_LINK_MAX - 1
};
enum {
  SMC_NLA_LGR_D_UNSPEC,
  SMC_NLA_LGR_D_ID,
  SMC_NLA_LGR_D_GID,
  SMC_NLA_LGR_D_PEER_GID,
  SMC_NLA_LGR_D_VLAN_ID,
  SMC_NLA_LGR_D_CONNS_NUM,
  SMC_NLA_LGR_D_PNETID,
  SMC_NLA_LGR_D_CHID,
  SMC_NLA_LGR_D_PAD,
  SMC_NLA_LGR_D_V2_COMMON,
  SMC_NLA_LGR_D_EXT_GID,
  SMC_NLA_LGR_D_PEER_EXT_GID,
  SMC_NLA_LGR_D_SNDBUF_ALLOC,
  SMC_NLA_LGR_D_DMB_ALLOC,
  __SMC_NLA_LGR_D_MAX,
  SMC_NLA_LGR_D_MAX = __SMC_NLA_LGR_D_MAX - 1
};
enum {
  SMC_NLA_DEV_PORT_UNSPEC,
  SMC_NLA_DEV_PORT_PNET_USR,
  SMC_NLA_DEV_PORT_PNETID,
  SMC_NLA_DEV_PORT_NETDEV,
  SMC_NLA_DEV_PORT_STATE,
  SMC_NLA_DEV_PORT_VALID,
  SMC_NLA_DEV_PORT_LNK_CNT,
  __SMC_NLA_DEV_PORT_MAX,
  SMC_NLA_DEV_PORT_MAX = __SMC_NLA_DEV_PORT_MAX - 1
};
enum {
  SMC_NLA_DEV_UNSPEC,
  SMC_NLA_DEV_USE_CNT,
  SMC_NLA_DEV_IS_CRIT,
  SMC_NLA_DEV_PCI_FID,
  SMC_NLA_DEV_PCI_CHID,
  SMC_NLA_DEV_PCI_VENDOR,
  SMC_NLA_DEV_PCI_DEVICE,
  SMC_NLA_DEV_PCI_ID,
  SMC_NLA_DEV_PORT,
  SMC_NLA_DEV_PORT2,
  SMC_NLA_DEV_IB_NAME,
  __SMC_NLA_DEV_MAX,
  SMC_NLA_DEV_MAX = __SMC_NLA_DEV_MAX - 1
};
enum {
  SMC_NLA_STATS_PLOAD_PAD,
  SMC_NLA_STATS_PLOAD_8K,
  SMC_NLA_STATS_PLOAD_16K,
  SMC_NLA_STATS_PLOAD_32K,
  SMC_NLA_STATS_PLOAD_64K,
  SMC_NLA_STATS_PLOAD_128K,
  SMC_NLA_STATS_PLOAD_256K,
  SMC_NLA_STATS_PLOAD_512K,
  SMC_NLA_STATS_PLOAD_1024K,
  SMC_NLA_STATS_PLOAD_G_1024K,
  __SMC_NLA_STATS_PLOAD_MAX,
  SMC_NLA_STATS_PLOAD_MAX = __SMC_NLA_STATS_PLOAD_MAX - 1
};
enum {
  SMC_NLA_STATS_RMB_PAD,
  SMC_NLA_STATS_RMB_SIZE_SM_PEER_CNT,
  SMC_NLA_STATS_RMB_SIZE_SM_CNT,
  SMC_NLA_STATS_RMB_FULL_PEER_CNT,
  SMC_NLA_STATS_RMB_FULL_CNT,
  SMC_NLA_STATS_RMB_REUSE_CNT,
  SMC_NLA_STATS_RMB_ALLOC_CNT,
  SMC_NLA_STATS_RMB_DGRADE_CNT,
  __SMC_NLA_STATS_RMB_MAX,
  SMC_NLA_STATS_RMB_MAX = __SMC_NLA_STATS_RMB_MAX - 1
};
enum {
  SMC_NLA_STATS_T_PAD,
  SMC_NLA_STATS_T_TX_RMB_SIZE,
  SMC_NLA_STATS_T_RX_RMB_SIZE,
  SMC_NLA_STATS_T_TXPLOAD_SIZE,
  SMC_NLA_STATS_T_RXPLOAD_SIZE,
  SMC_NLA_STATS_T_TX_RMB_STATS,
  SMC_NLA_STATS_T_RX_RMB_STATS,
  SMC_NLA_STATS_T_CLNT_V1_SUCC,
  SMC_NLA_STATS_T_CLNT_V2_SUCC,
  SMC_NLA_STATS_T_SRV_V1_SUCC,
  SMC_NLA_STATS_T_SRV_V2_SUCC,
  SMC_NLA_STATS_T_SENDPAGE_CNT,
  SMC_NLA_STATS_T_SPLICE_CNT,
  SMC_NLA_STATS_T_CORK_CNT,
  SMC_NLA_STATS_T_NDLY_CNT,
  SMC_NLA_STATS_T_URG_DATA_CNT,
  SMC_NLA_STATS_T_RX_BYTES,
  SMC_NLA_STATS_T_TX_BYTES,
  SMC_NLA_STATS_T_RX_CNT,
  SMC_NLA_STATS_T_TX_CNT,
  SMC_NLA_STATS_T_RX_RMB_USAGE,
  SMC_NLA_STATS_T_TX_RMB_USAGE,
  __SMC_NLA_STATS_T_MAX,
  SMC_NLA_STATS_T_MAX = __SMC_NLA_STATS_T_MAX - 1
};
enum {
  SMC_NLA_STATS_PAD,
  SMC_NLA_STATS_SMCD_TECH,
  SMC_NLA_STATS_SMCR_TECH,
  SMC_NLA_STATS_CLNT_HS_ERR_CNT,
  SMC_NLA_STATS_SRV_HS_ERR_CNT,
  __SMC_NLA_STATS_MAX,
  SMC_NLA_STATS_MAX = __SMC_NLA_STATS_MAX - 1
};
enum {
  SMC_NLA_FBACK_STATS_PAD,
  SMC_NLA_FBACK_STATS_TYPE,
  SMC_NLA_FBACK_STATS_SRV_CNT,
  SMC_NLA_FBACK_STATS_CLNT_CNT,
  SMC_NLA_FBACK_STATS_RSN_CODE,
  SMC_NLA_FBACK_STATS_RSN_CNT,
  __SMC_NLA_FBACK_STATS_MAX,
  SMC_NLA_FBACK_STATS_MAX = __SMC_NLA_FBACK_STATS_MAX - 1
};
enum {
  SMC_NLA_EID_TABLE_UNSPEC,
  SMC_NLA_EID_TABLE_ENTRY,
  __SMC_NLA_EID_TABLE_MAX,
  SMC_NLA_EID_TABLE_MAX = __SMC_NLA_EID_TABLE_MAX - 1
};
enum {
  SMC_NLA_SEID_UNSPEC,
  SMC_NLA_SEID_ENTRY,
  SMC_NLA_SEID_ENABLED,
  __SMC_NLA_SEID_TABLE_MAX,
  SMC_NLA_SEID_TABLE_MAX = __SMC_NLA_SEID_TABLE_MAX - 1
};
enum {
  SMC_NLA_HS_LIMITATION_UNSPEC,
  SMC_NLA_HS_LIMITATION_ENABLED,
  __SMC_NLA_HS_LIMITATION_MAX,
  SMC_NLA_HS_LIMITATION_MAX = __SMC_NLA_HS_LIMITATION_MAX - 1
};
#define SMC_LIMIT_HS 1
#endif
```