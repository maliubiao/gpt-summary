Response:
Let's break down the thought process for analyzing the `tipc_config.h` header file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C header file, focusing on:

* **Functionality:** What does this file do? What are its main components?
* **Android Relevance:** How does it relate to the Android OS? Provide concrete examples.
* **libc Function Details:** Explain the purpose and implementation of included libc functions.
* **Dynamic Linker Involvement:**  If applicable, show SO layout and linking process.
* **Logical Reasoning:**  Include example inputs and outputs for any logical components.
* **Common Errors:**  Point out typical user/programmer mistakes.
* **Android Framework/NDK Path:** Trace how this file is reached from higher levels.
* **Frida Hooking:** Provide examples for debugging.

**2. Initial Scan and Keyword Identification:**

The first step is to read through the header file and identify key terms and patterns. Keywords that immediately jump out are:

* `TIPC`:  This is the core subject. A quick search confirms it stands for "Transparent Inter-Process Communication".
* `CONFIG`: The file's name suggests it's related to configuration.
* `CMD_`:  A large number of `#define` directives starting with this prefix indicates commands.
* `TLV_`:  Another set of `#define` directives, suggesting "Tag-Length-Value" encoding.
* `struct`:  Definitions of data structures.
* `GENL`:  Likely relates to Generic Netlink, a Linux kernel mechanism.
* `NLMSG_ALIGN`:  Further confirms the Netlink association.
* `__be32`, `__u16`, etc.: Indicate data types, possibly with endianness specifications.
* `#include <linux/...>`:  Signals this is kernel-level code.

**3. High-Level Functionality Deduction:**

Based on the keywords, I can deduce the primary function of this header file:

* **Defines constants and data structures for configuring and controlling the TIPC protocol within the Linux kernel.**  This is a foundational element for interacting with the TIPC subsystem.

**4. Deeper Dive into Sections:**

Now, I'll examine each section of the header file in more detail:

* **Command Definitions (`TIPC_CMD_*`):** These clearly represent different actions that can be performed on the TIPC subsystem. They can be grouped into categories like getting information (nodes, media, links, stats), setting parameters (link tolerance, priority, window, log size), and enabling/disabling bearers.
* **TLV Definitions (`TIPC_TLV_*`):**  These define the types of data that can be exchanged when configuring TIPC. The "Tag-Length-Value" structure is a common way to serialize structured data.
* **Link Properties (`TIPC_MIN_LINK_PRI`, etc.):**  These define constraints and defaults for link parameters.
* **Data Structures (`tipc_node_info`, `tipc_link_info`, etc.):** These structures represent the data being exchanged, such as information about nodes, links, and bearer configurations.
* **Error Codes (`TIPC_CFG_*`):**  These indicate potential problems during TIPC configuration.
* **TLV Helper Macros (`TLV_ALIGNTO`, `TLV_LENGTH`, etc.):** These simplify the process of working with TLV encoded data.
* **Generic Netlink Definitions (`TIPC_GENL_NAME`, `tipc_genlmsghdr`, etc.):** This confirms that TIPC configuration utilizes the Generic Netlink mechanism for communication between user-space and the kernel.
* **Configuration Message Header (`tipc_cfg_msg_hdr`):** Defines the structure of messages used to configure TIPC.
* **Configuration Message Macros (`TCM_F_REQUEST`, `TCM_LENGTH`, etc.):**  Similar to the TLV macros, these aid in working with configuration messages.

**5. Addressing Specific Request Points:**

* **Android Relevance:** TIPC is used for inter-process communication, which is crucial in Android's process-based architecture. Examples could include communication between system services or even application processes (though less common directly). It's a lower-level transport mechanism.
* **libc Functions:** The file includes `<linux/types.h>` and `<linux/string.h>`. While these are Linux kernel headers, they often have corresponding functions in Android's libc (Bionic). I'll explain the common ones like `memcpy`, `memset`, data type definitions.
* **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. It defines kernel structures and constants. The dynamic linker comes into play when user-space applications or libraries interact with the kernel through system calls related to TIPC. I'll need to illustrate how a user-space SO might use these definitions.
* **Logical Reasoning:**  I can provide examples of how the command codes and data structures might be used. For instance, sending a `TIPC_CMD_GET_NODES` and receiving a list of `tipc_node_info` structures.
* **Common Errors:**  Incorrectly setting parameters, using invalid command codes, or not having sufficient privileges are typical mistakes.
* **Android Framework/NDK Path:** I'll need to trace the path from an Android application or service down to the kernel level, highlighting where these TIPC definitions become relevant. System calls like `socket()` with the `AF_TIPC` family are the key entry point.
* **Frida Hooking:** I'll demonstrate how to use Frida to intercept calls related to TIPC, potentially hooking the `socket()` system call or functions that interact with TIPC configuration.

**6. Structuring the Output:**

Finally, I'll organize the information logically, starting with a general overview and then delving into the specifics for each request point. Using headings and code blocks will improve readability. I need to ensure I address *all* the points in the prompt.

**Self-Correction/Refinement:**

* **Initial thought:**  Focus too much on the specific values of the `#define`s.
* **Correction:**  Shift focus to the *purpose* of these definitions and how they are used in the context of TIPC.
* **Initial thought:**  Overcomplicate the dynamic linker section.
* **Correction:** Keep it concise and focus on the interaction point: user-space code using these definitions when making TIPC-related system calls. Illustrate with a simple SO example.
* **Initial thought:**  Provide overly technical explanations of kernel internals.
* **Correction:** Tailor the explanation to be understandable to a developer familiar with Android and system programming concepts.

By following this thought process, I can generate a comprehensive and accurate analysis that addresses all the requirements of the request.
这是一个定义 Linux 内核中 TIPC (Transparent Inter-Process Communication) 配置接口的头文件。它主要定义了用于配置和管理 TIPC 协议的常量、数据结构和宏。因为其位于 `bionic/libc/kernel/uapi/linux/` 路径下，所以它是 Android Bionic 库中用于与 Linux 内核交互的一部分。

**它的功能:**

1. **定义 TIPC 配置命令 (`TIPC_CMD_*`)**:  这些常量代表了可以发送给 TIPC 内核模块进行配置或查询的操作。例如：
    * `TIPC_CMD_GET_NODES`: 获取 TIPC 集群中的节点信息。
    * `TIPC_CMD_ENABLE_BEARER`: 启用指定的 TIPC 承载 (bearer)。
    * `TIPC_CMD_SET_LINK_TOL`: 设置 TIPC 链路的容忍度。

2. **定义 TLV (Tag-Length-Value) 类型 (`TIPC_TLV_*`)**:  这些常量定义了在配置消息中用于编码不同类型数据的标签。TLV 是一种常见的数据序列化方式，用于灵活地传输结构化信息。例如：
    * `TIPC_TLV_STRING`: 表示一个字符串类型的值。
    * `TIPC_TLV_NET_ADDR`: 表示一个网络地址。

3. **定义 TIPC 链路属性的常量 (`TIPC_MIN_LINK_PRI`, `TIPC_DEF_LINK_TOL`, 等)`**: 这些常量定义了 TIPC 链路的最小/默认/最大优先级、容忍度、窗口大小等参数。

4. **定义用于表示 TIPC 信息的结构体 (`tipc_node_info`, `tipc_link_info`, 等)`**: 这些结构体用于存储从内核获取或发送给内核的 TIPC 配置信息。例如：
    * `tipc_node_info`:  包含 TIPC 节点的地址和状态。
    * `tipc_bearer_config`:  包含 TIPC 承载的优先级、发现域和名称。

5. **定义 TIPC 配置错误代码 (`TIPC_CFG_*`)**:  这些常量定义了 TIPC 配置操作可能返回的错误码。例如：
    * `TIPC_CFG_NOT_NET_ADMIN`: 表示操作需要网络管理员权限。

6. **定义用于处理 TLV 数据的宏 (`TLV_ALIGNTO`, `TLV_LENGTH`, 等)`**:  这些宏简化了 TLV 数据的打包和解包过程，包括对齐和长度计算。

7. **定义用于 Generic Netlink 通信的常量和结构体 (`TIPC_GENL_NAME`, `tipc_genlmsghdr`, 等)`**: TIPC 配置通常使用 Generic Netlink 机制与内核进行通信。这些定义指定了 Netlink 协议族名、版本和消息头格式。

8. **定义 TIPC 配置消息头结构体 (`tipc_cfg_msg_hdr`) 和相关宏 (`TCM_F_REQUEST`, `TCM_LENGTH`, 等)`**: 这些定义了用于封装 TIPC 配置命令和数据的消息头格式。

**与 Android 功能的关系及举例说明:**

TIPC 在 Android 中主要用于 **系统服务之间的进程间通信 (IPC)**。虽然它不如 Binder 那么普遍，但在某些特定的低层通信场景中可能会使用。

**举例说明:**

假设 Android 系统中有一个网络管理服务需要获取当前 TIPC 集群中的节点信息。

1. **Android Framework/Native Service:**  一个用 Java 或 C++ 编写的 Android 系统服务（例如，一个负责网络配置的服务）可能需要获取 TIPC 节点信息。

2. **NDK (Native Development Kit):** 该服务可能会使用 NDK 调用底层的 C/C++ 代码。

3. **System Call:**  底层的 C/C++ 代码会使用 `socket()` 系统调用创建一个 `AF_NETLINK` 类型的套接字，并指定 `NETLINK_GENERIC` 协议族，然后使用 `genlmsg_put()` 等函数构造一个包含 `TIPC_GENL_NAME` 协议族和 `TIPC_GENL_CMD` 命令（对应于需要执行的 TIPC 配置操作，例如获取节点信息）的 Netlink 消息。这个消息的负载会包含具体的 TIPC 配置命令，例如 `TIPC_CMD_GET_NODES`。

4. **Bionic Libc:**  Bionic libc 提供了 `socket()` 等系统调用的封装。当调用 `socket()` 时，Bionic libc 会将调用转发到 Linux 内核。

5. **Kernel TIPC Module:**  内核中的 TIPC 模块接收到 Netlink 消息后，会解析其中的 TIPC 命令 (`TIPC_CMD_GET_NODES`)。

6. **`tipc_config.h` 的作用:** 内核中的 TIPC 模块会使用 `tipc_config.h` 中定义的常量 (`TIPC_CMD_GET_NODES`) 来识别需要执行的操作。它还会使用头文件中定义的结构体 (`tipc_node_info`) 来组织返回的节点信息。

7. **返回结果:**  内核 TIPC 模块会将节点信息封装成 Netlink 消息返回给用户空间的服务。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了常量和数据结构。它引用的 `<linux/types.h>` 和 `<linux/string.h>` 是 Linux 内核的头文件，而不是 Bionic libc 的一部分。然而，Bionic libc 提供了与这些内核头文件中定义的类型和函数相对应的实现。

* **`<linux/types.h>`:**  定义了内核中使用的基本数据类型，例如 `__u32` (unsigned 32-bit integer)、`__be32` (big-endian 32-bit integer) 等。Bionic libc 也会定义类似的类型，确保用户空间程序可以正确地与内核数据结构交互。实现上，这些类型定义通常会映射到 C 标准类型，并可能包含针对特定架构的字节序处理。

* **`<linux/string.h>`:** 定义了字符串操作相关的函数，例如 `memcpy`、`memset` 等。Bionic libc 提供了这些函数的实现，这些实现通常经过优化，以提高性能和安全性。
    * **`memcpy(void *dest, const void *src, size_t n)`:** 将 `src` 指向的内存块的 `n` 个字节复制到 `dest` 指向的内存块。实现上，它会逐字节或按字（word）复制数据，并可能使用一些优化技巧，例如使用 SIMD 指令。
    * **`memset(void *s, int c, size_t n)`:** 将 `s` 指向的内存块的前 `n` 个字节设置为值 `c`。实现上，它会填充内存，通常会按字（word）进行填充以提高效率。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及动态链接器。动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 的主要任务是加载共享库 (`.so` 文件) 并解析符号引用。

然而，当一个用户空间的库或可执行文件需要与 TIPC 内核模块交互时，它可能会链接到提供 Netlink 通信功能的共享库（例如，`libnl`，虽然 Android 系统本身可能不会直接使用 `libnl`，而是使用其内部的网络通信机制）。

**SO 布局样本 (假设一个使用了 Netlink 与 TIPC 交互的库 `libtipc_client.so`):**

```
libtipc_client.so:
    .text         # 代码段
        - 函数1
        - 函数2 (可能包含构造 Netlink 消息并发送到内核的代码)
    .rodata       # 只读数据段
        - 字符串常量
    .data         # 可读写数据段
        - 全局变量
    .bss          # 未初始化数据段
    .dynamic      # 动态链接信息
        - NEEDED libnetutils.so  # 假设依赖了 libnetutils.so
        - ...
    .symtab       # 符号表
        - (导出的符号，例如函数1)
        - (导入的符号，例如来自 libnetutils.so 的函数)
    .strtab       # 字符串表
    ...
```

**链接的处理过程:**

1. **编译时链接:**  当 `libtipc_client.so` 被编译时，编译器会记录它依赖的其他共享库（例如 `libnetutils.so`）以及它使用的外部符号。

2. **加载时链接:** 当一个应用程序或服务加载 `libtipc_client.so` 时，动态链接器会执行以下操作：
    * **加载依赖库:**  动态链接器会先加载 `libtipc_client.so` 依赖的共享库 (`libnetutils.so`) 到内存中。
    * **符号解析:** 动态链接器会遍历 `libtipc_client.so` 的符号表，找到所有未定义的符号（即外部符号引用），并在已加载的共享库中查找这些符号的定义。
    * **重定位:** 动态链接器会修改 `libtipc_client.so` 代码段和数据段中的地址，将对外部符号的引用指向其在内存中的实际地址。这包括函数地址、全局变量地址等。

**对于 `tipc_config.h` 来说，它主要影响编译过程:**  编译器会使用这个头文件中定义的常量和结构体来正确地生成与 TIPC 交互的代码。链接器并不会直接处理这个头文件，但它会处理链接到使用这些定义的代码的共享库。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们编写了一个程序，想要获取 TIPC 节点数量的最大值。

**假设输入:**

* 程序构造一个 Netlink 消息，其中包含：
    * `TIPC_GENL_NAME`: "TIPC"
    * `TIPC_GENL_CMD`: 0x1 (对应于配置操作)
    * 配置消息头 (`tipc_cfg_msg_hdr`)，其中 `tcm_type` 指示这是一个请求，并包含 `TIPC_CMD_GET_MAX_NODES` 命令。

**预期输出:**

* 内核 TIPC 模块处理该请求后，会返回一个 Netlink 消息，其中包含：
    * 配置消息头 (`tipc_cfg_msg_hdr`)，指示这是一个响应。
    * TLV 编码的数据，其中包含：
        * `tlv_type`:  指示这是一个无符号整数 (`TIPC_TLV_UNSIGNED`)。
        * `tlv_len`:  指示数据长度（例如，4 字节）。
        * 数据:  一个 32 位的无符号整数，表示 TIPC 节点数量的最大值。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限不足:** 某些 TIPC 配置操作（例如，设置节点地址、启用/禁用承载）需要 root 权限或特定的网络管理权限。用户空间的应用程序如果尝试执行这些操作而没有足够的权限，将会收到 `TIPC_CFG_NOT_NET_ADMIN` 错误。

   ```c
   // 尝试设置节点地址 (需要 root 权限)
   // ... 构造包含 TIPC_CMD_SET_NODE_ADDR 的 Netlink 消息 ...
   if (send(sockfd, ...) < 0) {
       perror("send failed");
   }
   // ... 接收内核的响应 ...
   if (响应中包含 TIPC_CFG_NOT_NET_ADMIN) {
       fprintf(stderr, "权限不足，无法设置 TIPC 节点地址。\n");
   }
   ```

2. **使用错误的命令代码:**  如果程序使用了不存在或不适用的 `TIPC_CMD_*` 值，内核可能会返回一个错误，或者忽略该命令。

3. **构造错误的 TLV 数据:**  TIPC 配置消息通常使用 TLV 编码。如果程序构造的 TLV 数据的长度、类型或值不正确，内核可能无法解析该消息，并可能返回错误 (`TIPC_CFG_INVALID_VALUE`)。例如，为一个需要字符串的配置项传递了一个整数值。

4. **未正确处理字节序:**  TIPC 中使用的网络字节序（大端序）。如果用户空间的程序在构造消息时没有正确地转换字节序，可能会导致内核解析错误。例如，`__be32` 类型指示数据应以大端序存储。

   ```c
   struct tipc_node_info node_info;
   // 错误的做法（假设本地是小端序）
   node_info.addr = some_ip_address;

   // 正确的做法
   node_info.addr = htonl(some_ip_address); // 使用 htonl 转换为网络字节序
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到 `tipc_config.h` 的路径:**

1. **Android Framework (Java/Kotlin):**  Android Framework 中的某些网络管理相关的服务，例如 ConnectivityService 或 NetworkStack，可能需要获取或设置 TIPC 配置。这些服务通常用 Java 或 Kotlin 编写。

2. **Native Code (C/C++):**  Framework 服务通常会调用底层的 Native 代码来执行一些与内核交互的操作。这些 Native 代码可能位于 System Server 进程或其他特权进程中。

3. **NDK APIs (偶尔):**  理论上，开发者可以使用 NDK 直接访问 Linux 系统调用，从而与 TIPC 交互。但这在 Android 应用开发中非常罕见，因为 TIPC 主要用于系统级通信。

4. **System Calls:** Native 代码会使用诸如 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` 创建 Netlink 套接字，并使用 `sendto` 等函数向内核发送包含 TIPC 配置命令的 Netlink 消息。

5. **Bionic Libc:**  NDK 提供的 C/C++ 标准库和 Android 扩展库最终会调用 Bionic libc 提供的系统调用封装函数。例如，`socket()` 函数在 Bionic libc 中有对应的实现。

6. **Linux Kernel:**  Bionic libc 的系统调用封装最终会陷入 Linux 内核。对于 Netlink 套接字，内核的网络子系统会将消息路由到注册了 `TIPC_GENL_NAME` 的 Generic Netlink 协议族处理程序（即 TIPC 内核模块）。

7. **`tipc_config.h`:**  TIPC 内核模块的代码会包含并使用 `tipc_config.h` 中定义的常量、结构体和宏，以便正确地解析和处理用户空间发送的配置请求，并构造响应消息。

**Frida Hook 示例调试步骤:**

假设我们想观察 Android 系统中哪个进程在尝试获取 TIPC 节点信息 (`TIPC_CMD_GET_NODES`).

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received message: {message['payload']}")

def main():
    try:
        session = frida.get_usb_device().attach("system_server") # 或者其他可能相关的进程
    except frida.ProcessNotFoundError:
        print("system_server 进程未找到，请检查设备或进程名称。")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            const sockfd = args[0].toInt32();
            const buf = ptr(args[1]);
            const len = args[2].toInt32();

            // 检查是否是 Netlink 套接字 (简化判断，实际可能更复杂)
            const sock_family = Socket.getsockopt(sockfd, Socket.SOL_SOCKET, Socket.SO_DOMAIN);
            if (sock_family && sock_family.value.toInt32() === 16) { // AF_NETLINK = 16
                const nlmsghdr_size = 16; // sizeof(struct nlmsghdr)
                if (len > nlmsghdr_size) {
                    const genlhdr_offset = nlmsghdr_size;
                    const cmda_offset = genlhdr_offset + 4; // 假设 genlmsghdr 中的 cmd 字段是 u16，占 2 字节，加上族ID 2字节

                    const cmd = buf.add(cmda_offset).readU16();
                    if (cmd === 0x0001) { // TIPC_CMD_GET_NODES
                        console.log("[*] sendto called on Netlink socket with TIPC_CMD_GET_NODES");
                        console.log("    sockfd:", sockfd);
                        console.log("    length:", len);
                        // 可以进一步解析 Netlink 消息的内容
                    }
                }
            }
        },
        onLeave: function(retval) {
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Frida script loaded. Waiting for TIPC activity...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 解释:**

1. **`frida.get_usb_device().attach("system_server")`:**  连接到 USB 连接的 Android 设备上的 `system_server` 进程。你需要根据实际情况选择可能与 TIPC 交互的进程。

2. **`Interceptor.attach(Module.findExportByName(null, "sendto"), ...)`:**  Hook `sendto` 系统调用。我们选择 hook `sendto`，因为通常使用 `sendto` 在套接字上发送数据。

3. **`onEnter: function(args)`:**  在 `sendto` 函数执行前执行。`args` 包含了传递给 `sendto` 的参数。

4. **检查 Netlink 套接字:**  通过 `Socket.getsockopt` 获取套接字的域 (domain)，判断是否是 `AF_NETLINK`。这是一种简化的判断方式，实际可能需要更精确的检查。

5. **检查 TIPC 命令:**  如果检测到是 Netlink 套接字，我们读取缓冲区中的数据，尝试解析 Generic Netlink 头部和 TIPC 命令。这里假设 `TIPC_CMD_GET_NODES` 的值是 `0x0001`，并且位于 Netlink 消息的特定偏移位置。你需要根据实际的 Netlink 消息结构进行调整。

6. **打印信息:**  如果检测到 `TIPC_CMD_GET_NODES`，则打印相关信息，例如套接字描述符和数据长度。

**运行 Frida Hook:**

1. 确保你的电脑上安装了 Frida 和 Frida 工具。
2. 确保你的 Android 设备已连接并通过 adb 可访问，并且设备上运行了 frida-server。
3. 将上述 Python 代码保存为 `.py` 文件（例如 `hook_tipc.py`）。
4. 运行 `python hook_tipc.py`。

当系统上运行的进程（例如 `system_server`）尝试发送包含 `TIPC_CMD_GET_NODES` 的 Netlink 消息时，Frida 脚本将会拦截到 `sendto` 调用并打印相关信息。

通过修改 Frida 脚本，你可以 hook 不同的系统调用，例如 `recvfrom` 来查看内核返回的 TIPC 配置信息，或者 hook 与 Netlink 消息构造相关的函数。这可以帮助你理解 Android Framework 如何与底层的 TIPC 内核模块进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/tipc_config.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_TIPC_CONFIG_H_
#define _LINUX_TIPC_CONFIG_H_
#include <linux/types.h>
#include <linux/string.h>
#include <linux/tipc.h>
#include <asm/byteorder.h>
#define TIPC_CMD_NOOP 0x0000
#define TIPC_CMD_GET_NODES 0x0001
#define TIPC_CMD_GET_MEDIA_NAMES 0x0002
#define TIPC_CMD_GET_BEARER_NAMES 0x0003
#define TIPC_CMD_GET_LINKS 0x0004
#define TIPC_CMD_SHOW_NAME_TABLE 0x0005
#define TIPC_CMD_SHOW_PORTS 0x0006
#define TIPC_CMD_SHOW_LINK_STATS 0x000B
#define TIPC_CMD_SHOW_STATS 0x000F
#define TIPC_CMD_GET_REMOTE_MNG 0x4003
#define TIPC_CMD_GET_MAX_PORTS 0x4004
#define TIPC_CMD_GET_MAX_PUBL 0x4005
#define TIPC_CMD_GET_MAX_SUBSCR 0x4006
#define TIPC_CMD_GET_MAX_ZONES 0x4007
#define TIPC_CMD_GET_MAX_CLUSTERS 0x4008
#define TIPC_CMD_GET_MAX_NODES 0x4009
#define TIPC_CMD_GET_MAX_SLAVES 0x400A
#define TIPC_CMD_GET_NETID 0x400B
#define TIPC_CMD_ENABLE_BEARER 0x4101
#define TIPC_CMD_DISABLE_BEARER 0x4102
#define TIPC_CMD_SET_LINK_TOL 0x4107
#define TIPC_CMD_SET_LINK_PRI 0x4108
#define TIPC_CMD_SET_LINK_WINDOW 0x4109
#define TIPC_CMD_SET_LOG_SIZE 0x410A
#define TIPC_CMD_DUMP_LOG 0x410B
#define TIPC_CMD_RESET_LINK_STATS 0x410C
#define TIPC_CMD_SET_NODE_ADDR 0x8001
#define TIPC_CMD_SET_REMOTE_MNG 0x8003
#define TIPC_CMD_SET_MAX_PORTS 0x8004
#define TIPC_CMD_SET_MAX_PUBL 0x8005
#define TIPC_CMD_SET_MAX_SUBSCR 0x8006
#define TIPC_CMD_SET_MAX_ZONES 0x8007
#define TIPC_CMD_SET_MAX_CLUSTERS 0x8008
#define TIPC_CMD_SET_MAX_NODES 0x8009
#define TIPC_CMD_SET_MAX_SLAVES 0x800A
#define TIPC_CMD_SET_NETID 0x800B
#define TIPC_CMD_NOT_NET_ADMIN 0xC001
#define TIPC_TLV_NONE 0
#define TIPC_TLV_VOID 1
#define TIPC_TLV_UNSIGNED 2
#define TIPC_TLV_STRING 3
#define TIPC_TLV_LARGE_STRING 4
#define TIPC_TLV_ULTRA_STRING 5
#define TIPC_TLV_ERROR_STRING 16
#define TIPC_TLV_NET_ADDR 17
#define TIPC_TLV_MEDIA_NAME 18
#define TIPC_TLV_BEARER_NAME 19
#define TIPC_TLV_LINK_NAME 20
#define TIPC_TLV_NODE_INFO 21
#define TIPC_TLV_LINK_INFO 22
#define TIPC_TLV_BEARER_CONFIG 23
#define TIPC_TLV_LINK_CONFIG 24
#define TIPC_TLV_NAME_TBL_QUERY 25
#define TIPC_TLV_PORT_REF 26
#define TIPC_MIN_LINK_PRI 0
#define TIPC_DEF_LINK_PRI 10
#define TIPC_MAX_LINK_PRI 31
#define TIPC_MEDIA_LINK_PRI (TIPC_MAX_LINK_PRI + 1)
#define TIPC_MIN_LINK_TOL 50
#define TIPC_DEF_LINK_TOL 1500
#define TIPC_MAX_LINK_TOL 30000
#if TIPC_MIN_LINK_TOL < 16
#error "TIPC_MIN_LINK_TOL is too small (abort limit may be NaN)"
#endif
#define TIPC_MIN_LINK_WIN 16
#define TIPC_DEF_LINK_WIN 50
#define TIPC_MAX_LINK_WIN 8191
#define TIPC_DEF_LINK_UDP_MTU 14000
struct tipc_node_info {
  __be32 addr;
  __be32 up;
};
struct tipc_link_info {
  __be32 dest;
  __be32 up;
  char str[TIPC_MAX_LINK_NAME];
};
struct tipc_bearer_config {
  __be32 priority;
  __be32 disc_domain;
  char name[TIPC_MAX_BEARER_NAME];
};
struct tipc_link_config {
  __be32 value;
  char name[TIPC_MAX_LINK_NAME];
};
#define TIPC_NTQ_ALLTYPES 0x80000000
struct tipc_name_table_query {
  __be32 depth;
  __be32 type;
  __be32 lowbound;
  __be32 upbound;
};
#define TIPC_CFG_TLV_ERROR "\x80"
#define TIPC_CFG_NOT_NET_ADMIN "\x81"
#define TIPC_CFG_NOT_ZONE_MSTR "\x82"
#define TIPC_CFG_NO_REMOTE "\x83"
#define TIPC_CFG_NOT_SUPPORTED "\x84"
#define TIPC_CFG_INVALID_VALUE "\x85"
struct tlv_desc {
  __be16 tlv_len;
  __be16 tlv_type;
};
#define TLV_ALIGNTO 4
#define TLV_ALIGN(datalen) (((datalen) + (TLV_ALIGNTO - 1)) & ~(TLV_ALIGNTO - 1))
#define TLV_LENGTH(datalen) (sizeof(struct tlv_desc) + (datalen))
#define TLV_SPACE(datalen) (TLV_ALIGN(TLV_LENGTH(datalen)))
#define TLV_DATA(tlv) ((void *) ((char *) (tlv) + TLV_LENGTH(0)))
struct tlv_list_desc {
  struct tlv_desc * tlv_ptr;
  __u32 tlv_space;
};
#define TIPC_GENL_NAME "TIPC"
#define TIPC_GENL_VERSION 0x1
#define TIPC_GENL_CMD 0x1
struct tipc_genlmsghdr {
  __u32 dest;
  __u16 cmd;
  __u16 reserved;
};
#define TIPC_GENL_HDRLEN NLMSG_ALIGN(sizeof(struct tipc_genlmsghdr))
struct tipc_cfg_msg_hdr {
  __be32 tcm_len;
  __be16 tcm_type;
  __be16 tcm_flags;
  char tcm_reserved[8];
};
#define TCM_F_REQUEST 0x1
#define TCM_F_MORE 0x2
#define TCM_ALIGN(datalen) (((datalen) + 3) & ~3)
#define TCM_LENGTH(datalen) (sizeof(struct tipc_cfg_msg_hdr) + datalen)
#define TCM_SPACE(datalen) (TCM_ALIGN(TCM_LENGTH(datalen)))
#define TCM_DATA(tcm_hdr) ((void *) ((char *) (tcm_hdr) + TCM_LENGTH(0)))
#endif
```