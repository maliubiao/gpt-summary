Response:
Let's break down the thought process for analyzing the provided C header file for `ip_set`.

**1. Understanding the Context:**

The first step is to understand *what* this file is. The prompt clearly states it's a UAPI header file within the Android Bionic library related to Linux Netfilter's `ipset`. This immediately tells us:

* **UAPI (User-space API):** This header defines interfaces for user-space programs to interact with kernel functionality. It's *not* kernel code itself, but a contract between user and kernel.
* **Android Bionic:** This confirms it's relevant to the Android ecosystem and likely used by Android system components or applications that need to interact with network filtering.
* **Linux Netfilter `ipset`:**  This is the core functionality. `ipset` is a Linux kernel feature that allows for efficient storage and matching of IP address sets (or other network identifiers). Knowing this is crucial for understanding the purpose of the definitions.

**2. High-Level Overview of Functionality:**

Given the `ipset` context, I immediately anticipate this header will define structures and constants related to managing IP sets: creating, deleting, adding/removing members, listing, etc. Keywords like `IPSET_CMD_CREATE`, `IPSET_CMD_ADD`, `IPSET_ATTR_IP` reinforce this.

**3. Deconstructing the Header File:**

I'll go through the header section by section, noting down the purpose of each major block:

* **Includes:** `#include <linux/types.h>` - Standard Linux types, nothing surprising.
* **Macros:**
    * `IPSET_PROTOCOL`, `IPSET_PROTOCOL_MIN`, `IPSET_MAXNAMELEN`, `IPSET_MAX_COMMENT_SIZE`: These define constants related to the `ipset` protocol version and size limits. These are important for data exchange with the kernel.
* **Enums:** This is where the core functionality is defined. I'll go through each `enum`:
    * `ipset_cmd`: Lists the possible commands that can be sent to the kernel to interact with `ipset`. Examples: create, destroy, add, delete, list. This is the primary interface for controlling `ipset`.
    * `ipset_attr` (various):  These enums define the attributes or fields associated with `ipset` commands and data. They essentially describe the structure of the messages exchanged. I'll group them logically:
        * `IPSET_ATTR_*`: General attributes used in various commands.
        * `IPSET_ATTR_IP_*`, `IPSET_ATTR_PORT_*`, etc.: Attributes related to specific data types within the sets.
        * `IPSET_ATTR_CREATE_*`: Attributes specific to creating a new set.
        * `IPSET_ATTR_ADT_*`: Attributes related to adding/deleting/testing elements.
        * `IPSET_ATTR_IPADDR_*`: Attributes for IP address families.
    * `ipset_errno`:  Defines error codes returned by the kernel.
    * `ipset_cmd_flags`, `ipset_cadt_flags`, `ipset_create_flags`: Define flags that modify the behavior of commands.
    * `ipset_adt`:  Short for "add/delete/test," indicates the type of set modification operation.
    * `ip_set_dim`, `ip_set_kopt`:  Related to the dimensions and options of IP sets (e.g., source/destination IP).
    * `ipset_counter_*`:  Defines constants and structures for matching based on packet/byte counters associated with set elements.
* **Structs:** These define the data structures used for communication with the kernel:
    * `ip_set_counter_match0`, `ip_set_counter_match`: Structures for counter-based matching.
    * `ip_set_name_index`: A union to represent a set by either its name or index.
    * `ip_set_req_get_set`, `ip_set_req_get_set_family`, `ip_set_req_version`: Structures for specific `ipset` operations (getting set information, version).
* **Macros (again):** `SO_IP_SET`, `IP_SET_OP_*`:  Socket options and operation codes for interacting with `ipset` via sockets.

**4. Relating to Android:**

Now I'll think about how this fits into Android:

* **Network Filtering:**  Android relies heavily on network filtering for security (firewall), traffic management, VPNs, etc. `ipset` is a powerful tool for this.
* **`iptables` and `ndk`:**  Android uses `iptables` (or its modern counterpart `nftables`) for configuring the Netfilter firewall. The NDK might provide interfaces to interact with these tools, potentially indirectly using `ipset`.
* **System Services:**  Core Android system services involved in networking (like `netd`) are likely to use `ipset`.

**5. `libc` Functions:**

The header itself doesn't define `libc` functions; it defines *constants* and *data structures*. User-space programs would use standard `libc` functions like `socket()`, `sendto()`, `recvfrom()`, `ioctl()` (potentially with `SO_IP_SET`), and memory management functions (`malloc()`, `free()`) to interact with the kernel based on these definitions. I'll focus on how these *would* be used in conjunction with the defined structures.

**6. Dynamic Linker:**

This header file itself doesn't *directly* involve the dynamic linker. However, any Android component that *uses* this header and interacts with the kernel will be a shared library or executable. I'll consider how such a component would be linked and loaded.

**7. Logical Reasoning and Examples:**

I'll create hypothetical scenarios to illustrate how the structures and commands are used. For example, creating a set, adding members, testing membership.

**8. Common Errors:**

I'll think about potential programming errors when using these APIs, such as incorrect attribute usage, invalid data types, or not handling errors properly.

**9. Android Framework/NDK Path and Frida Hook:**

I'll trace a likely path from an Android app or framework component down to the kernel `ipset` interaction. Then, I'll devise a simple Frida script to hook relevant system calls or library functions.

**Self-Correction/Refinement during the Thought Process:**

* Initially, I might focus too much on the individual enum values. I need to step back and understand the *purpose* of the enums as a whole (defining commands, attributes, etc.).
* I need to be careful not to confuse the header file with the underlying kernel implementation. The header defines the interface, not the implementation.
* When discussing `libc` functions, it's crucial to emphasize *how* they are used in conjunction with the header's definitions, not just list random `libc` functions.
* The dynamic linker aspect needs to be framed correctly – the header doesn't directly involve it, but the *users* of the header do.

By following this structured approach, I can systematically analyze the header file and address all aspects of the prompt. The key is to understand the context, break down the information, and connect it to the broader Android ecosystem.
这是一个定义了 Linux Netfilter `ipset` 用户空间 API 的 C 头文件，用于 Android Bionic 库中。`ipset` 是 Linux 内核的一个功能，允许创建和管理存储 IP 地址、网络、端口等的集合，并能高效地与 iptables 等防火墙规则配合使用。

**文件功能：**

这个头文件定义了用户空间程序与 Linux 内核中 `ipset` 功能进行交互的接口。它包含了以下关键信息：

1. **协议定义:**  定义了 `ipset` 协议的版本号 (`IPSET_PROTOCOL`, `IPSET_PROTOCOL_MIN`)。
2. **常量定义:** 定义了最大名称长度 (`IPSET_MAXNAMELEN`) 和最大注释大小 (`IPSET_MAX_COMMENT_SIZE`) 等常量。
3. **枚举类型:**
    * `ipset_cmd`:  定义了可以执行的 `ipset` 命令，例如创建、销毁、添加、删除、测试 IP 集合等。
    * `ipset_attr`:  定义了与 `ipset` 命令相关的属性，例如集合名称、类型、IP 地址、端口、超时时间等。这些属性用于构造和解析与内核通信的消息。
    * `ipset_errno`: 定义了 `ipset` 操作可能返回的错误码。
    * `ipset_cmd_flags`, `ipset_cadt_flags`, `ipset_create_flags`: 定义了命令执行时的各种标志位，用于修改命令的行为。
    * `ipset_adt`: 定义了集合操作类型，如添加、删除、测试。
    * `ip_set_dim`, `ip_set_kopt`: 定义了 IP 集合的维度和选项。
    * `ipset_counter_*`: 定义了与计数器相关的常量和结构。
4. **结构体定义:**
    * `ip_set_counter_match0`, `ip_set_counter_match`:  定义了用于匹配 IP 集合中元素计数器的结构。
    * `ip_set_name_index`: 定义了一个联合体，用于通过名称或索引来标识 IP 集合。
    * `ip_set_req_get_set`, `ip_set_req_get_set_family`, `ip_set_req_version`: 定义了用于获取 IP 集合信息的请求结构。
5. **宏定义:** 定义了一些辅助宏，例如 `SO_IP_SET` (套接字选项) 和 `IP_SET_OP_*` (IP 集合操作码)。

**与 Android 功能的关系及举例：**

`ipset` 在 Android 中主要用于网络过滤和安全策略的实现。Android 系统（尤其是其网络组件）会利用 `ipset` 来高效地管理和匹配网络流量。

**举例说明：**

* **防火墙规则 (iptables/nftables)：** Android 的防火墙通常使用 `iptables` 或其后续替代者 `nftables`。这些工具可以利用 `ipset` 来创建包含大量 IP 地址或网络的规则，而无需为每个 IP 地址单独创建规则，从而提高效率。例如，可以创建一个名为 "blocklist" 的 IP 集合，并将恶意 IP 地址添加到其中。然后，一条 `iptables` 规则可以阻止来自 "blocklist" 中所有 IP 地址的流量。
* **VPN 服务:** VPN 客户端可能会使用 `ipset` 来管理需要通过 VPN 路由的 IP 地址或网络列表。
* **网络共享/热点:**  在网络共享或热点功能中，可能使用 `ipset` 来管理允许或拒绝连接到热点的设备 IP 地址。
* **流量控制:** Android 系统可以使用 `ipset` 来标记属于特定 IP 集合的流量，以便应用不同的流量控制策略。

**libc 函数的功能实现：**

这个头文件本身并没有实现任何 `libc` 函数。它只是定义了数据结构和常量。用户空间的程序会使用标准的 `libc` 函数（如 `socket`, `ioctl`, `sendto`, `recvfrom` 等）结合这些定义来与内核中的 `ipset` 功能进行交互。

通常的交互流程如下：

1. **创建套接字:** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` 创建一个 Netlink 套接字，用于与内核 Netfilter 子系统通信。
2. **构造消息:** 根据需要执行的 `ipset` 命令，填充相应的结构体（如 `ip_set_req_get_set`）和属性 (使用 `ipset_attr` 枚举)。这些数据会被放入 Netlink 消息的载荷中。
3. **发送消息:** 使用 `sendto` 或类似的函数将构造好的 Netlink 消息发送到内核。
4. **接收响应:** 使用 `recvfrom` 或类似的函数接收来自内核的响应。
5. **解析响应:** 解析内核返回的 Netlink 消息，根据 `ipset_errno` 判断操作是否成功，并提取返回的数据。

**涉及 dynamic linker 的功能：**

这个头文件本身与动态链接器没有直接关系。但是，任何使用这个头文件的 Android 组件（例如，一个实现了特定网络功能的共享库 `.so` 文件）都需要通过动态链接器加载到进程的内存空间中。

**so 布局样本：**

假设有一个名为 `libipset_manager.so` 的共享库使用了这个头文件：

```
libipset_manager.so:
    DEBUG
    .gnu.hash
    .dynsym
    .dynstr
    .rel.dyn
    .rel.plt
    .plt.got
    .text
    .rodata
    .eh_frame_hdr
    .eh_frame
    .data
    .bss
    __libc_init
```

* **.text:** 包含可执行代码，例如使用 `ipset` API 的函数。
* **.rodata:** 包含只读数据，例如字符串常量。
* **.data:** 包含已初始化的全局变量和静态变量。
* **.bss:** 包含未初始化的全局变量和静态变量。
* **.dynsym:** 动态符号表，列出了该共享库导出的和需要导入的符号。
* **.dynstr:** 动态字符串表，存储了符号表中使用的字符串。
* **.rel.dyn 和 .rel.plt:** 重定位表，用于在加载时调整代码和数据的地址。
* **.plt.got:** 程序链接表和全局偏移表，用于延迟绑定动态链接的函数。

**链接的处理过程：**

1. **加载时：** 当一个应用程序或服务需要使用 `libipset_manager.so` 中的功能时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责加载该共享库。
2. **依赖解析：** 链接器会检查 `libipset_manager.so` 的依赖关系，确保所有需要的其他共享库（例如 `libc.so`）也被加载。
3. **符号查找：** 链接器会解析 `libipset_manager.so` 中的动态符号表，找到需要的外部符号（例如 `libc` 中的函数）。
4. **重定位：** 链接器会根据重定位表中的信息，修改 `libipset_manager.so` 中需要调整的地址，使其指向正确的内存位置。这包括指向导入的函数和全局变量的地址。
5. **绑定：**  对于延迟绑定的函数调用，第一次调用时会触发链接器解析目标函数的地址并更新 PLT/GOT 表，后续调用将直接跳转到已解析的地址。

由于 `ip_set.h` 是一个头文件，它只提供编译时的信息，动态链接器主要处理的是编译后的共享库。`libipset_manager.so` 在编译时会包含对 `libc` 中函数的调用，这些调用需要在加载时由动态链接器解析。

**逻辑推理、假设输入与输出：**

假设我们想创建一个名为 "my_ipset" 的 IP 集合，类型为 `hash:ip`。

**假设输入：**

* 命令: `IPSET_CMD_CREATE`
* 属性:
    * `IPSET_ATTR_SETNAME`: "my_ipset"
    * `IPSET_ATTR_TYPENAME`: "hash:ip"
    * `IPSET_ATTR_FAMILY`:  `AF_INET` (假设是 IPv4)

**逻辑推理：**

用户空间程序会构造一个包含上述信息的 Netlink 消息，并发送给内核。内核的 `ipset` 模块接收到消息后，会检查参数的有效性，并在内核空间创建一个新的 `hash:ip` 类型的 IP 集合，名称为 "my_ipset"。

**假设输出：**

* 如果创建成功，内核会返回一个成功的 Netlink 消息，可能不包含额外的数据，或者包含新创建集合的索引。
* 如果创建失败（例如，名称已存在），内核会返回一个包含相应错误码（如 `IPSET_ERR_EXIST_SETNAME2`) 的 Netlink 消息。

**用户或编程常见的使用错误：**

1. **未正确初始化结构体:**  忘记初始化某些关键字段，导致发送给内核的数据不完整或错误。
   ```c
   struct nlmsghdr nlh;
   // 错误：未初始化 nlh 的长度和类型等字段
   sendto(sock, &nlh, sizeof(nlh), 0, (struct sockaddr*)&sa, sizeof(sa));
   ```
2. **属性顺序错误:** Netlink 消息中的属性需要按照一定的顺序排列，错误的顺序可能导致解析失败。
3. **属性值错误:** 提供了超出范围或格式不正确的属性值，例如 IP 地址格式错误。
4. **错误处理不当:** 没有检查内核返回的错误码，导致程序在操作失败后继续执行。
5. **内存管理错误:**  在使用动态分配内存来构建 Netlink 消息时，忘记释放内存，导致内存泄漏。
6. **并发问题:** 在多线程或多进程环境下，如果没有适当的同步机制，可能会导致对 `ipset` 的操作冲突。
7. **权限问题:**  执行 `ipset` 操作通常需要 root 权限。普通应用程序可能无法执行某些操作。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

**路径示例：**

1. **Android 应用或服务:**  一个需要进行网络过滤的应用或系统服务发起请求。
2. **Framework API:** 应用可能使用 Android Framework 提供的网络管理 API，例如 `NetworkPolicyManager` 或直接使用 `Socket` API。
3. **System Service (netd):**  Framework API 的请求通常会传递给系统服务 `netd`。`netd` 负责执行底层的网络配置和管理操作。
4. **`iptables`/`nftables` 工具:** `netd` 可能会调用 `iptables` 或 `nftables` 命令行工具来配置防火墙规则。
5. **`ipset` 命令行工具:** `iptables` 或 `nftables` 可以调用 `ipset` 命令行工具来管理 IP 集合。
6. **Netlink 接口:** `ipset` 命令行工具通过 Netlink 套接字与内核中的 `ipset` 模块通信，使用的就是这个头文件中定义的结构和常量。

**NDK 路径：**

1. **NDK 应用:** 一个使用 NDK 开发的 C/C++ 应用可能直接使用 Socket API 和 Netlink 接口来与内核 `ipset` 功能交互。
2. **直接 Netlink 调用:** 应用需要手动构建 Netlink 消息，使用这个头文件中定义的结构体和常量。

**Frida Hook 示例：**

假设我们要 hook `netd` 进程中发送 `IPSET_CMD_CREATE` 命令的操作。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        # 这里需要解析 Netlink 消息的结构，提取 ipset 命令和属性
        # 这需要对 Netlink 协议和 ipset 消息格式有一定的了解
        # 一个简化的示例，假设已知命令在特定偏移位置
        command = payload[4:8].hex() # 假设命令在 payload 的 4-7 字节
        if command == '00000002': # IPSET_CMD_CREATE 的值 (需要根据实际情况确定)
            print(f"发现 IPSET_CMD_CREATE 命令! Payload: {payload.hex()}")

def main():
    device = frida.get_usb_device()
    pid = device.spawn(["com.android.shell"]) # 这里假设 netd 运行在 shell 用户下，实际需要找到 netd 进程
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "sendto"), {
            onEnter: function(args) {
                const sockfd = args[0].toInt32();
                const buf = Memory.readByteArray(args[1], args[2].toInt32());
                const flags = args[3].toInt32();
                const dest_addr = args[4];
                const addrlen = args[5].toInt32();

                // 检查是否是 Netlink 套接字，并粗略判断是否是 ipset 相关消息
                // 这需要对 Netlink 协议有一定的了解
                if (sockfd > 0) { // 简单的套接字描述符判断
                    send({type: 'send', payload: buf});
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()

if __name__ == '__main__':
    main()
```

**Frida Hook 调试步骤：**

1. **找到目标进程:** 确定负责 `ipset` 操作的进程，通常是 `netd` 或执行相关命令的工具进程。
2. **Attach 到进程:** 使用 Frida attach 到目标进程。
3. **Hook `sendto` 系统调用:**  由于 `ipset` 操作通过 Netlink 套接字发送消息，我们需要 hook `sendto` 系统调用，拦截发送给内核的消息。
4. **过滤 Netlink 消息:** 在 `sendto` 的 `onEnter` 中，检查套接字类型是否为 `AF_NETLINK`，并尝试识别与 `ipset` 相关的消息（例如，通过检查目的地址或消息头）。
5. **解析 `ipset` 命令和属性:** 如果识别到 `ipset` 消息，需要根据 Netlink 协议和 `ipset` 消息格式解析消息内容，提取命令类型和相关属性。这可能需要查阅相关的内核文档和 `ipset` 协议规范。
6. **打印或修改消息:** 可以打印解析出的命令和属性，或者在必要时修改消息内容。

**更精细的 Hook (可能需要 root 权限和更多知识)：**

* **Hook `ipset` 命令行工具:** 如果操作是通过 `ipset` 命令行工具进行的，可以 hook `execve` 或相关的 `libc` 函数，拦截 `ipset` 命令及其参数。
* **Hook `libnetfilter_**` 库:**  很多用户空间工具使用 `libnetfilter_**` 系列库来与 Netfilter 交互，可以 hook 这些库中的函数。

请注意，Frida Hook 涉及到运行时内存操作，需要谨慎处理，并确保目标设备允许 Frida 运行。解析 Netlink 消息和 `ipset` 消息格式需要一定的专业知识。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/netfilter/ipset/ip_set.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_IP_SET_H
#define _UAPI_IP_SET_H
#include <linux/types.h>
#define IPSET_PROTOCOL 7
#define IPSET_PROTOCOL_MIN 6
#define IPSET_MAXNAMELEN 32
#define IPSET_MAX_COMMENT_SIZE 255
enum ipset_cmd {
  IPSET_CMD_NONE,
  IPSET_CMD_PROTOCOL,
  IPSET_CMD_CREATE,
  IPSET_CMD_DESTROY,
  IPSET_CMD_FLUSH,
  IPSET_CMD_RENAME,
  IPSET_CMD_SWAP,
  IPSET_CMD_LIST,
  IPSET_CMD_SAVE,
  IPSET_CMD_ADD,
  IPSET_CMD_DEL,
  IPSET_CMD_TEST,
  IPSET_CMD_HEADER,
  IPSET_CMD_TYPE,
  IPSET_CMD_GET_BYNAME,
  IPSET_CMD_GET_BYINDEX,
  IPSET_MSG_MAX,
  IPSET_CMD_RESTORE = IPSET_MSG_MAX,
  IPSET_CMD_HELP,
  IPSET_CMD_VERSION,
  IPSET_CMD_QUIT,
  IPSET_CMD_MAX,
  IPSET_CMD_COMMIT = IPSET_CMD_MAX,
};
enum {
  IPSET_ATTR_UNSPEC,
  IPSET_ATTR_PROTOCOL,
  IPSET_ATTR_SETNAME,
  IPSET_ATTR_TYPENAME,
  IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME,
  IPSET_ATTR_REVISION,
  IPSET_ATTR_FAMILY,
  IPSET_ATTR_FLAGS,
  IPSET_ATTR_DATA,
  IPSET_ATTR_ADT,
  IPSET_ATTR_LINENO,
  IPSET_ATTR_PROTOCOL_MIN,
  IPSET_ATTR_REVISION_MIN = IPSET_ATTR_PROTOCOL_MIN,
  IPSET_ATTR_INDEX,
  __IPSET_ATTR_CMD_MAX,
};
#define IPSET_ATTR_CMD_MAX (__IPSET_ATTR_CMD_MAX - 1)
enum {
  IPSET_ATTR_IP = IPSET_ATTR_UNSPEC + 1,
  IPSET_ATTR_IP_FROM = IPSET_ATTR_IP,
  IPSET_ATTR_IP_TO,
  IPSET_ATTR_CIDR,
  IPSET_ATTR_PORT,
  IPSET_ATTR_PORT_FROM = IPSET_ATTR_PORT,
  IPSET_ATTR_PORT_TO,
  IPSET_ATTR_TIMEOUT,
  IPSET_ATTR_PROTO,
  IPSET_ATTR_CADT_FLAGS,
  IPSET_ATTR_CADT_LINENO = IPSET_ATTR_LINENO,
  IPSET_ATTR_MARK,
  IPSET_ATTR_MARKMASK,
  IPSET_ATTR_BITMASK,
  IPSET_ATTR_CADT_MAX = 16,
  IPSET_ATTR_INITVAL,
  IPSET_ATTR_HASHSIZE,
  IPSET_ATTR_MAXELEM,
  IPSET_ATTR_NETMASK,
  IPSET_ATTR_BUCKETSIZE,
  IPSET_ATTR_RESIZE,
  IPSET_ATTR_SIZE,
  IPSET_ATTR_ELEMENTS,
  IPSET_ATTR_REFERENCES,
  IPSET_ATTR_MEMSIZE,
  __IPSET_ATTR_CREATE_MAX,
};
#define IPSET_ATTR_CREATE_MAX (__IPSET_ATTR_CREATE_MAX - 1)
enum {
  IPSET_ATTR_ETHER = IPSET_ATTR_CADT_MAX + 1,
  IPSET_ATTR_NAME,
  IPSET_ATTR_NAMEREF,
  IPSET_ATTR_IP2,
  IPSET_ATTR_CIDR2,
  IPSET_ATTR_IP2_TO,
  IPSET_ATTR_IFACE,
  IPSET_ATTR_BYTES,
  IPSET_ATTR_PACKETS,
  IPSET_ATTR_COMMENT,
  IPSET_ATTR_SKBMARK,
  IPSET_ATTR_SKBPRIO,
  IPSET_ATTR_SKBQUEUE,
  IPSET_ATTR_PAD,
  __IPSET_ATTR_ADT_MAX,
};
#define IPSET_ATTR_ADT_MAX (__IPSET_ATTR_ADT_MAX - 1)
enum {
  IPSET_ATTR_IPADDR_IPV4 = IPSET_ATTR_UNSPEC + 1,
  IPSET_ATTR_IPADDR_IPV6,
  __IPSET_ATTR_IPADDR_MAX,
};
#define IPSET_ATTR_IPADDR_MAX (__IPSET_ATTR_IPADDR_MAX - 1)
enum ipset_errno {
  IPSET_ERR_PRIVATE = 4096,
  IPSET_ERR_PROTOCOL,
  IPSET_ERR_FIND_TYPE,
  IPSET_ERR_MAX_SETS,
  IPSET_ERR_BUSY,
  IPSET_ERR_EXIST_SETNAME2,
  IPSET_ERR_TYPE_MISMATCH,
  IPSET_ERR_EXIST,
  IPSET_ERR_INVALID_CIDR,
  IPSET_ERR_INVALID_NETMASK,
  IPSET_ERR_INVALID_FAMILY,
  IPSET_ERR_TIMEOUT,
  IPSET_ERR_REFERENCED,
  IPSET_ERR_IPADDR_IPV4,
  IPSET_ERR_IPADDR_IPV6,
  IPSET_ERR_COUNTER,
  IPSET_ERR_COMMENT,
  IPSET_ERR_INVALID_MARKMASK,
  IPSET_ERR_SKBINFO,
  IPSET_ERR_BITMASK_NETMASK_EXCL,
  IPSET_ERR_TYPE_SPECIFIC = 4352,
};
enum ipset_cmd_flags {
  IPSET_FLAG_BIT_EXIST = 0,
  IPSET_FLAG_EXIST = (1 << IPSET_FLAG_BIT_EXIST),
  IPSET_FLAG_BIT_LIST_SETNAME = 1,
  IPSET_FLAG_LIST_SETNAME = (1 << IPSET_FLAG_BIT_LIST_SETNAME),
  IPSET_FLAG_BIT_LIST_HEADER = 2,
  IPSET_FLAG_LIST_HEADER = (1 << IPSET_FLAG_BIT_LIST_HEADER),
  IPSET_FLAG_BIT_SKIP_COUNTER_UPDATE = 3,
  IPSET_FLAG_SKIP_COUNTER_UPDATE = (1 << IPSET_FLAG_BIT_SKIP_COUNTER_UPDATE),
  IPSET_FLAG_BIT_SKIP_SUBCOUNTER_UPDATE = 4,
  IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE = (1 << IPSET_FLAG_BIT_SKIP_SUBCOUNTER_UPDATE),
  IPSET_FLAG_BIT_MATCH_COUNTERS = 5,
  IPSET_FLAG_MATCH_COUNTERS = (1 << IPSET_FLAG_BIT_MATCH_COUNTERS),
  IPSET_FLAG_BIT_RETURN_NOMATCH = 7,
  IPSET_FLAG_RETURN_NOMATCH = (1 << IPSET_FLAG_BIT_RETURN_NOMATCH),
  IPSET_FLAG_BIT_MAP_SKBMARK = 8,
  IPSET_FLAG_MAP_SKBMARK = (1 << IPSET_FLAG_BIT_MAP_SKBMARK),
  IPSET_FLAG_BIT_MAP_SKBPRIO = 9,
  IPSET_FLAG_MAP_SKBPRIO = (1 << IPSET_FLAG_BIT_MAP_SKBPRIO),
  IPSET_FLAG_BIT_MAP_SKBQUEUE = 10,
  IPSET_FLAG_MAP_SKBQUEUE = (1 << IPSET_FLAG_BIT_MAP_SKBQUEUE),
  IPSET_FLAG_CMD_MAX = 15,
};
enum ipset_cadt_flags {
  IPSET_FLAG_BIT_BEFORE = 0,
  IPSET_FLAG_BEFORE = (1 << IPSET_FLAG_BIT_BEFORE),
  IPSET_FLAG_BIT_PHYSDEV = 1,
  IPSET_FLAG_PHYSDEV = (1 << IPSET_FLAG_BIT_PHYSDEV),
  IPSET_FLAG_BIT_NOMATCH = 2,
  IPSET_FLAG_NOMATCH = (1 << IPSET_FLAG_BIT_NOMATCH),
  IPSET_FLAG_BIT_WITH_COUNTERS = 3,
  IPSET_FLAG_WITH_COUNTERS = (1 << IPSET_FLAG_BIT_WITH_COUNTERS),
  IPSET_FLAG_BIT_WITH_COMMENT = 4,
  IPSET_FLAG_WITH_COMMENT = (1 << IPSET_FLAG_BIT_WITH_COMMENT),
  IPSET_FLAG_BIT_WITH_FORCEADD = 5,
  IPSET_FLAG_WITH_FORCEADD = (1 << IPSET_FLAG_BIT_WITH_FORCEADD),
  IPSET_FLAG_BIT_WITH_SKBINFO = 6,
  IPSET_FLAG_WITH_SKBINFO = (1 << IPSET_FLAG_BIT_WITH_SKBINFO),
  IPSET_FLAG_BIT_IFACE_WILDCARD = 7,
  IPSET_FLAG_IFACE_WILDCARD = (1 << IPSET_FLAG_BIT_IFACE_WILDCARD),
  IPSET_FLAG_CADT_MAX = 15,
};
enum ipset_create_flags {
  IPSET_CREATE_FLAG_BIT_FORCEADD = 0,
  IPSET_CREATE_FLAG_FORCEADD = (1 << IPSET_CREATE_FLAG_BIT_FORCEADD),
  IPSET_CREATE_FLAG_BIT_BUCKETSIZE = 1,
  IPSET_CREATE_FLAG_BUCKETSIZE = (1 << IPSET_CREATE_FLAG_BIT_BUCKETSIZE),
  IPSET_CREATE_FLAG_BIT_MAX = 7,
};
enum ipset_adt {
  IPSET_ADD,
  IPSET_DEL,
  IPSET_TEST,
  IPSET_ADT_MAX,
  IPSET_CREATE = IPSET_ADT_MAX,
  IPSET_CADT_MAX,
};
typedef __u16 ip_set_id_t;
#define IPSET_INVALID_ID 65535
enum ip_set_dim {
  IPSET_DIM_ZERO = 0,
  IPSET_DIM_ONE,
  IPSET_DIM_TWO,
  IPSET_DIM_THREE,
  IPSET_DIM_MAX = 6,
  IPSET_BIT_RETURN_NOMATCH = 7,
};
enum ip_set_kopt {
  IPSET_INV_MATCH = (1 << IPSET_DIM_ZERO),
  IPSET_DIM_ONE_SRC = (1 << IPSET_DIM_ONE),
  IPSET_DIM_TWO_SRC = (1 << IPSET_DIM_TWO),
  IPSET_DIM_THREE_SRC = (1 << IPSET_DIM_THREE),
  IPSET_RETURN_NOMATCH = (1 << IPSET_BIT_RETURN_NOMATCH),
};
enum {
  IPSET_COUNTER_NONE = 0,
  IPSET_COUNTER_EQ,
  IPSET_COUNTER_NE,
  IPSET_COUNTER_LT,
  IPSET_COUNTER_GT,
};
struct ip_set_counter_match0 {
  __u8 op;
  __u64 value;
};
struct ip_set_counter_match {
  __aligned_u64 value;
  __u8 op;
};
#define SO_IP_SET 83
union ip_set_name_index {
  char name[IPSET_MAXNAMELEN];
  ip_set_id_t index;
};
#define IP_SET_OP_GET_BYNAME 0x00000006
struct ip_set_req_get_set {
  unsigned int op;
  unsigned int version;
  union ip_set_name_index set;
};
#define IP_SET_OP_GET_BYINDEX 0x00000007
#define IP_SET_OP_GET_FNAME 0x00000008
struct ip_set_req_get_set_family {
  unsigned int op;
  unsigned int version;
  unsigned int family;
  union ip_set_name_index set;
};
#define IP_SET_OP_VERSION 0x00000100
struct ip_set_req_version {
  unsigned int op;
  unsigned int version;
};
#endif

"""

```