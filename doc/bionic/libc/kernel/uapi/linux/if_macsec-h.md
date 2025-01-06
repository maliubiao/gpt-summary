Response:
Let's break down the thought process for analyzing this C header file and generating the comprehensive response.

**1. Initial Understanding and Goal Identification:**

The first step is to recognize that this is a C header file (`.h`) located within the Android Bionic library's kernel interface. The filename `if_macsec.h` and the directory structure strongly suggest it deals with MACsec (Media Access Control Security) at the network interface level. The comments explicitly state it's auto-generated and relates to Bionic's kernel interface. The request asks for its functions, relation to Android, libc function details, dynamic linker implications, usage errors, and how Android framework/NDK reaches this code, along with a Frida hook example.

**2. Core Functionality Extraction (High-Level):**

The `#define` statements and `enum` definitions are key to understanding the file's purpose.

*   **`#define MACSEC_GENL_NAME "macsec"` and `MACSEC_GENL_VERSION 1`**:  These immediately point to Netlink Generic Netlink family named "macsec", version 1. This is crucial because it establishes the primary mechanism for userspace interaction with the MACsec kernel module.
*   **`#define MACSEC_MAX_KEY_LEN ...` and similar**:  These defines specify constants related to key lengths, identifiers, and cipher suites. This hints at the cryptographic nature of MACsec.
*   **`enum macsec_attrs`**: This enumeration lists the attributes that can be exchanged via the Netlink interface. Terms like `IFINDEX`, `RXSC_CONFIG`, `SA_CONFIG`, `SECY` suggest configuration options related to interfaces, receive secure channels, security associations, and security entities.
*   **Other `enum`s (`macsec_secy_attrs`, `macsec_rxsc_attrs`, `macsec_sa_attrs`, `macsec_offload_attrs`)**: These further refine the attributes specific to security entities, receive secure channels, security associations, and hardware offloading.
*   **`enum macsec_nl_commands`**: This is a critical enumeration listing the Netlink commands that can be sent to the kernel module. Actions like `ADD_RXSC`, `DEL_TXSA`, `UPD_OFFLOAD` clearly indicate the operations supported.
*   **`enum macsec_*_stats_attr`**:  These enumerations define the various statistics that can be retrieved related to different MACsec components (RXSC, SA, TXSC, SECY).

**3. Connecting to Android Functionality:**

Knowing that this is within the Android Bionic library, the next step is to consider how MACsec relates to Android. MACsec provides link-layer encryption and authentication. In an Android context, this is most relevant in enterprise or secure environments where devices need to communicate securely over wired Ethernet connections. While not a core feature used by every Android device, it's a necessary capability for specific use cases.

**4. `libc` Function Analysis (Focus on `#include <linux/types.h>`):**

The only direct `libc` inclusion is `<linux/types.h>`. The key insight here is that this is a *kernel* header included in the *userspace* `libc`. This inclusion provides standard Linux types (`__u8`, `__u16`, `__u32`, `__u64`, etc.) to ensure data structure compatibility between userspace and kernel. It's important to note that the *implementation* of the MACsec functionality resides in the Linux kernel, not directly in `libc`. `libc` provides the *interface* to interact with this kernel functionality (primarily through system calls related to Netlink sockets).

**5. Dynamic Linker Implications:**

Since this is a header file, it doesn't directly involve the dynamic linker (`ld.so`). Header files are used during *compilation*. The dynamic linker comes into play when the compiled *code* that uses these definitions needs to be linked against libraries. In this case, the userspace code interacting with MACsec would likely use the Netlink library (`libnl`). The dynamic linker would ensure `libnl.so` (or similar) is loaded at runtime. The SO layout and linking process would be standard for any library dependency.

**6. Logical Reasoning and Example (Netlink Interaction):**

The core interaction mechanism is the Generic Netlink socket. A hypothetical example would be constructing a Netlink message to add a Receive Secure Channel (RXSC). This involves:

*   Creating a Netlink socket.
*   Building a Netlink message with the `MACSEC_GENL_NAME` family and the `MACSEC_CMD_ADD_RXSC` command.
*   Adding attributes like `MACSEC_ATTR_IFINDEX` and `MACSEC_ATTR_RXSC_CONFIG` containing the relevant configuration data.
*   Sending the message to the kernel.
*   Receiving and parsing the kernel's response.

**7. Common User/Programming Errors:**

These often stem from incorrect usage of the Netlink API or misunderstanding MACsec configuration:

*   Incorrect attribute IDs or data types.
*   Missing mandatory attributes.
*   Invalid key lengths or formats.
*   Trying to perform operations without sufficient privileges.

**8. Android Framework/NDK Path and Frida Hooking:**

The path from the Android framework/NDK involves:

1. **Framework/System Services:** Higher-level Android components (e.g., NetworkStack, Connectivity Service) might need to manage network interfaces and security.
2. **Native Code/NDK:** These framework components often delegate low-level network configuration to native code written in C/C++.
3. **Netlink Library (`libnl`):** The native code would use libraries like `libnl` to interact with the kernel's Netlink interface.
4. **System Calls:** `libnl` ultimately uses system calls (e.g., `socket`, `bind`, `sendto`, `recvfrom`) to communicate with the Netlink socket.
5. **Kernel MACsec Module:** The kernel receives the Netlink messages and acts upon them, using the definitions from `if_macsec.h`.

A Frida hook example would target the `sendto` system call (or a `libnl` function) to intercept the Netlink messages being sent to the MACsec family.

**9. Structuring the Response:**

Finally, organize the information logically, starting with the core functionality, then relating it to Android, diving into technical details (libc, dynamic linker), providing examples, and explaining the Android path and debugging. Using clear headings and bullet points improves readability.

**Self-Correction/Refinement During the Process:**

*   Initially, I might have focused too much on the `libc` aspects, forgetting that the core logic is in the kernel. Realizing that `<linux/types.h>` is primarily for data type consistency is crucial.
*   The dynamic linker's role is indirect. It's essential to clarify that the header itself isn't linked, but the *code* using it relies on linked libraries.
*   For the Android path, it's important to highlight the layered approach and the role of `libnl`.
*   The Frida hook example needs to target the right level of abstraction (system call or library function) for effective interception.

By following these steps, iteratively refining the understanding, and addressing all aspects of the prompt, the comprehensive and accurate response can be generated.
这是一个定义 Linux 内核用户空间 API 的头文件，专门用于配置和管理 MACsec (Media Access Control Security)。MACsec 是一种 IEEE 标准 (802.1AE)，用于在以太网链路上提供点对点的安全。它通过加密数据帧并添加完整性检查值（ICV）来保护数据传输的机密性和完整性。

**文件功能列举：**

1. **定义 MACsec 的通用 Netlink 接口:**
    *   `MACSEC_GENL_NAME "macsec"`: 定义了用于与 MACsec 内核模块通信的 Generic Netlink 族名称。
    *   `MACSEC_GENL_VERSION 1`: 定义了 Netlink 协议的版本号。

2. **定义 MACsec 相关的常量:**
    *   `MACSEC_MAX_KEY_LEN 128`:  定义了 MACsec 密钥的最大长度（128 字节）。
    *   `MACSEC_KEYID_LEN 16`: 定义了密钥标识符的长度（16 字节）。
    *   `MACSEC_SALT_LEN 12`: 定义了盐值的长度（12 字节）。
    *   `MACSEC_CIPHER_ID_GCM_AES_128` 等: 定义了支持的加密套件的 ID，例如 GCM-AES-128 和 GCM-AES-256。
    *   `MACSEC_DEFAULT_CIPHER_ID` 和 `MACSEC_DEFAULT_CIPHER_ALT`: 定义了默认的加密套件。
    *   `MACSEC_MIN_ICV_LEN`, `MACSEC_MAX_ICV_LEN`, `MACSEC_STD_ICV_LEN`: 定义了完整性检查值 (ICV) 的最小、最大和标准长度。

3. **定义用于配置和管理 MACsec 的属性 (attributes):**  这些属性用于在用户空间和内核空间之间传递配置信息。
    *   `enum macsec_attrs`: 定义了顶层 MACsec 对象的属性，例如接口索引 (`MACSEC_ATTR_IFINDEX`)，接收安全通道配置 (`MACSEC_ATTR_RXSC_CONFIG`)，安全关联配置 (`MACSEC_ATTR_SA_CONFIG`) 等。
    *   `enum macsec_secy_attrs`: 定义了安全实体 (Security Entity, SECY) 的属性，例如安全通道标识符 (`MACSEC_SECY_ATTR_SCI`)，加密套件 (`MACSEC_SECY_ATTR_CIPHER_SUITE`)，ICV 长度 (`MACSEC_SECY_ATTR_ICV_LEN`) 等。
    *   `enum macsec_rxsc_attrs`: 定义了接收安全通道 (Receive Secure Channel, RXSC) 的属性。
    *   `enum macsec_sa_attrs`: 定义了安全关联 (Security Association, SA) 的属性，例如关联号 (`MACSEC_SA_ATTR_AN`)，数据包号 (`MACSEC_SA_ATTR_PN`)，密钥 (`MACSEC_SA_ATTR_KEY`)，密钥 ID (`MACSEC_SA_ATTR_KEYID`) 等。
    *   `enum macsec_offload_attrs`: 定义了硬件卸载相关的属性。

4. **定义用于控制 MACsec 的 Netlink 命令 (commands):**  这些命令用于指示内核执行特定的操作。
    *   `enum macsec_nl_commands`: 定义了可用的 Netlink 命令，例如获取发送安全通道 (`MACSEC_CMD_GET_TXSC`)，添加、删除和更新接收安全通道 (`MACSEC_CMD_ADD_RXSC`, `MACSEC_CMD_DEL_RXSC`, `MACSEC_CMD_UPD_RXSC`)，添加、删除和更新发送安全关联和接收安全关联 (`MACSEC_CMD_ADD_TXSA`, `MACSEC_CMD_DEL_TXSA`, `MACSEC_CMD_UPD_TXSA`, `MACSEC_CMD_ADD_RXSA`, `MACSEC_CMD_DEL_RXSA`, `MACSEC_CMD_UPD_RXSA`)，以及更新硬件卸载 (`MACSEC_CMD_UPD_OFFLOAD`)。

5. **定义用于获取 MACsec 统计信息的属性 (statistics attributes):** 这些属性用于从内核获取 MACsec 的运行状态和性能数据。
    *   `enum macsec_rxsc_stats_attr`: 定义了接收安全通道的统计信息属性，例如已验证的字节数 (`MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED`)，已解密的字节数 (`MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED`)，以及各种类型的数据包计数（例如，延迟的数据包，通过的数据包，无效的数据包）。
    *   `enum macsec_sa_stats_attr`: 定义了安全关联的统计信息属性，例如接收和发送的数据包计数。
    *   `enum macsec_txsc_stats_attr`: 定义了发送安全通道的统计信息属性。
    *   `enum macsec_secy_stats_attr`: 定义了安全实体的统计信息属性，例如未标记的发送和接收数据包计数，过长的数据包计数，以及各种与标签相关的问题的数据包计数。

**与 Android 功能的关系：**

这个头文件定义了 Linux 内核中 MACsec 功能的 **用户空间接口 (UAPI)**。这意味着 Android 系统中需要使用 MACsec 功能的组件（通常是底层的网络管理或安全相关的服务）会通过这个接口与内核进行交互。

**举例说明：**

假设 Android 设备需要连接到支持 MACsec 的企业网络。Android 系统中的某个服务（可能是负责网络配置的守护进程，或者 VPN 客户端）需要配置设备的 MACsec 功能。这个服务会：

1. 使用 Netlink 套接字与内核通信。
2. 构建包含 MACsec 配置信息的 Netlink 消息。
3. 消息中的配置信息会使用这里定义的常量和属性，例如：
    *   指定要配置 MACsec 的网络接口的索引 (`MACSEC_ATTR_IFINDEX`)。
    *   配置安全实体 (SECY) 的属性，例如加密套件 (`MACSEC_SECY_ATTR_CIPHER_SUITE`)。
    *   配置安全关联 (SA) 的属性，例如密钥 (`MACSEC_SA_ATTR_KEY`) 和密钥 ID (`MACSEC_SA_ATTR_KEYID`)。
    *   使用 `enum macsec_nl_commands` 中定义的命令来执行添加、删除或更新 MACsec 配置的操作。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了一些宏、常量和枚举类型。它被设计为被用户空间的 C/C++ 代码包含，以便能够使用这些定义来构建与内核 MACsec 模块交互的 Netlink 消息。

用户空间的程序需要使用诸如 `socket()` (创建套接字), `bind()` (绑定地址), `sendto()` (发送数据), `recvfrom()` (接收数据) 等 libc 提供的套接字相关的函数，以及可能使用 `malloc()`, `free()` 等内存管理函数来构建和处理 Netlink 消息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身 **不直接涉及 dynamic linker**。它是一个头文件，在编译时被包含到源代码中。

然而，如果用户空间程序使用了 Netlink 库（例如 `libnl`）来简化与内核的 Netlink 通信，那么 dynamic linker 就会参与进来。

**so 布局样本 (假设使用了 libnl):**

```
/system/lib64/libnl.so  (或者 /system/lib/libnl.so，取决于架构)
```

**链接的处理过程:**

1. **编译时:** 编译器的命令行会包含链接 Netlink 库的指示，例如 `-lnl`。链接器会记录程序依赖于 `libnl.so`。
2. **运行时:** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会：
    *   读取程序的可执行文件头，找到依赖的共享库列表。
    *   在预定义的路径中查找 `libnl.so`。
    *   将 `libnl.so` 加载到进程的地址空间。
    *   解析 `libnl.so` 中的符号（函数和变量）。
    *   重定位程序中对 `libnl.so` 中符号的引用，使其指向加载到内存中的实际地址。

**如果做了逻辑推理，请给出假设输入与输出：**

**假设输入：** 用户空间程序想要添加一个接收安全通道 (RXSC)。

**Netlink 消息的构建 (逻辑表示):**

```
struct nlmsghdr nlh;
struct genlmsghdr gnlh;
// ... 其他 Netlink 头部 ...

// 指定 MACsec 族
nlh.nlmsg_type = ... //  Generic Netlink 类型
gnlh.cmd = MACSEC_CMD_ADD_RXSC;

// 添加属性
struct nlattr ifindex_attr;
ifindex_attr.nla_type = MACSEC_ATTR_IFINDEX;
ifindex_attr.nla_len = sizeof(struct nlattr) + sizeof(int);
int ifindex = 2; // 假设接口索引为 2
memcpy(ifindex_attr + 1, &ifindex, sizeof(int));

struct nlattr rxsc_config_attr;
rxsc_config_attr.nla_type = MACSEC_ATTR_RXSC_CONFIG;
// ... 填充 RXSC 配置信息，例如 SCI ...

// 将属性添加到 Netlink 消息
// ...
```

**预期输出：**

*   **成功:** 如果所有参数都正确，内核会成功创建 RXSC，并可能返回一个确认消息。
*   **失败:** 如果参数错误（例如，无效的接口索引，重复的 SCI），内核会返回一个错误消息，指示失败的原因。错误消息的格式也会遵循 Netlink 协议，并包含错误代码。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **错误的属性类型或长度:**  构建 Netlink 消息时，使用了错误的 `nla_type` 或 `nla_len` 值，导致内核无法正确解析消息。
2. **缺少必要的属性:**  某些 Netlink 命令需要特定的属性才能成功执行。例如，添加 RXSC 时，可能需要提供 SCI (Secure Channel Identifier)。如果缺少这些必要的属性，内核会返回错误。
3. **使用了无效的枚举值:**  例如，指定了不支持的加密套件 ID。
4. **密钥格式错误或长度不匹配:**  MACsec 密钥需要符合特定的格式和长度要求。如果提供的密钥不正确，内核会拒绝配置。
5. **权限不足:**  配置 MACsec 通常需要 root 权限。普通用户尝试执行这些操作会失败。
6. **Netlink 消息格式错误:**  整体的 Netlink 消息结构不符合规范，例如头部字段错误。
7. **并发问题:**  在多线程或多进程环境中，如果没有适当的同步机制，可能会导致 MACsec 配置冲突。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常情况下，Android Framework 或 NDK **不会直接** 使用这个头文件中定义的常量和结构体来直接操作 MACsec。MACsec 的配置和管理通常发生在更底层的系统服务或守护进程中。

**可能的路径 (较为复杂的情况):**

1. **Android Framework (Java):**  Android Framework 中的某些网络管理相关的 API (例如，`ConnectivityManager`) 可能会触发底层的 native 代码来执行网络配置。
2. **System Services (Native C++):**  负责网络配置的系统服务 (例如，`netd`, `wificond`) 会接收来自 Framework 的请求。
3. **Netlink 交互 (Native C/C++):**  这些系统服务会使用 Netlink 套接字与内核进行通信，配置网络接口和安全参数，包括 MACsec。
4. **`libnl` 或 自行构建 Netlink 消息:**  系统服务可能会使用 `libnl` 库来简化 Netlink 消息的构建和解析，或者自行实现 Netlink 消息的构造逻辑。
5. **包含头文件:** 在构建 Netlink 消息时，相关的 C/C++ 代码会包含 `bionic/libc/kernel/uapi/linux/if_macsec.h` 头文件，以便使用其中定义的常量和结构体。
6. **系统调用:**  最终，会调用 `sendto()` 等系统调用将构建好的 Netlink 消息发送到内核。
7. **Linux 内核 MACsec 模块:**  内核接收到 Netlink 消息后，MACsec 模块会解析消息，并根据消息中的指令配置 MACsec 功能。

**Frida Hook 示例 (Hook `sendto` 系统调用):**

这个示例 hook 了 `sendto` 系统调用，并尝试过滤出发送到 Netlink MACsec 族的消息。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["/system/bin/system_server"]) # 或者你需要调试的进程
    session = device.attach(pid)
    device.resume(pid)
except frida.ServerNotStartedError:
    print("Frida server is not running on the device.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "sendto"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var buf = args[1];
        var len = args[2].toInt32();
        var flags = args[3].toInt32();
        var dest_addr = args[4];
        var addrlen = args[5];

        // 检查是否是 Netlink 套接字 (简单判断，可能需要更精确的过滤)
        if (dest_addr.isNull() === false && addrlen.toInt32() > 0) {
            var sa_family = dest_addr.readU16();
            const AF_NETLINK = 16;
            if (sa_family === AF_NETLINK) {
                // 读取 Netlink 消息头
                var nlmsg_len = buf.readU32();
                var nlmsg_type = buf.readU16();
                var nlmsg_flags = buf.readU16();
                var nlmsg_seq = buf.readU32();
                var nlmsg_pid = buf.readU32();

                // 尝试读取 Generic Netlink 头 (假设消息体足够长)
                if (len >= 8 + 4) { // nlmsghdr + genlmsghdr.cmd
                    var gn_family = buf.add(16).readU16(); // 假设 genlmsghdr 在 nlmsghdr 之后
                    // 这里需要知道 MACsec 的 Generic Netlink 族 ID，或者通过名称查找
                    // 假设你知道 MACsec 的 Generic Netlink 族名称 "macsec"
                    // 你可能需要在内核中找到对应的族 ID

                    // 更可靠的方法是解析 Generic Netlink 消息中的族名称
                    // 这需要更复杂的 Netlink 消息解析逻辑

                    // 简单的基于命令的判断
                    const MACSEC_GENL_NAME = "macsec";
                    const MACSEC_CMD_GET_TXSC = 0; // 替换为实际的命令值
                    const MACSEC_CMD_ADD_RXSC = 1;

                    var gnl_header_offset = 16; // 假设 Generic Netlink 头部偏移量
                    if (len > gnl_header_offset) {
                        var genl_cmd = buf.add(gnl_header_offset).readU8();
                        if (genl_cmd == MACSEC_CMD_GET_TXSC || genl_cmd == MACSEC_CMD_ADD_RXSC) {
                            console.log("sendto called with MACsec Netlink message!");
                            console.log("Socket FD:", sockfd);
                            console.log("Length:", len);
                            console.log("Command:", genl_cmd);
                            // 可以进一步解析 Netlink 消息内容
                        }
                    }
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

**解释 Frida Hook 代码:**

1. **`Interceptor.attach(Module.findExportByName(null, "sendto"), ...)`:**  Hook 了 `sendto` 系统调用。
2. **`onEnter: function(args)`:**  在 `sendto` 函数入口处执行。
3. **检查地址族:**  检查目标地址的地址族是否为 `AF_NETLINK`，以过滤出 Netlink 套接字。
4. **读取 Netlink 头部:**  尝试读取 Netlink 消息的头部信息。
5. **读取 Generic Netlink 头部:**  尝试读取 Generic Netlink 头部，并根据 `cmd` 字段判断是否是 MACsec 相关的消息。 **注意：这个示例中的 Generic Netlink 族 ID 和命令值的判断是简化的，实际需要更精确的解析。**
6. **输出信息:** 如果检测到可能是 MACsec 相关的 Netlink 消息，则输出相关信息。

**更精确的 Hook 方法:**

更精确的方法是 Hook Netlink 库 (`libnl`) 中的函数，例如 `genl_connect()`, `genl_send_msg()`, `nla_parse()` 等。这样可以更方便地获取和解析 Netlink 消息的内容，并确定是否与 MACsec 族相关。你需要根据具体的 Android 版本和使用的 Netlink 库来调整 Hook 代码。

总结来说，虽然 Framework 和 NDK 不会直接操作这个头文件，但底层的系统服务在配置 MACsec 时会间接地使用到它，通过 Netlink 接口与内核交互。Frida 可以用来 Hook 相关的系统调用或库函数，以观察和调试这些交互过程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/if_macsec.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_MACSEC_H
#define _UAPI_MACSEC_H
#include <linux/types.h>
#define MACSEC_GENL_NAME "macsec"
#define MACSEC_GENL_VERSION 1
#define MACSEC_MAX_KEY_LEN 128
#define MACSEC_KEYID_LEN 16
#define MACSEC_SALT_LEN 12
#define MACSEC_CIPHER_ID_GCM_AES_128 0x0080C20001000001ULL
#define MACSEC_CIPHER_ID_GCM_AES_256 0x0080C20001000002ULL
#define MACSEC_CIPHER_ID_GCM_AES_XPN_128 0x0080C20001000003ULL
#define MACSEC_CIPHER_ID_GCM_AES_XPN_256 0x0080C20001000004ULL
#define MACSEC_DEFAULT_CIPHER_ID 0x0080020001000001ULL
#define MACSEC_DEFAULT_CIPHER_ALT MACSEC_CIPHER_ID_GCM_AES_128
#define MACSEC_MIN_ICV_LEN 8
#define MACSEC_MAX_ICV_LEN 32
#define MACSEC_STD_ICV_LEN 16
enum macsec_attrs {
  MACSEC_ATTR_UNSPEC,
  MACSEC_ATTR_IFINDEX,
  MACSEC_ATTR_RXSC_CONFIG,
  MACSEC_ATTR_SA_CONFIG,
  MACSEC_ATTR_SECY,
  MACSEC_ATTR_TXSA_LIST,
  MACSEC_ATTR_RXSC_LIST,
  MACSEC_ATTR_TXSC_STATS,
  MACSEC_ATTR_SECY_STATS,
  MACSEC_ATTR_OFFLOAD,
  __MACSEC_ATTR_END,
  NUM_MACSEC_ATTR = __MACSEC_ATTR_END,
  MACSEC_ATTR_MAX = __MACSEC_ATTR_END - 1,
};
enum macsec_secy_attrs {
  MACSEC_SECY_ATTR_UNSPEC,
  MACSEC_SECY_ATTR_SCI,
  MACSEC_SECY_ATTR_ENCODING_SA,
  MACSEC_SECY_ATTR_WINDOW,
  MACSEC_SECY_ATTR_CIPHER_SUITE,
  MACSEC_SECY_ATTR_ICV_LEN,
  MACSEC_SECY_ATTR_PROTECT,
  MACSEC_SECY_ATTR_REPLAY,
  MACSEC_SECY_ATTR_OPER,
  MACSEC_SECY_ATTR_VALIDATE,
  MACSEC_SECY_ATTR_ENCRYPT,
  MACSEC_SECY_ATTR_INC_SCI,
  MACSEC_SECY_ATTR_ES,
  MACSEC_SECY_ATTR_SCB,
  MACSEC_SECY_ATTR_PAD,
  __MACSEC_SECY_ATTR_END,
  NUM_MACSEC_SECY_ATTR = __MACSEC_SECY_ATTR_END,
  MACSEC_SECY_ATTR_MAX = __MACSEC_SECY_ATTR_END - 1,
};
enum macsec_rxsc_attrs {
  MACSEC_RXSC_ATTR_UNSPEC,
  MACSEC_RXSC_ATTR_SCI,
  MACSEC_RXSC_ATTR_ACTIVE,
  MACSEC_RXSC_ATTR_SA_LIST,
  MACSEC_RXSC_ATTR_STATS,
  MACSEC_RXSC_ATTR_PAD,
  __MACSEC_RXSC_ATTR_END,
  NUM_MACSEC_RXSC_ATTR = __MACSEC_RXSC_ATTR_END,
  MACSEC_RXSC_ATTR_MAX = __MACSEC_RXSC_ATTR_END - 1,
};
enum macsec_sa_attrs {
  MACSEC_SA_ATTR_UNSPEC,
  MACSEC_SA_ATTR_AN,
  MACSEC_SA_ATTR_ACTIVE,
  MACSEC_SA_ATTR_PN,
  MACSEC_SA_ATTR_KEY,
  MACSEC_SA_ATTR_KEYID,
  MACSEC_SA_ATTR_STATS,
  MACSEC_SA_ATTR_PAD,
  MACSEC_SA_ATTR_SSCI,
  MACSEC_SA_ATTR_SALT,
  __MACSEC_SA_ATTR_END,
  NUM_MACSEC_SA_ATTR = __MACSEC_SA_ATTR_END,
  MACSEC_SA_ATTR_MAX = __MACSEC_SA_ATTR_END - 1,
};
enum macsec_offload_attrs {
  MACSEC_OFFLOAD_ATTR_UNSPEC,
  MACSEC_OFFLOAD_ATTR_TYPE,
  MACSEC_OFFLOAD_ATTR_PAD,
  __MACSEC_OFFLOAD_ATTR_END,
  NUM_MACSEC_OFFLOAD_ATTR = __MACSEC_OFFLOAD_ATTR_END,
  MACSEC_OFFLOAD_ATTR_MAX = __MACSEC_OFFLOAD_ATTR_END - 1,
};
enum macsec_nl_commands {
  MACSEC_CMD_GET_TXSC,
  MACSEC_CMD_ADD_RXSC,
  MACSEC_CMD_DEL_RXSC,
  MACSEC_CMD_UPD_RXSC,
  MACSEC_CMD_ADD_TXSA,
  MACSEC_CMD_DEL_TXSA,
  MACSEC_CMD_UPD_TXSA,
  MACSEC_CMD_ADD_RXSA,
  MACSEC_CMD_DEL_RXSA,
  MACSEC_CMD_UPD_RXSA,
  MACSEC_CMD_UPD_OFFLOAD,
};
enum macsec_rxsc_stats_attr {
  MACSEC_RXSC_STATS_ATTR_UNSPEC,
  MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED,
  MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_USING_SA,
  MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNUSED_SA,
  MACSEC_RXSC_STATS_ATTR_PAD,
  __MACSEC_RXSC_STATS_ATTR_END,
  NUM_MACSEC_RXSC_STATS_ATTR = __MACSEC_RXSC_STATS_ATTR_END,
  MACSEC_RXSC_STATS_ATTR_MAX = __MACSEC_RXSC_STATS_ATTR_END - 1,
};
enum macsec_sa_stats_attr {
  MACSEC_SA_STATS_ATTR_UNSPEC,
  MACSEC_SA_STATS_ATTR_IN_PKTS_OK,
  MACSEC_SA_STATS_ATTR_IN_PKTS_INVALID,
  MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_VALID,
  MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_USING_SA,
  MACSEC_SA_STATS_ATTR_IN_PKTS_UNUSED_SA,
  MACSEC_SA_STATS_ATTR_OUT_PKTS_PROTECTED,
  MACSEC_SA_STATS_ATTR_OUT_PKTS_ENCRYPTED,
  __MACSEC_SA_STATS_ATTR_END,
  NUM_MACSEC_SA_STATS_ATTR = __MACSEC_SA_STATS_ATTR_END,
  MACSEC_SA_STATS_ATTR_MAX = __MACSEC_SA_STATS_ATTR_END - 1,
};
enum macsec_txsc_stats_attr {
  MACSEC_TXSC_STATS_ATTR_UNSPEC,
  MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED,
  MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED,
  MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED,
  MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED,
  MACSEC_TXSC_STATS_ATTR_PAD,
  __MACSEC_TXSC_STATS_ATTR_END,
  NUM_MACSEC_TXSC_STATS_ATTR = __MACSEC_TXSC_STATS_ATTR_END,
  MACSEC_TXSC_STATS_ATTR_MAX = __MACSEC_TXSC_STATS_ATTR_END - 1,
};
enum macsec_secy_stats_attr {
  MACSEC_SECY_STATS_ATTR_UNSPEC,
  MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED,
  MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI,
  MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN,
  MACSEC_SECY_STATS_ATTR_PAD,
  __MACSEC_SECY_STATS_ATTR_END,
  NUM_MACSEC_SECY_STATS_ATTR = __MACSEC_SECY_STATS_ATTR_END,
  MACSEC_SECY_STATS_ATTR_MAX = __MACSEC_SECY_STATS_ATTR_END - 1,
};
#endif

"""

```