Response:
Let's break down the thought process for answering the user's request about the `tc_em_meta.h` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this header file, its relationship to Android, explanations of any libc functions used, details about dynamic linking if relevant, potential errors, and how Android frameworks access this code, including a Frida hook example.

**2. Initial Analysis of the Header File:**

* **Auto-generated:**  This is the first and most important clue. It tells us this isn't something a developer *directly* interacts with often. Its purpose is primarily for kernel-level structures.
* **`#ifndef __LINUX_TC_EM_META_H`:**  Standard header guard, preventing multiple inclusions.
* **Includes:** `<linux/types.h>` and `<linux/pkt_cls.h>` indicate this is kernel-level code related to packet classification. This immediately suggests networking and traffic control.
* **Enums:** `TCA_EM_META_UNSPEC`, `TCA_EM_META_HDR`, etc., likely define constants used to identify different metadata types. The `TCA` prefix hints at Traffic Control Attributes.
* **`struct tcf_meta_val`:**  This structure seems to hold information about a single metadata value, with `kind`, `shift`, and `op` fields. The names suggest a type, bit manipulation, and possibly an operation.
* **Macros:** `TCF_META_TYPE_MASK`, `TCF_META_TYPE`, `TCF_META_ID_MASK`, `TCF_META_ID`. These are for extracting type and ID information from the `kind` field.
* **More Enums:** `TCF_META_TYPE_VAR`, `TCF_META_TYPE_INT` define metadata value types. The long list of `TCF_META_ID_*` enums is crucial. These define *specific* pieces of metadata the system can track (e.g., packet length, protocol, socket state, etc.).
* **`struct tcf_meta_hdr`:**  Combines two `tcf_meta_val` structures, suggesting a comparison or operation between two metadata values.

**3. Connecting to Android:**

* **Bionic:** The file path explicitly mentions "bionic," Android's C library. This confirms its direct relevance to Android's low-level system.
* **Traffic Shaping/QoS:** The filename "tc_ematch" strongly suggests Traffic Control (tc) and extended matching (ematch). This is a standard Linux kernel subsystem used for quality of service (QoS) and network traffic shaping. Android, being built on Linux, inherits this capability.
* **Android Use Cases (Hypothesizing):**  Based on the metadata IDs, it's reasonable to assume Android uses this for:
    * **Network Policy Enforcement:**  Limiting bandwidth for certain apps, prioritizing traffic.
    * **Firewalling:** Making decisions based on packet attributes (protocol, port).
    * **VPNs:**  Possibly examining encapsulated traffic.
    * **Debugging/Monitoring:**  Collecting network statistics.

**4. Addressing Specific Questions:**

* **Functionality:** Summarize the purpose of defining metadata structures and identifiers for traffic control filtering.
* **Android Relationship:** Explain the connection to Android's use of the Linux kernel's traffic control features. Provide concrete examples.
* **libc Functions:**  Acknowledge that *this specific header file* doesn't define libc functions. However, the *usage* of this data structure in the kernel's traffic control implementation would involve kernel functions. It's important to be precise.
* **Dynamic Linker:** Similarly, this header file itself doesn't directly involve the dynamic linker. However, if user-space tools were to *access* or *interpret* information related to traffic control, they would be dynamically linked. Provide a hypothetical scenario and a simple SO layout. Explain the linking process at a high level.
* **Logic/Assumptions:** The core logic is in the *kernel's traffic control implementation*. The header just defines the data structures. Provide a simple example of how these structures *could* be used for filtering.
* **Common Errors:** Focus on the user-space side. Incorrectly configuring `tc` commands is the most likely error.
* **Android Framework/NDK Access:**  This requires understanding how user-space interacts with kernel features. The sequence likely involves:
    1. Android Framework (Java/Kotlin) uses system services.
    2. System services make Binder calls to native daemons (written in C/C++ using the NDK).
    3. These daemons use netlink sockets to communicate with the kernel's traffic control subsystem.
    4. The kernel uses the data structures defined in this header.
* **Frida Hook:**  Provide a concrete example of hooking a function that likely interacts with these structures (e.g., a `tc` command-related syscall). Explain the hook's purpose and how it reveals information.

**5. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request clearly. Use headings and bullet points to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** "Maybe this file defines some helper functions for interacting with traffic control."
* **Correction:**  Realized it's primarily *data definitions* for the kernel. The *implementation* is elsewhere in the kernel source.
* **Initial Thought:** "Explain every detail of how the dynamic linker works."
* **Correction:** Focus on the *relevance* to this specific header. A high-level explanation of the linking process and a simple example are sufficient.
* **Initial Thought:** "Give a complex Frida hook example."
* **Correction:** Start with a simple hook that demonstrates the concept clearly.

By following this structured thought process, and constantly refining the understanding based on the file's contents and the user's questions, it's possible to generate a comprehensive and accurate answer.
## 对 `bionic/libc/kernel/uapi/linux/tc_ematch/tc_em_meta.h` 的功能分析

这个头文件 `tc_em_meta.h`  定义了 Linux 内核中用于流量控制（Traffic Control，TC）框架下扩展匹配器（Extended Match，ematch）的元数据（meta）相关的常量、枚举和结构体。由于它位于 `bionic/libc/kernel/uapi` 目录下，意味着它定义了用户空间程序可以通过系统调用等方式与内核交互时使用的数据结构。

**功能列举：**

1. **定义元数据属性类型：** 通过 `enum` 定义了元数据的不同属性类型，例如 `TCA_EM_META_HDR` (头部信息), `TCA_EM_META_LVALUE` (左值), `TCA_EM_META_RVALUE` (右值) 等。这些类型用于在配置流量策略时指定要匹配的元数据类别。
2. **定义元数据值的结构体：** `struct tcf_meta_val` 定义了单个元数据值的结构，包含 `kind`（类型和ID），`shift`（位移），`op`（操作）。
3. **定义元数据类型和ID：** 通过宏 `TCF_META_TYPE_MASK`, `TCF_META_TYPE`, `TCF_META_ID_MASK`, `TCF_META_ID` 定义了如何从 `kind` 字段中提取元数据的类型和ID信息。
4. **定义元数据的具体类型：** `enum` 定义了元数据的具体类型，例如 `TCF_META_TYPE_VAR` (变量), `TCF_META_TYPE_INT` (整数)。
5. **定义可匹配的元数据 ID：**  `enum` 定义了大量的 `TCF_META_ID_*` 常量，这些常量代表了内核可以提取并用于匹配的各种元数据信息，例如：
    * **通用信息：** `TCF_META_ID_VALUE` (固定值), `TCF_META_ID_RANDOM` (随机数)。
    * **系统负载：** `TCF_META_ID_LOADAVG_0`, `TCF_META_ID_LOADAVG_1`, `TCF_META_ID_LOADAVG_2` (系统平均负载)。
    * **网络设备：** `TCF_META_ID_DEV` (网络设备索引)。
    * **数据包属性：** `TCF_META_ID_PRIORITY` (优先级), `TCF_META_ID_PROTOCOL` (协议), `TCF_META_ID_PKTTYPE` (包类型), `TCF_META_ID_PKTLEN` (包长度), `TCF_META_ID_DATALEN` (数据长度), `TCF_META_ID_MACLEN` (MAC地址长度)。
    * **网络过滤/标记：** `TCF_META_ID_NFMARK` (netfilter 标记), `TCF_META_ID_TCINDEX` (TC 索引), `TCF_META_ID_RTCLASSID` (路由分类ID), `TCF_META_ID_RTIIF` (路由输入接口)。
    * **Socket 信息：** 大量的 `TCF_META_ID_SK_*` 常量，用于匹配 socket 的各种属性，例如：`TCF_META_ID_SK_FAMILY` (地址族), `TCF_META_ID_SK_STATE` (状态), `TCF_META_ID_SK_REUSE` (地址重用), `TCF_META_ID_SK_RCVBUF` (接收缓冲区大小) 等等。
    * **VLAN 信息：** `TCF_META_ID_VLAN_TAG` (VLAN 标签)。
    * **接收哈希：** `TCF_META_ID_RXHASH` (接收哈希值)。
6. **定义元数据头结构体：** `struct tcf_meta_hdr` 包含两个 `tcf_meta_val` 结构体 `left` 和 `right`，用于表示需要比较的两个元数据值。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android 底层网络功能实现的基础组成部分。Android 利用 Linux 内核的流量控制机制来实现：

* **网络策略控制：** Android 可以使用 TC 来限制特定应用的网络带宽使用，或者为某些类型的网络流量（例如 VoIP）设置更高的优先级。 `tc_em_meta.h` 中定义的元数据 ID，如 `TCF_META_ID_SK_UID` (虽然这个头文件中没有直接定义，但类似的 socket 相关的属性会被用到)，可以用于根据应用的用户 ID 进行流量控制。
* **防火墙规则：** 虽然 Android 的防火墙功能主要由 `iptables` 或 `nftables` 实现，但 TC 也可以用于实现更细粒度的流量过滤和策略。例如，可以根据 `TCF_META_ID_PROTOCOL` 来阻止特定协议的流量。
* **QoS (Quality of Service)：** Android 可以使用 TC 来保证某些关键应用的网络体验，例如在网络拥塞时优先处理语音或视频通话的数据包。这可以通过匹配 `TCF_META_ID_PRIORITY` 或其他包属性来实现。
* **VPN 连接管理：**  当 Android 设备连接 VPN 时，TC 可以用于管理 VPN 连接的网络流量，例如根据 `TCF_META_ID_RTIIF` (路由输入接口) 来区分 VPN 流量和普通流量。

**举例说明：**

假设 Android 系统想要限制某个后台应用的带宽使用。这可能涉及到以下步骤：

1. **用户空间配置：** Android 的网络管理服务或特定的应用可能会通过 Netlink socket 向内核发送配置命令。这些命令会指定要创建的 TC 规则。
2. **规则定义：** 这些规则会使用 `tc_ematch` 来定义匹配条件。例如，使用 `TCA_EM_META_LVALUE` 和 `TCA_EM_META_RVALUE` 来比较 `TCF_META_ID_SK_UID` 的值是否等于目标应用的 UID。
3. **内核执行：** 当网络数据包经过网络接口时，内核的 TC 代码会根据配置的规则进行匹配。`tc_ematch` 模块会提取数据包的 socket 关联信息，并根据 `tc_em_meta.h` 中定义的 ID 来获取 UID。
4. **策略应用：** 如果匹配成功，内核会应用相应的策略，例如限制该应用的发送速率。

**libc 函数的功能实现：**

这个头文件本身**没有定义任何 libc 函数**。它只是定义了内核数据结构的布局。libc 函数是 C 标准库提供的函数，例如 `malloc`, `printf`, `socket` 等。

然而，用户空间的程序（例如 Android 的网络管理服务）会使用 libc 提供的网络相关的系统调用接口（例如 `socket`, `bind`, `sendto`, `recvfrom`）以及与 Netlink socket 交互的库函数来配置和管理 TC 策略。这些 libc 函数的实现涉及到：

* **系统调用：** libc 函数通常是对系统调用的封装。例如，`socket` 函数会调用内核的 `sys_socket` 系统调用来创建一个 socket 文件描述符。
* **参数传递：** libc 函数负责将用户空间传递的参数转换为内核能够理解的格式，并传递给相应的系统调用。
* **错误处理：** libc 函数会检查系统调用的返回值，并根据错误码设置 `errno` 变量，方便用户空间程序进行错误处理。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`tc_em_meta.h` 本身并不直接涉及 dynamic linker。Dynamic linker（在 Android 上是 `linker64` 或 `linker`）负责在程序运行时加载和链接共享库（.so 文件）。

**虽然 `tc_em_meta.h` 不直接参与动态链接，但使用 TC 功能的用户空间程序会使用动态链接的共享库。**  例如，Android 的 `ip` 命令或者网络管理服务可能会链接到 `libc.so` 以及其他可能包含 Netlink 交互功能的共享库。

**so 布局样本：**

假设一个名为 `libnetcontrol.so` 的共享库，它封装了与内核 TC 功能交互的逻辑。

```
libnetcontrol.so:
    .text        # 代码段
        - 函数A (调用 Netlink API 配置 TC)
        - 函数B (处理 TC 相关的错误)
    .data        # 已初始化数据段
        - 全局变量 C
    .bss         # 未初始化数据段
        - 全局变量 D
    .dynamic     # 动态链接信息
        - DT_NEEDED (依赖 libc.so)
        - DT_SONAME (libnetcontrol.so)
        - ...
    .symtab      # 符号表
        - 函数A 的符号信息
        - 函数B 的符号信息
        - 全局变量 C 的符号信息
    .strtab      # 字符串表
        - 函数名、变量名等字符串
    .rel.dyn     # 动态重定位表
        - 需要在运行时重定位的符号信息 (例如对 libc.so 中函数的引用)
    .rel.plt     # PLT (Procedure Linkage Table) 重定位表
        - 用于延迟绑定的函数调用
```

**链接的处理过程：**

1. **加载器启动：** 当 Android 启动一个使用 `libnetcontrol.so` 的进程时，内核会加载该进程的 ELF 可执行文件。
2. **动态链接器加载：**  ELF 文件头会指示动态链接器的位置，内核会加载动态链接器 (`linker64` 或 `linker`)。
3. **解析依赖：** 动态链接器会解析 `libnetcontrol.so` 的 `.dynamic` 段，找到其依赖的共享库（例如 `libc.so`）。
4. **加载依赖库：** 动态链接器会加载 `libc.so` 到进程的地址空间。
5. **符号解析和重定位：** 动态链接器会遍历 `libnetcontrol.so` 的重定位表 (`.rel.dyn` 和 `.rel.plt`)。
    * 对于 `.rel.dyn` 中的符号，动态链接器会查找这些符号在已加载的共享库中的地址，并更新 `libnetcontrol.so` 中对应位置的地址。例如，如果 `libnetcontrol.so` 中调用了 `libc.so` 中的 `socket` 函数，动态链接器会找到 `socket` 函数的地址并写入。
    * 对于 `.rel.plt` 中的符号，会使用延迟绑定机制。第一次调用这些函数时，会触发动态链接器进行符号解析和地址绑定。后续调用将直接跳转到已绑定的地址。
6. **执行程序：** 动态链接完成后，进程开始执行。`libnetcontrol.so` 中的代码就可以调用 `libc.so` 中提供的函数，例如进行 Netlink 通信。

**逻辑推理，假设输入与输出：**

假设用户空间程序想要获取当前网络接口 "eth0" 的设备索引 (`TCF_META_ID_DEV`)。

**假设输入：**

* 用户空间程序通过 Netlink socket 向内核发送一个请求，该请求指示要使用 `tc_ematch` 匹配器，并获取类型为 `TCA_EM_META_LVALUE`，且 `left.kind` 为 `TCF_META_ID_DEV` 的元数据值。
* 当前系统存在名为 "eth0" 的网络接口，其设备索引在内核中为 2。

**逻辑推理：**

1. 内核接收到 Netlink 请求。
2. 内核的 TC 子系统解析请求，识别出需要获取 `TCF_META_ID_DEV` 的值。
3. 内核查找网络接口 "eth0" 的相关信息，获取其设备索引。
4. 内核将设备索引值（2）封装到 Netlink 响应消息中。

**假设输出：**

* 用户空间程序通过 Netlink socket 接收到内核的响应。
* 响应消息中包含 `TCA_EM_META_LVALUE` 类型的数据，其中 `left.kind` 为 `TCF_META_ID_DEV`，并且包含一个表示设备索引的整数值 `2`。

**用户或编程常见的使用错误：**

1. **错误的 `kind` 值：** 在配置 TC 规则时，如果 `tcf_meta_val` 结构体中的 `kind` 值设置错误，例如使用了不存在的 `TCF_META_ID_*` 常量，会导致内核无法识别要匹配的元数据，从而导致规则不生效或报错。
    ```c
    struct tcf_meta_val val = {
        .kind = 0xFFFF, // 错误的 kind 值
        .shift = 0,
        .op = 0
    };
    ```
2. **位移 (`shift`) 使用不当：**  某些元数据值可能由多个位域组成。如果 `shift` 值设置不正确，可能无法提取到期望的位域值。
3. **操作符 (`op`) 使用错误：**  `op` 字段定义了如何比较元数据值。使用错误的操作符会导致匹配逻辑错误。
4. **类型不匹配：** 尝试将一个预期为整数类型的元数据与字符串进行比较，或者进行其他类型不匹配的操作。
5. **没有理解不同 `TCF_META_ID_*` 的含义：** 错误地使用了某个 `TCF_META_ID_*`，例如本来想匹配数据包长度，却使用了 socket 接收缓冲区大小的 ID。
6. **在不支持的上下文中使用特定的 `TCF_META_ID_*`：** 某些元数据 ID 可能只在特定的 TC 匹配器或过滤器中有效。在不适用的上下文中尝试使用会导致错误。

**Android Framework 或 NDK 如何一步步的到达这里，给出 Frida hook 示例调试这些步骤：**

1. **Android Framework (Java/Kotlin)：** 用户或系统操作触发网络策略的变更，例如应用请求网络访问权限，或者系统根据电量状态调整网络策略。
2. **System Server (Java)：** Framework 将这些请求传递给 System Server 中的网络管理相关服务（例如 `ConnectivityService`, `NetworkPolicyManagerService`）。
3. **Native Daemon (C++)：** System Server 通过 Binder IPC 调用 Native Daemon，例如 `netd` (network daemon)。
4. **Netlink Socket Communication (C++)：** `netd` 使用 Netlink socket 与 Linux 内核的 TC 子系统进行通信。它会构建包含 TC 配置信息的 Netlink 消息。
5. **内核 TC 子系统：** 内核接收到 Netlink 消息，解析其中的 TC 配置信息，包括使用 `tc_ematch` 匹配器和其中定义的元数据匹配规则。在解析过程中，内核会读取 `tc_em_meta.h` 中定义的常量和结构体。

**Frida Hook 示例：**

我们可以 Hook `libc.so` 中用于发送 Netlink 消息的 `sendto` 函数，来观察 Android 是如何向内核发送 TC 配置信息的。

```python
import frida
import sys

package_name = "com.android.shell"  # 或者其他可能配置 TC 的进程

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Sending Netlink message:")
        # 假设 Netlink 消息内容包含 TC 配置信息
        try:
            payload = bytes(data).decode('utf-8', errors='ignore')
            print(payload)
        except Exception as e:
            print(f"[!] Error decoding payload: {e}")

session = frida.attach(package_name)

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
    onEnter: function(args) {
        const sockfd = args[0].toInt32();
        const buf = args[1];
        const len = args[2].toInt32();
        const flags = args[3].toInt32();
        const addr = args[4];
        const addrlen = args[5].toInt32();

        // 判断是否是 Netlink socket (通常地址族为 AF_NETLINK)
        if (addr.isNull() === false) {
            const sa_family = ptr(addr).readU16();
            if (sa_family === 16) { // 16 corresponds to AF_NETLINK
                this.data = Memory.readByteArray(buf, len);
                send({type: 'send'}, this.data);
            }
        }
    }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 解释：**

1. **`frida.attach(package_name)`:**  连接到目标 Android 进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "sendto"), ...)`:** Hook `libc.so` 中的 `sendto` 函数。`sendto` 是一个通用的发送数据报的系统调用，Netlink socket 也使用它。
3. **`onEnter: function(args)`:**  在 `sendto` 函数调用之前执行。
4. **参数解析：** 获取 `sendto` 函数的参数，包括 socket 文件描述符、发送缓冲区地址和长度等。
5. **判断 Netlink Socket：** 通过检查目标地址的地址族是否为 `AF_NETLINK` (通常为 16) 来判断是否是 Netlink socket 的发送。
6. **读取数据：** 如果是 Netlink socket，则读取发送缓冲区的内容。
7. **`send({type: 'send'}, this.data)`:** 将读取到的数据发送回 Frida 客户端。
8. **`script.on('message', on_message)`:**  注册消息处理函数，用于接收来自 Hook 代码的消息。
9. **`on_message(message, data)`:** 打印接收到的 Netlink 消息内容。

通过运行这个 Frida 脚本，我们可以观察到目标进程在进行网络配置时，通过 `sendto` 函数向内核发送的 Netlink 消息内容。这些消息可能包含与 TC 相关的配置信息，我们可以进一步分析这些消息，了解 Android 如何使用 `tc_ematch` 和 `tc_em_meta.h` 中定义的结构体来配置流量策略。

**总结：**

`tc_em_meta.h` 是 Android 底层网络流量控制的关键组成部分，定义了用于扩展匹配器的元数据结构和标识符。理解这个头文件有助于深入了解 Android 的网络策略管理和 QoS 实现机制。虽然它本身不包含 libc 函数或直接涉及 dynamic linker，但与用户空间程序和内核的交互密切相关，并通过动态链接的共享库来实现功能。 通过 Frida Hook 我们可以动态地观察 Android 系统如何利用这些底层的机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/tc_ematch/tc_em_meta.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_TC_EM_META_H
#define __LINUX_TC_EM_META_H
#include <linux/types.h>
#include <linux/pkt_cls.h>
enum {
  TCA_EM_META_UNSPEC,
  TCA_EM_META_HDR,
  TCA_EM_META_LVALUE,
  TCA_EM_META_RVALUE,
  __TCA_EM_META_MAX
};
#define TCA_EM_META_MAX (__TCA_EM_META_MAX - 1)
struct tcf_meta_val {
  __u16 kind;
  __u8 shift;
  __u8 op;
};
#define TCF_META_TYPE_MASK (0xf << 12)
#define TCF_META_TYPE(kind) (((kind) & TCF_META_TYPE_MASK) >> 12)
#define TCF_META_ID_MASK 0x7ff
#define TCF_META_ID(kind) ((kind) & TCF_META_ID_MASK)
enum {
  TCF_META_TYPE_VAR,
  TCF_META_TYPE_INT,
  __TCF_META_TYPE_MAX
};
#define TCF_META_TYPE_MAX (__TCF_META_TYPE_MAX - 1)
enum {
  TCF_META_ID_VALUE,
  TCF_META_ID_RANDOM,
  TCF_META_ID_LOADAVG_0,
  TCF_META_ID_LOADAVG_1,
  TCF_META_ID_LOADAVG_2,
  TCF_META_ID_DEV,
  TCF_META_ID_PRIORITY,
  TCF_META_ID_PROTOCOL,
  TCF_META_ID_PKTTYPE,
  TCF_META_ID_PKTLEN,
  TCF_META_ID_DATALEN,
  TCF_META_ID_MACLEN,
  TCF_META_ID_NFMARK,
  TCF_META_ID_TCINDEX,
  TCF_META_ID_RTCLASSID,
  TCF_META_ID_RTIIF,
  TCF_META_ID_SK_FAMILY,
  TCF_META_ID_SK_STATE,
  TCF_META_ID_SK_REUSE,
  TCF_META_ID_SK_BOUND_IF,
  TCF_META_ID_SK_REFCNT,
  TCF_META_ID_SK_SHUTDOWN,
  TCF_META_ID_SK_PROTO,
  TCF_META_ID_SK_TYPE,
  TCF_META_ID_SK_RCVBUF,
  TCF_META_ID_SK_RMEM_ALLOC,
  TCF_META_ID_SK_WMEM_ALLOC,
  TCF_META_ID_SK_OMEM_ALLOC,
  TCF_META_ID_SK_WMEM_QUEUED,
  TCF_META_ID_SK_RCV_QLEN,
  TCF_META_ID_SK_SND_QLEN,
  TCF_META_ID_SK_ERR_QLEN,
  TCF_META_ID_SK_FORWARD_ALLOCS,
  TCF_META_ID_SK_SNDBUF,
  TCF_META_ID_SK_ALLOCS,
  __TCF_META_ID_SK_ROUTE_CAPS,
  TCF_META_ID_SK_HASH,
  TCF_META_ID_SK_LINGERTIME,
  TCF_META_ID_SK_ACK_BACKLOG,
  TCF_META_ID_SK_MAX_ACK_BACKLOG,
  TCF_META_ID_SK_PRIO,
  TCF_META_ID_SK_RCVLOWAT,
  TCF_META_ID_SK_RCVTIMEO,
  TCF_META_ID_SK_SNDTIMEO,
  TCF_META_ID_SK_SENDMSG_OFF,
  TCF_META_ID_SK_WRITE_PENDING,
  TCF_META_ID_VLAN_TAG,
  TCF_META_ID_RXHASH,
  __TCF_META_ID_MAX
};
#define TCF_META_ID_MAX (__TCF_META_ID_MAX - 1)
struct tcf_meta_hdr {
  struct tcf_meta_val left;
  struct tcf_meta_val right;
};
#endif
```