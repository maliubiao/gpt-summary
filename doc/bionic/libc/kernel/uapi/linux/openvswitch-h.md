Response:
Let's break down the thought process for analyzing this kernel header file.

**1. Understanding the Context:**

The first crucial step is understanding the "where" and "what." The prompt tells us:

* **Location:** `bionic/libc/kernel/uapi/linux/openvswitch.h`
* **Purpose:** Part of Android's Bionic library, specifically related to kernel UAPI. This immediately tells us we're dealing with the interface between user-space (Android apps/services) and the Linux kernel's Open vSwitch (OVS) module.
* **Nature:**  "auto-generated." This means we're looking at data structures and definitions primarily for communication, not implementation logic within Bionic itself. The comment about losing modifications reinforces this.

**2. Identifying Core Functionality (High-Level):**

The filename `openvswitch.h` and the defined constants like `OVS_DATAPATH_FAMILY`, `OVS_VPORT_FAMILY`, `OVS_FLOW_FAMILY`, etc., strongly suggest the file defines the data structures and communication protocols for interacting with the OVS kernel module. The "families" represent different aspects of OVS that user-space can control.

**3. Deconstructing the Contents (Line by Line):**

Now, we go through the file systematically, focusing on key elements:

* **Includes:** `#include <linux/types.h>` and `#include <linux/if_ether.h>` indicate dependencies on standard Linux kernel types and Ethernet definitions. This confirms we're in a kernel context.
* **Structures:**  `struct ovs_header`, `struct ovs_dp_stats`, etc. These are the building blocks for exchanging data. We note the types of data they hold (counters, IDs, flags, addresses).
* **Defines:** `#define OVS_DATAPATH_FAMILY ...`, `#define OVS_DP_VER_FEATURES ...`. These define constants, often related to naming conventions, versions, and bit flags.
* **Enums:** `enum ovs_datapath_cmd`, `enum ovs_datapath_attr`, etc. Enums define sets of related constants, typically used for commands, attributes, and types. These are crucial for understanding the available operations and parameters.

**4. Categorizing Functionality:**

As we analyze the structures and enums, we start grouping them by their associated "family":

* **Datapath:**  Managing the OVS datapath (the core switching fabric). Commands like `NEW`, `DEL`, `GET`, `SET`. Attributes like `NAME`, `UPCALL_PID`, `STATS`.
* **Packet:** Handling individual packets. Commands like `MISS`, `ACTION`, `EXECUTE`. Attributes like `PACKET`, `KEY`, `ACTIONS`.
* **VPort:** Managing virtual ports. Commands like `NEW`, `DEL`, `GET`, `SET`. Attributes like `PORT_NO`, `TYPE`, `NAME`.
* **Flow:** Managing flow rules. Commands like `NEW`, `DEL`, `GET`, `SET`. Attributes like `KEY`, `ACTIONS`, `STATS`. The nested `ovs_key_...` and `ovs_action_...` structures are key here.
* **Meter:**  Implementing traffic shaping/policing. Commands like `SET`, `DEL`, `GET`. Attributes like `ID`, `KBPS`, `BANDS`.
* **CT Limit:** Managing connection tracking limits. Commands like `SET`, `DEL`, `GET`. Attributes like `ZONE_LIMIT`.

**5. Connecting to Android:**

The key here is recognizing that this file defines the *interface* to OVS. Android itself doesn't *implement* OVS within Bionic. Instead, it uses this interface to communicate with the OVS kernel module. This communication likely happens through Netlink sockets, a standard Linux mechanism for kernel-userspace communication.

* **Examples:**  Android might use this interface for network virtualization features, container networking, or even advanced Wi-Fi features that require sophisticated packet processing.

**6. Addressing Specific Prompt Requirements:**

* **libc functions:**  This header file *defines* structures and constants. It doesn't contain *implementations* of libc functions. The relevant libc functions would be related to interacting with Netlink sockets (`socket`, `bind`, `sendto`, `recvfrom`, etc.).
* **Dynamic Linker:**  This file doesn't directly involve the dynamic linker. However, user-space libraries that interact with OVS *would* be linked. A simple example SO would be a library containing functions to construct and send Netlink messages based on these definitions.
* **Logic/Assumptions:**  The analysis involves logical deduction based on the naming and structure of the definitions. We assume the names are indicative of their purpose (e.g., `OVS_DP_CMD_NEW` likely creates a new datapath).
* **Common Errors:**  Misinterpreting the meaning of attributes, sending invalid commands, or constructing incorrect Netlink messages are common errors.
* **Android Framework/NDK:**  We trace the path from higher-level Android APIs down to potential Netlink socket calls. The NDK provides access to lower-level Linux APIs.
* **Frida Hook:**  We suggest hooking Netlink functions as this is the likely communication mechanism.

**7. Structuring the Response:**

Finally, we organize the information in a clear and structured way, addressing each point of the prompt:

* **功能 (Functionality):**  List the core capabilities based on the identified "families."
* **与 Android 的关系 (Relationship with Android):** Explain the interface nature and provide concrete examples of Android features that might use OVS.
* **libc 函数 (libc functions):**  Explain that this file is a header and point to the relevant libc functions for Netlink communication.
* **Dynamic Linker:** Explain the indirect relationship and provide a simple SO example and the linking process.
* **逻辑推理 (Logic/Assumptions):** Briefly explain the reasoning behind the interpretation of the definitions.
* **常见错误 (Common Errors):**  Provide examples of typical mistakes developers might make.
* **Android Framework/NDK:** Detail the likely path from Android APIs to this header file and Netlink.
* **Frida Hook:**  Provide a practical Frida example for intercepting Netlink communication.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe this file contains actual C code.
* **Correction:**  The `/* This file is auto-generated... */` comment immediately refutes this. It's a header file defining the *interface*.
* **Initial Thought:**  Focus on internal Bionic implementation.
* **Correction:**  The `uapi` in the path signifies "user-space API" to the kernel. The focus should be on the communication interface.
* **Refinement:**  Initially, I might just list the enums and structs. But by grouping them by "family," the explanation becomes much clearer and easier to understand.

By following this detailed thought process, we can effectively analyze kernel header files like this and provide a comprehensive and accurate explanation.
这个文件 `bionic/libc/kernel/uapi/linux/openvswitch.h` 是 Android 系统中用于定义与 Linux 内核 Open vSwitch (OVS) 模块进行用户空间通信的接口头文件。它不包含任何 C 代码的实现，而是定义了一系列结构体、枚举和宏，用于在用户空间程序和内核 OVS 模块之间传递信息。

**功能列举:**

这个头文件定义了以下主要功能相关的结构体、枚举和宏：

1. **数据通路 (Datapath) 管理:**
   - 定义了创建、删除、获取和设置 OVS 数据通路的命令 (`enum ovs_datapath_cmd`)。
   - 定义了数据通路的属性，如名称、upcall 进程 ID、统计信息、巨流 (megaflow) 统计信息、用户特性等 (`enum ovs_datapath_attr`)。
   - 定义了数据通路的统计信息结构体 (`struct ovs_dp_stats`, `struct ovs_dp_megaflow_stats`)，包括命中数、未命中数、丢失数和流的数量等。
   - 定义了数据通路的特性标志 (`#define OVS_DP_F_UNALIGNED`, `#define OVS_DP_F_VPORT_PIDS` 等)。

2. **数据包 (Packet) 处理:**
   - 定义了处理数据包的命令，例如上报未匹配的数据包 (MISS)、执行动作 (ACTION)、执行特定操作 (EXECUTE) (`enum ovs_packet_cmd`)。
   - 定义了数据包相关的属性，如数据包内容、匹配关键字、执行的动作、用户数据等 (`enum ovs_packet_attr`)。

3. **虚拟端口 (VPort) 管理:**
   - 定义了创建、删除、获取和设置虚拟端口的命令 (`enum ovs_vport_cmd`)。
   - 定义了虚拟端口的类型，例如网络设备、内部端口、GRE、VXLAN、GENEVE 等隧道端口 (`enum ovs_vport_type`)。
   - 定义了虚拟端口的属性，如端口号、类型、名称、选项、upcall 进程 ID、统计信息等 (`enum ovs_vport_attr`)。
   - 定义了虚拟端口的统计信息结构体 (`struct ovs_vport_stats`)，包括收发包数量、字节数、错误数和丢包数等。

4. **流表 (Flow) 管理:**
   - 定义了创建、删除、获取和设置流表项的命令 (`enum ovs_flow_cmd`)。
   - 定义了流表项的匹配关键字属性 (`enum ovs_key_attr`)，包括以太网头部信息、VLAN 信息、IP 头部信息（IPv4 和 IPv6）、TCP/UDP/ICMP 信息、ARP/ND 信息、隧道信息、连接跟踪 (conntrack) 信息等。
   - 定义了流表项的统计信息结构体 (`struct ovs_flow_stats`)，包括匹配的包和字节数。
   - 定义了流表项的动作属性 (`enum ovs_action_attr`)，包括输出到端口、发送到用户空间、设置字段、推送/弹出 VLAN/MPLS 标签、采样、重定向、执行连接跟踪操作、丢弃数据包等。

5. **计量器 (Meter) 管理:**
   - 定义了获取计量器特性、设置、删除和获取计量器的命令 (`enum ovs_meter_cmd`)。
   - 定义了计量器的属性，如 ID、速率限制、统计信息、带宽信息等 (`enum ovs_meter_attr`)。
   - 定义了带宽的属性，如类型（例如丢弃）、速率、突发大小等 (`enum ovs_band_attr`)。

6. **连接跟踪限制 (Conntrack Limit) 管理:**
   - 定义了设置、删除和获取连接跟踪限制的命令 (`enum ovs_ct_limit_cmd`)。
   - 定义了连接跟踪限制的属性，例如区域限制 (`enum ovs_ct_limit_attr`)。

**与 Android 功能的关系举例说明:**

Open vSwitch 在 Android 系统中主要用于支持网络虚拟化和容器化等高级网络功能。Android 系统可能使用 OVS 来实现以下功能：

* **容器网络:**  在 Android 容器化方案 (例如使用 LXC 或 Docker) 中，OVS 可以作为虚拟交换机，连接不同的容器，提供隔离的网络环境，并支持复杂的网络策略。例如，可以使用 OVS 创建不同的 bridge，将容器连接到不同的网络，或者配置 VLAN 来隔离容器网络。
* **网络命名空间隔离:** Android 使用 Linux 网络命名空间来实现进程级别的网络隔离。OVS 可以与网络命名空间协同工作，为不同的命名空间创建独立的虚拟网络环境。
* **流量控制和 QoS:**  OVS 的计量器 (Meter) 功能可以用于实现流量控制和 Quality of Service (QoS)，限制特定虚拟机或容器的网络带宽，或者对不同类型的网络流量进行优先级划分。
* **虚拟网络功能 (VNF):**  在更高级的应用场景中，Android 设备可能作为虚拟网络功能 (VNF) 的宿主，OVS 可以负责 VNF 之间的网络连接和流量转发。

**libc 函数的功能实现解释:**

这个头文件本身不包含 libc 函数的实现。它只是定义了与内核模块通信的数据结构和接口。用户空间程序（包括 Android 的 Framework 和 NDK 应用）需要使用 **Netlink Socket** 这一 Linux 内核提供的机制与 OVS 内核模块进行通信。

以下是一些可能涉及的 libc 函数以及它们的功能：

* **`socket()`:**  用于创建一个 Netlink Socket。需要指定地址族为 `AF_NETLINK`，协议为 `NETLINK_GENERIC` 或特定的 OVS 相关的协议族（虽然这里定义了 `OVS_DATAPATH_FAMILY` 等字符串，但实际通信可能使用更底层的 Netlink 协议）。
* **`bind()`:**  将 Netlink Socket 绑定到特定的本地地址。对于与内核模块通信，通常需要绑定到进程 ID 或使用 `0` 来表示由内核分配。
* **`sendto()`:**  用于向 Netlink Socket 发送消息。发送的消息需要按照这个头文件中定义的结构体进行构造，例如，创建一个 `struct nlmsghdr` 类型的消息头，后面跟随具体的 OVS 命令和属性数据。
* **`recvfrom()`:**  用于从 Netlink Socket 接收消息。接收到的消息同样需要按照定义的结构体进行解析，以获取 OVS 模块的响应。
* **`close()`:** 关闭 Netlink Socket。

**详细实现解释:**

用户空间程序需要构造符合 Netlink 协议规范的消息，其中包含 OVS 定义的命令和属性。例如，要创建一个新的 OVS 数据通路，程序需要：

1. 创建一个 Netlink Socket。
2. 构造一个 Netlink 消息：
   - 设置消息头 `nlmsghdr`，指定消息类型为 `RTM_NEWLINK`（这是一个通用的 Netlink 消息类型，用于创建网络设备）。
   - 在消息数据部分，添加一个泛型 Netlink 头部 `genlmsghdr`，指定命令为 `OVS_DP_CMD_NEW`。
   - 继续添加 Netlink 属性 (NLA) 结构，每个属性包含属性类型和属性值。例如，添加 `OVS_DP_ATTR_NAME` 属性，并设置数据通路的名称。
3. 使用 `sendto()` 将构造好的 Netlink 消息发送到内核。
4. 内核中的 OVS 模块接收到消息，解析 Netlink 头部、泛型 Netlink 头部和 OVS 属性，执行相应的操作（创建数据通路）。
5. OVS 模块可能会通过 Netlink Socket 发送一个响应消息给用户空间程序，指示操作是否成功。

**涉及 dynamic linker 的功能 (实际上此文件不直接涉及 dynamic linker):**

这个头文件定义的是内核接口，不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 负责在程序启动时加载和链接共享库 (`.so` 文件)。

然而，用户空间程序如果需要使用这个头文件中定义的接口与 OVS 内核模块通信，通常会使用一些辅助库来简化 Netlink 通信的编写。这些辅助库可能会以 `.so` 文件的形式存在，需要在程序启动时由 dynamic linker 加载。

**so 布局样本:**

假设有一个名为 `libovsclient.so` 的共享库，用于封装与 OVS 通信的细节。它的布局可能如下：

```
libovsclient.so:
  .text:  # 代码段，包含实现 Netlink 通信的函数，例如创建数据通路、添加流表等
    - ovs_dp_create()
    - ovs_flow_add()
    - ...
  .data:  # 数据段，可能包含一些全局变量
    - ...
  .rodata: # 只读数据段，可能包含一些常量字符串
    - OVS_DATAPATH_FAMILY
    - ...
  .dynsym: # 动态符号表，包含导出的函数符号
    - ovs_dp_create
    - ovs_flow_add
    - ...
  .dynstr: # 动态字符串表，包含符号名称
    - ovs_dp_create
    - ...
  .plt:   # 程序链接表
  .got:   # 全局偏移表
  ...
```

**链接的处理过程:**

1. **编译时:** 开发者在编译应用程序时，需要链接 `libovsclient.so`。编译器会将对 `libovsclient.so` 中函数的调用生成相应的指令，并记录需要链接的符号。
2. **加载时:** 当 Android 系统启动应用程序时，dynamic linker 会解析应用程序的可执行文件头，找到需要加载的共享库列表（在这个例子中是 `libovsclient.so`）。
3. **查找共享库:** dynamic linker 会在预定义的路径中查找 `libovsclient.so` 文件。
4. **加载共享库:** dynamic linker 将 `libovsclient.so` 加载到内存中。
5. **符号解析 (Symbol Resolution):** dynamic linker 会解析 `libovsclient.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，找到应用程序中调用的函数在 `libovsclient.so` 中的地址。
6. **重定位 (Relocation):** dynamic linker 会修改应用程序和 `libovsclient.so` 中的一些指令和数据，以确保函数调用和全局变量访问指向正确的内存地址。例如，会更新程序链接表 (`.plt`) 和全局偏移表 (`.got`) 中的条目。

**逻辑推理的假设输入与输出:**

假设用户空间程序想要创建一个名为 "br0" 的 OVS 数据通路。

**假设输入:**

* 命令: `OVS_DP_CMD_NEW`
* 属性: `OVS_DP_ATTR_NAME`, 值为 "br0"

**输出 (内核行为):**

* 内核接收到 Netlink 消息，解析出创建数据通路的命令和名称属性。
* 内核创建一个新的 OVS 数据通路实例，名称为 "br0"。
* 内核可能会发送一个 Netlink 响应消息，指示创建成功，并可能包含新创建的数据通路的 index (例如 `dp_ifindex`)。

**用户或编程常见的使用错误举例说明:**

1. **Netlink 消息构造错误:**  没有正确设置 Netlink 消息头、泛型 Netlink 头部或 OVS 属性结构，导致内核无法解析消息。例如，忘记设置属性长度，或者属性类型和值不匹配。
2. **权限问题:**  执行需要 root 权限的 OVS 操作，例如创建数据通路或修改流表，但程序没有足够的权限。
3. **并发访问冲突:** 多个进程或线程同时修改 OVS 的配置，可能导致数据不一致或内核错误。
4. **错误的属性值:**  为 OVS 属性设置了无效的值，例如，尝试创建一个名称过长的数据通路，或者为端口号设置了超出范围的值。
5. **忘记处理 Netlink 错误:**  用户空间程序没有检查 `recvfrom()` 的返回值，或者没有解析 Netlink 消息中的错误信息，导致程序无法正确处理 OVS 操作失败的情况。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework 或应用层 API:**  Android Framework 或应用层可能会提供一些高级 API 来管理网络连接、容器网络等。例如，`ConnectivityManager` 或特定于容器管理的 API。
2. **系统服务:**  这些高级 API 通常会调用底层的系统服务，例如 `NetworkStack` 或负责容器管理的系统服务。
3. **JNI 调用:** 如果系统服务是用 Java 编写的，它可能需要通过 Java Native Interface (JNI) 调用 Native 代码来实现与内核的交互。
4. **NDK 库:**  一些 Android 系统库或开发者使用的 NDK 库可能会封装与 OVS 通信的细节。这些库会使用 Netlink Socket API 与内核进行交互。
5. **Netlink Socket 调用:**  这些库最终会调用 libc 提供的 Netlink Socket 相关函数 (`socket()`, `bind()`, `sendto()`, `recvfrom()`)，并按照 `openvswitch.h` 中定义的结构体构造和解析 Netlink 消息。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida hook Netlink 相关的 libc 函数来观察 Android 系统如何与 OVS 内核模块进行交互。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] sendto() called")
        print(message)
        if data:
            print("[*] Data:")
            # 可以尝试解析 Netlink 消息结构
            print(data.hex())
    elif message['type'] == 'recv':
        print("[*] recvfrom() returned")
        print(message)
        if data:
            print("[*] Data:")
            print(data.hex())
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function (args) {
            this.sockfd = args[0];
            this.buf = args[1];
            this.len = args[2];
            if (this.len.toInt() > 0) {
                send({type: 'send', args: [this.sockfd, this.buf, this.len]}, Memory.readByteArray(this.buf, this.len.toInt()));
            } else {
                send({type: 'send', args: [this.sockfd, this.buf, this.len]});
            }
        }
    });

    Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
        onEnter: function (args) {
            this.sockfd = args[0];
            this.buf = args[1];
            this.len = args[2];
            this.flags = args[3];
            this.addr = args[4];
            this.addrlen = args[5];
        },
        onLeave: function (retval) {
            if (retval.toInt() > 0) {
                send({type: 'recv', retval: retval, args: [this.sockfd, this.buf, this.len, this.flags, this.addr, this.addrlen]}, Memory.readByteArray(this.buf, retval.toInt()));
            } else {
                send({type: 'recv', retval: retval, args: [this.sockfd, this.buf, this.len, this.flags, this.addr, this.addrlen]});
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print(f"[*] Script loaded. Intercepting sendto() and recvfrom() in '{target}'. Press Ctrl+C to exit.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("[*] Exiting...")
        session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将以上 Python 代码保存为 `frida_ovs_hook.py`。
2. 找到你想要监控的 Android 进程的名称或 PID。这个进程可能是负责网络管理的系统服务，或者是使用了 OVS 相关功能的应用程序。
3. 运行 Frida 脚本：`frida -U -f <package name> -l frida_ovs_hook.py` 或者 `frida -U <process id> -l frida_ovs_hook.py`。
4. 当目标进程调用 `sendto()` 或 `recvfrom()` 时，Frida 会拦截这些调用，并打印出调用的参数以及发送/接收的数据（以十六进制形式）。通过分析这些数据，你可以了解 Android 系统是如何构造和解析与 OVS 模块通信的 Netlink 消息的。

这个 Frida 示例提供了一个基本的框架。你可以根据需要进一步解析 Netlink 消息的结构，以更清晰地理解 OVS 命令和属性。 你可能需要使用一些 Netlink 消息解析库或者手动解析消息头和属性字段。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/openvswitch.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_OPENVSWITCH_H
#define _UAPI__LINUX_OPENVSWITCH_H 1
#include <linux/types.h>
#include <linux/if_ether.h>
struct ovs_header {
  int dp_ifindex;
};
#define OVS_DATAPATH_FAMILY "ovs_datapath"
#define OVS_DATAPATH_MCGROUP "ovs_datapath"
#define OVS_DATAPATH_VERSION 2
#define OVS_DP_VER_FEATURES 2
enum ovs_datapath_cmd {
  OVS_DP_CMD_UNSPEC,
  OVS_DP_CMD_NEW,
  OVS_DP_CMD_DEL,
  OVS_DP_CMD_GET,
  OVS_DP_CMD_SET
};
enum ovs_datapath_attr {
  OVS_DP_ATTR_UNSPEC,
  OVS_DP_ATTR_NAME,
  OVS_DP_ATTR_UPCALL_PID,
  OVS_DP_ATTR_STATS,
  OVS_DP_ATTR_MEGAFLOW_STATS,
  OVS_DP_ATTR_USER_FEATURES,
  OVS_DP_ATTR_PAD,
  OVS_DP_ATTR_MASKS_CACHE_SIZE,
  OVS_DP_ATTR_PER_CPU_PIDS,
  OVS_DP_ATTR_IFINDEX,
  __OVS_DP_ATTR_MAX
};
#define OVS_DP_ATTR_MAX (__OVS_DP_ATTR_MAX - 1)
struct ovs_dp_stats {
  __u64 n_hit;
  __u64 n_missed;
  __u64 n_lost;
  __u64 n_flows;
};
struct ovs_dp_megaflow_stats {
  __u64 n_mask_hit;
  __u32 n_masks;
  __u32 pad0;
  __u64 n_cache_hit;
  __u64 pad1;
};
struct ovs_vport_stats {
  __u64 rx_packets;
  __u64 tx_packets;
  __u64 rx_bytes;
  __u64 tx_bytes;
  __u64 rx_errors;
  __u64 tx_errors;
  __u64 rx_dropped;
  __u64 tx_dropped;
};
#define OVS_DP_F_UNALIGNED (1 << 0)
#define OVS_DP_F_VPORT_PIDS (1 << 1)
#define OVS_DP_F_TC_RECIRC_SHARING (1 << 2)
#define OVS_DP_F_DISPATCH_UPCALL_PER_CPU (1 << 3)
#define OVSP_LOCAL ((__u32) 0)
#define OVS_PACKET_FAMILY "ovs_packet"
#define OVS_PACKET_VERSION 0x1
enum ovs_packet_cmd {
  OVS_PACKET_CMD_UNSPEC,
  OVS_PACKET_CMD_MISS,
  OVS_PACKET_CMD_ACTION,
  OVS_PACKET_CMD_EXECUTE
};
enum ovs_packet_attr {
  OVS_PACKET_ATTR_UNSPEC,
  OVS_PACKET_ATTR_PACKET,
  OVS_PACKET_ATTR_KEY,
  OVS_PACKET_ATTR_ACTIONS,
  OVS_PACKET_ATTR_USERDATA,
  OVS_PACKET_ATTR_EGRESS_TUN_KEY,
  OVS_PACKET_ATTR_UNUSED1,
  OVS_PACKET_ATTR_UNUSED2,
  OVS_PACKET_ATTR_PROBE,
  OVS_PACKET_ATTR_MRU,
  OVS_PACKET_ATTR_LEN,
  OVS_PACKET_ATTR_HASH,
  __OVS_PACKET_ATTR_MAX
};
#define OVS_PACKET_ATTR_MAX (__OVS_PACKET_ATTR_MAX - 1)
#define OVS_VPORT_FAMILY "ovs_vport"
#define OVS_VPORT_MCGROUP "ovs_vport"
#define OVS_VPORT_VERSION 0x1
enum ovs_vport_cmd {
  OVS_VPORT_CMD_UNSPEC,
  OVS_VPORT_CMD_NEW,
  OVS_VPORT_CMD_DEL,
  OVS_VPORT_CMD_GET,
  OVS_VPORT_CMD_SET
};
enum ovs_vport_type {
  OVS_VPORT_TYPE_UNSPEC,
  OVS_VPORT_TYPE_NETDEV,
  OVS_VPORT_TYPE_INTERNAL,
  OVS_VPORT_TYPE_GRE,
  OVS_VPORT_TYPE_VXLAN,
  OVS_VPORT_TYPE_GENEVE,
  __OVS_VPORT_TYPE_MAX
};
#define OVS_VPORT_TYPE_MAX (__OVS_VPORT_TYPE_MAX - 1)
enum ovs_vport_attr {
  OVS_VPORT_ATTR_UNSPEC,
  OVS_VPORT_ATTR_PORT_NO,
  OVS_VPORT_ATTR_TYPE,
  OVS_VPORT_ATTR_NAME,
  OVS_VPORT_ATTR_OPTIONS,
  OVS_VPORT_ATTR_UPCALL_PID,
  OVS_VPORT_ATTR_STATS,
  OVS_VPORT_ATTR_PAD,
  OVS_VPORT_ATTR_IFINDEX,
  OVS_VPORT_ATTR_NETNSID,
  OVS_VPORT_ATTR_UPCALL_STATS,
  __OVS_VPORT_ATTR_MAX
};
#define OVS_VPORT_ATTR_MAX (__OVS_VPORT_ATTR_MAX - 1)
enum ovs_vport_upcall_attr {
  OVS_VPORT_UPCALL_ATTR_SUCCESS,
  OVS_VPORT_UPCALL_ATTR_FAIL,
  __OVS_VPORT_UPCALL_ATTR_MAX
};
#define OVS_VPORT_UPCALL_ATTR_MAX (__OVS_VPORT_UPCALL_ATTR_MAX - 1)
enum {
  OVS_VXLAN_EXT_UNSPEC,
  OVS_VXLAN_EXT_GBP,
  __OVS_VXLAN_EXT_MAX,
};
#define OVS_VXLAN_EXT_MAX (__OVS_VXLAN_EXT_MAX - 1)
enum {
  OVS_TUNNEL_ATTR_UNSPEC,
  OVS_TUNNEL_ATTR_DST_PORT,
  OVS_TUNNEL_ATTR_EXTENSION,
  __OVS_TUNNEL_ATTR_MAX
};
#define OVS_TUNNEL_ATTR_MAX (__OVS_TUNNEL_ATTR_MAX - 1)
#define OVS_FLOW_FAMILY "ovs_flow"
#define OVS_FLOW_MCGROUP "ovs_flow"
#define OVS_FLOW_VERSION 0x1
enum ovs_flow_cmd {
  OVS_FLOW_CMD_UNSPEC,
  OVS_FLOW_CMD_NEW,
  OVS_FLOW_CMD_DEL,
  OVS_FLOW_CMD_GET,
  OVS_FLOW_CMD_SET
};
struct ovs_flow_stats {
  __u64 n_packets;
  __u64 n_bytes;
};
enum ovs_key_attr {
  OVS_KEY_ATTR_UNSPEC,
  OVS_KEY_ATTR_ENCAP,
  OVS_KEY_ATTR_PRIORITY,
  OVS_KEY_ATTR_IN_PORT,
  OVS_KEY_ATTR_ETHERNET,
  OVS_KEY_ATTR_VLAN,
  OVS_KEY_ATTR_ETHERTYPE,
  OVS_KEY_ATTR_IPV4,
  OVS_KEY_ATTR_IPV6,
  OVS_KEY_ATTR_TCP,
  OVS_KEY_ATTR_UDP,
  OVS_KEY_ATTR_ICMP,
  OVS_KEY_ATTR_ICMPV6,
  OVS_KEY_ATTR_ARP,
  OVS_KEY_ATTR_ND,
  OVS_KEY_ATTR_SKB_MARK,
  OVS_KEY_ATTR_TUNNEL,
  OVS_KEY_ATTR_SCTP,
  OVS_KEY_ATTR_TCP_FLAGS,
  OVS_KEY_ATTR_DP_HASH,
  OVS_KEY_ATTR_RECIRC_ID,
  OVS_KEY_ATTR_MPLS,
  OVS_KEY_ATTR_CT_STATE,
  OVS_KEY_ATTR_CT_ZONE,
  OVS_KEY_ATTR_CT_MARK,
  OVS_KEY_ATTR_CT_LABELS,
  OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,
  OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,
  OVS_KEY_ATTR_NSH,
  OVS_KEY_ATTR_PACKET_TYPE,
  OVS_KEY_ATTR_ND_EXTENSIONS,
  OVS_KEY_ATTR_TUNNEL_INFO,
  OVS_KEY_ATTR_IPV6_EXTHDRS,
  __OVS_KEY_ATTR_MAX
};
#define OVS_KEY_ATTR_MAX (__OVS_KEY_ATTR_MAX - 1)
enum ovs_tunnel_key_attr {
  OVS_TUNNEL_KEY_ATTR_ID,
  OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
  OVS_TUNNEL_KEY_ATTR_IPV4_DST,
  OVS_TUNNEL_KEY_ATTR_TOS,
  OVS_TUNNEL_KEY_ATTR_TTL,
  OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,
  OVS_TUNNEL_KEY_ATTR_CSUM,
  OVS_TUNNEL_KEY_ATTR_OAM,
  OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
  OVS_TUNNEL_KEY_ATTR_TP_SRC,
  OVS_TUNNEL_KEY_ATTR_TP_DST,
  OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,
  OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
  OVS_TUNNEL_KEY_ATTR_IPV6_DST,
  OVS_TUNNEL_KEY_ATTR_PAD,
  OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,
  OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE,
  __OVS_TUNNEL_KEY_ATTR_MAX
};
#define OVS_TUNNEL_KEY_ATTR_MAX (__OVS_TUNNEL_KEY_ATTR_MAX - 1)
enum ovs_frag_type {
  OVS_FRAG_TYPE_NONE,
  OVS_FRAG_TYPE_FIRST,
  OVS_FRAG_TYPE_LATER,
  __OVS_FRAG_TYPE_MAX
};
#define OVS_FRAG_TYPE_MAX (__OVS_FRAG_TYPE_MAX - 1)
struct ovs_key_ethernet {
  __u8 eth_src[ETH_ALEN];
  __u8 eth_dst[ETH_ALEN];
};
struct ovs_key_mpls {
  __be32 mpls_lse;
};
struct ovs_key_ipv4 {
  __be32 ipv4_src;
  __be32 ipv4_dst;
  __u8 ipv4_proto;
  __u8 ipv4_tos;
  __u8 ipv4_ttl;
  __u8 ipv4_frag;
};
struct ovs_key_ipv6 {
  __be32 ipv6_src[4];
  __be32 ipv6_dst[4];
  __be32 ipv6_label;
  __u8 ipv6_proto;
  __u8 ipv6_tclass;
  __u8 ipv6_hlimit;
  __u8 ipv6_frag;
};
struct ovs_key_ipv6_exthdrs {
  __u16 hdrs;
};
struct ovs_key_tcp {
  __be16 tcp_src;
  __be16 tcp_dst;
};
struct ovs_key_udp {
  __be16 udp_src;
  __be16 udp_dst;
};
struct ovs_key_sctp {
  __be16 sctp_src;
  __be16 sctp_dst;
};
struct ovs_key_icmp {
  __u8 icmp_type;
  __u8 icmp_code;
};
struct ovs_key_icmpv6 {
  __u8 icmpv6_type;
  __u8 icmpv6_code;
};
struct ovs_key_arp {
  __be32 arp_sip;
  __be32 arp_tip;
  __be16 arp_op;
  __u8 arp_sha[ETH_ALEN];
  __u8 arp_tha[ETH_ALEN];
};
struct ovs_key_nd {
  __be32 nd_target[4];
  __u8 nd_sll[ETH_ALEN];
  __u8 nd_tll[ETH_ALEN];
};
#define OVS_CT_LABELS_LEN_32 4
#define OVS_CT_LABELS_LEN (OVS_CT_LABELS_LEN_32 * sizeof(__u32))
struct ovs_key_ct_labels {
  union {
    __u8 ct_labels[OVS_CT_LABELS_LEN];
    __u32 ct_labels_32[OVS_CT_LABELS_LEN_32];
  };
};
#define OVS_CS_F_NEW 0x01
#define OVS_CS_F_ESTABLISHED 0x02
#define OVS_CS_F_RELATED 0x04
#define OVS_CS_F_REPLY_DIR 0x08
#define OVS_CS_F_INVALID 0x10
#define OVS_CS_F_TRACKED 0x20
#define OVS_CS_F_SRC_NAT 0x40
#define OVS_CS_F_DST_NAT 0x80
#define OVS_CS_F_NAT_MASK (OVS_CS_F_SRC_NAT | OVS_CS_F_DST_NAT)
struct ovs_key_ct_tuple_ipv4 {
  __be32 ipv4_src;
  __be32 ipv4_dst;
  __be16 src_port;
  __be16 dst_port;
  __u8 ipv4_proto;
};
struct ovs_key_ct_tuple_ipv6 {
  __be32 ipv6_src[4];
  __be32 ipv6_dst[4];
  __be16 src_port;
  __be16 dst_port;
  __u8 ipv6_proto;
};
enum ovs_nsh_key_attr {
  OVS_NSH_KEY_ATTR_UNSPEC,
  OVS_NSH_KEY_ATTR_BASE,
  OVS_NSH_KEY_ATTR_MD1,
  OVS_NSH_KEY_ATTR_MD2,
  __OVS_NSH_KEY_ATTR_MAX
};
#define OVS_NSH_KEY_ATTR_MAX (__OVS_NSH_KEY_ATTR_MAX - 1)
struct ovs_nsh_key_base {
  __u8 flags;
  __u8 ttl;
  __u8 mdtype;
  __u8 np;
  __be32 path_hdr;
};
#define NSH_MD1_CONTEXT_SIZE 4
struct ovs_nsh_key_md1 {
  __be32 context[NSH_MD1_CONTEXT_SIZE];
};
enum ovs_flow_attr {
  OVS_FLOW_ATTR_UNSPEC,
  OVS_FLOW_ATTR_KEY,
  OVS_FLOW_ATTR_ACTIONS,
  OVS_FLOW_ATTR_STATS,
  OVS_FLOW_ATTR_TCP_FLAGS,
  OVS_FLOW_ATTR_USED,
  OVS_FLOW_ATTR_CLEAR,
  OVS_FLOW_ATTR_MASK,
  OVS_FLOW_ATTR_PROBE,
  OVS_FLOW_ATTR_UFID,
  OVS_FLOW_ATTR_UFID_FLAGS,
  OVS_FLOW_ATTR_PAD,
  __OVS_FLOW_ATTR_MAX
};
#define OVS_FLOW_ATTR_MAX (__OVS_FLOW_ATTR_MAX - 1)
#define OVS_UFID_F_OMIT_KEY (1 << 0)
#define OVS_UFID_F_OMIT_MASK (1 << 1)
#define OVS_UFID_F_OMIT_ACTIONS (1 << 2)
enum ovs_sample_attr {
  OVS_SAMPLE_ATTR_UNSPEC,
  OVS_SAMPLE_ATTR_PROBABILITY,
  OVS_SAMPLE_ATTR_ACTIONS,
  __OVS_SAMPLE_ATTR_MAX,
};
#define OVS_SAMPLE_ATTR_MAX (__OVS_SAMPLE_ATTR_MAX - 1)
enum ovs_userspace_attr {
  OVS_USERSPACE_ATTR_UNSPEC,
  OVS_USERSPACE_ATTR_PID,
  OVS_USERSPACE_ATTR_USERDATA,
  OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,
  OVS_USERSPACE_ATTR_ACTIONS,
  __OVS_USERSPACE_ATTR_MAX
};
#define OVS_USERSPACE_ATTR_MAX (__OVS_USERSPACE_ATTR_MAX - 1)
struct ovs_action_trunc {
  __u32 max_len;
};
struct ovs_action_push_mpls {
  __be32 mpls_lse;
  __be16 mpls_ethertype;
};
struct ovs_action_add_mpls {
  __be32 mpls_lse;
  __be16 mpls_ethertype;
  __u16 tun_flags;
};
#define OVS_MPLS_L3_TUNNEL_FLAG_MASK (1 << 0)
struct ovs_action_push_vlan {
  __be16 vlan_tpid;
  __be16 vlan_tci;
};
enum ovs_hash_alg {
  OVS_HASH_ALG_L4,
  OVS_HASH_ALG_SYM_L4,
};
struct ovs_action_hash {
  __u32 hash_alg;
  __u32 hash_basis;
};
enum ovs_ct_attr {
  OVS_CT_ATTR_UNSPEC,
  OVS_CT_ATTR_COMMIT,
  OVS_CT_ATTR_ZONE,
  OVS_CT_ATTR_MARK,
  OVS_CT_ATTR_LABELS,
  OVS_CT_ATTR_HELPER,
  OVS_CT_ATTR_NAT,
  OVS_CT_ATTR_FORCE_COMMIT,
  OVS_CT_ATTR_EVENTMASK,
  OVS_CT_ATTR_TIMEOUT,
  __OVS_CT_ATTR_MAX
};
#define OVS_CT_ATTR_MAX (__OVS_CT_ATTR_MAX - 1)
enum ovs_nat_attr {
  OVS_NAT_ATTR_UNSPEC,
  OVS_NAT_ATTR_SRC,
  OVS_NAT_ATTR_DST,
  OVS_NAT_ATTR_IP_MIN,
  OVS_NAT_ATTR_IP_MAX,
  OVS_NAT_ATTR_PROTO_MIN,
  OVS_NAT_ATTR_PROTO_MAX,
  OVS_NAT_ATTR_PERSISTENT,
  OVS_NAT_ATTR_PROTO_HASH,
  OVS_NAT_ATTR_PROTO_RANDOM,
  __OVS_NAT_ATTR_MAX,
};
#define OVS_NAT_ATTR_MAX (__OVS_NAT_ATTR_MAX - 1)
struct ovs_action_push_eth {
  struct ovs_key_ethernet addresses;
};
enum ovs_check_pkt_len_attr {
  OVS_CHECK_PKT_LEN_ATTR_UNSPEC,
  OVS_CHECK_PKT_LEN_ATTR_PKT_LEN,
  OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER,
  OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL,
  __OVS_CHECK_PKT_LEN_ATTR_MAX,
};
#define OVS_CHECK_PKT_LEN_ATTR_MAX (__OVS_CHECK_PKT_LEN_ATTR_MAX - 1)
#define OVS_PSAMPLE_COOKIE_MAX_SIZE 16
enum ovs_psample_attr {
  OVS_PSAMPLE_ATTR_GROUP = 1,
  OVS_PSAMPLE_ATTR_COOKIE,
  __OVS_PSAMPLE_ATTR_MAX
};
#define OVS_PSAMPLE_ATTR_MAX (__OVS_PSAMPLE_ATTR_MAX - 1)
enum ovs_action_attr {
  OVS_ACTION_ATTR_UNSPEC,
  OVS_ACTION_ATTR_OUTPUT,
  OVS_ACTION_ATTR_USERSPACE,
  OVS_ACTION_ATTR_SET,
  OVS_ACTION_ATTR_PUSH_VLAN,
  OVS_ACTION_ATTR_POP_VLAN,
  OVS_ACTION_ATTR_SAMPLE,
  OVS_ACTION_ATTR_RECIRC,
  OVS_ACTION_ATTR_HASH,
  OVS_ACTION_ATTR_PUSH_MPLS,
  OVS_ACTION_ATTR_POP_MPLS,
  OVS_ACTION_ATTR_SET_MASKED,
  OVS_ACTION_ATTR_CT,
  OVS_ACTION_ATTR_TRUNC,
  OVS_ACTION_ATTR_PUSH_ETH,
  OVS_ACTION_ATTR_POP_ETH,
  OVS_ACTION_ATTR_CT_CLEAR,
  OVS_ACTION_ATTR_PUSH_NSH,
  OVS_ACTION_ATTR_POP_NSH,
  OVS_ACTION_ATTR_METER,
  OVS_ACTION_ATTR_CLONE,
  OVS_ACTION_ATTR_CHECK_PKT_LEN,
  OVS_ACTION_ATTR_ADD_MPLS,
  OVS_ACTION_ATTR_DEC_TTL,
  OVS_ACTION_ATTR_DROP,
  OVS_ACTION_ATTR_PSAMPLE,
  __OVS_ACTION_ATTR_MAX,
};
#define OVS_ACTION_ATTR_MAX (__OVS_ACTION_ATTR_MAX - 1)
#define OVS_METER_FAMILY "ovs_meter"
#define OVS_METER_MCGROUP "ovs_meter"
#define OVS_METER_VERSION 0x1
enum ovs_meter_cmd {
  OVS_METER_CMD_UNSPEC,
  OVS_METER_CMD_FEATURES,
  OVS_METER_CMD_SET,
  OVS_METER_CMD_DEL,
  OVS_METER_CMD_GET
};
enum ovs_meter_attr {
  OVS_METER_ATTR_UNSPEC,
  OVS_METER_ATTR_ID,
  OVS_METER_ATTR_KBPS,
  OVS_METER_ATTR_STATS,
  OVS_METER_ATTR_BANDS,
  OVS_METER_ATTR_USED,
  OVS_METER_ATTR_CLEAR,
  OVS_METER_ATTR_MAX_METERS,
  OVS_METER_ATTR_MAX_BANDS,
  OVS_METER_ATTR_PAD,
  __OVS_METER_ATTR_MAX
};
#define OVS_METER_ATTR_MAX (__OVS_METER_ATTR_MAX - 1)
enum ovs_band_attr {
  OVS_BAND_ATTR_UNSPEC,
  OVS_BAND_ATTR_TYPE,
  OVS_BAND_ATTR_RATE,
  OVS_BAND_ATTR_BURST,
  OVS_BAND_ATTR_STATS,
  __OVS_BAND_ATTR_MAX
};
#define OVS_BAND_ATTR_MAX (__OVS_BAND_ATTR_MAX - 1)
enum ovs_meter_band_type {
  OVS_METER_BAND_TYPE_UNSPEC,
  OVS_METER_BAND_TYPE_DROP,
  __OVS_METER_BAND_TYPE_MAX
};
#define OVS_METER_BAND_TYPE_MAX (__OVS_METER_BAND_TYPE_MAX - 1)
#define OVS_CT_LIMIT_FAMILY "ovs_ct_limit"
#define OVS_CT_LIMIT_MCGROUP "ovs_ct_limit"
#define OVS_CT_LIMIT_VERSION 0x1
enum ovs_ct_limit_cmd {
  OVS_CT_LIMIT_CMD_UNSPEC,
  OVS_CT_LIMIT_CMD_SET,
  OVS_CT_LIMIT_CMD_DEL,
  OVS_CT_LIMIT_CMD_GET
};
enum ovs_ct_limit_attr {
  OVS_CT_LIMIT_ATTR_UNSPEC,
  OVS_CT_LIMIT_ATTR_ZONE_LIMIT,
  __OVS_CT_LIMIT_ATTR_MAX
};
#define OVS_CT_LIMIT_ATTR_MAX (__OVS_CT_LIMIT_ATTR_MAX - 1)
#define OVS_ZONE_LIMIT_DEFAULT_ZONE - 1
struct ovs_zone_limit {
  int zone_id;
  __u32 limit;
  __u32 count;
};
enum ovs_dec_ttl_attr {
  OVS_DEC_TTL_ATTR_UNSPEC,
  OVS_DEC_TTL_ATTR_ACTION,
  __OVS_DEC_TTL_ATTR_MAX
};
#define OVS_DEC_TTL_ATTR_MAX (__OVS_DEC_TTL_ATTR_MAX - 1)
#endif
```