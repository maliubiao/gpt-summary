Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Context:**

The first step is to recognize the context: `bionic/libc/kernel/uapi/linux/if_bridge.h`. This tells us several crucial things:

* **`bionic`:** This is Android's C library. The file is part of the system-level infrastructure.
* **`libc`:**  This means it's related to fundamental operating system interactions.
* **`kernel/uapi`:** This signifies that the definitions are part of the kernel's user-space API. User-space programs (like apps or system daemons) use these definitions to interact with the kernel.
* **`linux`:**  It's a Linux-specific header file.
* **`if_bridge.h`:** The filename strongly suggests this file defines structures and constants related to network bridging.

**2. Initial Scan and Keyword Spotting:**

Quickly scan the content for recurring patterns and keywords. Things that immediately stand out:

* `#ifndef`, `#define`, `#include`: Standard C preprocessor directives for header file inclusion guards.
* `struct`: Defines data structures. Pay close attention to these.
* `enum`: Defines sets of named integer constants. These often represent states or options.
* `#define` with uppercase names: These are usually constants or macros. Look for patterns like `BRCTL_`, `BR_STATE_`, `IFLA_BRIDGE_`, etc. These prefixes often indicate categories of related constants.
* `SYSFS_`:  Indicates interaction with the sysfs filesystem, which is a kernel mechanism for exposing kernel parameters to user-space.

**3. Categorizing the Content:**

Based on the initial scan, we can start grouping the definitions by functionality:

* **BRCTL_* constants:**  These clearly relate to control operations for network bridges. The names suggest actions like adding, deleting, getting info about bridges and interfaces. This looks like a command set.
* **BR_STATE_* constants:** These represent the different operational states of a bridge.
* **`struct __bridge_info`, `struct __port_info`, `struct __fdb_entry`:** These structures seem to hold information about bridges, their ports, and the forwarding database (FDB).
* **IFLA_BRIDGE_* constants:**  The `IFLA` prefix often relates to netlink attributes (used for communication between kernel and user-space). These constants define different attributes associated with bridge configurations. The suffixes (FLAGS, MODE, VLAN_INFO, MRP, CFM, MST) indicate different aspects of bridge configuration.
* **MRP, CFM, MST related definitions:** These acronyms likely stand for specific bridging protocols or features (MRP - Media Redundancy Protocol, CFM - Connectivity Fault Management, MST - Multiple Spanning Tree).
* **BRIDGE_VLAN_* definitions:** These clearly handle VLAN (Virtual LAN) configurations on bridges.
* **MDBA_* and related definitions:**  These appear to deal with Multicast Database Agent (MDBA) entries and router ports, essential for multicast forwarding.
* **BRIDGE_XSTATS_* definitions:** These likely represent statistics related to bridge operations.

**4. Deeper Dive into Structures and Enums:**

Now, examine the individual structures and enums more carefully:

* **`struct __bridge_info`:**  Contains parameters related to Spanning Tree Protocol (STP), which prevents loops in bridged networks. Keywords like `designated_root`, `bridge_id`, `root_path_cost`, `max_age`, `hello_time`, `forward_delay` are strong indicators.
* **`struct __port_info`:**  Holds information about individual ports of a bridge, also related to STP.
* **`struct __fdb_entry`:**  Contains the MAC address, port number, and other information related to entries in the forwarding database. This is how a bridge learns which MAC addresses are connected to which ports.
* **`enum IFLA_BRIDGE_*`:**  These enums list the different attributes that can be used when configuring a bridge using netlink. The values correspond to specific data fields.

**5. Identifying Key Relationships and Functionality:**

Start connecting the dots:

* The `BRCTL_*` constants suggest a user-space utility (like `brctl` on Linux) that can control bridge behavior.
* The structures define the data exchanged between user-space and the kernel to configure and monitor bridges.
* The `IFLA_BRIDGE_*` constants are used in netlink messages to set and get bridge attributes.

**6. Considering Android Specifics:**

Think about how bridging might be used on Android:

* **Network Sharing/Tethering:** Bridging can be used internally when a phone acts as a hotspot, sharing its internet connection.
* **Virtualization/Containers:** If Android uses virtualization or container technologies, bridges might be used to connect virtual network interfaces.

**7. Addressing the Specific Questions:**

Now, go back to the prompt and address each question systematically:

* **功能 (Functions):** Summarize the capabilities identified in the previous steps (bridge control, configuration, monitoring, STP, VLAN, multicast).
* **与 Android 的关系 (Relationship with Android):**  Provide the examples identified in step 6.
* **libc 函数的功能 (Functions of libc functions):** Recognize that this header file *defines* structures and constants, but doesn't contain the *implementation* of libc functions. The actual functions that *use* these definitions would be in other parts of `bionic`. Focus on *how* these definitions *could be used* by libc functions involved in network management.
* **dynamic linker 的功能 (Dynamic linker functionality):** Acknowledge that this header file is primarily about kernel interfaces. It doesn't directly involve the dynamic linker. The linker deals with loading shared libraries, which is a different aspect of the system.
* **逻辑推理 (Logical Reasoning):**  Think about the data flow. User-space applications use system calls or netlink to interact with the kernel. The header file provides the necessary definitions for these interactions. Provide examples of how specific structures might be used in a command or response.
* **用户或编程常见的使用错误 (Common user/programming errors):** Consider typical mistakes when working with network configurations (incorrectly setting parameters, misinterpreting states).
* **android framework or ndk 如何一步步的到达这里 (How Android framework/NDK reaches here):** Trace the path from high-level framework components down to system calls or netlink interactions that would use these definitions.
* **frida hook 示例 (Frida hook examples):**  Provide examples of how to intercept calls to relevant system calls or netlink functions to observe the usage of these structures.

**8. Structuring the Output:**

Organize the information clearly with headings and bullet points. Use precise language and avoid jargon where possible, or explain it. Provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement:**

During the process, review your understanding and correct any misconceptions. For instance, initially, you might think this file *implements* bridge functionality. However, realizing it's in `kernel/uapi` clarifies that it's just the *interface* to kernel functionality. The actual implementation is in the kernel itself. Also, double-check the prompt to ensure you've addressed every part of it.
这是一个定义 Linux 内核用户空间 API 的头文件，专门用于配置和管理网络桥接（network bridging）功能。它定义了数据结构、常量和枚举类型，供用户空间的应用程序与内核中的桥接模块进行交互。由于它位于 `bionic` 的 `kernel/uapi` 目录下，这意味着 Android 系统也使用这些定义来管理其网络桥接功能。

**功能列举:**

这个头文件主要定义了以下功能相关的结构和常量：

1. **桥接控制操作 (Bridge Control Operations):**  定义了用于控制桥接行为的常量，例如：
   - `BRCTL_GET_VERSION`: 获取桥接工具版本。
   - `BRCTL_GET_BRIDGES`: 获取系统中所有桥接设备的列表。
   - `BRCTL_ADD_BRIDGE`: 创建一个新的桥接设备。
   - `BRCTL_DEL_BRIDGE`: 删除一个已存在的桥接设备。
   - `BRCTL_ADD_IF`: 将一个网络接口添加到桥接设备。
   - `BRCTL_DEL_IF`: 从桥接设备中移除一个网络接口。
   - `BRCTL_GET_BRIDGE_INFO`: 获取桥接设备的详细信息。
   - `BRCTL_GET_PORT_LIST`: 获取桥接设备上所有端口的列表。
   - `BRCTL_SET_BRIDGE_FORWARD_DELAY` 等一系列 `BRCTL_SET_BRIDGE_*` 和 `BRCTL_SET_PORT_*` 常量：用于设置桥接设备和端口的各种参数，例如转发延迟、Hello Time、最大年龄、老化时间、优先级、路径成本等。这些参数与 Spanning Tree Protocol (STP) 有关，用于防止网络环路。
   - `BRCTL_GET_FDB_ENTRIES`: 获取桥接设备的转发数据库 (Forwarding Database, FDB) 条目。

2. **桥接状态 (Bridge States):** 定义了桥接端口可以处于的不同状态，这些状态与 STP 相关：
   - `BR_STATE_DISABLED`: 禁用。
   - `BR_STATE_LISTENING`: 监听。
   - `BR_STATE_LEARNING`: 学习 MAC 地址。
   - `BR_STATE_FORWARDING`: 转发数据包。
   - `BR_STATE_BLOCKING`: 阻塞，不转发数据包，用于防止环路。

3. **桥接信息结构体 (Bridge Information Structures):** 定义了用于存储桥接设备和端口信息的结构体：
   - `struct __bridge_info`: 包含桥接设备的 STP 相关信息，如根桥 ID、桥 ID、根路径成本、各种定时器值等。
   - `struct __port_info`: 包含桥接端口的 STP 相关信息，如指定根、指定桥、端口 ID、路径成本、状态等。
   - `struct __fdb_entry`: 包含桥接设备转发数据库中的条目信息，如 MAC 地址、端口号、是否本地、老化计时器值等。

4. **Netlink 属性 (Netlink Attributes):**  定义了在使用 Netlink 与内核桥接模块通信时可以设置和获取的属性：
   - `IFLA_BRIDGE_FLAGS`: 桥接标志，如 `BRIDGE_FLAGS_MASTER` (表示这是一个桥接设备) 和 `BRIDGE_FLAGS_SELF`。
   - `IFLA_BRIDGE_MODE`: 桥接模式，如 VEB (Virtual Ethernet Bridge) 和 VEPA (Virtual Ethernet Port Aggregator)。
   - `IFLA_BRIDGE_VLAN_INFO`: VLAN (Virtual LAN) 相关信息。
   - `IFLA_BRIDGE_MRP`: Media Redundancy Protocol (MRP) 相关信息。
   - `IFLA_BRIDGE_CFM`: Connectivity Fault Management (CFM) 相关信息。
   - `IFLA_BRIDGE_MST`: Multiple Spanning Tree (MST) 相关信息。
   - 许多以 `IFLA_BRIDGE_MRP_*`, `IFLA_BRIDGE_CFM_*`, `IFLA_BRIDGE_MST_*` 开头的常量，定义了与这些高级桥接协议相关的更细粒度的属性。

5. **VLAN 相关 (VLAN Related):** 定义了用于配置和管理 VLAN 的结构体和常量，例如 `struct bridge_vlan_info` 和相关的 `IFLA_BRIDGE_VLAN_INFO_*` 常量。

6. **组播相关 (Multicast Related):** 定义了用于配置和管理组播的结构体和常量，例如 `struct br_mdb_entry` 以及与 MDBA (Multicast Database Agent) 相关的常量。

7. **统计信息 (Statistics):** 定义了用于获取桥接设备统计信息的结构体，例如 `struct bridge_stp_xstats` 和 `struct br_mcast_stats`。

**与 Android 功能的关系及举例说明:**

Android 系统内部使用了 Linux 内核的桥接功能来实现多种网络场景，例如：

* **Wi-Fi 热点 (Wi-Fi Hotspot / Tethering):** 当 Android 设备作为 Wi-Fi 热点时，它会创建一个桥接设备，将移动数据连接（例如 `rmnet_data0`）和 Wi-Fi 接口（例如 `wlan0`）桥接在一起。这样，连接到该热点的设备就可以通过 Android 设备的移动数据连接访问互联网。
    - 例如，Android Framework 会调用 `netd` 守护进程，`netd` 可能会使用 `ioctl` 系统调用配合 `BRCTL_*` 常量，或者使用 Netlink 配合 `IFLA_BRIDGE_*` 常量来创建和配置桥接设备，并将移动数据接口和 Wi-Fi 接口添加到该桥接中。
* **容器化 (Containerization):** 如果 Android 使用容器技术（例如在 Android 虚拟机或某些定制 ROM 中），桥接可以用于连接容器的网络接口和宿主机的网络接口，使得容器能够访问外部网络。
* **虚拟网络设备 (Virtual Network Devices):** Android 系统可能使用桥接来连接虚拟机或虚拟网络设备，实现更复杂的网络拓扑。

**libc 函数的功能实现:**

这个头文件本身 **不包含** libc 函数的实现。它只是定义了数据结构和常量，供 libc 中的网络相关的函数使用。libc 中的函数，例如：

* **`ioctl()`:**  一些桥接控制操作（例如 `BRCTL_*` 定义的操作）可以通过 `ioctl()` 系统调用来实现。用户空间的程序会填充一个 `ifreq` 结构体，其中包含要操作的桥接设备名称和命令（对应于 `BRCTL_*` 常量），然后调用 `ioctl()`。内核中的桥接模块会解析这个请求并执行相应的操作。
    - 例如，要创建一个新的桥接设备 "br0"，libc 中的某个函数可能会构造一个 `ifreq` 结构体，将 `ifr_name` 设置为 "br0"，并将 `ifr_data` 指向包含 `BRCTL_ADD_BRIDGE` 命令的数据。然后调用 `ioctl(socket, SIOCBRADDBR, &ifr)`。
* **Netlink 相关的函数 (`socket()`, `bind()`, `sendto()`, `recvfrom()`):**  更现代的桥接配置和管理通常使用 Netlink 套接字。libc 中与 Netlink 相关的函数会被用来构建和发送包含 `IFLA_BRIDGE_*` 属性的 Netlink 消息，以便配置桥接设备的各种参数。内核会解析这些消息并执行相应的配置。
    - 例如，要设置桥接设备 "br0" 的转发延迟，libc 中的某个函数可能会创建一个 Netlink 消息，其中包含 `IFLA_IFNAME` 属性设置为 "br0"，以及 `IFLA_BRIDGE_FORWARD_DELAY` 属性设置为期望的延迟值。然后通过 Netlink 套接字发送到内核。

**涉及 dynamic linker 的功能:**

这个头文件本身 **不涉及** dynamic linker 的功能。Dynamic linker (例如 Android 上的 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并在程序启动时解析符号依赖关系。

然而，如果用户空间的程序需要使用与桥接功能相关的特定库（这不太常见，因为桥接配置通常通过系统调用或 Netlink 完成），那么 dynamic linker 会在程序启动时加载这些库。

**so 布局样本和链接处理过程（假设存在这样的库，尽管通常不需要）：**

假设存在一个名为 `libbridge_utils.so` 的共享库，其中包含一些辅助函数来处理桥接操作。

**`libbridge_utils.so` 布局样本：**

```
libbridge_utils.so:
    .text          # 代码段
        bridge_create:
            ...
        bridge_add_interface:
            ...
    .data          # 数据段
        ...
    .rodata        # 只读数据段
        ...
    .dynsym        # 动态符号表
        bridge_create
        bridge_add_interface
        ...
    .dynstr        # 动态字符串表
        bridge_create
        bridge_add_interface
        ...
    .rel.dyn       # 动态重定位表
        ...
```

**链接处理过程：**

1. **程序启动：** 当一个使用 `libbridge_utils.so` 的程序启动时，内核会加载该程序的可执行文件。
2. **dynamic linker 启动：** 内核会启动 dynamic linker。
3. **依赖查找：** dynamic linker 会检查程序依赖的共享库列表，找到 `libbridge_utils.so`。
4. **库加载：** dynamic linker 会在内存中找到或加载 `libbridge_utils.so`。
5. **符号解析：** dynamic linker 会解析程序中对 `libbridge_utils.so` 中函数的引用（例如 `bridge_create`），并将这些引用绑定到 `libbridge_utils.so` 中对应函数的实际地址。这通常涉及查找 `.dynsym` 和 `.dynstr` 表。
6. **重定位：** dynamic linker 会根据 `.rel.dyn` 表中的信息，调整 `libbridge_utils.so` 中需要重定位的地址。

**逻辑推理、假设输入与输出:**

假设我们想获取桥接设备 "br0" 的信息。

**假设输入：**

* 程序调用 libc 中的一个函数（例如 `get_bridge_info("br0")`，这只是一个假设的函数名）。
* 该函数内部使用 `ioctl` 系统调用，并将命令设置为 `BRCTL_GET_BRIDGE_INFO`。
* `ifreq` 结构体的 `ifr_name` 字段被设置为 "br0"。

**逻辑推理：**

1. `ioctl` 系统调用会将请求传递给内核。
2. 内核中的桥接模块会识别出 `SIOCGGETBR` 命令 (这是与 `BRCTL_GET_BRIDGE_INFO` 对应的内核操作)。
3. 桥接模块会查找名为 "br0" 的桥接设备。
4. 如果找到，桥接模块会填充一个 `__bridge_info` 结构体，包含 "br0" 的 STP 参数等信息。
5. 这个结构体的数据会被复制回用户空间程序的 `ifreq` 结构体中（通常通过 `ifr_data` 指针）。

**假设输出：**

程序接收到的 `__bridge_info` 结构体可能包含以下信息（示例值）：

```
struct __bridge_info {
  designated_root: 0x8000000000000001,
  bridge_id: 0x8000000000000001,
  root_path_cost: 0,
  max_age: 2000,
  hello_time: 200,
  forward_delay: 1500,
  bridge_max_age: 2000,
  bridge_hello_time: 200,
  bridge_forward_delay: 1500,
  topology_change: 0,
  topology_change_detected: 0,
  root_port: 0,
  stp_enabled: 1,
  ageing_time: 30000,
  gc_interval: 400,
  hello_timer_value: 0,
  tcn_timer_value: 0,
  topology_change_timer_value: 0,
  gc_timer_value: 0
};
```

**用户或编程常见的使用错误:**

1. **尝试操作不存在的桥接设备或接口:**  例如，在创建桥接之前就尝试添加接口，或者删除一个不存在的桥接。这会导致 `ioctl` 或 Netlink 操作失败，并返回错误码。
2. **设置不合理的参数值:** 例如，将转发延迟设置为过小的值可能会导致网络不稳定。内核通常会对这些参数进行一定的范围检查，但仍然可能导致问题。
3. **权限不足:**  桥接操作通常需要 root 权限。如果普通用户尝试执行这些操作，会因为权限不足而失败。
4. **忘记处理错误返回值:**  `ioctl` 和 Netlink 操作都会返回表示成功或失败的值。程序员必须检查这些返回值并妥善处理错误情况。
5. **Netlink 消息构造错误:**  如果使用 Netlink 进行配置，错误地构造 Netlink 消息（例如，属性类型或长度错误）会导致内核解析失败。

**Android Framework 或 NDK 如何一步步的到达这里:**

以下是一个简化的步骤说明，展示了 Android Framework 如何通过不同的层级最终涉及到 `if_bridge.h` 中定义的常量和结构体：

1. **Android Framework (Java/Kotlin):**  用户或系统服务可能通过 Android Framework 提供的 Java API 来请求进行网络配置，例如创建 Wi-Fi 热点。
2. **`ConnectivityService` (Java):** Framework 的 `ConnectivityService` 负责处理连接相关的请求。当需要创建 Wi-Fi 热点时，`ConnectivityService` 会协调底层的网络管理操作。
3. **`NetworkManagementService` (Java):**  `ConnectivityService` 会与 `NetworkManagementService` 进行通信。`NetworkManagementService` 是一个系统服务，负责执行底层的网络管理命令。
4. **`netd` 守护进程 (Native C++):**  `NetworkManagementService` 通过 Binder IPC 与 `netd` 守护进程通信。`netd` 是一个 Native 守护进程，它执行实际的网络配置任务。
5. **`ioctl` 或 Netlink 调用 (Native C/C++):** `netd` 内部会使用 C/C++ 代码调用 Linux 系统调用，例如 `ioctl` 或使用 Netlink 套接字来与内核进行交互。
    - **`ioctl` 路径:** `netd` 可能会使用 `ioctl` 系统调用，并使用 `ifreq` 结构体和 `BRCTL_*` 常量来控制桥接设备（例如，添加桥接、添加接口到桥接）。
    - **Netlink 路径:** `netd` 可能会使用 Netlink 套接字，构建包含 `IFLA_BRIDGE_*` 属性的 Netlink 消息来配置桥接设备的属性（例如，设置 STP 参数、VLAN 配置）。
6. **Linux Kernel (C):** Linux 内核接收到来自用户空间的 `ioctl` 请求或 Netlink 消息后，会调用相应的内核函数来处理桥接相关的操作。这些内核函数会读取和写入与桥接设备相关的内核数据结构。这些数据结构的定义与 `bionic/libc/kernel/uapi/linux/if_bridge.h` 中的结构体定义相对应。

**NDK:**  使用 NDK 的开发者可以直接调用底层的 C/C++ API，因此可以绕过大部分 Framework 层，直接与 `netd` 提供的接口或者直接使用 `ioctl` 或 Netlink 与内核交互。

**Frida Hook 示例调试这些步骤:**

我们可以使用 Frida Hook 来拦截 `netd` 进程中与桥接操作相关的系统调用或 Netlink 函数，以观察参数的传递和执行过程。

**Frida Hook 示例 (拦截 `ioctl` 调用):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python frida_hook_bridge.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            const requests = {
                0x8990: "SIOCBRADDBR",
                0x8991: "SIOCBRDELBR",
                0x8992: "SIOCBRADDIF",
                0x8993: "SIOCBRDELIF",
                0x8994: "SIOCBRGETFDB",
                0x899f: "SIOCGGETBR",
                // ... 添加更多相关的 ioctl 请求
            };

            if (requests[request]) {
                console.log("[*] ioctl called");
                console.log("    fd:", fd);
                console.log("    request:", requests[request], "(" + request + ")");

                if (requests[request] === "SIOCBRADDBR" || requests[request] === "SIOCBRDELBR" || requests[request] === "SIOCBRADDIF" || requests[request] === "SIOCBRDELIF") {
                    const ifr = Memory.alloc(Process.pointerSize * 2 + 16); // 假设 ifreq 结构体
                    Memory.copy(ifr, argp, Process.pointerSize * 2 + 16);
                    const ifr_name = Memory.readCString(ifr);
                    console.log("    ifr_name:", ifr_name);
                } else if (requests[request] === "SIOCGGETBR") {
                    const ifr = Memory.alloc(Process.pointerSize * 2 + 40); // 假设 ifreq 结构体足够大容纳 __bridge_info
                    Memory.copy(ifr, argp, Process.pointerSize * 2 + 40);
                    const ifr_name = Memory.readCString(ifr);
                    console.log("    ifr_name:", ifr_name);
                    // 可以进一步解析 __bridge_info 结构体
                }
            }
        },
        onLeave: function(retval) {
            console.log("[*] ioctl returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Script loaded. Press Ctrl+C to stop.")
    sys.stdin.read()

    session.detach()

if __name__ == '__main__':
    main()
```

**Frida Hook 示例 (拦截 `sendto` 用于 Netlink):**

要 Hook Netlink 相关的操作，可以拦截 `sendto` 系统调用，并检查发送到 Netlink 套接字的消息内容，解析其中的 Netlink 头部和桥接相关的属性。这需要更深入地了解 Netlink 消息的结构。

**使用方法:**

1. 将上述 Python 代码保存为 `frida_hook_bridge.py`。
2. 找到 `netd` 进程的名称或 PID。
3. 运行 `python frida_hook_bridge.py netd` (如果 `netd` 是进程名) 或 `python frida_hook_bridge.py <netd 的 PID>`。
4. 在 Android 设备上执行一些涉及桥接的操作，例如开启 Wi-Fi 热点。
5. Frida Hook 脚本会在终端输出拦截到的 `ioctl` 调用信息，包括请求类型和相关的参数。

通过 Frida Hook，你可以动态地观察 Android 系统在进行桥接操作时如何使用这个头文件中定义的常量和数据结构，从而更深入地理解其工作原理。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/if_bridge.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IF_BRIDGE_H
#define _UAPI_LINUX_IF_BRIDGE_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#define SYSFS_BRIDGE_ATTR "bridge"
#define SYSFS_BRIDGE_FDB "brforward"
#define SYSFS_BRIDGE_PORT_SUBDIR "brif"
#define SYSFS_BRIDGE_PORT_ATTR "brport"
#define SYSFS_BRIDGE_PORT_LINK "bridge"
#define BRCTL_VERSION 1
#define BRCTL_GET_VERSION 0
#define BRCTL_GET_BRIDGES 1
#define BRCTL_ADD_BRIDGE 2
#define BRCTL_DEL_BRIDGE 3
#define BRCTL_ADD_IF 4
#define BRCTL_DEL_IF 5
#define BRCTL_GET_BRIDGE_INFO 6
#define BRCTL_GET_PORT_LIST 7
#define BRCTL_SET_BRIDGE_FORWARD_DELAY 8
#define BRCTL_SET_BRIDGE_HELLO_TIME 9
#define BRCTL_SET_BRIDGE_MAX_AGE 10
#define BRCTL_SET_AGEING_TIME 11
#define BRCTL_SET_GC_INTERVAL 12
#define BRCTL_GET_PORT_INFO 13
#define BRCTL_SET_BRIDGE_STP_STATE 14
#define BRCTL_SET_BRIDGE_PRIORITY 15
#define BRCTL_SET_PORT_PRIORITY 16
#define BRCTL_SET_PATH_COST 17
#define BRCTL_GET_FDB_ENTRIES 18
#define BR_STATE_DISABLED 0
#define BR_STATE_LISTENING 1
#define BR_STATE_LEARNING 2
#define BR_STATE_FORWARDING 3
#define BR_STATE_BLOCKING 4
struct __bridge_info {
  __u64 designated_root;
  __u64 bridge_id;
  __u32 root_path_cost;
  __u32 max_age;
  __u32 hello_time;
  __u32 forward_delay;
  __u32 bridge_max_age;
  __u32 bridge_hello_time;
  __u32 bridge_forward_delay;
  __u8 topology_change;
  __u8 topology_change_detected;
  __u8 root_port;
  __u8 stp_enabled;
  __u32 ageing_time;
  __u32 gc_interval;
  __u32 hello_timer_value;
  __u32 tcn_timer_value;
  __u32 topology_change_timer_value;
  __u32 gc_timer_value;
};
struct __port_info {
  __u64 designated_root;
  __u64 designated_bridge;
  __u16 port_id;
  __u16 designated_port;
  __u32 path_cost;
  __u32 designated_cost;
  __u8 state;
  __u8 top_change_ack;
  __u8 config_pending;
  __u8 unused0;
  __u32 message_age_timer_value;
  __u32 forward_delay_timer_value;
  __u32 hold_timer_value;
};
struct __fdb_entry {
  __u8 mac_addr[ETH_ALEN];
  __u8 port_no;
  __u8 is_local;
  __u32 ageing_timer_value;
  __u8 port_hi;
  __u8 pad0;
  __u16 unused;
};
#define BRIDGE_FLAGS_MASTER 1
#define BRIDGE_FLAGS_SELF 2
#define BRIDGE_MODE_VEB 0
#define BRIDGE_MODE_VEPA 1
#define BRIDGE_MODE_UNDEF 0xFFFF
enum {
  IFLA_BRIDGE_FLAGS,
  IFLA_BRIDGE_MODE,
  IFLA_BRIDGE_VLAN_INFO,
  IFLA_BRIDGE_VLAN_TUNNEL_INFO,
  IFLA_BRIDGE_MRP,
  IFLA_BRIDGE_CFM,
  IFLA_BRIDGE_MST,
  __IFLA_BRIDGE_MAX,
};
#define IFLA_BRIDGE_MAX (__IFLA_BRIDGE_MAX - 1)
#define BRIDGE_VLAN_INFO_MASTER (1 << 0)
#define BRIDGE_VLAN_INFO_PVID (1 << 1)
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)
#define BRIDGE_VLAN_INFO_RANGE_BEGIN (1 << 3)
#define BRIDGE_VLAN_INFO_RANGE_END (1 << 4)
#define BRIDGE_VLAN_INFO_BRENTRY (1 << 5)
#define BRIDGE_VLAN_INFO_ONLY_OPTS (1 << 6)
struct bridge_vlan_info {
  __u16 flags;
  __u16 vid;
};
enum {
  IFLA_BRIDGE_VLAN_TUNNEL_UNSPEC,
  IFLA_BRIDGE_VLAN_TUNNEL_ID,
  IFLA_BRIDGE_VLAN_TUNNEL_VID,
  IFLA_BRIDGE_VLAN_TUNNEL_FLAGS,
  __IFLA_BRIDGE_VLAN_TUNNEL_MAX,
};
#define IFLA_BRIDGE_VLAN_TUNNEL_MAX (__IFLA_BRIDGE_VLAN_TUNNEL_MAX - 1)
struct bridge_vlan_xstats {
  __u64 rx_bytes;
  __u64 rx_packets;
  __u64 tx_bytes;
  __u64 tx_packets;
  __u16 vid;
  __u16 flags;
  __u32 pad2;
};
enum {
  IFLA_BRIDGE_MRP_UNSPEC,
  IFLA_BRIDGE_MRP_INSTANCE,
  IFLA_BRIDGE_MRP_PORT_STATE,
  IFLA_BRIDGE_MRP_PORT_ROLE,
  IFLA_BRIDGE_MRP_RING_STATE,
  IFLA_BRIDGE_MRP_RING_ROLE,
  IFLA_BRIDGE_MRP_START_TEST,
  IFLA_BRIDGE_MRP_INFO,
  IFLA_BRIDGE_MRP_IN_ROLE,
  IFLA_BRIDGE_MRP_IN_STATE,
  IFLA_BRIDGE_MRP_START_IN_TEST,
  __IFLA_BRIDGE_MRP_MAX,
};
#define IFLA_BRIDGE_MRP_MAX (__IFLA_BRIDGE_MRP_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_INSTANCE_UNSPEC,
  IFLA_BRIDGE_MRP_INSTANCE_RING_ID,
  IFLA_BRIDGE_MRP_INSTANCE_P_IFINDEX,
  IFLA_BRIDGE_MRP_INSTANCE_S_IFINDEX,
  IFLA_BRIDGE_MRP_INSTANCE_PRIO,
  __IFLA_BRIDGE_MRP_INSTANCE_MAX,
};
#define IFLA_BRIDGE_MRP_INSTANCE_MAX (__IFLA_BRIDGE_MRP_INSTANCE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_PORT_STATE_UNSPEC,
  IFLA_BRIDGE_MRP_PORT_STATE_STATE,
  __IFLA_BRIDGE_MRP_PORT_STATE_MAX,
};
#define IFLA_BRIDGE_MRP_PORT_STATE_MAX (__IFLA_BRIDGE_MRP_PORT_STATE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_PORT_ROLE_UNSPEC,
  IFLA_BRIDGE_MRP_PORT_ROLE_ROLE,
  __IFLA_BRIDGE_MRP_PORT_ROLE_MAX,
};
#define IFLA_BRIDGE_MRP_PORT_ROLE_MAX (__IFLA_BRIDGE_MRP_PORT_ROLE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_RING_STATE_UNSPEC,
  IFLA_BRIDGE_MRP_RING_STATE_RING_ID,
  IFLA_BRIDGE_MRP_RING_STATE_STATE,
  __IFLA_BRIDGE_MRP_RING_STATE_MAX,
};
#define IFLA_BRIDGE_MRP_RING_STATE_MAX (__IFLA_BRIDGE_MRP_RING_STATE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_RING_ROLE_UNSPEC,
  IFLA_BRIDGE_MRP_RING_ROLE_RING_ID,
  IFLA_BRIDGE_MRP_RING_ROLE_ROLE,
  __IFLA_BRIDGE_MRP_RING_ROLE_MAX,
};
#define IFLA_BRIDGE_MRP_RING_ROLE_MAX (__IFLA_BRIDGE_MRP_RING_ROLE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_START_TEST_UNSPEC,
  IFLA_BRIDGE_MRP_START_TEST_RING_ID,
  IFLA_BRIDGE_MRP_START_TEST_INTERVAL,
  IFLA_BRIDGE_MRP_START_TEST_MAX_MISS,
  IFLA_BRIDGE_MRP_START_TEST_PERIOD,
  IFLA_BRIDGE_MRP_START_TEST_MONITOR,
  __IFLA_BRIDGE_MRP_START_TEST_MAX,
};
#define IFLA_BRIDGE_MRP_START_TEST_MAX (__IFLA_BRIDGE_MRP_START_TEST_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_INFO_UNSPEC,
  IFLA_BRIDGE_MRP_INFO_RING_ID,
  IFLA_BRIDGE_MRP_INFO_P_IFINDEX,
  IFLA_BRIDGE_MRP_INFO_S_IFINDEX,
  IFLA_BRIDGE_MRP_INFO_PRIO,
  IFLA_BRIDGE_MRP_INFO_RING_STATE,
  IFLA_BRIDGE_MRP_INFO_RING_ROLE,
  IFLA_BRIDGE_MRP_INFO_TEST_INTERVAL,
  IFLA_BRIDGE_MRP_INFO_TEST_MAX_MISS,
  IFLA_BRIDGE_MRP_INFO_TEST_MONITOR,
  IFLA_BRIDGE_MRP_INFO_I_IFINDEX,
  IFLA_BRIDGE_MRP_INFO_IN_STATE,
  IFLA_BRIDGE_MRP_INFO_IN_ROLE,
  IFLA_BRIDGE_MRP_INFO_IN_TEST_INTERVAL,
  IFLA_BRIDGE_MRP_INFO_IN_TEST_MAX_MISS,
  __IFLA_BRIDGE_MRP_INFO_MAX,
};
#define IFLA_BRIDGE_MRP_INFO_MAX (__IFLA_BRIDGE_MRP_INFO_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_IN_STATE_UNSPEC,
  IFLA_BRIDGE_MRP_IN_STATE_IN_ID,
  IFLA_BRIDGE_MRP_IN_STATE_STATE,
  __IFLA_BRIDGE_MRP_IN_STATE_MAX,
};
#define IFLA_BRIDGE_MRP_IN_STATE_MAX (__IFLA_BRIDGE_MRP_IN_STATE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_IN_ROLE_UNSPEC,
  IFLA_BRIDGE_MRP_IN_ROLE_RING_ID,
  IFLA_BRIDGE_MRP_IN_ROLE_IN_ID,
  IFLA_BRIDGE_MRP_IN_ROLE_ROLE,
  IFLA_BRIDGE_MRP_IN_ROLE_I_IFINDEX,
  __IFLA_BRIDGE_MRP_IN_ROLE_MAX,
};
#define IFLA_BRIDGE_MRP_IN_ROLE_MAX (__IFLA_BRIDGE_MRP_IN_ROLE_MAX - 1)
enum {
  IFLA_BRIDGE_MRP_START_IN_TEST_UNSPEC,
  IFLA_BRIDGE_MRP_START_IN_TEST_IN_ID,
  IFLA_BRIDGE_MRP_START_IN_TEST_INTERVAL,
  IFLA_BRIDGE_MRP_START_IN_TEST_MAX_MISS,
  IFLA_BRIDGE_MRP_START_IN_TEST_PERIOD,
  __IFLA_BRIDGE_MRP_START_IN_TEST_MAX,
};
#define IFLA_BRIDGE_MRP_START_IN_TEST_MAX (__IFLA_BRIDGE_MRP_START_IN_TEST_MAX - 1)
struct br_mrp_instance {
  __u32 ring_id;
  __u32 p_ifindex;
  __u32 s_ifindex;
  __u16 prio;
};
struct br_mrp_ring_state {
  __u32 ring_id;
  __u32 ring_state;
};
struct br_mrp_ring_role {
  __u32 ring_id;
  __u32 ring_role;
};
struct br_mrp_start_test {
  __u32 ring_id;
  __u32 interval;
  __u32 max_miss;
  __u32 period;
  __u32 monitor;
};
struct br_mrp_in_state {
  __u32 in_state;
  __u16 in_id;
};
struct br_mrp_in_role {
  __u32 ring_id;
  __u32 in_role;
  __u32 i_ifindex;
  __u16 in_id;
};
struct br_mrp_start_in_test {
  __u32 interval;
  __u32 max_miss;
  __u32 period;
  __u16 in_id;
};
enum {
  IFLA_BRIDGE_CFM_UNSPEC,
  IFLA_BRIDGE_CFM_MEP_CREATE,
  IFLA_BRIDGE_CFM_MEP_DELETE,
  IFLA_BRIDGE_CFM_MEP_CONFIG,
  IFLA_BRIDGE_CFM_CC_CONFIG,
  IFLA_BRIDGE_CFM_CC_PEER_MEP_ADD,
  IFLA_BRIDGE_CFM_CC_PEER_MEP_REMOVE,
  IFLA_BRIDGE_CFM_CC_RDI,
  IFLA_BRIDGE_CFM_CC_CCM_TX,
  IFLA_BRIDGE_CFM_MEP_CREATE_INFO,
  IFLA_BRIDGE_CFM_MEP_CONFIG_INFO,
  IFLA_BRIDGE_CFM_CC_CONFIG_INFO,
  IFLA_BRIDGE_CFM_CC_RDI_INFO,
  IFLA_BRIDGE_CFM_CC_CCM_TX_INFO,
  IFLA_BRIDGE_CFM_CC_PEER_MEP_INFO,
  IFLA_BRIDGE_CFM_MEP_STATUS_INFO,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_INFO,
  __IFLA_BRIDGE_CFM_MAX,
};
#define IFLA_BRIDGE_CFM_MAX (__IFLA_BRIDGE_CFM_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_MEP_CREATE_UNSPEC,
  IFLA_BRIDGE_CFM_MEP_CREATE_INSTANCE,
  IFLA_BRIDGE_CFM_MEP_CREATE_DOMAIN,
  IFLA_BRIDGE_CFM_MEP_CREATE_DIRECTION,
  IFLA_BRIDGE_CFM_MEP_CREATE_IFINDEX,
  __IFLA_BRIDGE_CFM_MEP_CREATE_MAX,
};
#define IFLA_BRIDGE_CFM_MEP_CREATE_MAX (__IFLA_BRIDGE_CFM_MEP_CREATE_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_MEP_DELETE_UNSPEC,
  IFLA_BRIDGE_CFM_MEP_DELETE_INSTANCE,
  __IFLA_BRIDGE_CFM_MEP_DELETE_MAX,
};
#define IFLA_BRIDGE_CFM_MEP_DELETE_MAX (__IFLA_BRIDGE_CFM_MEP_DELETE_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_MEP_CONFIG_UNSPEC,
  IFLA_BRIDGE_CFM_MEP_CONFIG_INSTANCE,
  IFLA_BRIDGE_CFM_MEP_CONFIG_UNICAST_MAC,
  IFLA_BRIDGE_CFM_MEP_CONFIG_MDLEVEL,
  IFLA_BRIDGE_CFM_MEP_CONFIG_MEPID,
  __IFLA_BRIDGE_CFM_MEP_CONFIG_MAX,
};
#define IFLA_BRIDGE_CFM_MEP_CONFIG_MAX (__IFLA_BRIDGE_CFM_MEP_CONFIG_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_CC_CONFIG_UNSPEC,
  IFLA_BRIDGE_CFM_CC_CONFIG_INSTANCE,
  IFLA_BRIDGE_CFM_CC_CONFIG_ENABLE,
  IFLA_BRIDGE_CFM_CC_CONFIG_EXP_INTERVAL,
  IFLA_BRIDGE_CFM_CC_CONFIG_EXP_MAID,
  __IFLA_BRIDGE_CFM_CC_CONFIG_MAX,
};
#define IFLA_BRIDGE_CFM_CC_CONFIG_MAX (__IFLA_BRIDGE_CFM_CC_CONFIG_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_CC_PEER_MEP_UNSPEC,
  IFLA_BRIDGE_CFM_CC_PEER_MEP_INSTANCE,
  IFLA_BRIDGE_CFM_CC_PEER_MEPID,
  __IFLA_BRIDGE_CFM_CC_PEER_MEP_MAX,
};
#define IFLA_BRIDGE_CFM_CC_PEER_MEP_MAX (__IFLA_BRIDGE_CFM_CC_PEER_MEP_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_CC_RDI_UNSPEC,
  IFLA_BRIDGE_CFM_CC_RDI_INSTANCE,
  IFLA_BRIDGE_CFM_CC_RDI_RDI,
  __IFLA_BRIDGE_CFM_CC_RDI_MAX,
};
#define IFLA_BRIDGE_CFM_CC_RDI_MAX (__IFLA_BRIDGE_CFM_CC_RDI_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_CC_CCM_TX_UNSPEC,
  IFLA_BRIDGE_CFM_CC_CCM_TX_INSTANCE,
  IFLA_BRIDGE_CFM_CC_CCM_TX_DMAC,
  IFLA_BRIDGE_CFM_CC_CCM_TX_SEQ_NO_UPDATE,
  IFLA_BRIDGE_CFM_CC_CCM_TX_PERIOD,
  IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV,
  IFLA_BRIDGE_CFM_CC_CCM_TX_IF_TLV_VALUE,
  IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV,
  IFLA_BRIDGE_CFM_CC_CCM_TX_PORT_TLV_VALUE,
  __IFLA_BRIDGE_CFM_CC_CCM_TX_MAX,
};
#define IFLA_BRIDGE_CFM_CC_CCM_TX_MAX (__IFLA_BRIDGE_CFM_CC_CCM_TX_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_MEP_STATUS_UNSPEC,
  IFLA_BRIDGE_CFM_MEP_STATUS_INSTANCE,
  IFLA_BRIDGE_CFM_MEP_STATUS_OPCODE_UNEXP_SEEN,
  IFLA_BRIDGE_CFM_MEP_STATUS_VERSION_UNEXP_SEEN,
  IFLA_BRIDGE_CFM_MEP_STATUS_RX_LEVEL_LOW_SEEN,
  __IFLA_BRIDGE_CFM_MEP_STATUS_MAX,
};
#define IFLA_BRIDGE_CFM_MEP_STATUS_MAX (__IFLA_BRIDGE_CFM_MEP_STATUS_MAX - 1)
enum {
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_UNSPEC,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_INSTANCE,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_PEER_MEPID,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_CCM_DEFECT,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_RDI,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_PORT_TLV_VALUE,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_IF_TLV_VALUE,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEEN,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_TLV_SEEN,
  IFLA_BRIDGE_CFM_CC_PEER_STATUS_SEQ_UNEXP_SEEN,
  __IFLA_BRIDGE_CFM_CC_PEER_STATUS_MAX,
};
#define IFLA_BRIDGE_CFM_CC_PEER_STATUS_MAX (__IFLA_BRIDGE_CFM_CC_PEER_STATUS_MAX - 1)
enum {
  IFLA_BRIDGE_MST_UNSPEC,
  IFLA_BRIDGE_MST_ENTRY,
  __IFLA_BRIDGE_MST_MAX,
};
#define IFLA_BRIDGE_MST_MAX (__IFLA_BRIDGE_MST_MAX - 1)
enum {
  IFLA_BRIDGE_MST_ENTRY_UNSPEC,
  IFLA_BRIDGE_MST_ENTRY_MSTI,
  IFLA_BRIDGE_MST_ENTRY_STATE,
  __IFLA_BRIDGE_MST_ENTRY_MAX,
};
#define IFLA_BRIDGE_MST_ENTRY_MAX (__IFLA_BRIDGE_MST_ENTRY_MAX - 1)
struct bridge_stp_xstats {
  __u64 transition_blk;
  __u64 transition_fwd;
  __u64 rx_bpdu;
  __u64 tx_bpdu;
  __u64 rx_tcn;
  __u64 tx_tcn;
};
struct br_vlan_msg {
  __u8 family;
  __u8 reserved1;
  __u16 reserved2;
  __u32 ifindex;
};
enum {
  BRIDGE_VLANDB_DUMP_UNSPEC,
  BRIDGE_VLANDB_DUMP_FLAGS,
  __BRIDGE_VLANDB_DUMP_MAX,
};
#define BRIDGE_VLANDB_DUMP_MAX (__BRIDGE_VLANDB_DUMP_MAX - 1)
#define BRIDGE_VLANDB_DUMPF_STATS (1 << 0)
#define BRIDGE_VLANDB_DUMPF_GLOBAL (1 << 1)
enum {
  BRIDGE_VLANDB_UNSPEC,
  BRIDGE_VLANDB_ENTRY,
  BRIDGE_VLANDB_GLOBAL_OPTIONS,
  __BRIDGE_VLANDB_MAX,
};
#define BRIDGE_VLANDB_MAX (__BRIDGE_VLANDB_MAX - 1)
enum {
  BRIDGE_VLANDB_ENTRY_UNSPEC,
  BRIDGE_VLANDB_ENTRY_INFO,
  BRIDGE_VLANDB_ENTRY_RANGE,
  BRIDGE_VLANDB_ENTRY_STATE,
  BRIDGE_VLANDB_ENTRY_TUNNEL_INFO,
  BRIDGE_VLANDB_ENTRY_STATS,
  BRIDGE_VLANDB_ENTRY_MCAST_ROUTER,
  BRIDGE_VLANDB_ENTRY_MCAST_N_GROUPS,
  BRIDGE_VLANDB_ENTRY_MCAST_MAX_GROUPS,
  BRIDGE_VLANDB_ENTRY_NEIGH_SUPPRESS,
  __BRIDGE_VLANDB_ENTRY_MAX,
};
#define BRIDGE_VLANDB_ENTRY_MAX (__BRIDGE_VLANDB_ENTRY_MAX - 1)
enum {
  BRIDGE_VLANDB_TINFO_UNSPEC,
  BRIDGE_VLANDB_TINFO_ID,
  BRIDGE_VLANDB_TINFO_CMD,
  __BRIDGE_VLANDB_TINFO_MAX,
};
#define BRIDGE_VLANDB_TINFO_MAX (__BRIDGE_VLANDB_TINFO_MAX - 1)
enum {
  BRIDGE_VLANDB_STATS_UNSPEC,
  BRIDGE_VLANDB_STATS_RX_BYTES,
  BRIDGE_VLANDB_STATS_RX_PACKETS,
  BRIDGE_VLANDB_STATS_TX_BYTES,
  BRIDGE_VLANDB_STATS_TX_PACKETS,
  BRIDGE_VLANDB_STATS_PAD,
  __BRIDGE_VLANDB_STATS_MAX,
};
#define BRIDGE_VLANDB_STATS_MAX (__BRIDGE_VLANDB_STATS_MAX - 1)
enum {
  BRIDGE_VLANDB_GOPTS_UNSPEC,
  BRIDGE_VLANDB_GOPTS_ID,
  BRIDGE_VLANDB_GOPTS_RANGE,
  BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING,
  BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION,
  BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION,
  BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT,
  BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT,
  BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL,
  BRIDGE_VLANDB_GOPTS_PAD,
  BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL,
  BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL,
  BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL,
  BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
  BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL,
  BRIDGE_VLANDB_GOPTS_MCAST_QUERIER,
  BRIDGE_VLANDB_GOPTS_MCAST_ROUTER_PORTS,
  BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_STATE,
  BRIDGE_VLANDB_GOPTS_MSTI,
  __BRIDGE_VLANDB_GOPTS_MAX
};
#define BRIDGE_VLANDB_GOPTS_MAX (__BRIDGE_VLANDB_GOPTS_MAX - 1)
enum {
  MDBA_UNSPEC,
  MDBA_MDB,
  MDBA_ROUTER,
  __MDBA_MAX,
};
#define MDBA_MAX (__MDBA_MAX - 1)
enum {
  MDBA_MDB_UNSPEC,
  MDBA_MDB_ENTRY,
  __MDBA_MDB_MAX,
};
#define MDBA_MDB_MAX (__MDBA_MDB_MAX - 1)
enum {
  MDBA_MDB_ENTRY_UNSPEC,
  MDBA_MDB_ENTRY_INFO,
  __MDBA_MDB_ENTRY_MAX,
};
#define MDBA_MDB_ENTRY_MAX (__MDBA_MDB_ENTRY_MAX - 1)
enum {
  MDBA_MDB_EATTR_UNSPEC,
  MDBA_MDB_EATTR_TIMER,
  MDBA_MDB_EATTR_SRC_LIST,
  MDBA_MDB_EATTR_GROUP_MODE,
  MDBA_MDB_EATTR_SOURCE,
  MDBA_MDB_EATTR_RTPROT,
  MDBA_MDB_EATTR_DST,
  MDBA_MDB_EATTR_DST_PORT,
  MDBA_MDB_EATTR_VNI,
  MDBA_MDB_EATTR_IFINDEX,
  MDBA_MDB_EATTR_SRC_VNI,
  __MDBA_MDB_EATTR_MAX
};
#define MDBA_MDB_EATTR_MAX (__MDBA_MDB_EATTR_MAX - 1)
enum {
  MDBA_MDB_SRCLIST_UNSPEC,
  MDBA_MDB_SRCLIST_ENTRY,
  __MDBA_MDB_SRCLIST_MAX
};
#define MDBA_MDB_SRCLIST_MAX (__MDBA_MDB_SRCLIST_MAX - 1)
enum {
  MDBA_MDB_SRCATTR_UNSPEC,
  MDBA_MDB_SRCATTR_ADDRESS,
  MDBA_MDB_SRCATTR_TIMER,
  __MDBA_MDB_SRCATTR_MAX
};
#define MDBA_MDB_SRCATTR_MAX (__MDBA_MDB_SRCATTR_MAX - 1)
enum {
  MDB_RTR_TYPE_DISABLED,
  MDB_RTR_TYPE_TEMP_QUERY,
  MDB_RTR_TYPE_PERM,
  MDB_RTR_TYPE_TEMP
};
enum {
  MDBA_ROUTER_UNSPEC,
  MDBA_ROUTER_PORT,
  __MDBA_ROUTER_MAX,
};
#define MDBA_ROUTER_MAX (__MDBA_ROUTER_MAX - 1)
enum {
  MDBA_ROUTER_PATTR_UNSPEC,
  MDBA_ROUTER_PATTR_TIMER,
  MDBA_ROUTER_PATTR_TYPE,
  MDBA_ROUTER_PATTR_INET_TIMER,
  MDBA_ROUTER_PATTR_INET6_TIMER,
  MDBA_ROUTER_PATTR_VID,
  __MDBA_ROUTER_PATTR_MAX
};
#define MDBA_ROUTER_PATTR_MAX (__MDBA_ROUTER_PATTR_MAX - 1)
struct br_port_msg {
  __u8 family;
  __u32 ifindex;
};
struct br_mdb_entry {
  __u32 ifindex;
#define MDB_TEMPORARY 0
#define MDB_PERMANENT 1
  __u8 state;
#define MDB_FLAGS_OFFLOAD (1 << 0)
#define MDB_FLAGS_FAST_LEAVE (1 << 1)
#define MDB_FLAGS_STAR_EXCL (1 << 2)
#define MDB_FLAGS_BLOCKED (1 << 3)
  __u8 flags;
  __u16 vid;
  struct {
    union {
      __be32 ip4;
      struct in6_addr ip6;
      unsigned char mac_addr[ETH_ALEN];
    } u;
    __be16 proto;
  } addr;
};
enum {
  MDBA_SET_ENTRY_UNSPEC,
  MDBA_SET_ENTRY,
  MDBA_SET_ENTRY_ATTRS,
  __MDBA_SET_ENTRY_MAX,
};
#define MDBA_SET_ENTRY_MAX (__MDBA_SET_ENTRY_MAX - 1)
enum {
  MDBA_GET_ENTRY_UNSPEC,
  MDBA_GET_ENTRY,
  MDBA_GET_ENTRY_ATTRS,
  __MDBA_GET_ENTRY_MAX,
};
#define MDBA_GET_ENTRY_MAX (__MDBA_GET_ENTRY_MAX - 1)
enum {
  MDBE_ATTR_UNSPEC,
  MDBE_ATTR_SOURCE,
  MDBE_ATTR_SRC_LIST,
  MDBE_ATTR_GROUP_MODE,
  MDBE_ATTR_RTPROT,
  MDBE_ATTR_DST,
  MDBE_ATTR_DST_PORT,
  MDBE_ATTR_VNI,
  MDBE_ATTR_IFINDEX,
  MDBE_ATTR_SRC_VNI,
  MDBE_ATTR_STATE_MASK,
  __MDBE_ATTR_MAX,
};
#define MDBE_ATTR_MAX (__MDBE_ATTR_MAX - 1)
enum {
  MDBE_SRC_LIST_UNSPEC,
  MDBE_SRC_LIST_ENTRY,
  __MDBE_SRC_LIST_MAX,
};
#define MDBE_SRC_LIST_MAX (__MDBE_SRC_LIST_MAX - 1)
enum {
  MDBE_SRCATTR_UNSPEC,
  MDBE_SRCATTR_ADDRESS,
  __MDBE_SRCATTR_MAX,
};
#define MDBE_SRCATTR_MAX (__MDBE_SRCATTR_MAX - 1)
enum {
  BRIDGE_XSTATS_UNSPEC,
  BRIDGE_XSTATS_VLAN,
  BRIDGE_XSTATS_MCAST,
  BRIDGE_XSTATS_PAD,
  BRIDGE_XSTATS_STP,
  __BRIDGE_XSTATS_MAX
};
#define BRIDGE_XSTATS_MAX (__BRIDGE_XSTATS_MAX - 1)
enum {
  BR_MCAST_DIR_RX,
  BR_MCAST_DIR_TX,
  BR_MCAST_DIR_SIZE
};
struct br_mcast_stats {
  __u64 igmp_v1queries[BR_MCAST_DIR_SIZE];
  __u64 igmp_v2queries[BR_MCAST_DIR_SIZE];
  __u64 igmp_v3queries[BR_MCAST_DIR_SIZE];
  __u64 igmp_leaves[BR_MCAST_DIR_SIZE];
  __u64 igmp_v1reports[BR_MCAST_DIR_SIZE];
  __u64 igmp_v2reports[BR_MCAST_DIR_SIZE];
  __u64 igmp_v3reports[BR_MCAST_DIR_SIZE];
  __u64 igmp_parse_errors;
  __u64 mld_v1queries[BR_MCAST_DIR_SIZE];
  __u64 mld_v2queries[BR_MCAST_DIR_SIZE];
  __u64 mld_leaves[BR_MCAST_DIR_SIZE];
  __u64 mld_v1reports[BR_MCAST_DIR_SIZE];
  __u64 mld_v2reports[BR_MCAST_DIR_SIZE];
  __u64 mld_parse_errors;
  __u64 mcast_bytes[BR_MCAST_DIR_SIZE];
  __u64 mcast_packets[BR_MCAST_DIR_SIZE];
};
enum br_boolopt_id {
  BR_BOOLOPT_NO_LL_LEARN,
  BR_BOOLOPT_MCAST_VLAN_SNOOPING,
  BR_BOOLOPT_MST_ENABLE,
  BR_BOOLOPT_MAX
};
struct br_boolopt_multi {
  __u32 optval;
  __u32 optmask;
};
enum {
  BRIDGE_QUERIER_UNSPEC,
  BRIDGE_QUERIER_IP_ADDRESS,
  BRIDGE_QUERIER_IP_PORT,
  BRIDGE_QUERIER_IP_OTHER_TIMER,
  BRIDGE_QUERIER_PAD,
  BRIDGE_QUERIER_IPV6_ADDRESS,
  BRIDGE_QUERIER_IPV6_PORT,
  BRIDGE_QUERIER_IPV6_OTHER_TIMER,
  __BRIDGE_QUERIER_MAX
};
#define BRIDGE_QUERIER_MAX (__BRIDGE_QUERIER_MAX - 1)
#endif
```