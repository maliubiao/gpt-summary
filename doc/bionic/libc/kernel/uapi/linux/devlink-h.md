Response:
Let's break down the thought process to answer the user's request about the `devlink.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided header file (`devlink.h`) within the context of Android. They are particularly interested in its relationship to Android's features, the implementation details of related libc functions (though this is less applicable to a header file), dynamic linker aspects, common errors, and how Android frameworks and the NDK interact with it. They also want Frida hook examples.

**2. Initial Assessment of the File:**

The file itself is a C header file (`.h`). Crucially, it starts with:

```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_DEVLINK_H_
#define _UAPI_LINUX_DEVLINK_H_
// ... rest of the file
```

This tells us several important things:

* **Auto-generated:** This means the file isn't directly written by humans but created by a tool. This implies a source of truth exists elsewhere (likely in the Linux kernel source).
* **UAPI (User API):**  This signifies that the definitions within are intended for use by user-space programs.
* **Linux Kernel Interface:** The file is located within the `bionic/libc/kernel/uapi/linux/` directory, indicating it's a header file defining interfaces to the Linux kernel.
* **No Actual Function Implementations:**  Header files primarily declare types, constants, and macros. They don't contain the actual *implementation* of functions. Therefore, the request to "详细解释每一个libc函数的功能是如何实现的" is not directly applicable to this file. We need to shift the focus to the *meaning* of the definitions.

**3. Deconstructing the Header File Content:**

The header file mainly defines:

* **Macros:** `DEVLINK_GENL_NAME`, `DEVLINK_GENL_VERSION`, `DEVLINK_GENL_MCGRP_CONFIG_NAME`, and a few bit manipulation macros.
* **Enums:** A large number of enums like `devlink_command`, `devlink_port_type`, `devlink_sb_pool_type`, etc. These enums represent different categories of actions, types of devices/resources, and states within the devlink subsystem.
* **Attribute Enums:** Enums named `devlink_attr_*` define the various attributes that can be associated with devlink objects.
* **Structure Definitions (Implicit):** Although not explicitly present, the enums and attributes strongly suggest the existence of data structures in the kernel that these definitions relate to.

**4. Identifying Key Concepts:**

Based on the enums and macros, the core functionality revolves around:

* **`devlink`:**  This is the central entity. It manages network devices.
* **Generic Netlink (Genl):**  The `DEVLINK_GENL_NAME` suggests the `devlink` subsystem communicates with user-space through the generic netlink protocol.
* **Ports:**  Represent physical or virtual network interfaces.
* **Switch Buffers (SB):**  Related to quality of service (QoS) and traffic management.
* **E-Switch:**  Refers to the embedded switch functionality in some network devices.
* **D-Pipe (Data Pipe):**  Likely related to data path programming and filtering rules.
* **Resources:**  Manage hardware resources on the device.
* **Parameters:**  Configuration settings for the device.
* **Regions:**  Memory regions on the device.
* **Health Reporters:**  Mechanisms for monitoring device health and reporting errors.
* **Firmware Updates:**  Managing firmware upgrades.
* **Traps:**  Mechanisms for intercepting specific network traffic or events.
* **Rates:**  Traffic shaping and rate limiting.
* **Line Cards:**  Physical interface cards in a network device.
* **Self-Tests:**  Diagnostic tests for the device.

**5. Connecting to Android Functionality:**

This is where we consider how these low-level network device management features might be used in Android:

* **Network Interface Management:** Android needs to configure and manage network interfaces (Wi-Fi, cellular, Ethernet). `devlink` provides a standardized way to interact with the underlying hardware.
* **Virtualization:**  Features like splitting ports (`DEVLINK_CMD_PORT_SPLIT`) and managing virtual functions (PCI-VF) are relevant for virtualization and containerization within Android.
* **QoS:**  The switch buffer (SB) related commands suggest control over traffic prioritization, important for ensuring a smooth user experience.
* **Firmware Updates:**  Android devices need to update the firmware of network interface controllers.
* **Debugging and Diagnostics:**  Health reporters and self-tests can be used for debugging network issues on Android devices.

**6. Addressing Specific User Questions:**

* **libc Function Implementation:**  As stated before, header files don't implement functions. We explain that this file *defines* the interface used by tools that *do* interact with the kernel via netlink.
* **Dynamic Linker:**  This header file itself isn't directly linked by user-space programs in the traditional sense. It's included by other system libraries or tools that use the netlink interface. We need to illustrate how a tool using these definitions might be structured and how the dynamic linker would handle its dependencies.
* **Common Errors:**  Focus on misusing the constants and enums defined in the header, or incorrect netlink message construction.
* **Android Framework/NDK Path:**  Outline the likely path, starting from high-level Android APIs, down to system services, and finally to tools that use netlink and this header file.
* **Frida Hooking:** Demonstrate how to hook functions in the tools that use these definitions, not the header file itself. Hooking `sendto` or a netlink library function would be appropriate.

**7. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request. Use clear headings and examples. Emphasize the distinction between header file definitions and actual implementations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this directly relates to specific Android network settings.
* **Correction:** While related, it's a lower-level interface used by system components, not directly exposed in standard Android settings.
* **Initial thought:**  Explain how `open()` and `read()` work with this file.
* **Correction:** This is a header file. It's `#include`d, not directly opened or read at runtime in the same way a data file is. Focus on its role in compilation.
* **Initial thought:** Provide complex C code examples directly using these definitions.
* **Refinement:**  Keep the examples simple and focused on the core concepts, like constructing a basic netlink message.

By following this detailed thought process, we can generate a comprehensive and accurate answer that addresses all aspects of the user's request, even those that might initially seem misdirected (like asking for libc function implementations within a header file). The key is to understand the *context* and the *role* of the provided file within the larger Android ecosystem.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/devlink.h` 这个头文件。

**功能概述**

`devlink.h` 是 Linux 内核提供给用户空间程序 (包括 Android 系统) 的一个头文件，它定义了与 `devlink` 子系统交互的常量、枚举和数据结构。`devlink` 子系统是 Linux 内核中用于管理网络设备的驱动程序和硬件的通用框架。  它的主要功能是提供一种统一的、可扩展的方式来：

* **发现和枚举网络设备:** 获取系统中存在的网络设备的信息。
* **配置网络设备:** 设置设备的各种参数，例如端口类型、速率限制、QoS 等。
* **管理设备资源:**  分配和管理设备上的硬件资源，例如内存、队列等。
* **监控设备状态:**  获取设备的运行状态、统计信息和健康状况。
* **执行设备操作:**  执行特定的设备操作，例如固件升级、重启等。

**与 Android 功能的关系及举例说明**

`devlink` 子系统以及 `devlink.h` 中定义的接口在 Android 系统中扮演着重要的角色，因为它直接关联到 Android 设备的网络功能。以下是一些具体的例子：

1. **网络接口管理:** Android 系统需要管理各种网络接口，例如 Wi-Fi、蓝牙、以太网、蜂窝网络等。`devlink` 提供了底层的接口来查询和配置这些网络接口的属性。例如，Android 系统可能使用 `DEVLINK_CMD_PORT_GET` 命令来获取特定网络端口的信息（例如接口索引、名称、类型），并使用 `DEVLINK_CMD_PORT_SET` 命令来配置端口的某些属性。

2. **虚拟化和容器化:** 在 Android 中，可能会使用虚拟化技术（例如运行虚拟机或容器）。`devlink` 可以用来管理虚拟网络设备和物理网络设备的连接和配置。例如，`DEVLINK_CMD_PORT_SPLIT` 可以用于将一个物理端口拆分成多个虚拟端口，供不同的虚拟机或容器使用。

3. **网络设备驱动程序开发:**  Android 的硬件抽象层 (HAL) 中的网络相关模块，以及更底层的设备驱动程序，可能会使用 `devlink` 接口与内核交互。驱动程序可以使用 `devlink` 来注册自身并暴露其管理功能。

4. **QoS (服务质量) 管理:** `devlink` 提供了管理设备上的流量控制和 QoS 功能的接口，例如通过 `DEVLINK_CMD_SB_GET/SET/NEW/DEL` 系列命令来管理交换缓冲区 (Switch Buffers)，从而控制不同类型流量的优先级和带宽分配。Android 系统可能会利用这些功能来优化网络性能，例如确保语音通话或视频流的流畅性。

5. **固件升级:** 一些网络设备允许固件升级。`devlink` 提供了 `DEVLINK_CMD_FLASH_UPDATE` 等命令来执行固件更新操作。Android 系统在进行 OTA (Over-The-Air) 更新时，可能涉及到更新网络设备的固件。

**libc 函数的实现**

`devlink.h` 本身是一个头文件，它只包含宏定义、枚举和结构体声明，并不包含任何 C 函数的实现代码。它的作用是为使用 `devlink` 子系统的程序提供编译时的类型和常量信息。

用户空间的程序要与 `devlink` 子系统交互，通常会使用 **Netlink Socket**。Netlink 是一种特殊的进程间通信 (IPC) 机制，Linux 内核用它来与用户空间的进程交换信息。

与 `devlink` 交互的步骤通常如下：

1. **创建 Netlink Socket:** 使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` 创建一个 Netlink socket。
2. **绑定 Socket:** 将 socket 绑定到 `devlink` 的通用 Netlink 协议族。
3. **构造 Netlink 消息:**  根据需要执行的 `devlink` 命令，构造包含命令类型和相关属性的 Netlink 消息。消息的格式需要符合 Netlink 协议和 `devlink` 子系统的规范。这通常涉及到使用 `nlmsghdr` 和 `genlmsghdr` 结构体，以及 Netlink 属性 (NLA) 来编码数据。
4. **发送 Netlink 消息:** 使用 `sendto()` 系统调用将构造好的 Netlink 消息发送到内核。
5. **接收 Netlink 消息:** 使用 `recvfrom()` 系统调用从内核接收响应消息。
6. **解析 Netlink 消息:** 解析接收到的消息，提取出内核返回的数据。

**动态链接器功能及 SO 布局样本和链接过程**

`devlink.h` 本身不是一个可执行的共享库 (SO)。它是一个头文件，在编译时被包含到其他源文件中。因此，它不涉及动态链接的过程。

然而，如果用户空间的程序使用了与 `devlink` 交互的共享库（例如，可能存在一个封装了 Netlink 交互的库），那么动态链接器就会发挥作用。

**SO 布局样本 (假设存在一个名为 `libdevlink_wrapper.so` 的库):**

```
libdevlink_wrapper.so:
    .init         # 初始化代码段
    .plt          # 过程链接表
    .text         # 代码段 (包含封装 Netlink 交互的函数)
    .rodata       # 只读数据段
    .data         # 可读写数据段
    .bss          # 未初始化数据段
```

**链接的处理过程:**

1. **编译时:** 编译器在编译依赖 `libdevlink_wrapper.so` 的程序时，会记录下对该库中函数的符号引用。
2. **加载时:** 当程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责加载程序依赖的共享库 `libdevlink_wrapper.so` 到内存中。
3. **符号解析:** 动态链接器会解析程序中对 `libdevlink_wrapper.so` 中函数的符号引用，并将这些引用绑定到库中实际的函数地址。这通常通过查看 `libdevlink_wrapper.so` 的导出符号表和程序的导入符号表来完成。
4. **重定位:**  如果 `libdevlink_wrapper.so` 中的代码或数据引用了其加载地址相关的地址，动态链接器会进行重定位，调整这些地址使其在当前内存布局中有效。
5. **PLT (过程链接表) 和 GOT (全局偏移量表):**  对于延迟绑定的情况，动态链接器会设置 PLT 和 GOT 条目，使得第一次调用 `libdevlink_wrapper.so` 中的函数时，会触发动态链接器去解析和绑定该函数的地址。后续调用将直接跳转到已解析的地址。

**逻辑推理 (假设输入与输出)**

由于 `devlink.h` 主要是定义，逻辑推理更多体现在如何使用这些定义来构造 Netlink 消息。

**假设输入:** 用户空间程序想要获取名为 "eth0" 的网络端口的类型。

**逻辑推理过程:**

1. **确定 Devlink 命令:** 需要使用 `DEVLINK_CMD_PORT_GET` 命令。
2. **构建 Netlink 消息头部:**  创建一个 `nlmsghdr` 结构体，设置消息类型为 `RTM_GETLINK`（虽然 `devlink` 使用通用 Netlink，但这里只是一个概念上的对应），标志为 `NLM_F_REQUEST`，以及消息长度。
3. **构建通用 Netlink 头部:** 创建一个 `genlmsghdr` 结构体，设置命令 ID 为 `DEVLINK_CMD_PORT_GET`，版本号为 `DEVLINK_GENL_VERSION`。
4. **添加 Netlink 属性 (NLA):**
   * 添加 `DEVLINK_ATTR_BUS_NAME` 属性，值为网络设备所属的总线名称（例如 "platform" 或 "pci"）。
   * 添加 `DEVLINK_ATTR_DEV_NAME` 属性，值为网络设备的名称（例如 "eth0" 对应的设备）。
   * **注意:**  更常见的做法是通过 `DEVLINK_ATTR_PORT_INDEX` 来指定端口，但这取决于具体的需求。
5. **发送 Netlink 消息:** 将构建好的消息通过 Netlink socket 发送到内核。
6. **接收 Netlink 响应:** 从内核接收响应消息。
7. **解析 Netlink 响应:**  解析响应消息，查找 `DEVLINK_ATTR_PORT_TYPE` 属性，提取端口类型的值。

**假设输出:**  内核返回的 Netlink 消息中，`DEVLINK_ATTR_PORT_TYPE` 的值为 `DEVLINK_PORT_TYPE_ETH` (假设 "eth0" 是一个以太网端口)。

**用户或编程常见的使用错误**

1. **头文件未包含:**  在代码中使用 `devlink.h` 中定义的常量或枚举时，忘记包含该头文件会导致编译错误。
2. **Netlink 消息构造错误:**  构造 Netlink 消息时，属性的类型、长度或顺序错误，会导致内核解析失败，返回错误信息或无法执行操作。
3. **权限不足:**  执行某些 `devlink` 命令可能需要 root 权限。普通用户尝试执行这些命令会失败。
4. **错误的命令或属性:** 使用了内核不支持的 `devlink` 命令或属性。
5. **Netlink socket 使用错误:**  例如，未正确创建或绑定 Netlink socket，或者在发送和接收消息时出现错误。
6. **假设设备状态:**  在没有检查设备状态的情况下，尝试执行某些操作可能会失败。例如，在端口未激活的情况下尝试配置其 QoS 参数。
7. **忽略错误处理:**  未能正确处理 `sendto()` 和 `recvfrom()` 等系统调用的返回值，可能导致程序在出现错误时无法正常运行。

**Frida Hook 示例调试步骤**

要调试与 `devlink` 相关的操作，可以使用 Frida hook 用户空间的程序与内核进行 Netlink 通信的关键点。

**Frida Hook 示例 (Hook `sendto` 系统调用):**

假设我们想观察某个 Android 进程（例如，负责网络配置的系统服务）发送的与 `devlink` 相关的 Netlink 消息。

```python
import frida
import sys

package_name = "com.android.shell" # 替换为目标进程的包名或进程名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Sent Netlink message:")
        # 可以进一步解析 data 来查看具体的 devlink 命令和属性
        print(hexdump(data))

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, str) else 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = ''.join([x if 0x20 <= ord(x) < 0x7F else '.' for x in s])
        result.append( "%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
    return '\n'.join(result)

session = frida.attach(package_name)

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "sendto"), {
  onEnter: function(args) {
    var sockfd = args[0].toInt32();
    var buf = args[1];
    var len = args[2].toInt32();
    var destaddr = args[3];
    var addrlen = args[4].toInt32();

    // 检查是否是 AF_NETLINK socket
    var sock_domain = Socket.getsockopt(sockfd, Socket.SOL_SOCKET, Socket.SO_DOMAIN);
    if (sock_domain && sock_domain.level == Socket.SOL_SOCKET && sock_domain.optval.toInt32() == 16) { // 16 是 AF_NETLINK 的值
      send({ 'type': 'send', 'data': Memory.readByteArray(buf, len) });
    }
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **确定目标进程:**  找到负责执行网络配置或管理操作的 Android 进程。可以使用 `adb shell ps | grep network` 或 `adb shell dumpsys activity services com.android.server.NetworkManagementService` 等命令来查找。
2. **编写 Frida 脚本:**  创建一个如上所示的 Frida 脚本，用于 hook `sendto` 系统调用。
3. **运行 Frida:** 使用 Frida 连接到目标 Android 设备并运行脚本：
   ```bash
   frida -U -f com.android.shell -l your_frida_script.py --no-pause
   ```
   将 `com.android.shell` 替换为实际的目标进程包名或进程名。
4. **执行相关操作:** 在 Android 设备上执行你想要观察的网络操作，例如连接 Wi-Fi、配置 IP 地址等。
5. **查看 Frida 输出:** Frida 脚本会拦截目标进程发送的 `sendto` 调用，并打印出发送的数据。如果发送的是 Netlink 消息（通过检查 socket 域），你就可以看到构造的 Netlink 消息的十六进制内容。
6. **分析 Netlink 消息:**  根据 Netlink 协议和 `devlink.h` 中定义的结构，分析捕获到的消息，了解程序正在执行哪些 `devlink` 命令以及传递了哪些属性。

**说明 Android Framework 或 NDK 是如何一步步到达这里的**

与 `devlink` 的交互通常发生在 Android 系统的底层。

1. **Android Framework (Java层):**  高层的 Android Framework API（例如 `ConnectivityManager`, `WifiManager`) 提供了配置和管理网络连接的接口。这些 API 通常不直接与 `devlink` 交互。

2. **System Services (Native/C++层):**  Framework API 的实现会调用底层的系统服务，例如 `NetworkManagementService`。这些服务是用 C++ 编写的，它们可能会使用 Netlink socket 与内核进行通信，但通常会使用更高级的网络配置接口，例如 `netd` (network daemon)。

3. **`netd` (Network Daemon):** `netd` 是 Android 系统中负责网络配置的关键守护进程。它接收来自 Framework 服务的请求，并负责执行实际的网络配置操作。`netd` 内部会使用 Netlink socket 与内核的各种网络子系统（包括 `devlink`，虽然 `devlink` 不是最常用的）进行通信。

4. **HAL (Hardware Abstraction Layer):**  对于一些特定的硬件相关操作，例如配置网络设备的某些低级属性或执行固件升级，Android 的 HAL 层可能会直接使用 Netlink 和 `devlink` 接口。例如，Wi-Fi HAL 或 Ethernet HAL 可能需要与底层的网络设备驱动程序交互。

5. **NDK (Native Development Kit):**  通过 NDK 开发的 Native 应用理论上可以直接使用 Netlink socket 和 `devlink.h` 中定义的接口与内核交互。但这通常只在需要进行非常底层的网络控制或监控时使用，并且需要具有相应的系统权限。普通的应用开发者通常不会直接使用 `devlink`。

**总结**

`bionic/libc/kernel/uapi/linux/devlink.h` 定义了与 Linux 内核 `devlink` 子系统交互的接口，用于管理网络设备。虽然普通 Android 应用开发者通常不直接使用它，但 Android 系统的底层组件（例如系统服务、HAL 模块）可能会利用 `devlink` 来配置和管理网络硬件。理解这个头文件的内容有助于深入理解 Android 系统的网络架构和底层实现。使用 Frida 可以帮助我们动态地观察和调试与 `devlink` 相关的系统调用和数据交换。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/devlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_DEVLINK_H_
#define _UAPI_LINUX_DEVLINK_H_
#include <linux/const.h>
#define DEVLINK_GENL_NAME "devlink"
#define DEVLINK_GENL_VERSION 0x1
#define DEVLINK_GENL_MCGRP_CONFIG_NAME "config"
enum devlink_command {
  DEVLINK_CMD_UNSPEC,
  DEVLINK_CMD_GET,
  DEVLINK_CMD_SET,
  DEVLINK_CMD_NEW,
  DEVLINK_CMD_DEL,
  DEVLINK_CMD_PORT_GET,
  DEVLINK_CMD_PORT_SET,
  DEVLINK_CMD_PORT_NEW,
  DEVLINK_CMD_PORT_DEL,
  DEVLINK_CMD_PORT_SPLIT,
  DEVLINK_CMD_PORT_UNSPLIT,
  DEVLINK_CMD_SB_GET,
  DEVLINK_CMD_SB_SET,
  DEVLINK_CMD_SB_NEW,
  DEVLINK_CMD_SB_DEL,
  DEVLINK_CMD_SB_POOL_GET,
  DEVLINK_CMD_SB_POOL_SET,
  DEVLINK_CMD_SB_POOL_NEW,
  DEVLINK_CMD_SB_POOL_DEL,
  DEVLINK_CMD_SB_PORT_POOL_GET,
  DEVLINK_CMD_SB_PORT_POOL_SET,
  DEVLINK_CMD_SB_PORT_POOL_NEW,
  DEVLINK_CMD_SB_PORT_POOL_DEL,
  DEVLINK_CMD_SB_TC_POOL_BIND_GET,
  DEVLINK_CMD_SB_TC_POOL_BIND_SET,
  DEVLINK_CMD_SB_TC_POOL_BIND_NEW,
  DEVLINK_CMD_SB_TC_POOL_BIND_DEL,
  DEVLINK_CMD_SB_OCC_SNAPSHOT,
  DEVLINK_CMD_SB_OCC_MAX_CLEAR,
  DEVLINK_CMD_ESWITCH_GET,
#define DEVLINK_CMD_ESWITCH_MODE_GET DEVLINK_CMD_ESWITCH_GET
  DEVLINK_CMD_ESWITCH_SET,
#define DEVLINK_CMD_ESWITCH_MODE_SET DEVLINK_CMD_ESWITCH_SET
  DEVLINK_CMD_DPIPE_TABLE_GET,
  DEVLINK_CMD_DPIPE_ENTRIES_GET,
  DEVLINK_CMD_DPIPE_HEADERS_GET,
  DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET,
  DEVLINK_CMD_RESOURCE_SET,
  DEVLINK_CMD_RESOURCE_DUMP,
  DEVLINK_CMD_RELOAD,
  DEVLINK_CMD_PARAM_GET,
  DEVLINK_CMD_PARAM_SET,
  DEVLINK_CMD_PARAM_NEW,
  DEVLINK_CMD_PARAM_DEL,
  DEVLINK_CMD_REGION_GET,
  DEVLINK_CMD_REGION_SET,
  DEVLINK_CMD_REGION_NEW,
  DEVLINK_CMD_REGION_DEL,
  DEVLINK_CMD_REGION_READ,
  DEVLINK_CMD_PORT_PARAM_GET,
  DEVLINK_CMD_PORT_PARAM_SET,
  DEVLINK_CMD_PORT_PARAM_NEW,
  DEVLINK_CMD_PORT_PARAM_DEL,
  DEVLINK_CMD_INFO_GET,
  DEVLINK_CMD_HEALTH_REPORTER_GET,
  DEVLINK_CMD_HEALTH_REPORTER_SET,
  DEVLINK_CMD_HEALTH_REPORTER_RECOVER,
  DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE,
  DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET,
  DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR,
  DEVLINK_CMD_FLASH_UPDATE,
  DEVLINK_CMD_FLASH_UPDATE_END,
  DEVLINK_CMD_FLASH_UPDATE_STATUS,
  DEVLINK_CMD_TRAP_GET,
  DEVLINK_CMD_TRAP_SET,
  DEVLINK_CMD_TRAP_NEW,
  DEVLINK_CMD_TRAP_DEL,
  DEVLINK_CMD_TRAP_GROUP_GET,
  DEVLINK_CMD_TRAP_GROUP_SET,
  DEVLINK_CMD_TRAP_GROUP_NEW,
  DEVLINK_CMD_TRAP_GROUP_DEL,
  DEVLINK_CMD_TRAP_POLICER_GET,
  DEVLINK_CMD_TRAP_POLICER_SET,
  DEVLINK_CMD_TRAP_POLICER_NEW,
  DEVLINK_CMD_TRAP_POLICER_DEL,
  DEVLINK_CMD_HEALTH_REPORTER_TEST,
  DEVLINK_CMD_RATE_GET,
  DEVLINK_CMD_RATE_SET,
  DEVLINK_CMD_RATE_NEW,
  DEVLINK_CMD_RATE_DEL,
  DEVLINK_CMD_LINECARD_GET,
  DEVLINK_CMD_LINECARD_SET,
  DEVLINK_CMD_LINECARD_NEW,
  DEVLINK_CMD_LINECARD_DEL,
  DEVLINK_CMD_SELFTESTS_GET,
  DEVLINK_CMD_SELFTESTS_RUN,
  DEVLINK_CMD_NOTIFY_FILTER_SET,
  __DEVLINK_CMD_MAX,
  DEVLINK_CMD_MAX = __DEVLINK_CMD_MAX - 1
};
enum devlink_port_type {
  DEVLINK_PORT_TYPE_NOTSET,
  DEVLINK_PORT_TYPE_AUTO,
  DEVLINK_PORT_TYPE_ETH,
  DEVLINK_PORT_TYPE_IB,
};
enum devlink_sb_pool_type {
  DEVLINK_SB_POOL_TYPE_INGRESS,
  DEVLINK_SB_POOL_TYPE_EGRESS,
};
enum devlink_sb_threshold_type {
  DEVLINK_SB_THRESHOLD_TYPE_STATIC,
  DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC,
};
#define DEVLINK_SB_THRESHOLD_TO_ALPHA_MAX 20
enum devlink_eswitch_mode {
  DEVLINK_ESWITCH_MODE_LEGACY,
  DEVLINK_ESWITCH_MODE_SWITCHDEV,
};
enum devlink_eswitch_inline_mode {
  DEVLINK_ESWITCH_INLINE_MODE_NONE,
  DEVLINK_ESWITCH_INLINE_MODE_LINK,
  DEVLINK_ESWITCH_INLINE_MODE_NETWORK,
  DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT,
};
enum devlink_eswitch_encap_mode {
  DEVLINK_ESWITCH_ENCAP_MODE_NONE,
  DEVLINK_ESWITCH_ENCAP_MODE_BASIC,
};
enum devlink_port_flavour {
  DEVLINK_PORT_FLAVOUR_PHYSICAL,
  DEVLINK_PORT_FLAVOUR_CPU,
  DEVLINK_PORT_FLAVOUR_DSA,
  DEVLINK_PORT_FLAVOUR_PCI_PF,
  DEVLINK_PORT_FLAVOUR_PCI_VF,
  DEVLINK_PORT_FLAVOUR_VIRTUAL,
  DEVLINK_PORT_FLAVOUR_UNUSED,
  DEVLINK_PORT_FLAVOUR_PCI_SF,
};
enum devlink_rate_type {
  DEVLINK_RATE_TYPE_LEAF,
  DEVLINK_RATE_TYPE_NODE,
};
enum devlink_param_cmode {
  DEVLINK_PARAM_CMODE_RUNTIME,
  DEVLINK_PARAM_CMODE_DRIVERINIT,
  DEVLINK_PARAM_CMODE_PERMANENT,
  __DEVLINK_PARAM_CMODE_MAX,
  DEVLINK_PARAM_CMODE_MAX = __DEVLINK_PARAM_CMODE_MAX - 1
};
enum devlink_param_fw_load_policy_value {
  DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DRIVER,
  DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_FLASH,
  DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_DISK,
  DEVLINK_PARAM_FW_LOAD_POLICY_VALUE_UNKNOWN,
};
enum devlink_param_reset_dev_on_drv_probe_value {
  DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_UNKNOWN,
  DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_ALWAYS,
  DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_NEVER,
  DEVLINK_PARAM_RESET_DEV_ON_DRV_PROBE_VALUE_DISK,
};
enum {
  DEVLINK_ATTR_STATS_RX_PACKETS,
  DEVLINK_ATTR_STATS_RX_BYTES,
  DEVLINK_ATTR_STATS_RX_DROPPED,
  __DEVLINK_ATTR_STATS_MAX,
  DEVLINK_ATTR_STATS_MAX = __DEVLINK_ATTR_STATS_MAX - 1
};
enum devlink_flash_overwrite {
  DEVLINK_FLASH_OVERWRITE_SETTINGS_BIT,
  DEVLINK_FLASH_OVERWRITE_IDENTIFIERS_BIT,
  __DEVLINK_FLASH_OVERWRITE_MAX_BIT,
  DEVLINK_FLASH_OVERWRITE_MAX_BIT = __DEVLINK_FLASH_OVERWRITE_MAX_BIT - 1
};
#define DEVLINK_FLASH_OVERWRITE_SETTINGS _BITUL(DEVLINK_FLASH_OVERWRITE_SETTINGS_BIT)
#define DEVLINK_FLASH_OVERWRITE_IDENTIFIERS _BITUL(DEVLINK_FLASH_OVERWRITE_IDENTIFIERS_BIT)
#define DEVLINK_SUPPORTED_FLASH_OVERWRITE_SECTIONS (_BITUL(__DEVLINK_FLASH_OVERWRITE_MAX_BIT) - 1)
enum devlink_attr_selftest_id {
  DEVLINK_ATTR_SELFTEST_ID_UNSPEC,
  DEVLINK_ATTR_SELFTEST_ID_FLASH,
  __DEVLINK_ATTR_SELFTEST_ID_MAX,
  DEVLINK_ATTR_SELFTEST_ID_MAX = __DEVLINK_ATTR_SELFTEST_ID_MAX - 1
};
enum devlink_selftest_status {
  DEVLINK_SELFTEST_STATUS_SKIP,
  DEVLINK_SELFTEST_STATUS_PASS,
  DEVLINK_SELFTEST_STATUS_FAIL
};
enum devlink_attr_selftest_result {
  DEVLINK_ATTR_SELFTEST_RESULT_UNSPEC,
  DEVLINK_ATTR_SELFTEST_RESULT,
  DEVLINK_ATTR_SELFTEST_RESULT_ID,
  DEVLINK_ATTR_SELFTEST_RESULT_STATUS,
  __DEVLINK_ATTR_SELFTEST_RESULT_MAX,
  DEVLINK_ATTR_SELFTEST_RESULT_MAX = __DEVLINK_ATTR_SELFTEST_RESULT_MAX - 1
};
enum devlink_trap_action {
  DEVLINK_TRAP_ACTION_DROP,
  DEVLINK_TRAP_ACTION_TRAP,
  DEVLINK_TRAP_ACTION_MIRROR,
};
enum devlink_trap_type {
  DEVLINK_TRAP_TYPE_DROP,
  DEVLINK_TRAP_TYPE_EXCEPTION,
  DEVLINK_TRAP_TYPE_CONTROL,
};
enum {
  DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT,
  DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE,
};
enum devlink_reload_action {
  DEVLINK_RELOAD_ACTION_UNSPEC,
  DEVLINK_RELOAD_ACTION_DRIVER_REINIT,
  DEVLINK_RELOAD_ACTION_FW_ACTIVATE,
  __DEVLINK_RELOAD_ACTION_MAX,
  DEVLINK_RELOAD_ACTION_MAX = __DEVLINK_RELOAD_ACTION_MAX - 1
};
enum devlink_reload_limit {
  DEVLINK_RELOAD_LIMIT_UNSPEC,
  DEVLINK_RELOAD_LIMIT_NO_RESET,
  __DEVLINK_RELOAD_LIMIT_MAX,
  DEVLINK_RELOAD_LIMIT_MAX = __DEVLINK_RELOAD_LIMIT_MAX - 1
};
#define DEVLINK_RELOAD_LIMITS_VALID_MASK (_BITUL(__DEVLINK_RELOAD_LIMIT_MAX) - 1)
enum devlink_linecard_state {
  DEVLINK_LINECARD_STATE_UNSPEC,
  DEVLINK_LINECARD_STATE_UNPROVISIONED,
  DEVLINK_LINECARD_STATE_UNPROVISIONING,
  DEVLINK_LINECARD_STATE_PROVISIONING,
  DEVLINK_LINECARD_STATE_PROVISIONING_FAILED,
  DEVLINK_LINECARD_STATE_PROVISIONED,
  DEVLINK_LINECARD_STATE_ACTIVE,
  __DEVLINK_LINECARD_STATE_MAX,
  DEVLINK_LINECARD_STATE_MAX = __DEVLINK_LINECARD_STATE_MAX - 1
};
enum devlink_attr {
  DEVLINK_ATTR_UNSPEC,
  DEVLINK_ATTR_BUS_NAME,
  DEVLINK_ATTR_DEV_NAME,
  DEVLINK_ATTR_PORT_INDEX,
  DEVLINK_ATTR_PORT_TYPE,
  DEVLINK_ATTR_PORT_DESIRED_TYPE,
  DEVLINK_ATTR_PORT_NETDEV_IFINDEX,
  DEVLINK_ATTR_PORT_NETDEV_NAME,
  DEVLINK_ATTR_PORT_IBDEV_NAME,
  DEVLINK_ATTR_PORT_SPLIT_COUNT,
  DEVLINK_ATTR_PORT_SPLIT_GROUP,
  DEVLINK_ATTR_SB_INDEX,
  DEVLINK_ATTR_SB_SIZE,
  DEVLINK_ATTR_SB_INGRESS_POOL_COUNT,
  DEVLINK_ATTR_SB_EGRESS_POOL_COUNT,
  DEVLINK_ATTR_SB_INGRESS_TC_COUNT,
  DEVLINK_ATTR_SB_EGRESS_TC_COUNT,
  DEVLINK_ATTR_SB_POOL_INDEX,
  DEVLINK_ATTR_SB_POOL_TYPE,
  DEVLINK_ATTR_SB_POOL_SIZE,
  DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE,
  DEVLINK_ATTR_SB_THRESHOLD,
  DEVLINK_ATTR_SB_TC_INDEX,
  DEVLINK_ATTR_SB_OCC_CUR,
  DEVLINK_ATTR_SB_OCC_MAX,
  DEVLINK_ATTR_ESWITCH_MODE,
  DEVLINK_ATTR_ESWITCH_INLINE_MODE,
  DEVLINK_ATTR_DPIPE_TABLES,
  DEVLINK_ATTR_DPIPE_TABLE,
  DEVLINK_ATTR_DPIPE_TABLE_NAME,
  DEVLINK_ATTR_DPIPE_TABLE_SIZE,
  DEVLINK_ATTR_DPIPE_TABLE_MATCHES,
  DEVLINK_ATTR_DPIPE_TABLE_ACTIONS,
  DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED,
  DEVLINK_ATTR_DPIPE_ENTRIES,
  DEVLINK_ATTR_DPIPE_ENTRY,
  DEVLINK_ATTR_DPIPE_ENTRY_INDEX,
  DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES,
  DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES,
  DEVLINK_ATTR_DPIPE_ENTRY_COUNTER,
  DEVLINK_ATTR_DPIPE_MATCH,
  DEVLINK_ATTR_DPIPE_MATCH_VALUE,
  DEVLINK_ATTR_DPIPE_MATCH_TYPE,
  DEVLINK_ATTR_DPIPE_ACTION,
  DEVLINK_ATTR_DPIPE_ACTION_VALUE,
  DEVLINK_ATTR_DPIPE_ACTION_TYPE,
  DEVLINK_ATTR_DPIPE_VALUE,
  DEVLINK_ATTR_DPIPE_VALUE_MASK,
  DEVLINK_ATTR_DPIPE_VALUE_MAPPING,
  DEVLINK_ATTR_DPIPE_HEADERS,
  DEVLINK_ATTR_DPIPE_HEADER,
  DEVLINK_ATTR_DPIPE_HEADER_NAME,
  DEVLINK_ATTR_DPIPE_HEADER_ID,
  DEVLINK_ATTR_DPIPE_HEADER_FIELDS,
  DEVLINK_ATTR_DPIPE_HEADER_GLOBAL,
  DEVLINK_ATTR_DPIPE_HEADER_INDEX,
  DEVLINK_ATTR_DPIPE_FIELD,
  DEVLINK_ATTR_DPIPE_FIELD_NAME,
  DEVLINK_ATTR_DPIPE_FIELD_ID,
  DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH,
  DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE,
  DEVLINK_ATTR_PAD,
  DEVLINK_ATTR_ESWITCH_ENCAP_MODE,
  DEVLINK_ATTR_RESOURCE_LIST,
  DEVLINK_ATTR_RESOURCE,
  DEVLINK_ATTR_RESOURCE_NAME,
  DEVLINK_ATTR_RESOURCE_ID,
  DEVLINK_ATTR_RESOURCE_SIZE,
  DEVLINK_ATTR_RESOURCE_SIZE_NEW,
  DEVLINK_ATTR_RESOURCE_SIZE_VALID,
  DEVLINK_ATTR_RESOURCE_SIZE_MIN,
  DEVLINK_ATTR_RESOURCE_SIZE_MAX,
  DEVLINK_ATTR_RESOURCE_SIZE_GRAN,
  DEVLINK_ATTR_RESOURCE_UNIT,
  DEVLINK_ATTR_RESOURCE_OCC,
  DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID,
  DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS,
  DEVLINK_ATTR_PORT_FLAVOUR,
  DEVLINK_ATTR_PORT_NUMBER,
  DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER,
  DEVLINK_ATTR_PARAM,
  DEVLINK_ATTR_PARAM_NAME,
  DEVLINK_ATTR_PARAM_GENERIC,
  DEVLINK_ATTR_PARAM_TYPE,
  DEVLINK_ATTR_PARAM_VALUES_LIST,
  DEVLINK_ATTR_PARAM_VALUE,
  DEVLINK_ATTR_PARAM_VALUE_DATA,
  DEVLINK_ATTR_PARAM_VALUE_CMODE,
  DEVLINK_ATTR_REGION_NAME,
  DEVLINK_ATTR_REGION_SIZE,
  DEVLINK_ATTR_REGION_SNAPSHOTS,
  DEVLINK_ATTR_REGION_SNAPSHOT,
  DEVLINK_ATTR_REGION_SNAPSHOT_ID,
  DEVLINK_ATTR_REGION_CHUNKS,
  DEVLINK_ATTR_REGION_CHUNK,
  DEVLINK_ATTR_REGION_CHUNK_DATA,
  DEVLINK_ATTR_REGION_CHUNK_ADDR,
  DEVLINK_ATTR_REGION_CHUNK_LEN,
  DEVLINK_ATTR_INFO_DRIVER_NAME,
  DEVLINK_ATTR_INFO_SERIAL_NUMBER,
  DEVLINK_ATTR_INFO_VERSION_FIXED,
  DEVLINK_ATTR_INFO_VERSION_RUNNING,
  DEVLINK_ATTR_INFO_VERSION_STORED,
  DEVLINK_ATTR_INFO_VERSION_NAME,
  DEVLINK_ATTR_INFO_VERSION_VALUE,
  DEVLINK_ATTR_SB_POOL_CELL_SIZE,
  DEVLINK_ATTR_FMSG,
  DEVLINK_ATTR_FMSG_OBJ_NEST_START,
  DEVLINK_ATTR_FMSG_PAIR_NEST_START,
  DEVLINK_ATTR_FMSG_ARR_NEST_START,
  DEVLINK_ATTR_FMSG_NEST_END,
  DEVLINK_ATTR_FMSG_OBJ_NAME,
  DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE,
  DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA,
  DEVLINK_ATTR_HEALTH_REPORTER,
  DEVLINK_ATTR_HEALTH_REPORTER_NAME,
  DEVLINK_ATTR_HEALTH_REPORTER_STATE,
  DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT,
  DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT,
  DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS,
  DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD,
  DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER,
  DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME,
  DEVLINK_ATTR_FLASH_UPDATE_COMPONENT,
  DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG,
  DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE,
  DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL,
  DEVLINK_ATTR_PORT_PCI_PF_NUMBER,
  DEVLINK_ATTR_PORT_PCI_VF_NUMBER,
  DEVLINK_ATTR_STATS,
  DEVLINK_ATTR_TRAP_NAME,
  DEVLINK_ATTR_TRAP_ACTION,
  DEVLINK_ATTR_TRAP_TYPE,
  DEVLINK_ATTR_TRAP_GENERIC,
  DEVLINK_ATTR_TRAP_METADATA,
  DEVLINK_ATTR_TRAP_GROUP_NAME,
  DEVLINK_ATTR_RELOAD_FAILED,
  DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS,
  DEVLINK_ATTR_NETNS_FD,
  DEVLINK_ATTR_NETNS_PID,
  DEVLINK_ATTR_NETNS_ID,
  DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP,
  DEVLINK_ATTR_TRAP_POLICER_ID,
  DEVLINK_ATTR_TRAP_POLICER_RATE,
  DEVLINK_ATTR_TRAP_POLICER_BURST,
  DEVLINK_ATTR_PORT_FUNCTION,
  DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER,
  DEVLINK_ATTR_PORT_LANES,
  DEVLINK_ATTR_PORT_SPLITTABLE,
  DEVLINK_ATTR_PORT_EXTERNAL,
  DEVLINK_ATTR_PORT_CONTROLLER_NUMBER,
  DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT,
  DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK,
  DEVLINK_ATTR_RELOAD_ACTION,
  DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED,
  DEVLINK_ATTR_RELOAD_LIMITS,
  DEVLINK_ATTR_DEV_STATS,
  DEVLINK_ATTR_RELOAD_STATS,
  DEVLINK_ATTR_RELOAD_STATS_ENTRY,
  DEVLINK_ATTR_RELOAD_STATS_LIMIT,
  DEVLINK_ATTR_RELOAD_STATS_VALUE,
  DEVLINK_ATTR_REMOTE_RELOAD_STATS,
  DEVLINK_ATTR_RELOAD_ACTION_INFO,
  DEVLINK_ATTR_RELOAD_ACTION_STATS,
  DEVLINK_ATTR_PORT_PCI_SF_NUMBER,
  DEVLINK_ATTR_RATE_TYPE,
  DEVLINK_ATTR_RATE_TX_SHARE,
  DEVLINK_ATTR_RATE_TX_MAX,
  DEVLINK_ATTR_RATE_NODE_NAME,
  DEVLINK_ATTR_RATE_PARENT_NODE_NAME,
  DEVLINK_ATTR_REGION_MAX_SNAPSHOTS,
  DEVLINK_ATTR_LINECARD_INDEX,
  DEVLINK_ATTR_LINECARD_STATE,
  DEVLINK_ATTR_LINECARD_TYPE,
  DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES,
  DEVLINK_ATTR_NESTED_DEVLINK,
  DEVLINK_ATTR_SELFTESTS,
  DEVLINK_ATTR_RATE_TX_PRIORITY,
  DEVLINK_ATTR_RATE_TX_WEIGHT,
  DEVLINK_ATTR_REGION_DIRECT,
  __DEVLINK_ATTR_MAX,
  DEVLINK_ATTR_MAX = __DEVLINK_ATTR_MAX - 1
};
enum devlink_dpipe_field_mapping_type {
  DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE,
  DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX,
};
enum devlink_dpipe_match_type {
  DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT,
};
enum devlink_dpipe_action_type {
  DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY,
};
enum devlink_dpipe_field_ethernet_id {
  DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC,
};
enum devlink_dpipe_field_ipv4_id {
  DEVLINK_DPIPE_FIELD_IPV4_DST_IP,
};
enum devlink_dpipe_field_ipv6_id {
  DEVLINK_DPIPE_FIELD_IPV6_DST_IP,
};
enum devlink_dpipe_header_id {
  DEVLINK_DPIPE_HEADER_ETHERNET,
  DEVLINK_DPIPE_HEADER_IPV4,
  DEVLINK_DPIPE_HEADER_IPV6,
};
enum devlink_resource_unit {
  DEVLINK_RESOURCE_UNIT_ENTRY,
};
enum devlink_port_fn_attr_cap {
  DEVLINK_PORT_FN_ATTR_CAP_ROCE_BIT,
  DEVLINK_PORT_FN_ATTR_CAP_MIGRATABLE_BIT,
  DEVLINK_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT,
  DEVLINK_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT,
  __DEVLINK_PORT_FN_ATTR_CAPS_MAX,
};
#define DEVLINK_PORT_FN_CAP_ROCE _BITUL(DEVLINK_PORT_FN_ATTR_CAP_ROCE_BIT)
#define DEVLINK_PORT_FN_CAP_MIGRATABLE _BITUL(DEVLINK_PORT_FN_ATTR_CAP_MIGRATABLE_BIT)
#define DEVLINK_PORT_FN_CAP_IPSEC_CRYPTO _BITUL(DEVLINK_PORT_FN_ATTR_CAP_IPSEC_CRYPTO_BIT)
#define DEVLINK_PORT_FN_CAP_IPSEC_PACKET _BITUL(DEVLINK_PORT_FN_ATTR_CAP_IPSEC_PACKET_BIT)
enum devlink_port_function_attr {
  DEVLINK_PORT_FUNCTION_ATTR_UNSPEC,
  DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR,
  DEVLINK_PORT_FN_ATTR_STATE,
  DEVLINK_PORT_FN_ATTR_OPSTATE,
  DEVLINK_PORT_FN_ATTR_CAPS,
  DEVLINK_PORT_FN_ATTR_DEVLINK,
  DEVLINK_PORT_FN_ATTR_MAX_IO_EQS,
  __DEVLINK_PORT_FUNCTION_ATTR_MAX,
  DEVLINK_PORT_FUNCTION_ATTR_MAX = __DEVLINK_PORT_FUNCTION_ATTR_MAX - 1
};
enum devlink_port_fn_state {
  DEVLINK_PORT_FN_STATE_INACTIVE,
  DEVLINK_PORT_FN_STATE_ACTIVE,
};
enum devlink_port_fn_opstate {
  DEVLINK_PORT_FN_OPSTATE_DETACHED,
  DEVLINK_PORT_FN_OPSTATE_ATTACHED,
};
#endif

"""

```