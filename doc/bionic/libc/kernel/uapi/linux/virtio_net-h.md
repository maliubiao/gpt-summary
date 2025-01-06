Response:
Let's break down the thought process for analyzing the provided `virtio_net.h` header file.

1. **Understanding the Context:** The prompt clearly states that this is a header file (`.h`) located within the Android Bionic library's kernel UAPI (User API) section. The path `bionic/libc/kernel/uapi/linux/virtio_net.handroid` strongly suggests it's related to the Linux kernel's interface for `virtio` networking, with a specific "handroid" flavor (likely an Android-specific adaptation or naming convention).

2. **Initial Scan for Keywords:**  A quick scan for keywords like "define", "struct", "typedef", and comments gives a high-level overview. We see a lot of `#define` for flags and constants, multiple `struct` definitions, and a `typedef`. This indicates the file primarily defines data structures and symbolic constants used for interacting with `virtio` network devices.

3. **Identifying the Core Purpose:**  The name `virtio_net.h` immediately points to "virtual I/O networking."  `virtio` is a standardized interface for virtual devices. This header likely defines how a guest operating system (like Android running in a VM) communicates with a virtual network device provided by the hypervisor.

4. **Analyzing `#define` Statements:**  These are symbolic constants. Group them by likely functionality:
    * **Feature Flags (`VIRTIO_NET_F_*`):**  These describe optional features the virtual network device might support (e.g., checksum offload, TCP segmentation offload, MAC address setting).
    * **Status Flags (`VIRTIO_NET_S_*`):** These indicate the current state of the virtual network interface (e.g., link up, announce).
    * **RSS Hash Types (`VIRTIO_NET_RSS_HASH_TYPE_*`):** These relate to Receive Side Scaling, a technique to distribute network traffic across multiple CPU cores.
    * **GSO Types (`VIRTIO_NET_HDR_GSO_*`):**  These specify the type of Generic Segmentation Offload being used.
    * **Control Command Definitions (`VIRTIO_NET_CTRL_*`):** These represent commands sent to control the virtual network device.
    * **Return Codes (`VIRTIO_NET_OK`, `VIRTIO_NET_ERR`):**  Basic status indications.
    * **Statistics Types (`VIRTIO_NET_STATS_TYPE_*`):**  Define the types of network statistics that can be queried.

5. **Analyzing `struct` Definitions:**  These represent data structures exchanged between the guest OS and the virtual network device.
    * **`virtio_net_config`:** Contains configuration information like MAC address, MTU, speed, duplex, and RSS capabilities.
    * **`virtio_net_hdr_v1` and `virtio_net_hdr` (legacy):** Define the header prepended to network packets. They include fields for checksum offload, GSO, and buffer management. The presence of a legacy version suggests backward compatibility.
    * **`virtio_net_hdr_v1_hash`:** Extends `virtio_net_hdr_v1` to include RSS hash information.
    * **`virtio_net_ctrl_hdr`:**  The header for control messages.
    * **`virtio_net_ctrl_mac`, `virtio_net_ctrl_vlan`, `virtio_net_ctrl_mq`, etc.:** Structures for specific control commands, such as setting MAC addresses, VLANs, and managing multiple queues.
    * **`virtio_net_rss_config` and `virtio_net_hash_config`:** Structures for configuring RSS.
    * **`virtio_net_ctrl_coal_*` and `virtio_net_ctrl_coal`:** Structures related to interrupt coalescing, a technique to reduce interrupt overhead.
    * **`virtio_net_stats_*`:** Structures defining the format of various network statistics.

6. **Identifying Relationships and Functionality:** Based on the names and fields of the structs and constants, deduce the functionalities:
    * **Feature Negotiation:**  The `VIRTIO_NET_F_*` flags are used during the initialization of the virtual network device to determine which features are supported by both the guest and the host.
    * **Packet Handling:** The header structures (`virtio_net_hdr*`) define the format for sending and receiving network packets. Fields like `csum_start`, `csum_offset`, `gso_type`, and `gso_size` are crucial for offloading tasks to the host.
    * **Control Plane:** The `virtio_net_ctrl_*` structures define the control interface to manage the virtual NIC (e.g., setting MAC address, enabling promiscuous mode, configuring VLANs, managing queues).
    * **Statistics Gathering:** The `virtio_net_stats_*` structures allow the guest OS to query various network statistics.
    * **Receive Side Scaling (RSS):** The structures and constants related to RSS enable the distribution of incoming network traffic across multiple queues/CPUs.
    * **Interrupt Coalescing:** The structures for interrupt coalescing aim to improve performance by reducing the number of interrupts.

7. **Considering Android Specifics:**  The "handroid" suffix suggests this header is tailored for Android. Think about how a virtualized Android system would use networking:
    * **Virtual Machines:** Android emulators or Android running on cloud platforms rely on virtualization.
    * **Network Stack:** Android's network stack needs to interact with the virtual network device.
    * **NDK:**  While not directly in userspace, the NDK provides interfaces that *could* indirectly interact with this at a lower level (though direct interaction is unlikely; it's more likely through Android's networking framework).

8. **Dynamic Linking (Less Relevant Here):**  This header file primarily defines data structures. It doesn't contain executable code. Therefore, dynamic linking is less directly relevant *to this specific file*. However, the *usage* of these definitions within Android's networking components would involve dynamic linking of those components. Keep this in mind for the "dynamic linker" part of the prompt.

9. **Libc Functions (Not Directly Defined):** This header defines *data structures*. It does not *implement* libc functions. Libc functions would *use* these definitions when interacting with the kernel.

10. **User/Programming Errors:**  Think about common mistakes when dealing with low-level networking or virtual devices:
    * **Incorrect Feature Negotiation:** Trying to use a feature not supported by the device.
    * **Incorrect Header Construction:**  Errors in setting the fields of `virtio_net_hdr`.
    * **Invalid Control Commands:** Sending malformed or unsupported control commands.
    * **Incorrectly Interpreting Statistics:** Misunderstanding the meaning of the statistics counters.

11. **Android Framework and NDK Path:**  Trace the logical path from high-level Android networking to this header:
    * **Application:** Makes a network request.
    * **Android Framework (Java/Kotlin):** Uses classes like `Socket`, `URLConnection`.
    * **Native Code (C/C++):** The framework calls down to native code in `netd` (the network daemon) or other system services.
    * **Kernel Interface:** `netd` or the kernel modules implementing the network stack interact with the virtual network device driver. This driver uses the definitions in `virtio_net.h`.
    * **NDK:**  While unlikely to directly interact with this header, NDK developers working on low-level networking might encounter concepts defined here.

12. **Frida Hooking:** Consider where and what you could hook to observe the use of these structures:
    * **System Calls:** Hook system calls related to network I/O (e.g., `sendto`, `recvfrom`, `ioctl`).
    * **Kernel Functions:** Hook functions within the virtual network device driver in the kernel (more advanced).
    * **`netd` or related processes:** Hook functions within Android's network daemon that interact with the kernel.

13. **Structuring the Answer:**  Organize the information logically, covering each point raised in the prompt: functionality, Android relevance, libc functions (explain the distinction), dynamic linking (in the context of usage), errors, the path from the framework, and Frida examples. Use clear and concise language.

By following these steps, we can systematically analyze the header file and provide a comprehensive answer to the prompt. The process involves understanding the context, identifying key elements, deducing functionality, considering the specific environment (Android), and thinking about practical usage and debugging.
这个头文件 `bionic/libc/kernel/uapi/linux/virtio_net.handroid` 定义了 Linux 内核中 virtio 网络设备的 **用户空间 API (UAPI)**。它定义了用于与虚拟化网络设备（通常在虚拟机中使用）进行通信的数据结构和常量。由于它位于 Android 的 Bionic 库中，因此它与 Android 运行在虚拟机或容器环境中的网络功能息息相关。

以下是这个文件的详细功能列表和解释：

**主要功能：**

1. **定义 Virtio 网络设备的特征位 (Features Bits):**
   - 以 `VIRTIO_NET_F_` 开头的宏定义了一系列特征位，用于协商虚拟机和宿主机之间网络设备的功能支持。
   - **举例说明:** `VIRTIO_NET_F_CSUM` 表示设备支持硬件校验和计算，`VIRTIO_NET_F_GUEST_TSO4` 表示虚拟机可以进行 TCP Segmentation Offload (TSO) for IPv4。

2. **定义 Virtio 网络设备的状态位 (Status Bits):**
   - 以 `VIRTIO_NET_S_` 开头的宏定义了网络设备的状态，例如 `VIRTIO_NET_S_LINK_UP` 表示链路已连接。

3. **定义 RSS 哈希类型 (RSS Hash Types):**
   - 以 `VIRTIO_NET_RSS_HASH_TYPE_` 开头的宏定义了 Receive Side Scaling (RSS) 使用的哈希类型，用于将网络流量分发到不同的接收队列。

4. **定义 Virtio 网络设备的配置结构体 (`virtio_net_config`):**
   - 描述了 virtio 网络设备的配置信息，例如 MAC 地址 (`mac`)、状态 (`status`)、最大 virtqueue 对数 (`max_virtqueue_pairs`)、MTU (`mtu`)、速度 (`speed`)、双工模式 (`duplex`) 以及 RSS 相关的配置。

5. **定义 Virtio 网络数据包头部结构体 (`virtio_net_hdr_v1`, `virtio_net_hdr`):**
   - 描述了发送和接收网络数据包时附加的头部信息，包括标志位 (`flags`)、GSO 类型 (`gso_type`)、头部长度 (`hdr_len`)、GSO 大小 (`gso_size`)、校验和相关信息 (`csum_start`, `csum_offset`) 以及用于接收缓冲区合并的信息 (`num_buffers`)。
   - **Android 关系:** Android 系统在虚拟机中运行时，其网络驱动程序会使用这些头部结构来与虚拟网络设备进行数据交互。

6. **定义 Virtio 网络控制头部结构体 (`virtio_net_ctrl_hdr`):**
   - 描述了用于控制 virtio 网络设备的控制消息头部，包括类别 (`__linux_class`) 和命令 (`cmd`)。

7. **定义 Virtio 网络控制命令相关的常量和结构体:**
   - 以 `VIRTIO_NET_CTRL_` 开头的宏和结构体定义了各种控制命令及其参数，例如：
     - `VIRTIO_NET_CTRL_RX`: 接收控制，包括设置混杂模式、多播/单播等。
     - `VIRTIO_NET_CTRL_MAC`: MAC 地址控制，用于设置 MAC 地址。
     - `VIRTIO_NET_CTRL_VLAN`: VLAN 控制，用于添加或删除 VLAN。
     - `VIRTIO_NET_CTRL_MQ`: 多队列控制，用于配置 virtqueue 的数量。
     - `VIRTIO_NET_CTRL_GUEST_OFFLOADS`: 配置客户机卸载功能。
     - `VIRTIO_NET_CTRL_NOTF_COAL`: 中断合并控制。
     - `VIRTIO_NET_CTRL_STATS`: 统计信息查询。
   - **Android 关系:** Android 系统可以通过这些控制命令来配置虚拟网络设备的行为，例如设置 MAC 地址、启用混杂模式等。

8. **定义 Virtio 网络设备统计信息相关的结构体 (`virtio_net_stats_*`):**
   - 描述了可以从 virtio 网络设备获取的各种统计信息，例如接收/发送的包数、字节数、错误数、校验和错误、GSO 相关统计等。
   - **Android 关系:** Android 系统可以查询这些统计信息来监控网络设备的状态和性能。

**与 Android 功能的关系举例说明：**

- **网络模拟器/虚拟机:** 当 Android 运行在模拟器（如 Android Emulator）或虚拟机（如在云平台上运行的 Android 实例）中时，底层的网络设备通常是 virtio 设备。Android 的内核驱动会使用这个头文件中定义的结构体和常量来与虚拟网络设备进行通信。
- **容器化 Android:**  在容器环境中运行 Android 时，网络也可能通过 virtio 设备提供。
- **Android 的网络栈:**  Android 的网络栈（从 Java 层的 `Socket` 到 Native 层的网络库）最终会通过 Linux 内核的网络接口与硬件设备（包括虚拟的 virtio 设备）进行交互。这个头文件定义了内核与 virtio 设备交互的 UAPI，是这个过程中的关键部分。

**libc 函数的功能实现：**

这个头文件本身**不包含 libc 函数的实现**。它只是定义了数据结构和常量，供 libc 中的网络相关函数（以及内核驱动）使用。libc 中的网络函数，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`, `ioctl()` 等，会使用这些定义来构造和解析与内核通信的数据。

例如，当 Android 应用创建一个 socket 并发送数据时，底层的 libc 函数（例如 `sendto()`）会使用这个头文件中定义的结构体（如 `virtio_net_hdr_v1`) 来构建发送到内核的数据包头部信息。

**Dynamic Linker 功能：**

这个头文件与 dynamic linker 的功能没有直接关系。它定义的是内核 UAPI，在编译内核模块或某些用户空间网络工具时会被使用。Dynamic linker 主要负责加载和链接共享库 (`.so` 文件)。

然而，使用这个头文件中定义的结构的**用户空间程序**，例如与 virtio 网络设备交互的网络工具，在运行时需要链接到 Android 的 libc 库。

**SO 布局样本和链接处理过程 (与本文件关系不大，但可以泛指网络库)：**

假设一个用户空间的网络应用程序 `my_net_app` 需要使用到网络功能，它会链接到 libc.so。

```
# 简单的 SO 布局样本 (libc.so 的一部分)
libc.so:
    .text:  # 代码段
        socket:  # socket() 函数的实现
        bind:    # bind() 函数的实现
        sendto:  # sendto() 函数的实现
        recvfrom: # recvfrom() 函数的实现
        ioctl:   # ioctl() 函数的实现
        ...
    .data:  # 数据段
        ...
    .bss:   # 未初始化数据段
        ...
    .symtab: # 符号表
        socket
        bind
        sendto
        recvfrom
        ioctl
        ...
```

**链接处理过程：**

1. **编译时链接：** 编译器在编译 `my_net_app` 时，会记录它需要使用的 libc.so 中的符号（例如 `socket`, `sendto`）。
2. **运行时链接：** 当 `my_net_app` 启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责：
   - 加载 `my_net_app` 到内存。
   - 加载 `libc.so` 到内存。
   - 解析 `my_net_app` 中未定义的符号，并在 `libc.so` 中找到对应的实现地址。
   - 更新 `my_net_app` 中的符号引用，使其指向 `libc.so` 中函数的实际地址。

**假设输入与输出 (针对 virtio 网络设备操作):**

假设一个用户空间程序想要获取 virtio 网络的配置信息（例如 MAC 地址）。

**假设输入:**

- 程序打开了与 virtio 网络设备对应的设备文件（例如 `/dev/virtio-ports/vport0pX`，具体路径可能不同）。
- 程序构造了一个 `ioctl` 请求，其中包含 `VIRTIO_NET_CTRL_MAC` 命令，期望获取 MAC 地址。

**假设输出:**

- 内核驱动会解析 `ioctl` 请求。
- 内核驱动读取 virtio 设备的配置信息。
- 内核驱动将 MAC 地址填充到 `virtio_net_config` 结构体中，并通过 `ioctl` 返回给用户空间程序。

**用户或编程常见的使用错误：**

1. **不正确的 `ioctl` 请求:**  构造 `ioctl` 请求时，命令代码、数据结构大小或内容不正确，导致内核无法正确解析或执行。
   ```c
   // 错误示例：ioctl 命令代码错误
   struct ifreq ifr;
   strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
   if (ioctl(sockfd, SIOCGIFHWADDR + 1, &ifr) == -1) { // SIOCGIFHWADDR 命令代码是错误的
       perror("ioctl error");
   }
   ```

2. **未检查返回值:**  调用 `ioctl` 或其他与网络设备交互的函数后，未检查返回值以判断操作是否成功。
   ```c
   // 错误示例：未检查 ioctl 的返回值
   struct ifreq ifr;
   strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
   ioctl(sockfd, SIOCGIFHWADDR, &ifr); // 如果 ioctl 失败，ifr 中的数据可能无效
   printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
          (unsigned char)ifr.ifr_hwaddr.sa_data[0],
          (unsigned char)ifr.ifr_hwaddr.sa_data[1],
          (unsigned char)ifr.ifr_hwaddr.sa_data[2],
          (unsigned char)ifr.ifr_hwaddr.sa_data[3],
          (unsigned char)ifr.ifr_hwaddr.sa_data[4],
          (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
   ```

3. **缓冲区溢出:** 在复制数据到或从内核空间时，没有正确管理缓冲区大小，可能导致缓冲区溢出。

4. **功能协商错误:** 在虚拟机启动时，客户机和宿主机之间对于 virtio 网络设备的支持功能协商失败，导致某些功能无法使用。

**Android Framework 或 NDK 如何到达这里：**

1. **应用程序发起网络请求:**  例如，一个 Android 应用使用 `OkHttp` 或 `HttpURLConnection` 发起 HTTP 请求。
2. **Framework 处理:** Android Framework 的 Java 代码处理请求，最终会调用到 Native 层的网络库 (例如 `bionic/libc/`).
3. **Native 网络库:** Native 网络库 (如 `libc.so`) 中的 `socket()`, `connect()`, `sendto()` 等函数会被调用。
4. **系统调用:** 这些 libc 函数会通过系统调用 (例如 `socket()`, `connect()`, `sendto()`) 进入 Linux 内核。
5. **内核网络栈:** Linux 内核的网络栈接收到系统调用，并根据目标地址等信息确定路由和网络接口。
6. **Virtio 设备驱动:** 如果目标网络接口是 virtio 设备，内核会调用相应的 virtio 网络设备驱动程序。
7. **UAPI 交互:**  virtio 设备驱动程序会使用 `bionic/libc/kernel/uapi/linux/virtio_net.handroid` 中定义的结构体和常量，与用户空间的虚拟化进程（例如 QEMU 或 KVM）进行通信，完成网络数据的发送和接收。

**Frida Hook 示例调试步骤：**

假设我们想观察 Android 系统在配置 virtio 网络设备的 MAC 地址时，如何使用这个头文件中定义的结构体。我们可以 hook `ioctl` 系统调用。

```python
import frida
import sys

# 要 hook 的进程名称或 PID
package_name = "com.android.systemui"  # 例如，hook SystemUI 进程
# 或者
# pid = 1234

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查是否是与网络设备相关的 ioctl 请求 (可以根据 fd 或 request 的值进行更精确的判断)
        if (request == 0x8913) { // 假设 SIOCSIFHWADDR 的值是 0x8913，需要根据实际情况确定
            console.log("\\n*** ioctl called ***");
            console.log("  fd:", fd);
            console.log("  request:", request, "(SIOCSIFHWADDR?)");

            // 读取 ifreq 结构体的内容 (假设是设置 MAC 地址的 ioctl)
            const ifreqPtr = ptr(argp);
            const ifr_name = ifreqPtr.readCString();
            const ifr_hwaddr_sa_family = ifreqPtr.add(16).readU8();
            const ifr_hwaddr_sa_data = ifreqPtr.add(18).readByteArray(6);
            console.log("  ifr_name:", ifr_name);
            console.log("  ifr_hwaddr.sa_family:", ifr_hwaddr_sa_family);
            console.log("  ifr_hwaddr.sa_data:", hexdump(ifr_hwaddr_sa_data));
        } else if (request == 0xc014da01) { // 假设是与 virtio 网络设备相关的控制命令，需要根据实际情况确定
            console.log("\\n*** virtio net ioctl called ***");
            console.log("  fd:", fd);
            console.log("  request:", request);

            // 可以尝试解析 argp 指向的数据，根据 virtio_net_ctrl_hdr 和相关结构体的定义
            const ctrl_hdr_ptr = ptr(argp);
            const class_ = ctrl_hdr_ptr.readU8();
            const cmd = ctrl_hdr_ptr.add(1).readU8();
            console.log("  virtio_net_ctrl_hdr.class:", class_);
            console.log("  virtio_net_ctrl_hdr.cmd:", cmd);

            if (cmd == 1) { // 假设 VIRTIO_NET_CTRL_MAC 的值为 1
                console.log("  Potentially setting MAC address...");
                // 进一步解析 virtio_net_ctrl_mac 结构体
                const entries = ctrl_hdr_ptr.add(2).readU32();
                console.log("  Number of entries:", entries);
                // ... 可以继续读取 MAC 地址数据
            }
        }
    },
    onLeave: function(retval) {
        // console.log("  Return value:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida]: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Frida Error]: {message['stack']}")

try:
    session = frida.attach(package_name) # 如果使用 PID，则使用 frida.attach(pid)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到.")
except Exception as e:
    print(f"发生错误: {e}")
```

**调试步骤:**

1. **找到目标进程:** 确定你想要观察的网络配置过程发生在哪个进程中。
2. **编写 Frida 脚本:**  使用 `Interceptor.attach` hook `ioctl` 系统调用。
3. **识别相关的 `ioctl` 请求:**  根据 `request` 参数的值来判断是否是与网络设备相关的 `ioctl` 调用。可能需要查阅 Linux 内核源码或进行实验来确定具体的请求代码。
4. **解析参数:** 根据 `ioctl` 的请求类型，解析 `argp` 指向的内存区域，将其解释为 `virtio_net_ctrl_hdr` 或其他相关的结构体。
5. **观察数据:**  打印出结构体中的关键字段，例如命令代码、MAC 地址等。
6. **触发事件:** 在 Android 系统中触发网络配置相关的操作，例如连接 Wi-Fi、修改网络设置等，观察 Frida 脚本的输出。

请注意，上述 Frida 脚本只是一个示例，实际调试中可能需要根据具体的场景和 `ioctl` 请求类型进行调整。你可能需要查阅内核源码来确定 `ioctl` 的命令代码和数据结构布局。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_net.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_VIRTIO_NET_H
#define _UAPI_LINUX_VIRTIO_NET_H
#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#include <linux/if_ether.h>
#define VIRTIO_NET_F_CSUM 0
#define VIRTIO_NET_F_GUEST_CSUM 1
#define VIRTIO_NET_F_CTRL_GUEST_OFFLOADS 2
#define VIRTIO_NET_F_MTU 3
#define VIRTIO_NET_F_MAC 5
#define VIRTIO_NET_F_GUEST_TSO4 7
#define VIRTIO_NET_F_GUEST_TSO6 8
#define VIRTIO_NET_F_GUEST_ECN 9
#define VIRTIO_NET_F_GUEST_UFO 10
#define VIRTIO_NET_F_HOST_TSO4 11
#define VIRTIO_NET_F_HOST_TSO6 12
#define VIRTIO_NET_F_HOST_ECN 13
#define VIRTIO_NET_F_HOST_UFO 14
#define VIRTIO_NET_F_MRG_RXBUF 15
#define VIRTIO_NET_F_STATUS 16
#define VIRTIO_NET_F_CTRL_VQ 17
#define VIRTIO_NET_F_CTRL_RX 18
#define VIRTIO_NET_F_CTRL_VLAN 19
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21
#define VIRTIO_NET_F_MQ 22
#define VIRTIO_NET_F_CTRL_MAC_ADDR 23
#define VIRTIO_NET_F_DEVICE_STATS 50
#define VIRTIO_NET_F_VQ_NOTF_COAL 52
#define VIRTIO_NET_F_NOTF_COAL 53
#define VIRTIO_NET_F_GUEST_USO4 54
#define VIRTIO_NET_F_GUEST_USO6 55
#define VIRTIO_NET_F_HOST_USO 56
#define VIRTIO_NET_F_HASH_REPORT 57
#define VIRTIO_NET_F_GUEST_HDRLEN 59
#define VIRTIO_NET_F_RSS 60
#define VIRTIO_NET_F_RSC_EXT 61
#define VIRTIO_NET_F_STANDBY 62
#define VIRTIO_NET_F_SPEED_DUPLEX 63
#ifndef VIRTIO_NET_NO_LEGACY
#define VIRTIO_NET_F_GSO 6
#endif
#define VIRTIO_NET_S_LINK_UP 1
#define VIRTIO_NET_S_ANNOUNCE 2
#define VIRTIO_NET_RSS_HASH_TYPE_IPv4 (1 << 0)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv4 (1 << 1)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv4 (1 << 2)
#define VIRTIO_NET_RSS_HASH_TYPE_IPv6 (1 << 3)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv6 (1 << 4)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv6 (1 << 5)
#define VIRTIO_NET_RSS_HASH_TYPE_IP_EX (1 << 6)
#define VIRTIO_NET_RSS_HASH_TYPE_TCP_EX (1 << 7)
#define VIRTIO_NET_RSS_HASH_TYPE_UDP_EX (1 << 8)
struct virtio_net_config {
  __u8 mac[ETH_ALEN];
  __virtio16 status;
  __virtio16 max_virtqueue_pairs;
  __virtio16 mtu;
  __le32 speed;
  __u8 duplex;
  __u8 rss_max_key_size;
  __le16 rss_max_indirection_table_length;
  __le32 supported_hash_types;
} __attribute__((packed));
struct virtio_net_hdr_v1 {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define VIRTIO_NET_HDR_F_DATA_VALID 2
#define VIRTIO_NET_HDR_F_RSC_INFO 4
  __u8 flags;
#define VIRTIO_NET_HDR_GSO_NONE 0
#define VIRTIO_NET_HDR_GSO_TCPV4 1
#define VIRTIO_NET_HDR_GSO_UDP 3
#define VIRTIO_NET_HDR_GSO_TCPV6 4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#define VIRTIO_NET_HDR_GSO_ECN 0x80
  __u8 gso_type;
  __virtio16 hdr_len;
  __virtio16 gso_size;
  union {
    struct {
      __virtio16 csum_start;
      __virtio16 csum_offset;
    };
    struct {
      __virtio16 start;
      __virtio16 offset;
    } csum;
    struct {
      __le16 segments;
      __le16 dup_acks;
    } rsc;
  };
  __virtio16 num_buffers;
};
struct virtio_net_hdr_v1_hash {
  struct virtio_net_hdr_v1 hdr;
  __le32 hash_value;
#define VIRTIO_NET_HASH_REPORT_NONE 0
#define VIRTIO_NET_HASH_REPORT_IPv4 1
#define VIRTIO_NET_HASH_REPORT_TCPv4 2
#define VIRTIO_NET_HASH_REPORT_UDPv4 3
#define VIRTIO_NET_HASH_REPORT_IPv6 4
#define VIRTIO_NET_HASH_REPORT_TCPv6 5
#define VIRTIO_NET_HASH_REPORT_UDPv6 6
#define VIRTIO_NET_HASH_REPORT_IPv6_EX 7
#define VIRTIO_NET_HASH_REPORT_TCPv6_EX 8
#define VIRTIO_NET_HASH_REPORT_UDPv6_EX 9
  __le16 hash_report;
  __le16 padding;
};
#ifndef VIRTIO_NET_NO_LEGACY
struct virtio_net_hdr {
  __u8 flags;
  __u8 gso_type;
  __virtio16 hdr_len;
  __virtio16 gso_size;
  __virtio16 csum_start;
  __virtio16 csum_offset;
};
struct virtio_net_hdr_mrg_rxbuf {
  struct virtio_net_hdr hdr;
  __virtio16 num_buffers;
};
#endif
struct virtio_net_ctrl_hdr {
  __u8 __linux_class;
  __u8 cmd;
} __attribute__((packed));
typedef __u8 virtio_net_ctrl_ack;
#define VIRTIO_NET_OK 0
#define VIRTIO_NET_ERR 1
#define VIRTIO_NET_CTRL_RX 0
#define VIRTIO_NET_CTRL_RX_PROMISC 0
#define VIRTIO_NET_CTRL_RX_ALLMULTI 1
#define VIRTIO_NET_CTRL_RX_ALLUNI 2
#define VIRTIO_NET_CTRL_RX_NOMULTI 3
#define VIRTIO_NET_CTRL_RX_NOUNI 4
#define VIRTIO_NET_CTRL_RX_NOBCAST 5
struct virtio_net_ctrl_mac {
  __virtio32 entries;
  __u8 macs[][ETH_ALEN];
} __attribute__((packed));
#define VIRTIO_NET_CTRL_MAC 1
#define VIRTIO_NET_CTRL_MAC_TABLE_SET 0
#define VIRTIO_NET_CTRL_MAC_ADDR_SET 1
#define VIRTIO_NET_CTRL_VLAN 2
#define VIRTIO_NET_CTRL_VLAN_ADD 0
#define VIRTIO_NET_CTRL_VLAN_DEL 1
#define VIRTIO_NET_CTRL_ANNOUNCE 3
#define VIRTIO_NET_CTRL_ANNOUNCE_ACK 0
#define VIRTIO_NET_CTRL_MQ 4
struct virtio_net_ctrl_mq {
  __virtio16 virtqueue_pairs;
};
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET 0
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN 1
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX 0x8000
struct virtio_net_rss_config {
  __le32 hash_types;
  __le16 indirection_table_mask;
  __le16 unclassified_queue;
  __le16 indirection_table[1];
  __le16 max_tx_vq;
  __u8 hash_key_length;
  __u8 hash_key_data[];
};
#define VIRTIO_NET_CTRL_MQ_RSS_CONFIG 1
struct virtio_net_hash_config {
  __le32 hash_types;
  __le16 reserved[4];
  __u8 hash_key_length;
  __u8 hash_key_data[];
};
#define VIRTIO_NET_CTRL_MQ_HASH_CONFIG 2
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS 5
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET 0
#define VIRTIO_NET_CTRL_NOTF_COAL 6
struct virtio_net_ctrl_coal_tx {
  __le32 tx_max_packets;
  __le32 tx_usecs;
};
#define VIRTIO_NET_CTRL_NOTF_COAL_TX_SET 0
struct virtio_net_ctrl_coal_rx {
  __le32 rx_max_packets;
  __le32 rx_usecs;
};
#define VIRTIO_NET_CTRL_NOTF_COAL_RX_SET 1
#define VIRTIO_NET_CTRL_NOTF_COAL_VQ_SET 2
#define VIRTIO_NET_CTRL_NOTF_COAL_VQ_GET 3
struct virtio_net_ctrl_coal {
  __le32 max_packets;
  __le32 max_usecs;
};
struct virtio_net_ctrl_coal_vq {
  __le16 vqn;
  __le16 reserved;
  struct virtio_net_ctrl_coal coal;
};
#define VIRTIO_NET_CTRL_STATS 8
#define VIRTIO_NET_CTRL_STATS_QUERY 0
#define VIRTIO_NET_CTRL_STATS_GET 1
struct virtio_net_stats_capabilities {
#define VIRTIO_NET_STATS_TYPE_CVQ (1ULL << 32)
#define VIRTIO_NET_STATS_TYPE_RX_BASIC (1ULL << 0)
#define VIRTIO_NET_STATS_TYPE_RX_CSUM (1ULL << 1)
#define VIRTIO_NET_STATS_TYPE_RX_GSO (1ULL << 2)
#define VIRTIO_NET_STATS_TYPE_RX_SPEED (1ULL << 3)
#define VIRTIO_NET_STATS_TYPE_TX_BASIC (1ULL << 16)
#define VIRTIO_NET_STATS_TYPE_TX_CSUM (1ULL << 17)
#define VIRTIO_NET_STATS_TYPE_TX_GSO (1ULL << 18)
#define VIRTIO_NET_STATS_TYPE_TX_SPEED (1ULL << 19)
  __le64 supported_stats_types[1];
};
struct virtio_net_ctrl_queue_stats {
  struct {
    __le16 vq_index;
    __le16 reserved[3];
    __le64 types_bitmap[1];
  } stats[1];
};
struct virtio_net_stats_reply_hdr {
#define VIRTIO_NET_STATS_TYPE_REPLY_CVQ 32
#define VIRTIO_NET_STATS_TYPE_REPLY_RX_BASIC 0
#define VIRTIO_NET_STATS_TYPE_REPLY_RX_CSUM 1
#define VIRTIO_NET_STATS_TYPE_REPLY_RX_GSO 2
#define VIRTIO_NET_STATS_TYPE_REPLY_RX_SPEED 3
#define VIRTIO_NET_STATS_TYPE_REPLY_TX_BASIC 16
#define VIRTIO_NET_STATS_TYPE_REPLY_TX_CSUM 17
#define VIRTIO_NET_STATS_TYPE_REPLY_TX_GSO 18
#define VIRTIO_NET_STATS_TYPE_REPLY_TX_SPEED 19
  __u8 type;
  __u8 reserved;
  __le16 vq_index;
  __le16 reserved1;
  __le16 size;
};
struct virtio_net_stats_cvq {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 command_num;
  __le64 ok_num;
};
struct virtio_net_stats_rx_basic {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 rx_notifications;
  __le64 rx_packets;
  __le64 rx_bytes;
  __le64 rx_interrupts;
  __le64 rx_drops;
  __le64 rx_drop_overruns;
};
struct virtio_net_stats_tx_basic {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 tx_notifications;
  __le64 tx_packets;
  __le64 tx_bytes;
  __le64 tx_interrupts;
  __le64 tx_drops;
  __le64 tx_drop_malformed;
};
struct virtio_net_stats_rx_csum {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 rx_csum_valid;
  __le64 rx_needs_csum;
  __le64 rx_csum_none;
  __le64 rx_csum_bad;
};
struct virtio_net_stats_tx_csum {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 tx_csum_none;
  __le64 tx_needs_csum;
};
struct virtio_net_stats_rx_gso {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 rx_gso_packets;
  __le64 rx_gso_bytes;
  __le64 rx_gso_packets_coalesced;
  __le64 rx_gso_bytes_coalesced;
};
struct virtio_net_stats_tx_gso {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 tx_gso_packets;
  __le64 tx_gso_bytes;
  __le64 tx_gso_segments;
  __le64 tx_gso_segments_bytes;
  __le64 tx_gso_packets_noseg;
  __le64 tx_gso_bytes_noseg;
};
struct virtio_net_stats_rx_speed {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 rx_ratelimit_packets;
  __le64 rx_ratelimit_bytes;
};
struct virtio_net_stats_tx_speed {
  struct virtio_net_stats_reply_hdr hdr;
  __le64 tx_ratelimit_packets;
  __le64 tx_ratelimit_bytes;
};
#endif

"""

```