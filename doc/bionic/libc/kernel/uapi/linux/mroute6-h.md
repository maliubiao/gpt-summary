Response:
Let's break down the thought process for analyzing the provided C header file and generating the comprehensive response.

**1. Understanding the Goal:**

The core request is to analyze a Linux kernel header file (`mroute6.h`) related to IPv6 multicast routing and explain its purpose, connections to Android, functionality, implementation details (where possible), potential errors, and how Android frameworks might interact with it.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the file, looking for keywords and recognizable patterns. Here are some initial observations:

* **`#ifndef _UAPI__LINUX_MROUTE6_H`:**  Standard header guard, indicating this is a header file meant to be included in userspace programs. The `_UAPI_` prefix strongly suggests this is for user-kernel interface.
* **`#include <linux/const.h>`, `#include <linux/types.h>`, etc.:** Standard Linux kernel headers. This confirms the context is within the Linux kernel.
* **`MRT6_BASE`, `MRT6_INIT`, `MRT6_ADD_MIF`, etc.:**  These look like symbolic constants defining command codes related to multicast routing. The `MRT6` prefix suggests "Multicast Routing IPv6".
* **`SIOCGETMIFCNT_IN6`, `SIOCGETSGCNT_IN6`, `SIOCGETRPF`:** These start with `SIOC`, which is a strong indicator of `ioctl` (input/output control) commands for sockets. The `_IN6` suffix confirms they are related to IPv6.
* **`MAXMIFS 32`:**  A constant, likely defining the maximum number of Multicast Interface Flags (MIFs).
* **`typedef unsigned long mifbitmap_t;`, `typedef unsigned short mifi_t;`:**  Type definitions, probably for representing MIFs.
* **`struct if_set`:** A structure for managing sets of network interfaces, using bitmasks. The macros `IF_SET`, `IF_CLR`, `IF_ISSET` are characteristic of bit manipulation.
* **`struct mif6ctl`, `struct mf6cctl`, `struct sioc_sg_req6`, etc.:**  These are data structures, likely used as arguments for the `ioctl` commands. Their names suggest their purpose (e.g., `mif6ctl` probably controls a multicast interface).
* **`struct mrt6msg`:** Another structure, potentially for exchanging multicast routing messages.
* **`enum { ... IP6MRA_CREPORT_... }`:** An enumeration, likely defining types of multicast routing reports.

**3. Inferring Functionality:**

Based on the identified keywords and structures, we can start inferring the functionality of this header file:

* **Managing Multicast Interfaces (MIFs):** The presence of `MRT6_ADD_MIF`, `MRT6_DEL_MIF`, `MAXMIFS`, `mifbitmap_t`, `mifi_t`, and `struct mif6ctl` strongly points to the ability to add, delete, and manage multicast routing interfaces.
* **Managing Multicast Forwarding Cache (MFC):**  `MRT6_ADD_MFC`, `MRT6_DEL_MFC`, `struct mf6cctl` suggest management of the multicast forwarding cache, which determines how multicast packets are forwarded.
* **`ioctl` Interface:** The `SIOC` prefixed constants clearly indicate the use of `ioctl` system calls for controlling multicast routing.
* **Retrieving Information:**  `SIOCGETMIFCNT_IN6`, `SIOCGETSGCNT_IN6`, `SIOCGETRPF` suggest ways to retrieve statistics and Reverse Path Forwarding (RPF) information.
* **Flushing:** `MRT6_FLUSH`, `MRT6_FLUSH_MFC`, `MRT6_FLUSH_MIFS` indicate operations to clear routing state.
* **Reporting:** `struct mrt6msg` and the `IP6MRA_CREPORT_*` enum suggest a mechanism for reporting multicast routing events.

**4. Connecting to Android:**

Now, consider how this kernel functionality relates to Android:

* **Network Stack:** Android's network stack, based on the Linux kernel, directly utilizes these functionalities. Applications using multicast on Android ultimately rely on these kernel interfaces.
* **NDK:**  Native applications using the NDK can potentially interact with these features through socket programming and `ioctl` calls.
* **Framework (Less Direct):**  While the Android Framework doesn't directly call these kernel functions, higher-level APIs for multicast (like `MulticastSocket`) abstract away these lower-level details.

**5. Explaining Libc Functions (and Acknowledging Limitations):**

The prompt asks for explanations of *libc* functions. However, this header file primarily defines *kernel* interfaces. The *libc* functions involved would be the standard system call wrappers, such as:

* **`socket()`:** To create a socket for multicast communication (typically `AF_INET6`, `SOCK_DGRAM`).
* **`ioctl()`:** The primary way to send the `MRT6_*` commands to the kernel.
* **`bind()`:**  Potentially to bind to a specific address or interface.
* **`sendto()`/`recvfrom()`:** For sending and receiving multicast packets.
* **`bcopy()`/`bzero()`:**  Used within the header file's macros, these are memory manipulation functions provided by `libc`. The explanation should focus on their basic memory copying/zeroing behavior.

It's crucial to acknowledge that the header file *itself* doesn't *implement* these functions. It defines the *interface* that user-space programs can use. The *implementation* resides within the Linux kernel.

**6. Dynamic Linker Aspects (and Acknowledging Absence):**

The prompt asks about the dynamic linker. This header file doesn't directly involve the dynamic linker. It defines data structures and constants used in system calls. The dynamic linker's role is primarily in loading shared libraries. Therefore, the explanation should clarify this lack of direct involvement. A sample SO layout and linking process are not directly relevant here.

**7. Assumptions, Inputs, and Outputs (where applicable):**

For the `ioctl` calls, we can imagine scenarios:

* **Input:**  A program wants to add a multicast interface. It would populate a `struct mif6ctl` and use `ioctl` with `MRT6_ADD_MIF`.
* **Output:** The `ioctl` call might return success (0) or an error code (-1) if the operation fails.

**8. Common Usage Errors:**

Think about potential errors when using these interfaces:

* **Incorrect `ioctl` request code:** Using the wrong `MRT6_*` constant.
* **Incorrectly populated structures:**  Providing invalid data in `struct mif6ctl`, `struct mf6cctl`, etc.
* **Insufficient privileges:**  Multicast routing configuration often requires root privileges.
* **Interface not found:** Trying to configure a non-existent network interface.

**9. Android Framework/NDK Path and Frida Hook:**

Describe the flow from a high-level Android API down to the kernel:

* **Framework:** An app uses `MulticastSocket`.
* **System Service:** The framework interacts with a system service (like `ConnectivityService`).
* **Native Code:**  The system service (or potentially an NDK application directly) uses socket system calls.
* **Kernel:** The socket calls trigger the relevant kernel code that handles multicast routing, using the structures and constants defined in `mroute6.h`.

The Frida hook example should target the `ioctl` system call and filter for calls with the `SIOCPROTOPRIVATE` family, as these are the ones used by the multicast routing commands.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings for better readability. Use code blocks for the Frida example and clearly explain each part of the response. Use precise language and avoid jargon where possible, or explain technical terms. Emphasize the distinction between user-space and kernel-space.

**Self-Correction/Refinement:**

During the process, review the explanations to ensure accuracy. For example, initially, I might have focused too much on specific libc functions *within* the header file. Realizing that this is a kernel header, the focus should shift to the *system calls* that *use* this header. Similarly, the dynamic linker aspect needs clarification that it's not directly involved in *this specific header*.
这是一个定义 Linux 内核 IPv6 组播路由用户空间 API 的头文件。它定义了用于配置和管理 IPv6 组播路由的常量、数据结构和 ioctl 命令。由于它位于 `bionic/libc/kernel/uapi` 目录下，表明它是用户空间程序可以使用的 Linux 内核 API 的一部分。

**功能列举：**

1. **定义 IPv6 组播路由相关的 ioctl 命令:**  例如 `MRT6_INIT`, `MRT6_ADD_MIF`, `MRT6_DEL_MFC` 等，这些常量代表了可以向内核发送的控制命令，用于管理 IPv6 组播路由。
2. **定义用于 ioctl 命令的数据结构:** 例如 `struct mif6ctl` (多播接口控制), `struct mf6cctl` (多播转发缓存控制), `struct sioc_sg_req6` (获取源组统计信息), `struct sioc_mif_req6` (获取接口统计信息) 和 `struct mrt6msg` (多播路由消息)。
3. **定义与接口相关的位图和集合:**  `mifbitmap_t` 和 `struct if_set` 用于表示和操作网络接口的集合。
4. **定义用于刷新组播路由状态的常量:** 例如 `MRT6_FLUSH_MFC`, `MRT6_FLUSH_MIFS` 等，用于清除内核中的组播路由信息。
5. **定义组播路由报告相关的枚举:** 例如 `IP6MRA_CREPORT_UNSPEC` 等，用于描述不同类型的组播路由报告。

**与 Android 功能的关系及举例说明：**

Android 的网络协议栈是基于 Linux 内核的，因此这个头文件中定义的接口会被 Android 系统底层的网络功能所使用。虽然应用开发者通常不会直接使用这些底层的 ioctl 命令，但 Android Framework 会在底层处理这些操作。

**举例说明：**

* **IP 组播应用程序:**  当 Android 应用程序需要发送或接收 IPv6 组播数据时，Android 系统底层的网络模块可能需要配置组播路由。例如，当一个应用程序加入一个 IPv6 组播组时，系统可能需要在内核中添加相应的组播转发条目 (MFC - Multicast Forwarding Cache)。这个过程可能会涉及到使用 `MRT6_ADD_MFC` 命令。
* **Wi-Fi Aware (NAN):** Wi-Fi Aware 技术允许附近的设备在没有互联网接入点的情况下发现彼此并进行通信。它在某些场景下会使用 IPv6 组播进行设备发现和服务发现。Android 系统需要配置合适的组播路由才能支持 Wi-Fi Aware 的功能，这可能会间接使用到这里定义的接口。
* **底层网络管理功能:** Android 系统可能需要监控和管理网络接口上的组播流量。例如，获取特定组播源组的统计信息（通过 `SIOCGETSGCNT_IN6`）或者特定接口的统计信息（通过 `SIOCGETMIFCNT_IN6`）。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身并没有定义 libc 函数，它定义的是 Linux 内核的 API。用户空间的程序需要通过 libc 提供的系统调用接口来与内核交互。这里涉及到的主要 libc 函数是：

* **`ioctl()`:**  这是最关键的函数，用于向设备驱动程序 (在这里是网络协议栈) 发送控制命令。用户空间程序会调用 `ioctl()`，并传入相应的 socket 文件描述符、ioctl 命令代码 (例如 `MRT6_ADD_MIF`) 和指向参数结构的指针 (例如 `struct mif6ctl`)。
    * **实现原理:** `ioctl()` 系统调用会陷入内核，内核根据传入的文件描述符找到对应的设备驱动程序，然后调用该驱动程序中处理 `ioctl` 命令的函数。对于 socket 相关的 `ioctl` 命令，内核会调用网络协议栈中相应的处理函数。
* **`socket()`:**  用于创建一个 socket 文件描述符，这是进行网络操作的前提。对于组播路由相关的操作，通常会创建一个 `AF_INET6` 类型的 socket。
    * **实现原理:** `socket()` 系统调用会陷入内核，内核会创建一个 socket 数据结构，并分配一个文件描述符返回给用户空间。
* **`bind()`:**  虽然不是所有组播路由操作都必须绑定地址，但在某些情况下可能会用到，例如绑定到一个特定的本地地址或接口。
    * **实现原理:** `bind()` 系统调用会将 socket 绑定到一个特定的本地地址和端口。
* **`sendto()` / `recvfrom()`:** 用于发送和接收网络数据包，包括组播数据包。虽然这里主要关注路由配置，但数据包的发送和接收最终会受到路由配置的影响。
    * **实现原理:** 这些系统调用涉及将数据从用户空间拷贝到内核空间，并交给网络协议栈进行处理和发送 (对于 `sendto`)，或者从内核空间接收数据并拷贝到用户空间 (对于 `recvfrom`)。
* **`bcopy()` 和 `bzero()`:**  这两个函数在头文件中以宏 `IF_COPY` 和 `IF_ZERO` 的形式被使用，用于内存的拷贝和清零操作。它们是 libc 提供的基本内存操作函数。
    * **实现原理:** `bcopy()` 将一块内存区域的内容复制到另一块内存区域。`bzero()` 将一块内存区域的内容设置为零。这些通常是基于汇编语言优化的快速内存操作实现。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件定义的是内核 API，与动态链接器（dynamic linker）没有直接关系。动态链接器主要负责在程序运行时加载和链接共享库 (`.so` 文件)。

虽然使用这个头文件中定义的内核 API 的程序可能会链接到 libc (`.so`)，但这个头文件本身并不涉及动态链接的过程。它定义的是内核与用户空间交互的接口。

**如果做了逻辑推理，请给出假设输入与输出：**

假设一个用户空间程序想要添加一个 IPv6 组播接口 (MIF)。

**假设输入:**

* **ioctl 命令:** `MRT6_ADD_MIF`
* **参数结构 `struct mif6ctl`:**
    * `mif6c_mifi`:  要添加的 MIF 的索引，例如 0。
    * `mif6c_flags`:  MIF 的标志，例如 `MIFF_REGISTER`。
    * `vifc_threshold`:  TTL 阈值，例如 1。
    * `mif6c_pifi`:  父接口的索引，例如 0。
    * `vifc_rate_limit`:  速率限制，例如 0。

**预期输出:**

* 如果添加成功，`ioctl()` 系统调用返回 0。
* 如果添加失败（例如，MIF 索引已存在，权限不足等），`ioctl()` 系统调用返回 -1，并且 `errno` 会被设置为相应的错误码（例如 `EEXIST`, `EPERM`）。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **错误的 ioctl 命令代码:**  使用了错误的 `MRT6_*` 常量，导致内核无法识别要执行的操作。
   ```c
   // 错误地使用了 MRT6_DONE 而不是 MRT6_ADD_MIF
   int ret = ioctl(sock_fd, MRT6_DONE, &mif_ctl);
   ```
2. **未正确初始化参数结构:**  `ioctl` 命令的参数结构中的某些字段未被正确设置，导致内核接收到无效的参数。
   ```c
   struct mif6ctl mif_ctl;
   mif_ctl.mif6c_mifi = 0; // 只设置了部分字段
   int ret = ioctl(sock_fd, MRT6_ADD_MIF, &mif_ctl);
   ```
3. **权限不足:**  某些组播路由操作可能需要 root 权限。如果非特权用户尝试执行这些操作，`ioctl()` 将返回错误。
4. **MIF 索引冲突:**  尝试添加一个已经存在的 MIF 索引。
5. **接口不存在:**  在 `struct mif6ctl` 中指定了一个不存在的父接口索引 (`mif6c_pifi`)。
6. **错误的网络地址格式:**  在使用涉及网络地址的结构体（如 `struct sockaddr_in6`）时，提供了错误的地址格式。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到内核的路径 (以添加组播路由为例):**

1. **应用程序 (Java/Kotlin):**  一个应用程序可能不需要直接操作组播路由，但某些网络功能的实现可能依赖于它。
2. **Android Framework (Java/Kotlin):** Framework 层的 API，例如 `java.net.MulticastSocket`，会在底层调用 native 代码来实现其功能。
3. **System Services (Java/Kotlin):**  一些系统服务，例如 `ConnectivityService`，负责管理网络的连接和配置。当需要进行底层的网络配置时，这些服务会与 native 代码交互。
4. **Native Code (C/C++):** Android 系统中有很多 native 代码，它们会使用 POSIX socket API (例如 `socket()`, `ioctl()`) 来与内核进行交互。例如，负责 IP 路由管理的守护进程或库可能会调用 `ioctl()` 来配置组播路由。
5. **Bionic libc:**  Native 代码通过 Bionic libc 提供的系统调用封装函数来调用内核的系统调用，例如 `ioctl()`。
6. **Linux Kernel:**  内核接收到 `ioctl()` 系统调用后，会根据 socket 的类型和 `ioctl` 的命令码，调用网络协议栈中处理 IPv6 组播路由的相应函数。这些函数会使用 `mroute6.h` 中定义的常量和数据结构。

**NDK 到内核的路径:**

1. **NDK 应用程序 (C/C++):** 使用 NDK 开发的应用程序可以直接调用 POSIX socket API。
2. **Bionic libc:**  NDK 应用程序链接到 Bionic libc，并使用其提供的系统调用封装函数，例如 `ioctl()`。
3. **Linux Kernel:**  与 Framework 的路径相同，内核接收到系统调用后进行处理。

**Frida Hook 示例:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于观察与 IPv6 组播路由相关的 `ioctl` 调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.attach('com.android.shell') # Hook 特定进程或整个 shell

    script = session.create_script("""
        const IOCTL_MAGIC = 0x89; // 通常 SIOCPROTOPRIVATE 命令会使用这个 magic number

        Interceptor.attach(Module.findExportByName(null, "ioctl"), {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                const argp = args[2];

                // 检查是否是 SIOCPROTOPRIVATE 族命令 (可能与 mroute6 相关)
                if ((request >> 8) & 0xff == IOCTL_MAGIC) {
                    const cmd = request & 0xff;
                    if (cmd >= 200 && cmd <= 212) { // MRT6_BASE 到 MRT6_MAX 的范围
                        console.log("\\n[*] ioctl called");
                        console.log("    fd: " + fd);
                        console.log("    request: 0x" + request.toString(16));
                        console.log("    cmd (MRT6_*): " + cmd);

                        // 你可以根据 cmd 的值，进一步解析 argp 指向的数据结构
                        if (cmd == 202) { // MRT6_ADD_MIF
                            const mif6ctlPtr = ptr(argp);
                            const mif6c_mifi = mif6ctlPtr.readU16();
                            const mif6c_flags = mif6ctlPtr.add(2).readU8();
                            console.log("    mif6c_mifi: " + mif6c_mifi);
                            console.log("    mif6c_flags: 0x" + mif6c_flags.toString(16));
                        } else if (cmd == 204) { // MRT6_ADD_MFC
                            // 解析 struct mf6cctl
                            const mf6cctlPtr = ptr(argp);
                            const originAddr = mf6cctlPtr.readByteArray(28); // sizeof(struct sockaddr_in6)
                            const mcastgrpAddr = mf6cctlPtr.add(28).readByteArray(28);
                            console.log("    origin: " + hexdump(originAddr));
                            console.log("    mcastgrp: " + hexdump(mcastgrpAddr));
                        }
                        // ... 其他 MRT6_* 命令的解析
                    }
                }
            }
        });
    """)

    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Waiting for ioctl calls...")
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print("进程未找到，请指定正确的进程 PID 或使用 'com.android.shell'")
except Exception as e:
    print(e)
```

**使用说明:**

1. **保存代码:** 将代码保存为 Python 文件，例如 `mroute6_hook.py`。
2. **安装 Frida:** 确保你的系统上安装了 Frida 和 frida-tools。
3. **连接设备:** 确保你的 Android 设备通过 USB 连接到计算机，并且 adb 可用。
4. **运行 Frida:**
   * **Hook 特定进程:** 找到你想要监控的进程的 PID，并运行 `python mroute6_hook.py <PID>`。
   * **Hook shell 进程:** 运行 `python mroute6_hook.py` (默认 hook `com.android.shell`)。然后在 adb shell 中执行可能触发组播路由配置的操作。

**代码解释:**

* **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 函数。
* **`onEnter`:** 在 `ioctl` 函数调用前执行。
* **`(request >> 8) & 0xff == IOCTL_MAGIC`:** 检查 `ioctl` 命令的高字节是否为 `IOCTL_MAGIC`，这是一种常见的识别 `SIOCPROTOPRIVATE` 命令的方式。
* **`cmd >= 200 && cmd <= 212`:** 检查 `ioctl` 命令的低字节是否在 `MRT6_BASE` 到 `MRT6_MAX` 的范围内。
* **条件判断和结构体解析:** 根据 `cmd` 的值，进一步解析 `argp` 指向的参数结构体，并打印相关信息。

通过运行这个 Frida 脚本，你可以观察到 Android 系统在底层调用 `ioctl` 配置 IPv6 组播路由的过程，从而了解 Android Framework 或 NDK 是如何与这里定义的内核 API 交互的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/mroute6.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_MROUTE6_H
#define _UAPI__LINUX_MROUTE6_H
#include <linux/const.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/in6.h>
#define MRT6_BASE 200
#define MRT6_INIT (MRT6_BASE)
#define MRT6_DONE (MRT6_BASE + 1)
#define MRT6_ADD_MIF (MRT6_BASE + 2)
#define MRT6_DEL_MIF (MRT6_BASE + 3)
#define MRT6_ADD_MFC (MRT6_BASE + 4)
#define MRT6_DEL_MFC (MRT6_BASE + 5)
#define MRT6_VERSION (MRT6_BASE + 6)
#define MRT6_ASSERT (MRT6_BASE + 7)
#define MRT6_PIM (MRT6_BASE + 8)
#define MRT6_TABLE (MRT6_BASE + 9)
#define MRT6_ADD_MFC_PROXY (MRT6_BASE + 10)
#define MRT6_DEL_MFC_PROXY (MRT6_BASE + 11)
#define MRT6_FLUSH (MRT6_BASE + 12)
#define MRT6_MAX (MRT6_BASE + 12)
#define SIOCGETMIFCNT_IN6 SIOCPROTOPRIVATE
#define SIOCGETSGCNT_IN6 (SIOCPROTOPRIVATE + 1)
#define SIOCGETRPF (SIOCPROTOPRIVATE + 2)
#define MRT6_FLUSH_MFC 1
#define MRT6_FLUSH_MFC_STATIC 2
#define MRT6_FLUSH_MIFS 4
#define MRT6_FLUSH_MIFS_STATIC 8
#define MAXMIFS 32
typedef unsigned long mifbitmap_t;
typedef unsigned short mifi_t;
#define ALL_MIFS ((mifi_t) (- 1))
#ifndef IF_SETSIZE
#define IF_SETSIZE 256
#endif
typedef __u32 if_mask;
#define NIFBITS (sizeof(if_mask) * 8)
typedef struct if_set {
  if_mask ifs_bits[__KERNEL_DIV_ROUND_UP(IF_SETSIZE, NIFBITS)];
} if_set;
#define IF_SET(n,p) ((p)->ifs_bits[(n) / NIFBITS] |= (1 << ((n) % NIFBITS)))
#define IF_CLR(n,p) ((p)->ifs_bits[(n) / NIFBITS] &= ~(1 << ((n) % NIFBITS)))
#define IF_ISSET(n,p) ((p)->ifs_bits[(n) / NIFBITS] & (1 << ((n) % NIFBITS)))
#define IF_COPY(f,t) bcopy(f, t, sizeof(* (f)))
#define IF_ZERO(p) bzero(p, sizeof(* (p)))
struct mif6ctl {
  mifi_t mif6c_mifi;
  unsigned char mif6c_flags;
  unsigned char vifc_threshold;
  __u16 mif6c_pifi;
  unsigned int vifc_rate_limit;
};
#define MIFF_REGISTER 0x1
struct mf6cctl {
  struct sockaddr_in6 mf6cc_origin;
  struct sockaddr_in6 mf6cc_mcastgrp;
  mifi_t mf6cc_parent;
  struct if_set mf6cc_ifset;
};
struct sioc_sg_req6 {
  struct sockaddr_in6 src;
  struct sockaddr_in6 grp;
  unsigned long pktcnt;
  unsigned long bytecnt;
  unsigned long wrong_if;
};
struct sioc_mif_req6 {
  mifi_t mifi;
  unsigned long icount;
  unsigned long ocount;
  unsigned long ibytes;
  unsigned long obytes;
};
struct mrt6msg {
#define MRT6MSG_NOCACHE 1
#define MRT6MSG_WRONGMIF 2
#define MRT6MSG_WHOLEPKT 3
#define MRT6MSG_WRMIFWHOLE 4
  __u8 im6_mbz;
  __u8 im6_msgtype;
  __u16 im6_mif;
  __u32 im6_pad;
  struct in6_addr im6_src, im6_dst;
};
enum {
  IP6MRA_CREPORT_UNSPEC,
  IP6MRA_CREPORT_MSGTYPE,
  IP6MRA_CREPORT_MIF_ID,
  IP6MRA_CREPORT_SRC_ADDR,
  IP6MRA_CREPORT_DST_ADDR,
  IP6MRA_CREPORT_PKT,
  __IP6MRA_CREPORT_MAX
};
#define IP6MRA_CREPORT_MAX (__IP6MRA_CREPORT_MAX - 1)
#endif
```