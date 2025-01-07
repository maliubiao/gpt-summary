Response:
Let's break down the thought process for analyzing the provided `sockios.handroid` header file.

**1. Understanding the Context:**

The first step is to recognize the origin and purpose of the file. The prompt clearly states it's from `bionic/libc/kernel/uapi/linux/sockios.handroid`. This immediately tells us:

* **Bionic:** It's part of Android's core C library.
* **libc:**  Specifically related to the C library's interface with the kernel.
* **kernel/uapi:** This signifies a *userspace Application Programming Interface* for the Linux kernel. These are header files that define how userspace programs interact with kernel functions.
* **linux/sockios.h:**  The core purpose is related to socket Input/Output Control (ioctl) operations. The `.handroid` suffix likely indicates Android-specific modifications or a direct copy from the upstream kernel.

**2. Identifying Key Elements:**

Next, we scan the file for the most important elements:

* **Header Guards (`#ifndef _LINUX_SOCKIOS_H`, `#define _LINUX_SOCKIOS_H`, `#endif`):** These prevent multiple inclusions of the header, a standard C/C++ practice.
* **Includes (`#include <asm/bitsperlong.h>`, `#include <asm/sockios.h>`):**  This tells us the file depends on other low-level kernel headers. `asm/bitsperlong.h` is about architecture-specific data types, and `asm/sockios.h` likely contains the fundamental definitions for socket ioctls.
* **Macros (`#define SIOCINQ FIONREAD`, `#define SIOCOUTQ TIOCOUTQ`, `#define SOCK_IOC_TYPE 0x89`, etc.):** The vast majority of the file consists of macro definitions. These are essentially symbolic constants or shorthand notations. The naming convention `SIOC*` is a strong indicator of socket ioctl commands.

**3. Deconstructing the Macros (The Core Task):**

The core functionality resides in these macros. We need to understand what they represent:

* **`SIOCINQ` and `SIOCOUTQ`:** These are simple aliases for `FIONREAD` and `TIOCOUTQ`. Recognizing these as related to "number of bytes in queue" for sockets and terminals respectively is important.
* **`SOCK_IOC_TYPE 0x89`:** This defines a common "type" value used in the subsequent `_IOR` macro calls. It's a way of categorizing the ioctl commands.
* **`SIOCGSTAMP_NEW`, `SIOCGSTAMPNS_NEW`:** The `_IOR` macro strongly suggests these are used to *read* data from the kernel. The names hint at getting timestamps of some kind ("STAMP"). The "NS" likely means nanoseconds. The `long long[2]` indicates the data structure being returned.
* **Conditional Definitions (`#if __BITS_PER_LONG == 64 ... #endif`):**  This shows that the definition of `SIOCGSTAMP` and `SIOCGSTAMPNS` can change depending on the system's architecture (32-bit vs. 64-bit). The comparison with `sizeof(struct timeval)` and `sizeof(struct timespec)` implies the older versions might use different data structures.
* **The Long List of `SIOC...` Macros (e.g., `SIOCADDRT`, `SIOCGIFNAME`):**  These are the bulk of the file. The naming convention (`SIOC` followed by a descriptive abbreviation) is key. We can infer their purpose based on these abbreviations:
    * `ADDRT`, `DELRT`, `RTMSG`: Routing table manipulation.
    * `GIFNAME`, `SIFLINK`: Network interface information.
    * `GIFCONF`, `GIFFLAGS`, `SIFFLAGS`: Interface configuration and flags.
    * And so on...

**4. Connecting to Android:**

Given that this is an Android-specific file, we need to consider how these socket ioctls are used within the Android ecosystem:

* **Networking Stack:** Android's networking relies heavily on the Linux kernel's networking capabilities. These `SIOC` commands are fundamental to configuring and managing network interfaces, routing, and other network-related operations.
* **System Services:** Android system services (written in Java/Kotlin and often using native code) interact with the kernel through system calls, which can eventually involve these ioctl commands. For instance, a service managing network connectivity would likely use these to set IP addresses, manage interfaces, etc.
* **NDK:**  Developers using the Native Development Kit (NDK) can directly access these ioctl commands through standard C/C++ socket programming interfaces.

**5. Explaining `libc` Functions (The Ioctl System Call):**

The key `libc` function here is `ioctl()`. While this header *defines* the *commands*, the `ioctl()` system call is the mechanism to *execute* them. We need to explain its purpose and how it uses these `SIOC` macros.

**6. Dynamic Linker and SO Layout (Less Relevant for This Specific File):**

While the prompt asks about the dynamic linker, this header file itself *doesn't directly involve the dynamic linker*. It defines constants. However, *code that uses these constants* (e.g., network daemons, system services) will be linked. Therefore, we need to provide a general explanation of SO layout and linking. A simple example would suffice.

**7. Assumptions, Inputs, and Outputs (Illustrative Examples):**

To make the explanation concrete, we need to provide hypothetical scenarios:

* **Getting Interface Name:** Assume a program calls `ioctl()` with `SIOCGIFNAME`. What input structures are needed? What output will be returned?
* **Setting IP Address:**  Similarly, for `SIOCSIFADDR`.

**8. Common Usage Errors:**

Highlighting common mistakes is helpful:

* Incorrect ioctl number.
* Wrong data structure passed to `ioctl()`.
* Insufficient permissions.

**9. Android Framework/NDK to Kernel (Tracing the Path):**

This requires outlining the layers involved:

* **Java/Kotlin Framework:** High-level APIs (e.g., `ConnectivityManager`).
* **System Services (Native):**  Implement core functionality (e.g., `netd`).
* **NDK (C/C++):** Direct socket API access.
* **`libc` Wrappers:**  Functions like `socket()`, `ioctl()`.
* **System Calls:** The bridge to the kernel.
* **Kernel Implementation:** The actual handling of the ioctl.

**10. Frida Hook Example:**

A simple Frida script demonstrating how to intercept the `ioctl()` call and potentially filter for specific `SIOC` commands provides a practical debugging technique.

**Self-Correction/Refinement during the Thought Process:**

* **Initial Thought:**  Focus heavily on every single `SIOC` macro.
* **Correction:** Realize that explaining the *purpose* of the categories of ioctls (network interface, routing, etc.) is more important than detailing each individual one. A few key examples are sufficient.
* **Initial Thought:**  Dive deep into the bitwise structure of the `_IOR` macro.
* **Correction:** Explain its general purpose (read from kernel) is sufficient for this level of explanation.
* **Initial Thought:** Provide highly complex SO layout diagrams.
* **Correction:** A simplified example demonstrating the basic concept of shared libraries is adequate.

By following these steps, we can construct a comprehensive and well-structured explanation of the `sockios.handroid` header file and its role within the Android ecosystem.
这个文件 `bionic/libc/kernel/uapi/linux/sockios.handroid` 是 Android Bionic C 库中定义 socket I/O 控制操作 (ioctl) 代码的头文件。它基本上是 Linux 内核中 `linux/sockios.h` 文件的一个 Android 特殊版本或者直接拷贝。这个头文件定义了大量的宏，这些宏代表了可以对 socket 文件描述符执行的不同控制命令。

**功能列举：**

这个头文件主要定义了以下类型的功能：

1. **获取/设置 Socket 状态信息:**
   - `SIOCINQ` (FIONREAD): 获取接收队列中的数据字节数。
   - `SIOCOUTQ` (TIOCOUTQ): 获取发送队列中的数据字节数。
   - `SIOCGSTAMP_NEW`, `SIOCGSTAMPNS_NEW`: 获取 socket 接收到最后一个包的时间戳（分别以 `timeval` 和 `timespec` 结构体返回）。

2. **路由表管理:**
   - `SIOCADDRT`: 添加路由。
   - `SIOCDELRT`: 删除路由。
   - `SIOCRTMSG`: 获取路由消息。

3. **网络接口配置和信息获取:**
   - `SIOCGIFNAME`: 通过接口索引获取接口名。
   - `SIOCSIFLINK`: 设置接口链路层地址。
   - `SIOCGIFCONF`: 获取所有网络接口配置信息。
   - `SIOCGIFFLAGS`, `SIOCSIFFLAGS`: 获取/设置接口标志（例如 UP, DOWN, BROADCAST, MULTICAST）。
   - `SIOCGIFADDR`, `SIOCSIFADDR`: 获取/设置接口的 IP 地址。
   - `SIOCGIFDSTADDR`, `SIOCSIFDSTADDR`: 获取/设置点对点接口的远端 IP 地址。
   - `SIOCGIFBRDADDR`, `SIOCSIFBRDADDR`: 获取/设置接口的广播地址。
   - `SIOCGIFNETMASK`, `SIOCSIFNETMASK`: 获取/设置接口的网络掩码。
   - `SIOCGIFMETRIC`, `SIOCSIFMETRIC`: 获取/设置接口的 metric 值（用于路由）。
   - `SIOCGIFMTU`, `SIOCSIFMTU`: 获取/设置接口的最大传输单元 (MTU)。
   - `SIOCSIFNAME`: 设置接口名称。
   - `SIOCSIFHWADDR`: 设置接口硬件地址（MAC 地址）。
   - `SIOCGIFHWADDR`: 获取接口硬件地址（MAC 地址）。
   - `SIOCGIFINDEX`, `SIOGIFINDEX`: 获取接口索引。
   - `SIOCSIFPFLAGS`, `SIOCGIFPFLAGS`: 设置/获取接口协议相关的标志。
   - `SIOCDIFADDR`: 删除接口地址。
   - `SIOCSIFHWBROADCAST`: 设置接口硬件广播地址。
   - `SIOCGIFCOUNT`: 获取接口计数。
   - `SIOCGIFTXQLEN`, `SIOCSIFTXQLEN`: 获取/设置接口发送队列长度。

4. **以太网工具 (ethtool) 相关:**
   - `SIOCETHTOOL`: 执行以太网卡的特定操作 (需要 root 权限)。

5. **MII 接口相关:**
   - `SIOCGMIIPHY`, `SIOCGMIIREG`, `SIOCSMIIREG`: 用于访问以太网 PHY 芯片寄存器。

6. **WAN 设备相关:**
   - `SIOCWANDEV`: 获取 WAN 设备信息。

7. **QoS 相关:**
   - `SIOCOUTQNSD`: 获取发送队列中非发送数据的字节数。

8. **Socket 网络命名空间相关:**
   - `SIOCGSKNS`: 获取 socket 关联的网络命名空间。

9. **ARP/RARP 表管理:**
   - `SIOCDARP`, `SIOCGARP`, `SIOCSARP`: 删除/获取/设置 ARP 缓存条目。
   - `SIOCDRARP`, `SIOCGRARP`, `SIOCSRARP`: 删除/获取/设置 RARP 缓存条目。

10. **接口映射相关:**
    - `SIOCGIFMAP`, `SIOCSIFMAP`: 获取/设置接口的 I/O 内存映射信息。

11. **DLCI (数据链路连接标识符) 相关:**
    - `SIOCADDDLCI`, `SIOCDELDLCI`: 添加/删除 DLCI。

12. **VLAN 相关:**
    - `SIOCGIFVLAN`, `SIOCSIFVLAN`: 获取/设置 VLAN 信息。

13. ** bonding 接口相关:**
    - `SIOCBONDENSLAVE`, `SIOCBONDRELEASE`, `SIOCBONDSETHWADDR`, `SIOCBONDSLAVEINFOQUERY`, `SIOCBONDINFOQUERY`, `SIOCBONDCHANGEACTIVE`: 用于配置和管理 bonding (链路聚合) 接口。

14. ** bridge 接口相关:**
    - `SIOCBRADDBR`, `SIOCBRDELBR`, `SIOCBRADDIF`, `SIOCBRDELIF`: 用于配置和管理 bridge (网桥) 接口。

15. **硬件时间戳相关:**
    - `SIOCSHWTSTAMP`, `SIOCGHWTSTAMP`: 设置/获取硬件时间戳配置。

16. **私有 ioctl 命令:**
    - `SIOCDEVPRIVATE`, `SIOCPROTOPRIVATE`: 用于设备驱动程序或协议栈的私有 ioctl 命令。

**与 Android 功能的关系及举例说明：**

这些 ioctl 命令是 Android 系统中网络功能的基础。Android 框架和 NDK 使用它们来执行各种网络相关的操作。

* **网络连接管理:** Android 的 `ConnectivityService` 系统服务会使用这些 ioctl 命令来配置网络接口（例如，分配 IP 地址、设置 DNS 服务器）、管理路由表、以及控制网络连接的状态（例如，开启/关闭 Wi-Fi 或移动数据）。例如，当 Android 设备连接到一个新的 Wi-Fi 网络时，`ConnectivityService` 可能会使用 `SIOCSIFADDR` 设置接口的 IP 地址，使用 `SIOCADDRT` 添加默认路由。

* **Wi-Fi 和移动数据:** 当你打开或关闭 Wi-Fi 或移动数据时，Android 系统会调用相应的底层函数，这些函数最终会使用 `SIOCSIFFLAGS` 来启用或禁用网络接口。

* **VPN 连接:** VPN 应用会使用这些 ioctl 命令来创建虚拟网络接口，配置其 IP 地址和路由，并将网络流量导向 VPN 服务器。例如，可以使用 `SIOCGIFCONF` 获取当前的网络接口列表，使用 `SIOCSIFADDR` 配置 VPN 接口的地址，使用 `SIOCADDRT` 添加路由规则将流量路由到 VPN 服务器。

* **NDK 网络编程:** 使用 NDK 进行网络编程的开发者可以直接使用 socket API，并通过 `ioctl()` 函数来调用这些命令。例如，一个网络监控应用可以使用 `SIOCGIFCONF` 获取所有网络接口的信息，然后使用 `SIOCGIFFLAGS` 获取每个接口的状态。

**libc 函数的实现细节：**

这个头文件本身并没有实现任何 `libc` 函数。它只是定义了可以传递给 `ioctl()` 系统调用的常量。实际的实现位于 Linux 内核中。

`ioctl()` 是一个系统调用，其原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

- `fd`: 是一个打开的文件描述符，通常是 socket 文件描述符。
- `request`: 是一个与特定设备驱动程序相关的请求码，这里就是 `SIOC` 开头的宏定义。
- `...`: 可选的第三个参数，通常是指向与请求相关的数据结构的指针。

当用户空间的程序调用 `ioctl()` 时，内核会根据 `fd` 找到对应的设备驱动程序，然后根据 `request` 代码调用驱动程序中相应的处理函数。对于 socket 相关的 `ioctl` 命令，内核会调用网络协议栈中相应的函数来执行操作。

**dynamic linker 的功能及 SO 布局样本、链接处理过程：**

这个头文件直接涉及到的是内核接口，与 dynamic linker 的关系较为间接。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的内存空间，并解析和绑定符号。

虽然这个头文件本身不涉及动态链接，但是使用了这些定义的程序（例如，`netd` 守护进程，或者使用 NDK 的应用）在构建时需要链接到相关的共享库（例如，`libc.so`）。

**SO 布局样本：**

一个简单的使用 socket ioctl 的可执行文件的链接可能如下：

```
可执行文件 (myapp)
  |
  +-- 依赖于 --> libc.so
```

`libc.so` 中包含了 `socket()`、`bind()`、`ioctl()` 等 socket 相关的函数实现。

**链接处理过程：**

1. **编译时链接：** 当你编译使用 socket ioctl 的代码时，编译器会查找头文件（如 `sockios.handroid`），并解析其中的宏定义。链接器会将对 `libc` 中函数的引用记录在可执行文件的 `.dynamic` 段中。

2. **运行时链接：** 当你运行 `myapp` 时，dynamic linker 会执行以下操作：
   - 加载 `myapp` 到内存。
   - 解析 `myapp` 的 `.dynamic` 段，找到依赖的共享库 `libc.so`。
   - 加载 `libc.so` 到内存。
   - 解析 `libc.so` 的符号表，找到 `socket`、`ioctl` 等函数的地址。
   - 将 `myapp` 中对这些函数的引用重定位到 `libc.so` 中实际的地址。

**假设输入与输出（逻辑推理）：**

假设一个程序想要获取名为 "eth0" 的网络接口的 IP 地址。

**假设输入：**

- `fd`: 一个打开的 socket 文件描述符。
- `request`: `SIOCGIFADDR`。
- `argp`: 指向 `struct ifreq` 结构的指针，其中 `ifr_name` 成员设置为 "eth0"。

**预期输出：**

如果 "eth0" 接口存在且已配置 IP 地址，`ioctl()` 调用成功返回 0，并且 `argp` 指向的 `struct ifreq` 结构的 `ifr_addr` 成员将包含该接口的 IP 地址信息（以 `sockaddr` 结构体表示）。如果接口不存在或其他错误发生，`ioctl()` 调用将返回 -1，并设置 `errno` 来指示错误原因。

**用户或编程常见的使用错误：**

1. **错误的 `request` 代码：** 传递了错误的 `SIOC` 宏，导致内核执行了错误的操作或返回了意外的结果。

   ```c
   // 错误地使用了 SIOCSIFADDR (设置 IP 地址) 而不是 SIOCGIFADDR (获取 IP 地址)
   struct ifreq ifr;
   strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
   ifr.ifr_name[IFNAMSIZ - 1] = 0;
   struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
   sin->sin_family = AF_INET;
   inet_pton(AF_INET, "192.168.1.100", &sin->sin_addr);
   if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) { // 这里本意是获取
       perror("ioctl SIOCSIFADDR");
   }
   ```

2. **传递了错误的数据结构：**  `ioctl()` 的第三个参数需要指向与 `request` 代码匹配的数据结构。如果传递了错误的数据结构，内核可能会读取或写入错误的内存区域，导致崩溃或不可预测的行为。

   ```c
   // 错误地传递了一个 int 而不是 struct ifreq
   int mtu = 1500;
   if (ioctl(sockfd, SIOCSIFMTU, &mtu) == -1) { // SIOCSIFMTU 需要 struct ifreq
       perror("ioctl SIOCSIFMTU");
   }
   ```

3. **权限不足：** 某些 `ioctl` 操作需要 root 权限才能执行（例如，修改网络接口配置）。普通用户尝试执行这些操作会失败，并返回 `EPERM` 错误。

   ```c
   // 在非 root 权限下尝试设置 IP 地址可能会失败
   struct ifreq ifr;
   // ... 设置 ifr ...
   if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) {
       perror("ioctl SIOCSIFADDR"); // 可能会输出 "Operation not permitted"
   }
   ```

4. **接口名称错误：**  对于需要指定网络接口的操作，如果传递了错误的接口名称，`ioctl()` 调用会失败，并可能返回 `ENODEV` 错误。

   ```c
   struct ifreq ifr;
   strncpy(ifr.ifr_name, "wlan99", IFNAMSIZ - 1); // 假设 "wlan99" 不存在
   ifr.ifr_name[IFNAMSIZ - 1] = 0;
   if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
       perror("ioctl SIOCGIFFLAGS"); // 可能会输出 "No such device"
   }
   ```

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

1. **Android Framework (Java/Kotlin):**
   - Android Framework 中的高级网络 API（例如，`ConnectivityManager`）会调用底层的系统服务（例如，`netd`）。
   - 这些系统服务通常是用 C++ 编写的。

2. **System Services (C++):**
   - 系统服务会使用标准的 socket API（例如，`socket()`, `bind()`, `ioctl()`）。
   - 当需要执行网络接口配置或管理操作时，系统服务会调用 `ioctl()` 函数，并将相应的 `SIOC` 宏作为 `request` 参数传递。

3. **NDK (C/C++):**
   - 使用 NDK 进行网络编程的应用可以直接调用 `ioctl()` 函数，并使用这里定义的 `SIOC` 宏。

**Frida Hook 示例：**

可以使用 Frida hook `ioctl` 函数来观察哪些 `SIOC` 命令被调用以及传递的参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(['com.example.myapp']) # 替换成你的应用包名

    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "ioctl"), {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                const requestHex = request.toString(16);
                console.log("\\n[*] ioctl called with fd:", fd, "request:", request, "(" + requestHex + ")");

                // 这里可以根据 request 的值来解析第三个参数
                if (request === 0x8915) { // SIOCGIFADDR
                    const ifrPtr = ptr(args[2]);
                    const ifrName = ifrPtr.readCString();
                    console.log("[*]   SIOCGIFADDR for interface:", ifrName);
                } else if (request === 0x8916) { // SIOCSIFADDR
                    const ifrPtr = ptr(args[2]);
                    const ifrName = ifrPtr.readCString();
                    const ifaAddrPtr = ifrPtr.add(16); // 假设 ifr_addr 在偏移 16 字节处
                    const sinFamily = ifaAddrPtr.readU16();
                    if (sinFamily === 2) { // AF_INET
                        const sinPort = ifaAddrPtr.add(2).readU16();
                        const sinAddr = ifaAddrPtr.add(4).readU32();
                        const ipString = [
                            (sinAddr >>> 0) & 0xFF,
                            (sinAddr >>> 8) & 0xFF,
                            (sinAddr >>> 16) & 0xFF,
                            (sinAddr >>> 24) & 0xFF
                        ].join('.');
                        console.log("[*]   SIOCSIFADDR setting IP address for interface:", ifrName, "to", ipString);
                    }
                }
                // ... 可以添加更多 request 代码的处理
            },
            onLeave: function(retval) {
                console.log("[*] ioctl returned:", retval.toInt32());
            }
        });
    """)
    script.on('message', on_message)
    script.load()

    if not pid:
        device.resume(session.pid)

    print("[!] Press <Enter> at any time to detach from the process.")
    input()

    session.detach()

except frida.ProcessNotFoundError:
    print("进程未找到，请提供正确的进程 ID 或启动应用。")
except frida.TransportError:
    print("无法连接到 Frida 服务，请确保 Frida 服务正在运行。")
except Exception as e:
    print(e)
```

**使用方法：**

1. 将上述 Python 代码保存为 `hook_ioctl.py`。
2. 找到你想要监控的 Android 应用的进程 ID (PID)。
3. 运行 Frida 脚本：`python hook_ioctl.py <PID>` （如果应用已运行）或者 `python hook_ioctl.py` （Frida 会尝试启动应用，你需要替换代码中的包名）。
4. 脚本会 hook `ioctl` 函数，并在控制台上打印调用的信息，包括 `fd`、`request` 代码（十六进制和十进制）、以及根据 `request` 代码尝试解析的参数。

通过 Frida hook，你可以实时观察 Android 系统或应用在执行网络操作时调用的 `ioctl` 命令，从而更好地理解其网络行为。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/sockios.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_SOCKIOS_H
#define _LINUX_SOCKIOS_H
#include <asm/bitsperlong.h>
#include <asm/sockios.h>
#define SIOCINQ FIONREAD
#define SIOCOUTQ TIOCOUTQ
#define SOCK_IOC_TYPE 0x89
#define SIOCGSTAMP_NEW _IOR(SOCK_IOC_TYPE, 0x06, long long[2])
#define SIOCGSTAMPNS_NEW _IOR(SOCK_IOC_TYPE, 0x07, long long[2])
#if __BITS_PER_LONG == 64 || defined(__x86_64__) && defined(__ILP32__)
#define SIOCGSTAMP SIOCGSTAMP_OLD
#define SIOCGSTAMPNS SIOCGSTAMPNS_OLD
#else
#define SIOCGSTAMP ((sizeof(struct timeval)) == 8 ? SIOCGSTAMP_OLD : SIOCGSTAMP_NEW)
#define SIOCGSTAMPNS ((sizeof(struct timespec)) == 8 ? SIOCGSTAMPNS_OLD : SIOCGSTAMPNS_NEW)
#endif
#define SIOCADDRT 0x890B
#define SIOCDELRT 0x890C
#define SIOCRTMSG 0x890D
#define SIOCGIFNAME 0x8910
#define SIOCSIFLINK 0x8911
#define SIOCGIFCONF 0x8912
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFADDR 0x8915
#define SIOCSIFADDR 0x8916
#define SIOCGIFDSTADDR 0x8917
#define SIOCSIFDSTADDR 0x8918
#define SIOCGIFBRDADDR 0x8919
#define SIOCSIFBRDADDR 0x891a
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFMETRIC 0x891d
#define SIOCSIFMETRIC 0x891e
#define SIOCGIFMEM 0x891f
#define SIOCSIFMEM 0x8920
#define SIOCGIFMTU 0x8921
#define SIOCSIFMTU 0x8922
#define SIOCSIFNAME 0x8923
#define SIOCSIFHWADDR 0x8924
#define SIOCGIFENCAP 0x8925
#define SIOCSIFENCAP 0x8926
#define SIOCGIFHWADDR 0x8927
#define SIOCGIFSLAVE 0x8929
#define SIOCSIFSLAVE 0x8930
#define SIOCADDMULTI 0x8931
#define SIOCDELMULTI 0x8932
#define SIOCGIFINDEX 0x8933
#define SIOGIFINDEX SIOCGIFINDEX
#define SIOCSIFPFLAGS 0x8934
#define SIOCGIFPFLAGS 0x8935
#define SIOCDIFADDR 0x8936
#define SIOCSIFHWBROADCAST 0x8937
#define SIOCGIFCOUNT 0x8938
#define SIOCGIFBR 0x8940
#define SIOCSIFBR 0x8941
#define SIOCGIFTXQLEN 0x8942
#define SIOCSIFTXQLEN 0x8943
#define SIOCETHTOOL 0x8946
#define SIOCGMIIPHY 0x8947
#define SIOCGMIIREG 0x8948
#define SIOCSMIIREG 0x8949
#define SIOCWANDEV 0x894A
#define SIOCOUTQNSD 0x894B
#define SIOCGSKNS 0x894C
#define SIOCDARP 0x8953
#define SIOCGARP 0x8954
#define SIOCSARP 0x8955
#define SIOCDRARP 0x8960
#define SIOCGRARP 0x8961
#define SIOCSRARP 0x8962
#define SIOCGIFMAP 0x8970
#define SIOCSIFMAP 0x8971
#define SIOCADDDLCI 0x8980
#define SIOCDELDLCI 0x8981
#define SIOCGIFVLAN 0x8982
#define SIOCSIFVLAN 0x8983
#define SIOCBONDENSLAVE 0x8990
#define SIOCBONDRELEASE 0x8991
#define SIOCBONDSETHWADDR 0x8992
#define SIOCBONDSLAVEINFOQUERY 0x8993
#define SIOCBONDINFOQUERY 0x8994
#define SIOCBONDCHANGEACTIVE 0x8995
#define SIOCBRADDBR 0x89a0
#define SIOCBRDELBR 0x89a1
#define SIOCBRADDIF 0x89a2
#define SIOCBRDELIF 0x89a3
#define SIOCSHWTSTAMP 0x89b0
#define SIOCGHWTSTAMP 0x89b1
#define SIOCDEVPRIVATE 0x89F0
#define SIOCPROTOPRIVATE 0x89E0
#endif

"""

```