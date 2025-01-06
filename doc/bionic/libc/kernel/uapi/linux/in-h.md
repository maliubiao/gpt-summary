Response:
Let's break down the thought process for answering the request about the `in.h` header file.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`in.h`) and explain its purpose, functionalities, relationship to Android, implementation details (where applicable), dynamic linker aspects, common errors, and how Android frameworks access it. The response needs to be in Chinese.

**2. Initial Examination of the File:**

The first thing to notice is the comment: "This file is auto-generated. Modifications will be lost." This immediately suggests that this file is derived from a more canonical source, likely within the Linux kernel. This is a crucial piece of information for understanding its role. It's a *user-space* view of kernel structures and definitions related to IP networking.

**3. Identifying Key Sections:**

Scanning the content reveals distinct sections:

* **Includes:** `<bits/ip_msfilter.h>`, `<bits/ip_mreq_source.h>`, `<bits/in_addr.h>`, `<linux/types.h>`, etc. These indicate dependencies on other header files. The `<linux/...>` inclusions signal a strong connection to the Linux kernel.
* **`enum` for `IPPROTO_*`:**  This section defines constants representing various IP protocols (TCP, UDP, ICMP, etc.).
* **`#define` for `IP_*`:**  These are constants related to IP socket options (TOS, TTL, multicast settings, etc.).
* **`struct` definitions:** `ip_mreq`, `ip_mreqn`, `group_req`, `group_source_req`, `group_filter`, `in_pktinfo`, `sockaddr_in`. These define data structures used for IP networking.
* **Macros for IP address classes:** `IN_CLASSA`, `IN_CLASSB`, etc., and constants like `INADDR_ANY`, `INADDR_BROADCAST`.

**4. Determining the File's Functionality:**

Based on the identified sections, the core function is clear: **This file provides definitions and constants necessary for user-space programs to interact with the IP networking layer of the Linux kernel.** It defines:

* IP protocol numbers.
* IP socket options.
* Data structures for managing IP addresses, multicast groups, and packet information.
* Macros for working with IP address classes.

**5. Relating to Android:**

Since Android's kernel is based on Linux, these definitions are directly relevant to Android's networking stack. Android apps and system services use these constants and structures when creating and configuring network sockets using system calls. Examples include:

* **Creating sockets:**  Specifying `AF_INET` and `SOCK_STREAM` (for TCP) or `SOCK_DGRAM` (for UDP) in the `socket()` system call.
* **Setting socket options:** Using `setsockopt()` with `IP_TOS`, `IP_TTL`, `IP_ADD_MEMBERSHIP`, etc.
* **Working with IP addresses:**  Using `struct sockaddr_in` to represent IPv4 addresses.

**6. Explaining libc Function Implementations:**

This is a tricky part of the request. The `in.h` file itself *doesn't contain libc function implementations*. It contains *definitions* used by libc functions. The actual implementation of functions like `socket()`, `setsockopt()`, `bind()`, etc., resides within the C library (`libc.so`) and makes system calls to the kernel. The `in.h` file acts as an interface between user-space code and the kernel's network API. Therefore, the explanation needs to focus on *how* libc functions use these definitions, not on the implementation of the definitions themselves.

**7. Dynamic Linker Aspects:**

`in.h` doesn't directly involve the dynamic linker. It's a header file providing compile-time constants and structure definitions. However, it's used by code *in* `libc.so`, which *is* a dynamically linked library. The explanation should highlight this indirect relationship. A sample SO layout for `libc.so` would show its sections (.text, .data, .bss, .dynsym, .dynstr, etc.) but wouldn't specifically point to `in.h`'s content. The linking process involves resolving symbols used by `libc.so` and other libraries.

**8. Logical Reasoning, Assumptions, and Output:**

Since this is a header file with definitions, direct logical reasoning about input and output is not the primary focus. However, one can think about *how the definitions are used*. For example, if a program sets the `IP_TTL` option to a value, the assumption is that the underlying network stack will respect this value when sending IP packets.

**9. Common Usage Errors:**

Examples of common errors include:

* Using incorrect IP protocol numbers.
* Incorrectly setting socket options, leading to unexpected network behavior.
* Misinterpreting the meaning of IP address classes.
* Not handling network errors properly.

**10. Android Framework and NDK Access:**

The explanation should trace the path from high-level Android frameworks (Java/Kotlin code using `java.net` package), through the Android runtime (ART), down to native code using NDK APIs, which eventually make system calls that rely on the definitions in `in.h`.

**11. Frida Hook Examples:**

Frida can be used to intercept system calls related to networking. Examples would include hooking `socket()`, `setsockopt()`, `bind()`, etc., to observe the values being passed, including constants defined in `in.h`.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "I need to explain how each `#define` works."  **Correction:** Realized that `#define` are simple text substitutions at compile time. The focus should be on their *meaning* and how they're *used*.
* **Initial thought:** "I need to describe the implementation of functions related to IP." **Correction:** Recognized that `in.h` doesn't *implement* functions. It provides *definitions* for use by functions in `libc.so` and the kernel.
* **Consideration:** Should I explain the history of each IP protocol? **Decision:**  While interesting, it's not directly relevant to the core request. Focus on the practical use within the Android context.
* **Refinement of Frida example:**  Instead of just saying "hook networking functions," provide concrete examples of which functions to hook and what information could be observed.

By following this thought process, addressing each part of the request systematically, and making necessary corrections along the way, we can construct a comprehensive and accurate answer in Chinese.
这是一个定义了与IP网络协议相关的常量、枚举和数据结构的C头文件。它属于Linux内核的UAPI（User API）部分，这意味着它定义了用户空间程序可以使用的接口。由于Android的底层是Linux内核，因此这个文件对于Android的网络功能至关重要。

**功能列举:**

1. **定义IP协议类型 (IP Protocol Types):**
   -  `IPPROTO_IP`, `IPPROTO_ICMP`, `IPPROTO_TCP`, `IPPROTO_UDP` 等等。
   -  这些宏定义了不同的网络层协议，用于在创建socket时指定使用哪种协议。

2. **定义IP socket选项 (IP Socket Options):**
   -  `IP_TOS`, `IP_TTL`, `IP_MULTICAST_IF`, `IP_ADD_MEMBERSHIP` 等等。
   -  这些宏定义了可以传递给 `setsockopt()` 系统调用的选项，用于配置IP协议的行为，例如设置服务类型 (TOS)、生存时间 (TTL)、以及加入多播组。

3. **定义IP组播相关的结构体 (IP Multicast Related Structures):**
   -  `struct ip_mreq`:  用于加入或离开多播组，包含多播组地址和本地接口地址。
   -  `struct ip_mreqn`:  类似 `ip_mreq`，但允许指定接口索引。
   -  `struct group_req`, `struct group_source_req`, `struct group_filter`: 用于更精细地控制多播组成员关系和源地址过滤。

4. **定义IP数据包信息结构体 (IP Packet Information Structure):**
   -  `struct in_pktinfo`:  用于接收有关接收到的IP数据包的额外信息，例如接收接口的索引和目标地址。

5. **定义IPv4地址结构体 (IPv4 Address Structure):**
   -  `struct sockaddr_in`:  定义了通用的IPv4 socket地址结构，包含地址族、端口号和IP地址。

6. **定义IP地址分类相关的宏 (IP Address Class Related Macros):**
   -  `IN_CLASSA`, `IN_CLASSB`, `IN_CLASSC`, `IN_CLASSD`:  用于判断IP地址属于哪个类别（A类、B类、C类、D类）。
   -  `INADDR_ANY`, `INADDR_BROADCAST`, `INADDR_LOOPBACK`:  常用的特殊IP地址常量。

**与Android功能的关联和举例说明:**

这个头文件直接影响Android设备上的网络通信。Android应用程序和系统服务在进行网络编程时，会间接地使用到这些定义。

* **网络连接:** 当一个Android应用需要建立TCP或UDP连接时，它会使用socket API。在创建socket时，需要指定协议族 (AF_INET) 和协议类型 (SOCK_STREAM 或 SOCK_DGRAM)，而协议类型最终会对应到这里定义的 `IPPROTO_TCP` 或 `IPPROTO_UDP`。

   ```c++
   // NDK 代码示例
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <stdio.h>

   int main() {
       int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 使用 IPPROTO_TCP
       if (sock == -1) {
           perror("socket creation failed");
           return 1;
       }
       // ... 进一步操作
       return 0;
   }
   ```

* **设置Socket选项:**  Android应用可以使用 `java.net.Socket` 或 NDK 中的 socket API 来设置socket选项。例如，设置数据包的生存时间 (TTL)。这会映射到 `setsockopt()` 系统调用，并使用 `IP_TTL` 这个宏。

   ```java
   // Java 代码示例
   import java.net.Socket;

   public class SocketOptions {
       public static void main(String[] args) throws Exception {
           Socket socket = new Socket("www.example.com", 80);
           socket.setOption(java.net.SocketOptions.IP_TOS, 0x10); // 间接使用 IP_TOS 相关的值
           socket.close();
       }
   }
   ```

* **组播:** Android设备可以加入和接收多播数据。这会使用到 `IP_ADD_MEMBERSHIP` 选项和 `ip_mreq` 结构体。例如，一个视频流应用可能会加入一个特定的多播组来接收视频数据。

**libc函数的功能实现:**

这个头文件本身并不包含libc函数的实现。它只是定义了常量和数据结构。libc中的网络相关函数（如 `socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()`, `setsockopt()`, `getsockopt()` 等）的实现位于 `libc.so` 中。这些函数会使用这个头文件中定义的常量和结构体来与Linux内核的网络协议栈进行交互。

例如，`setsockopt()` 函数的实现会根据传入的 `level` 和 `optname` 参数来识别要设置的选项。如果 `level` 是 `IPPROTO_IP`，`optname` 是 `IP_TTL`，那么 `setsockopt()` 内部的代码会调用相应的内核函数来设置IP数据包的生存时间。

**dynamic linker的功能:**

这个头文件本身不涉及动态链接器的功能。然而，它被 `libc.so` 使用，而 `libc.so` 是一个动态链接库。

**so布局样本 (libc.so):**

```
libc.so:
    .interp        0x...     // 指向动态链接器
    .note.android.ident 0x...
    .dynsym        0x...     // 动态符号表
    .dynstr        0x...     // 动态字符串表
    .hash          0x...     // 符号哈希表
    .gnu.version   0x...
    .gnu.version_r 0x...
    .rel.dyn       0x...     // 重定位表 (数据段)
    .rel.plt       0x...     // 重定位表 (PLT)
    .plt           0x...     // 过程链接表
    .text          0x...     // 代码段 (包含 socket(), setsockopt() 等函数的实现)
    .rodata        0x...     // 只读数据段 (可能包含一些与网络相关的常量)
    .data          0x...     // 已初始化数据段
    .bss           0x...     // 未初始化数据段
    .dynamic       0x...     // 动态链接信息
    ...
```

**链接的处理过程:**

当一个应用程序（例如，通过NDK编写的本地代码）调用 `socket()` 函数时，链接过程如下：

1. **编译时:** 编译器遇到 `socket()` 函数调用，它会生成一个对 `socket` 符号的未定义引用。
2. **链接时:** 链接器（通常是 `lld`）在链接应用程序时，会查找 `socket` 符号的定义。由于 `socket()` 函数位于 `libc.so` 中，链接器需要在 `libc.so` 中找到该符号的定义。
3. **动态链接:** 当应用程序启动时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载所有依赖的共享库，包括 `libc.so`。
4. **符号解析:** 动态链接器会解析应用程序中未定义的符号，找到它们在已加载的共享库中的地址。对于 `socket()` 函数，动态链接器会找到 `libc.so` 中 `socket()` 函数的地址，并将应用程序中的调用跳转到该地址。

**逻辑推理、假设输入与输出:**

这个头文件主要是定义，直接进行逻辑推理的场景较少。但可以考虑以下情况：

**假设输入:** 一个应用程序想要发送一个TTL值为 64 的IP数据包。

**逻辑推理:**

1. 应用程序调用 `setsockopt()` 函数。
2. `level` 参数设置为 `IPPROTO_IP`。
3. `optname` 参数设置为 `IP_TTL`。
4. `optval` 参数设置为 64。
5. `setsockopt()` 的实现会使用 `IP_TTL` 的宏定义值来识别要设置的选项。
6. 系统调用最终会传递到内核的网络协议栈。
7. 当发送IP数据包时，内核会设置IP头部的 TTL 字段为 64。

**输出:** 发送出去的IP数据包的TTL值为 64。

**用户或编程常见的使用错误:**

1. **使用错误的协议号:** 例如，在创建UDP socket时错误地使用了 `IPPROTO_TCP`。
   ```c++
   int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP); // 错误！应该使用 IPPROTO_UDP
   ```

2. **设置了无效的socket选项值:**  某些socket选项有特定的取值范围。设置超出范围的值可能会导致错误或未定义的行为。

3. **在错误的socket状态下设置选项:**  某些socket选项只能在socket未连接或已连接的情况下设置。

4. **字节序问题:** 在设置包含多字节值的socket选项时，需要注意主机字节序和网络字节序的转换，例如在使用 `struct sockaddr_in` 时需要使用 `htons()` 和 `htonl()` 函数。

**Android framework or ndk如何一步步的到达这里，给出frida hook示例调试这些步骤。**

**Android Framework 到 `in.h` 的路径:**

1. **Java 代码 (Android Framework):**  例如，使用 `java.net.Socket` 或 `java.net.DatagramSocket` 进行网络编程。
2. **Android Runtime (ART):** Java 网络相关的类的方法最终会调用到 native 方法。
3. **NDK (Native Development Kit):**  Android framework 的某些底层网络功能可能使用 NDK 实现。开发者也可以直接使用 NDK 进行网络编程。
4. **Bionic libc:** NDK 代码会链接到 Bionic libc (`/apex/com.android.runtime/lib[64]/bionic/libc.so`)。
5. **System Calls:** Bionic libc 中的网络函数（如 `socket()`, `setsockopt()`）会通过系统调用 (syscall) 进入 Linux 内核。
6. **Kernel:** Linux 内核的网络协议栈会处理这些系统调用，并使用到定义在 `bionic/libc/kernel/uapi/linux/in.h` 中的常量和结构体。

**Frida Hook 示例:**

可以使用 Frida Hook `setsockopt` 系统调用，观察其参数，从而了解 Android Framework 如何使用到 `in.h` 中定义的常量。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

package_name = "your.app.package.name" # 替换成你的应用包名

try:
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.ServerNotRunningError:
    print("Frida server is not running. Please ensure frida-server is running on the device.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();
        var optval = args[3];
        var optlen = args[4].toInt32();

        var level_str = "";
        var optname_str = "";

        if (level === 6) { // SOL_IP
            level_str = "SOL_IP";
            if (optname === 1) optname_str = "IP_TOS";
            else if (optname === 2) optname_str = "IP_TTL";
            else if (optname === 32) optname_str = "IP_MULTICAST_IF";
            else if (optname === 35) optname_str = "IP_ADD_MEMBERSHIP";
            // ... 添加更多 IP_ 开头的选项
        } else if (level === 17) { // SOL_SOCKET
            level_str = "SOL_SOCKET";
            // ... 添加更多 SOL_SOCKET 开头的选项
        }

        var optval_str = "";
        if (optlen === 4) {
            optval_str = ptr(optval).readU32();
        } else if (optlen === 8) {
            optval_str = ptr(optval).readU64();
        } else {
            optval_str = "size: " + optlen;
        }

        send({
            type: "send",
            payload: "setsockopt(sockfd=" + sockfd + ", level=" + level_str + "(" + level + "), optname=" + optname_str + "(" + optname + "), optval=" + optval_str + ", optlen=" + optlen + ")"
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

try:
    sys.stdin.read()
except KeyboardInterrupt:
    session.detach()
    sys.exit()
```

**工作原理:**

1. **`frida.get_usb_device()` 和 `device.spawn()`/`device.attach()`:** 连接到 USB 设备并启动或附加到目标 Android 应用进程。
2. **`Interceptor.attach()`:**  Hook `libc.so` 中的 `setsockopt` 函数。
3. **`onEnter`:**  在 `setsockopt` 函数被调用前执行。
4. **参数解析:**  获取 `setsockopt` 的参数，包括 socket 文件描述符、level、optname、optval 和 optlen。
5. **常量转换:**  根据 `level` 和 `optname` 的值，尝试将其转换为对应的宏定义字符串（例如，将 `6` 转换为 `SOL_IP`，将 `1` 转换为 `IP_TOS`）。这里需要根据 `in.h` 中的定义进行映射。
6. **打印信息:**  将 Hook 到的信息通过 `send()` 发送回 Frida 客户端。
7. **Frida 客户端:**  接收并打印 Hook 到的 `setsockopt` 调用信息，包括使用的 socket 选项及其值。

通过运行这个 Frida 脚本，并在 Android 应用中进行网络操作，你可以观察到 `setsockopt` 函数被调用的情况，以及它使用的 `level` 和 `optname` 参数，从而验证 Android Framework 或 NDK 如何使用到 `bionic/libc/kernel/uapi/linux/in.h` 中定义的常量。你需要根据 `in.h` 中定义的宏来完善 `script_code` 中的映射关系，以便更准确地显示选项的名称。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/in.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IN_H
#define _UAPI_LINUX_IN_H
#include <bits/ip_msfilter.h>
#include <bits/ip_mreq_source.h>
#include <bits/in_addr.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/libc-compat.h>
#include <linux/socket.h>
#if __UAPI_DEF_IN_IPPROTO
enum {
  IPPROTO_IP = 0,
#define IPPROTO_IP IPPROTO_IP
  IPPROTO_ICMP = 1,
#define IPPROTO_ICMP IPPROTO_ICMP
  IPPROTO_IGMP = 2,
#define IPPROTO_IGMP IPPROTO_IGMP
  IPPROTO_IPIP = 4,
#define IPPROTO_IPIP IPPROTO_IPIP
  IPPROTO_TCP = 6,
#define IPPROTO_TCP IPPROTO_TCP
  IPPROTO_EGP = 8,
#define IPPROTO_EGP IPPROTO_EGP
  IPPROTO_PUP = 12,
#define IPPROTO_PUP IPPROTO_PUP
  IPPROTO_UDP = 17,
#define IPPROTO_UDP IPPROTO_UDP
  IPPROTO_IDP = 22,
#define IPPROTO_IDP IPPROTO_IDP
  IPPROTO_TP = 29,
#define IPPROTO_TP IPPROTO_TP
  IPPROTO_DCCP = 33,
#define IPPROTO_DCCP IPPROTO_DCCP
  IPPROTO_IPV6 = 41,
#define IPPROTO_IPV6 IPPROTO_IPV6
  IPPROTO_RSVP = 46,
#define IPPROTO_RSVP IPPROTO_RSVP
  IPPROTO_GRE = 47,
#define IPPROTO_GRE IPPROTO_GRE
  IPPROTO_ESP = 50,
#define IPPROTO_ESP IPPROTO_ESP
  IPPROTO_AH = 51,
#define IPPROTO_AH IPPROTO_AH
  IPPROTO_MTP = 92,
#define IPPROTO_MTP IPPROTO_MTP
  IPPROTO_BEETPH = 94,
#define IPPROTO_BEETPH IPPROTO_BEETPH
  IPPROTO_ENCAP = 98,
#define IPPROTO_ENCAP IPPROTO_ENCAP
  IPPROTO_PIM = 103,
#define IPPROTO_PIM IPPROTO_PIM
  IPPROTO_COMP = 108,
#define IPPROTO_COMP IPPROTO_COMP
  IPPROTO_L2TP = 115,
#define IPPROTO_L2TP IPPROTO_L2TP
  IPPROTO_SCTP = 132,
#define IPPROTO_SCTP IPPROTO_SCTP
  IPPROTO_UDPLITE = 136,
#define IPPROTO_UDPLITE IPPROTO_UDPLITE
  IPPROTO_MPLS = 137,
#define IPPROTO_MPLS IPPROTO_MPLS
  IPPROTO_ETHERNET = 143,
#define IPPROTO_ETHERNET IPPROTO_ETHERNET
  IPPROTO_RAW = 255,
#define IPPROTO_RAW IPPROTO_RAW
  IPPROTO_SMC = 256,
#define IPPROTO_SMC IPPROTO_SMC
  IPPROTO_MPTCP = 262,
#define IPPROTO_MPTCP IPPROTO_MPTCP
  IPPROTO_MAX
};
#endif
#if __UAPI_DEF_IN_ADDR
#endif
#define IP_TOS 1
#define IP_TTL 2
#define IP_HDRINCL 3
#define IP_OPTIONS 4
#define IP_ROUTER_ALERT 5
#define IP_RECVOPTS 6
#define IP_RETOPTS 7
#define IP_PKTINFO 8
#define IP_PKTOPTIONS 9
#define IP_MTU_DISCOVER 10
#define IP_RECVERR 11
#define IP_RECVTTL 12
#define IP_RECVTOS 13
#define IP_MTU 14
#define IP_FREEBIND 15
#define IP_IPSEC_POLICY 16
#define IP_XFRM_POLICY 17
#define IP_PASSSEC 18
#define IP_TRANSPARENT 19
#define IP_RECVRETOPTS IP_RETOPTS
#define IP_ORIGDSTADDR 20
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#define IP_MINTTL 21
#define IP_NODEFRAG 22
#define IP_CHECKSUM 23
#define IP_BIND_ADDRESS_NO_PORT 24
#define IP_RECVFRAGSIZE 25
#define IP_RECVERR_RFC4884 26
#define IP_PMTUDISC_DONT 0
#define IP_PMTUDISC_WANT 1
#define IP_PMTUDISC_DO 2
#define IP_PMTUDISC_PROBE 3
#define IP_PMTUDISC_INTERFACE 4
#define IP_PMTUDISC_OMIT 5
#define IP_MULTICAST_IF 32
#define IP_MULTICAST_TTL 33
#define IP_MULTICAST_LOOP 34
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IP_UNBLOCK_SOURCE 37
#define IP_BLOCK_SOURCE 38
#define IP_ADD_SOURCE_MEMBERSHIP 39
#define IP_DROP_SOURCE_MEMBERSHIP 40
#define IP_MSFILTER 41
#define MCAST_JOIN_GROUP 42
#define MCAST_BLOCK_SOURCE 43
#define MCAST_UNBLOCK_SOURCE 44
#define MCAST_LEAVE_GROUP 45
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47
#define MCAST_MSFILTER 48
#define IP_MULTICAST_ALL 49
#define IP_UNICAST_IF 50
#define IP_LOCAL_PORT_RANGE 51
#define IP_PROTOCOL 52
#define MCAST_EXCLUDE 0
#define MCAST_INCLUDE 1
#define IP_DEFAULT_MULTICAST_TTL 1
#define IP_DEFAULT_MULTICAST_LOOP 1
#if __UAPI_DEF_IP_MREQ
struct ip_mreq {
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
};
struct ip_mreqn {
  struct in_addr imr_multiaddr;
  struct in_addr imr_address;
  int imr_ifindex;
};
#define IP_MSFILTER_SIZE(numsrc) (sizeof(struct ip_msfilter) - sizeof(__u32) + (numsrc) * sizeof(__u32))
struct group_req {
  __u32 gr_interface;
  struct sockaddr_storage gr_group;
};
struct group_source_req {
  __u32 gsr_interface;
  struct sockaddr_storage gsr_group;
  struct sockaddr_storage gsr_source;
};
struct group_filter {
  union {
    struct {
      __u32 gf_interface_aux;
      struct sockaddr_storage gf_group_aux;
      __u32 gf_fmode_aux;
      __u32 gf_numsrc_aux;
      struct sockaddr_storage gf_slist[1];
    };
    struct {
      __u32 gf_interface;
      struct sockaddr_storage gf_group;
      __u32 gf_fmode;
      __u32 gf_numsrc;
      struct sockaddr_storage gf_slist_flex[];
    };
  };
};
#define GROUP_FILTER_SIZE(numsrc) (sizeof(struct group_filter) - sizeof(struct sockaddr_storage) + (numsrc) * sizeof(struct sockaddr_storage))
#endif
#if __UAPI_DEF_IN_PKTINFO
struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
#endif
#if __UAPI_DEF_SOCKADDR_IN
#define __SOCK_SIZE__ 16
struct sockaddr_in {
  __kernel_sa_family_t sin_family;
  __be16 sin_port;
  struct in_addr sin_addr;
  unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#define sin_zero __pad
#endif
#if __UAPI_DEF_IN_CLASS
#define IN_CLASSA(a) ((((long int) (a)) & 0x80000000) == 0)
#define IN_CLASSA_NET 0xff000000
#define IN_CLASSA_NSHIFT 24
#define IN_CLASSA_HOST (0xffffffff & ~IN_CLASSA_NET)
#define IN_CLASSA_MAX 128
#define IN_CLASSB(a) ((((long int) (a)) & 0xc0000000) == 0x80000000)
#define IN_CLASSB_NET 0xffff0000
#define IN_CLASSB_NSHIFT 16
#define IN_CLASSB_HOST (0xffffffff & ~IN_CLASSB_NET)
#define IN_CLASSB_MAX 65536
#define IN_CLASSC(a) ((((long int) (a)) & 0xe0000000) == 0xc0000000)
#define IN_CLASSC_NET 0xffffff00
#define IN_CLASSC_NSHIFT 8
#define IN_CLASSC_HOST (0xffffffff & ~IN_CLASSC_NET)
#define IN_CLASSD(a) ((((long int) (a)) & 0xf0000000) == 0xe0000000)
#define IN_MULTICAST(a) IN_CLASSD(a)
#define IN_MULTICAST_NET 0xe0000000
#define IN_BADCLASS(a) (((long int) (a)) == (long int) 0xffffffff)
#define IN_EXPERIMENTAL(a) IN_BADCLASS((a))
#define IN_CLASSE(a) ((((long int) (a)) & 0xf0000000) == 0xf0000000)
#define IN_CLASSE_NET 0xffffffff
#define IN_CLASSE_NSHIFT 0
#define INADDR_ANY ((unsigned long int) 0x00000000)
#define INADDR_BROADCAST ((unsigned long int) 0xffffffff)
#define INADDR_NONE ((unsigned long int) 0xffffffff)
#define INADDR_DUMMY ((unsigned long int) 0xc0000008)
#define IN_LOOPBACKNET 127
#define INADDR_LOOPBACK 0x7f000001
#define IN_LOOPBACK(a) ((((long int) (a)) & 0xff000000) == 0x7f000000)
#define INADDR_UNSPEC_GROUP 0xe0000000U
#define INADDR_ALLHOSTS_GROUP 0xe0000001U
#define INADDR_ALLRTRS_GROUP 0xe0000002U
#define INADDR_ALLSNOOPERS_GROUP 0xe000006aU
#define INADDR_MAX_LOCAL_GROUP 0xe00000ffU
#endif
#include <asm/byteorder.h>
#endif

"""

```