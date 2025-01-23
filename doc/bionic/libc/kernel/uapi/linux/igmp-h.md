Response:
Let's break down the thought process for answering this complex request about the `igmp.h` header file.

**1. Understanding the Core Request:**

The central task is to analyze a C header file (`igmp.h`) within the context of Android's Bionic library. The request has several sub-questions:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it relate to Android's features?
* **Libc Implementation:** How are the defined structures and macros used within Bionic's libc?  (This requires understanding that header files define interfaces, not implementations).
* **Dynamic Linker:**  Is the dynamic linker involved, and how? (This is less about direct code *in* the header and more about how the *usage* of the header might be linked).
* **Logic & Examples:**  Provide concrete examples of usage and potential pitfalls.
* **Android Integration Path:** How does the Android framework or NDK lead to this code?
* **Debugging:** How can we use Frida to inspect its use?

**2. Initial Analysis of the Header File:**

* **`auto-generated`:** This immediately suggests the file is generated from some other source, likely a standard Linux kernel header. This means its primary purpose is to provide definitions for interacting with the Linux kernel's IGMP implementation.
* **`#ifndef _UAPI_LINUX_IGMP_H`:** Standard header guard, preventing multiple inclusions.
* **`#include <linux/types.h>`:**  Uses standard Linux kernel types.
* **`#include <asm/byteorder.h>`:** Deals with endianness, a crucial aspect of network protocols.
* **`struct igmphdr`:** Defines the structure of a basic IGMP header. Fields like `type`, `code`, `csum`, and `group` are typical for network protocols.
* **`IGMPV3_...` constants:** Define constants related to IGMPv3 message types and modes.
* **`struct igmpv3_grec`:** Defines a structure related to group records in IGMPv3.
* **`struct igmpv3_report`:** Defines the structure of an IGMPv3 report message.
* **`struct igmpv3_query`:** Defines the structure of an IGMPv3 query message, including bitfield usage for `qrv`, `suppress`, and `resv`. The `#ifdef __LITTLE_ENDIAN_BITFIELD` section is a key indicator of platform-specific handling.
* **`IGMP_HOST_MEMBERSHIP_QUERY`, `IGMP_HOST_MEMBERSHIP_REPORT`, etc.:** Defines various IGMP message types as constants.
* **`IGMP_MINLEN`, `IGMP_MAX_HOST_REPORT_DELAY`, etc.:** Define constants related to IGMP behavior and timers.
* **`IGMP_ALL_HOSTS`, `IGMP_ALL_ROUTER`, etc.:** Define well-known multicast addresses used by IGMP.

**3. Addressing the Sub-Questions (Iterative Process):**

* **Functionality:** The header file defines the data structures and constants necessary to work with the Internet Group Management Protocol (IGMP). It's about managing multicast group memberships.

* **Android Relevance:**  Android devices need to participate in multicast networking for various features. Examples include:
    * **mDNS/Bonjour:**  Service discovery.
    * **Chromecast:**  Media streaming.
    * **Local network communication:** Apps might use multicast for peer discovery.
    * The Android framework itself needs to manage network interfaces and routing, which involves IGMP.

* **Libc Implementation:**  Crucially, the header file itself *doesn't* contain libc function implementations. It defines *interfaces*. The actual implementation of functions that *use* these structures (like `sendto`, `recvfrom`, or socket option functions) resides in the Bionic libc. The header file provides the necessary type definitions so that code in libc can interact with the kernel's network stack. This is a critical distinction. I need to explain this carefully.

* **Dynamic Linker:** The dynamic linker isn't directly involved in *processing* this header file. However, if code *using* these definitions is in a shared library (like a network library), the dynamic linker will be responsible for loading that library. The `igmp.h` file contributes to the *interface* that these libraries present. A simple SO layout example would show a network-related library and its dependencies. The linking process involves resolving symbols, but `igmp.h` defines types, not symbols in the linking sense.

* **Logic & Examples:**
    * **Assume:** An application wants to join a multicast group.
    * **Input:** The application provides the multicast group address.
    * **Output:** The system sends an IGMP membership report.
    * **User Errors:** Incorrectly setting socket options, providing invalid multicast addresses, not handling network errors.

* **Android Integration Path:** This requires tracing the flow from the application level down to the kernel:
    1. **NDK:**  An app might use NDK socket APIs.
    2. **System Calls:** These APIs translate to system calls (e.g., `socket`, `setsockopt`).
    3. **Kernel:** The kernel's network stack handles the system call and interacts with the IGMP implementation.
    4. **`igmp.h`:** The kernel's IGMP implementation uses the definitions in `igmp.h`.

* **Frida Hook:**  To demonstrate this, I need to show how to hook a function that interacts with IGMP, like `sendto` when sending an IGMP message, or `setsockopt` when setting multicast membership options. The hook should print relevant data structures.

**4. Structuring the Answer:**

Organize the information logically, addressing each sub-question clearly and providing code examples where appropriate. Emphasize the distinction between header files and implementation.

**5. Refinement and Review:**

Read through the generated answer to ensure clarity, accuracy, and completeness. Are the examples easy to understand? Is the explanation of the dynamic linker's role precise? Is the Frida example practical?  For instance, initially, I might have focused too much on the *content* of the header. I need to shift the focus to its *purpose* and how it's used in the larger Android ecosystem. The explanation of libc and the dynamic linker needs to be nuanced, as they don't directly *implement* the content of the header but are crucial for *using* it.

By following this structured thought process, breaking down the complex request into manageable parts, and iteratively refining the answer, a comprehensive and accurate response can be generated.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/igmp.h` 这个头文件。

**功能列举**

这个头文件定义了用于互联网组管理协议 (IGMP) 的数据结构和常量。IGMP 允许主机向本地路由器报告它们对特定多播组的成员关系。该文件主要用于在用户空间程序和 Linux 内核之间进行 IGMP 消息的交互。

具体来说，它定义了：

1. **IGMP 消息头结构体 `igmphdr`:**  描述了基本的 IGMP 消息头部，包含类型、代码、校验和以及组地址。
2. **IGMPv3 相关的结构体和常量:**
   - `IGMPV3_MODE_IS_INCLUDE`, `IGMPV3_MODE_IS_EXCLUDE` 等常量：定义了 IGMPv3 报告中的组成员模式。
   - `struct igmpv3_grec`: 定义了 IGMPv3 报告中的组记录结构，用于描述一个多播组及其源地址列表。
   - `struct igmpv3_report`: 定义了 IGMPv3 报告消息的结构，包含组记录数组。
   - `struct igmpv3_query`: 定义了 IGMPv3 查询消息的结构，包括查询器信息和源地址列表。
3. **IGMP 消息类型常量:**  例如 `IGMP_HOST_MEMBERSHIP_QUERY`（主机成员查询）、`IGMP_HOST_MEMBERSHIP_REPORT`（主机成员报告）、`IGMP_HOST_LEAVE_MESSAGE`（主机离开消息）等，用于标识不同的 IGMP 消息类型。
4. **IGMP 成员状态常量:**  例如 `IGMP_DELAYING_MEMBER`（延迟成员）、`IGMP_IDLE_MEMBER`（空闲成员）等，用于描述主机的多播组成员状态。
5. **IGMP 相关参数常量:**  例如 `IGMP_MINLEN`（最小长度）、`IGMP_MAX_HOST_REPORT_DELAY`（最大主机报告延迟）等。
6. **预定义的特殊多播组地址:**  例如 `IGMP_ALL_HOSTS`（所有主机组）、`IGMP_ALL_ROUTER`（所有路由器组）等。

**与 Android 功能的关系及举例**

IGMP 在 Android 系统中扮演着重要的角色，主要与以下功能相关：

* **多播支持:** Android 设备需要支持多播功能，以便接收和发送多播数据包。这对于局域网内的服务发现（例如 Bonjour/mDNS）、流媒体传输（例如 Chromecast）等应用至关重要。
* **网络连接管理:** Android 系统需要管理网络接口和路由，其中可能涉及到 IGMP 协议，以确保正确的多播路由。
* **应用程序使用:**  一些 Android 应用程序可能需要使用多播功能进行通信，例如某些网络游戏、群组聊天应用等。

**举例说明:**

假设一个 Android 设备想要加入一个多播组以接收来自特定流媒体服务器的数据。

1. **应用程序发起请求:**  应用程序通过 Socket API（可能是 NDK 中的 socket 函数）请求加入特定的多播组地址。
2. **系统调用:**  Android Framework 或 NDK 会将此请求转换为相应的系统调用，例如 `setsockopt`，并设置 `IP_ADD_MEMBERSHIP` 选项。
3. **内核处理:**  Linux 内核的网络协议栈接收到这个系统调用，会创建一个 IGMP 成员关系记录。
4. **发送 IGMP 报告:**  内核会构造一个 IGMP 成员报告消息（例如 `IGMPV2_HOST_MEMBERSHIP_REPORT` 或 `IGMPV3_HOST_MEMBERSHIP_REPORT`），其中包含了要加入的多播组地址。这个消息的结构会使用 `igmp.h` 中定义的 `igmphdr` 和 `igmpv3_report` 等结构体。
5. **网络发送:**  内核通过网络接口发送这个 IGMP 报告消息给本地路由器。路由器接收到报告后，会更新其多播路由表，确保发送到该多播组的数据包能够转发到该 Android 设备。

**libc 函数的功能实现**

`bionic/libc/kernel/uapi/linux/igmp.h`  本身 **不是 libc 函数的实现**，而是一个 **内核头文件**，它定义了内核中使用的数据结构。libc 中的函数，例如与网络相关的 socket 函数（`socket`、`sendto`、`recvfrom`、`setsockopt`、`getsockopt` 等），在涉及到 IGMP 协议时，会使用这个头文件中定义的结构体和常量。

例如，当你在 Android 上使用 `setsockopt` 函数设置 `IP_ADD_MEMBERSHIP` 选项时，libc 中的 `setsockopt` 实现会构建一个与内核通信的结构体，其中会用到 `igmp.h` 中定义的结构体来表示多播组信息。内核接收到这个信息后，就会使用 `igmp.h` 中定义的结构体来处理 IGMP 相关的逻辑。

**详细解释 libc 函数的功能是如何实现的 (以 `setsockopt` 为例):**

1. **用户空间调用 `setsockopt`:**  应用程序调用 `setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))`，其中 `mreq` 是一个 `ip_mreq` 结构体，用于指定要加入的多播组地址和网络接口。
2. **libc 中的 `setsockopt` 实现:**  Bionic libc 中的 `setsockopt` 函数会接收这些参数，并进行一些必要的检查。
3. **系统调用:**  libc 中的 `setsockopt` 函数最终会通过系统调用接口（通常使用 `syscall` 指令）调用内核的 `sys_setsockopt` 函数。
4. **内核中的 `sys_setsockopt` 处理:**
   - 内核会根据 `IPPROTO_IP` 和 `IP_ADD_MEMBERSHIP` 参数，判断这是一个添加多播组成员关系的请求。
   - 内核会从用户空间复制 `mreq` 结构体的数据。
   - 内核会分配内存来存储新的多播组成员关系信息。
   - **关键点:** 内核在处理这个请求时，可能会涉及到与 IGMP 协议相关的操作。例如，内核可能会检查当前是否已经是该多播组的成员，或者需要发送 IGMP 报告消息。
   - **`igmp.h` 的作用:**  内核在构造和解析 IGMP 消息时，会使用 `igmp.h` 中定义的 `igmphdr`、`igmpv3_report` 等结构体来组织和解释消息的内容。例如，当内核决定发送一个 IGMPv2 或 IGMPv3 报告时，会填充相应的结构体字段，然后将其转换为网络字节序并发送出去。

**涉及 dynamic linker 的功能**

这个头文件本身并不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号引用。

但是，如果一个共享库 (例如一个网络相关的库) 中使用了 `igmp.h` 中定义的结构体和常量，那么 dynamic linker 会负责加载这个共享库，并确保其能够正确地访问 Bionic libc 中提供的网络相关函数。

**so 布局样本:**

假设有一个名为 `libnetwork.so` 的共享库，它使用了 IGMP 相关的定义。

```
libnetwork.so:
  - .text (代码段)
    - 实现了一些网络通信的功能，可能涉及到创建 socket，设置多播组等。
    - 其中可能会使用到 `igmp.h` 中定义的结构体，例如在构造 IGMP 消息时。
  - .data (数据段)
  - .rodata (只读数据段)
  - .dynamic (动态链接信息)
    - DT_NEEDED 条目，指向依赖的共享库，例如 `libc.so`。
  - .dynsym (动态符号表)
    - 包含 `libnetwork.so` 导出的符号以及它引用的来自其他共享库的符号。
    - 例如，如果 `libnetwork.so` 中调用了 `socket` 或 `setsockopt` 函数，这里会记录这些符号。
```

**链接的处理过程:**

1. **加载 `libnetwork.so`:**  当应用程序启动或者在运行时需要使用 `libnetwork.so` 时，dynamic linker 会加载这个共享库到内存中。
2. **解析依赖:** Dynamic linker 会读取 `libnetwork.so` 的 `.dynamic` 段，找到其依赖的共享库（例如 `libc.so`）。
3. **加载依赖:** Dynamic linker 会加载 `libc.so` 到内存中。
4. **符号解析 (Symbol Resolution):** Dynamic linker 会遍历 `libnetwork.so` 的 `.dynsym` 段，对于每一个未定义的符号（例如 `socket`、`setsockopt`），它会在其依赖的共享库（`libc.so`）的符号表中查找对应的定义。
5. **重定位 (Relocation):**  一旦找到符号的定义，dynamic linker 会修改 `libnetwork.so` 中对这些符号的引用，将其指向 `libc.so` 中对应函数的实际地址。

在这个过程中，`igmp.h` 定义的结构体和常量本身不会被 dynamic linker 直接处理。但是，如果 `libnetwork.so` 中使用了这些定义，那么当 `libnetwork.so` 调用 libc 中的网络函数时，这些定义会确保 `libnetwork.so` 和 libc 能够正确地交互，传递和解释 IGMP 相关的数据。

**逻辑推理、假设输入与输出**

假设有一个程序想要发送一个 IGMPv3 主机成员报告消息，报告它加入了组地址 `224.1.2.3`，并且只接收来自源地址 `192.168.1.100` 的数据。

**假设输入:**

* 多播组地址: `224.1.2.3` (网络字节序: `0x030201E0`)
* 源地址列表: `[192.168.1.100]` (网络字节序: `0x6401A8C0`)
* 报告类型: `IGMPV3_HOST_MEMBERSHIP_REPORT` (`0x22`)
* 组成员模式: `IGMPV3_MODE_IS_INCLUDE` (`1`)

**逻辑推理:**

1. 程序需要创建一个 `struct igmpv3_report` 结构体。
2. 设置 `type` 字段为 `IGMPV3_HOST_MEMBERSHIP_REPORT`。
3. 设置 `ngrec` 字段为 1，表示有一个组记录。
4. 创建一个 `struct igmpv3_grec` 结构体，并将其添加到 `grec` 数组中。
5. 在 `igmpv3_grec` 结构体中：
   - 设置 `grec_type` 为 `IGMPV3_MODE_IS_INCLUDE`。
   - 设置 `grec_auxwords` 为 0。
   - 设置 `grec_nsrcs` 为 1。
   - 设置 `grec_mca` 为多播组地址 `0x030201E0`。
   - 设置 `grec_src[0]` 为源地址 `0x6401A8C0`。
6. 计算整个 IGMP 消息的校验和并填充 `csum` 字段。
7. 将整个 `struct igmpv3_report` 结构体通过 socket 发送出去。

**假设输出 (发送的 IGMP 消息的字节序列，部分字段):**

```
0x22  // type (IGMPV3_HOST_MEMBERSHIP_REPORT)
0x00  // resv1
0x???? // csum (校验和)
0x00 0x00 // resv2
0x00 0x01 // ngrec (1个组记录)
0x01  // grec_type (IGMPV3_MODE_IS_INCLUDE)
0x00  // grec_auxwords
0x00 0x01 // grec_nsrcs (1个源地址)
0xE0 0x01 0x02 0xE0 // grec_mca (224.1.2.3)
0xC0 0xA8 0x01 0x64 // grec_src[0] (192.168.1.100)
...
```

**用户或编程常见的使用错误**

1. **字节序错误:**  IP 地址和端口号等网络数据通常需要以网络字节序（大端序）进行传输。如果程序没有正确地进行字节序转换（例如使用 `htonl` 和 `htons` 函数），会导致通信失败。
   ```c
   struct sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_port = 1234; // 错误：应该使用 htons(1234)
   addr.sin_addr.s_addr = inet_addr("224.1.2.3"); // 错误：inet_addr 返回的是网络字节序
   ```

2. **校验和计算错误:**  IGMP 消息头包含校验和字段，用于验证消息的完整性。如果校验和计算错误，接收方会丢弃该消息。
   ```c
   struct igmphdr igmp;
   igmp.type = IGMPV2_HOST_MEMBERSHIP_REPORT;
   igmp.code = 0;
   igmp.group.s_addr = htonl(0xE0010203); // 224.1.2.3
   igmp.csum = 0; // 先将校验和置零
   // ... 填充其他字段 ...
   igmp.csum = calculate_checksum((unsigned short *)&igmp, sizeof(igmp)); // 正确的做法
   ```

3. **不正确的消息类型或代码:**  发送错误的 IGMP 消息类型或代码会导致接收方无法正确解析或处理该消息. 例如，发送 IGMPv2 报告到只支持 IGMPv3 的网络。

4. **忘记设置 socket 选项:**  在使用多播功能之前，通常需要设置一些 socket 选项，例如 `IP_ADD_MEMBERSHIP` 来加入多播组，或 `IP_MULTICAST_IF` 来指定发送多播消息的网络接口。
   ```c
   struct ip_mreq mreq;
   mreq.imr_multiaddr.s_addr = inet_addr("224.1.2.3");
   mreq.imr_interface.s_addr = INADDR_ANY; // 或指定特定的接口地址
   if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
       perror("setsockopt IP_ADD_MEMBERSHIP failed");
       // ... 错误处理 ...
   }
   ```

**Android Framework 或 NDK 如何到达这里，Frida hook 示例**

1. **NDK 使用:**  开发者可以通过 NDK 使用标准的 socket API 来进行网络编程，包括多播。例如，使用 `socket()`, `bind()`, `setsockopt()` 等函数。
2. **System Call:**  NDK 中的 socket 函数最终会通过系统调用 (system call) 与 Linux 内核进行交互。例如，`setsockopt()` 会触发 `sys_setsockopt()` 系统调用。
3. **内核网络协议栈:**  Linux 内核的网络协议栈接收到 `sys_setsockopt()` 系统调用后，会根据传入的参数进行处理。当设置 `IP_ADD_MEMBERSHIP` 选项时，内核会涉及到 IGMP 协议的处理，并使用 `bionic/libc/kernel/uapi/linux/igmp.h` 中定义的结构体来操作 IGMP 消息。
4. **Android Framework:**  Android Framework 也提供了 Java 层的 API 来进行网络编程，例如 `MulticastSocket` 类。这些 Java API 底层也是通过 JNI 调用到 Native 代码，最终也会涉及到 NDK 的 socket API 和系统调用。

**Frida Hook 示例:**

可以使用 Frida 来 hook `setsockopt` 系统调用，查看应用程序是如何设置多播组的。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "your.app.package.name"  # 替换为你的应用程序包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var level = args[1].toInt32();
            var optname = args[2].toInt32();
            var optval = args[3];
            var optlen = args[4].toInt32();

            console.log("setsockopt called:");
            console.log("  sockfd:", sockfd);
            console.log("  level:", level);
            console.log("  optname:", optname);

            if (level === 6 /* SOL_IP */ && optname === 12 /* IP_ADD_MEMBERSHIP */) {
                console.log("  -> IP_ADD_MEMBERSHIP detected");
                var ip_mreq = Memory.readByteArray(optval, optlen);
                console.log("  -> ip_mreq:", hexdump(ip_mreq, { ansi: true }));
            }
        },
        onLeave: function(retval) {
            console.log("setsockopt returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Hooking setsockopt. Press Ctrl+C to stop.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用说明:**

1. 将 `your.app.package.name` 替换为你要调试的 Android 应用程序的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试模式连接到电脑。
3. 运行 Frida 脚本。当目标应用程序调用 `setsockopt` 函数，并且设置的选项是 `IP_ADD_MEMBERSHIP` 时，Frida 会打印出相关的参数，包括 `ip_mreq` 结构体的内存内容，其中包含了要加入的多播组地址和网络接口信息。

通过这个 Frida 示例，你可以观察到 Android 应用程序是如何通过 `setsockopt` 系统调用来设置多播组成员关系的，从而间接地验证了 `bionic/libc/kernel/uapi/linux/igmp.h` 中定义的结构体在内核中的作用。

希望以上详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/linux/igmp.h` 的功能、与 Android 的关系以及在系统中的作用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/igmp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IGMP_H
#define _UAPI_LINUX_IGMP_H
#include <linux/types.h>
#include <asm/byteorder.h>
struct igmphdr {
  __u8 type;
  __u8 code;
  __sum16 csum;
  __be32 group;
};
#define IGMPV3_MODE_IS_INCLUDE 1
#define IGMPV3_MODE_IS_EXCLUDE 2
#define IGMPV3_CHANGE_TO_INCLUDE 3
#define IGMPV3_CHANGE_TO_EXCLUDE 4
#define IGMPV3_ALLOW_NEW_SOURCES 5
#define IGMPV3_BLOCK_OLD_SOURCES 6
struct igmpv3_grec {
  __u8 grec_type;
  __u8 grec_auxwords;
  __be16 grec_nsrcs;
  __be32 grec_mca;
  __be32 grec_src[];
};
struct igmpv3_report {
  __u8 type;
  __u8 resv1;
  __sum16 csum;
  __be16 resv2;
  __be16 ngrec;
  struct igmpv3_grec grec[];
};
struct igmpv3_query {
  __u8 type;
  __u8 code;
  __sum16 csum;
  __be32 group;
#ifdef __LITTLE_ENDIAN_BITFIELD
  __u8 qrv : 3, suppress : 1, resv : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8 resv : 4, suppress : 1, qrv : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
  __u8 qqic;
  __be16 nsrcs;
  __be32 srcs[];
};
#define IGMP_HOST_MEMBERSHIP_QUERY 0x11
#define IGMP_HOST_MEMBERSHIP_REPORT 0x12
#define IGMP_DVMRP 0x13
#define IGMP_PIM 0x14
#define IGMP_TRACE 0x15
#define IGMPV2_HOST_MEMBERSHIP_REPORT 0x16
#define IGMP_HOST_LEAVE_MESSAGE 0x17
#define IGMPV3_HOST_MEMBERSHIP_REPORT 0x22
#define IGMP_MTRACE_RESP 0x1e
#define IGMP_MTRACE 0x1f
#define IGMP_MRDISC_ADV 0x30
#define IGMP_DELAYING_MEMBER 0x01
#define IGMP_IDLE_MEMBER 0x02
#define IGMP_LAZY_MEMBER 0x03
#define IGMP_SLEEPING_MEMBER 0x04
#define IGMP_AWAKENING_MEMBER 0x05
#define IGMP_MINLEN 8
#define IGMP_MAX_HOST_REPORT_DELAY 10
#define IGMP_TIMER_SCALE 10
#define IGMP_AGE_THRESHOLD 400
#define IGMP_ALL_HOSTS htonl(0xE0000001L)
#define IGMP_ALL_ROUTER htonl(0xE0000002L)
#define IGMPV3_ALL_MCR htonl(0xE0000016L)
#define IGMP_LOCAL_GROUP htonl(0xE0000000L)
#define IGMP_LOCAL_GROUP_MASK htonl(0xFFFFFF00L)
#endif
```