Response:
Let's break down the thought process for answering the request about `bionic/libc/kernel/uapi/linux/in6.h`.

**1. Understanding the Core Request:**

The fundamental goal is to understand the *purpose* and *functionality* of this specific header file within the Android ecosystem. The prompt explicitly asks for its function, relationship to Android, details on libc functions (though this file primarily *defines*, not *implements*), dynamic linker aspects, potential errors, and how it's reached from higher levels.

**2. Initial Analysis of the Header File:**

* **Filename and Path:** `bionic/libc/kernel/uapi/linux/in6.h`. This immediately suggests:
    * `bionic`: Part of Android's core C library.
    * `libc`:  Related to standard C library functions.
    * `kernel`:  Interfaces with the Linux kernel.
    * `uapi`:  User-space API definitions, intended for use by applications.
    * `linux`:  Specific to the Linux kernel.
    * `in6.h`: Likely related to IPv6 networking.

* **`#ifndef _UAPI_LINUX_IN6_H`:** Standard include guard to prevent multiple inclusions.

* **Includes:** `<linux/types.h>` and `<linux/libc-compat.h>`. This confirms it's defining types and ensuring compatibility with the kernel's conventions.

* **Structure Definitions:** The bulk of the file defines structures: `in6_addr`, `sockaddr_in6`, `ipv6_mreq`, and `in6_flowlabel_req`. These clearly relate to IPv6 addressing, socket addresses, multicast group management, and flow labels.

* **Macros and Constants:**  A large section defines macros and constants starting with `IPV6_`. These are flags, options, protocols, and other numerical values used when working with IPv6.

**3. Addressing the Specific Questions:**

* **功能 (Functionality):** The primary function is to define the *data structures* and *constants* necessary for applications to interact with the Linux kernel's IPv6 networking stack. It doesn't implement logic, but provides the blueprint.

* **与 Android 的关系 (Relationship with Android):**  Because this is part of Bionic, it's crucial for any Android application or system service that uses IPv6 networking. Examples include network communication apps, VPNs, and system daemons handling network connections.

* **libc 函数的实现 (Implementation of libc Functions):** This is a key point of clarification. This header file *defines*, it doesn't *implement*. The actual libc functions that *use* these definitions (like `socket()`, `bind()`, `connect()`, etc.) are implemented in other parts of Bionic. The explanation needs to focus on how these functions use the defined structures.

* **dynamic linker 功能 (Dynamic Linker Functionality):** This header doesn't directly involve the dynamic linker. However, the *libc* itself, which uses this header, *is* dynamically linked. The explanation should focus on how applications link against libc and how the linker resolves symbols related to networking functions that ultimately rely on these definitions. Providing a sample SO layout and linking process is important here.

* **逻辑推理 (Logical Deduction):**  Since the file is primarily definitions, logical deduction comes into play when explaining how the different structures and constants are *used together*. For example, explaining how `sockaddr_in6` uses `in6_addr` and `sin6_port`. The "假设输入与输出" (assumed input and output) is more conceptual here –  an application setting up an IPv6 socket would use these structures as input to system calls.

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Focus on misinterpreting or incorrectly using the defined constants and structures. Examples include wrong address formats, incorrect port numbers, or misunderstanding scope IDs.

* **Android framework or ndk 如何到达这里 (How Android Framework/NDK Reaches Here):** This requires tracing the path from high-level Android components down to the kernel. The explanation should start with an NDK application, then show how it uses standard socket functions, which are part of libc, which in turn includes this header. The Frida hook example should target a function call that uses these structures, like `connect()`.

**4. Structuring the Answer:**

A clear and structured answer is crucial. Using headings and bullet points helps organize the information and makes it easier to read. The flow should follow the order of the questions in the prompt.

**5. Refining and Detailing:**

* **Be Precise:** Use accurate terminology (e.g., "header file," "data structure," "system call").
* **Provide Concrete Examples:**  Illustrate concepts with examples, especially for usage errors and the Android framework/NDK path.
* **Explain Concepts Clearly:** Don't assume the reader has deep knowledge of networking or the Android internals.
* **Address All Parts of the Prompt:** Ensure each question is answered comprehensively.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on specific libc *implementations* within this header file.
* **Correction:** Realizing the header *defines* the structures and constants, and the implementations are elsewhere in Bionic. Shift the focus to how other libc functions *use* these definitions.
* **Initial thought:** Directly linking the dynamic linker to this header.
* **Correction:** Recognizing that the linkage is indirect, through the libc itself. Explain how applications link against libc and how the linker resolves symbols.
* **Initial thought:**  Providing very low-level kernel details.
* **Correction:** Keeping the explanation focused on the user-space perspective and the interaction between applications, libc, and the kernel through system calls.

By following this thought process, analyzing the code, and addressing each part of the prompt systematically, a comprehensive and accurate answer can be constructed.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/in6.h` 这个头文件。

**功能列举:**

这个头文件定义了用于 IPv6 网络编程的用户空间 API（UAPI），它主要包含以下功能：

1. **定义了表示 IPv6 地址的结构体 `in6_addr`:**  这个结构体用于存储 128 位的 IPv6 地址。它提供了联合体（union）的方式来访问地址的不同部分，可以按字节（`u6_addr8`）、16 位字（`u6_addr16`，可选）或 32 位字（`u6_addr32`，可选）来访问。
2. **定义了表示 IPv6 Socket 地址的结构体 `sockaddr_in6`:** 这个结构体用于在网络编程中指定 IPv6 的地址和端口。它包含了地址族（`sin6_family`，始终是 `AF_INET6`），端口号（`sin6_port`），流信息（`sin6_flowinfo`），IPv6 地址（`sin6_addr`）以及作用域 ID（`sin6_scope_id`，用于链路本地地址等）。
3. **定义了用于 IPv6 组播的结构体 `ipv6_mreq`:** 这个结构体用于加入或离开 IPv6 组播组。它包含要加入/离开的组播地址（`ipv6mr_multiaddr`）以及网络接口索引（`ipv6mr_ifindex`）。
4. **定义了用于 IPv6 流标签请求的结构体 `in6_flowlabel_req`:** 这个结构体用于请求或管理 IPv6 流标签。它包含了目标地址、流标签、操作类型、共享模式、标志位、过期时间和延迟释放时间等信息。
5. **定义了与 IPv6 相关的各种宏常量:**  这些常量用于指定 IPv6 的协议类型（例如 `IPPROTO_ICMPV6`），TLV 类型，Socket 选项（例如 `IPV6_V6ONLY`，`IPV6_JOIN_MEMBERSHIP`），流量优先级（例如 `IPV6_PRIORITY_BULK`）等等。

**与 Android 功能的关系及举例:**

这个头文件是 Android 网络编程的基础组成部分，任何涉及 IPv6 网络操作的 Android 组件或应用都会直接或间接地使用到这里定义的结构体和常量。

* **网络连接:**  当 Android 应用需要建立 IPv6 网络连接（例如使用 `java.net.Socket` 或 NDK 中的 Socket API）时，底层的 C 代码会使用 `sockaddr_in6` 结构体来指定目标服务器的 IPv6 地址和端口。
    * **例子:** 一个 Android 应用需要连接到 IPv6 only 的服务器，它会使用类似 `InetSocketAddress("[2001:db8::1]", 80)` 的方式指定地址和端口。这个地址信息最终会被转换为 `sockaddr_in6` 结构体传递给底层的 socket 系统调用。
* **组播:**  如果 Android 应用需要加入 IPv6 组播组（例如用于局域网服务发现），它会使用 `ipv6_mreq` 结构体来指定要加入的组播地址和网络接口。
    * **例子:** 一个智能家居应用需要监听局域网内的设备广播，这些广播可能使用 IPv6 组播地址。应用会使用 NDK 的 socket API，并通过 `setsockopt` 设置 `IPV6_ADD_MEMBERSHIP` 选项，其中会用到 `ipv6_mreq` 结构体。
* **网络配置:** Android 系统在进行网络配置时，例如设置 IPv6 地址、路由等，内核会使用这里定义的结构体来传递和处理 IPv6 地址信息。
* **VPN 和网络隧道:**  VPN 应用或网络隧道技术在 Android 上实现时，需要处理 IPv6 数据包和地址，因此也会依赖这些定义。

**libc 函数的功能实现:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了数据结构和常量。实际使用这些定义的 libc 函数的实现位于 Bionic 的其他源文件中，例如 `bionic/libc/net/ifaddr.cpp`，`bionic/libc/net/socket.cpp` 等。

举例说明几个相关的 libc 函数如何使用这些定义：

* **`socket(AF_INET6, ...)`:** 当调用 `socket` 函数创建 IPv6 socket 时，`AF_INET6` 常量（通常在 `<sys/socket.h>` 中定义，但与此文件相关联）会告诉内核创建一个 IPv6 类型的 socket。
* **`bind(sockfd, (const struct sockaddr *)&my_addr, sizeof(my_addr))`:**  `bind` 函数用于将 socket 绑定到特定的地址和端口。对于 IPv6 socket，`my_addr` 参数通常会被强制转换为 `struct sockaddr_in6 *` 类型，然后内核会读取其中的 `sin6_addr` 和 `sin6_port` 信息。
* **`connect(sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr))`:** `connect` 函数用于连接到远程服务器。对于 IPv6 连接，`serv_addr` 参数会被强制转换为 `struct sockaddr_in6 *`，内核会读取目标服务器的 IPv6 地址和端口。
* **`setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, ...)`:**  `setsockopt` 函数用于设置 socket 选项。当设置 `IPV6_ADD_MEMBERSHIP` 选项以加入 IPv6 组播组时，传递给此选项的值需要是一个 `struct ipv6_mreq` 结构体。

**dynamic linker 的功能及 SO 布局样本和链接过程:**

这个头文件本身与 dynamic linker 没有直接关系。Dynamic linker 的主要职责是加载共享库（.so 文件）并解析符号依赖。

然而，包含此头文件的 libc (`libc.so`) 是一个核心的共享库，所有 Android 应用都会链接到它。当应用调用与 IPv6 相关的网络函数时，这些函数的实现位于 `libc.so` 中。Dynamic linker 负责在应用启动时加载 `libc.so`，并将应用中对这些函数的调用链接到 `libc.so` 中对应的实现。

**SO 布局样本 (libc.so 的部分):**

```
libc.so:
    ...
    .text:  // 代码段
        socket:      // socket 函数的实现
            ...
        bind:        // bind 函数的实现
            ...
        connect:     // connect 函数的实现
            ...
        setsockopt:  // setsockopt 函数的实现
            ...
    .rodata: // 只读数据段
        // 可能包含一些与网络相关的常量
    .data:   // 可读写数据段
        // 可能包含一些全局网络状态信息
    .dynsym: // 动态符号表
        socket
        bind
        connect
        setsockopt
        // ... 其他网络相关的符号
    .dynstr: // 动态字符串表
        "socket"
        "bind"
        "connect"
        "setsockopt"
        // ... 其他符号的字符串表示
    ...
```

**链接的处理过程:**

1. **编译时:** 当使用 NDK 编译 C/C++ 代码时，编译器会识别对 `socket`，`bind` 等函数的调用。由于这些函数通常在标准 C 库中，编译器会生成对这些符号的未解析引用。
2. **链接时:**  链接器 (ld) 会将编译生成的目标文件链接在一起，并链接到必要的共享库。对于 Android 应用，链接器会自动链接到 `libc.so`。
3. **运行时:**
   a. **加载:** 当 Android 系统启动应用时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
   b. **加载依赖:** Dynamic linker 会读取应用的可执行文件头部的动态链接段，找到依赖的共享库，例如 `libc.so`。
   c. **加载 libc.so:** Dynamic linker 将 `libc.so` 加载到内存中。
   d. **符号解析:** Dynamic linker 会遍历应用的未解析符号表，并查找在 `libc.so` 的动态符号表中匹配的符号（例如 `socket`，`bind`）。
   e. **重定位:** Dynamic linker 会更新应用代码中的地址，将对 `socket` 等函数的调用指向 `libc.so` 中对应的函数实现地址。

**逻辑推理和假设输入与输出:**

由于这个头文件主要是定义，逻辑推理更多体现在如何组合使用这些结构体和常量。

**假设输入:**  一个 NDK 应用尝试创建一个监听 IPv6 所有接口和端口 8080 的 socket。

**代码片段 (假设):**

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/in6.h> // 包含此头文件
#include <stdio.h>

int main() {
    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any; // 使用预定义的 IPv6 通配地址
    server_addr.sin6_port = htons(8080);  // 将端口号转换为网络字节序

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("IPv6 socket bound to [::]:8080\n");
    return 0;
}
```

**输出:** 如果 `bind` 成功，程序会输出 "IPv6 socket bound to [::]:8080"。如果失败，会输出 "bind" 相关的错误信息。

**逻辑推理:**

* `socket(AF_INET6, SOCK_STREAM, 0)`:  指定创建 IPv6 的 TCP socket。
* `server_addr.sin6_family = AF_INET6;`: 设置地址族为 IPv6。
* `server_addr.sin6_addr = in6addr_any;`: 使用 `in6addr_any`（通常在 `<netinet/in.h>` 中定义，表示 IPv6 的通配地址 `::`），意味着监听所有 IPv6 接口。
* `server_addr.sin6_port = htons(8080);`: 将主机字节序的端口号 8080 转换为网络字节序。
* `bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))`: 将 socket 绑定到指定的 IPv6 地址和端口。

**用户或编程常见的使用错误:**

1. **地址族不匹配:**  尝试将 `sockaddr_in6` 结构体用于 `AF_INET` 类型的 socket，或者反之。
   * **例子:**  创建一个 `AF_INET` 的 socket，然后尝试绑定一个填充了 IPv6 地址的 `sockaddr_in6` 结构体。
2. **端口号字节序错误:**  忘记使用 `htons()` 将端口号从主机字节序转换为网络字节序，或者使用 `htonl()` (用于 32 位整数) 而不是 `htons()` (用于 16 位整数)。
   * **例子:** 直接将 `server_addr.sin6_port = 8080;` 而不使用 `htons()`。
3. **IPv4-mapped IPv6 地址混淆:**  不理解 IPv4-mapped IPv6 地址 (例如 `::ffff:192.168.1.1`) 的含义和使用场景，可能导致连接失败或行为不符合预期。
4. **作用域 ID 使用错误:**  对于链路本地地址（以 `fe80::` 开头），必须正确设置 `sin6_scope_id` 来指定网络接口，否则可能无法连接。
   * **例子:**  尝试连接到一个链路本地地址，但 `sin6_scope_id` 设置为 0 或错误的值。
5. **组播地址错误:**  加入组播组时，使用了非法的组播地址或未在接口上启用组播。
6. **Socket 选项设置错误:**  错误地使用 `setsockopt` 设置 IPv6 相关的选项，例如传递了错误大小的参数或使用了不兼容的选项值。

**Android framework or ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**路径:**

1. **Java/Kotlin 代码 (Android Framework 或 NDK 应用):**  应用层发起网络请求，例如使用 `java.net.Socket` 或 `java.net.DatagramSocket`。
2. **Framework 网络组件 (Java):**  Android Framework 的网络相关类（如 `java.net.InetSocketAddress`, `android.net.ConnectivityManager` 等）处理地址解析、连接管理等逻辑。
3. **System 服务 (Java/C++):** Framework 层调用底层的 System 服务，例如 `netd` (Network Daemon)。
4. **NDK 网络 API (C/C++):**  如果应用使用 NDK 进行网络编程，会直接调用 C 库的 socket API (例如 `socket`, `bind`, `connect`)。
5. **Bionic libc (C):** NDK 的 socket API 调用最终会进入 Bionic 的 `libc.so` 中的实现。
6. **Kernel 系统调用:** `libc.so` 中的网络函数实现会调用相应的 Linux Kernel 系统调用，例如 `socket(2)`, `bind(2)`, `connect(2)`。
7. **Kernel 网络协议栈:**  Kernel 接收到系统调用后，会使用 `linux/in6.h` 中定义的结构体来处理 IPv6 地址和相关信息。

**Frida Hook 示例:**

假设我们想查看一个 Android 应用在尝试连接到 IPv6 地址时传递给 `connect` 函数的参数。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名
target_process = None

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    global target_process
    try:
        device = frida.get_usb_device(timeout=10)
        pid = device.spawn([package_name])
        target_process = device.attach(pid)
    except frida.WaitforitTimeoutError:
        print(f"[-] Could not find USB device. Exiting...")
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Exiting...")
        sys.exit(1)

    session = target_process
    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var sockaddr_ptr = ptr(args[1]);
            var addrlen = args[2].toInt32();

            if (addrlen >= 16) { // sockaddr_in6 的大小
                var family = sockaddr_ptr.readU16();
                if (family === 10) { // AF_INET6 的值
                    var port = sockaddr_ptr.add(2).readU16();
                    var flowinfo = sockaddr_ptr.add(4).readU32();
                    var addr_bytes = sockaddr_ptr.add(8).readByteArray(16);
                    var scope_id = sockaddr_ptr.add(24).readU32();

                    console.log("[Connect] Socket FD: " + sockfd);
                    console.log("[Connect] Family: AF_INET6");
                    console.log("[Connect] Port: " + port);
                    console.log("[Connect] Flowinfo: " + flowinfo);
                    console.log("[Connect] Address: " + hexdump(addr_bytes));
                    console.log("[Connect] Scope ID: " + scope_id);
                }
            }
        },
        onLeave: function(retval) {
            console.log("[Connect] Return value: " + retval);
        }
    });
    """
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input() # Keep the script running until Enter is pressed

if __name__ == "__main__":
    main()
```

**Frida Hook 代码解释:**

1. **`frida.get_usb_device()` 和 `device.spawn()`/`device.attach()`:**  连接到 USB 设备上的 Android 应用。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "connect"), ...)`:**  Hook `libc.so` 中的 `connect` 函数。
3. **`onEnter`:**  在 `connect` 函数被调用前执行。
4. **`args`:**  包含 `connect` 函数的参数。`args[0]` 是 socket 文件描述符，`args[1]` 是指向 `sockaddr` 结构体的指针，`args[2]` 是地址结构的长度。
5. **检查 `addrlen` 和 `family`:**  确保地址结构至少是 `sockaddr_in6` 的大小，并且地址族是 `AF_INET6` (值为 10)。
6. **读取 `sockaddr_in6` 字段:** 使用 `sockaddr_ptr.readU16()`, `sockaddr_ptr.add().readU32()`, `sockaddr_ptr.add().readByteArray()` 等方法读取端口号、流信息、IPv6 地址和作用域 ID。
7. **`hexdump(addr_bytes)`:**  将 IPv6 地址的字节数组以十六进制形式打印出来。
8. **`onLeave`:**  在 `connect` 函数执行完毕后执行，打印返回值。

运行这个 Frida 脚本后，当目标应用尝试连接到 IPv6 地址时，你会在控制台上看到 `connect` 函数被调用时的参数信息，包括目标 IPv6 地址和端口，这可以帮助你调试网络连接问题。

希望这个详细的分析能够帮助你理解 `bionic/libc/kernel/uapi/linux/in6.h` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/in6.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IN6_H
#define _UAPI_LINUX_IN6_H
#include <linux/types.h>
#include <linux/libc-compat.h>
#if __UAPI_DEF_IN6_ADDR
struct in6_addr {
  union {
    __u8 u6_addr8[16];
#if __UAPI_DEF_IN6_ADDR_ALT
    __be16 u6_addr16[8];
    __be32 u6_addr32[4];
#endif
  } in6_u;
#define s6_addr in6_u.u6_addr8
#if __UAPI_DEF_IN6_ADDR_ALT
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#endif
};
#endif
#if __UAPI_DEF_SOCKADDR_IN6
struct sockaddr_in6 {
  unsigned short int sin6_family;
  __be16 sin6_port;
  __be32 sin6_flowinfo;
  struct in6_addr sin6_addr;
  __u32 sin6_scope_id;
};
#endif
#if __UAPI_DEF_IPV6_MREQ
struct ipv6_mreq {
  struct in6_addr ipv6mr_multiaddr;
  int ipv6mr_ifindex;
};
#endif
#define ipv6mr_acaddr ipv6mr_multiaddr
struct in6_flowlabel_req {
  struct in6_addr flr_dst;
  __be32 flr_label;
  __u8 flr_action;
  __u8 flr_share;
  __u16 flr_flags;
  __u16 flr_expires;
  __u16 flr_linger;
  __u32 __flr_pad;
};
#define IPV6_FL_A_GET 0
#define IPV6_FL_A_PUT 1
#define IPV6_FL_A_RENEW 2
#define IPV6_FL_F_CREATE 1
#define IPV6_FL_F_EXCL 2
#define IPV6_FL_F_REFLECT 4
#define IPV6_FL_F_REMOTE 8
#define IPV6_FL_S_NONE 0
#define IPV6_FL_S_EXCL 1
#define IPV6_FL_S_PROCESS 2
#define IPV6_FL_S_USER 3
#define IPV6_FL_S_ANY 255
#define IPV6_FLOWINFO_FLOWLABEL 0x000fffff
#define IPV6_FLOWINFO_PRIORITY 0x0ff00000
#define IPV6_PRIORITY_UNCHARACTERIZED 0x0000
#define IPV6_PRIORITY_FILLER 0x0100
#define IPV6_PRIORITY_UNATTENDED 0x0200
#define IPV6_PRIORITY_RESERVED1 0x0300
#define IPV6_PRIORITY_BULK 0x0400
#define IPV6_PRIORITY_RESERVED2 0x0500
#define IPV6_PRIORITY_INTERACTIVE 0x0600
#define IPV6_PRIORITY_CONTROL 0x0700
#define IPV6_PRIORITY_8 0x0800
#define IPV6_PRIORITY_9 0x0900
#define IPV6_PRIORITY_10 0x0a00
#define IPV6_PRIORITY_11 0x0b00
#define IPV6_PRIORITY_12 0x0c00
#define IPV6_PRIORITY_13 0x0d00
#define IPV6_PRIORITY_14 0x0e00
#define IPV6_PRIORITY_15 0x0f00
#if __UAPI_DEF_IPPROTO_V6
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_MH 135
#endif
#define IPV6_TLV_PAD1 0
#define IPV6_TLV_PADN 1
#define IPV6_TLV_ROUTERALERT 5
#define IPV6_TLV_CALIPSO 7
#define IPV6_TLV_IOAM 49
#define IPV6_TLV_JUMBO 194
#define IPV6_TLV_HAO 201
#if __UAPI_DEF_IPV6_OPTIONS
#define IPV6_ADDRFORM 1
#define IPV6_2292PKTINFO 2
#define IPV6_2292HOPOPTS 3
#define IPV6_2292DSTOPTS 4
#define IPV6_2292RTHDR 5
#define IPV6_2292PKTOPTIONS 6
#define IPV6_CHECKSUM 7
#define IPV6_2292HOPLIMIT 8
#define IPV6_NEXTHOP 9
#define IPV6_AUTHHDR 10
#define IPV6_FLOWINFO 11
#define IPV6_UNICAST_HOPS 16
#define IPV6_MULTICAST_IF 17
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_LOOP 19
#define IPV6_ADD_MEMBERSHIP 20
#define IPV6_DROP_MEMBERSHIP 21
#define IPV6_ROUTER_ALERT 22
#define IPV6_MTU_DISCOVER 23
#define IPV6_MTU 24
#define IPV6_RECVERR 25
#define IPV6_V6ONLY 26
#define IPV6_JOIN_ANYCAST 27
#define IPV6_LEAVE_ANYCAST 28
#define IPV6_MULTICAST_ALL 29
#define IPV6_ROUTER_ALERT_ISOLATE 30
#define IPV6_RECVERR_RFC4884 31
#define IPV6_PMTUDISC_DONT 0
#define IPV6_PMTUDISC_WANT 1
#define IPV6_PMTUDISC_DO 2
#define IPV6_PMTUDISC_PROBE 3
#define IPV6_PMTUDISC_INTERFACE 4
#define IPV6_PMTUDISC_OMIT 5
#define IPV6_FLOWLABEL_MGR 32
#define IPV6_FLOWINFO_SEND 33
#define IPV6_IPSEC_POLICY 34
#define IPV6_XFRM_POLICY 35
#define IPV6_HDRINCL 36
#endif
#define IPV6_RECVPKTINFO 49
#define IPV6_PKTINFO 50
#define IPV6_RECVHOPLIMIT 51
#define IPV6_HOPLIMIT 52
#define IPV6_RECVHOPOPTS 53
#define IPV6_HOPOPTS 54
#define IPV6_RTHDRDSTOPTS 55
#define IPV6_RECVRTHDR 56
#define IPV6_RTHDR 57
#define IPV6_RECVDSTOPTS 58
#define IPV6_DSTOPTS 59
#define IPV6_RECVPATHMTU 60
#define IPV6_PATHMTU 61
#define IPV6_DONTFRAG 62
#define IPV6_RECVTCLASS 66
#define IPV6_TCLASS 67
#define IPV6_AUTOFLOWLABEL 70
#define IPV6_ADDR_PREFERENCES 72
#define IPV6_PREFER_SRC_TMP 0x0001
#define IPV6_PREFER_SRC_PUBLIC 0x0002
#define IPV6_PREFER_SRC_PUBTMP_DEFAULT 0x0100
#define IPV6_PREFER_SRC_COA 0x0004
#define IPV6_PREFER_SRC_HOME 0x0400
#define IPV6_PREFER_SRC_CGA 0x0008
#define IPV6_PREFER_SRC_NONCGA 0x0800
#define IPV6_MINHOPCOUNT 73
#define IPV6_ORIGDSTADDR 74
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#define IPV6_TRANSPARENT 75
#define IPV6_UNICAST_IF 76
#define IPV6_RECVFRAGSIZE 77
#define IPV6_FREEBIND 78
#endif
```