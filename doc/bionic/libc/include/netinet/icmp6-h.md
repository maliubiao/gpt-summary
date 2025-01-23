Response:
Let's break down the thought process for analyzing the `icmp6.h` header file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C header file (`icmp6.h`) within the context of Android's Bionic library. Key areas of focus are:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android's networking stack?
* **libc Function Implementation:** Detailed explanation of functions (though this header *defines* structures, not implements functions). This needs to be reinterpreted as explaining the purpose and structure of the defined elements.
* **Dynamic Linker:**  How does it interact with shared libraries and linking? (Again, this header doesn't directly involve the dynamic linker, but its definitions are used by code that *is* linked).
* **Logic and Examples:**  Illustrative examples for better understanding.
* **Common Errors:** Potential pitfalls for developers using these definitions.
* **Android Framework/NDK Integration:** How does data flow from the application level down to this header?
* **Frida Hooking:** How to intercept and observe interactions with these structures.

**2. Initial File Analysis (Skimming and Keywords):**

The first step is to read through the header file, paying attention to comments and key terms. I'd look for things like:

* **Copyright notices:** Indicate origin and licensing. The presence of both WIDE Project and Regents of the University of California suggests it's derived from BSD/NetBSD.
* **`#ifndef`, `#define`, `#endif`:**  Standard include guard to prevent multiple inclusions.
* **`#include` statements:**  Dependencies on other headers (`sys/cdefs.h`, `netinet/in.h`).
* **`struct` definitions:** The core of the file – these define the data structures for ICMPv6.
* **`#define` macros:** Symbolic constants representing ICMPv6 types, codes, flags, and other values.
* **`__packed`:**  Indicates that structures should be tightly packed in memory, which is crucial for network protocols.
* **Keywords like "ICMP6", "MLD", "ND", "Router", "Neighbor":**  These reveal the main purpose of the file – defining structures related to IPv6 Internet Control Message Protocol (ICMPv6), Multicast Listener Discovery (MLD), and Neighbor Discovery (ND).

**3. Grouping and Categorizing:**

Next, I'd group the definitions based on their purpose:

* **Core ICMPv6 Header (`icmp6_hdr`):** The fundamental structure for all ICMPv6 messages.
* **ICMPv6 Message Types:**  `ICMP6_DST_UNREACH`, `ICMP6_ECHO_REQUEST`, etc.
* **MLD Structures (`mld_hdr`):**  Related to multicast group management.
* **Neighbor Discovery Structures (`nd_router_solicit`, `nd_router_advert`, etc.):**  Used for address resolution and router discovery.
* **Neighbor Discovery Options (`nd_opt_hdr`, `nd_opt_prefix_info`, etc.):**  Additional information within ND messages.
* **Node Information Structures (`icmp6_nodeinfo`):** For querying node information.
* **Router Renumbering Structures (`icmp6_router_renum`):** For dynamically reconfiguring network prefixes.
* **ICMPv6 Filter (`icmp6_filter`):** For controlling which ICMPv6 messages are processed.

**4. Explaining Functionality (Interpreting Structure Definitions):**

Since it's a header file, "functionality" means explaining the *purpose* of the defined structures and constants. For each structure, I would:

* Describe what kind of ICMPv6 message it represents.
* Explain the meaning of each member variable (type, code, checksum, specific data fields).
* Connect the constants (macros) to the corresponding structure members and their usage.

**5. Connecting to Android:**

This is where the "Bionic" context becomes important. I'd think about how these ICMPv6 concepts are used in an Android environment:

* **Networking Stack:** ICMPv6 is a fundamental part of IPv6, which Android supports. The definitions in this file are used by the kernel and network daemons to handle ICMPv6 packets.
* **`ping6` Utility:** The `ping6` command (often available on Android) directly uses ICMPv6 Echo Request/Reply messages, whose structures are defined here.
* **Multicast:** Android devices can participate in multicast groups, and MLD structures are crucial for this.
* **Neighbor Discovery:** Android devices need to discover routers and the MAC addresses of other devices on the local network, which involves the ND protocols defined here.
* **Network Configuration:** Router Advertisements (defined here) provide Android devices with crucial network configuration information.

**6. Addressing Other Points in the Request:**

* **libc Function Implementation:** Reinterpret as explaining the *use* of these structures by libc networking functions like `socket()`, `sendto()`, `recvfrom()`, etc.
* **Dynamic Linker:** Explain that while this *header* isn't directly linked, code that *uses* these structures (e.g., network libraries) will be. Provide a hypothetical `.so` layout and explain the linking process in general terms (symbol resolution).
* **Logic and Examples:** Create scenarios (e.g., `ping6`, router discovery) to illustrate how these structures are used in practice, showing hypothetical input and output.
* **Common Errors:**  Focus on common mistakes developers might make when working with network protocols, such as incorrect structure packing, endianness issues, and misinterpreting ICMPv6 error codes.
* **Android Framework/NDK:** Trace the path from a high-level Android API call (e.g., using `InetAddress` or `NetworkInterface` in Java/Kotlin) down to the native layer where these structures are used in kernel system calls.
* **Frida Hooking:**  Provide practical Frida examples to demonstrate how to intercept and examine ICMPv6 packets or function calls that use these structures. Focus on hooking system calls like `sendto` or functions within network libraries.

**7. Structuring the Response:**

Organize the information logically with clear headings and subheadings to make it easy to read and understand. Start with a general overview and then delve into specifics.

**8. Refinement and Clarity:**

Review the response for accuracy, clarity, and completeness. Ensure the language is precise and avoids jargon where possible. Provide concrete examples to illustrate abstract concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on libc *functions*. **Correction:** Realize this is a *header* file, so shift focus to the *structures* and their purpose. Explain how libc functions *use* these structures.
* **Initial thought:**  Provide very specific dynamic linker details. **Correction:**  Keep the dynamic linker explanation at a high level, as this header doesn't directly interact with it. Focus on the concept of linking against libraries that *use* these definitions.
* **Initial thought:**  Just list the structure members. **Correction:**  Explain the *meaning* and *purpose* of each member in the context of ICMPv6.
* **Initial thought:**  Provide very low-level kernel details. **Correction:** Keep the Android Framework/NDK explanation at a reasonable level of abstraction, showing the general flow of data.

By following this structured thought process, including self-correction,  I can create a comprehensive and accurate answer to the request.
这个文件 `bionic/libc/include/netinet/icmp6.h` 是 Android Bionic C 库中的一个头文件，它定义了 IPv6 协议中 ICMPv6 (Internet Control Message Protocol for IPv6) 相关的结构体、宏定义和常量。ICMPv6 用于在 IPv6 网络中传递错误消息和控制信息。

**主要功能：**

1. **定义 ICMPv6 报文结构:**  该文件定义了 `struct icmp6_hdr`，这是所有 ICMPv6 报文的基本头部结构，包含类型、代码和校验和等关键字段。

2. **定义不同类型的 ICMPv6 消息结构:**  根据 ICMPv6 的类型和代码，定义了各种特定类型的消息结构，例如：
    * **错误消息:**  目标不可达 (`ICMP6_DST_UNREACH`)，包过大 (`ICMP6_PACKET_TOO_BIG`)，超时 (`ICMP6_TIME_EXCEEDED`)，参数问题 (`ICMP6_PARAM_PROB`)。
    * **信息性消息:**  回显请求/应答 (`ICMP6_ECHO_REQUEST`/`ICMP6_ECHO_REPLY`)。
    * **组播监听者发现 (MLD):**  用于 IPv6 组播的管理，包括查询、报告和完成消息 (`MLD_LISTENER_QUERY`, `MLD_LISTENER_REPORT`, `MLD_LISTENER_DONE`)。
    * **邻居发现 (ND):**  用于 IPv6 网络中的地址解析、路由器发现和重定向等功能，包括路由器请求/通告 (`ND_ROUTER_SOLICIT`/`ND_ROUTER_ADVERT`)，邻居请求/通告 (`ND_NEIGHBOR_SOLICIT`/`ND_NEIGHBOR_ADVERT`)，重定向 (`ND_REDIRECT`)。
    * **邻居发现选项:** 定义了在 ND 消息中携带的各种选项结构，例如源/目标链路层地址、前缀信息、MTU 等。
    * **节点信息查询/应答:**  用于查询节点的各种信息 (`ICMP6_NI_QUERY`/`ICMP6_NI_REPLY`)。
    * **路由器重编号:**  用于动态更新网络前缀信息 (`ICMP6_ROUTER_RENUMBERING`)。

3. **定义 ICMPv6 消息类型和代码的常量:**  使用 `#define` 定义了各种 ICMPv6 消息类型和代码的常量，方便程序中使用和理解，例如 `ICMP6_ECHO_REQUEST` 的值为 128。

4. **定义 ICMPv6 过滤器结构:**  定义了 `struct icmp6_filter` 用于控制接收哪些 ICMPv6 消息。

**与 Android 功能的关系及举例说明：**

这个头文件对于 Android 设备的 IPv6 网络功能至关重要。Android 系统需要能够处理各种 ICMPv6 消息，以确保网络的正常运行和诊断网络问题。

* **`ping6` 命令:**  Android 系统中的 `ping6` 命令会使用 `ICMP6_ECHO_REQUEST` 发送回显请求报文，并期望收到 `ICMP6_ECHO_REPLY` 报文。`icmp6.h` 中定义的结构体会被用来构建和解析这些报文。

* **网络错误处理:**  当网络出现问题时，例如目标主机不可达，网络设备会发送 `ICMP6_DST_UNREACH` 报文。Android 系统需要解析这些报文，以便向用户或应用程序报告错误。

* **IPv6 组播:**  Android 设备如果加入了 IPv6 组播组，会发送和接收 MLD 报文。`icmp6.h` 中定义的 MLD 结构体用于处理这些组播成员关系管理。

* **邻居发现协议:**  Android 设备在连接到 IPv6 网络时，会使用邻居发现协议来查找路由器和同一链路上的其他设备的链路层地址。这涉及到 `ND_ROUTER_SOLICIT`、`ND_ROUTER_ADVERT`、`ND_NEIGHBOR_SOLICIT`、`ND_NEIGHBOR_ADVERT` 等消息，这些消息的结构都在 `icmp6.h` 中定义。例如，当 Android 设备启动并连接到 IPv6 网络时，它会发送 `ND_ROUTER_SOLICIT` 消息来寻找路由器。路由器会响应 `ND_ROUTER_ADVERT` 消息，包含网络配置信息。

* **网络配置:**  路由器通告消息 (`ND_ROUTER_ADVERT`) 中携带了重要的网络配置信息，例如前缀信息、MTU 等。Android 系统会解析这些信息来配置自身的网络参数。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **没有定义 libc 函数的实现**，它只定义了数据结构和常量。libc 函数（例如 `socket()`, `sendto()`, `recvfrom()` 等）会在其实现中使用这些结构体来操作 ICMPv6 报文。

例如，当应用程序调用 `sendto()` 发送一个 ICMPv6 回显请求时，libc 的网络库会根据 `struct icmp6_hdr` 的定义构建 ICMPv6 头部，并填充类型、代码、校验和等字段。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`icmp6.h` 文件本身 **不直接涉及 dynamic linker 的功能**。它只是一个头文件，会被其他源文件包含和使用。然而，使用这个头文件中定义的结构体的代码，最终会被编译成共享库 (`.so` 文件)，并由 dynamic linker 加载和链接。

**so 布局样本：**

一个使用 `icmp6.h` 中定义的结构的共享库 (例如 `libnetd_client.so`) 的布局可能如下：

```
libnetd_client.so:
    .text       # 包含代码段
        - 函数1 使用了 struct icmp6_hdr
        - 函数2 处理邻居发现消息
        ...
    .data       # 包含已初始化的数据
        ...
    .rodata     # 包含只读数据 (可能包含 ICMPv6 相关的常量)
        ...
    .bss        # 包含未初始化的数据
        ...
    .symtab     # 符号表 (包含导出的和导入的符号)
        - (导出) function1
        - (导入) socket, sendto, recvfrom (来自 libc.so 或其他库)
        - (导入) 在 icmp6.h 中定义的结构体和宏定义本身不会出现在符号表中，但使用它们的类型和变量可能会间接影响符号。
    .dynsym     # 动态符号表 (用于动态链接)
        - (导入) socket, sendto, recvfrom
    .rel.dyn    # 动态重定位表
        - 记录需要在加载时进行重定位的信息 (例如导入的函数地址)
    .plt        # 程序链接表 (用于延迟绑定)
        - socket@LIBC
        - sendto@LIBC
        - recvfrom@LIBC
    .got        # 全局偏移表 (存储导入的全局变量和函数地址)
        - socket 的实际地址
        - sendto 的实际地址
        - recvfrom 的实际地址
    ...
```

**链接的处理过程：**

1. **编译时：** 当编译 `libnetd_client.c` 等源文件时，编译器会遇到包含 `icmp6.h` 的语句。编译器会读取 `icmp6.h`，了解 `struct icmp6_hdr` 等结构的定义。如果代码中使用了这些结构，编译器会根据定义生成相应的代码。

2. **链接时：** 静态链接器 (在构建 `.so` 文件时使用) 会将编译后的目标文件链接在一起。它会解析符号引用，例如对 `socket`, `sendto`, `recvfrom` 等函数的调用。由于这些函数通常在 `libc.so` 中，静态链接器会将这些符号标记为需要动态链接。

3. **加载时 (动态链接)：** 当 Android 系统加载 `libnetd_client.so` 时，dynamic linker (例如 `linker64` 或 `linker`) 会执行以下步骤：
    * **加载依赖库：**  首先加载 `libnetd_client.so` 依赖的共享库，例如 `libc.so`。
    * **符号解析 (Symbol Resolution)：** dynamic linker 会查找 `libnetd_client.so` 中导入的符号 (例如 `socket`, `sendto`, `recvfrom`) 在其依赖库中的定义。
    * **重定位 (Relocation)：** dynamic linker 会更新 `.got` (全局偏移表) 中的条目，将导入的函数符号指向其在 `libc.so` 中的实际地址。这样，当 `libnetd_client.so` 中的代码调用 `socket` 时，实际上会跳转到 `libc.so` 中 `socket` 函数的实现。

**对于 `icmp6.h` 中定义的结构体，它们本身不会直接参与 dynamic linker 的符号解析过程。**  dynamic linker 解析的是函数和全局变量的符号。但是，`icmp6.h` 中定义的结构体会被使用这些结构体的代码间接引用。例如，如果 `libnetd_client.so` 中有一个函数使用了 `struct icmp6_hdr` 作为参数，那么这个函数本身会成为一个符号，并可能被其他库导入和调用。

**如果做了逻辑推理，请给出假设输入与输出：**

假设有一个程序需要发送一个 IPv6 的 Ping 请求。

**假设输入：**

* 目标 IPv6 地址：`2001:db8::1`
* 需要发送的数据负载 (可选)：例如 "Hello"

**逻辑推理过程：**

1. 程序调用 `socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)` 创建一个用于发送 ICMPv6 报文的原始套接字。
2. 程序构造一个 `struct icmp6_hdr` 结构体：
    * `icmp6_type` 设置为 `ICMP6_ECHO_REQUEST` (128)。
    * `icmp6_code` 设置为 0。
    * `icmp6_cksum` 计算校验和 (需要填充其他部分后计算)。
    * `icmp6_id` 和 `icmp6_seq` 设置为标识符和序列号。
3. 程序将 ICMPv6 头部和数据负载组合成一个完整的报文。
4. 程序调用 `sendto()` 函数，将构建好的报文发送到目标 IPv6 地址。

**假设输出 (预期网络行为)：**

1. 程序发送一个 ICMPv6 Echo Request 报文到 `2001:db8::1`。
2. 如果目标主机 `2001:db8::1` 正在运行并且可达，它会接收到该请求。
3. 目标主机构造一个 ICMPv6 Echo Reply 报文，并将 `icmp6_type` 设置为 `ICMP6_ECHO_REPLY` (129)，其他字段与请求报文对应。
4. 目标主机将 Echo Reply 报文发送回发送端。
5. 发送端程序可以通过原始套接字接收到该 Echo Reply 报文。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **结构体大小和对齐问题:**  网络协议报文的结构通常是固定的，如果程序在构建 ICMPv6 报文时，结构体成员的顺序、大小或对齐方式不正确，会导致发送的报文格式错误，接收端可能无法正确解析。
   ```c
   struct icmp6_hdr my_icmp;
   my_icmp.icmp6_type = ICMP6_ECHO_REQUEST;
   my_icmp.icmp6_code = 0;
   // 忘记计算和设置校验和
   // ...
   sendto(sockfd, &my_icmp, sizeof(my_icmp), ...); // 错误：校验和未设置
   ```

2. **字节序问题 (Endianness):**  网络字节序 (大端) 和主机字节序可能不同。如果程序直接将多字节数据 (例如校验和、ID、序列号) 填充到结构体中，而没有进行字节序转换，可能导致发送的报文字段值错误。需要使用 `htons()` 和 `ntohs()` 等函数进行转换。
   ```c
   struct icmp6_hdr my_icmp;
   my_icmp.icmp6_cksum = calculate_checksum(...); // 假设 calculate_checksum 返回主机字节序
   // 错误：直接赋值，没有转换为网络字节序
   ```
   **正确做法:**
   ```c
   my_icmp.icmp6_cksum = htons(calculate_checksum(...));
   ```

3. **错误地解释 ICMPv6 错误代码:**  当收到 ICMPv6 错误消息时，程序需要根据 `icmp6_type` 和 `icmp6_code` 来判断错误类型。如果错误地解释了错误代码，可能会导致程序做出错误的反应。

4. **忘记设置套接字选项:**  在使用原始套接字发送 ICMPv6 报文时，可能需要设置一些套接字选项，例如允许发送原始报文。忘记设置这些选项可能导致发送失败。

5. **缓冲区溢出:**  在接收 ICMPv6 报文时，如果没有正确处理接收缓冲区的大小，可能会导致缓冲区溢出。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

以下是一个简化的流程，说明 Android Framework 如何通过 NDK 最终涉及到 `icmp6.h` 中定义的结构体：

1. **Android Framework (Java/Kotlin):**  应用程序或 Framework 组件通过 Java/Kotlin API 发起网络操作，例如使用 `InetAddress` 解析主机名，或者使用 `ConnectivityManager` 获取网络状态。

2. **System Services (Java/Kotlin):**  Framework 的网络相关功能通常由 System Services 实现，例如 `NetworkManagementService`，`ConnectivityService` 等。这些服务可能会调用 native 方法来执行底层的网络操作。

3. **NDK (Native Code):**  System Services 或应用程序通过 JNI (Java Native Interface) 调用 NDK 库中的 native 代码。例如，`libnetd_client.so` 包含了许多用于执行网络操作的 native 函数。

4. **Native Libraries (C/C++):**  NDK 库中的 native 代码 (C/C++) 会使用标准的 socket API (`socket()`, `sendto()`, `recvfrom()`) 进行网络通信。当需要发送或接收 ICMPv6 报文时，这些 native 代码会包含 `<netinet/icmp6.h>` 头文件，并使用其中定义的结构体来构建和解析 ICMPv6 报文。

5. **Bionic libc:**  NDK 库链接到 Bionic libc，因此会使用 Bionic libc 提供的 socket API 实现。Bionic libc 的网络部分会与 Linux 内核进行交互。

6. **Linux Kernel:**  最终，网络数据包的发送和接收是由 Linux 内核的网络协议栈处理的。内核会使用与 `icmp6.h` 中定义相似的结构体来处理 ICMPv6 报文。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截发送 ICMPv6 Echo Request 报文的示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received message")
        print(message['payload'])

def main():
    package_name = "com.example.myapp" # 替换为目标应用包名
    device = frida.get_usb_device()
    session = device.attach(package_name)

    script_source = """
    Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var buf = ptr(args[1]);
            var len = args[2].toInt32();
            var destaddr = ptr(args[3]);
            var addrlen = args[4].toInt32();

            // 假设我们知道 ICMPv6 报文通常比较小，并且协议族是 AF_INET6
            if (len > 8 && addrlen > 0) {
                var sin6_family = destaddr.readU16();
                if (sin6_family === 10) { // AF_INET6 的值
                    console.log("[*] sendto called for IPv6");
                    var icmp6_type = buf.readU8();
                    var icmp6_code = buf.readU8();
                    console.log("    ICMPv6 Type: " + icmp6_type);
                    console.log("    ICMPv6 Code: " + icmp6_code);

                    if (icmp6_type === 128) { // ICMP6_ECHO_REQUEST
                        console.log("[*] Detected ICMPv6 Echo Request");
                        // 可以进一步解析 ICMPv6 头部和数据
                        var icmp6_id = buf.add(4).readU16();
                        var icmp6_seq = buf.add(6).readU16();
                        console.log("    ICMP ID: " + icmp6_id);
                        console.log("    ICMP Sequence: " + icmp6_seq);
                    }
                }
            }
        },
        onLeave: function(retval) {
            // console.log("sendto returned: " + retval);
        }
    });
    """

    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**Frida Hook 示例说明：**

1. **Attach 到目标进程:**  使用 `frida.get_usb_device().attach(package_name)` 连接到目标 Android 应用程序的进程。

2. **Hook `sendto` 函数:**  `sendto` 是一个常用的发送网络数据包的系统调用。我们使用 `Interceptor.attach` 拦截对 `libc.so` 中 `sendto` 函数的调用。

3. **在 `onEnter` 中检查参数:**  在 `sendto` 函数被调用时，`onEnter` 回调函数会被执行。我们可以访问 `args` 参数来获取 `sendto` 的参数，例如套接字描述符、发送缓冲区地址、数据长度、目标地址等。

4. **过滤 IPv6 数据包:**  我们通过检查目标地址结构中的协议族 (`sin6_family`) 是否为 `AF_INET6` (10) 来判断是否是 IPv6 数据包。

5. **解析 ICMPv6 头部:**  如果检测到 IPv6 数据包，我们读取发送缓冲区的前几个字节来获取 ICMPv6 的类型和代码。

6. **检测 ICMPv6 Echo Request:**  如果 `icmp6_type` 的值为 128 (`ICMP6_ECHO_REQUEST`)，我们就可以确定这是一个 Ping 请求报文。

7. **进一步解析:**  可以根据 `icmp6.h` 中定义的结构体布局，进一步读取 ICMPv6 报文中的其他字段，例如 ID 和序列号。

8. **加载 Frida 脚本:**  将脚本加载到目标进程中，Frida 会自动拦截 `sendto` 函数的调用并执行我们的 hook 代码。

通过这个 Frida Hook 示例，我们可以动态地观察 Android 应用程序在发送 ICMPv6 报文时的行为，验证 `icmp6.h` 中定义的结构体是否被正确使用。你可以根据需要 hook 其他相关的函数或使用不同的 Frida 功能来调试更复杂的情况。

### 提示词
```
这是目录为bionic/libc/include/netinet/icmp6.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: icmp6.h,v 1.47 2013/07/01 12:43:15 christos Exp $	*/
/*	$KAME: icmp6.h,v 1.84 2003/04/23 10:26:51 itojun Exp $	*/


/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip_icmp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_ICMP6_H_
#define _NETINET_ICMP6_H_

#include <sys/cdefs.h>

#include <netinet/in.h> /* android-added: glibc source compatibility. */

#define ICMPV6_PLD_MAXLEN	1232	/* IPV6_MMTU - sizeof(struct ip6_hdr)
					   - sizeof(struct icmp6_hdr) */

struct icmp6_hdr {
	u_int8_t	icmp6_type;	/* type field */
	u_int8_t	icmp6_code;	/* code field */
	u_int16_t	icmp6_cksum;	/* checksum field */
	union {
		u_int32_t	icmp6_un_data32[1]; /* type-specific field */
		u_int16_t	icmp6_un_data16[2]; /* type-specific field */
		u_int8_t	icmp6_un_data8[4];  /* type-specific field */
	} icmp6_dataun;
} __packed;

#define icmp6_data32	icmp6_dataun.icmp6_un_data32
#define icmp6_data16	icmp6_dataun.icmp6_un_data16
#define icmp6_data8	icmp6_dataun.icmp6_un_data8
#define icmp6_pptr	icmp6_data32[0]		/* parameter prob */
#define icmp6_mtu	icmp6_data32[0]		/* packet too big */
#define icmp6_id	icmp6_data16[0]		/* echo request/reply */
#define icmp6_seq	icmp6_data16[1]		/* echo request/reply */
#define icmp6_maxdelay	icmp6_data16[0]		/* mcast group membership */

#define ICMP6_DST_UNREACH		1	/* dest unreachable, codes: */
#define ICMP6_PACKET_TOO_BIG		2	/* packet too big */
#define ICMP6_TIME_EXCEEDED		3	/* time exceeded, code: */
#define ICMP6_PARAM_PROB		4	/* ip6 header bad */

#define ICMP6_ECHO_REQUEST		128	/* echo service */
#define ICMP6_ECHO_REPLY		129	/* echo reply */
#define MLD_LISTENER_QUERY		130 	/* multicast listener query */
#define MLD_LISTENER_REPORT		131	/* multicast listener report */
#define MLD_LISTENER_DONE		132	/* multicast listener done */
#define MLD_LISTENER_REDUCTION MLD_LISTENER_DONE /* RFC3542 definition */

/* RFC2292 decls */
#define ICMP6_MEMBERSHIP_QUERY		130	/* group membership query */
#define ICMP6_MEMBERSHIP_REPORT		131	/* group membership report */
#define ICMP6_MEMBERSHIP_REDUCTION	132	/* group membership termination */

#define ND_ROUTER_SOLICIT		133	/* router solicitation */
#define ND_ROUTER_ADVERT		134	/* router advertisement */
#define ND_NEIGHBOR_SOLICIT		135	/* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT		136	/* neighbor advertisement */
#define ND_REDIRECT			137	/* redirect */

#define ICMP6_ROUTER_RENUMBERING	138	/* router renumbering */

#define ICMP6_WRUREQUEST		139	/* who are you request */
#define ICMP6_WRUREPLY			140	/* who are you reply */
#define ICMP6_FQDN_QUERY		139	/* FQDN query */
#define ICMP6_FQDN_REPLY		140	/* FQDN reply */
#define ICMP6_NI_QUERY			139	/* node information request */
#define ICMP6_NI_REPLY			140	/* node information reply */
#define MLDV2_LISTENER_REPORT		143	/* RFC3810 listener report */

/* The definitions below are experimental. TBA */
#define MLD_MTRACE_RESP			200	/* mtrace response(to sender) */
#define MLD_MTRACE			201	/* mtrace messages */

#define ICMP6_MAXTYPE			201

#define ICMP6_DST_UNREACH_NOROUTE	0	/* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN	 	1	/* administratively prohibited */
#define ICMP6_DST_UNREACH_NOTNEIGHBOR	2	/* not a neighbor(obsolete) */
#define ICMP6_DST_UNREACH_BEYONDSCOPE	2	/* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR		3	/* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT	4	/* port unreachable */
#define ICMP6_DST_UNREACH_POLICY	5	/* source address failed ingress/egress policy */
#define ICMP6_DST_UNREACH_REJROUTE	6	/* reject route to destination */
#define ICMP6_DST_UNREACH_SOURCERT	7	/* error in source routing header */

#define ICMP6_TIME_EXCEED_TRANSIT 	0	/* ttl==0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY	1	/* ttl==0 in reass */

#define ICMP6_PARAMPROB_HEADER 	 	0	/* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER	1	/* unrecognized next header */
#define ICMP6_PARAMPROB_OPTION		2	/* unrecognized option */

#define ICMP6_INFOMSG_MASK		0x80	/* all informational messages */

#define ICMP6_NI_SUBJ_IPV6	0	/* Query Subject is an IPv6 address */
#define ICMP6_NI_SUBJ_FQDN	1	/* Query Subject is a Domain name */
#define ICMP6_NI_SUBJ_IPV4	2	/* Query Subject is an IPv4 address */

#define ICMP6_NI_SUCCESS	0	/* node information successful reply */
#define ICMP6_NI_REFUSED	1	/* node information request is refused */
#define ICMP6_NI_UNKNOWN	2	/* unknown Qtype */

#define ICMP6_ROUTER_RENUMBERING_COMMAND  0	/* rr command */
#define ICMP6_ROUTER_RENUMBERING_RESULT   1	/* rr result */
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255	/* rr seq num reset */

/* Used in kernel only */
#define ND_REDIRECT_ONLINK	0	/* redirect to an on-link node */
#define ND_REDIRECT_ROUTER	1	/* redirect to a better router */

/*
 * Multicast Listener Discovery
 */
struct mld_hdr {
	struct icmp6_hdr	mld_icmp6_hdr;
	struct in6_addr		mld_addr; /* multicast address */
} __packed;

/* shortcut macro definitions */
#define mld_type	mld_icmp6_hdr.icmp6_type
#define mld_code	mld_icmp6_hdr.icmp6_code
#define mld_cksum	mld_icmp6_hdr.icmp6_cksum
#define mld_maxdelay	mld_icmp6_hdr.icmp6_data16[0]
#define mld_reserved	mld_icmp6_hdr.icmp6_data16[1]

#define MLD_MINLEN			24

/*
 * Neighbor Discovery
 */

struct nd_router_solicit {	/* router solicitation */
	struct icmp6_hdr 	nd_rs_hdr;
	/* could be followed by options */
} __packed;

#define nd_rs_type	nd_rs_hdr.icmp6_type
#define nd_rs_code	nd_rs_hdr.icmp6_code
#define nd_rs_cksum	nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved	nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert {	/* router advertisement */
	struct icmp6_hdr	nd_ra_hdr;
	u_int32_t		nd_ra_reachable;	/* reachable time */
	u_int32_t		nd_ra_retransmit;	/* retransmit timer */
	/* could be followed by options */
} __packed;

#define nd_ra_type		nd_ra_hdr.icmp6_type
#define nd_ra_code		nd_ra_hdr.icmp6_code
#define nd_ra_cksum		nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit	nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved	nd_ra_hdr.icmp6_data8[1]
#define ND_RA_FLAG_MANAGED	0x80
#define ND_RA_FLAG_OTHER	0x40
#define ND_RA_FLAG_HOME_AGENT	0x20

/*
 * Router preference values based on RFC4191.
 */
#define ND_RA_FLAG_RTPREF_MASK	0x18 /* 00011000 */

#define ND_RA_FLAG_RTPREF_HIGH	0x08 /* 00001000 */
#define ND_RA_FLAG_RTPREF_MEDIUM	0x00 /* 00000000 */
#define ND_RA_FLAG_RTPREF_LOW	0x18 /* 00011000 */
#define ND_RA_FLAG_RTPREF_RSV	0x10 /* 00010000 */

#define nd_ra_router_lifetime	nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit {	/* neighbor solicitation */
	struct icmp6_hdr	nd_ns_hdr;
	struct in6_addr		nd_ns_target;	/*target address */
	/* could be followed by options */
} __packed;

#define nd_ns_type		nd_ns_hdr.icmp6_type
#define nd_ns_code		nd_ns_hdr.icmp6_code
#define nd_ns_cksum		nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved		nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert {	/* neighbor advertisement */
	struct icmp6_hdr	nd_na_hdr;
	struct in6_addr		nd_na_target;	/* target address */
	/* could be followed by options */
} __packed;

#define nd_na_type		nd_na_hdr.icmp6_type
#define nd_na_code		nd_na_hdr.icmp6_code
#define nd_na_cksum		nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved	nd_na_hdr.icmp6_data32[0]
#define ND_NA_FLAG_ROUTER		0x80
#define ND_NA_FLAG_SOLICITED		0x40
#define ND_NA_FLAG_OVERRIDE		0x20

struct nd_redirect {		/* redirect */
	struct icmp6_hdr	nd_rd_hdr;
	struct in6_addr		nd_rd_target;	/* target address */
	struct in6_addr		nd_rd_dst;	/* destination address */
	/* could be followed by options */
} __packed;

#define nd_rd_type		nd_rd_hdr.icmp6_type
#define nd_rd_code		nd_rd_hdr.icmp6_code
#define nd_rd_cksum		nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved		nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr {		/* Neighbor discovery option header */
	u_int8_t	nd_opt_type;
	u_int8_t	nd_opt_len;
	/* followed by option specific data*/
} __packed;

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5
#define ND_OPT_ADVINTERVAL		7
#define ND_OPT_HOMEAGENT_INFO		8
#define ND_OPT_SOURCE_ADDRLIST		9
#define ND_OPT_TARGET_ADDRLIST		10
#define ND_OPT_MAP			23	/* RFC 5380 */
#define ND_OPT_ROUTE_INFO		24	/* RFC 4191 */
#define ND_OPT_RDNSS			25	/* RFC 6016 */
#define ND_OPT_DNSSL			31	/* RFC 6016 */
#define ND_OPT_CAPTIVE_PORTAL		37	/* RFC 7710 */
#define ND_OPT_PREF64			38	/* RFC-ietf-6man-ra-pref64-09 */

struct nd_opt_route_info {	/* route info */
	u_int8_t	nd_opt_rti_type;
	u_int8_t	nd_opt_rti_len;
	u_int8_t	nd_opt_rti_prefixlen;
	u_int8_t	nd_opt_rti_flags;
	u_int32_t	nd_opt_rti_lifetime;
	/* prefix follows */
};

struct nd_opt_prefix_info {	/* prefix information */
	u_int8_t	nd_opt_pi_type;
	u_int8_t	nd_opt_pi_len;
	u_int8_t	nd_opt_pi_prefix_len;
	u_int8_t	nd_opt_pi_flags_reserved;
	u_int32_t	nd_opt_pi_valid_time;
	u_int32_t	nd_opt_pi_preferred_time;
	u_int32_t	nd_opt_pi_reserved2;
	struct in6_addr	nd_opt_pi_prefix;
} __packed;

#define ND_OPT_PI_FLAG_ONLINK		0x80
#define ND_OPT_PI_FLAG_AUTO		0x40

struct nd_opt_rd_hdr {		/* redirected header */
	u_int8_t	nd_opt_rh_type;
	u_int8_t	nd_opt_rh_len;
	u_int16_t	nd_opt_rh_reserved1;
	u_int32_t	nd_opt_rh_reserved2;
	/* followed by IP header and data */
} __packed;

struct nd_opt_mtu {		/* MTU option */
	u_int8_t	nd_opt_mtu_type;
	u_int8_t	nd_opt_mtu_len;
	u_int16_t	nd_opt_mtu_reserved;
	u_int32_t	nd_opt_mtu_mtu;
} __packed;

struct nd_opt_rdnss {		/* RDNSS option RFC 6106 */
	u_int8_t	nd_opt_rdnss_type;
	u_int8_t	nd_opt_rdnss_len;
	u_int16_t	nd_opt_rdnss_reserved;
	u_int32_t	nd_opt_rdnss_lifetime;
	/* followed by list of IP prefixes */
} __packed;

struct nd_opt_dnssl {		/* DNSSL option RFC 6106 */
	u_int8_t	nd_opt_dnssl_type;
	u_int8_t	nd_opt_dnssl_len;
	u_int16_t	nd_opt_dnssl_reserved;
	u_int32_t	nd_opt_dnssl_lifetime;
	/* followed by list of IP prefixes */
} __packed;

struct nd_opt_captive_portal {	/* CAPTIVE PORTAL option RFC 7710 */
	u_int8_t	nd_opt_captive_portal_type;   // ND_OPT_CAPTIVE_PORTAL
	u_int8_t	nd_opt_captive_portal_len;    // in 8 byte units
	u_int8_t	nd_opt_captive_portal_uri[];  // 6 + n*8 bytes
} __packed;

struct nd_opt_pref64 {		/* PREF64 option RFC-ietf-6man-ra-pref64-09 */
	u_int8_t	nd_opt_pref64_type;          // ND_OPT_PREF64
	u_int8_t	nd_opt_pref64_len;           // 8 byte units, thus '2'
	u_int16_t	nd_opt_pref64_lifetime_plc;  // net endian, 13 + 3 bits
	u_int8_t	nd_opt_pref64_prefix[12];    // top 96 bits
} __packed;

/*
 * icmp6 namelookup
 */

struct icmp6_namelookup {
	struct icmp6_hdr 	icmp6_nl_hdr;
	u_int8_t	icmp6_nl_nonce[8];
	int32_t		icmp6_nl_ttl;
#if 0
	u_int8_t	icmp6_nl_len;
	u_int8_t	icmp6_nl_name[3];
#endif
	/* could be followed by options */
} __packed;

/*
 * icmp6 node information
 */
struct icmp6_nodeinfo {
	struct icmp6_hdr icmp6_ni_hdr;
	u_int8_t icmp6_ni_nonce[8];
	/* could be followed by reply data */
} __packed;

/*
 * BEGIN android-removed: glibc doesn't have these, and external/ping declares them itself.
#define ni_type		icmp6_ni_hdr.icmp6_type
#define ni_code		icmp6_ni_hdr.icmp6_code
#define ni_cksum	icmp6_ni_hdr.icmp6_cksum
#define ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
#define ni_flags	icmp6_ni_hdr.icmp6_data16[1]
 * END android-removed
 */

#define NI_QTYPE_NOOP		0 /* NOOP  */
#define NI_QTYPE_SUPTYPES	1 /* Supported Qtypes */
#define NI_QTYPE_FQDN		2 /* FQDN (draft 04) */
#define NI_QTYPE_DNSNAME	2 /* DNS Name */
#define NI_QTYPE_NODEADDR	3 /* Node Addresses */
#define NI_QTYPE_IPV4ADDR	4 /* IPv4 Addresses */

#define NI_SUPTYPE_FLAG_COMPRESS	0x0100
#define NI_FQDN_FLAG_VALIDTTL		0x0100

#ifdef NAME_LOOKUPS_04
#define NI_NODEADDR_FLAG_LINKLOCAL	0x0100
#define NI_NODEADDR_FLAG_SITELOCAL	0x0200
#define NI_NODEADDR_FLAG_GLOBAL		0x0400
#define NI_NODEADDR_FLAG_ALL		0x0800
#define NI_NODEADDR_FLAG_TRUNCATE	0x1000
#define NI_NODEADDR_FLAG_ANYCAST	0x2000 /* just experimental. not in spec */
#else  /* draft-ietf-ipngwg-icmp-name-lookups-05 (and later?) */
#define NI_NODEADDR_FLAG_TRUNCATE	0x0100
#define NI_NODEADDR_FLAG_ALL		0x0200
#define NI_NODEADDR_FLAG_COMPAT		0x0400
#define NI_NODEADDR_FLAG_LINKLOCAL	0x0800
#define NI_NODEADDR_FLAG_SITELOCAL	0x1000
#define NI_NODEADDR_FLAG_GLOBAL		0x2000
#define NI_NODEADDR_FLAG_ANYCAST	0x4000 /* just experimental. not in spec */
#endif

struct ni_reply_fqdn {
	u_int32_t ni_fqdn_ttl;	/* TTL */
	u_int8_t ni_fqdn_namelen; /* length in octets of the FQDN */
	u_int8_t ni_fqdn_name[3]; /* XXX: alignment */
} __packed;

/*
 * Router Renumbering. as router-renum-08.txt
 */
struct icmp6_router_renum {	/* router renumbering header */
	struct icmp6_hdr	rr_hdr;
	u_int8_t	rr_segnum;
	u_int8_t	rr_flags;
	u_int16_t	rr_maxdelay;
	u_int32_t	rr_reserved;
} __packed;

#define ICMP6_RR_FLAGS_TEST		0x80
#define ICMP6_RR_FLAGS_REQRESULT	0x40
#define ICMP6_RR_FLAGS_FORCEAPPLY	0x20
#define ICMP6_RR_FLAGS_SPECSITE		0x10
#define ICMP6_RR_FLAGS_PREVDONE		0x08

#define rr_type		rr_hdr.icmp6_type
#define rr_code		rr_hdr.icmp6_code
#define rr_cksum	rr_hdr.icmp6_cksum
#define rr_seqnum 	rr_hdr.icmp6_data32[0]

struct rr_pco_match {		/* match prefix part */
	u_int8_t	rpm_code;
	u_int8_t	rpm_len;
	u_int8_t	rpm_ordinal;
	u_int8_t	rpm_matchlen;
	u_int8_t	rpm_minlen;
	u_int8_t	rpm_maxlen;
	u_int16_t	rpm_reserved;
	struct	in6_addr	rpm_prefix;
} __packed;

#define RPM_PCO_ADD		1
#define RPM_PCO_CHANGE		2
#define RPM_PCO_SETGLOBAL	3
#define RPM_PCO_MAX		4

struct rr_pco_use {		/* use prefix part */
	u_int8_t	rpu_uselen;
	u_int8_t	rpu_keeplen;
	u_int8_t	rpu_ramask;
	u_int8_t	rpu_raflags;
	u_int32_t	rpu_vltime;
	u_int32_t	rpu_pltime;
	u_int32_t	rpu_flags;
	struct	in6_addr rpu_prefix;
} __packed;
#define ICMP6_RR_PCOUSE_RAFLAGS_ONLINK	0x80
#define ICMP6_RR_PCOUSE_RAFLAGS_AUTO	0x40

#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME     0x80
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME     0x40

struct rr_result {		/* router renumbering result message */
	u_int16_t	rrr_flags;
	u_int8_t	rrr_ordinal;
	u_int8_t	rrr_matchedlen;
	u_int32_t	rrr_ifid;
	struct	in6_addr rrr_prefix;
} __packed;
#define ICMP6_RR_RESULT_FLAGS_OOB		0x0200
#define ICMP6_RR_RESULT_FLAGS_FORBIDDEN		0x0100

/*
 * icmp6 filter structures.
 */

struct icmp6_filter {
	u_int32_t icmp6_filt[8];
};

/*
 * BEGIN android-changed
 * Linux and *BSD kernels use opposite values to indicate pass/block in ICMPv6
 * filters, and assign a different value to the ICMP6_FILTER sockopt.
 */
#define ICMP6_FILTER 1

#define	ICMP6_FILTER_SETPASSALL(filterp) \
	(void)memset(filterp, 0x00, sizeof(struct icmp6_filter))
#define	ICMP6_FILTER_SETBLOCKALL(filterp) \
	(void)memset(filterp, 0xff, sizeof(struct icmp6_filter))
#define	ICMP6_FILTER_SETPASS(type, filterp) \
	(((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31)))
#define	ICMP6_FILTER_SETBLOCK(type, filterp) \
	(((filterp)->icmp6_filt[(type) >> 5]) |= (1 << ((type) & 31)))
#define	ICMP6_FILTER_WILLPASS(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) == 0)
#define	ICMP6_FILTER_WILLBLOCK(type, filterp) \
	((((filterp)->icmp6_filt[(type) >> 5]) & (1 << ((type) & 31))) != 0)
/*
 * END android-changed
 */

#endif /* !_NETINET_ICMP6_H_ */
```