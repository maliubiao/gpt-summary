Response:
Let's break down the thought process for answering the request about the `pfkeyv2.h` header file.

**1. Understanding the Core Request:**

The primary goal is to analyze a Linux kernel header file related to `pfkeyv2` within the Android bionic library and explain its functionality, relevance to Android, and related technical details. The request specifically asks for explanations of libc functions, dynamic linking aspects, error examples, and how Android framework/NDK interacts with this code. It also wants a Frida hook example.

**2. Initial Analysis of the Header File:**

* **`#ifndef _LINUX_PFKEY2_H` and `#define _LINUX_PFKEY2_H`:** This is a standard include guard, indicating this file defines structures and constants related to `PFKEYv2`.
* **`#include <linux/types.h>`:**  This confirms it's a kernel header file, relying on basic Linux type definitions.
* **`#define PF_KEY_V2 2` and `#define PFKEYV2_REVISION 199806L`:** These are constant definitions, suggesting this is a specific version of the PF_KEY protocol.
* **`struct sadb_*` definitions:** The bulk of the file consists of structure definitions starting with `sadb_`. The names are suggestive (e.g., `sadb_msg`, `sadb_sa`, `sadb_address`, `sadb_key`). The `__attribute__((packed))` indicates that the compiler should not add padding between structure members, which is important for network protocol data.
* **`#define SADB_*` definitions:** A large number of constant definitions starting with `SADB_`. These seem to represent message types, flags, states, types of algorithms, and extension types.

**3. Identifying the Core Functionality:**

Based on the structure and constant names, the core functionality revolves around **IPsec key management**. The "SA" in `sadb_` likely stands for Security Association, a core concept in IPsec. The different structures seem to represent different parts of an SA or related messages.

**4. Addressing Specific Questions:**

* **功能 (Functionality):**  The main function is defining the data structures and constants used for interacting with the Linux kernel's IPsec key management subsystem via the PF_KEYv2 protocol. This involves creating, modifying, querying, and deleting Security Associations.

* **与 Android 的关系 (Relationship with Android):** Android uses IPsec for VPN functionality and potentially for other secure communication. This header file is crucial for user-space applications or libraries (likely within the Android system) that need to interact with the kernel's IPsec implementation. A concrete example is the Android VPN client.

* **libc 函数功能实现 (libc Function Implementations):** This header file *doesn't* define libc functions. It defines *data structures* used *by* libc functions (and potentially other libraries). It's important to make this distinction clear. The relevant libc functions would be those dealing with socket communication, particularly raw sockets, which are used to send and receive PF_KEY messages. Examples are `socket()`, `bind()`, `sendto()`, `recvfrom()`. Explaining their implementation would involve delving into the kernel's socket layer.

* **dynamic linker 功能 (Dynamic Linker Functionality):** This header file itself doesn't directly involve the dynamic linker. It's a header file that gets included during compilation. Libraries that *use* these structures and constants (like a VPN client library) would be linked using the dynamic linker. The explanation should focus on how the library would be laid out in memory (`.so` structure) and the linking process (symbol resolution).

* **逻辑推理 (Logical Deduction):**  The structures and constants suggest a request-response pattern. A user-space process sends a message (e.g., `SADB_GETSPI`) with specific data structures filled in, and the kernel responds with another message. The example provided shows a request to get a Security Parameter Index (SPI).

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Common errors would involve incorrect structure packing, wrong byte order (network byte order), invalid message types, incorrect lengths, and not handling potential errors from socket operations.

* **Android Framework/NDK 到达这里的步骤 (Steps from Android Framework/NDK):** This requires tracing the path from a high-level Android API (like the `VpnService`) down to the system calls that would eventually involve PF_KEYv2. The explanation should highlight the layers involved: Java framework, native libraries, and finally, system calls interacting with the kernel.

* **Frida Hook 示例 (Frida Hook Example):** The example should target a system call that would likely be used in conjunction with PF_KEYv2, such as `sendto` or `recvfrom`, demonstrating how to inspect the data being exchanged.

**5. Structuring the Answer:**

A logical structure is important for clarity:

* **Introduction:** Briefly explain the file's location and purpose.
* **功能 (Functionality):**  Describe the core purpose related to IPsec key management.
* **与 Android 的关系 (Relationship with Android):**  Provide examples of how Android uses this (VPN being the most prominent).
* **libc 函数功能实现 (libc Function Implementations):** Explain that this file defines structures, not libc functions, and then discuss relevant libc functions for socket communication.
* **dynamic linker 功能 (Dynamic Linker Functionality):** Explain the role of the dynamic linker in linking libraries that use this header.
* **逻辑推理 (Logical Deduction):**  Illustrate the request-response pattern with an example.
* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Provide concrete examples of potential errors.
* **Android Framework/NDK 到达这里的步骤 (Steps from Android Framework/NDK):** Trace the path from high-level APIs to the kernel.
* **Frida Hook 示例 (Frida Hook Example):** Provide a practical Frida code snippet.

**6. Refinement and Language:**

* Use clear and concise language.
* Explain technical terms (like IPsec, Security Association, SPI).
* Provide specific examples where possible.
* Ensure the Chinese translation is accurate and natural.

By following these steps, the comprehensive and informative answer provided in the initial example can be constructed. The key is to systematically break down the request, analyze the provided code, and connect the technical details to the broader context of Android and system programming.
这是一个定义了Linux内核中PF_KEY v2协议相关数据结构和常量的头文件。它位于Android bionic库中，表明Android系统内部也使用了这个协议或其相关功能。

**功能列举：**

该头文件定义了用于与内核IPsec（Internet Protocol Security）子系统进行通信的数据结构和常量。PF_KEY v2 协议是用户空间程序与内核空间IPsec实现交互的标准方式。其主要功能包括：

1. **定义消息结构 (`sadb_msg`)**:  这是所有PF_KEY v2消息的基础结构，包含了消息的版本、类型、错误码、安全联盟类型、长度、序列号和进程ID等信息。

2. **定义扩展结构 (`sadb_ext`)**: 用于定义附加到消息上的各种扩展信息，例如安全联盟参数、密钥、地址等。

3. **定义安全联盟（Security Association, SA）相关结构 (`sadb_sa`)**: 描述了一个安全联盟的关键属性，如SPI（Security Parameter Index）、重放窗口大小、状态、认证和加密算法等。

4. **定义生命周期结构 (`sadb_lifetime`)**:  描述安全联盟的有效期限，包括分配次数、字节数、添加时间和使用时间等。

5. **定义地址结构 (`sadb_address`)**:  描述通信双方的IP地址和前缀长度。

6. **定义密钥结构 (`sadb_key`)**:  用于协商或传递加密和认证密钥。

7. **定义身份结构 (`sadb_ident`)**:  用于标识通信双方的身份。

8. **定义敏感度标签结构 (`sadb_sens`)**:  用于携带安全策略数据库（SPD）中的敏感度信息。

9. **定义提议结构 (`sadb_prop`)**:  用于在协商过程中提出安全协议和算法。

10. **定义组合结构 (`sadb_comb`)**:  用于指定可接受的认证和加密算法组合。

11. **定义支持的算法结构 (`sadb_supported`, `sadb_alg`)**:  用于查询内核支持的认证和加密算法。

12. **定义SPI范围结构 (`sadb_spirange`)**:  用于请求内核分配特定范围内的SPI。

13. **定义扩展的私有信息结构 (`sadb_x_kmprivate`)**:  用于传递内核模块私有的信息。

14. **定义扩展的安全联盟信息结构 (`sadb_x_sa2`)**:  包含额外的安全联盟信息，例如模式、序列号和请求ID。

15. **定义扩展的策略信息结构 (`sadb_x_policy`)**:  包含与安全策略数据库相关的策略信息。

16. **定义扩展的IPsec请求信息结构 (`sadb_x_ipsecrequest`)**:  描述IPsec协议请求的参数。

17. **定义扩展的NAT-T相关结构 (`sadb_x_nat_t_type`, `sadb_x_nat_t_port`)**:  用于处理网络地址转换遍历（NAT Traversal）相关的信息。

18. **定义扩展的安全上下文结构 (`sadb_x_sec_ctx`)**:  用于传递安全上下文信息。

19. **定义扩展的密钥管理地址结构 (`sadb_x_kmaddress`)**:  用于传递密钥管理相关的地址信息。

20. **定义扩展的过滤器结构 (`sadb_x_filter`)**:  用于定义安全策略数据库中的过滤器规则。

21. **定义消息类型常量 (`SADB_GETSPI`, `SADB_UPDATE`, etc.)**:  定义了各种PF_KEY v2消息的类型，例如获取SPI、更新SA、添加SA、删除SA等。

22. **定义安全联盟标志常量 (`SADB_SAFLAGS_PFS`, etc.)**:  定义了安全联盟的各种标志。

23. **定义安全联盟状态常量 (`SADB_SASTATE_LARVAL`, etc.)**:  定义了安全联盟的生命周期状态。

24. **定义安全联盟类型常量 (`SADB_SATYPE_AH`, `SADB_SATYPE_ESP`, etc.)**:  定义了不同的安全协议类型，例如AH（Authentication Header）、ESP（Encapsulating Security Payload）等。

25. **定义认证算法常量 (`SADB_AALG_MD5HMAC`, etc.)**:  定义了各种可用的认证算法。

26. **定义加密算法常量 (`SADB_EALG_DESCBC`, etc.)**:  定义了各种可用的加密算法。

27. **定义压缩算法常量 (`SADB_X_CALG_DEFLATE`, etc.)**: 定义了可用的压缩算法。

28. **定义扩展类型常量 (`SADB_EXT_SA`, `SADB_EXT_ADDRESS_SRC`, etc.)**:  定义了各种扩展信息的类型。

29. **定义身份类型常量 (`SADB_IDENTTYPE_PREFIX`, etc.)**: 定义了身份信息的类型。

**与 Android 功能的关系及举例：**

PF_KEY v2 协议与 Android 的 IPsec VPN 功能紧密相关。Android 系统需要与内核交互来建立、维护和删除 IPsec 连接。

* **VPN 连接建立**: 当用户在 Android 设备上配置并连接 VPN 时，Android 的 VPN 客户端（通常是 system server 中的一部分或一个独立的 VPN 应用）会使用 PF_KEY v2 协议向内核发送消息，请求建立 IPsec 安全联盟（SA）。这涉及到使用 `SADB_GETSPI` 获取 SPI，使用 `SADB_ADD` 添加 SA，并使用相关的 `sadb_*` 结构体传递加密、认证算法、密钥等参数。
* **VPN 连接维护**:  Android 系统可能需要定期更新密钥或重新协商安全联盟。这也会通过 PF_KEY v2 协议的消息进行，例如使用 `SADB_UPDATE`。
* **VPN 连接断开**: 当 VPN 连接断开时，Android 系统会使用 `SADB_DELETE` 消息通知内核删除相应的安全联盟。
* **IPsec Policy 管理**: Android 可能需要管理 IPsec 策略，例如指定哪些流量应该使用 IPsec 保护。这可能涉及到 `SADB_X_SPDADD`、`SADB_X_SPDDELETE` 等消息。

**libc 函数的功能实现：**

这个头文件本身并没有定义 libc 函数。它定义的是内核接口的数据结构和常量。用户空间的程序需要使用 libc 提供的 socket 相关函数，特别是 **`socket()`** 和 **`sendto()`/`recvfrom()`**，来与内核的 PF_KEY v2 接口进行通信。

* **`socket()`**: 用于创建一个 socket 文件描述符。对于 PF_KEY v2，需要使用 `PF_KEY` 协议族和 `SOCK_RAW` socket 类型。
    * **实现简述**:  `socket()` 系统调用最终会陷入内核，调用内核中 socket 子系统的实现。内核会分配一个 socket 数据结构，初始化相关成员，并返回一个文件描述符。对于 `PF_KEY` 协议族，内核会关联相应的 PF_KEY 协议处理函数。
* **`sendto()`**: 用于向指定的 socket 发送数据报。对于 PF_KEY v2，发送的数据就是按照 `sadb_*` 结构体组织的消息。
    * **实现简述**: `sendto()` 系统调用将用户空间的数据拷贝到内核空间，然后调用与 socket 关联的协议处理函数的发送例程。对于 PF_KEY，内核会将消息传递给 IPsec 子系统进行处理。
* **`recvfrom()`**: 用于从指定的 socket 接收数据报。对于 PF_KEY v2，接收的数据是内核对用户空间请求的响应消息。
    * **实现简述**: `recvfrom()` 系统调用会等待 socket 接收到数据。当内核的 IPsec 子系统有响应消息需要发送给用户空间时，内核会将数据拷贝到用户空间提供的缓冲区中。

**涉及 dynamic linker 的功能：**

这个头文件本身并不直接涉及 dynamic linker 的功能。它是一个会被编译到使用 PF_KEY v2 协议的程序或库中的头文件。dynamic linker 的作用在于链接这些使用了该头文件的库，并在运行时加载它们。

**so 布局样本：**

假设有一个名为 `libipsec_client.so` 的共享库，它使用了 `pfkeyv2.h` 中定义的结构和常量来与内核进行 IPsec 通信。其布局可能如下：

```
libipsec_client.so:
    .text          # 包含代码段，例如调用 socket(), sendto() 等操作 PF_KEY v2 的代码
    .rodata        # 包含只读数据，可能包含一些 PF_KEY v2 相关的常量
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .dynsym        # 动态符号表，列出库提供的和需要的符号
    .dynstr        # 动态字符串表，包含符号名称的字符串
    .plt           # 程序链接表，用于延迟绑定
    .got.plt       # 全局偏移量表，用于存储外部符号的地址
    ...           # 其他段
```

**链接的处理过程：**

1. **编译时**: 当编译 `libipsec_client.so` 的源文件时，编译器会包含 `pfkeyv2.h` 头文件，从而知道 `sadb_*` 结构体和常量的定义。
2. **链接时**: 静态链接器会将 `libipsec_client.so` 依赖的 libc 符号（例如 `socket`, `sendto`）标记为需要动态链接。
3. **运行时**: 当一个进程（例如 VPN 客户端应用）加载 `libipsec_client.so` 时，dynamic linker（在 Android 上通常是 `linker64` 或 `linker`）会执行以下步骤：
    * **加载共享库**: 将 `libipsec_client.so` 加载到进程的地址空间。
    * **解析依赖**: 确定 `libipsec_client.so` 依赖的其他共享库，通常是 `libc.so`。
    * **加载依赖库**: 将依赖的共享库也加载到进程的地址空间。
    * **符号解析**:  遍历 `libipsec_client.so` 的 `.dynsym` 表，找到需要解析的外部符号（例如 `socket`, `sendto`）。在依赖库（`libc.so`）的符号表中查找这些符号的地址，并更新 `libipsec_client.so` 的 `.got.plt` 表。
    * **重定位**: 调整 `libipsec_client.so` 中使用到外部符号地址的代码，使其指向 `.got.plt` 表中的正确地址。

这样，当 `libipsec_client.so` 中的代码调用 `socket()` 或 `sendto()` 时，实际上会通过 `.plt` 表跳转到 `.got.plt` 表中存储的 `libc.so` 中相应函数的地址。

**假设输入与输出（逻辑推理）：**

假设一个用户空间程序想要获取一个用于 ESP 协议的安全联盟的 SPI。

**假设输入：**

* 程序创建了一个 `PF_KEY` 类型的 `SOCK_RAW` socket。
* 程序构造了一个 `sadb_msg` 结构体，设置 `sadb_msg_type` 为 `SADB_GETSPI`，`sadb_msg_satype` 为 `SADB_SATYPE_ESP`。
* 程序可能还会附加其他扩展结构，例如 `sadb_address` 来指定源和目标地址。

**预期输出：**

* 内核收到 `SADB_GETSPI` 消息后，会查找或生成一个可用的 SPI。
* 内核会返回一个 `sadb_msg` 结构体，设置 `sadb_msg_type` 为相应的响应类型（通常与请求类型相同，但可能包含错误信息），并在附加的 `sadb_sa` 结构体中包含分配的 SPI。

**用户或者编程常见的使用错误：**

1. **字节序错误**: PF_KEY v2 协议中某些字段（例如 SPI）使用网络字节序（大端序），而主机字节序可能不同。如果程序没有正确地进行字节序转换（例如使用 `htonl` 和 `ntohl`），会导致内核解析错误。
    ```c
    struct sadb_sa sa;
    sa.sadb_sa_spi = 12345; // 错误：这里应该是网络字节序
    sa.sadb_sa_spi = htonl(12345); // 正确
    ```

2. **结构体长度错误**: `sadb_msg_len` 和扩展结构体的长度字段必须正确设置，否则内核可能无法正确解析消息。
    ```c
    struct sadb_msg msg;
    msg.sadb_msg_len = sizeof(struct sadb_msg); // 忘记计算扩展结构的长度
    // ... 添加扩展结构
    msg.sadb_msg_len = sizeof(struct sadb_msg) + sizeof(struct sadb_sa); // 正确
    ```

3. **消息类型错误**: 发送不支持或不期望的消息类型会导致内核返回错误。查阅内核文档以了解支持的消息序列和类型。

4. **状态不一致**:  在不正确的状态下尝试执行某些操作（例如，在 SA 建立之前尝试更新 SA）会导致错误。

5. **权限不足**:  操作 PF_KEY socket 通常需要 root 权限或者特定的 capabilities。普通应用可能无法直接操作。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **Android Framework (Java 层)**: 用户发起 VPN 连接请求，例如通过 Settings 应用或第三方 VPN 应用。这会调用 Android Framework 提供的 VPN 相关 API，例如 `VpnService.Builder` 等。

2. **System Server (Java/Native)**: Android Framework 将 VPN 连接请求传递给 System Server 中的 VPN 子系统。System Server 负责管理系统级的服务，包括 VPN 连接。

3. **Native VPN Service/Library (C/C++)**: System Server 中的 VPN 子系统通常会调用底层的 Native 代码来实现 VPN 的具体功能。这部分 Native 代码可能会使用 NDK 提供的接口，例如 socket 相关的函数。

4. **使用 libc 函数 (socket, sendto, recvfrom)**: Native 代码会使用 libc 提供的 `socket()` 函数创建一个 `PF_KEY` 类型的 socket，然后使用 `sendto()` 函数构造并发送 PF_KEY v2 消息到内核，使用 `recvfrom()` 接收内核的响应。

5. **内核 PF_KEY v2 接口**: 内核接收到 PF_KEY v2 消息后，会根据消息类型调用相应的处理函数。这些处理函数会操作内核的 IPsec 子系统，例如创建、更新或删除安全联盟。

**Frida Hook 示例调试这些步骤：**

可以使用 Frida Hook `sendto` 系统调用来观察 Android 系统发送的 PF_KEY v2 消息。

```python
import frida
import struct

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] sendto called")
        # 假设目标是 PF_KEY socket (需要根据实际情况判断)
        if data:
            # 解析 sadb_msg 结构
            sadb_msg_format = "<BBHHL"
            sadb_msg_size = struct.calcsize(sadb_msg_format)
            if len(data) >= sadb_msg_size:
                sadb_msg_data = struct.unpack(sadb_msg_format, data[:sadb_msg_size])
                print(f"    sadb_msg_version: {sadb_msg_data[0]}")
                print(f"    sadb_msg_type: {sadb_msg_data[1]}")
                # 可以根据 sadb_msg_type 继续解析后续的扩展结构

def main():
    device = frida.get_usb_device()
    pid = device.spawn(["com.android.settings"]) # 替换为目标进程，例如 VPN 应用或 system_server
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "sendto"), {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
                if (this.len > 0) {
                    var data = this.buf.readByteArray(this.len);
                    send({type: 'send'}, data);
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input()
    session.detach()

if __name__ == "__main__":
    main()
```

**说明：**

1. **目标进程**: 需要确定哪个进程发送 PF_KEY v2 消息。对于 VPN 连接，可能是 System Server 或特定的 VPN 应用。
2. **Hook `sendto`**:  Hook `sendto` 系统调用可以捕获所有发送到 socket 的数据。
3. **判断 PF_KEY Socket**: 需要通过其他方式（例如查看 socket 的文件描述符信息）来判断捕获的 `sendto` 调用是否针对 PF_KEY socket。
4. **解析数据**:  根据 PF_KEY v2 消息的结构（先解析 `sadb_msg`，然后根据 `sadb_msg_type` 和是否存在扩展头来解析后续结构），将捕获的字节流解析成有意义的数据。
5. **权限**: 运行 Frida 脚本可能需要 root 权限。

通过这个 Frida Hook 示例，可以在 Android 系统建立 VPN 连接的过程中，观察到发送到内核的 PF_KEY v2 消息，从而理解 Android 系统如何与内核 IPsec 子系统交互。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/pfkeyv2.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_PFKEY2_H
#define _LINUX_PFKEY2_H
#include <linux/types.h>
#define PF_KEY_V2 2
#define PFKEYV2_REVISION 199806L
struct sadb_msg {
  __u8 sadb_msg_version;
  __u8 sadb_msg_type;
  __u8 sadb_msg_errno;
  __u8 sadb_msg_satype;
  __u16 sadb_msg_len;
  __u16 sadb_msg_reserved;
  __u32 sadb_msg_seq;
  __u32 sadb_msg_pid;
} __attribute__((packed));
struct sadb_ext {
  __u16 sadb_ext_len;
  __u16 sadb_ext_type;
} __attribute__((packed));
struct sadb_sa {
  __u16 sadb_sa_len;
  __u16 sadb_sa_exttype;
  __be32 sadb_sa_spi;
  __u8 sadb_sa_replay;
  __u8 sadb_sa_state;
  __u8 sadb_sa_auth;
  __u8 sadb_sa_encrypt;
  __u32 sadb_sa_flags;
} __attribute__((packed));
struct sadb_lifetime {
  __u16 sadb_lifetime_len;
  __u16 sadb_lifetime_exttype;
  __u32 sadb_lifetime_allocations;
  __u64 sadb_lifetime_bytes;
  __u64 sadb_lifetime_addtime;
  __u64 sadb_lifetime_usetime;
} __attribute__((packed));
struct sadb_address {
  __u16 sadb_address_len;
  __u16 sadb_address_exttype;
  __u8 sadb_address_proto;
  __u8 sadb_address_prefixlen;
  __u16 sadb_address_reserved;
} __attribute__((packed));
struct sadb_key {
  __u16 sadb_key_len;
  __u16 sadb_key_exttype;
  __u16 sadb_key_bits;
  __u16 sadb_key_reserved;
} __attribute__((packed));
struct sadb_ident {
  __u16 sadb_ident_len;
  __u16 sadb_ident_exttype;
  __u16 sadb_ident_type;
  __u16 sadb_ident_reserved;
  __u64 sadb_ident_id;
} __attribute__((packed));
struct sadb_sens {
  __u16 sadb_sens_len;
  __u16 sadb_sens_exttype;
  __u32 sadb_sens_dpd;
  __u8 sadb_sens_sens_level;
  __u8 sadb_sens_sens_len;
  __u8 sadb_sens_integ_level;
  __u8 sadb_sens_integ_len;
  __u32 sadb_sens_reserved;
} __attribute__((packed));
struct sadb_prop {
  __u16 sadb_prop_len;
  __u16 sadb_prop_exttype;
  __u8 sadb_prop_replay;
  __u8 sadb_prop_reserved[3];
} __attribute__((packed));
struct sadb_comb {
  __u8 sadb_comb_auth;
  __u8 sadb_comb_encrypt;
  __u16 sadb_comb_flags;
  __u16 sadb_comb_auth_minbits;
  __u16 sadb_comb_auth_maxbits;
  __u16 sadb_comb_encrypt_minbits;
  __u16 sadb_comb_encrypt_maxbits;
  __u32 sadb_comb_reserved;
  __u32 sadb_comb_soft_allocations;
  __u32 sadb_comb_hard_allocations;
  __u64 sadb_comb_soft_bytes;
  __u64 sadb_comb_hard_bytes;
  __u64 sadb_comb_soft_addtime;
  __u64 sadb_comb_hard_addtime;
  __u64 sadb_comb_soft_usetime;
  __u64 sadb_comb_hard_usetime;
} __attribute__((packed));
struct sadb_supported {
  __u16 sadb_supported_len;
  __u16 sadb_supported_exttype;
  __u32 sadb_supported_reserved;
} __attribute__((packed));
struct sadb_alg {
  __u8 sadb_alg_id;
  __u8 sadb_alg_ivlen;
  __u16 sadb_alg_minbits;
  __u16 sadb_alg_maxbits;
  __u16 sadb_alg_reserved;
} __attribute__((packed));
struct sadb_spirange {
  __u16 sadb_spirange_len;
  __u16 sadb_spirange_exttype;
  __u32 sadb_spirange_min;
  __u32 sadb_spirange_max;
  __u32 sadb_spirange_reserved;
} __attribute__((packed));
struct sadb_x_kmprivate {
  __u16 sadb_x_kmprivate_len;
  __u16 sadb_x_kmprivate_exttype;
  __u32 sadb_x_kmprivate_reserved;
} __attribute__((packed));
struct sadb_x_sa2 {
  __u16 sadb_x_sa2_len;
  __u16 sadb_x_sa2_exttype;
  __u8 sadb_x_sa2_mode;
  __u8 sadb_x_sa2_reserved1;
  __u16 sadb_x_sa2_reserved2;
  __u32 sadb_x_sa2_sequence;
  __u32 sadb_x_sa2_reqid;
} __attribute__((packed));
struct sadb_x_policy {
  __u16 sadb_x_policy_len;
  __u16 sadb_x_policy_exttype;
  __u16 sadb_x_policy_type;
  __u8 sadb_x_policy_dir;
  __u8 sadb_x_policy_reserved;
  __u32 sadb_x_policy_id;
  __u32 sadb_x_policy_priority;
} __attribute__((packed));
struct sadb_x_ipsecrequest {
  __u16 sadb_x_ipsecrequest_len;
  __u16 sadb_x_ipsecrequest_proto;
  __u8 sadb_x_ipsecrequest_mode;
  __u8 sadb_x_ipsecrequest_level;
  __u16 sadb_x_ipsecrequest_reserved1;
  __u32 sadb_x_ipsecrequest_reqid;
  __u32 sadb_x_ipsecrequest_reserved2;
} __attribute__((packed));
struct sadb_x_nat_t_type {
  __u16 sadb_x_nat_t_type_len;
  __u16 sadb_x_nat_t_type_exttype;
  __u8 sadb_x_nat_t_type_type;
  __u8 sadb_x_nat_t_type_reserved[3];
} __attribute__((packed));
struct sadb_x_nat_t_port {
  __u16 sadb_x_nat_t_port_len;
  __u16 sadb_x_nat_t_port_exttype;
  __be16 sadb_x_nat_t_port_port;
  __u16 sadb_x_nat_t_port_reserved;
} __attribute__((packed));
struct sadb_x_sec_ctx {
  __u16 sadb_x_sec_len;
  __u16 sadb_x_sec_exttype;
  __u8 sadb_x_ctx_alg;
  __u8 sadb_x_ctx_doi;
  __u16 sadb_x_ctx_len;
} __attribute__((packed));
struct sadb_x_kmaddress {
  __u16 sadb_x_kmaddress_len;
  __u16 sadb_x_kmaddress_exttype;
  __u32 sadb_x_kmaddress_reserved;
} __attribute__((packed));
struct sadb_x_filter {
  __u16 sadb_x_filter_len;
  __u16 sadb_x_filter_exttype;
  __u32 sadb_x_filter_saddr[4];
  __u32 sadb_x_filter_daddr[4];
  __u16 sadb_x_filter_family;
  __u8 sadb_x_filter_splen;
  __u8 sadb_x_filter_dplen;
} __attribute__((packed));
#define SADB_RESERVED 0
#define SADB_GETSPI 1
#define SADB_UPDATE 2
#define SADB_ADD 3
#define SADB_DELETE 4
#define SADB_GET 5
#define SADB_ACQUIRE 6
#define SADB_REGISTER 7
#define SADB_EXPIRE 8
#define SADB_FLUSH 9
#define SADB_DUMP 10
#define SADB_X_PROMISC 11
#define SADB_X_PCHANGE 12
#define SADB_X_SPDUPDATE 13
#define SADB_X_SPDADD 14
#define SADB_X_SPDDELETE 15
#define SADB_X_SPDGET 16
#define SADB_X_SPDACQUIRE 17
#define SADB_X_SPDDUMP 18
#define SADB_X_SPDFLUSH 19
#define SADB_X_SPDSETIDX 20
#define SADB_X_SPDEXPIRE 21
#define SADB_X_SPDDELETE2 22
#define SADB_X_NAT_T_NEW_MAPPING 23
#define SADB_X_MIGRATE 24
#define SADB_MAX 24
#define SADB_SAFLAGS_PFS 1
#define SADB_SAFLAGS_NOPMTUDISC 0x20000000
#define SADB_SAFLAGS_DECAP_DSCP 0x40000000
#define SADB_SAFLAGS_NOECN 0x80000000
#define SADB_SASTATE_LARVAL 0
#define SADB_SASTATE_MATURE 1
#define SADB_SASTATE_DYING 2
#define SADB_SASTATE_DEAD 3
#define SADB_SASTATE_MAX 3
#define SADB_SATYPE_UNSPEC 0
#define SADB_SATYPE_AH 2
#define SADB_SATYPE_ESP 3
#define SADB_SATYPE_RSVP 5
#define SADB_SATYPE_OSPFV2 6
#define SADB_SATYPE_RIPV2 7
#define SADB_SATYPE_MIP 8
#define SADB_X_SATYPE_IPCOMP 9
#define SADB_SATYPE_MAX 9
#define SADB_AALG_NONE 0
#define SADB_AALG_MD5HMAC 2
#define SADB_AALG_SHA1HMAC 3
#define SADB_X_AALG_SHA2_256HMAC 5
#define SADB_X_AALG_SHA2_384HMAC 6
#define SADB_X_AALG_SHA2_512HMAC 7
#define SADB_X_AALG_RIPEMD160HMAC 8
#define SADB_X_AALG_AES_XCBC_MAC 9
#define SADB_X_AALG_SM3_256HMAC 10
#define SADB_X_AALG_NULL 251
#define SADB_AALG_MAX 251
#define SADB_EALG_NONE 0
#define SADB_EALG_DESCBC 2
#define SADB_EALG_3DESCBC 3
#define SADB_X_EALG_CASTCBC 6
#define SADB_X_EALG_BLOWFISHCBC 7
#define SADB_EALG_NULL 11
#define SADB_X_EALG_AESCBC 12
#define SADB_X_EALG_AESCTR 13
#define SADB_X_EALG_AES_CCM_ICV8 14
#define SADB_X_EALG_AES_CCM_ICV12 15
#define SADB_X_EALG_AES_CCM_ICV16 16
#define SADB_X_EALG_AES_GCM_ICV8 18
#define SADB_X_EALG_AES_GCM_ICV12 19
#define SADB_X_EALG_AES_GCM_ICV16 20
#define SADB_X_EALG_CAMELLIACBC 22
#define SADB_X_EALG_NULL_AES_GMAC 23
#define SADB_X_EALG_SM4CBC 24
#define SADB_EALG_MAX 253
#define SADB_X_EALG_SERPENTCBC 252
#define SADB_X_EALG_TWOFISHCBC 253
#define SADB_X_CALG_NONE 0
#define SADB_X_CALG_OUI 1
#define SADB_X_CALG_DEFLATE 2
#define SADB_X_CALG_LZS 3
#define SADB_X_CALG_LZJH 4
#define SADB_X_CALG_MAX 4
#define SADB_EXT_RESERVED 0
#define SADB_EXT_SA 1
#define SADB_EXT_LIFETIME_CURRENT 2
#define SADB_EXT_LIFETIME_HARD 3
#define SADB_EXT_LIFETIME_SOFT 4
#define SADB_EXT_ADDRESS_SRC 5
#define SADB_EXT_ADDRESS_DST 6
#define SADB_EXT_ADDRESS_PROXY 7
#define SADB_EXT_KEY_AUTH 8
#define SADB_EXT_KEY_ENCRYPT 9
#define SADB_EXT_IDENTITY_SRC 10
#define SADB_EXT_IDENTITY_DST 11
#define SADB_EXT_SENSITIVITY 12
#define SADB_EXT_PROPOSAL 13
#define SADB_EXT_SUPPORTED_AUTH 14
#define SADB_EXT_SUPPORTED_ENCRYPT 15
#define SADB_EXT_SPIRANGE 16
#define SADB_X_EXT_KMPRIVATE 17
#define SADB_X_EXT_POLICY 18
#define SADB_X_EXT_SA2 19
#define SADB_X_EXT_NAT_T_TYPE 20
#define SADB_X_EXT_NAT_T_SPORT 21
#define SADB_X_EXT_NAT_T_DPORT 22
#define SADB_X_EXT_NAT_T_OA 23
#define SADB_X_EXT_SEC_CTX 24
#define SADB_X_EXT_KMADDRESS 25
#define SADB_X_EXT_FILTER 26
#define SADB_EXT_MAX 26
#define SADB_IDENTTYPE_RESERVED 0
#define SADB_IDENTTYPE_PREFIX 1
#define SADB_IDENTTYPE_FQDN 2
#define SADB_IDENTTYPE_USERFQDN 3
#define SADB_IDENTTYPE_MAX 3
#endif

"""

```