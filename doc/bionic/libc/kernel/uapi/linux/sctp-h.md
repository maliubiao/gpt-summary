Response:
Let's break down the thought process for answering this complex question about the `sctp.h` header file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C header file, `sctp.h`, located within the Android bionic library. The core goal is to explain its purpose, how it relates to Android, its internal workings (as much as possible from the header), common errors, and how Android utilizes it. Frida hooking is also requested.

**2. Initial Scan and Keyword Identification:**

First, I'd scan the header file looking for key terms and patterns. Immediately, "SCTP" stands out as the central theme. Other important terms include:

* `_UAPI_`: This strongly suggests a userspace API header, designed to expose kernel functionality to user programs.
* `linux/types.h`, `linux/socket.h`: Standard Linux headers indicating network and type definitions.
* `typedef`, `struct`, `enum`, `#define`:  C language constructs for defining types, structures, enumerations, and constants.
* Names like `SCTP_RTOINFO`, `SCTP_ASSOCINFO`, etc.: These look like SCTP-specific options and parameters.
* Structures like `sctp_initmsg`, `sctp_sndrcvinfo`: These likely represent data structures used in SCTP communication.
* `MSG_NOTIFICATION`, `MSG_FIN`:  Flags related to message handling.
* `SCTP_SOCKOPT_BINDX_ADD`, `SCTP_SOCKOPT_PEELOFF`: Socket options for advanced SCTP features.
* `union sctp_notification`: A structure to handle various SCTP event notifications.
* `sctp_assoc_t`:  A type representing an SCTP association ID.

**3. Deconstructing the Request - Answering Piece by Piece:**

Now, I'd systematically address each part of the request:

* **功能列举:**  Based on the keywords and structures identified, I would infer the main functionalities. The header defines data structures and constants related to SCTP, implying it's about configuring, sending, receiving, and managing SCTP connections. I'd list these high-level functionalities.

* **与 Android 的关系和举例:**  Knowing that bionic is Android's C library, I'd deduce that this header enables Android applications to use SCTP. The key is *how*. SCTP is a transport protocol, so it would be used for network communication. I'd think of scenarios where a reliable, multi-homing, or multi-streaming transport is needed, and SCTP fits the bill. Examples like telephony signaling (IMS), certain types of data transfer, or potentially even internal Android services (though less common than TCP/UDP) come to mind. The core idea is that Android uses the *kernel's* SCTP implementation, and this header provides the *interface* to that implementation.

* **libc 函数功能解释:** This is a bit of a trick question. This header file itself *doesn't contain any libc function implementations*. It *defines the data structures and constants* that libc functions (like `setsockopt`, `getsockopt`, `sendmsg`, `recvmsg`) *use* when interacting with SCTP sockets. The key distinction is *definition* vs. *implementation*. I would explicitly state that the header defines *types and constants* used by libc functions, rather than implementing the functions themselves.

* **Dynamic Linker 功能:** This header doesn't directly involve the dynamic linker. It's a header file for kernel interfaces. Dynamic linking concerns how shared libraries (`.so` files) are loaded and linked. I would state that this header file doesn't directly relate to the dynamic linker. A sample `.so` layout and linking process explanation would be generally applicable to any shared library in Android, not specific to this header. So I would provide a general overview of the dynamic linker's role and a basic `.so` structure.

* **逻辑推理和假设输入/输出:** This is tricky for a header file. There's no direct "input" and "output" in the sense of a function. Instead, the header defines the *structure* of data exchanged with the kernel. I would provide an example of *how* a program might use these definitions. For instance, how to set the `SCTP_NODELAY` option using `setsockopt` and the defined constant. This demonstrates the practical use of the definitions.

* **用户或编程常见错误:** This involves understanding how the defined elements are used and what could go wrong. Common mistakes include: using incorrect option values, misunderstanding the meaning of flags, incorrect structure packing, and not handling notifications properly. I would provide examples related to `setsockopt` and notification handling.

* **Android Framework/NDK 到达路径和 Frida Hook:** This requires understanding the Android architecture. An NDK application would use standard socket APIs, which in turn call into the kernel. The framework might indirectly use SCTP for specific services. The key is to trace the call flow: NDK -> libc (bionic) -> kernel system call -> kernel SCTP implementation. For Frida hooking, I'd target the relevant system calls or libc wrappers, providing a concrete example.

**4. Structuring the Answer:**

Finally, I would organize the answer clearly, addressing each part of the prompt systematically. Using headings and bullet points would enhance readability. I'd start with a concise summary and then delve into the specifics.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the header file *implements* some simple functions via macros.
* **Correction:**  No, the `#define` directives are for constants and simple substitutions, not function implementations. This is a *header* file, primarily for *declarations*.

* **Initial thought:**  Provide very detailed explanations of each struct member.
* **Refinement:**  Focus on the *purpose* of the structures and key members, avoiding excessive detail that might overwhelm the reader. The names of the members are often quite descriptive.

* **Initial thought:**  The dynamic linker section needs very SCTP-specific information.
* **Correction:** The header itself doesn't drive dynamic linking. Provide a general explanation of the dynamic linker in Android and how `.so` files are structured.

By following these steps, systematically breaking down the request, and iteratively refining the understanding, a comprehensive and accurate answer can be constructed.
这个 `sctp.h` 文件定义了用户空间程序与 Linux 内核中 SCTP (Stream Control Transmission Protocol) 实现进行交互时使用的数据结构和常量。它属于 Android 的 Bionic 库，因此是 Android 系统中网络编程的基础组成部分。

**它的功能列举:**

1. **定义 SCTP 协议相关的常量:** 包括各种 SCTP 协议选项 (例如 `SCTP_NODELAY`, `SCTP_AUTOCLOSE`)，事件类型 (`SCTP_ASSOC_CHANGE`, `SCTP_SEND_FAILED`)，消息标志 (`MSG_NOTIFICATION`)，以及用于部分可靠传输的策略 (`SCTP_PR_SCTP_TTL`, `SCTP_PR_SCTP_RTX`) 等。
2. **定义用于配置和获取 SCTP 连接信息的结构体:** 这些结构体用于在用户空间和内核空间之间传递数据，例如 `sctp_initmsg` (用于初始化连接参数)，`sctp_sndrcvinfo` (用于发送和接收数据的附加信息)，`sctp_assoc_change` (描述关联状态变化的通知) 等。
3. **定义用于设置和获取 SCTP 套接字选项的常量:** 例如 `SCTP_RTOINFO` (获取/设置重传超时信息)，`SCTP_MAXSEG` (获取/设置最大分片大小) 等。这些常量会被 `getsockopt` 和 `setsockopt` 等套接字函数使用。
4. **定义用于处理 SCTP 事件通知的联合体 `sctp_notification`:**  当 SCTP 连接状态发生变化或发生错误时，内核会通过套接字发送通知给用户空间程序。这个联合体包含了各种可能的通知类型。
5. **定义用于多宿主和流控制的结构体:** 例如 `sctp_paddrparams` (用于配置对端地址参数)，`sctp_stream_reset_event` (用于描述流重置事件)。

**它与 Android 功能的关系以及举例说明:**

SCTP 是一种传输层协议，与 TCP 和 UDP 类似，但提供了多宿主、多流等特性。在 Android 中，一些特定的场景会使用 SCTP，例如：

* **IMS (IP Multimedia Subsystem) 相关的应用:** IMS 是 Android 移动网络中用于提供语音、视频和消息服务的框架。SCTP 由于其多宿主和多流特性，常被用于 IMS 协议栈中，例如在控制平面信令的传输上，可以提高连接的可靠性和效率。
    * **举例:** 当 Android 手机进行 VoLTE 通话时，底层的 IMS 协议可能会使用 SCTP 来传输 SIP (Session Initiation Protocol) 消息，用于建立和管理通话会话。如果手机连接到多个 Wi-Fi 或蜂窝网络，SCTP 的多宿主特性可以确保即使其中一个网络连接中断，通话也能继续。
* **某些类型的 P2P 应用:** SCTP 的特性使其适用于某些对可靠性和部分有序交付有要求的 P2P 应用。
* **未来可能的 Android 系统服务:**  虽然目前 Android 系统服务中 SCTP 的使用不如 TCP/UDP 广泛，但随着技术发展，未来可能会有更多系统服务利用 SCTP 的优势。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **并没有实现任何 libc 函数**。它仅仅是定义了常量、数据结构和类型。这些定义会被 libc 中的套接字相关函数使用，例如：

* **`socket()`:**  用于创建套接字。当指定协议族为 `AF_INET` 或 `AF_INET6`，且类型为 `SOCK_STREAM` 并指定协议为 `IPPROTO_SCTP` 时，就会创建一个 SCTP 套接字。
* **`bind()`:**  将套接字绑定到本地地址和端口。对于 SCTP，可以绑定到多个本地地址 (多宿主)。
* **`listen()`:**  将套接字设置为监听状态，等待连接请求。
* **`connect()`:**  连接到远程 SCTP 端点。
* **`accept()`:**  接受来自客户端的 SCTP 连接请求。
* **`sendmsg()` 和 `recvmsg()`:**  用于发送和接收 SCTP 数据包。`sendmsg` 可以通过 `control` 成员发送 SCTP 特定的控制信息，例如设置消息的流标识、优先级等，这些信息的结构体定义就来源于 `sctp.h`。
* **`getsockopt()` 和 `setsockopt()`:**  用于获取和设置套接字的各种选项。`sctp.h` 中定义的 `SCTP_*` 常量会被用作 `getsockopt` 和 `setsockopt` 的 `option_name` 参数，用于操作 SCTP 特有的选项，例如获取或设置对端的主地址 (`SCTP_PRIMARY_ADDR`)，或者启用/禁用 Nagle 算法的类似行为 (`SCTP_NODELAY`)。

**libc 函数的实现原理 (以 `setsockopt` 为例):**

当用户空间程序调用 `setsockopt(sockfd, SOL_SCTP, SCTP_NODELAY, &value, sizeof(value))` 时，会经历以下步骤：

1. **系统调用:**  `setsockopt` 是一个 libc 提供的 wrapper 函数，它最终会发起一个系统调用 (例如 `sys_setsockopt`) 进入内核。
2. **内核处理:**  内核接收到系统调用后，会根据 `sockfd` 找到对应的 SCTP 套接字结构。
3. **选项识别:**  内核根据 `level` (在这里是 `SOL_SCTP`) 和 `optname` (在这里是 `SCTP_NODELAY`) 识别用户要设置的 SCTP 特定选项。`SCTP_NODELAY` 的值在 `sctp.h` 中定义。
4. **选项处理:**  内核会执行与 `SCTP_NODELAY` 相关的逻辑，例如修改套接字结构中的相应标志位，从而影响后续 SCTP 数据包的发送行为。
5. **返回:**  内核操作完成后，将结果返回给用户空间。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个 `sctp.h` 文件本身 **并不直接涉及 dynamic linker 的功能**。它是一个头文件，用于定义常量和数据结构，在编译时被包含到使用 SCTP 的源代码中。

**Dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 的主要职责是:**

1. **加载共享库 (`.so` 文件):** 当程序启动或在运行时需要使用某个共享库时，dynamic linker 会负责将 `.so` 文件加载到内存中。
2. **符号解析 (Symbol Resolution):**  程序中调用的函数或访问的全局变量可能定义在共享库中。dynamic linker 需要找到这些符号在共享库中的地址，并将程序中的引用指向正确的地址。
3. **重定位 (Relocation):**  由于共享库在内存中的加载地址可能不固定，dynamic linker 需要修改代码中的一些地址，使其指向正确的内存位置。

**一个简单的 `.so` 文件布局样本:**

```
.so 文件 (ELF 格式)
├── ELF header
├── Program headers (描述内存段的加载信息)
│   ├── LOAD segment (包含代码段和数据段)
│   └── DYNAMIC segment (包含动态链接信息)
├── Section headers (描述各个 section 的信息)
│   ├── .text section (代码段)
│   ├── .rodata section (只读数据段)
│   ├── .data section (已初始化的可读写数据段)
│   ├── .bss section (未初始化的可读写数据段)
│   ├── .symtab section (符号表)
│   ├── .strtab section (字符串表)
│   ├── .dynsym section (动态符号表)
│   ├── .dynstr section (动态字符串表)
│   ├── .rel.dyn section (数据重定位表)
│   └── .rel.plt section (过程链接表重定位表)
└── ...其他 sections
```

**链接的处理过程:**

1. **编译时链接:**  当编译使用 SCTP 的程序时，编译器会根据 `#include <linux/sctp.h>` 找到头文件，并了解 SCTP 相关的类型和常量。如果程序中调用了与 SCTP 相关的系统调用 (通过 libc wrapper 函数)，链接器会确保程序链接到 libc (`libc.so`)，因为 libc 提供了这些 wrapper 函数的实现。
2. **运行时链接:** 当程序运行时，如果调用了 libc 中与 SCTP 相关的函数 (例如 `setsockopt`)，dynamic linker 会在加载 `libc.so` 时，解析这些函数的符号，并将程序中的调用指向 `libc.so` 中相应的函数实现。`libc.so` 内部会处理与内核的交互，包括发起系统调用。

**注意:** `linux/sctp.h` 主要定义了用户空间和内核空间交互的接口，它本身不是一个共享库，因此不直接参与 dynamic linker 的链接过程。但是，它定义的常量和数据结构会被编译到使用 SCTP 的程序以及提供 SCTP 功能的共享库 (例如 `libc.so`) 中。

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `sctp.h` 是一个头文件，它本身不执行任何逻辑。它的作用是提供定义。逻辑推理通常发生在使用了这些定义的代码中。

**假设场景:** 用户空间程序想要获取一个 SCTP 关联的重传超时 (RTO) 信息。

**假设输入:**

* 一个已经建立的 SCTP 套接字的文件描述符 `sockfd`。
* 一个 `sctp_rtoinfo` 结构体变量 `rto_info`。
* SCTP 关联 ID `assoc_id`。

**逻辑推理 (在 `getsockopt` 的实现中):**

1. 用户程序调用 `getsockopt(sockfd, SOL_SCTP, SCTP_RTOINFO, &rto_info, &len)`。
2. `getsockopt` 系统调用进入内核。
3. 内核根据 `sockfd` 找到对应的 SCTP 套接字。
4. 内核检查 `optname` 是否为 `SCTP_RTOINFO`。
5. 内核提取用户提供的关联 ID (`rto_info.srto_assoc_id`)。
6. 内核查找该关联的 RTO 相关信息。
7. 内核将 RTO 的初始值、最大值和最小值等信息填充到 `rto_info` 结构体中。

**假设输出:**

`getsockopt` 调用成功返回 0，并且 `rto_info` 结构体中的成员被填充了对应关联的 RTO 信息，例如：

```c
rto_info.srto_initial = 3000; // 初始 RTO 为 3000 毫秒
rto_info.srto_max = 60000;   // 最大 RTO 为 60000 毫秒
rto_info.srto_min = 1000;   // 最小 RTO 为 1000 毫秒
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的套接字选项值:** 例如，尝试将 `SCTP_NODELAY` 设置为除了 0 和 1 之外的值。
2. **传递错误的结构体大小:** 在使用 `getsockopt` 或 `setsockopt` 时，`len` 参数必须设置为正确的大小，否则可能导致读取或写入越界。
3. **不正确地处理 SCTP 通知:** 当 SCTP 连接状态发生变化时，内核会发送通知。如果程序没有正确地接收和解析这些通知，可能会导致程序状态与实际连接状态不一致。
    * **举例:** 程序没有订阅 `SCTP_ASSOC_CHANGE` 事件，当连接断开时，程序可能仍然认为连接是正常的。
4. **混淆关联 ID:** 在多宿主或多流场景下，需要正确地使用关联 ID 来操作特定的连接或流。使用错误的关联 ID 会导致操作失败或影响错误的连接。
5. **在不支持 SCTP 的系统上使用 SCTP 特有的选项:**  如果程序在不支持 SCTP 的内核上运行，尝试使用 `setsockopt` 设置 `SOL_SCTP` 级别的选项将会失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android NDK 到达 `sctp.h` 的路径:**

1. **NDK 应用使用 Socket API:** Android NDK 开发者可以使用标准的 BSD Socket API 进行网络编程，例如 `socket()`, `bind()`, `connect()`, `sendmsg()`, `recvmsg()`, `setsockopt()`, `getsockopt()` 等。
2. **指定 SCTP 协议:** 在创建套接字时，开发者需要指定协议族为 `AF_INET` 或 `AF_INET6`，套接字类型为 `SOCK_STREAM`，协议为 `IPPROTO_SCTP`。
   ```c
   int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
   ```
3. **调用 libc 函数:** NDK 应用调用的 Socket API 函数实际上是 Bionic libc 提供的 wrapper 函数。
4. **Bionic libc 实现:** Bionic libc 中与网络相关的函数会进行参数校验，并将请求转换为相应的系统调用。
5. **系统调用进入内核:** 例如，`socket()` 会触发 `sys_socket()` 系统调用，`setsockopt()` 会触发 `sys_setsockopt()` 系统调用。
6. **内核 SCTP 模块:** Linux 内核实现了 SCTP 协议栈。当系统调用涉及到 SCTP 套接字时，内核会将请求路由到 SCTP 模块进行处理。
7. **`sctp.h` 的作用:** 在 Bionic libc 的实现中，以及在内核 SCTP 模块的实现中，都会包含 `linux/sctp.h` 头文件。Bionic libc 使用 `sctp.h` 中定义的常量和数据结构来与内核进行交互。内核 SCTP 模块也使用这些定义来管理 SCTP 连接和处理数据。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `setsockopt` 系统调用，并打印出与 SCTP 相关的选项的示例：

```javascript
// attach 到目标进程
Java.perform(function() {
    const setsockopt = Module.findExportByName(null, "setsockopt");
    if (setsockopt) {
        Interceptor.attach(setsockopt, {
            onEnter: function(args) {
                const sockfd = args[0].toInt32();
                const level = args[1].toInt32();
                const optname = args[2].toInt32();
                const optval = args[3];
                const optlen = args[4].toInt32();

                if (level === 150) { // SOL_SCTP 的值，可以通过 getconf SOL_SCTP 获取
                    console.log("setsockopt called for SCTP socket:");
                    console.log("  sockfd:", sockfd);
                    console.log("  optname:", optname);

                    // 可以根据 optname 的值来判断具体设置了哪个 SCTP 选项
                    if (optname === 0) { // SCTP_RTOINFO
                        console.log("  Option: SCTP_RTOINFO");
                        // 可以进一步解析 optval 指向的 sctp_rtoinfo 结构体
                    } else if (optname === 3) { // SCTP_NODELAY
                        console.log("  Option: SCTP_NODELAY");
                        const value = optval.readInt();
                        console.log("  Value:", value);
                    }
                    // ... 其他 SCTP 选项
                }
            },
            onLeave: function(retval) {
                // console.log("setsockopt returned:", retval);
            }
        });
    } else {
        console.log("Error: setsockopt not found!");
    }
});
```

**Frida Hook 调试步骤：**

1. **准备环境:** 确保已经安装了 Frida 和 Python 的 Frida 模块，并且目标 Android 设备已经 root 并运行了 Frida Server。
2. **找到目标进程:** 确定你想要调试的，使用了 SCTP 的 Android 进程的进程 ID 或进程名。
3. **编写 Frida 脚本:**  将上面的 JavaScript 代码保存为一个 `.js` 文件，例如 `sctp_hook.js`。
4. **运行 Frida 命令:** 使用 Frida 命令将脚本注入到目标进程：
   ```bash
   frida -U -f <目标进程包名或进程名> -l sctp_hook.js --no-pause
   ```
   或者如果已经知道进程 ID：
   ```bash
   frida -U <进程ID> -l sctp_hook.js
   ```
5. **观察输出:** 当目标进程调用 `setsockopt` 并且 `level` 为 `SOL_SCTP` 时，Frida 会拦截该调用，并打印出相关的套接字描述符、选项名以及选项值。你可以根据输出信息来分析 Android Framework 或 NDK 是如何使用 SCTP 选项的。

**注意:**

* `SOL_SCTP` 的实际值可能因 Android 版本和内核配置而异，可以使用 `getconf SOL_SCTP` 命令在 Android 设备上查询。
* Hook 系统调用需要 root 权限。
* 可以根据需要 Hook 其他与 SCTP 相关的系统调用，例如 `sendmsg`, `recvmsg`, `getsockopt` 等。
* 可以使用 Frida 提供的更强大的功能来解析结构体数据，例如使用 `readStruct` 或定义结构体的布局。

通过以上分析和 Frida Hook 示例，你可以深入了解 Android 系统中 SCTP 的使用方式和底层实现细节。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/sctp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_SCTP_H
#define _UAPI_SCTP_H
#include <linux/types.h>
#include <linux/socket.h>
typedef __s32 sctp_assoc_t;
#define SCTP_FUTURE_ASSOC 0
#define SCTP_CURRENT_ASSOC 1
#define SCTP_ALL_ASSOC 2
#define SCTP_RTOINFO 0
#define SCTP_ASSOCINFO 1
#define SCTP_INITMSG 2
#define SCTP_NODELAY 3
#define SCTP_AUTOCLOSE 4
#define SCTP_SET_PEER_PRIMARY_ADDR 5
#define SCTP_PRIMARY_ADDR 6
#define SCTP_ADAPTATION_LAYER 7
#define SCTP_DISABLE_FRAGMENTS 8
#define SCTP_PEER_ADDR_PARAMS 9
#define SCTP_DEFAULT_SEND_PARAM 10
#define SCTP_EVENTS 11
#define SCTP_I_WANT_MAPPED_V4_ADDR 12
#define SCTP_MAXSEG 13
#define SCTP_STATUS 14
#define SCTP_GET_PEER_ADDR_INFO 15
#define SCTP_DELAYED_ACK_TIME 16
#define SCTP_DELAYED_ACK SCTP_DELAYED_ACK_TIME
#define SCTP_DELAYED_SACK SCTP_DELAYED_ACK_TIME
#define SCTP_CONTEXT 17
#define SCTP_FRAGMENT_INTERLEAVE 18
#define SCTP_PARTIAL_DELIVERY_POINT 19
#define SCTP_MAX_BURST 20
#define SCTP_AUTH_CHUNK 21
#define SCTP_HMAC_IDENT 22
#define SCTP_AUTH_KEY 23
#define SCTP_AUTH_ACTIVE_KEY 24
#define SCTP_AUTH_DELETE_KEY 25
#define SCTP_PEER_AUTH_CHUNKS 26
#define SCTP_LOCAL_AUTH_CHUNKS 27
#define SCTP_GET_ASSOC_NUMBER 28
#define SCTP_GET_ASSOC_ID_LIST 29
#define SCTP_AUTO_ASCONF 30
#define SCTP_PEER_ADDR_THLDS 31
#define SCTP_RECVRCVINFO 32
#define SCTP_RECVNXTINFO 33
#define SCTP_DEFAULT_SNDINFO 34
#define SCTP_AUTH_DEACTIVATE_KEY 35
#define SCTP_REUSE_PORT 36
#define SCTP_PEER_ADDR_THLDS_V2 37
#define SCTP_SOCKOPT_BINDX_ADD 100
#define SCTP_SOCKOPT_BINDX_REM 101
#define SCTP_SOCKOPT_PEELOFF 102
#define SCTP_SOCKOPT_CONNECTX_OLD 107
#define SCTP_GET_PEER_ADDRS 108
#define SCTP_GET_LOCAL_ADDRS 109
#define SCTP_SOCKOPT_CONNECTX 110
#define SCTP_SOCKOPT_CONNECTX3 111
#define SCTP_GET_ASSOC_STATS 112
#define SCTP_PR_SUPPORTED 113
#define SCTP_DEFAULT_PRINFO 114
#define SCTP_PR_ASSOC_STATUS 115
#define SCTP_PR_STREAM_STATUS 116
#define SCTP_RECONFIG_SUPPORTED 117
#define SCTP_ENABLE_STREAM_RESET 118
#define SCTP_RESET_STREAMS 119
#define SCTP_RESET_ASSOC 120
#define SCTP_ADD_STREAMS 121
#define SCTP_SOCKOPT_PEELOFF_FLAGS 122
#define SCTP_STREAM_SCHEDULER 123
#define SCTP_STREAM_SCHEDULER_VALUE 124
#define SCTP_INTERLEAVING_SUPPORTED 125
#define SCTP_SENDMSG_CONNECT 126
#define SCTP_EVENT 127
#define SCTP_ASCONF_SUPPORTED 128
#define SCTP_AUTH_SUPPORTED 129
#define SCTP_ECN_SUPPORTED 130
#define SCTP_EXPOSE_POTENTIALLY_FAILED_STATE 131
#define SCTP_EXPOSE_PF_STATE SCTP_EXPOSE_POTENTIALLY_FAILED_STATE
#define SCTP_REMOTE_UDP_ENCAPS_PORT 132
#define SCTP_PLPMTUD_PROBE_INTERVAL 133
#define SCTP_PR_SCTP_NONE 0x0000
#define SCTP_PR_SCTP_TTL 0x0010
#define SCTP_PR_SCTP_RTX 0x0020
#define SCTP_PR_SCTP_PRIO 0x0030
#define SCTP_PR_SCTP_MAX SCTP_PR_SCTP_PRIO
#define SCTP_PR_SCTP_MASK 0x0030
#define __SCTP_PR_INDEX(x) ((x >> 4) - 1)
#define SCTP_PR_INDEX(x) __SCTP_PR_INDEX(SCTP_PR_SCTP_ ##x)
#define SCTP_PR_POLICY(x) ((x) & SCTP_PR_SCTP_MASK)
#define SCTP_PR_SET_POLICY(flags,x) do { flags &= ~SCTP_PR_SCTP_MASK; flags |= x; } while(0)
#define SCTP_PR_TTL_ENABLED(x) (SCTP_PR_POLICY(x) == SCTP_PR_SCTP_TTL)
#define SCTP_PR_RTX_ENABLED(x) (SCTP_PR_POLICY(x) == SCTP_PR_SCTP_RTX)
#define SCTP_PR_PRIO_ENABLED(x) (SCTP_PR_POLICY(x) == SCTP_PR_SCTP_PRIO)
#define SCTP_ENABLE_RESET_STREAM_REQ 0x01
#define SCTP_ENABLE_RESET_ASSOC_REQ 0x02
#define SCTP_ENABLE_CHANGE_ASSOC_REQ 0x04
#define SCTP_ENABLE_STRRESET_MASK 0x07
#define SCTP_STREAM_RESET_INCOMING 0x01
#define SCTP_STREAM_RESET_OUTGOING 0x02
enum sctp_msg_flags {
  MSG_NOTIFICATION = 0x8000,
#define MSG_NOTIFICATION MSG_NOTIFICATION
};
struct sctp_initmsg {
  __u16 sinit_num_ostreams;
  __u16 sinit_max_instreams;
  __u16 sinit_max_attempts;
  __u16 sinit_max_init_timeo;
};
struct sctp_sndrcvinfo {
  __u16 sinfo_stream;
  __u16 sinfo_ssn;
  __u16 sinfo_flags;
  __u32 sinfo_ppid;
  __u32 sinfo_context;
  __u32 sinfo_timetolive;
  __u32 sinfo_tsn;
  __u32 sinfo_cumtsn;
  sctp_assoc_t sinfo_assoc_id;
};
struct sctp_sndinfo {
  __u16 snd_sid;
  __u16 snd_flags;
  __u32 snd_ppid;
  __u32 snd_context;
  sctp_assoc_t snd_assoc_id;
};
struct sctp_rcvinfo {
  __u16 rcv_sid;
  __u16 rcv_ssn;
  __u16 rcv_flags;
  __u32 rcv_ppid;
  __u32 rcv_tsn;
  __u32 rcv_cumtsn;
  __u32 rcv_context;
  sctp_assoc_t rcv_assoc_id;
};
struct sctp_nxtinfo {
  __u16 nxt_sid;
  __u16 nxt_flags;
  __u32 nxt_ppid;
  __u32 nxt_length;
  sctp_assoc_t nxt_assoc_id;
};
struct sctp_prinfo {
  __u16 pr_policy;
  __u32 pr_value;
};
struct sctp_authinfo {
  __u16 auth_keynumber;
};
enum sctp_sinfo_flags {
  SCTP_UNORDERED = (1 << 0),
  SCTP_ADDR_OVER = (1 << 1),
  SCTP_ABORT = (1 << 2),
  SCTP_SACK_IMMEDIATELY = (1 << 3),
  SCTP_SENDALL = (1 << 6),
  SCTP_PR_SCTP_ALL = (1 << 7),
  SCTP_NOTIFICATION = MSG_NOTIFICATION,
  SCTP_EOF = MSG_FIN,
};
typedef union {
  __u8 raw;
  struct sctp_initmsg init;
  struct sctp_sndrcvinfo sndrcv;
} sctp_cmsg_data_t;
typedef enum sctp_cmsg_type {
  SCTP_INIT,
#define SCTP_INIT SCTP_INIT
  SCTP_SNDRCV,
#define SCTP_SNDRCV SCTP_SNDRCV
  SCTP_SNDINFO,
#define SCTP_SNDINFO SCTP_SNDINFO
  SCTP_RCVINFO,
#define SCTP_RCVINFO SCTP_RCVINFO
  SCTP_NXTINFO,
#define SCTP_NXTINFO SCTP_NXTINFO
  SCTP_PRINFO,
#define SCTP_PRINFO SCTP_PRINFO
  SCTP_AUTHINFO,
#define SCTP_AUTHINFO SCTP_AUTHINFO
  SCTP_DSTADDRV4,
#define SCTP_DSTADDRV4 SCTP_DSTADDRV4
  SCTP_DSTADDRV6,
#define SCTP_DSTADDRV6 SCTP_DSTADDRV6
} sctp_cmsg_t;
struct sctp_assoc_change {
  __u16 sac_type;
  __u16 sac_flags;
  __u32 sac_length;
  __u16 sac_state;
  __u16 sac_error;
  __u16 sac_outbound_streams;
  __u16 sac_inbound_streams;
  sctp_assoc_t sac_assoc_id;
  __u8 sac_info[];
};
enum sctp_sac_state {
  SCTP_COMM_UP,
  SCTP_COMM_LOST,
  SCTP_RESTART,
  SCTP_SHUTDOWN_COMP,
  SCTP_CANT_STR_ASSOC,
};
struct sctp_paddr_change {
  __u16 spc_type;
  __u16 spc_flags;
  __u32 spc_length;
  struct sockaddr_storage spc_aaddr;
  int spc_state;
  int spc_error;
  sctp_assoc_t spc_assoc_id;
} __attribute__((packed, aligned(4)));
enum sctp_spc_state {
  SCTP_ADDR_AVAILABLE,
  SCTP_ADDR_UNREACHABLE,
  SCTP_ADDR_REMOVED,
  SCTP_ADDR_ADDED,
  SCTP_ADDR_MADE_PRIM,
  SCTP_ADDR_CONFIRMED,
  SCTP_ADDR_POTENTIALLY_FAILED,
#define SCTP_ADDR_PF SCTP_ADDR_POTENTIALLY_FAILED
};
struct sctp_remote_error {
  __u16 sre_type;
  __u16 sre_flags;
  __u32 sre_length;
  __be16 sre_error;
  sctp_assoc_t sre_assoc_id;
  __u8 sre_data[];
};
struct sctp_send_failed {
  __u16 ssf_type;
  __u16 ssf_flags;
  __u32 ssf_length;
  __u32 ssf_error;
  struct sctp_sndrcvinfo ssf_info;
  sctp_assoc_t ssf_assoc_id;
  __u8 ssf_data[];
};
struct sctp_send_failed_event {
  __u16 ssf_type;
  __u16 ssf_flags;
  __u32 ssf_length;
  __u32 ssf_error;
  struct sctp_sndinfo ssfe_info;
  sctp_assoc_t ssf_assoc_id;
  __u8 ssf_data[];
};
enum sctp_ssf_flags {
  SCTP_DATA_UNSENT,
  SCTP_DATA_SENT,
};
struct sctp_shutdown_event {
  __u16 sse_type;
  __u16 sse_flags;
  __u32 sse_length;
  sctp_assoc_t sse_assoc_id;
};
struct sctp_adaptation_event {
  __u16 sai_type;
  __u16 sai_flags;
  __u32 sai_length;
  __u32 sai_adaptation_ind;
  sctp_assoc_t sai_assoc_id;
};
struct sctp_pdapi_event {
  __u16 pdapi_type;
  __u16 pdapi_flags;
  __u32 pdapi_length;
  __u32 pdapi_indication;
  sctp_assoc_t pdapi_assoc_id;
  __u32 pdapi_stream;
  __u32 pdapi_seq;
};
enum {
  SCTP_PARTIAL_DELIVERY_ABORTED = 0,
};
struct sctp_authkey_event {
  __u16 auth_type;
  __u16 auth_flags;
  __u32 auth_length;
  __u16 auth_keynumber;
  __u16 auth_altkeynumber;
  __u32 auth_indication;
  sctp_assoc_t auth_assoc_id;
};
enum {
  SCTP_AUTH_NEW_KEY,
#define SCTP_AUTH_NEWKEY SCTP_AUTH_NEW_KEY
  SCTP_AUTH_FREE_KEY,
  SCTP_AUTH_NO_AUTH,
};
struct sctp_sender_dry_event {
  __u16 sender_dry_type;
  __u16 sender_dry_flags;
  __u32 sender_dry_length;
  sctp_assoc_t sender_dry_assoc_id;
};
#define SCTP_STREAM_RESET_INCOMING_SSN 0x0001
#define SCTP_STREAM_RESET_OUTGOING_SSN 0x0002
#define SCTP_STREAM_RESET_DENIED 0x0004
#define SCTP_STREAM_RESET_FAILED 0x0008
struct sctp_stream_reset_event {
  __u16 strreset_type;
  __u16 strreset_flags;
  __u32 strreset_length;
  sctp_assoc_t strreset_assoc_id;
  __u16 strreset_stream_list[];
};
#define SCTP_ASSOC_RESET_DENIED 0x0004
#define SCTP_ASSOC_RESET_FAILED 0x0008
struct sctp_assoc_reset_event {
  __u16 assocreset_type;
  __u16 assocreset_flags;
  __u32 assocreset_length;
  sctp_assoc_t assocreset_assoc_id;
  __u32 assocreset_local_tsn;
  __u32 assocreset_remote_tsn;
};
#define SCTP_ASSOC_CHANGE_DENIED 0x0004
#define SCTP_ASSOC_CHANGE_FAILED 0x0008
#define SCTP_STREAM_CHANGE_DENIED SCTP_ASSOC_CHANGE_DENIED
#define SCTP_STREAM_CHANGE_FAILED SCTP_ASSOC_CHANGE_FAILED
struct sctp_stream_change_event {
  __u16 strchange_type;
  __u16 strchange_flags;
  __u32 strchange_length;
  sctp_assoc_t strchange_assoc_id;
  __u16 strchange_instrms;
  __u16 strchange_outstrms;
};
struct sctp_event_subscribe {
  __u8 sctp_data_io_event;
  __u8 sctp_association_event;
  __u8 sctp_address_event;
  __u8 sctp_send_failure_event;
  __u8 sctp_peer_error_event;
  __u8 sctp_shutdown_event;
  __u8 sctp_partial_delivery_event;
  __u8 sctp_adaptation_layer_event;
  __u8 sctp_authentication_event;
  __u8 sctp_sender_dry_event;
  __u8 sctp_stream_reset_event;
  __u8 sctp_assoc_reset_event;
  __u8 sctp_stream_change_event;
  __u8 sctp_send_failure_event_event;
};
union sctp_notification {
  struct {
    __u16 sn_type;
    __u16 sn_flags;
    __u32 sn_length;
  } sn_header;
  struct sctp_assoc_change sn_assoc_change;
  struct sctp_paddr_change sn_paddr_change;
  struct sctp_remote_error sn_remote_error;
  struct sctp_send_failed sn_send_failed;
  struct sctp_shutdown_event sn_shutdown_event;
  struct sctp_adaptation_event sn_adaptation_event;
  struct sctp_pdapi_event sn_pdapi_event;
  struct sctp_authkey_event sn_authkey_event;
  struct sctp_sender_dry_event sn_sender_dry_event;
  struct sctp_stream_reset_event sn_strreset_event;
  struct sctp_assoc_reset_event sn_assocreset_event;
  struct sctp_stream_change_event sn_strchange_event;
  struct sctp_send_failed_event sn_send_failed_event;
};
enum sctp_sn_type {
  SCTP_SN_TYPE_BASE = (1 << 15),
  SCTP_DATA_IO_EVENT = SCTP_SN_TYPE_BASE,
#define SCTP_DATA_IO_EVENT SCTP_DATA_IO_EVENT
  SCTP_ASSOC_CHANGE,
#define SCTP_ASSOC_CHANGE SCTP_ASSOC_CHANGE
  SCTP_PEER_ADDR_CHANGE,
#define SCTP_PEER_ADDR_CHANGE SCTP_PEER_ADDR_CHANGE
  SCTP_SEND_FAILED,
#define SCTP_SEND_FAILED SCTP_SEND_FAILED
  SCTP_REMOTE_ERROR,
#define SCTP_REMOTE_ERROR SCTP_REMOTE_ERROR
  SCTP_SHUTDOWN_EVENT,
#define SCTP_SHUTDOWN_EVENT SCTP_SHUTDOWN_EVENT
  SCTP_PARTIAL_DELIVERY_EVENT,
#define SCTP_PARTIAL_DELIVERY_EVENT SCTP_PARTIAL_DELIVERY_EVENT
  SCTP_ADAPTATION_INDICATION,
#define SCTP_ADAPTATION_INDICATION SCTP_ADAPTATION_INDICATION
  SCTP_AUTHENTICATION_EVENT,
#define SCTP_AUTHENTICATION_INDICATION SCTP_AUTHENTICATION_EVENT
  SCTP_SENDER_DRY_EVENT,
#define SCTP_SENDER_DRY_EVENT SCTP_SENDER_DRY_EVENT
  SCTP_STREAM_RESET_EVENT,
#define SCTP_STREAM_RESET_EVENT SCTP_STREAM_RESET_EVENT
  SCTP_ASSOC_RESET_EVENT,
#define SCTP_ASSOC_RESET_EVENT SCTP_ASSOC_RESET_EVENT
  SCTP_STREAM_CHANGE_EVENT,
#define SCTP_STREAM_CHANGE_EVENT SCTP_STREAM_CHANGE_EVENT
  SCTP_SEND_FAILED_EVENT,
#define SCTP_SEND_FAILED_EVENT SCTP_SEND_FAILED_EVENT
  SCTP_SN_TYPE_MAX = SCTP_SEND_FAILED_EVENT,
#define SCTP_SN_TYPE_MAX SCTP_SN_TYPE_MAX
};
typedef enum sctp_sn_error {
  SCTP_FAILED_THRESHOLD,
  SCTP_RECEIVED_SACK,
  SCTP_HEARTBEAT_SUCCESS,
  SCTP_RESPONSE_TO_USER_REQ,
  SCTP_INTERNAL_ERROR,
  SCTP_SHUTDOWN_GUARD_EXPIRES,
  SCTP_PEER_FAULTY,
} sctp_sn_error_t;
struct sctp_rtoinfo {
  sctp_assoc_t srto_assoc_id;
  __u32 srto_initial;
  __u32 srto_max;
  __u32 srto_min;
};
struct sctp_assocparams {
  sctp_assoc_t sasoc_assoc_id;
  __u16 sasoc_asocmaxrxt;
  __u16 sasoc_number_peer_destinations;
  __u32 sasoc_peer_rwnd;
  __u32 sasoc_local_rwnd;
  __u32 sasoc_cookie_life;
};
struct sctp_setpeerprim {
  sctp_assoc_t sspp_assoc_id;
  struct sockaddr_storage sspp_addr;
} __attribute__((packed, aligned(4)));
struct sctp_prim {
  sctp_assoc_t ssp_assoc_id;
  struct sockaddr_storage ssp_addr;
} __attribute__((packed, aligned(4)));
#define sctp_setprim sctp_prim
struct sctp_setadaptation {
  __u32 ssb_adaptation_ind;
};
enum sctp_spp_flags {
  SPP_HB_ENABLE = 1 << 0,
  SPP_HB_DISABLE = 1 << 1,
  SPP_HB = SPP_HB_ENABLE | SPP_HB_DISABLE,
  SPP_HB_DEMAND = 1 << 2,
  SPP_PMTUD_ENABLE = 1 << 3,
  SPP_PMTUD_DISABLE = 1 << 4,
  SPP_PMTUD = SPP_PMTUD_ENABLE | SPP_PMTUD_DISABLE,
  SPP_SACKDELAY_ENABLE = 1 << 5,
  SPP_SACKDELAY_DISABLE = 1 << 6,
  SPP_SACKDELAY = SPP_SACKDELAY_ENABLE | SPP_SACKDELAY_DISABLE,
  SPP_HB_TIME_IS_ZERO = 1 << 7,
  SPP_IPV6_FLOWLABEL = 1 << 8,
  SPP_DSCP = 1 << 9,
};
struct sctp_paddrparams {
  sctp_assoc_t spp_assoc_id;
  struct sockaddr_storage spp_address;
  __u32 spp_hbinterval;
  __u16 spp_pathmaxrxt;
  __u32 spp_pathmtu;
  __u32 spp_sackdelay;
  __u32 spp_flags;
  __u32 spp_ipv6_flowlabel;
  __u8 spp_dscp;
} __attribute__((packed, aligned(4)));
struct sctp_authchunk {
  __u8 sauth_chunk;
};
enum {
  SCTP_AUTH_HMAC_ID_SHA1 = 1,
  SCTP_AUTH_HMAC_ID_SHA256 = 3,
};
struct sctp_hmacalgo {
  __u32 shmac_num_idents;
  __u16 shmac_idents[];
};
#define shmac_number_of_idents shmac_num_idents
struct sctp_authkey {
  sctp_assoc_t sca_assoc_id;
  __u16 sca_keynumber;
  __u16 sca_keylength;
  __u8 sca_key[];
};
struct sctp_authkeyid {
  sctp_assoc_t scact_assoc_id;
  __u16 scact_keynumber;
};
struct sctp_sack_info {
  sctp_assoc_t sack_assoc_id;
  uint32_t sack_delay;
  uint32_t sack_freq;
};
struct sctp_assoc_value {
  sctp_assoc_t assoc_id;
  uint32_t assoc_value;
};
struct sctp_stream_value {
  sctp_assoc_t assoc_id;
  uint16_t stream_id;
  uint16_t stream_value;
};
struct sctp_paddrinfo {
  sctp_assoc_t spinfo_assoc_id;
  struct sockaddr_storage spinfo_address;
  __s32 spinfo_state;
  __u32 spinfo_cwnd;
  __u32 spinfo_srtt;
  __u32 spinfo_rto;
  __u32 spinfo_mtu;
} __attribute__((packed, aligned(4)));
enum sctp_spinfo_state {
  SCTP_INACTIVE,
  SCTP_PF,
#define SCTP_POTENTIALLY_FAILED SCTP_PF
  SCTP_ACTIVE,
  SCTP_UNCONFIRMED,
  SCTP_UNKNOWN = 0xffff
};
struct sctp_status {
  sctp_assoc_t sstat_assoc_id;
  __s32 sstat_state;
  __u32 sstat_rwnd;
  __u16 sstat_unackdata;
  __u16 sstat_penddata;
  __u16 sstat_instrms;
  __u16 sstat_outstrms;
  __u32 sstat_fragmentation_point;
  struct sctp_paddrinfo sstat_primary;
};
struct sctp_authchunks {
  sctp_assoc_t gauth_assoc_id;
  __u32 gauth_number_of_chunks;
  uint8_t gauth_chunks[];
};
#define guth_number_of_chunks gauth_number_of_chunks
enum sctp_sstat_state {
  SCTP_EMPTY = 0,
  SCTP_CLOSED = 1,
  SCTP_COOKIE_WAIT = 2,
  SCTP_COOKIE_ECHOED = 3,
  SCTP_ESTABLISHED = 4,
  SCTP_SHUTDOWN_PENDING = 5,
  SCTP_SHUTDOWN_SENT = 6,
  SCTP_SHUTDOWN_RECEIVED = 7,
  SCTP_SHUTDOWN_ACK_SENT = 8,
};
struct sctp_assoc_ids {
  __u32 gaids_number_of_ids;
  sctp_assoc_t gaids_assoc_id[];
};
struct sctp_getaddrs_old {
  sctp_assoc_t assoc_id;
  int addr_num;
  struct sockaddr * addrs;
};
struct sctp_getaddrs {
  sctp_assoc_t assoc_id;
  __u32 addr_num;
  __u8 addrs[];
};
struct sctp_assoc_stats {
  sctp_assoc_t sas_assoc_id;
  struct sockaddr_storage sas_obs_rto_ipaddr;
  __u64 sas_maxrto;
  __u64 sas_isacks;
  __u64 sas_osacks;
  __u64 sas_opackets;
  __u64 sas_ipackets;
  __u64 sas_rtxchunks;
  __u64 sas_outofseqtsns;
  __u64 sas_idupchunks;
  __u64 sas_gapcnt;
  __u64 sas_ouodchunks;
  __u64 sas_iuodchunks;
  __u64 sas_oodchunks;
  __u64 sas_iodchunks;
  __u64 sas_octrlchunks;
  __u64 sas_ictrlchunks;
};
#define SCTP_BINDX_ADD_ADDR 0x01
#define SCTP_BINDX_REM_ADDR 0x02
typedef struct {
  sctp_assoc_t associd;
  int sd;
} sctp_peeloff_arg_t;
typedef struct {
  sctp_peeloff_arg_t p_arg;
  unsigned flags;
} sctp_peeloff_flags_arg_t;
struct sctp_paddrthlds {
  sctp_assoc_t spt_assoc_id;
  struct sockaddr_storage spt_address;
  __u16 spt_pathmaxrxt;
  __u16 spt_pathpfthld;
};
struct sctp_paddrthlds_v2 {
  sctp_assoc_t spt_assoc_id;
  struct sockaddr_storage spt_address;
  __u16 spt_pathmaxrxt;
  __u16 spt_pathpfthld;
  __u16 spt_pathcpthld;
};
struct sctp_prstatus {
  sctp_assoc_t sprstat_assoc_id;
  __u16 sprstat_sid;
  __u16 sprstat_policy;
  __u64 sprstat_abandoned_unsent;
  __u64 sprstat_abandoned_sent;
};
struct sctp_default_prinfo {
  sctp_assoc_t pr_assoc_id;
  __u32 pr_value;
  __u16 pr_policy;
};
struct sctp_info {
  __u32 sctpi_tag;
  __u32 sctpi_state;
  __u32 sctpi_rwnd;
  __u16 sctpi_unackdata;
  __u16 sctpi_penddata;
  __u16 sctpi_instrms;
  __u16 sctpi_outstrms;
  __u32 sctpi_fragmentation_point;
  __u32 sctpi_inqueue;
  __u32 sctpi_outqueue;
  __u32 sctpi_overall_error;
  __u32 sctpi_max_burst;
  __u32 sctpi_maxseg;
  __u32 sctpi_peer_rwnd;
  __u32 sctpi_peer_tag;
  __u8 sctpi_peer_capable;
  __u8 sctpi_peer_sack;
  __u16 __reserved1;
  __u64 sctpi_isacks;
  __u64 sctpi_osacks;
  __u64 sctpi_opackets;
  __u64 sctpi_ipackets;
  __u64 sctpi_rtxchunks;
  __u64 sctpi_outofseqtsns;
  __u64 sctpi_idupchunks;
  __u64 sctpi_gapcnt;
  __u64 sctpi_ouodchunks;
  __u64 sctpi_iuodchunks;
  __u64 sctpi_oodchunks;
  __u64 sctpi_iodchunks;
  __u64 sctpi_octrlchunks;
  __u64 sctpi_ictrlchunks;
  struct sockaddr_storage sctpi_p_address;
  __s32 sctpi_p_state;
  __u32 sctpi_p_cwnd;
  __u32 sctpi_p_srtt;
  __u32 sctpi_p_rto;
  __u32 sctpi_p_hbinterval;
  __u32 sctpi_p_pathmaxrxt;
  __u32 sctpi_p_sackdelay;
  __u32 sctpi_p_sackfreq;
  __u32 sctpi_p_ssthresh;
  __u32 sctpi_p_partial_bytes_acked;
  __u32 sctpi_p_flight_size;
  __u16 sctpi_p_error;
  __u16 __reserved2;
  __u32 sctpi_s_autoclose;
  __u32 sctpi_s_adaptation_ind;
  __u32 sctpi_s_pd_point;
  __u8 sctpi_s_nodelay;
  __u8 sctpi_s_disable_fragments;
  __u8 sctpi_s_v4mapped;
  __u8 sctpi_s_frag_interleave;
  __u32 sctpi_s_type;
  __u32 __reserved3;
};
struct sctp_reset_streams {
  sctp_assoc_t srs_assoc_id;
  uint16_t srs_flags;
  uint16_t srs_number_streams;
  uint16_t srs_stream_list[];
};
struct sctp_add_streams {
  sctp_assoc_t sas_assoc_id;
  uint16_t sas_instrms;
  uint16_t sas_outstrms;
};
struct sctp_event {
  sctp_assoc_t se_assoc_id;
  uint16_t se_type;
  uint8_t se_on;
};
struct sctp_udpencaps {
  sctp_assoc_t sue_assoc_id;
  struct sockaddr_storage sue_address;
  uint16_t sue_port;
};
enum sctp_sched_type {
  SCTP_SS_FCFS,
  SCTP_SS_DEFAULT = SCTP_SS_FCFS,
  SCTP_SS_PRIO,
  SCTP_SS_RR,
  SCTP_SS_FC,
  SCTP_SS_WFQ,
  SCTP_SS_MAX = SCTP_SS_WFQ
};
struct sctp_probeinterval {
  sctp_assoc_t spi_assoc_id;
  struct sockaddr_storage spi_address;
  __u32 spi_interval;
};
#endif

"""

```