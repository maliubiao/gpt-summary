Response:
Here's a breakdown of the thinking process to generate the comprehensive answer:

1. **Understand the Request:** The request asks for an analysis of a specific kernel header file (`tipc.h`) within the Android Bionic library. The core tasks are to explain its functionality, relate it to Android, detail libc function implementations (even though this file *doesn't define libc functions directly* - a crucial point), discuss dynamic linking (again, not directly involved in a header file, but relevant to how this code *would* be used), provide examples, and explain how Android frameworks reach this code.

2. **Initial Analysis of the Header File:**
    * **Purpose:** Recognize that this is a header file defining data structures, constants, and enums related to the TIPC (Transparent Inter-Process Communication) protocol. It's an interface definition for using TIPC.
    * **Key Components:** Identify the core structures (`tipc_socket_addr`, `tipc_service_addr`, `tipc_service_range`, `sockaddr_tipc`, etc.), constants (`TIPC_NODE_STATE`, `TIPC_MAX_USER_MSG_SIZE`, `AF_TIPC`, etc.), and enums (`tipc_scope`). Note the absence of function declarations or implementations – this is purely data definitions.
    * **"Auto-generated" Note:** Acknowledge the comment about the file being auto-generated, implying it's likely derived from a more authoritative source (like the upstream Linux kernel).

3. **Address Each Part of the Request Systematically:**

    * **Functionality:** Explain the primary purpose of TIPC: inter-process communication. Describe the key concepts like addressing (nodes, services), scopes (cluster, node), and message handling. Emphasize that this header *defines* these concepts, but doesn't *implement* them.

    * **Relationship to Android:**  This requires connecting TIPC to Android's broader architecture.
        * **Inter-Process Communication (IPC):**  Acknowledge that Android relies heavily on IPC and TIPC is *one* of the mechanisms.
        * **Binder:**  Mention Binder as the *primary* IPC mechanism in Android, but note that other options exist.
        * **Specific Use Cases (Hypothesize):** Since concrete Android usage within *this file* isn't visible,  *infer* potential uses. Consider scenarios where TIPC's features (like service discovery, fault tolerance) might be valuable. Examples: system services coordination, communication within a cluster of Android devices (though less common for typical mobile devices). *Crucially, acknowledge that direct, widespread use in typical Android app development is unlikely.*

    * **libc Function Implementation:**  **Critical realization:** This header file *doesn't contain libc function implementations*. It only defines data types. Therefore, the answer needs to explain *why* there are no function implementations here and clarify the role of header files. Mention the `socket()`, `bind()`, `sendto()`, `recvfrom()` family of functions as *related* to network/socket programming, but emphasize they are implemented in other parts of `libc` or the kernel. *Avoid inventing function implementations that don't exist in this file.*

    * **Dynamic Linker:**  Similar to the libc functions, this header file doesn't directly involve the dynamic linker. Explain the dynamic linker's role in resolving symbols at runtime. Provide a *hypothetical* scenario where a library using TIPC *might* be linked. Create a sample `so` layout and illustrate the linking process (symbol lookup, relocation). **Key point:** The linker operates on compiled code, not just header files.

    * **Logical Reasoning (Hypothetical):** Since the file primarily defines data structures, the logical reasoning examples should focus on how these structures are used.
        * **Subscription Example:**  Show how a `tipc_subscr` structure would be populated to subscribe to a service range.
        * **Address Example:** Demonstrate how a `sockaddr_tipc` structure is used to specify a service address.

    * **User/Programming Errors:** Think about common mistakes developers make when working with network programming or IPC. Examples: incorrect address family, port/type mismatches, incorrect data sizes, not handling errors.

    * **Android Framework/NDK Path:** Explain how a call from an Android application (using either Java Framework APIs or NDK) *could* potentially lead to the use of TIPC. Emphasize that it's not a direct, everyday path for most apps.
        * **Framework:**  Describe how a high-level framework API might, in some internal system service implementation, use lower-level networking primitives that *could* involve TIPC. This requires a bit of speculation as direct evidence isn't in the header.
        * **NDK:**  Show how an NDK developer could directly use socket-related system calls and potentially specify `AF_TIPC`.

    * **Frida Hook Example:** Provide practical Frida code to demonstrate how to intercept calls related to TIPC, focusing on `socket()` with `AF_TIPC` as the domain. This gives a tangible way to observe TIPC usage.

4. **Structure and Language:** Organize the answer logically with clear headings and subheadings. Use precise language and avoid jargon where possible. Since the request is in Chinese, provide the answer in Chinese.

5. **Review and Refine:**  Read through the entire answer to ensure accuracy, completeness, and clarity. Double-check that the explanations are consistent with the nature of a header file. Make sure the hypothetical examples are reasonable and well-explained. Address all parts of the original request.

**Self-Correction Example During the Process:**

* **Initial thought:** "I need to explain the implementation of `socket()` and `bind()`."
* **Correction:** "Wait, this is just a header file. It doesn't *implement* those functions. I should explain that this file *defines the structures used by* those functions, and point out where the actual implementations would be (in `libc` or the kernel)."

By following this structured approach and being mindful of the specific content of the header file, a comprehensive and accurate answer can be generated. The key is to distinguish between *definitions* (in the header) and *implementations* (elsewhere).

这是一个定义了 Linux TIPC (Transparent Inter-Process Communication) 协议相关数据结构和常量的头文件。它位于 Android Bionic 库中，这表明 Android 的底层可能使用了或者支持 TIPC 协议。

**功能列举：**

这个头文件定义了以下关键功能：

1. **地址结构体:**
   - `tipc_socket_addr`:  表示 TIPC 套接字的地址，包含一个引用计数 (`ref`) 和节点 ID (`node`)。
   - `tipc_service_addr`: 表示 TIPC 服务的地址，包含服务类型 (`type`) 和实例 (`instance`)。
   - `tipc_service_range`: 表示 TIPC 服务范围，包含服务类型 (`type`) 以及下限 (`lower`) 和上限 (`upper`) 实例。
   - `sockaddr_tipc`:  通用的 TIPC 地址结构，可以容纳以上三种地址类型，并通过 `addrtype` 区分。

2. **常量定义:**
   - **状态常量:** `TIPC_NODE_STATE`, `TIPC_TOP_SRV`, `TIPC_LINK_STATE` 等，用于表示 TIPC 组件的状态。
   - **作用域常量:** `TIPC_CLUSTER_SCOPE`, `TIPC_NODE_SCOPE`，定义了 TIPC 通信的作用范围。
   - **消息大小常量:** `TIPC_MAX_USER_MSG_SIZE`，定义了用户消息的最大尺寸。
   - **重要性常量:** `TIPC_LOW_IMPORTANCE`, `TIPC_MEDIUM_IMPORTANCE` 等，用于标记消息的重要性级别。
   - **错误码常量:** `TIPC_OK`, `TIPC_ERR_NO_NAME`, `TIPC_ERR_NO_PORT` 等，表示 TIPC 操作的返回状态。
   - **订阅常量:** `TIPC_SUB_PORTS`, `TIPC_SUB_SERVICE`, `TIPC_SUB_CANCEL`，用于 TIPC 服务订阅。
   - **事件常量:** `TIPC_PUBLISHED`, `TIPC_WITHDRAWN`, `TIPC_SUBSCR_TIMEOUT`，表示 TIPC 事件类型。
   - **Socket 选项常量:** `SOL_TIPC`, 以及以 `TIPC_` 开头的其他常量，用于 `setsockopt` 和 `getsockopt` 等系统调用。

3. **枚举类型:**
   - `tipc_scope`: 定义了 TIPC 通信的作用域（集群或节点）。

4. **其他结构体:**
   - `tipc_subscr`: 定义了 TIPC 服务订阅的结构，包含要订阅的服务范围、超时时间、过滤器和用户句柄。
   - `tipc_event`: 定义了 TIPC 事件的结构，包含事件类型、发现的服务范围、端口信息和订阅信息。
   - `tipc_group_req`: 定义了 TIPC 组操作的请求结构。
   - `tipc_sioc_ln_req`, `tipc_sioc_nodeid_req`: 用于通过 `ioctl` 系统调用获取 TIPC 连接和节点信息的结构。
   - `tipc_aead_key`:  定义了 TIPC AEAD (Authenticated Encryption with Associated Data) 加密算法密钥的结构。

5. **宏定义:**
   - `AF_TIPC`, `PF_TIPC`: 定义了地址族和协议族为 TIPC。
   - `SIOCGETLINKNAME`, `SIOCGETNODEID`:  与 `ioctl` 系统调用一起使用的命令宏。
   - 与地址相关的位掩码和偏移量宏，用于操作 TIPC 地址。

**与 Android 功能的关系及举例：**

TIPC 是一种进程间通信 (IPC) 机制，它允许同一主机或集群中的进程相互通信，而无需知道彼此的网络地址。虽然 Android 主要的 IPC 机制是 Binder，但 TIPC 在某些特定的 Android 子系统中可能被使用，尤其是在需要高性能、可靠的集群通信的场景下。

**举例说明：**

虽然在典型的 Android 应用开发中，开发者不会直接使用 TIPC，但 Android 系统内部的某些组件可能会利用它。例如：

* **系统服务协调:**  某些底层的系统服务可能使用 TIPC 来在不同的进程或甚至不同的设备（如果 Android 设备组成集群）之间同步状态或交换信息。
* **HAL (硬件抽象层) 通信:**  某些 HAL 的实现可能利用 TIPC 来与运行在不同进程中的服务进行通信。

**需要注意的是，直接使用 TIPC 对于 Android 应用开发者来说非常罕见。更常见的是使用 Android 提供的更高级别的 IPC 机制，如 Binder、AIDL、Messenger 等。**

**详细解释 libc 函数的功能是如何实现的：**

**这个头文件本身并不包含任何 libc 函数的实现。** 它只是定义了数据结构和常量。libc 函数的实现位于 Bionic 库的其他源文件中。

例如，如果要在 Android 中使用 TIPC 进行通信，你可能会使用以下 libc 函数（这些函数的具体实现不在 `tipc.h` 中）：

* **`socket(AF_TIPC, SOCK_SEQPACKET, 0)`:** 创建一个 TIPC 套接字。 `socket()` 函数的实现会根据指定的地址族 (`AF_TIPC`) 和套接字类型 (`SOCK_SEQPACKET`) 分配相应的内核资源。
* **`bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`:** 将套接字绑定到一个 TIPC 地址。`bind()` 函数会将套接字与 `sockaddr_tipc` 结构中指定的 TIPC 地址关联起来。
* **`connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`:** 连接到指定的 TIPC 服务。`connect()` 函数会尝试与目标服务建立连接。
* **`sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)` 或 `send(int sockfd, const void *buf, size_t len, int flags)`:** 发送数据到 TIPC 服务。这些函数会将用户数据封装成 TIPC 数据包，并发送到目标地址。
* **`recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)` 或 `recv(int sockfd, void *buf, size_t len, int flags)`:** 从 TIPC 套接字接收数据。这些函数会接收传入的 TIPC 数据包，并将有效负载复制到用户缓冲区。
* **`close(int fd)`:** 关闭 TIPC 套接字，释放相关资源。

这些函数的实现会涉及到系统调用，最终与 Linux 内核中 TIPC 协议栈的实现进行交互。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**这个头文件本身不直接涉及 dynamic linker 的功能。**  Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要任务是在程序启动时加载共享库 (`.so` 文件) 并解析符号引用。

如果一个 Android 的共享库 (`.so`) 中使用了 TIPC 相关的系统调用（例如上面列出的 `socket()` 等），那么这个库的布局可能如下：

**so 布局样本：**

```
my_tipc_library.so:
    .text        # 代码段，包含使用 TIPC 相关系统调用的函数
    .data        # 数据段
    .rodata      # 只读数据段
    .bss         # 未初始化数据段
    .dynamic     # 动态链接信息
    .symtab      # 符号表
    .strtab      # 字符串表
    .rel.dyn     # 动态重定位表
    .rel.plt     # PLT 重定位表
    ...
```

**链接的处理过程：**

1. **编译时：** 当 `my_tipc_library.so` 被编译时，编译器会识别出对诸如 `socket()` 等系统调用的引用。由于这些函数通常位于 `libc.so` 中，编译器会在符号表中记录下这些未解析的符号。

2. **加载时：** 当 Android 进程加载 `my_tipc_library.so` 时，dynamic linker 会执行以下操作：
   - **加载依赖库：**  Dynamic linker 会检查 `my_tipc_library.so` 的依赖关系，通常会包含 `libc.so`。
   - **解析符号：** Dynamic linker 会遍历 `my_tipc_library.so` 的重定位表 (`.rel.dyn` 和 `.rel.plt`)，找到所有未解析的符号引用 (例如 `socket`)。
   - **查找符号：** Dynamic linker 会在已加载的共享库 (如 `libc.so`) 的符号表中查找这些符号的定义。
   - **重定位：** 一旦找到符号的定义，dynamic linker 会修改 `my_tipc_library.so` 的代码或数据段，将对未解析符号的引用替换为实际的地址。例如，对 `socket()` 的调用会被重定向到 `libc.so` 中 `socket()` 函数的地址。

**假设输入与输出（逻辑推理）：**

由于这个头文件主要定义数据结构，我们可以假设一些使用这些结构体的场景。

**假设输入：**

一个程序想要订阅类型为 `1000`，实例范围从 `10` 到 `20` 的 TIPC 服务。

**输出（代码片段，并非实际运行结果）：**

```c
#include <linux/tipc.h>
#include <stdio.h>

int main() {
    struct tipc_subscr sub;
    sub.seq.type = 1000;
    sub.seq.lower = 10;
    sub.seq.upper = 20;
    sub.timeout = TIPC_WAIT_FOREVER;
    sub.filter = TIPC_SUB_SERVICE;
    // ... 其他设置 ...

    printf("Subscription parameters:\n");
    printf("  Type: %u\n", sub.seq.type);
    printf("  Lower Instance: %u\n", sub.seq.lower);
    printf("  Upper Instance: %u\n", sub.seq.upper);
    printf("  Timeout: %d\n", sub.timeout);
    printf("  Filter: %u\n", sub.filter);

    return 0;
}
```

这个例子展示了如何使用 `tipc_subscr` 结构体来设置订阅参数。实际使用中，这个结构体会被传递给相关的 TIPC 系统调用。

**用户或者编程常见的使用错误举例说明：**

1. **错误的地址族:**  在创建套接字时使用了错误的地址族，例如使用了 `AF_INET` 而不是 `AF_TIPC`。
   ```c
   int sockfd = socket(AF_INET, SOCK_SEQPACKET, 0); // 错误：应该使用 AF_TIPC
   ```

2. **地址结构体初始化错误:**  没有正确初始化 `sockaddr_tipc` 结构体的各个字段，例如 `family`，`addrtype`，或者 `addr` 联合体中的成员。
   ```c
   struct sockaddr_tipc addr;
   // 忘记设置 addr.family = AF_TIPC;
   addr.addrtype = TIPC_SERVICE_ADDR;
   addr.addr.name.type = 1000;
   addr.addr.name.instance = 15;
   // ... 绑定操作可能会失败 ...
   ```

3. **服务类型或实例错误:**  在连接或发送消息时，指定了不存在的服务类型或实例。这会导致连接失败或消息无法送达。

4. **消息大小超过限制:**  尝试发送超过 `TIPC_MAX_USER_MSG_SIZE` 的消息。

5. **忘记处理错误:**  TIPC 相关的系统调用可能会返回错误，例如 `TIPC_ERR_NO_NAME` 或 `TIPC_ERR_NO_PORT`。没有检查和处理这些错误会导致程序行为异常。

6. **作用域理解错误:**  对 TIPC 作用域 (`TIPC_CLUSTER_SCOPE`, `TIPC_NODE_SCOPE`) 的理解有误，导致无法与预期的目标进行通信。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的路径 (理论上，直接到达非常罕见):**

1. **Android Framework API 调用:** Android 应用通过 Framework API (Java 代码) 发起某些操作，例如可能涉及到系统服务间的通信。

2. **系统服务:**  Framework API 的调用可能会最终路由到 Android 系统服务 (通常用 Java 或 C++ 实现)。

3. **Native 代码 / NDK:**  某些系统服务的实现可能会使用 Native 代码 (C/C++)，并且这些 Native 代码可能会使用底层的 IPC 机制。

4. **Bionic libc:** 如果 Native 代码需要使用 TIPC，它会调用 Bionic libc 提供的套接字相关的函数 (如 `socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()`)。

5. **系统调用:**  Bionic libc 的这些函数会最终通过系统调用 (如 `socket`, `bind`, `connect`, `sendto`, `recvfrom`) 进入 Linux 内核。

6. **Linux Kernel TIPC 协议栈:**  内核中的 TIPC 协议栈会处理这些系统调用，并进行实际的 TIPC 通信。`bionic/libc/kernel/uapi/linux/tipc.h` 中定义的结构体和常量会被内核和 libc 使用。

**NDK 到达这里的路径 (更直接):**

1. **NDK 应用开发:**  开发者使用 Android NDK 编写 C/C++ 代码。

2. **直接使用 Socket API:**  NDK 代码可以直接调用 Bionic libc 提供的标准 Socket API 函数。

3. **指定 AF_TIPC:**  开发者在调用 `socket()` 函数时指定 `AF_TIPC` 作为地址族。
   ```c++
   #include <sys/socket.h>
   #include <linux/tipc.h>

   int sockfd = socket(AF_TIPC, SOCK_SEQPACKET, 0);
   ```

4. **后续操作:**  之后，NDK 代码可以使用 `bind()`, `connect()`, `sendto()`, `recvfrom()` 等函数，结合 `sockaddr_tipc` 结构体进行 TIPC 通信。

**Frida Hook 示例：**

可以使用 Frida 来 hook 与 TIPC 相关的系统调用或 libc 函数，以观察其行为和参数。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "socket"), {
    onEnter: function(args) {
        var domain = args[0].toInt32();
        var type = args[1].toInt32();
        var protocol = args[2].toInt32();
        if (domain === 30) { // AF_TIPC 的值
            send({
                type: 'send',
                payload: 'socket(AF_TIPC, ' + type + ', ' + protocol + ')'
            });
        }
    },
    onLeave: function(retval) {
        send({
            type: 'send',
            payload: 'socket 返回值: ' + retval
        });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "bind"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var addrPtr = ptr(args[1]);
        var addrlen = args[2].toInt32();

        var family = addrPtr.readU16();
        if (family === 30) { // AF_TIPC
            send({
                type: 'send',
                payload: 'bind(sockfd=' + sockfd + ', addr (AF_TIPC))'
            });
        }
    }
});

// 可以添加更多 hook，例如 connect, sendto, recvfrom 等
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的目标 Android 应用进程。
2. **`Interceptor.attach(...)`:**  Hook `libc.so` 中的 `socket` 和 `bind` 函数。
3. **`onEnter`:**  在函数调用之前执行。对于 `socket`，检查 `domain` 参数是否为 `30` ( `AF_TIPC` 的值)。对于 `bind`，检查地址结构体的 `family` 字段。
4. **`send(...)`:**  将 hook 到的信息发送回 Frida 客户端。
5. **`script.load()`:** 加载并运行 Frida 脚本。

这个示例可以帮助你观察目标应用是否以及何时使用了 TIPC 相关的函数调用，并查看传递的参数。你可以根据需要添加更多 hook 来调试其他 TIPC 相关的函数。

总而言之，`bionic/libc/kernel/uapi/linux/tipc.handroid` 这个头文件定义了 TIPC 协议的接口，虽然在典型的 Android 应用开发中不常用，但在 Android 系统底层或某些特定的子系统中可能扮演着重要的角色。 通过 NDK，开发者可以更直接地使用 TIPC 进行进程间通信。 Frida 可以作为强大的调试工具，帮助我们理解 Android 系统或应用如何与 TIPC 协议栈进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/tipc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_TIPC_H_
#define _LINUX_TIPC_H_
#include <linux/types.h>
#include <linux/sockios.h>
struct tipc_socket_addr {
  __u32 ref;
  __u32 node;
};
struct tipc_service_addr {
  __u32 type;
  __u32 instance;
};
struct tipc_service_range {
  __u32 type;
  __u32 lower;
  __u32 upper;
};
#define TIPC_NODE_STATE 0
#define TIPC_TOP_SRV 1
#define TIPC_LINK_STATE 2
#define TIPC_RESERVED_TYPES 64
enum tipc_scope {
  TIPC_CLUSTER_SCOPE = 2,
  TIPC_NODE_SCOPE = 3
};
#define TIPC_MAX_USER_MSG_SIZE 66000U
#define TIPC_LOW_IMPORTANCE 0
#define TIPC_MEDIUM_IMPORTANCE 1
#define TIPC_HIGH_IMPORTANCE 2
#define TIPC_CRITICAL_IMPORTANCE 3
#define TIPC_OK 0
#define TIPC_ERR_NO_NAME 1
#define TIPC_ERR_NO_PORT 2
#define TIPC_ERR_NO_NODE 3
#define TIPC_ERR_OVERLOAD 4
#define TIPC_CONN_SHUTDOWN 5
#define TIPC_SUB_PORTS 0x01
#define TIPC_SUB_SERVICE 0x02
#define TIPC_SUB_CANCEL 0x04
#define TIPC_WAIT_FOREVER (~0)
struct tipc_subscr {
  struct tipc_service_range seq;
  __u32 timeout;
  __u32 filter;
  char usr_handle[8];
};
#define TIPC_PUBLISHED 1
#define TIPC_WITHDRAWN 2
#define TIPC_SUBSCR_TIMEOUT 3
struct tipc_event {
  __u32 event;
  __u32 found_lower;
  __u32 found_upper;
  struct tipc_socket_addr port;
  struct tipc_subscr s;
};
#ifndef AF_TIPC
#define AF_TIPC 30
#endif
#ifndef PF_TIPC
#define PF_TIPC AF_TIPC
#endif
#ifndef SOL_TIPC
#define SOL_TIPC 271
#endif
#define TIPC_ADDR_MCAST 1
#define TIPC_SERVICE_RANGE 1
#define TIPC_SERVICE_ADDR 2
#define TIPC_SOCKET_ADDR 3
struct sockaddr_tipc {
  unsigned short family;
  unsigned char addrtype;
  signed char scope;
  union {
    struct tipc_socket_addr id;
    struct tipc_service_range nameseq;
    struct {
      struct tipc_service_addr name;
      __u32 domain;
    } name;
  } addr;
};
#define TIPC_ERRINFO 1
#define TIPC_RETDATA 2
#define TIPC_DESTNAME 3
#define TIPC_IMPORTANCE 127
#define TIPC_SRC_DROPPABLE 128
#define TIPC_DEST_DROPPABLE 129
#define TIPC_CONN_TIMEOUT 130
#define TIPC_NODE_RECVQ_DEPTH 131
#define TIPC_SOCK_RECVQ_DEPTH 132
#define TIPC_MCAST_BROADCAST 133
#define TIPC_MCAST_REPLICAST 134
#define TIPC_GROUP_JOIN 135
#define TIPC_GROUP_LEAVE 136
#define TIPC_SOCK_RECVQ_USED 137
#define TIPC_NODELAY 138
#define TIPC_GROUP_LOOPBACK 0x1
#define TIPC_GROUP_MEMBER_EVTS 0x2
struct tipc_group_req {
  __u32 type;
  __u32 instance;
  __u32 scope;
  __u32 flags;
};
#define TIPC_NODEID_LEN 16
#define TIPC_MAX_MEDIA_NAME 16
#define TIPC_MAX_IF_NAME 16
#define TIPC_MAX_BEARER_NAME 32
#define TIPC_MAX_LINK_NAME 68
#define SIOCGETLINKNAME SIOCPROTOPRIVATE
#define SIOCGETNODEID (SIOCPROTOPRIVATE + 1)
struct tipc_sioc_ln_req {
  __u32 peer;
  __u32 bearer_id;
  char linkname[TIPC_MAX_LINK_NAME];
};
struct tipc_sioc_nodeid_req {
  __u32 peer;
  char node_id[TIPC_NODEID_LEN];
};
#define TIPC_AEAD_ALG_NAME (32)
struct tipc_aead_key {
  char alg_name[TIPC_AEAD_ALG_NAME];
  unsigned int keylen;
  char key[];
};
#define TIPC_AEAD_KEYLEN_MIN (16 + 4)
#define TIPC_AEAD_KEYLEN_MAX (32 + 4)
#define TIPC_AEAD_KEY_SIZE_MAX (sizeof(struct tipc_aead_key) + TIPC_AEAD_KEYLEN_MAX)
#define TIPC_REKEYING_NOW (~0U)
#define TIPC_CFG_SRV 0
#define TIPC_ZONE_SCOPE 1
#define TIPC_ADDR_NAMESEQ 1
#define TIPC_ADDR_NAME 2
#define TIPC_ADDR_ID 3
#define TIPC_NODE_BITS 12
#define TIPC_CLUSTER_BITS 12
#define TIPC_ZONE_BITS 8
#define TIPC_NODE_OFFSET 0
#define TIPC_CLUSTER_OFFSET TIPC_NODE_BITS
#define TIPC_ZONE_OFFSET (TIPC_CLUSTER_OFFSET + TIPC_CLUSTER_BITS)
#define TIPC_NODE_SIZE ((1UL << TIPC_NODE_BITS) - 1)
#define TIPC_CLUSTER_SIZE ((1UL << TIPC_CLUSTER_BITS) - 1)
#define TIPC_ZONE_SIZE ((1UL << TIPC_ZONE_BITS) - 1)
#define TIPC_NODE_MASK (TIPC_NODE_SIZE << TIPC_NODE_OFFSET)
#define TIPC_CLUSTER_MASK (TIPC_CLUSTER_SIZE << TIPC_CLUSTER_OFFSET)
#define TIPC_ZONE_MASK (TIPC_ZONE_SIZE << TIPC_ZONE_OFFSET)
#define TIPC_ZONE_CLUSTER_MASK (TIPC_ZONE_MASK | TIPC_CLUSTER_MASK)
#define tipc_portid tipc_socket_addr
#define tipc_name tipc_service_addr
#define tipc_name_seq tipc_service_range
#endif
```