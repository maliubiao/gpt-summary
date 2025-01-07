Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Understanding - What is MCTP?**

The first thing that jumps out is "mctp". A quick search reveals it stands for "Management Component Transport Protocol". This immediately gives context: it's related to system management, likely at a lower level than typical user applications. The inclusion in the `bionic/libc/kernel/uapi/linux` directory reinforces this, suggesting it's a kernel-level interface exposed to user space.

**2. Deciphering the Header Guards and Includes:**

* `#ifndef __UAPI_MCTP_H` and `#define __UAPI_MCTP_H`: Standard header guards to prevent multiple inclusions.
* `#include <linux/types.h>`:  This is a common kernel header providing basic type definitions (`__u8`, `__u16`, etc.). It tells us the code interacts with kernel structures.
* `#include <linux/socket.h>`: This is a crucial clue. It strongly suggests that MCTP communicates using a socket-like interface, even if it's not a traditional TCP/IP socket.
* `#include <linux/netdevice.h>`: This reinforces the networking aspect and indicates interaction with network interfaces.

**3. Analyzing the Data Structures:**

* **`mctp_eid_t`**: A simple `__u8`, likely representing an endpoint identifier. The name "eid" supports this.
* **`mctp_addr`**: Contains a single `mctp_eid_t`. This looks like a basic address structure.
* **`sockaddr_mctp`**: This is clearly a socket address structure for MCTP. Key fields:
    * `smctp_family`:  Likely `AF_MCTP` (though not explicitly defined here, standard socket practice).
    * `smctp_network`: Hints at the possibility of multiple MCTP networks.
    * `smctp_addr`:  The actual MCTP address.
    * `smctp_type` and `smctp_tag`:  Protocol-specific information.
* **`sockaddr_mctp_ext`**:  An extended socket address. Key additions:
    * `smctp_base`:  Embeds the base `sockaddr_mctp`.
    * `smctp_ifindex`:  Specifies the network interface.
    * `smctp_halen` and `smctp_haddr`:  Looks like hardware address (MAC address) information. This confirms MCTP can interact directly with hardware.

**4. Examining the Constants:**

* **`MCTP_NET_ANY`, `MCTP_ADDR_NULL`, `MCTP_ADDR_ANY`**: Standard constants for "any" or "null" values in network addressing.
* **`MCTP_TAG_MASK`, `MCTP_TAG_OWNER`, `MCTP_TAG_PREALLOC`**: These suggest a tagging mechanism for MCTP messages or resources.
* **`MCTP_OPT_ADDR_EXT`**:  An option flag, probably used with `setsockopt` or similar functions to enable extended addressing.
* **`SIOCMCTPALLOCTAG`, `SIOCMCTPDROPTAG`, `SIOCMCTPALLOCTAG2`, `SIOCMCTPDROPTAG2`**:  These are the most significant constants. The `SIOC` prefix strongly suggests they are `ioctl` commands. The names clearly indicate operations related to allocating and dropping MCTP tags. The "2" variants likely introduce additional parameters or a different context. The `SIOCPROTOPRIVATE` base further confirms they are custom, protocol-specific ioctl calls.

**5. Analyzing the `ioctl` Structures:**

* **`mctp_ioc_tag_ctl`**:  Parameters for tag control. Includes peer address, the tag itself, and flags.
* **`mctp_ioc_tag_ctl2`**:  A more advanced tag control structure. Adds the `net` field and `local_addr`, suggesting more fine-grained control over tag allocation/deallocation within a specific network and for a specific local endpoint.

**6. Connecting to Android and libc:**

The file resides within `bionic/libc/kernel/uapi/linux`. This means it's part of the *user-space API* for the Linux kernel. Bionic, as Android's libc, provides the system call wrappers that user-space applications (including the Android framework and NDK apps) use to interact with the kernel.

* **System Calls:**  The `ioctl` constants directly map to `ioctl()` system calls. The data structures are passed as arguments to these calls.
* **Android Framework/NDK:** Android framework components (written in Java/Kotlin) might indirectly use MCTP if the underlying hardware or system services require it. NDK applications written in C/C++ can directly use the socket and `ioctl` interfaces defined here.

**7. Inferring Functionality and Relationships:**

Based on the names and structures, the core functionality revolves around:

* **Addressing:**  Defining how MCTP endpoints are addressed (simple and extended).
* **Tag Management:**  Allocating and deallocating tags, likely for identifying or managing MCTP sessions or resources. The two versions of the `ioctl` commands and structures suggest different levels of control.
* **Network Interface Binding:** The `smctp_ifindex` in the extended address allows binding MCTP communication to a specific network interface.

**8. Predicting Usage and Errors:**

* **Incorrect `ioctl` usage:**  Passing incorrect structure sizes, wrong command codes, or invalid data in the structures.
* **Address conflicts:** Trying to use the same MCTP address as another endpoint.
* **Incorrect tag management:** Trying to use a tag that hasn't been allocated or trying to free a tag that's in use.
* **Network interface errors:**  Specifying an invalid `ifindex`.

**9. Considering Dynamic Linking (Less Relevant Here):**

While this header file is *part* of libc, it doesn't directly define libc *functions*. It defines kernel data structures and `ioctl` constants. The dynamic linker is involved in loading libc, but this specific header primarily defines how user-space interacts with the kernel's MCTP implementation. Therefore, a detailed dynamic linking analysis for *this file alone* isn't the most fruitful. The relevant aspect is that libc provides the `socket()` and `ioctl()` wrappers.

**10. Frida Hooking Strategy:**

Focus on hooking the `ioctl` system call. Identify the specific `SIOCMCTP...` command codes and the corresponding structures. Log the input parameters to understand how the framework or NDK interacts with MCTP.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on the socket aspects, but the `ioctl` commands become a central point.
* Recognizing that this is a *kernel* UAPI header is key to understanding its role in system calls and the division of labor between the kernel and user space.
* Realizing that while dynamic linking is essential for libc, this particular header defines *data structures* used in system calls, not the functions themselves, helps to refine the focus.

By following these steps, combining knowledge of Linux system programming, networking concepts, and the structure of Android's Bionic library, we can arrive at a comprehensive understanding of the provided header file.
这个头文件 `bionic/libc/kernel/uapi/linux/mctp.handroid` 定义了 Linux 内核中用于 Management Component Transport Protocol (MCTP) 的用户空间 API。MCTP 是一种用于管理组件之间通信的协议，通常用于嵌入式系统和服务器管理等场景。由于它位于 `bionic` 目录，并且特别提到了 `handroid`，这表明这是 Android 平台特有的或者进行了定制的 MCTP 定义。

下面我们来详细分析其功能：

**1. 功能概述：**

这个头文件主要定义了以下内容，用于在用户空间程序中与内核中的 MCTP 子系统进行交互：

* **数据类型定义：** `mctp_eid_t` 定义了 MCTP 端点 ID (Endpoint ID)。
* **地址结构体：**
    * `struct mctp_addr`: 定义了基本的 MCTP 地址，只包含端点 ID。
    * `struct sockaddr_mctp`: 定义了用于 socket 操作的 MCTP 地址结构，类似于 `sockaddr_in` 或 `sockaddr_un`。它包含地址族（`smctp_family`）、网络标识符（`smctp_network`）、MCTP 地址（`smctp_addr`）、类型（`smctp_type`）和标签（`smctp_tag`）等信息。
    * `struct sockaddr_mctp_ext`:  扩展的 MCTP socket 地址结构，继承了 `sockaddr_mctp`，并添加了网络接口索引（`smctp_ifindex`）、硬件地址长度（`smctp_halen`）和硬件地址（`smctp_haddr`）。这允许将 MCTP 通信绑定到特定的网络接口，并指定硬件地址。
* **常量定义：** 定义了一些用于 MCTP 的常量，例如：
    * `MCTP_NET_ANY`: 表示任意网络。
    * `MCTP_ADDR_NULL`: 空地址。
    * `MCTP_ADDR_ANY`: 任意地址。
    * `MCTP_TAG_MASK`, `MCTP_TAG_OWNER`, `MCTP_TAG_PREALLOC`:  与 MCTP 消息或资源的标签管理相关的常量。
    * `MCTP_OPT_ADDR_EXT`:  一个选项，可能用于指示使用扩展的地址结构。
* **ioctl 命令定义：** 定义了用于与 MCTP 驱动程序交互的 `ioctl` 命令：
    * `SIOCMCTPALLOCTAG`:  用于分配 MCTP 标签。
    * `SIOCMCTPDROPTAG`:  用于释放 MCTP 标签。
    * `SIOCMCTPALLOCTAG2`, `SIOCMCTPDROPTAG2`:  可能是更新版本的标签分配和释放命令，可能支持更多的参数或功能。
* **ioctl 参数结构体：**
    * `struct mctp_ioc_tag_ctl`: 用于 `SIOCMCTPALLOCTAG` 和 `SIOCMCTPDROPTAG` 命令的参数结构体，包含对端地址（`peer_addr`）、标签（`tag`）和标志（`flags`）。
    * `struct mctp_ioc_tag_ctl2`: 用于 `SIOCMCTPALLOCTAG2` 和 `SIOCMCTPDROPTAG2` 命令的参数结构体，除了对端地址、标签和标志外，还包含网络标识符（`net`）和本地地址（`local_addr`）。

**2. 与 Android 功能的关系及举例说明：**

MCTP 在 Android 中的应用可能涉及底层硬件管理和组件通信。例如：

* **基带处理器 (Baseband Processor) 通信：** Android 设备中的应用处理器 (Application Processor, AP) 可能需要通过 MCTP 与基带处理器通信，以进行电源管理、状态查询或数据传输等操作。
* **电源管理集成电路 (PMIC) 通信：** AP 可能需要通过 MCTP 与 PMIC 通信，以控制电压、电流和功耗。
* **传感器 Hub 通信：** 用于连接和管理各种传感器（如加速度计、陀螺仪）的传感器 Hub 可能使用 MCTP 与 AP 通信。
* **其他系统芯片 (SoC) 内部组件通信：**  SoC 内部的不同模块之间也可能使用 MCTP 进行通信。

**举例说明：**

假设 Android 系统需要获取基带处理器的固件版本。应用处理器上的一个服务进程可能会执行以下步骤：

1. **创建 MCTP Socket:** 使用 `socket()` 系统调用创建一个 AF_MCTP 类型的 socket。
2. **构建 `sockaddr_mctp` 结构体:**  填充目标基带处理器的 MCTP 地址信息。
3. **发送请求:** 使用 `sendto()` 或类似的 socket 函数发送一个包含获取固件版本命令的 MCTP 消息。
4. **接收响应:** 使用 `recvfrom()` 或类似的 socket 函数接收来自基带处理器的响应消息，其中包含固件版本信息。

或者，可能使用 `ioctl` 来管理 MCTP 标签。例如，在与特定组件建立通信之前，可能需要分配一个唯一的标签：

1. **打开 MCTP 设备:** 打开与 MCTP 驱动程序关联的设备文件（如果存在）。
2. **构建 `mctp_ioc_tag_ctl` 或 `mctp_ioc_tag_ctl2` 结构体:**  指定对端地址等信息。
3. **调用 `ioctl`:**  使用 `SIOCMCTPALLOCTAG` 或 `SIOCMCTPALLOCTAG2` 命令，并将构建好的结构体作为参数传递。内核会分配一个可用的标签。

**3. libc 函数的功能实现：**

这个头文件本身并不定义 libc 函数的实现，而是定义了内核 API 的数据结构和常量。libc 提供了与这些内核 API 交互的系统调用包装函数，例如：

* **`socket()`:**  用于创建各种类型的 socket，包括 AF_MCTP 类型的 socket。`socket()` 的实现会调用内核的 `sys_socket()` 系统调用，内核根据指定的协议族创建相应的 socket 数据结构。
* **`bind()`:**  用于将 socket 绑定到本地地址。对于 MCTP socket，`bind()` 会调用内核的 `sys_bind()`，内核会将 socket 与指定的 MCTP 地址关联起来。
* **`sendto()`/`recvfrom()`:**  用于在 socket 上发送和接收数据。对于 MCTP socket，这些函数会调用内核的 `sys_sendto()` 和 `sys_recvfrom()`，内核会将数据封装成 MCTP 消息并通过相应的网络接口发送或接收。
* **`ioctl()`:**  用于执行设备特定的控制操作。对于 MCTP，可以使用 `ioctl()` 和这里定义的 `SIOCMCTP...` 命令来与 MCTP 驱动程序交互，例如分配和释放标签。`ioctl()` 的实现会调用内核的 `sys_ioctl()`，内核会根据命令码调用相应的设备驱动程序的 `ioctl` 处理函数。

**4. 涉及 dynamic linker 的功能：**

这个头文件主要定义的是内核 API，与 dynamic linker 的直接关系不大。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载动态链接库 (`.so` 文件) 并解析符号依赖关系。

**so 布局样本：**

假设有一个使用 MCTP 的 Android 本地库 `libmctp_client.so`：

```
libmctp_client.so:
    .init           // 初始化代码
    .plt            // Procedure Linkage Table，用于延迟绑定
    .text           // 代码段
        mctp_connect  // 连接到 MCTP 组件的函数
        mctp_send     // 发送 MCTP 消息的函数
        mctp_recv     // 接收 MCTP 消息的函数
        // ... 其他函数 ...
    .rodata         // 只读数据段
        // ... 常量数据 ...
    .data           // 可写数据段
        // ... 全局变量 ...
    .bss            // 未初始化数据段
        // ... 未初始化全局变量 ...
    .dynamic        // 动态链接信息
        // ... 依赖库、符号表等信息 ...
```

**链接的处理过程：**

1. **加载：** 当一个应用程序启动或加载 `libmctp_client.so` 时，dynamic linker 会将该 `.so` 文件加载到内存中。
2. **符号解析：** 如果 `libmctp_client.so` 中使用了 libc 提供的 socket 相关函数（如 `socket`, `bind`, `sendto`, `ioctl`），dynamic linker 会解析这些符号，并将 `libmctp_client.so` 中的函数调用地址指向 libc 中对应的函数实现。
3. **重定位：** Dynamic linker 会根据加载地址调整 `.so` 文件中的一些地址信息，确保代码能够正确执行。

在这个过程中，`bionic/libc/kernel/uapi/linux/mctp.handroid` 头文件定义的结构体和常量会被 `libmctp_client.so` 的源代码使用，但在链接阶段，dynamic linker 主要关注的是函数符号的解析和地址的重定位，而不是这些结构体和常量的定义。这些定义在编译时会被编译到 `libmctp_client.so` 中。

**5. 假设输入与输出（逻辑推理）：**

**假设输入（`ioctl` 调用分配标签）：**

```c
int fd = /* 打开 MCTP 设备文件的文件描述符 */;
struct mctp_ioc_tag_ctl2 tag_ctl;

tag_ctl.net = 0; // 假设在网络 0 上
tag_ctl.peer_addr = 0x10; // 假设对端地址为 0x10
tag_ctl.local_addr = 0x05; // 假设本地地址为 0x05
tag_ctl.flags = 0;
tag_ctl.tag = 0; // 期望内核分配标签

int ret = ioctl(fd, SIOCMCTPALLOCTAG2, &tag_ctl);
```

**预期输出：**

* **成功：** `ret` 返回 0，`tag_ctl.tag` 被内核更新为一个新分配的标签值（例如，0x01 到 0x07 之间的值，因为 `MCTP_TAG_MASK` 是 0x07）。
* **失败：** `ret` 返回 -1，并设置 `errno` 以指示错误原因，例如 `ENOMEM` (内存不足无法分配标签)，`EINVAL` (参数无效) 等。 `tag_ctl.tag` 的值可能不会被修改，或者被设置为一个错误指示值。

**假设输入（`ioctl` 调用释放标签）：**

```c
int fd = /* 打开 MCTP 设备文件的文件描述符 */;
struct mctp_ioc_tag_ctl2 tag_ctl;

tag_ctl.net = 0;
tag_ctl.peer_addr = 0x10;
tag_ctl.local_addr = 0x05;
tag_ctl.flags = 0;
tag_ctl.tag = 0x03; // 假设要释放的标签是 0x03

int ret = ioctl(fd, SIOCMCTPDROPTAG2, &tag_ctl);
```

**预期输出：**

* **成功：** `ret` 返回 0，表示标签已成功释放。
* **失败：** `ret` 返回 -1，并设置 `errno` 以指示错误原因，例如 `EINVAL` (指定的标签无效或未被分配给该端点)。

**6. 用户或编程常见的使用错误：**

* **错误的 `ioctl` 命令码：**  使用了错误的 `SIOCMCTP...` 常量，导致 `ioctl` 调用失败。
* **未初始化或错误初始化的结构体：**  传递给 `ioctl` 的结构体成员未正确初始化，例如，`peer_addr` 或 `tag` 的值不正确。
* **使用已释放的标签：**  尝试使用已经通过 `SIOCMCTPDROPTAG` 或 `SIOCMCTPDROPTAG2` 释放的标签。
* **权限不足：**  执行 `ioctl` 操作的用户或进程没有足够的权限访问 MCTP 设备或执行相关操作。
* **网络接口索引错误：**  在使用扩展地址结构时，`smctp_ifindex` 指定了不存在或无效的网络接口。
* **并发访问冲突：**  多个进程或线程同时尝试分配或释放相同的 MCTP 资源，可能导致竞争条件和错误。
* **忽略返回值和 `errno`：**  没有检查 `ioctl` 等系统调用的返回值，以及在出错时检查 `errno` 的值，导致无法正确处理错误。

**示例：未初始化结构体导致 `ioctl` 失败**

```c
int fd = /* 打开 MCTP 设备文件的文件描述符 */;
struct mctp_ioc_tag_ctl tag_ctl;

// 忘记初始化 tag_ctl 的成员
// tag_ctl.peer_addr 可能包含随机值
// tag_ctl.tag 也可能包含随机值

int ret = ioctl(fd, SIOCMCTPALLOCTAG, &tag_ctl);
if (ret == -1) {
    perror("ioctl SIOCMCTPALLOCTAG failed"); // 可能会打印 "Invalid argument" 或其他错误信息
}
```

**7. Android Framework 或 NDK 如何到达这里：**

通常，Android Framework 直接使用这些底层的内核 API 的情况比较少见。更常见的是，Framework 会通过以下方式间接使用：

1. **Native 系统服务：** Android Framework (Java/Kotlin 代码) 可能会调用一些由 C/C++ 实现的 Native 系统服务。这些 Native 服务可能会直接使用 `socket` 和 `ioctl` 系统调用，并使用这里定义的 MCTP 相关的结构体和常量。
2. **HAL (Hardware Abstraction Layer)：**  Framework 与硬件交互通常通过 HAL。HAL 模块 (通常是 `.so` 文件) 由硬件供应商提供，它们会实现一些标准接口，供 Framework 调用。HAL 模块的内部实现可能需要与底层硬件进行 MCTP 通信。
3. **Kernel Drivers：** 最终，这些调用会到达 Linux 内核中的 MCTP 驱动程序。用户空间的 `ioctl` 调用会触发内核中对应驱动程序的处理函数。

**NDK：**

使用 NDK 开发的应用程序可以直接调用 libc 提供的系统调用包装函数，例如 `socket`, `bind`, `sendto`, `ioctl`。开发者可以直接包含 `<linux/mctp.h>` (或者 Android Bionic 提供的对应头文件) 并使用其中定义的结构体和常量。

**Frida Hook 示例调试步骤：**

假设你想 hook `ioctl` 系统调用中与 `SIOCMCTPALLOCTAG2` 相关的操作，以查看传递的参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(__file__))
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
        session = frida.attach(pid)
    except ValueError:
        process_name = sys.argv[1]
        session = frida.attach(process_name)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const request = args[1].toInt();
            if (request === 0xc00c5af2) { // SIOCMCTPALLOCTAG2 的值 (需要根据实际平台确定)
                send("[ioctl] Calling ioctl with SIOCMCTPALLOCTAG2");
                const argp = ptr(args[2]);
                const tag_ctl = argp.readByteArray(16); // struct mctp_ioc_tag_ctl2 的大小
                send("[ioctl] mctp_ioc_tag_ctl2 data: " + hexdump(tag_ctl, { ansi: true }));

                // 可以进一步解析结构体中的字段
                const net = argp.readU32();
                const peer_addr = argp.add(4).readU8();
                const local_addr = argp.add(5).readU8();
                const flags = argp.add(6).readU16();
                const tag = argp.add(8).readU8();
                send("[ioctl]   net: " + net);
                send("[ioctl]   peer_addr: " + peer_addr);
                send("[ioctl]   local_addr: " + local_addr);
                send("[ioctl]   flags: " + flags);
                send("[ioctl]   tag: " + tag);
            }
        },
        onLeave: function(retval) {
            if (this.request === 0xc00c5af2) {
                send("[ioctl] ioctl with SIOCMCTPALLOCTAG2 returned: " + retval);
            }
        }
    });
    """
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, listening for ioctl calls...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤：**

1. **找到 `SIOCMCTPALLOCTAG2` 的值：**  需要在目标 Android 设备上找到 `SIOCMCTPALLOCTAG2` 宏的实际数值。可以使用 `adb shell getconf SIOCMCTPALLOCTAG2` 命令或者在相关的头文件中查找。
2. **运行 Frida 脚本：** 将上述 Python 代码保存为 `hook_mctp.py`，然后在 PC 上运行 `python hook_mctp.py <目标进程名或 PID>`。
3. **触发 MCTP 相关操作：** 在 Android 设备上执行会触发 `SIOCMCTPALLOCTAG2` `ioctl` 调用的操作。
4. **查看 Frida 输出：** Frida 脚本会拦截 `ioctl` 调用，并在终端上打印出相关的参数信息，包括 `mctp_ioc_tag_ctl2` 结构体的内容。

这个 Frida 脚本演示了如何 hook `ioctl` 系统调用并检查与特定 MCTP 命令相关的参数，可以帮助你调试 Android Framework 或 NDK 中与 MCTP 相关的操作。你需要根据具体的调试目标调整脚本中的命令码和结构体解析方式。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/mctp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UAPI_MCTP_H
#define __UAPI_MCTP_H
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
typedef __u8 mctp_eid_t;
struct mctp_addr {
  mctp_eid_t s_addr;
};
struct sockaddr_mctp {
  __kernel_sa_family_t smctp_family;
  __u16 __smctp_pad0;
  unsigned int smctp_network;
  struct mctp_addr smctp_addr;
  __u8 smctp_type;
  __u8 smctp_tag;
  __u8 __smctp_pad1;
};
struct sockaddr_mctp_ext {
  struct sockaddr_mctp smctp_base;
  int smctp_ifindex;
  __u8 smctp_halen;
  __u8 __smctp_pad0[3];
  __u8 smctp_haddr[MAX_ADDR_LEN];
};
#define MCTP_NET_ANY 0x0
#define MCTP_ADDR_NULL 0x00
#define MCTP_ADDR_ANY 0xff
#define MCTP_TAG_MASK 0x07
#define MCTP_TAG_OWNER 0x08
#define MCTP_TAG_PREALLOC 0x10
#define MCTP_OPT_ADDR_EXT 1
#define SIOCMCTPALLOCTAG (SIOCPROTOPRIVATE + 0)
#define SIOCMCTPDROPTAG (SIOCPROTOPRIVATE + 1)
#define SIOCMCTPALLOCTAG2 (SIOCPROTOPRIVATE + 2)
#define SIOCMCTPDROPTAG2 (SIOCPROTOPRIVATE + 3)
struct mctp_ioc_tag_ctl {
  mctp_eid_t peer_addr;
  __u8 tag;
  __u16 flags;
};
struct mctp_ioc_tag_ctl2 {
  unsigned int net;
  mctp_eid_t peer_addr;
  mctp_eid_t local_addr;
  __u16 flags;
  __u8 tag;
};
#endif

"""

```