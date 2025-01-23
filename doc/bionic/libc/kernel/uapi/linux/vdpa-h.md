Response:
Let's break down the thought process for generating the detailed answer about the `vdpa.h` header file.

**1. Understanding the Core Task:**

The request is to analyze a C header file located within Android's Bionic library, specifically related to `vdpa`. The core tasks are:

* **Functionality:**  What does this file *do*?
* **Android Relevance:** How does it tie into Android?
* **Libc Function Details:** Explanation of any libc functions (although this file doesn't *implement* libc functions, but *defines* constants used by them).
* **Dynamic Linker:** How does it relate to dynamic linking? (Again, primarily by defining constants used in dynamic contexts).
* **Logical Reasoning:** Any inferences based on the content.
* **Common Errors:** Potential user mistakes.
* **Android Framework Interaction:** How does Android use this?
* **Frida Hooking:**  How to observe its use.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_LINUX_VDPA_H_ ... #endif`:** Standard header guard to prevent multiple inclusions. This is a fundamental C/C++ practice.
* **`#define VDPA_GENL_NAME "vdpa"` and `#define VDPA_GENL_VERSION 0x1`:** These define constants. "vdpa" likely refers to the virtual data path acceleration framework in the Linux kernel. The version indicates a revision.
* **`enum vdpa_command`:** This defines a set of commands related to managing vdpa devices. Keywords like `NEW`, `GET`, `DEL`, `CONFIG`, `VSTATS`, `ATTR_SET` strongly suggest interaction with a system for creating, querying, and modifying vdpa devices.
* **`enum vdpa_attr`:** This defines attributes associated with vdpa devices and their management. The names clearly indicate properties like device names, IDs, queue sizes, network configurations (MAC address, MTU), block device configurations (capacity, block size, etc.), and vendor-specific attributes.

**3. Connecting to Key Concepts:**

* **UAPI (User API):** The path `bionic/libc/kernel/uapi/linux/` immediately tells us this is a *user-space* header file providing an interface to kernel functionality. It defines constants used by user-space programs to interact with the kernel's vdpa subsystem.
* **vdpa:**  Knowing it stands for Virtual Data Path Acceleration is crucial. This framework allows virtual machines or containers to directly access hardware devices, improving performance.
* **Generic Netlink:** The `VDPA_GENL_NAME` strongly suggests that the communication between user-space and the kernel happens via Generic Netlink, a flexible communication mechanism in the Linux kernel.

**4. Addressing Specific Questions:**

* **功能 (Functionality):** The primary function is to define constants and enumerations that represent the commands and attributes used to interact with the Linux kernel's vdpa subsystem from user space.
* **与 Android 的关系 (Android Relevance):**  Android, being built on the Linux kernel, can leverage vdpa for virtualization or containerization scenarios where direct hardware access is needed for performance-critical tasks. Examples: GPU passthrough, high-performance networking in virtualized environments.
* **Libc 函数 (Libc Functions):**  This file *defines* constants, it doesn't implement libc functions. However, these constants are *used* by libc functions (or functions in other libraries) when interacting with the kernel via system calls (like `ioctl` with netlink sockets).
* **Dynamic Linker:** This file itself isn't directly involved in dynamic linking. However, if code using these definitions is in a shared library, the dynamic linker will load that library.
* **逻辑推理 (Logical Reasoning):**  The structure of commands and attributes suggests a client-server communication model where user-space sends commands with specific attributes to the kernel to manage vdpa devices.
* **用户或编程常见的使用错误 (Common Errors):** Incorrectly using the attribute values, sending unsupported commands, or failing to handle errors returned from kernel interactions are common mistakes.
* **Android Framework or NDK:** The Android framework might indirectly use vdpa if it's managing virtualization or containerization. NDK developers could directly interact with vdpa through system calls and the defined constants in this header file.
* **Frida Hook:**  Frida can be used to intercept calls related to netlink sockets and observe the values of the vdpa commands and attributes being exchanged.

**5. Structuring the Answer:**

The answer should be organized logically to cover all the requested points. Using headings and bullet points makes it easier to read and understand.

**6. Refinement and Detail:**

* **Expand on Generic Netlink:** Explain its role in communication.
* **Provide concrete Android examples:**  Focus on likely use cases within Android.
* **Clarify the libc/dynamic linker relationship:**  Explain that while this file doesn't implement their functionality, it provides data they use.
* **Give specific Frida examples:** Show how to hook relevant system calls.

**Self-Correction/Improvements during the process:**

* **Initial Thought:**  "This file implements vdpa functionality."  **Correction:** Realized it *defines* the interface, the implementation is in the kernel.
* **Initial Thought:** "Libc functions are implemented here." **Correction:** This is a header file defining constants, not implementing functions.
* **Need to explain *how* user-space interacts with the kernel using these definitions.**  Added the explanation of Generic Netlink.

By following this detailed thought process,  the comprehensive and accurate answer addressing all aspects of the prompt can be constructed. The key is to break down the request, understand the underlying concepts, and systematically address each point with clarity and detail.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/vdpa.h` 这个头文件。

**文件功能总览**

这个头文件 `vdpa.h` 定义了用户空间程序与 Linux 内核中 Virtual Data Path Acceleration (VDPA) 子系统进行交互时所使用的常量、枚举类型。它本质上是定义了一个**应用程序编程接口 (API)**，允许用户空间的程序控制和管理 VDPA 设备。

**VDPA 的概念**

VDPA 是一种 Linux 内核技术，它允许虚拟机 (VM) 或容器内的客户机操作系统直接访问主机硬件设备。这可以显著提高 I/O 性能，因为它绕过了传统的虚拟化 I/O 路径。

**头文件内容解析**

1. **`#ifndef _UAPI_LINUX_VDPA_H_` 和 `#define _UAPI_LINUX_VDPA_H_`:** 这是标准的 C/C++ 头文件保护机制，防止头文件被重复包含。

2. **`#define VDPA_GENL_NAME "vdpa"`:** 定义了一个字符串常量 `"vdpa"`，这个常量很可能用于标识 VDPA 相关的 Generic Netlink 族。Generic Netlink 是 Linux 内核中一种灵活的、基于消息的通信机制，用于用户空间和内核空间之间的通信。

3. **`#define VDPA_GENL_VERSION 0x1`:** 定义了 VDPA Generic Netlink 接口的版本号为 1。这有助于内核和用户空间程序识别彼此的接口版本，确保兼容性。

4. **`enum vdpa_command`:** 定义了一组枚举常量，代表可以发送给 VDPA 内核子系统的命令类型。这些命令涵盖了 VDPA 设备的生命周期管理和属性获取：
   - `VDPA_CMD_UNSPEC`: 未指定的命令。通常作为枚举的第一个值，可能用于表示无效或默认情况。
   - `VDPA_CMD_MGMTDEV_NEW`: 创建一个新的管理设备（Management Device）。管理设备可能代表了物理硬件或虚拟硬件的抽象。
   - `VDPA_CMD_MGMTDEV_GET`: 获取已存在的管理设备的信息。
   - `VDPA_CMD_DEV_NEW`: 基于某个管理设备创建一个新的 VDPA 设备。VDPA 设备是真正可以被客户机操作系统使用的虚拟硬件设备。
   - `VDPA_CMD_DEV_DEL`: 删除一个 VDPA 设备。
   - `VDPA_CMD_DEV_GET`: 获取一个 VDPA 设备的信息。
   - `VDPA_CMD_DEV_CONFIG_GET`: 获取 VDPA 设备的配置信息。
   - `VDPA_CMD_DEV_VSTATS_GET`: 获取 VDPA 设备的虚拟化统计信息。
   - `VDPA_CMD_DEV_ATTR_SET`: 设置 VDPA 设备的属性。

5. **`enum vdpa_attr`:** 定义了一组枚举常量，代表与 VDPA 设备相关的各种属性。这些属性用于在创建、查询和配置 VDPA 设备时传递参数：
   - `VDPA_ATTR_UNSPEC`: 未指定的属性。
   - `VDPA_ATTR_PAD`: 用于填充对齐的属性，实际没有意义。
   - `VDPA_ATTR_MGMTDEV_BUS_NAME`: 管理设备所属的总线名称（例如，"pci"）。
   - `VDPA_ATTR_MGMTDEV_DEV_NAME`: 管理设备的设备名称。
   - `VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES`: 管理设备支持的设备类别。
   - `VDPA_ATTR_DEV_NAME`: VDPA 设备的名称。
   - `VDPA_ATTR_DEV_ID`: VDPA 设备的 ID。
   - `VDPA_ATTR_DEV_VENDOR_ID`: VDPA 设备的供应商 ID。
   - `VDPA_ATTR_DEV_MAX_VQS`: VDPA 设备支持的最大虚拟队列 (Virtqueue) 数量。
   - `VDPA_ATTR_DEV_MAX_VQ_SIZE`: 每个虚拟队列的最大大小。
   - `VDPA_ATTR_DEV_MIN_VQ_SIZE`: 每个虚拟队列的最小大小。
   - `VDPA_ATTR_DEV_NET_CFG_MACADDR`: 网络设备的 MAC 地址配置。
   - `VDPA_ATTR_DEV_NET_STATUS`: 网络设备的状态。
   - `VDPA_ATTR_DEV_NET_CFG_MAX_VQP`: 网络设备配置的最大 VQP (Virtual Queue Pair) 数量。
   - `VDPA_ATTR_DEV_NET_CFG_MTU`: 网络设备配置的最大传输单元 (MTU)。
   - `VDPA_ATTR_DEV_NEGOTIATED_FEATURES`: VDPA 设备协商后的特性。
   - `VDPA_ATTR_DEV_MGMTDEV_MAX_VQS`: 管理设备支持的最大虚拟队列数量。
   - `VDPA_ATTR_DEV_SUPPORTED_FEATURES`: VDPA 设备支持的特性。
   - `VDPA_ATTR_DEV_QUEUE_INDEX`: 队列索引。
   - `VDPA_ATTR_DEV_VENDOR_ATTR_NAME`: 供应商特定属性的名称。
   - `VDPA_ATTR_DEV_VENDOR_ATTR_VALUE`: 供应商特定属性的值。
   - `VDPA_ATTR_DEV_FEATURES`: VDPA 设备的特性。
   - `VDPA_ATTR_DEV_BLK_CFG_CAPACITY`: 块设备容量。
   - `VDPA_ATTR_DEV_BLK_CFG_SIZE_MAX`: 块设备的最大大小。
   - `VDPA_ATTR_DEV_BLK_CFG_BLK_SIZE`: 块设备的块大小。
   - ... (其他块设备相关的配置属性，如扇区大小、队列数量、对齐偏移等)
   - `VDPA_ATTR_DEV_BLK_READ_ONLY`: 块设备是否为只读。
   - `VDPA_ATTR_DEV_BLK_FLUSH`: 块设备的刷新操作。
   - `VDPA_ATTR_MAX`: 枚举的最大值，通常用于表示枚举类型的长度。

**与 Android 功能的关系及举例说明**

VDPA 技术在 Android 中主要应用于**虚拟化和容器化**场景。

* **虚拟化 (Virtualization):** Android 可以作为宿主机运行虚拟机，例如使用 KVM (Kernel-based Virtual Machine)。在虚拟机内部运行的客户机操作系统可以使用 VDPA 设备直接访问宿主机的硬件资源，例如网络适配器或块存储设备。这可以提高虚拟机内的网络和存储性能，使得在虚拟机中运行对性能敏感的应用成为可能。
    * **举例:**  假设一个 Android 设备运行一个虚拟化的 Linux 环境。在 Linux 虚拟机内部，可以创建 VDPA 网络设备，该设备直接连接到 Android 宿主机的物理网卡。虚拟机内部的网络操作将通过 VDPA 绕过传统的虚拟网络层，直接与物理网卡通信，从而获得更高的网络吞吐量和更低的延迟。

* **容器化 (Containerization):** 类似于虚拟机，容器也可以利用 VDPA 技术。例如，在 Android 上运行的 Docker 容器，如果需要高性能的网络或存储访问，可以使用 VDPA 设备连接到宿主机的硬件。
    * **举例:** 一个运行在 Android 上的容器需要进行大量的磁盘 I/O 操作。可以通过 VDPA 创建一个虚拟块设备，该设备直接映射到 Android 宿主机的物理存储设备。容器内部的应用程序可以像访问普通块设备一样访问这个 VDPA 设备，从而获得接近物理硬件的存储性能。

**详细解释 libc 函数的功能是如何实现的**

这个头文件本身并不包含任何 libc 函数的实现。它只是定义了用于与内核 VDPA 子系统交互的常量和枚举。用户空间的程序（包括 Android framework 或 NDK 开发的应用）会使用这些常量，结合 Linux 系统调用（例如 `socket`, `bind`, `sendto`, `recvfrom` 等），通过 Generic Netlink 与内核的 VDPA 子系统进行通信。

**涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程**

这个头文件本身也不直接涉及 dynamic linker 的功能。它是一个静态的头文件，在编译时会被包含到相关的源文件中。

但是，如果一个包含使用这些 VDPA 常量的函数库被编译成共享库 (`.so` 文件)，那么 dynamic linker 在加载这个共享库时会参与链接过程。

**so 布局样本 (假设一个名为 `libvdpa_client.so` 的库使用了 `vdpa.h`):**

```
libvdpa_client.so:
    .text         # 代码段，包含使用 VDPA 常量的函数
        ...
        # 示例代码，使用 VDPA_GENL_NAME 和 VDPA_CMD_DEV_NEW
        mov     r0, #VDPA_GENL_NAME_ADDR  ; 加载 VDPA_GENL_NAME 的地址
        bl      some_netlink_function   ; 调用一个发送 Netlink 消息的函数
        ...
    .rodata       # 只读数据段，可能包含 VDPA_GENL_NAME 字符串
        VDPA_GENL_NAME_STR: .string "vdpa"
    .data         # 可读写数据段
    .bss          # 未初始化数据段
    .symtab       # 符号表
    .strtab       # 字符串表
    .rel.dyn      # 动态重定位表
    .rela.dyn     # 额外的动态重定位表
    ...
```

**链接的处理过程:**

1. **编译时:** 当编译 `libvdpa_client.c` (假设) 时，编译器会读取 `vdpa.h` 头文件，并将其中定义的常量（如 `VDPA_GENL_NAME`）替换到代码中。
2. **链接时:**  静态链接器会将 `libvdpa_client.o` (目标文件) 与其他必要的库链接在一起，生成 `libvdpa_client.so`。此时，`VDPA_GENL_NAME` 等常量的值已经被嵌入到 `.rodata` 段。
3. **运行时:** 当 Android 系统加载 `libvdpa_client.so` 时，dynamic linker 会执行以下步骤：
   - **加载共享库:** 将 `libvdpa_client.so` 的代码段、数据段等加载到内存中。
   - **符号解析:**  如果 `libvdpa_client.so` 中有对其他共享库的函数或全局变量的引用，dynamic linker 会查找这些符号的定义并进行绑定（但在这个例子中，`vdpa.h` 定义的是常量，不太可能涉及需要动态链接的符号）。
   - **重定位:**  dynamic linker 会根据 `.rel.dyn` 和 `.rela.dyn` 表中的信息，修改代码段和数据段中的地址，使其指向正确的内存位置。例如，如果代码中使用了 `VDPA_GENL_NAME` 的地址，dynamic linker 会将其重定位到 `.rodata` 段中 `VDPA_GENL_NAME_STR` 的实际地址。

**如果做了逻辑推理，请给出假设输入与输出**

假设我们想要获取一个名为 "my_vdpa_net_dev" 的 VDPA 网络设备的信息。

**假设输入:**

* 用户空间程序创建一个 Generic Netlink 套接字。
* 用户空间程序构造一个 Netlink 消息，其中：
    * `nlmsghdr.nl_family` 设置为 `AF_NETLINK`。
    * `nlmsghdr.nl_type` 设置为 `NLMSG_MIN` 或其他合适的类型。
    * `nlmsghdr.nl_protocol` 设置为 `NETLINK_GENERIC`。
    * Generic Netlink 头部中的 `cmd` 字段设置为 `VDPA_CMD_DEV_GET`。
    * Netlink 消息的 payload 包含一个或多个属性 (Netlink attributes)，其中至少包含：
        * `VDPA_ATTR_DEV_NAME` 的值为 "my_vdpa_net_dev"。

**预期输出:**

* 如果内核中存在名为 "my_vdpa_net_dev" 的 VDPA 设备，内核会回复一个 Netlink 消息，其中：
    * Generic Netlink 头部中的 `cmd` 字段仍然是 `VDPA_CMD_DEV_GET`。
    * Netlink 消息的 payload 包含该 VDPA 设备的各种属性，例如 `VDPA_ATTR_DEV_ID`，`VDPA_ATTR_DEV_VENDOR_ID`，`VDPA_ATTR_DEV_NET_CFG_MACADDR` 等。
* 如果内核中不存在该设备，可能会返回一个错误消息。

**如果涉及用户或者编程常见的使用错误，请举例说明**

1. **使用错误的属性 ID:**  在构造 Netlink 消息时，使用了不存在或不适用于特定命令的属性 ID。例如，在创建新的管理设备时尝试设置 VDPA 设备的 MAC 地址。

2. **发送无效的命令:**  发送内核不支持或在当前状态下不允许执行的命令。例如，尝试删除一个正在被使用的 VDPA 设备。

3. **缺少必要的属性:**  对于某些命令，需要提供特定的属性才能成功执行。例如，创建新的 VDPA 设备时，可能需要指定管理设备的名称。

4. **属性值格式错误:**  提供的属性值不符合预期的数据类型或格式。例如，MAC 地址应该是一个特定的字节序列。

5. **没有正确处理 Netlink 消息的回复:** 用户空间程序没有正确解析内核返回的 Netlink 消息，导致无法获取到 VDPA 设备的信息或错误地处理了错误信息。

6. **权限问题:** 用户空间程序可能没有足够的权限与 VDPA 内核子系统进行交互。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常情况下，Android Framework 不会直接使用 VDPA 相关的头文件。VDPA 更常用于较低层次的系统服务或硬件抽象层 (HAL)。

**NDK 的使用路径:**

1. **NDK 应用开发:** 开发者可以使用 NDK 编写 C/C++ 代码。
2. **包含头文件:** 在 NDK 代码中，开发者可以包含 `<linux/vdpa.h>` 头文件。需要注意的是，通常 NDK 并不会直接提供 Linux 内核的头文件，开发者可能需要将其复制到合适的包含路径下。
3. **使用系统调用进行交互:** NDK 代码需要使用底层的 Linux 系统调用（例如通过 `syscall()` 函数或者封装了 Netlink 通信的库）来构建和发送与 VDPA 相关的 Netlink 消息。
4. **编译和链接:** NDK 编译工具链会将代码编译成共享库或者可执行文件。

**Android Framework 的可能间接使用:**

Android Framework 中负责虚拟化或容器化管理的组件可能会间接使用 VDPA。例如，如果 Android 使用了某种基于 KVM 的容器技术，那么相关的系统服务可能会通过 JNI 调用到 Native 代码，而 Native 代码中可能会使用 VDPA 相关的接口。

**Frida Hook 示例:**

我们可以使用 Frida Hook 来观察用户空间程序与 VDPA 内核子系统的交互过程。以下是一个 Hook 示例，用于拦截发送到 Netlink 套接字的 `sendto` 调用，并打印出与 VDPA 相关的消息：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

def main():
    package_name = "com.example.myapp" # 替换为你的应用包名
    try:
        session = frida.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process '{package_name}' not found. Please run the app first.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            const sockfd = args[0].toInt32();
            const buf = args[1];
            const len = args[2].toInt32();
            const flags = args[3].toInt32();
            const dest_addr = args[4];
            const addrlen = args[5].toInt32();

            // 检查是否是 Netlink 套接字 (可能需要更精确的判断)
            if (dest_addr.isNull() === false) {
                const sa_family = dest_addr.readU16();
                if (sa_family === 18) { // AF_NETLINK
                    console.log("[*] sendto() called on Netlink socket:", sockfd);
                    console.log("    Length:", len);

                    // 读取 Netlink 消息头部
                    const nlmsghdr = buf.readByteArray(16); // 假设 nlmsghdr 结构体大小为 16 字节
                    console.log("    Netlink Header:", hexdump(nlmsghdr, { ansi: true }));

                    // 可以进一步解析 Netlink 消息的 payload，判断是否与 VDPA 相关
                    const genlhdr_offset = 16; // Netlink 头部大小
                    if (len > genlhdr_offset) {
                        const cmd = buf.add(genlhdr_offset).readU8(); // 假设 Generic Netlink 头部的第一个字节是 cmd
                        console.log("    Generic Netlink Command:", cmd);
                        // 可以根据 cmd 的值判断是否是 VDPA 相关命令
                    }
                }
            }
        },
        onLeave: function(retval) {
            //console.log("sendto() returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Frida script loaded. Intercepting sendto() calls...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida 工具。
2. **找到目标进程:** 运行你想要监控的 Android 应用或服务。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `hook_vdpa.py`，然后在终端中运行 `frida -U -f com.example.myapp hook_vdpa.py` (替换 `com.example.myapp` 为实际的包名)。
4. **观察输出:** 当目标应用调用 `sendto` 发送 Netlink 消息时，Frida 脚本会拦截调用并打印相关信息，你可以从中分析是否与 VDPA 相关。

**请注意:**

* 上面的 Frida 脚本只是一个基本的示例，可能需要根据具体的应用和 VDPA 使用方式进行调整，以便更准确地识别和解析 VDPA 相关的 Netlink 消息。
* Hook 系统调用需要 root 权限或在可调试的进程中进行。
* 分析 Netlink 消息的 payload 需要了解 VDPA 的 Netlink 协议结构。

希望这个详细的分析对您有所帮助!

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/vdpa.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_VDPA_H_
#define _UAPI_LINUX_VDPA_H_
#define VDPA_GENL_NAME "vdpa"
#define VDPA_GENL_VERSION 0x1
enum vdpa_command {
  VDPA_CMD_UNSPEC,
  VDPA_CMD_MGMTDEV_NEW,
  VDPA_CMD_MGMTDEV_GET,
  VDPA_CMD_DEV_NEW,
  VDPA_CMD_DEV_DEL,
  VDPA_CMD_DEV_GET,
  VDPA_CMD_DEV_CONFIG_GET,
  VDPA_CMD_DEV_VSTATS_GET,
  VDPA_CMD_DEV_ATTR_SET,
};
enum vdpa_attr {
  VDPA_ATTR_UNSPEC,
  VDPA_ATTR_PAD = VDPA_ATTR_UNSPEC,
  VDPA_ATTR_MGMTDEV_BUS_NAME,
  VDPA_ATTR_MGMTDEV_DEV_NAME,
  VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES,
  VDPA_ATTR_DEV_NAME,
  VDPA_ATTR_DEV_ID,
  VDPA_ATTR_DEV_VENDOR_ID,
  VDPA_ATTR_DEV_MAX_VQS,
  VDPA_ATTR_DEV_MAX_VQ_SIZE,
  VDPA_ATTR_DEV_MIN_VQ_SIZE,
  VDPA_ATTR_DEV_NET_CFG_MACADDR,
  VDPA_ATTR_DEV_NET_STATUS,
  VDPA_ATTR_DEV_NET_CFG_MAX_VQP,
  VDPA_ATTR_DEV_NET_CFG_MTU,
  VDPA_ATTR_DEV_NEGOTIATED_FEATURES,
  VDPA_ATTR_DEV_MGMTDEV_MAX_VQS,
  VDPA_ATTR_DEV_SUPPORTED_FEATURES,
  VDPA_ATTR_DEV_QUEUE_INDEX,
  VDPA_ATTR_DEV_VENDOR_ATTR_NAME,
  VDPA_ATTR_DEV_VENDOR_ATTR_VALUE,
  VDPA_ATTR_DEV_FEATURES,
  VDPA_ATTR_DEV_BLK_CFG_CAPACITY,
  VDPA_ATTR_DEV_BLK_CFG_SIZE_MAX,
  VDPA_ATTR_DEV_BLK_CFG_BLK_SIZE,
  VDPA_ATTR_DEV_BLK_CFG_SEG_MAX,
  VDPA_ATTR_DEV_BLK_CFG_NUM_QUEUES,
  VDPA_ATTR_DEV_BLK_CFG_PHY_BLK_EXP,
  VDPA_ATTR_DEV_BLK_CFG_ALIGN_OFFSET,
  VDPA_ATTR_DEV_BLK_CFG_MIN_IO_SIZE,
  VDPA_ATTR_DEV_BLK_CFG_OPT_IO_SIZE,
  VDPA_ATTR_DEV_BLK_CFG_MAX_DISCARD_SEC,
  VDPA_ATTR_DEV_BLK_CFG_MAX_DISCARD_SEG,
  VDPA_ATTR_DEV_BLK_CFG_DISCARD_SEC_ALIGN,
  VDPA_ATTR_DEV_BLK_CFG_MAX_WRITE_ZEROES_SEC,
  VDPA_ATTR_DEV_BLK_CFG_MAX_WRITE_ZEROES_SEG,
  VDPA_ATTR_DEV_BLK_READ_ONLY,
  VDPA_ATTR_DEV_BLK_FLUSH,
  VDPA_ATTR_MAX,
};
#endif
```