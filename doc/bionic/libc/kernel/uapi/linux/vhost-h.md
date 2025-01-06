Response:
Let's break down the thought process for generating the detailed response to the user's request about `vhost.h`.

**1. Understanding the Core Request:**

The user provided a header file and asked for:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it connect to Android?
* **libc Function Details:**  Explain the libc functions used (if any).
* **Dynamic Linker:**  How does it relate to the dynamic linker?
* **Logic Reasoning:**  Any inherent logic and assumptions.
* **Common Errors:** Potential usage mistakes.
* **Android Framework/NDK Path:** How does execution reach this code?
* **Frida Hooking:** Examples for debugging.

**2. Initial Analysis of the Header File:**

* **`#ifndef _LINUX_VHOST_H` etc.:**  Standard header guard to prevent multiple inclusions. This is a preprocessor directive, not a libc function.
* **`#include <linux/vhost_types.h>` and `#include <linux/types.h>`:** These are including other kernel headers. This immediately signals that this file is primarily about kernel-level functionality.
* **`#include <linux/ioctl.h>`:**  Key indicator! `ioctl` is the primary mechanism for user-space programs to interact with device drivers in the Linux kernel. This strongly suggests that the rest of the file defines `ioctl` commands.
* **`#define VHOST_FILE_UNBIND -1` and `#define VHOST_VIRTIO 0xAF`:**  Simple constant definitions. `VHOST_VIRTIO` likely identifies the subsystem these `ioctl`s belong to.
* **`#define VHOST_GET_FEATURES _IOR(...)` etc.:** The bulk of the file. These are macro definitions for `ioctl` commands. The `_IOR`, `_IOW`, `_IO`, and `_IOWR` macros are standard Linux kernel macros for defining `ioctl` commands with different data transfer directions (read, write, none, read/write). The arguments to these macros specify the "magic number" (`VHOST_VIRTIO`), the command number (e.g., `0x00`), and the data structure being passed.
* **Structure definitions within the `ioctl` definitions:**  References to structures like `vhost_memory`, `vhost_worker_state`, `vhost_vring_state`, etc. This hints at the data being exchanged between user-space and the kernel.

**3. Deconstructing the Request Point by Point:**

* **功能 (Functionality):**  The core functionality is to define the interface between user-space and the `vhost` kernel module. This module is responsible for offloading virtualization tasks (specifically network and storage) to the host kernel for performance. The `ioctl` commands allow configuring and controlling this offloading.

* **与 Android 的关系 (Android Relevance):**  Android uses virtualization technologies, especially for its emulator and potentially for containerization or other isolation mechanisms. `vhost` plays a role in making these virtualized environments efficient. The connection is indirect but important for performance. Specifically, KVM (Kernel-based Virtual Machine) often uses `vhost`.

* **libc 函数的功能 (libc Function Details):** The crucial libc function here is `ioctl`. The explanation needs to cover its purpose (general device control), its arguments (file descriptor, request code, optional argument), and its return value. It's important to emphasize that the *implementation* of the `ioctl` command lies within the kernel driver, not in libc itself.

* **dynamic linker 的功能 (Dynamic Linker):**  This file is a header file defining kernel constants. It's not directly involved in dynamic linking. The connection is that *user-space programs* that use the `vhost` interface will be linked by the dynamic linker, but the header file itself doesn't contain dynamic linking information. It's important to clarify this distinction and provide an example of a user-space program and its libraries.

* **逻辑推理 (Logic Reasoning):** The logic is inherent in the `ioctl` design:  a standardized way to communicate with kernel drivers. The assumption is that the kernel `vhost` module is loaded and registered to handle these `ioctl` commands.

* **用户或编程常见的使用错误 (Common Errors):** Focus on common `ioctl` mistakes: incorrect file descriptor, wrong `ioctl` code, incorrect data structure size or format, permission issues, and error handling.

* **Android framework or ndk 是如何一步步的到达这里 (Android Framework/NDK Path):**  This requires tracing the execution flow. Start with a high-level component (e.g., the emulator, a virtual networking service), then identify the code that opens a file descriptor (likely to `/dev/vhost-net` or a similar device), and then calls `ioctl` with the defined `VHOST_*` constants. NDK applications would use similar mechanisms.

* **frida hook 示例 (Frida Hooking):** Provide concrete examples of hooking the `ioctl` function, showing how to intercept calls and inspect arguments (the file descriptor and the `ioctl` request code).

**4. Structuring the Response:**

Organize the response according to the user's original questions, using clear headings and subheadings. Use code blocks for the header file and Frida examples. Explain concepts clearly and avoid jargon where possible.

**5. Refinement and Review:**

After drafting the response, review it for accuracy, clarity, and completeness. Ensure that the language is precise and addresses all aspects of the user's request. Double-check the Frida examples for correctness. Make sure the distinctions between user-space and kernel-space are clear. For instance, emphasize that `ioctl` is a *system call* handled by the kernel.

By following these steps, a comprehensive and accurate answer can be constructed, effectively addressing the user's request about the `vhost.h` header file. The key is to understand the context of the file (kernel interface) and to break down the request into manageable parts.
## bionic/libc/kernel/uapi/linux/vhost.handroid 的功能解析

这个文件 `vhost.h` 定义了用于与 Linux 内核中的 `vhost` 模块进行交互的接口。 `vhost` 模块是一个内核驱动，它通过利用内核的上下文来加速虚拟机 (VM) 和主机之间的网络和存储操作。它主要用于提升虚拟机性能。

**功能列表:**

1. **定义与 `vhost` 模块交互的 ioctl 命令:**  该文件主要定义了一系列 `ioctl` 命令宏，这些宏用于用户空间程序向 `vhost` 内核模块发送指令和获取信息。
2. **配置 `vhost` 设备的特性:**  例如，获取和设置 `vhost` 设备支持的特性（`VHOST_GET_FEATURES`, `VHOST_SET_FEATURES`）。
3. **管理 `vhost` 设备的拥有权:**  设置和重置设备的拥有者（`VHOST_SET_OWNER`, `VHOST_RESET_OWNER`）。
4. **配置虚拟机内存映射:**  设置虚拟机内存区域的描述符，以便 `vhost` 模块可以直接访问虚拟机内存（`VHOST_SET_MEM_TABLE`）。
5. **设置日志记录:**  配置日志记录相关的设置（`VHOST_SET_LOG_BASE`, `VHOST_SET_LOG_FD`）。
6. **管理工作线程:**  创建和释放用于处理 `vhost` 事件的工作线程（`VHOST_NEW_WORKER`, `VHOST_FREE_WORKER`）。
7. **配置 Virtio 环 (vring):**  设置 Virtio 环的大小、地址、基地址、字节序等关键参数。Virtio 环是虚拟机和主机之间共享的用于传递数据的环形缓冲区（`VHOST_SET_VRING_NUM`, `VHOST_SET_VRING_ADDR`, `VHOST_SET_VRING_BASE`, `VHOST_GET_VRING_BASE`, `VHOST_SET_VRING_ENDIAN`, `VHOST_GET_VRING_ENDIAN`）。
8. **管理 Virtio 环的工作线程关联:**  将 Virtio 环与特定的工作线程关联起来（`VHOST_ATTACH_VRING_WORKER`, `VHOST_GET_VRING_WORKER`）。
9. **设置 Virtio 环的通知机制:**  配置用于通知虚拟机和主机彼此事件的文件描述符，例如用于通知新数据的到来或处理完成（`VHOST_SET_VRING_KICK`, `VHOST_SET_VRING_CALL`, `VHOST_SET_VRING_ERR`）。
10. **配置后端特性:**  设置后端驱动的特性（`VHOST_SET_BACKEND_FEATURES`, `VHOST_GET_BACKEND_FEATURES`）。
11. **网络后端配置:**  为网络设备设置后端文件描述符（`VHOST_NET_SET_BACKEND`）。
12. **SCSI 后端配置:**  配置 SCSI 目标端点，用于加速虚拟机 SCSI 设备（`VHOST_SCSI_SET_ENDPOINT`, `VHOST_SCSI_CLEAR_ENDPOINT`, `VHOST_SCSI_GET_ABI_VERSION`, `VHOST_SCSI_SET_EVENTS_MISSED`, `VHOST_SCSI_GET_EVENTS_MISSED`）。
13. **VSOCK 配置:**  配置 VSOCK (虚拟套接字) 相关的参数，用于虚拟机和主机之间的通信（`VHOST_VSOCK_SET_GUEST_CID`, `VHOST_VSOCK_SET_RUNNING`）。
14. **VDPA (vhost Data Path Acceleration) 配置:**  配置 VDPA 设备相关的参数，VDPA 是一种标准化的数据通路加速框架（一系列 `VHOST_VDPA_*` 命令）。

**与 Android 功能的关系及举例说明:**

`vhost` 模块在 Android 中主要用于 **Android 模拟器 (Emulator)** 和 **容器化技术 (例如 Chrome OS 的 ARC++)**。

* **Android 模拟器:**  当你在 Android Studio 中运行模拟器时，模拟器实际上是一个运行在主机操作系统上的虚拟机。为了提升模拟器的网络和磁盘 I/O 性能，Android 模拟器会利用 `vhost` 模块。
    * **例子:** 模拟器进程会打开 `/dev/vhost-net` 设备文件，然后通过 `ioctl` 系统调用使用 `VHOST_SET_MEM_TABLE` 来告知内核虚拟机内存的布局，这样内核就可以直接访问虚拟机内存中的网络数据包，而无需额外的拷贝。 使用 `VHOST_NET_SET_BACKEND` 将主机上的 TAP 设备或 UNIX 域套接字与虚拟机的网络接口关联起来。
* **容器化技术 (ARC++)**:  ARC++ 允许在 Chrome OS 上运行 Android 应用。在这种场景下，Android 运行在一个容器中。`vhost` 可以用于加速容器的网络和存储访问。
    * **例子:**  ARC++ 容器内的进程可能会使用 `vhost` 来加速与主机网络栈的通信。

**libc 函数的功能及其实现:**

这个头文件本身 **并没有定义任何 libc 函数**。它定义的是 **ioctl 命令的常量**。用户空间程序使用 libc 提供的 `ioctl` 函数来调用这些命令。

**`ioctl` 函数的功能和实现:**

* **功能:** `ioctl` (input/output control) 是一个 Linux 系统调用，允许用户空间程序向设备驱动程序发送控制命令和获取设备信息。它是一个通用的接口，用于执行设备特定的操作。
* **实现:**
    1. **系统调用入口:** 用户空间程序调用 libc 提供的 `ioctl` 函数，例如：
       ```c
       #include <sys/ioctl.h>
       #include <fcntl.h>
       #include <unistd.h>
       #include <linux/vhost.h>

       int fd = open("/dev/vhost-net", O_RDWR);
       if (fd < 0) {
           perror("open");
           return 1;
       }

       __u64 features = 0;
       if (ioctl(fd, VHOST_GET_FEATURES, &features) < 0) {
           perror("ioctl VHOST_GET_FEATURES");
           close(fd);
           return 1;
       }
       ```
    2. **系统调用处理:**  内核接收到 `ioctl` 系统调用后，会根据文件描述符 `fd` 找到对应的设备驱动程序（在本例中是 `vhost` 模块）。
    3. **驱动程序处理:** `vhost` 模块会根据 `ioctl` 命令的编号 (`VHOST_GET_FEATURES`) 执行相应的操作。这通常涉及到访问或修改内核数据结构，与虚拟机的内存进行交互，或者与底层的硬件设备进行通信。
    4. **数据传递:** `ioctl` 命令可以携带数据，例如，`VHOST_GET_FEATURES` 用于从内核读取特性信息到用户空间的 `features` 变量中。 `VHOST_SET_MEM_TABLE` 用于将用户空间提供的内存布局信息传递给内核。
    5. **返回结果:**  `ioctl` 系统调用会返回一个整数，通常 0 表示成功，-1 表示失败，并设置 `errno` 来指示错误类型。

**涉及 dynamic linker 的功能:**

这个头文件 **不涉及 dynamic linker 的功能**。它定义的是内核接口。Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 负责加载和链接用户空间程序所需的共享库 (.so 文件)。

**so 布局样本以及链接的处理过程 (假设用户空间程序使用了 vhost):**

假设有一个名为 `my_vhost_app` 的用户空间程序使用了 `vhost` 模块。

**so 布局样本:**

```
/system/bin/my_vhost_app  (可执行文件)
/system/lib64/libc.so     (C 标准库)
/system/lib64/libdl.so    (动态链接器辅助库)
```

**链接的处理过程:**

1. **编译时链接:**  在编译 `my_vhost_app` 时，编译器会链接到 libc.so，因为 `ioctl` 函数是 libc 提供的。  编译器并不会直接链接到 `vhost` 内核模块，因为内核模块不是一个用户空间的共享库。
2. **运行时加载:** 当运行 `my_vhost_app` 时，`linker64` (或 `linker`) 会加载可执行文件和它依赖的共享库 (libc.so, libdl.so)。
3. **符号解析:**  `linker64` 会解析 `my_vhost_app` 中对 `ioctl` 函数的调用，并将其地址指向 libc.so 中 `ioctl` 函数的实现。
4. **系统调用:** 当 `my_vhost_app` 调用 `ioctl` 函数时，会触发一个系统调用，进入内核空间。内核会根据文件描述符将调用路由到 `vhost` 模块。

**逻辑推理和假设输入与输出:**

* **假设输入:** 用户空间程序打开了 `/dev/vhost-net` 设备文件，并希望获取 `vhost` 设备支持的特性。
* **ioctl 调用:**  `ioctl(fd, VHOST_GET_FEATURES, &features);`
* **逻辑推理:** 内核中的 `vhost` 模块会查询其内部状态，确定支持的特性，并将这些特性值写入到用户空间提供的 `features` 变量的内存地址中。
* **假设输出:**  如果 `vhost` 设备支持例如虚拟队列中断 (virtqueue interrupt signaling) 特性，`features` 变量的值可能会变为一个包含该特性标志位的 `__u64` 值。

**用户或编程常见的使用错误:**

1. **忘记包含头文件:**  如果代码中使用了 `VHOST_GET_FEATURES` 等宏，但没有包含 `<linux/vhost.h>`，会导致编译错误。
2. **错误的文件描述符:**  如果 `ioctl` 的第一个参数 `fd` 不是一个指向 `/dev/vhost-net` (或相关 vhost 设备) 的有效文件描述符，`ioctl` 调用会失败并返回错误码。
3. **错误的 ioctl 命令:**  使用了错误的 `ioctl` 命令宏，导致内核执行了错误的操作或者无法识别该命令。
4. **传递了错误的数据结构或大小:**  有些 `ioctl` 命令需要传递数据结构。如果传递的数据结构类型、大小或内容不正确，会导致内核处理错误甚至崩溃。例如，`VHOST_SET_MEM_TABLE` 需要传递正确的 `struct vhost_memory` 结构。
5. **权限问题:**  用户空间程序可能没有足够的权限打开 `/dev/vhost-net` 设备或执行特定的 `ioctl` 命令。
6. **不检查 `ioctl` 的返回值:**  `ioctl` 调用可能会失败，但如果没有检查返回值并处理错误，可能会导致程序逻辑错误。
7. **并发问题:**  在多线程或多进程环境下，多个线程或进程同时访问同一个 `vhost` 设备可能会导致竞争条件和数据不一致。

**例子:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/vhost.h>

int main() {
    int fd = open("/dev/vhost-net", O_RDWR);
    if (fd < 0) {
        perror("打开 /dev/vhost-net 失败");
        return 1;
    }

    __u64 features;
    // 错误：忘记初始化 features，可能导致读取到脏数据
    if (ioctl(fd, VHOST_GET_FEATURES, &features) == 0) {
        printf("VHOST 特性: 0x%llx\n", features);
    } else {
        perror("获取 VHOST 特性失败");
    }

    close(fd);
    return 0;
}
```

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **Android Framework (Java 层):**  通常 Android Framework 本身不会直接调用 `vhost` 相关的 `ioctl`。 `vhost` 的使用更多发生在更底层的系统服务或 HAL (Hardware Abstraction Layer) 中。
2. **Native Service (C++ 层):**  一些系统服务，例如负责管理虚拟网络设备的 `netd`，可能会涉及到与 `vhost` 模块的交互。这些服务通常使用 NDK 提供的接口来调用底层的系统调用。
3. **HAL (C/C++ 层):**  如果某个硬件抽象层需要使用虚拟化技术，例如虚拟网卡设备的 HAL，它可能会直接调用 `ioctl` 与 `vhost` 模块进行通信。
4. **NDK 应用 (C/C++ 层):**  理论上，NDK 应用也可以直接访问 `/dev/vhost-net` 并调用 `ioctl`，但这通常发生在需要进行底层虚拟化操作的场景，例如开发自定义的虚拟机管理工具。

**Frida hook 示例调试这些步骤:**

假设我们要 hook 一个 NDK 应用或系统服务中对 `ioctl` 系统调用并且 `cmd` 参数为 `VHOST_GET_FEATURES` 的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    # 替换为你的目标进程名称或 PID
    process = frida.get_usb_device().attach('com.example.myapp')
except frida.ProcessNotFoundError:
    print("找不到目标进程，请确认进程正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const cmd = args[1].toInt32();
        const buf = args[2];

        if (cmd === 0xaf00) { // VHOST_GET_FEATURES 的值 (_IOR(VHOST_VIRTIO, 0x00, __u64))
            this.fd = fd;
            this.cmd = cmd;
            console.log("[*] ioctl called with fd:", fd, "cmd:", cmd);
            // 可以读取 buf 的内容，但要注意指针类型和大小
            // console.log("[*] buf:", buf.readU64());
        }
    },
    onLeave: function(retval) {
        if (this.cmd === 0xaf00 && retval.toInt32() === 0) {
            console.log("[*] ioctl returned:", retval, "Features:", ptr(this.buf).readU64());
        }
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

1. **`frida.get_usb_device().attach('com.example.myapp')`:** 连接到 USB 连接的 Android 设备，并附加到目标进程。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 系统调用。`Module.findExportByName(null, "ioctl")` 会找到任何模块（包括 libc）导出的 `ioctl` 函数。
3. **`onEnter`:** 在 `ioctl` 函数被调用时执行。
    * `args[0]` 是文件描述符 `fd`。
    * `args[1]` 是 `ioctl` 命令 `cmd`。
    * `args[2]` 是传递给 `ioctl` 的数据缓冲区 `buf`。
    * 我们检查 `cmd` 是否等于 `VHOST_GET_FEATURES` 的值 (需要计算 `_IOR(VHOST_VIRTIO, 0x00, __u64)` 的结果)。
    * 如果是，我们记录下 `fd` 和 `cmd`。
4. **`onLeave`:** 在 `ioctl` 函数执行完毕并返回时执行。
    * `retval` 是 `ioctl` 的返回值。
    * 如果 `cmd` 是 `VHOST_GET_FEATURES` 并且返回值是 0 (成功)，我们可以尝试读取 `buf` 指向的内存，获取返回的特性值。 **注意：这里需要根据实际情况调整指针读取的方式和大小。**

这个 Frida 脚本可以帮助你观察哪些进程调用了与 `vhost` 相关的 `ioctl` 命令，以及传递的参数和返回值，从而帮助你调试和理解 Android 中 `vhost` 的使用情况。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/vhost.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_VHOST_H
#define _LINUX_VHOST_H
#include <linux/vhost_types.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#define VHOST_FILE_UNBIND - 1
#define VHOST_VIRTIO 0xAF
#define VHOST_GET_FEATURES _IOR(VHOST_VIRTIO, 0x00, __u64)
#define VHOST_SET_FEATURES _IOW(VHOST_VIRTIO, 0x00, __u64)
#define VHOST_SET_OWNER _IO(VHOST_VIRTIO, 0x01)
#define VHOST_RESET_OWNER _IO(VHOST_VIRTIO, 0x02)
#define VHOST_SET_MEM_TABLE _IOW(VHOST_VIRTIO, 0x03, struct vhost_memory)
#define VHOST_SET_LOG_BASE _IOW(VHOST_VIRTIO, 0x04, __u64)
#define VHOST_SET_LOG_FD _IOW(VHOST_VIRTIO, 0x07, int)
#define VHOST_NEW_WORKER _IOR(VHOST_VIRTIO, 0x8, struct vhost_worker_state)
#define VHOST_FREE_WORKER _IOW(VHOST_VIRTIO, 0x9, struct vhost_worker_state)
#define VHOST_SET_VRING_NUM _IOW(VHOST_VIRTIO, 0x10, struct vhost_vring_state)
#define VHOST_SET_VRING_ADDR _IOW(VHOST_VIRTIO, 0x11, struct vhost_vring_addr)
#define VHOST_SET_VRING_BASE _IOW(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_GET_VRING_BASE _IOWR(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_VRING_LITTLE_ENDIAN 0
#define VHOST_VRING_BIG_ENDIAN 1
#define VHOST_SET_VRING_ENDIAN _IOW(VHOST_VIRTIO, 0x13, struct vhost_vring_state)
#define VHOST_GET_VRING_ENDIAN _IOW(VHOST_VIRTIO, 0x14, struct vhost_vring_state)
#define VHOST_ATTACH_VRING_WORKER _IOW(VHOST_VIRTIO, 0x15, struct vhost_vring_worker)
#define VHOST_GET_VRING_WORKER _IOWR(VHOST_VIRTIO, 0x16, struct vhost_vring_worker)
#define VHOST_SET_VRING_KICK _IOW(VHOST_VIRTIO, 0x20, struct vhost_vring_file)
#define VHOST_SET_VRING_CALL _IOW(VHOST_VIRTIO, 0x21, struct vhost_vring_file)
#define VHOST_SET_VRING_ERR _IOW(VHOST_VIRTIO, 0x22, struct vhost_vring_file)
#define VHOST_SET_VRING_BUSYLOOP_TIMEOUT _IOW(VHOST_VIRTIO, 0x23, struct vhost_vring_state)
#define VHOST_GET_VRING_BUSYLOOP_TIMEOUT _IOW(VHOST_VIRTIO, 0x24, struct vhost_vring_state)
#define VHOST_SET_BACKEND_FEATURES _IOW(VHOST_VIRTIO, 0x25, __u64)
#define VHOST_GET_BACKEND_FEATURES _IOR(VHOST_VIRTIO, 0x26, __u64)
#define VHOST_NET_SET_BACKEND _IOW(VHOST_VIRTIO, 0x30, struct vhost_vring_file)
#define VHOST_SCSI_SET_ENDPOINT _IOW(VHOST_VIRTIO, 0x40, struct vhost_scsi_target)
#define VHOST_SCSI_CLEAR_ENDPOINT _IOW(VHOST_VIRTIO, 0x41, struct vhost_scsi_target)
#define VHOST_SCSI_GET_ABI_VERSION _IOW(VHOST_VIRTIO, 0x42, int)
#define VHOST_SCSI_SET_EVENTS_MISSED _IOW(VHOST_VIRTIO, 0x43, __u32)
#define VHOST_SCSI_GET_EVENTS_MISSED _IOW(VHOST_VIRTIO, 0x44, __u32)
#define VHOST_VSOCK_SET_GUEST_CID _IOW(VHOST_VIRTIO, 0x60, __u64)
#define VHOST_VSOCK_SET_RUNNING _IOW(VHOST_VIRTIO, 0x61, int)
#define VHOST_VDPA_GET_DEVICE_ID _IOR(VHOST_VIRTIO, 0x70, __u32)
#define VHOST_VDPA_GET_STATUS _IOR(VHOST_VIRTIO, 0x71, __u8)
#define VHOST_VDPA_SET_STATUS _IOW(VHOST_VIRTIO, 0x72, __u8)
#define VHOST_VDPA_GET_CONFIG _IOR(VHOST_VIRTIO, 0x73, struct vhost_vdpa_config)
#define VHOST_VDPA_SET_CONFIG _IOW(VHOST_VIRTIO, 0x74, struct vhost_vdpa_config)
#define VHOST_VDPA_SET_VRING_ENABLE _IOW(VHOST_VIRTIO, 0x75, struct vhost_vring_state)
#define VHOST_VDPA_GET_VRING_NUM _IOR(VHOST_VIRTIO, 0x76, __u16)
#define VHOST_VDPA_SET_CONFIG_CALL _IOW(VHOST_VIRTIO, 0x77, int)
#define VHOST_VDPA_GET_IOVA_RANGE _IOR(VHOST_VIRTIO, 0x78, struct vhost_vdpa_iova_range)
#define VHOST_VDPA_GET_CONFIG_SIZE _IOR(VHOST_VIRTIO, 0x79, __u32)
#define VHOST_VDPA_GET_AS_NUM _IOR(VHOST_VIRTIO, 0x7A, unsigned int)
#define VHOST_VDPA_GET_VRING_GROUP _IOWR(VHOST_VIRTIO, 0x7B, struct vhost_vring_state)
#define VHOST_VDPA_SET_GROUP_ASID _IOW(VHOST_VIRTIO, 0x7C, struct vhost_vring_state)
#define VHOST_VDPA_SUSPEND _IO(VHOST_VIRTIO, 0x7D)
#define VHOST_VDPA_RESUME _IO(VHOST_VIRTIO, 0x7E)
#define VHOST_VDPA_GET_VRING_DESC_GROUP _IOWR(VHOST_VIRTIO, 0x7F, struct vhost_vring_state)
#define VHOST_VDPA_GET_VQS_COUNT _IOR(VHOST_VIRTIO, 0x80, __u32)
#define VHOST_VDPA_GET_GROUP_NUM _IOR(VHOST_VIRTIO, 0x81, __u32)
#define VHOST_VDPA_GET_VRING_SIZE _IOWR(VHOST_VIRTIO, 0x82, struct vhost_vring_state)
#endif

"""

```