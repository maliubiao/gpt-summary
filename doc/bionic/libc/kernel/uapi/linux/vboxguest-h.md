Response:
Let's break down the thought process for answering the request about the `vboxguest.h` header file.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`vboxguest.h`) and explain its purpose and relationship to Android. The request also specifically asks for details on `libc` functions, dynamic linking, usage errors, and how Android frameworks access this code.

**2. Initial Analysis of the Header File:**

* **`/* ... auto-generated ... */`:** This is a crucial hint. It tells us this isn't code written by hand, but rather generated, likely from some other definition. This immediately suggests it defines an interface rather than implementing logic directly.
* **`#ifndef __UAPI_VBOXGUEST_H__ ... #endif`:**  Standard include guard, preventing multiple inclusions.
* **Includes:**  `<asm/bitsperlong.h>`, `<linux/ioctl.h>`, `<linux/vbox_err.h>`, `<linux/vbox_vmmdev_types.h>`. These point strongly towards this being a kernel-level interface for interacting with a VirtualBox guest driver. `ioctl.h` is the giveaway for device control.
* **`#define VBG_IOCTL_HDR_VERSION ...` and `struct vbg_ioctl_hdr`:** This defines a common header structure for ioctl commands. It includes sizes, a version, a type, and a return code. This reinforces the ioctl nature of the file.
* **`#define VBG_IOC_VERSION ...` and `struct vbg_ioctl_driver_version_info`:**  Defines an ioctl to get driver version information. The structure contains input (requested versions) and output (actual versions).
* **`#define VBG_IOCTL_DRIVER_VERSION_INFO _IOWR('V', 0, ...)`:** This is the core of an ioctl definition. `_IOWR` indicates a read/write ioctl. `'V'` is the magic number for the device. `0` is the command number. This is how the kernel knows which operation to perform.
* **Other `VBG_IOCTL_*` definitions:**  These follow the same pattern, defining different ioctl commands and their associated data structures. Keywords like `HGCM` (Host Guest Communication Manager), `CONNECT`, `DISCONNECT`, `CALL`, `LOG`, `WAIT_FOR_EVENTS`, `CHANGE_FILTER`, `ACQUIRE_GUEST_CAPABILITIES`, `SET_GUEST_CAPS`, `CHECK_BALLOON`, `WRITE_CORE_DUMP` provide strong clues about the functionalities.
* **`#if __BITS_PER_LONG == 64 ... #endif`:** Conditional compilation based on the system's word size. This is common when dealing with kernel interfaces where data sizes matter.

**3. Connecting to the Request's Specific Points:**

* **功能 (Functionality):**  Based on the ioctl definitions and structure names, the file defines the interface for controlling and communicating with the VirtualBox guest driver. This involves tasks like:
    * Getting driver version.
    * Requesting VMM operations.
    * Connecting/disconnecting to HGCM services.
    * Making HGCM calls (inter-process communication between host and guest).
    * Logging messages.
    * Waiting for events.
    * Managing guest capabilities.
    * Checking balloon driver status.
    * Triggering a core dump.

* **与 Android 的关系 (Relationship to Android):** Android, when running as a guest in VirtualBox, uses this interface to interact with the host operating system. This allows for features like shared folders, clipboard sharing, and potentially enhanced graphics.

* **libc 函数 (libc functions):** The file *defines* the interface, it doesn't *implement* libc functions. The *use* of these definitions would likely involve standard libc functions like `open()`, `ioctl()`, and `close()`. The request to explain *how* each libc function is implemented is a misdirection; this file defines *arguments* to `ioctl`, not the implementation of `ioctl` itself.

* **Dynamic Linker (动态链接器):** This header file itself doesn't directly involve dynamic linking. However, *code that uses this header* (like a VirtualBox guest service) would be a shared library (.so) and would be subject to the dynamic linker.

* **逻辑推理 (Logical Deduction):** The naming conventions and structure of the ioctls allow for logical deductions about their purpose. For instance, `VBG_IOCTL_HGCM_CONNECT` likely takes service location info as input and returns a client ID.

* **用户/编程常见错误 (Common Usage Errors):**  Incorrectly sized data structures passed to `ioctl`, incorrect ioctl numbers, not checking the return code of `ioctl`, and misunderstanding the input/output expectations of each ioctl are all common errors.

* **Android Framework/NDK Access:**  The path would likely be:  Android framework (Java/Kotlin) -> Native code (C/C++) using NDK -> System calls (including `ioctl`) -> Kernel driver (VirtualBox guest driver).

* **Frida Hook 示例 (Frida Hook Example):** Focus on hooking the `ioctl` system call with the specific 'V' magic number to intercept calls related to the VirtualBox guest driver.

**4. Structuring the Answer:**

Organize the answer logically, addressing each part of the request. Start with a high-level overview, then delve into specifics. Use clear headings and examples.

**5. Refinement and Clarity:**

Review the answer for clarity and accuracy. Ensure the language is understandable and avoids overly technical jargon where possible. Explicitly state when something is not directly related to the header file (like the implementation of libc functions).

By following this thought process, we can systematically analyze the header file and provide a comprehensive and accurate answer to the complex request. The key is to understand the context (a kernel-level interface for a guest operating system) and how the different elements of the header contribute to that purpose.
这个头文件 `bionic/libc/kernel/uapi/linux/vboxguest.handroid/vboxguest.h` 定义了用户空间程序与 Linux 内核中的 VirtualBox Guest Driver 交互的接口。由于它位于 `uapi` 目录下，这意味着它是用户空间应用程序可以安全包含并使用的头文件，用于和内核模块通信。

**功能列举:**

这个头文件定义了一系列 ioctl 命令（Input/Output Control），这些命令允许虚拟机内的 Android 系统（Guest OS）与运行 VirtualBox 的宿主机（Host OS）上的 VirtualBox Guest Driver 进行通信。 主要功能包括：

1. **获取驱动版本信息 (`VBG_IOCTL_DRIVER_VERSION_INFO`):** 允许 Guest OS 查询 Guest Driver 的版本信息，包括会话版本、驱动版本和修订号。
2. **发送通用 VMM 设备请求 (`VBG_IOCTL_VMMDEV_REQUEST`, `VBG_IOCTL_VMMDEV_REQUEST_BIG`):** 提供一个通用的机制，允许 Guest OS 向 Virtual Machine Monitor (VMM) 发送请求。具体的请求内容由 `vmmdev_types.h` 中定义的结构体决定。
3. **连接到 HGCM 服务 (`VBG_IOCTL_HGCM_CONNECT`):** 允许 Guest OS 连接到宿主机上的 Host Guest Communication Manager (HGCM) 服务。这通常用于实现虚拟机和宿主机之间的功能共享，例如共享文件夹、剪贴板等。
4. **断开 HGCM 连接 (`VBG_IOCTL_HGCM_DISCONNECT`):**  允许 Guest OS 断开与 HGCM 服务的连接。
5. **调用 HGCM 函数 (`VBG_IOCTL_HGCM_CALL`):** 允许 Guest OS 调用宿主机上 HGCM 服务提供的特定函数。这是实现 Guest 和 Host 之间功能调用的核心机制。
6. **发送日志消息 (`VBG_IOCTL_LOG`):** 允许 Guest OS 向宿主机上的 VirtualBox 日志系统发送消息，用于调试和监控。
7. **等待事件 (`VBG_IOCTL_WAIT_FOR_EVENTS`):** 允许 Guest OS 等待特定的事件发生，并设置超时时间。
8. **中断所有等待事件的操作 (`VBG_IOCTL_INTERRUPT_ALL_WAIT_FOR_EVENTS`):** 允许中断所有正在进行的等待事件操作。
9. **修改事件过滤器 (`VBG_IOCTL_CHANGE_FILTER_MASK`):** 允许 Guest OS 修改它感兴趣的事件类型，通过设置或清除掩码来实现。
10. **获取 Guest 能力 (`VBG_IOCTL_ACQUIRE_GUEST_CAPABILITIES`):** 允许 Guest OS 查询自身的能力，例如支持的功能特性。
11. **设置 Guest 能力 (`VBG_IOCTL_CHANGE_GUEST_CAPABILITIES`):** 允许 Guest OS 设置或修改其能力标识。
12. **检查气球驱动状态 (`VBG_IOCTL_CHECK_BALLOON`):** 允许 Guest OS 检查 VirtualBox 的内存气球驱动的状态，该驱动用于动态调整 Guest OS 的内存使用。
13. **写入 Core Dump (`VBG_IOCTL_WRITE_CORE_DUMP`):** 允许 Guest OS 请求 VirtualBox Guest Driver 写入一个 core dump 文件，用于调试 Guest OS 的崩溃问题。

**与 Android 功能的关系及举例说明:**

当 Android 系统作为 VirtualBox 的 Guest OS 运行时，它需要与宿主机进行交互以实现一些虚拟化特性。这个头文件中定义的 ioctl 命令是实现这些交互的关键。以下是一些例子：

* **共享文件夹:**  Android 可以通过 HGCM 服务与宿主机共享文件夹。当用户在 Android 中访问共享文件夹时，相关的操作（例如列出文件、读取文件）会通过 `VBG_IOCTL_HGCM_CONNECT` 连接到 HGCM 服务，然后使用 `VBG_IOCTL_HGCM_CALL` 调用宿主机上相应的服务函数来完成文件系统的操作。

* **剪贴板共享:**  Android 和宿主机之间的剪贴板共享也是通过 HGCM 实现的。当用户在 Android 中复制内容时，数据会通过 `VBG_IOCTL_HGCM_CALL` 发送到宿主机的 HGCM 服务。当用户在宿主机中粘贴时，宿主机的 HGCM 服务会把数据发送回 Android (反之亦然)。

* **图形加速:**  虽然这个头文件没有直接涉及图形加速的 ioctl，但底层的图形驱动程序可能会使用 `VBG_IOCTL_VMMDEV_REQUEST` 发送与图形相关的命令给 VirtualBox 的 VMM，以利用宿主机的 GPU 进行加速。

* **内存管理 (气球驱动):** VirtualBox 的气球驱动允许宿主机回收 Guest OS 中未使用的内存。Android 中的相关服务可能会定期调用 `VBG_IOCTL_CHECK_BALLOON` 来了解气球驱动的状态，并根据需要调整自身的内存使用。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**并没有定义或实现任何 libc 函数**。它定义的是与内核模块通信的接口（ioctl 命令）。用户空间程序（包括 Android 的组件）会使用标准的 libc 函数，如 `open()`, `ioctl()`, 和 `close()`，来与 `/dev/vboxguest` 设备文件进行交互，从而调用这里定义的 ioctl 命令。

例如，要调用 `VBG_IOCTL_DRIVER_VERSION_INFO` 获取驱动版本，Android 应用程序会执行以下步骤：

1. 使用 `open("/dev/vboxguest", O_RDWR)` 打开 VirtualBox Guest Driver 的设备文件。
2. 填充 `vbg_ioctl_driver_version_info` 结构体的 `in` 部分，指定期望的版本信息（如果需要）。
3. 使用 `ioctl(fd, VBG_IOCTL_DRIVER_VERSION_INFO, &version_info)` 调用 ioctl 系统调用，其中 `fd` 是打开的文件描述符，`VBG_IOCTL_DRIVER_VERSION_INFO` 是要执行的 ioctl 命令，`&version_info` 是包含输入和输出数据的结构体指针。
4. `ioctl` 系统调用会将请求传递给内核中的 VirtualBox Guest Driver。
5. Guest Driver 处理该 ioctl，并将驱动版本信息填充到 `version_info` 结构体的 `out` 部分。
6. `ioctl` 系统调用返回，应用程序可以从 `version_info` 中读取驱动版本信息。
7. 使用 `close(fd)` 关闭设备文件。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。然而，任何使用这个头文件的用户空间程序（例如，一个实现 VirtualBox Guest 服务的 `.so` 库）都会受到 dynamic linker 的影响。

**so 布局样本:**

一个可能使用 `vboxguest.h` 的 `.so` 库的布局可能如下所示：

```
my_vbox_guest_service.so:
    .text         # 包含代码段
        - 函数实现，包括使用 ioctl 调用 Guest Driver 的代码
    .rodata       # 包含只读数据
        - 可能包含一些常量
    .data         # 包含可读写数据
        - 可能包含一些全局变量
    .bss          # 包含未初始化的数据
    .dynamic      # 包含动态链接信息
        - 指向 .dynsym, .dynstr, .plt, .got 等段
    .dynsym       # 动态符号表
        - 包含本 so 导出和导入的符号信息
    .dynstr       # 动态字符串表
        - 包含符号表中使用的字符串
    .plt          # 程序链接表 (Procedure Linkage Table)
        - 用于延迟绑定外部函数
    .got          # 全局偏移表 (Global Offset Table)
        - 用于存储外部函数的地址
    ... 其他段 ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译使用 `vboxguest.h` 的 `.c` 或 `.cpp` 文件时，编译器会解析头文件中的定义，但并不会解析 `ioctl` 系统调用的具体实现（因为它在内核中）。编译器会生成对 `ioctl` 等 libc 函数的调用。
2. **动态链接:** 当 Android 系统加载 `my_vbox_guest_service.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   - **加载依赖库:**  如果 `my_vbox_guest_service.so` 依赖于其他共享库（例如 libc），dynamic linker 会先加载这些依赖库。
   - **符号解析:** dynamic linker 会解析 `my_vbox_guest_service.so` 中引用的外部符号，例如 `ioctl`。由于 `ioctl` 是 libc 的一部分，dynamic linker 会在已加载的 libc 库中查找 `ioctl` 的地址。
   - **重定位:** dynamic linker 会修改 `my_vbox_guest_service.so` 的 `.got` 段中的条目，将外部符号的地址填入。对于通过 PLT 调用的函数，首次调用时会触发延迟绑定，dynamic linker 会解析符号并更新 GOT 表。
   - **执行初始化:** dynamic linker 会执行 `.init` 和 `.ctors` 段中的初始化代码。

在这个场景下，`vboxguest.h` 扮演的角色是定义了与内核交互的常量和数据结构，而 dynamic linker 负责确保程序能够正确调用 libc 提供的 `ioctl` 函数。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们调用 `VBG_IOCTL_DRIVER_VERSION_INFO` 获取驱动版本信息。

**假设输入:**

```c
struct vbg_ioctl_driver_version_info version_info;
version_info.hdr.size_in = sizeof(version_info.u.in);
version_info.hdr.version = VBG_IOCTL_HDR_VERSION;
version_info.hdr.type = VBG_IOCTL_HDR_TYPE_DEFAULT;
version_info.u.in.req_version = VBG_IOC_VERSION; // 请求的版本
version_info.u.in.min_version = 0x00010000;    // 期望的最低版本
version_info.u.in.reserved1 = 0;
version_info.u.in.reserved2 = 0;
```

**预期输出 (假设驱动版本为 0x00050001，修订号为 123):**

```c
version_info.hdr.rc = 0; // 成功
version_info.hdr.size_out = sizeof(version_info.u.out);
version_info.u.out.session_version = ...; // 具体会话版本号
version_info.u.out.driver_version = 0x00050001;
version_info.u.out.driver_revision = 123;
version_info.u.out.reserved1 = 0;
version_info.u.out.reserved2 = 0;
```

如果驱动版本不兼容，`version_info.hdr.rc` 可能会返回一个非零的错误码。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记初始化 `vbg_ioctl_hdr`:**  用户可能忘记设置 `size_in`、`version` 或 `type` 等字段，导致内核无法正确解析 ioctl 请求。
2. **传递错误的 `ioctl` 命令号:** 使用了错误的 `VBG_IOCTL_*` 宏，导致内核执行了错误的操作。
3. **传递大小不匹配的数据结构:**  `ioctl` 的第三个参数必须指向与 ioctl 命令预期大小匹配的数据结构。传递过小或过大的结构体可能导致数据损坏或内核崩溃。
4. **没有检查 `ioctl` 的返回值:** `ioctl` 函数返回 0 表示成功，-1 表示失败并设置 `errno`。用户如果没有检查返回值，可能无法发现错误。
5. **在错误的上下文中调用 `ioctl`:** 某些 ioctl 可能只能在特定的进程或线程上下文中调用。
6. **竞争条件:**  多个线程或进程同时尝试操作 VirtualBox Guest Driver 可能会导致竞争条件，需要适当的同步机制。
7. **对 `union` 的使用不当:** 结构体中使用了 `union`，用户需要确保只访问当前 ioctl 命令对应的成员，访问错误的成员可能导致数据错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java/Kotlin):**  Android Framework 层通常不会直接调用这些底层的 ioctl 命令。相反，它会通过更高层次的抽象接口与虚拟机进行交互。

2. **Native Code (C/C++ via NDK):**  如果 Android 需要执行一些虚拟机特定的操作，可能会使用 NDK 编写 C/C++ 代码。在这个 C/C++ 代码中，开发者会：
   - 包含 `vboxguest.h` 头文件。
   - 使用 `open("/dev/vboxguest", ...)` 打开 VirtualBox Guest Driver 设备文件。
   - 构造相应的 `vbg_ioctl_*` 结构体。
   - 调用 `ioctl(fd, VBG_IOCTL_..., &data)` 执行 ioctl 命令。
   - 处理 `ioctl` 的返回值。
   - 使用 `close(fd)` 关闭设备文件。

3. **System Call:**  `ioctl` 是一个系统调用。当 C/C++ 代码调用 `ioctl` 函数时，会触发一个从用户空间到内核空间的上下文切换。

4. **Kernel - VirtualBox Guest Driver:** Linux 内核接收到 `ioctl` 系统调用后，会根据设备文件 (`/dev/vboxguest`) 和 ioctl 命令号，将请求分发给 VirtualBox Guest Driver 模块。

5. **VirtualBox Guest Driver Logic:** Guest Driver 模块根据接收到的 ioctl 命令执行相应的操作，例如与宿主机的 VirtualBox 进程通信，获取或设置虚拟机状态等。

**Frida Hook 示例:**

可以使用 Frida Hook 来观察 Android 应用如何与 VirtualBox Guest Driver 交互。以下是一个 Hook `ioctl` 系统调用的示例，用于捕获与 VirtualBox Guest Driver 相关的 ioctl 调用：

```javascript
// attach 到目标进程
function hook_ioctl() {
    const ioctlPtr = Module.findExportByName(null, "ioctl");
    if (ioctlPtr) {
        Interceptor.attach(ioctlPtr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                const buf = args[2];

                // 检查文件描述符是否与 /dev/vboxguest 相关
                try {
                    const path = Socket.peerPath(fd);
                    if (path && path.includes("vboxguest")) {
                        console.log("[ioctl] Called with fd:", fd, "request:", request);

                        // 根据 request 的值，解析并打印相关数据
                        if (request === 0xc0045600) { // VBG_IOCTL_DRIVER_VERSION_INFO
                            const versionInfo = Memory.readByteArray(buf, 40); // 假设结构体大小为 40 字节
                            console.log("[ioctl] VBG_IOCTL_DRIVER_VERSION_INFO data:", hexdump(versionInfo, { ansi: true }));
                        } else if (request === 0xc0085604) { // VBG_IOCTL_HGCM_CONNECT
                            const connectInfo = Memory.readByteArray(buf, 40);
                            console.log("[ioctl] VBG_IOCTL_HGCM_CONNECT data:", hexdump(connectInfo, { ansi: true }));
                        }
                        // ... 其他 ioctl 命令的解析 ...
                    }
                } catch (e) {
                    // 可能文件描述符不是 socket，忽略错误
                }
            },
            onLeave: function (retval) {
                //console.log("[ioctl] Return value:", retval);
            }
        });
        console.log("[Frida] Hooked ioctl");
    } else {
        console.log("[Frida] Failed to find ioctl");
    }
}

setImmediate(hook_ioctl);
```

这个 Frida 脚本会 Hook `ioctl` 系统调用，并检查文件描述符是否与 `/dev/vboxguest` 相关。如果是，它会打印出 ioctl 命令号，并尝试解析和打印与该命令相关的数据结构的内容。你需要根据具体的 ioctl 命令和数据结构来修改解析部分的代码。

通过这样的 Hook，你可以观察到 Android 应用在运行时如何调用这些底层的 VirtualBox Guest Driver 接口，从而理解 Android Framework 或 NDK 是如何一步步到达这里的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/vboxguest.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UAPI_VBOXGUEST_H__
#define __UAPI_VBOXGUEST_H__
#include <asm/bitsperlong.h>
#include <linux/ioctl.h>
#include <linux/vbox_err.h>
#include <linux/vbox_vmmdev_types.h>
#define VBG_IOCTL_HDR_VERSION 0x10001
#define VBG_IOCTL_HDR_TYPE_DEFAULT 0
struct vbg_ioctl_hdr {
  __u32 size_in;
  __u32 version;
  __u32 type;
  __s32 rc;
  __u32 size_out;
  __u32 reserved;
};
#define VBG_IOC_VERSION 0x00010000u
struct vbg_ioctl_driver_version_info {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 req_version;
      __u32 min_version;
      __u32 reserved1;
      __u32 reserved2;
    } in;
    struct {
      __u32 session_version;
      __u32 driver_version;
      __u32 driver_revision;
      __u32 reserved1;
      __u32 reserved2;
    } out;
  } u;
};
#define VBG_IOCTL_DRIVER_VERSION_INFO _IOWR('V', 0, struct vbg_ioctl_driver_version_info)
#define VBG_IOCTL_VMMDEV_REQUEST(s) _IOC(_IOC_READ | _IOC_WRITE, 'V', 2, s)
#define VBG_IOCTL_VMMDEV_REQUEST_BIG _IO('V', 3)
struct vbg_ioctl_hgcm_connect {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      struct vmmdev_hgcm_service_location loc;
    } in;
    struct {
      __u32 client_id;
    } out;
  } u;
};
#define VBG_IOCTL_HGCM_CONNECT _IOWR('V', 4, struct vbg_ioctl_hgcm_connect)
struct vbg_ioctl_hgcm_disconnect {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 client_id;
    } in;
  } u;
};
#define VBG_IOCTL_HGCM_DISCONNECT _IOWR('V', 5, struct vbg_ioctl_hgcm_disconnect)
struct vbg_ioctl_hgcm_call {
  struct vbg_ioctl_hdr hdr;
  __u32 client_id;
  __u32 function;
  __u32 timeout_ms;
  __u8 interruptible;
  __u8 reserved;
  __u16 parm_count;
};
#define VBG_IOCTL_HGCM_CALL_32(s) _IOC(_IOC_READ | _IOC_WRITE, 'V', 6, s)
#define VBG_IOCTL_HGCM_CALL_64(s) _IOC(_IOC_READ | _IOC_WRITE, 'V', 7, s)
#if __BITS_PER_LONG == 64
#define VBG_IOCTL_HGCM_CALL(s) VBG_IOCTL_HGCM_CALL_64(s)
#else
#define VBG_IOCTL_HGCM_CALL(s) VBG_IOCTL_HGCM_CALL_32(s)
#endif
struct vbg_ioctl_log {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      char msg[1];
    } in;
  } u;
};
#define VBG_IOCTL_LOG(s) _IO('V', 9)
struct vbg_ioctl_wait_for_events {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 timeout_ms;
      __u32 events;
    } in;
    struct {
      __u32 events;
    } out;
  } u;
};
#define VBG_IOCTL_WAIT_FOR_EVENTS _IOWR('V', 10, struct vbg_ioctl_wait_for_events)
#define VBG_IOCTL_INTERRUPT_ALL_WAIT_FOR_EVENTS _IOWR('V', 11, struct vbg_ioctl_hdr)
struct vbg_ioctl_change_filter {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 or_mask;
      __u32 not_mask;
    } in;
  } u;
};
#define VBG_IOCTL_CHANGE_FILTER_MASK _IOWR('V', 12, struct vbg_ioctl_change_filter)
struct vbg_ioctl_acquire_guest_caps {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 flags;
      __u32 or_mask;
      __u32 not_mask;
    } in;
  } u;
};
#define VBGL_IOC_AGC_FLAGS_CONFIG_ACQUIRE_MODE 0x00000001
#define VBGL_IOC_AGC_FLAGS_VALID_MASK 0x00000001
#define VBG_IOCTL_ACQUIRE_GUEST_CAPABILITIES _IOWR('V', 13, struct vbg_ioctl_acquire_guest_caps)
struct vbg_ioctl_set_guest_caps {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 or_mask;
      __u32 not_mask;
    } in;
    struct {
      __u32 session_caps;
      __u32 global_caps;
    } out;
  } u;
};
#define VBG_IOCTL_CHANGE_GUEST_CAPABILITIES _IOWR('V', 14, struct vbg_ioctl_set_guest_caps)
struct vbg_ioctl_check_balloon {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 balloon_chunks;
      __u8 handle_in_r3;
      __u8 padding[3];
    } out;
  } u;
};
#define VBG_IOCTL_CHECK_BALLOON _IOWR('V', 17, struct vbg_ioctl_check_balloon)
struct vbg_ioctl_write_coredump {
  struct vbg_ioctl_hdr hdr;
  union {
    struct {
      __u32 flags;
    } in;
  } u;
};
#define VBG_IOCTL_WRITE_CORE_DUMP _IOWR('V', 19, struct vbg_ioctl_write_coredump)
#endif

"""

```