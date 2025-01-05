Response:
Let's break down the thought process to answer the user's request about the `ocxl.handroid` header file.

**1. Understanding the Request:**

The user wants to understand the functionality of the `ocxl.handroid` header file within the context of Android's bionic library. Key requests include:

* Listing functionalities.
* Explaining the relationship to Android.
* Detailed explanation of libc functions (even though this file *doesn't define* any libc functions directly). This requires careful nuance.
* Dynamic linker aspects (again, this file doesn't directly interact with it, but the *system* uses ioctls, which are syscalls, and syscalls are the bridge between user space and kernel, where the dynamic linker plays a role in setting things up).
* Logical reasoning with input/output (this requires making assumptions about how the defined structures might be used).
* Common user errors (requires knowledge of how device drivers and ioctls are typically used).
* Android framework/NDK path to this code.
* Frida hook examples.

**2. Initial Analysis of the Header File:**

The first step is to carefully examine the contents of `ocxl.handroid`:

* **`#ifndef _UAPI_MISC_OCXL_H` and `#define _UAPI_MISC_OCXL_H`:**  Standard header guard to prevent multiple inclusions.
* **`#include <linux/types.h>` and `#include <linux/ioctl.h>`:**  This immediately tells us this header defines structures and ioctl codes for communication with a Linux kernel driver. The "uapi" part of the path strongly confirms this (user-space API to the kernel).
* **`enum ocxl_event_type`:** Defines an enumeration for event types. `OCXL_AFU_EVENT_XSL_FAULT_ERROR` suggests this is related to hardware errors.
* **`struct ocxl_kernel_event_header` and `struct ocxl_kernel_event_xsl_fault_error`:** Structures defining the format of events received from the kernel driver. The naming convention suggests these are kernel-level event structures.
* **`struct ocxl_ioctl_...` structures:**  These structures are clearly for passing data to and from the kernel driver via `ioctl` system calls. The names hint at their purpose (attach, metadata, wait, features, irq).
* **`#define OCXL_KERNEL_EVENT_FLAG_LAST 0x0001`:** A flag likely used in the event header.
* **`#define OCXL_MAGIC 0xCA`:** A "magic number" used to identify the specific ioctl commands for this driver.
* **`#define OCXL_IOCTL_...` macros:**  These are the core of the file. They define the specific `ioctl` commands, associating them with the `OCXL_MAGIC`, a command number (0x10, 0x11, etc.), and the data structure used with that command. The `_IOW`, `_IOR` macros indicate the direction of data flow (write, read).

**3. Connecting to Android:**

Knowing this is a kernel interface, the connection to Android is through the standard Linux kernel mechanisms:

* **Device Drivers:** Android uses the Linux kernel, so this header defines the interface to a specific kernel driver related to OCXL (OpenCAPI Acceleration Framework).
* **ioctl System Call:** Android applications (or more likely, system services or HALs) will use the `ioctl()` system call to interact with this driver.
* **HAL (Hardware Abstraction Layer):**  It's highly probable that an Android HAL module would be the primary user of this interface, abstracting the low-level kernel driver details for higher-level Android components.

**4. Addressing the Libc and Dynamic Linker Questions:**

This is where careful wording is crucial. The header *itself* doesn't define libc functions. However:

* **Libc's `ioctl()`:** The key libc function involved is `ioctl()`. Explain its role in making system calls to interact with device drivers.
* **Dynamic Linker:** While the header isn't directly *linked* by the dynamic linker, the *system* relies on the dynamic linker to load the necessary libraries (like libc) that *contain* the `ioctl()` function. Explain the dynamic linker's role in setting up the environment for system calls. The SO layout example should show how libc is loaded.

**5. Logical Reasoning (Hypothetical Use Case):**

To demonstrate understanding, create a simple scenario:

* **Assumption:** An Android service wants to attach to an OCXL device.
* **Input:**  The service prepares an `ocxl_ioctl_attach` structure with the necessary `amr` value.
* **Output:** The `ioctl()` call (using `OCXL_IOCTL_ATTACH`) will either succeed (returning 0) or fail (returning -1 and setting `errno`).

**6. Common User Errors:**

Think about common mistakes when dealing with device drivers and ioctls:

* **Incorrect file descriptor:** Trying to use `ioctl()` on a file descriptor that doesn't correspond to the OCXL device.
* **Invalid ioctl command:** Using the wrong `ioctl` code.
* **Incorrect data structure:** Passing the wrong size or contents in the data structure.
* **Permissions issues:** Not having the necessary permissions to access the device.

**7. Android Framework/NDK Path and Frida Hook:**

* **Framework/NDK Path:** Trace the likely path:
    * Application (NDK) or Framework Service.
    * Potentially a custom HAL implementation for OCXL.
    * Open/close/ioctl system calls in the HAL.
    * Kernel driver interaction based on the ioctl definitions.
* **Frida Hook:**  Show examples of hooking the `ioctl` system call. Crucially, demonstrate how to filter for the specific OCXL ioctl commands using the `request` argument. Also, demonstrate how to read/modify the arguments passed to `ioctl`.

**8. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and bullet points for readability. Provide code examples for the Frida hooks.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on libc functions defined *within* the header.
* **Correction:** Realize the header *uses* libc functions (like `ioctl`), but doesn't define new ones. Shift focus to explaining `ioctl`'s role.
* **Initial thought:** The dynamic linker isn't directly involved.
* **Correction:**  Recognize that while the *header* isn't linked, the *code that uses this header* (in userspace) *is*, and the dynamic linker is essential for setting up the environment where `ioctl` calls can be made.
* **Ensure clarity:**  Use precise language to distinguish between the header file itself, the kernel driver, the `ioctl` system call, and the libc function.

By following these steps and iteratively refining the understanding, a comprehensive and accurate answer can be constructed.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/misc/ocxl.handroid` 这个头文件。

**功能列举:**

这个头文件定义了用户空间程序与 Linux 内核中 OCXL (OpenCAPI Acceleration Framework) 驱动进行交互的接口。具体来说，它定义了：

1. **事件类型 (Event Types):**
   - `OCXL_AFU_EVENT_XSL_FAULT_ERROR`:  定义了一个加速器功能单元 (AFU) 中发生的 XSL (执行状态日志) 错误事件类型。

2. **内核事件结构体 (Kernel Event Structures):**
   - `ocxl_kernel_event_header`:  定义了所有 OCXL 内核事件的通用头部，包含事件类型 (`type`) 和标志 (`flags`)。
   - `ocxl_kernel_event_xsl_fault_error`: 定义了 `OCXL_AFU_EVENT_XSL_FAULT_ERROR` 事件的特定数据，包括错误发生的地址 (`addr`)、设备状态寄存器 (`dsisr`)、错误计数 (`count`) 等信息。

3. **ioctl 命令和相关结构体 (ioctl Commands and Structures):**
   - `ocxl_ioctl_attach`:  用于将用户空间进程连接到 OCXL 设备。包含一个地址映射寄存器 (`amr`)。
   - `ocxl_ioctl_metadata`:  用于获取 OCXL 设备的元数据，例如版本信息、PASID (Process Address Space Identifier)、MMIO (Memory-Mapped I/O) 区域大小等。
   - `ocxl_ioctl_p9_wait`:  可能与 Power9 架构相关的等待操作有关，包含线程 ID (`thread_id`)。
   - `ocxl_ioctl_features`: 用于获取 OCXL 设备的特性标志。
   - `ocxl_ioctl_irq_fd`: 用于分配或设置中断请求 (IRQ) 的文件描述符 (`eventfd`) 和偏移量 (`irq_offset`)。

4. **ioctl 魔数和命令定义 (ioctl Magic Number and Command Definitions):**
   - `OCXL_MAGIC`: 定义了用于 OCXL ioctl 命令的魔数 `0xCA`，用于区分不同的 ioctl 命令集合。
   - `OCXL_IOCTL_ATTACH`, `OCXL_IOCTL_IRQ_ALLOC`, `OCXL_IOCTL_IRQ_FREE`, `OCXL_IOCTL_IRQ_SET_FD`, `OCXL_IOCTL_GET_METADATA`, `OCXL_IOCTL_ENABLE_P9_WAIT`, `OCXL_IOCTL_GET_FEATURES`:  使用 `_IOW` 和 `_IOR` 宏定义了具体的 ioctl 命令，将魔数、命令编号和数据结构关联起来。 `_IOW` 表示向内核写入数据，`_IOR` 表示从内核读取数据。

**与 Android 功能的关系及举例说明:**

OCXL 是一个硬件加速框架，允许应用程序利用连接到系统的加速器硬件。在 Android 中，虽然 OCXL 可能不是一个普遍使用的特性，但在某些高性能计算、特定硬件支持的设备或定制 Android 系统中可能会用到。

**举例说明:**

假设某个 Android 设备连接了一个支持 OCXL 的加速器卡，该加速器用于进行高性能的图像处理。

1. **HAL (硬件抽象层) 或 Native Service:**  一个负责管理该加速器卡的 Android HAL 模块或者 Native Service 可能会使用这些 ioctl 命令与内核驱动进行交互。

2. **`OCXL_IOCTL_ATTACH`:**  HAL 或 Service 会首先打开代表 OCXL 设备的设备文件 (例如 `/dev/ocxl0`)，然后使用 `OCXL_IOCTL_ATTACH` ioctl 命令，将自己的进程连接到该 OCXL 设备。`amr` 参数可能指定了进程可以访问的加速器内存区域。

3. **`OCXL_IOCTL_GET_METADATA`:**  在连接之后，HAL 或 Service 可以使用 `OCXL_IOCTL_GET_METADATA` 获取加速器的版本信息、MMIO 大小等，以便进行后续的配置和操作。

4. **`OCXL_IOCTL_IRQ_ALLOC` 和 `OCXL_IOCTL_IRQ_SET_FD`:**  如果加速器需要通过中断通知事件，HAL 或 Service 会使用 `OCXL_IOCTL_IRQ_ALLOC` 分配一个中断，然后使用 `OCXL_IOCTL_IRQ_SET_FD` 将该中断与一个 `eventfd` 关联起来。`eventfd` 可以让用户空间程序方便地等待内核事件的发生。

5. **`OCXL_IOCTL_GET_FEATURES`:**  HAL 或 Service 可以查询加速器支持的特性，根据特性选择不同的操作路径。

6. **`OCXL_IOCTL_ENABLE_P9_WAIT`:**  在特定的 Power9 架构的设备上，可能需要使用这个 ioctl 命令来启用某些等待机制。

7. **接收事件:**  当加速器发生错误时，内核驱动会生成一个 OCXL 事件。HAL 或 Service 可以通过读取与中断关联的 `eventfd` 来接收这些事件，并根据事件类型 (`OCXL_AFU_EVENT_XSL_FAULT_ERROR`) 和事件数据 (`ocxl_kernel_event_xsl_fault_error`) 来处理错误。

**libc 函数的实现:**

这个头文件本身并没有定义任何 libc 函数。它定义的是用于 `ioctl` 系统调用的数据结构和命令。`ioctl` 是一个标准的 POSIX 系统调用，在 bionic libc 中有相应的实现。

`ioctl` 函数的实现机制大致如下：

1. **系统调用入口:** 当用户空间程序调用 `ioctl` 函数时，会触发一个软中断（或异常），陷入内核态。
2. **系统调用处理:** 内核中的系统调用处理程序会根据 `ioctl` 的系统调用号找到对应的内核函数。
3. **设备驱动分发:** `ioctl` 内核函数会根据传递的文件描述符，找到对应的设备驱动程序。
4. **驱动程序处理:** 设备驱动程序中的 `ioctl` 函数会被调用，并根据传入的命令编号 (`request`) 和数据指针 (`argp`) 执行相应的操作。
5. **结果返回:** 驱动程序处理完成后，将结果返回给内核，内核再将结果返回给用户空间程序。

**动态链接器的功能:**

这个头文件定义的是内核接口，用户空间程序需要通过 libc 提供的 `ioctl` 函数来调用这些接口。动态链接器在其中扮演的角色是：

1. **加载 libc:** 当一个使用了 `ioctl` 函数的程序启动时，动态链接器 (e.g., `linker64` 或 `linker`) 会负责加载 bionic libc 共享库到进程的地址空间。
2. **符号解析:** 动态链接器会解析程序中对 `ioctl` 函数的符号引用，将其链接到 libc 中 `ioctl` 函数的实际地址。
3. **运行时绑定:** 在程序运行时，当首次调用 `ioctl` 函数时，动态链接器会确保该函数已经被正确加载和定位。

**so 布局样本:**

假设一个名为 `accelerator_service` 的 native service 使用了 OCXL 接口。其内存布局可能如下（简化）：

```
   低地址
   +-------------------+
   |     ...           |
   +-------------------+
   |  accelerator_service  |  (可执行文件代码和数据段)
   +-------------------+
   |     ...           |
   +-------------------+
   |     libc.so       |  (bionic libc 共享库)
   |   - ioctl 函数    |
   |     ...           |
   +-------------------+
   |     ld-android.so |  (动态链接器)
   +-------------------+
   |     [stack]       |
   +-------------------+
   |     [heap]        |
   +-------------------+
   高地址
```

**链接的处理过程:**

1. **编译时:** 编译器会生成对 `ioctl` 函数的未解析符号引用。
2. **链接时:** 静态链接器（如果使用静态链接）或者动态链接器会在加载时负责解析这个符号。对于动态链接，链接器会在 libc.so 中找到 `ioctl` 函数的实现。
3. **运行时:** 当 `accelerator_service` 第一次调用 `ioctl` 时，动态链接器会查找 libc.so 中 `ioctl` 函数的地址，并将 `accelerator_service` 中对 `ioctl` 的调用跳转到该地址。

**逻辑推理和假设输入/输出:**

**假设场景:**  一个 Android 应用尝试连接到 OCXL 设备并获取其元数据。

**假设输入:**

- 设备文件描述符 `fd` 指向 `/dev/ocxl0`，已成功打开。
- 一个未初始化的 `ocxl_ioctl_metadata` 结构体 `metadata`。

**代码片段:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <bionic/libc/kernel/uapi/misc/ocxl.handroid>

int main() {
    int fd = open("/dev/ocxl0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/ocxl0 failed");
        return 1;
    }

    struct ocxl_ioctl_metadata metadata;
    if (ioctl(fd, OCXL_IOCTL_GET_METADATA, &metadata) == -1) {
        perror("ioctl OCXL_IOCTL_GET_METADATA failed");
        close(fd);
        return 1;
    }

    printf("OCXL Metadata:\n");
    printf("  Version: %u\n", metadata.version);
    printf("  AFU Major Version: %u\n", metadata.afu_version_major);
    printf("  AFU Minor Version: %u\n", metadata.afu_version_minor);
    printf("  PASID: %u\n", metadata.pasid);
    printf("  PP MMIO Size: %lu\n", metadata.pp_mmio_size);
    printf("  Global MMIO Size: %lu\n", metadata.global_mmio_size);

    close(fd);
    return 0;
}
```

**预期输出 (成功情况):**

```
OCXL Metadata:
  Version: [某个版本号]
  AFU Major Version: [主版本号]
  AFU Minor Version: [次版本号]
  PASID: [进程 PASID]
  PP MMIO Size: [PP MMIO 大小]
  Global MMIO Size: [全局 MMIO 大小]
```

**预期输出 (失败情况，例如设备不存在或权限不足):**

```
open /dev/ocxl0 failed: No such file or directory
```

或

```
open /dev/ocxl0 failed: Permission denied
```

或

```
ioctl OCXL_IOCTL_GET_METADATA failed: Inappropriate ioctl for device
```

**用户或编程常见的使用错误:**

1. **忘记打开设备文件:** 在调用 ioctl 之前，必须先使用 `open()` 函数打开对应的 OCXL 设备文件 (例如 `/dev/ocxl0`)。
   ```c
   int fd;
   // 忘记打开设备文件
   struct ocxl_ioctl_metadata metadata;
   if (ioctl(fd, OCXL_IOCTL_GET_METADATA, &metadata) == -1) { // 错误：fd 未初始化
       perror("ioctl failed");
   }
   ```

2. **使用错误的 ioctl 命令:**  针对不同的操作需要使用不同的 ioctl 命令。使用错误的命令会导致内核返回错误。
   ```c
   int fd = open("/dev/ocxl0", O_RDWR);
   struct ocxl_ioctl_attach attach_data;
   // 错误：应该使用 OCXL_IOCTL_ATTACH，却使用了 OCXL_IOCTL_GET_METADATA
   if (ioctl(fd, OCXL_IOCTL_GET_METADATA, &attach_data) == -1) {
       perror("ioctl failed");
   }
   close(fd);
   ```

3. **传递不正确的数据结构或数据大小:**  每个 ioctl 命令都需要特定的数据结构作为参数。传递错误的数据结构或大小会导致内核解析错误或访问越界。
   ```c
   int fd = open("/dev/ocxl0", O_RDWR);
   struct ocxl_ioctl_metadata metadata;
   // 错误：传递的数据结构大小不匹配
   if (ioctl(fd, OCXL_IOCTL_GET_METADATA, &metadata, sizeof(int)) == -1) { // ioctl 的第三个参数是数据指针，不是大小
       perror("ioctl failed");
   }
   close(fd);
   ```

4. **权限问题:**  访问 `/dev/ocxl0` 可能需要特定的权限。如果用户没有足够的权限，`open()` 或 `ioctl()` 调用会失败。

5. **设备驱动未加载或设备不存在:** 如果 OCXL 驱动没有加载，或者系统中没有对应的 OCXL 硬件，尝试打开设备文件会失败。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 应用:**
   - NDK 应用开发者可以使用 C/C++ 代码，通过标准 Linux API (`open`, `ioctl`) 直接与 `/dev/ocxl*` 设备文件进行交互。
   - 需要包含 `<bionic/libc/kernel/uapi/misc/ocxl.handroid>` 头文件来使用定义的常量和结构体。

2. **Android Framework (HAL):**
   - 更常见的情况是，Android Framework 通过硬件抽象层 (HAL) 与内核驱动交互。
   - **Hardware Service:** Framework 中的一个硬件服务 (例如负责管理加速器硬件的服务) 可能会调用 HAL 接口。
   - **HAL Implementation:** HAL 的具体实现 (通常是 `.so` 动态库) 会包含打开设备文件、调用 `ioctl` 等操作的代码。这个 HAL 实现会使用到 `<bionic/libc/kernel/uapi/misc/ocxl.handroid>` 中定义的接口。
   - **Kernel Driver:** HAL 的 `ioctl` 调用最终会到达内核中的 OCXL 设备驱动程序。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来观察 Android Framework 或 NDK 应用与 OCXL 驱动的交互过程。以下是一些示例：

**1. Hook `open` 系统调用，观察设备文件是否被打开:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = device.spawn(["com.example.myapp"]) # 替换为目标应用的包名
session = device.attach(pid)
script = session.create_script("""
    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            if (path.indexOf("/dev/ocxl") !== -1) {
                this.fd_path = path;
                send({ tag: "open", message: "Opening file: " + path });
            }
        },
        onLeave: function(retval) {
            if (this.fd_path) {
                send({ tag: "open", message: "File opened with fd: " + retval });
            }
        }
    });
""")
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**2. Hook `ioctl` 系统调用，观察 OCXL 相关的 ioctl 调用:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = device.spawn(["com.example.myapp"]) # 替换为目标应用的包名
session = device.attach(pid)
script = session.create_script("""
    const OCXL_MAGIC = 0xCA;

    Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var request = args[1].toInt32();
            if ((request >> 8) === OCXL_MAGIC) {
                this.ioctl_cmd = request;
                send({ tag: "ioctl", message: "ioctl called with fd: " + fd + ", request: 0x" + request.toString(16) });

                // 可以进一步解析 ioctl 参数
                if (request === 0xc040ca14) { // OCXL_IOCTL_GET_METADATA
                    var metadataPtr = ptr(args[2]);
                    send({ tag: "ioctl_data", message: "  Metadata struct at: " + metadataPtr });
                    // 可以读取 metadata 结构体的内容
                }
            }
        },
        onLeave: function(retval) {
            if (this.ioctl_cmd) {
                send({ tag: "ioctl", message: "ioctl returned: " + retval });
                this.ioctl_cmd = null;
            }
        }
    });
""")
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**3. Hook HAL 层的函数:**

如果知道是哪个 HAL 模块在与 OCXL 驱动交互，可以直接 Hook HAL 模块中的相关函数。例如，可以使用 `Module.findExportByName` 或 `Module.getBaseAddress` 找到 HAL 库的地址，然后 Hook 其内部函数。

**调试步骤总结:**

1. **确定目标进程:**  找到与 OCXL 交互的 Android 应用或服务进程的 PID 或包名。
2. **编写 Frida 脚本:**  使用 Frida API 编写 JavaScript 脚本，用于 Hook 相关的系统调用 (`open`, `ioctl`) 或 HAL 函数。
3. **加载脚本:**  使用 Frida 客户端连接到目标设备和进程，加载并运行编写的脚本。
4. **分析输出:**  观察 Frida 输出的日志，分析 `open` 调用打开的文件路径，`ioctl` 调用的命令和参数，以及返回值，从而理解 Android 系统如何与 OCXL 驱动进行交互。

希望以上详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/misc/ocxl.handroid` 头文件的作用以及它在 Android 系统中的使用方式。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/misc/ocxl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_MISC_OCXL_H
#define _UAPI_MISC_OCXL_H
#include <linux/types.h>
#include <linux/ioctl.h>
enum ocxl_event_type {
  OCXL_AFU_EVENT_XSL_FAULT_ERROR = 0,
};
#define OCXL_KERNEL_EVENT_FLAG_LAST 0x0001
struct ocxl_kernel_event_header {
  __u16 type;
  __u16 flags;
  __u32 reserved;
};
struct ocxl_kernel_event_xsl_fault_error {
  __u64 addr;
  __u64 dsisr;
  __u64 count;
  __u64 reserved;
};
struct ocxl_ioctl_attach {
  __u64 amr;
  __u64 reserved1;
  __u64 reserved2;
  __u64 reserved3;
};
struct ocxl_ioctl_metadata {
  __u16 version;
  __u8 afu_version_major;
  __u8 afu_version_minor;
  __u32 pasid;
  __u64 pp_mmio_size;
  __u64 global_mmio_size;
  __u64 reserved[13];
};
struct ocxl_ioctl_p9_wait {
  __u16 thread_id;
  __u16 reserved1;
  __u32 reserved2;
  __u64 reserved3[3];
};
#define OCXL_IOCTL_FEATURES_FLAGS0_P9_WAIT 0x01
struct ocxl_ioctl_features {
  __u64 flags[4];
};
struct ocxl_ioctl_irq_fd {
  __u64 irq_offset;
  __s32 eventfd;
  __u32 reserved;
};
#define OCXL_MAGIC 0xCA
#define OCXL_IOCTL_ATTACH _IOW(OCXL_MAGIC, 0x10, struct ocxl_ioctl_attach)
#define OCXL_IOCTL_IRQ_ALLOC _IOR(OCXL_MAGIC, 0x11, __u64)
#define OCXL_IOCTL_IRQ_FREE _IOW(OCXL_MAGIC, 0x12, __u64)
#define OCXL_IOCTL_IRQ_SET_FD _IOW(OCXL_MAGIC, 0x13, struct ocxl_ioctl_irq_fd)
#define OCXL_IOCTL_GET_METADATA _IOR(OCXL_MAGIC, 0x14, struct ocxl_ioctl_metadata)
#define OCXL_IOCTL_ENABLE_P9_WAIT _IOR(OCXL_MAGIC, 0x15, struct ocxl_ioctl_p9_wait)
#define OCXL_IOCTL_GET_FEATURES _IOR(OCXL_MAGIC, 0x16, struct ocxl_ioctl_features)
#endif

"""

```