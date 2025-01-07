Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`virtio_scsi.h`) and explain its functionality within the Android context. The prompt specifically asks for:

* Functionality listing.
* Relevance to Android with examples.
* Detailed explanation of `libc` functions (though there aren't any actual `libc` function calls *within* the header file itself).
* Dynamic linker details (again, not directly present but relevant to how the definitions are used).
* Logical reasoning with input/output (this will be about how the structures are used).
* Common usage errors.
* How Android frameworks/NDK reach this code, including Frida hooking.

**2. Initial Analysis of the Header File:**

The first step is to read through the header file and identify the key elements:

* **Includes:** `#include <linux/virtio_types.h>` - This indicates a dependency on other VirtIO types.
* **Macros:**  `#define` statements define constants for sizes, flags, status codes, and event types. These are crucial for understanding the protocol.
* **Structures:** `struct` definitions describe the data exchanged between the host and guest (virtual machine) for SCSI commands and control operations. Key structures include:
    * `virtio_scsi_cmd_req`: Request for a SCSI command.
    * `virtio_scsi_cmd_resp`: Response to a SCSI command.
    * `virtio_scsi_ctrl_*`: Structures for control operations like task management and asynchronous notifications.
    * `virtio_scsi_event`: Represents asynchronous events.
    * `virtio_scsi_config`: Describes the capabilities of the VirtIO SCSI device.
* **Flags/Constants:**  These define various aspects of the VirtIO SCSI protocol, like feature flags, status codes, and task management function types.

**3. Identifying the Core Functionality:**

Based on the structures and constants, the core functionality is clearly related to **managing SCSI devices within a virtualized environment using the VirtIO framework.**  This involves:

* Sending SCSI commands (read, write, etc.).
* Receiving responses to those commands.
* Managing tasks (aborting, resetting, etc.).
* Handling asynchronous events (device removal, etc.).
* Negotiating device capabilities.

**4. Connecting to Android:**

The crucial link to Android is the **virtualization of storage**. Android devices, particularly emulators and some enterprise use cases, might run within virtual machines. VirtIO is a common framework for efficient I/O virtualization. Specifically, `virtio_scsi` enables virtual machines to interact with virtual SCSI storage devices provided by the host.

**Examples in Android:**

* **Android Emulator:**  The emulator often uses KVM and QEMU, which can employ VirtIO for storage virtualization. The virtual SD card and other storage might be presented via VirtIO SCSI.
* **Cloud Environments:** Android in the cloud (e.g., for app testing) will likely rely on virtualization technologies, including VirtIO.

**5. Addressing the `libc` and Dynamic Linker Questions:**

This is where careful reading of the *content* of the header is important. **The header file itself does not contain any `libc` function calls or dynamic linking information.** It's *data definitions*.

However, the *use* of these definitions *does* involve `libc` and the dynamic linker.

* **`libc`:**  The structures defined here will be used by C/C++ code in Android (likely within the kernel or hardware abstraction layers - HALs) to interact with the VirtIO SCSI driver. This code will use `libc` functions for memory management (`malloc`, `free`), data copying (`memcpy`), and potentially logging (`ALOG`).

* **Dynamic Linker:** The header file defines data structures. The code that *uses* these structures will be compiled into shared libraries (`.so` files). The dynamic linker is responsible for loading these libraries and resolving symbols (like the structure definitions).

**Generating the `.so` Layout and Linking Process Example (Conceptual):**

Since there's no actual code in the header, we need to *imagine* a scenario where these structures are used. A hypothetical HAL module for a VirtIO SCSI device would be a good example.

* **`libvirtio_scsi_hal.so`:** This shared library would contain code that uses the structures defined in `virtio_scsi.h`.
* **Linking:**  The compiler and linker would ensure that the code in `libvirtio_scsi_hal.so` correctly understands the layout and sizes of the structures defined in the header.

**6. Logical Reasoning (Hypothetical Input/Output):**

Consider sending a read command:

* **Input (Conceptual):**  A request to read a specific block of data from a virtual disk. This would involve populating a `virtio_scsi_cmd_req` structure with the LUN, tag, and the SCSI command descriptor block (CDB) for a READ operation.
* **Output (Conceptual):** The `virtio_scsi_cmd_resp` structure returned by the virtual SCSI device, containing the status of the operation, any sense data (error information), and the amount of data transferred.

**7. Common Usage Errors:**

These errors relate to *how the structures are used in code*, not errors *within* the header file itself:

* **Incorrect Size Assumptions:**  Assuming a fixed size for the CDB or sense data if the `#define` values are changed or not considered.
* **Endianness Issues:**  Forgetting to use `virtio32`, `virtio64`, etc., which handle endianness conversions between the host and guest.
* **Incorrectly Populating Structures:**  Putting data in the wrong fields or using incorrect values for flags or status codes.
* **Race Conditions:** If multiple threads try to access or modify the same VirtIO SCSI resources without proper synchronization.

**8. Android Framework/NDK Path and Frida Hooking:**

This involves tracing how a storage request initiated by an Android application travels down to the point where these VirtIO SCSI structures are relevant.

* **Application:** Makes a file I/O request (e.g., using Java `FileInputStream`).
* **Framework:**  The framework translates this into lower-level system calls.
* **HAL (Hardware Abstraction Layer):**  For virtualized storage, a HAL module responsible for the VirtIO SCSI device would be involved. This module would use the structures from `virtio_scsi.h`.
* **Kernel Driver:** The VirtIO SCSI kernel driver processes the requests from the HAL.

**Frida Hooking:**  We can use Frida to intercept function calls at various points in this stack to observe the data being exchanged, including the contents of the VirtIO SCSI structures. The example focuses on hooking a hypothetical function within the HAL that sends a command.

**9. Language and Formatting:**

Finally, ensure the answer is in Chinese and well-formatted for readability. Using headings, bullet points, and code blocks helps to organize the information clearly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on the literal content of the header.
* **Correction:** Realize the request is about the *purpose* and *usage* of these definitions within the broader Android ecosystem. Shift focus to how these structures are used in the context of virtualization and storage.
* **Initial thought:** Try to find specific `libc` function calls.
* **Correction:**  Understand that the header *defines data*, and the `libc` functions are used by the *code* that manipulates this data. Explain the *types* of `libc` functions involved.
* **Initial thought:**  Struggle with the dynamic linker part since it's not directly in the header.
* **Correction:**  Provide a *conceptual* example of how a `.so` might use these definitions and how the dynamic linker would be involved in resolving the symbols.

这是一个定义 Linux 内核中 VirtIO SCSI 接口的数据结构和常量的头文件 (`virtio_scsi.h`)。它描述了虚拟机 (Guest) 如何通过 VirtIO 框架与主机 (Host) 上的 SCSI 设备进行通信。由于它位于 `bionic/libc/kernel/uapi/linux` 目录下，说明它是 Android 系统中用户空间程序可以使用的内核接口的定义。

**功能列举：**

这个头文件定义了以下主要功能相关的结构体和宏：

1. **定义 VirtIO SCSI 命令请求 (`virtio_scsi_cmd_req`, `virtio_scsi_cmd_req_pi`):**  用于 Guest 向 Host 发送 SCSI 命令。包含了 LUN (逻辑单元号)、Tag (命令标识符)、任务属性、优先级、CDB (命令描述符块) 等信息。`virtio_scsi_cmd_req_pi` 增加了保护信息 (PI) 相关的字段。
2. **定义 VirtIO SCSI 命令响应 (`virtio_scsi_cmd_resp`):** 用于 Host 向 Guest 返回 SCSI 命令执行结果。包含了 Sense 数据长度、剩余数据长度、状态限定符、状态码、响应码和 Sense 数据。
3. **定义 VirtIO SCSI 控制任务管理功能请求和响应 (`virtio_scsi_ctrl_tmf_req`, `virtio_scsi_ctrl_tmf_resp`):**  用于 Guest 向 Host 发送任务管理功能请求，例如中止任务、逻辑单元重置等。
4. **定义 VirtIO SCSI 异步通知请求和响应 (`virtio_scsi_ctrl_an_req`, `virtio_scsi_ctrl_an_resp`):** 用于 Guest 请求和 Host 发送异步通知事件，例如设备移除、参数变化等。
5. **定义 VirtIO SCSI 事件 (`virtio_scsi_event`):**  描述 Host 发送给 Guest 的异步事件，包含事件类型、LUN 和原因。
6. **定义 VirtIO SCSI 配置 (`virtio_scsi_config`):**  描述 VirtIO SCSI 设备的能力和配置信息，例如队列数量、最大段数、最大扇区数等。
7. **定义 VirtIO SCSI 功能标志 (`VIRTIO_SCSI_F_*`):**  协商 VirtIO SCSI 设备支持的功能，例如双向数据传输、热插拔、T10-PI 数据完整性校验等。
8. **定义 VirtIO SCSI 状态码 (`VIRTIO_SCSI_S_*`):**  表示 SCSI 命令执行的状态，例如成功、溢出、中止、总线忙等。
9. **定义 VirtIO SCSI 任务管理功能类型 (`VIRTIO_SCSI_T_TMF_*`):**  定义具体的任务管理操作类型。
10. **定义 VirtIO SCSI 事件类型 (`VIRTIO_SCSI_T_EVENTS_MISSED`, `VIRTIO_SCSI_T_NO_EVENT`, `VIRTIO_SCSI_T_TRANSPORT_RESET`, `VIRTIO_SCSI_T_ASYNC_NOTIFY`, `VIRTIO_SCSI_T_PARAM_CHANGE`):** 定义异步事件的类型。
11. **定义 VirtIO SCSI 事件原因 (`VIRTIO_SCSI_EVT_*`):** 定义导致特定事件的原因。
12. **定义 VirtIO SCSI 排序类型 (`VIRTIO_SCSI_S_SIMPLE`, `VIRTIO_SCSI_S_ORDERED`, `VIRTIO_SCSI_S_HEAD`, `VIRTIO_SCSI_S_ACA`):** 定义 SCSI 命令的排序属性。
13. **定义默认大小 (`VIRTIO_SCSI_CDB_DEFAULT_SIZE`, `VIRTIO_SCSI_SENSE_DEFAULT_SIZE`):** 定义 CDB 和 Sense 数据的默认大小，并允许通过宏进行覆盖。

**与 Android 功能的关系及举例说明：**

这个头文件直接关联到 Android 系统中对虚拟化存储设备的支持。当 Android 运行在虚拟机中（例如使用 Android Emulator 或在云环境中），虚拟机需要访问虚拟磁盘时，就会使用 VirtIO SCSI 协议。

**举例说明：**

* **Android Emulator 使用虚拟磁盘:** 当你使用 Android Emulator 时，它通常会创建一个虚拟磁盘镜像（例如 `.img` 文件）。Emulator 内部的 Android 系统（Guest）通过 VirtIO SCSI 协议与 Emulator 进程（Host）进行通信，从而读写这个虚拟磁盘镜像。
* **Android 云环境:** 在云服务器上运行 Android 系统时，底层的存储设备很可能是通过虚拟化技术提供的。VirtIO SCSI 是一种常用的虚拟化存储方案，Android 系统会使用这里的定义来与虚拟磁盘交互。
* **访问外部存储（在虚拟机中）:** 如果你在虚拟机中连接了一个 USB 设备并将其挂载到虚拟机内部的 Android 系统，这个过程也可能涉及到 VirtIO SCSI 协议。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要强调的是，这个头文件本身并没有包含任何 `libc` 函数的调用。** 它只是定义了一些数据结构和常量。这些结构体会被 Android 系统中的 C/C++ 代码使用，而这些代码可能会调用 `libc` 函数。

例如，在实现 VirtIO SCSI 驱动或相关的 HAL (硬件抽象层) 模块时，可能会使用 `libc` 函数：

* **内存分配 (`malloc`, `calloc`, `free`):** 用于分配和释放存储这些结构体所需的内存。
* **内存拷贝 (`memcpy`, `memmove`):** 用于在 Host 和 Guest 之间传输数据时拷贝结构体或其中的字段。
* **日志输出 (`ALOG` 等 Android 特有的日志函数):**  用于在调试或记录信息时输出与 VirtIO SCSI 相关的日志。
* **原子操作 (`atomic_*` 系列函数):**  在多线程环境下，为了保证数据一致性，可能会使用原子操作来修改共享的 VirtIO SCSI 状态。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接。但是，如果使用了这些结构体的代码被编译成共享库 (`.so` 文件)，那么动态链接器就会参与到链接过程中。

**假设我们有一个名为 `libvirtio_scsi_hw.so` 的共享库，它使用了 `virtio_scsi_cmd_req` 结构体。**

**`.so` 布局样本 (简化):**

```
ELF Header
Program Headers
Section Headers
...
.rodata:  // 只读数据段
    ...
    virtio_scsi_cdb_default_size:  ; 定义了 VIRTIO_SCSI_CDB_DEFAULT_SIZE 的值
    ...
.data:    // 已初始化数据段
    ...
.bss:     // 未初始化数据段
    ...
.symtab:  // 符号表
    ...
    virtio_scsi_cmd_req:  ; 定义了 virtio_scsi_cmd_req 结构体的符号和地址
    ...
.strtab:  // 字符串表
    ...
    "virtio_scsi_cmd_req"
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当 `libvirtio_scsi_hw.so` 被编译时，编译器会读取 `virtio_scsi.h` 头文件，了解 `virtio_scsi_cmd_req` 结构体的布局和大小。这些信息会被编码到 `.rodata` 段（对于常量）和 `.symtab` (符号表) 中。
2. **运行时链接:** 当 Android 系统加载 `libvirtio_scsi_hw.so` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载共享库:** 将 `.so` 文件的各个段加载到内存中。
    * **符号解析:**  如果 `libvirtio_scsi_hw.so` 中的代码使用了 `virtio_scsi_cmd_req` 结构体，链接器会查找符号表 (`.symtab`)，找到 `virtio_scsi_cmd_req` 的地址和定义信息。由于 `virtio_scsi.h` 定义的是数据结构，其本身并不需要被“链接”，而是保证使用它的代码在编译时知道其布局。
    * **重定位:** 如果共享库中存在需要调整地址的代码（例如访问全局变量），链接器会根据加载地址调整这些地址。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设场景：Guest 需要向 Host 发送一个 SCSI 读命令。**

**假设输入 (Guest 端填充的 `virtio_scsi_cmd_req` 结构体):**

```c
struct virtio_scsi_cmd_req req;
memset(&req, 0, sizeof(req));

// 设置 LUN (逻辑单元号)
req.lun[1] = 0x01; // 假设 LUN 为 1

// 设置 Tag (命令标识符)
req.tag = 12345;

// 设置任务属性 (简单队列)
req.task_attr = VIRTIO_SCSI_S_SIMPLE;

// 填充 CDB (Command Descriptor Block) - 假设是读取逻辑块地址 0 的 8 个扇区
req.cdb[0] = 0x28; // READ(10) 命令
req.cdb[2] = 0x00; // MSB of LBA
req.cdb[3] = 0x00;
req.cdb[4] = 0x00;
req.cdb[5] = 0x00; // LSB of LBA (逻辑块地址 0)
req.cdb[7] = 0x00;
req.cdb[8] = 0x08; // 传输长度：8 个扇区
```

**假设输出 (Host 端返回的 `virtio_scsi_cmd_resp` 结构体，假设命令成功):**

```c
struct virtio_scsi_cmd_resp resp;
memset(&resp, 0, sizeof(resp));

// Sense 数据长度 (假设没有 Sense 数据)
resp.sense_len = 0;

// 剩余数据长度 (假设成功读取了所有请求的数据)
resp.resid = 0;

// 状态限定符 (通常为 0)
resp.status_qualifier = 0;

// 状态 (成功)
resp.status = 0; // 可以对应 VIRTIO_SCSI_S_OK

// 响应 (通常为 0)
resp.response = 0;
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **CDB 长度错误:**  填充 `req.cdb` 时，没有根据实际的 SCSI 命令正确设置 CDB 的长度。不同的 SCSI 命令有不同的 CDB 格式和长度。
2. **Sense 数据缓冲区溢出:** 在处理 `virtio_scsi_cmd_resp` 中的 `sense` 数据时，假设 Sense 数据的长度总是小于 `VIRTIO_SCSI_SENSE_SIZE`，而没有检查 `resp.sense_len` 的值，可能导致缓冲区溢出。
3. **字节序问题:**  直接赋值整数给 `__virtio32` 或 `__virtio64` 类型的字段，而没有考虑到 Host 和 Guest 之间的字节序差异。应该使用 `virtio_cpu_to_le32` 和 `virtio_cpu_to_le64` 等宏进行转换。
4. **不正确的状态码判断:**  没有正确理解和判断 `resp.status` 中的状态码，导致对错误情况处理不当。例如，将 `VIRTIO_SCSI_S_BUSY` 误认为致命错误。
5. **并发访问问题:** 在多线程环境中，多个线程同时尝试修改与 VirtIO SCSI 通信相关的共享数据结构，可能导致数据竞争和状态不一致。需要使用适当的同步机制（例如互斥锁）。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

从 Android Framework 或 NDK 到达这里通常需要经过以下步骤：

1. **应用程序 (Java/Kotlin 或 Native):**  应用程序发起存储相关的操作，例如读写文件。
2. **Framework 层 (Java):**  Framework 层的代码（例如 `java.io.FileInputStream`, `java.nio.file.Files`）将应用程序的请求转换为底层的系统调用。
3. **System Call:**  Framework 层通过 JNI (Java Native Interface) 调用到 Native 代码，最终触发一个系统调用，例如 `read()` 或 `write()`。
4. **内核 VFS 层:** 内核的虚拟文件系统 (VFS) 层接收到系统调用，并根据文件路径判断需要调用哪个文件系统的驱动。
5. **块设备层:** 如果访问的是块设备（例如虚拟磁盘），VFS 层会将请求传递给块设备层。
6. **VirtIO SCSI 驱动:** 块设备层会调用相应的块设备驱动，对于虚拟磁盘，可能是 VirtIO SCSI 驱动 (`virtio_scsi.ko`)。
7. **与 Guest OS 通信:** VirtIO SCSI 驱动会按照 `virtio_scsi.h` 中定义的结构体格式，构造请求（例如 `virtio_scsi_cmd_req`），并通过 VirtIO 机制与运行 Host 操作系统的 Hypervisor 或 QEMU 等虚拟化软件进行通信。

**Frida Hook 示例:**

假设我们想在 Android 系统中 hook VirtIO SCSI 驱动中发送 SCSI 命令请求的函数。由于驱动代码通常在内核空间，直接 hook 比较复杂。一个更可行的方案是 hook 用户空间中与 VirtIO SCSI 交互的 HAL (Hardware Abstraction Layer) 模块。

假设有一个名为 `android.hardware.scsi@1.0-service` 的 HAL 服务负责处理 SCSI 设备。我们可以尝试 hook 这个服务中发送 SCSI 命令的函数。

**Frida Hook 脚本示例 (假设函数名为 `sendScsiCommand`):**

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
console.log("Script loaded");

// 假设目标 HAL 库名为 libscsihal.so
var module = Process.getModuleByName("libscsihal.so");

// 遍历模块导出函数，查找可能的发送 SCSI 命令的函数
module.enumerateExports().forEach(function(exp) {
    if (exp.name.includes("sendScsiCommand") || exp.name.includes("executeScsi")) {
        console.log("Found potential function:", exp.name, "at", exp.address);
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                console.log("\\n[*] Calling function:", exp.name);
                // 假设第一个参数是指向 virtio_scsi_cmd_req 结构的指针
                if (args.length > 0) {
                    var cmd_req_ptr = ptr(args[0]);
                    console.log("[*] virtio_scsi_cmd_req pointer:", cmd_req_ptr);

                    // 读取结构体字段 (需要根据实际结构体定义和参数位置调整)
                    var lun = [];
                    for (var i = 0; i < 8; i++) {
                        lun.push(cmd_req_ptr.readU8(i));
                    }
                    console.log("[*] LUN:", lun);
                    console.log("[*] Tag:", cmd_req_ptr.readU64(8));
                    // ... 读取其他字段
                }
                console.log("[*] Arguments:", args);
            },
            onLeave: function(retval) {
                console.log("[*] Return value:", retval);
            }
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

* 这个 Frida 脚本尝试附加到指定的 Android 应用程序进程。
* 它搜索名为 `libscsihal.so` 的共享库（这只是一个假设，实际名称可能不同）。
* 它遍历该库的导出函数，查找包含 "sendScsiCommand" 或 "executeScsi" 关键字的函数，这可能是发送 SCSI 命令的函数。
* 使用 `Interceptor.attach` 来 hook 找到的函数，并在函数调用前后打印相关信息，包括参数（假设第一个参数是指向 `virtio_scsi_cmd_req` 结构的指针）和返回值。
* 你需要根据实际的 HAL 实现和函数签名来调整脚本中读取结构体字段的部分。

**请注意:**  直接 hook 内核驱动程序通常需要 root 权限和更高级的技术。 Hook 用户空间的 HAL 模块是观察 VirtIO SCSI 交互的一种更可行的方式。你需要根据具体的 Android 版本和设备查找相关的 HAL 服务和库。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_scsi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_VIRTIO_SCSI_H
#define _LINUX_VIRTIO_SCSI_H
#include <linux/virtio_types.h>
#define VIRTIO_SCSI_CDB_DEFAULT_SIZE 32
#define VIRTIO_SCSI_SENSE_DEFAULT_SIZE 96
#ifndef VIRTIO_SCSI_CDB_SIZE
#define VIRTIO_SCSI_CDB_SIZE VIRTIO_SCSI_CDB_DEFAULT_SIZE
#endif
#ifndef VIRTIO_SCSI_SENSE_SIZE
#define VIRTIO_SCSI_SENSE_SIZE VIRTIO_SCSI_SENSE_DEFAULT_SIZE
#endif
struct virtio_scsi_cmd_req {
  __u8 lun[8];
  __virtio64 tag;
  __u8 task_attr;
  __u8 prio;
  __u8 crn;
  __u8 cdb[VIRTIO_SCSI_CDB_SIZE];
} __attribute__((packed));
struct virtio_scsi_cmd_req_pi {
  __u8 lun[8];
  __virtio64 tag;
  __u8 task_attr;
  __u8 prio;
  __u8 crn;
  __virtio32 pi_bytesout;
  __virtio32 pi_bytesin;
  __u8 cdb[VIRTIO_SCSI_CDB_SIZE];
} __attribute__((packed));
struct virtio_scsi_cmd_resp {
  __virtio32 sense_len;
  __virtio32 resid;
  __virtio16 status_qualifier;
  __u8 status;
  __u8 response;
  __u8 sense[VIRTIO_SCSI_SENSE_SIZE];
} __attribute__((packed));
struct virtio_scsi_ctrl_tmf_req {
  __virtio32 type;
  __virtio32 subtype;
  __u8 lun[8];
  __virtio64 tag;
} __attribute__((packed));
struct virtio_scsi_ctrl_tmf_resp {
  __u8 response;
} __attribute__((packed));
struct virtio_scsi_ctrl_an_req {
  __virtio32 type;
  __u8 lun[8];
  __virtio32 event_requested;
} __attribute__((packed));
struct virtio_scsi_ctrl_an_resp {
  __virtio32 event_actual;
  __u8 response;
} __attribute__((packed));
struct virtio_scsi_event {
  __virtio32 event;
  __u8 lun[8];
  __virtio32 reason;
} __attribute__((packed));
struct virtio_scsi_config {
  __virtio32 num_queues;
  __virtio32 seg_max;
  __virtio32 max_sectors;
  __virtio32 cmd_per_lun;
  __virtio32 event_info_size;
  __virtio32 sense_size;
  __virtio32 cdb_size;
  __virtio16 max_channel;
  __virtio16 max_target;
  __virtio32 max_lun;
} __attribute__((packed));
#define VIRTIO_SCSI_F_INOUT 0
#define VIRTIO_SCSI_F_HOTPLUG 1
#define VIRTIO_SCSI_F_CHANGE 2
#define VIRTIO_SCSI_F_T10_PI 3
#define VIRTIO_SCSI_S_OK 0
#define VIRTIO_SCSI_S_OVERRUN 1
#define VIRTIO_SCSI_S_ABORTED 2
#define VIRTIO_SCSI_S_BAD_TARGET 3
#define VIRTIO_SCSI_S_RESET 4
#define VIRTIO_SCSI_S_BUSY 5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE 6
#define VIRTIO_SCSI_S_TARGET_FAILURE 7
#define VIRTIO_SCSI_S_NEXUS_FAILURE 8
#define VIRTIO_SCSI_S_FAILURE 9
#define VIRTIO_SCSI_S_FUNCTION_SUCCEEDED 10
#define VIRTIO_SCSI_S_FUNCTION_REJECTED 11
#define VIRTIO_SCSI_S_INCORRECT_LUN 12
#define VIRTIO_SCSI_T_TMF 0
#define VIRTIO_SCSI_T_AN_QUERY 1
#define VIRTIO_SCSI_T_AN_SUBSCRIBE 2
#define VIRTIO_SCSI_T_TMF_ABORT_TASK 0
#define VIRTIO_SCSI_T_TMF_ABORT_TASK_SET 1
#define VIRTIO_SCSI_T_TMF_CLEAR_ACA 2
#define VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET 3
#define VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET 4
#define VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET 5
#define VIRTIO_SCSI_T_TMF_QUERY_TASK 6
#define VIRTIO_SCSI_T_TMF_QUERY_TASK_SET 7
#define VIRTIO_SCSI_T_EVENTS_MISSED 0x80000000
#define VIRTIO_SCSI_T_NO_EVENT 0
#define VIRTIO_SCSI_T_TRANSPORT_RESET 1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY 2
#define VIRTIO_SCSI_T_PARAM_CHANGE 3
#define VIRTIO_SCSI_EVT_RESET_HARD 0
#define VIRTIO_SCSI_EVT_RESET_RESCAN 1
#define VIRTIO_SCSI_EVT_RESET_REMOVED 2
#define VIRTIO_SCSI_S_SIMPLE 0
#define VIRTIO_SCSI_S_ORDERED 1
#define VIRTIO_SCSI_S_HEAD 2
#define VIRTIO_SCSI_S_ACA 3
#endif

"""

```