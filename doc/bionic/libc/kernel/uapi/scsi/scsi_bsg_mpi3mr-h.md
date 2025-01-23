Response:
Let's break down the thought process for answering the user's request about the `scsi_bsg_mpi3mr.handroid` header file.

**1. Understanding the Core Request:**

The user wants to understand the purpose and functionality of this specific header file within the Android Bionic library. The key is to extract meaning from the definitions and connect them to Android's broader functionality.

**2. Initial Analysis of the Header File:**

* **`auto-generated`:**  This is crucial. It means we're likely dealing with kernel-level definitions exposed to userspace, and manual modifications are discouraged. The source URL reinforces this.
* **`#ifndef SCSI_BSG_MPI3MR_H_INCLUDED`:**  Standard header guard, preventing multiple inclusions.
* **Includes `<linux/types.h>`:**  Indicates interaction with the Linux kernel.
* **`MPI3MR_...` Definitions:**  A large number of `#define` and `enum` declarations. These are the core of the file, defining constants, data structures, and opcodes related to a specific hardware or software component. The "MPI3MR" prefix suggests a specific driver or protocol. The "BSG" likely stands for "Block SCSI Generic" or a similar concept related to generic SCSI command handling.
* **`struct mpi3_...` and `struct mpi3mr_...`:**  These define data structures used to communicate with the underlying hardware/driver. The naming conventions give clues about their purpose (e.g., `mpi3_driver_info_layout`, `mpi3mr_bsg_in_adpinfo`).
* **Constants and Enums:**  These provide semantic meaning to numerical values, making the code more readable and maintainable. They define things like adapter states, reset types, buffer types, opcodes, and error codes.

**3. Identifying the Core Functionality:**

By examining the defined constants and structures, patterns emerge:

* **Adapter Information (`MPI3MR_DRVBSG_OPCODE_ADPINFO`, `mpi3mr_bsg_in_adpinfo`):**  The ability to query the status and capabilities of a hardware adapter.
* **Adapter Reset (`MPI3MR_DRVBSG_OPCODE_ADPRESET`, `mpi3mr_bsg_adp_reset`):**  Functionality to reset the adapter.
* **Target Device Information (`MPI3MR_DRVBSG_OPCODE_ALLTGTDEVINFO`, `mpi3mr_all_tgt_info`):**  Retrieving information about connected SCSI target devices.
* **Logging (`MPI3MR_DRVBSG_OPCODE_LOGDATAENABLE`, `MPI3MR_DRVBSG_OPCODE_GETLOGDATA`, `mpi3mr_logdata_enable`, `mpi3mr_bsg_in_log_data`):** Enabling and retrieving diagnostic logs.
* **Host Data Buffer Management (`MPI3MR_DRVBSG_OPCODE_QUERY_HDB`, `MPI3MR_DRVBSG_OPCODE_REPOST_HDB`, etc., `mpi3mr_hdb_entry`):** Mechanisms for managing host memory buffers used for communication.
* **Command Submission (`MPI3MR_DRV_CMD`, `MPI3MR_MPT_CMD`, `mpi3mr_bsg_packet`):**  Structures to encapsulate commands sent to the adapter. Distinction between driver commands and more generic MPT (Message Passing Technology?) commands.
* **NVMe and SCSI Passthrough (`MPI3_BSG_FUNCTION_NVME_ENCAPSULATED`, `MPI3_BSG_FUNCTION_SCSI_IO`):** Support for sending raw NVMe and SCSI commands.
* **SCSI Task Management (`MPI3_BSG_FUNCTION_SCSI_TASK_MGMT`, `mpi3_scsi_task_mgmt_request`, `mpi3_scsi_task_mgmt_reply`):**  Sending commands to manage SCSI tasks (abort, reset, etc.).

**4. Connecting to Android:**

The "bionic" path is the key. Bionic is Android's C library. This header file provides a userspace interface to interact with a low-level hardware component, likely a RAID controller or a similar device. The `ioctl` system call is the standard way for userspace to communicate with device drivers. The `scsi_bsg` directory suggests this is part of the Block SCSI Generic interface.

**5. Addressing Specific User Questions:**

* **Functionality Listing:**  Summarize the identified functionalities clearly.
* **Android Relevance and Examples:** Focus on how a storage-related component like a RAID controller interacts with Android's storage stack. Mentioning file systems, disk management, and potential use in servers/high-end devices is important.
* **`libc` Function Explanation:** The header file itself *doesn't* contain `libc` function implementations. It defines *data structures* that would be used *with* `libc` functions like `open()`, `ioctl()`, `read()`, `write()`, and memory management functions. Explain this distinction clearly.
* **Dynamic Linker:**  This header file doesn't directly involve the dynamic linker. However, the *driver* that uses these definitions would be a kernel module. Explain the difference between kernel modules and userspace shared libraries (.so files). Provide a basic example of an `.so` layout for illustrative purposes, even though it's not directly relevant to this *specific* file.
* **Logic and Assumptions:** The primary assumption is that "MPI3MR" refers to a specific hardware RAID controller or similar device. The input/output examples should relate to the `ioctl` system call and the defined structures.
* **Common Errors:** Focus on incorrect `ioctl` usage, such as wrong command codes, buffer sizes, or permissions.
* **Android Framework/NDK Path and Frida:** Explain how a high-level framework component (like the Storage Manager) might eventually trigger low-level `ioctl` calls using these definitions. Provide a conceptual Frida hook example targeting the `ioctl` call with the relevant `ioctl` number.

**6. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request systematically. Use clear headings and bullet points to improve readability. Provide code snippets where appropriate (like the Frida example).

**7. Refining and Reviewing:**

Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on user-space `libc` functions. Recognizing that this header is about *interfacing* with the kernel driver is crucial.

By following this thought process, we can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to dissect the header file, identify the core functionalities it defines, and then connect those functionalities to the broader context of Android and its interaction with the underlying hardware.
这个文件 `bionic/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.handroid` 是 Android Bionic 库中的一个头文件，它定义了用于与基于 Broadcom (LSI/Avago) MegaRAID MPI3 芯片的 SCSI 控制器进行通信的常量、数据结构和枚举。 这里的 `bsg` 代表 "Block SCSI Generic"，这是一种通用的 SCSI 命令传输机制。 `uapi` 表明这是用户空间 API，意味着用户空间的应用程序可以使用这些定义来与内核驱动程序交互。

**它的主要功能可以总结如下:**

1. **定义了与 MegaRAID MPI3 控制器交互的 IOCTL 命令代码和数据结构。** 这些定义允许用户空间程序（例如，存储管理工具）发送命令到内核驱动程序，从而控制和管理 RAID 控制器。
2. **定义了适配器状态和属性相关的常量。** 例如，适配器的类型、状态（运行中、故障等）以及支持的重置类型。
3. **定义了驱动程序和固件信息的结构。** 这允许用户空间程序获取有关驱动程序版本、固件版本等信息。
4. **定义了设备映射信息相关的结构。**  提供有关连接到控制器的 SCSI 目标设备的信息，例如设备句柄、PERST ID、目标 ID 和总线 ID。
5. **定义了日志记录相关的结构和常量。** 允许启用、禁用和检索控制器的日志数据，用于诊断和故障排除。
6. **定义了事件记录 (PEL) 相关的结构和常量。** 提供了一种方式来控制和获取平台事件日志信息。
7. **定义了主机数据缓冲区 (HDB) 管理相关的结构和常量。**  这涉及到控制器如何与主机共享内存缓冲区，用于数据传输或其他目的。
8. **定义了用于封装驱动程序特定命令和通用 MPT (Message Passing Technology) 命令的结构。**  MPT 是 MegaRAID 控制器内部使用的一种通信协议。
9. **定义了 NVMe over Fabrics (NVMe-oF) 封装请求和响应的结构。** 这表明该控制器可能支持 NVMe 设备，并且可以通过特定的封装机制进行管理。
10. **定义了 SCSI 任务管理请求和响应的结构。** 允许发送 SCSI 任务管理命令，例如中止任务、重置目标等。

**与 Android 功能的关系及举例说明:**

这个头文件直接关联到 Android 设备中的存储子系统，特别是当设备使用了基于 Broadcom MegaRAID MPI3 芯片的硬件 RAID 控制器时。

* **存储管理和监控:**  Android 系统或特定的应用程序可以使用这些定义来查询 RAID 控制器的状态、磁盘信息、重建进度等。例如，一个底层的存储管理服务可能会使用 `MPI3MR_DRVBSG_OPCODE_ADPINFO` 来获取适配器信息，或者使用 `MPI3MR_DRVBSG_OPCODE_ALLTGTDEVINFO` 来获取连接的磁盘信息。
* **故障诊断和恢复:**  当存储出现问题时，可以使用日志记录功能（如 `MPI3MR_DRVBSG_OPCODE_GETLOGDATA`) 来收集控制器的诊断信息，帮助定位问题。
* **固件更新:** 虽然这个头文件本身不包含固件更新的直接功能，但它提供的接口可能被用于实现固件更新工具的一部分。例如，可能需要获取当前固件版本或发送特定的控制命令。
* **高性能存储:** 在一些高端 Android 设备或服务器场景中，使用硬件 RAID 可以提供更高的存储性能和数据冗余。这个头文件是与这些硬件交互的必要接口。

**libc 函数的功能是如何实现的:**

这个头文件本身**并不包含任何 libc 函数的实现**。它只是定义了常量、数据结构和枚举。用户空间的应用程序会使用标准的 libc 函数，例如：

* **`open()`:** 用于打开设备文件，通常是 `/dev/bsg/` 下与该控制器关联的设备节点。
* **`ioctl()`:**  这是与设备驱动程序进行交互的核心函数。应用程序会使用 `ioctl()` 系统调用，并传入这里定义的 `MPI3MR_DRVBSG_OPCODE_...` 常量作为命令代码，以及定义的数据结构作为参数，来发送命令到 RAID 控制器驱动程序。
* **`malloc()`, `free()`:**  用于分配和释放内存，以存储与 `ioctl()` 调用相关的数据结构。
* **`memcpy()`:**  用于在内存中复制数据，例如构建发送给驱动程序的数据包或解析接收到的数据。

**详细解释 `ioctl()` 的使用:**

`ioctl()` 系统调用允许用户空间的程序向设备驱动程序发送设备特定的控制命令。对于 `scsi_bsg_mpi3mr.h` 中定义的命令，其使用方式大致如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h> // 可能需要，取决于具体的ioctl调用
#include <scsi/scsi_ioctl.h> // 通常需要与 SCSI 设备交互
#include "scsi_bsg_mpi3mr.handroid" // 包含定义的头文件

int main() {
    int fd;
    struct bsg_header bhdr; // bsg 通用头部
    struct mpi3mr_bsg_packet packet; // MPI3MR 特定的数据包结构
    struct mpi3mr_bsg_in_adpinfo adp_info; // 用于接收适配器信息的结构

    fd = open("/dev/bsg/...", O_RDWR); // 打开对应的 bsg 设备节点，具体路径取决于系统配置
    if (fd < 0) {
        perror("打开设备失败");
        return 1;
    }

    // 填充 bsg 头部
    bhdr.magic = BSG_MAGIC;
    bhdr.version = BSG_VERSION;
    bhdr.request_len = sizeof(packet); // 请求数据长度
    bhdr.reply_len = sizeof(adp_info); // 预期的回复数据长度
    bhdr.timeout_ms = 1000; // 超时时间

    // 填充 MPI3MR 特定数据包，例如获取适配器信息
    packet.cmd_type = MPI3MR_DRV_CMD;
    packet.cmd.drvrcmd.opcode = MPI3MR_DRVBSG_OPCODE_ADPINFO;
    // ... 其他字段可能需要初始化为 0

    // 发送 IOCTL 命令
    if (ioctl(fd, SG_IO, &bhdr) < 0) { // 使用 SG_IO ioctl 命令进行 bsg 操作
        perror("发送 IOCTL 失败");
        close(fd);
        return 1;
    }

    // 检查状态并处理回复数据
    if (bhdr.status == 0) {
        // 成功，回复数据在 adp_info 中
        printf("适配器类型: %u\n", adp_info.adp_type);
        // ... 打印其他适配器信息
    } else {
        fprintf(stderr, "IOCTL 调用失败，状态: %d\n", bhdr.status);
    }

    close(fd);
    return 0;
}
```

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身**不涉及 dynamic linker 的功能**。 它定义的是内核接口，而不是用户空间的共享库。

与 dynamic linker 相关的是用户空间的应用程序，当它们需要使用与存储相关的库（这些库可能会使用到这里定义的接口）时，dynamic linker 会负责加载和链接这些库。

**一个假设的 so 布局样本:**

假设有一个名为 `libmegaraid.so` 的共享库，它封装了与 MegaRAID 控制器交互的功能。

```
libmegaraid.so:
    .text         # 包含代码段
        - 获取适配器信息的函数 (内部会使用 ioctl 并填充 mpi3mr_bsg_packet 等结构)
        - 获取磁盘信息的函数
        - ... 其他功能函数
    .data         # 包含已初始化的全局变量
    .bss          # 包含未初始化的全局变量
    .dynsym       # 动态符号表 (导出的函数和变量)
        - get_adapter_info
        - get_disk_info
        - ...
    .dynstr       # 动态字符串表 (符号名称)
    .plt          # 程序链接表 (用于延迟绑定)
    .got.plt      # 全局偏移量表 (用于动态链接)
    ... 其他段
```

**链接的处理过程:**

1. **编译时链接:** 当开发者编译使用 `libmegaraid.so` 的应用程序时，编译器会将对 `get_adapter_info` 等函数的调用标记为需要动态链接。
2. **加载时链接:** 当 Android 系统加载应用程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
    * **查找依赖:**  读取应用程序的 ELF 头，找到其依赖的共享库列表，包括 `libmegaraid.so`。
    * **加载共享库:**  在文件系统中查找 `libmegaraid.so`，并将其加载到内存中。
    * **符号解析:**  遍历应用程序的 `.plt` 和 `libmegaraid.so` 的 `.dynsym`，找到应用程序中调用的 `get_adapter_info` 等符号在 `libmegaraid.so` 中的地址。
    * **重定位:**  修改应用程序的 `.got.plt` 表项，将这些符号的地址指向 `libmegaraid.so` 中对应的函数地址。这样，当应用程序调用 `get_adapter_info` 时，实际上会跳转到 `libmegaraid.so` 中该函数的实现。

**逻辑推理的假设输入与输出:**

假设我们使用 `MPI3MR_DRVBSG_OPCODE_ADPINFO` 获取适配器信息。

**假设输入:**

* 打开设备文件描述符 `fd` 指向正确的 `/dev/bsg/...` 设备节点。
* `struct bsg_header bhdr` 结构体被正确初始化，`request_len` 设置为 `sizeof(struct mpi3mr_bsg_packet)`，`reply_len` 设置为 `sizeof(struct mpi3mr_bsg_in_adpinfo)`。
* `struct mpi3mr_bsg_packet packet` 结构体的 `cmd_type` 被设置为 `MPI3MR_DRV_CMD`，`opcode` 被设置为 `MPI3MR_DRVBSG_OPCODE_ADPINFO`。

**预期输出:**

* `ioctl()` 调用成功返回 0。
* `bhdr.status` 为 0，表示操作成功。
* `struct mpi3mr_bsg_in_adpinfo adp_info` 结构体被填充了 RAID 控制器的信息，例如 `adp_type` 可能为 `MPI3MR_BSG_ADPTYPE_AVGFAMILY`，`adp_state` 可能为 `MPI3MR_BSG_ADPSTATE_OPERATIONAL`，以及其他 PCI 设备信息、驱动程序信息等。

**涉及用户或者编程常见的使用错误，举例说明:**

1. **错误的设备节点路径:** 打开了错误的 `/dev/bsg/...` 设备节点，导致 `open()` 调用失败。
2. **`ioctl()` 命令代码错误:**  使用了不正确的 `MPI3MR_DRVBSG_OPCODE_...` 常量，导致驱动程序无法识别请求。
3. **数据结构大小不匹配:** `bhdr.request_len` 或 `bhdr.reply_len` 设置错误，与实际发送或接收的数据结构大小不符，可能导致数据截断或缓冲区溢出。
4. **未正确初始化数据结构:**  发送给驱动程序的数据结构中，某些字段未初始化为期望的值，导致驱动程序处理错误。
5. **权限问题:** 用户没有足够的权限打开设备节点或执行 `ioctl()` 操作。
6. **超时:**  `bhdr.timeout_ms` 设置过短，导致 `ioctl()` 调用因超时而失败。
7. **并发访问冲突:** 多个进程或线程同时尝试访问同一个 RAID 控制器，可能导致冲突和错误。
8. **假设硬件存在:** 代码中假设设备存在，但实际硬件可能未安装或未正确驱动。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android framework 不会直接调用这些底层的 `ioctl` 命令。 而是由更底层的系统服务或 HAL (Hardware Abstraction Layer) 模块来处理与硬件的交互。

**可能的路径:**

1. **Framework 层:**  例如，StorageManager 服务可能会请求获取磁盘信息或执行磁盘操作。
2. **System Server 层:** StorageManager 的请求可能被传递给更底层的服务，例如 vold (Volume Daemon)，它负责管理存储卷和设备。
3. **HAL 层:** vold 可能会调用存储 HAL 的接口，这些 HAL 模块通常是用 C/C++ 编写，并与内核驱动程序交互。
4. **Kernel Driver:**  存储 HAL 最终会通过 `open()` 打开 `/dev/bsg/...` 设备节点，并使用 `ioctl()` 系统调用，配合 `scsi_bsg_mpi3mr.h` 中定义的常量和数据结构，来发送命令到 MegaRAID 控制器的内核驱动程序。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `ioctl` 调用，并打印相关信息的示例。你需要先找到负责与 RAID 控制器交互的进程（例如，vold 或相关的 HAL 进程）。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload'], data))
    else:
        print(message)

try:
    # 替换为目标进程的名称或 PID
    process = frida.get_usb_device().attach('com.android.vold')
except frida.ProcessNotFoundError:
    print("目标进程未找到，请检查进程名称或 PID。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        // 检查是否是与 bsg 相关的 ioctl 命令 (SG_IO)
        if (request === 0x2285) { // SG_IO 的值，可能需要根据平台调整
            var bsg_header_ptr = ptr(argp);
            var magic = bsg_header_ptr.readU32();
            var version = bsg_header_ptr.add(4).readU32();
            var request_len = bsg_header_ptr.add(8).readU32();
            var reply_len = bsg_header_ptr.add(12).readU32();

            if (magic === 0x22355347) { // BSG_MAGIC
                send("ioctl called with fd: " + fd + ", request: 0x" + request.toString(16));
                send("BSG Header - Magic: 0x" + magic.toString(16) + ", Version: " + version +
                     ", Request Len: " + request_len + ", Reply Len: " + reply_len);

                // 尝试读取 mpi3mr_bsg_packet 的 opcode
                if (request_len >= 8) {
                    var packet_ptr = bsg_header_ptr.add(24); // bsg_header 之后是数据包
                    var cmd_type = packet_ptr.readU8();
                    var opcode = packet_ptr.add(1).readU8();
                    send("MPI3MR Packet - Cmd Type: " + cmd_type + ", Opcode: " + opcode);
                }
            }
        }
    },
    onLeave: function(retval) {
        send("ioctl returned: " + retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用 Frida Hook 调试步骤:**

1. **找到目标进程:**  确定负责存储管理的进程，通常是 `vold` 或相关的 HAL 进程。
2. **编写 Frida 脚本:**  使用 `Interceptor.attach` 拦截 `ioctl` 系统调用。
3. **过滤 `ioctl` 命令:**  检查 `ioctl` 的 `request` 参数是否是与 SCSI generic (SG_IO) 相关的命令，并进一步检查 BSG header 的 magic 值。
4. **解析数据结构:**  如果确定是与 `scsi_bsg_mpi3mr` 相关的调用，尝试读取 `bsg_header` 和 `mpi3mr_bsg_packet` 结构体中的关键字段，例如 `opcode`。
5. **打印信息:**  使用 `send()` 函数将拦截到的信息发送回 Frida 客户端。
6. **执行操作:**  在 Android 设备上执行触发存储操作的动作，例如挂载 USB 存储、访问文件等。
7. **查看 Frida 输出:**  观察 Frida 客户端的输出，查看拦截到的 `ioctl` 调用以及相关的参数信息，从而了解 framework 或系统服务是如何一步步调用到这个底层的接口的。

请注意，上述 Frida 脚本只是一个基本示例，可能需要根据具体的 Android 版本和实现细节进行调整。 你可能需要更深入地分析内存布局来准确读取结构体的内容。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef SCSI_BSG_MPI3MR_H_INCLUDED
#define SCSI_BSG_MPI3MR_H_INCLUDED
#include <linux/types.h>
#define MPI3MR_IOCTL_VERSION 0x06
#define MPI3MR_APP_DEFAULT_TIMEOUT (60)
#define MPI3MR_BSG_ADPTYPE_UNKNOWN 0
#define MPI3MR_BSG_ADPTYPE_AVGFAMILY 1
#define MPI3MR_BSG_ADPSTATE_UNKNOWN 0
#define MPI3MR_BSG_ADPSTATE_OPERATIONAL 1
#define MPI3MR_BSG_ADPSTATE_FAULT 2
#define MPI3MR_BSG_ADPSTATE_IN_RESET 3
#define MPI3MR_BSG_ADPSTATE_UNRECOVERABLE 4
#define MPI3MR_BSG_ADPRESET_UNKNOWN 0
#define MPI3MR_BSG_ADPRESET_SOFT 1
#define MPI3MR_BSG_ADPRESET_DIAG_FAULT 2
#define MPI3MR_BSG_LOGDATA_MAX_ENTRIES 400
#define MPI3MR_BSG_LOGDATA_ENTRY_HEADER_SZ 4
#define MPI3MR_DRVBSG_OPCODE_UNKNOWN 0
#define MPI3MR_DRVBSG_OPCODE_ADPINFO 1
#define MPI3MR_DRVBSG_OPCODE_ADPRESET 2
#define MPI3MR_DRVBSG_OPCODE_ALLTGTDEVINFO 4
#define MPI3MR_DRVBSG_OPCODE_GETCHGCNT 5
#define MPI3MR_DRVBSG_OPCODE_LOGDATAENABLE 6
#define MPI3MR_DRVBSG_OPCODE_PELENABLE 7
#define MPI3MR_DRVBSG_OPCODE_GETLOGDATA 8
#define MPI3MR_DRVBSG_OPCODE_QUERY_HDB 9
#define MPI3MR_DRVBSG_OPCODE_REPOST_HDB 10
#define MPI3MR_DRVBSG_OPCODE_UPLOAD_HDB 11
#define MPI3MR_DRVBSG_OPCODE_REFRESH_HDB_TRIGGERS 12
#define MPI3MR_BSG_BUFTYPE_UNKNOWN 0
#define MPI3MR_BSG_BUFTYPE_RAIDMGMT_CMD 1
#define MPI3MR_BSG_BUFTYPE_RAIDMGMT_RESP 2
#define MPI3MR_BSG_BUFTYPE_DATA_IN 3
#define MPI3MR_BSG_BUFTYPE_DATA_OUT 4
#define MPI3MR_BSG_BUFTYPE_MPI_REPLY 5
#define MPI3MR_BSG_BUFTYPE_ERR_RESPONSE 6
#define MPI3MR_BSG_BUFTYPE_MPI_REQUEST 0xFE
#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_UNKNOWN 0
#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_STATUS 1
#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_ADDRESS 2
#define MPI3MR_HDB_BUFTYPE_UNKNOWN 0
#define MPI3MR_HDB_BUFTYPE_TRACE 1
#define MPI3MR_HDB_BUFTYPE_FIRMWARE 2
#define MPI3MR_HDB_BUFTYPE_RESERVED 3
#define MPI3MR_HDB_BUFSTATUS_UNKNOWN 0
#define MPI3MR_HDB_BUFSTATUS_NOT_ALLOCATED 1
#define MPI3MR_HDB_BUFSTATUS_POSTED_UNPAUSED 2
#define MPI3MR_HDB_BUFSTATUS_POSTED_PAUSED 3
#define MPI3MR_HDB_BUFSTATUS_RELEASED 4
#define MPI3MR_HDB_TRIGGER_TYPE_UNKNOWN 0
#define MPI3MR_HDB_TRIGGER_TYPE_DIAGFAULT 1
#define MPI3MR_HDB_TRIGGER_TYPE_ELEMENT 2
#define MPI3MR_HDB_TRIGGER_TYPE_MASTER 3
enum command {
  MPI3MR_DRV_CMD = 1,
  MPI3MR_MPT_CMD = 2,
};
struct mpi3_driver_info_layout {
  __le32 information_length;
  __u8 driver_signature[12];
  __u8 os_name[16];
  __u8 os_version[12];
  __u8 driver_name[20];
  __u8 driver_version[32];
  __u8 driver_release_date[20];
  __le32 driver_capabilities;
};
struct mpi3mr_bsg_in_adpinfo {
  __u32 adp_type;
  __u32 rsvd1;
  __u32 pci_dev_id;
  __u32 pci_dev_hw_rev;
  __u32 pci_subsys_dev_id;
  __u32 pci_subsys_ven_id;
  __u32 pci_dev : 5;
  __u32 pci_func : 3;
  __u32 pci_bus : 8;
  __u16 rsvd2;
  __u32 pci_seg_id;
  __u32 app_intfc_ver;
  __u8 adp_state;
  __u8 rsvd3;
  __u16 rsvd4;
  __u32 rsvd5[2];
  struct mpi3_driver_info_layout driver_info;
};
struct mpi3mr_bsg_adp_reset {
  __u8 reset_type;
  __u8 rsvd1;
  __u16 rsvd2;
};
struct mpi3mr_change_count {
  __u16 change_count;
  __u16 rsvd;
};
struct mpi3mr_device_map_info {
  __u16 handle;
  __u16 perst_id;
  __u32 target_id;
  __u8 bus_id;
  __u8 rsvd1;
  __u16 rsvd2;
};
struct mpi3mr_all_tgt_info {
  __u16 num_devices;
  __u16 rsvd1;
  __u32 rsvd2;
  struct mpi3mr_device_map_info dmi[1];
};
struct mpi3mr_logdata_enable {
  __u16 max_entries;
  __u16 rsvd;
};
struct mpi3mr_bsg_out_pel_enable {
  __u16 pel_locale;
  __u8 pel_class;
  __u8 rsvd;
};
struct mpi3mr_logdata_entry {
  __u8 valid_entry;
  __u8 rsvd1;
  __u16 rsvd2;
  __u8 data[1];
};
struct mpi3mr_bsg_in_log_data {
  struct mpi3mr_logdata_entry entry[1];
};
struct mpi3mr_hdb_entry {
  __u8 buf_type;
  __u8 status;
  __u8 trigger_type;
  __u8 rsvd1;
  __u16 size;
  __u16 rsvd2;
  __u64 trigger_data;
  __u32 rsvd3;
  __u32 rsvd4;
};
struct mpi3mr_bsg_in_hdb_status {
  __u8 num_hdb_types;
  __u8 element_trigger_format;
  __u16 rsvd2;
  __u32 rsvd3;
  struct mpi3mr_hdb_entry entry[1];
};
struct mpi3mr_bsg_out_repost_hdb {
  __u8 buf_type;
  __u8 rsvd1;
  __u16 rsvd2;
};
struct mpi3mr_bsg_out_upload_hdb {
  __u8 buf_type;
  __u8 rsvd1;
  __u16 rsvd2;
  __u32 start_offset;
  __u32 length;
};
struct mpi3mr_bsg_out_refresh_hdb_triggers {
  __u8 page_type;
  __u8 rsvd1;
  __u16 rsvd2;
};
struct mpi3mr_bsg_drv_cmd {
  __u8 mrioc_id;
  __u8 opcode;
  __u16 rsvd1;
  __u32 rsvd2[4];
};
struct mpi3mr_bsg_in_reply_buf {
  __u8 mpi_reply_type;
  __u8 rsvd1;
  __u16 rsvd2;
  __u8 reply_buf[];
};
struct mpi3mr_buf_entry {
  __u8 buf_type;
  __u8 rsvd1;
  __u16 rsvd2;
  __u32 buf_len;
};
struct mpi3mr_buf_entry_list {
  __u8 num_of_entries;
  __u8 rsvd1;
  __u16 rsvd2;
  __u32 rsvd3;
  struct mpi3mr_buf_entry buf_entry[1];
};
struct mpi3mr_bsg_mptcmd {
  __u8 mrioc_id;
  __u8 rsvd1;
  __u16 timeout;
  __u32 rsvd2;
  struct mpi3mr_buf_entry_list buf_entry_list;
};
struct mpi3mr_bsg_packet {
  __u8 cmd_type;
  __u8 rsvd1;
  __u16 rsvd2;
  __u32 rsvd3;
  union {
    struct mpi3mr_bsg_drv_cmd drvrcmd;
    struct mpi3mr_bsg_mptcmd mptcmd;
  } cmd;
};
struct mpi3_nvme_encapsulated_request {
  __le16 host_tag;
  __u8 ioc_use_only02;
  __u8 function;
  __le16 ioc_use_only04;
  __u8 ioc_use_only06;
  __u8 msg_flags;
  __le16 change_count;
  __le16 dev_handle;
  __le16 encapsulated_command_length;
  __le16 flags;
  __le32 data_length;
  __le32 reserved14[3];
  __le32 command[];
};
struct mpi3_nvme_encapsulated_error_reply {
  __le16 host_tag;
  __u8 ioc_use_only02;
  __u8 function;
  __le16 ioc_use_only04;
  __u8 ioc_use_only06;
  __u8 msg_flags;
  __le16 ioc_use_only08;
  __le16 ioc_status;
  __le32 ioc_log_info;
  __le32 nvme_completion_entry[4];
};
#define MPI3MR_NVME_PRP_SIZE 8
#define MPI3MR_NVME_CMD_PRP1_OFFSET 24
#define MPI3MR_NVME_CMD_PRP2_OFFSET 32
#define MPI3MR_NVME_CMD_SGL_OFFSET 24
#define MPI3MR_NVME_DATA_FORMAT_PRP 0
#define MPI3MR_NVME_DATA_FORMAT_SGL1 1
#define MPI3MR_NVME_DATA_FORMAT_SGL2 2
#define MPI3MR_NVMESGL_DATA_SEGMENT 0x00
#define MPI3MR_NVMESGL_LAST_SEGMENT 0x03
struct mpi3_scsi_task_mgmt_request {
  __le16 host_tag;
  __u8 ioc_use_only02;
  __u8 function;
  __le16 ioc_use_only04;
  __u8 ioc_use_only06;
  __u8 msg_flags;
  __le16 change_count;
  __le16 dev_handle;
  __le16 task_host_tag;
  __u8 task_type;
  __u8 reserved0f;
  __le16 task_request_queue_id;
  __le16 reserved12;
  __le32 reserved14;
  __u8 lun[8];
};
#define MPI3_SCSITASKMGMT_MSGFLAGS_DO_NOT_SEND_TASK_IU (0x08)
#define MPI3_SCSITASKMGMT_TASKTYPE_ABORT_TASK (0x01)
#define MPI3_SCSITASKMGMT_TASKTYPE_ABORT_TASK_SET (0x02)
#define MPI3_SCSITASKMGMT_TASKTYPE_TARGET_RESET (0x03)
#define MPI3_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET (0x05)
#define MPI3_SCSITASKMGMT_TASKTYPE_CLEAR_TASK_SET (0x06)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_TASK (0x07)
#define MPI3_SCSITASKMGMT_TASKTYPE_CLEAR_ACA (0x08)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_TASK_SET (0x09)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_ASYNC_EVENT (0x0a)
#define MPI3_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET (0x0b)
struct mpi3_scsi_task_mgmt_reply {
  __le16 host_tag;
  __u8 ioc_use_only02;
  __u8 function;
  __le16 ioc_use_only04;
  __u8 ioc_use_only06;
  __u8 msg_flags;
  __le16 ioc_use_only08;
  __le16 ioc_status;
  __le32 ioc_log_info;
  __le32 termination_count;
  __le32 response_data;
  __le32 reserved18;
};
#define MPI3_SCSITASKMGMT_RSPCODE_TM_COMPLETE (0x00)
#define MPI3_SCSITASKMGMT_RSPCODE_INVALID_FRAME (0x02)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_FUNCTION_NOT_SUPPORTED (0x04)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_FAILED (0x05)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_SUCCEEDED (0x08)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_INVALID_LUN (0x09)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_OVERLAPPED_TAG (0x0a)
#define MPI3_SCSITASKMGMT_RSPCODE_IO_QUEUED_ON_IOC (0x80)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_NVME_DENIED (0x81)
#define MPI3_PEL_LOCALE_FLAGS_NON_BLOCKING_BOOT_EVENT (0x0200)
#define MPI3_PEL_LOCALE_FLAGS_BLOCKING_BOOT_EVENT (0x0100)
#define MPI3_PEL_LOCALE_FLAGS_PCIE (0x0080)
#define MPI3_PEL_LOCALE_FLAGS_CONFIGURATION (0x0040)
#define MPI3_PEL_LOCALE_FLAGS_CONTROLER (0x0020)
#define MPI3_PEL_LOCALE_FLAGS_SAS (0x0010)
#define MPI3_PEL_LOCALE_FLAGS_EPACK (0x0008)
#define MPI3_PEL_LOCALE_FLAGS_ENCLOSURE (0x0004)
#define MPI3_PEL_LOCALE_FLAGS_PD (0x0002)
#define MPI3_PEL_LOCALE_FLAGS_VD (0x0001)
#define MPI3_PEL_CLASS_DEBUG (0x00)
#define MPI3_PEL_CLASS_PROGRESS (0x01)
#define MPI3_PEL_CLASS_INFORMATIONAL (0x02)
#define MPI3_PEL_CLASS_WARNING (0x03)
#define MPI3_PEL_CLASS_CRITICAL (0x04)
#define MPI3_PEL_CLASS_FATAL (0x05)
#define MPI3_PEL_CLASS_FAULT (0x06)
#define MPI3_BSG_FUNCTION_MGMT_PASSTHROUGH (0x0a)
#define MPI3_BSG_FUNCTION_SCSI_IO (0x20)
#define MPI3_BSG_FUNCTION_SCSI_TASK_MGMT (0x21)
#define MPI3_BSG_FUNCTION_SMP_PASSTHROUGH (0x22)
#define MPI3_BSG_FUNCTION_NVME_ENCAPSULATED (0x24)
#endif
```