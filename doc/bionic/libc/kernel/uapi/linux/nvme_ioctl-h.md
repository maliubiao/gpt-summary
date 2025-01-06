Response:
Let's break down the thought process for answering the request about the `nvme_ioctl.h` file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of a header file related to NVMe IO control in Android's Bionic library. The key is to extract information about its function, its relevance to Android, its implementation details (if possible from a header), how it relates to dynamic linking, potential errors, and how Android uses it, along with a Frida example.

**2. Initial Analysis of the Header File:**

* **File Purpose:** The header file name `nvme_ioctl.h` and the presence of `NVME_IOCTL_*` macros strongly suggest it's related to controlling NVMe (Non-Volatile Memory Express) devices through ioctl system calls. The "uapi" in the path indicates it's part of the user-kernel API.
* **Data Structures:** The file defines several `struct` types: `nvme_user_io`, `nvme_passthru_cmd`, `nvme_passthru_cmd64`, and `nvme_uring_cmd`. These structures likely represent different ways to interact with the NVMe driver, containing parameters for various NVMe commands. The names suggest different command types and possibly different data transfer mechanisms (e.g., pass-through commands, I/O commands, and commands related to `io_uring`).
* **IOCTL Macros:** The `#define NVME_IOCTL_*` lines define constants used for ioctl calls. These macros encode the ioctl number, direction (read/write), and the associated data structure. The `_IO`, `_IOW`, and `_IOWR` macros are standard Linux kernel conventions.

**3. Addressing Each Part of the Request Systematically:**

* **功能 (Functions):**
    * Based on the structure definitions and IOCTL macros, the core function is to provide a way for user-space applications to interact with NVMe devices.
    *  Specific functionalities inferred from the structures and macros include:
        * Submitting I/O commands (`NVME_IOCTL_SUBMIT_IO`).
        * Sending pass-through commands (both 32-bit and 64-bit address versions) for more direct control (`NVME_IOCTL_ADMIN_CMD`, `NVME_IOCTL_IO_CMD`, `NVME_IOCTL_ADMIN64_CMD`, `NVME_IOCTL_IO64_CMD`, `NVME_IOCTL_IO64_CMD_VEC`).
        * Managing the NVMe subsystem (reset, rescan) (`NVME_IOCTL_RESET`, `NVME_IOCTL_SUBSYS_RESET`, `NVME_IOCTL_RESCAN`).
        * Utilizing `io_uring` for potentially more efficient I/O (`NVME_URING_CMD_*`).
* **与 Android 的关系 (Relationship with Android):**
    * Android uses NVMe for internal storage (e.g., flash memory).
    * This header provides the interface for Android's storage system (likely through higher-level APIs) to communicate with the underlying NVMe hardware.
    * Examples include file system operations, app data storage, and virtual memory management.
* **libc 函数功能实现 (libc Function Implementation):**
    * This header file *defines* data structures and constants. It doesn't *implement* libc functions. The actual implementation of the `ioctl` system call resides in the kernel.
    *  The user-space side involves calling the `ioctl` function with the defined constants and structures.
* **Dynamic Linker 功能 (Dynamic Linker Functionality):**
    * This header file is unlikely to be directly involved in dynamic linking. It defines kernel interfaces.
    * However, libraries that *use* these ioctls (e.g., a storage library in Android) would be linked dynamically.
    * The example SO layout and linking process is a conceptual illustration of how a user-space library might interact with the kernel interface.
* **逻辑推理 (Logical Inference):**
    * The example of submitting a read command demonstrates how the structures could be populated for a specific operation. It highlights the relationship between the structure members and the NVMe command parameters.
* **常见使用错误 (Common Usage Errors):**
    * The listed errors are typical when interacting with low-level APIs: incorrect structure population, invalid ioctl numbers, insufficient permissions, and device errors.
* **Android Framework/NDK 到达这里 (Android Framework/NDK path):**
    * The path traces the typical flow from high-level Android APIs to the kernel. It highlights the layers involved: Java framework, native code (NDK), and finally the system call to the kernel.
* **Frida Hook 示例 (Frida Hook Example):**
    * The Frida script provides a practical way to intercept and examine the `ioctl` calls related to NVMe, allowing developers to debug and understand the interaction with the driver.

**4. Refinement and Structuring the Answer:**

* Organize the answer according to the request's points.
* Use clear and concise language.
* Provide concrete examples where possible.
*  Distinguish between definition and implementation (important for the libc section).
* Clearly explain the assumed nature of the dynamic linking section, as the header itself doesn't directly involve it.
* Make the Frida example practical and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this header implements some helper functions. **Correction:** Realized it's a UAPI header, so it mainly *defines* the interface. The actual implementation is in the kernel and potentially in other Bionic libraries that *use* these definitions.
* **Initial thought:** How deeply to go into the NVMe protocol itself? **Correction:**  Focus on the information directly present in the header file and its implications for interacting with NVMe. Avoid detailed explanations of NVMe command sets, as that's beyond the scope of analyzing *this specific header file*.
* **Ensuring clarity on dynamic linking:**  Emphasize that the header itself isn't *part* of the dynamic linker but its definitions are *used* by dynamically linked libraries. The SO example helps illustrate this connection.

By following this structured thought process, addressing each part of the request, and performing necessary refinements, the detailed and informative answer can be generated.
这是一个定义了用于与 Linux 内核中的 NVMe (Non-Volatile Memory Express) 驱动程序进行交互的 ioctl 命令的头文件。它属于 Android 的 Bionic 库，这意味着 Android 系统本身以及运行在 Android 上的应用程序可以通过这些定义来控制和管理 NVMe 设备。

**功能列举:**

该文件定义了以下功能，允许用户空间程序与 NVMe 设备进行交互：

1. **定义 NVMe 操作相关的数据结构:**
   - `struct nvme_user_io`:  用于提交基本的 NVMe I/O 命令。
   - `struct nvme_passthru_cmd`: 用于发送原始的 NVMe 管理或 I/O 命令，提供更底层的控制。
   - `struct nvme_passthru_cmd64`: `nvme_passthru_cmd` 的 64 位版本，允许更大的内存地址。
   - `struct nvme_uring_cmd`: 用于通过 `io_uring` 接口提交 NVMe 命令，这是一种更高效的异步 I/O 机制。

2. **定义用于 ioctl 系统调用的宏:**
   - `NVME_IOCTL_ID`:  NVMe ioctl 的基本 ID。
   - `NVME_IOCTL_ADMIN_CMD`:  用于发送 NVMe 管理命令。
   - `NVME_IOCTL_SUBMIT_IO`: 用于提交 NVMe I/O 操作。
   - `NVME_IOCTL_IO_CMD`:  用于发送 NVMe I/O 命令。
   - `NVME_IOCTL_RESET`:  用于重置 NVMe 设备。
   - `NVME_IOCTL_SUBSYS_RESET`: 用于重置整个 NVMe 子系统。
   - `NVME_IOCTL_RESCAN`: 用于重新扫描 NVMe 设备。
   - `NVME_IOCTL_ADMIN64_CMD`: 用于发送 64 位地址的 NVMe 管理命令。
   - `NVME_IOCTL_IO64_CMD`:  用于发送 64 位地址的 NVMe I/O 命令。
   - `NVME_IOCTL_IO64_CMD_VEC`: 用于发送带有向量 I/O 的 64 位地址的 NVMe I/O 命令。
   - `NVME_URING_CMD_IO`:  通过 `io_uring` 提交 I/O 命令。
   - `NVME_URING_CMD_IO_VEC`: 通过 `io_uring` 提交向量 I/O 命令。
   - `NVME_URING_CMD_ADMIN`: 通过 `io_uring` 提交管理命令。
   - `NVME_URING_CMD_ADMIN_VEC`: 通过 `io_uring` 提交向量管理命令。

**与 Android 功能的关系及举例说明:**

这个文件对于 Android 的存储系统至关重要。现代 Android 设备通常使用 NVMe 固态硬盘 (SSD) 作为内部存储。Android 的文件系统、虚拟内存管理、以及应用程序的数据存储都依赖于与底层存储设备的交互。`nvme_ioctl.h` 定义的接口允许 Android 系统中的驱动程序或库与 NVMe 硬件进行通信，执行读写操作、管理设备状态等。

**举例说明:**

* 当 Android 应用程序需要读取或写入文件时，其操作最终会通过文件系统层层传递到存储驱动程序。如果底层的存储设备是 NVMe SSD，那么存储驱动程序可能会使用 `ioctl` 系统调用，并利用 `NVME_IOCTL_SUBMIT_IO` 或 `NVME_IOCTL_IO_CMD` 等宏以及相应的结构体来向 NVMe 设备发送读写命令。

* Android 的 OTA (Over-The-Air) 更新过程也可能涉及到直接与 NVMe 设备交互。例如，更新引导加载程序或系统镜像可能需要发送特定的 NVMe 管理命令，这可以通过 `NVME_IOCTL_ADMIN_CMD` 和相应的结构体来实现。

* 某些性能优化的场景，例如绕过标准文件系统缓存的直接 I/O 操作，也可能直接使用这些 ioctl 命令。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **并没有实现任何 libc 函数**。它只是 **定义了数据结构和常量**，用于与 Linux 内核的 NVMe 驱动程序进行交互。

用户空间的程序（例如 Android 的存储相关服务或某些 HAL 层）会使用标准的 libc 函数 `ioctl()` 来调用内核提供的功能。`ioctl()` 函数的签名如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

- `fd`: 是一个打开的文件描述符，通常是代表 NVMe 设备的文件节点（例如 `/dev/nvme0n1`）。
- `request`:  是 ioctl 命令的编号，就是这个头文件中定义的 `NVME_IOCTL_*` 宏。
- `...`:  是可选的参数，通常是指向与特定 ioctl 命令相关的数据结构的指针，例如 `struct nvme_user_io` 或 `struct nvme_passthru_cmd`。

**`ioctl()` 函数的实现位于 Linux 内核中。** 当用户空间程序调用 `ioctl()` 时，内核会根据文件描述符找到对应的设备驱动程序（在这里是 NVMe 驱动程序），然后根据 `request` 参数调用驱动程序中相应的 ioctl 处理函数。驱动程序会解析传递进来的数据结构，并执行与 NVMe 设备硬件相关的操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。它定义的是内核接口。然而，使用这些接口的共享库（例如 Android 的存储相关的本地库）会被动态链接。

**SO 布局样本 (假设一个名为 `libnvme_helper.so` 的库使用了这些 ioctl):**

```
libnvme_helper.so:
    .text         # 代码段
        # ... 调用 ioctl 函数的代码
    .rodata       # 只读数据段
        # ...
    .data         # 可读写数据段
        # ...
    .bss          # 未初始化数据段
        # ...
    .dynsym       # 动态符号表
        ioctl      # 指示需要链接 ioctl 函数
        # ... 其他符号
    .dynstr       # 动态字符串表
        ioctl
        # ... 其他字符串
    .plt          # 程序链接表 (Procedure Linkage Table)
        # ioctl 的 PLT 条目
    .got.plt      # 全局偏移表 (Global Offset Table)
        # ioctl 的 GOT 条目
```

**链接的处理过程:**

1. **编译时:** 当编译 `libnvme_helper.so` 时，如果代码中使用了 `ioctl` 函数，编译器会生成对 `ioctl` 的未定义引用。动态符号表 `.dynsym` 中会包含 `ioctl` 符号。

2. **链接时:** 链接器在创建 `libnvme_helper.so` 时，会标记 `ioctl` 为一个需要动态链接的外部符号。它会在 `.plt` 和 `.got.plt` 中为 `ioctl` 创建条目。

3. **加载时:** 当 Android 系统加载 `libnvme_helper.so` 时，dynamic linker (`linker64` 或 `linker`) 会解析 SO 文件的头部信息，包括动态段。

4. **符号解析:** Dynamic linker 会查找 `ioctl` 函数的定义。由于 `ioctl` 是一个 libc 函数，dynamic linker 会在已加载的 libc.so 中找到 `ioctl` 的地址。

5. **重定位:** Dynamic linker 会更新 `libnvme_helper.so` 的 `.got.plt` 中 `ioctl` 对应的条目，将其指向 libc.so 中 `ioctl` 函数的实际地址。

6. **调用:** 当 `libnvme_helper.so` 中的代码调用 `ioctl` 时，程序会跳转到 `.plt` 中 `ioctl` 对应的条目。PLT 条目会首先检查 GOT 表中的地址是否已解析。如果是，则直接跳转到 GOT 表中存储的 `ioctl` 地址。如果未解析，PLT 条目会调用 dynamic linker 来解析符号并更新 GOT 表，然后再跳转。

**逻辑推理 (假设输入与输出):**

假设一个程序想要读取 NVMe 设备 `/dev/nvme0n1` 上偏移量为 0 的 512 字节数据。

**假设输入:**

- 文件描述符 `fd`: 指向 `/dev/nvme0n1` 的文件描述符。
- `request`: `NVME_IOCTL_SUBMIT_IO`
- `argp`: 指向一个填充好的 `struct nvme_user_io` 结构体的指针，例如：

```c
struct nvme_user_io io_cmd;
memset(&io_cmd, 0, sizeof(io_cmd));
io_cmd.opcode = 0x02; // NVMe Read 命令
io_cmd.nblocks = 0;   // 读取 1 个 block (假设 block size 为 512 字节)
io_cmd.slba = 0;      // 起始逻辑块地址为 0
io_cmd.addr = (uintptr_t)buffer; // 指向用于存储读取数据的用户空间缓冲区
```

**假设输出:**

- 如果操作成功，`ioctl()` 返回 0。
- 用户空间缓冲区 `buffer` 中会包含从 NVMe 设备读取的 512 字节数据。
- 如果操作失败，`ioctl()` 返回 -1，并设置 `errno` 来指示错误类型（例如 `EACCES` 权限不足，`EIO` 输入/输出错误等）。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确初始化结构体:**  忘记将结构体中的某些字段初始化为正确的值，或者使用了未初始化的内存。这可能导致 NVMe 驱动程序无法正确解析命令。

   ```c
   struct nvme_user_io io_cmd; // 没有初始化就使用
   io_cmd.opcode = 0x02;
   // ... 其他字段未初始化 ...
   ioctl(fd, NVME_IOCTL_SUBMIT_IO, &io_cmd); // 可能导致不可预测的行为
   ```

2. **使用了错误的 ioctl 命令:**  为特定的操作使用了错误的 `NVME_IOCTL_*` 宏，导致内核无法正确处理请求。

3. **传递了错误的缓冲区地址或大小:**  `addr` 字段指向的缓冲区无效，或者缓冲区的大小不足以容纳读取的数据，可能导致崩溃或数据损坏。

4. **权限问题:** 用户进程可能没有足够的权限访问 NVMe 设备文件（例如 `/dev/nvme0n1`），导致 `ioctl()` 调用失败并返回 `EACCES`。

5. **设备状态错误:**  在 NVMe 设备处于错误状态时尝试执行操作，例如设备离线或发生内部错误，会导致 `ioctl()` 调用失败并返回 `EIO` 或其他相关的错误代码。

6. **竞态条件:** 在多线程或多进程环境中，如果没有适当的同步机制，多个线程或进程可能同时尝试访问 NVMe 设备，导致数据不一致或设备错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 和 NDK 访问 NVMe ioctl 通常会经历以下步骤：

1. **Java Framework 层:** Android Framework 中的高级 API（例如 `java.io.FileInputStream`, `java.io.FileOutputStream`, `android.os.storage.StorageManager` 等）处理文件和存储操作。

2. **Native 代码 (NDK):** Framework 层最终会调用 Native 代码（通常是 C/C++ 代码），这些代码通过 JNI (Java Native Interface) 与 Java 层交互。例如，`libbinder.so`、`libdiskfs.so` 等库可能涉及文件系统操作。

3. **系统调用:** Native 代码会使用 POSIX 标准的系统调用，例如 `open()`, `read()`, `write()`, `ioctl()` 等来与内核进行交互。对于 NVMe 设备，最终可能会调用 `ioctl()` 并使用 `nvme_ioctl.h` 中定义的宏。

4. **内核驱动程序:**  内核接收到 `ioctl()` 系统调用后，会根据文件描述符找到对应的 NVMe 驱动程序。驱动程序中的 ioctl 处理函数会解析传递的数据，并与 NVMe 硬件进行通信。

**Frida Hook 示例:**

可以使用 Frida 来 hook `ioctl()` 系统调用，并查看是否使用了与 NVMe 相关的 ioctl 命令。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

session = frida.attach("com.example.myapp") # 替换为你要监控的应用程序的包名

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function(args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    // 检查文件描述符是否可能与 NVMe 设备相关 (这是一个简化的假设)
    const pathBuf = Memory.allocUtf8String("/proc/self/fd/" + fd);
    const readlinkResult = Memory.alloc(256);
    const readlinkRet = syscall(39, pathBuf, readlinkResult, 255); // SYS_readlink

    if (readlinkRet.toInt32() > 0) {
      const targetPath = Memory.readCString(readlinkResult);
      if (targetPath.startsWith("/dev/nvme")) {
        this.isNvme = true;
        console.log("Detected ioctl on NVMe device:", targetPath);
        console.log("  File Descriptor:", fd);
        console.log("  Request:", request, " (0x" + request.toString(16) + ")");

        // 可以进一步解析 request 值来判断具体的 NVMe ioctl 命令
        if (request === 0x414e0041) { // NVME_IOCTL_ADMIN_CMD
            console.log("  NVME_IOCTL_ADMIN_CMD");
            // 可以进一步读取 args[2] 来解析 struct nvme_admin_cmd 的内容
        } else if (request === 0x414e0042) { // NVME_IOCTL_SUBMIT_IO
            console.log("  NVME_IOCTL_SUBMIT_IO");
            // 可以进一步读取 args[2] 来解析 struct nvme_user_io 的内容
        }
        // ... 添加其他 NVME_IOCTL_* 的判断
      }
    }
  },
  onLeave: function(retval) {
    if (this.isNvme) {
      console.log("  Return Value:", retval.toInt32());
      this.isNvme = false;
    }
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 示例:**

1. **`frida.attach("com.example.myapp")`**:  连接到目标 Android 应用程序。你需要将 `"com.example.myapp"` 替换为你想要监控的应用程序的包名。

2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`**:  Hook `ioctl()` 系统调用。`Module.findExportByName(null, "ioctl")` 会找到任何已加载的库中导出的 `ioctl` 函数（libc 中）。

3. **`onEnter: function(args)`**:  在 `ioctl()` 函数调用之前执行。
   - `args[0]` 是文件描述符。
   - `args[1]` 是 ioctl 请求码。
   - `args[2]` 是可选的参数指针。

4. **检查文件描述符**:  代码尝试通过读取 `/proc/self/fd/<fd>` 链接来判断文件描述符是否指向 NVMe 设备文件（以 `/dev/nvme` 开头）。这是一种简化的方法，可能不适用于所有情况。

5. **打印信息**: 如果检测到对 NVMe 设备的 ioctl 调用，会打印文件描述符、请求码（十六进制和十进制），并尝试根据请求码判断具体的 NVMe ioctl 命令。

6. **解析结构体 (可选)**:  在 `onEnter` 中，可以进一步读取 `args[2]` 指向的内存，并根据 `request` 的值将其解释为相应的 NVMe 结构体（例如 `struct nvme_user_io` 或 `struct nvme_passthru_cmd`）。这需要对结构体的布局有了解。

7. **`onLeave: function(retval)`**: 在 `ioctl()` 函数调用之后执行，打印返回值。

通过这个 Frida 脚本，你可以监控目标应用程序是否调用了与 NVMe 设备相关的 `ioctl()` 命令，并查看传递的参数，从而理解 Android Framework 或 NDK 是如何与 NVMe 驱动程序交互的。

请注意，hook 系统调用可能需要 root 权限或者在可调试的应用上进行。此外，内核的实现细节可能会因 Android 版本和设备而异。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/nvme_ioctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_NVME_IOCTL_H
#define _UAPI_LINUX_NVME_IOCTL_H
#include <linux/types.h>
struct nvme_user_io {
  __u8 opcode;
  __u8 flags;
  __u16 control;
  __u16 nblocks;
  __u16 rsvd;
  __u64 metadata;
  __u64 addr;
  __u64 slba;
  __u32 dsmgmt;
  __u32 reftag;
  __u16 apptag;
  __u16 appmask;
};
struct nvme_passthru_cmd {
  __u8 opcode;
  __u8 flags;
  __u16 rsvd1;
  __u32 nsid;
  __u32 cdw2;
  __u32 cdw3;
  __u64 metadata;
  __u64 addr;
  __u32 metadata_len;
  __u32 data_len;
  __u32 cdw10;
  __u32 cdw11;
  __u32 cdw12;
  __u32 cdw13;
  __u32 cdw14;
  __u32 cdw15;
  __u32 timeout_ms;
  __u32 result;
};
struct nvme_passthru_cmd64 {
  __u8 opcode;
  __u8 flags;
  __u16 rsvd1;
  __u32 nsid;
  __u32 cdw2;
  __u32 cdw3;
  __u64 metadata;
  __u64 addr;
  __u32 metadata_len;
  union {
    __u32 data_len;
    __u32 vec_cnt;
  };
  __u32 cdw10;
  __u32 cdw11;
  __u32 cdw12;
  __u32 cdw13;
  __u32 cdw14;
  __u32 cdw15;
  __u32 timeout_ms;
  __u32 rsvd2;
  __u64 result;
};
struct nvme_uring_cmd {
  __u8 opcode;
  __u8 flags;
  __u16 rsvd1;
  __u32 nsid;
  __u32 cdw2;
  __u32 cdw3;
  __u64 metadata;
  __u64 addr;
  __u32 metadata_len;
  __u32 data_len;
  __u32 cdw10;
  __u32 cdw11;
  __u32 cdw12;
  __u32 cdw13;
  __u32 cdw14;
  __u32 cdw15;
  __u32 timeout_ms;
  __u32 rsvd2;
};
#define nvme_admin_cmd nvme_passthru_cmd
#define NVME_IOCTL_ID _IO('N', 0x40)
#define NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct nvme_admin_cmd)
#define NVME_IOCTL_SUBMIT_IO _IOW('N', 0x42, struct nvme_user_io)
#define NVME_IOCTL_IO_CMD _IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_RESET _IO('N', 0x44)
#define NVME_IOCTL_SUBSYS_RESET _IO('N', 0x45)
#define NVME_IOCTL_RESCAN _IO('N', 0x46)
#define NVME_IOCTL_ADMIN64_CMD _IOWR('N', 0x47, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD _IOWR('N', 0x48, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD_VEC _IOWR('N', 0x49, struct nvme_passthru_cmd64)
#define NVME_URING_CMD_IO _IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC _IOWR('N', 0x81, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN _IOWR('N', 0x82, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN_VEC _IOWR('N', 0x83, struct nvme_uring_cmd)
#endif

"""

```