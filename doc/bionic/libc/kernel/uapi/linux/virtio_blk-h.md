Response:
Let's break down the thought process for answering the request about `virtio_blk.h`.

**1. Understanding the Core Request:**

The initial request asks for an explanation of the `virtio_blk.h` header file, specifically its functionalities, relation to Android, implementation details (especially libc and dynamic linker), common errors, and how Android uses it, along with a Frida hook example.

**2. Initial Analysis of the Header File:**

The first step is to read through the provided header file and identify the key elements:

* **Includes:**  `linux/types.h`, `linux/virtio_ids.h`, `linux/virtio_config.h`, `linux/virtio_types.h`. This immediately tells us it's part of the Linux kernel's UAPI (User-space API), specifically for the virtio block device driver.
* **Feature Flags (Macros starting with `VIRTIO_BLK_F_`):** These define optional features the virtio block device might support. Recognize that some have `_NO_LEGACY` guards, indicating evolution and deprecation.
* **Configuration Structure (`struct virtio_blk_config`):** This structure describes the capabilities and parameters of the virtual block device. Notice the use of `__virtioXX` types, hinting at specific sizes and endianness considerations for communication with the virtual device.
* **Request Types (Macros starting with `VIRTIO_BLK_T_`):** These represent the different commands that can be sent to the virtio block device (read, write, discard, flush, etc.). Again, the `_NO_LEGACY` guards are present.
* **Output Header (`struct virtio_blk_outhdr`):**  This structure seems to be part of the request sent to the device.
* **Zoned Block Device Structures (Macros and structs related to zones):**  Recognize the introduction of zoned block device concepts, with specific structures and request types.
* **Discard and Write Zeroes Structure (`struct virtio_blk_discard_write_zeroes`):** A specific structure for discard and write zeroes operations.
* **Legacy SCSI Header (`struct virtio_scsi_inhdr`):** Note the `_NO_LEGACY` guard. This indicates support for a SCSI-like interface in older versions.
* **Status Codes (Macros starting with `VIRTIO_BLK_S_`):**  These are the possible return status codes from the block device.

**3. Addressing the Request Points (Iterative Refinement):**

* **Functionality:**  Based on the identified elements, list the core functionalities:  defining features, configuring the block device, defining request types (read, write, discard, flush, etc.), and supporting zoned block devices.

* **Relationship to Android:** Connect `virtio_blk` to its role in virtualized environments within Android (emulators, virtual machines). Think about where Android uses virtualized storage. The connection to the HAL (Hardware Abstraction Layer) is crucial.

* **libc Function Implementation:** Realize that *this header file itself doesn't contain libc function implementations*. It's a header file defining *data structures and constants*. The *actual implementation* of interacting with the block device would be in the kernel driver and potentially in user-space libraries that use these definitions. Therefore, the answer should clarify this distinction and mention relevant system calls like `open`, `ioctl`, `read`, `write`, `close`, and `mmap`.

* **Dynamic Linker:**  Again, realize that *this header file doesn't directly involve the dynamic linker*. It's about device interaction. However, *libraries that use this header file* would be linked dynamically. Illustrate with a basic SO structure and the linking process, explaining how symbols are resolved. This demonstrates understanding of the broader Android ecosystem.

* **Logic Reasoning (Hypothetical Input/Output):**  Construct a simple scenario, like a read request, demonstrating how the structures defined in the header would be used. This requires making assumptions about the values involved.

* **Common Usage Errors:** Think about typical mistakes when interacting with block devices: incorrect usage of offsets and sizes, insufficient permissions, attempting unsupported operations, and improper handling of error codes.

* **Android Framework/NDK Path:**  Trace the path from the application level down to the kernel:  App -> Framework (StorageManager, MediaStore) -> Native code (NDK, potentially using direct file access or libraries) -> HAL (Vold) -> Kernel Driver (virtio_blk).

* **Frida Hook Example:**  Provide a practical example of hooking a relevant function (like `open` or `ioctl`) to observe the interaction with the virtual block device. Focus on what information can be intercepted and how it relates back to the `virtio_blk.h` definitions.

**4. Structuring the Answer:**

Organize the answer logically, following the points in the original request. Use clear headings and bullet points for readability.

**5. Refining and Adding Detail:**

Go back through the answer and add more specific details where needed. For example, when discussing the HAL, mention `vold`. When talking about system calls, list the relevant ones. Ensure the explanation of the dynamic linker is clear and concise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "I need to explain how specific libc functions are implemented *within this header file*."
* **Correction:** "Wait, this is just a header file. It defines structures. The *implementation* is elsewhere. I need to focus on how these structures are used by libc and the kernel."

* **Initial thought:** "The dynamic linker is directly involved in this header file."
* **Correction:** "Not directly. But libraries that use these definitions will be linked dynamically. I should explain the general dynamic linking process in Android and how it relates to libraries that *might* use this header."

By following this structured approach, analyzing the header file, and iteratively refining the answer, we can arrive at a comprehensive and accurate explanation that addresses all aspects of the request.
这是一个关于 VirtIO 块设备驱动程序的 Linux 内核 UAPI 头文件。让我详细解释它的功能以及与 Android 的关系。

**文件功能：**

`virtio_blk.h` 文件定义了用户空间程序与虚拟机中的虚拟块设备进行交互所需的常量、数据结构和接口规范。它不包含任何实际的 C 代码实现，而是作为一种“契约”，规定了用户空间程序和内核驱动程序之间如何进行数据交换和命令传递。

主要功能可以概括为：

1. **定义 VirtIO 块设备的功能标志 (Feature Flags):**  例如 `VIRTIO_BLK_F_SIZE_MAX`、`VIRTIO_BLK_F_SEG_MAX` 等，这些标志表示虚拟块设备所支持的特性，例如最大容量、最大段数、几何信息、是否只读、块大小、拓扑结构、多队列、丢弃 (discard) 操作、写零 (write zeroes) 操作、安全擦除 (secure erase) 以及 Zoned Block Devices (ZBD) 支持等。
2. **定义 VirtIO 块设备的配置结构体 (`virtio_blk_config`):**  这个结构体描述了虚拟块设备的配置信息，包括容量、最大尺寸、最大段数、几何信息（柱面、磁头、扇区）、块大小、物理块指数、对齐偏移、最小/最佳 I/O 大小、写缓存使能、队列数量以及与丢弃、写零和安全擦除相关的参数，以及 ZBD 的特性。
3. **定义 VirtIO 块设备的请求类型 (Request Types):** 例如 `VIRTIO_BLK_T_IN` (读)、`VIRTIO_BLK_T_OUT` (写)、`VIRTIO_BLK_T_FLUSH` (刷新缓存)、`VIRTIO_BLK_T_DISCARD` (丢弃)、`VIRTIO_BLK_T_WRITE_ZEROES` (写零) 等，以及 ZBD 相关的请求类型。这些定义了用户空间可以向虚拟块设备发送的各种操作命令。
4. **定义请求头结构体 (`virtio_blk_outhdr`):**  这是用户空间程序向虚拟块设备发送请求时需要填充的头部信息，包含请求类型、I/O 优先级和扇区号。
5. **定义 Zoned Block Devices (ZBD) 相关的结构体和常量:**  例如 `virtio_blk_zone_descriptor` (zone 描述符)、`virtio_blk_zone_report` (zone 报告)、以及 zone 的类型和状态常量。ZBD 是一种新型的块设备模型，用于提高高密度存储设备的性能和寿命。
6. **定义丢弃和写零操作的结构体 (`virtio_blk_discard_write_zeroes`):**  包含了扇区号、扇区数量和标志位。
7. **定义 VirtIO 块设备操作的状态码 (Status Codes):** 例如 `VIRTIO_BLK_S_OK` (成功)、`VIRTIO_BLK_S_IOERR` (I/O 错误)、`VIRTIO_BLK_S_UNSUPP` (不支持的操作) 等，用于指示操作的执行结果。

**与 Android 功能的关系及举例说明：**

`virtio_blk.h` 在 Android 中主要用于支持虚拟机环境，例如 Android 模拟器 (如 Android Studio 提供的模拟器) 和运行在云端的 Android 虚拟机 (如 Android in the Cloud)。

* **Android 模拟器:** 当你在 Android Studio 中运行模拟器时，模拟器内部的 Android 系统通常运行在一个虚拟机中。这个虚拟机需要一个虚拟的磁盘来存储系统文件、应用数据等。`virtio_blk` 就定义了 Android 虚拟机与宿主机提供的虚拟磁盘之间的交互方式。宿主机上的 QEMU 或其他虚拟化软件会模拟一个 VirtIO 块设备，而虚拟机内部的 Android 内核会使用遵循 `virtio_blk.h` 定义的驱动程序来访问这个虚拟磁盘。
* **Android in the Cloud:**  在云环境中运行 Android 实例时，存储通常也是虚拟化的。`virtio_blk` 提供了标准的接口，使得不同的云平台可以使用 VirtIO 来提供高性能的块存储服务给 Android 虚拟机。

**举例说明：**

假设一个 Android 应用需要向存储写入数据。在虚拟机环境中，这个过程可能涉及以下步骤：

1. 应用调用 Android Framework 提供的存储 API (例如 `FileOutputStream`)。
2. Framework 层将请求传递到 Native 层 (通过 NDK)。
3. Native 层可能会调用底层的 POSIX 文件操作函数 (如 `write`)。
4. 如果目标文件位于虚拟磁盘上，内核的 VFS (Virtual File System) 会将写操作路由到负责处理虚拟磁盘的驱动程序，即 VirtIO 块设备驱动程序。
5. VirtIO 块设备驱动程序会根据 `virtio_blk.h` 中定义的结构体和常量，构建一个 VirtIO 请求，包含 `virtio_blk_outhdr` 头部信息 (指定 `VIRTIO_BLK_T_OUT` 类型和要写入的扇区)，以及要写入的数据。
6. 这个 VirtIO 请求会被发送到虚拟机监控器 (Hypervisor)，由 Hypervisor 转发给宿主机上模拟的 VirtIO 块设备。
7. 宿主机处理请求，将数据写入到实际的磁盘文件或存储设备中。
8. 宿主机将操作结果返回给虚拟机，最终传递回应用。

**详细解释每一个 libc 函数的功能是如何实现的:**

**关键点：`virtio_blk.h` 本身** **不是 libc 函数的实现代码。** 它是一个头文件，定义了数据结构和常量，供内核驱动程序和用户空间程序使用。

libc (bionic 在 Android 中的实现) 提供了与文件系统和块设备交互的函数，例如：

* **`open()`:**  用于打开文件或块设备。在虚拟机中，打开虚拟磁盘设备文件 (通常在 `/dev/block` 下) 时，会涉及到与内核 VirtIO 块设备驱动程序的交互。
* **`read()` 和 `write()`:** 用于从文件或块设备读取和写入数据。当操作目标是虚拟磁盘时，这些函数最终会通过系统调用进入内核，并由 VirtIO 块设备驱动程序处理。驱动程序会根据 `virtio_blk.h` 中定义的结构体和请求类型与虚拟硬件进行通信。
* **`ioctl()`:**  用于执行设备特定的控制操作。尽管 `virtio_blk.h` 没有直接定义 `ioctl` 命令，但可能存在其他相关的 `ioctl` 命令用于配置或查询 VirtIO 块设备的状态。
* **`close()`:**  用于关闭文件或块设备。

**libc 函数的实现细节非常复杂，涉及到文件系统的管理、缓存机制、I/O 调度等。**  对于 VirtIO 块设备，libc 函数的实现最终会调用内核提供的系统调用，例如 `read` 和 `write` 系统调用，这些系统调用会将请求传递给相应的设备驱动程序 (在这里是 VirtIO 块设备驱动程序)。驱动程序会使用 `virtio_blk.h` 中定义的结构体来构造与虚拟硬件的交互。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`virtio_blk.h` 本身不直接涉及动态链接器。它是一个内核头文件，用于定义内核与用户空间之间的接口。然而，用户空间中与 VirtIO 块设备交互的库 (如果存在) 可能会通过动态链接器加载。

**SO 布局样本：**

假设有一个名为 `libvirtio_blk_client.so` 的共享库，它封装了与 VirtIO 块设备交互的功能。其布局可能如下：

```
libvirtio_blk_client.so:
    .interp         # 指向动态链接器的路径 (例如 /system/bin/linker64)
    .note.android.ident
    .dynsym         # 动态符号表
    .dynstr         # 动态字符串表
    .hash           # 符号哈希表
    .gnu.version    # 版本信息
    .gnu.version_r  # 版本需求信息
    .rela.dyn       # 重定位表
    .rela.plt       # PLT 重定位表
    .plt            # 程序链接表 (Procedure Linkage Table)
    .text           # 代码段 (包含使用 virtio_blk.h 中定义的结构体的函数)
    .rodata         # 只读数据段
    .data           # 数据段
    .bss            # 未初始化数据段
```

**链接的处理过程：**

1. **加载时：** 当一个应用 (或另一个 SO) 尝试使用 `libvirtio_blk_client.so` 中的函数时，Android 的动态链接器 (linker) 会负责加载这个 SO 到进程的内存空间。
2. **符号解析：** 动态链接器会解析 `libvirtio_blk_client.so` 的依赖项，并加载它们。它还会解析 `libvirtio_blk_client.so` 中引用的外部符号，例如 libc 中的函数 (如 `open`, `read`, `write`)。
3. **重定位：** 动态链接器会根据重定位表 (`.rela.dyn` 和 `.rela.plt`) 修改代码和数据中的地址，以指向正确的内存位置。对于函数调用，会使用 PLT (`.plt`) 来实现延迟绑定，即在第一次调用函数时才解析其地址。
4. **链接完成：** 加载、解析和重定位完成后，`libvirtio_blk_client.so` 就可以被使用了。

**使用 `virtio_blk.h` 的库在链接时需要找到内核提供的头文件。**  这通常通过编译器的 include 路径配置来完成。最终链接的二进制文件 (例如应用程序) 不会直接包含 `virtio_blk.h` 的内容，而是包含根据这些定义生成的代码。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要读取虚拟磁盘的第 100 个扇区 (假设扇区大小为 512 字节)。

**假设输入：**

* 请求类型: `VIRTIO_BLK_T_IN` (读取)
* 扇区号: 100
* 读取长度: 1 个扇区 (512 字节)

**逻辑推理过程 (在内核 VirtIO 块设备驱动程序中):**

1. 驱动程序接收到用户空间的读取请求，目标扇区号为 100，长度为 512 字节。
2. 驱动程序会构建一个 VirtIO 请求描述符，其中包含：
   * 一个或多个用于描述数据缓冲区的 Scatter-Gather List (SGL)。
   * 一个命令描述符，包含 `virtio_blk_outhdr` 结构体，设置 `type` 为 `VIRTIO_BLK_T_IN`，`sector` 为 100。
3. 驱动程序将 VirtIO 请求提交给虚拟化层 (例如 KVM)。
4. 虚拟化层通知宿主机上的虚拟设备。
5. 宿主机上的虚拟块设备读取实际存储的相应位置的数据。
6. 宿主机将读取的数据通过 VirtIO 机制返回给虚拟机。
7. 驱动程序接收到数据，并将数据复制到用户空间提供的缓冲区。

**假设输出：**

* 用户空间缓冲区中包含虚拟磁盘第 100 个扇区的 512 字节数据。
* 操作状态为 `VIRTIO_BLK_S_OK` (假设操作成功)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的请求类型:** 用户空间程序发送了错误的 `type` 值，例如将读取请求误设为写入请求。这会导致内核驱动程序执行错误的操作。
2. **无效的扇区号:**  请求读取或写入的扇区号超出了虚拟磁盘的容量范围。内核驱动程序会返回错误状态，例如 `VIRTIO_BLK_S_IOERR`.
3. **缓冲区大小不匹配:** 用户空间提供的读取缓冲区大小不足以容纳请求的数据量，或者写入的数据量超过了缓冲区大小。这可能导致数据截断或缓冲区溢出。
4. **未处理错误状态:** 用户空间程序在执行 VirtIO 操作后，没有检查内核驱动程序返回的状态码。如果操作失败，程序可能不知道并继续执行，导致逻辑错误。
5. **对只读设备进行写入:**  如果虚拟块设备的 `VIRTIO_BLK_F_RO` 特性被设置，用户空间程序尝试写入数据将会失败。
6. **不正确的 ZBD 操作:** 对于 Zoned Block Devices，必须按照 ZBD 的规则进行操作，例如只能顺序写入到一个打开的 zone。不遵守这些规则会导致错误，例如 `VIRTIO_BLK_S_ZONE_INVALID_CMD` 或 `VIRTIO_BLK_S_ZONE_UNALIGNED_WP`.

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **应用层 (Java/Kotlin):**  Android 应用通过 Framework 提供的 API 与存储交互，例如 `java.io.FileInputStream`, `java.io.FileOutputStream`, `android.provider.MediaStore` 等。

2. **Framework 层 (Java):**  Framework 层处理应用请求，并将其转换为底层的操作。例如，`FileOutputStream` 会调用 Native 方法。

3. **Native 层 (C/C++, NDK):**  Framework 层会通过 JNI (Java Native Interface) 调用 Native 代码。在 Native 代码中，可能会使用 POSIX 标准的 I/O 函数 (如 `open`, `read`, `write`) 来操作文件或块设备。

4. **系统调用 (Kernel Interface):**  Native 代码调用的 POSIX I/O 函数会触发系统调用，进入 Linux 内核。例如，`write()` 系统调用。

5. **VFS (Virtual File System):**  内核的 VFS 子系统接收到系统调用请求，并根据文件路径找到对应的文件系统驱动程序。

6. **块设备层 (Block Device Layer):**  如果目标是虚拟磁盘，VFS 会将请求传递给块设备层。

7. **VirtIO 块设备驱动程序:**  块设备层将请求传递给负责处理 VirtIO 块设备的驱动程序。这个驱动程序会使用 `virtio_blk.h` 中定义的结构体和常量来构建 VirtIO 请求，并与虚拟化层进行通信。

**Frida Hook 示例:**

可以使用 Frida hook Native 层的 `open` 或 `write` 函数，来观察与虚拟磁盘的交互。

```javascript
// hook write 系统调用，观察写入虚拟磁盘的操作
Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const buf = args[1];
    const count = args[2].toInt32();

    // 检查文件描述符是否指向虚拟磁盘设备文件 (可能需要根据实际情况判断)
    const path = readlink("/proc/self/fd/" + fd);
    if (path && path.startsWith("/dev/block/vda")) {
      console.log("write() called on virtual disk:", path);
      console.log("  File Descriptor:", fd);
      console.log("  Buffer:", buf);
      console.log("  Count:", count);

      // 可以进一步读取缓冲区内容
      // console.log("  Data:", hexdump(buf, { length: Math.min(count, 64) }));
    }
  },
  onLeave: function (retval) {
    // console.log("write() returned:", retval);
  },
});

// 辅助函数，用于读取符号链接的目标
function readlink(path) {
  try {
    const target = Socket.readLink(path);
    return target;
  } catch (e) {
    return null;
  }
}
```

**解释 Frida Hook 示例：**

* `Interceptor.attach(Module.findExportByName(null, "write"), ...)`: 这行代码使用 Frida 的 `Interceptor` API hook 了名为 "write" 的函数。`Module.findExportByName(null, "write")` 会在所有已加载的模块中查找 "write" 函数的地址，通常对应的是 `libc.so` 中的 `write` 系统调用封装函数。
* `onEnter: function (args)`:  当 `write` 函数被调用时，`onEnter` 函数会被执行。`args` 数组包含了传递给 `write` 函数的参数：文件描述符 (`fd`)、数据缓冲区指针 (`buf`) 和写入字节数 (`count`).
* `readlink("/proc/self/fd/" + fd)`:  这个部分尝试读取文件描述符对应的文件路径。在 Linux 中，`/proc/self/fd/` 目录下包含了当前进程打开的文件描述符的符号链接。
* `path.startsWith("/dev/block/vda")`:  这是一个简单的判断，用于确定文件描述符是否指向虚拟磁盘设备文件。实际的设备文件名可能不同，需要根据具体情况调整。
* `console.log(...)`:  打印 `write` 调用的相关信息，例如文件描述符、缓冲区指针和写入字节数。
* `hexdump(buf, ...)`:  可以使用 Frida 的 `hexdump` 函数来查看要写入的数据内容 (这里被注释掉了，可以取消注释来查看数据)。

通过运行这个 Frida 脚本，你可以在 Android 虚拟机中监控对虚拟磁盘的 `write` 操作，观察哪些进程、哪些文件描述符正在进行写入，以及写入的数据内容。你可以类似地 hook `open` 函数来查看哪些设备文件被打开。

请注意，调试系统底层操作可能需要 root 权限或在模拟器环境中进行。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_blk.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_VIRTIO_BLK_H
#define _LINUX_VIRTIO_BLK_H
#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#define VIRTIO_BLK_F_SIZE_MAX 1
#define VIRTIO_BLK_F_SEG_MAX 2
#define VIRTIO_BLK_F_GEOMETRY 4
#define VIRTIO_BLK_F_RO 5
#define VIRTIO_BLK_F_BLK_SIZE 6
#define VIRTIO_BLK_F_TOPOLOGY 10
#define VIRTIO_BLK_F_MQ 12
#define VIRTIO_BLK_F_DISCARD 13
#define VIRTIO_BLK_F_WRITE_ZEROES 14
#define VIRTIO_BLK_F_SECURE_ERASE 16
#define VIRTIO_BLK_F_ZONED 17
#ifndef VIRTIO_BLK_NO_LEGACY
#define VIRTIO_BLK_F_BARRIER 0
#define VIRTIO_BLK_F_SCSI 7
#define VIRTIO_BLK_F_FLUSH 9
#define VIRTIO_BLK_F_CONFIG_WCE 11
#define VIRTIO_BLK_F_WCE VIRTIO_BLK_F_FLUSH
#endif
#define VIRTIO_BLK_ID_BYTES 20
struct virtio_blk_config {
  __virtio64 capacity;
  __virtio32 size_max;
  __virtio32 seg_max;
  struct virtio_blk_geometry {
    __virtio16 cylinders;
    __u8 heads;
    __u8 sectors;
  } geometry;
  __virtio32 blk_size;
  __u8 physical_block_exp;
  __u8 alignment_offset;
  __virtio16 min_io_size;
  __virtio32 opt_io_size;
  __u8 wce;
  __u8 unused;
  __virtio16 num_queues;
  __virtio32 max_discard_sectors;
  __virtio32 max_discard_seg;
  __virtio32 discard_sector_alignment;
  __virtio32 max_write_zeroes_sectors;
  __virtio32 max_write_zeroes_seg;
  __u8 write_zeroes_may_unmap;
  __u8 unused1[3];
  __virtio32 max_secure_erase_sectors;
  __virtio32 max_secure_erase_seg;
  __virtio32 secure_erase_sector_alignment;
  struct virtio_blk_zoned_characteristics {
    __virtio32 zone_sectors;
    __virtio32 max_open_zones;
    __virtio32 max_active_zones;
    __virtio32 max_append_sectors;
    __virtio32 write_granularity;
    __u8 model;
    __u8 unused2[3];
  } zoned;
} __attribute__((packed));
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1
#ifndef VIRTIO_BLK_NO_LEGACY
#define VIRTIO_BLK_T_SCSI_CMD 2
#endif
#define VIRTIO_BLK_T_FLUSH 4
#define VIRTIO_BLK_T_GET_ID 8
#define VIRTIO_BLK_T_DISCARD 11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
#define VIRTIO_BLK_T_SECURE_ERASE 14
#define VIRTIO_BLK_T_ZONE_APPEND 15
#define VIRTIO_BLK_T_ZONE_REPORT 16
#define VIRTIO_BLK_T_ZONE_OPEN 18
#define VIRTIO_BLK_T_ZONE_CLOSE 20
#define VIRTIO_BLK_T_ZONE_FINISH 22
#define VIRTIO_BLK_T_ZONE_RESET 24
#define VIRTIO_BLK_T_ZONE_RESET_ALL 26
#ifndef VIRTIO_BLK_NO_LEGACY
#define VIRTIO_BLK_T_BARRIER 0x80000000
#endif
struct virtio_blk_outhdr {
  __virtio32 type;
  __virtio32 ioprio;
  __virtio64 sector;
};
#define VIRTIO_BLK_Z_NONE 0
#define VIRTIO_BLK_Z_HM 1
#define VIRTIO_BLK_Z_HA 2
struct virtio_blk_zone_descriptor {
  __virtio64 z_cap;
  __virtio64 z_start;
  __virtio64 z_wp;
  __u8 z_type;
  __u8 z_state;
  __u8 reserved[38];
};
struct virtio_blk_zone_report {
  __virtio64 nr_zones;
  __u8 reserved[56];
  struct virtio_blk_zone_descriptor zones[];
};
#define VIRTIO_BLK_ZT_CONV 1
#define VIRTIO_BLK_ZT_SWR 2
#define VIRTIO_BLK_ZT_SWP 3
#define VIRTIO_BLK_ZS_NOT_WP 0
#define VIRTIO_BLK_ZS_EMPTY 1
#define VIRTIO_BLK_ZS_IOPEN 2
#define VIRTIO_BLK_ZS_EOPEN 3
#define VIRTIO_BLK_ZS_CLOSED 4
#define VIRTIO_BLK_ZS_RDONLY 13
#define VIRTIO_BLK_ZS_FULL 14
#define VIRTIO_BLK_ZS_OFFLINE 15
#define VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP 0x00000001
struct virtio_blk_discard_write_zeroes {
  __le64 sector;
  __le32 num_sectors;
  __le32 flags;
};
#ifndef VIRTIO_BLK_NO_LEGACY
struct virtio_scsi_inhdr {
  __virtio32 errors;
  __virtio32 data_len;
  __virtio32 sense_len;
  __virtio32 residual;
};
#endif
#define VIRTIO_BLK_S_OK 0
#define VIRTIO_BLK_S_IOERR 1
#define VIRTIO_BLK_S_UNSUPP 2
#define VIRTIO_BLK_S_ZONE_INVALID_CMD 3
#define VIRTIO_BLK_S_ZONE_UNALIGNED_WP 4
#define VIRTIO_BLK_S_ZONE_OPEN_RESOURCE 5
#define VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE 6
#endif
```