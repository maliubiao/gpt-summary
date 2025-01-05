Response:
Let's break down the thought process for analyzing this C header file and generating the comprehensive answer.

**1. Initial Understanding of the Request:**

The user provided a C header file and asked for a detailed explanation of its functionality, its relationship to Android, explanations of libc functions, dynamic linker aspects, potential errors, and how Android framework/NDK interacts with it, including a Frida hook example. The key here is "detailed" and covering various aspects.

**2. High-Level Overview of the Header File:**

My first step was to recognize the purpose of the header file: it defines data structures and constants related to SCSI generic (sg) device interaction within the Linux kernel. The `bionic/libc/kernel/android/scsi/scsi/sg.handroid` path immediately tells me this is part of Android's low-level system interface.

**3. Identifying Key Structures and Constants:**

I started going through the code, identifying the core components:

* **`sg_iovec`:**  Represents a scatter/gather I/O vector (base address and length).
* **`sg_io_hdr`:** The central structure for issuing SCSI commands. It contains pointers to command data, transfer data, sense data, and various control flags and status fields.
* **Macros defining directions (`SG_DXFER_NONE`, `SG_DXFER_TO_DEV`, etc.):**  Enumerate how data is transferred.
* **Flags (`SG_FLAG_DIRECT_IO`, `SG_FLAG_MMAP_IO`, etc.):** Control the behavior of the I/O operation.
* **Status codes (`GOOD`, `CHECK_CONDITION`, etc.):** Indicate the result of the SCSI command.
* **`sg_scsi_id`:**  Identifies a specific SCSI device.
* **`sg_req_info`:**  Information about a request.
* **IOCTLs (e.g., `SG_IO`, `SG_GET_VERSION_NUM`):**  Control and query the sg driver.
* **Constants (`SG_SCATTER_SZ`, `SG_DEFAULT_TIMEOUT`, etc.):** Default values and limits.

**4. Categorizing Functionality:**

With the key elements identified, I started grouping them by their purpose:

* **Data Transfer:** `sg_iovec`, `sg_io_hdr`'s `dxferp`, `dxfer_len`, and direction macros.
* **Command Execution:** `sg_io_hdr`'s `cmdp`, `cmd_len`, `SG_IO` ioctl.
* **Status Reporting:** `sg_io_hdr`'s status fields, `sbp`, status code macros.
* **Device Identification:** `sg_scsi_id`.
* **Driver Control:**  Various `SG_SET_*` and `SG_GET_*` ioctls.
* **Memory Management (Implicit):** `SG_FLAG_DIRECT_IO`, `SG_FLAG_MMAP_IO`.

**5. Connecting to Android Functionality:**

This was a crucial step. I considered where SCSI devices are used in Android:

* **Storage:**  External SD cards, internal flash memory (sometimes accessed via a SCSI-like interface at a lower level).
* **Peripherals:**  Less common for direct SCSI interaction at the application level, but the kernel uses it for various hardware.

The key realization is that while applications don't directly use these structures, the *Android framework* and *hardware abstraction layers (HALs)* do. The `ioctl` system call is the bridge.

**6. Explaining Libc Functions:**

The header file *defines* structures and constants, but it doesn't *implement* libc functions. The libc functions involved are primarily related to system calls:

* **`ioctl()`:** The main system call used with sg devices. I explained its purpose and how it's used with the defined ioctls.
* **Memory management (`malloc`, `free`):** While not directly in the header, they are necessary for allocating memory for the structures.
* **File I/O (`open`, `close`, `read`, `write`):**  The sg device is accessed as a file.

**7. Addressing Dynamic Linker Aspects:**

This header file itself doesn't directly involve the dynamic linker. However, the *sg driver* is a kernel module, and *user-space libraries* that interact with it are dynamically linked. I provided a simplified example of how a library using these structures might be laid out in memory and how the linker resolves symbols.

**8. Considering Potential Errors:**

I thought about common mistakes developers might make:

* **Incorrect `ioctl` usage:** Wrong ioctl number, incorrect data structure size.
* **Buffer overflows:**  Not allocating enough space for data transfer or sense information.
* **Incorrect flags:** Using incompatible flag combinations.
* **Timeout issues:** Not handling command timeouts properly.

**9. Tracing the Android Framework/NDK Path:**

This required thinking about the layers involved:

* **Application:** Wants to access storage (e.g., read a file on an SD card).
* **Framework (Java):** Uses APIs like `StorageManager`, `MediaScanner`.
* **Native code (C++/NDK):**  Underlying implementation of framework components or direct access via NDK APIs (less common for direct sg).
* **HAL:**  Hardware Abstraction Layer for storage devices.
* **Kernel driver (sg):** The code defined in the header.

The path involves several layers of abstraction. I focused on the `ioctl` system call as the critical point where the user-space interacts with the kernel driver.

**10. Creating a Frida Hook Example:**

The goal was to demonstrate intercepting the `ioctl` call related to `SG_IO`. I focused on:

* **Targeting the `ioctl` function.**
* **Filtering for the `SG_IO` ioctl number.**
* **Accessing and printing the `sg_io_hdr` structure to show the command being sent.**

**11. Structuring the Answer:**

I organized the information logically, using headings and bullet points for clarity. I addressed each part of the user's request systematically.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe applications directly use this. **Correction:**  Realized it's mostly framework/HAL level.
* **Focusing too much on libc *implementation*:** **Correction:** Shifted focus to *how* libc functions are used in conjunction with these structures (system calls).
* **Overcomplicating the dynamic linker example:** **Correction:** Simplified it to illustrate the basic concept.
* **Not enough emphasis on `ioctl`:** **Correction:** Highlighted its central role.

By following this thought process, breaking down the problem, and iteratively refining my understanding, I was able to generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这个头文件 `bionic/libc/kernel/android/scsi/scsi/sg.handroid` 定义了与 SCSI 通用 (SCSI generic, sg) 设备交互的内核接口。它主要用于用户空间程序直接与 SCSI 设备进行通信，发送 SCSI 命令并接收响应。由于它位于 `bionic/libc/kernel` 路径下，这意味着它是 Android C 库 (bionic) 中对内核接口的定义，供用户空间程序通过系统调用访问。

**功能列举:**

1. **定义 SCSI 通用接口的数据结构:**  它定义了 `sg_iovec` 和 `sg_io_hdr` 结构体，用于描述 I/O 操作和 SCSI 命令。
2. **定义 I/O 方向常量:**  例如 `SG_DXFER_NONE`, `SG_DXFER_TO_DEV`, `SG_DXFER_FROM_DEV` 等，用于指定数据传输的方向。
3. **定义操作标志:**  例如 `SG_FLAG_DIRECT_IO`, `SG_FLAG_MMAP_IO`，用于控制 I/O 操作的行为。
4. **定义状态码:**  例如 `GOOD`, `CHECK_CONDITION`, `BUSY` 等，用于指示 SCSI 命令执行的结果。
5. **定义 SCSI 设备标识结构:** `sg_scsi_id` 用于标识一个特定的 SCSI 设备。
6. **定义请求信息结构:** `sg_req_info` 用于存储关于 SCSI 请求的信息。
7. **定义 ioctl 命令常量:**  例如 `SG_IO`, `SG_GET_VERSION_NUM` 等，这些常量用于通过 `ioctl` 系统调用与 SCSI 通用驱动程序进行交互。
8. **定义其他常量:**  例如超时时间、缓冲区大小等。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 系统与 SCSI 存储设备（例如 SD 卡、U 盘，甚至可能是内部存储在较低层）的交互。虽然应用开发者通常不会直接使用这些结构体和 ioctl 命令，但 Android 框架的底层组件和硬件抽象层 (HAL) 会使用它们来执行存储相关的操作。

**举例说明：**

* **访问外部存储（SD 卡、U 盘）：** 当 Android 系统挂载一个外部存储设备时，底层的存储服务可能需要发送 SCSI 命令来查询设备信息、执行读写操作等。`sg_io_hdr` 结构体会被用来构造这些 SCSI 命令，并通过 `SG_IO` ioctl 发送给内核中的 SCSI 通用驱动。
* **与某些类型的硬件进行交互:**  某些 Android 设备可能会通过 SCSI 接口与特定的硬件组件通信。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **没有实现任何 libc 函数**。它只是定义了数据结构和常量。用户空间程序会使用 libc 提供的函数（如 `ioctl`）来与内核交互，而这些结构体和常量会被传递给这些函数。

**涉及 dynamic linker 的功能，给出对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker**。它只是内核接口的定义。然而，当用户空间程序（例如一个 native library）需要使用这个接口时，它需要包含这个头文件，并且可能会链接到提供 `ioctl` 等系统调用封装的 libc 库。

**so 布局样本（假设一个 native library 使用了 SCSI 通用接口）：**

```
libmyscsi.so:
    ...
    .text:
        my_scsi_function:
            ; ... 构建 sg_io_hdr 结构体 ...
            ; ... 调用 ioctl ...
            bl  __ioctl  ; 假设 __ioctl 是 libc 中 ioctl 的符号
            ; ... 处理 ioctl 返回结果 ...
    ...
    .dynsym:
        __ioctl  ; 需要动态链接器解析的符号
    ...
```

**链接的处理过程：**

1. 当 `libmyscsi.so` 被加载到进程空间时，动态链接器（在 Android 中通常是 `linker64` 或 `linker`) 会扫描其 `.dynsym` 段，找到需要解析的外部符号，例如 `__ioctl`。
2. 动态链接器会查找依赖的共享库（通常由 `DT_NEEDED` 标签指定），例如 `libc.so`。
3. 在 `libc.so` 的符号表（`.symtab` 或 `.dynsym`) 中查找 `ioctl` 符号的定义。
4. 找到 `ioctl` 的地址后，动态链接器会将 `libmyscsi.so` 中 `__ioctl` 的引用重定位到 `libc.so` 中 `ioctl` 的实际地址。
5. 之后，当 `libmyscsi.so` 调用 `my_scsi_function` 并执行到 `bl __ioctl` 指令时，程序会跳转到 `libc.so` 中 `ioctl` 函数的实际代码执行。

**假设输入与输出 (对于使用该头文件的代码):**

**假设输入 (对于 `SG_IO` ioctl):**

* `fd`: 打开的 `/dev/sgX` 设备的 фай描述符。
* `request`:  `SG_IO` ioctl 命令。
* `argp`: 指向 `sg_io_hdr_t` 结构体的指针，该结构体包含了要执行的 SCSI 命令、数据传输缓冲区、预期的数据长度等信息。

   例如，`sg_io_hdr_t` 可能包含：
   * `interface_id = 'S'`
   * `dxfer_direction = SG_DXFER_FROM_DEV` (从设备读取数据)
   * `cmd_len = 6` (SCSI 命令长度为 6 字节)
   * `cmdp`: 指向包含 SCSI 命令的缓冲区（例如，用于读取数据的命令）
   * `dxfer_len`:  预期读取的数据长度
   * `dxferp`: 指向用于接收数据的缓冲区

**假设输出 (对于 `SG_IO` ioctl):**

* `ioctl` 系统调用成功返回 0，失败返回 -1 并设置 `errno`。
* 如果成功，`sg_io_hdr_t` 结构体会包含操作的结果信息：
    * `status`: SCSI 状态字节 (例如 `GOOD`, `CHECK_CONDITION`)
    * `masked_status`: 屏蔽后的状态
    * `msg_status`: 消息状态
    * `sb_len_wr`: 写入 sense buffer 的长度
    * `sbp`: 指向 sense buffer 的指针，其中包含 SCSI 错误信息（如果 `status` 是 `CHECK_CONDITION`）
    * `resid`:  剩余未传输的数据长度
    * `host_status`: 主机适配器状态
    * `driver_status`: 驱动程序状态
    * 如果 `dxfer_direction` 是 `SG_DXFER_FROM_DEV`，则 `dxferp` 指向的缓冲区会包含从设备读取的数据。

**用户或编程常见的使用错误举例说明:**

1. **错误的 `ioctl` 命令号:**  使用了错误的 `ioctl` 命令常量，导致内核无法识别请求。
   ```c
   // 错误地使用了 SG_GET_TIMEOUT + 1
   if (ioctl(fd, SG_GET_TIMEOUT + 1, &timeout) == -1) {
       perror("ioctl SG_GET_TIMEOUT failed");
   }
   ```

2. **`sg_io_hdr` 结构体设置不正确:**
   * **`dxfer_len` 与实际缓冲区大小不符:**  导致数据溢出或读取不足。
   * **`dxferp` 指向无效的内存地址:**  导致程序崩溃。
   * **`cmd_len` 与实际命令长度不符。**
   ```c
   sg_io_hdr_t io_hdr;
   memset(&io_hdr, 0, sizeof(io_hdr));
   io_hdr.interface_id = 'S';
   io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
   io_hdr.cmd_len = 6;
   unsigned char cmd[6] = {0x03, 0x00, 0x00, 0x00, 0x12, 0x00}; // Read(6) 命令
   io_hdr.cmdp = cmd;
   io_hdr.dxfer_len = 512;
   char buffer[256]; // 缓冲区太小
   io_hdr.dxferp = buffer;
   if (ioctl(fd, SG_IO, &io_hdr) == -1) {
       perror("ioctl SG_IO failed"); // 可能会发生数据溢出
   }
   ```

3. **没有正确处理 SCSI 状态:**  忽略 `CHECK_CONDITION` 状态，导致没有检查 sense buffer 中的错误信息。
   ```c
   if (ioctl(fd, SG_IO, &io_hdr) == 0) {
       if (io_hdr.status == CHECK_CONDITION) {
           // 应该检查 io_hdr.sbp 中的 sense 数据
           fprintf(stderr, "SCSI command failed, but sense data is not checked.\n");
       }
   }
   ```

4. **竞争条件:**  在多线程或多进程环境中，如果没有适当的同步机制，多个线程或进程可能同时访问同一个 SCSI 设备，导致数据损坏或错误。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **应用层 (Java/Kotlin):**  应用程序通常不会直接使用 SCSI 通用接口。它们会使用 Android Framework 提供的更高级的 API，例如 `StorageManager`, `MediaScanner`, 或文件 I/O API (`FileInputStream`, `FileOutputStream`)。

2. **Framework 层 (Java):**  Framework 层会根据用户的操作，调用底层的 native 代码来实现具体的功能。例如，当应用需要读取一个外部存储设备上的文件时，`StorageManager` 或相关的服务会通过 JNI 调用到 native 代码。

3. **Native 层 (C++/NDK):**  在 Framework 的 native 代码中，可能会使用到 POSIX 标准的系统调用，例如 `open`, `read`, `write`, `ioctl`。对于直接访问 SCSI 设备的场景，可能会打开 `/dev/sgX` 设备文件，并使用 `ioctl` 系统调用和 `SG_IO` 命令来与设备进行通信。  某些 Hardware Abstraction Layer (HAL) 的实现也可能直接使用这些接口。

4. **Kernel 层 (Linux Kernel):**  当 native 代码调用 `ioctl` 系统调用时，内核会根据设备文件的类型（字符设备）和 ioctl 命令号，将请求传递给相应的设备驱动程序。对于 `/dev/sgX` 设备，请求会传递给 SCSI 通用驱动程序 (`sg`)。

5. **SCSI 通用驱动程序:**  `sg` 驱动程序会解析 `sg_io_hdr_t` 结构体中的信息，构建 SCSI 请求，并将其发送到目标 SCSI 设备。驱动程序还会处理设备的响应，并将结果填充回 `sg_io_hdr_t` 结构体。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `ioctl` 调用，并打印出 `SG_IO` 命令相关信息的示例：

```javascript
// hook_sg_io.js

if (Process.platform === 'linux') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  const ioctl = new NativeFunction(ioctlPtr, 'int', ['int', 'uint', 'pointer']);

  const SG_IO = 0x2285; // SG_IO ioctl 命令号

  // 定义 sg_io_hdr 结构体布局 (需要与头文件中的定义一致)
  const sg_io_hdr_layout = {
    interface_id: 0,   // int
    dxfer_direction: 4, // int
    cmd_len: 8,        // uint8
    mx_sb_len: 9,      // uint8
    iovec_count: 10,   // uint16
    dxfer_len: 12,     // uint32
    dxferp: 16,        // pointer
    cmdp: 20,          // pointer
    sbp: 24,           // pointer
    timeout: 28,       // uint32
    flags: 32,         // uint32
    pack_id: 36,       // int
    usr_ptr: 40,       // pointer
    status: 44,        // uint8
    masked_status: 45, // uint8
    msg_status: 46,     // uint8
    sb_len_wr: 47,     // uint8
    host_status: 48,    // uint16
    driver_status: 50,  // uint16
    resid: 52,         // int
    duration: 56,      // uint32
    info: 60           // uint32
  };

  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();
      const argp = args[2];

      if (request === SG_IO) {
        console.log('ioctl called with SG_IO');
        console.log('  File Descriptor:', fd);

        const io_hdr = argp.readByteArray(Object.keys(sg_io_hdr_layout).length * 4); // 假设指针大小为 4 字节，实际应该根据架构调整
        const io_hdr_data = {};
        for (const key in sg_io_hdr_layout) {
          const offset = sg_io_hdr_layout[key];
          if (offset !== undefined) {
            if (key === 'cmdp' || key === 'dxferp' || key === 'sbp' || key === 'usr_ptr') {
              io_hdr_data[key] = new NativePointer(argp.add(offset).readPointer());
            } else if (key === 'cmd_len' || key === 'mx_sb_len' || key === 'status' || key === 'masked_status' || key === 'msg_status' || key === 'sb_len_wr') {
              io_hdr_data[key] = argp.add(offset).readU8();
            } else if (key === 'iovec_count' || key === 'host_status' || key === 'driver_status') {
              io_hdr_data[key] = argp.add(offset).readU16();
            }
             else {
              io_hdr_data[key] = argp.add(offset).readInt32();
            }
          }
        }

        console.log('  sg_io_hdr:');
        for (const key in io_hdr_data) {
          console.log(`    ${key}:`, io_hdr_data[key]);
        }

        if (io_hdr_data.cmdp) {
          const cmdLength = io_hdr_data.cmd_len;
          const command = io_hdr_data.cmdp.readByteArray(cmdLength);
          console.log('  Command:', hexdump(command, { ansi: true }));
        }

        if (io_hdr_data.dxferp && io_hdr_data.dxfer_len > 0) {
          console.log('  Data Transfer Buffer Address:', io_hdr_data.dxferp);
          console.log('  Data Transfer Length:', io_hdr_data.dxfer_len);
          // 注意：不要在这里读取大量数据，可能会导致性能问题
        }
      }
    },
    onLeave: function (retval) {
      if (this.request === SG_IO) {
        console.log('ioctl SG_IO returned:', retval);
        // 可以在这里检查 io_hdr 中的状态信息
      }
    }
  });
} else {
  console.log('This script is designed for Linux.');
}
```

**使用方法:**

1. 将上述代码保存为 `hook_sg_io.js`。
2. 找到你想要调试的 Android 进程的包名或进程 ID。
3. 使用 Frida 连接到目标进程：
   ```bash
   frida -U -f <包名> -l hook_sg_io.js --no-pause
   # 或
   frida -U <进程ID> -l hook_sg_io.js --no-pause
   ```
4. 当目标应用执行涉及 SCSI 通用接口的操作时，Frida 会拦截 `ioctl` 调用，并打印出相关信息，例如文件描述符、`sg_io_hdr` 结构体的内容（包括命令、数据缓冲区地址和长度等）。

**注意:**

* Frida Hook 需要 root 权限或在可调试的应用上运行。
* 上述 Frida 代码假设指针大小为 4 字节，在 64 位 Android 系统上需要调整。
* 读取大量数据缓冲区的内容可能会影响性能，应该谨慎操作。
* 需要根据目标 Android 系统的架构和 libc 版本，确保 `sg_io_hdr_layout` 的定义与实际情况一致。

通过这种方式，你可以逐步跟踪 Android Framework 或 NDK 如何使用底层的 SCSI 通用接口，并深入理解数据是如何传递的。

Prompt: 
```
这是目录为bionic/libc/kernel/android/scsi/scsi/sg.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _SCSI_GENERIC_H
#define _SCSI_GENERIC_H
#include <linux/compiler.h>
typedef struct sg_iovec {
  void  * iov_base;
  size_t iov_len;
} sg_iovec_t;
typedef struct sg_io_hdr {
  int interface_id;
  int dxfer_direction;
  unsigned char cmd_len;
  unsigned char mx_sb_len;
  unsigned short iovec_count;
  unsigned int dxfer_len;
  void  * dxferp;
  unsigned char  * cmdp;
  void  * sbp;
  unsigned int timeout;
  unsigned int flags;
  int pack_id;
  void  * usr_ptr;
  unsigned char status;
  unsigned char masked_status;
  unsigned char msg_status;
  unsigned char sb_len_wr;
  unsigned short host_status;
  unsigned short driver_status;
  int resid;
  unsigned int duration;
  unsigned int info;
} sg_io_hdr_t;
#define SG_INTERFACE_ID_ORIG 'S'
#define SG_DXFER_NONE (- 1)
#define SG_DXFER_TO_DEV (- 2)
#define SG_DXFER_FROM_DEV (- 3)
#define SG_DXFER_TO_FROM_DEV (- 4)
#define SG_DXFER_UNKNOWN (- 5)
#define SG_FLAG_DIRECT_IO 1
#define SG_FLAG_UNUSED_LUN_INHIBIT 2
#define SG_FLAG_MMAP_IO 4
#define SG_FLAG_NO_DXFER 0x10000
#define SG_FLAG_Q_AT_TAIL 0x10
#define SG_FLAG_Q_AT_HEAD 0x20
#define SG_INFO_OK_MASK 0x1
#define SG_INFO_OK 0x0
#define SG_INFO_CHECK 0x1
#define SG_INFO_DIRECT_IO_MASK 0x6
#define SG_INFO_INDIRECT_IO 0x0
#define SG_INFO_DIRECT_IO 0x2
#define SG_INFO_MIXED_IO 0x4
#define DRIVER_SENSE 0x08
#define driver_byte(result) (((result) >> 24) & 0xff)
#define GOOD 0x00
#define CHECK_CONDITION 0x01
#define CONDITION_GOOD 0x02
#define BUSY 0x04
#define INTERMEDIATE_GOOD 0x08
#define INTERMEDIATE_C_GOOD 0x0a
#define RESERVATION_CONFLICT 0x0c
#define COMMAND_TERMINATED 0x11
#define QUEUE_FULL 0x14
#define ACA_ACTIVE 0x18
#define TASK_ABORTED 0x20
#define sg_status_byte(result) (((result) >> 1) & 0x7f)
typedef struct sg_scsi_id {
  int host_no;
  int channel;
  int scsi_id;
  int lun;
  int scsi_type;
  short h_cmd_per_lun;
  short d_queue_depth;
  int unused[2];
} sg_scsi_id_t;
typedef struct sg_req_info {
  char req_state;
  char orphan;
  char sg_io_owned;
  char problem;
  int pack_id;
  void  * usr_ptr;
  unsigned int duration;
  int unused;
} sg_req_info_t;
#define SG_EMULATED_HOST 0x2203
#define SG_SET_TRANSFORM 0x2204
#define SG_GET_TRANSFORM 0x2205
#define SG_SET_RESERVED_SIZE 0x2275
#define SG_GET_RESERVED_SIZE 0x2272
#define SG_GET_SCSI_ID 0x2276
#define SG_SET_FORCE_LOW_DMA 0x2279
#define SG_GET_LOW_DMA 0x227a
#define SG_SET_FORCE_PACK_ID 0x227b
#define SG_GET_PACK_ID 0x227c
#define SG_GET_NUM_WAITING 0x227d
#define SG_GET_SG_TABLESIZE 0x227F
#define SG_GET_VERSION_NUM 0x2282
#define SG_SCSI_RESET 0x2284
#define SG_SCSI_RESET_NOTHING 0
#define SG_SCSI_RESET_DEVICE 1
#define SG_SCSI_RESET_BUS 2
#define SG_SCSI_RESET_HOST 3
#define SG_SCSI_RESET_TARGET 4
#define SG_SCSI_RESET_NO_ESCALATE 0x100
#define SG_IO 0x2285
#define SG_GET_REQUEST_TABLE 0x2286
#define SG_SET_KEEP_ORPHAN 0x2287
#define SG_GET_KEEP_ORPHAN 0x2288
#define SG_GET_ACCESS_COUNT 0x2289
#define SG_SCATTER_SZ (8 * 4096)
#define SG_DEFAULT_RETRIES 0
#define SG_DEF_FORCE_PACK_ID 0
#define SG_DEF_KEEP_ORPHAN 0
#define SG_DEF_RESERVED_SIZE SG_SCATTER_SZ
#define SG_MAX_QUEUE 16
#define SG_BIG_BUFF SG_DEF_RESERVED_SIZE
typedef struct sg_io_hdr Sg_io_hdr;
typedef struct sg_io_vec Sg_io_vec;
typedef struct sg_scsi_id Sg_scsi_id;
typedef struct sg_req_info Sg_req_info;
#define SG_MAX_SENSE 16
struct sg_header {
  int pack_len;
  int reply_len;
  int pack_id;
  int result;
  unsigned int twelve_byte : 1;
  unsigned int target_status : 5;
  unsigned int host_status : 8;
  unsigned int driver_status : 8;
  unsigned int other_flags : 10;
  unsigned char sense_buffer[SG_MAX_SENSE];
};
#define SG_SET_TIMEOUT 0x2201
#define SG_GET_TIMEOUT 0x2202
#define SG_GET_COMMAND_Q 0x2270
#define SG_SET_COMMAND_Q 0x2271
#define SG_SET_DEBUG 0x227e
#define SG_NEXT_CMD_LEN 0x2283
#define SG_DEFAULT_TIMEOUT (60 * HZ)
#define SG_DEF_COMMAND_Q 0
#define SG_DEF_UNDERRUN_FLAG 0
#endif

"""

```