Response:
Let's break down the thought process for analyzing this C header file and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C header file (`mtd-abi.handroid`) and explain its purpose, functionality, relation to Android, implementation details (where applicable), dynamic linking aspects, potential errors, and how it's accessed from higher layers in Android.

**2. Initial Scan and Keyword Recognition:**

First, I'd quickly scan the file, looking for keywords and patterns:

* **`#ifndef`, `#define`, `#include`:**  Standard C preprocessor directives. This file is a header file meant to prevent multiple inclusions.
* **`struct`:**  Indicates data structures. This is a core part of the file, defining how data related to MTD is organized.
* **`enum`:** Defines a set of named integer constants. Useful for representing states or options.
* **`#define` (constants without struct/enum):**  More constants, often flags or magic numbers.
* **`_IOR`, `_IOW`, `_IOWR`, `_IO`:** These macros are strong indicators of ioctl commands. The 'M' likely signifies operations on memory technology devices.
* **`mtd`:** This acronym appears frequently, strongly suggesting the file deals with Memory Technology Devices (like flash memory).
* **`oob`:** Likely stands for Out-Of-Band data, often used with flash memory for ECC or metadata.
* **`ecc`:** Error Correction Code.
* **`64` suffixes (e.g., `erase_info_user64`):**  Indicates 64-bit versions of structures, accommodating larger memory addresses and sizes.

**3. Deconstructing the Structures:**

I'd analyze each `struct` definition:

* **Purpose:**  What information does this structure hold? What operation is it likely used for?
* **Members:** What are the individual fields and their types?  What kind of data do they represent (start address, length, pointers, etc.)?
* **Relation to MTD:** How does this structure relate to the concepts of erasing, reading, writing, or getting information from MTD devices?

For example, for `erase_info_user`:

* **Purpose:** Seems to describe a region to be erased.
* **Members:** `start` and `length` – clearly define the memory range.
* **Relation to MTD:** Directly related to the erase operation on flash memory.

**4. Understanding the Enums and Defines:**

I'd go through the `enum` and `#define` constants:

* **Categorization:** Group them by their purpose (e.g., MTD types, operating modes, capabilities).
* **Meaning:** Understand the significance of each constant. What does it represent?
* **Usage:** How are these constants likely used in code interacting with MTD devices?  (e.g., checking the type of MTD device, specifying an operation mode).

**5. Deciphering the ioctl Commands:**

The macros like `MEMGETINFO`, `MEMERASE`, etc., are crucial.

* **Pattern Recognition:** Notice the pattern `MEM` followed by an operation (GETINFO, ERASE, WRITE, READ, etc.).
* **Data Flow:**  The `_IOR`, `_IOW`, `_IOWR` macros indicate the direction of data flow (read, write, or both) for the ioctl command. The third argument specifies the data structure associated with the command.
* **Purpose:**  What operation does each ioctl command initiate? What information does it retrieve or modify?

**6. Connecting to Android Functionality:**

Now, the key is to connect these low-level definitions to how Android uses MTD devices.

* **Flash Storage:** Recognize that MTD is the interface for interacting with flash memory, which is fundamental to Android for the system partition, data partition, etc.
* **File Systems:**  Consider how file systems like ext4 or F2FS interact with the underlying block devices, which in turn use MTD.
* **Device Drivers:** Understand that there's a kernel driver for MTD devices that implements these operations. This header file defines the user-space interface to that driver.

**7. Addressing Specific Requirements:**

* **libc Functions:** This header file *defines* data structures and constants used by libc functions when interacting with MTD devices through system calls like `ioctl()`. It doesn't contain the *implementation* of libc functions. The explanation should clarify this distinction.
* **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. However, code that *uses* these definitions (within libc or other shared libraries) will be linked. The explanation needs to focus on where this header might be used within a larger Android system and how dynamic linking would play a role in that broader context. Providing a hypothetical `.so` layout and linking process helps illustrate this.
* **Common Errors:** Think about typical mistakes developers might make when working with low-level device interactions, like incorrect sizes, invalid offsets, or not handling errors.
* **Android Framework/NDK Interaction:**  Trace the path from high-level Android APIs down to the kernel. Start with file I/O operations, then consider the VFS layer, block device layer, and finally the MTD driver. Frida hooks can be used at various points along this path to observe the data and calls.

**8. Structuring the Explanation:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Detail the functionality by category (structures, enums, defines, ioctls).
* Explain the connection to Android.
* Address the specific requirements about libc, dynamic linking, errors, and the Android framework/NDK.
* Use clear and concise language, providing examples where necessary.

**9. Iteration and Refinement:**

Review the generated explanation for clarity, accuracy, and completeness. Ensure all aspects of the prompt have been addressed. For example, initially, I might focus too much on the structures and forget to emphasize the role of `ioctl`. A review would catch this and prompt me to elaborate on the ioctl commands and their significance. Similarly, ensuring the explanation about dynamic linking is accurate and relevant (even if the header file itself doesn't directly *do* linking) is crucial.
这个C头文件 `mtd-abi.handroid` 定义了用户空间程序与 Linux 内核中的 MTD (Memory Technology Device) 子系统进行交互的接口。MTD 子系统是 Linux 内核中用于访问诸如闪存之类的存储设备的框架。`bionic` 是 Android 的 C 库，这个文件属于 `bionic`，意味着它是 Android 系统中与 MTD 设备交互的基础接口定义。

**功能列表:**

1. **定义数据结构:**  定义了多种 C 结构体，用于在用户空间和内核空间之间传递关于 MTD 设备操作的信息。这些结构体包括：
    * `erase_info_user`, `erase_info_user64`:  描述擦除操作的起始地址和长度。
    * `mtd_oob_buf`, `mtd_oob_buf64`: 描述读写操作的带外 (Out-of-Band, OOB) 数据缓冲区信息。
    * `mtd_write_req`, `mtd_read_req`: 描述读写操作的详细请求，包括起始地址、长度、OOB 数据信息等。
    * `mtd_read_req_ecc_stats`:  描述读取操作的 ECC (Error Correction Code) 统计信息。
    * `mtd_info_user`:  描述 MTD 设备的基本信息，如类型、标志、大小、擦除大小、写入大小、OOB 大小等。
    * `region_info_user`:  描述 MTD 设备分区的区域信息。
    * `otp_info`: 描述 OTP (One-Time Programmable) 区域的信息。
    * `nand_oobinfo`, `nand_oobfree`, `nand_ecclayout_user`:  描述 NAND 闪存特有的 OOB 数据布局和 ECC 信息。
    * `mtd_ecc_stats`: 描述 MTD 设备的 ECC 统计信息。

2. **定义枚举类型:**  定义了枚举类型 `mtd_file_modes`，用于指定 MTD 文件操作的模式。

3. **定义常量:**  定义了大量的宏常量，用于表示：
    * MTD 设备的类型 (如 `MTD_RAM`, `MTD_NANDFLASH`)。
    * MTD 设备的特性和能力 (如 `MTD_WRITEABLE`, `MTD_NO_ERASE`)。
    * NAND 闪存的 ECC 处理模式 (如 `MTD_NANDECC_OFF`, `MTD_NANDECC_AUTOPLACE`)。
    * OTP 区域的类型 (如 `MTD_OTP_FACTORY`, `MTD_OTP_USER`)。
    * ioctl 命令的魔数和编号 (如 `MEMGETINFO`, `MEMERASE`)，用于用户空间程序调用内核接口。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 底层硬件抽象层 (HAL) 和内核驱动程序之间沟通的桥梁。Android 系统需要与底层的存储设备（特别是闪存）进行交互，才能实现文件存储、系统更新等功能。

* **文件系统挂载:** Android 的文件系统（例如 ext4, f2fs）通常建立在 MTD 设备之上。当 Android 启动时，需要挂载各种文件系统（如 system, data, cache 分区），这些分区通常对应于 MTD 设备或其分区。系统调用 `mount()` 最终可能会通过内核中的 VFS (Virtual File System) 层，调用到与 MTD 设备相关的驱动程序，而驱动程序会使用这里定义的 ioctl 命令和数据结构与硬件交互。

* **OTA 更新:**  Android 的 OTA (Over-The-Air) 更新过程通常需要擦除和写入闪存的不同分区。例如，更新 system 分区时，会涉及到擦除旧的 system 分区，然后写入新的 system 镜像。这些操作会使用到 `MEMERASE` 和 `MEMWRITE` 相关的 ioctl 命令。

* **工厂恢复:**  在执行工厂恢复时，Android 需要擦除 user data 分区。这也会用到 `MEMERASE` 相关的 ioctl 命令。

* **访问特定分区:**  Android 系统中的某些工具或守护进程可能需要直接访问 MTD 设备或其分区。例如，用于读取或写入设备特定信息的工具，可能会打开 `/dev/mtdX` 或 `/dev/mtdblockX` 设备文件，并使用这里定义的 ioctl 命令进行操作。

**libc 函数的实现 (并非直接实现，而是定义接口):**

这个头文件本身**并不实现** libc 函数。它只是定义了与 MTD 子系统交互所需的数据结构和常量。实际的 libc 函数（例如，`open()`, `ioctl()`）的实现位于 `bionic` 库的其他源文件中。

当用户空间的程序想要与 MTD 设备交互时，它通常会：

1. **打开 MTD 设备文件:** 使用 `open()` 系统调用打开 `/dev/mtdX` 或 `/dev/mtdblockX` 这样的设备文件。这些设备文件由内核中的 MTD 驱动程序创建。
2. **构造参数结构体:** 根据需要执行的操作（例如，擦除、读写），填充这里定义的结构体（如 `erase_info_user`, `mtd_write_req`）。
3. **调用 ioctl:** 使用 `ioctl()` 系统调用，传入打开的文件描述符、这里定义的 ioctl 命令（例如 `MEMERASE`），以及指向构造好的参数结构体的指针。

`ioctl()` 系统调用是连接用户空间和内核空间的桥梁。当 `ioctl()` 被调用时，内核会根据传入的文件描述符找到对应的设备驱动程序（在这里是 MTD 驱动程序），然后执行与 ioctl 命令相关的操作，并使用传入的参数结构体中的数据。

**涉及 dynamic linker 的功能:**

这个头文件本身**不直接涉及** dynamic linker 的功能。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的作用是在程序启动时加载和链接共享库 (`.so` 文件)。

然而，如果一个共享库 (例如，一个底层的 HAL 库)  需要与 MTD 设备交互，它可能会包含使用这里定义的结构体和常量的代码，并调用 `ioctl()` 系统调用。这个共享库在加载时会被 dynamic linker 处理。

**so 布局样本 (假设一个使用 MTD 接口的 HAL 库):**

假设有一个名为 `mtd_hal.so` 的共享库，它使用了 `mtd-abi.handroid` 中定义的接口：

```
mtd_hal.so:
    .text          // 代码段，包含实现 MTD 相关功能的函数
    .rodata        // 只读数据段，可能包含一些常量
    .data          // 可读写数据段
    .bss           // 未初始化数据段
    .dynamic       // 动态链接信息
    .symtab        // 符号表
    .strtab        // 字符串表
    .rel.dyn       // 动态重定位表
    .rel.plt       // PLT (Procedure Linkage Table) 重定位表

    ... 其他段 ...
```

**链接的处理过程:**

1. **编译时:** 当编译 `mtd_hal.so` 的源代码时，编译器会识别出对 `ioctl()` 系统调用的使用以及对 `mtd-abi.handroid` 中定义的结构体和常量的引用。编译器会生成相应的机器码，并记录需要进行动态链接的信息。

2. **程序启动时:** 当一个应用程序（或 Android 系统服务）需要使用 `mtd_hal.so` 时，dynamic linker 会执行以下步骤：
    * **加载:** 将 `mtd_hal.so` 加载到内存中。
    * **查找依赖:** 查找 `mtd_hal.so` 依赖的其他共享库（例如，`libc.so`）。
    * **重定位:**  根据 `.rel.dyn` 和 `.rel.plt` 中的信息，修改 `mtd_hal.so` 中的代码和数据，使其能够正确访问其他共享库中的函数和全局变量。例如，对 `ioctl()` 函数的调用需要被重定位到 `libc.so` 中 `ioctl()` 的实际地址。
    * **符号解析:**  解析 `mtd_hal.so` 中引用的外部符号，找到它们在其他已加载的共享库中的地址。

在 `mtd_hal.so` 的代码中，可能存在类似这样的调用：

```c
#include <sys/ioctl.h>
#include <mtd/mtd-abi.h>
#include <fcntl.h>
#include <unistd.h>

int erase_mtd_region(const char *dev_path, __u64 start, __u64 length) {
    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct erase_info_user64 erase_info;
    erase_info.start = start;
    erase_info.length = length;

    if (ioctl(fd, MEMERASE64, &erase_info) < 0) {
        perror("ioctl MEMERASE64");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}
```

在动态链接时，`ioctl` 这个符号会被解析到 `libc.so` 中 `ioctl` 函数的地址。

**假设输入与输出 (针对上述 `erase_mtd_region` 函数):**

**假设输入:**
* `dev_path`: "/dev/mtd0" (假设 MTD 设备节点)
* `start`: 0x00000000 (起始地址)
* `length`: 0x00100000 (长度，例如 1MB)

**预期输出:**
* 如果擦除成功，函数返回 0。
* 如果打开设备文件失败，`perror("open")` 会输出错误信息，函数返回 -1。
* 如果 `ioctl` 调用失败（例如，权限不足、设备不存在等），`perror("ioctl MEMERASE64")` 会输出错误信息，函数返回 -1。

**用户或编程常见的使用错误:**

1. **错误的设备路径:**  使用了不存在或错误的 MTD 设备路径（例如，拼写错误、设备节点未创建）。
   ```c
   int fd = open("/dev/mtdwrong", O_RDWR); // 错误的设备路径
   ```

2. **权限不足:**  尝试对 MTD 设备执行操作，但当前用户没有足够的权限。通常需要 root 权限才能直接操作 MTD 设备。

3. **构造参数结构体错误:**  错误地设置了参数结构体中的字段，例如：
    * 擦除起始地址或长度超出设备范围。
    * 缓冲区指针 `ptr` 为 NULL 或指向无效的内存区域。
    * 使用了不兼容的结构体版本（例如，在只支持 32 位地址的系统上使用了 `erase_info_user64`）。

4. **忘记检查返回值:**  没有检查 `open()` 或 `ioctl()` 的返回值，导致错误发生时没有进行处理。

5. **并发访问冲突:**  多个进程或线程同时尝试访问同一个 MTD 设备，可能导致数据损坏或其他不可预测的行为。

6. **错误的 ioctl 命令:**  使用了错误的 ioctl 命令，与想要执行的操作不符。

7. **OOB 数据处理不当:**  在读写 OOB 数据时，错误地计算偏移量或长度，可能导致读取或写入错误的数据。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **高层 Java 代码 (Android Framework):**  用户或系统服务可能发起涉及存储操作的请求，例如：
   * 下载并安装应用 (需要写入 `/data` 分区)。
   * 系统更新。
   * 格式化存储设备。

2. **Framework API 调用:**  高层 Java 代码会调用 Android Framework 提供的 API，例如 `android.os.storage.StorageManager` 或 `android.os.RecoverySystem`。

3. **System Services:**  Framework API 的调用通常会委托给系统服务，例如 `installd` (负责应用安装) 或 `vold` (Volume Daemon，负责存储设备管理)。

4. **Native 代码 (C/C++):**  这些系统服务通常使用 Native 代码 (C/C++) 实现。例如，`vold` 使用 C++ 实现，并且会与内核交互来管理存储设备。

5. **HAL (Hardware Abstraction Layer):**  系统服务可能会调用 HAL 模块提供的接口来执行底层的硬件操作。例如，对于闪存操作，可能会调用 `mtd` HAL 模块。

6. **ioctl 系统调用:**  HAL 模块的实现会打开相应的 MTD 设备文件 (`/dev/mtdX`)，构造参数结构体（使用 `mtd-abi.handroid` 中定义的结构体），并调用 `ioctl()` 系统调用，将请求传递给内核中的 MTD 驱动程序。

7. **内核 MTD 子系统:**  内核中的 MTD 驱动程序接收到 `ioctl()` 请求后，会解析命令和参数，并与底层的闪存硬件进行交互。

**Frida Hook 示例调试步骤:**

假设你想观察 Android 系统在擦除 MTD 分区时的行为。你可以使用 Frida hook `ioctl()` 系统调用，并过滤出与 MTD 相关的 ioctl 命令。

**Frida 脚本示例:**

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查文件描述符是否指向 /dev/mtd* 设备
        const pathBuf = Memory.allocUtf8String(256);
        const bytesRead = recvfrom(fd, pathBuf, 255, 0, null, null);
        if (bytesRead > 0) {
          const path = pathBuf.readUtf8String();
          if (path.startsWith('/dev/mtd')) {
            console.log(`ioctl called on ${path} (fd: ${fd}), request: 0x${request.toString(16)}`);

            // 根据 ioctl 命令打印参数信息
            if (request === 0xc0044d02) { // MEMERASE 的魔数 (需要根据架构调整)
              const eraseInfo = argp.readByteArray(8); // struct erase_info_user 的大小
              console.log("  MEMERASE parameters:", hexdump(eraseInfo));
            } else if (request === 0xc0104d14) { // MEMERASE64 的魔数 (需要根据架构调整)
              const eraseInfo64 = argp.readByteArray(16); // struct erase_info_user64 的大小
              console.log("  MEMERASE64 parameters:", hexdump(eraseInfo64));
            }
            // 可以添加更多 ioctl 命令的解析
          }
        }
      },
      onLeave: function (retval) {
        // console.log('ioctl returned:', retval);
      }
    });
  } else {
    console.error('Could not find ioctl function');
  }
}

function recvfrom(sockfd, buf, len, flags, src_addr, addrlen) {
  const recvfromPtr = Module.getExportByName(null, 'recvfrom');
  if (recvfromPtr) {
    const recvfromFunc = new NativeFunction(recvfromPtr, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'pointer']);
    return recvfromFunc(sockfd, buf, len, flags, src_addr, addrlen);
  }
  return -1;
}
```

**调试步骤:**

1. **找到目标进程:**  确定你想要 hook 的进程，例如 `vold` 或负责 OTA 更新的进程。
2. **运行 Frida:**  使用 Frida 连接到目标进程：`frida -U -f <process_name> -l your_script.js --no-pause` 或者 `frida -U <process_pid> -l your_script.js`.
3. **观察输出:**  当目标进程调用 `ioctl()` 操作 MTD 设备时，Frida 脚本会在控制台上打印相关的日志信息，包括设备路径、ioctl 命令以及参数信息。
4. **分析数据:**  通过分析 Frida 的输出，你可以了解哪些 ioctl 命令被调用，以及传递的参数是什么，从而理解 Android Framework 是如何与 MTD 子系统进行交互的。

**注意:**  ioctl 命令的魔数 (例如 `0xc0044d02`) 是与架构相关的，需要根据目标设备的架构 (32 位或 64 位) 进行调整。你可以通过查看内核头文件或使用工具 (如 `_IOC_NR`, `_IOC_TYPE`, `_IOC_SIZE`, `_IOC_DIR` 宏) 来计算。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/mtd/mtd-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __MTD_ABI_H__
#define __MTD_ABI_H__
#include <linux/types.h>
struct erase_info_user {
  __u32 start;
  __u32 length;
};
struct erase_info_user64 {
  __u64 start;
  __u64 length;
};
struct mtd_oob_buf {
  __u32 start;
  __u32 length;
  unsigned char  * ptr;
};
struct mtd_oob_buf64 {
  __u64 start;
  __u32 pad;
  __u32 length;
  __u64 usr_ptr;
};
enum {
  MTD_OPS_PLACE_OOB = 0,
  MTD_OPS_AUTO_OOB = 1,
  MTD_OPS_RAW = 2,
};
struct mtd_write_req {
  __u64 start;
  __u64 len;
  __u64 ooblen;
  __u64 usr_data;
  __u64 usr_oob;
  __u8 mode;
  __u8 padding[7];
};
struct mtd_read_req_ecc_stats {
  __u32 uncorrectable_errors;
  __u32 corrected_bitflips;
  __u32 max_bitflips;
};
struct mtd_read_req {
  __u64 start;
  __u64 len;
  __u64 ooblen;
  __u64 usr_data;
  __u64 usr_oob;
  __u8 mode;
  __u8 padding[7];
  struct mtd_read_req_ecc_stats ecc_stats;
};
#define MTD_ABSENT 0
#define MTD_RAM 1
#define MTD_ROM 2
#define MTD_NORFLASH 3
#define MTD_NANDFLASH 4
#define MTD_DATAFLASH 6
#define MTD_UBIVOLUME 7
#define MTD_MLCNANDFLASH 8
#define MTD_WRITEABLE 0x400
#define MTD_BIT_WRITEABLE 0x800
#define MTD_NO_ERASE 0x1000
#define MTD_POWERUP_LOCK 0x2000
#define MTD_SLC_ON_MLC_EMULATION 0x4000
#define MTD_CAP_ROM 0
#define MTD_CAP_RAM (MTD_WRITEABLE | MTD_BIT_WRITEABLE | MTD_NO_ERASE)
#define MTD_CAP_NORFLASH (MTD_WRITEABLE | MTD_BIT_WRITEABLE)
#define MTD_CAP_NANDFLASH (MTD_WRITEABLE)
#define MTD_CAP_NVRAM (MTD_WRITEABLE | MTD_BIT_WRITEABLE | MTD_NO_ERASE)
#define MTD_NANDECC_OFF 0
#define MTD_NANDECC_PLACE 1
#define MTD_NANDECC_AUTOPLACE 2
#define MTD_NANDECC_PLACEONLY 3
#define MTD_NANDECC_AUTOPL_USR 4
#define MTD_OTP_OFF 0
#define MTD_OTP_FACTORY 1
#define MTD_OTP_USER 2
struct mtd_info_user {
  __u8 type;
  __u32 flags;
  __u32 size;
  __u32 erasesize;
  __u32 writesize;
  __u32 oobsize;
  __u64 padding;
};
struct region_info_user {
  __u32 offset;
  __u32 erasesize;
  __u32 numblocks;
  __u32 regionindex;
};
struct otp_info {
  __u32 start;
  __u32 length;
  __u32 locked;
};
#define MEMGETINFO _IOR('M', 1, struct mtd_info_user)
#define MEMERASE _IOW('M', 2, struct erase_info_user)
#define MEMWRITEOOB _IOWR('M', 3, struct mtd_oob_buf)
#define MEMREADOOB _IOWR('M', 4, struct mtd_oob_buf)
#define MEMLOCK _IOW('M', 5, struct erase_info_user)
#define MEMUNLOCK _IOW('M', 6, struct erase_info_user)
#define MEMGETREGIONCOUNT _IOR('M', 7, int)
#define MEMGETREGIONINFO _IOWR('M', 8, struct region_info_user)
#define MEMGETOOBSEL _IOR('M', 10, struct nand_oobinfo)
#define MEMGETBADBLOCK _IOW('M', 11, __kernel_loff_t)
#define MEMSETBADBLOCK _IOW('M', 12, __kernel_loff_t)
#define OTPSELECT _IOR('M', 13, int)
#define OTPGETREGIONCOUNT _IOW('M', 14, int)
#define OTPGETREGIONINFO _IOW('M', 15, struct otp_info)
#define OTPLOCK _IOR('M', 16, struct otp_info)
#define ECCGETLAYOUT _IOR('M', 17, struct nand_ecclayout_user)
#define ECCGETSTATS _IOR('M', 18, struct mtd_ecc_stats)
#define MTDFILEMODE _IO('M', 19)
#define MEMERASE64 _IOW('M', 20, struct erase_info_user64)
#define MEMWRITEOOB64 _IOWR('M', 21, struct mtd_oob_buf64)
#define MEMREADOOB64 _IOWR('M', 22, struct mtd_oob_buf64)
#define MEMISLOCKED _IOR('M', 23, struct erase_info_user)
#define MEMWRITE _IOWR('M', 24, struct mtd_write_req)
#define OTPERASE _IOW('M', 25, struct otp_info)
#define MEMREAD _IOWR('M', 26, struct mtd_read_req)
struct nand_oobinfo {
  __u32 useecc;
  __u32 eccbytes;
  __u32 oobfree[8][2];
  __u32 eccpos[32];
};
struct nand_oobfree {
  __u32 offset;
  __u32 length;
};
#define MTD_MAX_OOBFREE_ENTRIES 8
#define MTD_MAX_ECCPOS_ENTRIES 64
struct nand_ecclayout_user {
  __u32 eccbytes;
  __u32 eccpos[MTD_MAX_ECCPOS_ENTRIES];
  __u32 oobavail;
  struct nand_oobfree oobfree[MTD_MAX_OOBFREE_ENTRIES];
};
struct mtd_ecc_stats {
  __u32 corrected;
  __u32 failed;
  __u32 badblocks;
  __u32 bbtblocks;
};
enum mtd_file_modes {
  MTD_FILE_MODE_NORMAL = MTD_OTP_OFF,
  MTD_FILE_MODE_OTP_FACTORY = MTD_OTP_FACTORY,
  MTD_FILE_MODE_OTP_USER = MTD_OTP_USER,
  MTD_FILE_MODE_RAW,
};
#endif
```