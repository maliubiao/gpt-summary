Response:
Let's break down the thought process for answering the user's request about `ndctl.handroid`.

**1. Understanding the Core Request:**

The user provided a header file and asked for:

* Functionality explanation.
* Connection to Android.
* Detailed explanation of libc functions (within the context of the file).
* Dynamic linker aspects (if relevant).
* Logical reasoning examples.
* Common usage errors.
* How Android framework/NDK reaches this code (and a Frida hook example).

**2. Initial Analysis of the Header File:**

* **`#ifndef __NDCTL_H__` etc.:** Standard header guard, indicates a header file.
* **Includes `<linux/types.h>`:**  This immediately signals kernel-level interaction. `linux/types.h` defines fundamental Linux data types.
* **`struct nd_cmd_*`:**  Numerous structures with names starting with `nd_cmd_`. This strongly suggests these are data structures used for commands or requests related to some "nd" subsystem. The `__attribute__((__packed__))` further reinforces that these structures are likely used for direct communication with hardware or drivers where memory layout is critical.
* **`enum { ND_CMD_* ... }`:** Enumerations define constants likely representing specific commands within the "nd" subsystem.
* **`#define ND_IOCTL 'N'` and `#define ND_IOCTL_* ...`:**  The presence of `ND_IOCTL` and definitions using `_IOWR` macro strongly indicate this file defines ioctl commands. Ioctl is a system call mechanism for device-specific control. The 'N' is a magic number for the ioctl calls related to this specific driver/subsystem.
* **`enum { ND_DEVICE_* ... }` and `enum nd_driver_flags { ND_DRIVER_* ... }`:** These enums define types of devices and flags related to drivers, further reinforcing the kernel interaction.
* **`struct nd_cmd_pkg`:** This looks like a general-purpose command package structure, potentially used for more complex interactions.
* **`#define NVDIMM_FAMILY_*` and `#define NVDIMM_BUS_FAMILY_*`:**  These constants point towards Non-Volatile Dual In-line Memory Modules (NVDIMMs) as the underlying hardware.
* **`#define ND_IOCTL_CALL`:** Another ioctl definition, likely using the `nd_cmd_pkg` structure.

**3. Connecting to Android (Crucial Step):**

The file resides in `bionic/libc/kernel/uapi/linux/ndctl.handroid`.

* **`bionic`:**  Android's C library. This is a direct connection.
* **`libc`:**  Part of the C library, specifically dealing with system calls and standard library functions.
* **`kernel/uapi/linux/`:** This is where the *user-space API* for Linux kernel features is defined. The `uapi` part is key. It means this isn't kernel code, but rather header files that user-space programs (like those in Android) can use to interact with kernel features.
* **`ndctl.handroid`:** The `.handroid` suffix is a bionic convention indicating that this is a kernel header file specifically selected and potentially slightly adapted for Android.

**Therefore, the primary functionality is to provide the *user-space interface* for controlling and interacting with the Linux kernel's NVDIMM (Non-Volatile DIMM) subsystem.**

**4. Addressing Specific Questions:**

* **Functionality Listing:**  Based on the structure definitions and ioctl definitions, I can list the main functionalities: getting/setting NVDIMM configuration, triggering/checking Automatic Remediation Scrub (ARS), clearing errors, getting DIMM flags, and potentially vendor-specific commands.
* **Android Relationship:** Explicitly connect the `bionic` location to Android's C library. Explain that this allows Android applications or system services to manage NVDIMM hardware if present.
* **libc Functions:** Focus on `ioctl`. Explain what `ioctl` does, its purpose, and how the macros like `_IOWR` are used to generate the correct ioctl request numbers. Emphasize that the header file *defines* the structures and constants, but the *implementation* of the `ioctl` call is in the kernel. Mention `open()` and `close()` as necessary file operations.
* **Dynamic Linker:**  Recognize that this header file itself doesn't involve the dynamic linker directly. It's used *before* linking. However, *using* these functions would involve linking with `libc`. Provide a basic `so` layout and explain that the dynamic linker resolves the `ioctl` symbol from `libc.so`.
* **Logical Reasoning:**  Invent simple scenarios to demonstrate how these structures and commands might be used. For example, getting the configuration size, then retrieving the data.
* **Common Errors:** Focus on incorrect ioctl numbers, incorrect data structures, permission issues, and the device not existing.
* **Android Framework/NDK Path:**  Start with an Android app or service. Explain how the NDK can be used to make direct system calls. Show a simplified path: App -> JNI -> NDK C code -> `open()` -> `ioctl()` using the defined constants.
* **Frida Hook:** Provide a concrete JavaScript Frida hook example targeting the `ioctl` system call. Show how to filter for the specific `ND_IOCTL_*` commands and inspect the arguments.

**5. Refinement and Language:**

* **Clarity:** Use clear and concise language. Avoid overly technical jargon where possible, or explain it.
* **Structure:** Organize the answer logically, following the user's questions. Use headings and bullet points for readability.
* **Accuracy:** Ensure technical correctness in the explanations and examples.
* **Completeness:**  Address all aspects of the user's request.
* **Chinese:** Provide the answer in fluent Chinese.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Maybe this file defines actual functions.
* **Correction:** Realized it's a header file defining *data structures and constants* for ioctl calls, not function implementations. The actual implementation resides in the Linux kernel driver.
* **Initial thought:** Focus heavily on specific libc functions *within the header*.
* **Correction:**  Shifted focus to *how* libc functions like `ioctl` are used *with* the definitions from this header to interact with the kernel.
* **Initial thought:**  The dynamic linker is directly involved in this header.
* **Correction:** The dynamic linker is involved in resolving the *libc* functions used to *call* the ioctls defined here, not the header itself.

By following these steps, including analyzing the header file's contents and context within the Android build system, I can construct a comprehensive and accurate answer to the user's request.
这是一个位于 Android Bionic C 库中的内核用户空间 API 头文件，用于与 Linux 内核的 `ndctl` 子系统进行交互。`ndctl` 是一个用于管理 NVDIMM (Non-Volatile Dual In-line Memory Module) 设备的工具和内核子系统。NVDIMM 是一种结合了 DRAM 的速度和 NAND 闪存的持久性的内存技术。

**功能列举:**

这个头文件定义了用于与 NVDIMM 设备进行交互的数据结构和 ioctl 命令。其主要功能包括：

1. **获取和设置 DIMM (Dual In-line Memory Module) 标志:**  `ND_IOCTL_DIMM_FLAGS` 和相关的结构体 `nd_cmd_dimm_flags` 允许读取和修改 NVDIMM 设备的特定标志状态。

2. **获取配置数据大小:** `ND_IOCTL_GET_CONFIG_SIZE` 和 `nd_cmd_get_config_size` 用于获取 NVDIMM 设备配置数据的总大小以及最大传输单元大小。

3. **获取和设置配置数据:** `ND_IOCTL_GET_CONFIG_DATA`、`nd_cmd_get_config_data_hdr`、`ND_IOCTL_SET_CONFIG_DATA` 和 `nd_cmd_set_config_hdr` 用于读取和写入 NVDIMM 设备的配置数据。这允许用户空间程序修改 NVDIMM 的设置。

4. **执行厂商特定命令:** `ND_IOCTL_VENDOR`、`nd_cmd_vendor_hdr` 和 `nd_cmd_vendor_tail` 允许发送厂商自定义的命令到 NVDIMM 设备，并接收响应。

5. **管理自动修复扫描 (ARS):**
   - `ND_IOCTL_ARS_CAP` 和 `nd_cmd_ars_cap` 用于获取 NVDIMM 设备 ARS 功能的容量和限制。
   - `ND_IOCTL_ARS_START` 和 `nd_cmd_ars_start` 用于启动 NVDIMM 设备的 ARS 进程，对指定区域进行扫描和修复。
   - `ND_IOCTL_ARS_STATUS` 和 `nd_cmd_ars_status` 用于查询 ARS 进程的状态和错误记录。

6. **清除错误:** `ND_IOCTL_CLEAR_ERROR` 和 `nd_cmd_clear_error` 用于清除 NVDIMM 设备上的特定错误。

7. **调用通用命令:** `ND_IOCTL_CALL` 和 `nd_cmd_pkg` 提供了一种更通用的机制来发送和接收与 NVDIMM 设备交互的命令，可能用于实现更复杂或新的功能。

**与 Android 功能的关系及举例说明:**

虽然 NVDIMM 硬件可能不是所有 Android 设备都具备，但在一些高性能服务器或嵌入式设备中可能会使用。Android 系统或特定的供应商 HAL (Hardware Abstraction Layer) 可以利用这些接口来管理和维护 NVDIMM 设备。

**举例说明:**

假设一个 Android 设备配备了 NVDIMM，并且需要定期检查和修复内存错误。

1. **HAL 或系统服务:**  一个 Android 系统服务或硬件抽象层 (HAL) 模块可能会打开与 NVDIMM 设备相关的设备节点（例如 `/dev/nvdimm0`）。
2. **获取 ARS 能力:** 它可能会使用 `ioctl(fd, ND_IOCTL_ARS_CAP, &ars_cap)` 来查询设备的 ARS 能力，例如支持的最大扫描范围和输出数据量。
3. **启动 ARS:**  如果需要进行内存扫描，它会填充 `nd_cmd_ars_start` 结构体，指定要扫描的地址范围和类型（例如 `ND_ARS_PERSISTENT`），然后调用 `ioctl(fd, ND_IOCTL_ARS_START, &ars_start)`.
4. **监控 ARS 状态:** 定期使用 `ioctl(fd, ND_IOCTL_ARS_STATUS, &ars_status)` 来检查 ARS 的状态，包括是否完成，是否有错误发生，以及错误的位置等信息。
5. **清除错误:** 如果发现错误，可以使用 `ioctl(fd, ND_IOCTL_CLEAR_ERROR, &clear_error)` 来尝试清除这些错误。

**详细解释每一个 libc 函数的功能是如何实现的:**

这里涉及的并不是直接的 libc 函数实现，而是定义了与内核交互的 ioctl 命令的参数结构体和宏定义。用户空间程序会使用标准的 libc 函数，如 `open()`, `close()`, 和 `ioctl()` 来与内核驱动程序进行通信。

- **`open()`:**  用于打开与 NVDIMM 设备相关的设备文件，例如 `/dev/ndctl0` 或 `/dev/pmem0`。这会返回一个文件描述符，用于后续的 ioctl 操作。`open()` 的实现涉及到系统调用，最终会由内核中的文件系统和设备驱动程序处理。
- **`close()`:** 用于关闭之前打开的文件描述符，释放相关资源。同样是一个系统调用。
- **`ioctl()`:**  这是与设备驱动程序通信的主要方式。它的原型是 `int ioctl(int fd, unsigned long request, ...)`.
    - `fd`:  是 `open()` 返回的文件描述符。
    - `request`:  是一个与特定设备和操作相关的请求码。在这个文件中，`ND_IOCTL_DIMM_FLAGS` 等宏定义会被展开成这样的请求码。这些宏通常使用 `_IOW`, `_IOR`, `_IOWR` 等宏来生成，包含了设备类型、操作类型和数据大小等信息。
    - `...`:  是与请求相关的数据的指针。在这个文件中定义的 `struct nd_cmd_*` 结构体会被用作这些数据的载体。

**`ioctl()` 的实现过程简述:**

1. 用户空间的程序调用 `ioctl()`，这是一个系统调用，会陷入内核。
2. 内核接收到系统调用请求。
3. 内核根据文件描述符 `fd` 找到对应的设备驱动程序。
4. 内核将 `ioctl()` 的请求码 `request` 和数据指针传递给设备驱动程序的 `ioctl` 函数处理。
5. 设备驱动程序根据 `request` 的值，执行相应的操作，例如访问硬件寄存器、发送命令到 NVDIMM 设备等。
6. 设备驱动程序将操作结果写入提供的数据缓冲区（如果需要）。
7. 内核将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及动态链接。它定义的是内核接口。然而，任何使用这个头文件的用户空间程序都需要链接到 C 库 (`libc.so`)，因为它们会调用 `open()`, `close()`, `ioctl()` 等 libc 函数。

**`libc.so` 布局样本（简化）：**

```
libc.so:
    .text:  // 代码段
        ...
        __NR_open:  // open 系统调用号
        open:       // open 函数的实现
        __NR_close: // close 系统调用号
        close:      // close 函数的实现
        __NR_ioctl: // ioctl 系统调用号
        ioctl:      // ioctl 函数的实现
        ...
    .data:  // 数据段
        ...
    .dynamic: // 动态链接信息
        ...
    .symtab: // 符号表
        open
        close
        ioctl
        ...
```

**链接的处理过程:**

1. **编译阶段:** 当编译使用 `ndctl.handroid` 的 C/C++ 代码时，编译器会识别出 `open()`, `close()`, `ioctl()` 等函数调用。
2. **链接阶段:** 链接器会将编译生成的目标文件与必要的库进行链接。对于 Android 应用程序或 NDK 构建的库，链接器会链接到 `libc.so`。
3. **动态链接:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载 `libc.so` 到进程的地址空间。
4. **符号解析:** 动态链接器会解析应用程序中对 `open()`, `close()`, `ioctl()` 等符号的引用，将它们指向 `libc.so` 中对应的函数实现。
5. **系统调用:** 当应用程序调用这些函数时，实际上会执行 `libc.so` 中实现的包装函数，这些包装函数会发起相应的系统调用，最终与内核进行交互。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们想要获取一个 NVDIMM 设备的配置大小：

**假设输入:**

- 文件描述符 `fd` 已通过 `open()` 打开了 NVDIMM 设备。
- `ioctl` 的请求码为 `ND_IOCTL_GET_CONFIG_SIZE`。
- `nd_cmd_get_config_size` 结构体 `config_size_data` 已分配内存。

**逻辑推理:**

调用 `ioctl(fd, ND_IOCTL_GET_CONFIG_SIZE, &config_size_data)` 会将请求发送到内核驱动。内核驱动会查询 NVDIMM 设备，获取配置大小等信息，并将结果填充到 `config_size_data` 结构体中。

**假设输出:**

- `ioctl` 函数返回 0 表示成功。
- `config_size_data.status` 可能为 0 表示操作成功。
- `config_size_data.config_size` 包含 NVDIMM 配置数据的总大小（以字节为单位）。
- `config_size_data.max_xfer` 包含单次传输操作的最大字节数。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **文件描述符无效:**  在调用 `ioctl` 之前没有成功打开设备文件，或者文件描述符已被关闭。这会导致 `ioctl` 调用失败，返回 -1，并设置 `errno` 为 `EBADF` (Bad file descriptor)。

   ```c
   int fd = open("/dev/ndctl0", O_RDWR);
   if (fd == -1) {
       perror("open failed");
       return -1;
   }
   close(fd); // 错误：过早关闭了文件描述符

   struct nd_cmd_get_config_size config_size_data;
   if (ioctl(fd, ND_IOCTL_GET_CONFIG_SIZE, &config_size_data) == -1) {
       perror("ioctl failed"); // 这里会失败
   }
   ```

2. **`ioctl` 请求码错误:** 使用了错误的 `ioctl` 请求码，或者与传递的数据结构不匹配。这会导致内核无法识别请求，`ioctl` 调用失败，返回 -1，并可能设置 `errno` 为 `EINVAL` (Invalid argument) 或其他错误。

   ```c
   int fd = open("/dev/ndctl0", O_RDWR);
   if (fd != -1) {
       struct nd_cmd_dimm_flags flags;
       // 错误：使用了错误的 ioctl 请求码和数据结构
       if (ioctl(fd, ND_IOCTL_GET_CONFIG_SIZE, &flags) == -1) {
           perror("ioctl failed");
       }
       close(fd);
   }
   ```

3. **数据结构未正确初始化或分配内存:**  传递给 `ioctl` 的数据结构没有正确初始化，或者是指向未分配内存的指针。这会导致未定义的行为，可能导致程序崩溃或数据错误。

   ```c
   int fd = open("/dev/ndctl0", O_RDWR);
   if (fd != -1) {
       struct nd_cmd_get_config_size config_size_data; // 未初始化

       // 依赖于 config_size_data 中 status 的初始值，这是不安全的
       if (ioctl(fd, ND_IOCTL_GET_CONFIG_SIZE, &config_size_data) == -1) {
           perror("ioctl failed");
       } else {
           printf("Status: %u\n", config_size_data.status);
       }
       close(fd);
   }
   ```

4. **权限不足:**  用户空间程序没有足够的权限访问 NVDIMM 设备文件或执行相关的 ioctl 操作。这会导致 `ioctl` 调用失败，返回 -1，并设置 `errno` 为 `EACCES` (Permission denied)。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 `ndctl.handroid` 的步骤:**

1. **应用程序或系统服务:** Android 应用程序或系统服务需要与 NVDIMM 硬件进行交互。
2. **NDK (Native Development Kit):** 如果是应用程序，它可能会使用 NDK 来编写 C/C++ 代码，以便直接调用系统接口。系统服务通常是用 C/C++ 编写的。
3. **打开设备文件:** C/C++ 代码使用 `open()` 函数打开与 NVDIMM 设备关联的设备文件，例如 `/dev/ndctl0` 或 `/dev/pmem0`。
4. **包含头文件:** 代码中需要包含 `<linux/ndctl.h>` 头文件，以便使用定义的结构体和宏。由于 `ndctl.handroid` 是 Bionic 中对内核头文件的适配，所以实际上会包含 Bionic 提供的版本。
5. **调用 `ioctl()`:** 使用 `ioctl()` 函数，并传入相应的文件描述符、`ND_IOCTL_*` 请求码和 `struct nd_cmd_*` 数据结构指针，来与内核驱动进行通信。
6. **内核驱动处理:** 内核接收到 `ioctl` 调用，`ndctl` 驱动或其他相关驱动程序会处理这些请求，与 NVDIMM 硬件交互，并将结果返回给用户空间。

**Frida Hook 示例调试步骤:**

假设我们想监控一个应用程序对 `ND_IOCTL_GET_CONFIG_SIZE` 的调用。

**Frida Hook 代码 (JavaScript):**

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.findExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const ND_IOCTL_GET_CONFIG_SIZE = 0x40084e04; // 根据你的系统架构和内核版本可能会有所不同，需要查找实际值

        if (request === ND_IOCTL_GET_CONFIG_SIZE) {
          console.log('[ioctl] ND_IOCTL_GET_CONFIG_SIZE called');
          console.log('  File Descriptor:', fd);

          // 可以尝试读取和解析 args[2] 指向的 nd_cmd_get_config_size 结构体
          const configSizePtr = args[2];
          if (configSizePtr) {
            const status = configSizePtr.readU32();
            const config_size = configSizePtr.add(4).readU32();
            const max_xfer = configSizePtr.add(8).readU32();
            console.log('  nd_cmd_get_config_size:');
            console.log('    status:', status);
            console.log('    config_size:', config_size);
            console.log('    max_xfer:', max_xfer);
          }
        }
      },
      onLeave: function (retval) {
        // console.log('[ioctl] Return value:', retval.toInt32());
      }
    });
    console.log('[Frida] ioctl hook installed.');
  } else {
    console.log('[Frida] ioctl not found.');
  }
} else {
  console.log('[Frida] This script is for Linux.');
}
```

**调试步骤:**

1. **找到目标进程:** 确定你想要监控的 Android 应用程序或系统服务的进程 ID 或包名。
2. **运行 Frida:** 使用 Frida 连接到目标进程：`frida -U -f <包名> -l your_frida_script.js --no-pause` 或 `frida -p <进程ID> -l your_frida_script.js`.
3. **观察输出:** 当目标应用程序或服务调用 `ioctl` 并使用 `ND_IOCTL_GET_CONFIG_SIZE` 请求码时，Frida hook 会拦截这次调用，并在控制台上打印相关信息，例如文件描述符和 `nd_cmd_get_config_size` 结构体的内容。
4. **动态调整:** 可以根据需要修改 Frida 脚本，例如添加更多的 hook 点，解析更复杂的数据结构，或者修改参数值。

**注意:**

- `ND_IOCTL_GET_CONFIG_SIZE` 的实际值可能会因为 Android 版本和内核配置的不同而有所变化。你需要根据你的目标环境查找正确的值。一种方法是在目标设备上运行一个简单的程序，调用这个 ioctl，然后使用 `strace` 或类似的工具来查看实际的 ioctl 调用号。
- Hook 系统调用需要 root 权限。

通过以上步骤，你可以使用 Frida 动态地观察和调试 Android 应用程序或系统服务与 NVDIMM 设备的交互过程。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ndctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __NDCTL_H__
#define __NDCTL_H__
#include <linux/types.h>
struct nd_cmd_dimm_flags {
  __u32 status;
  __u32 flags;
} __attribute__((__packed__));
struct nd_cmd_get_config_size {
  __u32 status;
  __u32 config_size;
  __u32 max_xfer;
} __attribute__((__packed__));
struct nd_cmd_get_config_data_hdr {
  __u32 in_offset;
  __u32 in_length;
  __u32 status;
  __u8 out_buf[];
} __attribute__((__packed__));
struct nd_cmd_set_config_hdr {
  __u32 in_offset;
  __u32 in_length;
  __u8 in_buf[];
} __attribute__((__packed__));
struct nd_cmd_vendor_hdr {
  __u32 opcode;
  __u32 in_length;
  __u8 in_buf[];
} __attribute__((__packed__));
struct nd_cmd_vendor_tail {
  __u32 status;
  __u32 out_length;
  __u8 out_buf[];
} __attribute__((__packed__));
struct nd_cmd_ars_cap {
  __u64 address;
  __u64 length;
  __u32 status;
  __u32 max_ars_out;
  __u32 clear_err_unit;
  __u16 flags;
  __u16 reserved;
} __attribute__((__packed__));
struct nd_cmd_ars_start {
  __u64 address;
  __u64 length;
  __u16 type;
  __u8 flags;
  __u8 reserved[5];
  __u32 status;
  __u32 scrub_time;
} __attribute__((__packed__));
struct nd_cmd_ars_status {
  __u32 status;
  __u32 out_length;
  __u64 address;
  __u64 length;
  __u64 restart_address;
  __u64 restart_length;
  __u16 type;
  __u16 flags;
  __u32 num_records;
  struct nd_ars_record {
    __u32 handle;
    __u32 reserved;
    __u64 err_address;
    __u64 length;
  } __attribute__((__packed__)) records[];
} __attribute__((__packed__));
struct nd_cmd_clear_error {
  __u64 address;
  __u64 length;
  __u32 status;
  __u8 reserved[4];
  __u64 cleared;
} __attribute__((__packed__));
enum {
  ND_CMD_IMPLEMENTED = 0,
  ND_CMD_ARS_CAP = 1,
  ND_CMD_ARS_START = 2,
  ND_CMD_ARS_STATUS = 3,
  ND_CMD_CLEAR_ERROR = 4,
  ND_CMD_SMART = 1,
  ND_CMD_SMART_THRESHOLD = 2,
  ND_CMD_DIMM_FLAGS = 3,
  ND_CMD_GET_CONFIG_SIZE = 4,
  ND_CMD_GET_CONFIG_DATA = 5,
  ND_CMD_SET_CONFIG_DATA = 6,
  ND_CMD_VENDOR_EFFECT_LOG_SIZE = 7,
  ND_CMD_VENDOR_EFFECT_LOG = 8,
  ND_CMD_VENDOR = 9,
  ND_CMD_CALL = 10,
};
enum {
  ND_ARS_VOLATILE = 1,
  ND_ARS_PERSISTENT = 2,
  ND_ARS_RETURN_PREV_DATA = 1 << 1,
  ND_CONFIG_LOCKED = 1,
};
#define ND_IOCTL 'N'
#define ND_IOCTL_DIMM_FLAGS _IOWR(ND_IOCTL, ND_CMD_DIMM_FLAGS, struct nd_cmd_dimm_flags)
#define ND_IOCTL_GET_CONFIG_SIZE _IOWR(ND_IOCTL, ND_CMD_GET_CONFIG_SIZE, struct nd_cmd_get_config_size)
#define ND_IOCTL_GET_CONFIG_DATA _IOWR(ND_IOCTL, ND_CMD_GET_CONFIG_DATA, struct nd_cmd_get_config_data_hdr)
#define ND_IOCTL_SET_CONFIG_DATA _IOWR(ND_IOCTL, ND_CMD_SET_CONFIG_DATA, struct nd_cmd_set_config_hdr)
#define ND_IOCTL_VENDOR _IOWR(ND_IOCTL, ND_CMD_VENDOR, struct nd_cmd_vendor_hdr)
#define ND_IOCTL_ARS_CAP _IOWR(ND_IOCTL, ND_CMD_ARS_CAP, struct nd_cmd_ars_cap)
#define ND_IOCTL_ARS_START _IOWR(ND_IOCTL, ND_CMD_ARS_START, struct nd_cmd_ars_start)
#define ND_IOCTL_ARS_STATUS _IOWR(ND_IOCTL, ND_CMD_ARS_STATUS, struct nd_cmd_ars_status)
#define ND_IOCTL_CLEAR_ERROR _IOWR(ND_IOCTL, ND_CMD_CLEAR_ERROR, struct nd_cmd_clear_error)
#define ND_DEVICE_DIMM 1
#define ND_DEVICE_REGION_PMEM 2
#define ND_DEVICE_REGION_BLK 3
#define ND_DEVICE_NAMESPACE_IO 4
#define ND_DEVICE_NAMESPACE_PMEM 5
#define ND_DEVICE_DAX_PMEM 7
enum nd_driver_flags {
  ND_DRIVER_DIMM = 1 << ND_DEVICE_DIMM,
  ND_DRIVER_REGION_PMEM = 1 << ND_DEVICE_REGION_PMEM,
  ND_DRIVER_REGION_BLK = 1 << ND_DEVICE_REGION_BLK,
  ND_DRIVER_NAMESPACE_IO = 1 << ND_DEVICE_NAMESPACE_IO,
  ND_DRIVER_NAMESPACE_PMEM = 1 << ND_DEVICE_NAMESPACE_PMEM,
  ND_DRIVER_DAX_PMEM = 1 << ND_DEVICE_DAX_PMEM,
};
enum ars_masks {
  ARS_STATUS_MASK = 0x0000FFFF,
  ARS_EXT_STATUS_SHIFT = 16,
};
struct nd_cmd_pkg {
  __u64 nd_family;
  __u64 nd_command;
  __u32 nd_size_in;
  __u32 nd_size_out;
  __u32 nd_reserved2[9];
  __u32 nd_fw_size;
  unsigned char nd_payload[];
};
#define NVDIMM_FAMILY_INTEL 0
#define NVDIMM_FAMILY_HPE1 1
#define NVDIMM_FAMILY_HPE2 2
#define NVDIMM_FAMILY_MSFT 3
#define NVDIMM_FAMILY_HYPERV 4
#define NVDIMM_FAMILY_PAPR 5
#define NVDIMM_FAMILY_MAX NVDIMM_FAMILY_PAPR
#define NVDIMM_BUS_FAMILY_NFIT 0
#define NVDIMM_BUS_FAMILY_INTEL 1
#define NVDIMM_BUS_FAMILY_MAX NVDIMM_BUS_FAMILY_INTEL
#define ND_IOCTL_CALL _IOWR(ND_IOCTL, ND_CMD_CALL, struct nd_cmd_pkg)
#endif
```