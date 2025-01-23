Response:
Thinking Process:

1. **Understand the Goal:** The request asks for a comprehensive analysis of a C header file (`cxlflash_ioctl.h`) within Android's Bionic library. The analysis needs to cover functionality, relation to Android, libc function details, dynamic linker aspects, error scenarios, and how Android frameworks interact with this code. A Frida hook example is also required.

2. **Initial File Scan:** Quickly read through the header file to identify key elements:
    * `#ifndef`, `#define`:  Standard header guard to prevent multiple inclusions.
    * `#include <linux/types.h>`: Indicates interaction with the Linux kernel.
    * Structure definitions (e.g., `dk_cxlflash_hdr`, `dk_cxlflash_attach`): These represent data structures used for interacting with CXLFlash devices.
    * Macros (e.g., `CXLFLASH_WWID_LEN`, `DK_CXLFLASH_ALL_PORTS_ACTIVE`): Define constants and flags.
    * `union` definitions (e.g., `cxlflash_ioctls`, `cxlflash_ht_ioctls`): Allow different structures to share the same memory, typically used with `ioctl` system calls.
    * `_IOWR` macros and associated `DK_CXLFLASH_...` and `HT_CXLFLASH_...` definitions: These define `ioctl` command codes.

3. **Categorize Functionality:** Based on the structures and `ioctl` definitions, group the functionality:
    * **Device Attachment/Detachment:**  `dk_cxlflash_attach`, `dk_cxlflash_detach`.
    * **User Direct/Virtual Access:** `dk_cxlflash_udirect`, `dk_cxlflash_uvirtual`.
    * **Resource Management:** `dk_cxlflash_release`, `dk_cxlflash_resize`, `dk_cxlflash_clone`.
    * **Verification:** `dk_cxlflash_verify`.
    * **Error Recovery:** `dk_cxlflash_recover_afu`.
    * **LUN Management:** `dk_cxlflash_manage_lun`, `ht_cxlflash_lun_provision`.
    * **Debugging:** `ht_cxlflash_afu_debug`.

4. **Relate to Android:**  CXLFlash is related to persistent memory or storage devices. Think about how Android might use such devices:
    * High-performance storage for apps or system data.
    * Potential use in specialized hardware scenarios.
    * The `ioctl` interface suggests a low-level interaction, likely within system services or HALs.

5. **`libc` Function Explanation:** The header file *defines* structures and constants but doesn't *implement* `libc` functions. The key `libc` function involved is `ioctl()`. Explain its role in sending control commands to device drivers.

6. **Dynamic Linker:**  This header file is a *header file*. It doesn't contain executable code, so it's not directly linked. However, code that *uses* these definitions will be linked. Provide a general overview of dynamic linking in Android, focusing on how libraries are loaded and symbols are resolved. A sample `so` layout and the linking process are important here.

7. **Logic and Assumptions:**  For each `ioctl`, consider the purpose, potential inputs, and expected outputs. Focus on the core functionality (e.g., attaching requires a context ID, detaching releases it).

8. **User Errors:**  Think about common mistakes developers might make when using these ioctls:
    * Incorrect `ioctl` command codes.
    * Passing invalid data in the structures.
    * Calling ioctls in the wrong sequence.
    * Insufficient permissions.

9. **Android Framework/NDK Interaction:** Trace the path from a high-level Android operation down to this header file:
    * App uses NDK for low-level access.
    * NDK code uses system calls like `open()` and `ioctl()`.
    * `ioctl()` calls eventually reach the kernel driver that uses these definitions. A simplified block diagram can be helpful.

10. **Frida Hook:**  Provide a practical example of how to use Frida to intercept `ioctl()` calls related to CXLFlash. Focus on:
    * Finding the `ioctl()` function.
    * Filtering based on the file descriptor (if possible) or the `ioctl` command code.
    * Accessing and printing the arguments of the `ioctl()` call.

11. **Structure and Language:** Organize the information logically using headings and subheadings. Use clear and concise Chinese. Ensure all parts of the request are addressed.

12. **Review and Refine:**  Read through the entire response to check for accuracy, completeness, and clarity. Ensure the technical details are correct and the explanations are easy to understand. For example, initially, I might have focused too much on the structures themselves, but the core functionality revolves around the `ioctl` calls they enable.

By following these steps, I can construct a comprehensive and accurate answer to the user's request. The key is to break down the problem into manageable parts and systematically address each aspect.
这是一个关于CXL Flash设备的ioctl命令头文件，定义了用户空间程序与CXL Flash设备驱动程序进行交互的各种命令和数据结构。让我们逐一分析其功能，并结合Android的上下文进行说明。

**文件功能概览:**

该头文件定义了一系列用于控制和管理CXL (Compute Express Link) Flash设备的ioctl命令。这些ioctl命令允许用户空间的应用程序执行诸如以下操作：

* **连接/分离 (Attach/Detach):**  与CXL Flash设备的特定上下文建立或断开连接。
* **用户直接/虚拟访问 (User Direct/Virtual):**  获取对CXL Flash设备资源的直接或虚拟访问权限。
* **资源释放 (Release):**  释放之前获取的CXL Flash设备资源。
* **调整大小 (Resize):**  调整虚拟LUN（Logical Unit Number）的大小。
* **克隆 (Clone):**  克隆一个虚拟LUN到另一个虚拟LUN。
* **校验 (Verify):**  校验CXL Flash设备上的数据。
* **恢复AFU (Recover AFU):**  在AFU (Accelerator Function Unit) 上下文出现问题时进行恢复。
* **管理LUN (Manage LUN):**  管理CXL Flash设备上的LUN，例如启用/禁用超级通道。
* **LUN配置 (LUN Provision):**  创建、删除和查询CXL Flash设备上的LUN。
* **AFU调试 (AFU Debug):**  向AFU发送调试命令并获取数据。

**与Android功能的关联和举例:**

CXL Flash是一种高性能的存储技术，它可以为Android设备提供更快的存储访问速度和更低的延迟。虽然目前Android设备上CXL Flash的应用可能还不是非常普及，但其潜力是巨大的，尤其是在对存储性能有较高要求的场景中，例如：

* **高性能缓存:**  CXL Flash可以作为高速缓存，加速应用程序的启动和数据访问速度。例如，Android系统可以使用CXL Flash来缓存常用的应用程序代码或数据，从而缩短应用的启动时间。
* **持久内存:**  CXL Flash可以作为持久内存使用，提供字节寻址能力和非易失性特性。这可以简化某些应用程序的开发，例如数据库或关键数据存储应用。
* **虚拟机或容器存储:**  在Android虚拟化或容器化场景中，CXL Flash可以为虚拟机或容器提供高性能的存储支持。

**libc 函数功能详解:**

该头文件本身并不包含libc函数的实现代码，它只是定义了一些宏和数据结构。实际与CXL Flash设备交互是通过 `ioctl` 系统调用实现的。

`ioctl` (input/output control) 是一个 Linux 系统调用，允许用户空间的程序向设备驱动程序发送控制命令并传递数据。其基本用法如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  是打开的设备文件的文件描述符。这个设备文件通常对应于 CXL Flash 设备的驱动程序。
* `request`: 是一个与设备相关的请求码，用于指定要执行的操作。在本例中，`DK_CXLFLASH_ATTACH`, `DK_CXLFLASH_DETACH` 等宏就是这样的请求码。这些宏通常使用 `_IOWR` 等宏来定义，包含了设备类型、操作方向、命令编号以及数据大小等信息。
* `...`:  是可选的参数，用于传递与特定 `ioctl` 命令相关的数据。这些数据通常是以结构体的形式传递，例如 `struct dk_cxlflash_attach`。

**`_IOWR` 宏的解释:**

`_IOWR(type, nr, size)` 是一个用于生成 `ioctl` 请求码的宏。

* `type`:  通常是一个幻数，用于标识设备类型。在本例中是 `CXL_MAGIC` (0xCA)。
* `nr`:  是命令编号，用于区分不同的操作。例如，`DK_CXLFLASH_ATTACH` 的命令编号是 `0x80`。
* `size`:  是传递给 `ioctl` 命令的数据结构的大小。

**涉及 dynamic linker 的功能:**

这个头文件本身不涉及 dynamic linker 的功能，因为它只是定义了数据结构和常量。然而，如果用户空间的程序使用了这些定义，那么在编译和链接时，就需要确保相关的库（例如，包含 `ioctl` 系统调用声明的 `libc`）被正确链接。

**so 布局样本和链接的处理过程:**

假设有一个名为 `libcxflashtool.so` 的动态链接库，它使用了 `cxlflash_ioctl.h` 中定义的结构体和宏来与 CXL Flash 设备交互。

**`libcxflashtool.so` 布局样本 (简化):**

```
libcxflashtool.so:
    .text           # 代码段，包含与 CXL Flash 设备交互的函数实现
    .data           # 数据段，包含全局变量等
    .rodata         # 只读数据段，包含常量字符串等
    .dynsym         # 动态符号表，记录导出的和导入的符号
    .dynstr         # 动态字符串表，存储符号名称
    .plt            # 程序链接表，用于延迟绑定
    .got.plt        # 全局偏移表，用于存储外部符号的地址
```

**链接的处理过程:**

1. **编译:** 当编译 `libcxflashtool.so` 的源文件时，编译器会读取 `cxlflash_ioctl.h` 头文件，获取结构体定义和宏定义。
2. **链接:**  链接器会将编译后的目标文件链接成动态链接库。在这个过程中，链接器会处理对外部符号的引用，例如 `ioctl` 系统调用。
3. **动态链接:** 当一个应用程序加载 `libcxflashtool.so` 时，Android 的 dynamic linker (linker64 或 linker) 会执行以下操作：
    * **加载共享库:** 将 `libcxflashtool.so` 加载到内存中。
    * **符号解析:**  解析 `libcxflashtool.so` 中对外部符号（例如 `ioctl`）的引用，找到这些符号在其他共享库（例如 `libc.so`）中的地址。这通常涉及到查找 `.dynsym` 和 `.dynstr` 表。
    * **重定位:**  根据解析到的地址，修改 `libcxflashtool.so` 中对外部符号的引用，使其指向正确的地址。` .plt` 和 `.got.plt` 表在这个过程中起到关键作用。

**假设输入与输出 (逻辑推理):**

假设我们调用 `DK_CXLFLASH_ATTACH` 这个 ioctl 命令来连接 CXL Flash 设备。

**假设输入:**

* `fd`:  打开的 CXL Flash 设备文件描述符，例如通过 `open("/dev/cxl-flash0", O_RDWR)` 获取。
* `request`: `DK_CXLFLASH_ATTACH` 宏的值。
* `argp`: 指向 `struct dk_cxlflash_attach` 结构体的指针，该结构体包含了连接所需的参数，例如中断数量、上下文 ID 等。

```c
struct dk_cxlflash_attach attach_data;
attach_data.hdr.version = DK_CXLFLASH_VERSION_0;
attach_data.num_interrupts = 1;
// ... 其他参数赋值 ...

int fd = open("/dev/cxl-flash0", O_RDWR);
if (fd < 0) {
    perror("open");
    // 处理错误
}

int ret = ioctl(fd, DK_CXLFLASH_ATTACH, &attach_data);
if (ret < 0) {
    perror("ioctl");
    // 处理错误
} else {
    // 连接成功
    printf("CXL Flash device attached successfully.\n");
}

close(fd);
```

**假设输出:**

* **成功:** `ioctl` 函数返回 0。
* **失败:** `ioctl` 函数返回 -1，并设置 `errno` 变量以指示错误类型（例如，设备不存在、权限不足、参数错误等）。

**用户或编程常见的使用错误:**

* **错误的 ioctl 请求码:**  使用了错误的宏，导致设备驱动程序无法识别请求。
* **传递错误的数据结构:**  传递给 `ioctl` 的数据结构的大小或内容与驱动程序期望的不符。
* **忘记初始化数据结构:**  结构体中的某些字段可能需要初始化，如果忘记初始化，可能会导致未定义的行为。
* **设备文件未打开或打开失败:**  在调用 `ioctl` 之前，必须先成功打开 CXL Flash 设备的设备文件。
* **权限不足:**  执行 `ioctl` 操作可能需要特定的权限。
* **在错误的设备文件上调用 ioctl:** 确保在正确的 CXL Flash 设备文件描述符上调用相关的 ioctl 命令。
* **并发问题:** 如果多个进程或线程同时访问同一个 CXL Flash 设备，可能会导致竞争条件和数据损坏。

**Android Framework 或 NDK 如何到达这里:**

1. **应用层 (Java/Kotlin):**  应用程序可能需要高性能存储功能。
2. **NDK 层 (C/C++):**  开发者使用 NDK 编写 C/C++ 代码，以便直接与底层硬件交互，或者使用更底层的库。
3. **系统调用:**  NDK 代码会使用标准 C 库提供的函数，例如 `open()` 打开设备文件，然后使用 `ioctl()` 系统调用与 CXL Flash 设备驱动程序进行通信.
4. **Bionic libc:**  NDK 中使用的 C 库是 Android 的 Bionic libc，它提供了 `ioctl` 等系统调用的封装。
5. **内核空间:**  `ioctl()` 系统调用最终会进入 Linux 内核，由 CXL Flash 设备的驱动程序处理。驱动程序会解析 `ioctl` 请求码和传递的数据，并执行相应的操作。驱动程序中会包含处理这些 `ioctl` 命令的逻辑，这些逻辑会使用到 `cxlflash_ioctl.h` 中定义的结构体和常量。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook `ioctl` 系统调用来观察应用程序与 CXL Flash 设备驱动程序的交互。以下是一个简单的 Frida Hook 脚本示例：

```javascript
//attach to the target process
Process.enumerateModules().forEach(function (m) {
    if (m.name.startsWith("libc.")) { // Target libc to hook ioctl
        var ioctl_addr = Module.findExportByName(m.name, "ioctl");
        if (ioctl_addr) {
            Interceptor.attach(ioctl_addr, {
                onEnter: function (args) {
                    const fd = args[0].toInt32();
                    const request = args[1].toInt32();
                    const argp = args[2];

                    console.log("ioctl called");
                    console.log("  fd:", fd);
                    console.log("  request:", request, " (0x" + request.toString(16) + ")");

                    // 判断是否是 CXL Flash 相关的 ioctl (通过 magic number 或其他特征判断)
                    const CXL_MAGIC = 0xCA;
                    if ((request >> 8) === CXL_MAGIC) {
                        console.log("  Possible CXL Flash ioctl detected!");
                        // 根据 request 的值，解析 argp 指向的数据结构
                        if (request === 0xCA80) { // DK_CXLFLASH_ATTACH
                            const attach_struct = Memory.readByteArray(argp, 80); // 假设结构体大小为 80 字节
                            console.log("  dk_cxlflash_attach:", hexdump(attach_struct, { length: 80 }));
                        } else if (request === 0xCA83) { // DK_CXLFLASH_DETACH
                            const detach_struct = Memory.readByteArray(argp, 16); // 假设结构体大小为 16 字节
                            console.log("  dk_cxlflash_detach:", hexdump(detach_struct, { length: 16 }));
                        }
                        // ... 添加其他 CXL Flash ioctl 的解析 ...
                    }
                },
                onLeave: function (retval) {
                    console.log("ioctl returned:", retval.toInt32());
                }
            });
        }
    }
});
```

**调试步骤:**

1. **安装 Frida:**  确保你的 Android 设备上安装了 Frida 服务，并且你的 PC 上安装了 Frida 客户端。
2. **连接到目标进程:**  使用 Frida 客户端连接到你想要调试的 Android 进程。
3. **运行 Frida 脚本:**  将上面的 JavaScript 代码保存为 `.js` 文件，并使用 Frida 客户端执行该脚本。例如：`frida -U -f <package_name> -l your_script.js --no-pause`。
4. **执行目标操作:**  在 Android 设备上执行会触发 CXL Flash 相关 ioctl 调用的操作。
5. **查看 Frida 输出:**  Frida 脚本会在控制台中打印出 `ioctl` 调用的相关信息，包括文件描述符、请求码以及传递的数据结构内容（如果已解析）。

这个 Frida Hook 示例只是一个基本的框架。你需要根据具体的 CXL Flash ioctl 命令和数据结构来扩展解析部分。可以通过查看内核驱动程序的代码或者进行逆向工程来确定数据结构的布局。

希望以上详细的解释能够帮助你理解 `cxlflash_ioctl.handroid` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/scsi/cxlflash_ioctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _CXLFLASH_IOCTL_H
#define _CXLFLASH_IOCTL_H
#include <linux/types.h>
#define CXLFLASH_WWID_LEN 16
#define DK_CXLFLASH_VERSION_0 0
struct dk_cxlflash_hdr {
  __u16 version;
  __u16 rsvd[3];
  __u64 flags;
  __u64 return_flags;
};
#define DK_CXLFLASH_ALL_PORTS_ACTIVE 0x0000000000000001ULL
#define DK_CXLFLASH_APP_CLOSE_ADAP_FD 0x0000000000000002ULL
#define DK_CXLFLASH_CONTEXT_SQ_CMD_MODE 0x0000000000000004ULL
#define DK_CXLFLASH_ATTACH_REUSE_CONTEXT 0x8000000000000000ULL
struct dk_cxlflash_attach {
  struct dk_cxlflash_hdr hdr;
  __u64 num_interrupts;
  __u64 context_id;
  __u64 mmio_size;
  __u64 block_size;
  __u64 adap_fd;
  __u64 last_lba;
  __u64 max_xfer;
  __u64 reserved[8];
};
struct dk_cxlflash_detach {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 reserved[8];
};
struct dk_cxlflash_udirect {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 rsrc_handle;
  __u64 last_lba;
  __u64 reserved[8];
};
#define DK_CXLFLASH_UVIRTUAL_NEED_WRITE_SAME 0x8000000000000000ULL
struct dk_cxlflash_uvirtual {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 lun_size;
  __u64 rsrc_handle;
  __u64 last_lba;
  __u64 reserved[8];
};
struct dk_cxlflash_release {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 rsrc_handle;
  __u64 reserved[8];
};
struct dk_cxlflash_resize {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 rsrc_handle;
  __u64 req_size;
  __u64 last_lba;
  __u64 reserved[8];
};
struct dk_cxlflash_clone {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id_src;
  __u64 context_id_dst;
  __u64 adap_fd_src;
  __u64 reserved[8];
};
#define DK_CXLFLASH_VERIFY_SENSE_LEN 18
#define DK_CXLFLASH_VERIFY_HINT_SENSE 0x8000000000000000ULL
struct dk_cxlflash_verify {
  struct dk_cxlflash_hdr hdr;
  __u64 context_id;
  __u64 rsrc_handle;
  __u64 hint;
  __u64 last_lba;
  __u8 sense_data[DK_CXLFLASH_VERIFY_SENSE_LEN];
  __u8 pad[6];
  __u64 reserved[8];
};
#define DK_CXLFLASH_RECOVER_AFU_CONTEXT_RESET 0x8000000000000000ULL
struct dk_cxlflash_recover_afu {
  struct dk_cxlflash_hdr hdr;
  __u64 reason;
  __u64 context_id;
  __u64 mmio_size;
  __u64 adap_fd;
  __u64 reserved[8];
};
#define DK_CXLFLASH_MANAGE_LUN_WWID_LEN CXLFLASH_WWID_LEN
#define DK_CXLFLASH_MANAGE_LUN_ENABLE_SUPERPIPE 0x8000000000000000ULL
#define DK_CXLFLASH_MANAGE_LUN_DISABLE_SUPERPIPE 0x4000000000000000ULL
#define DK_CXLFLASH_MANAGE_LUN_ALL_PORTS_ACCESSIBLE 0x2000000000000000ULL
struct dk_cxlflash_manage_lun {
  struct dk_cxlflash_hdr hdr;
  __u8 wwid[DK_CXLFLASH_MANAGE_LUN_WWID_LEN];
  __u64 reserved[8];
};
union cxlflash_ioctls {
  struct dk_cxlflash_attach attach;
  struct dk_cxlflash_detach detach;
  struct dk_cxlflash_udirect udirect;
  struct dk_cxlflash_uvirtual uvirtual;
  struct dk_cxlflash_release release;
  struct dk_cxlflash_resize resize;
  struct dk_cxlflash_clone clone;
  struct dk_cxlflash_verify verify;
  struct dk_cxlflash_recover_afu recover_afu;
  struct dk_cxlflash_manage_lun manage_lun;
};
#define MAX_CXLFLASH_IOCTL_SZ (sizeof(union cxlflash_ioctls))
#define CXL_MAGIC 0xCA
#define CXL_IOWR(_n,_s) _IOWR(CXL_MAGIC, _n, struct _s)
#define DK_CXLFLASH_ATTACH CXL_IOWR(0x80, dk_cxlflash_attach)
#define DK_CXLFLASH_USER_DIRECT CXL_IOWR(0x81, dk_cxlflash_udirect)
#define DK_CXLFLASH_RELEASE CXL_IOWR(0x82, dk_cxlflash_release)
#define DK_CXLFLASH_DETACH CXL_IOWR(0x83, dk_cxlflash_detach)
#define DK_CXLFLASH_VERIFY CXL_IOWR(0x84, dk_cxlflash_verify)
#define DK_CXLFLASH_RECOVER_AFU CXL_IOWR(0x85, dk_cxlflash_recover_afu)
#define DK_CXLFLASH_MANAGE_LUN CXL_IOWR(0x86, dk_cxlflash_manage_lun)
#define DK_CXLFLASH_USER_VIRTUAL CXL_IOWR(0x87, dk_cxlflash_uvirtual)
#define DK_CXLFLASH_VLUN_RESIZE CXL_IOWR(0x88, dk_cxlflash_resize)
#define DK_CXLFLASH_VLUN_CLONE CXL_IOWR(0x89, dk_cxlflash_clone)
#define HT_CXLFLASH_VERSION_0 0
struct ht_cxlflash_hdr {
  __u16 version;
  __u16 subcmd;
  __u16 rsvd[2];
  __u64 flags;
  __u64 return_flags;
};
#define HT_CXLFLASH_HOST_READ 0x0000000000000000ULL
#define HT_CXLFLASH_HOST_WRITE 0x0000000000000001ULL
#define HT_CXLFLASH_LUN_PROVISION_SUBCMD_CREATE_LUN 0x0001
#define HT_CXLFLASH_LUN_PROVISION_SUBCMD_DELETE_LUN 0x0002
#define HT_CXLFLASH_LUN_PROVISION_SUBCMD_QUERY_PORT 0x0003
struct ht_cxlflash_lun_provision {
  struct ht_cxlflash_hdr hdr;
  __u16 port;
  __u16 reserved16[3];
  __u64 size;
  __u64 lun_id;
  __u8 wwid[CXLFLASH_WWID_LEN];
  __u64 max_num_luns;
  __u64 cur_num_luns;
  __u64 max_cap_port;
  __u64 cur_cap_port;
  __u64 reserved[8];
};
#define HT_CXLFLASH_AFU_DEBUG_MAX_DATA_LEN 262144
#define HT_CXLFLASH_AFU_DEBUG_SUBCMD_LEN 12
struct ht_cxlflash_afu_debug {
  struct ht_cxlflash_hdr hdr;
  __u8 reserved8[4];
  __u8 afu_subcmd[HT_CXLFLASH_AFU_DEBUG_SUBCMD_LEN];
  __u64 data_ea;
  __u32 data_len;
  __u32 reserved32;
  __u64 reserved[8];
};
union cxlflash_ht_ioctls {
  struct ht_cxlflash_lun_provision lun_provision;
  struct ht_cxlflash_afu_debug afu_debug;
};
#define MAX_HT_CXLFLASH_IOCTL_SZ (sizeof(union cxlflash_ht_ioctls))
#define HT_CXLFLASH_LUN_PROVISION CXL_IOWR(0xBF, ht_cxlflash_lun_provision)
#define HT_CXLFLASH_AFU_DEBUG CXL_IOWR(0xBE, ht_cxlflash_afu_debug)
#endif
```