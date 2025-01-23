Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Context:**

The prompt clearly states: "这是目录为bionic/libc/kernel/uapi/linux/hdreg.h android bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker."  This immediately tells us several key things:

* **Location:** This file is part of Bionic, Android's C library. Specifically, it's located in the `kernel/uapi` directory, which signifies it's a header file copied from the Linux kernel's user-facing API.
* **Purpose:**  It likely defines structures, constants, and types related to hard drive (HD) operations at a low level. The `hdreg.h` name is a strong hint.
* **Target Audience:**  This header is primarily used by system-level components and drivers that interact directly with storage devices. It's less likely to be used directly by typical Android application developers.

**2. Initial Scan and Keyword Identification:**

I'd quickly scan the file for recurring keywords and patterns. Some obvious ones jump out:

* `HDIO_`:  This strongly suggests ioctl commands related to hard drives.
* `WIN_`:  Many constants start with `WIN_`, which is highly indicative of commands and features related to the Windows operating system's (historical) interaction with IDE/ATA drives. This is a common inheritance in storage device interfaces.
* `IDE_`:  References to IDE (Integrated Drive Electronics), a common interface for connecting hard drives.
* `SMART_`:  Likely related to Self-Monitoring, Analysis, and Reporting Technology for hard drives.
* `TASKFILE_`, `hob_struct_t`, `task_struct_t`: These suggest low-level interactions with the drive's registers.
* `struct hd_driveid`, `struct hd_geometry`: These are clearly data structures containing drive information.
* `__u8`, `unsigned short`, `unsigned long`:  Standard C types used for representing data.

**3. Categorizing and Grouping:**

Based on the keywords, I'd start mentally grouping related definitions:

* **Data Structures:** `hd_drive_cmd_hdr`, `hd_drive_task_hdr`, `hd_drive_hob_hdr`, `ide_task_request_t`, `ide_ioctl_request_t`, `hd_geometry`, `hd_driveid`. These define how data is structured for communication with the drive.
* **Constants (Commands and Features):** `HDIO_...`, `WIN_...`, `SMART_...`, `SETFEATURES_...`. These represent the actions that can be performed on the drive.
* **Constants (Sizes):** `HDIO_DRIVE_CMD_HDR_SIZE`, etc. These define the sizes of data structures.
* **Constants (Task Types):** `IDE_DRIVE_TASK_NO_DATA`, etc. These categorize the type of operation.
* **Type Definitions:** `task_ioreg_t`, `sata_ioreg_t`, `ide_reg_valid_t`. These create aliases for existing types.
* **Enums:** The `enum { BUSSTATE_OFF, ... }` defines possible bus states.

**4. Inferring Functionality from Definitions:**

Now I'd start interpreting the meaning of these grouped definitions:

* **`HDIO_` constants:**  These are clearly ioctl (input/output control) commands used to interact with the hard drive driver in the kernel. Examples like `HDIO_GETGEO` (get geometry) and `HDIO_DRIVE_RESET` (reset the drive) are self-explanatory.
* **`WIN_` constants:** These represent the ATA command set. They define actions like reading sectors (`WIN_READ`), writing sectors (`WIN_WRITE`), identifying the drive (`WIN_IDENTIFY`), and managing power (`WIN_STANDBY`).
* **`SMART_` constants:** These relate to the SMART features, allowing monitoring of drive health and retrieving diagnostics.
* **`SETFEATURES_` constants:** These control various drive features, such as enabling write caching or setting transfer modes.
* **Data Structures:** These define the format of data exchanged with the drive. For example, `hd_driveid` contains detailed information about the drive's capabilities and configuration. `ide_task_request_t` structures the information needed to send low-level commands using the task file interface.

**5. Connecting to Android:**

The prompt asks about the relationship to Android. Since this is part of Bionic and within the `kernel/uapi` directory, the connection is clear:

* **Kernel Drivers:** Android's kernel drivers for storage devices (like block device drivers) will directly use these definitions to interact with the hardware.
* **HAL (Hardware Abstraction Layer):**  Higher-level components in Android, such as the HAL for storage, will likely use these low-level definitions indirectly through system calls and ioctls.
* **NDK (Native Development Kit):** While typical NDK developers won't directly use this header, understanding its existence helps in comprehending the underlying storage mechanisms. Some advanced NDK applications dealing with low-level storage might interact with device nodes and thus indirectly use concepts defined here.

**6. Addressing Specific Questions from the Prompt:**

* **libc functions:**  This header file itself *doesn't* define libc functions. It defines constants and structures used *by* libc functions (specifically the `ioctl` function). The libc `ioctl` function is the entry point for user-space programs to send control commands to kernel drivers.
* **Dynamic Linker:** This header file has no direct connection to the dynamic linker. It defines structures for interacting with hardware, while the dynamic linker is concerned with linking and loading shared libraries.
* **Logic Inference (Assumptions):** My assumptions are based on the standard structure of operating systems and hardware interaction. I assume that the `HDIO_` constants are used with the `ioctl` system call, and the structures define the data format for these calls.
* **User/Programming Errors:**  Common errors would involve incorrect usage of `ioctl` with the wrong command or data structure, leading to unexpected behavior or crashes. Trying to directly manipulate hardware registers from user space (without proper driver support) would be a major error.
* **Android Framework/NDK to This Point:** I traced the path from higher-level Android frameworks down to the kernel level, highlighting the role of the HAL and system calls.
* **Frida Hook Example:** I focused on hooking the `ioctl` system call as the most direct way to observe the usage of these definitions.

**7. Structuring the Output:**

Finally, I organized the information into logical sections as requested by the prompt, including:

* **功能概要 (Summary of Functionality)**
* **与 Android 功能的关系 (Relationship with Android)**
* **libc 函数详解 (Detailed Explanation of libc Functions - focusing on `ioctl`)**
* **Dynamic Linker 功能 (Dynamic Linker Functionality - noting the lack of direct connection)**
* **逻辑推理 (Logical Inference)**
* **用户或编程常见的使用错误 (Common User/Programming Errors)**
* **Android Framework 或 NDK 如何到达这里 (How Android Framework/NDK Reaches Here)**
* **Frida Hook 示例 (Frida Hook Example)**

This structured approach ensures that all aspects of the prompt are addressed in a clear and comprehensive manner. The iterative process of scanning, categorizing, inferring, and connecting to the larger context is crucial for understanding the purpose and usage of this type of header file.
这个C头文件 `bionic/libc/kernel/uapi/linux/hdreg.h` 定义了与硬盘驱动器（Hard Disk Drive, HDD）交互的底层接口，尤其关注传统的IDE/ATA接口。 由于它位于 `bionic/libc/kernel/uapi` 路径下，这意味着它是从 Linux 内核的头文件中复制而来，供用户空间的程序使用，以便与内核中的硬盘驱动器驱动程序进行交互。

**功能概要:**

这个头文件主要定义了以下功能：

1. **定义了与硬盘驱动器通信时使用的常量和数据结构：** 这些常量和结构体用于构造发送给硬盘驱动器的命令，以及解析从硬盘驱动器返回的数据。
2. **定义了用于执行各种硬盘操作的命令代码 (`WIN_` 开头的宏)：** 这些命令涵盖了读取、写入、格式化、识别硬盘等操作。这些命令很大程度上是历史遗留的 ATA/IDE 命令集。
3. **定义了用于控制硬盘特定功能的特征代码 (`SETFEATURES_` 开头的宏)：** 这些特征包括启用/禁用写缓存、设置电源管理模式、控制数据传输模式等。
4. **定义了与SMART (Self-Monitoring, Analysis and Reporting Technology) 相关的常量 (`SMART_` 开头的宏)：** SMART 用于监控硬盘的健康状况，预测潜在的故障。
5. **定义了用于通过 `ioctl` 系统调用与硬盘驱动程序交互的请求代码 (`HDIO_` 开头的宏)：** 这些 `ioctl` 请求允许用户空间程序向内核发送命令，例如获取硬盘几何信息、重置驱动器、执行任务文件命令等。
6. **定义了描述硬盘驱动器信息的结构体 (`hd_driveid`, `hd_geometry`)：** 这些结构体用于存储硬盘的各种参数，例如磁头数、扇区数、柱面数、容量、固件版本、序列号等。
7. **定义了用于处理 IDE 任务文件操作的数据结构 (`ide_task_request_t`, `ide_ioctl_request_t`)：** 任务文件是与 IDE 设备通信的一种底层方法，涉及直接操作设备的寄存器。

**与 Android 功能的关系及举例说明:**

这个头文件定义的接口是 Android 系统与底层存储设备交互的基础。尽管应用程序开发者通常不会直接使用这些定义，但它们对于 Android 框架和底层的 Native 层至关重要。

* **文件系统操作:** 当 Android 应用进行文件读写时，最终会通过文件系统层（例如 ext4, f2fs）到达内核的块设备层。块设备层会使用类似这里定义的 `ioctl` 命令和数据结构与硬盘驱动程序进行通信，执行实际的磁盘操作。例如，当一个应用保存一张图片到存储设备时，底层就可能涉及到使用 `WIN_WRITE` 命令将数据写入磁盘扇区。
* **存储管理:** Android 的存储管理框架（Storage Manager）需要获取存储设备的各种信息，例如容量、分区信息等。这些信息可能通过 `HDIO_GETGEO` 或 `HDIO_GET_IDENTITY` 等 `ioctl` 命令获取，这些命令返回的数据结构就包含了这里定义的 `hd_geometry` 和 `hd_driveid`。
* **设备驱动开发:** Android 的硬件抽象层 (HAL) 中，与存储设备相关的 HAL 模块，以及内核中的块设备驱动程序，都会直接使用这个头文件中定义的结构体和常量。例如，一个负责 IDE 硬盘控制的驱动程序会使用 `ide_task_request_t` 结构体来构造发送给硬盘的指令。
* **OTA (Over-The-Air) 更新:** 系统更新过程通常需要直接操作存储设备的扇区，例如写入新的系统镜像。这个过程很可能涉及到使用 `WIN_WRITE_EXT` 或类似的命令。
* **调试和诊断:** 一些底层的调试工具或系统工具可能会使用 `ioctl` 命令来获取硬盘的 SMART 信息 (`SMART_READ_VALUES`)，以诊断硬盘的健康状况。

**libc 函数详解 (针对这个头文件而言):**

这个头文件本身**并不定义**任何 libc 函数。它定义的是数据结构和常量，这些数据结构和常量会被 libc 提供的系统调用接口所使用，最主要的系统调用是 `ioctl`。

* **`ioctl` 函数:**
    * **功能:** `ioctl` (input/output control) 是一个通用的设备输入输出控制系统调用。它允许用户空间程序向设备驱动程序发送与设备相关的控制命令和参数。
    * **实现:** `ioctl` 的具体实现位于内核中。当用户空间程序调用 `ioctl` 时，系统会根据传递的文件描述符找到对应的设备驱动程序，并将 `ioctl` 的命令代码和参数传递给该驱动程序的 `ioctl` 函数。
    * **与此头文件的关系:** 这个头文件中定义的 `HDIO_` 开头的宏就是 `ioctl` 系统调用的命令代码。例如，要获取硬盘的几何信息，用户空间程序会使用打开的硬盘设备文件描述符，调用 `ioctl(fd, HDIO_GETGEO, &geometry)`，其中 `HDIO_GETGEO` 就是一个命令代码，`geometry` 是一个 `hd_geometry` 类型的结构体，用于接收返回的硬盘信息。

**对于涉及 dynamic linker 的功能:**

这个头文件**不涉及** dynamic linker 的功能。Dynamic linker (例如 Android 的 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的内存空间，并解析和处理库之间的依赖关系。`hdreg.h` 关注的是与硬件设备交互的底层细节，与动态链接过程无关。

**so 布局样本和链接的处理过程 (不适用):**

由于此头文件不涉及 dynamic linker，所以没有相关的 `.so` 布局或链接处理过程。

**逻辑推理 (假设输入与输出):**

假设我们想获取硬盘的几何信息：

* **假设输入:**
    * 打开硬盘设备文件 `/dev/sda` (假设它是第一个 SATA 硬盘)。
    * 调用 `ioctl` 函数，命令代码为 `HDIO_GETGEO`。
    * 提供一个 `hd_geometry` 类型的结构体变量 `geometry` 的地址。
* **预期输出:**
    * `ioctl` 调用成功返回 0。
    * `geometry` 结构体中的 `heads`, `sectors`, `cylinders`, `start` 字段会被填充上硬盘的相应几何参数。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的文件描述符:**  如果传递给 `ioctl` 的文件描述符不是一个打开的硬盘设备文件，`ioctl` 调用将会失败，并返回错误代码（通常是 -1），`errno` 会被设置为相应的错误值（例如 `EBADF` - 无效的文件描述符）。
  ```c
  #include <sys/ioctl.h>
  #include <fcntl.h>
  #include <linux/hdreg.h>
  #include <stdio.h>
  #include <errno.h>
  #include <string.h>

  int main() {
      int fd = open("/some/nonexistent/file", O_RDONLY); // 错误的文件
      struct hd_geometry geometry;

      if (fd < 0) {
          perror("open");
          return 1;
      }

      if (ioctl(fd, HDIO_GETGEO, &geometry) < 0) {
          perror("ioctl"); // 输出类似 "ioctl: Bad file descriptor" 的错误信息
          printf("errno: %d, strerror: %s\n", errno, strerror(errno)); // 输出 errno 和对应的错误描述
      }

      close(fd);
      return 0;
  }
  ```

* **传递了错误的命令代码:** 如果使用了不适用于硬盘设备的 `ioctl` 命令代码，或者使用了与设备驱动程序不兼容的命令代码，`ioctl` 调用也会失败。
* **传递了不兼容的数据结构:**  `ioctl` 需要传递正确类型的参数。例如，如果 `HDIO_GETGEO` 期望一个 `hd_geometry` 结构体的指针，却传递了其他类型的指针，会导致未定义的行为甚至崩溃。
* **权限不足:** 访问硬盘设备通常需要 root 权限。如果用户没有足够的权限，`open` 或 `ioctl` 调用可能会失败，返回 `EACCES` (权限被拒绝)。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework:**  用户在 Android 设备上进行存储相关的操作，例如保存照片、安装应用等，这些操作首先会经过 Android Framework 层的组件。例如：
   * **MediaStore:**  当应用使用 `MediaStore` API 保存图片时。
   * **PackageManager:** 当系统安装或卸载应用时。
   * **StorageManager:** 当进行存储管理操作，例如格式化 SD 卡时。

2. **System Services:**  Framework 层的组件会将这些请求传递给 System Services，例如 `MediaProvider`, `PackageManagerService`, `MountService` 等。这些服务运行在独立的进程中，拥有更高的权限。

3. **Native Code (C/C++):**  System Services 的实现通常会调用 Native 代码，例如使用 JNI (Java Native Interface) 调用 C/C++ 代码。这些 Native 代码可能会直接使用 libc 提供的系统调用接口。

4. **libc 系统调用 (ioctl):**  在 Native 层，会调用 libc 提供的 `open` 函数打开硬盘设备文件（例如 `/dev/block/sda` 或 `/dev/block/mmcblk0pX`），然后使用 `ioctl` 函数，并传入 `hdreg.h` 中定义的 `HDIO_` 常量作为命令代码，以及相应的结构体指针，与内核中的硬盘驱动程序进行通信。

5. **Kernel Driver:**  内核中的块设备驱动程序接收到 `ioctl` 调用后，会根据命令代码执行相应的操作，例如读取硬盘的几何信息，或者发送 ATA/IDE 命令到硬盘控制器。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与硬盘相关的 `ioctl` 命令代码，以观察 Android Framework 如何最终到达这里。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['api'], message['payload']['args']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.attach('com.android.systemui') # 可以替换为其他感兴趣的进程
    script = session.create_script("""
        const HDIO_GETGEO = 0x0301;
        const HDIO_GET_IDENTITY = 0x030d;
        const HDIO_DRIVE_CMD = 0x031f;

        Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();

                if (request === HDIO_GETGEO || request === HDIO_GET_IDENTITY || request === HDIO_DRIVE_CMD) {
                    this.api = "ioctl";
                    this.args = {
                        fd: fd,
                        request: request,
                        // 可以尝试读取 arg[2] 指向的数据结构内容，但这可能比较复杂
                    };
                    send({ api: this.api, args: this.args });
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    print("[*] Running, press Ctrl+C to stop")
    sys.stdin.read()
except KeyboardInterrupt:
    print("[*] Stopping")
    session.detach()
except frida.ProcessNotFoundError:
    print("Process not found. Please specify a PID or target process name.")

```

**使用方法:**

1. 确保你的电脑上安装了 Frida 和 Python 的 Frida 模块。
2. 找到你想要监控的 Android 进程的 PID (例如，可以使用 `adb shell ps | grep systemui` 找到 `com.android.systemui` 进程的 PID)。
3. 运行 Frida 脚本，将进程的 PID 作为参数传递，或者直接指定进程名称。
4. 当 Android 系统进行与硬盘相关的操作时，Frida 脚本会 hook `ioctl` 调用，并打印出文件描述符和 `ioctl` 的命令代码。

**调试步骤:**

1. 运行 Frida 脚本并 attach 到目标进程。
2. 在 Android 设备上执行一些涉及存储的操作，例如打开一个包含大量图片的相册，或者尝试下载一个文件。
3. 观察 Frida 的输出，查看是否有 `ioctl` 调用，并且其 `request` 参数是 `HDIO_GETGEO`, `HDIO_GET_IDENTITY` 或其他与硬盘相关的 `HDIO_` 常量。
4. 如果需要更详细的调试信息，可以尝试在 Frida 脚本中读取 `ioctl` 的第三个参数，该参数通常指向传递给驱动程序的数据结构。但这需要了解具体的 `ioctl` 命令和对应的数据结构布局。

通过 Frida hook，你可以观察到 Android Framework 的组件是如何通过 `ioctl` 系统调用，使用 `hdreg.h` 中定义的常量与底层的硬盘驱动程序进行交互的。 这有助于理解 Android 存储子系统的运作机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/hdreg.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_HDREG_H
#define _LINUX_HDREG_H
#include <linux/types.h>
#define HDIO_DRIVE_CMD_HDR_SIZE (4 * sizeof(__u8))
#define HDIO_DRIVE_HOB_HDR_SIZE (8 * sizeof(__u8))
#define HDIO_DRIVE_TASK_HDR_SIZE (8 * sizeof(__u8))
#define IDE_DRIVE_TASK_NO_DATA 0
#define IDE_DRIVE_TASK_INVALID - 1
#define IDE_DRIVE_TASK_SET_XFER 1
#define IDE_DRIVE_TASK_IN 2
#define IDE_DRIVE_TASK_OUT 3
#define IDE_DRIVE_TASK_RAW_WRITE 4
#define IDE_TASKFILE_STD_IN_FLAGS 0xFE
#define IDE_HOB_STD_IN_FLAGS 0x3C
#define IDE_TASKFILE_STD_OUT_FLAGS 0xFE
#define IDE_HOB_STD_OUT_FLAGS 0x3C
typedef unsigned char task_ioreg_t;
typedef unsigned long sata_ioreg_t;
typedef union ide_reg_valid_s {
  unsigned all : 16;
  struct {
    unsigned data : 1;
    unsigned error_feature : 1;
    unsigned sector : 1;
    unsigned nsector : 1;
    unsigned lcyl : 1;
    unsigned hcyl : 1;
    unsigned select : 1;
    unsigned status_command : 1;
    unsigned data_hob : 1;
    unsigned error_feature_hob : 1;
    unsigned sector_hob : 1;
    unsigned nsector_hob : 1;
    unsigned lcyl_hob : 1;
    unsigned hcyl_hob : 1;
    unsigned select_hob : 1;
    unsigned control_hob : 1;
  } b;
} ide_reg_valid_t;
typedef struct ide_task_request_s {
  __u8 io_ports[8];
  __u8 hob_ports[8];
  ide_reg_valid_t out_flags;
  ide_reg_valid_t in_flags;
  int data_phase;
  int req_cmd;
  unsigned long out_size;
  unsigned long in_size;
} ide_task_request_t;
typedef struct ide_ioctl_request_s {
  ide_task_request_t * task_request;
  unsigned char * out_buffer;
  unsigned char * in_buffer;
} ide_ioctl_request_t;
struct hd_drive_cmd_hdr {
  __u8 command;
  __u8 sector_number;
  __u8 feature;
  __u8 sector_count;
};
typedef struct hd_drive_task_hdr {
  __u8 data;
  __u8 feature;
  __u8 sector_count;
  __u8 sector_number;
  __u8 low_cylinder;
  __u8 high_cylinder;
  __u8 device_head;
  __u8 command;
} task_struct_t;
typedef struct hd_drive_hob_hdr {
  __u8 data;
  __u8 feature;
  __u8 sector_count;
  __u8 sector_number;
  __u8 low_cylinder;
  __u8 high_cylinder;
  __u8 device_head;
  __u8 control;
} hob_struct_t;
#define TASKFILE_NO_DATA 0x0000
#define TASKFILE_IN 0x0001
#define TASKFILE_MULTI_IN 0x0002
#define TASKFILE_OUT 0x0004
#define TASKFILE_MULTI_OUT 0x0008
#define TASKFILE_IN_OUT 0x0010
#define TASKFILE_IN_DMA 0x0020
#define TASKFILE_OUT_DMA 0x0040
#define TASKFILE_IN_DMAQ 0x0080
#define TASKFILE_OUT_DMAQ 0x0100
#define TASKFILE_P_IN 0x0200
#define TASKFILE_P_OUT 0x0400
#define TASKFILE_P_IN_DMA 0x0800
#define TASKFILE_P_OUT_DMA 0x1000
#define TASKFILE_P_IN_DMAQ 0x2000
#define TASKFILE_P_OUT_DMAQ 0x4000
#define TASKFILE_48 0x8000
#define TASKFILE_INVALID 0x7fff
#define WIN_NOP 0x00
#define CFA_REQ_EXT_ERROR_CODE 0x03
#define WIN_SRST 0x08
#define WIN_DEVICE_RESET 0x08
#define WIN_RECAL 0x10
#define WIN_RESTORE WIN_RECAL
#define WIN_READ 0x20
#define WIN_READ_ONCE 0x21
#define WIN_READ_LONG 0x22
#define WIN_READ_LONG_ONCE 0x23
#define WIN_READ_EXT 0x24
#define WIN_READDMA_EXT 0x25
#define WIN_READDMA_QUEUED_EXT 0x26
#define WIN_READ_NATIVE_MAX_EXT 0x27
#define WIN_MULTREAD_EXT 0x29
#define WIN_WRITE 0x30
#define WIN_WRITE_ONCE 0x31
#define WIN_WRITE_LONG 0x32
#define WIN_WRITE_LONG_ONCE 0x33
#define WIN_WRITE_EXT 0x34
#define WIN_WRITEDMA_EXT 0x35
#define WIN_WRITEDMA_QUEUED_EXT 0x36
#define WIN_SET_MAX_EXT 0x37
#define CFA_WRITE_SECT_WO_ERASE 0x38
#define WIN_MULTWRITE_EXT 0x39
#define WIN_WRITE_VERIFY 0x3C
#define WIN_VERIFY 0x40
#define WIN_VERIFY_ONCE 0x41
#define WIN_VERIFY_EXT 0x42
#define WIN_FORMAT 0x50
#define WIN_INIT 0x60
#define WIN_SEEK 0x70
#define CFA_TRANSLATE_SECTOR 0x87
#define WIN_DIAGNOSE 0x90
#define WIN_SPECIFY 0x91
#define WIN_DOWNLOAD_MICROCODE 0x92
#define WIN_STANDBYNOW2 0x94
#define WIN_STANDBY2 0x96
#define WIN_SETIDLE2 0x97
#define WIN_CHECKPOWERMODE2 0x98
#define WIN_SLEEPNOW2 0x99
#define WIN_PACKETCMD 0xA0
#define WIN_PIDENTIFY 0xA1
#define WIN_QUEUED_SERVICE 0xA2
#define WIN_SMART 0xB0
#define CFA_ERASE_SECTORS 0xC0
#define WIN_MULTREAD 0xC4
#define WIN_MULTWRITE 0xC5
#define WIN_SETMULT 0xC6
#define WIN_READDMA_QUEUED 0xC7
#define WIN_READDMA 0xC8
#define WIN_READDMA_ONCE 0xC9
#define WIN_WRITEDMA 0xCA
#define WIN_WRITEDMA_ONCE 0xCB
#define WIN_WRITEDMA_QUEUED 0xCC
#define CFA_WRITE_MULTI_WO_ERASE 0xCD
#define WIN_GETMEDIASTATUS 0xDA
#define WIN_ACKMEDIACHANGE 0xDB
#define WIN_POSTBOOT 0xDC
#define WIN_PREBOOT 0xDD
#define WIN_DOORLOCK 0xDE
#define WIN_DOORUNLOCK 0xDF
#define WIN_STANDBYNOW1 0xE0
#define WIN_IDLEIMMEDIATE 0xE1
#define WIN_STANDBY 0xE2
#define WIN_SETIDLE1 0xE3
#define WIN_READ_BUFFER 0xE4
#define WIN_CHECKPOWERMODE1 0xE5
#define WIN_SLEEPNOW1 0xE6
#define WIN_FLUSH_CACHE 0xE7
#define WIN_WRITE_BUFFER 0xE8
#define WIN_WRITE_SAME 0xE9
#define WIN_FLUSH_CACHE_EXT 0xEA
#define WIN_IDENTIFY 0xEC
#define WIN_MEDIAEJECT 0xED
#define WIN_IDENTIFY_DMA 0xEE
#define WIN_SETFEATURES 0xEF
#define EXABYTE_ENABLE_NEST 0xF0
#define WIN_SECURITY_SET_PASS 0xF1
#define WIN_SECURITY_UNLOCK 0xF2
#define WIN_SECURITY_ERASE_PREPARE 0xF3
#define WIN_SECURITY_ERASE_UNIT 0xF4
#define WIN_SECURITY_FREEZE_LOCK 0xF5
#define WIN_SECURITY_DISABLE 0xF6
#define WIN_READ_NATIVE_MAX 0xF8
#define WIN_SET_MAX 0xF9
#define DISABLE_SEAGATE 0xFB
#define SMART_READ_VALUES 0xD0
#define SMART_READ_THRESHOLDS 0xD1
#define SMART_AUTOSAVE 0xD2
#define SMART_SAVE 0xD3
#define SMART_IMMEDIATE_OFFLINE 0xD4
#define SMART_READ_LOG_SECTOR 0xD5
#define SMART_WRITE_LOG_SECTOR 0xD6
#define SMART_WRITE_THRESHOLDS 0xD7
#define SMART_ENABLE 0xD8
#define SMART_DISABLE 0xD9
#define SMART_STATUS 0xDA
#define SMART_AUTO_OFFLINE 0xDB
#define SMART_LCYL_PASS 0x4F
#define SMART_HCYL_PASS 0xC2
#define SETFEATURES_EN_8BIT 0x01
#define SETFEATURES_EN_WCACHE 0x02
#define SETFEATURES_DIS_DEFECT 0x04
#define SETFEATURES_EN_APM 0x05
#define SETFEATURES_EN_SAME_R 0x22
#define SETFEATURES_DIS_MSN 0x31
#define SETFEATURES_DIS_RETRY 0x33
#define SETFEATURES_EN_AAM 0x42
#define SETFEATURES_RW_LONG 0x44
#define SETFEATURES_SET_CACHE 0x54
#define SETFEATURES_DIS_RLA 0x55
#define SETFEATURES_EN_RI 0x5D
#define SETFEATURES_EN_SI 0x5E
#define SETFEATURES_DIS_RPOD 0x66
#define SETFEATURES_DIS_ECC 0x77
#define SETFEATURES_DIS_8BIT 0x81
#define SETFEATURES_DIS_WCACHE 0x82
#define SETFEATURES_EN_DEFECT 0x84
#define SETFEATURES_DIS_APM 0x85
#define SETFEATURES_EN_ECC 0x88
#define SETFEATURES_EN_MSN 0x95
#define SETFEATURES_EN_RETRY 0x99
#define SETFEATURES_EN_RLA 0xAA
#define SETFEATURES_PREFETCH 0xAB
#define SETFEATURES_EN_REST 0xAC
#define SETFEATURES_4B_RW_LONG 0xBB
#define SETFEATURES_DIS_AAM 0xC2
#define SETFEATURES_EN_RPOD 0xCC
#define SETFEATURES_DIS_RI 0xDD
#define SETFEATURES_EN_SAME_M 0xDD
#define SETFEATURES_DIS_SI 0xDE
#define SECURITY_SET_PASSWORD 0xBA
#define SECURITY_UNLOCK 0xBB
#define SECURITY_ERASE_PREPARE 0xBC
#define SECURITY_ERASE_UNIT 0xBD
#define SECURITY_FREEZE_LOCK 0xBE
#define SECURITY_DISABLE_PASSWORD 0xBF
struct hd_geometry {
  unsigned char heads;
  unsigned char sectors;
  unsigned short cylinders;
  unsigned long start;
};
#define HDIO_GETGEO 0x0301
#define HDIO_GET_UNMASKINTR 0x0302
#define HDIO_GET_MULTCOUNT 0x0304
#define HDIO_GET_QDMA 0x0305
#define HDIO_SET_XFER 0x0306
#define HDIO_OBSOLETE_IDENTITY 0x0307
#define HDIO_GET_KEEPSETTINGS 0x0308
#define HDIO_GET_32BIT 0x0309
#define HDIO_GET_NOWERR 0x030a
#define HDIO_GET_DMA 0x030b
#define HDIO_GET_NICE 0x030c
#define HDIO_GET_IDENTITY 0x030d
#define HDIO_GET_WCACHE 0x030e
#define HDIO_GET_ACOUSTIC 0x030f
#define HDIO_GET_ADDRESS 0x0310
#define HDIO_GET_BUSSTATE 0x031a
#define HDIO_TRISTATE_HWIF 0x031b
#define HDIO_DRIVE_RESET 0x031c
#define HDIO_DRIVE_TASKFILE 0x031d
#define HDIO_DRIVE_TASK 0x031e
#define HDIO_DRIVE_CMD 0x031f
#define HDIO_DRIVE_CMD_AEB HDIO_DRIVE_TASK
#define HDIO_SET_MULTCOUNT 0x0321
#define HDIO_SET_UNMASKINTR 0x0322
#define HDIO_SET_KEEPSETTINGS 0x0323
#define HDIO_SET_32BIT 0x0324
#define HDIO_SET_NOWERR 0x0325
#define HDIO_SET_DMA 0x0326
#define HDIO_SET_PIO_MODE 0x0327
#define HDIO_SCAN_HWIF 0x0328
#define HDIO_UNREGISTER_HWIF 0x032a
#define HDIO_SET_NICE 0x0329
#define HDIO_SET_WCACHE 0x032b
#define HDIO_SET_ACOUSTIC 0x032c
#define HDIO_SET_BUSSTATE 0x032d
#define HDIO_SET_QDMA 0x032e
#define HDIO_SET_ADDRESS 0x032f
enum {
  BUSSTATE_OFF = 0,
  BUSSTATE_ON,
  BUSSTATE_TRISTATE
};
#define __NEW_HD_DRIVE_ID
struct hd_driveid {
  unsigned short config;
  unsigned short cyls;
  unsigned short reserved2;
  unsigned short heads;
  unsigned short track_bytes;
  unsigned short sector_bytes;
  unsigned short sectors;
  unsigned short vendor0;
  unsigned short vendor1;
  unsigned short vendor2;
  unsigned char serial_no[20];
  unsigned short buf_type;
  unsigned short buf_size;
  unsigned short ecc_bytes;
  unsigned char fw_rev[8];
  unsigned char model[40];
  unsigned char max_multsect;
  unsigned char vendor3;
  unsigned short dword_io;
  unsigned char vendor4;
  unsigned char capability;
  unsigned short reserved50;
  unsigned char vendor5;
  unsigned char tPIO;
  unsigned char vendor6;
  unsigned char tDMA;
  unsigned short field_valid;
  unsigned short cur_cyls;
  unsigned short cur_heads;
  unsigned short cur_sectors;
  unsigned short cur_capacity0;
  unsigned short cur_capacity1;
  unsigned char multsect;
  unsigned char multsect_valid;
  unsigned int lba_capacity;
  unsigned short dma_1word;
  unsigned short dma_mword;
  unsigned short eide_pio_modes;
  unsigned short eide_dma_min;
  unsigned short eide_dma_time;
  unsigned short eide_pio;
  unsigned short eide_pio_iordy;
  unsigned short words69_70[2];
  unsigned short words71_74[4];
  unsigned short queue_depth;
  unsigned short words76_79[4];
  unsigned short major_rev_num;
  unsigned short minor_rev_num;
  unsigned short command_set_1;
  unsigned short command_set_2;
  unsigned short cfsse;
  unsigned short cfs_enable_1;
  unsigned short cfs_enable_2;
  unsigned short csf_default;
  unsigned short dma_ultra;
  unsigned short trseuc;
  unsigned short trsEuc;
  unsigned short CurAPMvalues;
  unsigned short mprc;
  unsigned short hw_config;
  unsigned short acoustic;
  unsigned short msrqs;
  unsigned short sxfert;
  unsigned short sal;
  unsigned int spg;
  unsigned long long lba_capacity_2;
  unsigned short words104_125[22];
  unsigned short last_lun;
  unsigned short word127;
  unsigned short dlf;
  unsigned short csfo;
  unsigned short words130_155[26];
  unsigned short word156;
  unsigned short words157_159[3];
  unsigned short cfa_power;
  unsigned short words161_175[15];
  unsigned short words176_205[30];
  unsigned short words206_254[49];
  unsigned short integrity_word;
};
#define IDE_NICE_DSC_OVERLAP (0)
#define IDE_NICE_ATAPI_OVERLAP (1)
#define IDE_NICE_1 (3)
#define IDE_NICE_0 (2)
#define IDE_NICE_2 (4)
#endif
```