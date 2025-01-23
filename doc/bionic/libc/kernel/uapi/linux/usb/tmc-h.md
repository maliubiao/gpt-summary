Response:
Let's break down the thought process for analyzing this USBTMC header file.

**1. Understanding the Context:**

The initial prompt highlights that this is a header file within the Android Bionic library, specifically related to USB Test and Measurement Class (USBTMC) and a potential extension (USBTMC488). This immediately tells me it's about interacting with USB devices that adhere to these protocols, primarily for controlling and communicating with test equipment.

**2. Deconstructing the File - Identifying Key Sections:**

I'll scan the file for distinct sections and analyze each:

* **Header Guards:** `#ifndef __LINUX_USB_TMC_H` and `#define __LINUX_USB_TMC_H`. Standard practice to prevent multiple inclusions. I acknowledge its purpose but it's not a functional part of the protocol itself.

* **Includes:** `#include <linux/types.h>`. This tells me it uses standard Linux types, which is expected for kernel-level interaction or definitions intended for kernel modules.

* **Status Codes:**  `USBTMC_STATUS_...`. These are clearly defined constants indicating the result of an operation. I'll make a note that these represent states within the USBTMC protocol.

* **Request Codes:** `USBTMC_REQUEST_...` and `USBTMC488_REQUEST_...`. These look like commands sent to the USB device. I'll group them and note the distinction between standard USBTMC and the 488 extension.

* **Structures:** `struct usbtmc_request`, `struct usbtmc_ctrlrequest`, `struct usbtmc_termchar`, `struct usbtmc_message`. These are data structures used for communication. I'll analyze each field and its potential purpose based on the names. The `__attribute__((packed))` is important, signifying no padding in the structure, crucial for binary communication.

* **Flags:** `USBTMC_FLAG_...`. These look like bitmasks to modify the behavior of certain operations.

* **IOCTLs:** `USBTMC_IOCTL_...` and `USBTMC488_IOCTL_...`. This is a critical section. IOCTLs are the primary mechanism for user-space applications to interact with kernel drivers. I'll analyze each IOCTL, noting the associated data structures or types, and the direction of data flow (_IO, _IOW, _IOR, _IOWR). The numbering scheme might suggest related functionalities.

* **Capabilities:** `USBTMC488_CAPABILITY_...`. These are bitmasks representing supported features of a USBTMC488 device.

* **Footer:** `#endif`. Closing the header guard.

**3. Connecting to Android:**

Knowing this is within Bionic, I'll consider how Android applications might use these definitions. The most likely scenario is through system calls that eventually interact with a USB driver. NDK would be the direct interface for C/C++ developers.

**4. Elaborating on Functionality:**

Based on the identified sections, I can deduce the following functionalities:

* **Status Reporting:** The status codes indicate the outcome of commands.
* **Control Operations:** Request codes and related IOCTLs suggest actions like aborting transfers, clearing buffers, and initiating communication.
* **Data Transfer:** `usbtmc_message` structure and `USBTMC_IOCTL_WRITE`/`READ` are clearly for sending and receiving data.
* **Configuration:**  `usbtmc_termchar` and related IOCTLs hint at setting termination characters.
* **USB Control Requests:** `usbtmc_ctrlrequest` and `USBTMC_IOCTL_CTRL_REQUEST` allow sending arbitrary USB control commands.
* **Timeouts:** `USBTMC_IOCTL_GET_TIMEOUT`/`SET_TIMEOUT`.
* **USBTMC488 Extensions:**  The `USBTMC488_` prefixed constants and IOCTLs indicate support for the IEEE 488.2 standard, adding functionalities like triggering, remote control, and status byte reading.

**5. Considering Implementation (libc functions):**

This header file *defines* the interface, it doesn't *implement* the functions. The implementation would be in a kernel driver for USBTMC. However, I can discuss how libc functions like `ioctl()` would *use* these definitions.

**6. Dynamic Linker (Not Directly Relevant):**

This header file doesn't directly involve the dynamic linker. It defines constants and structures. The *driver* might be a kernel module, and user-space libraries interacting with the driver *would* be linked. I'll need to clarify this distinction.

**7. Logic Reasoning (Assumptions and Examples):**

I can create hypothetical scenarios:

* **Scenario:** Sending a command. Assume an application wants to send a "*IDN?*" command. It would use `USBTMC_IOCTL_WRITE` with a `usbtmc_message` containing this data. The `transferred` field would initially be 0, and after the call, it should be the size of the sent command.
* **Scenario:** Checking status. After initiating an abort, the application might use `USBTMC_IOCTL_CHECK_ABORT_BULK_OUT_STATUS`.

**8. Common Usage Errors:**

I'll think about typical mistakes when working with low-level interfaces:

* Incorrect IOCTL numbers.
* Mismatched data structures.
* Incorrect buffer sizes.
* Not handling errors returned by `ioctl()`.

**9. Android Framework and Frida Hooking:**

I'll trace the path from Android framework to the kernel:

* **High-level:**  Android might have specific APIs for interacting with test equipment (though this is less common directly within the standard framework).
* **NDK:**  C/C++ developers would use standard Linux system calls like `open()`, `ioctl()`, `read()`, `write()`.
* **Kernel:**  The `ioctl()` call would dispatch to the appropriate USBTMC driver.

For Frida, I'll demonstrate hooking the `ioctl()` system call and filtering for the relevant `USBTMC_IOCTL_NR`.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on *implementing* the functions. I need to remember this header *defines* the interface.
* I need to be careful to distinguish between user-space (libc) and kernel-space (driver) components.
* The dynamic linker isn't directly involved in *this file*, but it's relevant to how applications using these definitions are built.

By following this structured thought process, I can systematically analyze the header file and provide a comprehensive answer covering its functionality, its relationship to Android, and how it's used.
这个头文件 `bionic/libc/kernel/uapi/linux/usb/tmc.handroid` 定义了 Linux 内核中用于 USB 测试和测量类 (USBTMC) 设备的接口。Bionic 作为 Android 的 C 库，提供了用户空间程序与内核交互的桥梁。这个头文件中的定义使得用户空间程序可以通过系统调用与 USBTMC 设备进行通信。

**它的功能:**

这个头文件主要定义了以下内容，共同构成了与 USBTMC 设备交互的接口：

1. **状态码 (Status Codes):** 定义了操作执行结果的状态，例如 `USBTMC_STATUS_SUCCESS` (成功), `USBTMC_STATUS_PENDING` (挂起), `USBTMC_STATUS_FAILED` (失败) 等。
2. **请求码 (Request Codes):**  定义了通过 USB 控制传输发送给设备的控制请求，用于执行特定的操作，例如中止批量传输、清除设备状态、获取设备能力等。区分了标准 USBTMC 请求和 USBTMC488 (基于 IEEE 488.2 标准的扩展) 请求。
3. **数据结构 (Data Structures):** 定义了用于与设备通信的数据结构，包括：
    * `struct usbtmc_request`: 用于描述 USB 控制请求的通用结构。
    * `struct usbtmc_ctrlrequest`: 用于发送带数据的 USB 控制请求。
    * `struct usbtmc_termchar`: 用于配置传输的终止字符。
    * `struct usbtmc_message`: 用于描述批量数据传输，包含传输大小、已传输大小、标志和数据指针。
4. **标志位 (Flags):** 定义了用于修改传输行为的标志，例如 `USBTMC_FLAG_ASYNC` (异步传输), `USBTMC_FLAG_APPEND` (追加数据) 等。
5. **IO 控制命令 (IO Control Commands - IOCTLs):** 定义了通过 `ioctl` 系统调用与 USBTMC 驱动程序通信的命令。这些命令覆盖了各种操作，例如触发指示灯、清除设备、中止传输、配置超时、发送和接收数据等。同样区分了标准 USBTMC IOCTL 和 USBTMC488 IOCTL。
6. **能力常量 (Capability Constants):** 定义了 USBTMC488 设备可以支持的特定功能，例如触发、基本功能、远程控制、本地锁定等。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 系统底层与硬件交互的一部分，特别是与通过 USB 连接的测试和测量设备进行通信。

**举例说明：**

假设一个 Android 应用需要控制一个连接到设备的频谱分析仪 (它实现了 USBTMC 协议)。

1. **发送命令到设备:** 应用可能需要发送一个 SCPI 命令 (Standard Commands for Programmable Instruments) 来设置频谱分析仪的中心频率。 这可以通过使用 `USBTMC_IOCTL_WRITE` IOCTL 来实现，将命令数据放在 `struct usbtmc_message` 的 `message` 字段中。
2. **从设备读取数据:** 应用发送命令后，可能需要从频谱分析仪读取测量结果。这可以通过使用 `USBTMC_IOCTL_READ` IOCTL 来实现，接收到的数据会填充 `struct usbtmc_message` 的 `message` 字段指向的缓冲区。
3. **配置设备参数:** 应用可能需要配置设备的某些参数，例如设置终止字符。这可以通过使用 `USBTMC_IOCTL_CONFIG_TERMCHAR` IOCTL 来实现，传递 `struct usbtmc_termchar` 结构来设置终止字符和是否启用。
4. **处理错误:** 如果设备操作失败，驱动程序可能会返回带有 `USBTMC_STATUS_FAILED` 状态码的响应。应用程序需要检查这些状态码并采取相应的错误处理措施。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含** libc 函数的实现。它只是定义了内核接口。libc 函数（例如 `open`, `close`, `ioctl`, `read`, `write` 等）是 C 库提供的，用于与操作系统内核进行交互。

当 Android 应用使用这些 libc 函数与 USBTMC 设备交互时，流程如下：

1. **`open()`:**  应用程序使用 `open()` 系统调用打开表示 USBTMC 设备的设备文件 (例如 `/dev/usbtmc0`)。`open()` 函数在 libc 中的实现会调用内核的 `sys_open` 系统调用，内核会找到对应的设备驱动程序 (即 USBTMC 驱动)。
2. **`ioctl()`:**  应用程序使用 `ioctl()` 系统调用，并传入这个头文件中定义的 `USBTMC_IOCTL_*` 命令以及相应的参数结构。`ioctl()` 函数在 libc 中的实现会调用内核的 `sys_ioctl` 系统调用。内核会根据传入的设备文件和 IOCTL 命令，将请求传递给 USBTMC 设备驱动程序。驱动程序会解析 IOCTL 命令和参数，并与 USBTMC 设备进行实际的通信 (通常通过 USB 控制传输或批量传输)。
3. **`read()` 和 `write()`:** 对于批量数据传输，应用程序可以使用 `read()` 和 `write()` 系统调用。libc 中的 `read()` 和 `write()` 会调用内核的 `sys_read` 和 `sys_write` 系统调用。内核会将这些请求传递给 USBTMC 驱动程序，驱动程序会通过 USB 批量端点与设备进行数据交换。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库 (`.so` 文件) 并解析库之间的依赖关系，然后将库中的符号 (函数、变量等) 链接到调用者的地址空间。

然而，如果用户空间应用程序需要使用自定义的库来处理 USBTMC 通信，那么 dynamic linker 就会参与进来。

**so 布局样本：**

假设你有一个名为 `libusbtmc_helper.so` 的共享库，它封装了与 USBTMC 设备通信的逻辑。该库可能包含使用 `ioctl` 系统调用以及这个头文件中定义的常量和结构的函数。

```
libusbtmc_helper.so 的布局可能如下：

.text       # 包含可执行代码
.data       # 包含已初始化的全局变量
.bss        # 包含未初始化的全局变量
.rodata     # 包含只读数据
.symtab     # 符号表，包含库中定义的符号
.strtab     # 字符串表，包含符号名称等字符串
.dynsym     # 动态符号表
.dynstr     # 动态字符串表
.plt        # 程序链接表 (Procedure Linkage Table)
.got        # 全局偏移表 (Global Offset Table)
... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接：** 当你编译使用 `libusbtmc_helper.so` 的应用程序时，编译器会记录对该库中函数的引用。链接器会将这些引用标记为需要动态链接。
2. **程序启动：** 当 Android 启动你的应用程序时，dynamic linker 会被加载。
3. **加载共享库：** Dynamic linker 会根据应用程序的依赖信息加载 `libusbtmc_helper.so` 到内存中的某个地址。
4. **符号解析：** Dynamic linker 会解析应用程序中对 `libusbtmc_helper.so` 中函数的未定义引用。它会查找 `libusbtmc_helper.so` 的 `.dynsym` 和 `.dynstr` 段，找到匹配的符号，并将应用程序的调用地址重定向到 `libusbtmc_helper.so` 中对应函数的地址。这通常通过修改应用程序的 `.plt` 和 `.got` 表来实现。

**假设输入与输出 (对于逻辑推理):**

假设我们使用 `USBTMC_IOCTL_WRITE` 发送一个命令到设备。

**假设输入：**

* `fd`:  打开的 USBTMC 设备文件描述符。
* `ioctl_cmd`: `USBTMC_IOCTL_WRITE`
* `argp`: 指向 `struct usbtmc_message` 的指针，其内容如下：
    * `transfer_size`:  要发送的命令字符串的长度 (例如，`strlen("*IDN?\n") + 1`)
    * `transferred`:  初始值为 0。
    * `flags`:  通常为 0。
    * `message`:  指向包含命令字符串的缓冲区 (例如，`"*IDN?\n"` )。

**预期输出：**

* `ioctl()` 系统调用成功返回 0。
* `argp->transferred`:  更新为实际发送的字节数，应该等于 `transfer_size`。
* USBTMC 设备接收到命令 `"*IDN?\n"`。

**假设输入：**

假设我们使用 `USBTMC_IOCTL_READ` 从设备读取响应。

**假设输入：**

* `fd`:  打开的 USBTMC 设备文件描述符。
* `ioctl_cmd`: `USBTMC_IOCTL_READ`
* `argp`: 指向 `struct usbtmc_message` 的指针，其内容如下：
    * `transfer_size`:  要读取的最大字节数 (例如，预期的最大响应长度)。
    * `transferred`:  初始值为 0。
    * `flags`:  通常为 0。
    * `message`:  指向用于存储接收数据的缓冲区。

**预期输出：**

* `ioctl()` 系统调用成功返回 0。
* `argp->transferred`:  更新为实际接收到的字节数。
* `argp->message`:  包含从设备读取的响应数据。

**用户或编程常见的使用错误:**

1. **IOCTL 命令错误:** 使用了错误的 `USBTMC_IOCTL_*` 常量，导致内核无法识别操作。
2. **数据结构错误:**  传递给 `ioctl` 的参数结构 (`struct usbtmc_message` 等) 中的字段设置不正确，例如 `transfer_size` 与实际数据长度不符。
3. **缓冲区溢出:** 在使用 `USBTMC_IOCTL_READ` 时，提供的接收缓冲区 (`message`) 太小，无法容纳设备返回的所有数据。
4. **设备文件未打开:**  在调用 `ioctl` 前忘记使用 `open()` 打开 USBTMC 设备文件。
5. **权限问题:** 应用程序可能没有足够的权限访问 USBTMC 设备文件 (通常位于 `/dev` 目录下)。
6. **错误处理不足:**  没有检查 `ioctl` 等系统调用的返回值，忽略了可能发生的错误。
7. **超时设置不当:**  没有设置合适的超时时间，导致程序在设备无响应时一直等待。
8. **不正确的标志位使用:**  错误地使用了 `USBTMC_FLAG_*` 标志位，导致非预期的传输行为。

**Android framework 或 NDK 是如何一步步的到达这里:**

1. **Android Framework (Java/Kotlin):**
   - Android Framework 本身通常不会直接使用这些底层的 USBTMC 接口。
   - 如果有需要与 USBTMC 设备交互的功能，可能会通过以下方式：
     - **USB Host API:**  Android Framework 提供了 `android.hardware.usb` 包，允许应用程序与连接的 USB 设备进行通信。开发者可以使用 `UsbDeviceConnection` 类来发送控制请求和批量传输。
     - **HAL (Hardware Abstraction Layer):**  设备制造商可能会实现一个 HAL 模块，用于封装与特定硬件的交互，包括 USBTMC 设备。Framework 可以通过 HAL 与设备通信。

2. **NDK (Native Development Kit - C/C++):**
   - 使用 NDK 开发的 C/C++ 应用程序可以直接使用标准的 Linux 系统调用与 USBTMC 设备交互。
   - **打开设备:** 使用 `open("/dev/usbtmc0", O_RDWR)` 打开 USBTMC 设备文件。
   - **执行 IO 控制:** 使用 `ioctl(fd, USBTMC_IOCTL_WRITE, &message)` 发送命令，使用 `ioctl(fd, USBTMC_IOCTL_READ, &message)` 接收数据，等等。
   - **读取/写入数据:**  对于批量传输，可以使用 `read(fd, buffer, size)` 和 `write(fd, buffer, size)`。
   - **错误处理:** 检查系统调用的返回值。

**Frida hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 拦截 `ioctl` 系统调用，并过滤出与 USBTMC 相关的操作的示例：

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.findExportByName(null, 'ioctl');

  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是 USBTMC 相关的 IOCTL 命令
        if ((request & 0xff) === 91) { // USBTMC_IOC_NR 的值是 91
          console.log("ioctl called with USBTMC command:");
          console.log("  File Descriptor:", fd);
          console.log("  Request Code:", request.toString(16));

          // 可以进一步解析参数，例如当 request 是 USBTMC_IOCTL_WRITE 或 USBTMC_IOCTL_READ 时，解析 struct usbtmc_message
          if (request === 0xc0085b0d || request === 0xc0085b0e) { // USBTMC_IOCTL_WRITE 和 USBTMC_IOCTL_READ 的具体值
            const messagePtr = args[2];
            if (messagePtr) {
              const transfer_size = messagePtr.readU32();
              const transferred = messagePtr.add(4).readU32();
              const flags = messagePtr.add(8).readU32();
              const message = messagePtr.add(12).readPointer();
              const messageContent = message.readCString(transfer_size);

              console.log("  struct usbtmc_message:");
              console.log("    transfer_size:", transfer_size);
              console.log("    transferred:", transferred);
              console.log("    flags:", flags);
              console.log("    message:", messageContent);
            }
          }
        }
      },
      onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
      }
    });
  } else {
    console.log("Failed to find ioctl export");
  }
} else {
  console.log("This script is for Linux platforms.");
}
```

**Frida Hook 解释:**

1. **查找 `ioctl`:**  使用 `Module.findExportByName(null, 'ioctl')` 找到 `ioctl` 系统调用在内存中的地址。
2. **拦截 `ioctl`:** 使用 `Interceptor.attach()` 拦截对 `ioctl` 函数的调用。
3. **`onEnter` 回调:** 在 `ioctl` 函数执行之前调用。
   - 获取文件描述符 (`fd`) 和请求码 (`request`)。
   - 检查请求码是否属于 USBTMC 相关的 IOCTL (通过检查高位字节，`USBTMC_IOC_NR` 的值)。
   - 打印相关的调用信息。
   - 如果是 `USBTMC_IOCTL_WRITE` 或 `USBTMC_IOCTL_READ`，则尝试解析 `struct usbtmc_message` 结构，读取传输大小、标志以及要发送/接收的数据。
4. **`onLeave` 回调:** 在 `ioctl` 函数执行之后调用 (本例中被注释掉，可以用来查看返回值)。

通过这个 Frida 脚本，你可以在 Android 设备上运行目标应用程序，并观察它如何使用 `ioctl` 系统调用与 USBTMC 设备进行通信，从而调试底层的 USB 交互过程。你需要根据具体的 Android 版本和架构调整脚本中硬编码的 IOCTL 值。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/usb/tmc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_USB_TMC_H
#define __LINUX_USB_TMC_H
#include <linux/types.h>
#define USBTMC_STATUS_SUCCESS 0x01
#define USBTMC_STATUS_PENDING 0x02
#define USBTMC_STATUS_FAILED 0x80
#define USBTMC_STATUS_TRANSFER_NOT_IN_PROGRESS 0x81
#define USBTMC_STATUS_SPLIT_NOT_IN_PROGRESS 0x82
#define USBTMC_STATUS_SPLIT_IN_PROGRESS 0x83
#define USBTMC_REQUEST_INITIATE_ABORT_BULK_OUT 1
#define USBTMC_REQUEST_CHECK_ABORT_BULK_OUT_STATUS 2
#define USBTMC_REQUEST_INITIATE_ABORT_BULK_IN 3
#define USBTMC_REQUEST_CHECK_ABORT_BULK_IN_STATUS 4
#define USBTMC_REQUEST_INITIATE_CLEAR 5
#define USBTMC_REQUEST_CHECK_CLEAR_STATUS 6
#define USBTMC_REQUEST_GET_CAPABILITIES 7
#define USBTMC_REQUEST_INDICATOR_PULSE 64
#define USBTMC488_REQUEST_READ_STATUS_BYTE 128
#define USBTMC488_REQUEST_REN_CONTROL 160
#define USBTMC488_REQUEST_GOTO_LOCAL 161
#define USBTMC488_REQUEST_LOCAL_LOCKOUT 162
struct usbtmc_request {
  __u8 bRequestType;
  __u8 bRequest;
  __u16 wValue;
  __u16 wIndex;
  __u16 wLength;
} __attribute__((packed));
struct usbtmc_ctrlrequest {
  struct usbtmc_request req;
  void  * data;
} __attribute__((packed));
struct usbtmc_termchar {
  __u8 term_char;
  __u8 term_char_enabled;
} __attribute__((packed));
#define USBTMC_FLAG_ASYNC 0x0001
#define USBTMC_FLAG_APPEND 0x0002
#define USBTMC_FLAG_IGNORE_TRAILER 0x0004
struct usbtmc_message {
  __u32 transfer_size;
  __u32 transferred;
  __u32 flags;
  void  * message;
} __attribute__((packed));
#define USBTMC_IOC_NR 91
#define USBTMC_IOCTL_INDICATOR_PULSE _IO(USBTMC_IOC_NR, 1)
#define USBTMC_IOCTL_CLEAR _IO(USBTMC_IOC_NR, 2)
#define USBTMC_IOCTL_ABORT_BULK_OUT _IO(USBTMC_IOC_NR, 3)
#define USBTMC_IOCTL_ABORT_BULK_IN _IO(USBTMC_IOC_NR, 4)
#define USBTMC_IOCTL_CLEAR_OUT_HALT _IO(USBTMC_IOC_NR, 6)
#define USBTMC_IOCTL_CLEAR_IN_HALT _IO(USBTMC_IOC_NR, 7)
#define USBTMC_IOCTL_CTRL_REQUEST _IOWR(USBTMC_IOC_NR, 8, struct usbtmc_ctrlrequest)
#define USBTMC_IOCTL_GET_TIMEOUT _IOR(USBTMC_IOC_NR, 9, __u32)
#define USBTMC_IOCTL_SET_TIMEOUT _IOW(USBTMC_IOC_NR, 10, __u32)
#define USBTMC_IOCTL_EOM_ENABLE _IOW(USBTMC_IOC_NR, 11, __u8)
#define USBTMC_IOCTL_CONFIG_TERMCHAR _IOW(USBTMC_IOC_NR, 12, struct usbtmc_termchar)
#define USBTMC_IOCTL_WRITE _IOWR(USBTMC_IOC_NR, 13, struct usbtmc_message)
#define USBTMC_IOCTL_READ _IOWR(USBTMC_IOC_NR, 14, struct usbtmc_message)
#define USBTMC_IOCTL_WRITE_RESULT _IOWR(USBTMC_IOC_NR, 15, __u32)
#define USBTMC_IOCTL_API_VERSION _IOR(USBTMC_IOC_NR, 16, __u32)
#define USBTMC488_IOCTL_GET_CAPS _IOR(USBTMC_IOC_NR, 17, unsigned char)
#define USBTMC488_IOCTL_READ_STB _IOR(USBTMC_IOC_NR, 18, unsigned char)
#define USBTMC488_IOCTL_REN_CONTROL _IOW(USBTMC_IOC_NR, 19, unsigned char)
#define USBTMC488_IOCTL_GOTO_LOCAL _IO(USBTMC_IOC_NR, 20)
#define USBTMC488_IOCTL_LOCAL_LOCKOUT _IO(USBTMC_IOC_NR, 21)
#define USBTMC488_IOCTL_TRIGGER _IO(USBTMC_IOC_NR, 22)
#define USBTMC488_IOCTL_WAIT_SRQ _IOW(USBTMC_IOC_NR, 23, __u32)
#define USBTMC_IOCTL_MSG_IN_ATTR _IOR(USBTMC_IOC_NR, 24, __u8)
#define USBTMC_IOCTL_AUTO_ABORT _IOW(USBTMC_IOC_NR, 25, __u8)
#define USBTMC_IOCTL_GET_STB _IOR(USBTMC_IOC_NR, 26, __u8)
#define USBTMC_IOCTL_GET_SRQ_STB _IOR(USBTMC_IOC_NR, 27, __u8)
#define USBTMC_IOCTL_CANCEL_IO _IO(USBTMC_IOC_NR, 35)
#define USBTMC_IOCTL_CLEANUP_IO _IO(USBTMC_IOC_NR, 36)
#define USBTMC488_CAPABILITY_TRIGGER 1
#define USBTMC488_CAPABILITY_SIMPLE 2
#define USBTMC488_CAPABILITY_REN_CONTROL 2
#define USBTMC488_CAPABILITY_GOTO_LOCAL 2
#define USBTMC488_CAPABILITY_LOCAL_LOCKOUT 2
#define USBTMC488_CAPABILITY_488_DOT_2 4
#define USBTMC488_CAPABILITY_DT1 16
#define USBTMC488_CAPABILITY_RL1 32
#define USBTMC488_CAPABILITY_SR1 64
#define USBTMC488_CAPABILITY_FULL_SCPI 128
#endif
```