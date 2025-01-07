Response:
Let's break down the thought process for answering the user's request about the `usbdevice_fs.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this specific header file within the Android Bionic library. The key is to extract the information it provides and relate it to Android's USB interaction mechanisms. The prompt also has several specific sub-questions that need to be addressed systematically.

**2. Initial Analysis of the Header File:**

The file name `usbdevice_fs.h` and its location within `bionic/libc/kernel/uapi/linux/` immediately suggest it's a *userspace API* (UAPI) header providing definitions for interacting with the *Linux kernel's USB device filesystem*. This is a crucial starting point. The "auto-generated" comment indicates it reflects the kernel's interface, not Bionic-specific logic.

**3. Identifying Key Components:**

Scanning the header reveals a collection of `struct` definitions and `#define` constants. These are the building blocks of the API. The structs represent data structures used for communication with the kernel, and the defines represent constants, ioctl codes, and flags.

**4. Categorizing Functionality:**

To make the information digestible, it's helpful to group the elements by their purpose. I mentally categorized them into:

* **Data Transfer Structures:**  `usbdevfs_ctrltransfer`, `usbdevfs_bulktransfer`, `usbdevfs_urb`, `usbdevfs_iso_packet_desc`. These clearly deal with sending and receiving data over USB.
* **Device Configuration/Management:** `usbdevfs_setinterface`, `usbdevfs_setconfiguration`, `usbdevfs_disconnectsignal`, `usbdevfs_getdriver`, `usbdevfs_connectinfo`, `usbdevfs_conninfo_ex`, `usbdevfs_disconnect_claim`. These manage the state and identification of the USB device.
* **ioctl Structures:** `usbdevfs_ioctl`, `usbdevfs_hub_portinfo`. These represent generic control mechanisms.
* **Capabilities and Status:** The various `USBDEVFS_CAP_*` defines and the `USBDEVFS_GET_SPEED` ioctl.
* **Stream Management:** `usbdevfs_streams`, `USBDEVFS_ALLOC_STREAMS`, `USBDEVFS_FREE_STREAMS`. This points to a more advanced feature for bulk transfers.
* **ioctl Definitions:**  The large block of `#define USBDEVFS_*` lines. These are the actual *system call numbers* or *request codes* used with the `ioctl()` system call.

**5. Relating to Android Functionality:**

This is where the "Android context" comes in. I started thinking about how Android applications and the Android framework interact with USB devices. Key areas include:

* **Accessing USB Devices:** Android uses the Linux device filesystem (specifically `/dev/bus/usb/`) to represent USB devices. Applications need a way to open and interact with these device files. This header provides the low-level interface for that.
* **USB Host Mode:** Android devices often act as USB hosts, connecting to peripherals. The functions defined here are essential for this role.
* **USB OTG (On-The-Go):**  The ability for Android devices to switch between host and device modes.
* **Hardware Abstraction Layer (HAL):**  Android's HALs for USB would use these definitions internally to communicate with the kernel.
* **NDK APIs:**  The NDK likely provides wrappers around these low-level ioctls to make USB access easier for native developers.

**6. Explaining `libc` Functions (Implicitly):**

The header itself *doesn't define* `libc` functions. Instead, it defines the *data structures and constants* that `libc` functions (like `ioctl()`, `open()`, `close()`, `read()`, `write()`, and memory management functions) *use* to interact with the USB device filesystem. The explanation needed to focus on *how* these structures are passed to `ioctl()`.

**7. Dynamic Linker and `.so` Layout:**

Since this header is part of the kernel UAPI, it doesn't directly involve the dynamic linker. The `.so` files that *use* these definitions (like a USB HAL or an NDK library) would have a standard ELF layout. The explanation needed to highlight this separation and provide a generic example of `.so` structure.

**8. Logical Inference and Examples:**

For each major structure or ioctl, it's important to provide hypothetical input and output scenarios to illustrate their usage. For example, with `usbdevfs_ctrltransfer`, demonstrating how to send a request and receive data.

**9. Common User Errors:**

Think about typical mistakes developers make when working with low-level APIs:

* Incorrect buffer sizes.
* Incorrectly setting flags.
* Not handling timeouts.
* Permissions issues when accessing device files.
* Incorrectly interpreting return codes.

**10. Android Framework and NDK Path:**

This requires tracing the flow from the application level down to the kernel:

* **Java Application:** Uses `UsbManager` in the Android SDK.
* **Framework (Java):**  `UsbManager` interacts with system services.
* **System Services (Native):**  Use Binder to communicate with lower-level components.
* **HAL (Hardware Abstraction Layer):**  The USB HAL implementation (likely in C/C++) opens the device file and uses `ioctl()` with the structures defined in this header.
* **Kernel:**  Receives the `ioctl()` calls and interacts with the USB driver.
* **NDK:**  The NDK provides C/C++ APIs that might wrap these lower-level `ioctl()` calls directly or indirectly through libraries.

**11. Frida Hook Example:**

A practical example using Frida is crucial for demonstrating how to intercept these calls. Focus on hooking the `ioctl()` system call and filtering for calls related to the USB device file descriptor.

**12. Structuring the Answer:**

Organize the information logically using headings and bullet points to make it easy to read and understand. Address each part of the user's request clearly.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This is about USB."  -> **Refinement:** "It's about the *userspace interface* to the Linux USB subsystem."
* **Initial thought:** "Need to explain each struct." -> **Refinement:** "Explain the *purpose* of each struct and how it's used in the context of USB communication."
* **Initial thought:** "Focus on Bionic `libc` functions." -> **Refinement:** "Focus on the `ioctl()` system call and how these structures are arguments to it. Bionic `libc` *provides* `ioctl()`, but this header defines the *data* for it."
* **Initial thought:** "Explain dynamic linking in detail." -> **Refinement:**  "Acknowledge the separation. The header itself isn't linked. Explain how *using* code might be linked."

By following this structured approach and continuously refining the understanding, it's possible to generate a comprehensive and accurate answer to the user's request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/usbdevice_fs.h` 这个头文件的功能。

**功能概述**

这个头文件定义了用户空间程序与 Linux 内核 USB 设备文件系统进行交互所需的各种数据结构和常量。它本质上是用户空间程序调用 `ioctl` 系统调用来控制和与 USB 设备通信的接口规范。通过这些定义，用户空间的程序可以直接向 USB 设备发送控制、批量、中断和同步传输请求，获取设备信息，管理设备连接和断开等。

**与 Android 功能的关系及举例**

这个头文件对于 Android 系统的 USB 功能至关重要。Android 设备经常需要作为 USB 主机（连接其他 USB 设备）或 USB 设备（连接到电脑）。这个头文件中定义的接口是实现这些功能的基石。

**举例说明:**

* **USB 调试 (ADB):** 当你使用 ADB 连接你的 Android 设备到电脑时，电脑上的 ADB 服务会通过 USB 与你的设备进行通信。这种通信的底层就可能涉及到这里定义的结构，例如发送控制命令来建立连接，发送批量数据来传输文件等。
* **USB OTG (On-The-Go):**  当你在 Android 设备上连接 USB 鼠标、键盘或 U 盘时，Android 系统需要识别这些设备并与之交互。这个过程会用到这里定义的接口，例如获取设备的描述符、配置接口、进行数据传输等。
* **USB Audio/Video:**  连接 USB 音频设备或摄像头时，Android 系统需要使用这些接口来传输音频和视频数据。例如，使用同步传输 (`URB_TYPE_ISO`) 来保证实时性。
* **HID 设备:** 连接 USB 键盘、鼠标等 HID (Human Interface Device) 设备时，需要使用中断传输 (`URB_TYPE_INTERRUPT`) 来接收输入事件。

**详细解释每一个 `libc` 函数的功能是如何实现的**

需要明确的是，这个头文件本身**没有定义任何 `libc` 函数**。它定义的是数据结构和常量，这些数据结构会被传递给 `libc` 提供的系统调用接口，尤其是 `ioctl` 函数。

`ioctl` 函数是一个通用的设备控制操作接口。它的原型通常是：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  要操作的文件描述符，通常是通过 `open()` 打开的 USB 设备文件（例如 `/dev/bus/usb/XXX/YYY`）。
* `request`:  一个与设备相关的请求码，通常由宏定义给出，例如 `USBDEVFS_CONTROL`, `USBDEVFS_BULK` 等，这些宏定义在这个头文件中。
* `...`:  可选的参数，通常是一个指向数据结构的指针，这个数据结构的类型取决于 `request` 的值，例如 `struct usbdevfs_ctrltransfer *`。

**实现原理:**

1. **用户空间程序准备数据结构:** 用户空间程序根据要执行的 USB 操作，填充相应的结构体，例如 `usbdevfs_ctrltransfer` 结构体包含控制传输的请求类型、请求码、数据等。
2. **调用 `ioctl`:**  程序调用 `ioctl` 函数，将 USB 设备的文件描述符、对应的 `USBDEVFS_*` 请求码以及指向填充好的数据结构的指针作为参数传递给内核。
3. **内核处理:** Linux 内核接收到 `ioctl` 调用后，会根据文件描述符找到对应的 USB 设备驱动程序。然后，内核会根据 `request` 码和传递的数据结构，调用 USB 设备驱动程序中相应的处理函数。
4. **驱动程序交互:** USB 设备驱动程序会与 USB 硬件控制器进行交互，按照请求执行相应的操作，例如发送 USB 数据包、读取设备状态等。
5. **内核返回结果:**  驱动程序执行完操作后，会将结果写回传递的数据结构中（例如，实际传输的字节数），然后内核将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

这个头文件主要涉及内核接口，**不直接涉及 dynamic linker (动态链接器)**。Dynamic linker 的主要任务是加载共享库 (`.so` 文件) 并解析符号，以便程序能够调用共享库中的函数。

然而，用户空间的程序如果需要使用这里定义的结构体和常量，通常会通过一些库来间接访问，例如 Android 的 USB Host API。这些 API 的底层实现可能会使用 `ioctl` 并传递这里定义的数据结构。这些实现通常会放在 `.so` 文件中。

**`.so` 布局样本 (示例 - 假设一个 USB 相关的 HAL 库):**

```
libusb_hal.so:
    .text          # 代码段，包含 HAL 库的函数实现
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 可读写数据段，可能包含一些全局变量
    .bss           # 未初始化数据段
    .symtab        # 符号表，包含导出的函数和变量
    .strtab        # 字符串表，存储符号名称等字符串
    .dynsym        # 动态符号表，用于动态链接
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译使用 USB HAL 库的程序时，链接器会将程序的目标文件与 `libusb_hal.so` 的导入库进行链接，生成最终的可执行文件或共享库。链接器会在程序中记录需要链接的符号信息。
2. **运行时链接 (Dynamic Linker 的工作):** 当程序启动时，dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 会负责加载程序依赖的共享库，例如 `libusb_hal.so`。
3. **符号解析:** Dynamic linker 会解析程序中对共享库函数的调用，并找到 `libusb_hal.so` 中对应的函数地址。这通常通过查看 `.dynsym` 和 `.dynstr` 表完成。
4. **重定位:** Dynamic linker 会根据 `.rel.dyn` 和 `.rel.plt` 表中的信息，修改程序中的地址引用，使其指向共享库中实际的函数或变量地址。
5. **执行:** 一旦链接完成，程序就可以正常调用 `libusb_hal.so` 中提供的 USB 相关功能。这些功能最终会调用 `ioctl`，并使用 `usbdevice_fs.h` 中定义的数据结构与内核进行交互。

**逻辑推理和假设输入输出**

让我们以 `usbdevfs_ctrltransfer` 结构体为例，演示一个控制传输的场景：

**假设输入:**

* USB 设备文件描述符 `fd`.
* `usbdevfs_ctrltransfer` 结构体：
    * `bRequestType`: `0x40` (主机到设备，标准请求，接收者是接口)
    * `bRequest`: `0x06` (GET_DESCRIPTOR)
    * `wValue`: `0x0200` (配置描述符)
    * `wIndex`: `0x0000` (接口编号 0)
    * `wLength`: `256` (请求读取 256 字节)
    * `timeout`: `1000` (超时时间 1000 毫秒)
    * `data`:  一个 256 字节的缓冲区，用于接收数据。

**操作:**

调用 `ioctl(fd, USBDEVFS_CONTROL, &ctrl)`，其中 `ctrl` 是填充好的 `usbdevfs_ctrltransfer` 结构体。

**可能的输出:**

* **成功:** `ioctl` 返回 `0`。`ctrl.data` 缓冲区中包含 USB 设备的配置描述符数据，`ctrl.actual_length` 可能小于或等于 `ctrl.wLength`，表示实际接收到的字节数。
* **失败:** `ioctl` 返回 `-1`，并设置 `errno` 错误码，可能的原因包括：
    * `ETIMEDOUT`: 操作超时。
    * `EPIPE`:  端点停止或传输错误。
    * `EACCES`:  没有访问设备的权限。
    * `ENODEV`:  设备不存在。

**用户或编程常见的使用错误**

* **缓冲区大小错误:**  `data` 缓冲区的大小没有正确设置为预期接收的数据大小，可能导致数据截断或溢出。
* **错误的请求类型或请求码:** `bRequestType` 和 `bRequest` 的值不正确，导致设备无法识别请求。
* **超时时间设置不当:** `timeout` 设置过短可能导致操作频繁超时，设置过长则会影响响应速度。
* **未检查 `ioctl` 的返回值:**  忽略 `ioctl` 的返回值和 `errno`，无法正确处理错误情况。
* **权限问题:** 用户程序没有足够的权限访问 USB 设备文件（通常位于 `/dev/bus/usb/` 下）。
* **并发访问:** 多个进程或线程同时访问同一个 USB 设备，可能导致冲突。
* **不正确的端点地址:** 在批量或中断传输中使用了错误的端点地址 (`ep` 字段)。

**Android Framework 或 NDK 如何一步步地到达这里**

以下是 Android Framework 和 NDK 如何逐步使用这些底层接口的一个简要说明：

**Android Framework (Java 层):**

1. **应用程序调用:**  Android 应用程序通常使用 `android.hardware.usb` 包下的类，例如 `UsbManager`, `UsbDevice`, `UsbInterface`, `UsbEndpoint`, `UsbDeviceConnection` 等。
2. **UsbManager 服务:** `UsbManager` 类通过 Binder IPC 与系统服务 `usb` 通信。
3. **UsbService (Java/Native):**  `UsbService` 是一个系统服务，负责管理 USB 设备的连接和交互。它的一部分是用 Java 实现，另一部分是 Native 代码 (C++)。
4. **HAL (Hardware Abstraction Layer):** `UsbService` 的 Native 代码会调用 USB HAL (Hardware Abstraction Layer) 的接口。USB HAL 的实现通常由设备制造商提供，负责与底层的 USB 驱动进行交互。

**NDK (Native 开发):**

1. **Native 代码:**  NDK 开发者可以直接编写 C/C++ 代码。
2. **libusb 或自定义库:**  NDK 开发者可以使用像 `libusb` 这样的用户空间 USB 库，或者自己编写代码来与 USB 设备交互。
3. **直接调用 `ioctl`:**  在某些情况下，NDK 开发者可能会直接使用 `open()` 打开 USB 设备文件，然后调用 `ioctl()`，并使用 `usbdevice_fs.h` 中定义的数据结构。

**Frida Hook 示例调试步骤**

假设我们想监控 Android 应用程序进行 USB 控制传输的过程。我们可以使用 Frida Hook `ioctl` 系统调用：

```javascript
// frida script

function hook_ioctl() {
  const ioctlPtr = Module.findExportByName(null, "ioctl");
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查是否是 USB 控制传输
        if (request === 0xc0555500) { // USBDEVFS_CONTROL 的值，需要根据实际平台确定
          console.log("ioctl called with USBDEVFS_CONTROL");
          console.log("  File Descriptor:", fd);
          console.log("  Request Code:", request.toString(16));

          // 读取 usbdevfs_ctrltransfer 结构体的内容
          const ctrlTransferPtr = argp;
          const bRequestType = Memory.readU8(ctrlTransferPtr);
          const bRequest = Memory.readU8(ctrlTransferPtr.add(1));
          const wValue = Memory.readU16(ctrlTransferPtr.add(2));
          const wIndex = Memory.readU16(ctrlTransferPtr.add(4));
          const wLength = Memory.readU16(ctrlTransferPtr.add(6));
          const timeout = Memory.readU32(ctrlTransferPtr.add(8));
          const dataPtr = Memory.readPointer(ctrlTransferPtr.add(12));

          console.log("  usbdevfs_ctrltransfer:");
          console.log("    bRequestType:", bRequestType.toString(16));
          console.log("    bRequest:", bRequest.toString(16));
          console.log("    wValue:", wValue.toString(16));
          console.log("    wIndex:", wIndex.toString(16));
          console.log("    wLength:", wLength.toString(16));
          console.log("    timeout:", timeout);
          console.log("    dataPtr:", dataPtr);

          // 如果需要，可以进一步读取 data 指向的数据
          // if (wLength.toInt32() > 0 && dataPtr.isNull() === false) {
          //   const data = Memory.readByteArray(dataPtr, wLength.toInt32());
          //   console.log("    Data:", hexdump(data));
          // }
        }
      },
      onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
      },
    });
  } else {
    console.error("Failed to find ioctl symbol");
  }
}

setImmediate(hook_ioctl);
```

**步骤:**

1. **找到目标进程:** 确定你想要监控的 Android 应用程序的进程 ID 或进程名称。
2. **运行 Frida:** 使用 Frida 连接到目标进程，例如：
   ```bash
   frida -U -n <应用程序名称> -l your_script.js
   ```
   或者
   ```bash
   frida -U <进程ID> -l your_script.js
   ```
3. **观察输出:**  当目标应用程序进行 USB 控制传输时，Frida 会拦截 `ioctl` 调用，并打印出相关的参数信息，包括文件描述符、请求码以及 `usbdevfs_ctrltransfer` 结构体的内容。

通过这种方式，你可以深入了解 Android Framework 或 NDK 是如何使用这些底层的 USB 接口与硬件进行交互的。

希望这个详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/linux/usbdevice_fs.h` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/usbdevice_fs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_USBDEVICE_FS_H
#define _UAPI_LINUX_USBDEVICE_FS_H
#include <linux/types.h>
#include <linux/magic.h>
struct usbdevfs_ctrltransfer {
  __u8 bRequestType;
  __u8 bRequest;
  __u16 wValue;
  __u16 wIndex;
  __u16 wLength;
  __u32 timeout;
  void  * data;
};
struct usbdevfs_bulktransfer {
  unsigned int ep;
  unsigned int len;
  unsigned int timeout;
  void  * data;
};
struct usbdevfs_setinterface {
  unsigned int interface;
  unsigned int altsetting;
};
struct usbdevfs_disconnectsignal {
  unsigned int signr;
  void  * context;
};
#define USBDEVFS_MAXDRIVERNAME 255
struct usbdevfs_getdriver {
  unsigned int interface;
  char driver[USBDEVFS_MAXDRIVERNAME + 1];
};
struct usbdevfs_connectinfo {
  unsigned int devnum;
  unsigned char slow;
};
struct usbdevfs_conninfo_ex {
  __u32 size;
  __u32 busnum;
  __u32 devnum;
  __u32 speed;
  __u8 num_ports;
  __u8 ports[7];
};
#define USBDEVFS_URB_SHORT_NOT_OK 0x01
#define USBDEVFS_URB_ISO_ASAP 0x02
#define USBDEVFS_URB_BULK_CONTINUATION 0x04
#define USBDEVFS_URB_NO_FSBR 0x20
#define USBDEVFS_URB_ZERO_PACKET 0x40
#define USBDEVFS_URB_NO_INTERRUPT 0x80
#define USBDEVFS_URB_TYPE_ISO 0
#define USBDEVFS_URB_TYPE_INTERRUPT 1
#define USBDEVFS_URB_TYPE_CONTROL 2
#define USBDEVFS_URB_TYPE_BULK 3
struct usbdevfs_iso_packet_desc {
  unsigned int length;
  unsigned int actual_length;
  unsigned int status;
};
struct usbdevfs_urb {
  unsigned char type;
  unsigned char endpoint;
  int status;
  unsigned int flags;
  void  * buffer;
  int buffer_length;
  int actual_length;
  int start_frame;
  union {
    int number_of_packets;
    unsigned int stream_id;
  };
  int error_count;
  unsigned int signr;
  void  * usercontext;
  struct usbdevfs_iso_packet_desc iso_frame_desc[];
};
struct usbdevfs_ioctl {
  int ifno;
  int ioctl_code;
  void  * data;
};
struct usbdevfs_hub_portinfo {
  char nports;
  char port[127];
};
#define USBDEVFS_CAP_ZERO_PACKET 0x01
#define USBDEVFS_CAP_BULK_CONTINUATION 0x02
#define USBDEVFS_CAP_NO_PACKET_SIZE_LIM 0x04
#define USBDEVFS_CAP_BULK_SCATTER_GATHER 0x08
#define USBDEVFS_CAP_REAP_AFTER_DISCONNECT 0x10
#define USBDEVFS_CAP_MMAP 0x20
#define USBDEVFS_CAP_DROP_PRIVILEGES 0x40
#define USBDEVFS_CAP_CONNINFO_EX 0x80
#define USBDEVFS_CAP_SUSPEND 0x100
#define USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER 0x01
#define USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER 0x02
struct usbdevfs_disconnect_claim {
  unsigned int interface;
  unsigned int flags;
  char driver[USBDEVFS_MAXDRIVERNAME + 1];
};
struct usbdevfs_streams {
  unsigned int num_streams;
  unsigned int num_eps;
  unsigned char eps[];
};
#define USBDEVFS_CONTROL _IOWR('U', 0, struct usbdevfs_ctrltransfer)
#define USBDEVFS_CONTROL32 _IOWR('U', 0, struct usbdevfs_ctrltransfer32)
#define USBDEVFS_BULK _IOWR('U', 2, struct usbdevfs_bulktransfer)
#define USBDEVFS_BULK32 _IOWR('U', 2, struct usbdevfs_bulktransfer32)
#define USBDEVFS_RESETEP _IOR('U', 3, unsigned int)
#define USBDEVFS_SETINTERFACE _IOR('U', 4, struct usbdevfs_setinterface)
#define USBDEVFS_SETCONFIGURATION _IOR('U', 5, unsigned int)
#define USBDEVFS_GETDRIVER _IOW('U', 8, struct usbdevfs_getdriver)
#define USBDEVFS_SUBMITURB _IOR('U', 10, struct usbdevfs_urb)
#define USBDEVFS_SUBMITURB32 _IOR('U', 10, struct usbdevfs_urb32)
#define USBDEVFS_DISCARDURB _IO('U', 11)
#define USBDEVFS_REAPURB _IOW('U', 12, void *)
#define USBDEVFS_REAPURB32 _IOW('U', 12, __u32)
#define USBDEVFS_REAPURBNDELAY _IOW('U', 13, void *)
#define USBDEVFS_REAPURBNDELAY32 _IOW('U', 13, __u32)
#define USBDEVFS_DISCSIGNAL _IOR('U', 14, struct usbdevfs_disconnectsignal)
#define USBDEVFS_DISCSIGNAL32 _IOR('U', 14, struct usbdevfs_disconnectsignal32)
#define USBDEVFS_CLAIMINTERFACE _IOR('U', 15, unsigned int)
#define USBDEVFS_RELEASEINTERFACE _IOR('U', 16, unsigned int)
#define USBDEVFS_CONNECTINFO _IOW('U', 17, struct usbdevfs_connectinfo)
#define USBDEVFS_IOCTL _IOWR('U', 18, struct usbdevfs_ioctl)
#define USBDEVFS_IOCTL32 _IOWR('U', 18, struct usbdevfs_ioctl32)
#define USBDEVFS_HUB_PORTINFO _IOR('U', 19, struct usbdevfs_hub_portinfo)
#define USBDEVFS_RESET _IO('U', 20)
#define USBDEVFS_CLEAR_HALT _IOR('U', 21, unsigned int)
#define USBDEVFS_DISCONNECT _IO('U', 22)
#define USBDEVFS_CONNECT _IO('U', 23)
#define USBDEVFS_CLAIM_PORT _IOR('U', 24, unsigned int)
#define USBDEVFS_RELEASE_PORT _IOR('U', 25, unsigned int)
#define USBDEVFS_GET_CAPABILITIES _IOR('U', 26, __u32)
#define USBDEVFS_DISCONNECT_CLAIM _IOR('U', 27, struct usbdevfs_disconnect_claim)
#define USBDEVFS_ALLOC_STREAMS _IOR('U', 28, struct usbdevfs_streams)
#define USBDEVFS_FREE_STREAMS _IOR('U', 29, struct usbdevfs_streams)
#define USBDEVFS_DROP_PRIVILEGES _IOW('U', 30, __u32)
#define USBDEVFS_GET_SPEED _IO('U', 31)
#define USBDEVFS_CONNINFO_EX(len) _IOC(_IOC_READ, 'U', 32, len)
#define USBDEVFS_FORBID_SUSPEND _IO('U', 33)
#define USBDEVFS_ALLOW_SUSPEND _IO('U', 34)
#define USBDEVFS_WAIT_FOR_RESUME _IO('U', 35)
#endif

"""

```