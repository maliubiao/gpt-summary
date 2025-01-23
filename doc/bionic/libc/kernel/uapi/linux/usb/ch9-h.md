Response:
Let's break down the thought process to analyze the provided C header file.

**1. Understanding the Request:**

The core request is to analyze a C header file (`ch9.h`) related to USB, specifically within the Android bionic library. The request asks for:

* **Functionality:** What does this file do?
* **Android Relation:** How does it relate to Android?
* **libc Function Explanation:**  (While the file *doesn't* contain libc functions directly, the request anticipates this type of analysis, so it's important to address why it's not applicable here).
* **Dynamic Linker:** (Similar to libc, it's not directly involved in *defining* constants, but understanding how these constants are used by linked code is relevant).
* **Logic Reasoning:**  Inferring behavior based on the defined constants.
* **Common Errors:**  Potential mistakes when using these definitions.
* **Android Framework/NDK Path:** How a request might reach this code.
* **Frida Hooking:** Examples for debugging.

**2. Initial File Examination:**

The first step is to read through the file and identify its key components. Keywords like `#define`, `struct`, and comments like "This file is auto-generated" immediately stand out.

* **`#ifndef`, `#define`, `#endif`:** These are standard C preprocessor directives for header guards, preventing multiple inclusions.
* **`#include <linux/types.h>`, `#include <asm/byteorder.h>`:**  This indicates the file relies on basic Linux types and byte order definitions, suggesting it's a low-level interface.
* **`#define` statements:**  A large number of these define constants. These are the primary functional elements of the file. The names of the constants (e.g., `USB_DIR_OUT`, `USB_REQ_GET_DESCRIPTOR`) strongly suggest USB communication.
* **`struct` definitions:** These define data structures for representing USB entities like control requests and descriptors. The `__attribute__((packed))` indicates the importance of memory layout for interoperability with hardware.
* **Comments:**  The initial comment about auto-generation and the link to the bionic repository provide context.

**3. Determining Functionality:**

Based on the observations, the core functionality is clearly the definition of constants and data structures related to the USB protocol, specifically Chapter 9 of the USB specification (indicated by the filename `ch9.h`). It's *not* about implementing functions.

**4. Connecting to Android:**

The "bionic" directory in the path strongly indicates Android's involvement. The file being in `kernel/uapi` further suggests it's a user-space API mirroring kernel definitions. This leads to the understanding that Android's USB stack (both in the kernel and user-space) uses these definitions for interacting with USB devices. Examples include:

* **Hardware Abstraction Layer (HAL):**  HALs dealing with USB will use these definitions to configure and communicate with USB hardware.
* **Android Framework (Java):**  APIs like `UsbManager` eventually translate to lower-level calls that utilize these constants.
* **NDK:** Native code interacting with USB devices through the Linux kernel will directly use these definitions.

**5. Addressing Unrelated Requests (libc, Dynamic Linker):**

The file *doesn't* define libc functions or directly involve the dynamic linker in its core purpose. It's crucial to state this clearly and explain *why*. The file provides *definitions*, not executable code that needs linking. However, the *use* of these definitions in other bionic libraries or NDK modules *does* involve linking. This nuance needs to be highlighted. For the dynamic linker part, a simple example of how a hypothetical `libusb.so` might be laid out and linked against is useful to illustrate the concept even if this specific header doesn't *cause* the linking.

**6. Logical Reasoning (Assumptions and Outputs):**

This involves understanding how the defined constants are used. For example, the `USB_DIR_IN` and `USB_DIR_OUT` flags, combined with request types, determine the direction of USB control transfers. An example of constructing a `usb_ctrlrequest` structure demonstrates this.

**7. Common Errors:**

Thinking about how developers might misuse these definitions is important. Examples include:

* **Incorrect bitwise operations:**  Misunderstanding the masks and shifts.
* **Using the wrong constant:**  Choosing the wrong request type or descriptor type.
* **Endianness issues:**  Forgetting about `__le16` and `__le32` for little-endian values.

**8. Android Framework/NDK Path and Frida Hooking:**

This requires tracing the journey of a USB request. Starting from a high-level Android API (like `UsbManager`), describe how it goes through the framework layers (Java, native), potentially reaches a HAL, and finally interacts with the kernel using system calls that rely on these definitions.

Frida examples should demonstrate how to intercept calls at different levels (e.g., hooking a system call related to USB control transfers or even a Java API in the framework). Choosing relevant functions (like `ioctl` or `UsbDeviceConnection.controlTransfer`) is crucial.

**9. Structuring the Answer:**

Organizing the information logically with clear headings makes the analysis easier to understand. Using examples and code snippets improves clarity. Addressing each part of the original request ensures a comprehensive answer.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this file defines some utility functions related to USB.
* **Correction:**  Realizing it's primarily about constants and data structures.
* **Initial thought:** Focus only on direct linking.
* **Correction:** Expanding to how these definitions are *used* by linked code, even if the header itself isn't directly linked.
* **Initial thought:** Provide very technical, kernel-level Frida hooks.
* **Correction:** Including higher-level Java hooks for a broader understanding of the Android stack.

By following this systematic approach, including analyzing the code, connecting it to the Android ecosystem, and anticipating potential points of confusion, a comprehensive and helpful answer can be constructed.
这个文件 `bionic/libc/kernel/uapi/linux/usb/ch9.h` 是 Android Bionic 库中的一个头文件，它直接来源于 Linux 内核的 UAPI（User API），定义了 USB 规范第九章（Chapter 9）中描述的通用 USB 数据结构和常量。这意味着它为用户空间程序（包括 Android 框架和 NDK 开发的应用程序）提供了与 USB 设备进行底层交互的基础。

**它的功能：**

该头文件的主要功能是提供以下定义，用于描述和控制 USB 设备：

1. **USB 请求类型和方向:**
   - 定义了 USB 控制传输的方向 (`USB_DIR_IN`, `USB_DIR_OUT`)。
   - 定义了 USB 请求的类型（`USB_TYPE_STANDARD`, `USB_TYPE_CLASS`, `USB_TYPE_VENDOR`, `USB_TYPE_RESERVED`）。
   - 定义了请求的目标接收者 (`USB_RECIP_DEVICE`, `USB_RECIP_INTERFACE`, `USB_RECIP_ENDPOINT` 等）。

2. **标准 USB 请求码:**
   - 定义了各种标准的 USB 请求码，例如获取设备状态 (`USB_REQ_GET_STATUS`)、设置设备地址 (`USB_REQ_SET_ADDRESS`)、获取描述符 (`USB_REQ_GET_DESCRIPTOR`)、设置配置 (`USB_REQ_SET_CONFIGURATION`) 等。这些请求是与 USB 设备进行基本控制和信息交换的关键。

3. **USB 设备特性和状态标志:**
   - 定义了 USB 设备可以支持的特性，例如自供电 (`USB_DEVICE_SELF_POWERED`)、远程唤醒 (`USB_DEVICE_REMOTE_WAKEUP`) 等。
   - 定义了用于测试模式的常量 (`USB_TEST_J`, `USB_TEST_K` 等）。
   - 定义了设备和接口的状态标志，例如使能U1/U2低功耗模式。

4. **USB 描述符类型:**
   - 定义了各种 USB 描述符的类型代码，例如设备描述符 (`USB_DT_DEVICE`)、配置描述符 (`USB_DT_CONFIG`)、字符串描述符 (`USB_DT_STRING`)、接口描述符 (`USB_DT_INTERFACE`)、端点描述符 (`USB_DT_ENDPOINT`) 等。这些描述符包含了 USB 设备的结构和能力信息。

5. **USB 数据结构:**
   - 定义了 C 结构体来表示 USB 的各种数据结构，例如控制请求 (`usb_ctrlrequest`)、各种描述符（`usb_device_descriptor`, `usb_config_descriptor`, `usb_endpoint_descriptor` 等）。这些结构体用于在内核和用户空间之间传递 USB 相关的信息。

6. **USB 类代码:**
   - 定义了一些常见的 USB 设备类代码 (`USB_CLASS_AUDIO`, `USB_CLASS_MASS_STORAGE`, `USB_CLASS_HID` 等），用于标识设备的类型。

**与 Android 功能的关系及举例说明：**

这个头文件对于 Android 系统与 USB 设备的交互至关重要。Android 的 USB 子系统（包括内核驱动和用户空间库）会使用这里定义的常量和数据结构来：

* **枚举 USB 设备:** 当一个 USB 设备连接到 Android 设备时，Android 系统会读取设备的各种描述符（使用 `USB_REQ_GET_DESCRIPTOR` 请求），以了解设备的类型、功能和配置信息。这些描述符的结构体定义就在这个头文件中。例如，`usb_device_descriptor` 结构体中的 `idVendor` 和 `idProduct` 用于唯一标识 USB 设备。
* **配置 USB 设备:**  Android 系统会根据需要选择一个合适的配置（使用 `USB_REQ_SET_CONFIGURATION` 请求）。配置描述符 (`usb_config_descriptor`) 定义了设备支持的接口和功耗等信息。
* **与 USB 设备进行数据传输:**  通过端点进行数据传输，端点描述符 (`usb_endpoint_descriptor`) 定义了端点的地址、传输类型（控制、批量、中断、同步）等信息。
* **执行特定设备的控制操作:**  例如，对于一个 USB 摄像头，可能需要发送特定的控制请求来调整焦距或曝光度。这些请求的类型和结构会用到这里定义的常量。
* **支持 USB Host 模式和 USB OTG:** Android 设备通常可以作为 USB Host 连接其他 USB 设备，或者作为 USB Device 连接到电脑。这个头文件中的定义为实现这些功能提供了基础。

**举例说明：**

假设一个 Android 应用需要与一个连接的 USB 打印机通信。

1. **枚举设备:** Android 系统底层会使用 `USB_REQ_GET_DESCRIPTOR` 请求获取打印机的设备描述符 (`usb_device_descriptor`)、配置描述符 (`usb_config_descriptor`) 和接口描述符 (`usb_interface_descriptor`)。这些描述符的结构定义在 `ch9.h` 中。通过这些描述符，系统可以知道这是一个打印机设备（`bDeviceClass` 可能为 `USB_CLASS_PRINTER`）。
2. **查找打印接口:** 系统会遍历配置描述符中的接口描述符，找到与打印相关的接口。接口描述符中的 `bInterfaceClass`、`bInterfaceSubClass` 和 `bInterfaceProtocol` 用于识别接口的功能。
3. **查找端点:** 在打印接口中，系统会查找用于数据传输的端点，例如批量输出端点，用于发送打印数据。端点描述符 (`usb_endpoint_descriptor`) 定义了端点的地址和传输类型 (`USB_ENDPOINT_XFER_BULK`)。
4. **发送打印数据:**  应用层通过 Android Framework 提供的 USB API，最终会调用底层的驱动程序，构造符合 USB 协议的数据包，并通过批量输出端点发送给打印机。这个过程中会使用到 `USB_DIR_OUT` 来指定传输方向。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示：** `bionic/libc/kernel/uapi/linux/usb/ch9.h` **本身并不包含任何 libc 函数的实现**。它只是一个定义了常量和数据结构的头文件。它被 libc 库中的其他组件以及 Android 系统更底层的部分使用。

libc 函数的实现通常位于 `bionic/libc` 目录下的 C 源文件中。这些函数会使用这个头文件中定义的常量和结构体来与内核中的 USB 驱动程序进行交互，通常是通过系统调用（例如 `ioctl`）。

例如，如果你想了解 Android 中用于与 USB 设备通信的 libc 函数，你可能需要查看 `bionic/libc/bionic/syscalls.h` (系统调用号定义) 和相关的系统调用实现，以及 Android Framework 中 JNI 层对 USB 功能的封装。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `ch9.h` 本身不直接涉及 dynamic linker，但理解它的使用场景有助于理解动态链接。假设有一个名为 `libusb.so` 的动态链接库，它提供了与 USB 设备交互的功能，并且使用了 `ch9.h` 中定义的常量和结构体。

**`libusb.so` 布局样本：**

```
libusb.so:
    .text          # 代码段，包含函数实现
        usb_open
        usb_close
        usb_control_transfer
        ...
    .data          # 初始化数据段
        ...
    .bss           # 未初始化数据段
        ...
    .dynsym        # 动态符号表，包含导出的符号
        usb_open
        usb_close
        usb_control_transfer
        ...
    .dynstr        # 动态字符串表，包含符号名称的字符串
        "usb_open"
        "usb_close"
        "usb_control_transfer"
        ...
    .plt           # 程序链接表，用于延迟绑定
        条目指向 .got.plt 中的地址
    .got.plt       # 全局偏移量表，用于存储外部符号的地址（运行时填充）
        ...
    .rel.dyn       # 动态重定位表，描述如何修改 .got.plt
        ...
    ... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接：** 当一个应用程序或另一个共享库（例如 Android Framework 中的某个 native 组件）需要使用 `libusb.so` 提供的功能时，编译器会将对 `libusb.so` 中函数的调用标记为外部符号。链接器会记录这些符号的依赖关系。

2. **运行时链接（动态链接）：**
   - 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有依赖的共享库，包括 `libusb.so`。
   - Dynamic linker 会解析 `libusb.so` 的 `.dynsym` 和 `.dynstr` 段，找到导出的符号（例如 `usb_control_transfer`）。
   - Dynamic linker 会遍历应用程序或依赖库的重定位表（例如 `.rel.dyn`），找到对 `libusb.so` 中符号的引用。
   - 对于每个外部符号引用，dynamic linker 会在 `libusb.so` 的符号表中查找该符号的地址，并将该地址填充到应用程序或依赖库的 `.got.plt` 表中对应的条目。
   - 当应用程序第一次调用 `usb_control_transfer` 时，会跳转到 `.plt` 表中对应的条目。由于此时 `.got.plt` 中的地址尚未被填充，会触发 dynamic linker 的延迟绑定机制。
   - Dynamic linker 再次解析符号表，找到 `usb_control_transfer` 的真实地址，并更新 `.got.plt` 中的地址。
   - 后续对 `usb_control_transfer` 的调用将直接跳转到其真实地址，而无需再次经过 dynamic linker。

在这个过程中，`libusb.so` 的实现代码可能会使用 `ch9.h` 中定义的 `usb_ctrlrequest` 结构体和各种 `USB_REQ_*` 常量来构造和发送 USB 控制请求。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个函数需要构造一个获取设备描述符的 USB 控制请求。

**假设输入：**

- 设备地址： 0x00
- 描述符类型： `USB_DT_DEVICE` (0x01)
- 描述符索引： 0
- 期望的描述符长度： 18 字节 (sizeof(usb_device_descriptor))

**逻辑推理：**

该函数需要填充 `usb_ctrlrequest` 结构体的成员，以构建一个获取设备描述符的请求。根据 USB 规范：

- `bRequestType`:  `USB_DIR_IN` (数据从设备到主机) | `USB_TYPE_STANDARD` | `USB_RECIP_DEVICE`  => `0x80 | 0x00 | 0x00 = 0x80`
- `bRequest`: `USB_REQ_GET_DESCRIPTOR` => `0x06`
- `wValue`:  (描述符类型 << 8) | 描述符索引 => `(0x01 << 8) | 0x00 = 0x0100`
- `wIndex`: 0 (设备接收者通常为 0)
- `wLength`: 期望的描述符长度 => `0x0012` (18 的十六进制)

**假设输出 (填充后的 `usb_ctrlrequest` 结构体):**

```c
struct usb_ctrlrequest req;
req.bRequestType = 0x80;
req.bRequest = 0x06;
req.wValue = htole16(0x0100); // 使用 htole16 转换为小端序
req.wIndex = htole16(0x0000);
req.wLength = htole16(0x0012);
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **字节序错误：** USB 协议通常使用小端序。如果开发者直接赋值多字节字段而不进行字节序转换（例如使用 `htole16` 或 `htole32`），可能会导致设备无法正确解析请求。

   **错误示例：**
   ```c
   req.wValue = 0x0100; // 假设主机是大端序，这将发送 0x0001 给设备
   ```

   **正确做法：**
   ```c
   req.wValue = htole16(0x0100);
   ```

2. **请求类型错误：** 使用了错误的 `bRequestType`、`bRequest` 或接收者 (`USB_RECIP_*`)，导致请求无法到达预期的目标或执行错误的操作。

   **错误示例：** 尝试获取接口描述符，但 `bRequestType` 仍然设置为 `USB_RECIP_DEVICE`。

3. **描述符长度错误：** 在获取描述符时，`wLength` 设置为错误的长度，可能导致读取不足或超出实际描述符大小的数据。

4. **未初始化结构体：**  忘记初始化 `usb_ctrlrequest` 结构体的某些成员，导致发送的请求数据不完整或包含垃圾数据。

5. **位操作错误：**  在组合 `bRequestType` 时，使用了错误的位运算，导致请求类型或方向错误。

   **错误示例：** 使用 `+` 代替 `|` 进行位或操作。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `ch9.h` 的路径：**

1. **Android 应用层 (Java/Kotlin):**  应用通过 `android.hardware.usb.UsbManager` 获取 `UsbDevice` 和 `UsbDeviceConnection` 对象。

2. **Android Framework (Java):** `UsbManager` 和 `UsbDeviceConnection` 类在 framework 中提供 Java API 来操作 USB 设备。当应用调用 `UsbDeviceConnection.controlTransfer()` 等方法时，会通过 JNI 调用到 native 代码。

3. **Android Framework (Native - `frameworks/base/core/jni/android_hardware_UsbDeviceConnection.cpp` 等):** JNI 代码会将 Java 层的调用转换为底层的 native 函数调用。例如，`android_hardware_UsbDeviceConnection_controlTransfer` 函数会调用 Bionic 库中的 USB 相关函数。

4. **Bionic Libc (`bionic/libc`):**  Bionic Libc 提供了与 Linux 内核交互的接口。在处理 USB 相关操作时，可能会使用系统调用，例如 `ioctl`，来与 USB 驱动程序通信。

5. **Linux Kernel USB Driver (`drivers/usb/core` 等):** 内核中的 USB 驱动程序负责实际与 USB 设备进行硬件通信。用户空间的请求（通过 `ioctl`）会被传递到相应的内核驱动程序处理。

6. **`ch9.h` 的使用:** 在 Bionic Libc 和内核 USB 驱动程序中，`ch9.h` 中定义的常量和数据结构被用来构造和解析 USB 控制请求、描述符等。例如，`ioctl` 系统调用的参数中会包含指向 `usb_ctrlrequest` 结构体的指针，该结构体的定义来源于 `ch9.h`。

**NDK 到 `ch9.h` 的路径：**

1. **NDK 应用层 (C/C++):** NDK 应用可以直接使用 Linux 系统提供的头文件和函数，例如 `<linux/usb/ch9.h>`。但是，为了与 Android 的 Bionic 库保持一致，通常会使用 Bionic 提供的头文件。

2. **Bionic Libc:** NDK 应用链接到 Bionic Libc。应用可以直接调用 Bionic 提供的与 USB 交互的函数（如果有），或者使用更底层的系统调用接口。

3. **系统调用和内核驱动:** 路径与 Android Framework 类似，最终会通过系统调用到达内核 USB 驱动程序。

**Frida Hook 示例：**

以下是一些 Frida Hook 的示例，可以用来调试 USB 相关的步骤。

**Hook Android Framework Java API:**

```javascript
// Hook UsbDeviceConnection.controlTransfer
Java.perform(function() {
  var UsbDeviceConnection = Java.use("android.hardware.usb.UsbDeviceConnection");
  UsbDeviceConnection.controlTransfer.overload('int', 'int', 'int', 'int', '[B', 'int', 'int').implementation = function(requestType, request, value, index, buffer, length, timeout) {
    console.log("controlTransfer called:");
    console.log("  requestType: " + requestType);
    console.log("  request:     " + request);
    console.log("  value:       " + value);
    console.log("  index:       " + index);
    console.log("  length:      " + length);
    // 可以进一步打印 buffer 的内容
    var result = this.controlTransfer(requestType, request, value, index, buffer, length, timeout);
    console.log("controlTransfer result: " + result);
    return result;
  };
});
```

**Hook Bionic Libc `ioctl` 系统调用 (针对 USB 设备文件描述符):**

```javascript
// 需要确定 USB 设备文件描述符通常是什么，或者动态获取
var usb_fd = /* 获取 USB 设备文件描述符 */;
if (usb_fd) {
  Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
      var fd = args[0].toInt32();
      var request = args[1].toInt32();
      if (fd === usb_fd) { // 假设我们知道 USB 设备的文件描述符
        console.log("ioctl called on USB device:");
        console.log("  request: 0x" + request.toString(16));
        // 可以根据 request 的值来解析后续的参数，例如指向 usb_ctrlrequest 的指针
        if (request === 0xc00f5501) { // 假设这是 USB 控制传输的 ioctl 请求码
          var dataPtr = args[2];
          var ctrlRequest = dataPtr.readByteArray(8); // 假设 usb_ctrlrequest 是 8 字节
          console.log("  usb_ctrlrequest: " + hexdump(ctrlRequest));
        }
      }
    },
    onLeave: function(retval) {
      // ...
    }
  });
}
```

**Hook 内核函数 (需要 root 权限和内核符号地址):**

```javascript
// 这需要更多的准备工作，需要找到内核符号的地址
var ksym = Module.findSymbol("usb_submit_urb"); // 示例内核函数
if (ksym) {
  Interceptor.attach(ksym, {
    onEnter: function(args) {
      console.log("usb_submit_urb called:");
      // 解析 URB 结构体，这非常复杂，需要内核数据结构的知识
    },
    onLeave: function(retval) {
      // ...
    }
  });
}
```

请注意，Hook 内核函数需要 root 权限并且对内核的内部结构有深入的了解。Hook 系统调用和 Framework API 相对容易一些。

这些 Frida 示例可以帮助你跟踪 Android 应用与 USB 设备交互的整个过程，并观察 `ch9.h` 中定义的常量和数据结构是如何被使用的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/usb/ch9.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_USB_CH9_H
#define _UAPI__LINUX_USB_CH9_H
#include <linux/types.h>
#include <asm/byteorder.h>
#define USB_DIR_OUT 0
#define USB_DIR_IN 0x80
#define USB_TYPE_MASK (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_TYPE_RESERVED (0x03 << 5)
#define USB_RECIP_MASK 0x1f
#define USB_RECIP_DEVICE 0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT 0x02
#define USB_RECIP_OTHER 0x03
#define USB_RECIP_PORT 0x04
#define USB_RECIP_RPIPE 0x05
#define USB_REQ_GET_STATUS 0x00
#define USB_REQ_CLEAR_FEATURE 0x01
#define USB_REQ_SET_FEATURE 0x03
#define USB_REQ_SET_ADDRESS 0x05
#define USB_REQ_GET_DESCRIPTOR 0x06
#define USB_REQ_SET_DESCRIPTOR 0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE 0x0A
#define USB_REQ_SET_INTERFACE 0x0B
#define USB_REQ_SYNCH_FRAME 0x0C
#define USB_REQ_SET_SEL 0x30
#define USB_REQ_SET_ISOCH_DELAY 0x31
#define USB_REQ_SET_ENCRYPTION 0x0D
#define USB_REQ_GET_ENCRYPTION 0x0E
#define USB_REQ_RPIPE_ABORT 0x0E
#define USB_REQ_SET_HANDSHAKE 0x0F
#define USB_REQ_RPIPE_RESET 0x0F
#define USB_REQ_GET_HANDSHAKE 0x10
#define USB_REQ_SET_CONNECTION 0x11
#define USB_REQ_SET_SECURITY_DATA 0x12
#define USB_REQ_GET_SECURITY_DATA 0x13
#define USB_REQ_SET_WUSB_DATA 0x14
#define USB_REQ_LOOPBACK_DATA_WRITE 0x15
#define USB_REQ_LOOPBACK_DATA_READ 0x16
#define USB_REQ_SET_INTERFACE_DS 0x17
#define USB_REQ_GET_PARTNER_PDO 20
#define USB_REQ_GET_BATTERY_STATUS 21
#define USB_REQ_SET_PDO 22
#define USB_REQ_GET_VDM 23
#define USB_REQ_SEND_VDM 24
#define USB_DEVICE_SELF_POWERED 0
#define USB_DEVICE_REMOTE_WAKEUP 1
#define USB_DEVICE_TEST_MODE 2
#define USB_DEVICE_BATTERY 2
#define USB_DEVICE_B_HNP_ENABLE 3
#define USB_DEVICE_WUSB_DEVICE 3
#define USB_DEVICE_A_HNP_SUPPORT 4
#define USB_DEVICE_A_ALT_HNP_SUPPORT 5
#define USB_DEVICE_DEBUG_MODE 6
#define USB_TEST_J 1
#define USB_TEST_K 2
#define USB_TEST_SE0_NAK 3
#define USB_TEST_PACKET 4
#define USB_TEST_FORCE_ENABLE 5
#define USB_STATUS_TYPE_STANDARD 0
#define USB_STATUS_TYPE_PTM 1
#define USB_DEVICE_U1_ENABLE 48
#define USB_DEVICE_U2_ENABLE 49
#define USB_DEVICE_LTM_ENABLE 50
#define USB_INTRF_FUNC_SUSPEND 0
#define USB_INTR_FUNC_SUSPEND_OPT_MASK 0xFF00
#define USB_INTRF_FUNC_SUSPEND_LP (1 << (8 + 0))
#define USB_INTRF_FUNC_SUSPEND_RW (1 << (8 + 1))
#define USB_INTRF_STAT_FUNC_RW_CAP 1
#define USB_INTRF_STAT_FUNC_RW 2
#define USB_ENDPOINT_HALT 0
#define USB_DEV_STAT_U1_ENABLED 2
#define USB_DEV_STAT_U2_ENABLED 3
#define USB_DEV_STAT_LTM_ENABLED 4
#define USB_DEVICE_BATTERY_WAKE_MASK 40
#define USB_DEVICE_OS_IS_PD_AWARE 41
#define USB_DEVICE_POLICY_MODE 42
#define USB_PORT_PR_SWAP 43
#define USB_PORT_GOTO_MIN 44
#define USB_PORT_RETURN_POWER 45
#define USB_PORT_ACCEPT_PD_REQUEST 46
#define USB_PORT_REJECT_PD_REQUEST 47
#define USB_PORT_PORT_PD_RESET 48
#define USB_PORT_C_PORT_PD_CHANGE 49
#define USB_PORT_CABLE_PD_RESET 50
#define USB_DEVICE_CHARGING_POLICY 54
struct usb_ctrlrequest {
  __u8 bRequestType;
  __u8 bRequest;
  __le16 wValue;
  __le16 wIndex;
  __le16 wLength;
} __attribute__((packed));
#define USB_DT_DEVICE 0x01
#define USB_DT_CONFIG 0x02
#define USB_DT_STRING 0x03
#define USB_DT_INTERFACE 0x04
#define USB_DT_ENDPOINT 0x05
#define USB_DT_DEVICE_QUALIFIER 0x06
#define USB_DT_OTHER_SPEED_CONFIG 0x07
#define USB_DT_INTERFACE_POWER 0x08
#define USB_DT_OTG 0x09
#define USB_DT_DEBUG 0x0a
#define USB_DT_INTERFACE_ASSOCIATION 0x0b
#define USB_DT_SECURITY 0x0c
#define USB_DT_KEY 0x0d
#define USB_DT_ENCRYPTION_TYPE 0x0e
#define USB_DT_BOS 0x0f
#define USB_DT_DEVICE_CAPABILITY 0x10
#define USB_DT_WIRELESS_ENDPOINT_COMP 0x11
#define USB_DT_WIRE_ADAPTER 0x21
#define USB_DT_DFU_FUNCTIONAL 0x21
#define USB_DT_RPIPE 0x22
#define USB_DT_CS_RADIO_CONTROL 0x23
#define USB_DT_PIPE_USAGE 0x24
#define USB_DT_SS_ENDPOINT_COMP 0x30
#define USB_DT_SSP_ISOC_ENDPOINT_COMP 0x31
#define USB_DT_CS_DEVICE (USB_TYPE_CLASS | USB_DT_DEVICE)
#define USB_DT_CS_CONFIG (USB_TYPE_CLASS | USB_DT_CONFIG)
#define USB_DT_CS_STRING (USB_TYPE_CLASS | USB_DT_STRING)
#define USB_DT_CS_INTERFACE (USB_TYPE_CLASS | USB_DT_INTERFACE)
#define USB_DT_CS_ENDPOINT (USB_TYPE_CLASS | USB_DT_ENDPOINT)
struct usb_descriptor_header {
  __u8 bLength;
  __u8 bDescriptorType;
} __attribute__((packed));
struct usb_device_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 bcdUSB;
  __u8 bDeviceClass;
  __u8 bDeviceSubClass;
  __u8 bDeviceProtocol;
  __u8 bMaxPacketSize0;
  __le16 idVendor;
  __le16 idProduct;
  __le16 bcdDevice;
  __u8 iManufacturer;
  __u8 iProduct;
  __u8 iSerialNumber;
  __u8 bNumConfigurations;
} __attribute__((packed));
#define USB_DT_DEVICE_SIZE 18
#define USB_CLASS_PER_INTERFACE 0
#define USB_CLASS_AUDIO 1
#define USB_CLASS_COMM 2
#define USB_CLASS_HID 3
#define USB_CLASS_PHYSICAL 5
#define USB_CLASS_STILL_IMAGE 6
#define USB_CLASS_PRINTER 7
#define USB_CLASS_MASS_STORAGE 8
#define USB_CLASS_HUB 9
#define USB_CLASS_CDC_DATA 0x0a
#define USB_CLASS_CSCID 0x0b
#define USB_CLASS_CONTENT_SEC 0x0d
#define USB_CLASS_VIDEO 0x0e
#define USB_CLASS_WIRELESS_CONTROLLER 0xe0
#define USB_CLASS_PERSONAL_HEALTHCARE 0x0f
#define USB_CLASS_AUDIO_VIDEO 0x10
#define USB_CLASS_BILLBOARD 0x11
#define USB_CLASS_USB_TYPE_C_BRIDGE 0x12
#define USB_CLASS_MISC 0xef
#define USB_CLASS_APP_SPEC 0xfe
#define USB_SUBCLASS_DFU 0x01
#define USB_CLASS_VENDOR_SPEC 0xff
#define USB_SUBCLASS_VENDOR_SPEC 0xff
struct usb_config_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 wTotalLength;
  __u8 bNumInterfaces;
  __u8 bConfigurationValue;
  __u8 iConfiguration;
  __u8 bmAttributes;
  __u8 bMaxPower;
} __attribute__((packed));
#define USB_DT_CONFIG_SIZE 9
#define USB_CONFIG_ATT_ONE (1 << 7)
#define USB_CONFIG_ATT_SELFPOWER (1 << 6)
#define USB_CONFIG_ATT_WAKEUP (1 << 5)
#define USB_CONFIG_ATT_BATTERY (1 << 4)
#define USB_MAX_STRING_LEN 126
struct usb_string_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  union {
    __le16 legacy_padding;
    __DECLARE_FLEX_ARRAY(__le16, wData);
  };
} __attribute__((packed));
struct usb_interface_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bInterfaceNumber;
  __u8 bAlternateSetting;
  __u8 bNumEndpoints;
  __u8 bInterfaceClass;
  __u8 bInterfaceSubClass;
  __u8 bInterfaceProtocol;
  __u8 iInterface;
} __attribute__((packed));
#define USB_DT_INTERFACE_SIZE 9
struct usb_endpoint_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bEndpointAddress;
  __u8 bmAttributes;
  __le16 wMaxPacketSize;
  __u8 bInterval;
  __u8 bRefresh;
  __u8 bSynchAddress;
} __attribute__((packed));
#define USB_DT_ENDPOINT_SIZE 7
#define USB_DT_ENDPOINT_AUDIO_SIZE 9
#define USB_ENDPOINT_NUMBER_MASK 0x0f
#define USB_ENDPOINT_DIR_MASK 0x80
#define USB_ENDPOINT_XFERTYPE_MASK 0x03
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define USB_ENDPOINT_MAX_ADJUSTABLE 0x80
#define USB_ENDPOINT_MAXP_MASK 0x07ff
#define USB_EP_MAXP_MULT_SHIFT 11
#define USB_EP_MAXP_MULT_MASK (3 << USB_EP_MAXP_MULT_SHIFT)
#define USB_EP_MAXP_MULT(m) (((m) & USB_EP_MAXP_MULT_MASK) >> USB_EP_MAXP_MULT_SHIFT)
#define USB_ENDPOINT_INTRTYPE 0x30
#define USB_ENDPOINT_INTR_PERIODIC (0 << 4)
#define USB_ENDPOINT_INTR_NOTIFICATION (1 << 4)
#define USB_ENDPOINT_SYNCTYPE 0x0c
#define USB_ENDPOINT_SYNC_NONE (0 << 2)
#define USB_ENDPOINT_SYNC_ASYNC (1 << 2)
#define USB_ENDPOINT_SYNC_ADAPTIVE (2 << 2)
#define USB_ENDPOINT_SYNC_SYNC (3 << 2)
#define USB_ENDPOINT_USAGE_MASK 0x30
#define USB_ENDPOINT_USAGE_DATA 0x00
#define USB_ENDPOINT_USAGE_FEEDBACK 0x10
#define USB_ENDPOINT_USAGE_IMPLICIT_FB 0x20
struct usb_ssp_isoc_ep_comp_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 wReseved;
  __le32 dwBytesPerInterval;
} __attribute__((packed));
#define USB_DT_SSP_ISOC_EP_COMP_SIZE 8
struct usb_ss_ep_comp_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bMaxBurst;
  __u8 bmAttributes;
  __le16 wBytesPerInterval;
} __attribute__((packed));
#define USB_DT_SS_EP_COMP_SIZE 6
#define USB_SS_MULT(p) (1 + ((p) & 0x3))
#define USB_SS_SSP_ISOC_COMP(p) ((p) & (1 << 7))
struct usb_qualifier_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 bcdUSB;
  __u8 bDeviceClass;
  __u8 bDeviceSubClass;
  __u8 bDeviceProtocol;
  __u8 bMaxPacketSize0;
  __u8 bNumConfigurations;
  __u8 bRESERVED;
} __attribute__((packed));
struct usb_otg_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bmAttributes;
} __attribute__((packed));
struct usb_otg20_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bmAttributes;
  __le16 bcdOTG;
} __attribute__((packed));
#define USB_OTG_SRP (1 << 0)
#define USB_OTG_HNP (1 << 1)
#define USB_OTG_ADP (1 << 2)
#define USB_OTG_RSP (1 << 3)
#define OTG_STS_SELECTOR 0xF000
struct usb_debug_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDebugInEndpoint;
  __u8 bDebugOutEndpoint;
} __attribute__((packed));
struct usb_interface_assoc_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bFirstInterface;
  __u8 bInterfaceCount;
  __u8 bFunctionClass;
  __u8 bFunctionSubClass;
  __u8 bFunctionProtocol;
  __u8 iFunction;
} __attribute__((packed));
#define USB_DT_INTERFACE_ASSOCIATION_SIZE 8
struct usb_security_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 wTotalLength;
  __u8 bNumEncryptionTypes;
} __attribute__((packed));
struct usb_key_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 tTKID[3];
  __u8 bReserved;
  __u8 bKeyData[];
} __attribute__((packed));
struct usb_encryption_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bEncryptionType;
#define USB_ENC_TYPE_UNSECURE 0
#define USB_ENC_TYPE_WIRED 1
#define USB_ENC_TYPE_CCM_1 2
#define USB_ENC_TYPE_RSA_1 3
  __u8 bEncryptionValue;
  __u8 bAuthKeyIndex;
} __attribute__((packed));
struct usb_bos_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __le16 wTotalLength;
  __u8 bNumDeviceCaps;
} __attribute__((packed));
#define USB_DT_BOS_SIZE 5
struct usb_dev_cap_header {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
} __attribute__((packed));
#define USB_CAP_TYPE_WIRELESS_USB 1
struct usb_wireless_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bmAttributes;
#define USB_WIRELESS_P2P_DRD (1 << 1)
#define USB_WIRELESS_BEACON_MASK (3 << 2)
#define USB_WIRELESS_BEACON_SELF (1 << 2)
#define USB_WIRELESS_BEACON_DIRECTED (2 << 2)
#define USB_WIRELESS_BEACON_NONE (3 << 2)
  __le16 wPHYRates;
#define USB_WIRELESS_PHY_53 (1 << 0)
#define USB_WIRELESS_PHY_80 (1 << 1)
#define USB_WIRELESS_PHY_107 (1 << 2)
#define USB_WIRELESS_PHY_160 (1 << 3)
#define USB_WIRELESS_PHY_200 (1 << 4)
#define USB_WIRELESS_PHY_320 (1 << 5)
#define USB_WIRELESS_PHY_400 (1 << 6)
#define USB_WIRELESS_PHY_480 (1 << 7)
  __u8 bmTFITXPowerInfo;
  __u8 bmFFITXPowerInfo;
  __le16 bmBandGroup;
  __u8 bReserved;
} __attribute__((packed));
#define USB_DT_USB_WIRELESS_CAP_SIZE 11
#define USB_CAP_TYPE_EXT 2
struct usb_ext_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __le32 bmAttributes;
#define USB_LPM_SUPPORT (1 << 1)
#define USB_BESL_SUPPORT (1 << 2)
#define USB_BESL_BASELINE_VALID (1 << 3)
#define USB_BESL_DEEP_VALID (1 << 4)
#define USB_SET_BESL_BASELINE(p) (((p) & 0xf) << 8)
#define USB_SET_BESL_DEEP(p) (((p) & 0xf) << 12)
#define USB_GET_BESL_BASELINE(p) (((p) & (0xf << 8)) >> 8)
#define USB_GET_BESL_DEEP(p) (((p) & (0xf << 12)) >> 12)
} __attribute__((packed));
#define USB_DT_USB_EXT_CAP_SIZE 7
#define USB_SS_CAP_TYPE 3
struct usb_ss_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bmAttributes;
#define USB_LTM_SUPPORT (1 << 1)
  __le16 wSpeedSupported;
#define USB_LOW_SPEED_OPERATION (1)
#define USB_FULL_SPEED_OPERATION (1 << 1)
#define USB_HIGH_SPEED_OPERATION (1 << 2)
#define USB_5GBPS_OPERATION (1 << 3)
  __u8 bFunctionalitySupport;
  __u8 bU1devExitLat;
  __le16 bU2DevExitLat;
} __attribute__((packed));
#define USB_DT_USB_SS_CAP_SIZE 10
#define CONTAINER_ID_TYPE 4
struct usb_ss_container_id_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved;
  __u8 ContainerID[16];
} __attribute__((packed));
#define USB_DT_USB_SS_CONTN_ID_SIZE 20
#define USB_PLAT_DEV_CAP_TYPE 5
struct usb_plat_dev_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved;
  __u8 UUID[16];
  __u8 CapabilityData[];
} __attribute__((packed));
#define USB_DT_USB_PLAT_DEV_CAP_SIZE(capability_data_size) (20 + capability_data_size)
#define USB_SSP_CAP_TYPE 0xa
struct usb_ssp_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved;
  __le32 bmAttributes;
#define USB_SSP_SUBLINK_SPEED_ATTRIBS (0x1f << 0)
#define USB_SSP_SUBLINK_SPEED_IDS (0xf << 5)
  __le16 wFunctionalitySupport;
#define USB_SSP_MIN_SUBLINK_SPEED_ATTRIBUTE_ID (0xf)
#define USB_SSP_MIN_RX_LANE_COUNT (0xf << 8)
#define USB_SSP_MIN_TX_LANE_COUNT (0xf << 12)
  __le16 wReserved;
  union {
    __le32 legacy_padding;
    __DECLARE_FLEX_ARRAY(__le32, bmSublinkSpeedAttr);
  };
#define USB_SSP_SUBLINK_SPEED_SSID (0xf)
#define USB_SSP_SUBLINK_SPEED_LSE (0x3 << 4)
#define USB_SSP_SUBLINK_SPEED_LSE_BPS 0
#define USB_SSP_SUBLINK_SPEED_LSE_KBPS 1
#define USB_SSP_SUBLINK_SPEED_LSE_MBPS 2
#define USB_SSP_SUBLINK_SPEED_LSE_GBPS 3
#define USB_SSP_SUBLINK_SPEED_ST (0x3 << 6)
#define USB_SSP_SUBLINK_SPEED_ST_SYM_RX 0
#define USB_SSP_SUBLINK_SPEED_ST_ASYM_RX 1
#define USB_SSP_SUBLINK_SPEED_ST_SYM_TX 2
#define USB_SSP_SUBLINK_SPEED_ST_ASYM_TX 3
#define USB_SSP_SUBLINK_SPEED_RSVD (0x3f << 8)
#define USB_SSP_SUBLINK_SPEED_LP (0x3 << 14)
#define USB_SSP_SUBLINK_SPEED_LP_SS 0
#define USB_SSP_SUBLINK_SPEED_LP_SSP 1
#define USB_SSP_SUBLINK_SPEED_LSM (0xff << 16)
} __attribute__((packed));
#define USB_PD_POWER_DELIVERY_CAPABILITY 0x06
#define USB_PD_BATTERY_INFO_CAPABILITY 0x07
#define USB_PD_PD_CONSUMER_PORT_CAPABILITY 0x08
#define USB_PD_PD_PROVIDER_PORT_CAPABILITY 0x09
struct usb_pd_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved;
  __le32 bmAttributes;
#define USB_PD_CAP_BATTERY_CHARGING (1 << 1)
#define USB_PD_CAP_USB_PD (1 << 2)
#define USB_PD_CAP_PROVIDER (1 << 3)
#define USB_PD_CAP_CONSUMER (1 << 4)
#define USB_PD_CAP_CHARGING_POLICY (1 << 5)
#define USB_PD_CAP_TYPE_C_CURRENT (1 << 6)
#define USB_PD_CAP_PWR_AC (1 << 8)
#define USB_PD_CAP_PWR_BAT (1 << 9)
#define USB_PD_CAP_PWR_USE_V_BUS (1 << 14)
  __le16 bmProviderPorts;
  __le16 bmConsumerPorts;
  __le16 bcdBCVersion;
  __le16 bcdPDVersion;
  __le16 bcdUSBTypeCVersion;
} __attribute__((packed));
struct usb_pd_cap_battery_info_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 iBattery;
  __u8 iSerial;
  __u8 iManufacturer;
  __u8 bBatteryId;
  __u8 bReserved;
  __le32 dwChargedThreshold;
  __le32 dwWeakThreshold;
  __le32 dwBatteryDesignCapacity;
  __le32 dwBatteryLastFullchargeCapacity;
} __attribute__((packed));
struct usb_pd_cap_consumer_port_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved;
  __u8 bmCapabilities;
#define USB_PD_CAP_CONSUMER_BC (1 << 0)
#define USB_PD_CAP_CONSUMER_PD (1 << 1)
#define USB_PD_CAP_CONSUMER_TYPE_C (1 << 2)
  __le16 wMinVoltage;
  __le16 wMaxVoltage;
  __u16 wReserved;
  __le32 dwMaxOperatingPower;
  __le32 dwMaxPeakPower;
  __le32 dwMaxPeakPowerTime;
#define USB_PD_CAP_CONSUMER_UNKNOWN_PEAK_POWER_TIME 0xffff
} __attribute__((packed));
struct usb_pd_cap_provider_port_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
  __u8 bReserved1;
  __u8 bmCapabilities;
#define USB_PD_CAP_PROVIDER_BC (1 << 0)
#define USB_PD_CAP_PROVIDER_PD (1 << 1)
#define USB_PD_CAP_PROVIDER_TYPE_C (1 << 2)
  __u8 bNumOfPDObjects;
  __u8 bReserved2;
  __le32 wPowerDataObject[];
} __attribute__((packed));
#define USB_PTM_CAP_TYPE 0xb
struct usb_ptm_cap_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bDevCapabilityType;
} __attribute__((packed));
#define USB_DT_USB_PTM_ID_SIZE 3
#define USB_DT_USB_SSP_CAP_SIZE(ssac) (12 + (ssac + 1) * 4)
struct usb_wireless_ep_comp_descriptor {
  __u8 bLength;
  __u8 bDescriptorType;
  __u8 bMaxBurst;
  __u8 bMaxSequence;
  __le16 wMaxStreamDelay;
  __le16 wOverTheAirPacketSize;
  __u8 bOverTheAirInterval;
  __u8 bmCompAttributes;
#define USB_ENDPOINT_SWITCH_MASK 0x03
#define USB_ENDPOINT_SWITCH_NO 0
#define USB_ENDPOINT_SWITCH_SWITCH 1
#define USB_ENDPOINT_SWITCH_SCALE 2
} __attribute__((packed));
struct usb_handshake {
  __u8 bMessageNumber;
  __u8 bStatus;
  __u8 tTKID[3];
  __u8 bReserved;
  __u8 CDID[16];
  __u8 nonce[16];
  __u8 MIC[8];
} __attribute__((packed));
struct usb_connection_context {
  __u8 CHID[16];
  __u8 CDID[16];
  __u8 CK[16];
} __attribute__((packed));
enum usb_device_speed {
  USB_SPEED_UNKNOWN = 0,
  USB_SPEED_LOW,
  USB_SPEED_FULL,
  USB_SPEED_HIGH,
  USB_SPEED_WIRELESS,
  USB_SPEED_SUPER,
  USB_SPEED_SUPER_PLUS,
};
enum usb_device_state {
  USB_STATE_NOTATTACHED = 0,
  USB_STATE_ATTACHED,
  USB_STATE_POWERED,
  USB_STATE_RECONNECTING,
  USB_STATE_UNAUTHENTICATED,
  USB_STATE_DEFAULT,
  USB_STATE_ADDRESS,
  USB_STATE_CONFIGURED,
  USB_STATE_SUSPENDED
};
enum usb3_link_state {
  USB3_LPM_U0 = 0,
  USB3_LPM_U1,
  USB3_LPM_U2,
  USB3_LPM_U3
};
#define USB3_LPM_DISABLED 0x0
#define USB3_LPM_U1_MAX_TIMEOUT 0x7F
#define USB3_LPM_U2_MAX_TIMEOUT 0xFE
#define USB3_LPM_DEVICE_INITIATED 0xFF
struct usb_set_sel_req {
  __u8 u1_sel;
  __u8 u1_pel;
  __le16 u2_sel;
  __le16 u2_pel;
} __attribute__((packed));
#define USB3_LPM_MAX_U1_SEL_PEL 0xFF
#define USB3_LPM_MAX_U2_SEL_PEL 0xFFFF
#define USB_SELF_POWER_VBUS_MAX_DRAW 100
#endif
```