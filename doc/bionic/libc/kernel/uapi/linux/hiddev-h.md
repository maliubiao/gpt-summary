Response:
Let's break down the thought process for analyzing this header file.

**1. Understanding the Context:**

The first and most crucial step is recognizing the context provided: `bionic/libc/kernel/uapi/linux/hiddev.h`. This immediately tells us several things:

* **Bionic:**  This is Android's C library. So, the definitions here are likely used within the Android system.
* **libc:**  This means the definitions are fundamental and low-level.
* **kernel:**  This is a kernel header file, specifically for the user-space API (`uapi`). This implies these structures and constants are used for communication between user-space programs (like apps or system services) and the Linux kernel's HID (Human Interface Device) subsystem.
* **linux/hiddev.h:** This pinpoints the specific kernel subsystem: the HID device driver interface.

**2. Initial Scan and Categorization:**

A quick scan of the file reveals several distinct types of definitions:

* **Structures (`struct hiddev_...`):** These define data structures used to exchange information about HID devices.
* **Constants (`#define HID_...`, `#define HIDDEV_...`):**  These represent fixed values, often used as flags, identifiers, or limits.
* **IO Control Macros (`#define HIDIOC...`):**  These define the commands used with the `ioctl()` system call to interact with HID devices.

**3. Analyzing Structures:**

For each structure, the key is to understand what information it represents:

* **`hiddev_event`:**  Looks like a single input event from a HID device. It has a `hid` (likely a usage code) and a `value`.
* **`hiddev_devinfo`:**  Information about the HID device itself (bus type, IDs, etc.). This is likely used when opening or identifying a device.
* **`hiddev_collection_info`:** Describes a HID collection (a hierarchical grouping of related controls, like a mouse having button and axis collections).
* **`hiddev_string_descriptor`:**  Used to retrieve string descriptors from the device (like manufacturer or product name).
* **`hiddev_report_info`:** Information about a HID report (a data packet sent or received). It includes the report type (input, output, feature) and ID.
* **`hiddev_field_info`:**  Details about a specific field within a HID report. This includes usage, logical/physical ranges, and flags describing the field's behavior.
* **`hiddev_usage_ref`:**  A reference to a specific HID usage (a particular control or data point) within a report.
* **`hiddev_usage_ref_multi`:**  Similar to `hiddev_usage_ref`, but allows retrieving or setting multiple values for a usage, often used for arrays of data.

**4. Analyzing Constants:**

Constants provide context and meaning to the structure members and ioctl commands. It's important to group them logically:

* **Report IDs (`HID_REPORT_ID_...`):**  Used to identify specific reports when a device supports multiple report types.
* **Report Types (`HID_REPORT_TYPE_...`):**  Indicate the direction and purpose of a report.
* **Field Flags (`HID_FIELD_...`):**  Describe the properties of a field within a report.
* **Other Constants (`HID_STRING_SIZE`, `HID_MAX_MULTI_USAGES`, `HID_FIELD_INDEX_NONE`, `HID_VERSION`):** Represent limits, special values, and version information.
* **Device Flags (`HIDDEV_FLAG_...`, `HIDDEV_FLAGS`):** Flags related to device behavior or filtering.

**5. Analyzing IO Control Macros:**

The `HIDIOC...` macros are the action verbs for interacting with HID devices. Understanding the naming convention is key:

* **`HIDIOC`:**  Indicates an ioctl command for HID devices.
* **`G` (Get):**  Retrieves information from the kernel.
* **`S` (Set):**  Sends information to the kernel.
* **`REPORT`, `DEVINFO`, `STRING`, `USAGE`, `FLAG`, `COLLECTION`:**  Indicate the type of information being accessed.
* **`(len)`:**  Indicates that the ioctl takes a length parameter (usually for string retrieval).
* **`_IOR`, `_IOW`, `_IOWR`, `_IO`:** These are standard Linux ioctl macros indicating the direction of data transfer (Read, Write, Read-Write, None).

By examining the structure associated with each ioctl, we can deduce its purpose. For example, `HIDIOCGDEVINFO` takes `struct hiddev_devinfo` as an argument (for reading), so it's used to get device information.

**6. Connecting to Android:**

At this point, having analyzed the individual components, we can start connecting them to Android:

* **Framework and NDK:** The Android Framework (Java/Kotlin) uses the NDK (Native Development Kit) to interact with low-level system services and the kernel. The HID subsystem is accessed via the NDK, using standard Linux system calls like `open()`, `ioctl()`, and `read()`.
* **Input System:** The most obvious connection is to Android's input system. Touchscreens, keyboards, mice, gamepads, and other HID devices are managed through this interface.
* **System Services:**  System services responsible for managing input devices would use these ioctl commands to query device capabilities, receive input events, and potentially send output reports (for devices with force feedback, for example).

**7. Considering `libc` and Dynamic Linker:**

Since this is a header file, it doesn't contain actual `libc` function *implementations*. It *defines* the structures and constants used by those functions. The `ioctl()` system call itself is a `libc` function.

The dynamic linker comes into play when libraries that use these definitions are loaded. The `so` layout would involve a standard structure with code, data, and symbol tables. Linking involves resolving symbols (like the `ioctl` function) to their actual addresses.

**8. Examples, Errors, and Frida Hooks:**

Thinking about usage errors involves considering how a programmer might misuse these structures and ioctl commands (e.g., incorrect report IDs, buffer overflows).

Frida hooks are a powerful way to observe the interaction between Android components and the kernel. Hooks can be placed on the `ioctl()` system call to monitor the specific commands and data being exchanged.

**9. Refinement and Organization:**

The final step involves organizing the information logically, providing clear explanations, examples, and code snippets. This involves:

* Grouping related concepts together.
* Using clear and concise language.
* Providing concrete examples to illustrate abstract concepts.
* Adding disclaimers or caveats where necessary (e.g., that this is a header file, not implementation code).

This detailed process, moving from understanding the context to analyzing individual components and then connecting them to the larger Android ecosystem, allows for a comprehensive and accurate interpretation of the header file.
这个目录 `bionic/libc/kernel/uapi/linux/hiddev.h` 下的源代码文件定义了 Linux 内核中用于与 HID (Human Interface Device) 设备进行用户空间交互的接口。由于它位于 `uapi` 目录下，这意味着它定义了用户空间程序可以使用的结构体、常量和宏，以便与内核中的 HID 设备驱动程序进行通信。

**功能列举：**

这个头文件定义了以下主要功能：

1. **HID 事件报告结构体 (`struct hiddev_event`)**:  用于描述来自 HID 设备的单个事件，包含 HID 用法代码 (usage) 和对应的值。

2. **HID 设备信息结构体 (`struct hiddev_devinfo`)**:  包含了 HID 设备的各种静态信息，例如总线类型、总线编号、设备编号、接口编号、供应商 ID、产品 ID 和版本号等。

3. **HID 集合信息结构体 (`struct hiddev_collection_info`)**:  描述了 HID 设备中的集合 (collection)，用于组织相关的功能单元，例如鼠标的按钮和轴可以分别属于不同的集合。

4. **HID 字符串描述符结构体 (`struct hiddev_string_descriptor`)**:  用于获取 HID 设备的字符串描述符，例如设备名称、制造商名称等。

5. **HID 报告信息结构体 (`struct hiddev_report_info`)**:  描述了 HID 设备的报告，报告是设备发送或接收的数据包。结构体包含了报告类型（输入、输出、特性）、报告 ID 和字段数量。

6. **HID 字段信息结构体 (`struct hiddev_field_info`)**:  描述了 HID 报告中的一个字段，包含了字段所属的报告类型和 ID、字段索引、最大用法数量、标志位（如常量、变量、相对值等）、物理和逻辑范围、单位等信息。

7. **HID 用法引用结构体 (`struct hiddev_usage_ref`)**:  用于引用 HID 报告中的特定用法 (usage)，包含了报告类型、报告 ID、字段索引、用法索引、用法代码和对应的值。

8. **HID 多用法引用结构体 (`struct hiddev_usage_ref_multi`)**:  类似于 `hiddev_usage_ref`，但用于处理一个用法的多个值，例如模拟摇杆的多个轴。

9. **ioctl 命令宏 (`HIDIOCGVERSION`, `HIDIOCGDEVINFO` 等)**:  定义了用户空间程序可以使用 `ioctl` 系统调用与 HID 设备驱动程序通信的命令。这些命令用于获取设备信息、设置/获取报告、获取用法信息等。

10. **常量定义 (`HID_STRING_SIZE`, `HID_REPORT_ID_UNKNOWN`, `HID_FIELD_CONSTANT` 等)**:  定义了各种常量，用于表示大小限制、特殊值、标志位等。

**与 Android 功能的关系及举例说明：**

这个头文件对于 Android 的输入系统至关重要。Android 系统需要与各种 HID 设备（例如触摸屏、键盘、鼠标、游戏手柄等）进行交互。

* **输入事件处理:**  Android 的输入系统使用这些结构体来接收和处理来自 HID 设备的输入事件。例如，当用户触摸屏幕时，触摸屏控制器会生成 HID 事件，内核驱动程序会将这些事件转换为 `hiddev_event` 结构体，并通过字符设备接口传递给用户空间。Android 的 `InputReader` 等组件会读取这些事件并进行处理。

* **设备信息查询:**  Android 系统需要获取连接的 HID 设备的各种信息，例如设备名称、供应商 ID、产品 ID 等，以便正确识别和配置设备。`HIDIOCGDEVINFO` 和 `HIDIOCGSTRING` 等 ioctl 命令就是用于实现这个目的。例如，当连接一个新的蓝牙键盘时，Android 系统会使用这些命令来获取键盘的信息。

* **HID 报告交互:**  某些 HID 设备支持输出报告或特性报告，例如力反馈手柄。Android 应用可以通过 `HIDIOCSREPORT` 等 ioctl 命令向设备发送数据，控制设备的行为。

**libc 函数功能实现解释：**

这个头文件本身并不包含 `libc` 函数的实现，它只是定义了数据结构和常量。实际的 `libc` 函数（例如 `open`, `ioctl`, `read`, `write` 等）的实现位于 Bionic 的其他源文件中。

* **`open`**: 用户空间程序通过 `open` 系统调用打开与 HID 设备关联的字符设备文件（通常位于 `/dev/hidraw*`）。内核的设备驱动程序会创建这些设备文件。

* **`ioctl`**:  `ioctl` 系统调用是与设备驱动程序进行控制交互的主要方式。当用户空间程序调用 `ioctl` 并传入 `HIDIOCGVERSION`、`HIDIOCGDEVINFO` 等命令时，内核的 HID 设备驱动程序会根据命令执行相应的操作，例如读取设备信息并填充到 `hiddev_devinfo` 结构体中，然后将数据返回给用户空间。

* **`read`**:  对于某些 HID 设备，例如简单的输入设备，用户空间程序可以使用 `read` 系统调用从设备文件中读取输入事件。内核驱动程序会将接收到的 HID 报告转换为 `hiddev_event` 结构体并放入读取缓冲区。

* **`write`**:  对于支持输出报告的 HID 设备，用户空间程序可以使用 `write` 系统调用向设备发送数据。内核驱动程序会将写入的数据封装成 HID 输出报告并发送给设备。

**dynamic linker 功能：**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的作用是在程序运行时加载和链接共享库 (`.so` 文件)。

如果某个共享库（例如负责 HID 设备管理的系统服务或库）使用了这个头文件中定义的结构体和常量，那么 dynamic linker 会在加载这个共享库时，确保相关的符号（例如使用这些结构体的函数）能够正确地被解析和链接。

**so 布局样本：**

假设有一个名为 `libhidmanager.so` 的共享库使用了 `hiddev.h` 中定义的结构体：

```
libhidmanager.so:
    .text          # 代码段
        hid_device_open:   # 打开 HID 设备的函数
            ...
            // 使用 open 系统调用打开 /dev/hidraw*
            // 可能使用 hiddev_devinfo 结构体来存储设备信息
            ...
        hid_get_device_info: # 获取设备信息的函数
            ...
            // 使用 ioctl 系统调用和 HIDIOCGDEVINFO 命令
            // 填充 hiddev_devinfo 结构体
            ...
        hid_process_event:  # 处理 HID 事件的函数
            ...
            // 接收 hiddev_event 结构体
            ...
    .data          # 数据段
        ...
    .rodata        # 只读数据段
        ...
    .dynsym        # 动态符号表
        hid_device_open
        hid_get_device_info
        hid_process_event
        ioctl         # 来自 libc.so
        ...
    .dynstr        # 动态字符串表
        hid_device_open
        hid_get_device_info
        hid_process_event
        ioctl
        ...
    .rel.dyn       # 动态重定位表
        # 指示需要在运行时解析的符号及其地址
        重定位 ioctl 函数的地址
        ...
```

**链接的处理过程：**

1. 当一个应用程序或系统服务需要使用 `libhidmanager.so` 中的功能时，操作系统会加载这个共享库。
2. Dynamic linker 会读取 `libhidmanager.so` 的头部信息，包括 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)。
3. Dynamic linker 会遍历 `libhidmanager.so` 的 `.rel.dyn` (动态重定位表)，找到需要重定位的符号。例如，如果 `hid_get_device_info` 函数中调用了 `ioctl`，那么 `ioctl` 就是一个需要重定位的符号。
4. Dynamic linker 会在已经加载的共享库（例如 `libc.so`）中查找 `ioctl` 函数的地址。`libc.so` 中包含了 `ioctl` 的实现。
5. Dynamic linker 将找到的 `ioctl` 函数的地址更新到 `hid_get_device_info` 函数中调用 `ioctl` 的位置。
6. 这样，当 `hid_get_device_info` 函数被执行时，它就可以正确地调用 `libc.so` 中的 `ioctl` 函数。

**逻辑推理、假设输入与输出：**

假设用户空间程序想要获取一个 HID 设备的设备信息，并使用了 `HIDIOCGDEVINFO` ioctl 命令。

**假设输入：**

* 打开 HID 设备的字符设备文件描述符 `fd`。
* 声明一个 `struct hiddev_devinfo` 类型的变量 `devinfo`。

**逻辑推理：**

1. 用户空间程序调用 `ioctl(fd, HIDIOCGDEVINFO, &devinfo)`。
2. 内核的 HID 设备驱动程序接收到 `HIDIOCGDEVINFO` 命令。
3. 驱动程序会读取 HID 设备的硬件信息，例如通过 USB 或蓝牙协议获取设备的 Vendor ID、Product ID 等。
4. 驱动程序将读取到的信息填充到 `devinfo` 结构体中。
5. `ioctl` 系统调用返回，并将填充好的 `devinfo` 结构体的数据返回给用户空间程序。

**假设输出：**

`devinfo` 结构体中的成员将被填充为 HID 设备的实际信息，例如：

```
devinfo.bustype = 0x03;       // USB 总线
devinfo.busnum = 1;
devinfo.devnum = 10;
devinfo.ifnum = 0;
devinfo.vendor = 0x1234;      // 假设的 Vendor ID
devinfo.product = 0x5678;     // 假设的 Product ID
devinfo.version = 0x0100;
devinfo.num_applications = 1;
```

**用户或编程常见的使用错误：**

1. **错误的 `ioctl` 命令:**  使用了错误的 `ioctl` 命令编号，导致内核无法识别请求。
   ```c
   ioctl(fd, 0xBAD, &devinfo); // 错误的命令编号
   ```

2. **传递错误大小的结构体:**  `ioctl` 命令可能期望特定大小的结构体，如果传递的结构体大小不匹配，可能会导致数据损坏或程序崩溃。

3. **未正确初始化结构体:**  某些 `ioctl` 命令需要在传递结构体之前初始化某些成员。如果未正确初始化，可能会导致意外的行为。
   ```c
   struct hiddev_report_info report;
   // report.report_type 未初始化
   ioctl(fd, HIDIOCGREPORTINFO, &report);
   ```

4. **操作未打开的设备文件描述符:**  尝试在未通过 `open` 系统调用打开的设备文件描述符上执行 `ioctl` 操作会导致错误。

5. **权限问题:**  用户可能没有足够的权限访问 HID 设备文件（例如 `/dev/hidraw*`），导致 `open` 或 `ioctl` 调用失败。

6. **缓冲区溢出:**  在使用需要传递缓冲区的 `ioctl` 命令时，例如 `HIDIOCGSTRING`，如果没有正确分配和管理缓冲区大小，可能会导致缓冲区溢出。

**Android framework 或 ndk 如何一步步的到达这里：**

1. **Framework (Java/Kotlin):**  Android Framework 中的 `InputManagerService` 或相关的系统服务负责管理输入设备。当需要与 HID 设备交互时，Framework 会通过 JNI (Java Native Interface) 调用 NDK 中的 native 代码。

2. **NDK (Native 代码):**
   * NDK 中可能存在一个 HID 设备管理模块，或者直接使用 Linux 的标准 C 库函数。
   * 该模块会使用 `open` 系统调用打开 HID 设备的字符设备文件（例如 `/dev/input/event*` 或 `/dev/hidraw*`，取决于具体的设备类型和访问方式）。
   * 为了获取或设置 HID 设备的属性或进行数据交互，NDK 代码会调用 `ioctl` 系统调用，并使用 `hiddev.h` 中定义的 `HIDIOC*` 命令和相关的结构体。例如，使用 `HIDIOCGDEVINFO` 获取设备信息，使用 `HIDIOCGREPORT` 或 `HIDIOCSREPORT` 获取或设置报告。
   * 对于输入事件的读取，NDK 代码可能会使用 `read` 系统调用读取设备文件中的事件数据。

**Frida hook 示例调试这些步骤：**

可以使用 Frida hook `ioctl` 系统调用来观察 Android 系统与 HID 设备的交互。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    'use strict';

    rpc.exports = {};

    const ioctlPtr = Module.getExportByName(null, "ioctl");

    Interceptor.attach(ioctlPtr, {
        onEnter: function (args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            let requestName = "UNKNOWN";
            if (request === 0x4801) requestName = "HIDIOCGVERSION";
            else if (request === 0x4803) requestName = "HIDIOCGDEVINFO";
            else if (request === 0x4804) requestName = "HIDIOCGSTRING";
            else if (request === 0xc00c4807) requestName = "HIDIOCGREPORT";
            else if (request === 0xc00c4808) requestName = "HIDIOCSREPORT";
            // 添加更多 HIDIOC 命令

            let deviceInfo = {};
            if (request === 0x4803) {
                deviceInfo = {
                    bustype: argp.readU32(),
                    busnum: argp.add(4).readU32(),
                    devnum: argp.add(8).readU32(),
                    ifnum: argp.add(12).readU32(),
                    vendor: argp.add(16).readU16(),
                    product: argp.add(18).readU16(),
                    version: argp.add(20).readU16(),
                    num_applications: argp.add(24).readU32()
                };
            } else if (request === 0x4804) {
                deviceInfo = {
                    index: argp.readS32(),
                    value: argp.add(4).readUtf8String(256)
                };
            }

            send({ tag: "ioctl", data: { fd: fd, request: requestName, request_raw: request, argp: argp, devinfo: deviceInfo } });
        },
        onLeave: function (retval) {
            //console.log("ioctl returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()

    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 将上述 Python 代码保存为 `frida_hid_hook.py`。
2. 运行 Frida 服务，并确保目标 Android 设备或模拟器已连接。
3. 运行脚本，替换 `<process name or PID>` 为你想要监控的进程名称或 PID（例如，`system_server`，它负责处理许多系统服务）。
   ```bash
   python frida_hid_hook.py system_server
   ```

**Frida hook 示例输出：**

当你运行脚本后，任何目标进程调用的 `ioctl` 系统调用都会被 hook，并打印出相关信息，包括文件描述符、ioctl 命令编号和名称，以及部分参数（例如，当调用 `HIDIOCGDEVINFO` 或 `HIDIOCGSTRING` 时，会尝试解析并打印 `hiddev_devinfo` 或 `hiddev_string_descriptor` 结构体的内容）。

例如，你可能会看到类似以下的输出：

```
[*] ioctl: {'fd': 98, 'request': 'HIDIOCGDEVINFO', 'request_raw': 1153, 'argp': <NativePointer value=0xXXXXXXXXX>, 'devinfo': {'bustype': 3, 'busnum': 0, 'devnum': 12, 'ifnum': 0, 'vendor': 8086, 'product': 9, 'version': 256, 'num_applications': 1}}
[*] ioctl: {'fd': 98, 'request': 'HIDIOCGSTRING', 'request_raw': 1156, 'argp': <NativePointer value=0xXXXXXXXXX>, 'devinfo': {'index': 0, 'value': 'Logitech USB Keyboard'}}
```

这个 Frida hook 示例可以帮助你理解 Android 系统在底层是如何使用 `ioctl` 命令与 HID 设备进行交互的，并观察传递的具体数据。你需要根据需要添加更多 `HIDIOC` 命令的解析。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/hiddev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_HIDDEV_H
#define _UAPI_HIDDEV_H
#include <linux/types.h>
struct hiddev_event {
  unsigned hid;
  signed int value;
};
struct hiddev_devinfo {
  __u32 bustype;
  __u32 busnum;
  __u32 devnum;
  __u32 ifnum;
  __s16 vendor;
  __s16 product;
  __s16 version;
  __u32 num_applications;
};
struct hiddev_collection_info {
  __u32 index;
  __u32 type;
  __u32 usage;
  __u32 level;
};
#define HID_STRING_SIZE 256
struct hiddev_string_descriptor {
  __s32 index;
  char value[HID_STRING_SIZE];
};
struct hiddev_report_info {
  __u32 report_type;
  __u32 report_id;
  __u32 num_fields;
};
#define HID_REPORT_ID_UNKNOWN 0xffffffff
#define HID_REPORT_ID_FIRST 0x00000100
#define HID_REPORT_ID_NEXT 0x00000200
#define HID_REPORT_ID_MASK 0x000000ff
#define HID_REPORT_ID_MAX 0x000000ff
#define HID_REPORT_TYPE_INPUT 1
#define HID_REPORT_TYPE_OUTPUT 2
#define HID_REPORT_TYPE_FEATURE 3
#define HID_REPORT_TYPE_MIN 1
#define HID_REPORT_TYPE_MAX 3
struct hiddev_field_info {
  __u32 report_type;
  __u32 report_id;
  __u32 field_index;
  __u32 maxusage;
  __u32 flags;
  __u32 physical;
  __u32 logical;
  __u32 application;
  __s32 logical_minimum;
  __s32 logical_maximum;
  __s32 physical_minimum;
  __s32 physical_maximum;
  __u32 unit_exponent;
  __u32 unit;
};
#define HID_FIELD_CONSTANT 0x001
#define HID_FIELD_VARIABLE 0x002
#define HID_FIELD_RELATIVE 0x004
#define HID_FIELD_WRAP 0x008
#define HID_FIELD_NONLINEAR 0x010
#define HID_FIELD_NO_PREFERRED 0x020
#define HID_FIELD_NULL_STATE 0x040
#define HID_FIELD_VOLATILE 0x080
#define HID_FIELD_BUFFERED_BYTE 0x100
struct hiddev_usage_ref {
  __u32 report_type;
  __u32 report_id;
  __u32 field_index;
  __u32 usage_index;
  __u32 usage_code;
  __s32 value;
};
#define HID_MAX_MULTI_USAGES 1024
struct hiddev_usage_ref_multi {
  struct hiddev_usage_ref uref;
  __u32 num_values;
  __s32 values[HID_MAX_MULTI_USAGES];
};
#define HID_FIELD_INDEX_NONE 0xffffffff
#define HID_VERSION 0x010004
#define HIDIOCGVERSION _IOR('H', 0x01, int)
#define HIDIOCAPPLICATION _IO('H', 0x02)
#define HIDIOCGDEVINFO _IOR('H', 0x03, struct hiddev_devinfo)
#define HIDIOCGSTRING _IOR('H', 0x04, struct hiddev_string_descriptor)
#define HIDIOCINITREPORT _IO('H', 0x05)
#define HIDIOCGNAME(len) _IOC(_IOC_READ, 'H', 0x06, len)
#define HIDIOCGREPORT _IOW('H', 0x07, struct hiddev_report_info)
#define HIDIOCSREPORT _IOW('H', 0x08, struct hiddev_report_info)
#define HIDIOCGREPORTINFO _IOWR('H', 0x09, struct hiddev_report_info)
#define HIDIOCGFIELDINFO _IOWR('H', 0x0A, struct hiddev_field_info)
#define HIDIOCGUSAGE _IOWR('H', 0x0B, struct hiddev_usage_ref)
#define HIDIOCSUSAGE _IOW('H', 0x0C, struct hiddev_usage_ref)
#define HIDIOCGUCODE _IOWR('H', 0x0D, struct hiddev_usage_ref)
#define HIDIOCGFLAG _IOR('H', 0x0E, int)
#define HIDIOCSFLAG _IOW('H', 0x0F, int)
#define HIDIOCGCOLLECTIONINDEX _IOW('H', 0x10, struct hiddev_usage_ref)
#define HIDIOCGCOLLECTIONINFO _IOWR('H', 0x11, struct hiddev_collection_info)
#define HIDIOCGPHYS(len) _IOC(_IOC_READ, 'H', 0x12, len)
#define HIDIOCGUSAGES _IOWR('H', 0x13, struct hiddev_usage_ref_multi)
#define HIDIOCSUSAGES _IOW('H', 0x14, struct hiddev_usage_ref_multi)
#define HIDDEV_FLAG_UREF 0x1
#define HIDDEV_FLAG_REPORT 0x2
#define HIDDEV_FLAGS 0x3
#endif
```