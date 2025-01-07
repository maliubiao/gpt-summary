Response:
Let's break down the thought process for generating the detailed explanation of the `uvcvideo.h` header file.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`uvcvideo.h`) within the context of Android's Bionic library. The request specifically asks for:

* **Functionality Listing:** What does this code *do*?
* **Android Relevance:** How does this relate to Android features? Examples needed.
* **Libc Function Details:**  Explain the libc functions used.
* **Dynamic Linker Aspects:** How does this interact with the dynamic linker (if at all)? Provide SO layout and linking process.
* **Logical Reasoning:** Any inferences about input/output.
* **Common Errors:** Potential pitfalls for users/programmers.
* **Android Framework/NDK Flow:** How does Android reach this code? Frida hooking examples.

**2. Initial Code Scan and Keyword Identification:**

My first step is to quickly scan the code for keywords and structures that reveal its purpose. I see:

* `#ifndef`, `#define`, `#include`: Standard C preprocessor directives for header guards and inclusion.
* `linux/ioctl.h`, `linux/types.h`: Includes indicating interaction with the Linux kernel. `ioctl` is a strong clue about device control.
* `UVC_CTRL_*`:  Constants suggesting control mechanisms related to UVC (USB Video Class).
* `struct uvc_menu_info`, `struct uvc_xu_control_mapping`, `struct uvc_xu_control_query`, `struct uvc_meta_buf`: Structure definitions likely representing data exchanged with the kernel.
* `UVCIOC_*`: Constants that strongly suggest `ioctl` commands. The `_IOWR` macro further confirms this (Input/Output/Read/Write).
* `__u32`, `__u8`, `__u16`, `__u64`:  Typedefs for unsigned integer types, common in kernel interfaces.
* `__attribute__((__packed__))`:  Compiler directive to avoid padding in the structure.

**3. Deduction of Core Functionality:**

Based on the keywords, the main purpose of this header file becomes clear: **defining the interface for controlling UVC (USB Video Class) devices from user space within Android.**  The `ioctl` commands and data structures are the key to this interaction.

**4. Connecting to Android Functionality:**

Now I need to bridge this low-level interface to user-visible Android features. The most obvious connection is the **camera**. Android devices frequently use UVC-compliant cameras. This header likely plays a role in how the Android camera framework interacts with the underlying camera hardware.

**5. Analyzing Specific Code Elements:**

* **Control Constants (`UVC_CTRL_*`):** These define the different types of controls and operations that can be performed on UVC devices (setting, getting, min, max, etc.). I categorize them and explain their meanings.
* **Data Type Constants (`UVC_CTRL_DATA_TYPE_*`):**  These indicate the data types of the control values (raw, signed, unsigned, etc.).
* **`struct uvc_menu_info`:** This seems to be used for enumerating possible values for controls that have a discrete set of options (like quality settings).
* **`struct uvc_xu_control_mapping`:** This is more complex and likely describes the mapping of UVC extension unit controls to V4L2 (Video4Linux2) controls. This is a crucial link between UVC and the standard Linux video framework.
* **`struct uvc_xu_control_query`:** This structure is used for sending control requests to the UVC device.
* **`UVCIOC_CTRL_MAP` and `UVCIOC_CTRL_QUERY`:** These are the `ioctl` request codes used to interact with the kernel driver. I explain the meaning of the `_IOWR` macro and the arguments.
* **`struct uvc_meta_buf`:** This structure seems to carry metadata associated with video frames, including timestamps and flags.

**6. Addressing Libc and Dynamic Linker:**

The file includes `<linux/ioctl.h>` and `<linux/types.h>`. These aren't strictly *libc functions* themselves but *kernel headers* that Bionic provides. The *use* of the defined constants and structures will likely involve libc functions like `open()`, `close()`, and `ioctl()`. I focus on `ioctl()` and explain its role.

The dynamic linker aspect is trickier. This header file itself doesn't directly involve dynamic linking. However, the *code that uses this header* (likely in Android system services or HALs) *will* be part of shared libraries. Therefore, I provide a general example of SO layout and the linking process relevant to how such a library might interact with the kernel.

**7. Logical Reasoning (Assumptions and Input/Output):**

I consider a simple scenario: setting a camera brightness control. This involves using the `UVC_CTRL_FLAG_SET_CUR` flag and sending the desired brightness value using `UVCIOC_CTRL_QUERY`. I illustrate this with a hypothetical input and output.

**8. Common Usage Errors:**

I think about potential mistakes developers could make: incorrect `ioctl` codes, incorrect data sizes, or not handling errors from `ioctl()`.

**9. Android Framework/NDK Flow and Frida Hooking:**

This requires tracing the execution path from the Android application layer down to the kernel interaction. I outline the general layers involved: Java Camera2 API -> Native Camera Service -> HAL (Hardware Abstraction Layer) -> Kernel Driver.

For Frida hooking, I choose key points in this path: the `ioctl` call itself in the HAL or the camera service. I provide concrete Frida examples to intercept these calls and inspect the arguments.

**10. Structuring the Output:**

Finally, I organize the information logically, using headings and bullet points for clarity. I make sure to address each part of the original request comprehensively and provide clear explanations and examples. I use precise language and avoid jargon where possible, or explain it when necessary. The goal is to create a detailed yet understandable explanation of the header file's purpose and its role within the Android ecosystem.
这是一个描述USB视频类 (UVC) 设备在 Linux 内核中用户空间接口的头文件 (`uvcvideo.h`)。 它定义了与 UVC 设备交互所需的常量、结构体和ioctl命令。 因为它位于 `bionic/libc/kernel/uapi/linux/`, 这意味着它是从 Linux 内核头文件中复制过来的，用于 Android Bionic C 库，使得用户空间程序能够以类型安全的方式与内核进行交互。

**功能列举:**

1. **定义UVC控制单元的数据类型:**  `UVC_CTRL_DATA_TYPE_*` 定义了UVC控制单元可以表示的不同数据类型，例如原始数据、有符号整数、无符号整数、布尔值、枚举和位掩码。
2. **定义UVC控制单元的标志位:** `UVC_CTRL_FLAG_*` 定义了可以应用于UVC控制单元的不同操作标志，例如设置当前值、获取当前值、获取最小值、获取最大值、获取分辨率、获取默认值、恢复默认值、自动更新和异步操作。 `UVC_CTRL_FLAG_GET_RANGE` 是一个组合标志，用于一次性获取最小值、最大值、分辨率和默认值。
3. **定义菜单项信息结构体 `uvc_menu_info`:** 用于描述具有离散值的控制单元的菜单项，包含菜单项的值和名称。
4. **定义扩展单元控制映射结构体 `uvc_xu_control_mapping`:**  描述了UVC扩展单元中的一个控制的属性，包括ID、名称、所属实体、选择器、大小、偏移量、V4L2类型、数据类型、相关的菜单信息以及菜单项的数量。这对于用户空间程序理解和操作扩展单元控制至关重要。
5. **定义扩展单元控制查询结构体 `uvc_xu_control_query`:** 用于向UVC扩展单元发送控制查询请求，包含单元ID、选择器、查询类型、数据大小和指向数据的指针。
6. **定义ioctl命令:** `UVCIOC_CTRL_MAP` 和 `UVCIOC_CTRL_QUERY` 是用于与UVC驱动程序进行交互的ioctl命令。 `UVCIOC_CTRL_MAP` 用于获取扩展单元控制的映射信息，`UVCIOC_CTRL_QUERY` 用于查询或设置扩展单元控制的值。
7. **定义元数据缓冲区结构体 `uvc_meta_buf`:**  用于携带与视频帧相关的元数据，例如纳秒级时间戳、帧起始符 (SOF)、长度和标志。

**与Android功能的关联及举例说明:**

这个头文件直接关系到 **Android 设备上的摄像头功能**。  Android 设备通常使用符合 UVC 标准的摄像头。

* **摄像头控制:** Android Camera2 API 或旧的 Camera API 最终会调用底层的 Native 代码，这些代码会使用这里定义的ioctl命令和数据结构来控制摄像头硬件的各种参数，例如曝光、增益、白平衡、对焦等。
    * **举例:** 当你在 Android 相机应用中调整亮度滑块时，Framework 会将这个操作转换为相应的 UVC 控制指令，例如设置 `UVC_CTRL_FLAG_SET_CUR` 标志，并通过 `UVCIOC_CTRL_QUERY` ioctl 命令发送到摄像头驱动。
* **扩展单元控制:** 某些摄像头可能具有标准的 UVC 规范之外的扩展功能。 `uvc_xu_control_mapping` 和 `uvc_xu_control_query` 结构体允许 Android 代码与这些扩展单元进行交互，以实现更高级或特定的摄像头功能。
    * **举例:**  某些摄像头可能具有自定义的滤镜或特效控制，这些控制可能通过扩展单元实现。Android HAL (Hardware Abstraction Layer) 或 vendor 提供的库可以使用这里的结构体来读取和设置这些自定义控制。
* **获取摄像头信息:**  `UVCIOC_CTRL_MAP` 可以用来查询摄像头支持的各种控制单元及其属性，Android 系统可以使用这些信息来构建用户界面或进行能力检测。
* **元数据获取:**  `uvc_meta_buf` 结构体允许 Android 框架获取与视频帧同步的元数据信息，这对于实现时间戳同步、帧同步等高级功能非常有用。
    * **举例:** 在需要精确时间戳的视频录制或图像处理应用中，可以使用 `uvc_meta_buf` 中的 `ns` 字段来获取帧捕获的纳秒级时间戳。

**libc函数的功能实现:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了数据结构和常量。 真正与内核进行交互的是通过 `ioctl` 系统调用，而 `ioctl` 是一个标准的 libc 函数。

* **`ioctl()` 函数的功能:** `ioctl` (input/output control) 是一个通用的设备输入输出控制系统调用。它允许用户空间的应用程序向设备驱动程序发送设备特定的控制命令和数据。其基本功能是向设备文件描述符发送一个控制命令代码（通常是一个宏定义，如 `UVCIOC_CTRL_MAP`），并可以携带一些数据（通过指针传递）。

* **`ioctl()` 的实现原理:**
    1. 当用户空间程序调用 `ioctl(fd, request, argp)` 时，其中 `fd` 是设备文件描述符，`request` 是控制命令代码，`argp` 是指向参数结构的指针。
    2. 系统调用陷入内核。
    3. 内核根据 `fd` 找到对应的设备驱动程序。
    4. 内核根据 `request` 值调用设备驱动程序中相应的 `ioctl` 处理函数。
    5. 设备驱动程序根据 `request` 和 `argp` 指向的数据执行相应的操作，例如读取或设置硬件寄存器的值。
    6. 驱动程序将结果返回给内核，内核再将结果返回给用户空间程序。

**涉及dynamic linker的功能，so布局样本，以及链接的处理过程:**

这个头文件定义的是内核接口，本身不涉及动态链接。然而，**使用这个头文件的代码** 通常会存在于 Android 的共享库 (shared object, .so) 中，例如 Camera Service 或 HAL 实现。

**so 布局样本:**

```
libcamera_service.so:
  .text         # 代码段
  .rodata       # 只读数据段
  .data         # 初始化数据段
  .bss          # 未初始化数据段
  .dynamic      # 动态链接信息
  .dynsym       # 动态符号表
  .dynstr       # 动态字符串表
  .plt          # 过程链接表
  .got.plt      # 全局偏移量表 (过程链接表项)
  ...
```

**链接的处理过程:**

1. **编译时:**  当编译包含 `uvcvideo.h` 的 C/C++ 代码时，编译器会识别出 `ioctl` 系统调用以及相关的结构体和常量。 由于 `uvcvideo.h` 来自内核头文件，这些结构体和常量定义会被直接嵌入到编译后的目标文件中。
2. **链接时:**
   * 如果代码直接调用了 `ioctl`，链接器会确保链接到提供 `ioctl` 函数的 C 运行时库 (libc.so)。
   * 如果代码位于一个共享库中，动态链接器 (linker) 在加载这个库时，会解析库的依赖关系，并加载所需的其他共享库 (例如 libc.so)。
   * 动态链接器会处理符号的重定位，确保函数调用和数据访问指向正确的内存地址。  例如，对 `ioctl` 的调用会通过过程链接表 (PLT) 和全局偏移量表 (GOT) 进行间接调用。

**假设输入与输出 (逻辑推理):**

假设一个 Android Camera HAL 需要获取某个 UVC 扩展单元控制的最小值。

**假设输入:**

* 设备文件描述符 `fd`: 指向 UVC 摄像头设备的 `/dev/videoX` 文件。
* `uvc_xu_control_mapping` 结构体 `mapping`:  已经通过 `UVCIOC_CTRL_MAP` 获取，包含了目标控制的 `unit` (扩展单元 ID) 和 `selector` (控制选择器)。
* 需要获取最小值的控制，因此 `query` 字段设置为获取最小值对应的宏 (在实际的 UVC 驱动代码中定义，但通常与 `UVC_CTRL_FLAG_GET_MIN` 相关联)。
* `size`:  目标控制值的数据类型大小。
* `data`:  指向足够大小的内存缓冲区的指针，用于接收最小值。

**输出:**

* `ioctl` 系统调用成功返回 0。
* `data` 指向的内存缓冲区中包含了目标 UVC 控制的最小值。

**代码示例 (伪代码):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/uvcvideo.h>

int main() {
    int fd = open("/dev/video0", O_RDWR);
    if (fd < 0) {
        perror("打开设备失败");
        return 1;
    }

    struct uvc_xu_control_mapping mapping;
    // ... 假设已经通过 UVCIOC_CTRL_MAP 获取了 mapping 信息 ...
    mapping.unit = /* 扩展单元 ID */;
    mapping.selector = /* 控制选择器 */;
    mapping.size = /* 控制值大小 */;

    struct uvc_xu_control_query query;
    query.unit = mapping.unit;
    query.selector = mapping.selector;
    query.query = /* 获取最小值的查询类型 */; // 实际值由驱动定义
    query.size = mapping.size;
    __u8 *data = malloc(query.size);
    if (!data) {
        perror("分配内存失败");
        close(fd);
        return 1;
    }
    query.data = data;

    if (ioctl(fd, UVCIOC_CTRL_QUERY, &query) == 0) {
        printf("成功获取最小值: ");
        // 根据 mapping.data_type 将 data 转换为相应的类型并打印
        if (mapping.data_type == UVC_CTRL_DATA_TYPE_UNSIGNED) {
            if (mapping.size == 1) printf("%u\n", *(__u8*)data);
            else if (mapping.size == 2) printf("%u\n", *(__u16*)data);
            else if (mapping.size == 4) printf("%u\n", *(__u32*)data);
        }
        // ... 其他数据类型的处理 ...
    } else {
        perror("ioctl 调用失败");
    }

    free(data);
    close(fd);
    return 0;
}
```

**用户或编程常见的使用错误:**

1. **错误的 ioctl 命令代码:** 使用了错误的 `UVCIOC_CTRL_MAP` 或 `UVCIOC_CTRL_QUERY` 命令，或者使用了其他不适用于 UVC 设备的 ioctl 命令。
2. **数据结构大小不匹配:**  传递给 `ioctl` 的数据结构大小与内核驱动程序期望的大小不一致，可能导致数据截断或内存访问错误。
3. **访问无效的设备文件:** 尝试打开不存在或没有权限访问的 UVC 设备文件 (例如 `/dev/videoX`)。
4. **错误的控制单元或选择器:**  在 `uvc_xu_control_query` 结构体中指定了不存在的扩展单元 ID 或控制选择器。
5. **未正确处理 `ioctl` 的返回值:**  `ioctl` 调用可能失败，返回 -1 并设置 `errno`，但程序没有检查返回值并处理错误。
6. **数据类型不匹配:**  在设置或获取控制值时，使用了与控制单元实际数据类型不符的数据类型。
7. **并发访问冲突:**  多个进程或线程同时访问同一个 UVC 设备，可能导致数据竞争或设备状态异常。
8. **内存管理错误:**  例如，在 `uvc_xu_control_query` 中分配的 `data` 缓冲区大小不足以存储返回的数据，或者忘记释放分配的内存。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android 应用开发者不会直接使用 `uvcvideo.h` 中定义的接口。 这些接口主要在 Android Framework 的底层服务和硬件抽象层 (HAL) 中使用。

**步骤:**

1. **Android 应用层 (Java/Kotlin):** 开发者使用 Android 的 Camera2 API 或旧的 Camera API 来访问摄像头。
2. **Framework 层 (Java):**  Camera Service (或 Media Server 中的相关组件) 接收来自应用层的请求，并进行权限检查、资源管理等操作。
3. **Native Framework 层 (C++):** Camera Service 的 Native 代码 (通常在 `system/media/camera/` 或相关目录) 会与 HAL 进行交互。
4. **Hardware Abstraction Layer (HAL) (C/C++):**  Camera HAL 实现 (通常由设备制造商提供，位于 `/vendor/` 分区) 负责与底层的摄像头驱动程序进行交互。  **在这里，HAL 代码会使用 `open()` 打开设备文件，并使用 `ioctl()` 系统调用，以及 `uvcvideo.h` 中定义的结构体和常量来控制 UVC 摄像头。**
5. **Kernel Driver:**  UVC 摄像头的内核驱动程序 (通常是 Linux 内核自带的 `uvcvideo` 驱动) 接收到 `ioctl` 命令后，会解析命令和数据，并与摄像头硬件进行通信。

**Frida Hook 示例:**

可以使用 Frida hook Camera HAL 中调用 `ioctl` 的地方，来观察传递给 `ioctl` 的参数，从而了解 Android Framework 如何使用 `uvcvideo.h` 中定义的接口。

假设我们想 hook 一个 Camera HAL 库 (`/vendor/lib64/hw/camera.device@3.5-impl.so`) 中调用 `ioctl` 的地方。我们需要找到 HAL 中与 UVC 控制相关的函数，这可能需要一些逆向分析或查看 HAL 的源代码。

```python
import frida
import sys

# 替换为你的目标进程名称或进程 ID
package_name = "com.android.camera2"

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保相机应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查是否是与 UVC 相关的 ioctl 命令 (这里只是一个示例，实际需要根据 UVCIOC 的值进行判断)
        if (request === 0xc0107520 || request === 0xc00c7521) { // 示例: UVCIOC_CTRL_MAP 和 UVCIOC_CTRL_QUERY 的值 (需要根据实际情况替换)
            console.log("ioctl called with fd:", fd, "request:", request);

            if (request === 0xc0107520) {
                // UVCIOC_CTRL_MAP
                const mappingPtr = argp;
                const mapping = Memory.readByteArray(mappingPtr, 80); // 假设 uvc_xu_control_mapping 结构体大小为 80 字节
                console.log("  uvc_xu_control_mapping:", hexdump(mapping, { ansi: true }));
            } else if (request === 0xc00c7521) {
                // UVCIOC_CTRL_QUERY
                const queryPtr = argp;
                const query = Memory.readByteArray(queryPtr, 16); // 假设 uvc_xu_control_query 结构体大小为 16 字节
                console.log("  uvc_xu_control_query:", hexdump(query, { ansi: true }));
            }
        }
    },
    onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
session.detach()
```

**解释 Frida 脚本:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 应用程序的进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), ...)`:**  Hook `libc.so` 库中的 `ioctl` 函数。
3. **`onEnter: function (args)`:**  在 `ioctl` 函数被调用时执行。
4. **`args[0]`, `args[1]`, `args[2]`:**  分别对应 `ioctl` 的文件描述符 `fd`、请求代码 `request` 和参数指针 `argp`。
5. **`if (request === 0xc0107520 || request === 0xc00c7521)`:**  这是一个示例，你需要根据实际的 `UVCIOC_CTRL_MAP` 和 `UVCIOC_CTRL_QUERY` 宏定义的值来替换。你可以通过查看内核头文件或反汇编 HAL 库来找到这些值。
6. **`Memory.readByteArray(mappingPtr, ...)` 和 `Memory.readByteArray(queryPtr, ...)`:** 读取参数指针指向的内存，以便查看传递给 `ioctl` 的 `uvc_xu_control_mapping` 和 `uvc_xu_control_query` 结构体的内容。
7. **`hexdump(...)`:**  以十六进制格式打印内存内容，方便查看结构体中的数据。

**使用 Frida Hook 的步骤:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida 工具。
2. **连接到 Android 设备:** 确保你的电脑可以通过 adb 连接到已 root 的 Android 设备，并且设备上安装了 frida-server。
3. **运行 Frida 脚本:** 保存上面的 Python 代码为 `.py` 文件，然后在终端中运行 `python your_script_name.py`。
4. **启动或操作相机应用:**  当 Frida 脚本运行时，启动你的 Android 相机应用程序并进行一些操作 (例如调整设置、拍照等)。
5. **查看输出:** Frida 会拦截 `ioctl` 调用，并在终端中打印出相关的参数信息，包括文件描述符、ioctl 请求代码以及 `uvc_xu_control_mapping` 和 `uvc_xu_control_query` 结构体的内容。

通过分析 Frida 的输出，你可以了解 Android Framework 是如何使用 `uvcvideo.h` 中定义的结构体和 ioctl 命令来与摄像头驱动程序进行交互的。  你需要根据实际情况调整 Frida 脚本中的 `request` 值和结构体大小。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/uvcvideo.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_UVCVIDEO_H_
#define __LINUX_UVCVIDEO_H_
#include <linux/ioctl.h>
#include <linux/types.h>
#define UVC_CTRL_DATA_TYPE_RAW 0
#define UVC_CTRL_DATA_TYPE_SIGNED 1
#define UVC_CTRL_DATA_TYPE_UNSIGNED 2
#define UVC_CTRL_DATA_TYPE_BOOLEAN 3
#define UVC_CTRL_DATA_TYPE_ENUM 4
#define UVC_CTRL_DATA_TYPE_BITMASK 5
#define UVC_CTRL_FLAG_SET_CUR (1 << 0)
#define UVC_CTRL_FLAG_GET_CUR (1 << 1)
#define UVC_CTRL_FLAG_GET_MIN (1 << 2)
#define UVC_CTRL_FLAG_GET_MAX (1 << 3)
#define UVC_CTRL_FLAG_GET_RES (1 << 4)
#define UVC_CTRL_FLAG_GET_DEF (1 << 5)
#define UVC_CTRL_FLAG_RESTORE (1 << 6)
#define UVC_CTRL_FLAG_AUTO_UPDATE (1 << 7)
#define UVC_CTRL_FLAG_ASYNCHRONOUS (1 << 8)
#define UVC_CTRL_FLAG_GET_RANGE (UVC_CTRL_FLAG_GET_CUR | UVC_CTRL_FLAG_GET_MIN | UVC_CTRL_FLAG_GET_MAX | UVC_CTRL_FLAG_GET_RES | UVC_CTRL_FLAG_GET_DEF)
#define UVC_MENU_NAME_LEN 32
struct uvc_menu_info {
  __u32 value;
  __u8 name[UVC_MENU_NAME_LEN];
};
struct uvc_xu_control_mapping {
  __u32 id;
  __u8 name[32];
  __u8 entity[16];
  __u8 selector;
  __u8 size;
  __u8 offset;
  __u32 v4l2_type;
  __u32 data_type;
  struct uvc_menu_info  * menu_info;
  __u32 menu_count;
  __u32 reserved[4];
};
struct uvc_xu_control_query {
  __u8 unit;
  __u8 selector;
  __u8 query;
  __u16 size;
  __u8  * data;
};
#define UVCIOC_CTRL_MAP _IOWR('u', 0x20, struct uvc_xu_control_mapping)
#define UVCIOC_CTRL_QUERY _IOWR('u', 0x21, struct uvc_xu_control_query)
struct uvc_meta_buf {
  __u64 ns;
  __u16 sof;
  __u8 length;
  __u8 flags;
  __u8 buf[];
} __attribute__((__packed__));
#endif

"""

```