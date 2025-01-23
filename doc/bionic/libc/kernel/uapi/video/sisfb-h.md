Response:
Let's break down the thought process for answering the request about `sisfb.h`.

**1. Understanding the Request:**

The core of the request is to analyze the provided C header file (`sisfb.h`) located within the Android Bionic library's kernel UAPI (User API) directory. The request asks for several things:

* **Functionality:** What does this file *do* or represent?
* **Android Relevance:** How does it connect to the broader Android ecosystem?
* **libc Function Explanation:** Detailed explanation of any libc functions (though this file doesn't directly *define* libc functions, it *uses* them via headers).
* **Dynamic Linker Aspects:** Analysis of any dynamic linking implications (again, not directly present in a header file like this, but usage can imply it).
* **Logical Reasoning:**  Examples of input and output if the code were executing.
* **Common Errors:**  Potential mistakes developers might make when interacting with it.
* **Android Framework/NDK Path:** How Android code gets to this point.
* **Frida Hooking:** Examples of using Frida for debugging.

**2. Initial Analysis of the Header File:**

The first step is to read through the header file and identify its key components:

* **Include Guards:** `#ifndef _UAPI_LINUX_SISFB_H_`, `#define _UAPI_LINUX_SISFB_H_`, `#endif` – Standard practice to prevent multiple inclusions.
* **Includes:** `<linux/types.h>`, `<asm/ioctl.h>` – Indicates interaction with the Linux kernel and specifically with ioctl (input/output control) system calls.
* **Macros:** A large number of `#define` statements. These represent constants and bit flags related to display settings (CRT, LCD, TV types, display modes).
* **Structures:** `struct sisfb_info` and `struct sisfb_cmd`. These define data structures used to exchange information with the kernel driver.
* **ioctl Definitions:**  More `#define` statements using `_IOR`, `_IOW`, and `_IOWR`. These define the specific ioctl commands and the data structures they use.

**3. Identifying Key Concepts and Functionality:**

From the analysis above, the central theme is clearly **framebuffer management for SiS graphics hardware**. Key concepts include:

* **Framebuffer (FB):** A memory region representing the display.
* **SiS:**  Silicon Integrated Systems, a historical graphics card manufacturer.
* **CRT/LCD/TV:**  Different types of display outputs.
* **Display Modes:** Single, Mirror, Dual View.
* **ioctl:** The primary mechanism for user-space applications to communicate with the kernel driver. The defined ioctl commands (`SISFB_GET_INFO`, `SISFB_COMMAND`, etc.) suggest ways to query information and control the display.

**4. Addressing the Specific Questions:**

Now, let's tackle each part of the request systematically:

* **功能 (Functionality):**  This is about summarizing the purpose of the header file. It's an interface definition for interacting with the SiS framebuffer driver in the Linux kernel.

* **与 Android 功能的关系 (Relationship with Android):** This is where we connect the dots to Android. Android uses the Linux kernel, and this header file provides the user-space interface to a specific piece of kernel functionality. Examples would involve displaying the Android UI, handling multiple displays, and potentially video playback.

* **详细解释 libc 函数的功能是如何实现的 (Detailed Explanation of libc Functions):**  Crucially, this header file *doesn't implement* libc functions. It *uses* types defined in `<linux/types.h>` which is part of the kernel's UAPI, not glibc directly. The `ioctl` macro comes from `<asm/ioctl.h>`, which again relates to kernel interfaces. It's important to clarify this distinction.

* **涉及 dynamic linker 的功能 (Dynamic Linker Aspects):**  Again, a header file doesn't directly involve the dynamic linker. However, a user-space application *using* these definitions would link against libraries (like `libc`) that provide the `ioctl` function. We need to explain the linking process conceptually and provide a basic SO layout example.

* **逻辑推理 (Logical Reasoning):**  Here, we need to imagine a simplified scenario. If an application wants to get the framebuffer information, it would open a device file (e.g., `/dev/fb0`) and use the `ioctl` system call with the `SISFB_GET_INFO` command. The kernel driver would then populate the `sisfb_info` structure.

* **用户或者编程常见的使用错误 (Common Usage Errors):** This involves thinking about how developers might misuse the API. Incorrect ioctl numbers, wrong data structures, permission issues with the device file are good examples.

* **说明 android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK Reaches Here):** This requires tracing the execution path. A high-level explanation would involve: Android framework (SurfaceFlinger, etc.) -> Native code (using NDK) ->  `ioctl` system call -> Kernel driver (using these definitions).

* **给出 frida hook 示例调试这些步骤 (Frida Hooking Example):**  Provide a simple Frida script that intercepts the `ioctl` call and logs relevant information like the ioctl number and file descriptor.

**5. Structuring the Answer:**

Organize the information clearly, using headings and bullet points to make it easier to read. Address each part of the request directly.

**6. Refining and Reviewing:**

Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For example, initially, I might have incorrectly focused on glibc functions. Reviewing would catch this and allow for correction. It's also important to be precise about what the header file *defines* versus what user-space code *does* with those definitions.
这个目录 `bionic/libc/kernel/uapi/video/sisfb.h` 中的 `sisfb.h` 文件定义了用户空间程序与 Linux 内核中 SiS (Silicon Integrated Systems) 帧缓冲驱动程序通信的接口。因为它位于 `uapi` 目录下，这意味着它是用户空间应用程序可以直接使用的头文件。

让我们逐一解答你的问题：

**1. 列举一下它的功能:**

`sisfb.h` 文件的主要功能是定义了与 SiS 帧缓冲设备进行交互所需的常量、数据结构和 ioctl 命令。具体来说，它定义了：

* **各种显示相关的常量:**  例如 `CRT2_DEFAULT`, `CRT2_LCD`, `TV_NTSC`, `TV_PAL` 等，用于表示不同的显示器类型、电视制式和连接方式。
* **显示模式常量:** 例如 `VB_SINGLE_MODE`, `VB_MIRROR_MODE`, `VB_DUALVIEW_MODE`，用于控制显示输出的模式。
* **`sisfb_info` 结构体:**  包含 SiS 帧缓冲设备信息的结构体，例如芯片 ID、内存大小、版本信息、当前显示配置等。
* **`sisfb_cmd` 结构体:**  用于向 SiS 帧缓冲驱动发送命令的结构体，包含命令编号和参数。
* **ioctl 命令常量:**  例如 `SISFB_GET_INFO`, `SISFB_COMMAND`, `SISFB_SET_AUTOMAXIMIZE` 等，定义了可以发送给驱动程序的具体操作。

**简单来说，这个头文件定义了用户空间程序如何查询和控制 SiS 显卡的显示输出行为。**

**2. 如果它与 android 的功能有关系，请做出对应的举例说明:**

是的，它与 Android 的功能有关系。虽然现在 Android 设备中 SiS 显卡已经非常罕见，但在早期或者某些特定的嵌入式 Android 设备上，可能会使用 SiS 的显卡。

* **显示驱动支持:** Android 底层依赖 Linux 内核，如果硬件使用了 SiS 显卡，那么内核需要有对应的 SiS 帧缓冲驱动。`sisfb.h` 就是定义了这个驱动的用户空间接口。
* **多显示器支持:**  Android 可能会利用这里定义的常量和 ioctl 命令来实现多显示器功能，例如连接外部显示器（通过 CRT、LCD 或 TV 接口），并设置不同的显示模式（镜像、扩展等）。
* **视频输出:**  Android 的媒体框架在处理视频输出时，可能会通过底层的帧缓冲驱动来将图像显示到屏幕上。这里定义的电视制式常量（`TV_NTSC`, `TV_PAL` 等）就可能与视频输出的格式设置有关。

**举例说明:**

假设一个早期的 Android 设备使用了 SiS 显卡，并且需要支持将画面同时输出到内置 LCD 屏幕和一个外接的 CRT 显示器。

1. Android 的 SurfaceFlinger 服务（负责屏幕合成和显示）可能需要查询当前连接的显示器类型和状态。它可能会打开 `/dev/fbX` 设备节点（对应帧缓冲），然后使用 `ioctl` 系统调用，并传入 `SISFB_GET_INFO` 命令，从内核获取 `sisfb_info` 结构体，从而得知 CRT 是否连接。
2. 当用户设置将画面镜像输出到两个屏幕时，SurfaceFlinger 可能会使用 `SISFB_COMMAND` ioctl 命令，并设置 `sisfb_cmd` 结构体中的 `sisfb_cmd` 为某个预定义的命令（可能需要定义新的命令，或者利用现有命令组合），以及设置相应的参数（例如 `VB_MIRROR_MODE`），来通知 SiS 驱动切换到镜像模式。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **并没有定义或实现 libc 函数**。它定义的是常量、结构体和宏，这些是 C 语言的基本元素，用于声明接口。

但是，用户空间的程序会使用 libc 提供的函数来与内核交互，例如：

* **`open()`:**  用于打开帧缓冲设备文件，例如 `/dev/fb0`。
* **`ioctl()`:**  用于向设备驱动程序发送控制命令。这个头文件中定义的 `SISFB_GET_INFO` 等宏会被用作 `ioctl()` 的请求参数。

**`ioctl()` 的简要实现过程：**

1. 用户空间程序调用 `ioctl(fd, request, argp)`，其中 `fd` 是打开的文件描述符，`request` 是 ioctl 命令编号（例如 `SISFB_GET_INFO`），`argp` 是指向参数的指针（可以是指向 `sisfb_info` 结构体的指针）。
2. 系统调用陷入内核。
3. 内核根据文件描述符找到对应的设备驱动程序（SiS 帧缓冲驱动）。
4. 内核驱动程序的 `ioctl` 函数会被调用，并接收到 `request` 和 `argp`。
5. 驱动程序根据 `request` 的值执行相应的操作。例如，如果 `request` 是 `SISFB_GET_INFO`，驱动程序会读取 SiS 显卡的硬件信息，填充 `sisfb_info` 结构体，并将数据拷贝回用户空间。
6. `ioctl()` 系统调用返回。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。它是定义内核接口的头文件。

但是，如果用户空间程序需要使用 `ioctl()` 函数来与 SiS 帧缓冲驱动交互，它需要链接到提供 `ioctl()` 函数的共享库，通常是 `libc.so`。

**`libc.so` 布局样本 (简化)：**

```
libc.so:
    .text         # 包含函数代码，例如 ioctl() 的实现
    .data         # 包含全局变量
    .rodata       # 包含只读数据
    .dynsym       # 动态符号表，列出导出的符号
    .dynstr       # 动态字符串表，存储符号名称
    .plt          # 程序链接表，用于延迟绑定
    .got.plt      # 全局偏移量表，用于存储外部符号的地址
    ...
```

**链接的处理过程 (简化)：**

1. **编译时：** 编译器遇到 `ioctl()` 函数调用时，会生成一个对外部符号 `ioctl` 的引用。
2. **链接时：** 链接器会查找提供 `ioctl` 符号的共享库。通常，链接器会默认链接 `libc.so`。链接器会将程序代码中对 `ioctl` 的引用关联到 `libc.so` 的动态符号表中的 `ioctl` 符号。
3. **运行时：** 当程序启动时，dynamic linker (例如 Android 的 `linker64` 或 `linker`) 会负责加载程序依赖的共享库，例如 `libc.so`。
4. **符号解析/重定位：** dynamic linker 会解析程序中对外部符号的引用。它会查找 `libc.so` 的 `.dynsym` 表，找到 `ioctl` 符号的地址，并将该地址填入程序的 `.got.plt` 表中。
5. **延迟绑定 (如果使用)：**  通常情况下，为了提高启动速度，会使用延迟绑定。这意味着在第一次调用 `ioctl()` 时，程序会先跳转到 `.plt` 表中的一个桩代码，该桩代码会调用 dynamic linker 来真正解析 `ioctl` 的地址并更新 `.got.plt` 表。后续的调用将直接通过 `.got.plt` 表中的地址跳转到 `ioctl()` 函数。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要获取 SiS 帧缓冲设备的信息：

**假设输入:**

* 打开帧缓冲设备文件 `/dev/fb0` 成功，得到文件描述符 `fd`。
* 调用 `ioctl(fd, SISFB_GET_INFO, &info)`，其中 `info` 是一个 `sisfb_info` 结构体变量的地址。

**可能的输出 (取决于具体的硬件和驱动实现):**

`ioctl()` 调用成功返回 0，并且 `info` 结构体被填充了 SiS 显卡的信息，例如：

```
info.sisfb_id = 0x53495346;  // SISF
info.chip_id = 0x0315;      // 假设的芯片 ID
info.memory = 8388608;     // 8MB 显存
info.sisfb_vbflags = 0;
info.sisfb_currentvbflags = CRT1_VGA; // 当前连接的是 VGA 显示器
...
```

如果 `ioctl()` 调用失败，可能会返回 -1，并设置 `errno` 来指示错误原因（例如设备不存在、权限不足等）。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **使用了错误的 ioctl 命令编号:**  例如，错误地使用了其他设备的 ioctl 命令，或者拼写错误了 `SISFB_GET_INFO` 等常量。这会导致 `ioctl()` 调用失败，并可能返回 `EINVAL` 错误。
* **传递了不正确的参数结构体:**  例如，传递了一个大小或类型不匹配的结构体指针作为 `ioctl()` 的 `argp` 参数。这会导致内核在访问内存时出现错误。
* **没有检查 `ioctl()` 的返回值:**  程序应该始终检查 `ioctl()` 的返回值是否为 0，如果不为 0，则应该通过 `perror()` 或其他方式打印错误信息，以便调试。
* **在错误的文件描述符上调用 `ioctl()`:**  例如，在未打开的设备文件描述符上调用 `ioctl()`，或者在错误类型的设备文件描述符上调用。
* **权限问题:**  用户可能没有足够的权限访问帧缓冲设备文件 `/dev/fb0`，导致 `open()` 或 `ioctl()` 调用失败。
* **假设硬件总是存在:**  程序可能没有考虑到某些设备上可能没有 SiS 显卡，或者驱动没有加载的情况，直接调用相关的 ioctl 命令会导致错误。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `sisfb.h` 的路径 (概念性流程):**

1. **应用层 (Java/Kotlin):**  Android 应用通常不会直接操作底层的帧缓冲设备。
2. **Framework 层 (Java/Kotlin):**  Android Framework 中的 SurfaceFlinger 服务负责管理屏幕合成和显示。
3. **Native 代码 (C++/NDK):**  SurfaceFlinger 是一个 native 服务，使用 C++ 实现。它会通过 NDK 提供的接口与底层的图形驱动进行交互。
4. **HAL (Hardware Abstraction Layer):**  Android 使用 HAL 来抽象硬件细节。对于显示相关的操作，可能会涉及到 Display HAL。
5. **Kernel 驱动:** Display HAL 的实现最终会调用 Linux 内核提供的帧缓冲驱动接口。对于 SiS 显卡，就是这里定义的 `sisfb.h` 相关的接口。
6. **`ioctl()` 系统调用:**  SurfaceFlinger 或 Display HAL 的实现中会调用 `ioctl()` 系统调用，并使用 `sisfb.h` 中定义的常量和结构体来与 SiS 帧缓冲驱动通信。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `ioctl` 系统调用，并针对 `SISFB_GET_INFO` 命令打印相关信息的示例 (假设目标进程是 SurfaceFlinger):

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach("SurfaceFlinger")  # 替换为目标进程名称或 PID
except frida.ProcessNotFoundError:
    print("SurfaceFlinger not found. Please make sure it's running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 定义 SISFB_GET_INFO 的值 (从头文件中获取)
        const SISFB_GET_INFO = 0xc0180001;

        if (request === SISFB_GET_INFO) {
            send(`[ioctl] Called with fd: ${fd}, request: SISFB_GET_INFO`);

            // 可以尝试读取 argp 指向的内存，解析 sisfb_info 结构体
            // 注意：需要根据目标架构和结构体定义来正确读取内存
            // const info = {};
            // info.sisfb_id = argp.readU32();
            // send(`[ioctl] sisfb_id: ${info.sisfb_id}`);
        }
    },
    onLeave: function(retval) {
        // console.log("[ioctl] Return value:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 确保你的设备或模拟器上运行着 SurfaceFlinger 进程。
2. 将上述 Python 代码保存为 `hook_ioctl.py`。
3. 运行 Frida 命令：`frida -UF -l hook_ioctl.py` (如果连接了 USB 设备) 或 `frida -H <device_ip> -f SurfaceFlinger -l hook_ioctl.py` (如果连接了模拟器或远程设备)。

**解释:**

* **`frida.attach("SurfaceFlinger")`:** 连接到目标进程。
* **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:** Hook 了 `ioctl` 系统调用。
* **`onEnter`:** 在 `ioctl` 函数执行前调用。
* **`args[0]`, `args[1]`, `args[2]`:** 分别是 `ioctl` 函数的参数 `fd`, `request`, `argp`。
* **`SISFB_GET_INFO = 0xc0180001;`:**  这是根据 `_IOR(0xF3, 0x01, struct sisfb_info)` 宏计算出的 `SISFB_GET_INFO` 的实际值。你需要根据目标架构（32 位或 64 位）和宏定义来计算。
* **`send(...)`:**  通过 Frida 将消息发送回主机。
* **读取 `argp` 指向的内存:**  示例代码中注释了如何读取 `sisfb_info` 结构体的成员。你需要根据目标架构和结构体的内存布局进行读取。

这个 Frida 脚本会在 SurfaceFlinger 调用 `ioctl` 时，如果 `request` 参数是 `SISFB_GET_INFO`，则会打印出相关信息，帮助你调试 Android Framework 与底层驱动的交互过程。

请注意，实际的 Android 系统可能不会直接使用这个 `sisfb.h` 文件，因为它针对的是特定的 SiS 显卡。现代 Android 设备通常使用其他的图形驱动框架（例如 Android Graphics Architecture - AGSA）和对应的驱动接口。但是，理解这个文件的作用和如何与内核交互的原理，有助于理解 Android 图形系统的底层运作方式。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/video/sisfb.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_SISFB_H_
#define _UAPI_LINUX_SISFB_H_
#include <linux/types.h>
#include <asm/ioctl.h>
#define CRT2_DEFAULT 0x00000001
#define CRT2_LCD 0x00000002
#define CRT2_TV 0x00000004
#define CRT2_VGA 0x00000008
#define TV_NTSC 0x00000010
#define TV_PAL 0x00000020
#define TV_HIVISION 0x00000040
#define TV_YPBPR 0x00000080
#define TV_AVIDEO 0x00000100
#define TV_SVIDEO 0x00000200
#define TV_SCART 0x00000400
#define TV_PALM 0x00001000
#define TV_PALN 0x00002000
#define TV_NTSCJ 0x00001000
#define TV_CHSCART 0x00008000
#define TV_CHYPBPR525I 0x00010000
#define CRT1_VGA 0x00000000
#define CRT1_LCDA 0x00020000
#define VGA2_CONNECTED 0x00040000
#define VB_DISPTYPE_CRT1 0x00080000
#define VB_SINGLE_MODE 0x20000000
#define VB_MIRROR_MODE 0x40000000
#define VB_DUALVIEW_MODE 0x80000000
#define CRT2_ENABLE (CRT2_LCD | CRT2_TV | CRT2_VGA)
#define TV_STANDARD (TV_NTSC | TV_PAL | TV_PALM | TV_PALN | TV_NTSCJ)
#define TV_INTERFACE (TV_AVIDEO | TV_SVIDEO | TV_SCART | TV_HIVISION | TV_YPBPR | TV_CHSCART | TV_CHYPBPR525I)
#define TV_YPBPR525I TV_NTSC
#define TV_YPBPR525P TV_PAL
#define TV_YPBPR750P TV_PALM
#define TV_YPBPR1080I TV_PALN
#define TV_YPBPRALL (TV_YPBPR525I | TV_YPBPR525P | TV_YPBPR750P | TV_YPBPR1080I)
#define VB_DISPTYPE_DISP2 CRT2_ENABLE
#define VB_DISPTYPE_CRT2 CRT2_ENABLE
#define VB_DISPTYPE_DISP1 VB_DISPTYPE_CRT1
#define VB_DISPMODE_SINGLE VB_SINGLE_MODE
#define VB_DISPMODE_MIRROR VB_MIRROR_MODE
#define VB_DISPMODE_DUAL VB_DUALVIEW_MODE
#define VB_DISPLAY_MODE (SINGLE_MODE | MIRROR_MODE | DUALVIEW_MODE)
struct sisfb_info {
  __u32 sisfb_id;
#ifndef SISFB_ID
#define SISFB_ID 0x53495346
#endif
  __u32 chip_id;
  __u32 memory;
  __u32 heapstart;
  __u8 fbvidmode;
  __u8 sisfb_version;
  __u8 sisfb_revision;
  __u8 sisfb_patchlevel;
  __u8 sisfb_caps;
  __u32 sisfb_tqlen;
  __u32 sisfb_pcibus;
  __u32 sisfb_pcislot;
  __u32 sisfb_pcifunc;
  __u8 sisfb_lcdpdc;
  __u8 sisfb_lcda;
  __u32 sisfb_vbflags;
  __u32 sisfb_currentvbflags;
  __u32 sisfb_scalelcd;
  __u32 sisfb_specialtiming;
  __u8 sisfb_haveemi;
  __u8 sisfb_emi30, sisfb_emi31, sisfb_emi32, sisfb_emi33;
  __u8 sisfb_haveemilcd;
  __u8 sisfb_lcdpdca;
  __u16 sisfb_tvxpos, sisfb_tvypos;
  __u32 sisfb_heapsize;
  __u32 sisfb_videooffset;
  __u32 sisfb_curfstn;
  __u32 sisfb_curdstn;
  __u16 sisfb_pci_vendor;
  __u32 sisfb_vbflags2;
  __u8 sisfb_can_post;
  __u8 sisfb_card_posted;
  __u8 sisfb_was_boot_device;
  __u8 reserved[183];
};
#define SISFB_CMD_GETVBFLAGS 0x55AA0001
#define SISFB_CMD_SWITCHCRT1 0x55AA0010
#define SISFB_CMD_ERR_OK 0x80000000
#define SISFB_CMD_ERR_LOCKED 0x80000001
#define SISFB_CMD_ERR_EARLY 0x80000002
#define SISFB_CMD_ERR_NOVB 0x80000003
#define SISFB_CMD_ERR_NOCRT2 0x80000004
#define SISFB_CMD_ERR_UNKNOWN 0x8000ffff
#define SISFB_CMD_ERR_OTHER 0x80010000
struct sisfb_cmd {
  __u32 sisfb_cmd;
  __u32 sisfb_arg[16];
  __u32 sisfb_result[4];
};
#define SISFB_GET_INFO_SIZE _IOR(0xF3, 0x00, __u32)
#define SISFB_GET_INFO _IOR(0xF3, 0x01, struct sisfb_info)
#define SISFB_GET_VBRSTATUS _IOR(0xF3, 0x02, __u32)
#define SISFB_GET_AUTOMAXIMIZE _IOR(0xF3, 0x03, __u32)
#define SISFB_SET_AUTOMAXIMIZE _IOW(0xF3, 0x03, __u32)
#define SISFB_GET_TVPOSOFFSET _IOR(0xF3, 0x04, __u32)
#define SISFB_SET_TVPOSOFFSET _IOW(0xF3, 0x04, __u32)
#define SISFB_COMMAND _IOWR(0xF3, 0x05, struct sisfb_cmd)
#define SISFB_SET_LOCK _IOW(0xF3, 0x06, __u32)
#define SISFB_GET_INFO_OLD _IOR('n', 0xF8, __u32)
#define SISFB_GET_VBRSTATUS_OLD _IOR('n', 0xF9, __u32)
#define SISFB_GET_AUTOMAXIMIZE_OLD _IOR('n', 0xFA, __u32)
#define SISFB_SET_AUTOMAXIMIZE_OLD _IOW('n', 0xFA, __u32)
struct sis_memreq {
  __u32 offset;
  __u32 size;
};
#endif
```