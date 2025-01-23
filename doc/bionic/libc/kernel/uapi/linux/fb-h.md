Response:
Let's break down the thought process to answer the request about the `fb.h` header file.

**1. Understanding the Core Request:**

The request asks for a detailed analysis of a kernel UAPI header file related to the framebuffer. Key aspects to cover are: functionality, relation to Android, implementation details (especially for libc functions, although this file mostly *defines* things), dynamic linker aspects (again, less relevant here, but good to address), error scenarios, how Android reaches this code, and Frida hooks.

**2. Initial Scan and Keyword Identification:**

First, I quickly skim the code, looking for obvious keywords and patterns. I see:

* `#define`:  Lots of these, suggesting constants and macros.
* `struct`: Definitions of data structures.
* `FBIOGET_*`, `FBIOPUT_*`, `FBIO_*`:  These look like ioctl commands.
* `FB_TYPE_*`, `FB_VISUAL_*`, `FB_ACCEL_*`:  More constants, likely enums or flags.
* `<linux/types.h>`, `<linux/i2c.h>`, `<linux/vesa.h>`: Included headers, indicating dependencies.

This gives me a high-level understanding: this file defines the interface between user-space programs and the kernel's framebuffer driver.

**3. Deciphering Functionality:**

* **Configuration (GET/PUT):** The `FBIOGET_*` and `FBIOPUT_*` macros strongly suggest getting and setting framebuffer parameters. I can categorize these by what they access:
    * `VSCREENINFO`:  Virtual screen information (resolution, etc.).
    * `FSCREENINFO`: Fixed screen information (memory address, etc.).
    * `CMAP`: Colormap manipulation.
    * `CON2FBMAP`: Mapping consoles to framebuffers.
    * `VBLANK`: Vertical blanking information.
    * `HWCINFO`, `DISPINFO`, `MODEINFO`:  Hardware-specific display information.
* **Control (IO):** The `FBIO_*` macros point to control operations:
    * `PAN_DISPLAY`: Scrolling/panning the display.
    * `CURSOR`:  Cursor manipulation.
    * `BLANK`:  Screen blanking.
    * `ALLOC`, `FREE`:  Memory allocation/deallocation (less common, but present).
    * `WAITFORVSYNC`:  Synchronizing with the vertical sync signal.
* **Data Types:** The `FB_TYPE_*`, `FB_VISUAL_*`, etc., constants define the possible values for framebuffer attributes, like pixel formats, visual types, and hardware acceleration.
* **Structures:** The `struct fb_*` definitions describe the data structures exchanged between user-space and the kernel via the ioctl calls. I should go through these briefly and understand what kind of information they hold.

**4. Connecting to Android:**

Since the file is in the Android bionic library, it's clearly used by the Android graphics stack. I need to think about where framebuffers are used in Android:

* **SurfaceFlinger:** The core Android service responsible for compositing and displaying UI. It interacts with framebuffer devices.
* **Graphics drivers (HAL):** Hardware Abstraction Layers for graphics likely use these ioctls.
* **Native UI elements:**  Applications or system services rendering directly to the screen might use these.
* **Bootloader/Kernel initialization:** The framebuffer might be used early in the boot process for displaying logos or console output.

I should provide concrete examples related to SurfaceFlinger and HAL.

**5. Addressing Specific Questions:**

* **libc Function Implementation:**  The key realization here is that this file *defines* constants and structures, not actual libc function implementations. The *implementation* of the `ioctl()` system call (which uses these constants) is in the kernel. However, bionic provides wrappers for `ioctl()`, so I should briefly mention that.
* **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. However, the *code that uses* these definitions (like SurfaceFlinger) *does* get linked. I need to explain this distinction and provide a simple SO layout example of a hypothetical graphics library. The linking process involves resolving symbols (like function calls that eventually lead to `ioctl()`).
* **Logical Inference (Input/Output):**  For ioctl calls, the "input" is the structure passed to `ioctl()`, and the "output" is the modification of that structure or the return value of `ioctl()`. I can give a simple example using `FBIOGET_VSCREENINFO`.
* **User/Programming Errors:** Common errors include incorrect `ioctl()` calls, wrong structure sizes, or attempting operations on an invalid framebuffer device.

**6. Tracing the Path from Android Framework/NDK:**

I need to describe the layers involved:

* **High-level Framework (Java):**  UI elements in Android apps.
* **Android Runtime (ART):** Executes the Java code and interacts with native libraries.
* **NDK (Native Development Kit):** Allows developers to write C/C++ code.
* **SurfaceFlinger (Native Service):**  The key component interacting with the framebuffer.
* **Graphics HAL:**  Abstracts the hardware.
* **Kernel Driver:** The actual driver for the display hardware.

I should illustrate the call flow with an example, like a simple drawing operation.

**7. Frida Hook Example:**

A Frida hook intercepts function calls. The relevant function to hook is `ioctl()`. The hook should check if the `ioctl` command matches one of the framebuffer commands defined in the header file. This helps demonstrate how to observe the interaction with the framebuffer driver.

**8. Structuring the Response:**

I should organize the answer clearly, using headings and bullet points. It's important to address each part of the request systematically.

**Self-Correction/Refinement:**

* **Initial Thought:**  Focus heavily on libc function *implementation*.
* **Correction:** Realize that this header file primarily *defines* the interface, and the implementation is mostly in the kernel. Shift focus to the *usage* of these definitions in user-space programs.
* **Initial Thought:** Overcomplicate the dynamic linker section.
* **Correction:** Keep it concise and focus on the fact that code *using* these definitions will be linked. The header itself isn't directly linked.
* **Initial Thought:** Provide very detailed code for the Frida hook.
* **Correction:**  Provide a conceptual example to illustrate the idea, without getting bogged down in platform-specific details.

By following this structured thought process and incorporating corrections, I can generate a comprehensive and accurate answer to the request.
这个文件 `bionic/libc/kernel/uapi/linux/fb.h` 是 Android Bionic 库中的一个头文件，它直接来源于 Linux 内核的 UAPI（用户空间应用程序接口），定义了 **帧缓冲（Framebuffer）** 相关的常量、数据结构和 ioctl 命令。帧缓冲是 Linux 系统中访问显示硬件的一种抽象接口。

**它的主要功能是定义用户空间程序与 Linux 内核帧缓冲驱动程序交互的接口。** 简单来说，它规定了用户程序如何告诉内核来操作显示设备，比如设置分辨率、颜色、显示内容等等。

**与 Android 功能的关系及举例说明：**

帧缓冲在 Android 系统中扮演着至关重要的角色，它是 Android 图形系统的基础。Android 的 SurfaceFlinger 服务，以及底层的图形 HAL（硬件抽象层）都会直接或间接地使用到这些定义。

* **显示内容渲染:** Android 应用最终看到的界面，例如应用窗口、壁纸等，都需要通过帧缓冲绘制到屏幕上。
* **屏幕参数配置:**  Android 系统需要读取和设置屏幕的分辨率、颜色深度、刷新率等参数，这些操作会用到这里定义的 `FBIOGET_VSCREENINFO`、`FBIOPUT_VSCREENINFO` 等 ioctl 命令。
* **硬件加速:** 一些硬件加速的功能，例如 GPU 渲染的结果，最终也会通过帧缓冲显示出来。`FB_ACCEL_*` 定义了各种硬件加速器的类型。
* **电源管理:**  屏幕的休眠和唤醒等电源管理操作，可能会涉及到 `FBIOBLANK` 命令。

**举例说明:**

假设一个 Android 应用需要全屏显示一张图片。其背后的流程可能涉及到：

1. **应用层 (Java/Kotlin):** 应用通过 Android Framework 提供的 API（例如 `SurfaceView`, `Canvas`）来绘制图片。
2. **Android Framework (Java/Kotlin):** Framework 层将绘制指令转换为底层的图形操作。
3. **SurfaceFlinger (C++):** SurfaceFlinger 负责合成各个应用的图层，并最终将合成结果输出到显示设备。
4. **Graphics HAL (C/C++):** SurfaceFlinger 通过 Graphics HAL 与底层的图形驱动交互。HAL 层可能会使用 `ioctl` 系统调用，并使用 `fb.h` 中定义的常量和结构体来配置帧缓冲。例如，使用 `FBIOPUT_VSCREENINFO` 设置屏幕分辨率，使用内存映射的方式将像素数据写入帧缓冲。
5. **Linux Kernel (C):** 内核的帧缓冲驱动接收到 HAL 层的 ioctl 命令，根据 `fb.h` 中的定义解析命令，并操作底层的显示硬件。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个 `fb.h` 文件本身 **不是 libc 函数**，而是 Linux 内核的 UAPI 头文件。它定义的是内核接口，而不是 libc 提供的函数。

libc (Bionic in Android) 提供的与帧缓冲交互的通常是 `open`, `close`, `ioctl`, `mmap` 等系统调用相关的函数。这些函数的功能实现都在内核中，libc 只是提供了用户空间访问这些系统调用的接口。

* **`open()`:** 用于打开帧缓冲设备文件，例如 `/dev/fb0`。  内核会创建一个表示该设备文件的 file descriptor，并与对应的帧缓冲驱动关联。
* **`close()`:** 用于关闭打开的帧缓冲设备文件，释放相关的内核资源。
* **`ioctl()`:** 这是与帧缓冲驱动交互的核心系统调用。用户空间程序通过 `ioctl()` 发送命令（例如 `FBIOGET_VSCREENINFO`）和数据（例如 `fb_var_screeninfo` 结构体）给内核驱动，以获取或设置帧缓冲的状态。内核驱动会根据 `ioctl` 的命令码执行相应的操作。
* **`mmap()`:** 用于将帧缓冲的内存映射到用户空间的进程地址空间。这样用户程序可以直接读写帧缓冲的内存，从而在屏幕上绘制内容。内核会建立用户空间地址和帧缓冲物理内存之间的映射关系。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个 `fb.h` 文件本身不直接涉及动态链接器的功能。动态链接器负责加载和链接共享库 (`.so` 文件)。

虽然 `fb.h` 定义了内核接口，但最终使用这些接口的代码（例如 Graphics HAL 的实现）通常会被编译成动态链接库。

**so 布局样本 (以 Graphics HAL 为例):**

```
libhardware.so:
    ... 代码段 ...
    ... 数据段 ...
    ... .dynsym (动态符号表) ...
    ... .rel.dyn (动态重定位表) ...
    ... .plt (过程链接表) ...

    # 可能会包含调用 open, ioctl 等函数的代码
    ... 调用 open("/dev/fb0", ...) ...
    ... 调用 ioctl(fd, FBIOGET_VSCREENINFO, ...) ...
    ...

lib অন্য_graphics_hal.so:  # 具体的硬件厂商提供的 HAL 库
    ... 代码段 ...
    ... 数据段 ...
    ... .dynsym ...
    ... .rel.dyn ...
    ... .plt ...

    # 可能会实现具体的帧缓冲操作逻辑，使用 fb.h 中定义的常量
    ...
```

**链接的处理过程：**

1. **编译时：** 当编译 Graphics HAL 库时，编译器会识别到对 `open`, `ioctl` 等函数的调用。由于这些是外部符号（定义在 libc 中），编译器会在生成的 `.o` 文件中记录下这些未解析的符号。
2. **链接时：** 动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 在加载 `libhardware.so` 或具体的 HAL 库时发挥作用。
3. **符号查找：** 链接器会查找所需的符号（例如 `open`, `ioctl`）在哪些共享库中定义。通常这些符号在 `libc.so` 中。
4. **重定位：** 链接器会修改 `.so` 文件中的代码和数据，将对外部符号的引用指向它们在 `libc.so` 中的实际地址。过程链接表 (`.plt`) 和动态符号表 (`.dynsym`) 以及重定位表 (`.rel.dyn`) 在这个过程中起关键作用。
5. **加载：** 链接器将相关的共享库加载到进程的地址空间。

**假设输入与输出 (针对 ioctl 调用)：**

假设我们要获取帧缓冲的 `fb_var_screeninfo` 信息：

**假设输入：**

* 打开的帧缓冲设备文件描述符 `fd`。
* `ioctl` 命令码：`FBIOGET_VSCREENINFO` (值为 `0x4600`)。
* 指向 `fb_var_screeninfo` 结构体的指针 `vinfo_ptr`，该结构体用于接收内核返回的信息。

**逻辑推理 (内核驱动的行为):**

1. 内核的帧缓冲驱动接收到 `ioctl(fd, FBIOGET_VSCREENINFO, vinfo_ptr)` 调用。
2. 驱动程序根据 `FBIOGET_VSCREENINFO` 命令码，执行相应的操作，读取当前帧缓冲的虚拟屏幕信息。
3. 驱动程序将读取到的信息填充到 `vinfo_ptr` 指向的 `fb_var_screeninfo` 结构体中。

**输出：**

* `ioctl` 函数的返回值：成功时通常返回 0，失败时返回 -1 并设置 `errno`。
* `vinfo_ptr` 指向的 `fb_var_screeninfo` 结构体被填充了当前帧缓冲的虚拟屏幕信息，例如分辨率 (`xres`, `yres`)，颜色深度 (`bits_per_pixel`) 等。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **无效的文件描述符:**  在使用 `ioctl` 之前没有成功打开帧缓冲设备文件，导致 `fd` 是一个无效的值。
   ```c
   int fd = open("/dev/fb0", O_RDWR);
   if (fd < 0) {
       perror("Failed to open framebuffer");
       return -1;
   }
   struct fb_var_screeninfo vinfo;
   // 忘记检查 fd 的有效性就直接使用
   if (ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) == -1) {
       perror("Error reading screen info");
   }
   close(fd);
   ```

2. **传递错误的 ioctl 命令码:** 使用了 `fb.h` 中未定义的或者与预期操作不符的命令码。
   ```c
   int fd = open("/dev/fb0", O_RDWR);
   // 使用了一个错误的命令码 (假设 0x1234 是不存在的)
   if (ioctl(fd, 0x1234, &vinfo) == -1) {
       perror("ioctl failed");
   }
   close(fd);
   ```

3. **传递的结构体大小或类型不匹配:**  `ioctl` 需要接收特定类型的结构体指针，如果传递了错误的类型或者大小不匹配的结构体，会导致内核访问越界或者数据解析错误。
   ```c
   int fd = open("/dev/fb0", O_RDWR);
   int some_integer; // 错误地传递了一个整型变量的地址
   if (ioctl(fd, FBIOGET_VSCREENINFO, &some_integer) == -1) {
       perror("ioctl failed");
   }
   close(fd);
   ```

4. **权限问题:**  用户进程可能没有足够的权限访问帧缓冲设备文件 (`/dev/fb0`)。
   ```bash
   # 在没有足够权限的情况下运行程序
   ./my_framebuffer_app
   # 可能会遇到 "Permission denied" 错误
   ```

5. **忘记处理错误返回值:** `ioctl` 调用失败时会返回 -1 并设置 `errno`，程序员需要检查返回值并根据 `errno` 进行错误处理。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 `fb.h` 的步骤：**

1. **应用层 (Java/Kotlin):**  应用通过 Android Framework 提供的 UI 组件（例如 `View`, `SurfaceView`）或者直接使用 NDK 进行图形绘制。
2. **Android Framework (Java/Kotlin):** Framework 层的代码会调用底层的图形服务，例如 SurfaceFlinger。
3. **SurfaceFlinger (C++):** SurfaceFlinger 是一个系统服务，负责管理和合成显示 buffer。它会通过 Graphics HAL 与底层的图形驱动交互。
4. **Graphics HAL (C/C++):** Graphics HAL 是硬件抽象层，不同的硬件厂商会提供不同的 HAL 实现。HAL 层会打开帧缓冲设备文件 (`/dev/fb0`)，并使用 `ioctl` 系统调用和 `fb.h` 中定义的常量和结构体与内核的帧缓冲驱动进行通信。
5. **Linux Kernel (C):** 内核的帧缓冲驱动程序接收到来自 HAL 的 `ioctl` 调用，并根据命令执行相应的操作。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `ioctl` 系统调用，并过滤出与帧缓冲相关的操作的示例（假设目标进程是 SurfaceFlinger）：

```javascript
// attach 到目标进程
const processName = " सरफेसफ्लिंगर "; // 根据实际进程名修改
const session = frida.attach(processName);

session.then(session => {
  const ioctlPtr = Module.getExportByName(null, "ioctl"); // 获取 ioctl 函数的地址

  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();

      // 判断文件描述符是否指向 framebuffer 设备 (这里可以根据实际情况进行更精确的判断)
      // 一种简单的判断方式是检查文件路径，但这可能不总是可靠的
      try {
        const fdPath = Socket.peerAddress(fd);
        if (fdPath && fdPath.startsWith("/dev/fb")) {
          console.log(`[ioctl] fd: ${fd}, request: 0x${request.toString(16)}`);

          // 可以进一步解析 request，判断具体是哪个 FBIO_* 命令
          switch (request) {
            case 0x4600: // FBIOGET_VSCREENINFO
              console.log("  -> FBIOGET_VSCREENINFO");
              break;
            case 0x4601: // FBIOPUT_VSCREENINFO
              console.log("  -> FBIOPUT_VSCREENINFO");
              break;
            // ... 其他 FBIO_* 命令
          }
        }
      } catch (e) {
        // 可能不是 socket fd，忽略错误
      }
    },
    onLeave: function (retval) {
      // console.log('[ioctl] 返回值:', retval);
    }
  });

  console.log("Frida hook for ioctl on SurfaceFlinger is running...");
});
```

**代码解释：**

1. **`frida.attach(processName)`:** 连接到名为 "SurfaceFlinger" 的进程。你需要根据实际情况修改进程名。
2. **`Module.getExportByName(null, "ioctl")`:** 获取 `ioctl` 函数在内存中的地址。
3. **`Interceptor.attach(ioctlPtr, { ... })`:**  拦截 `ioctl` 函数的调用。
4. **`onEnter`:** 在 `ioctl` 函数执行之前被调用。
   - `args[0]`：文件描述符 `fd`。
   - `args[1]`：`ioctl` 命令码 `request`。
   - 代码尝试判断文件描述符是否指向 framebuffer 设备（这部分可能需要根据实际情况进行调整，例如检查文件路径或通过其他方式判断）。
   - 如果是 framebuffer 设备的操作，则打印文件描述符和命令码。
   - 可以根据命令码进一步判断具体是哪个 `FBIO_*` 命令。
5. **`onLeave`:** 在 `ioctl` 函数执行之后被调用，可以查看返回值。

**使用方法：**

1. 确保你的 Android 设备已 root，并且安装了 Frida 和 Frida-server。
2. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_fb.js`)。
3. 运行 Frida 命令，将 hook 代码注入到 SurfaceFlinger 进程：
   ```bash
   frida -U -f सरफेसफ्लिंगर -l hook_fb.js --no-pause
   ```
   或者，如果 SurfaceFlinger 已经在运行：
   ```bash
   frida -U -n सरफेसफ्लिंगर -l hook_fb.js
   ```

通过这个 Frida hook，你可以在 SurfaceFlinger 进程调用 `ioctl` 时，实时查看与 framebuffer 相关的操作，帮助你理解 Android 图形系统是如何与帧缓冲驱动交互的。你可以根据需要添加更多的 `case` 分支来解析不同的 `FBIO_*` 命令，或者进一步分析传递给 `ioctl` 的数据结构。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/fb.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_FB_H
#define _UAPI_LINUX_FB_H
#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/vesa.h>
#define FB_MAX 32
#define FBIOGET_VSCREENINFO 0x4600
#define FBIOPUT_VSCREENINFO 0x4601
#define FBIOGET_FSCREENINFO 0x4602
#define FBIOGETCMAP 0x4604
#define FBIOPUTCMAP 0x4605
#define FBIOPAN_DISPLAY 0x4606
#define FBIO_CURSOR _IOWR('F', 0x08, struct fb_cursor)
#define FBIOGET_CON2FBMAP 0x460F
#define FBIOPUT_CON2FBMAP 0x4610
#define FBIOBLANK 0x4611
#define FBIOGET_VBLANK _IOR('F', 0x12, struct fb_vblank)
#define FBIO_ALLOC 0x4613
#define FBIO_FREE 0x4614
#define FBIOGET_GLYPH 0x4615
#define FBIOGET_HWCINFO 0x4616
#define FBIOPUT_MODEINFO 0x4617
#define FBIOGET_DISPINFO 0x4618
#define FBIO_WAITFORVSYNC _IOW('F', 0x20, __u32)
#define FB_TYPE_PACKED_PIXELS 0
#define FB_TYPE_PLANES 1
#define FB_TYPE_INTERLEAVED_PLANES 2
#define FB_TYPE_TEXT 3
#define FB_TYPE_VGA_PLANES 4
#define FB_TYPE_FOURCC 5
#define FB_AUX_TEXT_MDA 0
#define FB_AUX_TEXT_CGA 1
#define FB_AUX_TEXT_S3_MMIO 2
#define FB_AUX_TEXT_MGA_STEP16 3
#define FB_AUX_TEXT_MGA_STEP8 4
#define FB_AUX_TEXT_SVGA_GROUP 8
#define FB_AUX_TEXT_SVGA_MASK 7
#define FB_AUX_TEXT_SVGA_STEP2 8
#define FB_AUX_TEXT_SVGA_STEP4 9
#define FB_AUX_TEXT_SVGA_STEP8 10
#define FB_AUX_TEXT_SVGA_STEP16 11
#define FB_AUX_TEXT_SVGA_LAST 15
#define FB_AUX_VGA_PLANES_VGA4 0
#define FB_AUX_VGA_PLANES_CFB4 1
#define FB_AUX_VGA_PLANES_CFB8 2
#define FB_VISUAL_MONO01 0
#define FB_VISUAL_MONO10 1
#define FB_VISUAL_TRUECOLOR 2
#define FB_VISUAL_PSEUDOCOLOR 3
#define FB_VISUAL_DIRECTCOLOR 4
#define FB_VISUAL_STATIC_PSEUDOCOLOR 5
#define FB_VISUAL_FOURCC 6
#define FB_ACCEL_NONE 0
#define FB_ACCEL_ATARIBLITT 1
#define FB_ACCEL_AMIGABLITT 2
#define FB_ACCEL_S3_TRIO64 3
#define FB_ACCEL_NCR_77C32BLT 4
#define FB_ACCEL_S3_VIRGE 5
#define FB_ACCEL_ATI_MACH64GX 6
#define FB_ACCEL_DEC_TGA 7
#define FB_ACCEL_ATI_MACH64CT 8
#define FB_ACCEL_ATI_MACH64VT 9
#define FB_ACCEL_ATI_MACH64GT 10
#define FB_ACCEL_SUN_CREATOR 11
#define FB_ACCEL_SUN_CGSIX 12
#define FB_ACCEL_SUN_LEO 13
#define FB_ACCEL_IMS_TWINTURBO 14
#define FB_ACCEL_3DLABS_PERMEDIA2 15
#define FB_ACCEL_MATROX_MGA2064W 16
#define FB_ACCEL_MATROX_MGA1064SG 17
#define FB_ACCEL_MATROX_MGA2164W 18
#define FB_ACCEL_MATROX_MGA2164W_AGP 19
#define FB_ACCEL_MATROX_MGAG100 20
#define FB_ACCEL_MATROX_MGAG200 21
#define FB_ACCEL_SUN_CG14 22
#define FB_ACCEL_SUN_BWTWO 23
#define FB_ACCEL_SUN_CGTHREE 24
#define FB_ACCEL_SUN_TCX 25
#define FB_ACCEL_MATROX_MGAG400 26
#define FB_ACCEL_NV3 27
#define FB_ACCEL_NV4 28
#define FB_ACCEL_NV5 29
#define FB_ACCEL_CT_6555x 30
#define FB_ACCEL_3DFX_BANSHEE 31
#define FB_ACCEL_ATI_RAGE128 32
#define FB_ACCEL_IGS_CYBER2000 33
#define FB_ACCEL_IGS_CYBER2010 34
#define FB_ACCEL_IGS_CYBER5000 35
#define FB_ACCEL_SIS_GLAMOUR 36
#define FB_ACCEL_3DLABS_PERMEDIA3 37
#define FB_ACCEL_ATI_RADEON 38
#define FB_ACCEL_I810 39
#define FB_ACCEL_SIS_GLAMOUR_2 40
#define FB_ACCEL_SIS_XABRE 41
#define FB_ACCEL_I830 42
#define FB_ACCEL_NV_10 43
#define FB_ACCEL_NV_20 44
#define FB_ACCEL_NV_30 45
#define FB_ACCEL_NV_40 46
#define FB_ACCEL_XGI_VOLARI_V 47
#define FB_ACCEL_XGI_VOLARI_Z 48
#define FB_ACCEL_OMAP1610 49
#define FB_ACCEL_TRIDENT_TGUI 50
#define FB_ACCEL_TRIDENT_3DIMAGE 51
#define FB_ACCEL_TRIDENT_BLADE3D 52
#define FB_ACCEL_TRIDENT_BLADEXP 53
#define FB_ACCEL_CIRRUS_ALPINE 53
#define FB_ACCEL_NEOMAGIC_NM2070 90
#define FB_ACCEL_NEOMAGIC_NM2090 91
#define FB_ACCEL_NEOMAGIC_NM2093 92
#define FB_ACCEL_NEOMAGIC_NM2097 93
#define FB_ACCEL_NEOMAGIC_NM2160 94
#define FB_ACCEL_NEOMAGIC_NM2200 95
#define FB_ACCEL_NEOMAGIC_NM2230 96
#define FB_ACCEL_NEOMAGIC_NM2360 97
#define FB_ACCEL_NEOMAGIC_NM2380 98
#define FB_ACCEL_PXA3XX 99
#define FB_ACCEL_SAVAGE4 0x80
#define FB_ACCEL_SAVAGE3D 0x81
#define FB_ACCEL_SAVAGE3D_MV 0x82
#define FB_ACCEL_SAVAGE2000 0x83
#define FB_ACCEL_SAVAGE_MX_MV 0x84
#define FB_ACCEL_SAVAGE_MX 0x85
#define FB_ACCEL_SAVAGE_IX_MV 0x86
#define FB_ACCEL_SAVAGE_IX 0x87
#define FB_ACCEL_PROSAVAGE_PM 0x88
#define FB_ACCEL_PROSAVAGE_KM 0x89
#define FB_ACCEL_S3TWISTER_P 0x8a
#define FB_ACCEL_S3TWISTER_K 0x8b
#define FB_ACCEL_SUPERSAVAGE 0x8c
#define FB_ACCEL_PROSAVAGE_DDR 0x8d
#define FB_ACCEL_PROSAVAGE_DDRK 0x8e
#define FB_ACCEL_PUV3_UNIGFX 0xa0
#define FB_CAP_FOURCC 1
struct fb_fix_screeninfo {
  char id[16];
  unsigned long smem_start;
  __u32 smem_len;
  __u32 type;
  __u32 type_aux;
  __u32 visual;
  __u16 xpanstep;
  __u16 ypanstep;
  __u16 ywrapstep;
  __u32 line_length;
  unsigned long mmio_start;
  __u32 mmio_len;
  __u32 accel;
  __u16 capabilities;
  __u16 reserved[2];
};
struct fb_bitfield {
  __u32 offset;
  __u32 length;
  __u32 msb_right;
};
#define FB_NONSTD_HAM 1
#define FB_NONSTD_REV_PIX_IN_B 2
#define FB_ACTIVATE_NOW 0
#define FB_ACTIVATE_NXTOPEN 1
#define FB_ACTIVATE_TEST 2
#define FB_ACTIVATE_MASK 15
#define FB_ACTIVATE_VBL 16
#define FB_CHANGE_CMAP_VBL 32
#define FB_ACTIVATE_ALL 64
#define FB_ACTIVATE_FORCE 128
#define FB_ACTIVATE_INV_MODE 256
#define FB_ACTIVATE_KD_TEXT 512
#define FB_ACCELF_TEXT 1
#define FB_SYNC_HOR_HIGH_ACT 1
#define FB_SYNC_VERT_HIGH_ACT 2
#define FB_SYNC_EXT 4
#define FB_SYNC_COMP_HIGH_ACT 8
#define FB_SYNC_BROADCAST 16
#define FB_SYNC_ON_GREEN 32
#define FB_VMODE_NONINTERLACED 0
#define FB_VMODE_INTERLACED 1
#define FB_VMODE_DOUBLE 2
#define FB_VMODE_ODD_FLD_FIRST 4
#define FB_VMODE_MASK 255
#define FB_VMODE_YWRAP 256
#define FB_VMODE_SMOOTH_XPAN 512
#define FB_VMODE_CONUPDATE 512
#define FB_ROTATE_UR 0
#define FB_ROTATE_CW 1
#define FB_ROTATE_UD 2
#define FB_ROTATE_CCW 3
#define PICOS2KHZ(a) (1000000000UL / (a))
#define KHZ2PICOS(a) (1000000000UL / (a))
struct fb_var_screeninfo {
  __u32 xres;
  __u32 yres;
  __u32 xres_virtual;
  __u32 yres_virtual;
  __u32 xoffset;
  __u32 yoffset;
  __u32 bits_per_pixel;
  __u32 grayscale;
  struct fb_bitfield red;
  struct fb_bitfield green;
  struct fb_bitfield blue;
  struct fb_bitfield transp;
  __u32 nonstd;
  __u32 activate;
  __u32 height;
  __u32 width;
  __u32 accel_flags;
  __u32 pixclock;
  __u32 left_margin;
  __u32 right_margin;
  __u32 upper_margin;
  __u32 lower_margin;
  __u32 hsync_len;
  __u32 vsync_len;
  __u32 sync;
  __u32 vmode;
  __u32 rotate;
  __u32 colorspace;
  __u32 reserved[4];
};
struct fb_cmap {
  __u32 start;
  __u32 len;
  __u16 * red;
  __u16 * green;
  __u16 * blue;
  __u16 * transp;
};
struct fb_con2fbmap {
  __u32 console;
  __u32 framebuffer;
};
enum {
  FB_BLANK_UNBLANK = VESA_NO_BLANKING,
  FB_BLANK_NORMAL = VESA_NO_BLANKING + 1,
  FB_BLANK_VSYNC_SUSPEND = VESA_VSYNC_SUSPEND + 1,
  FB_BLANK_HSYNC_SUSPEND = VESA_HSYNC_SUSPEND + 1,
  FB_BLANK_POWERDOWN = VESA_POWERDOWN + 1
};
#define FB_VBLANK_VBLANKING 0x001
#define FB_VBLANK_HBLANKING 0x002
#define FB_VBLANK_HAVE_VBLANK 0x004
#define FB_VBLANK_HAVE_HBLANK 0x008
#define FB_VBLANK_HAVE_COUNT 0x010
#define FB_VBLANK_HAVE_VCOUNT 0x020
#define FB_VBLANK_HAVE_HCOUNT 0x040
#define FB_VBLANK_VSYNCING 0x080
#define FB_VBLANK_HAVE_VSYNC 0x100
struct fb_vblank {
  __u32 flags;
  __u32 count;
  __u32 vcount;
  __u32 hcount;
  __u32 reserved[4];
};
#define ROP_COPY 0
#define ROP_XOR 1
struct fb_copyarea {
  __u32 dx;
  __u32 dy;
  __u32 width;
  __u32 height;
  __u32 sx;
  __u32 sy;
};
struct fb_fillrect {
  __u32 dx;
  __u32 dy;
  __u32 width;
  __u32 height;
  __u32 color;
  __u32 rop;
};
struct fb_image {
  __u32 dx;
  __u32 dy;
  __u32 width;
  __u32 height;
  __u32 fg_color;
  __u32 bg_color;
  __u8 depth;
  const char * data;
  struct fb_cmap cmap;
};
#define FB_CUR_SETIMAGE 0x01
#define FB_CUR_SETPOS 0x02
#define FB_CUR_SETHOT 0x04
#define FB_CUR_SETCMAP 0x08
#define FB_CUR_SETSHAPE 0x10
#define FB_CUR_SETSIZE 0x20
#define FB_CUR_SETALL 0xFF
struct fbcurpos {
  __u16 x, y;
};
struct fb_cursor {
  __u16 set;
  __u16 enable;
  __u16 rop;
  const char * mask;
  struct fbcurpos hot;
  struct fb_image image;
};
#define FB_BACKLIGHT_LEVELS 128
#define FB_BACKLIGHT_MAX 0xFF
#endif
```