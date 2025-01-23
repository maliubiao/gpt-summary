Response:
Let's break down the thought process for answering the request about the `omapfb.h` header file.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`omapfb.h`) and explain its purpose and relationship to Android. The request specifically asks about functionalities, Android integration, libc functions, dynamic linker aspects, usage errors, and how Android reaches this code.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI__LINUX_OMAPFB_H__` and `#define _UAPI__LINUX_OMAPFB_H__`:** This is a standard include guard to prevent multiple inclusions of the header file.
* **Includes:** The file includes `<linux/fb.h>`, `<linux/ioctl.h>`, and `<linux/types.h>`. This immediately signals that this header is about interacting with a framebuffer device in the Linux kernel. "uapi" in the path confirms it's for user-space programs.
* **`OMAP_IOW`, `OMAP_IOR`, etc.:** These macros define how to construct ioctl commands. The 'O' likely refers to the OMAP family of processors. `IOW` means "IO Write", `IOR` means "IO Read", and so on.
* **`OMAPFB_...` Constants:** A large number of constants starting with `OMAPFB_`. These are likely the specific ioctl command numbers and associated flags/masks for controlling the OMAP framebuffer.
* **`struct omapfb_...` Structures:**  Several structures define data exchanged between user space and the kernel via ioctl calls. The names of the structures (e.g., `omapfb_update_window`, `omapfb_plane_info`) give hints about their purpose.
* **`enum omapfb_...` Enumerations:** Enumerations define possible values for certain settings, like color formats (`omapfb_color_format`) and plane types (`omapfb_plane`).

**3. Identifying Key Functionalities:**

Based on the constants and structures, the core functionalities become apparent:

* **Framebuffer Control:**  This is the central theme. The file defines how to interact with a framebuffer device.
* **Display Configuration:**  Setting resolution, position, mirroring, update modes.
* **Memory Management:**  Allocating and querying memory for the framebuffer.
* **Overlay Management:**  Working with multiple display layers (planes).
* **Color Keying:**  Implementing transparency.
* **Synchronization:**  Waiting for vertical sync (VSYNC) to avoid tearing.
* **Capabilities Querying:**  Discovering what features the framebuffer supports.

**4. Connecting to Android:**

Knowing that `bionic` is Android's C library and the header is about framebuffer control, the connection to Android's graphics subsystem is clear.

* **SurfaceFlinger:** This Android system service is responsible for compositing the UI and relies heavily on the framebuffer. The ioctls defined here are likely used by SurfaceFlinger (or lower-level drivers it interacts with).
* **Hardware Abstraction Layer (HAL):** Android uses HALs to interact with hardware. A display HAL would use these ioctls to control the display hardware.
* **Native Development Kit (NDK):** While NDK developers don't directly use these ioctls frequently, they are indirectly involved because the Android framework relies on them.

**5. Addressing Specific Questions:**

* **libc Functions:**  The header file *defines* constants and structures but doesn't *implement* any libc functions. The interaction happens via the `ioctl()` system call, which is a libc function. The explanation should focus on how `ioctl()` is used with the defined constants.
* **Dynamic Linker:** This header file doesn't directly involve dynamic linking. It's a kernel header used by user-space applications. The explanation should clarify this.
* **Logical Reasoning (Assumptions):**  Give examples of how ioctl calls using these constants might affect the display. For instance, setting `OMAPFB_MIRROR` with a non-zero value would likely flip the display.
* **User Errors:** Focus on the common mistake of using incorrect ioctl numbers or passing incompatible data structures.
* **Android Framework/NDK Path:** Start from the user interaction (touch, app launch) and trace it down through the layers to the kernel interaction. Mention relevant components like WindowManager, SurfaceFlinger, and the display HAL.
* **Frida Hook:** Demonstrate how to hook the `ioctl()` system call and filter for calls related to the OMAP framebuffer driver by checking the `request` parameter against the defined `OMAPFB_...` constants.

**6. Structuring the Response:**

Organize the information logically, using headings and bullet points for clarity. Start with a general overview and then delve into the specifics requested. Use code examples where appropriate.

**7. Refining the Language:**

Ensure the language is clear, concise, and accurate. Avoid jargon where possible, or explain it if necessary. Since the request is in Chinese, the response should also be in Chinese.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this header is directly used by apps. **Correction:** It's more likely used by system services and HALs due to the low-level nature of the operations.
* **Initial thought:** Focus heavily on individual struct members. **Correction:** Emphasize the overall purpose of each struct in the context of ioctl communication.
* **Initial thought:** Give a very complex dynamic linking example. **Correction:** Realize this header doesn't directly involve dynamic linking and explain why.

By following this thought process, the detailed and accurate answer provided in the initial example can be constructed. The key is to understand the context of the file (Linux kernel framebuffer), its components (ioctl commands, structures), and its place within the Android ecosystem.
这个头文件 `bionic/libc/kernel/uapi/linux/omapfb.h` 定义了与 OMAP (Open Multimedia Application Platform) 相关的 Framebuffer (帧缓冲) 设备的用户空间 API。OMAP 是德州仪器 (Texas Instruments) 生产的一系列片上系统 (SoC)，常用于嵌入式设备，包括早期的 Android 设备。

**功能列举:**

这个头文件定义了一系列常量、结构体和枚举类型，用于用户空间程序与 Linux 内核中的 OMAP Framebuffer 驱动进行交互。其主要功能包括：

1. **定义 ioctl 命令:**  通过 `OMAP_IOW`, `OMAP_IOR`, `OMAP_IOWR`, `OMAP_IO` 等宏定义了一系列用于和 OMAP Framebuffer 设备通信的 ioctl 命令。这些命令用于设置和获取设备的状态、属性以及执行特定操作。
2. **帧缓冲属性控制:**  允许用户空间程序控制帧缓冲的各种属性，例如镜像 (mirroring)、更新模式 (update mode)、颜色键 (color key) 等。
3. **显示同步:**  提供了同步机制，例如等待图形处理器的完成 (`OMAPFB_SYNC_GFX`) 和垂直同步信号 (`OMAPFB_VSYNC`, `OMAPFB_WAITFORVSYNC`)，以避免画面撕裂。
4. **窗口更新:**  定义了用于更新帧缓冲特定区域 (窗口) 的结构体 (`omapfb_update_window`, `omapfb_update_window_old`)，允许只更新屏幕的一部分，提高效率。
5. **图层控制 (Plane Control):**  OMAP Framebuffer 驱动通常支持多个硬件图层 (planes)。这个头文件定义了用于设置和查询图层信息的结构体 (`omapfb_plane_info`)，例如图层的位置、大小、是否启用、输出通道等。
6. **内存管理:**  定义了用于设置和查询帧缓冲内存信息的结构体 (`omapfb_mem_info`)，例如内存大小和类型。
7. **能力查询:**  提供了查询 OMAP Framebuffer 设备能力的机制 (`OMAPFB_GET_CAPS`)，例如是否支持手动更新、垂直同步、图层缩放等。
8. **颜色格式:**  定义了支持的颜色格式 (`omapfb_color_format`)。
9. **背光控制 (间接):**  `OMAPFB_CAPS_SET_BACKLIGHT` 常量暗示了对背光控制的支持，虽然实际的背光控制可能通过其他机制实现。
10. **显示信息:**  提供了获取显示设备信息的功能 (`OMAPFB_GET_DISPLAY_INFO`)，例如分辨率。
11. **Tear Sync (撕裂同步):**  支持通过 `OMAPFB_SET_TEARSYNC` 来控制撕裂同步。

**与 Android 功能的关系及举例说明:**

OMAP Framebuffer 是早期 Android 设备中用于显示内容的核心组件。Android 的图形系统需要与底层的 Framebuffer 驱动进行交互才能将 UI 渲染到屏幕上。

* **SurfaceFlinger:** Android 的 SurfaceFlinger 服务负责合成屏幕上的所有图层，并将最终的图像输出到 Framebuffer。SurfaceFlinger 可能会使用这里定义的 ioctl 命令来配置 Framebuffer，例如设置更新区域、颜色格式、启用/禁用图层等。
    * **举例:** SurfaceFlinger 可能使用 `OMAPFB_UPDATE_WINDOW` 来更新屏幕上某个应用窗口的内容。
    * **举例:** SurfaceFlinger 可能使用 `OMAPFB_WAITFORVSYNC` 来同步屏幕更新，避免画面撕裂。
* **Hardware Composer (HWC):** 后来的 Android 版本引入了 HWC，它将部分显示合成工作委托给硬件。HWC 的实现可能会依赖这些 ioctl 命令来配置硬件图层。
    * **举例:** HWC 可能会使用 `OMAPFB_SETUP_PLANE` 来配置一个硬件图层，用于显示视频内容。
* **Display HAL (硬件抽象层):** Android 的 Display HAL 负责与底层的显示驱动进行交互。Display HAL 的实现会使用这些 ioctl 命令来控制 OMAP Framebuffer 设备。
    * **举例:** Display HAL 可能会使用 `OMAPFB_GET_CAPS` 来查询设备支持的特性。
* **低级别图形库 (例如 libui):** Android 的 libui 库提供了一些用于图形操作的底层接口，它可能会间接地使用这些 ioctl 命令。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义任何 libc 函数。它定义的是用于与内核驱动交互的常量、结构体和枚举。与这个头文件相关的 libc 函数主要是 `ioctl`。

`ioctl` 函数是一个通用的设备输入/输出控制系统调用。它的原型如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* **`fd`:**  文件描述符，通常是通过 `open()` 系统调用打开 Framebuffer 设备文件 (例如 `/dev/fb0`) 获得的。
* **`request`:**  一个与设备相关的请求码，通常是这里定义的 `OMAPFB_...` 常量。
* **`...`:**  可选的参数，通常是指向与请求相关的结构体的指针。

**实现原理:**

当用户空间程序调用 `ioctl` 时，内核会根据文件描述符 `fd` 找到对应的设备驱动程序。然后，内核会将 `request` 参数传递给驱动程序的 `ioctl` 函数处理。对于 OMAP Framebuffer 驱动，它会解析 `request` 参数（例如 `OMAPFB_UPDATE_WINDOW`），并根据提供的参数（例如 `omapfb_update_window` 结构体中的窗口位置和大小）执行相应的硬件操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。它定义的是内核 API，用于用户空间程序通过系统调用与内核交互。Dynamic linker (例如 Android 中的 `linker`) 负责加载和链接共享库 (`.so` 文件)。

如果用户空间程序使用了依赖于 Framebuffer 的库 (例如 Android 的 libgui.so)，那么 dynamic linker 会在程序启动时加载这些库。这些库内部可能会使用 `ioctl` 系统调用，并使用这里定义的常量。

**SO 布局样本 (libgui.so):**

```
libgui.so:
    .text         # 代码段
        ...
        call    ioctl   # 调用 ioctl 系统调用
        ...
    .data         # 数据段
        ...
    .rodata       # 只读数据段
        ...
    .dynamic      # 动态链接信息
        NEEDED   libbinder.so
        NEEDED   libcutils.so
        ...
```

**链接处理过程:**

1. **编译时:** 开发者使用 NDK 或 SDK 编译应用程序和依赖的库。编译器和链接器会将应用程序和库的代码和数据组织成特定的格式 (ELF 格式)。对于共享库，链接器会记录其依赖的其他共享库。
2. **程序启动时:** 当 Android 系统启动应用程序时，`zygote` 进程会 fork 出一个新的进程。然后，`linker` 会被加载到新进程的地址空间。
3. **加载共享库:** `linker` 会解析应用程序的可执行文件头，找到它依赖的共享库列表。然后，`linker` 会按照依赖顺序加载这些共享库到进程的地址空间。
4. **符号解析和重定位:** `linker` 会解析共享库中的符号 (函数和变量)。如果一个共享库调用了另一个共享库中的函数，`linker` 需要将调用地址重定位到目标函数的实际地址。
5. **`ioctl` 调用:** 当 libgui.so 中的代码调用 `ioctl` 时，它实际上是调用了 libc.so 中提供的 `ioctl` 函数的实现。libc.so 是所有 Android 应用程序都需要链接的系统库。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要将屏幕设置为镜像模式：

* **假设输入:**
    * 打开 Framebuffer 设备文件 `/dev/fb0` 获得文件描述符 `fd`。
    * 设置 `mirror_mode` 变量为 `1` (表示水平镜像)。
    * 调用 `ioctl(fd, OMAPFB_MIRROR, &mirror_mode)`。
* **预期输出:**
    * 如果 `ioctl` 调用成功，返回值应为 `0`。
    * 屏幕显示的内容会水平翻转。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的 ioctl 请求码:** 使用了错误的 `OMAPFB_...` 常量，导致内核无法识别请求，`ioctl` 调用会返回错误。
    * **举例:** 调用 `ioctl(fd, OMAPFB_SET_COLOR_KEY + 1, ...)`，使用了错误的请求码。
2. **传递错误的数据结构:**  `ioctl` 的第三个参数必须是指向与请求码匹配的结构体的指针。如果传递了错误的结构体类型或大小，内核可能会访问非法内存或解析错误的数据。
    * **举例:**  调用 `ioctl(fd, OMAPFB_UPDATE_WINDOW, &some_other_struct)`，传递了一个不匹配的结构体。
3. **未打开 Framebuffer 设备:** 在调用 `ioctl` 之前，必须先使用 `open()` 打开 Framebuffer 设备文件。如果文件描述符无效，`ioctl` 调用会失败。
    * **举例:** 直接调用 `ioctl(invalid_fd, OMAPFB_MIRROR, ...)`。
4. **权限不足:**  访问 Framebuffer 设备通常需要特定的权限。如果用户空间程序没有足够的权限，`open()` 调用可能会失败，或者 `ioctl` 调用返回权限错误。
5. **逻辑错误导致参数不合理:**  例如，设置的窗口更新区域超出屏幕边界，或者使用了不支持的颜色格式。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

以下是从 Android Framework 到达 `omapfb.h` 中定义的 ioctl 命令的一个典型路径：

1. **应用层 (Java/Kotlin):** 用户与应用程序交互，例如点击屏幕上的一个按钮。
2. **Framework 层 (Java):**  应用程序的事件会传递到 Android Framework 的 View 系统。例如，`View.invalidate()` 方法会被调用，请求重绘。
3. **WindowManagerService (Java):** WindowManagerService 负责管理窗口，它会收到重绘请求。
4. **SurfaceFlinger (Native C++):** WindowManagerService 会通知 SurfaceFlinger 进行屏幕合成。SurfaceFlinger 是一个 native 服务，负责将不同的图层合成到最终的显示输出。
5. **libgui (Native C++):** SurfaceFlinger 内部会使用 libgui 库来与图形缓冲区 (Gralloc) 和硬件 Composer (HWC) 进行交互。
6. **Hardware Composer HAL (Native C++):** 如果设备支持 HWC，SurfaceFlinger 会尝试使用 HWC 来进行硬件合成。HWC HAL 的实现会调用底层的驱动程序接口。
7. **Framebuffer Driver (Kernel):** 如果 HWC 无法处理或者某些操作需要直接操作 Framebuffer，HWC HAL 或 libgui 可能会直接调用 `ioctl` 系统调用，使用 `omapfb.h` 中定义的 `OMAPFB_...` 常量与 OMAP Framebuffer 驱动进行通信。

**NDK 路径:**

使用 NDK 开发的应用程序可以直接调用 Android 的 native API，这些 API 最终也可能调用到 SurfaceFlinger 或 HWC。

1. **NDK 应用 (C/C++):**  NDK 应用可以使用 `ANativeWindow` 来获取用于绘制的 Surface。
2. **EGL/OpenGL ES:** NDK 应用通常使用 EGL 和 OpenGL ES 进行图形渲染。
3. **Gralloc HAL (Native C++):** EGL 会使用 Gralloc HAL 来分配和管理图形缓冲区。
4. **SurfaceFlinger/HWC (Native C++):**  分配的缓冲区最终会被传递给 SurfaceFlinger 或 HWC 进行合成和显示，从而可能触发对 Framebuffer 驱动的 ioctl 调用。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `ioctl` 系统调用的示例，用于监控与 OMAP Framebuffer 相关的操作：

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.findExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是与 OMAP Framebuffer 相关的 ioctl 请求
        const omapfb_magic = 'O'.charCodeAt(0) << 8;
        if ((request >> 8 & 0xFF) === (omapfb_magic >> 8)) {
          console.log(`ioctl called with fd: ${fd}, request: 0x${request.toString(16)}`);

          // 可以进一步解析请求和参数
          if (request === 0x4f2f) { // OMAPFB_UPDATE_WINDOW 的值 (需要根据实际情况确定)
            const argp = this.context.sp.add(Process.pointerSize * 2); // 获取第三个参数的地址
            const updateWindowPtr = Memory.readPointer(argp);
            if (updateWindowPtr) {
              const updateWindow = {
                x: Memory.readU32(updateWindowPtr.add(0)),
                y: Memory.readU32(updateWindowPtr.add(4)),
                width: Memory.readU32(updateWindowPtr.add(8)),
                height: Memory.readU32(updateWindowPtr.add(12)),
                format: Memory.readU32(updateWindowPtr.add(16)),
                // ... 读取更多字段
              };
              console.log("  OMAPFB_UPDATE_WINDOW data:", updateWindow);
            }
          }
        }
      },
      onLeave: function (retval) {
        // console.log('ioctl returned:', retval.toInt32());
      }
    });
  } else {
    console.log('Error: ioctl symbol not found.');
  }
} else {
  console.log('This script is for Linux platforms only.');
}
```

**解释:**

1. **`Process.platform === 'linux'`:** 确保脚本只在 Linux 平台上运行 (Android 基于 Linux)。
2. **`Module.findExportByName(null, 'ioctl')`:** 找到 `ioctl` 函数的地址。
3. **`Interceptor.attach(ioctlPtr, ...)`:**  Hook `ioctl` 函数。
4. **`onEnter`:**  在 `ioctl` 函数被调用时执行。
5. **检查 Magic Number:** `omapfb_magic` 用于过滤 OMAP Framebuffer 相关的 ioctl 调用。OMAP 的 ioctl magic number 通常是 'O'。
6. **解析参数:**  根据 `request` 的值，可以进一步解析传递给 `ioctl` 的结构体参数。需要根据 `omapfb.h` 中的定义来确定结构体字段的偏移量。
7. **`onLeave`:** 在 `ioctl` 函数返回后执行 (可选)。

**使用步骤:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_omapfb.js`)。
2. 找到目标 Android 进程的进程 ID (PID)。
3. 使用 Frida 连接到目标进程并运行脚本：
   ```bash
   frida -U -f <package_name> -l hook_omapfb.js --no-pause
   # 或者连接到已运行的进程
   frida -U <package_name_or_pid> -l hook_omapfb.js
   ```

通过这个 Frida 脚本，你可以监控哪些进程调用了与 OMAP Framebuffer 相关的 ioctl 命令，以及传递的具体参数，从而帮助你理解 Android 图形系统的运作方式和问题所在。请注意，实际的 ioctl 值可能因 Android 版本和设备而异，你需要根据你的目标环境进行调整。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/omapfb.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_OMAPFB_H__
#define _UAPI__LINUX_OMAPFB_H__
#include <linux/fb.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#define OMAP_IOW(num,dtype) _IOW('O', num, dtype)
#define OMAP_IOR(num,dtype) _IOR('O', num, dtype)
#define OMAP_IOWR(num,dtype) _IOWR('O', num, dtype)
#define OMAP_IO(num) _IO('O', num)
#define OMAPFB_MIRROR OMAP_IOW(31, int)
#define OMAPFB_SYNC_GFX OMAP_IO(37)
#define OMAPFB_VSYNC OMAP_IO(38)
#define OMAPFB_SET_UPDATE_MODE OMAP_IOW(40, int)
#define OMAPFB_GET_CAPS OMAP_IOR(42, struct omapfb_caps)
#define OMAPFB_GET_UPDATE_MODE OMAP_IOW(43, int)
#define OMAPFB_LCD_TEST OMAP_IOW(45, int)
#define OMAPFB_CTRL_TEST OMAP_IOW(46, int)
#define OMAPFB_UPDATE_WINDOW_OLD OMAP_IOW(47, struct omapfb_update_window_old)
#define OMAPFB_SET_COLOR_KEY OMAP_IOW(50, struct omapfb_color_key)
#define OMAPFB_GET_COLOR_KEY OMAP_IOW(51, struct omapfb_color_key)
#define OMAPFB_SETUP_PLANE OMAP_IOW(52, struct omapfb_plane_info)
#define OMAPFB_QUERY_PLANE OMAP_IOW(53, struct omapfb_plane_info)
#define OMAPFB_UPDATE_WINDOW OMAP_IOW(54, struct omapfb_update_window)
#define OMAPFB_SETUP_MEM OMAP_IOW(55, struct omapfb_mem_info)
#define OMAPFB_QUERY_MEM OMAP_IOW(56, struct omapfb_mem_info)
#define OMAPFB_WAITFORVSYNC OMAP_IO(57)
#define OMAPFB_MEMORY_READ OMAP_IOR(58, struct omapfb_memory_read)
#define OMAPFB_GET_OVERLAY_COLORMODE OMAP_IOR(59, struct omapfb_ovl_colormode)
#define OMAPFB_WAITFORGO OMAP_IO(60)
#define OMAPFB_GET_VRAM_INFO OMAP_IOR(61, struct omapfb_vram_info)
#define OMAPFB_SET_TEARSYNC OMAP_IOW(62, struct omapfb_tearsync_info)
#define OMAPFB_GET_DISPLAY_INFO OMAP_IOR(63, struct omapfb_display_info)
#define OMAPFB_CAPS_GENERIC_MASK 0x00000fff
#define OMAPFB_CAPS_LCDC_MASK 0x00fff000
#define OMAPFB_CAPS_PANEL_MASK 0xff000000
#define OMAPFB_CAPS_MANUAL_UPDATE 0x00001000
#define OMAPFB_CAPS_TEARSYNC 0x00002000
#define OMAPFB_CAPS_PLANE_RELOCATE_MEM 0x00004000
#define OMAPFB_CAPS_PLANE_SCALE 0x00008000
#define OMAPFB_CAPS_WINDOW_PIXEL_DOUBLE 0x00010000
#define OMAPFB_CAPS_WINDOW_SCALE 0x00020000
#define OMAPFB_CAPS_WINDOW_OVERLAY 0x00040000
#define OMAPFB_CAPS_WINDOW_ROTATE 0x00080000
#define OMAPFB_CAPS_SET_BACKLIGHT 0x01000000
#define OMAPFB_FORMAT_MASK 0x00ff
#define OMAPFB_FORMAT_FLAG_DOUBLE 0x0100
#define OMAPFB_FORMAT_FLAG_TEARSYNC 0x0200
#define OMAPFB_FORMAT_FLAG_FORCE_VSYNC 0x0400
#define OMAPFB_FORMAT_FLAG_ENABLE_OVERLAY 0x0800
#define OMAPFB_FORMAT_FLAG_DISABLE_OVERLAY 0x1000
#define OMAPFB_MEMTYPE_SDRAM 0
#define OMAPFB_MEMTYPE_SRAM 1
#define OMAPFB_MEMTYPE_MAX 1
#define OMAPFB_MEM_IDX_ENABLED 0x80
#define OMAPFB_MEM_IDX_MASK 0x7f
enum omapfb_color_format {
  OMAPFB_COLOR_RGB565 = 0,
  OMAPFB_COLOR_YUV422,
  OMAPFB_COLOR_YUV420,
  OMAPFB_COLOR_CLUT_8BPP,
  OMAPFB_COLOR_CLUT_4BPP,
  OMAPFB_COLOR_CLUT_2BPP,
  OMAPFB_COLOR_CLUT_1BPP,
  OMAPFB_COLOR_RGB444,
  OMAPFB_COLOR_YUY422,
  OMAPFB_COLOR_ARGB16,
  OMAPFB_COLOR_RGB24U,
  OMAPFB_COLOR_RGB24P,
  OMAPFB_COLOR_ARGB32,
  OMAPFB_COLOR_RGBA32,
  OMAPFB_COLOR_RGBX32,
};
struct omapfb_update_window {
  __u32 x, y;
  __u32 width, height;
  __u32 format;
  __u32 out_x, out_y;
  __u32 out_width, out_height;
  __u32 reserved[8];
};
struct omapfb_update_window_old {
  __u32 x, y;
  __u32 width, height;
  __u32 format;
};
enum omapfb_plane {
  OMAPFB_PLANE_GFX = 0,
  OMAPFB_PLANE_VID1,
  OMAPFB_PLANE_VID2,
};
enum omapfb_channel_out {
  OMAPFB_CHANNEL_OUT_LCD = 0,
  OMAPFB_CHANNEL_OUT_DIGIT,
};
struct omapfb_plane_info {
  __u32 pos_x;
  __u32 pos_y;
  __u8 enabled;
  __u8 channel_out;
  __u8 mirror;
  __u8 mem_idx;
  __u32 out_width;
  __u32 out_height;
  __u32 reserved2[12];
};
struct omapfb_mem_info {
  __u32 size;
  __u8 type;
  __u8 reserved[3];
};
struct omapfb_caps {
  __u32 ctrl;
  __u32 plane_color;
  __u32 wnd_color;
};
enum omapfb_color_key_type {
  OMAPFB_COLOR_KEY_DISABLED = 0,
  OMAPFB_COLOR_KEY_GFX_DST,
  OMAPFB_COLOR_KEY_VID_SRC,
};
struct omapfb_color_key {
  __u8 channel_out;
  __u32 background;
  __u32 trans_key;
  __u8 key_type;
};
enum omapfb_update_mode {
  OMAPFB_UPDATE_DISABLED = 0,
  OMAPFB_AUTO_UPDATE,
  OMAPFB_MANUAL_UPDATE
};
struct omapfb_memory_read {
  __u16 x;
  __u16 y;
  __u16 w;
  __u16 h;
  size_t buffer_size;
  void  * buffer;
};
struct omapfb_ovl_colormode {
  __u8 overlay_idx;
  __u8 mode_idx;
  __u32 bits_per_pixel;
  __u32 nonstd;
  struct fb_bitfield red;
  struct fb_bitfield green;
  struct fb_bitfield blue;
  struct fb_bitfield transp;
};
struct omapfb_vram_info {
  __u32 total;
  __u32 free;
  __u32 largest_free_block;
  __u32 reserved[5];
};
struct omapfb_tearsync_info {
  __u8 enabled;
  __u8 reserved1[3];
  __u16 line;
  __u16 reserved2;
};
struct omapfb_display_info {
  __u16 xres;
  __u16 yres;
  __u32 width;
  __u32 height;
  __u32 reserved[5];
};
#endif
```