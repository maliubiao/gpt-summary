Response:
Let's break down the thought process for analyzing this DRM header file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the `drm.handroid.h` header file. Key points are:

* **Functionality:** What does this file *do*?
* **Android Relationship:** How does it tie into Android?
* **libc Functions:** Explain the libc functions used (though, as we'll see, there aren't really *libc functions* in the usual sense).
* **Dynamic Linker:** How does this relate to the dynamic linker? (Crucially, it's a *header file*, so it doesn't directly *use* the dynamic linker in the same way a `.so` library does).
* **Logic Inference:**  Hypothetical inputs and outputs.
* **Common Errors:** How can developers misuse this?
* **Android Framework/NDK Path:** How does a call reach this code?
* **Frida Hooking:**  Examples of how to intercept calls.

**2. Initial Scan and Key Observations:**

My first pass through the code would highlight these things:

* **`#ifndef _DRM_H_`:** This is a standard header guard, preventing multiple inclusions.
* **`#include <linux/types.h>` and `#include <asm/ioctl.h>` (under `__linux__`):** This immediately tells me this header is designed for interaction with the Linux kernel's Direct Rendering Manager (DRM) subsystem. The `ioctl.h` inclusion is a strong indicator of kernel interaction.
* **`typedef`s for `drm_handle_t`:**  Different definitions based on `__linux__`. This points to platform-specific handling, even within Android.
* **`#define` constants starting with `DRM_`:**  These define symbolic names for various DRM concepts (like `DRM_NAME`, `DRM_MIN_ORDER`, capabilities, etc.).
* **`struct` definitions starting with `drm_`:**  These are the core data structures used to communicate with the DRM kernel module. They represent things like clip rectangles, versions, maps, contexts, buffers, etc.
* **`enum` definitions starting with `drm_`:** These define sets of possible values for certain fields within the structures (like map types, map flags, DMA flags).
* **`#define DRM_IOCTL_*`:**  These are *the* crucial part. They define the ioctl commands used to send requests to the DRM kernel driver. The `_IO`, `_IOR`, `_IOW`, `_IOWR` macros confirm this is about ioctl communication.
* **`#include "drm_mode.h"`:** This suggests that this header is part of a larger DRM API, with modesetting details separated.
* **`struct drm_event`:**  Defines structures for events coming *from* the kernel.

**3. Categorizing and Explaining Functionality:**

Based on the observations, I would start grouping the content by functionality:

* **Core DRM Definitions:**  Basic types (`drm_handle_t`), constants (`DRM_NAME`), and lock definitions.
* **Resource Management:** Structures like `drm_map`, `drm_buf_*`, `drm_agp_*`, `drm_scatter_gather`.
* **Context and Client Management:** `drm_context_t`, `drm_client`, `drm_ctx_*`.
* **Synchronization:** `drm_lock`, `drm_wait_vblank`, `drm_syncobj_*`.
* **Modesetting:** This is mostly in `drm_mode.h` (mentioned in the include), but `drm_modeset_ctl` hints at its purpose.
* **IOCTL Interface:** The `DRM_IOCTL_*` macros are the interface for user-space programs to interact with the kernel driver.
* **Events:**  Structures like `drm_event_vblank`.
* **Capabilities:** `DRM_CAP_*` and `DRM_CLIENT_CAP_*` indicate features the driver or client supports.

**4. Connecting to Android:**

This is where understanding Android's graphics stack is crucial.

* **SurfaceFlinger:** This is the key Android service that uses DRM to manage the display. It opens the DRM device and uses ioctls to control the display.
* **Hardware Composer (HWC/HWC2):**  These are hardware abstraction layers that often sit between SurfaceFlinger and the kernel DRM driver.
* **Gralloc:**  The graphics allocator that manages buffers used for rendering. These buffers might be tied to DRM resources.
* **NDK (libdrm):** Android provides a userspace library (`libdrm`) that wraps the ioctl calls, making it easier for NDK developers to interact with DRM (though direct use is less common than going through the framework).

**5. Addressing Specific Questions:**

* **libc Functions:**  The header *itself* doesn't directly implement libc functions. It *uses* standard C types (`unsigned int`, `char`, etc.) that are part of libc. The *implementation* of the ioctl calls would be in libc (likely `ioctl()`).
* **Dynamic Linker:**  This header file isn't a dynamically linked library. However, the `libdrm.so` library (if used) *would* be.
* **Logic Inference:**  This is about understanding the purpose of structures and ioctls. For example, calling `DRM_IOCTL_GET_VERSION` will populate a `drm_version` struct.
* **Common Errors:**  Focus on incorrect ioctl usage, memory management issues with DRM resources, and synchronization problems.
* **Android Framework/NDK Path:**  Trace a simple graphics operation (like displaying an image) from the application level down to the kernel DRM driver.
* **Frida Hooking:** Target the `ioctl()` system call, filtering for DRM-related ioctl numbers.

**6. Refinement and Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Provide specific examples and code snippets where possible. Ensure the language is clear and concise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This file defines DRM functions."  **Correction:** It defines *data structures and ioctl numbers* used to interact with the DRM *kernel driver*. The *functions* are in `libdrm.so` or within the kernel itself.
* **Overemphasis on libc:**  Realized the prompt was slightly misleading. This header *defines types*, not implements libc functions in the typical sense. The key libc function involved is `ioctl`.
* **Dynamic Linker Confusion:**  Clarified that the header itself isn't linked, but the library using it would be. Provided an example of a linked library.

By following this structured approach, breaking down the problem into smaller pieces, and continually refining my understanding, I can generate a comprehensive and accurate answer like the example provided.
这个文件 `drm.handroid.h` 是 Android Bionic C 库的一部分，它定义了与 Linux 内核的 Direct Rendering Manager (DRM) 子系统进行交互的数据结构和常量。DRM 是一个内核子系统，用于管理显卡硬件，提供用户空间程序访问显卡功能（如模式设置、帧缓冲管理、同步等）的接口。由于这个文件位于 `bionic/libc/kernel/uapi/drm/`，它实际上是从 Linux 内核的 UAPI (用户空间应用程序编程接口) 复制过来的，目的是为了让 Android 的用户空间程序可以直接使用这些定义，而无需依赖完整的 Linux 内核头文件。

**功能列举:**

1. **定义 DRM 数据结构:**  文件中定义了各种 C 结构体 (`struct drm_*`)，这些结构体用于在用户空间程序和 DRM 内核驱动之间传递信息。这些结构体涵盖了 DRM 的核心概念，例如：
    * **版本信息 (`drm_version`)**: 获取 DRM 驱动的版本信息。
    * **唯一标识符 (`drm_unique`)**:  获取 DRM 设备的唯一标识符。
    * **裁剪矩形 (`drm_clip_rect`) 和可绘制信息 (`drm_drawable_info`)**:  用于管理渲染目标的可绘制区域。
    * **硬件锁 (`drm_hw_lock`)**:  用于同步访问显卡硬件的锁。
    * **内存映射 (`drm_map`)**:  描述了用户空间可以映射的显卡内存区域。
    * **客户端信息 (`drm_client`)**:  描述了连接到 DRM 驱动的客户端进程的信息。
    * **统计信息 (`drm_stats`)**:  获取 DRM 驱动的各种统计数据。
    * **锁管理 (`drm_lock`)**:  用于请求和释放 DRM 锁。
    * **DMA (`drm_dma`)**:  用于发起直接内存访问操作。
    * **上下文 (`drm_ctx`)**:  用于管理不同的渲染上下文。
    * **AGP 和 Scatter-Gather (`drm_agp_*`, `drm_scatter_gather`)**:  用于处理老旧的 AGP 接口和更通用的 Scatter-Gather DMA。
    * **GEM 对象 (`drm_gem_*`)**:  用于管理图形执行管理器 (GEM) 对象，这是现代 DRM 中管理显存的主要方式。
    * **VBlank 同步 (`drm_wait_vblank`)**:  用于等待垂直回扫信号，以进行画面同步。
    * **同步对象 (`drm_syncobj_*`)**:  用于更精细的帧同步和资源同步。
    * **模式设置 (`drm_mode_*`)**: 定义了与显示模式设置相关的结构体（这部分定义在 `drm_mode.h` 中，被当前文件包含）。

2. **定义 DRM 常量:** 文件中定义了大量的宏 (`#define DRM_*`)，这些宏代表了各种 DRM 相关的常量，例如：
    * **DRM 设备名称 (`DRM_NAME`)**
    * **锁标志 (`_DRM_LOCK_*`)**
    * **映射类型和标志 (`_DRM_MAP_TYPE_*`, `_DRM_MAP_FLAGS_*`)**
    * **统计类型 (`_DRM_STAT_TYPE_*`)**
    * **DMA 标志 (`_DRM_DMA_FLAGS_*`)**
    * **上下文标志 (`_DRM_CONTEXT_FLAGS_*`)**
    * **VBlank 序列类型 (`_DRM_VBLANK_SEQ_TYPE_*`)**
    * **功能标志 (`DRM_CAP_*`, `DRM_CLIENT_CAP_*`)**
    * **IOCTL 命令 (`DRM_IOCTL_*`)**:  定义了与 DRM 驱动进行通信的 ioctl 命令编号。

3. **定义 IOCTL 接口:**  最重要的是，这个文件定义了大量的 `DRM_IOCTL_*` 宏。这些宏是用于构建 `ioctl()` 系统调用的请求码，用于向 DRM 内核驱动发送命令，并传递相应的数据结构。每个 `DRM_IOCTL_` 宏都对应一个特定的 DRM 操作，例如获取版本信息、创建 GEM 对象、设置显示模式等。

**与 Android 功能的关系及举例说明:**

DRM 是 Android 图形框架的基石。Android 的 SurfaceFlinger 服务以及底层的硬件抽象层 (HAL) 经常需要与 DRM 驱动交互来完成屏幕显示、合成、同步等任务。

* **SurfaceFlinger**:  SurfaceFlinger 是 Android 系统中负责屏幕内容合成和显示的组件。它使用 DRM API 来：
    * **获取显示器信息**: 使用 `DRM_IOCTL_MODE_GETRESOURCES`、`DRM_IOCTL_MODE_GETCONNECTOR` 等 ioctl 获取连接的显示器信息，例如分辨率、刷新率等。
    * **设置显示模式**: 使用 `DRM_IOCTL_MODE_SETCRTC` ioctl 来设置显示器的分辨率和刷新率。
    * **分配和管理帧缓冲**: 使用 `DRM_IOCTL_MODE_ADDFB`、`DRM_IOCTL_MODE_RMFB` 以及 GEM 相关的 ioctl (例如 `DRM_IOCTL_GEM_OPEN`) 来分配和管理用于渲染的帧缓冲。
    * **页面翻转 (Page Flipping)**: 使用 `DRM_IOCTL_MODE_PAGE_FLIP` ioctl 来实现无撕裂的屏幕更新。
    * **VBlank 同步**: 使用 `DRM_IOCTL_WAIT_VBLANK` ioctl 来等待垂直回扫信号，以实现帧同步，避免画面撕裂。
    * **Cursor 控制**: 使用 `DRM_IOCTL_MODE_CURSOR` 或 `DRM_IOCTL_MODE_CURSOR2` 来控制鼠标光标的显示。

* **Hardware Composer (HWC/HWC2)**: HWC 是 Android 的硬件合成器框架，它将部分显示合成任务卸载到硬件上。HWC/HWC2 的实现经常需要与 DRM 驱动交互：
    * **提交图层 (Layers)**: HWC 使用 DRM API 将需要合成的图层信息提交给硬件进行合成。这可能涉及到 GEM 对象的传递和同步。
    * **同步 Fence**: HWC 使用 DRM 的同步对象 (`drm_syncobj_*`) 来管理不同硬件组件之间的同步，确保渲染和显示的正确顺序。

* **Gralloc HAL**: Gralloc 是 Android 的图形缓冲区分配器。它可能会使用 DRM GEM API (`DRM_IOCTL_GEM_OPEN`, `DRM_IOCTL_GEM_CLOSE`, `DRM_IOCTL_PRIME_FD_TO_HANDLE`, `DRM_IOCTL_PRIME_HANDLE_TO_FD`) 来分配和管理显存缓冲区，并与其他组件共享这些缓冲区的文件描述符。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**不包含任何 libc 函数的实现**。它仅仅是定义了数据结构和常量。真正与 DRM 交互的 libc 函数是 `ioctl()`。

`ioctl()` 是一个通用的系统调用，用于执行设备特定的控制操作。它的原型通常是：

```c
int ioctl(int fd, unsigned long request, ...);
```

* **`fd`**:  文件描述符，通常是通过 `open()` 系统调用打开的 DRM 设备文件（例如 `/dev/dri/card0`）。
* **`request`**:  一个设备特定的请求码，在这个场景下，就是 `DRM_IOCTL_*` 宏定义的值。
* **`...`**:  可选的参数，通常是一个指向数据结构的指针，用于向驱动程序传递数据或接收驱动程序返回的数据。

**`ioctl()` 的实现过程 (简化):**

1. **用户空间调用:** 用户空间程序调用 `ioctl()` 函数，并传入 DRM 设备的文件描述符、`DRM_IOCTL_*` 请求码以及指向相关数据结构的指针。
2. **系统调用陷入内核:** `ioctl()` 是一个系统调用，会触发从用户空间到内核空间的切换。
3. **内核处理:** 内核接收到 `ioctl()` 系统调用后，会根据传入的文件描述符找到对应的设备驱动程序（这里是 DRM 驱动）。
4. **驱动程序处理:** DRM 驱动程序会检查 `ioctl()` 的请求码 (`DRM_IOCTL_*`)，并根据请求码执行相应的操作。
    * **解析数据:** 驱动程序会解析用户空间传递过来的数据结构。
    * **硬件交互:** 驱动程序可能会与显卡硬件进行交互，例如设置寄存器、分配显存、控制显示引擎等。
    * **返回结果:** 驱动程序会将操作结果填充到用户空间传递的数据结构中，或者返回一个状态码。
5. **内核返回用户空间:** 内核将控制权返回给用户空间程序，`ioctl()` 函数返回执行结果。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接器。然而，用户空间程序通常会链接到 `libdrm.so` 库来方便地使用 DRM API。`libdrm.so` 库封装了对 `ioctl()` 的调用，并提供更高级的函数接口。

**`libdrm.so` 布局样本 (简化):**

```
libdrm.so:
    .text          # 包含函数代码，例如 drmOpen, drmIoctl 等
    .data          # 包含全局变量
    .rodata        # 包含只读数据，例如字符串常量
    .bss           # 包含未初始化的全局变量
    .dynsym        # 动态符号表，列出导出的符号
    .dynstr        # 动态字符串表，存储符号名称
    .rel.dyn       # 动态重定位表，用于链接时修正地址
    .plt           # 程序链接表，用于延迟绑定
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当用户空间程序使用 `libdrm.so` 提供的函数时，编译器会将对这些函数的调用记录下来，并在生成的目标文件中创建对这些符号的未解析引用。
2. **动态链接器介入:** 当程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的动态库，例如 `libdrm.so`。
3. **查找符号:** 动态链接器会扫描 `libdrm.so` 的 `.dynsym` (动态符号表) 来查找程序中未解析的符号。
4. **重定位:** 动态链接器会根据 `.rel.dyn` (动态重定位表) 中的信息，修改程序代码和数据段中对 `libdrm.so` 中符号的引用，将其指向 `libdrm.so` 中实际的地址。
5. **延迟绑定 (PLT):** 通常情况下，动态链接器会使用延迟绑定技术。这意味着在程序刚启动时，只会解析必要的符号。当程序第一次调用 `libdrm.so` 中的某个函数时，会通过 `.plt` (程序链接表) 跳转到一个特殊的地址，该地址会调用动态链接器来解析该函数的真实地址，并将 `PLT` 表项更新为该真实地址。后续对该函数的调用将直接跳转到真实地址，避免重复解析。

**假设输入与输出 (针对 ioctl 调用):**

**假设输入:**

* 用户空间程序打开了 DRM 设备文件 `/dev/dri/card0`，获取了文件描述符 `fd`.
* 用户空间程序想要获取 DRM 驱动的版本信息，定义了一个 `drm_version` 结构体变量 `version`.
* 用户空间程序调用 `ioctl(fd, DRM_IOCTL_VERSION, &version)`.

**预期输出:**

* `ioctl()` 函数执行成功，返回 0。
* `version` 结构体中的字段 `version_major`, `version_minor`, `version_patchlevel`, `name`, `date`, `desc` 将被 DRM 驱动填充为实际的版本信息。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确初始化数据结构:**  在使用 `ioctl()` 发送命令时，如果传递的数据结构未被正确初始化，可能会导致驱动程序解析错误或崩溃。例如，在使用 `DRM_IOCTL_MODE_SETCRTC` 设置显示模式时，必须正确填充 `drm_mode_crtc` 结构体中的各个字段，包括模式信息、帧缓冲 ID 等。

2. **传递错误的 ioctl 请求码:**  使用错误的 `DRM_IOCTL_*` 宏值会导致驱动程序无法识别请求，或者执行错误的操作。

3. **内存管理错误:**  当 `ioctl()` 涉及到指针传递时，用户空间程序需要确保指针指向的内存是有效的，并且在 `ioctl()` 调用期间不会被释放或修改。例如，在使用 `DRM_IOCTL_ADD_MAP` 创建内存映射时，需要提供有效的内存大小和地址。

4. **权限问题:**  访问 DRM 设备通常需要特定的权限。如果用户空间程序没有足够的权限打开 DRM 设备文件，或者执行某些需要 root 权限的 ioctl 操作，将会失败。

5. **同步问题:**  在多线程或多进程环境中，访问 DRM 资源时需要进行适当的同步，避免竞争条件和数据损坏。例如，多个线程同时尝试修改同一个帧缓冲可能会导致问题。

6. **错误处理:**  用户空间程序应该检查 `ioctl()` 的返回值，以判断操作是否成功，并根据错误码进行相应的处理。忽略错误可能会导致程序行为异常。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida 来 hook `ioctl` 系统调用，并过滤出与 DRM 相关的调用，以观察 Android Framework 或 NDK 如何与 DRM 驱动交互。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['timestamp'], message['payload']['details']))
    else:
        print(message)

session = frida.attach('com.android.systemui') # 或者你需要调试的进程

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var timestamp = new Date().toISOString();

        // 检查是否是 DRM 相关的 ioctl (基于 DRM_IOCTL_BASE 'd' 的特征)
        if ((request >> 8 & 0xFF) == 'd'.charCodeAt(0)) {
            var requestName = "Unknown DRM IOCTL";
            // 可以添加更多已知的 DRM_IOCTL_* 宏的映射来解析 requestName
            if (request == 0x6400) requestName = "DRM_IOCTL_VERSION";
            if (request == 0x64a0) requestName = "DRM_IOCTL_MODE_GETRESOURCES";
            // ... 添加更多你关心的 IOCTL

            var details = "ioctl(fd=" + fd + ", request=0x" + request.toString(16) + " (" + requestName + "))";
            send({'timestamp': timestamp, 'details': details});
            // 可以进一步解析 args[2] 指向的数据结构的内容，如果需要的话
        }
    },
    onLeave: function(retval) {
        // 可以记录 ioctl 的返回值
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **`frida.attach('com.android.systemui')`**:  连接到 `com.android.systemui` 进程，你可以替换为你想要监控的进程，例如某个应用或 SurfaceFlinger。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`**:  Hook 全局的 `ioctl` 函数。
3. **`onEnter`**: 在 `ioctl` 函数调用前执行。
4. **`args[0]`**:  `ioctl` 的第一个参数，文件描述符 `fd`。
5. **`args[1]`**:  `ioctl` 的第二个参数，请求码 `request`。
6. **`(request >> 8 & 0xFF) == 'd'.charCodeAt(0)`**:  一个简单的判断，检查请求码的某个字节是否与 'd' 的 ASCII 码相同，这可以粗略地判断是否是 DRM 相关的 ioctl。
7. **解析 `requestName`**:  你可以添加更多 `if` 条件来将数值型的 `request` 映射到对应的 `DRM_IOCTL_*` 宏的名称，提高可读性。
8. **`send({'timestamp': timestamp, 'details': details})`**: 使用 Frida 的 `send` 函数将信息发送到你的 Python 脚本。
9. **`on_message` 函数**:  接收 Frida 发送的消息并打印出来。

通过运行这个 Frida 脚本，你可以观察到 `com.android.systemui`（或其他目标进程）在与 DRM 驱动交互时调用的 `ioctl` 函数，以及传递的请求码。你可以根据输出的请求码进一步分析 Android Framework 如何使用 DRM API 来完成其图形任务。如果需要更深入的调试，可以在 Frida 脚本中解析 `args[2]` 指向的数据结构的内容，但这需要对具体的 `DRM_IOCTL_*` 命令和对应的数据结构有更深入的了解。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _DRM_H_
#define _DRM_H_
#ifdef __linux__
#include <linux/types.h>
#include <asm/ioctl.h>
typedef unsigned int drm_handle_t;
#else
#include <stdint.h>
#include <sys/ioccom.h>
#include <sys/types.h>
typedef int8_t __s8;
typedef uint8_t __u8;
typedef int16_t __s16;
typedef uint16_t __u16;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef int64_t __s64;
typedef uint64_t __u64;
typedef size_t __kernel_size_t;
typedef unsigned long drm_handle_t;
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_NAME "drm"
#define DRM_MIN_ORDER 5
#define DRM_MAX_ORDER 22
#define DRM_RAM_PERCENT 10
#define _DRM_LOCK_HELD 0x80000000U
#define _DRM_LOCK_CONT 0x40000000U
#define _DRM_LOCK_IS_HELD(lock) ((lock) & _DRM_LOCK_HELD)
#define _DRM_LOCK_IS_CONT(lock) ((lock) & _DRM_LOCK_CONT)
#define _DRM_LOCKING_CONTEXT(lock) ((lock) & ~(_DRM_LOCK_HELD | _DRM_LOCK_CONT))
typedef unsigned int drm_context_t;
typedef unsigned int drm_drawable_t;
typedef unsigned int drm_magic_t;
struct drm_clip_rect {
  unsigned short x1;
  unsigned short y1;
  unsigned short x2;
  unsigned short y2;
};
struct drm_drawable_info {
  unsigned int num_rects;
  struct drm_clip_rect * rects;
};
struct drm_tex_region {
  unsigned char next;
  unsigned char prev;
  unsigned char in_use;
  unsigned char padding;
  unsigned int age;
};
struct drm_hw_lock {
  __volatile__ unsigned int lock;
  char padding[60];
};
struct drm_version {
  int version_major;
  int version_minor;
  int version_patchlevel;
  __kernel_size_t name_len;
  char  * name;
  __kernel_size_t date_len;
  char  * date;
  __kernel_size_t desc_len;
  char  * desc;
};
struct drm_unique {
  __kernel_size_t unique_len;
  char  * unique;
};
struct drm_list {
  int count;
  struct drm_version  * version;
};
struct drm_block {
  int unused;
};
struct drm_control {
  enum {
    DRM_ADD_COMMAND,
    DRM_RM_COMMAND,
    DRM_INST_HANDLER,
    DRM_UNINST_HANDLER
  } func;
  int irq;
};
enum drm_map_type {
  _DRM_FRAME_BUFFER = 0,
  _DRM_REGISTERS = 1,
  _DRM_SHM = 2,
  _DRM_AGP = 3,
  _DRM_SCATTER_GATHER = 4,
  _DRM_CONSISTENT = 5
};
enum drm_map_flags {
  _DRM_RESTRICTED = 0x01,
  _DRM_READ_ONLY = 0x02,
  _DRM_LOCKED = 0x04,
  _DRM_KERNEL = 0x08,
  _DRM_WRITE_COMBINING = 0x10,
  _DRM_CONTAINS_LOCK = 0x20,
  _DRM_REMOVABLE = 0x40,
  _DRM_DRIVER = 0x80
};
struct drm_ctx_priv_map {
  unsigned int ctx_id;
  void * handle;
};
struct drm_map {
  unsigned long offset;
  unsigned long size;
  enum drm_map_type type;
  enum drm_map_flags flags;
  void * handle;
  int mtrr;
};
struct drm_client {
  int idx;
  int auth;
  unsigned long pid;
  unsigned long uid;
  unsigned long magic;
  unsigned long iocs;
};
enum drm_stat_type {
  _DRM_STAT_LOCK,
  _DRM_STAT_OPENS,
  _DRM_STAT_CLOSES,
  _DRM_STAT_IOCTLS,
  _DRM_STAT_LOCKS,
  _DRM_STAT_UNLOCKS,
  _DRM_STAT_VALUE,
  _DRM_STAT_BYTE,
  _DRM_STAT_COUNT,
  _DRM_STAT_IRQ,
  _DRM_STAT_PRIMARY,
  _DRM_STAT_SECONDARY,
  _DRM_STAT_DMA,
  _DRM_STAT_SPECIAL,
  _DRM_STAT_MISSED
};
struct drm_stats {
  unsigned long count;
  struct {
    unsigned long value;
    enum drm_stat_type type;
  } data[15];
};
enum drm_lock_flags {
  _DRM_LOCK_READY = 0x01,
  _DRM_LOCK_QUIESCENT = 0x02,
  _DRM_LOCK_FLUSH = 0x04,
  _DRM_LOCK_FLUSH_ALL = 0x08,
  _DRM_HALT_ALL_QUEUES = 0x10,
  _DRM_HALT_CUR_QUEUES = 0x20
};
struct drm_lock {
  int context;
  enum drm_lock_flags flags;
};
enum drm_dma_flags {
  _DRM_DMA_BLOCK = 0x01,
  _DRM_DMA_WHILE_LOCKED = 0x02,
  _DRM_DMA_PRIORITY = 0x04,
  _DRM_DMA_WAIT = 0x10,
  _DRM_DMA_SMALLER_OK = 0x20,
  _DRM_DMA_LARGER_OK = 0x40
};
struct drm_buf_desc {
  int count;
  int size;
  int low_mark;
  int high_mark;
  enum {
    _DRM_PAGE_ALIGN = 0x01,
    _DRM_AGP_BUFFER = 0x02,
    _DRM_SG_BUFFER = 0x04,
    _DRM_FB_BUFFER = 0x08,
    _DRM_PCI_BUFFER_RO = 0x10
  } flags;
  unsigned long agp_start;
};
struct drm_buf_info {
  int count;
  struct drm_buf_desc  * list;
};
struct drm_buf_free {
  int count;
  int  * list;
};
struct drm_buf_pub {
  int idx;
  int total;
  int used;
  void  * address;
};
struct drm_buf_map {
  int count;
#ifdef __cplusplus
  void  * virt;
#else
  void  * __linux_virtual;
#endif
  struct drm_buf_pub  * list;
};
struct drm_dma {
  int context;
  int send_count;
  int  * send_indices;
  int  * send_sizes;
  enum drm_dma_flags flags;
  int request_count;
  int request_size;
  int  * request_indices;
  int  * request_sizes;
  int granted_count;
};
enum drm_ctx_flags {
  _DRM_CONTEXT_PRESERVED = 0x01,
  _DRM_CONTEXT_2DONLY = 0x02
};
struct drm_ctx {
  drm_context_t handle;
  enum drm_ctx_flags flags;
};
struct drm_ctx_res {
  int count;
  struct drm_ctx  * contexts;
};
struct drm_draw {
  drm_drawable_t handle;
};
typedef enum {
  DRM_DRAWABLE_CLIPRECTS
} drm_drawable_info_type_t;
struct drm_update_draw {
  drm_drawable_t handle;
  unsigned int type;
  unsigned int num;
  unsigned long long data;
};
struct drm_auth {
  drm_magic_t magic;
};
struct drm_irq_busid {
  int irq;
  int busnum;
  int devnum;
  int funcnum;
};
enum drm_vblank_seq_type {
  _DRM_VBLANK_ABSOLUTE = 0x0,
  _DRM_VBLANK_RELATIVE = 0x1,
  _DRM_VBLANK_HIGH_CRTC_MASK = 0x0000003e,
  _DRM_VBLANK_EVENT = 0x4000000,
  _DRM_VBLANK_FLIP = 0x8000000,
  _DRM_VBLANK_NEXTONMISS = 0x10000000,
  _DRM_VBLANK_SECONDARY = 0x20000000,
  _DRM_VBLANK_SIGNAL = 0x40000000
};
#define _DRM_VBLANK_HIGH_CRTC_SHIFT 1
#define _DRM_VBLANK_TYPES_MASK (_DRM_VBLANK_ABSOLUTE | _DRM_VBLANK_RELATIVE)
#define _DRM_VBLANK_FLAGS_MASK (_DRM_VBLANK_EVENT | _DRM_VBLANK_SIGNAL | _DRM_VBLANK_SECONDARY | _DRM_VBLANK_NEXTONMISS)
struct drm_wait_vblank_request {
  enum drm_vblank_seq_type type;
  unsigned int sequence;
  unsigned long signal;
};
struct drm_wait_vblank_reply {
  enum drm_vblank_seq_type type;
  unsigned int sequence;
  long tval_sec;
  long tval_usec;
};
union drm_wait_vblank {
  struct drm_wait_vblank_request request;
  struct drm_wait_vblank_reply reply;
};
#define _DRM_PRE_MODESET 1
#define _DRM_POST_MODESET 2
struct drm_modeset_ctl {
  __u32 crtc;
  __u32 cmd;
};
struct drm_agp_mode {
  unsigned long mode;
};
struct drm_agp_buffer {
  unsigned long size;
  unsigned long handle;
  unsigned long type;
  unsigned long physical;
};
struct drm_agp_binding {
  unsigned long handle;
  unsigned long offset;
};
struct drm_agp_info {
  int agp_version_major;
  int agp_version_minor;
  unsigned long mode;
  unsigned long aperture_base;
  unsigned long aperture_size;
  unsigned long memory_allowed;
  unsigned long memory_used;
  unsigned short id_vendor;
  unsigned short id_device;
};
struct drm_scatter_gather {
  unsigned long size;
  unsigned long handle;
};
struct drm_set_version {
  int drm_di_major;
  int drm_di_minor;
  int drm_dd_major;
  int drm_dd_minor;
};
struct drm_gem_close {
  __u32 handle;
  __u32 pad;
};
struct drm_gem_flink {
  __u32 handle;
  __u32 name;
};
struct drm_gem_open {
  __u32 name;
  __u32 handle;
  __u64 size;
};
#define DRM_CAP_DUMB_BUFFER 0x1
#define DRM_CAP_VBLANK_HIGH_CRTC 0x2
#define DRM_CAP_DUMB_PREFERRED_DEPTH 0x3
#define DRM_CAP_DUMB_PREFER_SHADOW 0x4
#define DRM_CAP_PRIME 0x5
#define DRM_PRIME_CAP_IMPORT 0x1
#define DRM_PRIME_CAP_EXPORT 0x2
#define DRM_CAP_TIMESTAMP_MONOTONIC 0x6
#define DRM_CAP_ASYNC_PAGE_FLIP 0x7
#define DRM_CAP_CURSOR_WIDTH 0x8
#define DRM_CAP_CURSOR_HEIGHT 0x9
#define DRM_CAP_ADDFB2_MODIFIERS 0x10
#define DRM_CAP_PAGE_FLIP_TARGET 0x11
#define DRM_CAP_CRTC_IN_VBLANK_EVENT 0x12
#define DRM_CAP_SYNCOBJ 0x13
#define DRM_CAP_SYNCOBJ_TIMELINE 0x14
#define DRM_CAP_ATOMIC_ASYNC_PAGE_FLIP 0x15
struct drm_get_cap {
  __u64 capability;
  __u64 value;
};
#define DRM_CLIENT_CAP_STEREO_3D 1
#define DRM_CLIENT_CAP_UNIVERSAL_PLANES 2
#define DRM_CLIENT_CAP_ATOMIC 3
#define DRM_CLIENT_CAP_ASPECT_RATIO 4
#define DRM_CLIENT_CAP_WRITEBACK_CONNECTORS 5
#define DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT 6
struct drm_set_client_cap {
  __u64 capability;
  __u64 value;
};
#define DRM_RDWR O_RDWR
#define DRM_CLOEXEC O_CLOEXEC
struct drm_prime_handle {
  __u32 handle;
  __u32 flags;
  __s32 fd;
};
struct drm_syncobj_create {
  __u32 handle;
#define DRM_SYNCOBJ_CREATE_SIGNALED (1 << 0)
  __u32 flags;
};
struct drm_syncobj_destroy {
  __u32 handle;
  __u32 pad;
};
#define DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE (1 << 0)
#define DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE (1 << 0)
struct drm_syncobj_handle {
  __u32 handle;
  __u32 flags;
  __s32 fd;
  __u32 pad;
};
struct drm_syncobj_transfer {
  __u32 src_handle;
  __u32 dst_handle;
  __u64 src_point;
  __u64 dst_point;
  __u32 flags;
  __u32 pad;
};
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL (1 << 0)
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT (1 << 1)
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE (1 << 2)
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE (1 << 3)
struct drm_syncobj_wait {
  __u64 handles;
  __s64 timeout_nsec;
  __u32 count_handles;
  __u32 flags;
  __u32 first_signaled;
  __u32 pad;
  __u64 deadline_nsec;
};
struct drm_syncobj_timeline_wait {
  __u64 handles;
  __u64 points;
  __s64 timeout_nsec;
  __u32 count_handles;
  __u32 flags;
  __u32 first_signaled;
  __u32 pad;
  __u64 deadline_nsec;
};
struct drm_syncobj_eventfd {
  __u32 handle;
  __u32 flags;
  __u64 point;
  __s32 fd;
  __u32 pad;
};
struct drm_syncobj_array {
  __u64 handles;
  __u32 count_handles;
  __u32 pad;
};
#define DRM_SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED (1 << 0)
struct drm_syncobj_timeline_array {
  __u64 handles;
  __u64 points;
  __u32 count_handles;
  __u32 flags;
};
struct drm_crtc_get_sequence {
  __u32 crtc_id;
  __u32 active;
  __u64 sequence;
  __s64 sequence_ns;
};
#define DRM_CRTC_SEQUENCE_RELATIVE 0x00000001
#define DRM_CRTC_SEQUENCE_NEXT_ON_MISS 0x00000002
struct drm_crtc_queue_sequence {
  __u32 crtc_id;
  __u32 flags;
  __u64 sequence;
  __u64 user_data;
};
#ifdef __cplusplus
}
#endif
#include "drm_mode.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_IOCTL_BASE 'd'
#define DRM_IO(nr) _IO(DRM_IOCTL_BASE, nr)
#define DRM_IOR(nr,type) _IOR(DRM_IOCTL_BASE, nr, type)
#define DRM_IOW(nr,type) _IOW(DRM_IOCTL_BASE, nr, type)
#define DRM_IOWR(nr,type) _IOWR(DRM_IOCTL_BASE, nr, type)
#define DRM_IOCTL_VERSION DRM_IOWR(0x00, struct drm_version)
#define DRM_IOCTL_GET_UNIQUE DRM_IOWR(0x01, struct drm_unique)
#define DRM_IOCTL_GET_MAGIC DRM_IOR(0x02, struct drm_auth)
#define DRM_IOCTL_IRQ_BUSID DRM_IOWR(0x03, struct drm_irq_busid)
#define DRM_IOCTL_GET_MAP DRM_IOWR(0x04, struct drm_map)
#define DRM_IOCTL_GET_CLIENT DRM_IOWR(0x05, struct drm_client)
#define DRM_IOCTL_GET_STATS DRM_IOR(0x06, struct drm_stats)
#define DRM_IOCTL_SET_VERSION DRM_IOWR(0x07, struct drm_set_version)
#define DRM_IOCTL_MODESET_CTL DRM_IOW(0x08, struct drm_modeset_ctl)
#define DRM_IOCTL_GEM_CLOSE DRM_IOW(0x09, struct drm_gem_close)
#define DRM_IOCTL_GEM_FLINK DRM_IOWR(0x0a, struct drm_gem_flink)
#define DRM_IOCTL_GEM_OPEN DRM_IOWR(0x0b, struct drm_gem_open)
#define DRM_IOCTL_GET_CAP DRM_IOWR(0x0c, struct drm_get_cap)
#define DRM_IOCTL_SET_CLIENT_CAP DRM_IOW(0x0d, struct drm_set_client_cap)
#define DRM_IOCTL_SET_UNIQUE DRM_IOW(0x10, struct drm_unique)
#define DRM_IOCTL_AUTH_MAGIC DRM_IOW(0x11, struct drm_auth)
#define DRM_IOCTL_BLOCK DRM_IOWR(0x12, struct drm_block)
#define DRM_IOCTL_UNBLOCK DRM_IOWR(0x13, struct drm_block)
#define DRM_IOCTL_CONTROL DRM_IOW(0x14, struct drm_control)
#define DRM_IOCTL_ADD_MAP DRM_IOWR(0x15, struct drm_map)
#define DRM_IOCTL_ADD_BUFS DRM_IOWR(0x16, struct drm_buf_desc)
#define DRM_IOCTL_MARK_BUFS DRM_IOW(0x17, struct drm_buf_desc)
#define DRM_IOCTL_INFO_BUFS DRM_IOWR(0x18, struct drm_buf_info)
#define DRM_IOCTL_MAP_BUFS DRM_IOWR(0x19, struct drm_buf_map)
#define DRM_IOCTL_FREE_BUFS DRM_IOW(0x1a, struct drm_buf_free)
#define DRM_IOCTL_RM_MAP DRM_IOW(0x1b, struct drm_map)
#define DRM_IOCTL_SET_SAREA_CTX DRM_IOW(0x1c, struct drm_ctx_priv_map)
#define DRM_IOCTL_GET_SAREA_CTX DRM_IOWR(0x1d, struct drm_ctx_priv_map)
#define DRM_IOCTL_SET_MASTER DRM_IO(0x1e)
#define DRM_IOCTL_DROP_MASTER DRM_IO(0x1f)
#define DRM_IOCTL_ADD_CTX DRM_IOWR(0x20, struct drm_ctx)
#define DRM_IOCTL_RM_CTX DRM_IOWR(0x21, struct drm_ctx)
#define DRM_IOCTL_MOD_CTX DRM_IOW(0x22, struct drm_ctx)
#define DRM_IOCTL_GET_CTX DRM_IOWR(0x23, struct drm_ctx)
#define DRM_IOCTL_SWITCH_CTX DRM_IOW(0x24, struct drm_ctx)
#define DRM_IOCTL_NEW_CTX DRM_IOW(0x25, struct drm_ctx)
#define DRM_IOCTL_RES_CTX DRM_IOWR(0x26, struct drm_ctx_res)
#define DRM_IOCTL_ADD_DRAW DRM_IOWR(0x27, struct drm_draw)
#define DRM_IOCTL_RM_DRAW DRM_IOWR(0x28, struct drm_draw)
#define DRM_IOCTL_DMA DRM_IOWR(0x29, struct drm_dma)
#define DRM_IOCTL_LOCK DRM_IOW(0x2a, struct drm_lock)
#define DRM_IOCTL_UNLOCK DRM_IOW(0x2b, struct drm_lock)
#define DRM_IOCTL_FINISH DRM_IOW(0x2c, struct drm_lock)
#define DRM_IOCTL_PRIME_HANDLE_TO_FD DRM_IOWR(0x2d, struct drm_prime_handle)
#define DRM_IOCTL_PRIME_FD_TO_HANDLE DRM_IOWR(0x2e, struct drm_prime_handle)
#define DRM_IOCTL_AGP_ACQUIRE DRM_IO(0x30)
#define DRM_IOCTL_AGP_RELEASE DRM_IO(0x31)
#define DRM_IOCTL_AGP_ENABLE DRM_IOW(0x32, struct drm_agp_mode)
#define DRM_IOCTL_AGP_INFO DRM_IOR(0x33, struct drm_agp_info)
#define DRM_IOCTL_AGP_ALLOC DRM_IOWR(0x34, struct drm_agp_buffer)
#define DRM_IOCTL_AGP_FREE DRM_IOW(0x35, struct drm_agp_buffer)
#define DRM_IOCTL_AGP_BIND DRM_IOW(0x36, struct drm_agp_binding)
#define DRM_IOCTL_AGP_UNBIND DRM_IOW(0x37, struct drm_agp_binding)
#define DRM_IOCTL_SG_ALLOC DRM_IOWR(0x38, struct drm_scatter_gather)
#define DRM_IOCTL_SG_FREE DRM_IOW(0x39, struct drm_scatter_gather)
#define DRM_IOCTL_WAIT_VBLANK DRM_IOWR(0x3a, union drm_wait_vblank)
#define DRM_IOCTL_CRTC_GET_SEQUENCE DRM_IOWR(0x3b, struct drm_crtc_get_sequence)
#define DRM_IOCTL_CRTC_QUEUE_SEQUENCE DRM_IOWR(0x3c, struct drm_crtc_queue_sequence)
#define DRM_IOCTL_UPDATE_DRAW DRM_IOW(0x3f, struct drm_update_draw)
#define DRM_IOCTL_MODE_GETRESOURCES DRM_IOWR(0xA0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_GETCRTC DRM_IOWR(0xA1, struct drm_mode_crtc)
#define DRM_IOCTL_MODE_SETCRTC DRM_IOWR(0xA2, struct drm_mode_crtc)
#define DRM_IOCTL_MODE_CURSOR DRM_IOWR(0xA3, struct drm_mode_cursor)
#define DRM_IOCTL_MODE_GETGAMMA DRM_IOWR(0xA4, struct drm_mode_crtc_lut)
#define DRM_IOCTL_MODE_SETGAMMA DRM_IOWR(0xA5, struct drm_mode_crtc_lut)
#define DRM_IOCTL_MODE_GETENCODER DRM_IOWR(0xA6, struct drm_mode_get_encoder)
#define DRM_IOCTL_MODE_GETCONNECTOR DRM_IOWR(0xA7, struct drm_mode_get_connector)
#define DRM_IOCTL_MODE_ATTACHMODE DRM_IOWR(0xA8, struct drm_mode_mode_cmd)
#define DRM_IOCTL_MODE_DETACHMODE DRM_IOWR(0xA9, struct drm_mode_mode_cmd)
#define DRM_IOCTL_MODE_GETPROPERTY DRM_IOWR(0xAA, struct drm_mode_get_property)
#define DRM_IOCTL_MODE_SETPROPERTY DRM_IOWR(0xAB, struct drm_mode_connector_set_property)
#define DRM_IOCTL_MODE_GETPROPBLOB DRM_IOWR(0xAC, struct drm_mode_get_blob)
#define DRM_IOCTL_MODE_GETFB DRM_IOWR(0xAD, struct drm_mode_fb_cmd)
#define DRM_IOCTL_MODE_ADDFB DRM_IOWR(0xAE, struct drm_mode_fb_cmd)
#define DRM_IOCTL_MODE_RMFB DRM_IOWR(0xAF, unsigned int)
#define DRM_IOCTL_MODE_PAGE_FLIP DRM_IOWR(0xB0, struct drm_mode_crtc_page_flip)
#define DRM_IOCTL_MODE_DIRTYFB DRM_IOWR(0xB1, struct drm_mode_fb_dirty_cmd)
#define DRM_IOCTL_MODE_CREATE_DUMB DRM_IOWR(0xB2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB DRM_IOWR(0xB3, struct drm_mode_map_dumb)
#define DRM_IOCTL_MODE_DESTROY_DUMB DRM_IOWR(0xB4, struct drm_mode_destroy_dumb)
#define DRM_IOCTL_MODE_GETPLANERESOURCES DRM_IOWR(0xB5, struct drm_mode_get_plane_res)
#define DRM_IOCTL_MODE_GETPLANE DRM_IOWR(0xB6, struct drm_mode_get_plane)
#define DRM_IOCTL_MODE_SETPLANE DRM_IOWR(0xB7, struct drm_mode_set_plane)
#define DRM_IOCTL_MODE_ADDFB2 DRM_IOWR(0xB8, struct drm_mode_fb_cmd2)
#define DRM_IOCTL_MODE_OBJ_GETPROPERTIES DRM_IOWR(0xB9, struct drm_mode_obj_get_properties)
#define DRM_IOCTL_MODE_OBJ_SETPROPERTY DRM_IOWR(0xBA, struct drm_mode_obj_set_property)
#define DRM_IOCTL_MODE_CURSOR2 DRM_IOWR(0xBB, struct drm_mode_cursor2)
#define DRM_IOCTL_MODE_ATOMIC DRM_IOWR(0xBC, struct drm_mode_atomic)
#define DRM_IOCTL_MODE_CREATEPROPBLOB DRM_IOWR(0xBD, struct drm_mode_create_blob)
#define DRM_IOCTL_MODE_DESTROYPROPBLOB DRM_IOWR(0xBE, struct drm_mode_destroy_blob)
#define DRM_IOCTL_SYNCOBJ_CREATE DRM_IOWR(0xBF, struct drm_syncobj_create)
#define DRM_IOCTL_SYNCOBJ_DESTROY DRM_IOWR(0xC0, struct drm_syncobj_destroy)
#define DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD DRM_IOWR(0xC1, struct drm_syncobj_handle)
#define DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE DRM_IOWR(0xC2, struct drm_syncobj_handle)
#define DRM_IOCTL_SYNCOBJ_WAIT DRM_IOWR(0xC3, struct drm_syncobj_wait)
#define DRM_IOCTL_SYNCOBJ_RESET DRM_IOWR(0xC4, struct drm_syncobj_array)
#define DRM_IOCTL_SYNCOBJ_SIGNAL DRM_IOWR(0xC5, struct drm_syncobj_array)
#define DRM_IOCTL_MODE_CREATE_LEASE DRM_IOWR(0xC6, struct drm_mode_create_lease)
#define DRM_IOCTL_MODE_LIST_LESSEES DRM_IOWR(0xC7, struct drm_mode_list_lessees)
#define DRM_IOCTL_MODE_GET_LEASE DRM_IOWR(0xC8, struct drm_mode_get_lease)
#define DRM_IOCTL_MODE_REVOKE_LEASE DRM_IOWR(0xC9, struct drm_mode_revoke_lease)
#define DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT DRM_IOWR(0xCA, struct drm_syncobj_timeline_wait)
#define DRM_IOCTL_SYNCOBJ_QUERY DRM_IOWR(0xCB, struct drm_syncobj_timeline_array)
#define DRM_IOCTL_SYNCOBJ_TRANSFER DRM_IOWR(0xCC, struct drm_syncobj_transfer)
#define DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL DRM_IOWR(0xCD, struct drm_syncobj_timeline_array)
#define DRM_IOCTL_MODE_GETFB2 DRM_IOWR(0xCE, struct drm_mode_fb_cmd2)
#define DRM_IOCTL_SYNCOBJ_EVENTFD DRM_IOWR(0xCF, struct drm_syncobj_eventfd)
#define DRM_IOCTL_MODE_CLOSEFB DRM_IOWR(0xD0, struct drm_mode_closefb)
#define DRM_COMMAND_BASE 0x40
#define DRM_COMMAND_END 0xA0
struct drm_event {
  __u32 type;
  __u32 length;
};
#define DRM_EVENT_VBLANK 0x01
#define DRM_EVENT_FLIP_COMPLETE 0x02
#define DRM_EVENT_CRTC_SEQUENCE 0x03
struct drm_event_vblank {
  struct drm_event base;
  __u64 user_data;
  __u32 tv_sec;
  __u32 tv_usec;
  __u32 sequence;
  __u32 crtc_id;
};
struct drm_event_crtc_sequence {
  struct drm_event base;
  __u64 user_data;
  __s64 time_ns;
  __u64 sequence;
};
typedef struct drm_clip_rect drm_clip_rect_t;
typedef struct drm_drawable_info drm_drawable_info_t;
typedef struct drm_tex_region drm_tex_region_t;
typedef struct drm_hw_lock drm_hw_lock_t;
typedef struct drm_version drm_version_t;
typedef struct drm_unique drm_unique_t;
typedef struct drm_list drm_list_t;
typedef struct drm_block drm_block_t;
typedef struct drm_control drm_control_t;
typedef enum drm_map_type drm_map_type_t;
typedef enum drm_map_flags drm_map_flags_t;
typedef struct drm_ctx_priv_map drm_ctx_priv_map_t;
typedef struct drm_map drm_map_t;
typedef struct drm_client drm_client_t;
typedef enum drm_stat_type drm_stat_type_t;
typedef struct drm_stats drm_stats_t;
typedef enum drm_lock_flags drm_lock_flags_t;
typedef struct drm_lock drm_lock_t;
typedef enum drm_dma_flags drm_dma_flags_t;
typedef struct drm_buf_desc drm_buf_desc_t;
typedef struct drm_buf_info drm_buf_info_t;
typedef struct drm_buf_free drm_buf_free_t;
typedef struct drm_buf_pub drm_buf_pub_t;
typedef struct drm_buf_map drm_buf_map_t;
typedef struct drm_dma drm_dma_t;
typedef union drm_wait_vblank drm_wait_vblank_t;
typedef struct drm_agp_mode drm_agp_mode_t;
typedef enum drm_ctx_flags drm_ctx_flags_t;
typedef struct drm_ctx drm_ctx_t;
typedef struct drm_ctx_res drm_ctx_res_t;
typedef struct drm_draw drm_draw_t;
typedef struct drm_update_draw drm_update_draw_t;
typedef struct drm_auth drm_auth_t;
typedef struct drm_irq_busid drm_irq_busid_t;
typedef enum drm_vblank_seq_type drm_vblank_seq_type_t;
typedef struct drm_agp_buffer drm_agp_buffer_t;
typedef struct drm_agp_binding drm_agp_binding_t;
typedef struct drm_agp_info drm_agp_info_t;
typedef struct drm_scatter_gather drm_scatter_gather_t;
typedef struct drm_set_version drm_set_version_t;
#ifdef __cplusplus
}
#endif
#endif

"""

```