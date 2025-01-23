Response:
Let's break down the thought process for answering this complex request about the `etnaviv_drm.h` header file.

**1. Understanding the Core Request:**

The primary goal is to understand the purpose and functionality of the provided header file within the context of Android's Bionic library. This involves identifying the core components, their interactions with Android, and how developers might use them.

**2. Initial Analysis of the Header File:**

* **DRM Context:** The file name `etnaviv_drm.h` immediately signals a connection to the Direct Rendering Manager (DRM) subsystem in the Linux kernel. The inclusion of `drm.h` confirms this. This tells us we're dealing with low-level graphics hardware access.
* **Etnaviv Specific:** The `etnaviv` prefix indicates that this header is specific to a particular GPU family, likely from Vivante (though the provided text doesn't explicitly state this).
* **UAPI:** The path `bionic/libc/kernel/uapi/drm/` confirms this is a userspace API header for the DRM subsystem. "uapi" signifies the user-kernel interface.
* **Auto-Generated:** The comment at the top is crucial: "This file is auto-generated. Modifications will be lost." This means we should focus on the *structures* and *macros* defined, as those are the intended API. We shouldn't try to reverse-engineer implementation details from this header alone.
* **Key Elements:**  Scanning the header reveals various structures and macros. The structures often represent data exchanged with the kernel via ioctls. The macros define constants for parameters, flags, and ioctl commands.

**3. Categorizing Functionality:**

Based on the identified elements, I started grouping the functionalities:

* **GPU Information Retrieval:**  The `ETNAVIV_PARAM_*` macros and `drm_etnaviv_param` structure clearly relate to querying GPU properties like model, revision, features, etc.
* **Memory Management (GEM):**  Structures like `drm_etnaviv_gem_new`, `drm_etnaviv_gem_info`, `drm_etnaviv_gem_cpu_prep`, `drm_etnaviv_gem_cpu_fini`, `drm_etnaviv_gem_userptr`, and `drm_etnaviv_gem_wait` point to functionalities for managing GPU memory buffers (Graphics Execution Manager - GEM). This involves creating, accessing (CPU prep/fini), and waiting on these buffers.
* **Command Submission:** The `drm_etnaviv_gem_submit`, `drm_etnaviv_gem_submit_bo`, and `drm_etnaviv_gem_submit_reloc` structures are related to submitting commands to the GPU for execution, including managing buffer objects and relocations.
* **Synchronization:** `drm_etnaviv_wait_fence` and related macros deal with synchronizing operations between the CPU and GPU.
* **Power Management (PM):**  The `drm_etnaviv_pm_domain` and `drm_etnaviv_pm_signal` structures suggest functionalities for querying power management domains and signals.
* **IOCTL Definitions:** The `DRM_IOCTL_ETNAVIV_*` macros define the specific ioctl commands used to interact with the kernel driver.

**4. Connecting to Android:**

The key connection to Android is through the graphics stack. I considered the layers involved:

* **Application (Java/Kotlin):**  High-level graphics APIs like OpenGL ES, Vulkan.
* **Android Framework (SurfaceFlinger, etc.):** Manages display composition, buffer allocation, and interacts with the HAL.
* **Hardware Abstraction Layer (HAL):**  The `android.hardware.graphics.composer` HAL is the primary interface for interacting with the DRM/KMS driver.
* **Kernel Driver (Etnaviv DRM):** The actual driver for the Etnaviv GPU.

The header file acts as the userspace interface to the kernel driver, meaning the HAL (or libraries used by the HAL) would use these structures and ioctls.

**5. Explaining libc Functions (and the lack thereof):**

A crucial observation is that this header file *doesn't define any libc functions*. It defines *structures* and *macros*. The interaction happens via the `ioctl()` system call, which is a libc function. Therefore, the explanation focused on how `ioctl()` is used in conjunction with these definitions.

**6. Dynamic Linker (and its limited relevance):**

This header file is a *static* header. It's included at compile time. The dynamic linker's role is primarily in linking shared libraries (.so files) at runtime. While the *driver* itself might be a dynamically loaded kernel module, the header file doesn't directly involve the dynamic linker. The explanation clarified this distinction and provided a hypothetical scenario of a userspace library using these definitions.

**7. Assumptions, Input/Output, and Common Errors:**

I considered common pitfalls when working with low-level APIs like DRM:

* **Incorrect ioctl arguments:** Providing wrong sizes or data in the structures.
* **Race conditions:** Failing to properly synchronize CPU and GPU operations.
* **Memory management errors:** Incorrectly managing GEM buffer lifetimes.
* **Permission issues:** Not having the necessary permissions to access the DRM device.

**8. Frida Hooking:**

The Frida example focused on hooking the `ioctl()` call and filtering for the Etnaviv-specific ioctl numbers. This allows inspection of the data being passed to the kernel.

**9. Structuring the Answer:**

I organized the answer logically, starting with the overall function, then delving into specific areas, and finally covering the more complex topics like dynamic linking and Frida. Using clear headings and bullet points helps readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file defines some inline functions. **Correction:** Realized it's an auto-generated kernel UAPI header, so it primarily defines structures and macros for system calls.
* **Initial thought:** Focus heavily on specific libc function implementations. **Correction:** Recognized that the interaction is primarily via `ioctl()`, so focus shifted to explaining how `ioctl()` uses these structures.
* **Initial thought:** Go deep into the Etnaviv GPU architecture. **Correction:**  The request is about the *header file*, not the GPU itself. Keep the focus on the API provided by the header.
* **Initial thought:**  Provide a complex dynamic linking scenario. **Correction:**  Keep the dynamic linking example simple and illustrative, as the header file's direct involvement is limited.

By following this thought process, including analysis, categorization, connecting to the Android ecosystem, and anticipating common issues, I could construct a comprehensive and accurate answer to the user's request.
这个目录 `bionic/libc/kernel/uapi/drm/etnaviv_drm.handroid` 下的源代码文件 `etnaviv_drm.h` 是 Android Bionic 库的一部分，它定义了 **用户空间程序与 Etnaviv GPU 内核驱动程序交互的接口**。

**它的功能：**

这个头文件定义了一系列结构体、宏和常量，用于：

1. **查询 Etnaviv GPU 的参数信息:**
   - 定义了 `ETNAVIV_PARAM_*` 系列宏，用于指定要查询的 GPU 参数，例如 GPU 型号、修订版本、各种特性（Features）等。
   - 定义了 `drm_etnaviv_param` 结构体，用于向内核传递要查询的参数以及接收返回值。
   - **例子:** 用户空间程序可以通过这些定义查询 GPU 支持的纹理单元数量，从而根据硬件能力进行渲染优化。

2. **管理 GPU 内存 (GEM - Graphics Execution Manager):**
   - 定义了 `drm_etnaviv_gem_new` 结构体，用于请求分配新的 GPU 内存对象 (Buffer Object, BO)。可以指定内存大小和缓存策略。
   - 定义了 `drm_etnaviv_gem_info` 结构体，用于获取已分配的 GPU 内存对象的信息，例如内核地址偏移。
   - 定义了 `drm_etnaviv_gem_cpu_prep` 和 `drm_etnaviv_gem_cpu_fini` 结构体，用于准备和完成 CPU 对 GPU 内存的访问，包括同步操作。
   - 定义了 `drm_etnaviv_gem_userptr` 结构体，允许将用户空间的内存映射到 GPU 地址空间。
   - 定义了 `drm_etnaviv_gem_wait` 结构体，用于等待 GPU 内存操作完成。
   - **例子:**  Android 图形框架 (SurfaceFlinger) 可以使用这些结构体分配 GPU 内存来存储屏幕缓冲区。

3. **提交 GPU 命令流:**
   - 定义了 `drm_etnaviv_gem_submit_reloc` 结构体，用于描述提交的命令流中需要进行地址重定位的信息。
   - 定义了 `drm_etnaviv_gem_submit_bo` 结构体，用于指定提交的命令流中使用的 GPU 内存对象及其访问权限。
   - 定义了 `drm_etnaviv_gem_submit_pmr` 结构体，用于指定电源管理相关的操作。
   - 定义了 `drm_etnaviv_gem_submit` 结构体，用于向内核提交 GPU 命令流进行执行，包括指定 Fence (用于同步)、使用的 GPU 管道、内存对象、重定位信息等。
   - **例子:**  OpenGL ES 驱动程序可以使用这些结构体将渲染命令和顶点数据提交给 GPU 执行。

4. **GPU 同步机制 (Fence):**
   - 定义了 `drm_etnaviv_wait_fence` 结构体，用于等待 GPU 完成特定的操作，通过 Fence 机制进行同步。
   - **例子:**  在渲染一帧图像后，应用程序可以等待 Fence 信号，确保 GPU 完成渲染后再进行下一帧的操作。

5. **电源管理:**
   - 定义了 `drm_etnaviv_pm_domain` 和 `drm_etnaviv_pm_signal` 结构体，用于查询电源管理域和信号的信息。
   - **例子:** 系统可以查询不同 GPU 组件的电源状态，以便进行更精细的电源控制。

6. **定义 IOCTL 命令:**
   - 定义了 `DRM_ETNAVIV_*` 系列宏，对应不同的 ioctl 命令，例如 `DRM_ETNAVIV_GET_PARAM` 用于获取参数，`DRM_ETNAVIV_GEM_NEW` 用于分配 GPU 内存等。
   - 这些宏定义了与内核驱动交互的具体指令。

**与 Android 功能的关系和举例说明:**

这个头文件是 Android 图形栈的关键组成部分，它使得 Android 系统能够利用 Etnaviv GPU 的硬件加速能力。

* **图形渲染 (OpenGL ES, Vulkan):**  Android 上的 OpenGL ES 或 Vulkan 驱动程序会使用这个头文件中定义的结构体和 ioctl 命令与 Etnaviv GPU 内核驱动进行交互。例如，分配 GPU 内存用于纹理存储，提交渲染命令到 GPU 执行。
* **显示合成 (SurfaceFlinger):** SurfaceFlinger 负责将不同的图形缓冲区合成到屏幕上。它会使用这个头文件中的定义来管理显示缓冲区（分配、同步等）。
* **Camera 子系统:**  Camera 预览和图像处理也可能涉及到 GPU 的使用，例如使用 GPU 进行图像滤镜或格式转换，这时也会用到这个头文件中的功能。
* **计算任务 (Compute Shaders):**  Android 上的应用程序可以使用 GPU 进行通用计算，这也会用到这个头文件来管理内存和提交计算任务。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了数据结构和宏。与内核交互是通过 **ioctl 系统调用** 来实现的。

`ioctl` 是一个 libc 函数，其原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`: 文件描述符，通常是打开的 DRM 设备文件（例如 `/dev/dri/card0`）。
* `request`:  一个与驱动程序相关的请求码，这里就是 `DRM_IOCTL_ETNAVIV_*` 系列宏。
* `...`: 可变参数，通常是指向数据结构的指针，用于向内核传递数据或接收内核返回的数据。

**实现原理:** 当用户空间程序调用 `ioctl` 时，内核会根据文件描述符找到对应的设备驱动程序（这里是 Etnaviv DRM 驱动）。然后，内核会根据 `request` 参数找到对应的处理函数，并将可变参数指向的数据传递给该函数。驱动程序会执行相应的操作（例如，分配 GPU 内存，提交命令等），并将结果写回到用户空间提供的缓冲区中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。它是一个静态头文件，在编译时被包含到程序中。

但是，使用这个头文件的 **用户空间库** (例如 OpenGL ES 驱动程序) 可能会被动态链接。

**so 布局样本:**

假设有一个名为 `libetna_gl.so` 的共享库，它使用了 `etnaviv_drm.h` 中定义的接口：

```
libetna_gl.so:
    .text         # 代码段
        ... (调用 ioctl 等) ...
    .rodata       # 只读数据段
        ...
    .data         # 可读写数据段
        ...
    .dynsym       # 动态符号表
        ioctl      # 依赖的外部符号
        ...
    .dynstr       # 动态字符串表
        ioctl
        ...
    .plt          # 程序链接表 (PLT)
        ioctl@...
        ...
    .got.plt      # 全局偏移表 (GOT)
        ... (ioctl 的地址) ...
```

**链接的处理过程:**

1. **编译时链接:**  当编译 `libetna_gl.so` 的源代码时，编译器会识别到对 `ioctl` 函数的调用。由于 `ioctl` 是 libc 的一部分，编译器会在 `libetna_gl.so` 的动态符号表中添加一个对 `ioctl` 的未定义引用。

2. **加载时链接:** 当 Android 系统加载使用 `libetna_gl.so` 的应用程序时，dynamic linker (例如 `linker64`) 会执行以下步骤：
   - 加载 `libetna_gl.so` 到内存中。
   - 扫描 `libetna_gl.so` 的动态符号表，找到未定义的符号（例如 `ioctl`）。
   - 查找这些未定义符号的定义。对于 `ioctl`，它会在已加载的共享库中查找，通常是 `libc.so`。
   - 将 `libetna_gl.so` 中对 `ioctl` 的调用重定向到 `libc.so` 中 `ioctl` 的实际地址。这通常通过修改 `.got.plt` 表中的条目来实现。

**假设输入与输出 (针对 ioctl 调用):**

假设用户空间程序想要查询 Etnaviv GPU 的型号：

**假设输入:**

* `fd`:  打开的 DRM 设备文件描述符 (例如，通过 `open("/dev/dri/card0", O_RDWR)`)
* `request`: `DRM_IOCTL_ETNAVIV_GET_PARAM`
* `argp` (指向 `drm_etnaviv_param` 结构体的指针):
  ```c
  struct drm_etnaviv_param param;
  param.pipe = 0; // 可以是 0
  param.param = ETNAVIV_PARAM_GPU_MODEL;
  param.value = 0; // 用于接收返回值
  ```

**预期输出:**

* `ioctl` 函数返回 0 (成功)。
* `param.value` 包含 GPU 型号的编码值 (例如，一个整数 ID)。

**用户或编程常见的使用错误:**

1. **忘记打开 DRM 设备文件:** 在调用任何 ioctl 命令之前，必须先使用 `open()` 函数打开 DRM 设备文件。
2. **传递错误的 ioctl 请求码:** 使用了不正确的 `DRM_IOCTL_ETNAVIV_*` 宏。
3. **传递不正确的参数结构体:**  例如，结构体大小不匹配，或者结构体中的字段值设置错误。
4. **权限问题:** 用户可能没有足够的权限访问 DRM 设备文件。
5. **未处理 ioctl 的返回值:** `ioctl` 函数可能会返回错误代码 (通常是 -1)，需要检查并处理这些错误。
6. **竞争条件:** 在多线程或多进程环境下，如果没有适当的同步机制，可能会出现对 GPU 资源的竞争访问。
7. **内存管理错误:**  对于 GEM 对象，如果分配后没有正确释放，会导致内存泄漏。

**Android framework or ndk 是如何一步步的到达这里:**

1. **应用层 (Java/Kotlin):**  应用程序通常不会直接调用这些底层的 DRM ioctl。而是使用更高层的图形 API，例如 OpenGL ES 或 Vulkan。

2. **NDK (C/C++):**  如果应用程序使用 NDK 进行图形开发，它会调用 OpenGL ES 或 Vulkan 的 C/C++ 接口。

3. **OpenGL ES/Vulkan 驱动程序 (位于 system/lib[64]/egl/ 或 vendor/lib[64]/egl/):**  这些驱动程序会将 OpenGL ES/Vulkan 的 API 调用转换为底层的 GPU 命令。它们会使用这个 `etnaviv_drm.h` 头文件中定义的结构体和 ioctl 命令与 Etnaviv GPU 内核驱动进行通信。例如，当应用程序调用 `glGenBuffers()` 分配缓冲区时，OpenGL ES 驱动程序可能会调用 `ioctl` 并传入 `DRM_IOCTL_ETNAVIV_GEM_NEW` 命令来在 GPU 上分配内存。

4. **HAL (Hardware Abstraction Layer) (位于 /dev/hw_module ):**  在一些情况下，更底层的图形操作可能会通过 HAL 进行抽象。例如，SurfaceFlinger 会使用 `android.hardware.graphics.composer` HAL 来与 DRM/KMS (Kernel Mode Setting) 驱动交互，而 Etnaviv DRM 驱动是 KMS 的一部分。

5. **内核驱动程序 (位于内核空间):**  Etnaviv GPU 的内核驱动程序接收来自用户空间的 ioctl 调用，并执行相应的 GPU 操作。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 Etnaviv DRM 相关的 ioctl 命令，以观察 Android framework 或 NDK 是如何与 GPU 驱动进行交互的。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

session = frida.attach('com.example.myapp') # 替换为你的应用包名

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是与 DRM 相关的设备文件 (你可以根据实际情况添加更精确的判断)
        const pathBuf = Memory.allocUtf8String("/proc/self/fd/" + fd);
        const readLinkBuf = Memory.alloc(256);
        const readLinkResult = recv(readLinkBuf, pathBuf, 255);
        if (readLinkResult.type === 'success') {
            const path = readLinkBuf.readUtf8String();
            if (path.includes("/dev/dri/")) {
                this.is_drm = true;
                this.request_code = request;
                console.log("[*] ioctl called with fd:", fd, "request:", request);

                // 这里可以根据 request code 判断具体的 ETNAVIV_IOCTL 并解析参数
                if (request === 0xc0106400) { // 替换为 DRM_IOCTL_ETNAVIV_GET_PARAM 的实际值
                    const paramPtr = ptr(args[2]);
                    const pipe = paramPtr.readU32();
                    const param = paramPtr.add(4).readU32();
                    console.log("    -> DRM_IOCTL_ETNAVIV_GET_PARAM, pipe:", pipe, "param:", param);
                } else if (request === 0xc0106402) { // 替换为 DRM_IOCTL_ETNAVIV_GEM_NEW 的实际值
                    const gemNewPtr = ptr(args[2]);
                    const size = gemNewPtr.readU64();
                    const flags = gemNewPtr.add(8).readU32();
                    console.log("    -> DRM_IOCTL_ETNAVIV_GEM_NEW, size:", size, "flags:", flags);
                }
            }
        }
    },
    onLeave: function(retval) {
        if (this.is_drm) {
            console.log("[*] ioctl returned:", retval.toInt32(), "request code:", this.request_code);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释:**

1. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook 了 `ioctl` 系统调用。
2. **`onEnter`:** 在 `ioctl` 调用之前执行。
3. **检查设备文件路径:**  通过读取 `/proc/self/fd/` 下的文件链接，判断是否是与 DRM 相关的设备文件。
4. **打印 ioctl 的 fd 和 request:**  输出调用的文件描述符和请求码。
5. **根据 request 代码解析参数:**  示例中展示了如何解析 `DRM_IOCTL_ETNAVIV_GET_PARAM` 和 `DRM_IOCTL_ETNAVIV_GEM_NEW` 的参数。你需要根据实际要调试的 ioctl 命令添加相应的解析逻辑。
6. **`onLeave`:** 在 `ioctl` 调用返回之后执行，打印返回值。

通过运行这个 Frida 脚本，并让目标 Android 应用程序执行一些图形操作，你就可以在 Frida 的输出中看到应用程序是如何通过 ioctl 与 Etnaviv GPU 驱动进行交互的，包括调用的 ioctl 命令和传递的参数。记得将 `com.example.myapp` 替换为你想要分析的应用程序的包名，并将示例中的 request 代码替换为实际的宏定义值（可以通过查看 `bionic/libc/kernel/uapi/drm/etnaviv_drm.handroid` 中的定义计算出来）。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/drm/etnaviv_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __ETNAVIV_DRM_H__
#define __ETNAVIV_DRM_H__
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
struct drm_etnaviv_timespec {
  __s64 tv_sec;
  __s64 tv_nsec;
};
#define ETNAVIV_PARAM_GPU_MODEL 0x01
#define ETNAVIV_PARAM_GPU_REVISION 0x02
#define ETNAVIV_PARAM_GPU_FEATURES_0 0x03
#define ETNAVIV_PARAM_GPU_FEATURES_1 0x04
#define ETNAVIV_PARAM_GPU_FEATURES_2 0x05
#define ETNAVIV_PARAM_GPU_FEATURES_3 0x06
#define ETNAVIV_PARAM_GPU_FEATURES_4 0x07
#define ETNAVIV_PARAM_GPU_FEATURES_5 0x08
#define ETNAVIV_PARAM_GPU_FEATURES_6 0x09
#define ETNAVIV_PARAM_GPU_FEATURES_7 0x0a
#define ETNAVIV_PARAM_GPU_FEATURES_8 0x0b
#define ETNAVIV_PARAM_GPU_FEATURES_9 0x0c
#define ETNAVIV_PARAM_GPU_FEATURES_10 0x0d
#define ETNAVIV_PARAM_GPU_FEATURES_11 0x0e
#define ETNAVIV_PARAM_GPU_FEATURES_12 0x0f
#define ETNAVIV_PARAM_GPU_STREAM_COUNT 0x10
#define ETNAVIV_PARAM_GPU_REGISTER_MAX 0x11
#define ETNAVIV_PARAM_GPU_THREAD_COUNT 0x12
#define ETNAVIV_PARAM_GPU_VERTEX_CACHE_SIZE 0x13
#define ETNAVIV_PARAM_GPU_SHADER_CORE_COUNT 0x14
#define ETNAVIV_PARAM_GPU_PIXEL_PIPES 0x15
#define ETNAVIV_PARAM_GPU_VERTEX_OUTPUT_BUFFER_SIZE 0x16
#define ETNAVIV_PARAM_GPU_BUFFER_SIZE 0x17
#define ETNAVIV_PARAM_GPU_INSTRUCTION_COUNT 0x18
#define ETNAVIV_PARAM_GPU_NUM_CONSTANTS 0x19
#define ETNAVIV_PARAM_GPU_NUM_VARYINGS 0x1a
#define ETNAVIV_PARAM_SOFTPIN_START_ADDR 0x1b
#define ETNAVIV_PARAM_GPU_PRODUCT_ID 0x1c
#define ETNAVIV_PARAM_GPU_CUSTOMER_ID 0x1d
#define ETNAVIV_PARAM_GPU_ECO_ID 0x1e
#define ETNA_MAX_PIPES 4
struct drm_etnaviv_param {
  __u32 pipe;
  __u32 param;
  __u64 value;
};
#define ETNA_BO_CACHE_MASK 0x000f0000
#define ETNA_BO_CACHED 0x00010000
#define ETNA_BO_WC 0x00020000
#define ETNA_BO_UNCACHED 0x00040000
#define ETNA_BO_FORCE_MMU 0x00100000
struct drm_etnaviv_gem_new {
  __u64 size;
  __u32 flags;
  __u32 handle;
};
struct drm_etnaviv_gem_info {
  __u32 handle;
  __u32 pad;
  __u64 offset;
};
#define ETNA_PREP_READ 0x01
#define ETNA_PREP_WRITE 0x02
#define ETNA_PREP_NOSYNC 0x04
struct drm_etnaviv_gem_cpu_prep {
  __u32 handle;
  __u32 op;
  struct drm_etnaviv_timespec timeout;
};
struct drm_etnaviv_gem_cpu_fini {
  __u32 handle;
  __u32 flags;
};
struct drm_etnaviv_gem_submit_reloc {
  __u32 submit_offset;
  __u32 reloc_idx;
  __u64 reloc_offset;
  __u32 flags;
};
#define ETNA_SUBMIT_BO_READ 0x0001
#define ETNA_SUBMIT_BO_WRITE 0x0002
struct drm_etnaviv_gem_submit_bo {
  __u32 flags;
  __u32 handle;
  __u64 presumed;
};
#define ETNA_PM_PROCESS_PRE 0x0001
#define ETNA_PM_PROCESS_POST 0x0002
struct drm_etnaviv_gem_submit_pmr {
  __u32 flags;
  __u8 domain;
  __u8 pad;
  __u16 signal;
  __u32 sequence;
  __u32 read_offset;
  __u32 read_idx;
};
#define ETNA_SUBMIT_NO_IMPLICIT 0x0001
#define ETNA_SUBMIT_FENCE_FD_IN 0x0002
#define ETNA_SUBMIT_FENCE_FD_OUT 0x0004
#define ETNA_SUBMIT_SOFTPIN 0x0008
#define ETNA_SUBMIT_FLAGS (ETNA_SUBMIT_NO_IMPLICIT | ETNA_SUBMIT_FENCE_FD_IN | ETNA_SUBMIT_FENCE_FD_OUT | ETNA_SUBMIT_SOFTPIN)
#define ETNA_PIPE_3D 0x00
#define ETNA_PIPE_2D 0x01
#define ETNA_PIPE_VG 0x02
struct drm_etnaviv_gem_submit {
  __u32 fence;
  __u32 pipe;
  __u32 exec_state;
  __u32 nr_bos;
  __u32 nr_relocs;
  __u32 stream_size;
  __u64 bos;
  __u64 relocs;
  __u64 stream;
  __u32 flags;
  __s32 fence_fd;
  __u64 pmrs;
  __u32 nr_pmrs;
  __u32 pad;
};
#define ETNA_WAIT_NONBLOCK 0x01
struct drm_etnaviv_wait_fence {
  __u32 pipe;
  __u32 fence;
  __u32 flags;
  __u32 pad;
  struct drm_etnaviv_timespec timeout;
};
#define ETNA_USERPTR_READ 0x01
#define ETNA_USERPTR_WRITE 0x02
struct drm_etnaviv_gem_userptr {
  __u64 user_ptr;
  __u64 user_size;
  __u32 flags;
  __u32 handle;
};
struct drm_etnaviv_gem_wait {
  __u32 pipe;
  __u32 handle;
  __u32 flags;
  __u32 pad;
  struct drm_etnaviv_timespec timeout;
};
struct drm_etnaviv_pm_domain {
  __u32 pipe;
  __u8 iter;
  __u8 id;
  __u16 nr_signals;
  char name[64];
};
struct drm_etnaviv_pm_signal {
  __u32 pipe;
  __u8 domain;
  __u8 pad;
  __u16 iter;
  __u16 id;
  char name[64];
};
#define DRM_ETNAVIV_GET_PARAM 0x00
#define DRM_ETNAVIV_GEM_NEW 0x02
#define DRM_ETNAVIV_GEM_INFO 0x03
#define DRM_ETNAVIV_GEM_CPU_PREP 0x04
#define DRM_ETNAVIV_GEM_CPU_FINI 0x05
#define DRM_ETNAVIV_GEM_SUBMIT 0x06
#define DRM_ETNAVIV_WAIT_FENCE 0x07
#define DRM_ETNAVIV_GEM_USERPTR 0x08
#define DRM_ETNAVIV_GEM_WAIT 0x09
#define DRM_ETNAVIV_PM_QUERY_DOM 0x0a
#define DRM_ETNAVIV_PM_QUERY_SIG 0x0b
#define DRM_ETNAVIV_NUM_IOCTLS 0x0c
#define DRM_IOCTL_ETNAVIV_GET_PARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_GET_PARAM, struct drm_etnaviv_param)
#define DRM_IOCTL_ETNAVIV_GEM_NEW DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_NEW, struct drm_etnaviv_gem_new)
#define DRM_IOCTL_ETNAVIV_GEM_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_INFO, struct drm_etnaviv_gem_info)
#define DRM_IOCTL_ETNAVIV_GEM_CPU_PREP DRM_IOW(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_CPU_PREP, struct drm_etnaviv_gem_cpu_prep)
#define DRM_IOCTL_ETNAVIV_GEM_CPU_FINI DRM_IOW(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_CPU_FINI, struct drm_etnaviv_gem_cpu_fini)
#define DRM_IOCTL_ETNAVIV_GEM_SUBMIT DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_SUBMIT, struct drm_etnaviv_gem_submit)
#define DRM_IOCTL_ETNAVIV_WAIT_FENCE DRM_IOW(DRM_COMMAND_BASE + DRM_ETNAVIV_WAIT_FENCE, struct drm_etnaviv_wait_fence)
#define DRM_IOCTL_ETNAVIV_GEM_USERPTR DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_USERPTR, struct drm_etnaviv_gem_userptr)
#define DRM_IOCTL_ETNAVIV_GEM_WAIT DRM_IOW(DRM_COMMAND_BASE + DRM_ETNAVIV_GEM_WAIT, struct drm_etnaviv_gem_wait)
#define DRM_IOCTL_ETNAVIV_PM_QUERY_DOM DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_PM_QUERY_DOM, struct drm_etnaviv_pm_domain)
#define DRM_IOCTL_ETNAVIV_PM_QUERY_SIG DRM_IOWR(DRM_COMMAND_BASE + DRM_ETNAVIV_PM_QUERY_SIG, struct drm_etnaviv_pm_signal)
#ifdef __cplusplus
}
#endif
#endif
```