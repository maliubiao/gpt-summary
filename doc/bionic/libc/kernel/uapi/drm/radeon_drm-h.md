Response:
Let's break down the thought process for analyzing the given C header file for a DRM driver.

**1. Understanding the Context:**

*   The file path `bionic/libc/kernel/uapi/drm/radeon_drm.handroid` immediately tells us this is a header file (`.h`) within Android's Bionic library, specifically for interacting with the kernel's DRM (Direct Rendering Manager) subsystem.
*   The `radeon_drm.h` name strongly suggests it's for AMD Radeon graphics cards.
*   The "auto-generated" comment and the URL point to the Bionic source, emphasizing its kernel-level API nature. This isn't userspace code.

**2. Initial Code Scan - Identifying Key Sections:**

I'd quickly scan the file, looking for distinct blocks:

*   **Include Headers:** `#include "drm.h"`  -  This is fundamental. This file builds upon the generic DRM API.
*   **C++ Compatibility:** The `ifdef __cplusplus` block is boilerplate for making C headers usable in C++ code. It's important but doesn't define core functionality.
*   **Macro Definitions (`#define`):**  A *lot* of `#define` statements. These are clearly enumerations, flags, and constants used throughout the driver API. I'd group them mentally:
    *   `RADEON_UPLOAD_*`:  Relating to uploading data, likely for rendering.
    *   `RADEON_EMIT_*`: Commands for sending instructions to the GPU.
    *   `RADEON_CMD_*`, `R300_CMD_*`:  Different command types and variations, possibly for different generations of Radeon hardware.
    *   `RADEON_WAIT_*`, `R300_WAIT_*`: Flags for synchronization.
    *   `RADEON_*_SIZE`, `RADEON_*_OFFSET`, `RADEON_NR_*`:  Size and offset definitions, probably related to memory management and data structures.
    *   `DRM_RADEON_*`:  IOCTL command definitions.
    *   `RADEON_PARAM_*`: Parameters that can be queried or set.
    *   `RADEON_MEM_REGION_*`: Identifiers for memory regions.
    *   `RADEON_GEM_*`:  Related to Graphics Execution Manager (GEM), the memory management system in modern DRM drivers.
    *   `RADEON_TILING_*`: Defines for memory tiling modes.
    *   `RADEON_CHUNK_ID_*`, `RADEON_CS_*`: For command submission and related structures.
    *   `RADEON_INFO_*`:  Information codes for querying driver/hardware details.
    *   `SI_TILE_MODE_*`, `CIK_TILE_MODE_*`: Specific tiling modes for later Radeon architectures (Southern Islands and Kaveri).

*   **Type Definitions (`typedef struct`, `typedef union`):** These define the data structures used to interact with the driver:
    *   `radeon_color_regs_t`:  Color registers.
    *   `drm_radeon_context_regs_t`, `drm_radeon_context2_regs_t`:  GPU context settings.
    *   `drm_radeon_texture_regs_t`: Texture-related settings.
    *   `drm_radeon_prim_t`:  Primitive drawing information.
    *   `drm_radeon_state_t`:  Aggregates context and texture states.
    *   `drm_radeon_sarea_t`: Shared area between userspace and kernel. Crucial for synchronization and data exchange.
    *   Various `drm_radeon_*_t` structures related to specific IOCTLs (init, cp\_stop, fullscreen, clear, vertex, indices, etc.).
    *   `drm_radeon_cmd_header_t`, `drm_r300_cmd_header_t`: Headers for command submission.
    *   Structures related to GEM object management (`drm_radeon_gem_*`).
    *   `drm_radeon_cs_*`: Structures for command stream submission.
    *   `drm_radeon_info`: Structure for querying driver information.

*   **IOCTL Definitions (`#define DRM_IOCTL_RADEON_*`):** These define the specific system calls that userspace can make to interact with the kernel driver. The `DRM_IOW`, `DRM_IO`, `DRM_IOWR` macros indicate the direction of data flow (write, none, read/write).

**3. Analyzing Functionality (Based on the Scanned Sections):**

*   **Initialization and Shutdown:**  `DRM_RADEON_CP_INIT`, `DRM_RADEON_CP_START`, `DRM_RADEON_CP_STOP`, `DRM_RADEON_CP_RESET`. These manage the command processor (CP) on the GPU.
*   **Rendering Primitives:**  `DRM_RADEON_VERTEX`, `DRM_RADEON_INDICES`, `DRM_RADEON_VERTEX2`. These are fundamental for drawing 3D geometry.
*   **Command Buffers:** `DRM_RADEON_CMDBUF`, `drm_radeon_cmd_buffer_t`, `drm_radeon_cmd_header_t`. This indicates a command buffer submission mechanism for sending sequences of GPU instructions.
*   **Texture Management:** `DRM_RADEON_TEXTURE`, `drm_radeon_texture_t`, `RADEON_UPLOAD_TEX*`. For uploading and managing texture data.
*   **Memory Management:** `DRM_RADEON_ALLOC`, `DRM_RADEON_FREE`, `DRM_RADEON_INIT_HEAP`, and the entire `DRM_RADEON_GEM_*` set of IOCTLs. Crucial for managing GPU memory (VRAM and GTT). GEM provides a modern, object-based approach.
*   **Synchronization:** `DRM_RADEON_IRQ_EMIT`, `DRM_RADEON_IRQ_WAIT`, `RADEON_WAIT_*`. Mechanisms to ensure the CPU and GPU stay in sync.
*   **Framebuffer Operations:** `DRM_RADEON_FULLSCREEN`, `DRM_RADEON_SWAP`, `DRM_RADEON_CLEAR`. Operations on the display framebuffer.
*   **Querying Information:** `DRM_RADEON_GETPARAM`, `DRM_RADEON_INFO`. Allows userspace to get details about the driver and hardware.
*   **Command Stream Submission (CS):** `DRM_RADEON_CS`, `drm_radeon_cs_*`. A more advanced way to submit commands, often involving relocation and more complex buffer management.
*   **Virtual Addressing (VA):** `DRM_RADEON_GEM_VA`. For mapping GPU memory into process address spaces.

**4. Connecting to Android:**

*   Android's graphics stack (SurfaceFlinger, Vulkan drivers, OpenGL ES drivers) will ultimately use these low-level DRM interfaces to communicate with the GPU.
*   The NDK provides access to OpenGL ES and Vulkan, which internally rely on these DRM calls.
*   SurfaceFlinger uses DRM to manage the display and compositing.

**5. Libc Functions and Dynamic Linker:**

*   The header itself doesn't *implement* libc functions. It defines data structures and constants used by code that *does* use libc (like the userspace driver components).
*   Similarly, the dynamic linker isn't directly involved here, but the userspace Radeon driver will be a shared library (`.so`) loaded by the linker.

**6. Reasoning and Assumptions:**

*   The naming conventions (`RADEON_`, `DRM_RADEON_`) strongly suggest the target hardware.
*   The presence of GEM-related structures indicates a modern DRM driver.
*   The structure of the IOCTLs follows standard Linux DRM patterns.

**7. User Errors:**

*   Incorrectly setting flags or parameters in the IOCTL structures is a common error.
*   Forgetting to synchronize GPU operations can lead to race conditions and rendering issues.
*   Memory management errors (double frees, use-after-frees) are always a risk with low-level APIs.

**8. Tracing the Call Flow:**

*   Understanding that applications use higher-level APIs (OpenGL ES, Vulkan).
*   These APIs are implemented by libraries (e.g., libGLESv2.so, libvulkan.so).
*   These libraries, in turn, make ioctl calls using the defined structures and constants.

**9. Frida Hooking:**

*   Focusing on hooking the `ioctl` system call with the specific `DRM_IOCTL_RADEON_*` commands. This allows interception of the low-level communication.

**Self-Correction/Refinement:**

*   Initially, I might focus too much on individual macros. It's more effective to group them by functionality.
*   Realizing that while the header is in Bionic, it's a *kernel* UAPI header. The actual driver implementation is in the Linux kernel, not Bionic itself. Bionic provides the definitions for userspace to interact with it.
*   Remembering the role of the dynamic linker in loading the userspace driver component.

By following these steps, I can systematically analyze the header file and address all the points raised in the prompt, even without prior knowledge of this specific driver. The key is to leverage the structure of the code, naming conventions, and general knowledge of operating system and graphics driver architecture.
好的，我们来详细分析一下这个名为 `radeon_drm.h` 的头文件。

**功能列举:**

这个头文件定义了用于与 AMD Radeon 显卡设备的 DRM (Direct Rendering Manager) 驱动程序进行用户空间交互的常量、数据结构和 ioctl 命令。 它的主要功能可以归纳为：

1. **定义 GPU 硬件相关的常量和位掩码:**  例如 `RADEON_UPLOAD_CONTEXT`，`RADEON_EMIT_PP_MISC` 等，这些常量代表了 GPU 硬件寄存器、状态和命令的不同方面。
2. **定义用于在用户空间和内核空间之间传递数据的结构体:**  例如 `drm_radeon_context_regs_t`，`drm_radeon_texture_regs_t`，以及各种以 `drm_radeon_*_t` 结尾的结构体，它们用于配置 GPU 状态、提交渲染命令、管理内存等。
3. **定义了一系列 ioctl 命令:**  以 `DRM_IOCTL_RADEON_` 开头的宏定义，例如 `DRM_IOCTL_RADEON_CP_INIT`，`DRM_IOCTL_RADEON_GEM_CREATE` 等，这些命令是用户空间程序与内核驱动程序进行通信的主要方式，用于执行诸如初始化、提交命令、内存管理等操作。
4. **定义了用于 GEM (Graphics Execution Manager) 的相关结构体和常量:**  GEM 是 Linux DRM 子系统中用于管理 GPU 内存的对象，例如 `drm_radeon_gem_create`，`drm_radeon_gem_mmap` 等。
5. **定义了用于命令流提交 (Command Submission, CS) 的相关结构体和常量:**  例如 `drm_radeon_cs`，`drm_radeon_cs_chunk`，用于更高效地向 GPU 提交命令。
6. **定义了用于查询 GPU 信息的结构体和常量:**  例如 `drm_radeon_info`，以及 `RADEON_INFO_DEVICE_ID` 等，用于获取设备 ID、管道数量、时钟频率等硬件信息。

**与 Android 功能的关系举例:**

这个头文件对于 Android 设备的图形显示至关重要，因为它定义了与 AMD Radeon GPU 交互的底层接口。以下是一些具体的例子：

*   **图形渲染 (OpenGL ES, Vulkan):** Android 上的应用程序通常使用 OpenGL ES 或 Vulkan 进行 3D 图形渲染。 这些图形 API 的驱动程序最终会调用这里定义的 ioctl 命令，例如 `DRM_IOCTL_RADEON_CMDBUF` 或 `DRM_IOCTL_RADEON_CS`，将渲染命令提交给 Radeon GPU 执行。 `RADEON_UPLOAD_*` 定义了上传渲染数据（如顶点、纹理坐标等）的方式，`RADEON_EMIT_*` 定义了具体的渲染命令。
*   **显示合成 (SurfaceFlinger):** Android 的 SurfaceFlinger 服务负责将不同的图形缓冲区合成为最终的屏幕显示。 它会使用这里定义的 ioctl 命令，例如 `DRM_IOCTL_RADEON_FLIP`，来控制帧缓冲的切换，实现双缓冲或三缓冲等显示技术。
*   **内存管理:** Android 的图形系统需要管理 GPU 的内存，包括显存和系统内存 (通过 AGP/PCIe 总线访问)。 这里定义的 GEM 相关的 ioctl 命令，例如 `DRM_IOCTL_RADEON_GEM_CREATE`，`DRM_IOCTL_RADEON_GEM_MMAP`，用于创建、映射和管理 GPU 内存对象，供图形应用程序和 SurfaceFlinger 使用。
*   **电源管理:**  驱动程序可能会使用这里定义的接口来控制 GPU 的电源状态，例如通过特定的 ioctl 命令来进入低功耗模式或调整时钟频率。

**libc 函数的功能实现:**

这个头文件本身是 C 头文件，它只包含宏定义、结构体和枚举类型的声明，**不包含任何 libc 函数的实现**。  libc 函数的实现位于 Bionic 库的其他源文件中。

这个头文件中定义的结构体和常量会被使用 libc 函数的 C/C++ 代码引用，例如：

*   **`open()` 和 `close()`:**  用户空间程序会使用 `open("/dev/dri/cardX")` (X 是设备编号) 打开 DRM 设备文件，并使用 `close()` 关闭。
*   **`ioctl()`:** 这是与 DRM 驱动程序通信的核心 libc 函数。 用户空间程序会调用 `ioctl(fd, DRM_IOCTL_RADEON_XXX, arg)` 来执行特定的 GPU 操作，其中 `fd` 是 DRM 设备文件的文件描述符，`DRM_IOCTL_RADEON_XXX` 是这里定义的 ioctl 命令，`arg` 是指向与该命令相关的结构体的指针。
*   **`mmap()` 和 `munmap()`:** 用于将 GEM 对象映射到用户空间的地址空间，以便用户空间程序可以直接访问 GPU 内存。

**dynamic linker 的功能和处理过程:**

虽然这个头文件本身不直接涉及 dynamic linker，但使用这个头文件的用户空间 Radeon 驱动程序（通常是一个 `.so` 文件）会被 dynamic linker 加载和链接。

**so 布局样本:**

一个典型的 Radeon DRM 用户空间驱动程序的 `.so` 文件布局可能如下：

```
libradeon.so:
    .text          # 代码段，包含驱动程序的逻辑
    .rodata        # 只读数据段，包含常量字符串等
    .data          # 已初始化的全局变量和静态变量
    .bss           # 未初始化的全局变量和静态变量
    .dynsym        # 动态符号表，包含导出的和导入的符号
    .dynstr        # 动态字符串表，包含符号名
    .rel.dyn       # 数据段的重定位信息
    .rel.plt       # PLT (Procedure Linkage Table) 的重定位信息
    ...             # 其他段
```

**链接的处理过程:**

1. **加载:** 当一个使用了 Radeon DRM 驱动程序的应用程序启动时，dynamic linker（例如 Android 上的 `linker64` 或 `linker`）会根据应用程序的依赖关系找到 `libradeon.so`。
2. **映射:** dynamic linker 会将 `libradeon.so` 的各个段映射到进程的地址空间。
3. **符号解析:**
    *   **导出符号:** `libradeon.so` 可能会导出一些符号（函数或变量），供其他共享库使用。
    *   **导入符号:** `libradeon.so` 也会导入一些符号，这些符号通常来自 libc (`libc.so`) 或其他系统库。 例如，`libradeon.so` 可能会导入 `ioctl` 函数。
4. **重定位:** 由于共享库被加载到内存的地址是不确定的，dynamic linker 需要根据重定位信息（`.rel.dyn` 和 `.rel.plt`）修改代码和数据段中的地址，使其指向正确的内存位置。
    *   **数据段重定位:**  修改全局变量和静态变量的地址。
    *   **PLT 重定位:**  为导入的函数创建 PLT 条目，并在第一次调用时解析函数的实际地址。
5. **执行:** 完成加载、映射、符号解析和重定位后，应用程序就可以调用 `libradeon.so` 中定义的函数，这些函数会进一步调用 `ioctl` 等 libc 函数与内核驱动程序进行交互。

**假设输入与输出 (逻辑推理示例):**

假设用户空间程序想要创建一个 GEM 对象。

**假设输入:**

*   `fd`:  打开的 DRM 设备文件的文件描述符。
*   `ioctl_cmd`: `DRM_IOCTL_RADEON_GEM_CREATE`
*   `arg`: 一个指向 `drm_radeon_gem_create` 结构体的指针，该结构体包含：
    *   `size`:  要分配的 GEM 对象的大小 (例如 1MB)。
    *   `alignment`:  内存对齐要求 (例如 4KB)。
    *   其他成员设置为默认值或所需的值。

**逻辑推理和处理过程 (在内核驱动程序中):**

1. 内核驱动程序接收到来自 `ioctl` 系统调用的 `DRM_IOCTL_RADEON_GEM_CREATE` 命令。
2. 驱动程序检查用户提供的参数是否有效（例如，大小是否为正数，对齐是否是 2 的幂）。
3. 驱动程序在 GPU 的内存空间中分配指定大小和对齐的内存块。
4. 驱动程序创建一个 GEM 对象来管理这块内存，并分配一个唯一的句柄 (handle) 来标识该对象。
5. 驱动程序将分配的 GEM 对象的句柄写入 `drm_radeon_gem_create` 结构体的 `handle` 成员中。

**假设输出:**

*   `ioctl()` 系统调用成功返回 (通常返回 0)。
*   `arg->handle` 中包含新创建的 GEM 对象的句柄 (一个非零的整数)。

**用户或编程常见的使用错误举例:**

1. **忘记打开 DRM 设备文件:**  直接调用 `ioctl` 会导致文件描述符无效的错误。
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <drm/drm.h>
    #include <drm/radeon_drm.h>

    int main() {
        int fd;
        struct drm_radeon_info info;
        info.request = RADEON_INFO_DEVICE_ID;

        // 错误：忘记打开设备文件
        // fd = open("/dev/dri/card0", O_RDWR);
        // if (fd < 0) {
        //     perror("open");
        //     return 1;
        // }

        if (ioctl(fd, DRM_IOCTL_RADEON_INFO, &info) == -1) {
            perror("ioctl"); // 这里会报错，因为 fd 未初始化或无效
            return 1;
        }

        printf("Device ID: 0x%llx\n", info.value);

        // close(fd); // 如果打开了，需要关闭
        return 0;
    }
    ```

2. **传递错误的 ioctl 命令或参数:**  例如，使用错误的结构体或设置了无效的标志位。这会导致 `ioctl` 返回错误代码，并且 GPU 操作可能失败或产生不可预测的结果。
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <drm/drm.h>
    #include <drm/radeon_drm.h>

    int main() {
        int fd = open("/dev/dri/card0", O_RDWR);
        if (fd < 0) {
            perror("open");
            return 1;
        }

        struct drm_radeon_clear clear;
        // 错误：clear 结构体的成员没有正确初始化
        // clear.flags = RADEON_FRONT | RADEON_BACK;
        // clear.clear_color = 0xFF0000FF; // Red

        if (ioctl(fd, DRM_IOCTL_RADEON_CLEAR, &clear) == -1) {
            perror("ioctl"); // 这里可能会报错，或者清除操作不会按预期执行
            return 1;
        }

        close(fd);
        return 0;
    }
    ```

3. **内存管理错误:**  例如，创建了 GEM 对象但忘记释放，或者在释放后仍然尝试访问。
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <drm/drm.h>
    #include <drm/radeon_drm.h>

    int main() {
        int fd = open("/dev/dri/card0", O_RDWR);
        if (fd < 0) {
            perror("open");
            return 1;
        }

        struct drm_radeon_gem_create create_req = { .size = 1024 };
        if (ioctl(fd, DRM_IOCTL_RADEON_GEM_CREATE, &create_req) == -1) {
            perror("ioctl DRM_IOCTL_RADEON_GEM_CREATE");
            close(fd);
            return 1;
        }

        __u32 handle = create_req.handle;
        printf("GEM object handle: %u\n", handle);

        // 错误：忘记释放 GEM 对象
        // struct drm_radeon_gem_free free_req = { .handle = handle };
        // if (ioctl(fd, DRM_IOCTL_RADEON_GEM_FREE, &free_req) == -1) {
        //     perror("ioctl DRM_IOCTL_RADEON_GEM_FREE");
        // }

        close(fd);
        return 0; // 内存泄漏
    }
    ```

**Android framework or ndk 如何一步步的到达这里:**

1. **Android Framework (Java/Kotlin):**
    *   应用程序通过 Android SDK 提供的图形 API (例如 `android.opengl.GLES20` 或 `android.graphics.Canvas`) 进行图形操作。
    *   这些 API 的实现通常位于 Android Framework 层的 `frameworks/base/opengl/java/android/opengl/` 和 `frameworks/base/graphics/java/android/graphics/` 等目录中。
    *   Framework 层的代码会调用 Native 层的图形库，例如 libagl.so (旧版本) 或 libhwui.so (用于硬件加速的 UI 渲染)。

2. **Native Graphics Libraries (C/C++):**
    *   **libhwui.so:**  用于硬件加速的 UI 渲染，它会使用 Skia 图形库。
    *   **libagl.so (deprecated):**  旧版本的 OpenGL ES 包装库。
    *   **libGLESv1_CM.so, libGLESv2.so, libGLESv3.so:**  OpenGL ES 的实现库，通常由设备制造商提供。
    *   **libvulkan.so:**  Vulkan API 的实现库。

3. **Vendor Graphics Drivers (C/C++):**
    *   这些 OpenGL ES 或 Vulkan 库会加载特定于硬件的驱动程序，例如 `libRadeonGL.so` (示例名称)。
    *   这些驱动程序会将 OpenGL ES 或 Vulkan 的调用转换为底层的 GPU 命令。

4. **DRM 用户空间库 (C/C++):**
    *   Vendor 提供的图形驱动程序会使用 DRM 用户空间库 (通常是 `libdrm.so`) 来与内核 DRM 驱动程序进行通信。
    *   `libdrm.so` 提供了一些封装了 `ioctl` 调用的函数，例如 `drmOpen()`, `drmIoctl()`, `drmClose()` 等。

5. **内核 DRM 驱动程序 (Kernel C):**
    *   `libdrm.so` 中的函数最终会调用 `ioctl()` 系统调用，并传递这里定义的 `DRM_IOCTL_RADEON_XXX` 命令和相应的结构体，与内核中的 Radeon DRM 驱动程序 (`drivers/gpu/drm/radeon/`) 进行交互。

**NDK 的路径:**

*   如果应用程序使用 NDK 开发，可以直接使用 OpenGL ES 或 Vulkan API。
*   NDK 提供的 OpenGL ES 和 Vulkan 库 (例如 `<GLES3/gl3.h>` 或 `<vulkan/vulkan.h>`)  最终也会通过类似上述的路径到达内核 DRM 驱动程序。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida hook `ioctl` 系统调用，并过滤出与 Radeon DRM 相关的 ioctl 命令。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    if pid:
        session = device.attach(pid)
    else:
        package_name = sys.argv[1]
        session = device.attach(package_name)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查是否是与 DRM 相关的设备文件 (通常在 /dev/dri/cardX)
            const pathBuf = Memory.allocUtf8String(256);
            const bytesRead = recvfrom(fd, pathBuf, 256, 0, null, null);
            const path = pathBuf.readUtf8String();
            if (path.startsWith("/dev/dri/card")) {
                // 过滤 Radeon DRM ioctl 命令
                const DRM_COMMAND_BASE = 0x40006400; // 从内核头文件中获取
                if ((request & 0xff000000) == DRM_COMMAND_BASE) {
                    console.log("[*] ioctl called with fd:", fd, "request:", request.toString(16));
                    // 可以进一步解析参数
                    // 例如，如果 request 是 DRM_IOCTL_RADEON_GEM_CREATE，可以读取 args[2] 指向的结构体
                }
            }
        },
        onLeave: function(retval) {
            // console.log("ioctl returned:", retval.toInt32());
        }
    });

    function recvfrom(sockfd, buf, len, flags, src_addr, addrlen) {
        const recvfromPtr = Module.findExportByName(null, "recvfrom");
        const recvfromFunc = new NativeFunction(recvfromPtr, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'pointer']);
        return recvfromFunc(sockfd, buf, len, flags, src_addr, addrlen);
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print(f"Process with name or PID '{sys.argv[1]}' not found.")
except KeyboardInterrupt:
    print("Exiting...")
```

**使用说明:**

1. **安装 Frida:**  确保你的系统上安装了 Frida 和 Frida-tools。
2. **运行 Android 设备或模拟器。**
3. **找到目标进程的 PID 或包名。**
4. **运行 Frida 脚本:**
    *   如果使用 PID： `python your_frida_script.py <PID>`
    *   如果使用包名： `python your_frida_script.py <package_name>`

这个 Frida 脚本会 hook `ioctl` 系统调用，并尝试判断调用的文件描述符是否指向 DRM 设备。 如果是，它会进一步检查 ioctl 命令是否属于 Radeon DRM 的命令范围，并打印出文件描述符和命令编号。 你可以根据需要修改脚本来解析 ioctl 的参数，以获取更详细的信息。

希望这个详细的解释能够帮助你理解 `radeon_drm.h` 文件的作用以及它在 Android 图形系统中的位置。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/radeon_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __RADEON_DRM_H__
#define __RADEON_DRM_H__
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#ifndef __RADEON_SAREA_DEFINES__
#define __RADEON_SAREA_DEFINES__
#define RADEON_UPLOAD_CONTEXT 0x00000001
#define RADEON_UPLOAD_VERTFMT 0x00000002
#define RADEON_UPLOAD_LINE 0x00000004
#define RADEON_UPLOAD_BUMPMAP 0x00000008
#define RADEON_UPLOAD_MASKS 0x00000010
#define RADEON_UPLOAD_VIEWPORT 0x00000020
#define RADEON_UPLOAD_SETUP 0x00000040
#define RADEON_UPLOAD_TCL 0x00000080
#define RADEON_UPLOAD_MISC 0x00000100
#define RADEON_UPLOAD_TEX0 0x00000200
#define RADEON_UPLOAD_TEX1 0x00000400
#define RADEON_UPLOAD_TEX2 0x00000800
#define RADEON_UPLOAD_TEX0IMAGES 0x00001000
#define RADEON_UPLOAD_TEX1IMAGES 0x00002000
#define RADEON_UPLOAD_TEX2IMAGES 0x00004000
#define RADEON_UPLOAD_CLIPRECTS 0x00008000
#define RADEON_REQUIRE_QUIESCENCE 0x00010000
#define RADEON_UPLOAD_ZBIAS 0x00020000
#define RADEON_UPLOAD_ALL 0x003effff
#define RADEON_UPLOAD_CONTEXT_ALL 0x003e01ff
#define RADEON_EMIT_PP_MISC 0
#define RADEON_EMIT_PP_CNTL 1
#define RADEON_EMIT_RB3D_COLORPITCH 2
#define RADEON_EMIT_RE_LINE_PATTERN 3
#define RADEON_EMIT_SE_LINE_WIDTH 4
#define RADEON_EMIT_PP_LUM_MATRIX 5
#define RADEON_EMIT_PP_ROT_MATRIX_0 6
#define RADEON_EMIT_RB3D_STENCILREFMASK 7
#define RADEON_EMIT_SE_VPORT_XSCALE 8
#define RADEON_EMIT_SE_CNTL 9
#define RADEON_EMIT_SE_CNTL_STATUS 10
#define RADEON_EMIT_RE_MISC 11
#define RADEON_EMIT_PP_TXFILTER_0 12
#define RADEON_EMIT_PP_BORDER_COLOR_0 13
#define RADEON_EMIT_PP_TXFILTER_1 14
#define RADEON_EMIT_PP_BORDER_COLOR_1 15
#define RADEON_EMIT_PP_TXFILTER_2 16
#define RADEON_EMIT_PP_BORDER_COLOR_2 17
#define RADEON_EMIT_SE_ZBIAS_FACTOR 18
#define RADEON_EMIT_SE_TCL_OUTPUT_VTX_FMT 19
#define RADEON_EMIT_SE_TCL_MATERIAL_EMMISSIVE_RED 20
#define R200_EMIT_PP_TXCBLEND_0 21
#define R200_EMIT_PP_TXCBLEND_1 22
#define R200_EMIT_PP_TXCBLEND_2 23
#define R200_EMIT_PP_TXCBLEND_3 24
#define R200_EMIT_PP_TXCBLEND_4 25
#define R200_EMIT_PP_TXCBLEND_5 26
#define R200_EMIT_PP_TXCBLEND_6 27
#define R200_EMIT_PP_TXCBLEND_7 28
#define R200_EMIT_TCL_LIGHT_MODEL_CTL_0 29
#define R200_EMIT_TFACTOR_0 30
#define R200_EMIT_VTX_FMT_0 31
#define R200_EMIT_VAP_CTL 32
#define R200_EMIT_MATRIX_SELECT_0 33
#define R200_EMIT_TEX_PROC_CTL_2 34
#define R200_EMIT_TCL_UCP_VERT_BLEND_CTL 35
#define R200_EMIT_PP_TXFILTER_0 36
#define R200_EMIT_PP_TXFILTER_1 37
#define R200_EMIT_PP_TXFILTER_2 38
#define R200_EMIT_PP_TXFILTER_3 39
#define R200_EMIT_PP_TXFILTER_4 40
#define R200_EMIT_PP_TXFILTER_5 41
#define R200_EMIT_PP_TXOFFSET_0 42
#define R200_EMIT_PP_TXOFFSET_1 43
#define R200_EMIT_PP_TXOFFSET_2 44
#define R200_EMIT_PP_TXOFFSET_3 45
#define R200_EMIT_PP_TXOFFSET_4 46
#define R200_EMIT_PP_TXOFFSET_5 47
#define R200_EMIT_VTE_CNTL 48
#define R200_EMIT_OUTPUT_VTX_COMP_SEL 49
#define R200_EMIT_PP_TAM_DEBUG3 50
#define R200_EMIT_PP_CNTL_X 51
#define R200_EMIT_RB3D_DEPTHXY_OFFSET 52
#define R200_EMIT_RE_AUX_SCISSOR_CNTL 53
#define R200_EMIT_RE_SCISSOR_TL_0 54
#define R200_EMIT_RE_SCISSOR_TL_1 55
#define R200_EMIT_RE_SCISSOR_TL_2 56
#define R200_EMIT_SE_VAP_CNTL_STATUS 57
#define R200_EMIT_SE_VTX_STATE_CNTL 58
#define R200_EMIT_RE_POINTSIZE 59
#define R200_EMIT_TCL_INPUT_VTX_VECTOR_ADDR_0 60
#define R200_EMIT_PP_CUBIC_FACES_0 61
#define R200_EMIT_PP_CUBIC_OFFSETS_0 62
#define R200_EMIT_PP_CUBIC_FACES_1 63
#define R200_EMIT_PP_CUBIC_OFFSETS_1 64
#define R200_EMIT_PP_CUBIC_FACES_2 65
#define R200_EMIT_PP_CUBIC_OFFSETS_2 66
#define R200_EMIT_PP_CUBIC_FACES_3 67
#define R200_EMIT_PP_CUBIC_OFFSETS_3 68
#define R200_EMIT_PP_CUBIC_FACES_4 69
#define R200_EMIT_PP_CUBIC_OFFSETS_4 70
#define R200_EMIT_PP_CUBIC_FACES_5 71
#define R200_EMIT_PP_CUBIC_OFFSETS_5 72
#define RADEON_EMIT_PP_TEX_SIZE_0 73
#define RADEON_EMIT_PP_TEX_SIZE_1 74
#define RADEON_EMIT_PP_TEX_SIZE_2 75
#define R200_EMIT_RB3D_BLENDCOLOR 76
#define R200_EMIT_TCL_POINT_SPRITE_CNTL 77
#define RADEON_EMIT_PP_CUBIC_FACES_0 78
#define RADEON_EMIT_PP_CUBIC_OFFSETS_T0 79
#define RADEON_EMIT_PP_CUBIC_FACES_1 80
#define RADEON_EMIT_PP_CUBIC_OFFSETS_T1 81
#define RADEON_EMIT_PP_CUBIC_FACES_2 82
#define RADEON_EMIT_PP_CUBIC_OFFSETS_T2 83
#define R200_EMIT_PP_TRI_PERF_CNTL 84
#define R200_EMIT_PP_AFS_0 85
#define R200_EMIT_PP_AFS_1 86
#define R200_EMIT_ATF_TFACTOR 87
#define R200_EMIT_PP_TXCTLALL_0 88
#define R200_EMIT_PP_TXCTLALL_1 89
#define R200_EMIT_PP_TXCTLALL_2 90
#define R200_EMIT_PP_TXCTLALL_3 91
#define R200_EMIT_PP_TXCTLALL_4 92
#define R200_EMIT_PP_TXCTLALL_5 93
#define R200_EMIT_VAP_PVS_CNTL 94
#define RADEON_MAX_STATE_PACKETS 95
#define RADEON_CMD_PACKET 1
#define RADEON_CMD_SCALARS 2
#define RADEON_CMD_VECTORS 3
#define RADEON_CMD_DMA_DISCARD 4
#define RADEON_CMD_PACKET3 5
#define RADEON_CMD_PACKET3_CLIP 6
#define RADEON_CMD_SCALARS2 7
#define RADEON_CMD_WAIT 8
#define RADEON_CMD_VECLINEAR 9
typedef union {
  int i;
  struct {
    unsigned char cmd_type, pad0, pad1, pad2;
  } header;
  struct {
    unsigned char cmd_type, packet_id, pad0, pad1;
  } packet;
  struct {
    unsigned char cmd_type, offset, stride, count;
  } scalars;
  struct {
    unsigned char cmd_type, offset, stride, count;
  } vectors;
  struct {
    unsigned char cmd_type, addr_lo, addr_hi, count;
  } veclinear;
  struct {
    unsigned char cmd_type, buf_idx, pad0, pad1;
  } dma;
  struct {
    unsigned char cmd_type, flags, pad0, pad1;
  } wait;
} drm_radeon_cmd_header_t;
#define RADEON_WAIT_2D 0x1
#define RADEON_WAIT_3D 0x2
#define R300_CMD_PACKET3_CLEAR 0
#define R300_CMD_PACKET3_RAW 1
#define R300_CMD_PACKET0 1
#define R300_CMD_VPU 2
#define R300_CMD_PACKET3 3
#define R300_CMD_END3D 4
#define R300_CMD_CP_DELAY 5
#define R300_CMD_DMA_DISCARD 6
#define R300_CMD_WAIT 7
#define R300_WAIT_2D 0x1
#define R300_WAIT_3D 0x2
#define R300_WAIT_2D_CLEAN 0x3
#define R300_WAIT_3D_CLEAN 0x4
#define R300_NEW_WAIT_2D_3D 0x3
#define R300_NEW_WAIT_2D_2D_CLEAN 0x4
#define R300_NEW_WAIT_3D_3D_CLEAN 0x6
#define R300_NEW_WAIT_2D_2D_CLEAN_3D_3D_CLEAN 0x8
#define R300_CMD_SCRATCH 8
#define R300_CMD_R500FP 9
typedef union {
  unsigned int u;
  struct {
    unsigned char cmd_type, pad0, pad1, pad2;
  } header;
  struct {
    unsigned char cmd_type, count, reglo, reghi;
  } packet0;
  struct {
    unsigned char cmd_type, count, adrlo, adrhi;
  } vpu;
  struct {
    unsigned char cmd_type, packet, pad0, pad1;
  } packet3;
  struct {
    unsigned char cmd_type, packet;
    unsigned short count;
  } delay;
  struct {
    unsigned char cmd_type, buf_idx, pad0, pad1;
  } dma;
  struct {
    unsigned char cmd_type, flags, pad0, pad1;
  } wait;
  struct {
    unsigned char cmd_type, reg, n_bufs, flags;
  } scratch;
  struct {
    unsigned char cmd_type, count, adrlo, adrhi_flags;
  } r500fp;
} drm_r300_cmd_header_t;
#define RADEON_FRONT 0x1
#define RADEON_BACK 0x2
#define RADEON_DEPTH 0x4
#define RADEON_STENCIL 0x8
#define RADEON_CLEAR_FASTZ 0x80000000
#define RADEON_USE_HIERZ 0x40000000
#define RADEON_USE_COMP_ZBUF 0x20000000
#define R500FP_CONSTANT_TYPE (1 << 1)
#define R500FP_CONSTANT_CLAMP (1 << 2)
#define RADEON_POINTS 0x1
#define RADEON_LINES 0x2
#define RADEON_LINE_STRIP 0x3
#define RADEON_TRIANGLES 0x4
#define RADEON_TRIANGLE_FAN 0x5
#define RADEON_TRIANGLE_STRIP 0x6
#define RADEON_BUFFER_SIZE 65536
#define RADEON_INDEX_PRIM_OFFSET 20
#define RADEON_SCRATCH_REG_OFFSET 32
#define R600_SCRATCH_REG_OFFSET 256
#define RADEON_NR_SAREA_CLIPRECTS 12
#define RADEON_LOCAL_TEX_HEAP 0
#define RADEON_GART_TEX_HEAP 1
#define RADEON_NR_TEX_HEAPS 2
#define RADEON_NR_TEX_REGIONS 64
#define RADEON_LOG_TEX_GRANULARITY 16
#define RADEON_MAX_TEXTURE_LEVELS 12
#define RADEON_MAX_TEXTURE_UNITS 3
#define RADEON_MAX_SURFACES 8
#define RADEON_OFFSET_SHIFT 10
#define RADEON_OFFSET_ALIGN (1 << RADEON_OFFSET_SHIFT)
#define RADEON_OFFSET_MASK (RADEON_OFFSET_ALIGN - 1)
#endif
typedef struct {
  unsigned int red;
  unsigned int green;
  unsigned int blue;
  unsigned int alpha;
} radeon_color_regs_t;
typedef struct {
  unsigned int pp_misc;
  unsigned int pp_fog_color;
  unsigned int re_solid_color;
  unsigned int rb3d_blendcntl;
  unsigned int rb3d_depthoffset;
  unsigned int rb3d_depthpitch;
  unsigned int rb3d_zstencilcntl;
  unsigned int pp_cntl;
  unsigned int rb3d_cntl;
  unsigned int rb3d_coloroffset;
  unsigned int re_width_height;
  unsigned int rb3d_colorpitch;
  unsigned int se_cntl;
  unsigned int se_coord_fmt;
  unsigned int re_line_pattern;
  unsigned int re_line_state;
  unsigned int se_line_width;
  unsigned int pp_lum_matrix;
  unsigned int pp_rot_matrix_0;
  unsigned int pp_rot_matrix_1;
  unsigned int rb3d_stencilrefmask;
  unsigned int rb3d_ropcntl;
  unsigned int rb3d_planemask;
  unsigned int se_vport_xscale;
  unsigned int se_vport_xoffset;
  unsigned int se_vport_yscale;
  unsigned int se_vport_yoffset;
  unsigned int se_vport_zscale;
  unsigned int se_vport_zoffset;
  unsigned int se_cntl_status;
  unsigned int re_top_left;
  unsigned int re_misc;
} drm_radeon_context_regs_t;
typedef struct {
  unsigned int se_zbias_factor;
  unsigned int se_zbias_constant;
} drm_radeon_context2_regs_t;
typedef struct {
  unsigned int pp_txfilter;
  unsigned int pp_txformat;
  unsigned int pp_txoffset;
  unsigned int pp_txcblend;
  unsigned int pp_txablend;
  unsigned int pp_tfactor;
  unsigned int pp_border_color;
} drm_radeon_texture_regs_t;
typedef struct {
  unsigned int start;
  unsigned int finish;
  unsigned int prim : 8;
  unsigned int stateidx : 8;
  unsigned int numverts : 16;
  unsigned int vc_format;
} drm_radeon_prim_t;
typedef struct {
  drm_radeon_context_regs_t context;
  drm_radeon_texture_regs_t tex[RADEON_MAX_TEXTURE_UNITS];
  drm_radeon_context2_regs_t context2;
  unsigned int dirty;
} drm_radeon_state_t;
typedef struct {
  drm_radeon_context_regs_t context_state;
  drm_radeon_texture_regs_t tex_state[RADEON_MAX_TEXTURE_UNITS];
  unsigned int dirty;
  unsigned int vertsize;
  unsigned int vc_format;
  struct drm_clip_rect boxes[RADEON_NR_SAREA_CLIPRECTS];
  unsigned int nbox;
  unsigned int last_frame;
  unsigned int last_dispatch;
  unsigned int last_clear;
  struct drm_tex_region tex_list[RADEON_NR_TEX_HEAPS][RADEON_NR_TEX_REGIONS + 1];
  unsigned int tex_age[RADEON_NR_TEX_HEAPS];
  int ctx_owner;
  int pfState;
  int pfCurrentPage;
  int crtc2_base;
  int tiling_enabled;
} drm_radeon_sarea_t;
#define DRM_RADEON_CP_INIT 0x00
#define DRM_RADEON_CP_START 0x01
#define DRM_RADEON_CP_STOP 0x02
#define DRM_RADEON_CP_RESET 0x03
#define DRM_RADEON_CP_IDLE 0x04
#define DRM_RADEON_RESET 0x05
#define DRM_RADEON_FULLSCREEN 0x06
#define DRM_RADEON_SWAP 0x07
#define DRM_RADEON_CLEAR 0x08
#define DRM_RADEON_VERTEX 0x09
#define DRM_RADEON_INDICES 0x0A
#define DRM_RADEON_NOT_USED
#define DRM_RADEON_STIPPLE 0x0C
#define DRM_RADEON_INDIRECT 0x0D
#define DRM_RADEON_TEXTURE 0x0E
#define DRM_RADEON_VERTEX2 0x0F
#define DRM_RADEON_CMDBUF 0x10
#define DRM_RADEON_GETPARAM 0x11
#define DRM_RADEON_FLIP 0x12
#define DRM_RADEON_ALLOC 0x13
#define DRM_RADEON_FREE 0x14
#define DRM_RADEON_INIT_HEAP 0x15
#define DRM_RADEON_IRQ_EMIT 0x16
#define DRM_RADEON_IRQ_WAIT 0x17
#define DRM_RADEON_CP_RESUME 0x18
#define DRM_RADEON_SETPARAM 0x19
#define DRM_RADEON_SURF_ALLOC 0x1a
#define DRM_RADEON_SURF_FREE 0x1b
#define DRM_RADEON_GEM_INFO 0x1c
#define DRM_RADEON_GEM_CREATE 0x1d
#define DRM_RADEON_GEM_MMAP 0x1e
#define DRM_RADEON_GEM_PREAD 0x21
#define DRM_RADEON_GEM_PWRITE 0x22
#define DRM_RADEON_GEM_SET_DOMAIN 0x23
#define DRM_RADEON_GEM_WAIT_IDLE 0x24
#define DRM_RADEON_CS 0x26
#define DRM_RADEON_INFO 0x27
#define DRM_RADEON_GEM_SET_TILING 0x28
#define DRM_RADEON_GEM_GET_TILING 0x29
#define DRM_RADEON_GEM_BUSY 0x2a
#define DRM_RADEON_GEM_VA 0x2b
#define DRM_RADEON_GEM_OP 0x2c
#define DRM_RADEON_GEM_USERPTR 0x2d
#define DRM_IOCTL_RADEON_CP_INIT DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_CP_INIT, drm_radeon_init_t)
#define DRM_IOCTL_RADEON_CP_START DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_CP_START)
#define DRM_IOCTL_RADEON_CP_STOP DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_CP_STOP, drm_radeon_cp_stop_t)
#define DRM_IOCTL_RADEON_CP_RESET DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_CP_RESET)
#define DRM_IOCTL_RADEON_CP_IDLE DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_CP_IDLE)
#define DRM_IOCTL_RADEON_RESET DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_RESET)
#define DRM_IOCTL_RADEON_FULLSCREEN DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_FULLSCREEN, drm_radeon_fullscreen_t)
#define DRM_IOCTL_RADEON_SWAP DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_SWAP)
#define DRM_IOCTL_RADEON_CLEAR DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_CLEAR, drm_radeon_clear_t)
#define DRM_IOCTL_RADEON_VERTEX DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_VERTEX, drm_radeon_vertex_t)
#define DRM_IOCTL_RADEON_INDICES DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_INDICES, drm_radeon_indices_t)
#define DRM_IOCTL_RADEON_STIPPLE DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_STIPPLE, drm_radeon_stipple_t)
#define DRM_IOCTL_RADEON_INDIRECT DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_INDIRECT, drm_radeon_indirect_t)
#define DRM_IOCTL_RADEON_TEXTURE DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_TEXTURE, drm_radeon_texture_t)
#define DRM_IOCTL_RADEON_VERTEX2 DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_VERTEX2, drm_radeon_vertex2_t)
#define DRM_IOCTL_RADEON_CMDBUF DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_CMDBUF, drm_radeon_cmd_buffer_t)
#define DRM_IOCTL_RADEON_GETPARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GETPARAM, drm_radeon_getparam_t)
#define DRM_IOCTL_RADEON_FLIP DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_FLIP)
#define DRM_IOCTL_RADEON_ALLOC DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_ALLOC, drm_radeon_mem_alloc_t)
#define DRM_IOCTL_RADEON_FREE DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_FREE, drm_radeon_mem_free_t)
#define DRM_IOCTL_RADEON_INIT_HEAP DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_INIT_HEAP, drm_radeon_mem_init_heap_t)
#define DRM_IOCTL_RADEON_IRQ_EMIT DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_IRQ_EMIT, drm_radeon_irq_emit_t)
#define DRM_IOCTL_RADEON_IRQ_WAIT DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_IRQ_WAIT, drm_radeon_irq_wait_t)
#define DRM_IOCTL_RADEON_CP_RESUME DRM_IO(DRM_COMMAND_BASE + DRM_RADEON_CP_RESUME)
#define DRM_IOCTL_RADEON_SETPARAM DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_SETPARAM, drm_radeon_setparam_t)
#define DRM_IOCTL_RADEON_SURF_ALLOC DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_SURF_ALLOC, drm_radeon_surface_alloc_t)
#define DRM_IOCTL_RADEON_SURF_FREE DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_SURF_FREE, drm_radeon_surface_free_t)
#define DRM_IOCTL_RADEON_GEM_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_INFO, struct drm_radeon_gem_info)
#define DRM_IOCTL_RADEON_GEM_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_CREATE, struct drm_radeon_gem_create)
#define DRM_IOCTL_RADEON_GEM_MMAP DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_MMAP, struct drm_radeon_gem_mmap)
#define DRM_IOCTL_RADEON_GEM_PREAD DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_PREAD, struct drm_radeon_gem_pread)
#define DRM_IOCTL_RADEON_GEM_PWRITE DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_PWRITE, struct drm_radeon_gem_pwrite)
#define DRM_IOCTL_RADEON_GEM_SET_DOMAIN DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_SET_DOMAIN, struct drm_radeon_gem_set_domain)
#define DRM_IOCTL_RADEON_GEM_WAIT_IDLE DRM_IOW(DRM_COMMAND_BASE + DRM_RADEON_GEM_WAIT_IDLE, struct drm_radeon_gem_wait_idle)
#define DRM_IOCTL_RADEON_CS DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_CS, struct drm_radeon_cs)
#define DRM_IOCTL_RADEON_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_INFO, struct drm_radeon_info)
#define DRM_IOCTL_RADEON_GEM_SET_TILING DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_SET_TILING, struct drm_radeon_gem_set_tiling)
#define DRM_IOCTL_RADEON_GEM_GET_TILING DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_GET_TILING, struct drm_radeon_gem_get_tiling)
#define DRM_IOCTL_RADEON_GEM_BUSY DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_BUSY, struct drm_radeon_gem_busy)
#define DRM_IOCTL_RADEON_GEM_VA DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_VA, struct drm_radeon_gem_va)
#define DRM_IOCTL_RADEON_GEM_OP DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_OP, struct drm_radeon_gem_op)
#define DRM_IOCTL_RADEON_GEM_USERPTR DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_USERPTR, struct drm_radeon_gem_userptr)
typedef struct drm_radeon_init {
  enum {
    RADEON_INIT_CP = 0x01,
    RADEON_CLEANUP_CP = 0x02,
    RADEON_INIT_R200_CP = 0x03,
    RADEON_INIT_R300_CP = 0x04,
    RADEON_INIT_R600_CP = 0x05
  } func;
  unsigned long sarea_priv_offset;
  int is_pci;
  int cp_mode;
  int gart_size;
  int ring_size;
  int usec_timeout;
  unsigned int fb_bpp;
  unsigned int front_offset, front_pitch;
  unsigned int back_offset, back_pitch;
  unsigned int depth_bpp;
  unsigned int depth_offset, depth_pitch;
  unsigned long fb_offset;
  unsigned long mmio_offset;
  unsigned long ring_offset;
  unsigned long ring_rptr_offset;
  unsigned long buffers_offset;
  unsigned long gart_textures_offset;
} drm_radeon_init_t;
typedef struct drm_radeon_cp_stop {
  int flush;
  int idle;
} drm_radeon_cp_stop_t;
typedef struct drm_radeon_fullscreen {
  enum {
    RADEON_INIT_FULLSCREEN = 0x01,
    RADEON_CLEANUP_FULLSCREEN = 0x02
  } func;
} drm_radeon_fullscreen_t;
#define CLEAR_X1 0
#define CLEAR_Y1 1
#define CLEAR_X2 2
#define CLEAR_Y2 3
#define CLEAR_DEPTH 4
typedef union drm_radeon_clear_rect {
  float f[5];
  unsigned int ui[5];
} drm_radeon_clear_rect_t;
typedef struct drm_radeon_clear {
  unsigned int flags;
  unsigned int clear_color;
  unsigned int clear_depth;
  unsigned int color_mask;
  unsigned int depth_mask;
  drm_radeon_clear_rect_t  * depth_boxes;
} drm_radeon_clear_t;
typedef struct drm_radeon_vertex {
  int prim;
  int idx;
  int count;
  int discard;
} drm_radeon_vertex_t;
typedef struct drm_radeon_indices {
  int prim;
  int idx;
  int start;
  int end;
  int discard;
} drm_radeon_indices_t;
typedef struct drm_radeon_vertex2 {
  int idx;
  int discard;
  int nr_states;
  drm_radeon_state_t  * state;
  int nr_prims;
  drm_radeon_prim_t  * prim;
} drm_radeon_vertex2_t;
typedef struct drm_radeon_cmd_buffer {
  int bufsz;
  char  * buf;
  int nbox;
  struct drm_clip_rect  * boxes;
} drm_radeon_cmd_buffer_t;
typedef struct drm_radeon_tex_image {
  unsigned int x, y;
  unsigned int width, height;
  const void  * data;
} drm_radeon_tex_image_t;
typedef struct drm_radeon_texture {
  unsigned int offset;
  int pitch;
  int format;
  int width;
  int height;
  drm_radeon_tex_image_t  * image;
} drm_radeon_texture_t;
typedef struct drm_radeon_stipple {
  unsigned int  * mask;
} drm_radeon_stipple_t;
typedef struct drm_radeon_indirect {
  int idx;
  int start;
  int end;
  int discard;
} drm_radeon_indirect_t;
#define RADEON_CARD_PCI 0
#define RADEON_CARD_AGP 1
#define RADEON_CARD_PCIE 2
#define RADEON_PARAM_GART_BUFFER_OFFSET 1
#define RADEON_PARAM_LAST_FRAME 2
#define RADEON_PARAM_LAST_DISPATCH 3
#define RADEON_PARAM_LAST_CLEAR 4
#define RADEON_PARAM_IRQ_NR 5
#define RADEON_PARAM_GART_BASE 6
#define RADEON_PARAM_REGISTER_HANDLE 7
#define RADEON_PARAM_STATUS_HANDLE 8
#define RADEON_PARAM_SAREA_HANDLE 9
#define RADEON_PARAM_GART_TEX_HANDLE 10
#define RADEON_PARAM_SCRATCH_OFFSET 11
#define RADEON_PARAM_CARD_TYPE 12
#define RADEON_PARAM_VBLANK_CRTC 13
#define RADEON_PARAM_FB_LOCATION 14
#define RADEON_PARAM_NUM_GB_PIPES 15
#define RADEON_PARAM_DEVICE_ID 16
#define RADEON_PARAM_NUM_Z_PIPES 17
typedef struct drm_radeon_getparam {
  int param;
  void  * value;
} drm_radeon_getparam_t;
#define RADEON_MEM_REGION_GART 1
#define RADEON_MEM_REGION_FB 2
typedef struct drm_radeon_mem_alloc {
  int region;
  int alignment;
  int size;
  int  * region_offset;
} drm_radeon_mem_alloc_t;
typedef struct drm_radeon_mem_free {
  int region;
  int region_offset;
} drm_radeon_mem_free_t;
typedef struct drm_radeon_mem_init_heap {
  int region;
  int size;
  int start;
} drm_radeon_mem_init_heap_t;
typedef struct drm_radeon_irq_emit {
  int  * irq_seq;
} drm_radeon_irq_emit_t;
typedef struct drm_radeon_irq_wait {
  int irq_seq;
} drm_radeon_irq_wait_t;
typedef struct drm_radeon_setparam {
  unsigned int param;
  __s64 value;
} drm_radeon_setparam_t;
#define RADEON_SETPARAM_FB_LOCATION 1
#define RADEON_SETPARAM_SWITCH_TILING 2
#define RADEON_SETPARAM_PCIGART_LOCATION 3
#define RADEON_SETPARAM_NEW_MEMMAP 4
#define RADEON_SETPARAM_PCIGART_TABLE_SIZE 5
#define RADEON_SETPARAM_VBLANK_CRTC 6
typedef struct drm_radeon_surface_alloc {
  unsigned int address;
  unsigned int size;
  unsigned int flags;
} drm_radeon_surface_alloc_t;
typedef struct drm_radeon_surface_free {
  unsigned int address;
} drm_radeon_surface_free_t;
#define DRM_RADEON_VBLANK_CRTC1 1
#define DRM_RADEON_VBLANK_CRTC2 2
#define RADEON_GEM_DOMAIN_CPU 0x1
#define RADEON_GEM_DOMAIN_GTT 0x2
#define RADEON_GEM_DOMAIN_VRAM 0x4
struct drm_radeon_gem_info {
  __u64 gart_size;
  __u64 vram_size;
  __u64 vram_visible;
};
#define RADEON_GEM_NO_BACKING_STORE (1 << 0)
#define RADEON_GEM_GTT_UC (1 << 1)
#define RADEON_GEM_GTT_WC (1 << 2)
#define RADEON_GEM_CPU_ACCESS (1 << 3)
#define RADEON_GEM_NO_CPU_ACCESS (1 << 4)
struct drm_radeon_gem_create {
  __u64 size;
  __u64 alignment;
  __u32 handle;
  __u32 initial_domain;
  __u32 flags;
};
#define RADEON_GEM_USERPTR_READONLY (1 << 0)
#define RADEON_GEM_USERPTR_ANONONLY (1 << 1)
#define RADEON_GEM_USERPTR_VALIDATE (1 << 2)
#define RADEON_GEM_USERPTR_REGISTER (1 << 3)
struct drm_radeon_gem_userptr {
  __u64 addr;
  __u64 size;
  __u32 flags;
  __u32 handle;
};
#define RADEON_TILING_MACRO 0x1
#define RADEON_TILING_MICRO 0x2
#define RADEON_TILING_SWAP_16BIT 0x4
#define RADEON_TILING_SWAP_32BIT 0x8
#define RADEON_TILING_SURFACE 0x10
#define RADEON_TILING_MICRO_SQUARE 0x20
#define RADEON_TILING_EG_BANKW_SHIFT 8
#define RADEON_TILING_EG_BANKW_MASK 0xf
#define RADEON_TILING_EG_BANKH_SHIFT 12
#define RADEON_TILING_EG_BANKH_MASK 0xf
#define RADEON_TILING_EG_MACRO_TILE_ASPECT_SHIFT 16
#define RADEON_TILING_EG_MACRO_TILE_ASPECT_MASK 0xf
#define RADEON_TILING_EG_TILE_SPLIT_SHIFT 24
#define RADEON_TILING_EG_TILE_SPLIT_MASK 0xf
#define RADEON_TILING_EG_STENCIL_TILE_SPLIT_SHIFT 28
#define RADEON_TILING_EG_STENCIL_TILE_SPLIT_MASK 0xf
struct drm_radeon_gem_set_tiling {
  __u32 handle;
  __u32 tiling_flags;
  __u32 pitch;
};
struct drm_radeon_gem_get_tiling {
  __u32 handle;
  __u32 tiling_flags;
  __u32 pitch;
};
struct drm_radeon_gem_mmap {
  __u32 handle;
  __u32 pad;
  __u64 offset;
  __u64 size;
  __u64 addr_ptr;
};
struct drm_radeon_gem_set_domain {
  __u32 handle;
  __u32 read_domains;
  __u32 write_domain;
};
struct drm_radeon_gem_wait_idle {
  __u32 handle;
  __u32 pad;
};
struct drm_radeon_gem_busy {
  __u32 handle;
  __u32 domain;
};
struct drm_radeon_gem_pread {
  __u32 handle;
  __u32 pad;
  __u64 offset;
  __u64 size;
  __u64 data_ptr;
};
struct drm_radeon_gem_pwrite {
  __u32 handle;
  __u32 pad;
  __u64 offset;
  __u64 size;
  __u64 data_ptr;
};
struct drm_radeon_gem_op {
  __u32 handle;
  __u32 op;
  __u64 value;
};
#define RADEON_GEM_OP_GET_INITIAL_DOMAIN 0
#define RADEON_GEM_OP_SET_INITIAL_DOMAIN 1
#define RADEON_VA_MAP 1
#define RADEON_VA_UNMAP 2
#define RADEON_VA_RESULT_OK 0
#define RADEON_VA_RESULT_ERROR 1
#define RADEON_VA_RESULT_VA_EXIST 2
#define RADEON_VM_PAGE_VALID (1 << 0)
#define RADEON_VM_PAGE_READABLE (1 << 1)
#define RADEON_VM_PAGE_WRITEABLE (1 << 2)
#define RADEON_VM_PAGE_SYSTEM (1 << 3)
#define RADEON_VM_PAGE_SNOOPED (1 << 4)
struct drm_radeon_gem_va {
  __u32 handle;
  __u32 operation;
  __u32 vm_id;
  __u32 flags;
  __u64 offset;
};
#define RADEON_CHUNK_ID_RELOCS 0x01
#define RADEON_CHUNK_ID_IB 0x02
#define RADEON_CHUNK_ID_FLAGS 0x03
#define RADEON_CHUNK_ID_CONST_IB 0x04
#define RADEON_CS_KEEP_TILING_FLAGS 0x01
#define RADEON_CS_USE_VM 0x02
#define RADEON_CS_END_OF_FRAME 0x04
#define RADEON_CS_RING_GFX 0
#define RADEON_CS_RING_COMPUTE 1
#define RADEON_CS_RING_DMA 2
#define RADEON_CS_RING_UVD 3
#define RADEON_CS_RING_VCE 4
struct drm_radeon_cs_chunk {
  __u32 chunk_id;
  __u32 length_dw;
  __u64 chunk_data;
};
#define RADEON_RELOC_PRIO_MASK (0xf << 0)
struct drm_radeon_cs_reloc {
  __u32 handle;
  __u32 read_domains;
  __u32 write_domain;
  __u32 flags;
};
struct drm_radeon_cs {
  __u32 num_chunks;
  __u32 cs_id;
  __u64 chunks;
  __u64 gart_limit;
  __u64 vram_limit;
};
#define RADEON_INFO_DEVICE_ID 0x00
#define RADEON_INFO_NUM_GB_PIPES 0x01
#define RADEON_INFO_NUM_Z_PIPES 0x02
#define RADEON_INFO_ACCEL_WORKING 0x03
#define RADEON_INFO_CRTC_FROM_ID 0x04
#define RADEON_INFO_ACCEL_WORKING2 0x05
#define RADEON_INFO_TILING_CONFIG 0x06
#define RADEON_INFO_WANT_HYPERZ 0x07
#define RADEON_INFO_WANT_CMASK 0x08
#define RADEON_INFO_CLOCK_CRYSTAL_FREQ 0x09
#define RADEON_INFO_NUM_BACKENDS 0x0a
#define RADEON_INFO_NUM_TILE_PIPES 0x0b
#define RADEON_INFO_FUSION_GART_WORKING 0x0c
#define RADEON_INFO_BACKEND_MAP 0x0d
#define RADEON_INFO_VA_START 0x0e
#define RADEON_INFO_IB_VM_MAX_SIZE 0x0f
#define RADEON_INFO_MAX_PIPES 0x10
#define RADEON_INFO_TIMESTAMP 0x11
#define RADEON_INFO_MAX_SE 0x12
#define RADEON_INFO_MAX_SH_PER_SE 0x13
#define RADEON_INFO_FASTFB_WORKING 0x14
#define RADEON_INFO_RING_WORKING 0x15
#define RADEON_INFO_SI_TILE_MODE_ARRAY 0x16
#define RADEON_INFO_SI_CP_DMA_COMPUTE 0x17
#define RADEON_INFO_CIK_MACROTILE_MODE_ARRAY 0x18
#define RADEON_INFO_SI_BACKEND_ENABLED_MASK 0x19
#define RADEON_INFO_MAX_SCLK 0x1a
#define RADEON_INFO_VCE_FW_VERSION 0x1b
#define RADEON_INFO_VCE_FB_VERSION 0x1c
#define RADEON_INFO_NUM_BYTES_MOVED 0x1d
#define RADEON_INFO_VRAM_USAGE 0x1e
#define RADEON_INFO_GTT_USAGE 0x1f
#define RADEON_INFO_ACTIVE_CU_COUNT 0x20
#define RADEON_INFO_CURRENT_GPU_TEMP 0x21
#define RADEON_INFO_CURRENT_GPU_SCLK 0x22
#define RADEON_INFO_CURRENT_GPU_MCLK 0x23
#define RADEON_INFO_READ_REG 0x24
#define RADEON_INFO_VA_UNMAP_WORKING 0x25
#define RADEON_INFO_GPU_RESET_COUNTER 0x26
struct drm_radeon_info {
  __u32 request;
  __u32 pad;
  __u64 value;
};
#define SI_TILE_MODE_COLOR_LINEAR_ALIGNED 8
#define SI_TILE_MODE_COLOR_1D 13
#define SI_TILE_MODE_COLOR_1D_SCANOUT 9
#define SI_TILE_MODE_COLOR_2D_8BPP 14
#define SI_TILE_MODE_COLOR_2D_16BPP 15
#define SI_TILE_MODE_COLOR_2D_32BPP 16
#define SI_TILE_MODE_COLOR_2D_64BPP 17
#define SI_TILE_MODE_COLOR_2D_SCANOUT_16BPP 11
#define SI_TILE_MODE_COLOR_2D_SCANOUT_32BPP 12
#define SI_TILE_MODE_DEPTH_STENCIL_1D 4
#define SI_TILE_MODE_DEPTH_STENCIL_2D 0
#define SI_TILE_MODE_DEPTH_STENCIL_2D_2AA 3
#define SI_TILE_MODE_DEPTH_STENCIL_2D_4AA 3
#define SI_TILE_MODE_DEPTH_STENCIL_2D_8AA 2
#define CIK_TILE_MODE_DEPTH_STENCIL_1D 5
#ifdef __cplusplus
}
#endif
#endif

"""

```