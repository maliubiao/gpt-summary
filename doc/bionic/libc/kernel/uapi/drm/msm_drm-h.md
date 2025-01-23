Response:
Let's break down the thought process for analyzing this DRM header file.

**1. Initial Understanding & Context:**

* **File Location:**  The path `bionic/libc/kernel/uapi/drm/msm_drm.handroid` immediately tells us this is a kernel UAPI header. "uapi" means "userspace API,"  so it defines structures and constants that userspace programs interact with the kernel. The `drm` part signifies it's related to Direct Rendering Manager, a Linux subsystem for managing graphics hardware. `msm` likely refers to Qualcomm's Snapdragon mobile platforms, as they are prominent users of DRM on Android. `handroid` is a specific Qualcomm branch/variant. The `bionic` context reinforces that this is for Android's C library.

* **Purpose:** Header files define interfaces. This file specifically defines the interface between userspace (like Android apps or graphics drivers in userspace) and the Qualcomm MSM DRM kernel driver.

* **Auto-Generated:** The comment at the top is crucial. It warns that manual edits will be lost. This implies the definitions are likely generated from some other source of truth, probably a definition in the kernel driver itself.

**2. Decomposition and Analysis (Structure by Structure, Define by Define):**

* **Pipes (`MSM_PIPE_*`):** These constants clearly define different graphics processing units or pipelines within the MSM system. The bitwise operations (`MSM_PIPE_ID`, `MSM_PIPE_FLAGS`) suggest a way to extract information from a pipe identifier.

* **`drm_msm_timespec`:**  A standard time representation (seconds and nanoseconds). This is commonly used for timeouts and timing-related operations.

* **Parameters (`MSM_PARAM_*`, `drm_msm_param`):** This section is about querying and potentially setting various characteristics of the GPU. The `MSM_PARAM_*` defines a set of named parameters (GPU ID, memory size, frequency, etc.). The `drm_msm_param` structure defines how to pass the pipe, parameter ID, and a value (or buffer) related to that parameter to the kernel. The `len` field suggests some parameters might have variable-sized data.

* **Buffer Objects (`MSM_BO_*`, `drm_msm_gem_new`):**  This is fundamental to DRM. Buffer objects (BOs) are memory regions managed by the GPU. `MSM_BO_*` flags define properties of these buffers (scanout for display, read-only for GPU, caching policies). `drm_msm_gem_new` is the structure used to *create* new buffer objects, specifying their size and flags.

* **Buffer Object Information (`MSM_INFO_*`, `drm_msm_gem_info`):** This is about querying or setting metadata *about* existing buffer objects. You can get their offset, I/O virtual address (IOVA), and names, or set names and metadata.

* **CPU Preparation (`MSM_PREP_*`, `drm_msm_gem_cpu_prep`, `drm_msm_gem_cpu_fini`):** Before the CPU can access GPU memory, it often needs to be prepared. `MSM_PREP_*` flags define the type of access (read, write). `drm_msm_gem_cpu_prep` and `drm_msm_gem_cpu_fini` are structures for initiating and finalizing this preparation. The timeout is important for preventing deadlocks.

* **Submitting Commands (`drm_msm_gem_submit_reloc`, `MSM_SUBMIT_CMD_*`, `drm_msm_gem_submit_cmd`, `MSM_SUBMIT_BO_*`, `drm_msm_gem_submit_bo`, `MSM_SUBMIT_*`, `drm_msm_gem_submit_syncobj`, `drm_msm_gem_submit`):** This is the core of GPU interaction. This complex section deals with building and submitting command buffers to the GPU.
    * `drm_msm_gem_submit_reloc`: Describes how to relocate addresses within the command buffer.
    * `MSM_SUBMIT_CMD_*`: Defines different types of commands being submitted.
    * `drm_msm_gem_submit_cmd`:  Encapsulates a single command within the submission.
    * `MSM_SUBMIT_BO_*`:  Flags related to buffer objects used in the submission (read, write).
    * `drm_msm_gem_submit_bo`:  Associates a buffer object with the submission.
    * `MSM_SUBMIT_*`:  High-level flags for the overall submission (fences for synchronization, sudo for privileged operations).
    * `drm_msm_gem_submit_syncobj`:  Deals with synchronization objects for more fine-grained control over execution order.
    * `drm_msm_gem_submit`:  The main structure for submitting a batch of commands and buffer objects to the GPU.

* **Waiting for Fences (`MSM_WAIT_FENCE_*`, `drm_msm_wait_fence`):** Fences are kernel-managed synchronization primitives. Userspace can submit work and then wait for a fence to signal completion.

* **Memory Advising (`MSM_MADV_*`, `drm_msm_gem_madvise`):**  Similar to the standard `madvise` system call, this allows userspace to give hints to the kernel about how it intends to use memory, potentially improving performance.

* **Submit Queues (`MSM_SUBMITQUEUE_*`, `drm_msm_submitqueue`, `drm_msm_submitqueue_query`):** This introduces the concept of multiple command queues, allowing for prioritization and potentially better concurrency.

* **IOCTL Definitions (`DRM_MSM_*`):** These are the actual system call numbers used to communicate with the kernel driver. The `DRM_IOCTL_*` macros build the complete IOCTL numbers using `DRM_COMMAND_BASE` (defined elsewhere in DRM headers) and the specific `DRM_MSM_*` command codes. The `_IOWR`, `_IOW` macros specify the direction of data transfer (read/write).

**3. Connecting to Android:**

* **Graphics Stack:** Recognize that this is a low-level component of Android's graphics stack. SurfaceFlinger (the compositor), graphics drivers (in userspace), and even some NDK APIs will eventually interact with this interface.

* **Binder:**  While this header itself doesn't directly involve Binder, understand that Binder is the underlying IPC mechanism in Android. Higher-level graphics services use Binder to communicate with drivers.

* **NDK:**  The NDK exposes APIs that abstract away some of this complexity, but ultimately, the implementations rely on these lower-level DRM interfaces.

**4. Dynamic Linking (and why it's less prominent here):**

* **Kernel Interface:** This header defines a *kernel* interface. Kernel code is not dynamically linked in the same way as userspace libraries. The kernel driver is loaded directly by the operating system.

* **Userspace Libraries (Indirect Relation):** Userspace libraries that interact with this DRM interface *are* dynamically linked. For example, a vendor-specific graphics driver (`.so`) would link against standard libraries and make ioctl calls defined here.

* **Hypothetical Scenario:** Imagine a userspace library that wraps these DRM ioctls. It would be an `.so` file. The dynamic linker would resolve its dependencies (like `libc`).

**5. Common Errors:**

* **Incorrect Flag Usage:** Misunderstanding the purpose or combination of flags is a common mistake.

* **Handle Management:**  Forgetting to release buffer object handles or synchronization objects can lead to resource leaks.

* **Synchronization Issues:** Failing to properly synchronize access to shared GPU resources can cause corruption or crashes.

**6. Frida Hooking:**

* **IOCTL Interception:**  Frida is ideal for hooking system calls like `ioctl`. The examples focus on intercepting calls to specific `DRM_IOCTL_MSM_*` commands and inspecting the arguments.

**Self-Correction/Refinement During Analysis:**

* **Initial Oversimplification:**  Might initially think of it as just "graphics." Realize the broader implications for compute, display, and synchronization.

* **Depth of Explanation:**  Adjust the level of detail based on the prompt's requirements. Initially might skim over individual bitfields, then realize a more thorough explanation is needed.

* **Connecting the Dots:** Consciously try to link the low-level details to higher-level Android concepts (SurfaceFlinger, NDK).

By following this structured approach, we can systematically analyze the header file, understand its purpose, and connect it to the broader Android ecosystem. The key is to break down the information into manageable chunks and build up an understanding piece by piece.
这个头文件 `bionic/libc/kernel/uapi/drm/msm_drm.handroid` 定义了用户空间程序与 Qualcomm MSM (移动站调制解调器) 图形驱动程序进行交互的接口。它基于 Linux 的 Direct Rendering Manager (DRM) 子系统，并针对 Qualcomm 的 Adreno GPU 进行了扩展。

**功能列举:**

这个头文件定义了以下主要功能：

1. **管道 (Pipe) 定义:** 定义了不同的图形处理单元或管道，例如 `MSM_PIPE_2D0`, `MSM_PIPE_3D0` 等。这些用于指定操作的目标硬件单元。

2. **时间戳结构体 (`drm_msm_timespec`):** 定义了用于表示时间和超时时间的结构体，包含秒和纳秒。

3. **参数查询和设置 (`MSM_PARAM_*`, `drm_msm_param`):**  允许用户空间查询和设置 GPU 的各种参数，例如 GPU ID、全局内存大小、芯片 ID、最大频率、时间戳、全局内存基地址、优先级、页表地址、故障计数、挂起计数、系统 профилирование 数据、进程名、命令行参数、虚拟地址范围、最高内存 bank 位、光线追踪支持、UBWC 抖动模式和宏瓦片模式。

4. **缓冲区对象 (Buffer Object, BO) 管理 (`MSM_BO_*`, `drm_msm_gem_new`):**  定义了用于创建和管理 GPU 内存缓冲区的结构体和标志。这些缓冲区对象用于存储纹理、顶点数据和其他图形资源。标志位如 `MSM_BO_SCANOUT` 表明缓冲区用于显示输出，`MSM_BO_GPU_READONLY` 表明缓冲区只能被 GPU 读取，以及各种缓存策略 (`MSM_BO_CACHED`, `MSM_BO_WC`, `MSM_BO_UNCACHED`, `MSM_BO_CACHED_COHERENT`)。

5. **缓冲区对象信息查询和设置 (`MSM_INFO_*`, `drm_msm_gem_info`):**  允许查询和设置缓冲区对象的各种信息，例如偏移量、IO 虚拟地址 (IOVA)、名称、标志和元数据。

6. **CPU 访问准备和完成 (`MSM_PREP_*`, `drm_msm_gem_cpu_prep`, `drm_msm_gem_cpu_fini`):**  定义了用于准备 CPU 访问 GPU 缓冲区对象的结构体和标志。这涉及到缓存一致性管理。`MSM_PREP_READ` 和 `MSM_PREP_WRITE` 指定访问类型，`MSM_PREP_NOSYNC` 表明不需要同步。

7. **提交命令到 GPU (`drm_msm_gem_submit_reloc`, `MSM_SUBMIT_CMD_*`, `drm_msm_gem_submit_cmd`, `MSM_SUBMIT_BO_*`, `drm_msm_gem_submit_bo`, `MSM_SUBMIT_*`, `drm_msm_gem_submit_syncobj`, `drm_msm_gem_submit`):**  定义了用于构建和提交命令到 GPU 执行的结构体和标志。这包括命令缓冲区的类型 (`MSM_SUBMIT_CMD_BUF`)、缓冲区对象 (`drm_msm_gem_submit_bo`)、内存重定位信息 (`drm_msm_gem_submit_reloc`) 和各种提交标志 (`MSM_SUBMIT_BO_READ`, `MSM_SUBMIT_BO_WRITE`, `MSM_SUBMIT_FENCE_FD_IN`, `MSM_SUBMIT_FENCE_FD_OUT`)，用于控制数据读写、同步和权限。

8. **等待 GPU 执行完成 (`MSM_WAIT_FENCE_*`, `drm_msm_wait_fence`):**  定义了用于等待 GPU 完成特定操作的结构体和标志。这通常通过文件描述符形式的栅栏 (fence) 来实现。

9. **内存建议 (`MSM_MADV_*`, `drm_msm_gem_madvise`):**  允许用户空间向内核提供关于缓冲区对象使用方式的建议，例如 `MSM_MADV_WILLNEED` 和 `MSM_MADV_DONTNEED`，以帮助内核进行内存管理。

10. **提交队列管理 (`MSM_SUBMITQUEUE_*`, `drm_msm_submitqueue`, `drm_msm_submitqueue_query`):**  定义了用于创建、关闭和查询提交队列的结构体和标志。这允许将不同的命令流提交到不同的队列，可能用于实现优先级或并发控制。

11. **IOCTL 定义 (`DRM_MSM_*`, `DRM_IOCTL_MSM_*`):**  定义了用户空间与内核驱动程序通信所使用的 ioctl (输入/输出控制) 命令。每个功能都对应一个 ioctl 命令，例如 `DRM_IOCTL_MSM_GET_PARAM` 用于获取参数，`DRM_IOCTL_MSM_GEM_NEW` 用于创建新的 GEM (Graphics Execution Manager) 对象。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 图形栈的底层组成部分，直接关系到 Android 设备的图形渲染能力。

* **图形渲染:** Android 应用程序使用 OpenGL ES 或 Vulkan API 进行图形渲染。这些 API 的底层实现最终会通过 DRM 接口与 GPU 驱动程序交互。例如，当一个应用程序请求渲染一个三角形时，图形驱动程序会使用 `drm_msm_gem_new` 创建缓冲区对象来存储顶点数据，然后使用 `drm_msm_gem_submit` 将渲染命令提交到 GPU。

* **显示系统 (SurfaceFlinger):** Android 的 SurfaceFlinger 负责合成屏幕上所有可见的图层。它使用 DRM 接口来配置显示设备、管理帧缓冲区 (framebuffer) 以及进行垂直同步 (vsync)。例如，`MSM_BO_SCANOUT` 标志表明一个缓冲区对象被用作扫描输出，即直接显示到屏幕上。

* **视频解码和编码:** 硬件加速的视频解码和编码也经常使用 DRM 接口来管理视频帧缓冲区和提交解码/编码命令。

* **计算着色器 (Compute Shaders):**  Vulkan 等现代图形 API 允许使用 GPU 进行通用计算。这些计算任务也通过 DRM 接口提交到 GPU 执行。

**libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了数据结构和常量，用于与内核驱动程序交互。  用户空间的程序会使用标准 libc 函数（例如 `open`, `close`, `ioctl`）来打开 DRM 设备文件 (`/dev/dri/cardX`) 并调用定义的 ioctl 命令。

* **`open` 和 `close`:** 用于打开和关闭 DRM 设备文件，建立与内核驱动程序的连接。
* **`ioctl`:**  是与内核驱动程序通信的核心函数。用户空间程序会将一个 ioctl 命令码和指向数据结构的指针传递给 `ioctl`，内核驱动程序会根据命令码执行相应的操作。

**涉及 dynamic linker 的功能及处理过程:**

这个头文件定义的是内核接口，**本身不直接涉及 dynamic linker**。Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 的作用是加载和链接用户空间的共享库 (`.so` 文件)。

但是，**使用这个头文件的用户空间库** 会通过 dynamic linker 加载。

**so 布局样本:**

假设有一个名为 `libmsm_gpu.so` 的共享库，它使用了 `msm_drm.h` 中定义的接口：

```
libmsm_gpu.so:
    .text           # 包含代码段
    .rodata         # 包含只读数据
    .data           # 包含已初始化的数据
    .bss            # 包含未初始化的数据
    .dynamic        # 包含动态链接信息
        NEEDED      libc.so  # 依赖 libc.so
        NEEDED      libdl.so  # 依赖 libdl.so (如果使用了动态加载)
        SONAME      libmsm_gpu.so
        ...
    .dynsym         # 包含动态符号表
        ioctl
        DRM_IOCTL_MSM_GEM_NEW
        ...
    .dynstr         # 包含动态符号字符串表
        libc.so
        libdl.so
        ioctl
        DRM_IOCTL_MSM_GEM_NEW
        ...
    .rel.dyn        # 包含动态重定位信息 (例如，如何填充 `ioctl` 函数的地址)
        offset1: R_AARCH64_GLOB_DAT ioctl@LIBC
        offset2: R_AARCH64_ADR_PAGE DRM_IOCTL_MSM_GEM_NEW
        offset3: R_AARCH64_ADD_ABS_LO12_NC DRM_IOCTL_MSM_GEM_NEW
        ...
```

**链接的处理过程:**

1. **加载:** 当一个应用程序启动并加载 `libmsm_gpu.so` 时，dynamic linker 会读取其 `.dynamic` 段，找到其依赖的共享库（例如 `libc.so`）。

2. **查找依赖:** dynamic linker 会在预定义的路径中查找这些依赖库。

3. **加载依赖:** dynamic linker 会加载依赖库到内存中。

4. **符号解析:** dynamic linker 会解析 `libmsm_gpu.so` 中引用的外部符号。例如，当 `libmsm_gpu.so` 调用 `ioctl` 函数时，dynamic linker 会在已加载的 `libc.so` 中找到 `ioctl` 函数的地址，并将其填充到 `libmsm_gpu.so` 的相应位置（通过 `.rel.dyn` 段中的重定位信息）。

5. **重定位:** dynamic linker 会根据 `.rel.dyn` 段中的信息，调整 `libmsm_gpu.so` 中的地址和引用，使其指向正确的内存位置。例如，`DRM_IOCTL_MSM_GEM_NEW` 是一个宏，在编译时会被计算为一个常量，但其最终的值可能需要在加载时确定。

**假设输入与输出 (逻辑推理):**

假设我们想要创建一个新的 GPU 缓冲区对象：

**假设输入:**

* `fd`:  DRM 设备文件的文件描述符。
* `size`:  想要创建的缓冲区的大小 (例如，1024 字节)。
* `flags`:  缓冲区标志 (例如，`MSM_BO_CACHED`，表示使用缓存)。

**操作:**

1. 构造 `drm_msm_gem_new` 结构体：
   ```c
   struct drm_msm_gem_new req;
   req.size = 1024;
   req.flags = MSM_BO_CACHED;
   ```

2. 调用 `ioctl`：
   ```c
   if (ioctl(fd, DRM_IOCTL_MSM_GEM_NEW, &req) == 0) {
       // ioctl 调用成功，req.handle 中包含新缓冲区的句柄
       printf("成功创建缓冲区，句柄为: %u\n", req.handle);
   } else {
       perror("ioctl DRM_IOCTL_MSM_GEM_NEW 失败");
   }
   ```

**假设输出 (成功情况下):**

* `ioctl` 返回 0。
* `req.handle` 包含一个非零的整数，表示新创建的缓冲区对象的句柄。

**用户或编程常见的使用错误:**

1. **忘记打开 DRM 设备文件:**  在调用任何 DRM ioctl 之前，必须先使用 `open("/dev/dri/cardX", ...)` 打开 DRM 设备文件。

2. **使用错误的 ioctl 命令码:**  使用了与预期操作不符的 ioctl 命令码。例如，尝试使用 `DRM_IOCTL_MSM_GET_PARAM` 来创建缓冲区。

3. **传递不正确的数据结构:**  传递给 `ioctl` 的数据结构的大小或内容不符合 ioctl 命令的要求。例如，`drm_msm_gem_new` 结构体的 `size` 成员没有正确设置。

4. **资源泄漏:**  创建了缓冲区对象或其他资源 (例如提交队列)，但没有在不再使用时释放它们。缓冲区对象通常通过 `DRM_IOCTL_GEM_CLOSE` (在 `drm.h` 中定义，这里没有直接展示) 来释放。

5. **同步错误:**  在 GPU 操作完成之前就尝试访问或修改缓冲区对象，导致数据损坏或崩溃。需要使用栅栏或其他同步机制来确保操作的顺序。

6. **权限问题:**  用户没有访问 DRM 设备的权限。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 图形相关的操作通常从 Android Framework 的 Java 层开始，例如通过 `android.graphics.Surface` 或 `android.opengl.EGLSurface`。
   - 这些 Java 类的底层实现会调用 Native 代码。

2. **NDK (Native 代码):**
   - NDK 提供了 C/C++ 接口来访问 Android 的底层功能。
   - 例如，使用 OpenGL ES 的 NDK 应用会调用 `eglSwapBuffers` 来提交渲染结果到屏幕。
   - 或者，使用 Vulkan 的 NDK 应用会调用 Vulkan API 函数，例如 `vkQueueSubmit`。

3. **图形驱动程序 (Userspace):**
   - `eglSwapBuffers` 或 `vkQueueSubmit` 的底层实现会调用特定于硬件的图形驱动程序库 (通常是 `.so` 文件，由设备制造商提供)。

4. **DRM 接口调用:**
   - 图形驱动程序库会使用标准 libc 函数 (`open`, `ioctl`) 打开 DRM 设备文件，并调用 `msm_drm.h` 中定义的 ioctl 命令。
   - 例如，当需要创建一个用于渲染的缓冲区时，驱动程序会构造 `drm_msm_gem_new` 结构体，并调用 `ioctl(fd, DRM_IOCTL_MSM_GEM_NEW, ...)`。
   - 当需要提交渲染命令时，驱动程序会构造 `drm_msm_gem_submit` 结构体，并调用 `ioctl(fd, DRM_IOCTL_MSM_GEM_SUBMIT, ...)`。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida hook `DRM_IOCTL_MSM_GEM_NEW` 的示例：

```javascript
// hook_msm_gem_new.js

Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    if (request === 0xc0104d02) { // DRM_IOCTL_MSM_GEM_NEW 的值
      console.log("Detected DRM_IOCTL_MSM_GEM_NEW call");
      const argp = ptr(args[2]);
      const size = argp.readU64();
      const flags = argp.add(8).readU32();
      console.log("  File Descriptor:", fd);
      console.log("  Size:", size);
      console.log("  Flags:", flags.toString(16));
      // 可以进一步读取和解析结构体的其他成员
    }
  },
  onLeave: function (retval) {
    if (this.request === 0xc0104d02 && retval.toInt32() === 0) {
      const argp = ptr(this.args[2]);
      const handle = argp.add(12).readU32();
      console.log("  New GEM handle:", handle);
    }
  }
});
```

**使用 Frida 运行:**

1. **找到目标进程:**  确定要 hook 的进程的进程 ID 或进程名称。

2. **运行 Frida 命令:**
   ```bash
   frida -U -f <package_name> -l hook_msm_gem_new.js  # Hook 启动时附加
   # 或
   frida -U <process_name_or_pid> -l hook_msm_gem_new.js  # Hook 已运行的进程
   ```

**调试步骤解释:**

* **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 函数。`Module.findExportByName(null, "ioctl")` 在所有已加载的模块中查找 `ioctl` 函数的地址。
* **`onEnter`:**  在 `ioctl` 函数被调用时执行。
    * `args[0]` 是文件描述符。
    * `args[1]` 是 ioctl 命令码。
    * `args[2]` 是指向传递给 ioctl 的数据结构的指针。
    * `0xc0104d02` 是 `DRM_IOCTL_MSM_GEM_NEW` 的十六进制值。你需要根据你的 Android 版本和架构确定这个值。可以使用 `adb shell getconf _SC_IOCTL_MAX` 查看系统允许的最大 ioctl 值，并结合头文件中的定义来计算。
    * `ptr(args[2])` 将参数转换为 Frida 的 `NativePointer` 对象，方便读取内存。
    * `readU64()` 和 `readU32()` 读取结构体的成员。
* **`onLeave`:** 在 `ioctl` 函数返回时执行。
    * `retval` 是 `ioctl` 函数的返回值。
    * 如果 `ioctl` 调用成功 (`retval.toInt32() === 0`)，则读取新创建的 GEM 对象的句柄。

这个 Frida 示例可以帮助你观察应用程序如何使用 DRM 接口来创建 GPU 缓冲区对象，从而理解 Android 图形栈的运作方式。你可以修改这个脚本来 hook 其他的 DRM ioctl 命令，以深入了解不同的图形操作。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/drm/msm_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __MSM_DRM_H__
#define __MSM_DRM_H__
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MSM_PIPE_NONE 0x00
#define MSM_PIPE_2D0 0x01
#define MSM_PIPE_2D1 0x02
#define MSM_PIPE_3D0 0x10
#define MSM_PIPE_ID_MASK 0xffff
#define MSM_PIPE_ID(x) ((x) & MSM_PIPE_ID_MASK)
#define MSM_PIPE_FLAGS(x) ((x) & ~MSM_PIPE_ID_MASK)
struct drm_msm_timespec {
  __s64 tv_sec;
  __s64 tv_nsec;
};
#define MSM_PARAM_GPU_ID 0x01
#define MSM_PARAM_GMEM_SIZE 0x02
#define MSM_PARAM_CHIP_ID 0x03
#define MSM_PARAM_MAX_FREQ 0x04
#define MSM_PARAM_TIMESTAMP 0x05
#define MSM_PARAM_GMEM_BASE 0x06
#define MSM_PARAM_PRIORITIES 0x07
#define MSM_PARAM_PP_PGTABLE 0x08
#define MSM_PARAM_FAULTS 0x09
#define MSM_PARAM_SUSPENDS 0x0a
#define MSM_PARAM_SYSPROF 0x0b
#define MSM_PARAM_COMM 0x0c
#define MSM_PARAM_CMDLINE 0x0d
#define MSM_PARAM_VA_START 0x0e
#define MSM_PARAM_VA_SIZE 0x0f
#define MSM_PARAM_HIGHEST_BANK_BIT 0x10
#define MSM_PARAM_RAYTRACING 0x11
#define MSM_PARAM_UBWC_SWIZZLE 0x12
#define MSM_PARAM_MACROTILE_MODE 0x13
#define MSM_PARAM_NR_RINGS MSM_PARAM_PRIORITIES
struct drm_msm_param {
  __u32 pipe;
  __u32 param;
  __u64 value;
  __u32 len;
  __u32 pad;
};
#define MSM_BO_SCANOUT 0x00000001
#define MSM_BO_GPU_READONLY 0x00000002
#define MSM_BO_CACHE_MASK 0x000f0000
#define MSM_BO_CACHED 0x00010000
#define MSM_BO_WC 0x00020000
#define MSM_BO_UNCACHED 0x00040000
#define MSM_BO_CACHED_COHERENT 0x080000
#define MSM_BO_FLAGS (MSM_BO_SCANOUT | MSM_BO_GPU_READONLY | MSM_BO_CACHE_MASK)
struct drm_msm_gem_new {
  __u64 size;
  __u32 flags;
  __u32 handle;
};
#define MSM_INFO_GET_OFFSET 0x00
#define MSM_INFO_GET_IOVA 0x01
#define MSM_INFO_SET_NAME 0x02
#define MSM_INFO_GET_NAME 0x03
#define MSM_INFO_SET_IOVA 0x04
#define MSM_INFO_GET_FLAGS 0x05
#define MSM_INFO_SET_METADATA 0x06
#define MSM_INFO_GET_METADATA 0x07
struct drm_msm_gem_info {
  __u32 handle;
  __u32 info;
  __u64 value;
  __u32 len;
  __u32 pad;
};
#define MSM_PREP_READ 0x01
#define MSM_PREP_WRITE 0x02
#define MSM_PREP_NOSYNC 0x04
#define MSM_PREP_BOOST 0x08
#define MSM_PREP_FLAGS (MSM_PREP_READ | MSM_PREP_WRITE | MSM_PREP_NOSYNC | MSM_PREP_BOOST | 0)
struct drm_msm_gem_cpu_prep {
  __u32 handle;
  __u32 op;
  struct drm_msm_timespec timeout;
};
struct drm_msm_gem_cpu_fini {
  __u32 handle;
};
struct drm_msm_gem_submit_reloc {
  __u32 submit_offset;
#ifdef __cplusplus
  __u32 _or;
#else
  __u32 or;
#endif
  __s32 shift;
  __u32 reloc_idx;
  __u64 reloc_offset;
};
#define MSM_SUBMIT_CMD_BUF 0x0001
#define MSM_SUBMIT_CMD_IB_TARGET_BUF 0x0002
#define MSM_SUBMIT_CMD_CTX_RESTORE_BUF 0x0003
struct drm_msm_gem_submit_cmd {
  __u32 type;
  __u32 submit_idx;
  __u32 submit_offset;
  __u32 size;
  __u32 pad;
  __u32 nr_relocs;
  __u64 relocs;
};
#define MSM_SUBMIT_BO_READ 0x0001
#define MSM_SUBMIT_BO_WRITE 0x0002
#define MSM_SUBMIT_BO_DUMP 0x0004
#define MSM_SUBMIT_BO_NO_IMPLICIT 0x0008
#define MSM_SUBMIT_BO_FLAGS (MSM_SUBMIT_BO_READ | MSM_SUBMIT_BO_WRITE | MSM_SUBMIT_BO_DUMP | MSM_SUBMIT_BO_NO_IMPLICIT)
struct drm_msm_gem_submit_bo {
  __u32 flags;
  __u32 handle;
  __u64 presumed;
};
#define MSM_SUBMIT_NO_IMPLICIT 0x80000000
#define MSM_SUBMIT_FENCE_FD_IN 0x40000000
#define MSM_SUBMIT_FENCE_FD_OUT 0x20000000
#define MSM_SUBMIT_SUDO 0x10000000
#define MSM_SUBMIT_SYNCOBJ_IN 0x08000000
#define MSM_SUBMIT_SYNCOBJ_OUT 0x04000000
#define MSM_SUBMIT_FENCE_SN_IN 0x02000000
#define MSM_SUBMIT_FLAGS (MSM_SUBMIT_NO_IMPLICIT | MSM_SUBMIT_FENCE_FD_IN | MSM_SUBMIT_FENCE_FD_OUT | MSM_SUBMIT_SUDO | MSM_SUBMIT_SYNCOBJ_IN | MSM_SUBMIT_SYNCOBJ_OUT | MSM_SUBMIT_FENCE_SN_IN | 0)
#define MSM_SUBMIT_SYNCOBJ_RESET 0x00000001
#define MSM_SUBMIT_SYNCOBJ_FLAGS (MSM_SUBMIT_SYNCOBJ_RESET | 0)
struct drm_msm_gem_submit_syncobj {
  __u32 handle;
  __u32 flags;
  __u64 point;
};
struct drm_msm_gem_submit {
  __u32 flags;
  __u32 fence;
  __u32 nr_bos;
  __u32 nr_cmds;
  __u64 bos;
  __u64 cmds;
  __s32 fence_fd;
  __u32 queueid;
  __u64 in_syncobjs;
  __u64 out_syncobjs;
  __u32 nr_in_syncobjs;
  __u32 nr_out_syncobjs;
  __u32 syncobj_stride;
  __u32 pad;
};
#define MSM_WAIT_FENCE_BOOST 0x00000001
#define MSM_WAIT_FENCE_FLAGS (MSM_WAIT_FENCE_BOOST | 0)
struct drm_msm_wait_fence {
  __u32 fence;
  __u32 flags;
  struct drm_msm_timespec timeout;
  __u32 queueid;
};
#define MSM_MADV_WILLNEED 0
#define MSM_MADV_DONTNEED 1
#define __MSM_MADV_PURGED 2
struct drm_msm_gem_madvise {
  __u32 handle;
  __u32 madv;
  __u32 retained;
};
#define MSM_SUBMITQUEUE_FLAGS (0)
struct drm_msm_submitqueue {
  __u32 flags;
  __u32 prio;
  __u32 id;
};
#define MSM_SUBMITQUEUE_PARAM_FAULTS 0
struct drm_msm_submitqueue_query {
  __u64 data;
  __u32 id;
  __u32 param;
  __u32 len;
  __u32 pad;
};
#define DRM_MSM_GET_PARAM 0x00
#define DRM_MSM_SET_PARAM 0x01
#define DRM_MSM_GEM_NEW 0x02
#define DRM_MSM_GEM_INFO 0x03
#define DRM_MSM_GEM_CPU_PREP 0x04
#define DRM_MSM_GEM_CPU_FINI 0x05
#define DRM_MSM_GEM_SUBMIT 0x06
#define DRM_MSM_WAIT_FENCE 0x07
#define DRM_MSM_GEM_MADVISE 0x08
#define DRM_MSM_SUBMITQUEUE_NEW 0x0A
#define DRM_MSM_SUBMITQUEUE_CLOSE 0x0B
#define DRM_MSM_SUBMITQUEUE_QUERY 0x0C
#define DRM_IOCTL_MSM_GET_PARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_GET_PARAM, struct drm_msm_param)
#define DRM_IOCTL_MSM_SET_PARAM DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_SET_PARAM, struct drm_msm_param)
#define DRM_IOCTL_MSM_GEM_NEW DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_GEM_NEW, struct drm_msm_gem_new)
#define DRM_IOCTL_MSM_GEM_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_GEM_INFO, struct drm_msm_gem_info)
#define DRM_IOCTL_MSM_GEM_CPU_PREP DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_GEM_CPU_PREP, struct drm_msm_gem_cpu_prep)
#define DRM_IOCTL_MSM_GEM_CPU_FINI DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_GEM_CPU_FINI, struct drm_msm_gem_cpu_fini)
#define DRM_IOCTL_MSM_GEM_SUBMIT DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_GEM_SUBMIT, struct drm_msm_gem_submit)
#define DRM_IOCTL_MSM_WAIT_FENCE DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_WAIT_FENCE, struct drm_msm_wait_fence)
#define DRM_IOCTL_MSM_GEM_MADVISE DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_GEM_MADVISE, struct drm_msm_gem_madvise)
#define DRM_IOCTL_MSM_SUBMITQUEUE_NEW DRM_IOWR(DRM_COMMAND_BASE + DRM_MSM_SUBMITQUEUE_NEW, struct drm_msm_submitqueue)
#define DRM_IOCTL_MSM_SUBMITQUEUE_CLOSE DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_SUBMITQUEUE_CLOSE, __u32)
#define DRM_IOCTL_MSM_SUBMITQUEUE_QUERY DRM_IOW(DRM_COMMAND_BASE + DRM_MSM_SUBMITQUEUE_QUERY, struct drm_msm_submitqueue_query)
#ifdef __cplusplus
}
#endif
#endif
```