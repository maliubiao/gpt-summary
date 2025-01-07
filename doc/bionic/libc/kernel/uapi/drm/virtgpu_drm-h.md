Response:
Let's break down the thought process for analyzing this header file and generating the comprehensive response.

**1. Understanding the Context:**

The initial prompt clearly states the file's location within the Android Bionic library, specifically related to the `virtgpu` DRM driver. This immediately tells us we're dealing with low-level graphics, virtualization, and kernel interactions. The "auto-generated" comment suggests this file is likely derived from a more fundamental definition (perhaps in the kernel source itself).

**2. High-Level Functionality Identification:**

The `#define` statements prefixed with `DRM_VIRTGPU_` are the most obvious starting point. These define the various operations that can be performed on the `virtgpu` device. Listing these out and briefly describing their names (MAP, EXECBUFFER, GETPARAM, etc.) is the first step in understanding the file's purpose.

**3. Connecting to Android:**

The prompt explicitly asks about the connection to Android. Knowing this is a DRM driver for a virtual GPU, the immediate connection is to the Android graphics stack. Concepts like virtualization (for emulators, containers, or even potentially security sandboxing), OpenGL/Vulkan APIs (which rely on DRM for device access), and SurfaceFlinger (for display composition) come to mind. Thinking about how a guest OS running on Android might use a virtual GPU is also relevant.

**4. Analyzing Data Structures:**

The `struct` definitions are crucial for understanding how data is exchanged with the kernel driver. For each struct:

* **Identify its purpose:** What operation is it associated with? (e.g., `drm_virtgpu_map` is for memory mapping).
* **Analyze its members:** What information does it contain?  What are the data types?  Are there any specific flags or constants related to its members?  For example, `__u64 offset`, `__u32 handle`, etc., in `drm_virtgpu_map` suggest mapping a buffer object.
* **Look for related `#define` constants:**  Constants like `VIRTGPU_EXECBUF_FENCE_FD_IN` provide context and flags for the struct members.

**5. Examining IOCTLs:**

The `#define DRM_IOCTL_VIRTGPU_...` lines define the ioctl commands. This is the mechanism user-space code uses to communicate with the kernel driver. For each ioctl:

* **Identify the associated operation:** Match it to the `DRM_VIRTGPU_` defines.
* **Note the data structure:** The ioctl definition includes the corresponding struct, which dictates the data passed to the kernel.
* **Understand the direction (IOWR):**  `DRM_IOWR` indicates data is being written to the kernel.

**6. Addressing Specific Prompt Requirements:**

* **Libc Function Explanation:**  The header itself doesn't *define* libc functions. However, the interaction *involves* libc functions, particularly `ioctl()`. The explanation should focus on how `ioctl()` is used in this context. Since the header is about kernel interaction, functions like `open()`, `close()`, and `mmap()` are also relevant.
* **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. *However*, the libraries that *use* this header (like graphics drivers) *do*. The explanation needs to clarify this distinction and provide a general overview of how the dynamic linker works and how shared libraries are loaded. A sample `so` layout and linking process explanation are needed.
* **Logical Reasoning (Assumptions and Input/Output):** For each major operation (like `EXECBUFFER`), consider a plausible scenario. What data would a user-space application provide as input, and what would it expect as output (or side-effects)? This helps illustrate how the structures and ioctls are used in practice.
* **User/Programming Errors:**  Think about common mistakes developers might make when using these low-level interfaces. Examples include incorrect struct sizes, invalid handles, or misuse of flags.
* **Android Framework/NDK Path:**  Trace the high-level path from an Android application to this header file. Start with application code using graphics APIs, then go through the Android framework layers (like SurfaceFlinger or hardware abstraction layers), and finally reach the kernel DRM driver.
* **Frida Hook Example:** Provide a practical example of how Frida could be used to intercept and inspect the ioctl calls, demonstrating a common debugging/reverse engineering technique. Focus on hooking the `ioctl` function and printing the command and relevant data structures.

**7. Structuring the Response:**

Organize the information logically using headings and subheadings. Start with a general overview, then delve into specifics for each functional area (operations, structs, ioctls). Address each point of the prompt systematically.

**8. Refining and Elaborating:**

After the initial draft, review and refine the explanations. Ensure clarity, accuracy, and completeness. Provide enough detail without being overly verbose. For example, when explaining `ioctl()`, briefly mention its purpose and parameters. When discussing the dynamic linker, provide a simplified explanation of the linking process.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file defines operations on a GPU."  **Refinement:** "It's for a *virtual* GPU, which adds the layer of virtualization to consider."
* **Initial thought:** "Just list the functions." **Refinement:** "Explain *how* these functions relate to Android's graphics system."
* **Initial thought:** "Explain every detail of the dynamic linker." **Refinement:** "Focus on the key concepts relevant to how libraries that use this header are loaded."
* **Initial thought:** "Provide a very complex Frida script." **Refinement:** "Keep the Frida example simple and focused on demonstrating the interception of `ioctl` calls."

By following these steps and constantly refining the understanding and explanation, a comprehensive and accurate response can be generated. The key is to start with the obvious, progressively analyze the details, and always keep the context of Android and the user's questions in mind.
这个文件 `virtgpu_drm.h` 定义了用于与虚拟 GPU (virtgpu) 设备进行交互的接口。它位于 Android Bionic 库的内核头文件路径下，这意味着它定义了用户空间程序（例如 Android Framework 或 NDK 开发的应用程序）如何通过系统调用与 Linux 内核中的 virtgpu DRM (Direct Rendering Manager) 驱动进行通信。

让我们详细列举一下它的功能，并解答你的所有问题：

**1. 功能概述:**

这个头文件定义了以下主要功能，这些功能都是通过 ioctl 系统调用来实现的：

* **内存映射 (DRM_VIRTGPU_MAP):** 允许用户空间进程将虚拟 GPU 设备内存的一部分映射到自己的地址空间。这使得可以直接访问 GPU 内存，而无需额外的复制操作。
* **执行命令缓冲区 (DRM_VIRTGPU_EXECBUFFER):**  用于向虚拟 GPU 提交命令缓冲区以执行。这些命令通常包含 GPU 指令，用于图形渲染或其他计算任务。
* **获取参数 (DRM_VIRTGPU_GETPARAM):**  查询虚拟 GPU 的各种参数和功能，例如支持的 3D 特性、能力集等。
* **创建资源 (DRM_VIRTGPU_RESOURCE_CREATE):**  在虚拟 GPU 上创建图形资源，例如纹理、渲染目标等。
* **获取资源信息 (DRM_VIRTGPU_RESOURCE_INFO):**  获取已创建资源的详细信息，例如其分配的缓冲区对象 (bo_handle) 和大小。
* **主机到设备数据传输 (DRM_VIRTGPU_TRANSFER_FROM_HOST):** 将数据从主机（CPU 内存）传输到虚拟 GPU 资源。
* **设备到主机数据传输 (DRM_VIRTGPU_TRANSFER_TO_HOST):** 将数据从虚拟 GPU 资源传输到主机（CPU 内存）。
* **等待事件 (DRM_VIRTGPU_WAIT):**  等待虚拟 GPU 完成特定的操作，例如命令缓冲区的执行。
* **获取能力 (DRM_VIRTGPU_GET_CAPS):**  获取虚拟 GPU 的更详细的能力信息，允许查询特定能力集及其版本。
* **创建 BLOB 资源 (DRM_VIRTGPU_RESOURCE_CREATE_BLOB):**  创建基于 BLOB (Binary Large Object) 的资源，这可以用于传递更复杂的数据结构或固件。
* **初始化上下文 (DRM_VIRTGPU_CONTEXT_INIT):**  初始化虚拟 GPU 的执行上下文，可以用于隔离不同任务的执行环境。

**2. 与 Android 功能的关系及举例:**

virtgpu DRM 驱动是 Android 图形栈的关键组成部分，尤其在以下场景中：

* **Android 模拟器 (Emulator):**  Android 模拟器通常使用虚拟 GPU 来模拟真实设备的图形硬件。`virtgpu_drm.h` 中定义的功能是模拟器中 guest 系统 (模拟的 Android 系统) 与 host 系统 (运行模拟器的系统) 之间的图形交互接口。例如，模拟器中的应用调用 OpenGL ES API 进行渲染时，最终会通过这些 ioctl 调用与 host 上的图形驱动进行交互。
* **容器化环境 (Containerization):** 在某些容器化 Android 环境中，可能会使用虚拟 GPU 来提供图形加速。
* **安全虚拟化 (Secure Virtualization):**  为了安全隔离，可能会使用虚拟 GPU 来限制对物理 GPU 的直接访问。

**举例说明:**

假设一个 Android 应用使用 OpenGL ES 绘制一个三角形。这个过程可能涉及以下步骤：

1. **应用调用 OpenGL ES API:**  例如 `glDrawArrays()`.
2. **Android Framework 的图形栈处理:**  例如 SurfaceFlinger 或一个渲染库会将 OpenGL ES 命令转换为底层的 GPU 命令。
3. **Binder 调用:**  这些命令可能需要通过 Binder IPC 传递到 system_server 进程中的 SurfaceFlinger 或其他图形服务。
4. **ioctl 调用:**  图形服务最终会使用 `ioctl()` 系统调用，并传入 `virtgpu_drm.h` 中定义的常量和结构体，与内核中的 virtgpu DRM 驱动进行交互。例如，可能使用 `DRM_IOCTL_VIRTGPU_EXECBUFFER` 提交包含绘制三角形指令的命令缓冲区。

**3. libc 函数的功能实现:**

这个头文件本身并没有定义或实现 libc 函数。它定义的是与内核驱动交互的接口。用户空间程序会使用 libc 提供的系统调用接口（例如 `ioctl`）来使用这里定义的常量和结构体。

**`ioctl()` 函数的实现简述:**

`ioctl()` 是一个通用的 Linux 系统调用，用于设备特定的控制操作。它的实现涉及以下步骤：

1. **系统调用入口:** 当用户空间程序调用 `ioctl()` 时，会触发一个系统调用异常，进入内核态。
2. **系统调用处理函数:** 内核会根据系统调用号 (在 `ioctl()` 的情况下) 调用相应的内核处理函数。
3. **设备驱动程序的分发:** `ioctl()` 的第二个参数 (`request`) 通常用于标识要执行的具体操作。内核会根据这个请求值以及与文件描述符关联的设备驱动程序，将请求分发到相应的设备驱动程序中的 `ioctl` 函数。
4. **设备驱动程序处理:**  对于 `virtgpu` 设备，内核会将 `ioctl` 调用分发到 virtgpu DRM 驱动的 `ioctl` 函数。该函数会根据 `request` 值（例如 `DRM_IOCTL_VIRTGPU_EXECBUFFER`）执行相应的操作，例如将命令缓冲区提交到 GPU。
5. **数据传输:** `ioctl()` 的第三个参数 (`argp`) 是一个指向用户空间内存的指针，用于传递参数给驱动程序或接收驱动程序的返回值。内核需要小心处理用户空间指针，以避免安全问题。
6. **返回用户空间:** 设备驱动程序处理完成后，会将结果返回给内核，内核再将结果返回给用户空间的调用者。

**4. 涉及 dynamic linker 的功能和 so 布局样本及链接处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。但是，使用这个头文件的库（例如图形库）通常是动态链接库 (`.so` 文件)。

**so 布局样本:**

一个使用 virtgpu DRM 的图形库的 `.so` 文件可能包含以下部分：

* **.text 段:**  包含库的代码指令。这些代码会调用 `ioctl()` 并使用 `virtgpu_drm.h` 中定义的常量和结构体。
* **.data 段:**  包含已初始化的全局变量和静态变量。
* **.bss 段:**  包含未初始化的全局变量和静态变量。
* **.rodata 段:**  包含只读数据，例如字符串常量。
* **.dynsym 段:**  包含动态符号表，列出库导出的和需要导入的符号（函数和变量）。
* **.dynstr 段:**  包含动态符号表中使用的字符串。
* **.plt/.got 段:**  用于延迟绑定（Lazy Binding）的程序链接表 (PLT) 和全局偏移表 (GOT)。
* **其他段:**  例如调试信息、重定位信息等。

**链接的处理过程:**

1. **编译时链接:**  当编译使用该图形库的应用程序时，编译器会生成包含对库中函数的未解析引用的目标文件。
2. **动态链接器 (ld-linux.so):**  当应用程序启动时，内核会加载程序的入口点，然后控制权转移到动态链接器。
3. **加载依赖库:**  动态链接器会解析应用程序的依赖关系，并加载所有需要的共享库到内存中。这包括使用 virtgpu DRM 的图形库。
4. **符号解析:**  动态链接器会遍历所有加载的共享库的动态符号表，解析应用程序中未解析的符号引用。例如，如果应用程序调用了图形库中的一个函数，动态链接器会找到该函数在库中的地址。
5. **重定位:**  动态链接器会修改代码和数据段中的地址，以便它们指向正确的内存位置。这包括更新 GOT 表中的条目，使其指向已解析的函数地址。
6. **执行应用程序:**  当所有依赖库都加载并链接完成后，动态链接器会将控制权转移到应用程序的入口点。

**5. 逻辑推理、假设输入与输出:**

**假设输入 (DRM_IOCTL_VIRTGPU_EXECBUFFER):**

一个应用程序想要提交一个渲染三角形的命令缓冲区。

* **`flags`:**  可能设置为 0。
* **`size`:**  命令缓冲区的大小，取决于 GPU 指令的长度。
* **`command`:**  指向用户空间分配的内存，其中包含实际的 GPU 指令。这些指令的格式由具体的虚拟 GPU 架构定义。
* **`bo_handles`:**  指向一个数组，包含渲染所需的 buffer object 的句柄，例如顶点缓冲区、索引缓冲区。
* **`num_bo_handles`:**  `bo_handles` 数组的元素个数。
* **`fence_fd`:**  如果需要同步，可以设置为一个 fence 文件描述符。
* **其他字段:**  可能为 0 或根据具体需求设置。

**预期输出 (DRM_IOCTL_VIRTGPU_EXECBUFFER):**

* 如果成功，`ioctl()` 调用返回 0。
* 虚拟 GPU 开始执行命令缓冲区中的指令。
* 如果设置了 `fence_fd`，当命令缓冲区执行完毕后，该 fence 会被 signaled。
* 如果发生错误（例如无效的句柄、内存不足），`ioctl()` 调用返回 -1，并设置 `errno` 错误码。

**6. 用户或编程常见的使用错误:**

* **传递错误的结构体大小:**  在 `ioctl()` 调用中，内核需要知道传递的结构体的大小。如果用户空间传递的结构体大小与内核期望的不一致，可能会导致数据解析错误或安全问题。
* **使用无效的句柄:**  例如，传递一个未创建或已销毁的 buffer object 句柄。
* **错误的内存映射:**  在 `DRM_IOCTL_VIRTGPU_MAP` 中指定错误的偏移量或大小，可能导致访问越界或程序崩溃。
* **忘记同步:**  在多个命令缓冲区之间缺乏适当的同步机制，可能导致数据竞争和渲染错误。
* **不正确的命令缓冲区格式:**  提交到 `DRM_IOCTL_VIRTGPU_EXECBUFFER` 的命令缓冲区必须符合虚拟 GPU 的指令格式。格式错误会导致 GPU 执行失败。
* **资源泄漏:**  创建了资源但忘记释放，例如通过 `DRM_IOCTL_VIRTGPU_RESOURCE_CREATE` 创建了资源，但程序退出前没有相应的释放操作。

**7. Android Framework 或 NDK 如何到达这里，以及 Frida hook 示例:**

**路径:**

1. **NDK 应用 (C/C++) 或 Framework 应用 (Java/Kotlin):**  用户编写的应用代码调用图形 API，例如 OpenGL ES 或 Vulkan。
2. **图形 API 库 (e.g., libGLESv2.so, libvulkan.so):**  这些库将高级 API 调用转换为更底层的 GPU 命令。
3. **Hardware Abstraction Layer (HAL) (e.g., gralloc, hardware composer):**  HAL 提供了一个标准接口，供 Android Framework 与特定的硬件驱动进行交互。对于图形，HAL 包括 gralloc (用于分配图形缓冲区) 和 hardware composer (用于管理显示)。
4. **DRM 框架 (Direct Rendering Manager):**  Android 使用 Linux DRM 框架来管理 GPU 资源和进行渲染。
5. **virtgpu DRM 驱动 (内核模块):**  这是负责与虚拟 GPU 硬件进行交互的内核模块。`virtgpu_drm.h` 中定义的接口正是用户空间与这个驱动通信的桥梁。
6. **ioctl 系统调用:**  图形库或 HAL 组件会使用 `ioctl()` 系统调用，并携带 `virtgpu_drm.h` 中定义的常量和结构体，来与 virtgpu DRM 驱动进行交互。

**Frida Hook 示例:**

以下是一个使用 Frida hook `ioctl` 系统调用来观察与 virtgpu DRM 驱动交互的示例：

```javascript
// Frida 脚本

const ioctlPtr = Module.findExportByName(null, "ioctl");

if (ioctlPtr) {
  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();

      // 检查文件描述符是否与 /dev/dri/renderD* 或 /dev/dri/card* 相关，
      // 这通常是 DRM 设备的路径
      const pathBuf = Memory.allocUtf8String(256);
      const readlinkResult = syscall(Process.constants.SYS_readlinkat, Process.constants.AT_FDCWD, "/proc/self/fd/" + fd, pathBuf, 256);
      if (readlinkResult.retval.toInt32() > 0) {
        const path = pathBuf.readUtf8String();
        if (path.startsWith("/dev/dri/renderD") || path.startsWith("/dev/dri/card")) {
          console.log("ioctl called with fd:", fd, "request:", request.toString(16));

          // 检查是否是 virtgpu 相关的 ioctl
          if ((request & 0xff) >= 0x80 && (request & 0xff) <= 0x8f) { // virtgpu ioctl range
            console.log("Potential virtgpu ioctl detected!");

            // 根据 request 值，尝试解析参数 (需要根据 virtgpu_drm.h 中的定义)
            if (request === 0xc0186481) { // DRM_IOCTL_VIRTGPU_EXECBUFFER
              const argp = this.context.r2; // 或根据架构使用不同的寄存器
              if (argp) {
                const execbuffer = ptr(argp);
                const flags = execbuffer.readU32();
                const size = execbuffer.add(4).readU32();
                const command = execbuffer.add(8).readU64();
                console.log("  DRM_IOCTL_VIRTGPU_EXECBUFFER");
                console.log("    flags:", flags);
                console.log("    size:", size);
                console.log("    command:", command);
                // 继续解析其他字段...
              }
            } else if (request === 0xc0106400) { // DRM_IOCTL_VIRTGPU_MAP
                const argp = this.context.r2;
                if (argp) {
                    const mapData = ptr(argp);
                    const offset = mapData.readU64();
                    const handle = mapData.add(8).readU32();
                    console.log("  DRM_IOCTL_VIRTGPU_MAP");
                    console.log("    offset:", offset);
                    console.log("    handle:", handle);
                }
            }
            // 添加其他 virtgpu ioctl 的解析...
          }
        }
      }
    },
    onLeave: function (retval) {
      // console.log("ioctl returned:", retval.toInt32());
    },
  });
} else {
  console.error("Could not find ioctl function");
}
```

**解释:**

1. **`Module.findExportByName(null, "ioctl")`:** 找到 `ioctl` 函数的地址。
2. **`Interceptor.attach(...)`:**  Hook `ioctl` 函数的入口和出口。
3. **`onEnter`:** 在 `ioctl` 函数调用前执行。
4. **检查文件描述符:**  通过 `/proc/self/fd/` 检查文件描述符是否指向 DRM 设备。
5. **检查请求值:**  判断 `request` 是否在 virtgpu DRM 的 ioctl 范围内。
6. **解析参数:**  根据 `request` 值和 `virtgpu_drm.h` 中定义的结构体，读取并打印 ioctl 的参数。你需要根据具体的 `request` 值来解析 `argp` 指向的数据。
7. **`onLeave`:** 在 `ioctl` 函数返回后执行 (可选)。

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_virtgpu.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l hook_virtgpu.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <进程名或 PID> -l hook_virtgpu.js
   ```

这个 Frida 脚本会拦截所有对 `ioctl` 的调用，并尝试识别与 virtgpu DRM 相关的调用，然后打印出相关的参数信息，帮助你调试和理解 Android 图形栈的工作原理。你需要根据你要调试的具体场景，扩展脚本以解析更多的 ioctl 命令和结构体。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/virtgpu_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef VIRTGPU_DRM_H
#define VIRTGPU_DRM_H
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_VIRTGPU_MAP 0x01
#define DRM_VIRTGPU_EXECBUFFER 0x02
#define DRM_VIRTGPU_GETPARAM 0x03
#define DRM_VIRTGPU_RESOURCE_CREATE 0x04
#define DRM_VIRTGPU_RESOURCE_INFO 0x05
#define DRM_VIRTGPU_TRANSFER_FROM_HOST 0x06
#define DRM_VIRTGPU_TRANSFER_TO_HOST 0x07
#define DRM_VIRTGPU_WAIT 0x08
#define DRM_VIRTGPU_GET_CAPS 0x09
#define DRM_VIRTGPU_RESOURCE_CREATE_BLOB 0x0a
#define DRM_VIRTGPU_CONTEXT_INIT 0x0b
#define VIRTGPU_EXECBUF_FENCE_FD_IN 0x01
#define VIRTGPU_EXECBUF_FENCE_FD_OUT 0x02
#define VIRTGPU_EXECBUF_RING_IDX 0x04
#define VIRTGPU_EXECBUF_FLAGS (VIRTGPU_EXECBUF_FENCE_FD_IN | VIRTGPU_EXECBUF_FENCE_FD_OUT | VIRTGPU_EXECBUF_RING_IDX | 0)
struct drm_virtgpu_map {
  __u64 offset;
  __u32 handle;
  __u32 pad;
};
#define VIRTGPU_EXECBUF_SYNCOBJ_RESET 0x01
#define VIRTGPU_EXECBUF_SYNCOBJ_FLAGS (VIRTGPU_EXECBUF_SYNCOBJ_RESET | 0)
struct drm_virtgpu_execbuffer_syncobj {
  __u32 handle;
  __u32 flags;
  __u64 point;
};
struct drm_virtgpu_execbuffer {
  __u32 flags;
  __u32 size;
  __u64 command;
  __u64 bo_handles;
  __u32 num_bo_handles;
  __s32 fence_fd;
  __u32 ring_idx;
  __u32 syncobj_stride;
  __u32 num_in_syncobjs;
  __u32 num_out_syncobjs;
  __u64 in_syncobjs;
  __u64 out_syncobjs;
};
#define VIRTGPU_PARAM_3D_FEATURES 1
#define VIRTGPU_PARAM_CAPSET_QUERY_FIX 2
#define VIRTGPU_PARAM_RESOURCE_BLOB 3
#define VIRTGPU_PARAM_HOST_VISIBLE 4
#define VIRTGPU_PARAM_CROSS_DEVICE 5
#define VIRTGPU_PARAM_CONTEXT_INIT 6
#define VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs 7
#define VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME 8
struct drm_virtgpu_getparam {
  __u64 param;
  __u64 value;
};
struct drm_virtgpu_resource_create {
  __u32 target;
  __u32 format;
  __u32 bind;
  __u32 width;
  __u32 height;
  __u32 depth;
  __u32 array_size;
  __u32 last_level;
  __u32 nr_samples;
  __u32 flags;
  __u32 bo_handle;
  __u32 res_handle;
  __u32 size;
  __u32 stride;
};
struct drm_virtgpu_resource_info {
  __u32 bo_handle;
  __u32 res_handle;
  __u32 size;
  __u32 blob_mem;
};
struct drm_virtgpu_3d_box {
  __u32 x;
  __u32 y;
  __u32 z;
  __u32 w;
  __u32 h;
  __u32 d;
};
struct drm_virtgpu_3d_transfer_to_host {
  __u32 bo_handle;
  struct drm_virtgpu_3d_box box;
  __u32 level;
  __u32 offset;
  __u32 stride;
  __u32 layer_stride;
};
struct drm_virtgpu_3d_transfer_from_host {
  __u32 bo_handle;
  struct drm_virtgpu_3d_box box;
  __u32 level;
  __u32 offset;
  __u32 stride;
  __u32 layer_stride;
};
#define VIRTGPU_WAIT_NOWAIT 1
struct drm_virtgpu_3d_wait {
  __u32 handle;
  __u32 flags;
};
struct drm_virtgpu_get_caps {
  __u32 cap_set_id;
  __u32 cap_set_ver;
  __u64 addr;
  __u32 size;
  __u32 pad;
};
struct drm_virtgpu_resource_create_blob {
#define VIRTGPU_BLOB_MEM_GUEST 0x0001
#define VIRTGPU_BLOB_MEM_HOST3D 0x0002
#define VIRTGPU_BLOB_MEM_HOST3D_GUEST 0x0003
#define VIRTGPU_BLOB_FLAG_USE_MAPPABLE 0x0001
#define VIRTGPU_BLOB_FLAG_USE_SHAREABLE 0x0002
#define VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE 0x0004
  __u32 blob_mem;
  __u32 blob_flags;
  __u32 bo_handle;
  __u32 res_handle;
  __u64 size;
  __u32 pad;
  __u32 cmd_size;
  __u64 cmd;
  __u64 blob_id;
};
#define VIRTGPU_CONTEXT_PARAM_CAPSET_ID 0x0001
#define VIRTGPU_CONTEXT_PARAM_NUM_RINGS 0x0002
#define VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK 0x0003
#define VIRTGPU_CONTEXT_PARAM_DEBUG_NAME 0x0004
struct drm_virtgpu_context_set_param {
  __u64 param;
  __u64 value;
};
struct drm_virtgpu_context_init {
  __u32 num_params;
  __u32 pad;
  __u64 ctx_set_params;
};
#define VIRTGPU_EVENT_FENCE_SIGNALED 0x90000000
#define DRM_IOCTL_VIRTGPU_MAP DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_MAP, struct drm_virtgpu_map)
#define DRM_IOCTL_VIRTGPU_EXECBUFFER DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_EXECBUFFER, struct drm_virtgpu_execbuffer)
#define DRM_IOCTL_VIRTGPU_GETPARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_GETPARAM, struct drm_virtgpu_getparam)
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_RESOURCE_CREATE, struct drm_virtgpu_resource_create)
#define DRM_IOCTL_VIRTGPU_RESOURCE_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_RESOURCE_INFO, struct drm_virtgpu_resource_info)
#define DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_TRANSFER_FROM_HOST, struct drm_virtgpu_3d_transfer_from_host)
#define DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_TRANSFER_TO_HOST, struct drm_virtgpu_3d_transfer_to_host)
#define DRM_IOCTL_VIRTGPU_WAIT DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_WAIT, struct drm_virtgpu_3d_wait)
#define DRM_IOCTL_VIRTGPU_GET_CAPS DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_GET_CAPS, struct drm_virtgpu_get_caps)
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_RESOURCE_CREATE_BLOB, struct drm_virtgpu_resource_create_blob)
#define DRM_IOCTL_VIRTGPU_CONTEXT_INIT DRM_IOWR(DRM_COMMAND_BASE + DRM_VIRTGPU_CONTEXT_INIT, struct drm_virtgpu_context_init)
#ifdef __cplusplus
}
#endif
#endif

"""

```