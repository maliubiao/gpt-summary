Response:
Let's break down the thought process for analyzing this AMDGPU DRM header file.

1. **Understanding the Context:** The first crucial step is recognizing where this file comes from: `bionic/libc/kernel/uapi/drm/amdgpu_drm.handroid`. This immediately tells us several things:
    * **Bionic:** This is part of Android's core C library. This implies the file is related to how Android interacts with low-level kernel features.
    * **libc:** Specifically, it's within the C library, suggesting it defines interfaces for C/C++ code to use.
    * **kernel/uapi:**  This indicates that it's a header file meant to be used by *userspace* (the "u" in uapi) to interact with the *kernel* (DRM subsystem). It defines the structures and constants for system calls or ioctls.
    * **drm:** This stands for Direct Rendering Manager. It's a Linux kernel subsystem that allows userspace programs to directly control graphics hardware.
    * **amdgpu_drm.h:**  This pinpoints the specific driver: AMD GPUs. The `.h` confirms it's a header file.
    * **.handroid:** This suffix is a good clue that this is a modified or specific version of the AMDGPU DRM header for Android.

2. **Initial Scan for Key Features:**  A quick scan reveals common patterns in kernel header files:
    * **`#ifndef`, `#define`, `#endif`:**  Standard include guards to prevent multiple inclusions.
    * **`#include "drm.h"`:**  Indicates a dependency on the base DRM header file.
    * **`#ifdef __cplusplus extern "C" { ... } #endif`:** Allows this header to be used in both C and C++ code.
    * **`#define` statements:** A large number of these define constants. These are likely used as command codes, flags, or bitmasks for interacting with the AMDGPU driver.
    * **`struct` and `union` definitions:** These define the data structures used to pass information between userspace and the kernel via ioctls.
    * **`DRM_IOCTL_AMDGPU_*` macros:** These define the specific ioctl numbers that userspace programs will use. The `DRM_IOWR` and `DRM_IOW` macros hint at the direction of data flow (write, read, or both).

3. **Categorizing Functionality based on Constants and Structures:** Now, let's organize the information:

    * **GEM (Graphics Execution Manager):**  The prefixes `DRM_AMDGPU_GEM_*` and constants like `AMDGPU_GEM_CREATE`, `AMDGPU_GEM_MMAP`, etc., clearly relate to memory management on the GPU. This includes creating, mapping, waiting for idle, and operating on GPU memory objects (GEM objects or "buffers").

    * **Context Management:** `DRM_AMDGPU_CTX` and related constants (`AMDGPU_CTX_OP_ALLOC_CTX`, `AMDGPU_CTX_PRIORITY_*`) deal with creating and managing execution contexts on the GPU. Priorities are important for scheduling.

    * **Buffer Objects (BOs):** `DRM_AMDGPU_BO_LIST` and `AMDGPU_BO_LIST_OP_*` suggest the ability to manage lists of buffer objects, likely for efficient command submission.

    * **Command Submission (CS):** `DRM_AMDGPU_CS` and `AMDGPU_CHUNK_ID_*` are central to submitting command buffers to the GPU for execution. The chunk IDs indicate different types of data within the command stream (IBs, fences, dependencies, etc.).

    * **Virtual Memory (VM):** `DRM_AMDGPU_VM` and `AMDGPU_VM_OP_*` relate to managing the GPU's virtual address space.

    * **Fences:** `DRM_AMDGPU_WAIT_FENCES` and `DRM_AMDGPU_FENCE_TO_HANDLE` are about synchronization, allowing the CPU to wait for the GPU to complete certain tasks. Fences are used as signaling mechanisms.

    * **Scheduling:** `DRM_AMDGPU_SCHED` allows for overriding the priority of processes or contexts.

    * **Information Retrieval:** `DRM_AMDGPU_INFO` and the numerous `AMDGPU_INFO_*` constants provide ways to query the GPU's capabilities, status, firmware versions, memory usage, and other information.

    * **User Pointers:** `DRM_AMDGPU_GEM_USERPTR` allows registering user-space memory for direct GPU access.

    * **Metadata:** `DRM_AMDGPU_GEM_METADATA` deals with associating metadata with GEM objects, like tiling information.

4. **Connecting to Android:** The "`.handroid`" suffix is a strong indicator of Android-specific modifications. The fact that it's in `bionic/libc` confirms its role in Android's low-level system. Android's graphics stack (SurfaceFlinger, Vulkan drivers, OpenGL ES drivers) relies on the DRM subsystem to interact with the GPU. This header provides the necessary definitions for those Android components to talk to the AMDGPU kernel driver.

5. **libc Function Explanation (Focus on `ioctl`):** The core libc function involved here is `ioctl`. This system call allows userspace programs to send control commands and data to device drivers in the kernel. The `DRM_IOCTL_AMDGPU_*` macros expand to `_IOWR`, `_IOW`, etc., which are ultimately used to build the ioctl request number. The `union` definitions paired with these ioctls define the data structures passed to the `ioctl` system call.

6. **Dynamic Linker (Less Relevant Here, but still a thought):** While this specific header file doesn't directly *define* dynamic linker functionality, it's part of Bionic. Android's dynamic linker (`linker64` or `linker`) loads shared libraries (`.so` files) into process memory. Graphics drivers (like the AMDGPU driver) are often implemented as shared libraries. So, the Android graphics stack components that *use* this header file will be loaded by the dynamic linker.

7. **User Errors:**  Common errors would involve:
    * **Incorrect `ioctl` numbers:** Using the wrong constant.
    * **Incorrect data structures:**  Passing incorrectly sized or formatted data to the ioctl.
    * **Invalid handles:** Trying to operate on a GEM object or context that hasn't been created or has been destroyed.
    * **Permissions issues:** Not having the necessary permissions to access the DRM device.
    * **Logic errors:** Incorrectly sequencing operations or misunderstanding the semantics of the ioctls.

8. **Framework/NDK Path:** The journey from the Android framework or NDK to this header file goes something like this:
    * **Application (Java/Kotlin or Native):** An app wants to render graphics.
    * **Android Framework (SurfaceFlinger, etc.):** Uses the graphics APIs (Vulkan, OpenGL ES).
    * **NDK Libraries (libvulkan.so, libGLESv2.so, etc.):**  These libraries implement the APIs and internally use the DRM.
    * **Vendor Graphics Driver (AMDGPU DRM Kernel Module and Userspace Library):** The NDK libraries make ioctl calls using the definitions from this header file to communicate with the AMDGPU kernel driver.

9. **Frida Hooking:**  Frida can be used to intercept the `ioctl` calls made by the NDK libraries. This allows observing the ioctl numbers and the data being passed, helping to understand how the Android graphics stack interacts with the AMDGPU driver.

Essentially, the process is about dissecting the code, understanding its components, and then connecting those components to the larger Android ecosystem and the underlying Linux kernel. The "`.handroid`" suffix served as a crucial starting point, indicating the Android connection.
这是一个位于 `bionic/libc/kernel/uapi/drm/amdgpu_drm.handroid` 的 C 头文件，它是 Android Bionic C 库的一部分，专门用于定义与 AMD GPU Direct Rendering Manager (DRM) 子系统交互的接口。这个文件并非实现代码，而是定义了用户空间程序与 AMDGPU 内核驱动程序通信所需的常量、数据结构和ioctl命令。

**它的功能：**

这个头文件的主要功能是定义了：

1. **IOCTL 命令宏:**  例如 `DRM_IOCTL_AMDGPU_GEM_CREATE`，这些宏定义了用户空间程序可以通过 `ioctl` 系统调用发送给 AMDGPU 内核驱动的命令。每个宏都对应着一个特定的操作，例如创建 GEM 对象、内存映射等。
2. **常量定义:**  定义了各种与 AMDGPU 相关的常量，例如：
    * **GEM 对象操作类型:** `AMDGPU_GEM_CREATE`, `AMDGPU_GEM_MMAP` 等，用于指定 GEM 对象的操作。
    * **上下文操作类型:** `AMDGPU_CTX_OP_ALLOC_CTX`, `AMDGPU_CTX_OP_FREE_CTX` 等，用于管理 GPU 执行上下文。
    * **内存域:** `AMDGPU_GEM_DOMAIN_CPU`, `AMDGPU_GEM_DOMAIN_GTT`, `AMDGPU_GEM_DOMAIN_VRAM` 等，用于指定内存分配的位置。
    * **GEM 对象创建标志:** `AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED`, `AMDGPU_GEM_CREATE_NO_CPU_ACCESS` 等，用于控制 GEM 对象的属性。
    * **各种标志位:**  用于控制各种操作的行为，例如同步、缓存策略等。
    * **硬件 IP 类型:** `AMDGPU_HW_IP_GFX`, `AMDGPU_HW_IP_COMPUTE` 等，用于标识不同的 GPU 硬件模块。
    * **信息查询类型:** `AMDGPU_INFO_ACCEL_WORKING`, `AMDGPU_INFO_FW_VERSION` 等，用于查询 GPU 的状态和信息。
3. **数据结构定义:** 定义了用于与内核驱动程序交换数据的结构体，例如：
    * `struct drm_amdgpu_gem_create_in/out`: 用于创建 GEM 对象的输入和输出参数。
    * `struct drm_amdgpu_bo_list_in/out`: 用于管理 Buffer Object (BO) 列表。
    * `struct drm_amdgpu_cs_in/out`: 用于提交命令流 (Command Submission)。
    * `struct drm_amdgpu_info`: 用于查询 GPU 的各种信息。
    * 其他各种用于特定 IOCTL 命令的输入/输出结构体。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android 图形栈与底层 AMD GPU 硬件交互的关键桥梁。Android 设备如果使用 AMD GPU，其图形驱动程序就需要利用这些定义与内核进行通信。

**举例：**

* **SurfaceFlinger 和 GPU 缓冲区管理:** 当 Android 的 SurfaceFlinger 需要分配一块 GPU 缓冲区来显示内容时，它会通过底层图形库 (例如 Vulkan 或 OpenGL ES 驱动) 调用 `ioctl`，并使用 `DRM_IOCTL_AMDGPU_GEM_CREATE` 命令，同时填充 `struct drm_amdgpu_gem_create_in` 结构体来指定缓冲区的大小、对齐方式和内存域等。内核驱动程序会根据这些参数分配 GPU 内存，并返回一个 GEM 句柄 (`handle`)。
* **Vulkan 驱动程序提交渲染命令:**  Vulkan 驱动程序会将渲染命令打包成命令流，然后使用 `DRM_IOCTL_AMDGPU_CS` 命令通过 `ioctl` 提交给内核。命令流的数据会放在 `struct drm_amdgpu_cs_in` 结构体中指定的内存区域。
* **查询 GPU 信息:**  Android 框架或驱动程序可能需要查询 GPU 的固件版本、内存使用情况等。它们会使用 `DRM_IOCTL_AMDGPU_INFO` 命令，并填充 `struct drm_amdgpu_info` 结构体来指定要查询的信息类型 (`query`)。内核驱动程序会将查询结果写回到 `return_pointer` 指向的内存区域。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身不包含任何 libc 函数的实现。它只是定义了与内核交互的接口。真正进行系统调用的是 libc 提供的 `ioctl` 函数。

**`ioctl` 函数的功能和实现：**

`ioctl` (input/output control) 是一个 Linux 系统调用，允许用户空间程序向设备驱动程序发送控制命令和数据，或从驱动程序接收数据。

**实现过程 (简化描述)：**

1. **用户空间调用 `ioctl(fd, request, ...)`:**
   - `fd`:  是打开的设备文件的文件描述符，例如 `/dev/dri/card0`，对应着 AMDGPU 设备。
   - `request`:  是一个与驱动程序相关的请求代码，通常由 `DRM_IOCTL_AMDGPU_*` 宏展开得到。这个代码标识了要执行的具体操作。
   - `...`:  可选的参数，通常是一个指向数据结构的指针，用于向驱动程序传递输入参数或接收输出结果。

2. **内核处理 `ioctl` 调用:**
   - 当用户空间程序调用 `ioctl` 时，内核会根据 `fd` 找到对应的设备驱动程序 (AMDGPU 驱动)。
   - 内核会根据 `request` 代码调用驱动程序中相应的 `ioctl` 处理函数。
   - AMDGPU 驱动程序的 `ioctl` 处理函数会解析 `request` 代码，并根据传入的数据结构执行相应的操作，例如分配 GPU 内存、提交命令等。
   - 如果有输出数据，驱动程序会将结果写入到用户空间传递的数据结构中。

3. **`ioctl` 返回:**
   - 内核驱动程序完成操作后，`ioctl` 系统调用会返回到用户空间。返回值通常表示操作是否成功。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker 主要负责加载和链接共享库 (`.so` 文件)。然而，使用这个头文件的代码通常位于共享库中，例如 AMDGPU 的用户空间驱动库 (可能是 Vulkan 或 OpenGL ES 的一部分)。

**so 布局样本 (假设为一个名为 `amdgpu_drv.so` 的库):**

```
amdgpu_drv.so:
    .text          # 代码段，包含函数实现
    .rodata        # 只读数据段，包含常量
    .data          # 已初始化数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表 (针对数据段)
    .rel.plt       # 动态重定位表 (针对过程链接表)
    ...           # 其他段
```

**链接的处理过程 (简化描述)：**

1. **编译时链接:** 当编译依赖 AMDGPU 驱动的应用程序或库时，编译器会将对 AMDGPU 相关函数的调用生成符号引用。
2. **动态链接时加载:**  当应用程序启动时，Android 的 dynamic linker (`linker64` 或 `linker`) 会负责加载所需的共享库，包括 `amdgpu_drv.so`。
3. **符号解析和重定位:** Dynamic linker 会遍历 `amdgpu_drv.so` 的动态符号表 (`.dynsym`)，找到程序中引用的 AMDGPU 相关符号的地址。然后，它会根据重定位表 (`.rel.dyn` 和 `.rel.plt`) 修改代码和数据段中对这些符号的引用，使其指向正确的地址。
4. **建立链接:**  通过符号解析和重定位，dynamic linker 将应用程序的代码与 `amdgpu_drv.so` 中的代码链接起来，使得应用程序可以调用 AMDGPU 驱动提供的功能。

**如果做了逻辑推理，请给出假设输入与输出：**

假设用户空间程序想要创建一个 4MB 的 GPU 缓冲区，并且希望 CPU 可以访问它。

**假设输入 (传递给 `ioctl` 的数据结构):**

```c
struct drm_amdgpu_gem_create create_params;
create_params.in.bo_size = 4 * 1024 * 1024; // 4MB
create_params.in.alignment = 4096;        // 通常的页对齐
create_params.in.domains = AMDGPU_GEM_DOMAIN_GTT; // 从 GTT 域分配，CPU 可访问
create_params.in.domain_flags = 0;
```

**假设输出 (`ioctl` 返回，并且 `create_params` 的 `out` 字段被填充):**

```
ioctl() 返回值: 0 (表示成功)

create_params.out.handle:  // 一个非零的整数，表示新创建的 GEM 对象的句柄
```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **使用错误的 IOCTL 命令号:** 例如，误将 `DRM_IOCTL_AMDGPU_GEM_MMAP` 用于创建 GEM 对象。这将导致内核驱动程序无法识别该命令，并返回错误。
2. **填充数据结构错误:** 例如，在创建 GEM 对象时，将 `bo_size` 设置为负数或零。内核驱动程序会进行参数校验，并返回错误。
3. **传递无效的句柄:**  尝试对一个已经释放的 GEM 对象或上下文执行操作。内核驱动程序会检查句柄的有效性，并返回错误。
4. **权限不足:**  如果用户没有访问 `/dev/dri/cardX` 设备的权限，`ioctl` 调用将会失败，返回权限错误。
5. **忘记处理错误:**  用户空间程序在调用 `ioctl` 后，应该检查其返回值，以确保操作成功。忽略错误可能导致程序行为异常或崩溃。
6. **不正确的内存管理:**  例如，在 `mmap` 之后忘记 `munmap` 映射的内存，或者在释放 GEM 对象之前忘记取消映射。这可能导致资源泄漏。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达这里的步骤 (以 Vulkan 为例):**

1. **Application (Java/Kotlin/C++):**  应用程序使用 Vulkan API 进行图形渲染。
2. **NDK Vulkan Library (`libvulkan.so`):** 应用程序的 Vulkan API 调用会被转发到 NDK 提供的 `libvulkan.so` 库。
3. **Vendor Vulkan Driver (AMDGPU Vulkan Driver):** `libvulkan.so` 会加载特定于硬件的 Vulkan 驱动程序，这通常是 AMDGPU 提供的用户空间驱动库。
4. **驱动程序内部的 `ioctl` 调用:** AMDGPU Vulkan 驱动程序在内部需要与内核驱动程序交互，例如分配 GPU 内存、提交渲染命令等。它会使用 libc 的 `ioctl` 函数，并使用 `amdgpu_drm.handroid` 中定义的宏和数据结构。
5. **Kernel AMDGPU Driver:** 内核接收到 `ioctl` 调用，并执行相应的操作。

**Frida Hook 示例:**

假设我们想 hook `ioctl` 调用，查看当 Vulkan 分配 GPU 内存时传递给内核的参数。

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
    pid = device.spawn(["<your_app_package_name>"]) # 替换为你的应用包名
    process = device.attach(pid)
    device.resume(pid)

    session = process.attach(pid)

    script_source = """
    Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查是否是 AMDGPU 相关的 IOCTL
            if ((request & 0xff) >= 0xa0 && (request & 0xff) <= 0xbf) {
                console.log("[*] ioctl called");
                console.log("[*] File Descriptor:", fd);
                console.log("[*] Request Code:", request.toString(16));

                // 尝试解析 GEM 创建相关的 IOCTL
                if (request == 0xc0104400) { // DRM_IOCTL_AMDGPU_GEM_CREATE 的值
                    const argp = this.context.sp.add(Process.pointerSize * 2); // 假设参数在栈上的位置
                    const create_params_ptr = Memory.readPointer(argp);
                    const bo_size = Memory.readU64(create_params_ptr);
                    const alignment = Memory.readU64(create_params_ptr.add(8));
                    const domains = Memory.readU64(create_params_ptr.add(16));
                    console.log("[*]   bo_size:", bo_size.toString());
                    console.log("[*]   alignment:", alignment.toString());
                    console.log("[*]   domains:", domains.toString(16));
                }
            }
        },
        onLeave: function(retval) {
            // console.log("[*] ioctl returned:", retval);
        }
    });
    """
    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print("错误：找不到指定的进程。")
except Exception as e:
    print(f"发生错误: {e}")
```

**代码解释:**

1. **连接到目标进程:** 使用 Frida 连接到目标 Android 应用程序的进程。
2. **Hook `ioctl` 函数:**  使用 `Interceptor.attach` 拦截 `libc.so` 中的 `ioctl` 函数。
3. **检查 AMDGPU IOCTL:** 在 `onEnter` 中，检查 `request` 代码是否在 AMDGPU IOCTL 的范围内 (通常以 `0xa0` 到 `0xbf` 开头)。
4. **解析 GEM 创建参数:** 如果 `request` 代码是 `DRM_IOCTL_AMDGPU_GEM_CREATE`，则尝试读取传递给 `ioctl` 的 `struct drm_amdgpu_gem_create` 结构体的成员，例如 `bo_size`, `alignment`, `domains`。 **注意:** 这里假设了参数在栈上的位置，实际情况可能需要根据架构和调用约定进行调整。
5. **打印信息:** 将拦截到的信息打印到控制台。

**使用步骤:**

1. 确保你的 Android 设备已连接并通过 `adb` 可访问。
2. 安装 Frida 和 Frida 的 Python 绑定。
3. 将 `<your_app_package_name>` 替换为你要调试的应用程序的包名。
4. 运行 Frida 脚本。
5. 在 Android 设备上运行目标应用程序，并执行触发 GPU 内存分配的操作 (例如，启动一个使用 Vulkan 渲染的 Activity)。
6. 查看 Frida 的输出，你将会看到拦截到的 `ioctl` 调用以及 GEM 创建相关的参数。

这个 Frida 示例提供了一个基本的框架，你可以根据需要修改和扩展它，以 hook 其他 AMDGPU 相关的 IOCTL 命令，并分析传递的数据。请注意，直接读取栈上的参数可能不稳定，更可靠的方法是分析汇编代码，确定参数传递的方式。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/amdgpu_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __AMDGPU_DRM_H__
#define __AMDGPU_DRM_H__
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_AMDGPU_GEM_CREATE 0x00
#define DRM_AMDGPU_GEM_MMAP 0x01
#define DRM_AMDGPU_CTX 0x02
#define DRM_AMDGPU_BO_LIST 0x03
#define DRM_AMDGPU_CS 0x04
#define DRM_AMDGPU_INFO 0x05
#define DRM_AMDGPU_GEM_METADATA 0x06
#define DRM_AMDGPU_GEM_WAIT_IDLE 0x07
#define DRM_AMDGPU_GEM_VA 0x08
#define DRM_AMDGPU_WAIT_CS 0x09
#define DRM_AMDGPU_GEM_OP 0x10
#define DRM_AMDGPU_GEM_USERPTR 0x11
#define DRM_AMDGPU_WAIT_FENCES 0x12
#define DRM_AMDGPU_VM 0x13
#define DRM_AMDGPU_FENCE_TO_HANDLE 0x14
#define DRM_AMDGPU_SCHED 0x15
#define DRM_IOCTL_AMDGPU_GEM_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_CREATE, union drm_amdgpu_gem_create)
#define DRM_IOCTL_AMDGPU_GEM_MMAP DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_MMAP, union drm_amdgpu_gem_mmap)
#define DRM_IOCTL_AMDGPU_CTX DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_CTX, union drm_amdgpu_ctx)
#define DRM_IOCTL_AMDGPU_BO_LIST DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_BO_LIST, union drm_amdgpu_bo_list)
#define DRM_IOCTL_AMDGPU_CS DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_CS, union drm_amdgpu_cs)
#define DRM_IOCTL_AMDGPU_INFO DRM_IOW(DRM_COMMAND_BASE + DRM_AMDGPU_INFO, struct drm_amdgpu_info)
#define DRM_IOCTL_AMDGPU_GEM_METADATA DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_METADATA, struct drm_amdgpu_gem_metadata)
#define DRM_IOCTL_AMDGPU_GEM_WAIT_IDLE DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_WAIT_IDLE, union drm_amdgpu_gem_wait_idle)
#define DRM_IOCTL_AMDGPU_GEM_VA DRM_IOW(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_VA, struct drm_amdgpu_gem_va)
#define DRM_IOCTL_AMDGPU_WAIT_CS DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_WAIT_CS, union drm_amdgpu_wait_cs)
#define DRM_IOCTL_AMDGPU_GEM_OP DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_OP, struct drm_amdgpu_gem_op)
#define DRM_IOCTL_AMDGPU_GEM_USERPTR DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_GEM_USERPTR, struct drm_amdgpu_gem_userptr)
#define DRM_IOCTL_AMDGPU_WAIT_FENCES DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_WAIT_FENCES, union drm_amdgpu_wait_fences)
#define DRM_IOCTL_AMDGPU_VM DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_VM, union drm_amdgpu_vm)
#define DRM_IOCTL_AMDGPU_FENCE_TO_HANDLE DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDGPU_FENCE_TO_HANDLE, union drm_amdgpu_fence_to_handle)
#define DRM_IOCTL_AMDGPU_SCHED DRM_IOW(DRM_COMMAND_BASE + DRM_AMDGPU_SCHED, union drm_amdgpu_sched)
#define AMDGPU_GEM_DOMAIN_CPU 0x1
#define AMDGPU_GEM_DOMAIN_GTT 0x2
#define AMDGPU_GEM_DOMAIN_VRAM 0x4
#define AMDGPU_GEM_DOMAIN_GDS 0x8
#define AMDGPU_GEM_DOMAIN_GWS 0x10
#define AMDGPU_GEM_DOMAIN_OA 0x20
#define AMDGPU_GEM_DOMAIN_DOORBELL 0x40
#define AMDGPU_GEM_DOMAIN_MASK (AMDGPU_GEM_DOMAIN_CPU | AMDGPU_GEM_DOMAIN_GTT | AMDGPU_GEM_DOMAIN_VRAM | AMDGPU_GEM_DOMAIN_GDS | AMDGPU_GEM_DOMAIN_GWS | AMDGPU_GEM_DOMAIN_OA | AMDGPU_GEM_DOMAIN_DOORBELL)
#define AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED (1 << 0)
#define AMDGPU_GEM_CREATE_NO_CPU_ACCESS (1 << 1)
#define AMDGPU_GEM_CREATE_CPU_GTT_USWC (1 << 2)
#define AMDGPU_GEM_CREATE_VRAM_CLEARED (1 << 3)
#define AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS (1 << 5)
#define AMDGPU_GEM_CREATE_VM_ALWAYS_VALID (1 << 6)
#define AMDGPU_GEM_CREATE_EXPLICIT_SYNC (1 << 7)
#define AMDGPU_GEM_CREATE_CP_MQD_GFX9 (1 << 8)
#define AMDGPU_GEM_CREATE_VRAM_WIPE_ON_RELEASE (1 << 9)
#define AMDGPU_GEM_CREATE_ENCRYPTED (1 << 10)
#define AMDGPU_GEM_CREATE_PREEMPTIBLE (1 << 11)
#define AMDGPU_GEM_CREATE_DISCARDABLE (1 << 12)
#define AMDGPU_GEM_CREATE_COHERENT (1 << 13)
#define AMDGPU_GEM_CREATE_UNCACHED (1 << 14)
#define AMDGPU_GEM_CREATE_EXT_COHERENT (1 << 15)
#define AMDGPU_GEM_CREATE_GFX12_DCC (1 << 16)
struct drm_amdgpu_gem_create_in {
  __u64 bo_size;
  __u64 alignment;
  __u64 domains;
  __u64 domain_flags;
};
struct drm_amdgpu_gem_create_out {
  __u32 handle;
  __u32 _pad;
};
union drm_amdgpu_gem_create {
  struct drm_amdgpu_gem_create_in in;
  struct drm_amdgpu_gem_create_out out;
};
#define AMDGPU_BO_LIST_OP_CREATE 0
#define AMDGPU_BO_LIST_OP_DESTROY 1
#define AMDGPU_BO_LIST_OP_UPDATE 2
struct drm_amdgpu_bo_list_in {
  __u32 operation;
  __u32 list_handle;
  __u32 bo_number;
  __u32 bo_info_size;
  __u64 bo_info_ptr;
};
struct drm_amdgpu_bo_list_entry {
  __u32 bo_handle;
  __u32 bo_priority;
};
struct drm_amdgpu_bo_list_out {
  __u32 list_handle;
  __u32 _pad;
};
union drm_amdgpu_bo_list {
  struct drm_amdgpu_bo_list_in in;
  struct drm_amdgpu_bo_list_out out;
};
#define AMDGPU_CTX_OP_ALLOC_CTX 1
#define AMDGPU_CTX_OP_FREE_CTX 2
#define AMDGPU_CTX_OP_QUERY_STATE 3
#define AMDGPU_CTX_OP_QUERY_STATE2 4
#define AMDGPU_CTX_OP_GET_STABLE_PSTATE 5
#define AMDGPU_CTX_OP_SET_STABLE_PSTATE 6
#define AMDGPU_CTX_NO_RESET 0
#define AMDGPU_CTX_GUILTY_RESET 1
#define AMDGPU_CTX_INNOCENT_RESET 2
#define AMDGPU_CTX_UNKNOWN_RESET 3
#define AMDGPU_CTX_QUERY2_FLAGS_RESET (1 << 0)
#define AMDGPU_CTX_QUERY2_FLAGS_VRAMLOST (1 << 1)
#define AMDGPU_CTX_QUERY2_FLAGS_GUILTY (1 << 2)
#define AMDGPU_CTX_QUERY2_FLAGS_RAS_CE (1 << 3)
#define AMDGPU_CTX_QUERY2_FLAGS_RAS_UE (1 << 4)
#define AMDGPU_CTX_QUERY2_FLAGS_RESET_IN_PROGRESS (1 << 5)
#define AMDGPU_CTX_PRIORITY_UNSET - 2048
#define AMDGPU_CTX_PRIORITY_VERY_LOW - 1023
#define AMDGPU_CTX_PRIORITY_LOW - 512
#define AMDGPU_CTX_PRIORITY_NORMAL 0
#define AMDGPU_CTX_PRIORITY_HIGH 512
#define AMDGPU_CTX_PRIORITY_VERY_HIGH 1023
#define AMDGPU_CTX_STABLE_PSTATE_FLAGS_MASK 0xf
#define AMDGPU_CTX_STABLE_PSTATE_NONE 0
#define AMDGPU_CTX_STABLE_PSTATE_STANDARD 1
#define AMDGPU_CTX_STABLE_PSTATE_MIN_SCLK 2
#define AMDGPU_CTX_STABLE_PSTATE_MIN_MCLK 3
#define AMDGPU_CTX_STABLE_PSTATE_PEAK 4
struct drm_amdgpu_ctx_in {
  __u32 op;
  __u32 flags;
  __u32 ctx_id;
  __s32 priority;
};
union drm_amdgpu_ctx_out {
  struct {
    __u32 ctx_id;
    __u32 _pad;
  } alloc;
  struct {
    __u64 flags;
    __u32 hangs;
    __u32 reset_status;
  } state;
  struct {
    __u32 flags;
    __u32 _pad;
  } pstate;
};
union drm_amdgpu_ctx {
  struct drm_amdgpu_ctx_in in;
  union drm_amdgpu_ctx_out out;
};
#define AMDGPU_VM_OP_RESERVE_VMID 1
#define AMDGPU_VM_OP_UNRESERVE_VMID 2
struct drm_amdgpu_vm_in {
  __u32 op;
  __u32 flags;
};
struct drm_amdgpu_vm_out {
  __u64 flags;
};
union drm_amdgpu_vm {
  struct drm_amdgpu_vm_in in;
  struct drm_amdgpu_vm_out out;
};
#define AMDGPU_SCHED_OP_PROCESS_PRIORITY_OVERRIDE 1
#define AMDGPU_SCHED_OP_CONTEXT_PRIORITY_OVERRIDE 2
struct drm_amdgpu_sched_in {
  __u32 op;
  __u32 fd;
  __s32 priority;
  __u32 ctx_id;
};
union drm_amdgpu_sched {
  struct drm_amdgpu_sched_in in;
};
#define AMDGPU_GEM_USERPTR_READONLY (1 << 0)
#define AMDGPU_GEM_USERPTR_ANONONLY (1 << 1)
#define AMDGPU_GEM_USERPTR_VALIDATE (1 << 2)
#define AMDGPU_GEM_USERPTR_REGISTER (1 << 3)
struct drm_amdgpu_gem_userptr {
  __u64 addr;
  __u64 size;
  __u32 flags;
  __u32 handle;
};
#define AMDGPU_TILING_ARRAY_MODE_SHIFT 0
#define AMDGPU_TILING_ARRAY_MODE_MASK 0xf
#define AMDGPU_TILING_PIPE_CONFIG_SHIFT 4
#define AMDGPU_TILING_PIPE_CONFIG_MASK 0x1f
#define AMDGPU_TILING_TILE_SPLIT_SHIFT 9
#define AMDGPU_TILING_TILE_SPLIT_MASK 0x7
#define AMDGPU_TILING_MICRO_TILE_MODE_SHIFT 12
#define AMDGPU_TILING_MICRO_TILE_MODE_MASK 0x7
#define AMDGPU_TILING_BANK_WIDTH_SHIFT 15
#define AMDGPU_TILING_BANK_WIDTH_MASK 0x3
#define AMDGPU_TILING_BANK_HEIGHT_SHIFT 17
#define AMDGPU_TILING_BANK_HEIGHT_MASK 0x3
#define AMDGPU_TILING_MACRO_TILE_ASPECT_SHIFT 19
#define AMDGPU_TILING_MACRO_TILE_ASPECT_MASK 0x3
#define AMDGPU_TILING_NUM_BANKS_SHIFT 21
#define AMDGPU_TILING_NUM_BANKS_MASK 0x3
#define AMDGPU_TILING_SWIZZLE_MODE_SHIFT 0
#define AMDGPU_TILING_SWIZZLE_MODE_MASK 0x1f
#define AMDGPU_TILING_DCC_OFFSET_256B_SHIFT 5
#define AMDGPU_TILING_DCC_OFFSET_256B_MASK 0xFFFFFF
#define AMDGPU_TILING_DCC_PITCH_MAX_SHIFT 29
#define AMDGPU_TILING_DCC_PITCH_MAX_MASK 0x3FFF
#define AMDGPU_TILING_DCC_INDEPENDENT_64B_SHIFT 43
#define AMDGPU_TILING_DCC_INDEPENDENT_64B_MASK 0x1
#define AMDGPU_TILING_DCC_INDEPENDENT_128B_SHIFT 44
#define AMDGPU_TILING_DCC_INDEPENDENT_128B_MASK 0x1
#define AMDGPU_TILING_SCANOUT_SHIFT 63
#define AMDGPU_TILING_SCANOUT_MASK 0x1
#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT 0
#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK 0x7
#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT 3
#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK 0x3
#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT 5
#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK 0x7
#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT 8
#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK 0x3f
#define AMDGPU_TILING_SET(field,value) (((__u64) (value) & AMDGPU_TILING_ ##field ##_MASK) << AMDGPU_TILING_ ##field ##_SHIFT)
#define AMDGPU_TILING_GET(value,field) (((__u64) (value) >> AMDGPU_TILING_ ##field ##_SHIFT) & AMDGPU_TILING_ ##field ##_MASK)
#define AMDGPU_GEM_METADATA_OP_SET_METADATA 1
#define AMDGPU_GEM_METADATA_OP_GET_METADATA 2
struct drm_amdgpu_gem_metadata {
  __u32 handle;
  __u32 op;
  struct {
    __u64 flags;
    __u64 tiling_info;
    __u32 data_size_bytes;
    __u32 data[64];
  } data;
};
struct drm_amdgpu_gem_mmap_in {
  __u32 handle;
  __u32 _pad;
};
struct drm_amdgpu_gem_mmap_out {
  __u64 addr_ptr;
};
union drm_amdgpu_gem_mmap {
  struct drm_amdgpu_gem_mmap_in in;
  struct drm_amdgpu_gem_mmap_out out;
};
struct drm_amdgpu_gem_wait_idle_in {
  __u32 handle;
  __u32 flags;
  __u64 timeout;
};
struct drm_amdgpu_gem_wait_idle_out {
  __u32 status;
  __u32 domain;
};
union drm_amdgpu_gem_wait_idle {
  struct drm_amdgpu_gem_wait_idle_in in;
  struct drm_amdgpu_gem_wait_idle_out out;
};
struct drm_amdgpu_wait_cs_in {
  __u64 handle;
  __u64 timeout;
  __u32 ip_type;
  __u32 ip_instance;
  __u32 ring;
  __u32 ctx_id;
};
struct drm_amdgpu_wait_cs_out {
  __u64 status;
};
union drm_amdgpu_wait_cs {
  struct drm_amdgpu_wait_cs_in in;
  struct drm_amdgpu_wait_cs_out out;
};
struct drm_amdgpu_fence {
  __u32 ctx_id;
  __u32 ip_type;
  __u32 ip_instance;
  __u32 ring;
  __u64 seq_no;
};
struct drm_amdgpu_wait_fences_in {
  __u64 fences;
  __u32 fence_count;
  __u32 wait_all;
  __u64 timeout_ns;
};
struct drm_amdgpu_wait_fences_out {
  __u32 status;
  __u32 first_signaled;
};
union drm_amdgpu_wait_fences {
  struct drm_amdgpu_wait_fences_in in;
  struct drm_amdgpu_wait_fences_out out;
};
#define AMDGPU_GEM_OP_GET_GEM_CREATE_INFO 0
#define AMDGPU_GEM_OP_SET_PLACEMENT 1
struct drm_amdgpu_gem_op {
  __u32 handle;
  __u32 op;
  __u64 value;
};
#define AMDGPU_VA_OP_MAP 1
#define AMDGPU_VA_OP_UNMAP 2
#define AMDGPU_VA_OP_CLEAR 3
#define AMDGPU_VA_OP_REPLACE 4
#define AMDGPU_VM_DELAY_UPDATE (1 << 0)
#define AMDGPU_VM_PAGE_READABLE (1 << 1)
#define AMDGPU_VM_PAGE_WRITEABLE (1 << 2)
#define AMDGPU_VM_PAGE_EXECUTABLE (1 << 3)
#define AMDGPU_VM_PAGE_PRT (1 << 4)
#define AMDGPU_VM_MTYPE_MASK (0xf << 5)
#define AMDGPU_VM_MTYPE_DEFAULT (0 << 5)
#define AMDGPU_VM_MTYPE_NC (1 << 5)
#define AMDGPU_VM_MTYPE_WC (2 << 5)
#define AMDGPU_VM_MTYPE_CC (3 << 5)
#define AMDGPU_VM_MTYPE_UC (4 << 5)
#define AMDGPU_VM_MTYPE_RW (5 << 5)
#define AMDGPU_VM_PAGE_NOALLOC (1 << 9)
struct drm_amdgpu_gem_va {
  __u32 handle;
  __u32 _pad;
  __u32 operation;
  __u32 flags;
  __u64 va_address;
  __u64 offset_in_bo;
  __u64 map_size;
};
#define AMDGPU_HW_IP_GFX 0
#define AMDGPU_HW_IP_COMPUTE 1
#define AMDGPU_HW_IP_DMA 2
#define AMDGPU_HW_IP_UVD 3
#define AMDGPU_HW_IP_VCE 4
#define AMDGPU_HW_IP_UVD_ENC 5
#define AMDGPU_HW_IP_VCN_DEC 6
#define AMDGPU_HW_IP_VCN_ENC 7
#define AMDGPU_HW_IP_VCN_JPEG 8
#define AMDGPU_HW_IP_VPE 9
#define AMDGPU_HW_IP_NUM 10
#define AMDGPU_HW_IP_INSTANCE_MAX_COUNT 1
#define AMDGPU_CHUNK_ID_IB 0x01
#define AMDGPU_CHUNK_ID_FENCE 0x02
#define AMDGPU_CHUNK_ID_DEPENDENCIES 0x03
#define AMDGPU_CHUNK_ID_SYNCOBJ_IN 0x04
#define AMDGPU_CHUNK_ID_SYNCOBJ_OUT 0x05
#define AMDGPU_CHUNK_ID_BO_HANDLES 0x06
#define AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES 0x07
#define AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT 0x08
#define AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL 0x09
#define AMDGPU_CHUNK_ID_CP_GFX_SHADOW 0x0a
struct drm_amdgpu_cs_chunk {
  __u32 chunk_id;
  __u32 length_dw;
  __u64 chunk_data;
};
struct drm_amdgpu_cs_in {
  __u32 ctx_id;
  __u32 bo_list_handle;
  __u32 num_chunks;
  __u32 flags;
  __u64 chunks;
};
struct drm_amdgpu_cs_out {
  __u64 handle;
};
union drm_amdgpu_cs {
  struct drm_amdgpu_cs_in in;
  struct drm_amdgpu_cs_out out;
};
#define AMDGPU_IB_FLAG_CE (1 << 0)
#define AMDGPU_IB_FLAG_PREAMBLE (1 << 1)
#define AMDGPU_IB_FLAG_PREEMPT (1 << 2)
#define AMDGPU_IB_FLAG_TC_WB_NOT_INVALIDATE (1 << 3)
#define AMDGPU_IB_FLAG_RESET_GDS_MAX_WAVE_ID (1 << 4)
#define AMDGPU_IB_FLAGS_SECURE (1 << 5)
#define AMDGPU_IB_FLAG_EMIT_MEM_SYNC (1 << 6)
struct drm_amdgpu_cs_chunk_ib {
  __u32 _pad;
  __u32 flags;
  __u64 va_start;
  __u32 ib_bytes;
  __u32 ip_type;
  __u32 ip_instance;
  __u32 ring;
};
struct drm_amdgpu_cs_chunk_dep {
  __u32 ip_type;
  __u32 ip_instance;
  __u32 ring;
  __u32 ctx_id;
  __u64 handle;
};
struct drm_amdgpu_cs_chunk_fence {
  __u32 handle;
  __u32 offset;
};
struct drm_amdgpu_cs_chunk_sem {
  __u32 handle;
};
struct drm_amdgpu_cs_chunk_syncobj {
  __u32 handle;
  __u32 flags;
  __u64 point;
};
#define AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ 0
#define AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD 1
#define AMDGPU_FENCE_TO_HANDLE_GET_SYNC_FILE_FD 2
union drm_amdgpu_fence_to_handle {
  struct {
    struct drm_amdgpu_fence fence;
    __u32 what;
    __u32 pad;
  } in;
  struct {
    __u32 handle;
  } out;
};
struct drm_amdgpu_cs_chunk_data {
  union {
    struct drm_amdgpu_cs_chunk_ib ib_data;
    struct drm_amdgpu_cs_chunk_fence fence_data;
  };
};
#define AMDGPU_CS_CHUNK_CP_GFX_SHADOW_FLAGS_INIT_SHADOW 0x1
struct drm_amdgpu_cs_chunk_cp_gfx_shadow {
  __u64 shadow_va;
  __u64 csa_va;
  __u64 gds_va;
  __u64 flags;
};
#define AMDGPU_IDS_FLAGS_FUSION 0x1
#define AMDGPU_IDS_FLAGS_PREEMPTION 0x2
#define AMDGPU_IDS_FLAGS_TMZ 0x4
#define AMDGPU_IDS_FLAGS_CONFORMANT_TRUNC_COORD 0x8
#define AMDGPU_INFO_ACCEL_WORKING 0x00
#define AMDGPU_INFO_CRTC_FROM_ID 0x01
#define AMDGPU_INFO_HW_IP_INFO 0x02
#define AMDGPU_INFO_HW_IP_COUNT 0x03
#define AMDGPU_INFO_TIMESTAMP 0x05
#define AMDGPU_INFO_FW_VERSION 0x0e
#define AMDGPU_INFO_FW_VCE 0x1
#define AMDGPU_INFO_FW_UVD 0x2
#define AMDGPU_INFO_FW_GMC 0x03
#define AMDGPU_INFO_FW_GFX_ME 0x04
#define AMDGPU_INFO_FW_GFX_PFP 0x05
#define AMDGPU_INFO_FW_GFX_CE 0x06
#define AMDGPU_INFO_FW_GFX_RLC 0x07
#define AMDGPU_INFO_FW_GFX_MEC 0x08
#define AMDGPU_INFO_FW_SMC 0x0a
#define AMDGPU_INFO_FW_SDMA 0x0b
#define AMDGPU_INFO_FW_SOS 0x0c
#define AMDGPU_INFO_FW_ASD 0x0d
#define AMDGPU_INFO_FW_VCN 0x0e
#define AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_CNTL 0x0f
#define AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_GPM_MEM 0x10
#define AMDGPU_INFO_FW_GFX_RLC_RESTORE_LIST_SRM_MEM 0x11
#define AMDGPU_INFO_FW_DMCU 0x12
#define AMDGPU_INFO_FW_TA 0x13
#define AMDGPU_INFO_FW_DMCUB 0x14
#define AMDGPU_INFO_FW_TOC 0x15
#define AMDGPU_INFO_FW_CAP 0x16
#define AMDGPU_INFO_FW_GFX_RLCP 0x17
#define AMDGPU_INFO_FW_GFX_RLCV 0x18
#define AMDGPU_INFO_FW_MES_KIQ 0x19
#define AMDGPU_INFO_FW_MES 0x1a
#define AMDGPU_INFO_FW_IMU 0x1b
#define AMDGPU_INFO_FW_VPE 0x1c
#define AMDGPU_INFO_NUM_BYTES_MOVED 0x0f
#define AMDGPU_INFO_VRAM_USAGE 0x10
#define AMDGPU_INFO_GTT_USAGE 0x11
#define AMDGPU_INFO_GDS_CONFIG 0x13
#define AMDGPU_INFO_VRAM_GTT 0x14
#define AMDGPU_INFO_READ_MMR_REG 0x15
#define AMDGPU_INFO_DEV_INFO 0x16
#define AMDGPU_INFO_VIS_VRAM_USAGE 0x17
#define AMDGPU_INFO_NUM_EVICTIONS 0x18
#define AMDGPU_INFO_MEMORY 0x19
#define AMDGPU_INFO_VCE_CLOCK_TABLE 0x1A
#define AMDGPU_INFO_VBIOS 0x1B
#define AMDGPU_INFO_VBIOS_SIZE 0x1
#define AMDGPU_INFO_VBIOS_IMAGE 0x2
#define AMDGPU_INFO_VBIOS_INFO 0x3
#define AMDGPU_INFO_NUM_HANDLES 0x1C
#define AMDGPU_INFO_SENSOR 0x1D
#define AMDGPU_INFO_SENSOR_GFX_SCLK 0x1
#define AMDGPU_INFO_SENSOR_GFX_MCLK 0x2
#define AMDGPU_INFO_SENSOR_GPU_TEMP 0x3
#define AMDGPU_INFO_SENSOR_GPU_LOAD 0x4
#define AMDGPU_INFO_SENSOR_GPU_AVG_POWER 0x5
#define AMDGPU_INFO_SENSOR_VDDNB 0x6
#define AMDGPU_INFO_SENSOR_VDDGFX 0x7
#define AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_SCLK 0x8
#define AMDGPU_INFO_SENSOR_STABLE_PSTATE_GFX_MCLK 0x9
#define AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_SCLK 0xa
#define AMDGPU_INFO_SENSOR_PEAK_PSTATE_GFX_MCLK 0xb
#define AMDGPU_INFO_SENSOR_GPU_INPUT_POWER 0xc
#define AMDGPU_INFO_NUM_VRAM_CPU_PAGE_FAULTS 0x1E
#define AMDGPU_INFO_VRAM_LOST_COUNTER 0x1F
#define AMDGPU_INFO_RAS_ENABLED_FEATURES 0x20
#define AMDGPU_INFO_RAS_ENABLED_UMC (1 << 0)
#define AMDGPU_INFO_RAS_ENABLED_SDMA (1 << 1)
#define AMDGPU_INFO_RAS_ENABLED_GFX (1 << 2)
#define AMDGPU_INFO_RAS_ENABLED_MMHUB (1 << 3)
#define AMDGPU_INFO_RAS_ENABLED_ATHUB (1 << 4)
#define AMDGPU_INFO_RAS_ENABLED_PCIE (1 << 5)
#define AMDGPU_INFO_RAS_ENABLED_HDP (1 << 6)
#define AMDGPU_INFO_RAS_ENABLED_XGMI (1 << 7)
#define AMDGPU_INFO_RAS_ENABLED_DF (1 << 8)
#define AMDGPU_INFO_RAS_ENABLED_SMN (1 << 9)
#define AMDGPU_INFO_RAS_ENABLED_SEM (1 << 10)
#define AMDGPU_INFO_RAS_ENABLED_MP0 (1 << 11)
#define AMDGPU_INFO_RAS_ENABLED_MP1 (1 << 12)
#define AMDGPU_INFO_RAS_ENABLED_FUSE (1 << 13)
#define AMDGPU_INFO_VIDEO_CAPS 0x21
#define AMDGPU_INFO_VIDEO_CAPS_DECODE 0
#define AMDGPU_INFO_VIDEO_CAPS_ENCODE 1
#define AMDGPU_INFO_MAX_IBS 0x22
#define AMDGPU_INFO_GPUVM_FAULT 0x23
#define AMDGPU_INFO_MMR_SE_INDEX_SHIFT 0
#define AMDGPU_INFO_MMR_SE_INDEX_MASK 0xff
#define AMDGPU_INFO_MMR_SH_INDEX_SHIFT 8
#define AMDGPU_INFO_MMR_SH_INDEX_MASK 0xff
struct drm_amdgpu_query_fw {
  __u32 fw_type;
  __u32 ip_instance;
  __u32 index;
  __u32 _pad;
};
struct drm_amdgpu_info {
  __u64 return_pointer;
  __u32 return_size;
  __u32 query;
  union {
    struct {
      __u32 id;
      __u32 _pad;
    } mode_crtc;
    struct {
      __u32 type;
      __u32 ip_instance;
    } query_hw_ip;
    struct {
      __u32 dword_offset;
      __u32 count;
      __u32 instance;
      __u32 flags;
    } read_mmr_reg;
    struct drm_amdgpu_query_fw query_fw;
    struct {
      __u32 type;
      __u32 offset;
    } vbios_info;
    struct {
      __u32 type;
    } sensor_info;
    struct {
      __u32 type;
    } video_cap;
  };
};
struct drm_amdgpu_info_gds {
  __u32 gds_gfx_partition_size;
  __u32 compute_partition_size;
  __u32 gds_total_size;
  __u32 gws_per_gfx_partition;
  __u32 gws_per_compute_partition;
  __u32 oa_per_gfx_partition;
  __u32 oa_per_compute_partition;
  __u32 _pad;
};
struct drm_amdgpu_info_vram_gtt {
  __u64 vram_size;
  __u64 vram_cpu_accessible_size;
  __u64 gtt_size;
};
struct drm_amdgpu_heap_info {
  __u64 total_heap_size;
  __u64 usable_heap_size;
  __u64 heap_usage;
  __u64 max_allocation;
};
struct drm_amdgpu_memory_info {
  struct drm_amdgpu_heap_info vram;
  struct drm_amdgpu_heap_info cpu_accessible_vram;
  struct drm_amdgpu_heap_info gtt;
};
struct drm_amdgpu_info_firmware {
  __u32 ver;
  __u32 feature;
};
struct drm_amdgpu_info_vbios {
  __u8 name[64];
  __u8 vbios_pn[64];
  __u32 version;
  __u32 pad;
  __u8 vbios_ver_str[32];
  __u8 date[32];
};
#define AMDGPU_VRAM_TYPE_UNKNOWN 0
#define AMDGPU_VRAM_TYPE_GDDR1 1
#define AMDGPU_VRAM_TYPE_DDR2 2
#define AMDGPU_VRAM_TYPE_GDDR3 3
#define AMDGPU_VRAM_TYPE_GDDR4 4
#define AMDGPU_VRAM_TYPE_GDDR5 5
#define AMDGPU_VRAM_TYPE_HBM 6
#define AMDGPU_VRAM_TYPE_DDR3 7
#define AMDGPU_VRAM_TYPE_DDR4 8
#define AMDGPU_VRAM_TYPE_GDDR6 9
#define AMDGPU_VRAM_TYPE_DDR5 10
#define AMDGPU_VRAM_TYPE_LPDDR4 11
#define AMDGPU_VRAM_TYPE_LPDDR5 12
struct drm_amdgpu_info_device {
  __u32 device_id;
  __u32 chip_rev;
  __u32 external_rev;
  __u32 pci_rev;
  __u32 family;
  __u32 num_shader_engines;
  __u32 num_shader_arrays_per_engine;
  __u32 gpu_counter_freq;
  __u64 max_engine_clock;
  __u64 max_memory_clock;
  __u32 cu_active_number;
  __u32 cu_ao_mask;
  __u32 cu_bitmap[4][4];
  __u32 enabled_rb_pipes_mask;
  __u32 num_rb_pipes;
  __u32 num_hw_gfx_contexts;
  __u32 pcie_gen;
  __u64 ids_flags;
  __u64 virtual_address_offset;
  __u64 virtual_address_max;
  __u32 virtual_address_alignment;
  __u32 pte_fragment_size;
  __u32 gart_page_size;
  __u32 ce_ram_size;
  __u32 vram_type;
  __u32 vram_bit_width;
  __u32 vce_harvest_config;
  __u32 gc_double_offchip_lds_buf;
  __u64 prim_buf_gpu_addr;
  __u64 pos_buf_gpu_addr;
  __u64 cntl_sb_buf_gpu_addr;
  __u64 param_buf_gpu_addr;
  __u32 prim_buf_size;
  __u32 pos_buf_size;
  __u32 cntl_sb_buf_size;
  __u32 param_buf_size;
  __u32 wave_front_size;
  __u32 num_shader_visible_vgprs;
  __u32 num_cu_per_sh;
  __u32 num_tcc_blocks;
  __u32 gs_vgt_table_depth;
  __u32 gs_prim_buffer_depth;
  __u32 max_gs_waves_per_vgt;
  __u32 pcie_num_lanes;
  __u32 cu_ao_bitmap[4][4];
  __u64 high_va_offset;
  __u64 high_va_max;
  __u32 pa_sc_tile_steering_override;
  __u64 tcc_disabled_mask;
  __u64 min_engine_clock;
  __u64 min_memory_clock;
  __u32 tcp_cache_size;
  __u32 num_sqc_per_wgp;
  __u32 sqc_data_cache_size;
  __u32 sqc_inst_cache_size;
  __u32 gl1c_cache_size;
  __u32 gl2c_cache_size;
  __u64 mall_size;
  __u32 enabled_rb_pipes_mask_hi;
  __u32 shadow_size;
  __u32 shadow_alignment;
  __u32 csa_size;
  __u32 csa_alignment;
};
struct drm_amdgpu_info_hw_ip {
  __u32 hw_ip_version_major;
  __u32 hw_ip_version_minor;
  __u64 capabilities_flags;
  __u32 ib_start_alignment;
  __u32 ib_size_alignment;
  __u32 available_rings;
  __u32 ip_discovery_version;
};
struct drm_amdgpu_info_num_handles {
  __u32 uvd_max_handles;
  __u32 uvd_used_handles;
};
#define AMDGPU_VCE_CLOCK_TABLE_ENTRIES 6
struct drm_amdgpu_info_vce_clock_table_entry {
  __u32 sclk;
  __u32 mclk;
  __u32 eclk;
  __u32 pad;
};
struct drm_amdgpu_info_vce_clock_table {
  struct drm_amdgpu_info_vce_clock_table_entry entries[AMDGPU_VCE_CLOCK_TABLE_ENTRIES];
  __u32 num_valid_entries;
  __u32 pad;
};
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG2 0
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4 1
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VC1 2
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_MPEG4_AVC 3
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_HEVC 4
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_JPEG 5
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_VP9 6
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_AV1 7
#define AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_COUNT 8
struct drm_amdgpu_info_video_codec_info {
  __u32 valid;
  __u32 max_width;
  __u32 max_height;
  __u32 max_pixels_per_frame;
  __u32 max_level;
  __u32 pad;
};
struct drm_amdgpu_info_video_caps {
  struct drm_amdgpu_info_video_codec_info codec_info[AMDGPU_INFO_VIDEO_CAPS_CODEC_IDX_COUNT];
};
#define AMDGPU_VMHUB_TYPE_MASK 0xff
#define AMDGPU_VMHUB_TYPE_SHIFT 0
#define AMDGPU_VMHUB_TYPE_GFX 0
#define AMDGPU_VMHUB_TYPE_MM0 1
#define AMDGPU_VMHUB_TYPE_MM1 2
#define AMDGPU_VMHUB_IDX_MASK 0xff00
#define AMDGPU_VMHUB_IDX_SHIFT 8
struct drm_amdgpu_info_gpuvm_fault {
  __u64 addr;
  __u32 status;
  __u32 vmhub;
};
#define AMDGPU_FAMILY_UNKNOWN 0
#define AMDGPU_FAMILY_SI 110
#define AMDGPU_FAMILY_CI 120
#define AMDGPU_FAMILY_KV 125
#define AMDGPU_FAMILY_VI 130
#define AMDGPU_FAMILY_CZ 135
#define AMDGPU_FAMILY_AI 141
#define AMDGPU_FAMILY_RV 142
#define AMDGPU_FAMILY_NV 143
#define AMDGPU_FAMILY_VGH 144
#define AMDGPU_FAMILY_GC_11_0_0 145
#define AMDGPU_FAMILY_YC 146
#define AMDGPU_FAMILY_GC_11_0_1 148
#define AMDGPU_FAMILY_GC_10_3_6 149
#define AMDGPU_FAMILY_GC_10_3_7 151
#define AMDGPU_FAMILY_GC_11_5_0 150
#define AMDGPU_FAMILY_GC_12_0_0 152
struct drm_color_ctm_3x4 {
  __u64 matrix[12];
};
#ifdef __cplusplus
}
#endif
#endif

"""

```