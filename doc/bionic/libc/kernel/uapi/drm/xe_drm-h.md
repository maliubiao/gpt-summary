Response:
Let's break down the thought process for analyzing the given header file `xe_drm.h`.

**1. Initial Understanding and Context:**

* **File Location:** The path `bionic/libc/kernel/uapi/drm/xe_drm.handroid` immediately tells us this is part of Android's low-level graphics subsystem (`drm`) and is an API for the kernel. The `uapi` suggests it's for user-space programs to interact with the kernel driver.
* **`bionic`:**  Knowing this is in `bionic` means it's related to Android's core C library, implying the structures and defines here are used by higher-level Android components.
* **`xe_` prefix:**  This strongly suggests this header file is specific to a particular hardware component, likely an Intel GPU (codename "Xe").

**2. Identifying Core Functionality (High-Level):**

* **IOCTLs:**  The `#define DRM_IOCTL_XE_*` lines are the most prominent indicators of functionality. IOCTLs are the primary way user-space interacts with device drivers in Linux. Each `DRM_IOCTL_XE_...` corresponds to a specific action.
* **Structures:** The `struct drm_xe_*` definitions define the data structures used to pass information between user-space and the kernel for each IOCTL.

**3. Grouping and Categorizing IOCTLs (Logical Organization):**

I start grouping related IOCTLs together based on their names:

* **Device Management:** `DRM_IOCTL_XE_DEVICE_QUERY` - Seems like a general information retrieval mechanism.
* **Memory Management (GEM):** `DRM_IOCTL_XE_GEM_CREATE`, `DRM_IOCTL_XE_GEM_MMAP_OFFSET` -  Clearly related to managing GPU memory objects.
* **Virtual Memory Management (VM):** `DRM_IOCTL_XE_VM_CREATE`, `DRM_IOCTL_XE_VM_DESTROY`, `DRM_IOCTL_XE_VM_BIND` - Deal with managing address spaces for the GPU.
* **Execution Queues:** `DRM_IOCTL_XE_EXEC_QUEUE_CREATE`, `DRM_IOCTL_XE_EXEC_QUEUE_DESTROY`, `DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY`, `DRM_IOCTL_XE_EXEC` -  Manage the submission of work to the GPU.
* **Synchronization:** `DRM_IOCTL_XE_WAIT_USER_FENCE` -  Mechanism for synchronizing between CPU and GPU.
* **Observation/Profiling:** `DRM_IOCTL_XE_OBSERVATION` - Likely for performance monitoring or debugging.

**4. Examining Structures and their Purpose:**

For each group of IOCTLs, I look at the associated structures:

* **`drm_xe_device_query`:**  The `query` field and associated `#define DRM_XE_DEVICE_QUERY_*` values indicate this IOCTL can retrieve various types of information about the GPU (engines, memory regions, configuration, etc.). The `data` field suggests a pointer to where this information is returned.
* **`drm_xe_gem_*`:**  These structures define parameters for creating GPU memory objects (size, placement, flags), and getting an offset for `mmap`ing them into user space.
* **`drm_xe_vm_*`:**  These structures handle creating and destroying GPU virtual address spaces and binding GPU memory objects into those spaces. The `drm_xe_vm_bind_op` structure is particularly interesting as it defines different binding operations (map, unmap, userptr).
* **`drm_xe_exec_queue_*`:** These manage the creation and destruction of command queues, and submitting execution commands (`drm_xe_exec`).
* **`drm_xe_sync`:** Defines different synchronization primitives.
* **`drm_xe_wait_user_fence`:**  Allows waiting on a specific value in a user-space memory location, enabling CPU-GPU synchronization.
* **`drm_xe_observation_param`:** Configures observation/profiling functionalities.

**5. Connecting to Android:**

* **DRM Framework:** The "drm" in the path immediately connects this to Android's DRM framework, which is used for managing display and graphics.
* **Hardware Abstraction:** This header provides a low-level interface, and Android's higher-level graphics layers (like SurfaceFlinger, Vulkan drivers, etc.) would use these IOCTLs indirectly through libraries.
* **Specific Example (GEM):** When an app wants to display something on the screen, the graphics compositor (SurfaceFlinger) might use `DRM_IOCTL_XE_GEM_CREATE` to allocate a buffer, fill it with pixel data, and then use other DRM IOCTLs to display it.

**6. libc Function Analysis:**

* **`ioctl()`:**  The core libc function used to invoke these DRM operations. The explanation focuses on its role in sending control commands to device drivers.

**7. Dynamic Linker (if applicable):**

* In this specific header file, there are no direct calls to dynamic linker functions. The dynamic linker would be involved when loading the graphics driver libraries that *use* these IOCTLs. The SO layout and linking process explanation is generic but relevant to how drivers are loaded.

**8. Assumptions and Logic:**

* **Intel GPU:** The "xe" prefix is a strong indicator.
* **Graphics Context:** The functions clearly relate to graphics operations like memory management, command submission, and synchronization.

**9. Common Errors:**

Focus on common mistakes when working with low-level APIs: invalid handles, incorrect sizes, memory corruption, race conditions, and permission issues.

**10. Android Framework/NDK Path:**

* Start with a high-level action (app drawing something), trace down through the Android graphics stack (SurfaceFlinger, HAL, kernel driver). The `ioctl()` calls are the bridge to this kernel interface.

**11. Frida Hooking:**

* Focus on hooking the `ioctl()` system call with the specific `DRM_IOCTL_XE_*` commands and inspecting the arguments (especially the pointers to the `drm_xe_*` structures).

**Self-Correction/Refinement during the process:**

* **Initially, I might not immediately recognize all the acronyms (GEM, VM).**  Looking at the structure members and the context helps to deduce their meanings (Graphics Execution Manager, Virtual Memory).
* **The sheer number of structures can be overwhelming.** Grouping them by functionality (memory, execution, etc.) makes it more manageable.
* **Connecting to Android requires some knowledge of the Android graphics stack.**  If I didn't know about SurfaceFlinger or HAL, I'd need to research that.

By following these steps, combining code analysis with knowledge of operating system concepts and the Android architecture,  a comprehensive understanding of the header file and its role can be achieved.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/drm/xe_drm.handroid` 这个头文件。

**功能列举**

这个头文件定义了用于与 Intel Xe 系列 GPU 的 DRM (Direct Rendering Manager) 驱动进行用户空间交互的常量、结构体和宏定义。 它的主要功能可以概括为：

1. **定义 IOCTL 命令:**  它定义了一系列 `DRM_IOCTL_XE_...` 宏，这些宏对应着用户空间程序可以向内核驱动发送的特定操作请求。 例如：
    * `DRM_IOCTL_XE_DEVICE_QUERY`: 查询设备信息。
    * `DRM_IOCTL_XE_GEM_CREATE`: 创建 GPU 内存对象。
    * `DRM_IOCTL_XE_EXEC`:  提交 GPU 执行命令。
2. **定义 IOCTL 请求参数结构体:**  它定义了与每个 IOCTL 命令关联的数据结构，用于在用户空间和内核空间之间传递参数。 例如：
    * `struct drm_xe_device_query`: 用于 `DRM_IOCTL_XE_DEVICE_QUERY`，指定要查询的设备信息的类型。
    * `struct drm_xe_gem_create`: 用于 `DRM_IOCTL_XE_GEM_CREATE`，指定要创建的内存对象的大小、标志等。
3. **定义辅助常量和枚举:** 它定义了一些常量和枚举类型，用于更清晰地表示 IOCTL 参数的选项和状态。 例如：
    * `DRM_XE_ENGINE_CLASS_RENDER`: 表示渲染引擎类型。
    * `DRM_XE_GEM_CREATE_FLAG_SCANOUT`: 表示创建的 GEM 对象用于扫描输出到显示器。
4. **定义用于扩展的结构体:**  例如 `struct drm_xe_user_extension`，允许在未来的版本中添加新的功能而无需修改现有的结构体布局。

**与 Android 功能的关系及举例**

这个头文件是 Android 图形栈的底层组成部分，直接关系到 Android 设备上使用 Intel Xe GPU 进行图形渲染、计算等操作。

**举例说明:**

* **图形渲染:** 当 Android 应用使用 OpenGL ES 或 Vulkan 进行 3D 渲染时，底层的图形驱动程序会使用这个头文件中定义的 IOCTL 来与 GPU 交互。例如，应用需要分配一块 GPU 内存来存储纹理数据，图形驱动会调用 `DRM_IOCTL_XE_GEM_CREATE` 并填充 `struct drm_xe_gem_create` 结构体，指定内存大小和用途（例如 `DRM_XE_GEM_CREATE_FLAG_SCANOUT` 用于帧缓冲区）。
* **视频解码/编码:** Android 的媒体框架可以使用这个头文件中定义的机制来利用 GPU 的视频解码/编码引擎。例如，解码器可能使用 `DRM_IOCTL_XE_EXEC_QUEUE_CREATE` 创建一个执行队列，然后使用 `DRM_IOCTL_XE_EXEC` 提交解码命令。
* **通用计算 (GPGPU):**  如果 Android 应用使用 Vulkan Compute 或 OpenCL 来执行通用计算任务，它也会通过这个头文件中定义的 IOCTL 与 GPU 交互，管理内存、提交计算任务等。例如，使用 `DRM_IOCTL_XE_GEM_CREATE` 分配输入和输出缓冲区，然后使用 `DRM_IOCTL_XE_EXEC` 提交计算内核。

**libc 函数功能实现详解**

这个头文件本身并没有定义任何 libc 函数。它定义的是与内核交互的接口。用户空间的程序会使用 libc 提供的系统调用接口（主要是 `ioctl` 函数）来调用这里定义的 DRM IOCTL。

**`ioctl` 函数的功能实现:**

`ioctl` (input/output control) 是一个通用的系统调用，用于执行设备特定的控制操作。其基本原型如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* **`fd`:**  文件描述符，通常是通过 `open` 系统调用打开的设备文件，例如 `/dev/dri/card0` (代表一个 DRM 设备)。
* **`request`:**  一个与特定设备驱动相关的请求码。在这个场景下，`request` 就是这个头文件中定义的 `DRM_IOCTL_XE_...` 宏展开后的值。这些宏通常使用 `_IOW`, `_IOR`, `_IOWR` 等宏来生成，包含了命令类型和数据大小信息。
* **`...`:**  可变参数，通常是一个指向数据结构的指针，用于传递 IOCTL 命令需要的参数。这个数据结构的类型由 `request` 指定。

**`ioctl` 的实现过程 (简化):**

1. **用户空间调用 `ioctl`:**  用户程序调用 `ioctl` 函数，传入设备文件描述符、IOCTL 请求码和参数结构体指针。
2. **系统调用陷入内核:**  `ioctl` 是一个系统调用，会触发 CPU 从用户态切换到内核态。
3. **内核处理系统调用:**  内核接收到 `ioctl` 系统调用请求。
4. **查找设备驱动:**  内核根据文件描述符找到对应的设备驱动程序 (在这个例子中是 Intel Xe DRM 驱动)。
5. **调用驱动的 `ioctl` 处理函数:**  内核将 `ioctl` 请求传递给设备驱动的 `ioctl` 处理函数。
6. **驱动程序执行操作:**  DRM 驱动程序根据 `request` (例如 `DRM_IOCTL_XE_GEM_CREATE`) 和参数结构体中的信息，执行相应的硬件操作，例如分配 GPU 内存。
7. **驱动程序返回结果:**  驱动程序将操作结果（例如分配的内存对象的句柄）写入参数结构体或作为 `ioctl` 函数的返回值返回。
8. **内核返回用户空间:**  内核将结果返回给用户空间的 `ioctl` 调用。

**涉及 dynamic linker 的功能及处理过程**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker 主要负责在程序运行时加载和链接共享库 (`.so` 文件)。

但是，与 GPU 交互的库（例如 Mesa 3D 图形库）通常是以共享库的形式存在的。当 Android 应用需要使用 GPU 功能时，dynamic linker 会负责加载这些库。

**so 布局样本:**

假设一个使用了 Intel Xe GPU 的 Android 应用，其进程的内存布局可能包含以下共享库：

```
...
7000000000-7000100000 r-xp  /system/lib64/libutils.so
7000100000-7000180000 r--p  /system/lib64/libutils.so
7000180000-70001a0000 rw-p  /system/lib64/libutils.so
7100000000-7200000000 r-xp  /vendor/lib64/libvulkan.so  // Vulkan 库
7200000000-7210000000 r--p  /vendor/lib64/libvulkan.so
7210000000-7220000000 rw-p  /vendor/lib64/libvulkan.so
7300000000-7400000000 r-xp  /vendor/lib64/libVkLayer_intel_xe.so // Intel Xe Vulkan 层
7400000000-7410000000 r--p  /vendor/lib64/libVkLayer_intel_xe.so
7410000000-7420000000 rw-p  /vendor/lib64/libVkLayer_intel_xe.so
...
```

* **`libutils.so`:** Android 的基础工具库。
* **`libvulkan.so`:**  Android 的 Vulkan API 库。
* **`libVkLayer_intel_xe.so`:**  Intel 提供的特定于 Xe GPU 的 Vulkan 实现层。这个库会使用 `ioctl` 系统调用，并利用 `xe_drm.h` 中定义的 IOCTL 命令与内核驱动交互。

**链接的处理过程:**

1. **应用启动:** 当 Android 应用启动时，zygote 进程 fork 出应用的进程。
2. **加载器启动:** 应用进程的加载器开始工作。
3. **加载主程序:** 加载器首先加载应用的主可执行文件。
4. **解析依赖:** 加载器解析主程序依赖的共享库。
5. **查找共享库:** 加载器在预定义的路径（例如 `/system/lib64`, `/vendor/lib64`）中查找依赖的共享库。
6. **加载共享库:** 加载器将找到的共享库加载到进程的地址空间。这包括将代码段、数据段等映射到内存。
7. **符号解析与重定位:**  加载器解析共享库中的符号引用，并将这些引用重定位到正确的内存地址。例如，如果 `libVkLayer_intel_xe.so` 中调用了 `ioctl` 函数，加载器会将这个调用指向 libc 中 `ioctl` 函数的实际地址。
8. **执行初始化代码:** 加载器执行共享库中的初始化代码（例如 `.init` 和 `.ctors` 段）。

在图形相关的场景中，`libvulkan.so` 或其他图形库会在初始化阶段打开 DRM 设备文件 (`/dev/dri/cardX`)，并获取文件描述符，以便后续使用 `ioctl` 与内核驱动通信。

**逻辑推理、假设输入与输出**

假设我们调用 `DRM_IOCTL_XE_GEM_CREATE` 来创建一个 4MB 的 GPU 内存对象，用于扫描输出 (帧缓冲区)。

**假设输入:**

* `fd`:  指向 DRM 设备的有效文件描述符 (例如通过 `open("/dev/dri/card0", O_RDWR)`) 获得。
* `request`: `DRM_IOCTL_XE_GEM_CREATE` 的宏展开值。
* `argp`: 指向 `struct drm_xe_gem_create` 结构体的指针，该结构体的内容如下：
    ```c
    struct drm_xe_gem_create create_params = {
        .extensions = 0,
        .size = 4 * 1024 * 1024, // 4MB
        .placement = 0,          // 默认放置
        .flags = DRM_XE_GEM_CREATE_FLAG_SCANOUT,
        .vm_id = 0,              // 默认 VM ID
        .handle = 0,             // 由内核填充
        .cpu_caching = DRM_XE_GEM_CPU_CACHING_WB, // 写回缓存
        .pad = {0},
        .reserved = {0}
    };
    ```

**预期输出:**

* `ioctl` 函数返回 0，表示成功。
* `create_params.handle` 被内核驱动填充为一个非零的整数值，表示新创建的 GEM 对象的句柄。这个句柄可以用于后续的 GPU 操作，例如映射到用户空间或提交到执行队列。

**用户或编程常见的使用错误**

1. **无效的文件描述符:**  在调用 `ioctl` 之前没有正确打开 DRM 设备文件，或者使用了已经关闭的文件描述符。
   ```c
   int fd;
   // 忘记 open 或者 open 失败
   struct drm_xe_gem_create create_params = { /* ... */ };
   ioctl(fd, DRM_IOCTL_XE_GEM_CREATE, &create_params); // 错误：fd 无效
   ```

2. **错误的 IOCTL 请求码:**  使用了与驱动程序不匹配的 IOCTL 请求码。
   ```c
   int fd = open("/dev/dri/card0", O_RDWR);
   struct drm_xe_gem_create create_params = { /* ... */ };
   ioctl(fd, DRM_IOCTL_XE_VM_CREATE, &create_params); // 错误：应该使用 DRM_IOCTL_XE_GEM_CREATE
   ```

3. **参数结构体初始化错误:**  没有正确初始化参数结构体，导致传递给内核驱动的数据不正确。例如，大小字段设置为 0。
   ```c
   int fd = open("/dev/dri/card0", O_RDWR);
   struct drm_xe_gem_create create_params; // 没有初始化
   ioctl(fd, DRM_IOCTL_XE_GEM_CREATE, &create_params); // 错误：create_params 的内容是未定义的
   ```

4. **缓冲区溢出:**  在某些 IOCTL 中，内核驱动会将数据写回用户空间的缓冲区。如果用户提供的缓冲区太小，可能会导致缓冲区溢出。

5. **权限问题:**  用户程序可能没有足够的权限访问 DRM 设备文件。

6. **不正确的内存管理:**  例如，创建了 GEM 对象但没有正确释放，导致 GPU 内存泄漏。

7. **并发问题:**  在多线程程序中，如果没有采取适当的同步措施，多个线程可能同时访问和修改 DRM 资源，导致竞争条件和未定义的行为。

**Android Framework 或 NDK 如何到达这里**

一个典型的流程如下：

1. **Android 应用使用图形 API:**  例如，一个游戏应用使用 OpenGL ES 或 Vulkan 进行渲染。
2. **NDK 库调用:**  应用的渲染代码最终会调用 NDK 提供的图形库（例如 libEGL.so, libGLESv3.so 或 Vulkan Loader）。
3. **图形驱动库:** NDK 库会调用 vendor 提供的特定于 GPU 的驱动库（例如上面例子中的 `libVkLayer_intel_xe.so`）。
4. **Mesa 库 (对于 OpenGL ES):**  对于 OpenGL ES，通常会涉及到 Mesa 3D 图形库的实现。
5. **DRM 库 (libdrm):** 图形驱动库或 Mesa 库会使用 `libdrm.so` 库，这是一个用户空间库，封装了与 DRM 内核接口的交互。
6. **`ioctl` 系统调用:** `libdrm.so` 最终会调用 `ioctl` 系统调用，并使用 `xe_drm.h` 中定义的 IOCTL 命令和数据结构与 Intel Xe DRM 驱动进行通信。

**Frida Hook 示例调试步骤**

可以使用 Frida Hook 来观察 Android 图形栈如何使用这些 IOCTL。以下是一个简单的 Frida Hook 示例，用于监控 `DRM_IOCTL_XE_GEM_CREATE` 的调用：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(['com.example.my_graphics_app']) # 替换为你的应用包名
    if not pid:
        device.resume(session.pid)
    script = session.create_script("""
        const IOCTL_MAGIC = 0xad; // _IO, _IOR, _IOW, _IOWR 等宏定义的 magic number
        const DRM_COMMAND_BASE = 0x40; // 根据 DRM 驱动的定义

        const DRM_XE_GEM_CREATE = 0x01;
        const DRM_IOCTL_XE_GEM_CREATE = _IOWR(IOCTL_MAGIC, DRM_COMMAND_BASE + DRM_XE_GEM_CREATE, 0); // 假设第三个参数是大小

        const ioctlPtr = Module.findExportByName(null, "ioctl");
        if (ioctlPtr) {
            Interceptor.attach(ioctlPtr, {
                onEnter: function(args) {
                    const fd = args[0].toInt32();
                    const request = args[1].toInt32();

                    if (request === DRM_IOCTL_XE_GEM_CREATE) {
                        send({ type: 'info', payload: "Detected DRM_IOCTL_XE_GEM_CREATE" });
                        const createParamsPtr = args[2];
                        const size = createParamsPtr.readU64(); // 假设 size 是结构体的第一个成员
                        send({ type: 'info', payload: "GEM size: " + size });
                        // 可以进一步读取其他结构体成员
                    }
                }
            });
        } else {
            send({ type: 'error', payload: "Failed to find ioctl function" });
        }

        function _IOWR(type, nr, size) {
            return (type << 0) | (size << 8) | (nr << 16) | (0x02 << 30); // 0x02 for read/write
        }
    """)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()
except frida.common.rpc_error.RPCError as e:
    print(f"[-] Frida RPCError: {e}")
except KeyboardInterrupt:
    print("[*] Exiting...")
    if 'session' in locals():
        session.detach()
    sys.exit()

```

**步骤解释:**

1. **导入 Frida 库:**  导入 `frida` 和 `sys` 库。
2. **定义消息处理函数:** `on_message` 函数用于处理 Frida 脚本发送的消息。
3. **连接到设备/应用:** 使用 `frida.get_usb_device()` 连接到 USB 设备，并通过进程 ID (`pid`) 或应用包名附加到目标应用。
4. **创建 Frida 脚本:**  使用 JavaScript 代码创建 Frida 脚本。
5. **定义 IOCTL 常量:**  在脚本中定义 `DRM_IOCTL_XE_GEM_CREATE` 的值。**注意：这里需要根据实际的宏定义计算出具体的值。**
6. **查找 `ioctl` 函数:** 使用 `Module.findExportByName()` 查找 `ioctl` 函数的地址。
7. **Hook `ioctl` 函数:** 使用 `Interceptor.attach()` Hook `ioctl` 函数。
8. **`onEnter` 回调:** 在 `onEnter` 回调函数中，检查 `request` 参数是否为 `DRM_IOCTL_XE_GEM_CREATE`。
9. **读取参数:** 如果是 `DRM_IOCTL_XE_GEM_CREATE`，则读取指向 `drm_xe_gem_create` 结构体的指针，并从中读取 `size` 成员（假设 `size` 是第一个成员）。
10. **发送消息:** 使用 `send()` 函数将检测到的信息发送回 Python 脚本。
11. **加载脚本:** 使用 `script.load()` 加载并运行 Frida 脚本。
12. **接收消息:** Python 脚本的 `on_message` 函数会打印接收到的消息。

**运行此脚本:**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 确保已安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 如果要附加到正在运行的进程，找到目标应用的进程 ID (`pid`)。
4. 运行脚本：`python your_frida_script.py [进程ID]`  (如果附加到现有进程) 或 `python your_frida_script.py` (如果让 Frida 启动应用)。

通过这个 Frida Hook 示例，你可以观察到当 Android 应用请求分配 GPU 内存时，`ioctl` 系统调用是如何被调用的，以及传递给内核驱动的参数是什么。你可以修改脚本来 hook 其他的 IOCTL 并检查相关的参数。

希望这个详细的分析能够帮助你理解 `bionic/libc/kernel/uapi/drm/xe_drm.handroid` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/drm/xe_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_XE_DRM_H_
#define _UAPI_XE_DRM_H_
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_XE_DEVICE_QUERY 0x00
#define DRM_XE_GEM_CREATE 0x01
#define DRM_XE_GEM_MMAP_OFFSET 0x02
#define DRM_XE_VM_CREATE 0x03
#define DRM_XE_VM_DESTROY 0x04
#define DRM_XE_VM_BIND 0x05
#define DRM_XE_EXEC_QUEUE_CREATE 0x06
#define DRM_XE_EXEC_QUEUE_DESTROY 0x07
#define DRM_XE_EXEC_QUEUE_GET_PROPERTY 0x08
#define DRM_XE_EXEC 0x09
#define DRM_XE_WAIT_USER_FENCE 0x0a
#define DRM_XE_OBSERVATION 0x0b
#define DRM_IOCTL_XE_DEVICE_QUERY DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY, struct drm_xe_device_query)
#define DRM_IOCTL_XE_GEM_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_CREATE, struct drm_xe_gem_create)
#define DRM_IOCTL_XE_GEM_MMAP_OFFSET DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_MMAP_OFFSET, struct drm_xe_gem_mmap_offset)
#define DRM_IOCTL_XE_VM_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_VM_CREATE, struct drm_xe_vm_create)
#define DRM_IOCTL_XE_VM_DESTROY DRM_IOW(DRM_COMMAND_BASE + DRM_XE_VM_DESTROY, struct drm_xe_vm_destroy)
#define DRM_IOCTL_XE_VM_BIND DRM_IOW(DRM_COMMAND_BASE + DRM_XE_VM_BIND, struct drm_xe_vm_bind)
#define DRM_IOCTL_XE_EXEC_QUEUE_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_CREATE, struct drm_xe_exec_queue_create)
#define DRM_IOCTL_XE_EXEC_QUEUE_DESTROY DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_DESTROY, struct drm_xe_exec_queue_destroy)
#define DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_GET_PROPERTY, struct drm_xe_exec_queue_get_property)
#define DRM_IOCTL_XE_EXEC DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC, struct drm_xe_exec)
#define DRM_IOCTL_XE_WAIT_USER_FENCE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_WAIT_USER_FENCE, struct drm_xe_wait_user_fence)
#define DRM_IOCTL_XE_OBSERVATION DRM_IOW(DRM_COMMAND_BASE + DRM_XE_OBSERVATION, struct drm_xe_observation_param)
struct drm_xe_user_extension {
  __u64 next_extension;
  __u32 name;
  __u32 pad;
};
struct drm_xe_ext_set_property {
  struct drm_xe_user_extension base;
  __u32 property;
  __u32 pad;
  __u64 value;
  __u64 reserved[2];
};
struct drm_xe_engine_class_instance {
#define DRM_XE_ENGINE_CLASS_RENDER 0
#define DRM_XE_ENGINE_CLASS_COPY 1
#define DRM_XE_ENGINE_CLASS_VIDEO_DECODE 2
#define DRM_XE_ENGINE_CLASS_VIDEO_ENHANCE 3
#define DRM_XE_ENGINE_CLASS_COMPUTE 4
#define DRM_XE_ENGINE_CLASS_VM_BIND 5
  __u16 engine_class;
  __u16 engine_instance;
  __u16 gt_id;
  __u16 pad;
};
struct drm_xe_engine {
  struct drm_xe_engine_class_instance instance;
  __u64 reserved[3];
};
struct drm_xe_query_engines {
  __u32 num_engines;
  __u32 pad;
  struct drm_xe_engine engines[];
};
enum drm_xe_memory_class {
  DRM_XE_MEM_REGION_CLASS_SYSMEM = 0,
  DRM_XE_MEM_REGION_CLASS_VRAM
};
struct drm_xe_mem_region {
  __u16 mem_class;
  __u16 instance;
  __u32 min_page_size;
  __u64 total_size;
  __u64 used;
  __u64 cpu_visible_size;
  __u64 cpu_visible_used;
  __u64 reserved[6];
};
struct drm_xe_query_mem_regions {
  __u32 num_mem_regions;
  __u32 pad;
  struct drm_xe_mem_region mem_regions[];
};
struct drm_xe_query_config {
  __u32 num_params;
  __u32 pad;
#define DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID 0
#define DRM_XE_QUERY_CONFIG_FLAGS 1
#define DRM_XE_QUERY_CONFIG_FLAG_HAS_VRAM (1 << 0)
#define DRM_XE_QUERY_CONFIG_MIN_ALIGNMENT 2
#define DRM_XE_QUERY_CONFIG_VA_BITS 3
#define DRM_XE_QUERY_CONFIG_MAX_EXEC_QUEUE_PRIORITY 4
  __u64 info[];
};
struct drm_xe_gt {
#define DRM_XE_QUERY_GT_TYPE_MAIN 0
#define DRM_XE_QUERY_GT_TYPE_MEDIA 1
  __u16 type;
  __u16 tile_id;
  __u16 gt_id;
  __u16 pad[3];
  __u32 reference_clock;
  __u64 near_mem_regions;
  __u64 far_mem_regions;
  __u16 ip_ver_major;
  __u16 ip_ver_minor;
  __u16 ip_ver_rev;
  __u16 pad2;
  __u64 reserved[7];
};
struct drm_xe_query_gt_list {
  __u32 num_gt;
  __u32 pad;
  struct drm_xe_gt gt_list[];
};
struct drm_xe_query_topology_mask {
  __u16 gt_id;
#define DRM_XE_TOPO_DSS_GEOMETRY 1
#define DRM_XE_TOPO_DSS_COMPUTE 2
#define DRM_XE_TOPO_L3_BANK 3
#define DRM_XE_TOPO_EU_PER_DSS 4
#define DRM_XE_TOPO_SIMD16_EU_PER_DSS 5
  __u16 type;
  __u32 num_bytes;
  __u8 mask[];
};
struct drm_xe_query_engine_cycles {
  struct drm_xe_engine_class_instance eci;
  __s32 clockid;
  __u32 width;
  __u64 engine_cycles;
  __u64 cpu_timestamp;
  __u64 cpu_delta;
};
struct drm_xe_query_uc_fw_version {
#define XE_QUERY_UC_TYPE_GUC_SUBMISSION 0
#define XE_QUERY_UC_TYPE_HUC 1
  __u16 uc_type;
  __u16 pad;
  __u32 branch_ver;
  __u32 major_ver;
  __u32 minor_ver;
  __u32 patch_ver;
  __u32 pad2;
  __u64 reserved;
};
struct drm_xe_device_query {
  __u64 extensions;
#define DRM_XE_DEVICE_QUERY_ENGINES 0
#define DRM_XE_DEVICE_QUERY_MEM_REGIONS 1
#define DRM_XE_DEVICE_QUERY_CONFIG 2
#define DRM_XE_DEVICE_QUERY_GT_LIST 3
#define DRM_XE_DEVICE_QUERY_HWCONFIG 4
#define DRM_XE_DEVICE_QUERY_GT_TOPOLOGY 5
#define DRM_XE_DEVICE_QUERY_ENGINE_CYCLES 6
#define DRM_XE_DEVICE_QUERY_UC_FW_VERSION 7
#define DRM_XE_DEVICE_QUERY_OA_UNITS 8
  __u32 query;
  __u32 size;
  __u64 data;
  __u64 reserved[2];
};
struct drm_xe_gem_create {
  __u64 extensions;
  __u64 size;
  __u32 placement;
#define DRM_XE_GEM_CREATE_FLAG_DEFER_BACKING (1 << 0)
#define DRM_XE_GEM_CREATE_FLAG_SCANOUT (1 << 1)
#define DRM_XE_GEM_CREATE_FLAG_NEEDS_VISIBLE_VRAM (1 << 2)
  __u32 flags;
  __u32 vm_id;
  __u32 handle;
#define DRM_XE_GEM_CPU_CACHING_WB 1
#define DRM_XE_GEM_CPU_CACHING_WC 2
  __u16 cpu_caching;
  __u16 pad[3];
  __u64 reserved[2];
};
struct drm_xe_gem_mmap_offset {
  __u64 extensions;
  __u32 handle;
  __u32 flags;
  __u64 offset;
  __u64 reserved[2];
};
struct drm_xe_vm_create {
  __u64 extensions;
#define DRM_XE_VM_CREATE_FLAG_SCRATCH_PAGE (1 << 0)
#define DRM_XE_VM_CREATE_FLAG_LR_MODE (1 << 1)
#define DRM_XE_VM_CREATE_FLAG_FAULT_MODE (1 << 2)
  __u32 flags;
  __u32 vm_id;
  __u64 reserved[2];
};
struct drm_xe_vm_destroy {
  __u32 vm_id;
  __u32 pad;
  __u64 reserved[2];
};
struct drm_xe_vm_bind_op {
  __u64 extensions;
  __u32 obj;
  __u16 pat_index;
  __u16 pad;
  union {
    __u64 obj_offset;
    __u64 userptr;
  };
  __u64 range;
  __u64 addr;
#define DRM_XE_VM_BIND_OP_MAP 0x0
#define DRM_XE_VM_BIND_OP_UNMAP 0x1
#define DRM_XE_VM_BIND_OP_MAP_USERPTR 0x2
#define DRM_XE_VM_BIND_OP_UNMAP_ALL 0x3
#define DRM_XE_VM_BIND_OP_PREFETCH 0x4
  __u32 op;
#define DRM_XE_VM_BIND_FLAG_READONLY (1 << 0)
#define DRM_XE_VM_BIND_FLAG_IMMEDIATE (1 << 1)
#define DRM_XE_VM_BIND_FLAG_NULL (1 << 2)
#define DRM_XE_VM_BIND_FLAG_DUMPABLE (1 << 3)
  __u32 flags;
  __u32 prefetch_mem_region_instance;
  __u32 pad2;
  __u64 reserved[3];
};
struct drm_xe_vm_bind {
  __u64 extensions;
  __u32 vm_id;
  __u32 exec_queue_id;
  __u32 pad;
  __u32 num_binds;
  union {
    struct drm_xe_vm_bind_op bind;
    __u64 vector_of_binds;
  };
  __u32 pad2;
  __u32 num_syncs;
  __u64 syncs;
  __u64 reserved[2];
};
struct drm_xe_exec_queue_create {
#define DRM_XE_EXEC_QUEUE_EXTENSION_SET_PROPERTY 0
#define DRM_XE_EXEC_QUEUE_SET_PROPERTY_PRIORITY 0
#define DRM_XE_EXEC_QUEUE_SET_PROPERTY_TIMESLICE 1
  __u64 extensions;
  __u16 width;
  __u16 num_placements;
  __u32 vm_id;
  __u32 flags;
  __u32 exec_queue_id;
  __u64 instances;
  __u64 reserved[2];
};
struct drm_xe_exec_queue_destroy {
  __u32 exec_queue_id;
  __u32 pad;
  __u64 reserved[2];
};
struct drm_xe_exec_queue_get_property {
  __u64 extensions;
  __u32 exec_queue_id;
#define DRM_XE_EXEC_QUEUE_GET_PROPERTY_BAN 0
  __u32 property;
  __u64 value;
  __u64 reserved[2];
};
struct drm_xe_sync {
  __u64 extensions;
#define DRM_XE_SYNC_TYPE_SYNCOBJ 0x0
#define DRM_XE_SYNC_TYPE_TIMELINE_SYNCOBJ 0x1
#define DRM_XE_SYNC_TYPE_USER_FENCE 0x2
  __u32 type;
#define DRM_XE_SYNC_FLAG_SIGNAL (1 << 0)
  __u32 flags;
  union {
    __u32 handle;
    __u64 addr;
  };
  __u64 timeline_value;
  __u64 reserved[2];
};
struct drm_xe_exec {
  __u64 extensions;
  __u32 exec_queue_id;
  __u32 num_syncs;
  __u64 syncs;
  __u64 address;
  __u16 num_batch_buffer;
  __u16 pad[3];
  __u64 reserved[2];
};
struct drm_xe_wait_user_fence {
  __u64 extensions;
  __u64 addr;
#define DRM_XE_UFENCE_WAIT_OP_EQ 0x0
#define DRM_XE_UFENCE_WAIT_OP_NEQ 0x1
#define DRM_XE_UFENCE_WAIT_OP_GT 0x2
#define DRM_XE_UFENCE_WAIT_OP_GTE 0x3
#define DRM_XE_UFENCE_WAIT_OP_LT 0x4
#define DRM_XE_UFENCE_WAIT_OP_LTE 0x5
  __u16 op;
#define DRM_XE_UFENCE_WAIT_FLAG_ABSTIME (1 << 0)
  __u16 flags;
  __u32 pad;
  __u64 value;
  __u64 mask;
  __s64 timeout;
  __u32 exec_queue_id;
  __u32 pad2;
  __u64 reserved[2];
};
enum drm_xe_observation_type {
  DRM_XE_OBSERVATION_TYPE_OA,
};
enum drm_xe_observation_op {
  DRM_XE_OBSERVATION_OP_STREAM_OPEN,
  DRM_XE_OBSERVATION_OP_ADD_CONFIG,
  DRM_XE_OBSERVATION_OP_REMOVE_CONFIG,
};
struct drm_xe_observation_param {
  __u64 extensions;
  __u64 observation_type;
  __u64 observation_op;
  __u64 param;
};
enum drm_xe_observation_ioctls {
  DRM_XE_OBSERVATION_IOCTL_ENABLE = _IO('i', 0x0),
  DRM_XE_OBSERVATION_IOCTL_DISABLE = _IO('i', 0x1),
  DRM_XE_OBSERVATION_IOCTL_CONFIG = _IO('i', 0x2),
  DRM_XE_OBSERVATION_IOCTL_STATUS = _IO('i', 0x3),
  DRM_XE_OBSERVATION_IOCTL_INFO = _IO('i', 0x4),
};
enum drm_xe_oa_unit_type {
  DRM_XE_OA_UNIT_TYPE_OAG,
  DRM_XE_OA_UNIT_TYPE_OAM,
};
struct drm_xe_oa_unit {
  __u64 extensions;
  __u32 oa_unit_id;
  __u32 oa_unit_type;
  __u64 capabilities;
#define DRM_XE_OA_CAPS_BASE (1 << 0)
  __u64 oa_timestamp_freq;
  __u64 reserved[4];
  __u64 num_engines;
  struct drm_xe_engine_class_instance eci[];
};
struct drm_xe_query_oa_units {
  __u64 extensions;
  __u32 num_oa_units;
  __u32 pad;
  __u64 oa_units[];
};
enum drm_xe_oa_format_type {
  DRM_XE_OA_FMT_TYPE_OAG,
  DRM_XE_OA_FMT_TYPE_OAR,
  DRM_XE_OA_FMT_TYPE_OAM,
  DRM_XE_OA_FMT_TYPE_OAC,
  DRM_XE_OA_FMT_TYPE_OAM_MPEC,
  DRM_XE_OA_FMT_TYPE_PEC,
};
enum drm_xe_oa_property_id {
#define DRM_XE_OA_EXTENSION_SET_PROPERTY 0
  DRM_XE_OA_PROPERTY_OA_UNIT_ID = 1,
  DRM_XE_OA_PROPERTY_SAMPLE_OA,
  DRM_XE_OA_PROPERTY_OA_METRIC_SET,
  DRM_XE_OA_PROPERTY_OA_FORMAT,
#define DRM_XE_OA_FORMAT_MASK_FMT_TYPE (0xffu << 0)
#define DRM_XE_OA_FORMAT_MASK_COUNTER_SEL (0xffu << 8)
#define DRM_XE_OA_FORMAT_MASK_COUNTER_SIZE (0xffu << 16)
#define DRM_XE_OA_FORMAT_MASK_BC_REPORT (0xffu << 24)
  DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT,
  DRM_XE_OA_PROPERTY_OA_DISABLED,
  DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID,
  DRM_XE_OA_PROPERTY_OA_ENGINE_INSTANCE,
  DRM_XE_OA_PROPERTY_NO_PREEMPT,
};
struct drm_xe_oa_config {
  __u64 extensions;
  char uuid[36];
  __u32 n_regs;
  __u64 regs_ptr;
};
struct drm_xe_oa_stream_status {
  __u64 extensions;
  __u64 oa_status;
#define DRM_XE_OASTATUS_MMIO_TRG_Q_FULL (1 << 3)
#define DRM_XE_OASTATUS_COUNTER_OVERFLOW (1 << 2)
#define DRM_XE_OASTATUS_BUFFER_OVERFLOW (1 << 1)
#define DRM_XE_OASTATUS_REPORT_LOST (1 << 0)
  __u64 reserved[3];
};
struct drm_xe_oa_stream_info {
  __u64 extensions;
  __u64 oa_buf_size;
  __u64 reserved[3];
};
#ifdef __cplusplus
}
#endif
#endif

"""

```