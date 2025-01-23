Response:
Let's break down the thought process for analyzing the provided header file `panthor_drm.h`.

**1. Initial Scan and Purpose Identification:**

The first thing I notice is the comment at the top: "This file is auto-generated. Modifications will be lost." and the link to the bionic repository. This immediately tells me this is a low-level, likely kernel-facing interface. The name `panthor_drm.h` strongly suggests it's related to the Direct Rendering Manager (DRM) subsystem within the Linux kernel, and specifically for a GPU with the codename "Panthor." The "handroid bionic" part confirms its use within the Android ecosystem.

**2. Core Functionality - DRM IOCTLs:**

My eyes are drawn to the `DRM_IOCTL_PANTHOR` macros and the `enum drm_panthor_ioctl_id`. These are the primary means by which user-space applications interact with the Panthor GPU driver in the kernel. I recognize the `DRM_IOCTL_*` pattern which is standard for DRM. I list these out and interpret their potential meanings based on their names:

* `DEV_QUERY`:  Getting information about the device (GPU).
* `VM_CREATE/DESTROY`: Managing virtual memory spaces for the GPU.
* `VM_BIND`: Mapping GPU buffers into the GPU's virtual address space.
* `VM_GET_STATE`: Checking the status of a GPU virtual memory space.
* `BO_CREATE`: Allocating GPU buffers (Buffer Objects).
* `BO_MMAP_OFFSET`:  Getting an offset to mmap a GPU buffer.
* `GROUP_CREATE/DESTROY`:  Managing groups of execution queues.
* `GROUP_SUBMIT`: Submitting work to the GPU.
* `GROUP_GET_STATE`: Checking the status of submitted work.
* `TILER_HEAP_CREATE/DESTROY`: Managing memory specifically for the GPU's tiling functionality.

**3. Data Structures and Their Roles:**

Next, I examine the `struct` definitions. I try to connect them to the IOCTLs. For example, `drm_panthor_dev_query` is clearly used with `DRM_IOCTL_PANTHOR_DEV_QUERY`. I go through each structure and try to understand what information it holds and how it relates to the overall GPU management. Key structures I identify and analyze are:

* **`drm_panthor_gpu_info`:**  Detailed information about the GPU hardware (ID, revision, features). The bit-field macros like `DRM_PANTHOR_ARCH_MAJOR` are important for decoding this information.
* **`drm_panthor_csif_info`:** Information about the command stream interface.
* **`drm_panthor_vm_*` structures:**  Related to virtual memory management on the GPU, including creating VMs, binding buffers, and getting state. The `flags` fields are significant, indicating different options.
* **`drm_panthor_bo_*` structures:**  Related to buffer object management (creation and mapping).
* **`drm_panthor_group_*` structures:**  Central to submitting work to the GPU, involving queues and synchronization.
* **`drm_panthor_tiler_heap_*` structures:** Specific to managing tiled memory.
* **`drm_panthor_sync_op`:**  Deals with synchronization primitives (sync objects or timeline sync objects).
* **`drm_panthor_obj_array`:**  A helper structure to pass arrays of objects (like sync operations) to the kernel.

**4. Identifying Android Relevance:**

Knowing this is an Android file, I consider how these functions relate to Android's graphics stack. DRM is a fundamental part of how Android interacts with GPUs. I make the connection that user-space graphics libraries (like those used by SurfaceFlinger, Vulkan, OpenGL ES) would use these IOCTLs indirectly or through higher-level wrappers.

**5. `libc` and Dynamic Linker Aspects:**

I review the file for direct usage of `libc` functions. I see none directly called within *this header file*. This is expected, as it's a header defining the *interface* to the kernel. The `libc` connection is that the data structures defined here are used by user-space programs, which *do* use `libc` functions for tasks like opening the DRM device (`/dev/dri/cardX`) and calling the `ioctl()` system call.

Regarding the dynamic linker, the header file itself doesn't directly involve it. However, I recognize that the eventual user-space libraries that interact with this driver *will* be dynamically linked. I consider how those libraries would be laid out in memory (.so files, dependencies) and how the linker resolves symbols. I provide a generic example of an SO layout.

**6. Logic and Assumptions:**

When discussing the IOCTLs, I make logical deductions about their purpose based on their names and the associated data structures. For example, I assume `DRM_PANTHOR_VM_BIND` takes a buffer object and maps it into a virtual address space. My assumptions are based on general knowledge of DRM and GPU architecture.

**7. Common Usage Errors:**

I think about common mistakes a developer might make when using these IOCTLs, such as passing invalid handles, incorrect sizes, or improper synchronization.

**8. Tracing the Call Path (Framework/NDK to Kernel):**

I start from the user-facing side (Android Framework/NDK) and work my way down. I know that higher-level graphics APIs eventually need to interact with the kernel driver. I outline the likely path:

* **NDK (Vulkan, OpenGL ES):** Developers use these APIs.
* **Implementation Libraries (e.g., libvulkan.so, libGLESv2.so):** These libraries translate API calls into lower-level operations.
* **DRM Library (libdrm.so):** This library provides a standard way to interact with DRM drivers, including opening the device and making `ioctl()` calls.
* **System Call (`ioctl()`):** This is the actual kernel entry point.
* **Kernel DRM Subsystem:**  The kernel's DRM framework handles the `ioctl()` call.
* **Panthor DRM Driver:** The specific driver for the Panthor GPU handles the Panthor-specific IOCTLs.

**9. Frida Hooking:**

Finally, I think about how to use Frida to inspect these interactions. I target the `ioctl()` system call and potentially functions within the `libdrm.so` library to intercept the specific DRM IOCTL calls related to Panthor. I provide example Frida scripts for both scenarios.

**Self-Correction/Refinement:**

Throughout this process, I might re-evaluate my initial assumptions. For instance, if I see a structure that doesn't quite fit my initial understanding of an IOCTL, I would revisit the documentation or the structure's members to refine my interpretation. I also ensure my explanations are clear, concise, and avoid overly technical jargon where possible. I double-check that my Frida examples target the correct functions and parameters.
这个头文件 `bionic/libc/kernel/uapi/drm/panthor_drm.h` 定义了用户空间程序与 Panthor GPU 内核驱动进行交互的接口。Panthor 很可能是某个特定 GPU 的代号。这个文件是 Android Bionic 库的一部分，它提供了访问 Linux 内核 DRM (Direct Rendering Manager) 子系统的接口。

**功能列表:**

该头文件定义了以下主要功能，这些功能通过一系列的 IOCTL (Input/Output Control) 命令实现：

1. **设备查询 (Device Query):**
   - `DRM_IOCTL_PANTHOR_DEV_QUERY`: 用于查询 Panthor GPU 的信息，例如 GPU ID、架构信息、特性等。

2. **虚拟机管理 (Virtual Machine Management):**
   - `DRM_IOCTL_PANTHOR_VM_CREATE`: 创建 GPU 虚拟机 (VM)，允许用户空间进程拥有隔离的 GPU 虚拟地址空间。
   - `DRM_IOCTL_PANTHOR_VM_DESTROY`: 销毁已创建的 GPU 虚拟机。
   - `DRM_IOCTL_PANTHOR_VM_BIND`: 将 GPU 缓冲区对象 (Buffer Object, BO) 映射到 GPU 虚拟机的地址空间。
   - `DRM_IOCTL_PANTHOR_VM_GET_STATE`: 获取 GPU 虚拟机的状态。

3. **缓冲区对象管理 (Buffer Object Management):**
   - `DRM_IOCTL_PANTHOR_BO_CREATE`: 创建 GPU 缓冲区对象，用于存储 GPU 需要处理的数据。
   - `DRM_IOCTL_PANTHOR_BO_MMAP_OFFSET`: 获取可以用于 `mmap` 系统调用的偏移量，以便将 GPU 缓冲区对象映射到用户空间进程的地址空间。

4. **执行组管理 (Execution Group Management):**
   - `DRM_IOCTL_PANTHOR_GROUP_CREATE`: 创建 GPU 执行组，用于组织和调度 GPU 上的计算任务。
   - `DRM_IOCTL_PANTHOR_GROUP_DESTROY`: 销毁已创建的 GPU 执行组。
   - `DRM_IOCTL_PANTHOR_GROUP_SUBMIT`: 提交任务到 GPU 执行组进行处理。
   - `DRM_IOCTL_PANTHOR_GROUP_GET_STATE`: 获取 GPU 执行组的状态，例如是否完成、是否发生错误等。

5. **瓦片堆管理 (Tiler Heap Management):**
   - `DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE`: 创建 GPU 瓦片堆，用于管理 GPU 上的瓦片内存，这是一种用于高效渲染的技术。
   - `DRM_IOCTL_PANTHOR_TILER_HEAP_DESTROY`: 销毁已创建的 GPU 瓦片堆。

**与 Android 功能的关系及举例说明:**

这些功能是 Android 图形栈的核心组成部分，用于实现 GPU 资源的分配、管理和任务调度。

* **SurfaceFlinger:** Android 的 SurfaceFlinger 服务负责合成屏幕上的所有图层。它会使用 DRM 接口来管理显示设备的帧缓冲区，并可能使用 GPU 执行组来执行合成操作。例如，SurfaceFlinger 可能会创建 BO 来存储屏幕内容，并使用 VM 绑定将其映射到 GPU 地址空间，然后提交执行组来完成图层混合和渲染。
* **图形 API (OpenGL ES, Vulkan):**  当应用程序使用 OpenGL ES 或 Vulkan 进行图形渲染时，底层的图形驱动程序会使用这些 DRM IOCTL 来与 GPU 硬件交互。
    * **BO 创建:**  创建用于存储顶点数据、纹理数据的 GPU 缓冲区。
    * **VM 管理:**  管理 GPU 虚拟地址空间，将这些缓冲区映射到 GPU 可以访问的地址。
    * **执行组提交:**  提交渲染命令到 GPU 执行组进行执行。
* **计算任务:**  Android 可以使用 GPU 进行通用计算。例如，机器学习框架 (如 TensorFlow Lite) 可以利用这些接口来创建 BO 存储模型和数据，并使用执行组在 GPU 上运行计算密集型任务。

**libc 函数的实现:**

这个头文件本身并没有实现任何 `libc` 函数。它只是定义了一些宏、枚举和结构体，作为用户空间程序与内核驱动通信的协议。

用户空间程序会使用 `libc` 提供的系统调用接口，例如 `open` 打开 DRM 设备文件 (通常位于 `/dev/dri/cardX`)，然后使用 `ioctl` 系统调用来发送这些定义的命令到内核驱动。

`ioctl` 系统调用的功能是向设备驱动程序发送控制命令。它的实现细节在 Linux 内核中，涉及到文件系统的驱动程序框架。当用户空间程序调用 `ioctl` 时，内核会根据传入的文件描述符找到对应的设备驱动程序，并将命令和参数传递给驱动程序的 `ioctl` 函数进行处理。

**涉及 dynamic linker 的功能:**

这个头文件本身并不直接涉及动态链接器。然而，使用这些定义的程序通常是动态链接的，例如图形驱动程序的用户空间部分 (`libGLESv2.so`, `libvulkan.so`) 或者使用 GPU 计算的库。

**so 布局样本:**

假设有一个名为 `libpanthorgpu.so` 的动态链接库，它使用了这里定义的 DRM 接口：

```
libpanthorgpu.so:
    NEEDED libdrm.so   // 依赖于 libdrm.so 库来与 DRM 子系统交互
    NEEDED libc.so
    ...其他依赖库...

    .text         // 代码段
        function_a:
            ; 调用 ioctl 发送 DRM_IOCTL_PANTHOR_BO_CREATE 等命令
            ; ...
        function_b:
            ; ...
    .rodata       // 只读数据段
        string_constant: "Panthor GPU Initialized"
    .data         // 可读写数据段
        global_variable: 0
```

**链接的处理过程:**

1. **编译时:** 编译器会根据头文件中的定义，生成调用 `ioctl` 系统调用的代码，并使用宏定义生成正确的 IOCTL 命令号。
2. **链接时:** 动态链接器会解析 `libpanthorgpu.so` 的依赖关系，找到 `libdrm.so` 和 `libc.so` 等共享库。
3. **运行时:** 当程序加载 `libpanthorgpu.so` 时，动态链接器会将 `libdrm.so` 和 `libc.so` 加载到进程的地址空间，并解析符号引用，将 `libpanthorgpu.so` 中对 `ioctl` 等函数的调用链接到 `libc.so` 中对应的实现。

**逻辑推理、假设输入与输出:**

假设一个程序想要创建一个 GPU 缓冲区对象：

**假设输入:**

* 打开 DRM 设备文件描述符 `fd`.
* `size` (缓冲区大小): 1024 字节.
* `flags`: 0 (默认标志).
* `exclusive_vm_id`: 0 (不绑定到特定的 VM).

**程序代码 (简化):**

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "panthor_drm.h"
#include <unistd.h>
#include <errno.h>

int main() {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct drm_panthor_bo_create bo_create_req = {
        .size = 1024,
        .flags = 0,
        .exclusive_vm_id = 0,
    };

    if (ioctl(fd, DRM_IOCTL_PANTHOR_BO_CREATE, &bo_create_req) == -1) {
        perror("ioctl DRM_IOCTL_PANTHOR_BO_CREATE");
        close(fd);
        return 1;
    }

    printf("BO Handle: %u\n", bo_create_req.handle); // 输出新创建的 BO 句柄

    close(fd);
    return 0;
}
```

**预期输出:**

如果调用成功，`ioctl` 会返回 0，并且 `bo_create_req.handle` 会被内核驱动填充为新创建的缓冲区对象的句柄。程序会打印出这个句柄。如果调用失败，`ioctl` 会返回 -1，并且 `errno` 会被设置为相应的错误代码，程序会打印错误信息。

**用户或编程常见的使用错误:**

1. **无效的设备文件描述符:**  在调用 `ioctl` 之前没有成功打开 DRM 设备文件。
2. **错误的 IOCTL 命令号:**  使用了错误的宏定义，导致内核无法识别请求。
3. **参数结构体未正确初始化:**  例如，`size` 或其他必要的字段没有设置正确的值。
4. **权限不足:**  用户可能没有足够的权限访问 DRM 设备。
5. **资源耗尽:**  例如，尝试创建过多的 BO 或 VM，导致 GPU 内存不足。
6. **不匹配的内核驱动版本:**  用户空间程序使用的头文件与内核驱动程序的版本不兼容。
7. **忘记检查返回值:**  没有检查 `ioctl` 的返回值，导致错误没有被及时处理。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **NDK (例如 Vulkan):** 开发者使用 NDK 提供的图形 API，例如 Vulkan。
2. **Vulkan 库 (`libvulkan.so`):**  NDK 的 Vulkan 库会将 Vulkan API 调用转换为底层的 GPU 命令。
3. **图形驱动程序的用户空间部分 (`libpanthorgpu.so` 或类似的):** Vulkan 库会调用特定于 GPU 厂商的驱动程序库。这个库会使用 `libdrm.so` 来与内核交互。
4. **`libdrm.so`:**  这是一个标准的 DRM 库，提供了打开 DRM 设备、执行 IOCTL 等功能的封装。`libdrm.so` 会调用 `libc` 的 `open` 和 `ioctl` 系统调用。
5. **`libc` (`bionic`):**  `libc` 提供了 `open` 和 `ioctl` 等系统调用的实现。
6. **Linux 内核:**  内核接收到 `ioctl` 调用后，会根据设备文件找到对应的 DRM 驱动程序。
7. **Panthor DRM 驱动程序:**  内核中的 Panthor DRM 驱动程序会处理 `DRM_IOCTL_PANTHOR_*` 命令，根据请求进行 GPU 资源管理和任务调度。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 Panthor DRM 相关的调用。

**示例 Frida Hook 脚本:**

```javascript
// hook ioctl 系统调用
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    // 检查文件描述符是否可能是 DRM 设备 (通常 /dev/dri/card*)
    const pathBuf = Memory.allocUtf8String("/proc/self/fd/" + fd);
    const readLinkResult = Socket.readLink(pathBuf.readUtf8String());
    if (readLinkResult && readLinkResult.startsWith("/dev/dri/card")) {
      // 检查是否是 Panthor 相关的 IOCTL
      if ((request & 0xff) == 0xaf) { // 假设 Panthor 的魔数是 0xaf，需要根据实际情况调整
        console.log("ioctl called with fd:", fd, "request:", request.toString(16));

        // 可以进一步解析参数，根据 request 的值来判断是哪个 IOCTL，并解析对应的结构体
        if (request == 0xc010af00) { // 假设 DRM_IOCTL_PANTHOR_DEV_QUERY 的值是 0xc010af00，需要根据实际情况调整
          const argp = args[2];
          const dev_query = argp.readByteArray(24); // 读取 drm_panthor_dev_query 结构体
          console.log("  DRM_IOCTL_PANTHOR_DEV_QUERY, arg:", hexdump(dev_query, { ansi: true }));
        }
        // ... 可以添加其他 IOCTL 的解析
      }
    }
  },
  onLeave: function (retval) {
    // console.log("ioctl returned:", retval.toInt32());
  },
});
```

**调试步骤:**

1. **启动 Frida 服务:**  在 Android 设备或模拟器上启动 Frida 服务。
2. **运行目标应用:**  运行你想要调试的 Android 应用或进程。
3. **执行 Frida Hook 脚本:** 使用 Frida CLI 将上述脚本注入到目标进程：
   ```bash
   frida -U -f <package_name_or_process_name> -l your_script.js --no-pause
   ```
4. **观察输出:**  Frida 会打印出 `ioctl` 调用以及相关的参数信息。你需要根据 `request` 的值和头文件中的定义来解析参数结构体的内容。

通过这种方式，你可以跟踪 Android Framework 或 NDK 如何一步步调用到 Panthor DRM 驱动程序的 IOCTL 接口，并观察传递的参数。这对于理解图形栈的运作机制和调试图形相关问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/drm/panthor_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _PANTHOR_DRM_H_
#define _PANTHOR_DRM_H_
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define DRM_PANTHOR_USER_MMIO_OFFSET_32BIT (1ull << 43)
#define DRM_PANTHOR_USER_MMIO_OFFSET_64BIT (1ull << 56)
#define DRM_PANTHOR_USER_MMIO_OFFSET (sizeof(unsigned long) < 8 ? DRM_PANTHOR_USER_MMIO_OFFSET_32BIT : DRM_PANTHOR_USER_MMIO_OFFSET_64BIT)
#define DRM_PANTHOR_USER_FLUSH_ID_MMIO_OFFSET (DRM_PANTHOR_USER_MMIO_OFFSET | 0)
enum drm_panthor_ioctl_id {
  DRM_PANTHOR_DEV_QUERY = 0,
  DRM_PANTHOR_VM_CREATE,
  DRM_PANTHOR_VM_DESTROY,
  DRM_PANTHOR_VM_BIND,
  DRM_PANTHOR_VM_GET_STATE,
  DRM_PANTHOR_BO_CREATE,
  DRM_PANTHOR_BO_MMAP_OFFSET,
  DRM_PANTHOR_GROUP_CREATE,
  DRM_PANTHOR_GROUP_DESTROY,
  DRM_PANTHOR_GROUP_SUBMIT,
  DRM_PANTHOR_GROUP_GET_STATE,
  DRM_PANTHOR_TILER_HEAP_CREATE,
  DRM_PANTHOR_TILER_HEAP_DESTROY,
};
#define DRM_IOCTL_PANTHOR(__access,__id,__type) DRM_IO ##__access(DRM_COMMAND_BASE + DRM_PANTHOR_ ##__id, struct drm_panthor_ ##__type)
#define DRM_IOCTL_PANTHOR_DEV_QUERY DRM_IOCTL_PANTHOR(WR, DEV_QUERY, dev_query)
#define DRM_IOCTL_PANTHOR_VM_CREATE DRM_IOCTL_PANTHOR(WR, VM_CREATE, vm_create)
#define DRM_IOCTL_PANTHOR_VM_DESTROY DRM_IOCTL_PANTHOR(WR, VM_DESTROY, vm_destroy)
#define DRM_IOCTL_PANTHOR_VM_BIND DRM_IOCTL_PANTHOR(WR, VM_BIND, vm_bind)
#define DRM_IOCTL_PANTHOR_VM_GET_STATE DRM_IOCTL_PANTHOR(WR, VM_GET_STATE, vm_get_state)
#define DRM_IOCTL_PANTHOR_BO_CREATE DRM_IOCTL_PANTHOR(WR, BO_CREATE, bo_create)
#define DRM_IOCTL_PANTHOR_BO_MMAP_OFFSET DRM_IOCTL_PANTHOR(WR, BO_MMAP_OFFSET, bo_mmap_offset)
#define DRM_IOCTL_PANTHOR_GROUP_CREATE DRM_IOCTL_PANTHOR(WR, GROUP_CREATE, group_create)
#define DRM_IOCTL_PANTHOR_GROUP_DESTROY DRM_IOCTL_PANTHOR(WR, GROUP_DESTROY, group_destroy)
#define DRM_IOCTL_PANTHOR_GROUP_SUBMIT DRM_IOCTL_PANTHOR(WR, GROUP_SUBMIT, group_submit)
#define DRM_IOCTL_PANTHOR_GROUP_GET_STATE DRM_IOCTL_PANTHOR(WR, GROUP_GET_STATE, group_get_state)
#define DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE DRM_IOCTL_PANTHOR(WR, TILER_HEAP_CREATE, tiler_heap_create)
#define DRM_IOCTL_PANTHOR_TILER_HEAP_DESTROY DRM_IOCTL_PANTHOR(WR, TILER_HEAP_DESTROY, tiler_heap_destroy)
struct drm_panthor_obj_array {
  __u32 stride;
  __u32 count;
  __u64 array;
};
#define DRM_PANTHOR_OBJ_ARRAY(cnt,ptr) {.stride = sizeof((ptr)[0]),.count = (cnt),.array = (__u64) (uintptr_t) (ptr) }
enum drm_panthor_sync_op_flags {
  DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_MASK = 0xff,
  DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ = 0,
  DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ = 1,
  DRM_PANTHOR_SYNC_OP_WAIT = 0 << 31,
  DRM_PANTHOR_SYNC_OP_SIGNAL = (int) (1u << 31),
};
struct drm_panthor_sync_op {
  __u32 flags;
  __u32 handle;
  __u64 timeline_value;
};
enum drm_panthor_dev_query_type {
  DRM_PANTHOR_DEV_QUERY_GPU_INFO = 0,
  DRM_PANTHOR_DEV_QUERY_CSIF_INFO,
};
struct drm_panthor_gpu_info {
  __u32 gpu_id;
#define DRM_PANTHOR_ARCH_MAJOR(x) ((x) >> 28)
#define DRM_PANTHOR_ARCH_MINOR(x) (((x) >> 24) & 0xf)
#define DRM_PANTHOR_ARCH_REV(x) (((x) >> 20) & 0xf)
#define DRM_PANTHOR_PRODUCT_MAJOR(x) (((x) >> 16) & 0xf)
#define DRM_PANTHOR_VERSION_MAJOR(x) (((x) >> 12) & 0xf)
#define DRM_PANTHOR_VERSION_MINOR(x) (((x) >> 4) & 0xff)
#define DRM_PANTHOR_VERSION_STATUS(x) ((x) & 0xf)
  __u32 gpu_rev;
  __u32 csf_id;
#define DRM_PANTHOR_CSHW_MAJOR(x) (((x) >> 26) & 0x3f)
#define DRM_PANTHOR_CSHW_MINOR(x) (((x) >> 20) & 0x3f)
#define DRM_PANTHOR_CSHW_REV(x) (((x) >> 16) & 0xf)
#define DRM_PANTHOR_MCU_MAJOR(x) (((x) >> 10) & 0x3f)
#define DRM_PANTHOR_MCU_MINOR(x) (((x) >> 4) & 0x3f)
#define DRM_PANTHOR_MCU_REV(x) ((x) & 0xf)
  __u32 l2_features;
  __u32 tiler_features;
  __u32 mem_features;
  __u32 mmu_features;
#define DRM_PANTHOR_MMU_VA_BITS(x) ((x) & 0xff)
  __u32 thread_features;
  __u32 max_threads;
  __u32 thread_max_workgroup_size;
  __u32 thread_max_barrier_size;
  __u32 coherency_features;
  __u32 texture_features[4];
  __u32 as_present;
  __u64 shader_present;
  __u64 l2_present;
  __u64 tiler_present;
  __u32 core_features;
  __u32 pad;
};
struct drm_panthor_csif_info {
  __u32 csg_slot_count;
  __u32 cs_slot_count;
  __u32 cs_reg_count;
  __u32 scoreboard_slot_count;
  __u32 unpreserved_cs_reg_count;
  __u32 pad;
};
struct drm_panthor_dev_query {
  __u32 type;
  __u32 size;
  __u64 pointer;
};
struct drm_panthor_vm_create {
  __u32 flags;
  __u32 id;
  __u64 user_va_range;
};
struct drm_panthor_vm_destroy {
  __u32 id;
  __u32 pad;
};
enum drm_panthor_vm_bind_op_flags {
  DRM_PANTHOR_VM_BIND_OP_MAP_READONLY = 1 << 0,
  DRM_PANTHOR_VM_BIND_OP_MAP_NOEXEC = 1 << 1,
  DRM_PANTHOR_VM_BIND_OP_MAP_UNCACHED = 1 << 2,
  DRM_PANTHOR_VM_BIND_OP_TYPE_MASK = (int) (0xfu << 28),
  DRM_PANTHOR_VM_BIND_OP_TYPE_MAP = 0 << 28,
  DRM_PANTHOR_VM_BIND_OP_TYPE_UNMAP = 1 << 28,
  DRM_PANTHOR_VM_BIND_OP_TYPE_SYNC_ONLY = 2 << 28,
};
struct drm_panthor_vm_bind_op {
  __u32 flags;
  __u32 bo_handle;
  __u64 bo_offset;
  __u64 va;
  __u64 size;
  struct drm_panthor_obj_array syncs;
};
enum drm_panthor_vm_bind_flags {
  DRM_PANTHOR_VM_BIND_ASYNC = 1 << 0,
};
struct drm_panthor_vm_bind {
  __u32 vm_id;
  __u32 flags;
  struct drm_panthor_obj_array ops;
};
enum drm_panthor_vm_state {
  DRM_PANTHOR_VM_STATE_USABLE,
  DRM_PANTHOR_VM_STATE_UNUSABLE,
};
struct drm_panthor_vm_get_state {
  __u32 vm_id;
  __u32 state;
};
enum drm_panthor_bo_flags {
  DRM_PANTHOR_BO_NO_MMAP = (1 << 0),
};
struct drm_panthor_bo_create {
  __u64 size;
  __u32 flags;
  __u32 exclusive_vm_id;
  __u32 handle;
  __u32 pad;
};
struct drm_panthor_bo_mmap_offset {
  __u32 handle;
  __u32 pad;
  __u64 offset;
};
struct drm_panthor_queue_create {
  __u8 priority;
  __u8 pad[3];
  __u32 ringbuf_size;
};
enum drm_panthor_group_priority {
  PANTHOR_GROUP_PRIORITY_LOW = 0,
  PANTHOR_GROUP_PRIORITY_MEDIUM,
  PANTHOR_GROUP_PRIORITY_HIGH,
};
struct drm_panthor_group_create {
  struct drm_panthor_obj_array queues;
  __u8 max_compute_cores;
  __u8 max_fragment_cores;
  __u8 max_tiler_cores;
  __u8 priority;
  __u32 pad;
  __u64 compute_core_mask;
  __u64 fragment_core_mask;
  __u64 tiler_core_mask;
  __u32 vm_id;
  __u32 group_handle;
};
struct drm_panthor_group_destroy {
  __u32 group_handle;
  __u32 pad;
};
struct drm_panthor_queue_submit {
  __u32 queue_index;
  __u32 stream_size;
  __u64 stream_addr;
  __u32 latest_flush;
  __u32 pad;
  struct drm_panthor_obj_array syncs;
};
struct drm_panthor_group_submit {
  __u32 group_handle;
  __u32 pad;
  struct drm_panthor_obj_array queue_submits;
};
enum drm_panthor_group_state_flags {
  DRM_PANTHOR_GROUP_STATE_TIMEDOUT = 1 << 0,
  DRM_PANTHOR_GROUP_STATE_FATAL_FAULT = 1 << 1,
};
struct drm_panthor_group_get_state {
  __u32 group_handle;
  __u32 state;
  __u32 fatal_queues;
  __u32 pad;
};
struct drm_panthor_tiler_heap_create {
  __u32 vm_id;
  __u32 initial_chunk_count;
  __u32 chunk_size;
  __u32 max_chunks;
  __u32 target_in_flight;
  __u32 handle;
  __u64 tiler_heap_ctx_gpu_va;
  __u64 first_heap_chunk_gpu_va;
};
struct drm_panthor_tiler_heap_destroy {
  __u32 handle;
  __u32 pad;
};
#ifdef __cplusplus
}
#endif
#endif
```