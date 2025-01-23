Response:
Let's break down the thought process for generating the detailed response to the KFD ioctl header file.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C header file (`kfd_ioctl.h`) and explain its functionality within the context of Android, including implementation details, dynamic linking, potential errors, and how Android frameworks interact with it. The request emphasizes clarity and detail, requiring specific examples.

**2. Initial Skim and Keyword Identification:**

The first step is to quickly read through the header file, identifying key terms and patterns. This includes:

* **`ioctl`:**  This immediately signals interaction with a device driver.
* **`KFD`:**  Likely stands for Kernel Fusion Driver, a component related to GPU functionality.
* **`struct kfd_ioctl_*_args`:**  These structures define the data exchanged between user space and the kernel for specific operations.
* **`#define KFD_IOC_*`:**  These are macros that define the specific ioctl commands.
* **Memory management terms:** `alloc_memory`, `free_memory`, `map_memory`, `unmap_memory`, `dmabuf`.
* **Queue management terms:** `create_queue`, `destroy_queue`, `update_queue`.
* **Event management terms:** `create_event`, `destroy_event`, `wait_events`.
* **Debugging terms:** `dbg_register`, `dbg_unregister`, `dbg_address_watch`, `dbg_wave_control`, `dbg_trap`.
* **Error/Exception related terms:**  `HW_EXCEPTION`, `memory_exception`, `trap`.
* **Version information:** `KFD_IOCTL_MAJOR_VERSION`, `KFD_IOCTL_MINOR_VERSION`.

**3. Categorizing Functionality:**

Based on the identified keywords, group the functionalities into logical categories. This makes the explanation more organized. Good categories here are:

* **Version Management:**  Getting the KFD driver version.
* **Queue Management:** Creating, destroying, and updating command queues for the GPU.
* **Memory Management:** Allocating, freeing, mapping, and unmapping memory on the GPU.
* **Event Handling:**  Creating, destroying, setting, resetting, and waiting for events.
* **Debugging:**  Registering, unregistering for debugging, address watching, wave control, and more advanced trap handling.
* **System Monitoring:** Getting clock counters, available memory, process apertures.
* **Synchronization & Interoperability:**  DMABUF import/export, SVM (Shared Virtual Memory).
* **CRIU (Checkpoint/Restore in Userspace):**  Related to virtual machine management.
* **SMI Events:** System Management Interrupt events.

**4. Explaining Each Category and Individual Functions:**

For each category and individual `ioctl`, explain its purpose in simple terms. Focus on what the user-space application is trying to achieve by calling this ioctl. Use the structure names and macro definitions to guide the explanation.

**5. Connecting to Android:**

This is a crucial part of the request. Think about how these GPU-related functionalities are used in the Android ecosystem. Consider:

* **Graphics rendering:**  OpenGL ES, Vulkan. These APIs ultimately need to submit commands to the GPU.
* **Compute tasks:**  Using the GPU for general-purpose computations (e.g., machine learning, image processing).
* **Hardware acceleration:**  Offloading tasks from the CPU to the GPU.
* **Memory sharing:**  Efficiently sharing data between the CPU and GPU.
* **Debugging:** Tools for profiling and debugging GPU applications.

Provide concrete examples, like using Vulkan to create command buffers (which relates to queue management) or using `AHardwareBuffer` which might involve DMABUF.

**6. Detailed Explanation of `libc` Functions:**

The request specifically asks for explanations of `libc` functions. However, the provided header file primarily defines structures and macros for `ioctl` calls. The `ioctl` function itself *is* a `libc` function. Therefore, the explanation should focus on the `ioctl` system call: its purpose, how it works (system call interface), and common error handling. It's important to distinguish between the *header file* defining the *arguments* for the `ioctl` call and the `ioctl` function itself.

**7. Dynamic Linker and SO Layout:**

The provided header file *doesn't directly involve dynamic linking*. It defines the interface for interacting with a kernel driver. However, *the code that uses these ioctls* will reside in shared libraries (`.so` files). Address this by explaining:

* The role of the dynamic linker (`linker64` or `linker`).
* A typical `.so` layout (code, data, GOT, PLT).
* The linking process: resolving symbols, relocation.
* Provide a simplified example of how a function in a `.so` might call the `ioctl` function.

**8. Logical Reasoning and Examples:**

For each `ioctl`, think about:

* **Input:** What data does the user-space application provide to the kernel?
* **Output:** What information does the kernel return?
* **Assumptions:** What conditions must be met for the ioctl to succeed?

Provide simple examples to illustrate the input and output of a few key ioctls, like `KFD_IOC_GET_VERSION` or `KFD_IOC_CREATE_QUEUE`.

**9. Common Usage Errors:**

Think about the types of mistakes a programmer might make when using these ioctls:

* Incorrectly sized structures.
* Invalid flags or parameters.
* Not checking return values.
* Memory management issues (e.g., double freeing).
* Race conditions when accessing shared resources.

Provide specific code snippets to illustrate these errors.

**10. Android Framework and NDK Interaction:**

Trace the path from high-level Android frameworks down to the kernel driver:

* **Android Framework:**  UI rendering, compute APIs (RenderScript, NNAPI), media processing.
* **HAL (Hardware Abstraction Layer):**  Provides an interface between the framework and hardware-specific drivers. This is a key point where the transition to native code often occurs.
* **NDK:** Allows developers to write native code (C/C++) that can interact with the HAL.
* **Binder:**  The inter-process communication mechanism used by Android.
* **Kernel Drivers:** The KFD driver is the final destination.

Illustrate this with a diagram or step-by-step description.

**11. Frida Hooking:**

Provide practical Frida examples to intercept and inspect `ioctl` calls related to KFD. Show how to:

* Attach to a process.
* Hook the `ioctl` function.
* Filter for KFD-related ioctl numbers.
* Inspect the input arguments.
* Potentially modify arguments or return values (with caution).

**12. Review and Refine:**

After drafting the response, review it for clarity, accuracy, and completeness. Ensure that the language is accessible and that technical terms are explained where necessary. Check that all parts of the original request have been addressed. For example, initially, I might forget to explicitly mention the `ioctl` libc function itself when asked about libc functions. Review helps catch these omissions.

This detailed and iterative process ensures a comprehensive and accurate response to the complex request. The key is to break down the problem into smaller, manageable parts and systematically address each one.
## KFD IOCTL 功能详解

这个头文件 `kfd_ioctl.h` 定义了用户空间程序与 Linux 内核中的 **Kernel Fusion Driver (KFD)** 交互的接口。KFD 是 AMD GPU 计算功能的驱动程序，它允许用户空间应用程序利用 AMD GPU 的计算能力，例如通过 ROCm (Radeon Open Compute platform) 进行通用 GPU 计算 (GPGPU)。

**主要功能列表：**

该头文件定义了一系列用于控制和管理 AMD GPU 的 ioctl 命令，主要功能包括：

1. **版本查询:**
    * `KFD_IOC_GET_VERSION`: 获取 KFD 驱动的主版本号和次版本号。

2. **队列管理:**
    * `KFD_IOC_CREATE_QUEUE`: 创建一个 GPU 命令队列，用于向 GPU 提交计算任务或其他指令。
    * `KFD_IOC_DESTROY_QUEUE`: 销毁一个已创建的 GPU 命令队列。
    * `KFD_IOC_UPDATE_QUEUE`: 更新现有 GPU 命令队列的属性，例如环形缓冲区基地址、大小、优先级等。
    * `KFD_IOC_GET_QUEUE_WAVE_STATE`: 获取指定队列中 wavefront（GPU 上的执行单元）的状态信息，用于调试。
    * `KFD_IOC_ALLOC_QUEUE_GWS`: 为队列分配全局工作组大小 (Global Work Size) 相关的内存。

3. **内存管理:**
    * `KFD_IOC_ALLOC_MEMORY_OF_GPU`: 在指定的 GPU 上分配内存。可以指定内存类型 (VRAM, GTT)、标志 (可写、可执行、共享等)。
    * `KFD_IOC_FREE_MEMORY_OF_GPU`: 释放之前在 GPU 上分配的内存。
    * `KFD_IOC_MAP_MEMORY_TO_GPU`: 将分配的内存映射到指定的 GPU 设备。
    * `KFD_IOC_UNMAP_MEMORY_FROM_GPU`: 从指定的 GPU 设备取消映射内存。
    * `KFD_IOC_SET_MEMORY_POLICY`: 设置 GPU 内存策略，例如指定备用地址范围和缓存策略。
    * `KFD_IOC_GET_AVAILABLE_MEMORY`: 获取指定 GPU 上可用的内存大小。
    * `KFD_IOC_GET_PROCESS_APERTURES`: 获取进程可以访问的 GPU 地址空间范围信息，包括 LDS、Scratch 和 GPUVM 的基地址和限制。
    * `KFD_IOC_GET_PROCESS_APERTURES_NEW`: `KFD_IOC_GET_PROCESS_APERTURES` 的新版本，使用指针传递数据。
    * `KFD_IOC_IMPORT_DMABUF`: 导入一个 DMA 缓冲区 (dmabuf) 到 KFD 管理的内存中。
    * `KFD_IOC_EXPORT_DMABUF`: 导出 KFD 管理的内存为一个 DMA 缓冲区。

4. **事件处理:**
    * `KFD_IOC_CREATE_EVENT`: 创建一个 KFD 事件对象，用于 GPU 和 CPU 之间的同步。
    * `KFD_IOC_DESTROY_EVENT`: 销毁一个 KFD 事件对象。
    * `KFD_IOC_SET_EVENT`: 设置一个 KFD 事件。
    * `KFD_IOC_RESET_EVENT`: 重置一个 KFD 事件。
    * `KFD_IOC_WAIT_EVENTS`: 等待一个或多个 KFD 事件发生。

5. **调试功能:**
    * `KFD_IOC_DBG_REGISTER_DEPRECATED`:  (已弃用) 注册进程以进行 KFD 调试。
    * `KFD_IOC_DBG_UNREGISTER_DEPRECATED`: (已弃用) 取消注册进程的 KFD 调试。
    * `KFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED`: (已弃用) 设置 GPU 地址监视点。
    * `KFD_IOC_DBG_WAVE_CONTROL_DEPRECATED`: (已弃用) 控制 GPU wavefront 的执行。
    * `KFD_IOC_SET_SCRATCH_BACKING_VA`: 设置 scratch 内存的后备虚拟地址。
    * `KFD_IOC_SET_TRAP_HANDLER`: 设置陷阱处理程序的地址。
    * `KFD_IOC_DBG_TRAP`: 提供更细粒度的调试控制，包括启用/禁用陷阱、发送运行时事件、查询调试事件和异常信息等。

6. **系统信息:**
    * `KFD_IOC_GET_CLOCK_COUNTERS`: 获取 GPU 和 CPU 的时钟计数器信息。
    * `KFD_IOC_GET_TILE_CONFIG`: 获取 GPU 的 tile 配置信息。

7. **虚拟化:**
    * `KFD_IOC_ACQUIRE_VM`: 获取虚拟机的访问权限。

8. **共享虚拟内存 (SVM):**
    * `KFD_IOC_SVM`:  用于管理共享虚拟内存，允许 CPU 和 GPU 访问同一块内存区域。可以设置和获取 SVM 属性。

9. **系统管理接口 (SMI) 事件:**
    * `KFD_IOC_SMI_EVENTS`: 订阅和接收来自 KFD 的系统管理接口事件，例如 VM 故障、热节流等。

10. **CRIU (Checkpoint/Restore in Userspace) 支持:**
    * `KFD_IOC_CRIU_OP`:  用于支持 CRIU 功能，允许对正在使用 GPU 的进程进行检查点和恢复。

11. **其他:**
    * `KFD_IOC_SET_CU_MASK`: 设置用于队列的计算单元 (Compute Unit) 掩码。
    * `KFD_IOC_SET_XNACK_MODE`: 设置 XNACK (eXtended Negative ACKnowledgement) 模式。
    * `KFD_IOC_RUNTIME_ENABLE`: 启用 KFD 运行时功能。

**与 Android 功能的关系和举例说明:**

KFD 驱动及其提供的 ioctl 命令对于 Android 上的 GPU 计算至关重要，尤其是在使用 Vulkan 或 OpenCL 进行通用计算时。

* **Vulkan 计算:**  Android 上的 Vulkan 驱动程序会利用 KFD 驱动来管理 GPU 资源和提交计算任务。例如：
    * 当一个 Vulkan 应用创建一个计算管线并分发计算任务时，底层的 Vulkan 驱动程序会调用 `KFD_IOC_CREATE_QUEUE` 来创建一个 GPU 命令队列。
    * 计算任务的数据可能需要通过 `KFD_IOC_ALLOC_MEMORY_OF_GPU` 分配 GPU 内存，并通过 `KFD_IOC_MAP_MEMORY_TO_GPU` 映射到 GPU。
    * 计算完成后的同步可能使用 `KFD_IOC_CREATE_EVENT` 和 `KFD_IOC_WAIT_EVENTS`。

* **机器学习 (ML) 加速:** Android 的神经网络 API (NNAPI) 可以利用 GPU 进行模型加速。底层的 NNAPI 实现可能会使用 KFD 驱动来分配内存、提交计算任务和进行同步。

* **RenderScript (已弃用但仍可能存在):** 虽然 RenderScript 正在被废弃，但旧版本的 Android 可能仍然使用它进行并行计算。RenderScript 的实现也可能依赖于 KFD 驱动。

* **图形渲染 (间接关系):**  虽然 OpenGL ES 主要通过 DRM (Direct Rendering Manager) 与 GPU 交互，但涉及到计算着色器等功能时，也可能间接使用到 KFD 提供的一些底层机制。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件定义的是 **ioctl 命令的参数结构和宏定义**，它本身不包含任何 `libc` 函数的实现。 `libc` 函数是 C 标准库提供的函数。这里涉及到的关键 `libc` 函数是 `ioctl`。

**`ioctl` 函数:**

* **功能:** `ioctl` (input/output control) 是一个 Linux 系统调用，允许用户空间程序向设备驱动程序发送控制命令并接收响应。
* **实现原理:**
    1. 用户空间程序调用 `ioctl` 函数，传递文件描述符 (通常是 `/dev/dri/cardX` 这样的设备文件)、一个命令码 (例如 `AMDKFD_IOC_CREATE_QUEUE`) 和一个指向参数结构的指针。
    2. 系统调用陷入内核。
    3. 内核根据文件描述符找到对应的设备驱动程序 (这里是 KFD 驱动)。
    4. 内核将 `ioctl` 命令码和参数传递给 KFD 驱动程序的 `ioctl` 处理函数。
    5. KFD 驱动程序根据命令码执行相应的操作，例如创建队列、分配内存等。这通常涉及到与 GPU 硬件的交互。
    6. KFD 驱动程序将操作结果写入参数结构或通过返回值传递给内核。
    7. 内核将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker。Dynamic linker 主要负责在程序启动时加载共享库 (`.so` 文件) 并解析符号。然而，**使用这些 KFD ioctl 命令的代码** 会存在于用户空间的共享库中，例如 Vulkan 驱动程序、OpenCL 运行时库或自定义的 GPGPU 库。

**SO 布局样本:**

一个典型的包含 KFD ioctl 调用的共享库 (`libcompute.so`) 的布局可能如下：

```
libcompute.so:
    .text:  # 代码段
        compute_function:
            # ... 调用 ioctl 函数的代码 ...
            mov     r0, fd          ; 文件描述符
            mov     r1, #KFD_IOC_CREATE_QUEUE ; ioctl 命令码
            mov     r2, queue_args_ptr ; 参数结构指针
            bl      ioctl@PLT       ; 调用 ioctl 函数 (通过 PLT)
            # ...
    .data:  # 初始化数据段
        some_global_data: .word 0
    .bss:   # 未初始化数据段
        some_uninitialized_data: .space 4
    .rodata: # 只读数据段
        some_constant: .asciz "KFD initialized"
    .dynamic: # 动态链接信息
        NEEDED      libdrm.so.2  # 依赖的共享库
        SONAME      libcompute.so
        SYMTAB      ...
        STRTAB      ...
        REL.plt     ...
        JREL.dyn    ...
    .plt:   # 程序链接表 (Procedure Linkage Table)
        ioctl@GLIBC_2.17:
            jmp     [GOT + ioctl@GLIBC_2.17]  # 跳转到 GOT 中的地址
    .got:   # 全局偏移表 (Global Offset Table)
        ioctl@GLIBC_2.17: 0  # 初始为 0，dynamic linker 会填充实际地址

```

**链接的处理过程:**

1. **编译时:** 当 `libcompute.so` 被编译时，编译器看到 `ioctl` 函数调用，但不知道 `ioctl` 函数的具体地址。它会在 `.plt` 段生成一个条目 (`ioctl@PLT`)，并在 `.got` 段生成一个对应的条目 (`ioctl@GLIBC_2.17`)，初始值为 0。
2. **加载时:** 当一个应用程序加载 `libcompute.so` 时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载依赖库:**  Dynamic linker 解析 `.dynamic` 段的 `NEEDED` 条目，发现 `libcompute.so` 依赖于 `libdrm.so.2` 和其他的 `libc` 库。它会先加载这些依赖库。
    * **符号解析:** Dynamic linker 遍历 `.rel.plt` 和 `.jreldyn` 段，找到需要重定位的符号。对于 `ioctl` 函数，dynamic linker 会在 `libc.so` 中查找 `ioctl` 符号的地址。
    * **重定位:** Dynamic linker 将 `ioctl` 函数在 `libc.so` 中的实际地址填充到 `libcompute.so` 的 `.got` 段中 `ioctl@GLIBC_2.17` 对应的条目。
    * **PLT 的作用:** 当程序第一次调用 `ioctl` 函数时，会跳转到 `.plt` 段的 `ioctl@PLT` 条目。该条目会先跳转到 `.got` 中 `ioctl` 的地址。由于第一次调用时 `.got` 中的地址已经被 dynamic linker 填充为 `ioctl` 的实际地址，所以会直接跳转到 `ioctl` 函数执行。后续的调用会直接跳转到 `.got` 中缓存的地址，避免了重复的符号解析。

**假设输入与输出 (以 `KFD_IOC_GET_VERSION` 为例):**

**假设输入:**

* 用户空间程序打开了 KFD 设备文件，例如 `/dev/dri/card0`，获取了文件描述符 `fd`。
* 声明了一个 `kfd_ioctl_get_version_args` 结构体变量 `version_args`。

**C 代码示例:**

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "kfd_ioctl.h"

int main() {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct kfd_ioctl_get_version_args version_args;

    if (ioctl(fd, AMDKFD_IOC_GET_VERSION, &version_args) == 0) {
        printf("KFD Major Version: %u\n", version_args.major_version);
        printf("KFD Minor Version: %u\n", version_args.minor_version);
    } else {
        perror("ioctl");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
```

**预期输出:**

```
KFD Major Version: 1
KFD Minor Version: 17
```

**假设输入与输出 (以 `KFD_IOC_CREATE_QUEUE` 为例):**

**假设输入:**

* 已打开 KFD 设备文件，获取文件描述符 `fd`。
* 已分配用于队列环形缓冲区、读写指针等内存。
* 声明并初始化了一个 `kfd_ioctl_create_queue_args` 结构体变量 `create_queue_args`，包含了队列的各种参数，例如 `ring_base_address`, `ring_size`, `queue_type` 等。

**预期输出:**

* 如果创建成功，`ioctl` 返回 0，并且 `create_queue_args.queue_id` 字段会被 KFD 驱动填充为新创建的队列 ID。
* 如果创建失败，`ioctl` 返回 -1，并设置 `errno` 以指示错误原因。

**用户或编程常见的使用错误:**

1. **传递错误的 ioctl 命令码:**  使用了与预期功能不符的 `AMDKFD_IOC_*` 宏。
2. **参数结构体大小不匹配:**  用户空间传递的结构体大小与内核驱动期望的大小不一致，可能导致数据错乱或崩溃。
3. **未正确初始化参数结构体:**  关键字段未设置或设置了无效值，例如传入无效的内存地址或大小。
4. **权限不足:**  尝试执行需要特定权限的 ioctl 命令。
5. **设备文件未打开或打开失败:**  在调用 `ioctl` 之前没有成功打开 KFD 设备文件。
6. **内存管理错误:**
    * 尝试释放未分配的或已释放的内存句柄。
    * 映射的内存大小或地址不正确。
    * 忘记取消映射内存。
7. **队列管理错误:**
    * 尝试销毁不存在的队列。
    * 在队列还在使用时尝试销毁它。
    * 队列参数设置不合理，例如环形缓冲区太小。
8. **事件处理错误:**
    * 尝试等待不存在的事件。
    * 事件的设置和重置逻辑错误。
9. **忽略 ioctl 的返回值:**  未检查 `ioctl` 的返回值，导致无法判断操作是否成功，可能会继续执行导致更严重的错误。
10. **并发问题:** 在多线程环境下，如果没有适当的同步机制，多个线程可能同时访问和修改 KFD 资源，导致数据竞争和未定义的行为。

**Android framework 或 NDK 是如何一步步的到达这里:**

1. **Android Framework (例如，使用 Vulkan):**
    * 应用程序使用 Java 层的 Vulkan API (位于 `android.graphics.vulkan` 包)。
    * Framework 层的 Vulkan API 调用会传递到 Native 层的 Vulkan 驱动程序 (通常是厂商提供的 `.so` 库)。

2. **Native Vulkan Driver (C/C++):**
    * Native 层的 Vulkan 驱动程序负责将 Vulkan API 调用转换为 GPU 可以理解的命令。
    * 当需要与内核中的 GPU 驱动程序交互时 (例如，创建命令队列、分配内存)，Vulkan 驱动程序会调用底层的 KFD 接口。

3. **KFD 用户空间库 (如果存在):**
    * 有些厂商可能会提供一个用户空间的库来封装 KFD ioctl 调用，提供更高级的抽象。Vulkan 驱动程序可能会使用这个库。

4. **直接调用 `ioctl`:**
    * 或者，Vulkan 驱动程序可能会直接使用 `libc` 提供的 `ioctl` 函数。
    * 这需要驱动程序打开 KFD 设备文件 (例如 `/dev/dri/cardX`) 并构造正确的 `kfd_ioctl_*_args` 结构体。
    * 然后调用 `ioctl(fd, AMDKFD_IOC_*, &args)` 来与 KFD 驱动通信。

5. **KFD 内核驱动程序:**
    * 内核接收到 `ioctl` 系统调用后，会将其路由到 KFD 驱动程序。
    * KFD 驱动程序根据 `ioctl` 命令码执行相应的内核操作，与 GPU 硬件交互。

**Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于监控 KFD 相关的 ioctl 调用：

```javascript
function hook_ioctl() {
    const ioctlPtr = Module.findExportByName(null, "ioctl");
    if (ioctlPtr) {
        Interceptor.attach(ioctlPtr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                const argp = args[2];

                // 检查是否是 KFD 相关的 ioctl 命令
                if ((request & 0xff) === 'K'.charCodeAt(0)) { // AMDKFD_IOCTL_BASE 'K'
                    console.log("ioctl called with fd:", fd, "request:", request.toString(16));

                    // 可以进一步解析参数结构体
                    if (request === 0xc0104b02) { // 假设是 AMDKFD_IOC_CREATE_QUEUE
                        const createQueueArgs = Memory.readByteArray(argp, 100); // 读取部分参数
                        console.log("  KFD_IOC_CREATE_QUEUE args:", hexdump(createQueueArgs, { ansi: true }));
                    }
                }
            },
            onLeave: function (retval) {
                // console.log("ioctl returned:", retval);
            }
        });
        console.log("ioctl hooked!");
    } else {
        console.log("Failed to find ioctl export.");
    }
}

function main() {
    console.log("Script loaded, hooking...");
    hook_ioctl();
}

setImmediate(main);
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `kfd_hook.js`。
2. 使用 Frida 连接到目标 Android 进程 (例如，一个使用 Vulkan 的游戏或应用):
   ```bash
   frida -U -f <package_name> -l kfd_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <process_name> -l kfd_hook.js
   ```
3. 当目标应用执行 KFD 相关的 `ioctl` 调用时，Frida 会拦截这些调用并在控制台上打印相关信息，包括文件描述符、ioctl 命令码以及部分参数数据。

**进一步的 Frida 调试:**

* 可以根据 `ioctl` 的命令码，定义不同的结构体解析逻辑，以更详细地查看参数内容。
* 可以在 `onLeave` 中查看 `ioctl` 的返回值。
* 可以尝试修改参数值来观察应用程序的行为 (谨慎操作)。
* 可以结合其他 Frida 功能，例如 hook 函数调用栈，来追踪 KFD ioctl 调用的来源。

这个头文件 `kfd_ioctl.handroid` 是 Android bionic libc 中的一部分，这意味着 Android 系统本身就包含了对 KFD 驱动接口的定义，这进一步说明了 KFD 在 Android 图形和计算领域的重要性。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/kfd_ioctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef KFD_IOCTL_H_INCLUDED
#define KFD_IOCTL_H_INCLUDED
#include <drm/drm.h>
#include <linux/ioctl.h>
#define KFD_IOCTL_MAJOR_VERSION 1
#define KFD_IOCTL_MINOR_VERSION 17
struct kfd_ioctl_get_version_args {
  __u32 major_version;
  __u32 minor_version;
};
#define KFD_IOC_QUEUE_TYPE_COMPUTE 0x0
#define KFD_IOC_QUEUE_TYPE_SDMA 0x1
#define KFD_IOC_QUEUE_TYPE_COMPUTE_AQL 0x2
#define KFD_IOC_QUEUE_TYPE_SDMA_XGMI 0x3
#define KFD_IOC_QUEUE_TYPE_SDMA_BY_ENG_ID 0x4
#define KFD_MAX_QUEUE_PERCENTAGE 100
#define KFD_MAX_QUEUE_PRIORITY 15
struct kfd_ioctl_create_queue_args {
  __u64 ring_base_address;
  __u64 write_pointer_address;
  __u64 read_pointer_address;
  __u64 doorbell_offset;
  __u32 ring_size;
  __u32 gpu_id;
  __u32 queue_type;
  __u32 queue_percentage;
  __u32 queue_priority;
  __u32 queue_id;
  __u64 eop_buffer_address;
  __u64 eop_buffer_size;
  __u64 ctx_save_restore_address;
  __u32 ctx_save_restore_size;
  __u32 ctl_stack_size;
  __u32 sdma_engine_id;
  __u32 pad;
};
struct kfd_ioctl_destroy_queue_args {
  __u32 queue_id;
  __u32 pad;
};
struct kfd_ioctl_update_queue_args {
  __u64 ring_base_address;
  __u32 queue_id;
  __u32 ring_size;
  __u32 queue_percentage;
  __u32 queue_priority;
};
struct kfd_ioctl_set_cu_mask_args {
  __u32 queue_id;
  __u32 num_cu_mask;
  __u64 cu_mask_ptr;
};
struct kfd_ioctl_get_queue_wave_state_args {
  __u64 ctl_stack_address;
  __u32 ctl_stack_used_size;
  __u32 save_area_used_size;
  __u32 queue_id;
  __u32 pad;
};
struct kfd_ioctl_get_available_memory_args {
  __u64 available;
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_dbg_device_info_entry {
  __u64 exception_status;
  __u64 lds_base;
  __u64 lds_limit;
  __u64 scratch_base;
  __u64 scratch_limit;
  __u64 gpuvm_base;
  __u64 gpuvm_limit;
  __u32 gpu_id;
  __u32 location_id;
  __u32 vendor_id;
  __u32 device_id;
  __u32 revision_id;
  __u32 subsystem_vendor_id;
  __u32 subsystem_device_id;
  __u32 fw_version;
  __u32 gfx_target_version;
  __u32 simd_count;
  __u32 max_waves_per_simd;
  __u32 array_count;
  __u32 simd_arrays_per_engine;
  __u32 num_xcc;
  __u32 capability;
  __u32 debug_prop;
};
#define KFD_IOC_CACHE_POLICY_COHERENT 0
#define KFD_IOC_CACHE_POLICY_NONCOHERENT 1
struct kfd_ioctl_set_memory_policy_args {
  __u64 alternate_aperture_base;
  __u64 alternate_aperture_size;
  __u32 gpu_id;
  __u32 default_policy;
  __u32 alternate_policy;
  __u32 pad;
};
struct kfd_ioctl_get_clock_counters_args {
  __u64 gpu_clock_counter;
  __u64 cpu_clock_counter;
  __u64 system_clock_counter;
  __u64 system_clock_freq;
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_process_device_apertures {
  __u64 lds_base;
  __u64 lds_limit;
  __u64 scratch_base;
  __u64 scratch_limit;
  __u64 gpuvm_base;
  __u64 gpuvm_limit;
  __u32 gpu_id;
  __u32 pad;
};
#define NUM_OF_SUPPORTED_GPUS 7
struct kfd_ioctl_get_process_apertures_args {
  struct kfd_process_device_apertures process_apertures[NUM_OF_SUPPORTED_GPUS];
  __u32 num_of_nodes;
  __u32 pad;
};
struct kfd_ioctl_get_process_apertures_new_args {
  __u64 kfd_process_device_apertures_ptr;
  __u32 num_of_nodes;
  __u32 pad;
};
#define MAX_ALLOWED_NUM_POINTS 100
#define MAX_ALLOWED_AW_BUFF_SIZE 4096
#define MAX_ALLOWED_WAC_BUFF_SIZE 128
struct kfd_ioctl_dbg_register_args {
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_ioctl_dbg_unregister_args {
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_ioctl_dbg_address_watch_args {
  __u64 content_ptr;
  __u32 gpu_id;
  __u32 buf_size_in_bytes;
};
struct kfd_ioctl_dbg_wave_control_args {
  __u64 content_ptr;
  __u32 gpu_id;
  __u32 buf_size_in_bytes;
};
#define KFD_INVALID_FD 0xffffffff
#define KFD_IOC_EVENT_SIGNAL 0
#define KFD_IOC_EVENT_NODECHANGE 1
#define KFD_IOC_EVENT_DEVICESTATECHANGE 2
#define KFD_IOC_EVENT_HW_EXCEPTION 3
#define KFD_IOC_EVENT_SYSTEM_EVENT 4
#define KFD_IOC_EVENT_DEBUG_EVENT 5
#define KFD_IOC_EVENT_PROFILE_EVENT 6
#define KFD_IOC_EVENT_QUEUE_EVENT 7
#define KFD_IOC_EVENT_MEMORY 8
#define KFD_IOC_WAIT_RESULT_COMPLETE 0
#define KFD_IOC_WAIT_RESULT_TIMEOUT 1
#define KFD_IOC_WAIT_RESULT_FAIL 2
#define KFD_SIGNAL_EVENT_LIMIT 4096
#define KFD_HW_EXCEPTION_WHOLE_GPU_RESET 0
#define KFD_HW_EXCEPTION_PER_ENGINE_RESET 1
#define KFD_HW_EXCEPTION_GPU_HANG 0
#define KFD_HW_EXCEPTION_ECC 1
#define KFD_MEM_ERR_NO_RAS 0
#define KFD_MEM_ERR_SRAM_ECC 1
#define KFD_MEM_ERR_POISON_CONSUMED 2
#define KFD_MEM_ERR_GPU_HANG 3
struct kfd_ioctl_create_event_args {
  __u64 event_page_offset;
  __u32 event_trigger_data;
  __u32 event_type;
  __u32 auto_reset;
  __u32 node_id;
  __u32 event_id;
  __u32 event_slot_index;
};
struct kfd_ioctl_destroy_event_args {
  __u32 event_id;
  __u32 pad;
};
struct kfd_ioctl_set_event_args {
  __u32 event_id;
  __u32 pad;
};
struct kfd_ioctl_reset_event_args {
  __u32 event_id;
  __u32 pad;
};
struct kfd_memory_exception_failure {
  __u32 NotPresent;
  __u32 ReadOnly;
  __u32 NoExecute;
  __u32 imprecise;
};
struct kfd_hsa_memory_exception_data {
  struct kfd_memory_exception_failure failure;
  __u64 va;
  __u32 gpu_id;
  __u32 ErrorType;
};
struct kfd_hsa_hw_exception_data {
  __u32 reset_type;
  __u32 reset_cause;
  __u32 memory_lost;
  __u32 gpu_id;
};
struct kfd_hsa_signal_event_data {
  __u64 last_event_age;
};
struct kfd_event_data {
  union {
    struct kfd_hsa_memory_exception_data memory_exception_data;
    struct kfd_hsa_hw_exception_data hw_exception_data;
    struct kfd_hsa_signal_event_data signal_event_data;
  };
  __u64 kfd_event_data_ext;
  __u32 event_id;
  __u32 pad;
};
struct kfd_ioctl_wait_events_args {
  __u64 events_ptr;
  __u32 num_events;
  __u32 wait_for_all;
  __u32 timeout;
  __u32 wait_result;
};
struct kfd_ioctl_set_scratch_backing_va_args {
  __u64 va_addr;
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_ioctl_get_tile_config_args {
  __u64 tile_config_ptr;
  __u64 macro_tile_config_ptr;
  __u32 num_tile_configs;
  __u32 num_macro_tile_configs;
  __u32 gpu_id;
  __u32 gb_addr_config;
  __u32 num_banks;
  __u32 num_ranks;
};
struct kfd_ioctl_set_trap_handler_args {
  __u64 tba_addr;
  __u64 tma_addr;
  __u32 gpu_id;
  __u32 pad;
};
struct kfd_ioctl_acquire_vm_args {
  __u32 drm_fd;
  __u32 gpu_id;
};
#define KFD_IOC_ALLOC_MEM_FLAGS_VRAM (1 << 0)
#define KFD_IOC_ALLOC_MEM_FLAGS_GTT (1 << 1)
#define KFD_IOC_ALLOC_MEM_FLAGS_USERPTR (1 << 2)
#define KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL (1 << 3)
#define KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP (1 << 4)
#define KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE (1 << 31)
#define KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE (1 << 30)
#define KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC (1 << 29)
#define KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE (1 << 28)
#define KFD_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM (1 << 27)
#define KFD_IOC_ALLOC_MEM_FLAGS_COHERENT (1 << 26)
#define KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED (1 << 25)
#define KFD_IOC_ALLOC_MEM_FLAGS_EXT_COHERENT (1 << 24)
#define KFD_IOC_ALLOC_MEM_FLAGS_CONTIGUOUS (1 << 23)
struct kfd_ioctl_alloc_memory_of_gpu_args {
  __u64 va_addr;
  __u64 size;
  __u64 handle;
  __u64 mmap_offset;
  __u32 gpu_id;
  __u32 flags;
};
struct kfd_ioctl_free_memory_of_gpu_args {
  __u64 handle;
};
struct kfd_ioctl_map_memory_to_gpu_args {
  __u64 handle;
  __u64 device_ids_array_ptr;
  __u32 n_devices;
  __u32 n_success;
};
struct kfd_ioctl_unmap_memory_from_gpu_args {
  __u64 handle;
  __u64 device_ids_array_ptr;
  __u32 n_devices;
  __u32 n_success;
};
struct kfd_ioctl_alloc_queue_gws_args {
  __u32 queue_id;
  __u32 num_gws;
  __u32 first_gws;
  __u32 pad;
};
struct kfd_ioctl_get_dmabuf_info_args {
  __u64 size;
  __u64 metadata_ptr;
  __u32 metadata_size;
  __u32 gpu_id;
  __u32 flags;
  __u32 dmabuf_fd;
};
struct kfd_ioctl_import_dmabuf_args {
  __u64 va_addr;
  __u64 handle;
  __u32 gpu_id;
  __u32 dmabuf_fd;
};
struct kfd_ioctl_export_dmabuf_args {
  __u64 handle;
  __u32 flags;
  __u32 dmabuf_fd;
};
enum kfd_smi_event {
  KFD_SMI_EVENT_NONE = 0,
  KFD_SMI_EVENT_VMFAULT = 1,
  KFD_SMI_EVENT_THERMAL_THROTTLE = 2,
  KFD_SMI_EVENT_GPU_PRE_RESET = 3,
  KFD_SMI_EVENT_GPU_POST_RESET = 4,
  KFD_SMI_EVENT_MIGRATE_START = 5,
  KFD_SMI_EVENT_MIGRATE_END = 6,
  KFD_SMI_EVENT_PAGE_FAULT_START = 7,
  KFD_SMI_EVENT_PAGE_FAULT_END = 8,
  KFD_SMI_EVENT_QUEUE_EVICTION = 9,
  KFD_SMI_EVENT_QUEUE_RESTORE = 10,
  KFD_SMI_EVENT_UNMAP_FROM_GPU = 11,
  KFD_SMI_EVENT_ALL_PROCESS = 64
};
enum KFD_MIGRATE_TRIGGERS {
  KFD_MIGRATE_TRIGGER_PREFETCH,
  KFD_MIGRATE_TRIGGER_PAGEFAULT_GPU,
  KFD_MIGRATE_TRIGGER_PAGEFAULT_CPU,
  KFD_MIGRATE_TRIGGER_TTM_EVICTION
};
enum KFD_QUEUE_EVICTION_TRIGGERS {
  KFD_QUEUE_EVICTION_TRIGGER_SVM,
  KFD_QUEUE_EVICTION_TRIGGER_USERPTR,
  KFD_QUEUE_EVICTION_TRIGGER_TTM,
  KFD_QUEUE_EVICTION_TRIGGER_SUSPEND,
  KFD_QUEUE_EVICTION_CRIU_CHECKPOINT,
  KFD_QUEUE_EVICTION_CRIU_RESTORE
};
enum KFD_SVM_UNMAP_TRIGGERS {
  KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY,
  KFD_SVM_UNMAP_TRIGGER_MMU_NOTIFY_MIGRATE,
  KFD_SVM_UNMAP_TRIGGER_UNMAP_FROM_CPU
};
#define KFD_SMI_EVENT_MASK_FROM_INDEX(i) (1ULL << ((i) - 1))
#define KFD_SMI_EVENT_MSG_SIZE 96
struct kfd_ioctl_smi_events_args {
  __u32 gpuid;
  __u32 anon_fd;
};
#define KFD_EVENT_FMT_UPDATE_GPU_RESET(reset_seq_num,reset_cause) "%x %s\n", (reset_seq_num), (reset_cause)
#define KFD_EVENT_FMT_THERMAL_THROTTLING(bitmask,counter) "%llx:%llx\n", (bitmask), (counter)
#define KFD_EVENT_FMT_VMFAULT(pid,task_name) "%x:%s\n", (pid), (task_name)
#define KFD_EVENT_FMT_PAGEFAULT_START(ns,pid,addr,node,rw) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (rw)
#define KFD_EVENT_FMT_PAGEFAULT_END(ns,pid,addr,node,migrate_update) "%lld -%d @%lx(%x) %c\n", (ns), (pid), (addr), (node), (migrate_update)
#define KFD_EVENT_FMT_MIGRATE_START(ns,pid,start,size,from,to,prefetch_loc,preferred_loc,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %x:%x %d\n", (ns), (pid), (start), (size), (from), (to), (prefetch_loc), (preferred_loc), (migrate_trigger)
#define KFD_EVENT_FMT_MIGRATE_END(ns,pid,start,size,from,to,migrate_trigger) "%lld -%d @%lx(%lx) %x->%x %d\n", (ns), (pid), (start), (size), (from), (to), (migrate_trigger)
#define KFD_EVENT_FMT_QUEUE_EVICTION(ns,pid,node,evict_trigger) "%lld -%d %x %d\n", (ns), (pid), (node), (evict_trigger)
#define KFD_EVENT_FMT_QUEUE_RESTORE(ns,pid,node,rescheduled) "%lld -%d %x %c\n", (ns), (pid), (node), (rescheduled)
#define KFD_EVENT_FMT_UNMAP_FROM_GPU(ns,pid,addr,size,node,unmap_trigger) "%lld -%d @%lx(%lx) %x %d\n", (ns), (pid), (addr), (size), (node), (unmap_trigger)
enum kfd_criu_op {
  KFD_CRIU_OP_PROCESS_INFO,
  KFD_CRIU_OP_CHECKPOINT,
  KFD_CRIU_OP_UNPAUSE,
  KFD_CRIU_OP_RESTORE,
  KFD_CRIU_OP_RESUME,
};
struct kfd_ioctl_criu_args {
  __u64 devices;
  __u64 bos;
  __u64 priv_data;
  __u64 priv_data_size;
  __u32 num_devices;
  __u32 num_bos;
  __u32 num_objects;
  __u32 pid;
  __u32 op;
};
struct kfd_criu_device_bucket {
  __u32 user_gpu_id;
  __u32 actual_gpu_id;
  __u32 drm_fd;
  __u32 pad;
};
struct kfd_criu_bo_bucket {
  __u64 addr;
  __u64 size;
  __u64 offset;
  __u64 restored_offset;
  __u32 gpu_id;
  __u32 alloc_flags;
  __u32 dmabuf_fd;
  __u32 pad;
};
enum kfd_mmio_remap {
  KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL = 0,
  KFD_MMIO_REMAP_HDP_REG_FLUSH_CNTL = 4,
};
#define KFD_IOCTL_SVM_FLAG_HOST_ACCESS 0x00000001
#define KFD_IOCTL_SVM_FLAG_COHERENT 0x00000002
#define KFD_IOCTL_SVM_FLAG_HIVE_LOCAL 0x00000004
#define KFD_IOCTL_SVM_FLAG_GPU_RO 0x00000008
#define KFD_IOCTL_SVM_FLAG_GPU_EXEC 0x00000010
#define KFD_IOCTL_SVM_FLAG_GPU_READ_MOSTLY 0x00000020
#define KFD_IOCTL_SVM_FLAG_GPU_ALWAYS_MAPPED 0x00000040
#define KFD_IOCTL_SVM_FLAG_EXT_COHERENT 0x00000080
enum kfd_ioctl_svm_op {
  KFD_IOCTL_SVM_OP_SET_ATTR,
  KFD_IOCTL_SVM_OP_GET_ATTR
};
enum kfd_ioctl_svm_location {
  KFD_IOCTL_SVM_LOCATION_SYSMEM = 0,
  KFD_IOCTL_SVM_LOCATION_UNDEFINED = 0xffffffff
};
enum kfd_ioctl_svm_attr_type {
  KFD_IOCTL_SVM_ATTR_PREFERRED_LOC,
  KFD_IOCTL_SVM_ATTR_PREFETCH_LOC,
  KFD_IOCTL_SVM_ATTR_ACCESS,
  KFD_IOCTL_SVM_ATTR_ACCESS_IN_PLACE,
  KFD_IOCTL_SVM_ATTR_NO_ACCESS,
  KFD_IOCTL_SVM_ATTR_SET_FLAGS,
  KFD_IOCTL_SVM_ATTR_CLR_FLAGS,
  KFD_IOCTL_SVM_ATTR_GRANULARITY
};
struct kfd_ioctl_svm_attribute {
  __u32 type;
  __u32 value;
};
struct kfd_ioctl_svm_args {
  __u64 start_addr;
  __u64 size;
  __u32 op;
  __u32 nattr;
  struct kfd_ioctl_svm_attribute attrs[];
};
struct kfd_ioctl_set_xnack_mode_args {
  __s32 xnack_enabled;
};
enum kfd_dbg_trap_override_mode {
  KFD_DBG_TRAP_OVERRIDE_OR = 0,
  KFD_DBG_TRAP_OVERRIDE_REPLACE = 1
};
enum kfd_dbg_trap_mask {
  KFD_DBG_TRAP_MASK_FP_INVALID = 1,
  KFD_DBG_TRAP_MASK_FP_INPUT_DENORMAL = 2,
  KFD_DBG_TRAP_MASK_FP_DIVIDE_BY_ZERO = 4,
  KFD_DBG_TRAP_MASK_FP_OVERFLOW = 8,
  KFD_DBG_TRAP_MASK_FP_UNDERFLOW = 16,
  KFD_DBG_TRAP_MASK_FP_INEXACT = 32,
  KFD_DBG_TRAP_MASK_INT_DIVIDE_BY_ZERO = 64,
  KFD_DBG_TRAP_MASK_DBG_ADDRESS_WATCH = 128,
  KFD_DBG_TRAP_MASK_DBG_MEMORY_VIOLATION = 256,
  KFD_DBG_TRAP_MASK_TRAP_ON_WAVE_START = (1 << 30),
  KFD_DBG_TRAP_MASK_TRAP_ON_WAVE_END = (1 << 31)
};
enum kfd_dbg_trap_wave_launch_mode {
  KFD_DBG_TRAP_WAVE_LAUNCH_MODE_NORMAL = 0,
  KFD_DBG_TRAP_WAVE_LAUNCH_MODE_HALT = 1,
  KFD_DBG_TRAP_WAVE_LAUNCH_MODE_DEBUG = 3
};
enum kfd_dbg_trap_address_watch_mode {
  KFD_DBG_TRAP_ADDRESS_WATCH_MODE_READ = 0,
  KFD_DBG_TRAP_ADDRESS_WATCH_MODE_NONREAD = 1,
  KFD_DBG_TRAP_ADDRESS_WATCH_MODE_ATOMIC = 2,
  KFD_DBG_TRAP_ADDRESS_WATCH_MODE_ALL = 3
};
enum kfd_dbg_trap_flags {
  KFD_DBG_TRAP_FLAG_SINGLE_MEM_OP = 1,
  KFD_DBG_TRAP_FLAG_SINGLE_ALU_OP = 2,
};
enum kfd_dbg_trap_exception_code {
  EC_NONE = 0,
  EC_QUEUE_WAVE_ABORT = 1,
  EC_QUEUE_WAVE_TRAP = 2,
  EC_QUEUE_WAVE_MATH_ERROR = 3,
  EC_QUEUE_WAVE_ILLEGAL_INSTRUCTION = 4,
  EC_QUEUE_WAVE_MEMORY_VIOLATION = 5,
  EC_QUEUE_WAVE_APERTURE_VIOLATION = 6,
  EC_QUEUE_PACKET_DISPATCH_DIM_INVALID = 16,
  EC_QUEUE_PACKET_DISPATCH_GROUP_SEGMENT_SIZE_INVALID = 17,
  EC_QUEUE_PACKET_DISPATCH_CODE_INVALID = 18,
  EC_QUEUE_PACKET_RESERVED = 19,
  EC_QUEUE_PACKET_UNSUPPORTED = 20,
  EC_QUEUE_PACKET_DISPATCH_WORK_GROUP_SIZE_INVALID = 21,
  EC_QUEUE_PACKET_DISPATCH_REGISTER_INVALID = 22,
  EC_QUEUE_PACKET_VENDOR_UNSUPPORTED = 23,
  EC_QUEUE_PREEMPTION_ERROR = 30,
  EC_QUEUE_NEW = 31,
  EC_DEVICE_QUEUE_DELETE = 32,
  EC_DEVICE_MEMORY_VIOLATION = 33,
  EC_DEVICE_RAS_ERROR = 34,
  EC_DEVICE_FATAL_HALT = 35,
  EC_DEVICE_NEW = 36,
  EC_PROCESS_RUNTIME = 48,
  EC_PROCESS_DEVICE_REMOVE = 49,
  EC_MAX
};
#define KFD_EC_MASK(ecode) (1ULL << (ecode - 1))
#define KFD_EC_MASK_QUEUE (KFD_EC_MASK(EC_QUEUE_WAVE_ABORT) | KFD_EC_MASK(EC_QUEUE_WAVE_TRAP) | KFD_EC_MASK(EC_QUEUE_WAVE_MATH_ERROR) | KFD_EC_MASK(EC_QUEUE_WAVE_ILLEGAL_INSTRUCTION) | KFD_EC_MASK(EC_QUEUE_WAVE_MEMORY_VIOLATION) | KFD_EC_MASK(EC_QUEUE_WAVE_APERTURE_VIOLATION) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_DIM_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_GROUP_SEGMENT_SIZE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_CODE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_RESERVED) | KFD_EC_MASK(EC_QUEUE_PACKET_UNSUPPORTED) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_WORK_GROUP_SIZE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_REGISTER_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_VENDOR_UNSUPPORTED) | KFD_EC_MASK(EC_QUEUE_PREEMPTION_ERROR) | KFD_EC_MASK(EC_QUEUE_NEW))
#define KFD_EC_MASK_DEVICE (KFD_EC_MASK(EC_DEVICE_QUEUE_DELETE) | KFD_EC_MASK(EC_DEVICE_RAS_ERROR) | KFD_EC_MASK(EC_DEVICE_FATAL_HALT) | KFD_EC_MASK(EC_DEVICE_MEMORY_VIOLATION) | KFD_EC_MASK(EC_DEVICE_NEW))
#define KFD_EC_MASK_PROCESS (KFD_EC_MASK(EC_PROCESS_RUNTIME) | KFD_EC_MASK(EC_PROCESS_DEVICE_REMOVE))
#define KFD_EC_MASK_PACKET (KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_DIM_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_GROUP_SEGMENT_SIZE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_CODE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_RESERVED) | KFD_EC_MASK(EC_QUEUE_PACKET_UNSUPPORTED) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_WORK_GROUP_SIZE_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_DISPATCH_REGISTER_INVALID) | KFD_EC_MASK(EC_QUEUE_PACKET_VENDOR_UNSUPPORTED))
#define KFD_DBG_EC_IS_VALID(ecode) (ecode > EC_NONE && ecode < EC_MAX)
#define KFD_DBG_EC_TYPE_IS_QUEUE(ecode) (KFD_DBG_EC_IS_VALID(ecode) && ! ! (KFD_EC_MASK(ecode) & KFD_EC_MASK_QUEUE))
#define KFD_DBG_EC_TYPE_IS_DEVICE(ecode) (KFD_DBG_EC_IS_VALID(ecode) && ! ! (KFD_EC_MASK(ecode) & KFD_EC_MASK_DEVICE))
#define KFD_DBG_EC_TYPE_IS_PROCESS(ecode) (KFD_DBG_EC_IS_VALID(ecode) && ! ! (KFD_EC_MASK(ecode) & KFD_EC_MASK_PROCESS))
#define KFD_DBG_EC_TYPE_IS_PACKET(ecode) (KFD_DBG_EC_IS_VALID(ecode) && ! ! (KFD_EC_MASK(ecode) & KFD_EC_MASK_PACKET))
enum kfd_dbg_runtime_state {
  DEBUG_RUNTIME_STATE_DISABLED = 0,
  DEBUG_RUNTIME_STATE_ENABLED = 1,
  DEBUG_RUNTIME_STATE_ENABLED_BUSY = 2,
  DEBUG_RUNTIME_STATE_ENABLED_ERROR = 3
};
struct kfd_runtime_info {
  __u64 r_debug;
  __u32 runtime_state;
  __u32 ttmp_setup;
};
#define KFD_RUNTIME_ENABLE_MODE_ENABLE_MASK 1
#define KFD_RUNTIME_ENABLE_MODE_TTMP_SAVE_MASK 2
struct kfd_ioctl_runtime_enable_args {
  __u64 r_debug;
  __u32 mode_mask;
  __u32 capabilities_mask;
};
struct kfd_queue_snapshot_entry {
  __u64 exception_status;
  __u64 ring_base_address;
  __u64 write_pointer_address;
  __u64 read_pointer_address;
  __u64 ctx_save_restore_address;
  __u32 queue_id;
  __u32 gpu_id;
  __u32 ring_size;
  __u32 queue_type;
  __u32 ctx_save_restore_area_size;
  __u32 reserved;
};
#define KFD_DBG_QUEUE_ERROR_BIT 30
#define KFD_DBG_QUEUE_INVALID_BIT 31
#define KFD_DBG_QUEUE_ERROR_MASK (1 << KFD_DBG_QUEUE_ERROR_BIT)
#define KFD_DBG_QUEUE_INVALID_MASK (1 << KFD_DBG_QUEUE_INVALID_BIT)
struct kfd_context_save_area_header {
  struct {
    __u32 control_stack_offset;
    __u32 control_stack_size;
    __u32 wave_state_offset;
    __u32 wave_state_size;
  } wave_state;
  __u32 debug_offset;
  __u32 debug_size;
  __u64 err_payload_addr;
  __u32 err_event_id;
  __u32 reserved1;
};
enum kfd_dbg_trap_operations {
  KFD_IOC_DBG_TRAP_ENABLE = 0,
  KFD_IOC_DBG_TRAP_DISABLE = 1,
  KFD_IOC_DBG_TRAP_SEND_RUNTIME_EVENT = 2,
  KFD_IOC_DBG_TRAP_SET_EXCEPTIONS_ENABLED = 3,
  KFD_IOC_DBG_TRAP_SET_WAVE_LAUNCH_OVERRIDE = 4,
  KFD_IOC_DBG_TRAP_SET_WAVE_LAUNCH_MODE = 5,
  KFD_IOC_DBG_TRAP_SUSPEND_QUEUES = 6,
  KFD_IOC_DBG_TRAP_RESUME_QUEUES = 7,
  KFD_IOC_DBG_TRAP_SET_NODE_ADDRESS_WATCH = 8,
  KFD_IOC_DBG_TRAP_CLEAR_NODE_ADDRESS_WATCH = 9,
  KFD_IOC_DBG_TRAP_SET_FLAGS = 10,
  KFD_IOC_DBG_TRAP_QUERY_DEBUG_EVENT = 11,
  KFD_IOC_DBG_TRAP_QUERY_EXCEPTION_INFO = 12,
  KFD_IOC_DBG_TRAP_GET_QUEUE_SNAPSHOT = 13,
  KFD_IOC_DBG_TRAP_GET_DEVICE_SNAPSHOT = 14
};
struct kfd_ioctl_dbg_trap_enable_args {
  __u64 exception_mask;
  __u64 rinfo_ptr;
  __u32 rinfo_size;
  __u32 dbg_fd;
};
struct kfd_ioctl_dbg_trap_send_runtime_event_args {
  __u64 exception_mask;
  __u32 gpu_id;
  __u32 queue_id;
};
struct kfd_ioctl_dbg_trap_set_exceptions_enabled_args {
  __u64 exception_mask;
};
struct kfd_ioctl_dbg_trap_set_wave_launch_override_args {
  __u32 override_mode;
  __u32 enable_mask;
  __u32 support_request_mask;
  __u32 pad;
};
struct kfd_ioctl_dbg_trap_set_wave_launch_mode_args {
  __u32 launch_mode;
  __u32 pad;
};
struct kfd_ioctl_dbg_trap_suspend_queues_args {
  __u64 exception_mask;
  __u64 queue_array_ptr;
  __u32 num_queues;
  __u32 grace_period;
};
struct kfd_ioctl_dbg_trap_resume_queues_args {
  __u64 queue_array_ptr;
  __u32 num_queues;
  __u32 pad;
};
struct kfd_ioctl_dbg_trap_set_node_address_watch_args {
  __u64 address;
  __u32 mode;
  __u32 mask;
  __u32 gpu_id;
  __u32 id;
};
struct kfd_ioctl_dbg_trap_clear_node_address_watch_args {
  __u32 gpu_id;
  __u32 id;
};
struct kfd_ioctl_dbg_trap_set_flags_args {
  __u32 flags;
  __u32 pad;
};
struct kfd_ioctl_dbg_trap_query_debug_event_args {
  __u64 exception_mask;
  __u32 gpu_id;
  __u32 queue_id;
};
struct kfd_ioctl_dbg_trap_query_exception_info_args {
  __u64 info_ptr;
  __u32 info_size;
  __u32 source_id;
  __u32 exception_code;
  __u32 clear_exception;
};
struct kfd_ioctl_dbg_trap_queue_snapshot_args {
  __u64 exception_mask;
  __u64 snapshot_buf_ptr;
  __u32 num_queues;
  __u32 entry_size;
};
struct kfd_ioctl_dbg_trap_device_snapshot_args {
  __u64 exception_mask;
  __u64 snapshot_buf_ptr;
  __u32 num_devices;
  __u32 entry_size;
};
struct kfd_ioctl_dbg_trap_args {
  __u32 pid;
  __u32 op;
  union {
    struct kfd_ioctl_dbg_trap_enable_args enable;
    struct kfd_ioctl_dbg_trap_send_runtime_event_args send_runtime_event;
    struct kfd_ioctl_dbg_trap_set_exceptions_enabled_args set_exceptions_enabled;
    struct kfd_ioctl_dbg_trap_set_wave_launch_override_args launch_override;
    struct kfd_ioctl_dbg_trap_set_wave_launch_mode_args launch_mode;
    struct kfd_ioctl_dbg_trap_suspend_queues_args suspend_queues;
    struct kfd_ioctl_dbg_trap_resume_queues_args resume_queues;
    struct kfd_ioctl_dbg_trap_set_node_address_watch_args set_node_address_watch;
    struct kfd_ioctl_dbg_trap_clear_node_address_watch_args clear_node_address_watch;
    struct kfd_ioctl_dbg_trap_set_flags_args set_flags;
    struct kfd_ioctl_dbg_trap_query_debug_event_args query_debug_event;
    struct kfd_ioctl_dbg_trap_query_exception_info_args query_exception_info;
    struct kfd_ioctl_dbg_trap_queue_snapshot_args queue_snapshot;
    struct kfd_ioctl_dbg_trap_device_snapshot_args device_snapshot;
  };
};
#define AMDKFD_IOCTL_BASE 'K'
#define AMDKFD_IO(nr) _IO(AMDKFD_IOCTL_BASE, nr)
#define AMDKFD_IOR(nr,type) _IOR(AMDKFD_IOCTL_BASE, nr, type)
#define AMDKFD_IOW(nr,type) _IOW(AMDKFD_IOCTL_BASE, nr, type)
#define AMDKFD_IOWR(nr,type) _IOWR(AMDKFD_IOCTL_BASE, nr, type)
#define AMDKFD_IOC_GET_VERSION AMDKFD_IOR(0x01, struct kfd_ioctl_get_version_args)
#define AMDKFD_IOC_CREATE_QUEUE AMDKFD_IOWR(0x02, struct kfd_ioctl_create_queue_args)
#define AMDKFD_IOC_DESTROY_QUEUE AMDKFD_IOWR(0x03, struct kfd_ioctl_destroy_queue_args)
#define AMDKFD_IOC_SET_MEMORY_POLICY AMDKFD_IOW(0x04, struct kfd_ioctl_set_memory_policy_args)
#define AMDKFD_IOC_GET_CLOCK_COUNTERS AMDKFD_IOWR(0x05, struct kfd_ioctl_get_clock_counters_args)
#define AMDKFD_IOC_GET_PROCESS_APERTURES AMDKFD_IOR(0x06, struct kfd_ioctl_get_process_apertures_args)
#define AMDKFD_IOC_UPDATE_QUEUE AMDKFD_IOW(0x07, struct kfd_ioctl_update_queue_args)
#define AMDKFD_IOC_CREATE_EVENT AMDKFD_IOWR(0x08, struct kfd_ioctl_create_event_args)
#define AMDKFD_IOC_DESTROY_EVENT AMDKFD_IOW(0x09, struct kfd_ioctl_destroy_event_args)
#define AMDKFD_IOC_SET_EVENT AMDKFD_IOW(0x0A, struct kfd_ioctl_set_event_args)
#define AMDKFD_IOC_RESET_EVENT AMDKFD_IOW(0x0B, struct kfd_ioctl_reset_event_args)
#define AMDKFD_IOC_WAIT_EVENTS AMDKFD_IOWR(0x0C, struct kfd_ioctl_wait_events_args)
#define AMDKFD_IOC_DBG_REGISTER_DEPRECATED AMDKFD_IOW(0x0D, struct kfd_ioctl_dbg_register_args)
#define AMDKFD_IOC_DBG_UNREGISTER_DEPRECATED AMDKFD_IOW(0x0E, struct kfd_ioctl_dbg_unregister_args)
#define AMDKFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED AMDKFD_IOW(0x0F, struct kfd_ioctl_dbg_address_watch_args)
#define AMDKFD_IOC_DBG_WAVE_CONTROL_DEPRECATED AMDKFD_IOW(0x10, struct kfd_ioctl_dbg_wave_control_args)
#define AMDKFD_IOC_SET_SCRATCH_BACKING_VA AMDKFD_IOWR(0x11, struct kfd_ioctl_set_scratch_backing_va_args)
#define AMDKFD_IOC_GET_TILE_CONFIG AMDKFD_IOWR(0x12, struct kfd_ioctl_get_tile_config_args)
#define AMDKFD_IOC_SET_TRAP_HANDLER AMDKFD_IOW(0x13, struct kfd_ioctl_set_trap_handler_args)
#define AMDKFD_IOC_GET_PROCESS_APERTURES_NEW AMDKFD_IOWR(0x14, struct kfd_ioctl_get_process_apertures_new_args)
#define AMDKFD_IOC_ACQUIRE_VM AMDKFD_IOW(0x15, struct kfd_ioctl_acquire_vm_args)
#define AMDKFD_IOC_ALLOC_MEMORY_OF_GPU AMDKFD_IOWR(0x16, struct kfd_ioctl_alloc_memory_of_gpu_args)
#define AMDKFD_IOC_FREE_MEMORY_OF_GPU AMDKFD_IOW(0x17, struct kfd_ioctl_free_memory_of_gpu_args)
#define AMDKFD_IOC_MAP_MEMORY_TO_GPU AMDKFD_IOWR(0x18, struct kfd_ioctl_map_memory_to_gpu_args)
#define AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU AMDKFD_IOWR(0x19, struct kfd_ioctl_unmap_memory_from_gpu_args)
#define AMDKFD_IOC_SET_CU_MASK AMDKFD_IOW(0x1A, struct kfd_ioctl_set_cu_mask_args)
#define AMDKFD_IOC_GET_QUEUE_WAVE_STATE AMDKFD_IOWR(0x1B, struct kfd_ioctl_get_queue_wave_state_args)
#define AMDKFD_IOC_GET_DMABUF_INFO AMDKFD_IOWR(0x1C, struct kfd_ioctl_get_dmabuf_info_args)
#define AMDKFD_IOC_IMPORT_DMABUF AMDKFD_IOWR(0x1D, struct kfd_ioctl_import_dmabuf_args)
#define AMDKFD_IOC_ALLOC_QUEUE_GWS AMDKFD_IOWR(0x1E, struct kfd_ioctl_alloc_queue_gws_args)
#define AMDKFD_IOC_SMI_EVENTS AMDKFD_IOWR(0x1F, struct kfd_ioctl_smi_events_args)
#define AMDKFD_IOC_SVM AMDKFD_IOWR(0x20, struct kfd_ioctl_svm_args)
#define AMDKFD_IOC_SET_XNACK_MODE AMDKFD_IOWR(0x21, struct kfd_ioctl_set_xnack_mode_args)
#define AMDKFD_IOC_CRIU_OP AMDKFD_IOWR(0x22, struct kfd_ioctl_criu_args)
#define AMDKFD_IOC_AVAILABLE_MEMORY AMDKFD_IOWR(0x23, struct kfd_ioctl_get_available_memory_args)
#define AMDKFD_IOC_EXPORT_DMABUF AMDKFD_IOWR(0x24, struct kfd_ioctl_export_dmabuf_args)
#define AMDKFD_IOC_RUNTIME_ENABLE AMDKFD_IOWR(0x25, struct kfd_ioctl_runtime_enable_args)
#define AMDKFD_IOC_DBG_TRAP AMDKFD_IOWR(0x26, struct kfd_ioctl_dbg_trap_args)
#define AMDKFD_COMMAND_START 0x01
#define AMDKFD_COMMAND_END 0x27
#endif
```