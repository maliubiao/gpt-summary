Response:
Let's break down the thought process for answering the request. The request is quite comprehensive, touching on several aspects of the provided header file. Here's a possible internal monologue and step-by-step approach:

1. **Understand the Core:** The first step is to recognize that this is a header file defining the user-space API for interacting with the Nouveau DRM driver. The `drm` in the path and the definitions themselves (`DRM_IOCTL_*`) confirm this. Nouveau is an open-source driver for NVIDIA graphics cards. The `uapi` part indicates it's meant for user-space programs.

2. **Identify the Functionalities (High-Level):** Scan the definitions and structures to grasp the main categories of operations. Keywords like `GETPARAM`, `CHANNEL_ALLOC`, `GEM_NEW`, `PUSHBUF`, `VM_BIND`, `EXEC` stand out. These suggest the driver handles:
    * Getting information about the hardware.
    * Managing communication channels with the GPU.
    * Allocating and managing GPU memory (GEM - Graphics Execution Manager).
    * Sending commands to the GPU.
    * Managing virtual memory for the GPU.

3. **Categorize and Elaborate on Functionalities:**  Now, go through the definitions systematically and group related ones.

    * **Hardware Information (`NOUVEAU_GETPARAM_*`, `drm_nouveau_getparam`):** These are clearly for querying hardware details. List the specific parameters.

    * **Channel Management (`drm_nouveau_channel_alloc`, `drm_nouveau_channel_free`):**  These are for creating and destroying communication channels. Note the sub-channel structure.

    * **GPU Object Management (`drm_nouveau_notifierobj_alloc`, `drm_nouveau_gpuobj_free`):**  These handle allocation and deallocation of general GPU objects and specific notifier objects (for synchronization).

    * **Graphics Memory Management (GEM) (`drm_nouveau_gem_*` structures and defines):** This is a major part. Identify the different domains (CPU, VRAM, GART), tiling modes, buffer objects (`drm_nouveau_gem_new`), push buffers (`drm_nouveau_gem_pushbuf`), relocations, and CPU preparation/finishing.

    * **Synchronization (`drm_nouveau_sync`):** This structure is explicitly for synchronization.

    * **Virtual Memory Management (`drm_nouveau_vm_*` structures):**  These handle initializing the GPU's virtual memory and binding/unbinding memory regions.

    * **Command Execution (`drm_nouveau_exec_*` structures):** These are for submitting command buffers to the GPU.

4. **Relate to Android (if applicable):**  Consider how these functionalities fit into the Android ecosystem. The key connection is the hardware abstraction layer (HAL) for graphics (`android.hardware.graphics.composer`). Explain that Android frameworks use the NDK to interact with these low-level drivers. Mention the SurfaceFlinger and its role in composition.

5. **Explain libc Functions (Crucially, There Aren't Any):**  Realize that *this header file itself doesn't define any libc functions*. It *defines structures and constants* used in system calls. The actual system calls (`ioctl`) are implemented in the kernel. Emphasize this distinction. Don't try to invent explanations for non-existent libc functions.

6. **Address Dynamic Linker (Again, Not Directly Applicable):**  Similar to libc, this header doesn't directly involve the dynamic linker. It defines structures that *user-space applications* using the driver would use. Explain that the linker is involved in loading the *user-space libraries* that make these `ioctl` calls. Provide a basic example of a hypothetical SO's layout and the linking process.

7. **Logical Reasoning (Example):** For `drm_nouveau_gem_pushbuf`, hypothesize a simple scenario of pushing a single buffer. Show the input structure and what it might represent (buffer handle, offset, length).

8. **Common Usage Errors:** Think about typical mistakes when working with low-level APIs:
    * Incorrect handle usage.
    * Domain mismatches.
    * Synchronization issues.
    * Buffer overflows (though not directly exposed here, it's a consequence of incorrect usage).

9. **Android Framework/NDK Interaction:** Trace the path from the Android framework to the kernel driver:
    * Framework (SurfaceFlinger).
    * Graphics HAL (implementation often uses the NDK).
    * NDK (system calls like `ioctl`).
    * Kernel driver (Nouveau).

10. **Frida Hooking:** Provide practical examples of how to use Frida to intercept the `ioctl` calls. Show how to get the command number and the structure being passed.

11. **Structure and Language:** Organize the answer logically with clear headings. Use precise language. Since the request is in Chinese, respond in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "I need to explain the `open`, `close`, `read`, `write` libc functions used by the driver."
* **Correction:** "Wait, this is just a *header* file. It doesn't *implement* any libc functions. It defines the *interface* for interacting with the *kernel driver* via `ioctl`. The focus should be on the structures and constants."

* **Initial thought:** "I need to show how the dynamic linker resolves symbols in the Nouveau driver SO."
* **Correction:** "The Nouveau driver is a *kernel* module, not a user-space SO. The dynamic linker is involved in the *user-space libraries* that interact with the driver. I should explain the linking process for a *hypothetical* user-space library using this header."

By following this detailed thought process and making necessary corrections, we can arrive at a comprehensive and accurate answer that addresses all parts of the request.
这是一个定义了与Nouveau DRM驱动交互的头文件。Nouveau是Linux内核中一个开源的NVIDIA显卡驱动。这个头文件定义了用户空间程序与Nouveau驱动进行交互所需要的数据结构和ioctl命令。

**它的功能：**

这个头文件定义了以下主要功能，允许用户空间程序执行与Nouveau驱动相关的操作：

1. **获取硬件参数 (Get Parameters):**
   - 允许查询GPU的各种硬件信息，例如PCI vendor ID、PCI device ID、总线类型、显存大小、AGP大小、芯片ID、显存的虚拟地址基址、图形单元数量、精确计时器时间、是否支持buffer object usage tracking、是否支持页面翻转、执行推送缓冲区的最大大小、显存BAR大小、已使用的显存大小、是否支持VMA tiling mode等。

2. **通道管理 (Channel Management):**
   - 允许分配和释放与GPU通信的通道。通道是用户空间程序向GPU提交命令的机制。
   - 可以为一个通道分配多个子通道。

3. **通知对象管理 (Notifier Object Management):**
   - 允许分配用于GPU事件通知的对象。

4. **GPU对象管理 (GPU Object Management):**
   - 允许释放之前分配的GPU对象。

5. **GEM (Graphics Execution Manager) 对象管理:**
   - **创建和管理显存对象 (Buffer Objects):** 允许创建、查询和管理GPU显存中的对象。可以指定对象所在的内存域（CPU、VRAM、GART等）、对齐方式、平铺模式等。
   - **推送缓冲区 (Push Buffers):** 允许构建和提交包含GPU命令的缓冲区。涉及到缓冲区的绑定、重定位和实际的命令数据。
   - **CPU 准备和完成 (CPU Prepare/Finish):**  允许用户空间程序通知驱动程序CPU即将访问或已完成访问某个GEM对象，以便驱动程序进行必要的缓存同步等操作。

6. **同步 (Synchronization):**
   - 允许进行GPU操作的同步，可以使用同步对象或时间线同步对象。

7. **虚拟机 (Virtual Machine) 管理:**
   - 允许初始化GPU的虚拟地址空间。
   - 允许将GEM对象绑定和解绑到GPU的虚拟地址空间。

8. **执行 (Execution):**
   - 允许执行之前准备好的推送缓冲区中的命令。

9. **SVM (Shared Virtual Memory) 管理:**
   - 允许初始化共享虚拟内存区域。
   - 允许将内存页绑定到共享虚拟内存区域。

**与 Android 功能的关系及举例：**

这个头文件直接关联到 Android 图形栈的底层实现。Android 的图形系统，特别是 SurfaceFlinger 和 OpenGL ES 驱动程序，会使用这些接口与底层的 Nouveau 驱动进行交互。

**举例说明：**

* **SurfaceFlinger 的 BufferQueue:** 当 SurfaceFlinger 需要将一个图形 Buffer (由应用渲染或解码得到) 提交到屏幕显示时，它可能会使用 GEM 对象来管理这个 Buffer 在 GPU 显存中的存储。`DRM_IOCTL_NOUVEAU_GEM_NEW` 用于分配这个 Buffer，`DRM_IOCTL_NOUVEAU_GEM_PUSHBUF` 用于将渲染命令提交到 GPU 以便进行合成。
* **OpenGL ES 驱动程序:**  当一个 Android 应用使用 OpenGL ES 进行渲染时，OpenGL ES 驱动程序会使用这些 ioctl 命令来分配显存用于纹理、顶点缓冲区等，并将渲染命令通过推送缓冲区提交给 GPU。例如，分配一个纹理可以使用 `DRM_IOCTL_NOUVEAU_GEM_NEW`，然后通过推送缓冲区使用这个纹理。
* **图形合成:** SurfaceFlinger 在进行图层合成时，需要将多个图形 Buffer 组合成最终的屏幕输出。这会涉及到使用 GEM 对象来管理这些 Buffer，并使用推送缓冲区提交合成命令。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示:** 这个头文件本身 **没有定义任何 libc 函数**。它定义的是 **ioctl 命令的编号和相关的数据结构**。  `ioctl` 是一个系统调用，它允许用户空间程序向设备驱动程序发送控制命令。

当用户空间程序调用 `ioctl` 时，内核会将调用传递给对应的设备驱动程序（在这个例子中是 Nouveau 驱动）。Nouveau 驱动的代码（位于内核空间）会根据 `ioctl` 的命令编号和传入的参数结构来执行相应的操作，例如分配显存、提交命令等。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件定义的是与 **内核驱动** 交互的接口，通常 **不直接涉及动态链接器**。动态链接器主要负责加载和链接用户空间共享库 (`.so` 文件)。

但是，用户空间程序可能会使用一个封装了这些 `ioctl` 调用的共享库来与 Nouveau 驱动进行交互。

**SO 布局样本 (假设一个名为 `libnouveau_client.so` 的用户空间库):**

```
libnouveau_client.so:
    .text:  // 代码段，包含封装了 ioctl 调用的函数
        nouveau_gem_new:
            // ... 准备 drm_nouveau_gem_new 结构 ...
            // ... 调用 ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_NEW, &gem_new_struct) ...
            // ... 处理 ioctl 返回值 ...
            // ... 返回结果 ...

        nouveau_pushbuf_submit:
            // ... 准备 drm_nouveau_gem_pushbuf 结构 ...
            // ... 调用 ioctl(fd, DRM_IOCTL_NOUVEAU_GEM_PUSHBUF, &pushbuf_struct) ...
            // ... 处理 ioctl 返回值 ...
            // ... 返回结果 ...

    .data:  // 数据段，包含全局变量等

    .bss:   // 未初始化数据段

    .dynsym: // 动态符号表，记录了库提供的函数和需要外部提供的函数

    .dynstr: // 动态字符串表，存储符号名称等字符串

    .plt:    // 程序链接表，用于延迟绑定外部函数

    .got:    // 全局偏移表，存储外部函数的地址
```

**链接的处理过程：**

1. **编译时链接:** 当开发者编译使用 `libnouveau_client.so` 的应用程序时，链接器会记录下应用程序需要使用 `libnouveau_client.so` 提供的哪些函数 (例如 `nouveau_gem_new`, `nouveau_pushbuf_submit`)。这些信息会存储在应用程序的可执行文件的 `.dynamic` 段中。

2. **运行时链接 (动态链接器 `ld-linux.so` 或 `linker64`):**
   - 当应用程序启动时，操作系统会加载动态链接器。
   - 动态链接器会读取应用程序的 `.dynamic` 段，找到需要加载的共享库 `libnouveau_client.so`。
   - 动态链接器会加载 `libnouveau_client.so` 到内存中。
   - **符号解析:** 动态链接器会遍历 `libnouveau_client.so` 的 `.dynsym` (动态符号表)，找到应用程序需要的符号 (例如 `nouveau_gem_new`) 的地址。
   - **重定位:** 动态链接器会修改应用程序的 `.got` (全局偏移表) 和 `libnouveau_client.so` 的 `.plt` (程序链接表)，将这些符号的地址填入。
   - **延迟绑定 (Lazy Binding):**  通常，外部函数的地址在第一次被调用时才会被解析和绑定。当应用程序第一次调用 `nouveau_gem_new` 时，控制流会先跳转到 `.plt` 中的一个桩代码，这个桩代码会调用动态链接器来解析 `nouveau_gem_new` 的实际地址，并将地址填入 `.got` 中。后续的调用将直接跳转到 `.got` 中存储的地址。

**如果做了逻辑推理，请给出假设输入与输出：**

**假设输入 (针对 `DRM_IOCTL_NOUVEAU_GEM_NEW`)：**

```c
struct drm_nouveau_gem_new gem_new_args;
gem_new_args.info.size = 1024 * 1024; // 分配 1MB 的显存
gem_new_args.info.domain = NOUVEAU_GEM_DOMAIN_VRAM; // 分配在 VRAM 中
gem_new_args.align = 4096; // 4KB 对齐
```

**预期输出：**

如果 `ioctl` 调用成功，驱动程序会填充 `gem_new_args.info` 结构体的其他字段：

```c
gem_new_args.info.handle = 123; // 假设分配的 GEM 对象的句柄是 123
gem_new_args.info.offset = 0x10000000; // 假设分配的显存的 GPU 地址是 0x10000000
// ... 其他字段 ...
```

`ioctl` 系统调用会返回 0 表示成功，返回 -1 并设置 `errno` 表示失败。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **无效的句柄:** 尝试使用一个未分配或已释放的通道句柄或 GEM 对象句柄。例如，在调用 `DRM_IOCTL_NOUVEAU_GEM_PUSHBUF` 时使用了错误的 `channel` 或 `buffers` 中的 `handle`。

2. **内存域错误:** 尝试在不支持的内存域分配 GEM 对象，或者尝试在错误的内存域访问 GEM 对象。例如，尝试将一个仅在 VRAM 中分配的 GEM 对象映射到 CPU 可访问的地址空间，而没有设置 `NOUVEAU_GEM_DOMAIN_MAPPABLE` 标志。

3. **同步错误:**  在 GPU 操作完成之前就尝试访问其结果，或者没有正确地进行同步操作。例如，在调用 `DRM_IOCTL_NOUVEAU_GEM_PUSHBUF` 提交命令后，没有等待 GPU 执行完成就尝试读取修改后的显存内容。

4. **推送缓冲区溢出:**  在构建推送缓冲区时，写入的数据超过了缓冲区的大小限制。

5. **错误的 ioctl 命令编号或参数结构:**  传递了错误的 `ioctl` 命令编号或者参数结构体的布局与驱动程序期望的不一致。

6. **权限问题:** 用户没有足够的权限访问 `/dev/dri/cardX` 设备文件。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**路径：**

1. **Android Framework (Java/Kotlin):**  应用程序通常通过 Android Framework 的 Surface 或 OpenGL ES API 与图形系统交互。
2. **Graphics HAL (Hardware Abstraction Layer):**  Framework 层调用 Graphics HAL 接口 (例如 `android.hardware.graphics.composer` AIDL 接口)。
3. **NDK (Native Development Kit):**  Graphics HAL 的实现通常使用 C/C++，并通过 NDK 提供的接口与底层驱动交互。
4. **DRM (Direct Rendering Manager) API:**  NDK 代码会使用标准的 DRM API (例如 `drmOpen`, `drmIoctl`) 来与内核 DRM 子系统交互。
5. **Nouveau DRM Driver:** 内核 DRM 子系统会将 `ioctl` 调用路由到对应的 Nouveau 驱动程序。

**Frida Hook 示例：**

假设你想 hook `DRM_IOCTL_NOUVEAU_GEM_NEW` 这个 ioctl 调用。你需要 hook `ioctl` 系统调用，并判断其参数是否匹配 Nouveau 相关的设备文件和命令编号。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(['com.example.myapp']) # 替换为你的应用包名
    if not pid:
        device.resume(session.pid)

    script = session.create_script("""
        const ioctlPtr = Module.getExportByName(null, "ioctl");
        const DRM_IOCTL_BASE = 0x40006400; // Assuming DRM_COMMAND_BASE is 0x40
        const DRM_NOUVEAU_GEM_NEW = 0x40;
        const DRM_IOCTL_NOUVEAU_GEM_NEW_CMD = DRM_IOCTL_BASE + DRM_NOUVEAU_GEM_NEW;

        Interceptor.attach(ioctlPtr, {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                if (request === DRM_IOCTL_NOUVEAU_GEM_NEW_CMD) {
                    this.is_nouveau_gem_new = true;
                    const argp = ptr(args[2]);
                    // 读取 drm_nouveau_gem_new 结构体的内容
                    const size_ptr = argp.add(8); // offset of info.size
                    const domain_ptr = argp.add(16); // offset of info.domain
                    const size = size_ptr.readU64();
                    const domain = domain_ptr.readU32();
                    send({
                        type: "nouveau_gem_new",
                        fd: fd,
                        size: size,
                        domain: domain
                    });
                }
            },
            onLeave: function(retval) {
                if (this.is_nouveau_gem_new) {
                    this.is_nouveau_gem_new = false;
                    send({
                        type: "nouveau_gem_new_ret",
                        retval: retval.toInt32()
                    });
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    print('[*] Script loaded, press Ctrl+C to exit')
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print("进程未找到，请指定正确的进程 ID 或应用包名。")
except KeyboardInterrupt:
    print("Exiting...")
```

**使用方法：**

1. 将上述代码保存为 `nouveau_hook.py`。
2. 找到你想要调试的 Android 应用的进程 ID (可以使用 `adb shell ps | grep your_app_package_name`)。
3. 运行 `python nouveau_hook.py <进程ID>` 或 `python nouveau_hook.py com.example.myapp` (如果应用尚未运行)。

**Frida Hook 解释：**

* **`Module.getExportByName(null, "ioctl")`:** 获取 `ioctl` 系统调用的地址。
* **`DRM_IOCTL_BASE` 和 `DRM_NOUVEAU_GEM_NEW_CMD`:**  计算 `DRM_IOCTL_NOUVEAU_GEM_NEW` 命令的完整编号。你需要根据你的 Android 平台的 DRM 定义来确定 `DRM_COMMAND_BASE` 的值。
* **`Interceptor.attach(ioctlPtr, ...)`:**  拦截 `ioctl` 函数的调用。
* **`onEnter`:**  在 `ioctl` 函数调用之前执行。检查 `request` 参数是否匹配 `DRM_IOCTL_NOUVEAU_GEM_NEW_CMD`。如果是，则读取 `drm_nouveau_gem_new` 结构体中的 `size` 和 `domain` 字段并发送消息到 Frida 客户端。
* **`onLeave`:** 在 `ioctl` 函数调用返回之后执行。发送返回值信息。
* **`script.on('message', on_message)`:**  注册消息处理函数，用于打印从 Frida 脚本接收到的信息。

通过这个 Frida 脚本，你可以监控你的 Android 应用在与 Nouveau 驱动交互时，何时以及如何分配 GEM 对象，从而帮助你调试图形相关的 issues。你可以根据需要修改脚本来 hook 其他的 ioctl 命令和读取更多的参数信息。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/drm/nouveau_drm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __NOUVEAU_DRM_H__
#define __NOUVEAU_DRM_H__
#define DRM_NOUVEAU_EVENT_NVIF 0x80000000
#include "drm.h"
#ifdef __cplusplus
extern "C" {
#endif
#define NOUVEAU_GETPARAM_PCI_VENDOR 3
#define NOUVEAU_GETPARAM_PCI_DEVICE 4
#define NOUVEAU_GETPARAM_BUS_TYPE 5
#define NOUVEAU_GETPARAM_FB_SIZE 8
#define NOUVEAU_GETPARAM_AGP_SIZE 9
#define NOUVEAU_GETPARAM_CHIPSET_ID 11
#define NOUVEAU_GETPARAM_VM_VRAM_BASE 12
#define NOUVEAU_GETPARAM_GRAPH_UNITS 13
#define NOUVEAU_GETPARAM_PTIMER_TIME 14
#define NOUVEAU_GETPARAM_HAS_BO_USAGE 15
#define NOUVEAU_GETPARAM_HAS_PAGEFLIP 16
#define NOUVEAU_GETPARAM_EXEC_PUSH_MAX 17
#define NOUVEAU_GETPARAM_VRAM_BAR_SIZE 18
#define NOUVEAU_GETPARAM_VRAM_USED 19
#define NOUVEAU_GETPARAM_HAS_VMA_TILEMODE 20
struct drm_nouveau_getparam {
  __u64 param;
  __u64 value;
};
#define NOUVEAU_FIFO_ENGINE_GR 0x01
#define NOUVEAU_FIFO_ENGINE_VP 0x02
#define NOUVEAU_FIFO_ENGINE_PPP 0x04
#define NOUVEAU_FIFO_ENGINE_BSP 0x08
#define NOUVEAU_FIFO_ENGINE_CE 0x30
struct drm_nouveau_channel_alloc {
  __u32 fb_ctxdma_handle;
  __u32 tt_ctxdma_handle;
  __s32 channel;
  __u32 pushbuf_domains;
  __u32 notifier_handle;
  struct {
    __u32 handle;
    __u32 grclass;
  } subchan[8];
  __u32 nr_subchan;
};
struct drm_nouveau_channel_free {
  __s32 channel;
};
struct drm_nouveau_notifierobj_alloc {
  __u32 channel;
  __u32 handle;
  __u32 size;
  __u32 offset;
};
struct drm_nouveau_gpuobj_free {
  __s32 channel;
  __u32 handle;
};
#define NOUVEAU_GEM_DOMAIN_CPU (1 << 0)
#define NOUVEAU_GEM_DOMAIN_VRAM (1 << 1)
#define NOUVEAU_GEM_DOMAIN_GART (1 << 2)
#define NOUVEAU_GEM_DOMAIN_MAPPABLE (1 << 3)
#define NOUVEAU_GEM_DOMAIN_COHERENT (1 << 4)
#define NOUVEAU_GEM_DOMAIN_NO_SHARE (1 << 5)
#define NOUVEAU_GEM_TILE_COMP 0x00030000
#define NOUVEAU_GEM_TILE_LAYOUT_MASK 0x0000ff00
#define NOUVEAU_GEM_TILE_16BPP 0x00000001
#define NOUVEAU_GEM_TILE_32BPP 0x00000002
#define NOUVEAU_GEM_TILE_ZETA 0x00000004
#define NOUVEAU_GEM_TILE_NONCONTIG 0x00000008
struct drm_nouveau_gem_info {
  __u32 handle;
  __u32 domain;
  __u64 size;
  __u64 offset;
  __u64 map_handle;
  __u32 tile_mode;
  __u32 tile_flags;
};
struct drm_nouveau_gem_new {
  struct drm_nouveau_gem_info info;
  __u32 channel_hint;
  __u32 align;
};
#define NOUVEAU_GEM_MAX_BUFFERS 1024
struct drm_nouveau_gem_pushbuf_bo_presumed {
  __u32 valid;
  __u32 domain;
  __u64 offset;
};
struct drm_nouveau_gem_pushbuf_bo {
  __u64 user_priv;
  __u32 handle;
  __u32 read_domains;
  __u32 write_domains;
  __u32 valid_domains;
  struct drm_nouveau_gem_pushbuf_bo_presumed presumed;
};
#define NOUVEAU_GEM_RELOC_LOW (1 << 0)
#define NOUVEAU_GEM_RELOC_HIGH (1 << 1)
#define NOUVEAU_GEM_RELOC_OR (1 << 2)
#define NOUVEAU_GEM_MAX_RELOCS 1024
struct drm_nouveau_gem_pushbuf_reloc {
  __u32 reloc_bo_index;
  __u32 reloc_bo_offset;
  __u32 bo_index;
  __u32 flags;
  __u32 data;
  __u32 vor;
  __u32 tor;
};
#define NOUVEAU_GEM_MAX_PUSH 512
struct drm_nouveau_gem_pushbuf_push {
  __u32 bo_index;
  __u32 pad;
  __u64 offset;
  __u64 length;
#define NOUVEAU_GEM_PUSHBUF_NO_PREFETCH (1 << 23)
};
struct drm_nouveau_gem_pushbuf {
  __u32 channel;
  __u32 nr_buffers;
  __u64 buffers;
  __u32 nr_relocs;
  __u32 nr_push;
  __u64 relocs;
  __u64 push;
  __u32 suffix0;
  __u32 suffix1;
#define NOUVEAU_GEM_PUSHBUF_SYNC (1ULL << 0)
  __u64 vram_available;
  __u64 gart_available;
};
#define NOUVEAU_GEM_CPU_PREP_NOWAIT 0x00000001
#define NOUVEAU_GEM_CPU_PREP_WRITE 0x00000004
struct drm_nouveau_gem_cpu_prep {
  __u32 handle;
  __u32 flags;
};
struct drm_nouveau_gem_cpu_fini {
  __u32 handle;
};
struct drm_nouveau_sync {
  __u32 flags;
#define DRM_NOUVEAU_SYNC_SYNCOBJ 0x0
#define DRM_NOUVEAU_SYNC_TIMELINE_SYNCOBJ 0x1
#define DRM_NOUVEAU_SYNC_TYPE_MASK 0xf
  __u32 handle;
  __u64 timeline_value;
};
struct drm_nouveau_vm_init {
  __u64 kernel_managed_addr;
  __u64 kernel_managed_size;
};
struct drm_nouveau_vm_bind_op {
  __u32 op;
#define DRM_NOUVEAU_VM_BIND_OP_MAP 0x0
#define DRM_NOUVEAU_VM_BIND_OP_UNMAP 0x1
  __u32 flags;
#define DRM_NOUVEAU_VM_BIND_SPARSE (1 << 8)
  __u32 handle;
  __u32 pad;
  __u64 addr;
  __u64 bo_offset;
  __u64 range;
};
struct drm_nouveau_vm_bind {
  __u32 op_count;
  __u32 flags;
#define DRM_NOUVEAU_VM_BIND_RUN_ASYNC 0x1
  __u32 wait_count;
  __u32 sig_count;
  __u64 wait_ptr;
  __u64 sig_ptr;
  __u64 op_ptr;
};
struct drm_nouveau_exec_push {
  __u64 va;
  __u32 va_len;
  __u32 flags;
#define DRM_NOUVEAU_EXEC_PUSH_NO_PREFETCH 0x1
};
struct drm_nouveau_exec {
  __u32 channel;
  __u32 push_count;
  __u32 wait_count;
  __u32 sig_count;
  __u64 wait_ptr;
  __u64 sig_ptr;
  __u64 push_ptr;
};
#define DRM_NOUVEAU_GETPARAM 0x00
#define DRM_NOUVEAU_SETPARAM 0x01
#define DRM_NOUVEAU_CHANNEL_ALLOC 0x02
#define DRM_NOUVEAU_CHANNEL_FREE 0x03
#define DRM_NOUVEAU_GROBJ_ALLOC 0x04
#define DRM_NOUVEAU_NOTIFIEROBJ_ALLOC 0x05
#define DRM_NOUVEAU_GPUOBJ_FREE 0x06
#define DRM_NOUVEAU_NVIF 0x07
#define DRM_NOUVEAU_SVM_INIT 0x08
#define DRM_NOUVEAU_SVM_BIND 0x09
#define DRM_NOUVEAU_VM_INIT 0x10
#define DRM_NOUVEAU_VM_BIND 0x11
#define DRM_NOUVEAU_EXEC 0x12
#define DRM_NOUVEAU_GEM_NEW 0x40
#define DRM_NOUVEAU_GEM_PUSHBUF 0x41
#define DRM_NOUVEAU_GEM_CPU_PREP 0x42
#define DRM_NOUVEAU_GEM_CPU_FINI 0x43
#define DRM_NOUVEAU_GEM_INFO 0x44
struct drm_nouveau_svm_init {
  __u64 unmanaged_addr;
  __u64 unmanaged_size;
};
struct drm_nouveau_svm_bind {
  __u64 header;
  __u64 va_start;
  __u64 va_end;
  __u64 npages;
  __u64 stride;
  __u64 result;
  __u64 reserved0;
  __u64 reserved1;
};
#define NOUVEAU_SVM_BIND_COMMAND_SHIFT 0
#define NOUVEAU_SVM_BIND_COMMAND_BITS 8
#define NOUVEAU_SVM_BIND_COMMAND_MASK ((1 << 8) - 1)
#define NOUVEAU_SVM_BIND_PRIORITY_SHIFT 8
#define NOUVEAU_SVM_BIND_PRIORITY_BITS 8
#define NOUVEAU_SVM_BIND_PRIORITY_MASK ((1 << 8) - 1)
#define NOUVEAU_SVM_BIND_TARGET_SHIFT 16
#define NOUVEAU_SVM_BIND_TARGET_BITS 32
#define NOUVEAU_SVM_BIND_TARGET_MASK 0xffffffff
#define NOUVEAU_SVM_BIND_VALID_BITS 48
#define NOUVEAU_SVM_BIND_VALID_MASK ((1ULL << NOUVEAU_SVM_BIND_VALID_BITS) - 1)
#define NOUVEAU_SVM_BIND_COMMAND__MIGRATE 0
#define NOUVEAU_SVM_BIND_TARGET__GPU_VRAM (1UL << 31)
#define DRM_IOCTL_NOUVEAU_GETPARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GETPARAM, struct drm_nouveau_getparam)
#define DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_ALLOC, struct drm_nouveau_channel_alloc)
#define DRM_IOCTL_NOUVEAU_CHANNEL_FREE DRM_IOW(DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_FREE, struct drm_nouveau_channel_free)
#define DRM_IOCTL_NOUVEAU_SVM_INIT DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_SVM_INIT, struct drm_nouveau_svm_init)
#define DRM_IOCTL_NOUVEAU_SVM_BIND DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_SVM_BIND, struct drm_nouveau_svm_bind)
#define DRM_IOCTL_NOUVEAU_GEM_NEW DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_NEW, struct drm_nouveau_gem_new)
#define DRM_IOCTL_NOUVEAU_GEM_PUSHBUF DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_PUSHBUF, struct drm_nouveau_gem_pushbuf)
#define DRM_IOCTL_NOUVEAU_GEM_CPU_PREP DRM_IOW(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_PREP, struct drm_nouveau_gem_cpu_prep)
#define DRM_IOCTL_NOUVEAU_GEM_CPU_FINI DRM_IOW(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_FINI, struct drm_nouveau_gem_cpu_fini)
#define DRM_IOCTL_NOUVEAU_GEM_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_INFO, struct drm_nouveau_gem_info)
#define DRM_IOCTL_NOUVEAU_VM_INIT DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_VM_INIT, struct drm_nouveau_vm_init)
#define DRM_IOCTL_NOUVEAU_VM_BIND DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_VM_BIND, struct drm_nouveau_vm_bind)
#define DRM_IOCTL_NOUVEAU_EXEC DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_EXEC, struct drm_nouveau_exec)
#ifdef __cplusplus
}
#endif
#endif
```