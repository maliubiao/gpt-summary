Response:
Let's break down the thought process for answering this request, simulating how I might approach it as a large language model.

**1. Initial Understanding of the Request:**

The user has provided a header file (`kfd_sysfs.handroid`) and wants to understand its purpose and context within the Android ecosystem. The request is quite detailed, asking for:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it relate to Android features? Examples are needed.
* **`libc` Functions:**  Explanation of each `libc` function used (which, in this *specific* case, is a trick question, as there are *no* `libc` functions in the provided header file).
* **Dynamic Linker:**  How does it interact with the dynamic linker? Provide SO layout and linking process examples. (Another trick question; this is a header file defining constants, not directly involved in dynamic linking.)
* **Logic/Inference:**  Provide examples of input/output if any logical deductions are made.
* **Common Errors:**  What mistakes might users make when interacting with this?
* **Android Framework/NDK Path:** How does a call from Android eventually reach this level?  Include a Frida hook example.

**2. First Pass - Identifying Key Elements:**

I immediately recognize that this is a header file defining a set of constants, likely for interacting with a kernel driver. The naming convention (`HSA_CAP_*`, `HSA_MEM_*`, `HSA_IOLINK_*`) strongly suggests it's related to the Heterogeneous System Architecture (HSA). The "kfd" in the filename likely stands for "Kernel Function Driver," a common naming pattern for kernel drivers. The "sysfs" part indicates these constants are used to interact with the driver via the sysfs filesystem in Linux.

**3. Addressing Specific Questions (and identifying the "tricks"):**

* **Functionality:** The primary function is to define constants that represent capabilities, memory heap types, cache types, and I/O link types related to an HSA-compliant device. These constants are used to query and potentially configure the device.
* **Android Relevance:**  This is directly tied to hardware acceleration and GPU compute in Android. Features like rendering, machine learning inference (using things like TensorFlow Lite GPU), and potentially some camera processing could leverage this.
* **`libc` Functions:** This is where I realize the trick. There are *no* `libc` function calls in this header file. It's purely declarations of `#define` macros. My answer needs to explicitly state this.
* **Dynamic Linker:**  Another trick. Header files don't directly participate in dynamic linking. They *inform* code that gets linked. My answer must clarify this. While SO layouts and linking processes are relevant to understanding Android's internals, they aren't directly applicable to *this specific file*. I should give a *general* explanation of how SOs and linking work in Android to provide context, even though this file doesn't directly participate.
* **Logic/Inference:**  The constants themselves represent a kind of "input" and the driver's behavior based on these constants is the "output."  I can create hypothetical scenarios where an Android component checks for specific capabilities.
* **Common Errors:**  Incorrectly using or interpreting these constants in user-space code is the main error. For example, assuming a feature is present when the corresponding capability bit isn't set.
* **Android Framework/NDK Path:**  This requires tracing a call from the high-level framework down to the kernel driver. I need to identify likely entry points (e.g., the NDK's AHardwareBuffer, RenderScript, or potentially vendor-specific HALs). The Frida hook example should target an area where these constants are likely to be used or checked (e.g., during device initialization or when querying device properties).

**4. Structuring the Answer:**

I need to organize the answer logically, addressing each part of the user's request. Using headings and bullet points will improve readability. It's important to be clear and concise, especially when explaining the "trick" questions about `libc` and the dynamic linker.

**5. Generating Examples:**

* **Android Relevance:**  Provide concrete examples of how each category of constants (capabilities, memory heaps, etc.) might be used in Android.
* **Logic/Inference:**  Create a simple scenario of checking for a specific capability.
* **Common Errors:**  Illustrate a mistake a developer might make when using these constants.
* **Frida Hook:**  Write a practical Frida script that demonstrates how to intercept calls related to these constants. I need to make a reasonable assumption about where these constants might be used. Hooking a `read` or `open` call on the sysfs path is a good starting point.

**6. Refining and Reviewing:**

Before submitting the answer, I would review it to ensure accuracy, clarity, and completeness. I would double-check that I've addressed all parts of the user's request and that my explanations are easy to understand. I'd also make sure to use precise language, especially when discussing the relationship between the header file and other system components.

This iterative process of understanding the request, identifying key elements, addressing specific points (including the tricky ones), structuring the answer, generating examples, and refining the output allows me to construct a comprehensive and accurate response, even to complex and multi-faceted questions like this one.
这是一个定义了与Linux内核中的KFD（Kernel Function Driver）子系统交互时使用的一些常量的头文件。KFD是AMD GPU的开源内核驱动，用于支持异构计算，即CPU和GPU协同工作。这个头文件位于Android的Bionic库中，意味着Android系统也使用了KFD驱动或其相关概念。

**功能列举:**

这个头文件定义了一系列宏常量，这些常量用于：

1. **描述GPU的功能 (HSA Capabilities - HSA_CAP_*)**: 这些常量定义了GPU硬件和驱动所支持的各种特性，例如：
    * **热插拔 (HSA_CAP_HOT_PLUGGABLE):**  GPU是否支持在系统运行时添加或移除。
    * **地址转换服务 (ATS Present - HSA_CAP_ATS_PRESENT):**  GPU是否支持ATS，用于更高效的内存访问。
    * **与图形共享 (Shared with Graphics - HSA_CAP_SHARED_WITH_GRAPHICS):** GPU是否可以与图形处理单元共享资源。
    * **队列大小 (Queue Size - HSA_CAP_QUEUE_SIZE_POW2, HSA_CAP_QUEUE_SIZE_32BIT):**  关于提交给GPU的命令队列大小的限制。
    * **事件 (Idle Event - HSA_CAP_QUEUE_IDLE_EVENT):** GPU队列空闲事件的支持。
    * **虚拟地址限制 (VA Limit - HSA_CAP_VA_LIMIT):**  GPU支持的虚拟地址空间大小。
    * **观察点 (Watch Points - HSA_CAP_WATCH_POINTS_*):** 用于调试的硬件观察点功能。
    * **门铃类型 (Doorbell Type - HSA_CAP_DOORBELL_TYPE_*):**  用于通知GPU有新工作提交的机制类型。
    * **其他高级特性 (AQL Queue Double Map, Trap Debug Support 等):**  更底层的硬件和调试支持。

2. **描述内存堆类型 (HSA Memory Heap Types - HSA_MEM_HEAP_TYPE_*)**: 这些常量定义了GPU可用的不同类型的内存，例如：
    * **系统内存 (System - HSA_MEM_HEAP_TYPE_SYSTEM):**  主机（CPU）可以访问的系统内存。
    * **帧缓冲区 (FB Public/Private - HSA_MEM_HEAP_TYPE_FB_PUBLIC, HSA_MEM_HEAP_TYPE_FB_PRIVATE):**  GPU的本地显存。
    * **片上全局数据共享 (GPU GDS - HSA_MEM_HEAP_TYPE_GPU_GDS):**  GPU内部核心之间共享的内存。
    * **本地数据共享 (GPU LDS - HSA_MEM_HEAP_TYPE_GPU_LDS):**  每个计算单元（CU）本地的共享内存。
    * **暂存内存 (GPU Scratch - HSA_MEM_HEAP_TYPE_GPU_SCRATCH):**  用于临时存储的内存。

3. **描述内存堆的标志 (HSA Memory Flags - HSA_MEM_FLAGS_*)**:  定义了内存的一些属性，例如：
    * **热插拔 (HOT_PLUGGABLE):**  指示内存是否支持热插拔。
    * **非易失性 (NON_VOLATILE):** 指示内存是否是非易失性的。

4. **描述缓存类型 (HSA Cache Types - HSA_CACHE_TYPE_*)**:  定义了不同类型的缓存，例如：
    * **数据缓存 (Data):** 用于存储数据的缓存。
    * **指令缓存 (Instruction):** 用于存储指令的缓存。
    * **CPU 缓存 (CPU):** CPU上的缓存。
    * **HSACU 缓存 (HSACU):** HSA 计算单元上的缓存。

5. **描述I/O链路类型和标志 (HSA I/O Link Types & Flags - HSA_IOLINK_TYPE_*, HSA_IOLINK_FLAGS_*)**: 定义了GPU与其他设备（例如CPU）之间的互连类型和属性，例如：
    * **各种互连协议 (HYPERTRANSPORT, PCIEXPRESS, XGMI 等):**  不同的硬件连接方式。
    * **链路状态 (ENABLED):**  链路是否激活。
    * **缓存一致性 (NON_COHERENT):**  链路是否支持缓存一致性。
    * **原子操作支持 (NO_ATOMICS_32_BIT, NO_ATOMICS_64_BIT):**  链路是否支持原子操作。
    * **点对点DMA支持 (NO_PEER_TO_PEER_DMA):** 链路是否支持设备之间的直接内存访问。

6. **描述调试相关的常量 (HSA Debug - HSA_DBG_*)**: 定义了与GPU调试相关的常量，例如观察点的地址掩码和调度信息。

**与Android功能的关联及举例说明:**

这个头文件直接关系到Android系统中使用GPU进行通用计算（GPGPU）的能力。Android设备上使用的GPU不仅仅用于图形渲染，还可以执行并行计算任务，例如：

* **机器学习/AI加速:**  TensorFlow Lite等框架可以使用GPU来加速模型推理。这些框架底层的实现可能会使用KFD驱动提供的接口，而这些常量就是与驱动交互的参数。例如，TensorFlow Lite可能会检查`HSA_CAP_QUEUE_SIZE_POW2`来确定可以创建的最大命令队列大小。
* **图像处理和计算机视觉:**  Android的Camera API或者一些图像处理库可能会利用GPU加速图像滤波、边缘检测等操作。这些操作也可能通过KFD驱动与GPU进行交互，例如分配GPU内存（使用`HSA_MEM_HEAP_TYPE_FB_PUBLIC`）。
* **游戏和高性能图形:** 虽然主要用于图形渲染，但现代游戏引擎也会利用GPU的计算能力进行物理模拟、粒子特效等。即使是图形渲染路径，也可能在某些底层操作上与KFD驱动有交集。
* **RenderScript:**  虽然RenderScript已弃用，但它是Android早期利用GPU进行并行计算的一种方式。RenderScript的底层实现很可能使用了类似的机制与GPU进行交互。

**libc 函数的功能实现:**

这个头文件本身不包含任何 `libc` 函数的定义或调用。它仅仅定义了一些宏常量。`libc` (Android's C library) 可能会包含一些函数，用于与内核驱动进行交互，例如 `ioctl` 系统调用。这些函数会使用这里定义的常量作为参数传递给内核，以查询或配置GPU的状态。

**动态链接器的功能:**

这个头文件定义的是宏常量，它不涉及动态链接。动态链接器负责将应用程序和共享库在运行时连接在一起。这个头文件会被编译到使用它的库或应用程序中。

**SO 布局样本和链接处理过程 (与本文件无关，但为了理解Android的动态链接):**

假设有一个使用了KFD相关功能的共享库 `libcompute.so`。

**libcompute.so 的布局样本:**

```
libcompute.so:
    .text         # 代码段
        compute_task:
            ... // 使用KFD相关常量与GPU交互的代码
    .data         # 已初始化数据段
    .bss          # 未初始化数据段
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .rel.dyn      # 动态重定位表
    .plt          # 程序链接表
    .got.plt      # 全局偏移表
```

**链接的处理过程:**

1. **编译时:** 当编译 `libcompute.so` 的源代码时，编译器会遇到使用了 `KFD_SYSFS_H_INCLUDED` 中定义的宏常量的地方。这些常量会被直接替换到代码中。
2. **链接时:**  静态链接器会将目标文件链接成共享库。如果 `libcompute.so` 依赖于其他共享库，链接器会记录这些依赖关系。
3. **运行时:** 当一个应用程序（例如一个使用GPU加速的图像处理应用）启动并加载 `libcompute.so` 时，Android 的动态链接器 `linker64` 或 `linker` 会执行以下操作：
    * **加载共享库:** 将 `libcompute.so` 加载到内存中的某个地址空间。
    * **解析依赖关系:** 检查 `libcompute.so` 依赖的其他共享库。
    * **加载依赖库:** 如果依赖的库尚未加载，则加载它们。
    * **重定位:**  由于共享库被加载到内存的哪个地址是运行时决定的，链接器需要修改代码和数据中的地址引用，使其指向正确的内存位置。这通常涉及到修改全局偏移表（GOT）和程序链接表（PLT）。
    * **符号绑定:**  将应用程序和共享库中使用的符号（例如函数名、全局变量名）解析到它们的实际内存地址。

**逻辑推理、假设输入与输出 (针对宏定义，较为简单):**

假设有一段C++代码使用了 `HSA_CAP_QUEUE_SIZE_POW2` 这个宏：

```c++
#include <linux/kfd_sysfs.h>
#include <iostream>

int main() {
    if (HSA_CAP_QUEUE_SIZE_POW2) {
        std::cout << "GPU supports power-of-two queue sizes." << std::endl;
    } else {
        std::cout << "GPU does not support power-of-two queue sizes." << std::endl;
    }
    return 0;
}
```

**假设输入:** 编译并运行这段代码的Android设备，其GPU驱动报告支持 power-of-two 队列大小。

**输出:**

```
GPU supports power-of-two queue sizes.
```

**假设输入:** 编译并运行这段代码的Android设备，其GPU驱动报告不支持 power-of-two 队列大小。

**输出:**

```
GPU does not support power-of-two queue sizes.
```

实际上，这些宏通常被用于更复杂的场景，例如在与内核驱动交互时设置标志位。

**用户或编程常见的使用错误:**

1. **直接使用宏的值进行假设:** 开发者可能会错误地假设某个宏的值总是固定的。实际上，这些宏的值是由内核驱动在运行时确定的。应该通过读取sysfs文件或其他驱动接口来获取实际的设备能力。
2. **不理解宏的含义:** 可能会错误地使用宏来设置不正确的参数，导致驱动程序行为异常或崩溃。
3. **平台兼容性问题:**  依赖于特定宏的存在或值，而没有考虑不同Android设备或不同GPU驱动版本之间的差异，可能导致应用程序在某些设备上无法正常工作。例如，某个功能可能只在支持 `HSA_CAP_TRAP_DEBUG_SUPPORT` 的设备上可用。
4. **忽略 `#ifndef` 保护:** 虽然这个文件本身有 `#ifndef` 保护，但在其他头文件中如果没有正确处理，可能会导致重复定义错误。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **高层 Framework (Java/Kotlin):**  例如，一个使用机器学习功能的Android应用可能会调用 TensorFlow Lite 的 Java API。
2. **TensorFlow Lite JNI:** TensorFlow Lite 的 Java API 会通过 JNI (Java Native Interface) 调用其 Native (C++) 代码。
3. **TensorFlow Lite Native Code:**  TensorFlow Lite 的 C++ 代码中，为了利用GPU进行加速，可能会使用相关的库，这些库最终会与底层的 GPU 驱动进行交互。
4. **Android Hardware Abstraction Layer (HAL):**  一些硬件相关的操作会通过 HAL 进行抽象。例如，GPU相关的操作可能会通过 `android.hardware.graphics.composer` HAL 或 vendor-specific 的 HAL 实现。
5. **Vendor Specific Libraries/Drivers:**  HAL 的实现通常由硬件厂商提供，它们会调用底层的 GPU 驱动程序。
6. **Kernel Driver (KFD):**  最终，这些调用会到达 Linux 内核的 KFD 驱动。用户空间程序（例如 TensorFlow Lite 的 native 代码或 HAL 实现）会使用 `ioctl` 系统调用与 KFD 驱动进行通信，并使用 `kfd_sysfs.h` 中定义的常量作为参数。

**Frida Hook 示例调试步骤:**

假设我们想查看 Android 系统在查询 GPU 能力时如何使用 `HSA_CAP_HOT_PLUGGABLE` 这个常量。我们可以 Hook 与 KFD 驱动交互的 `ioctl` 系统调用。

**Frida Hook 脚本示例 (需要 root 权限):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["com.example.myapp"]) # 替换为你要调试的应用的包名
    session = device.attach(pid)
    script = session.create_script("""
        var constants = {
            "HSA_CAP_HOT_PLUGGABLE": 0x00000001
            // ... 其他你感兴趣的常量
        };

        Interceptor.attach(Module.findExportByName(null, "ioctl"), {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                var request = args[1].toInt32();
                var argp = args[2];

                // 检查是否是与 KFD 相关的 ioctl 调用 (需要一些知识来判断具体的 ioctl 命令)
                // 这里只是一个示例，具体的判断需要根据实际情况
                if (request == 0x40044b01) { // 假设 0x40044b01 是一个与 KFD 交互的 ioctl 命令
                    send({
                        type: "ioctl",
                        fd: fd,
                        request: request,
                        argp: argp.toString()
                    });

                    // 如果已知 argp 指向的结构体内容，可以进一步解析
                    // 例如，如果它是一个指向查询 GPU 能力的结构体，可以读取并打印相关字段
                    // var capabilitiesPtr = Memory.readU32(argp);
                    // if (capabilitiesPtr.and(constants.HSA_CAP_HOT_PLUGGABLE)) {
                    //     send("HSA_CAP_HOT_PLUGGABLE is being checked!");
                    // }
                }
            },
            onLeave: function(retval) {
                // 可以查看 ioctl 的返回值
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except Exception as e:
    print(e)
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **找到目标应用:** 替换脚本中的 `"com.example.myapp"` 为你要监控的应用的包名。
3. **确定 KFD 相关的 `ioctl` 命令:**  这需要一定的逆向工程知识，或者查阅相关的内核文档。你需要找到与查询或设置 GPU 能力相关的 `ioctl` 命令的编号。
4. **运行 Frida 脚本:**  将脚本保存为 Python 文件（例如 `kfd_hook.py`），然后在 PC 上运行 `frida -UF kfd_hook.py`。
5. **操作目标应用:**  启动或操作你想要监控的应用，触发其与 GPU 交互的流程。
6. **查看 Frida 输出:** Frida 会拦截 `ioctl` 调用，并在控制台上打印相关信息。你可以根据输出判断是否涉及到查询 `HSA_CAP_HOT_PLUGGABLE`。

**更精细的 Hook:**

如果已知 `ioctl` 的参数结构，可以在 Frida 脚本中读取参数指向的内存，更精确地判断是否正在使用特定的宏常量。例如，如果 `argp` 指向一个包含 capability 字段的结构体，你可以读取该字段的值，并与 `HSA_CAP_HOT_PLUGGABLE` 进行比较。

请注意，Hook 底层的系统调用需要 root 权限，并且需要一定的逆向工程知识来确定相关的系统调用和参数。这个示例提供了一个基本的框架，具体的实现可能需要根据实际情况进行调整。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/kfd_sysfs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef KFD_SYSFS_H_INCLUDED
#define KFD_SYSFS_H_INCLUDED
#define HSA_CAP_HOT_PLUGGABLE 0x00000001
#define HSA_CAP_ATS_PRESENT 0x00000002
#define HSA_CAP_SHARED_WITH_GRAPHICS 0x00000004
#define HSA_CAP_QUEUE_SIZE_POW2 0x00000008
#define HSA_CAP_QUEUE_SIZE_32BIT 0x00000010
#define HSA_CAP_QUEUE_IDLE_EVENT 0x00000020
#define HSA_CAP_VA_LIMIT 0x00000040
#define HSA_CAP_WATCH_POINTS_SUPPORTED 0x00000080
#define HSA_CAP_WATCH_POINTS_TOTALBITS_MASK 0x00000f00
#define HSA_CAP_WATCH_POINTS_TOTALBITS_SHIFT 8
#define HSA_CAP_DOORBELL_TYPE_TOTALBITS_MASK 0x00003000
#define HSA_CAP_DOORBELL_TYPE_TOTALBITS_SHIFT 12
#define HSA_CAP_DOORBELL_TYPE_PRE_1_0 0x0
#define HSA_CAP_DOORBELL_TYPE_1_0 0x1
#define HSA_CAP_DOORBELL_TYPE_2_0 0x2
#define HSA_CAP_AQL_QUEUE_DOUBLE_MAP 0x00004000
#define HSA_CAP_TRAP_DEBUG_SUPPORT 0x00008000
#define HSA_CAP_TRAP_DEBUG_WAVE_LAUNCH_TRAP_OVERRIDE_SUPPORTED 0x00010000
#define HSA_CAP_TRAP_DEBUG_WAVE_LAUNCH_MODE_SUPPORTED 0x00020000
#define HSA_CAP_TRAP_DEBUG_PRECISE_MEMORY_OPERATIONS_SUPPORTED 0x00040000
#define HSA_CAP_RESERVED_WAS_SRAM_EDCSUPPORTED 0x00080000
#define HSA_CAP_MEM_EDCSUPPORTED 0x00100000
#define HSA_CAP_RASEVENTNOTIFY 0x00200000
#define HSA_CAP_ASIC_REVISION_MASK 0x03c00000
#define HSA_CAP_ASIC_REVISION_SHIFT 22
#define HSA_CAP_SRAM_EDCSUPPORTED 0x04000000
#define HSA_CAP_SVMAPI_SUPPORTED 0x08000000
#define HSA_CAP_FLAGS_COHERENTHOSTACCESS 0x10000000
#define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED 0x20000000
#define HSA_CAP_TRAP_DEBUG_PRECISE_ALU_OPERATIONS_SUPPORTED 0x40000000
#define HSA_CAP_RESERVED 0x800f8000
#define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_MASK 0x0000000f
#define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_SHIFT 0
#define HSA_DBG_WATCH_ADDR_MASK_HI_BIT_MASK 0x000003f0
#define HSA_DBG_WATCH_ADDR_MASK_HI_BIT_SHIFT 4
#define HSA_DBG_DISPATCH_INFO_ALWAYS_VALID 0x00000400
#define HSA_DBG_WATCHPOINTS_EXCLUSIVE 0x00000800
#define HSA_DBG_RESERVED 0xfffffffffffff000ull
#define HSA_MEM_HEAP_TYPE_SYSTEM 0
#define HSA_MEM_HEAP_TYPE_FB_PUBLIC 1
#define HSA_MEM_HEAP_TYPE_FB_PRIVATE 2
#define HSA_MEM_HEAP_TYPE_GPU_GDS 3
#define HSA_MEM_HEAP_TYPE_GPU_LDS 4
#define HSA_MEM_HEAP_TYPE_GPU_SCRATCH 5
#define HSA_MEM_FLAGS_HOT_PLUGGABLE 0x00000001
#define HSA_MEM_FLAGS_NON_VOLATILE 0x00000002
#define HSA_MEM_FLAGS_RESERVED 0xfffffffc
#define HSA_CACHE_TYPE_DATA 0x00000001
#define HSA_CACHE_TYPE_INSTRUCTION 0x00000002
#define HSA_CACHE_TYPE_CPU 0x00000004
#define HSA_CACHE_TYPE_HSACU 0x00000008
#define HSA_CACHE_TYPE_RESERVED 0xfffffff0
#define HSA_IOLINK_TYPE_UNDEFINED 0
#define HSA_IOLINK_TYPE_HYPERTRANSPORT 1
#define HSA_IOLINK_TYPE_PCIEXPRESS 2
#define HSA_IOLINK_TYPE_AMBA 3
#define HSA_IOLINK_TYPE_MIPI 4
#define HSA_IOLINK_TYPE_QPI_1_1 5
#define HSA_IOLINK_TYPE_RESERVED1 6
#define HSA_IOLINK_TYPE_RESERVED2 7
#define HSA_IOLINK_TYPE_RAPID_IO 8
#define HSA_IOLINK_TYPE_INFINIBAND 9
#define HSA_IOLINK_TYPE_RESERVED3 10
#define HSA_IOLINK_TYPE_XGMI 11
#define HSA_IOLINK_TYPE_XGOP 12
#define HSA_IOLINK_TYPE_GZ 13
#define HSA_IOLINK_TYPE_ETHERNET_RDMA 14
#define HSA_IOLINK_TYPE_RDMA_OTHER 15
#define HSA_IOLINK_TYPE_OTHER 16
#define HSA_IOLINK_FLAGS_ENABLED (1 << 0)
#define HSA_IOLINK_FLAGS_NON_COHERENT (1 << 1)
#define HSA_IOLINK_FLAGS_NO_ATOMICS_32_BIT (1 << 2)
#define HSA_IOLINK_FLAGS_NO_ATOMICS_64_BIT (1 << 3)
#define HSA_IOLINK_FLAGS_NO_PEER_TO_PEER_DMA (1 << 4)
#define HSA_IOLINK_FLAGS_RESERVED 0xffffffe0
#endif

"""

```