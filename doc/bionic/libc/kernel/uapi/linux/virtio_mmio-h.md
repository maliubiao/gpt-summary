Response:
Let's break down the thought process to answer the request about `virtio_mmio.h`.

1. **Understand the Core Request:** The primary goal is to understand the functionality of the provided header file and its relevance within the Android context, specifically regarding `bionic`. The request also touches upon low-level details like `libc`, dynamic linking, potential errors, and how to trace execution using Frida.

2. **Initial Analysis of the Header File:**  The first step is to recognize that this is a C header file (`.h`). Its content consists mainly of `#define` macros. These macros define constants. The names of the constants (e.g., `VIRTIO_MMIO_MAGIC_VALUE`, `VIRTIO_MMIO_VERSION`) strongly suggest they are related to memory-mapped I/O for a `virtio` device.

3. **Identifying the Role of `virtio`:** The name `virtio` is a key indicator. It refers to a standardized interface for virtual devices in a virtualized environment. This immediately suggests the context is related to virtual machines or emulators running Android.

4. **`MMIO` - Memory-Mapped I/O:**  The `MMIO` in the filename and constant names signifies Memory-Mapped Input/Output. This is a technique where hardware registers are accessed as if they were memory locations. This is crucial for communication between the host (hypervisor) and the guest (Android VM).

5. **Categorizing the Defined Constants:**  The constants can be grouped logically:
    * **Identification:** `MAGIC_VALUE`, `VERSION`, `DEVICE_ID`, `VENDOR_ID` -  Used to identify the specific virtio device.
    * **Feature Negotiation:** `DEVICE_FEATURES`, `DEVICE_FEATURES_SEL`, `DRIVER_FEATURES`, `DRIVER_FEATURES_SEL` -  Allow the guest OS to discover and agree upon supported features with the host.
    * **Queue Management:** `QUEUE_SEL`, `QUEUE_NUM_MAX`, `QUEUE_NUM`, `QUEUE_ALIGN`, `QUEUE_PFN`, `QUEUE_READY`, `QUEUE_NOTIFY`, `QUEUE_DESC_LOW/HIGH`, `QUEUE_AVAIL_LOW/HIGH`, `QUEUE_USED_LOW/HIGH` -  These are central to how `virtio` devices communicate using queues (ring buffers).
    * **Interrupts:** `INTERRUPT_STATUS`, `INTERRUPT_ACK` - Handle signaling between the device and the guest.
    * **Status:** `STATUS` -  Indicates the current state of the device.
    * **Shared Memory:** `SHM_SEL`, `SHM_LEN_LOW/HIGH`, `SHM_BASE_LOW/HIGH` - Allow sharing memory between the host and guest.
    * **Configuration:** `CONFIG_GENERATION`, `CONFIG` - Used to access device-specific configuration data.
    * **Interrupt Flags:** `INT_VRING`, `INT_CONFIG` - Flags indicating the source of an interrupt.

6. **Connecting to Android:**  The prompt explicitly mentions `bionic`. `bionic` is Android's C library, so this header file defines how Android interacts with `virtio` devices. A concrete example is the graphics subsystem. Android emulators (like the one used in Android Studio) often use `virtio-gpu` for accelerated graphics. The driver within the Android VM would use these constants to communicate with the host's graphics capabilities.

7. **`libc` Functions (or Lack Thereof):**  Crucially, this header file *doesn't define any `libc` functions*. It only defines constants. The *use* of these constants would happen *within* `libc` or other parts of the Android system. Therefore, explaining the implementation of `libc` functions *within this file* is impossible. The answer needs to clarify this distinction.

8. **Dynamic Linker and `.so` Layout:** Similarly, this header file itself doesn't directly involve the dynamic linker. However, the *drivers* that use these definitions *will* be linked. A hypothetical `.so` (shared object) containing a `virtio` driver would be loaded by the dynamic linker. The answer should provide a basic `.so` structure and explain the linking process in general terms (symbol resolution, relocation).

9. **Logical Inference (Not applicable here):** This file defines constants, not logic. There's no need for input/output scenarios in the traditional sense.

10. **Common Usage Errors:**  The most common errors would involve *incorrectly using the defined constants* when programming the driver. Examples include writing to read-only registers, using incorrect offsets, or misunderstanding the queue management protocol.

11. **Tracing with Frida:**  To trace how Android reaches this code, Frida can be used to hook functions that interact with `virtio` devices. The answer needs to provide a practical Frida script example, focusing on functions likely to use these constants (e.g., `open`, `mmap`, `ioctl` related to device access).

12. **Structuring the Answer:**  A clear and organized structure is essential. Using headings and subheadings makes the information easier to digest. The answer should directly address each part of the prompt.

13. **Refinement and Language:**  The answer needs to be in Chinese as requested. The language should be precise and avoid jargon where possible, or explain technical terms clearly.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file contains `libc` function implementations related to `virtio`.
* **Correction:** Upon closer inspection, it only defines constants. The `libc` implementations would be in separate source files that *use* these constants.
* **Initial thought:** Focus heavily on the technical details of `virtio` queues.
* **Refinement:** While important, the answer should also explain the broader context within Android and provide practical examples like the graphics driver.
* **Initial thought:** Provide a very complex Frida script.
* **Refinement:**  A simpler, focused Frida script targeting key functions is more effective for demonstration.

By following these steps, the comprehensive and accurate answer provided in the initial prompt can be constructed. The key is to break down the problem, understand the individual components, and connect them within the larger Android ecosystem.
这个头文件 `bionic/libc/kernel/uapi/linux/virtio_mmio.h` 定义了与 **virtio-mmio** 相关的常量。`virtio` 是一种标准化的虚拟化接口，允许虚拟机（guest）访问主机（host）上的虚拟设备。`mmio` 指的是内存映射 I/O（Memory-Mapped I/O），这是一种将设备寄存器映射到内存地址空间的技术，使得软件可以通过读写内存来控制硬件设备。

**功能列举:**

该头文件定义了访问和控制 `virtio-mmio` 设备的寄存器偏移地址。这些常量用于：

1. **设备识别和版本协商:**
   - `VIRTIO_MMIO_MAGIC_VALUE`:  用于识别这是一个 `virtio-mmio` 设备。
   - `VIRTIO_MMIO_VERSION`:  表示设备支持的 `virtio` 规范版本。
   - `VIRTIO_MMIO_DEVICE_ID`:  标识设备的类型（例如，网络设备、块设备等）。
   - `VIRTIO_MMIO_VENDOR_ID`:  标识设备的制造商。

2. **特性协商 (Feature Negotiation):**
   - `VIRTIO_MMIO_DEVICE_FEATURES`:  指示设备支持的特性。
   - `VIRTIO_MMIO_DEVICE_FEATURES_SEL`:  用于选择要读取的设备特性集的索引。
   - `VIRTIO_MMIO_DRIVER_FEATURES`:  用于设置驱动程序希望启用的特性。
   - `VIRTIO_MMIO_DRIVER_FEATURES_SEL`:  用于选择要设置的驱动程序特性集的索引。

3. **队列管理 (Queue Management):** `virtio` 使用队列（ring buffers）进行设备和驱动程序之间的通信。
   - `VIRTIO_MMIO_QUEUE_SEL`:  用于选择要操作的队列。
   - `VIRTIO_MMIO_QUEUE_NUM_MAX`:  指定队列允许的最大元素数量。
   - `VIRTIO_MMIO_QUEUE_NUM`:  用于设置队列的实际元素数量。
   - `VIRTIO_MMIO_QUEUE_ALIGN`:  指定队列的对齐要求（已废弃，但可能存在于旧版本中）。
   - `VIRTIO_MMIO_QUEUE_PFN`:  指定队列描述符表的物理页帧号（已废弃，但可能存在于旧版本中）。
   - `VIRTIO_MMIO_QUEUE_READY`:  指示队列是否已准备好使用。
   - `VIRTIO_MMIO_QUEUE_NOTIFY`:  用于通知设备有新的请求添加到队列中。
   - `VIRTIO_MMIO_QUEUE_DESC_LOW`, `VIRTIO_MMIO_QUEUE_DESC_HIGH`:  指定队列描述符表的物理地址。
   - `VIRTIO_MMIO_QUEUE_AVAIL_LOW`, `VIRTIO_MMIO_QUEUE_AVAIL_HIGH`:  指定可用环（available ring）的物理地址。
   - `VIRTIO_MMIO_QUEUE_USED_LOW`, `VIRTIO_MMIO_QUEUE_USED_HIGH`:  指定已用环（used ring）的物理地址。

4. **中断管理 (Interrupt Management):**
   - `VIRTIO_MMIO_INTERRUPT_STATUS`:  指示发生的中断类型。
   - `VIRTIO_MMIO_INTERRUPT_ACK`:  用于确认中断已处理。
   - `VIRTIO_MMIO_INT_VRING`:  表示队列有更新导致的中断。
   - `VIRTIO_MMIO_INT_CONFIG`:  表示设备配置发生变化导致的中断。

5. **设备状态 (Device Status):**
   - `VIRTIO_MMIO_STATUS`:  指示设备的当前状态，驱动程序可以通过写入此寄存器来控制设备状态。

6. **共享内存 (Shared Memory):**
   - `VIRTIO_MMIO_SHM_SEL`:  选择共享内存区域。
   - `VIRTIO_MMIO_SHM_LEN_LOW`, `VIRTIO_MMIO_SHM_LEN_HIGH`:  指定共享内存区域的长度。
   - `VIRTIO_MMIO_SHM_BASE_LOW`, `VIRTIO_MMIO_SHM_BASE_HIGH`:  指定共享内存区域的基地址。

7. **配置空间 (Configuration Space):**
   - `VIRTIO_MMIO_CONFIG_GENERATION`:  指示配置空间是否已更改。
   - `VIRTIO_MMIO_CONFIG`:  配置空间的起始偏移量，具体的配置取决于设备类型。

**与 Android 功能的关系及举例:**

`virtio` 是 Android 虚拟化架构中重要的组成部分，特别是在运行在虚拟机或模拟器中的 Android 系统中。Android Framework 或 NDK 通过内核驱动程序与虚拟硬件进行交互，而这些驱动程序就需要读取这些定义来与 `virtio-mmio` 设备通信。

**举例：图形加速 (Virtio-GPU)**

在 Android 模拟器 (例如 Android Studio 的模拟器) 中，为了提供图形加速，通常会使用 `virtio-gpu` 设备。

* **Android Framework:**  应用程序通过 Android Framework 的 OpenGL ES API 发出绘图指令。
* **NDK:** 一些性能敏感的图形应用可能会直接使用 NDK 的 OpenGL ES 或 Vulkan API。
* **图形驱动 (Guest Kernel):**  Android 虚拟机内部的图形驱动程序（例如 `virtio_gpu` 内核模块）会接收这些绘图指令。
* **访问 `virtio-mmio` 寄存器:**  图形驱动程序会使用 `virtio_mmio.h` 中定义的常量来读写 MMIO 区域，从而与宿主机（hypervisor）上的虚拟 GPU 设备进行通信。例如：
    * 使用 `VIRTIO_MMIO_QUEUE_SEL` 选择命令队列。
    * 使用 `VIRTIO_MMIO_QUEUE_DESC_LOW/HIGH` 等配置命令队列的描述符表。
    * 使用 `VIRTIO_MMIO_QUEUE_NOTIFY` 通知宿主机有新的图形命令需要处理。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身 **并没有定义任何 `libc` 函数**。它只是定义了一些常量。这些常量会被内核驱动程序（通常是内核模块）使用，而这些驱动程序可能会通过 `libc` 提供的系统调用接口与用户空间程序交互。

例如，用户空间的程序可能会使用 `open()` 系统调用打开一个表示 `virtio` 设备的设备文件（例如 `/dev/virtio-ports/vport0p1`）。内核中处理 `open()` 调用的代码可能会涉及到读取 `virtio_mmio.h` 中定义的常量，以初始化和管理该设备。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

这个头文件本身并不直接涉及 dynamic linker。但是，与 `virtio` 设备交互的内核驱动程序通常是作为内核模块加载的，这不涉及用户空间的动态链接。

如果用户空间程序需要直接与 `virtio` 设备交互（这种情况比较少见，通常通过内核驱动程序），那么可能会有一个用户空间的库（`.so` 文件）来封装与 `virtio` 设备的交互。

**so 布局样本:**

```
my_virtio_lib.so:
    .text          # 代码段
        my_virtio_init:
            # ... 使用 mmap 等系统调用访问 virtio MMIO 区域 ...
        my_virtio_send:
            # ... 向 virtio 队列发送数据 ...
        my_virtio_recv:
            # ... 从 virtio 队列接收数据 ...
    .rodata        # 只读数据段
        # ... 可能包含一些常量 ...
    .data          # 可读写数据段
        # ... 可能包含一些全局变量 ...
    .dynamic       # 动态链接信息
        # ... 依赖的 so 列表，符号表等 ...
    .symtab        # 符号表
        my_virtio_init
        my_virtio_send
        my_virtio_recv
        # ... 其他符号 ...
    .strtab        # 字符串表
        # ... 符号名称字符串 ...
```

**链接的处理过程:**

1. **编译:** 用户空间的程序在编译时，如果需要使用 `my_virtio_lib.so` 提供的功能，需要包含相应的头文件（可能不是 `virtio_mmio.h`，而是该库提供的接口头文件）。
2. **链接:** 链接器会将程序的可执行文件与所需的共享库链接起来。在动态链接中，这主要是记录依赖关系和符号信息。
3. **加载:** 当程序运行时，动态链接器（例如 Android 的 `linker64` 或 `linker`）会负责加载所有依赖的共享库到内存中。
4. **符号解析:** 动态链接器会解析程序中对共享库中符号的引用，找到对应的函数地址。例如，当程序调用 `my_virtio_init()` 时，动态链接器会找到 `my_virtio_lib.so` 中 `my_virtio_init` 函数的地址。
5. **重定位:** 动态链接器可能需要修改代码中的一些地址，以适应共享库被加载到内存中的实际位置。

**逻辑推理的假设输入与输出:**

由于 `virtio_mmio.h` 只是定义常量，本身不涉及逻辑推理。逻辑推理发生在驱动程序中，驱动程序会根据读取到的寄存器值和设备状态来做出相应的操作。

**假设输入与输出的例子（在驱动程序层面）：**

* **假设输入:** 驱动程序读取 `VIRTIO_MMIO_STATUS` 寄存器，得到值为 `0x1`（表示设备处于“driver_ok”状态）。
* **逻辑推理:** 驱动程序判断设备已准备好，可以开始初始化队列。
* **输出:** 驱动程序写入 `VIRTIO_MMIO_QUEUE_NUM` 寄存器，设置队列的大小。

* **假设输入:** 驱动程序读取 `VIRTIO_MMIO_INTERRUPT_STATUS` 寄存器，得到值为 `0x1` (即 `VIRTIO_MMIO_INT_VRING` 被设置)。
* **逻辑推理:** 驱动程序判断是队列有更新导致的中断。
* **输出:** 驱动程序检查已用环（used ring），处理设备完成的任务，并写入 `VIRTIO_MMIO_INTERRUPT_ACK` 寄存器来确认中断。

**涉及用户或者编程常见的使用错误:**

1. **错误的偏移地址:**  使用了错误的常量值来访问 MMIO 寄存器，导致读写到错误的内存位置，可能引起崩溃或设备行为异常。
2. **访问顺序错误:**  `virtio` 设备对寄存器的访问顺序可能有要求。例如，在设置队列之前可能需要先选择队列。不遵守正确的访问顺序可能导致设备初始化失败或工作不正常。
3. **特性协商错误:**  驱动程序和设备之间的特性协商失败，导致某些功能不可用或工作不正常。例如，驱动程序启用了设备不支持的特性。
4. **队列管理错误:**
   - 错误的队列大小或对齐方式。
   - 错误的描述符表、可用环或已用环的地址。
   - 未正确处理队列的环绕。
   - 在队列未准备好时尝试使用。
5. **中断处理错误:**  未正确处理中断，导致设备请求无法及时响应。
6. **并发访问问题:**  如果在多线程环境下访问 `virtio` 设备的寄存器，需要进行适当的同步，以避免竞争条件。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **应用层 (Android Framework/NDK):**
   - 应用程序通过 Android Framework 的 API (例如，访问网络、存储、图形等) 发出请求，或者通过 NDK 直接调用底层的库。
   - 例如，一个使用 OpenGL ES 进行渲染的应用会调用 `eglSwapBuffers()`。

2. **系统服务 (System Services):**
   - Framework 的 API 调用通常会传递给相应的系统服务，例如 `SurfaceFlinger` (负责屏幕合成) 或 `NetworkStack`。

3. **HAL (Hardware Abstraction Layer):**
   - 系统服务会与 HAL 层进行交互，HAL 层提供了一组标准的接口来访问硬件设备。
   - 例如，`SurfaceFlinger` 会调用 `gralloc` HAL 来分配和管理图形缓冲区。

4. **Binder IPC:**
   - Framework 和 System Services 之间，以及 System Services 和 HAL 之间通常使用 Binder IPC 进行通信。

5. **内核驱动程序 (Kernel Drivers):**
   - HAL 的实现最终会调用到内核驱动程序，例如 `virtio_net` (网络设备) 或 `virtio_blk` (块设备) 或 `virtio_gpu` (图形设备)。
   - 这些驱动程序会读取 `bionic/libc/kernel/uapi/linux/virtio_mmio.h` 中定义的常量。

6. **MMIO 访问:**
   - 内核驱动程序会使用 `ioremap()` 等内核函数将设备的 MMIO 区域映射到内核地址空间。
   - 然后，驱动程序会使用读取到的常量作为偏移地址，通过指针操作来访问设备的寄存器，例如：

   ```c
   #include <linux/io.h>
   #include <linux/virtio_mmio.h>

   struct virtio_mmio_config {
       void __iomem *base;
   };

   u32 read_status(struct virtio_mmio_config *cfg) {
       return ioread32(cfg->base + VIRTIO_MMIO_STATUS);
   }

   void write_queue_num(struct virtio_mmio_config *cfg, u32 num) {
       iowrite32(num, cfg->base + VIRTIO_MMIO_QUEUE_NUM);
   }
   ```

**Frida Hook 示例:**

以下是一个使用 Frida Hook 内核驱动程序访问 `virtio-mmio` 寄存器的示例。你需要找到相关的内核模块，并 Hook 其访问 MMIO 区域的函数。

```javascript
function hook_virtio_mmio_access() {
  // 假设你知道负责 virtio-mmio 访问的内核模块名称，例如 "virtio_mmio"
  const module_name = "virtio_mmio";
  const module = Process.getModuleByName(module_name);

  if (module) {
    // 假设你知道驱动程序中使用 ioread32 和 iowrite32 进行 MMIO 访问
    // 你可能需要通过反汇编驱动程序来找到具体的调用点

    // Hook ioread32
    const ioread32_ptr = Module.findExportByName(null, "ioread32");
    if (ioread32_ptr) {
      Interceptor.attach(ioread32_ptr, {
        onEnter: function (args) {
          const address = ptr(args[0]);
          console.log(`ioread32 from address: ${address}`);

          // 你可以进一步解析地址，判断是否在 virtio MMIO 区域内
          // 并根据偏移地址推断访问的寄存器
        },
        onLeave: function (retval) {
          console.log(`ioread32 returned: ${retval}`);
        },
      });
    } else {
      console.log("ioread32 symbol not found.");
    }

    // Hook iowrite32
    const iowrite32_ptr = Module.findExportByName(null, "iowrite32");
    if (iowrite32_ptr) {
      Interceptor.attach(iowrite32_ptr, {
        onEnter: function (args) {
          const value = args[0];
          const address = ptr(args[1]);
          console.log(`iowrite32 value: ${value}, to address: ${address}`);
        },
      });
    } else {
      console.log("iowrite32 symbol not found.");
    }
  } else {
    console.log(`Module ${module_name} not found.`);
  }
}

setImmediate(hook_virtio_mmio_access);
```

**使用 Frida 调试步骤：**

1. **找到目标进程:**  确定你想要调试的进程，例如一个使用了硬件加速的应用程序或者模拟器进程。
2. **连接 Frida:** 使用 Frida 连接到目标进程（如果是在模拟器中，需要连接到模拟器的内核）。
3. **加载 Hook 脚本:** 将上面的 JavaScript 代码保存到一个文件中（例如 `virtio_hook.js`），然后使用 Frida 加载并运行该脚本。
4. **执行操作:** 在目标应用程序中执行一些操作，例如滑动屏幕、播放视频等，这些操作可能会触发对 `virtio` 设备的访问。
5. **查看输出:**  Frida 会在控制台中打印出 `ioread32` 和 `iowrite32` 的调用信息，包括访问的地址和读写的值。通过分析这些信息，你可以了解驱动程序是如何与 `virtio-mmio` 设备进行交互的。

**注意:**

* Hook 内核函数需要 root 权限。
* 你需要了解目标内核模块的名称以及相关的 MMIO 访问函数。这可能需要一些内核调试和反汇编的知识。
* 在实际的 Android 系统中，`virtio` 设备的访问可能被更上层的抽象层封装，你需要找到正确的入口点进行 Hook。

这个 `virtio_mmio.h` 头文件虽然简单，却是理解 Android 虚拟化底层硬件交互的关键。通过它可以了解到 Android 如何与虚拟机环境中的虚拟硬件进行通信，从而实现各种功能。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_mmio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_VIRTIO_MMIO_H
#define _LINUX_VIRTIO_MMIO_H
#define VIRTIO_MMIO_MAGIC_VALUE 0x000
#define VIRTIO_MMIO_VERSION 0x004
#define VIRTIO_MMIO_DEVICE_ID 0x008
#define VIRTIO_MMIO_VENDOR_ID 0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024
#ifndef VIRTIO_MMIO_NO_LEGACY
#define VIRTIO_MMIO_GUEST_PAGE_SIZE 0x028
#endif
#define VIRTIO_MMIO_QUEUE_SEL 0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034
#define VIRTIO_MMIO_QUEUE_NUM 0x038
#ifndef VIRTIO_MMIO_NO_LEGACY
#define VIRTIO_MMIO_QUEUE_ALIGN 0x03c
#define VIRTIO_MMIO_QUEUE_PFN 0x040
#endif
#define VIRTIO_MMIO_QUEUE_READY 0x044
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064
#define VIRTIO_MMIO_STATUS 0x070
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW 0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH 0x094
#define VIRTIO_MMIO_QUEUE_USED_LOW 0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH 0x0a4
#define VIRTIO_MMIO_SHM_SEL 0x0ac
#define VIRTIO_MMIO_SHM_LEN_LOW 0x0b0
#define VIRTIO_MMIO_SHM_LEN_HIGH 0x0b4
#define VIRTIO_MMIO_SHM_BASE_LOW 0x0b8
#define VIRTIO_MMIO_SHM_BASE_HIGH 0x0bc
#define VIRTIO_MMIO_CONFIG_GENERATION 0x0fc
#define VIRTIO_MMIO_CONFIG 0x100
#define VIRTIO_MMIO_INT_VRING (1 << 0)
#define VIRTIO_MMIO_INT_CONFIG (1 << 1)
#endif

"""

```