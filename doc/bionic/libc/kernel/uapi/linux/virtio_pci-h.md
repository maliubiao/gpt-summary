Response:
Let's break down the thought process for analyzing the provided `virtio_pci.h` header file and answering the complex prompt.

**1. Understanding the Context:**

The first step is to recognize the file's origin: `bionic/libc/kernel/uapi/linux/virtio_pci.handroid bionic`. This tells us:

* **bionic:** This is Android's core C library. The file is part of the kernel headers used by bionic.
* **libc/kernel/uapi/linux:** This indicates these are user-space API definitions directly mirroring Linux kernel structures. `uapi` signifies user-space API.
* **virtio_pci.h:** This clearly relates to the VirtIO PCI specification, a standard for virtualized hardware devices.
* **handroid bionic:**  This likely signifies Android-specific modifications or inclusion of these headers within the bionic build.

**2. Identifying the Core Functionality:**

The file defines structures, constants, and macros related to VirtIO PCI device configuration and communication. The keywords "VIRTIO_PCI" are prominent and recurring, immediately suggesting its primary purpose. Key areas to focus on:

* **Register Offsets:**  Definitions like `VIRTIO_PCI_HOST_FEATURES`, `VIRTIO_PCI_GUEST_FEATURES`, `VIRTIO_PCI_QUEUE_PFN`, etc., point to how software interacts with the VirtIO PCI device's registers.
* **Capabilities (`virtio_pci_cap`):**  The structure and related constants (e.g., `VIRTIO_PCI_CAP_COMMON_CFG`) define a mechanism for discovering and accessing different configuration areas of the device.
* **Common Configuration (`virtio_pci_common_cfg`):** This structure details the fields for setting up queues, features, and interrupt handling.
* **MSI/MSIX:** The presence of `VIRTIO_MSI_CONFIG_VECTOR` and mentions of MSIX indicate support for Message Signaled Interrupts.
* **Admin Commands (`virtio_admin_cmd_*`):** These structures suggest a more advanced control interface for managing the VirtIO device, particularly in modern implementations.

**3. Relating to Android:**

The key here is to connect the dots between virtualized hardware and Android's use of virtualization. The most obvious link is the Android Emulator and potentially hardware virtualization features used for improved performance or security. Think about:

* **Emulated Devices:**  The emulator needs to simulate hardware like network cards, block devices, etc. VirtIO is a common choice for these emulated devices.
* **Kernel Drivers:** Android's kernel will have drivers that interact with VirtIO devices. This header provides the necessary definitions for those drivers.
* **User-space Interaction:** While the header itself is kernel-level, user-space processes might indirectly interact with VirtIO devices through higher-level APIs (e.g., network sockets, file system operations) that rely on kernel drivers using these structures.

**4. Addressing Specific Prompt Points:**

* **List of Functions:** Since this is a header file, it *defines* structures and constants, not functions in the traditional sense of executable code. The "functions" are conceptual register accesses and configuration steps defined by the header.
* **libc Function Implementation:**  Header files don't *implement* libc functions. They provide the *definitions* that libc functions (or kernel drivers) use. Therefore, the answer needs to clarify this distinction.
* **Dynamic Linker:**  This header itself doesn't directly involve the dynamic linker. However, if a shared library were interacting with a VirtIO device, it would be loaded by the dynamic linker. The answer should explain this indirect relationship and provide a typical `.so` layout and linking process.
* **Logical Reasoning (Assumptions):** For example, when discussing MSI/MSIX, we assume the device supports it. When discussing queue setup, we assume the guest OS is configuring the device.
* **Common Usage Errors:**  These would relate to misconfiguring the VirtIO device, like incorrect register values, invalid memory addresses for queues, or not handling interrupts properly.
* **Android Framework/NDK Path:** This requires tracing how a user-space action (e.g., network request) might eventually lead to the kernel interacting with the VirtIO device. This involves a multi-layered approach, starting from the framework, down to native code (NDK), system calls, and finally, kernel drivers.
* **Frida Hook Example:** The example needs to target relevant points of interaction, like writing to specific PCI configuration registers.

**5. Structuring the Answer:**

A logical flow is essential for a comprehensive answer. Consider these sections:

* **Introduction:** Briefly explain what the file is and its purpose.
* **Functionality:** List the key aspects defined in the header.
* **Relationship to Android:** Provide concrete examples.
* **libc Functions:** Explain the role of the header vs. actual function implementation.
* **Dynamic Linker:** Detail the indirect connection and provide an example.
* **Logical Reasoning:** Present scenarios with assumptions, inputs, and outputs.
* **Common Errors:** Give practical examples of mistakes.
* **Android Framework/NDK Path:** Describe the step-by-step process.
* **Frida Hook Example:** Provide a working Frida script.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly defines some low-level I/O functions.
* **Correction:** Realized it's a header file, so it *declares* structures and constants used by functions elsewhere (in the kernel or libc).
* **Initial thought:** Focus heavily on libc functions.
* **Correction:**  Recognized the primary domain is kernel-level interaction with hardware. libc's involvement is indirect.
* **Considering the prompt's complexity:** Ensured each point in the prompt is addressed with sufficient detail and relevant examples. Used headings and bullet points for clarity.

By following these steps, including identifying the core functionality, connecting it to Android, and systematically addressing each part of the prompt, you can construct a detailed and accurate answer like the example provided in the initial prompt.好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/virtio_pci.h` 这个头文件。

**功能列举:**

这个头文件定义了 Linux 内核中用于与 VirtIO PCI 设备交互的结构体、常量和宏。它的主要功能是：

1. **定义 VirtIO PCI 设备的寄存器布局:**  定义了访问 VirtIO PCI 设备配置空间的各个寄存器的偏移地址，例如：
   - `VIRTIO_PCI_HOST_FEATURES`: 主机支持的特性寄存器
   - `VIRTIO_PCI_GUEST_FEATURES`: 客户机请求的特性寄存器
   - `VIRTIO_PCI_QUEUE_PFN`: 虚拟队列页帧号寄存器
   - `VIRTIO_PCI_QUEUE_NUM`: 虚拟队列大小寄存器
   - `VIRTIO_PCI_STATUS`: 设备状态寄存器
   - `VIRTIO_PCI_ISR`: 中断状态寄存器

2. **定义 VirtIO PCI Capability 结构:**  定义了用于协商和发现 VirtIO PCI 设备特性的 Capability 结构 (`virtio_pci_cap`) 及其相关常量，例如：
   - `VIRTIO_PCI_CAP_COMMON_CFG`: 通用配置 Capability
   - `VIRTIO_PCI_CAP_NOTIFY_CFG`: 通知配置 Capability
   - `VIRTIO_PCI_CAP_ISR_CFG`: 中断状态配置 Capability
   - `VIRTIO_PCI_CAP_DEVICE_CFG`: 设备特定配置 Capability
   - `VIRTIO_PCI_CAP_PCI_CFG`: PCI 配置 Capability

3. **定义 VirtIO PCI 通用配置结构:** 定义了 `virtio_pci_common_cfg` 结构，包含了 VirtIO 设备通用的配置信息，例如：
   - 设备和客户机的特性位
   - MSI-X 配置
   - 队列数量
   - 设备状态
   - 队列选择、大小、MSI-X 向量和使能状态
   - 队列的描述符、可用环和已用环的物理地址

4. **定义现代 VirtIO PCI 配置结构:** 定义了 `virtio_pci_modern_common_cfg` 结构，扩展了通用的配置，添加了例如通知数据、队列重置等字段。

5. **定义 VirtIO Admin Command 结构:** 定义了用于管理 VirtIO 设备的管理命令相关的结构体，例如 `virtio_admin_cmd_hdr` (命令头), `virtio_admin_cmd_status` (命令状态) 等。这些命令用于执行更高级的操作，如查询设备能力、配置设备等。

**与 Android 功能的关系及举例说明:**

VirtIO PCI 是一个标准化的接口，用于在虚拟机中驱动虚拟硬件设备。Android 作为一个操作系统，在其虚拟化环境中（例如使用 Android Emulator 或运行在虚拟机内的 Android 系统），会使用 VirtIO PCI 来与虚拟化的硬件设备进行通信。

**举例说明：**

* **网络设备 (virtio_net):** Android 虚拟机中的网络功能通常由 `virtio_net` 驱动提供支持。该驱动会使用 `virtio_pci.h` 中定义的结构体和常量来配置和管理虚拟网卡，例如设置接收和发送队列的大小和地址。
* **块设备 (virtio_blk):**  虚拟机的存储功能可能由 `virtio_blk` 驱动实现。该驱动会使用 `virtio_pci.h` 中的定义来配置虚拟磁盘，进行数据读写操作。
* **控制台 (virtio_console):** 虚拟机的控制台输出可以使用 `virtio_console` 驱动，它同样依赖于 `virtio_pci.h` 定义的接口。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身 **并不包含任何 libc 函数的实现代码**。它只是定义了一些结构体和常量，这些定义会被 Linux 内核驱动程序使用。  libc (Android 的 C 库) 中的函数可能会间接地使用这些定义，例如通过系统调用与内核驱动程序交互。

**举例:**

假设 Android 应用需要进行网络通信。底层的步骤可能包括：

1. 应用调用 libc 中的 `socket()`, `bind()`, `connect()`, `send()`, `recv()` 等函数。
2. 这些 libc 函数会进行一些用户空间的处理，然后通过系统调用（例如 `sendto`, `recvfrom`）将请求传递给 Linux 内核。
3. Linux 内核的网络协议栈会处理这些请求。如果目标网络接口是一个 VirtIO 设备，内核中的 `virtio_net` 驱动程序会使用 `virtio_pci.h` 中定义的结构体来与虚拟网卡进行交互，例如将数据包放入发送队列，或者从接收队列中取出数据包。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身也 **不直接涉及 dynamic linker 的功能**。Dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的地址空间，并解析库之间的依赖关系。

**间接关联：**

如果一个用户空间的共享库需要与 VirtIO 设备交互（但这通常不太常见，因为 VirtIO 设备交互主要在内核空间完成），那么 dynamic linker 会负责加载这个库。

**SO 布局样本 (假设一个 Hypothetical 的用户空间库 `libvirtio_user.so`):**

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x...
  Start of program headers:          ... (bytes into file)
  Number of program headers:         ...
  Start of section headers:          ... (bytes into file)
  Number of section headers:         ...
  Section header string table index: ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags  Align
  LOAD           0x0000000000000000 0x0000007ffffff000 0x0000007ffffff000 0x0000000000001000 0x0000000000001000 R E    0x1000
  LOAD           0x0000000000001000 0x0000008000000000 0x0000008000000000 0x0000000000000100 0x0000000000000200 RW     0x1000
  DYNAMIC        ...
  GNU_RELRO      ...

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         0000007ffffff000  00000000
       0000000000000800  0000000000000000  AX       0     0     16
  [ 2] .data             PROGBITS         0000008000000000  00001000
       0000000000000080  0000000000000000  WA       0     0     8
  [ 3] .bss              NOBITS           0000008000000080  00001080
       0000000000000080  0000000000000000  WA       0     0     8
  [ 4] .symtab           SYMTAB           ...
  [ 5] .strtab           STRTAB           ...
  [ 6] .rel.dyn          REL              ...
  [ 7] .rela.dyn         RELA             ...
  ...
```

**链接处理过程 (假设 `libvirtio_user.so` 依赖于 `libc.so`)：**

1. **加载:** 当一个进程需要使用 `libvirtio_user.so` 时，dynamic linker 会首先加载这个 `.so` 文件到进程的地址空间。这涉及到读取 ELF header 和 program headers，并根据这些信息将代码段、数据段等映射到内存中。
2. **依赖解析:** Dynamic linker 会检查 `libvirtio_user.so` 的依赖关系，例如它可能依赖于 `libc.so`。
3. **符号解析 (Symbol Resolution):**  `libvirtio_user.so` 中可能会调用 `libc.so` 中定义的函数。Dynamic linker 会找到这些未定义的符号，并在 `libc.so` 的符号表（`.symtab`）中查找对应的符号定义。
4. **重定位 (Relocation):** 一旦找到符号定义，dynamic linker 就需要更新 `libvirtio_user.so` 中对这些符号的引用，将它们指向 `libc.so` 中实际的函数地址。这个过程涉及到处理 `.rel.dyn` 和 `.rela.dyn` section 中的重定位条目。

**由于 `virtio_pci.h` 主要用于内核空间，用户空间库直接操作 VirtIO PCI 设备的情况非常少见。更常见的情况是用户空间通过系统调用与内核驱动程序交互，而内核驱动程序会使用这个头文件中的定义。**

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个内核驱动程序正在配置一个 VirtIO 设备的队列。

**假设输入:**

* `dev`: 指向 VirtIO PCI 设备结构体的指针。
* `queue_index`: 要配置的队列索引 (例如 0)。
* `queue_size`: 队列的大小 (例如 256 个元素)。
* `pfn`: 队列描述符表的物理页帧号 (例如 0x1000)。

**逻辑推理:**

驱动程序需要按照 `virtio_pci.h` 中定义的寄存器偏移来写入配置信息。

1. **选择队列:** 写入 `VIRTIO_PCI_QUEUE_SEL` 寄存器，值为 `queue_index` (0)。
2. **设置队列大小:** 写入 `VIRTIO_PCI_QUEUE_NUM` 寄存器，值为 `queue_size` (256)。
3. **设置队列的页帧号:** 写入 `VIRTIO_PCI_QUEUE_PFN` 寄存器，值为 `pfn` (0x1000)。
4. **使能队列:** 写入 `VIRTIO_PCI_QUEUE_ENABLE` 寄存器，设置为 1。

**假设输出:**

通过读取 VirtIO 设备的配置空间，相应的寄存器值会被更新：

* `VIRTIO_PCI_QUEUE_SEL` 的值为 0。
* `VIRTIO_PCI_QUEUE_NUM` 的值为 256。
* `VIRTIO_PCI_QUEUE_PFN` 的值为 0x1000。
* `VIRTIO_PCI_QUEUE_ENABLE` 的值为 1。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的寄存器偏移:**  程序员可能错误地使用了 `virtio_pci.h` 中定义的偏移量，导致写入到错误的寄存器，从而导致设备配置失败或行为异常。
   ```c
   // 错误地写入了状态寄存器，而不是队列大小寄存器
   writew(queue_size, pci_base + VIRTIO_PCI_STATUS); 
   ```

2. **未使能 MSI-X 时的 MSI-X 配置:**  如果在设备没有正确使能 MSI-X 的情况下，就尝试配置 MSI-X 相关的向量，可能会导致不可预测的结果。

3. **队列大小不为 2 的幂:** VirtIO 规范通常要求队列的大小是 2 的幂次方。如果设置了不符合要求的队列大小，设备可能会拒绝配置。
   ```c
   // 队列大小不是 2 的幂
   writew(255, pci_base + VIRTIO_PCI_QUEUE_NUM);
   ```

4. **内存屏障缺失:** 在多核系统中，当驱动程序修改了用于 VirtIO 队列的共享内存时，如果没有使用适当的内存屏障指令，可能会导致缓存一致性问题，从而导致数据错误或死锁。

5. **竞争条件:**  在多个 CPU 或进程同时访问和修改 VirtIO 设备配置的情况下，如果没有适当的同步机制（例如互斥锁），可能会导致数据竞争和配置错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

用户空间的 Android 应用程序通常不会直接访问 `virtio_pci.h` 中定义的底层硬件接口。它们会通过更高层次的框架和库进行交互。

**路径示例：网络请求**

1. **Android Framework (Java/Kotlin):** 应用程序使用 `java.net.Socket` 或 `HttpURLConnection` 等类发起网络请求。
2. **Android NDK (C/C++):**  如果应用程序使用了 native 代码，它可能会通过 NDK 提供的接口（例如 POSIX sockets）进行网络操作。
3. **System Calls:** 无论是 Framework 还是 NDK，最终的网络操作都会通过系统调用 (例如 `socket()`, `connect()`, `sendto()`, `recvfrom()`) 进入 Linux 内核。
4. **Linux Kernel Networking Stack:** 内核的网络协议栈会处理这些系统调用。如果目标网络接口是一个虚拟网卡 (virtio_net)，内核会调用相应的 `virtio_net` 驱动程序。
5. **VirtIO Net Driver:** `virtio_net` 驱动程序会使用 `virtio_pci.h` 中定义的结构体和常量，通过读写 PCI 配置空间或 MMIO 区域来与虚拟网卡硬件进行通信，例如设置队列、发送和接收数据包。

**Frida Hook 示例：**

我们可以使用 Frida 来 hook 内核中 `virtio_pci` 驱动程序的函数，以观察其如何使用这些定义。以下是一个假设的例子，hook 了 `virtio_pci` 驱动中设置队列大小的函数（函数名可能因内核版本而异）：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'error':
        print(f"[-] Error: {message['stack']}")
    elif message['type'] == 'send':
        print(f"[->] {message['payload']}")
    else:
        print(f"[<-] {message['payload']}")

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.android.emulator.armeabi-v7a"],  # 替换为你的目标进程
                       stdio='pipe')
    session = device.attach(pid)
    device.resume(pid)
except frida.TimedOutError:
    print("[-] Timed out trying to find USB device.")
    sys.exit(1)
except frida.RPCError as e:
    print(f"[-] RPC Error: {e}")
    sys.exit(1)

script_code = """
console.log("Script loaded");

// 假设的内核函数名，需要根据实际情况修改
const target_function = Module.findExportByName(null, "virtio_pci_set_queue_size");

if (target_function) {
    Interceptor.attach(target_function, {
        onEnter: function(args) {
            console.log("[+] Called virtio_pci_set_queue_size");
            // 假设第一个参数是指向 virtio_pci_dev 结构体的指针
            const dev = args[0];
            // 假设第二个参数是队列索引
            const queue_index = args[1].toInt32();
            // 假设第三个参数是要设置的队列大小
            const queue_size = args[2].toInt32();

            console.log("    Device:", dev);
            console.log("    Queue Index:", queue_index);
            console.log("    Queue Size:", queue_size);

            // 你可以进一步读取 dev 指向的内存，查看相关寄存器的值
            // 例如，读取 VIRTIO_PCI_QUEUE_SEL 的值
            // const queue_sel_offset = 14; // 根据 virtio_pci.h
            // const queue_sel_value = dev.readU16(queue_sel_offset);
            // console.log("    Current Queue Sel:", queue_sel_value);
        },
        onLeave: function(retval) {
            console.log("[+] virtio_pci_set_queue_size returned:", retval);
        }
    });
} else {
    console.log("[-] Function virtio_pci_set_queue_size not found.");
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **目标进程:** 需要将 `com.android.emulator.armeabi-v7a` 替换为你想要监控的进程，通常是在 Android Emulator 中运行的进程。
2. **查找内核函数:**  `Module.findExportByName(null, "virtio_pci_set_queue_size")` 尝试在所有已加载的模块中查找名为 `virtio_pci_set_queue_size` 的导出函数。你需要根据实际的内核符号来调整函数名。这可能需要一些内核调试的知识。
3. **Hook 函数:** `Interceptor.attach` 用于 hook 目标函数。`onEnter` 回调函数会在目标函数被调用时执行，你可以在这里打印参数的值，甚至读取内存。
4. **读取内存:**  可以尝试读取 `dev` 指针指向的内存，来查看 VirtIO PCI 设备的寄存器值。你需要根据 `virtio_pci.h` 中的定义计算出正确的偏移量。

**重要提示:**

* **内核调试:**  Hook 内核函数需要 root 权限，并且需要对内核结构和符号有一定的了解。
* **函数名:**  内核函数的名称可能因内核版本和驱动程序实现而异。你需要使用工具（例如 `adb shell cat /proc/kallsyms`）来找到确切的函数名。
* **安全性:**  在生产环境中 hook 内核函数需要谨慎，因为它可能会导致系统不稳定。

希望这个详细的解答能够帮助你理解 `bionic/libc/kernel/uapi/linux/virtio_pci.h` 的作用以及它在 Android 系统中的位置。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_pci.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_VIRTIO_PCI_H
#define _LINUX_VIRTIO_PCI_H
#include <linux/types.h>
#ifndef VIRTIO_PCI_NO_LEGACY
#define VIRTIO_PCI_HOST_FEATURES 0
#define VIRTIO_PCI_GUEST_FEATURES 4
#define VIRTIO_PCI_QUEUE_PFN 8
#define VIRTIO_PCI_QUEUE_NUM 12
#define VIRTIO_PCI_QUEUE_SEL 14
#define VIRTIO_PCI_QUEUE_NOTIFY 16
#define VIRTIO_PCI_STATUS 18
#define VIRTIO_PCI_ISR 19
#define VIRTIO_MSI_CONFIG_VECTOR 20
#define VIRTIO_MSI_QUEUE_VECTOR 22
#define VIRTIO_PCI_CONFIG_OFF(msix_enabled) ((msix_enabled) ? 24 : 20)
#define VIRTIO_PCI_CONFIG(dev) VIRTIO_PCI_CONFIG_OFF((dev)->msix_enabled)
#define VIRTIO_PCI_ABI_VERSION 0
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12
#define VIRTIO_PCI_VRING_ALIGN 4096
#endif
#define VIRTIO_PCI_ISR_CONFIG 0x2
#define VIRTIO_MSI_NO_VECTOR 0xffff
#ifndef VIRTIO_PCI_NO_MODERN
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG 3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_PCI_CAP_PCI_CFG 5
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8
struct virtio_pci_cap {
  __u8 cap_vndr;
  __u8 cap_next;
  __u8 cap_len;
  __u8 cfg_type;
  __u8 bar;
  __u8 id;
  __u8 padding[2];
  __le32 offset;
  __le32 length;
};
struct virtio_pci_cap64 {
  struct virtio_pci_cap cap;
  __le32 offset_hi;
  __le32 length_hi;
};
struct virtio_pci_notify_cap {
  struct virtio_pci_cap cap;
  __le32 notify_off_multiplier;
};
struct virtio_pci_common_cfg {
  __le32 device_feature_select;
  __le32 device_feature;
  __le32 guest_feature_select;
  __le32 guest_feature;
  __le16 msix_config;
  __le16 num_queues;
  __u8 device_status;
  __u8 config_generation;
  __le16 queue_select;
  __le16 queue_size;
  __le16 queue_msix_vector;
  __le16 queue_enable;
  __le16 queue_notify_off;
  __le32 queue_desc_lo;
  __le32 queue_desc_hi;
  __le32 queue_avail_lo;
  __le32 queue_avail_hi;
  __le32 queue_used_lo;
  __le32 queue_used_hi;
};
struct virtio_pci_modern_common_cfg {
  struct virtio_pci_common_cfg cfg;
  __le16 queue_notify_data;
  __le16 queue_reset;
  __le16 admin_queue_index;
  __le16 admin_queue_num;
};
struct virtio_pci_cfg_cap {
  struct virtio_pci_cap cap;
  __u8 pci_cfg_data[4];
};
#define VIRTIO_PCI_CAP_VNDR 0
#define VIRTIO_PCI_CAP_NEXT 1
#define VIRTIO_PCI_CAP_LEN 2
#define VIRTIO_PCI_CAP_CFG_TYPE 3
#define VIRTIO_PCI_CAP_BAR 4
#define VIRTIO_PCI_CAP_OFFSET 8
#define VIRTIO_PCI_CAP_LENGTH 12
#define VIRTIO_PCI_NOTIFY_CAP_MULT 16
#define VIRTIO_PCI_COMMON_DFSELECT 0
#define VIRTIO_PCI_COMMON_DF 4
#define VIRTIO_PCI_COMMON_GFSELECT 8
#define VIRTIO_PCI_COMMON_GF 12
#define VIRTIO_PCI_COMMON_MSIX 16
#define VIRTIO_PCI_COMMON_NUMQ 18
#define VIRTIO_PCI_COMMON_STATUS 20
#define VIRTIO_PCI_COMMON_CFGGENERATION 21
#define VIRTIO_PCI_COMMON_Q_SELECT 22
#define VIRTIO_PCI_COMMON_Q_SIZE 24
#define VIRTIO_PCI_COMMON_Q_MSIX 26
#define VIRTIO_PCI_COMMON_Q_ENABLE 28
#define VIRTIO_PCI_COMMON_Q_NOFF 30
#define VIRTIO_PCI_COMMON_Q_DESCLO 32
#define VIRTIO_PCI_COMMON_Q_DESCHI 36
#define VIRTIO_PCI_COMMON_Q_AVAILLO 40
#define VIRTIO_PCI_COMMON_Q_AVAILHI 44
#define VIRTIO_PCI_COMMON_Q_USEDLO 48
#define VIRTIO_PCI_COMMON_Q_USEDHI 52
#define VIRTIO_PCI_COMMON_Q_NDATA 56
#define VIRTIO_PCI_COMMON_Q_RESET 58
#define VIRTIO_PCI_COMMON_ADM_Q_IDX 60
#define VIRTIO_PCI_COMMON_ADM_Q_NUM 62
#endif
#define VIRTIO_ADMIN_STATUS_OK 0
#define VIRTIO_ADMIN_CMD_LIST_QUERY 0x0
#define VIRTIO_ADMIN_CMD_LIST_USE 0x1
#define VIRTIO_ADMIN_GROUP_TYPE_SRIOV 0x1
#define VIRTIO_ADMIN_CMD_LEGACY_COMMON_CFG_WRITE 0x2
#define VIRTIO_ADMIN_CMD_LEGACY_COMMON_CFG_READ 0x3
#define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_WRITE 0x4
#define VIRTIO_ADMIN_CMD_LEGACY_DEV_CFG_READ 0x5
#define VIRTIO_ADMIN_CMD_LEGACY_NOTIFY_INFO 0x6
struct virtio_admin_cmd_hdr {
  __le16 opcode;
  __le16 group_type;
  __u8 reserved1[12];
  __le64 group_member_id;
};
struct virtio_admin_cmd_status {
  __le16 status;
  __le16 status_qualifier;
  __u8 reserved2[4];
};
struct virtio_admin_cmd_legacy_wr_data {
  __u8 offset;
  __u8 reserved[7];
  __u8 registers[];
};
struct virtio_admin_cmd_legacy_rd_data {
  __u8 offset;
};
#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_END 0
#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_OWNER_DEV 0x1
#define VIRTIO_ADMIN_CMD_NOTIFY_INFO_FLAGS_OWNER_MEM 0x2
#define VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO 4
struct virtio_admin_cmd_notify_info_data {
  __u8 flags;
  __u8 bar;
  __u8 padding[6];
  __le64 offset;
};
struct virtio_admin_cmd_notify_info_result {
  struct virtio_admin_cmd_notify_info_data entries[VIRTIO_ADMIN_CMD_MAX_NOTIFY_INFO];
};
#endif
```