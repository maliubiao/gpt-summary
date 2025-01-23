Response:
Let's break down the thought process for analyzing the provided C header file (`vfio.handroid`).

**1. Understanding the Context:**

The initial prompt highlights that this is a header file within the Android Bionic library, specifically related to the Linux kernel's VFIO (Virtual Function I/O) framework. This immediately tells us that the file defines interfaces for interacting with VFIO, a mechanism for secure device assignment to user-space processes (like VMs or containers).

**2. High-Level Overview and Initial Categorization:**

A quick scan reveals various definitions:

* **Macros:**  `VFIO_API_VERSION`, `VFIO_TYPE1_IOMMU`, `VFIO_GET_API_VERSION`, etc. These seem to be constants and potentially ioctl command definitions.
* **Structures:** `vfio_info_cap_header`, `vfio_group_status`, `vfio_device_info`, etc. These represent data structures used to exchange information with the kernel.
* **Enums:**  `VFIO_PCI_BAR0_REGION_INDEX`, `VFIO_DEVICE_STATE_ERROR`, etc. These define sets of named integer constants.

The presence of `_IO` macros strongly suggests that this file primarily defines the interface for making ioctl calls to the VFIO kernel module.

**3. Deeper Dive into Functionality (Iterative Analysis):**

Now, let's go through the file section by section, trying to understand the purpose of each definition:

* **API Version and IOMMU Types:**  `VFIO_API_VERSION` and `VFIO_*_IOMMU` constants likely define the supported API version and different IOMMU (Input/Output Memory Management Unit) types VFIO can work with. This hints at the core function of VFIO: managing access to hardware devices while ensuring memory isolation.

* **Capability Structures (`vfio_info_cap_header`):**  The `vfio_info_cap_header` structure, along with `cap_offset` fields in other structures, suggests a capability negotiation mechanism. This allows VFIO to be extended with new features without breaking backward compatibility.

* **Group Management (`vfio_group_status`, `VFIO_GROUP_*` ioctls):** These structures and ioctls deal with grouping devices for assignment. The flags like `VFIO_GROUP_FLAGS_VIABLE` and `VFIO_GROUP_FLAGS_CONTAINER_SET` indicate the state of a device group.

* **Device Management (`vfio_device_info`, `VFIO_DEVICE_*` ioctls):** This is a major part. It includes getting device information (flags indicating PCI, platform, etc.), accessing regions of device memory (`vfio_region_info`), and managing interrupts (`vfio_irq_info`, `vfio_irq_set`). The different `VFIO_DEVICE_FLAGS_*` constants tell us about the nature of the assigned device.

* **Region Information (`vfio_region_info` and related structures):** This section describes how to query and interact with memory regions of the assigned device. The flags indicate read/write/mmap permissions. The capability structures (`VFIO_REGION_INFO_CAP_*`) allow for specific region features like sparse mapping.

* **Interrupt Management (`vfio_irq_info`, `vfio_irq_set`):** This covers how to get information about available interrupts and how to configure them (e.g., associating them with eventfds for user-space notification).

* **Device Reset (`VFIO_DEVICE_RESET`):**  A fundamental operation for device management.

* **PCI Specific Information (`VFIO_PCI_*` enums, `vfio_pci_dependent_device`, `vfio_pci_hot_reset_*`):**  Since PCI devices are a common use case for VFIO, there's a dedicated section for PCI-specific details like BAR regions, interrupt types, and hot reset capabilities.

* **Graphics Specific Information (`vfio_device_gfx_*`):**  Handles graphics-related features like querying plane information and getting DMABUF handles.

* **IO EventFD (`vfio_device_ioeventfd`):**  Allows user-space to be notified when specific memory locations are accessed by the assigned device.

* **Device Features (`vfio_device_feature`):**  A generic mechanism to query and set device-specific features.

* **IOMMU Interaction (`vfio_iommu_type1_*`, `VFIO_IOMMU_*` ioctls):** This section focuses on the core IOMMU functionality: getting IOMMU information, mapping and unmapping DMA regions, and enabling/disabling the IOMMU.

* **Error Handling (`vfio_eeh_*`):**  Deals with error handling mechanisms related to PCI Express Advanced Error Reporting (EEH).

* **Migration (`VFIO_DEVICE_FEATURE_MIGRATION`, related structures):**  Supports live migration of assigned devices.

**4. Connecting to Android:**

At this stage, consider how these VFIO functionalities relate to Android. Key areas include:

* **Virtualization:** Android can host virtual machines or containers, and VFIO is crucial for providing these guests with direct access to hardware (e.g., GPUs for gaming or AI acceleration).
* **Security:** VFIO's IOMMU protection is essential for isolating guest VMs from the host and other guests.
* **Device Drivers (User-space):**  Instead of traditional kernel drivers, VFIO enables user-space drivers, giving more control to applications.

**5. Libc Functions and Dynamic Linker (If Applicable):**

This header file *itself* doesn't define libc functions or interact directly with the dynamic linker. It *describes* the interface for interacting with the kernel through ioctl. The *use* of these definitions in user-space code would involve standard libc functions like `open()`, `ioctl()`, `close()`, `mmap()`, etc. The dynamic linker comes into play when the application using VFIO is linked against libraries that interact with the VFIO interface.

**6. Logic Reasoning and Examples:**

Think about scenarios where these structures and ioctls would be used. For example, setting up a VFIO device involves a sequence of steps: opening the VFIO group, setting the container, getting the device FD, getting device info, mapping regions, setting up interrupts, etc. This helps in understanding the data flow and purpose of each structure.

**7. Common Errors:**

Consider common mistakes developers might make, such as incorrect ioctl numbers, wrong structure sizes, permission issues, or not handling errors properly.

**8. Android Framework/NDK and Frida Hooking:**

Trace how Android frameworks or NDK applications might use VFIO. This often involves opening specific device files (`/dev/vfio/vfio`), making ioctl calls, and potentially using `mmap()` for direct memory access. Consider where Frida hooks could be placed to observe these interactions (e.g., at the `ioctl()` system call level).

**9. Structuring the Response:**

Finally, organize the information logically, starting with a high-level overview, then diving into specifics for each functional area. Provide clear explanations, examples, and code snippets where appropriate. Use headings and bullet points to improve readability.

**Self-Correction/Refinement:**

During the process, review and refine your understanding. For example, initially, you might focus too much on individual structures. Realize that the *ioctl calls* are the primary actions, and the structures are just the data carriers for these calls. Also, ensure the connection to Android's use cases is clear and concrete. Don't just list the definitions; explain *why* they exist and *how* they are used.
这个文件 `vfio.handroid` 是 Android Bionic 库中定义 VFIO (Virtual Function I/O) 用户空间 API 的头文件。 VFIO 是 Linux 内核提供的一种机制，允许用户空间程序以安全的方式访问和控制硬件设备，通常用于虚拟机或容器技术中，将物理硬件（例如 PCI 设备）直接分配给虚拟机或容器使用。

**功能列举:**

这个头文件定义了以下功能：

1. **VFIO API 版本查询:** 定义了 `VFIO_API_VERSION` 常量和 `VFIO_GET_API_VERSION` ioctl 命令，用于查询 VFIO API 的版本。
2. **VFIO IOMMU 类型定义:**  定义了各种 IOMMU (Input/Output Memory Management Unit) 类型的常量，例如 `VFIO_TYPE1_IOMMU`、`VFIO_SPAPR_TCE_IOMMU` 等，用于指定使用的 IOMMU 类型。
3. **VFIO 扩展检查:** 定义了 `VFIO_CHECK_EXTENSION` ioctl 命令，用于检查 VFIO 是否支持特定的扩展功能。
4. **IOMMU 设置:** 定义了 `VFIO_SET_IOMMU` ioctl 命令，用于设置 VFIO 使用的 IOMMU 类型。
5. **设备组管理:**
    * `vfio_group_status` 结构体用于获取设备组的状态（例如，是否可用，是否已设置容器）。
    * `VFIO_GROUP_GET_STATUS` ioctl 命令用于获取设备组状态。
    * `VFIO_GROUP_SET_CONTAINER` 和 `VFIO_GROUP_UNSET_CONTAINER` ioctl 命令用于将设备组关联或取消关联到 VFIO 容器。
    * `VFIO_GROUP_GET_DEVICE_FD` ioctl 命令用于获取设备组中某个设备的 FD (文件描述符)。
6. **设备信息获取:**
    * `vfio_device_info` 结构体用于获取设备的详细信息（例如，设备标志、区域数量、中断数量）。
    * `VFIO_DEVICE_GET_INFO` ioctl 命令用于获取设备信息。
    * 定义了不同设备 API 字符串，例如 `VFIO_DEVICE_API_PCI_STRING`，用于标识设备类型。
    * 定义了设备信息能力相关的常量和结构体，例如 `VFIO_DEVICE_INFO_CAP_PCI_ATOMIC_COMP`，用于获取设备支持的特定能力。
7. **设备区域信息获取:**
    * `vfio_region_info` 结构体用于获取设备内存区域的信息（例如，大小、偏移、读写权限）。
    * `VFIO_DEVICE_GET_REGION_INFO` ioctl 命令用于获取设备区域信息。
    * 定义了区域信息能力相关的常量和结构体，例如 `VFIO_REGION_INFO_CAP_SPARSE_MMAP` 和 `vfio_region_sparse_mmap_area`，用于描述稀疏内存映射。
    * 定义了区域类型和子类型相关的常量，例如 `VFIO_REGION_TYPE_GFX` 和 `VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION`。
    * 定义了图形设备 EDID (Extended Display Identification Data) 相关的结构体 `vfio_region_gfx_edid`。
8. **设备中断信息获取和设置:**
    * `vfio_irq_info` 结构体用于获取设备中断的信息（例如，是否支持事件通知，是否可屏蔽）。
    * `VFIO_DEVICE_GET_IRQ_INFO` ioctl 命令用于获取设备中断信息。
    * `vfio_irq_set` 结构体用于设置设备中断的状态（例如，绑定事件 FD）。
    * `VFIO_DEVICE_SET_IRQS` ioctl 命令用于设置设备中断。
9. **设备重置:** 定义了 `VFIO_DEVICE_RESET` ioctl 命令，用于重置 VFIO 设备。
10. **PCI 设备特定操作:**
    * 定义了 PCI 设备的常用区域索引和中断索引，例如 `VFIO_PCI_BAR0_REGION_INDEX` 和 `VFIO_PCI_MSI_IRQ_INDEX`。
    * `vfio_pci_dependent_device` 结构体用于描述依赖的 PCI 设备。
    * `vfio_pci_hot_reset_info` 和 `vfio_pci_hot_reset` 结构体和 ioctl 命令用于获取和执行 PCI 热重置操作。
11. **图形设备特定操作:**
    * `vfio_device_gfx_plane_info` 结构体和 `VFIO_DEVICE_QUERY_GFX_PLANE` ioctl 命令用于查询图形设备的平面信息。
    * `VFIO_DEVICE_GET_GFX_DMABUF` ioctl 命令用于获取图形设备的 DMABUF (DMA buffer) 文件描述符。
12. **IO 事件通知:**
    * `vfio_device_ioeventfd` 结构体和 `VFIO_DEVICE_IOEVENTFD` ioctl 命令用于设置 IO 事件通知，当设备访问特定内存地址时通知用户空间。
13. **设备特性查询和设置:**
    * `vfio_device_feature` 结构体和 `VFIO_DEVICE_FEATURE` ioctl 命令用于查询和设置设备的特定特性。
14. **IOMMU 操作:**
    * `vfio_iommu_type1_info` 结构体和 `VFIO_IOMMU_GET_INFO` ioctl 命令用于获取 IOMMU 的信息。
    * `vfio_iommu_type1_dma_map` 结构体和 `VFIO_IOMMU_MAP_DMA` ioctl 命令用于映射设备 DMA (Direct Memory Access) 到用户空间。
    * `vfio_iommu_type1_dma_unmap` 结构体和 `VFIO_IOMMU_UNMAP_DMA` ioctl 命令用于取消映射设备 DMA。
    * `VFIO_IOMMU_ENABLE` 和 `VFIO_IOMMU_DISABLE` ioctl 命令用于启用和禁用 IOMMU。
    * `vfio_iommu_type1_dirty_bitmap` 结构体和 `VFIO_IOMMU_DIRTY_PAGES` ioctl 命令用于跟踪 DMA 页面的脏位，用于虚拟机迁移等场景。
15. **EEH (Enhanced Error Handling) 支持:**
    * `vfio_eeh_pe_err` 和 `vfio_eeh_pe_op` 结构体和 `VFIO_EEH_PE_OP` ioctl 命令用于处理 PCI 设备的 EEH 错误。
16. **设备迁移支持:**
    * 定义了与设备迁移相关的特性常量和结构体，例如 `VFIO_DEVICE_FEATURE_MIGRATION` 和 `vfio_device_feature_migration`，用于支持设备的实时迁移。
17. **低功耗状态管理:**
    * 定义了与低功耗状态相关的特性常量和结构体，例如 `VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY`。
18. **DMA 日志记录:**
    * 定义了与 DMA 日志记录相关的特性常量和结构体，用于跟踪设备的 DMA 活动。

**与 Android 功能的关系举例:**

VFIO 在 Android 中主要用于支持以下场景：

* **虚拟化 (Virtualization):**  Android 设备上运行虚拟机或容器时，VFIO 可以将物理硬件（如 GPU、网络适配器等）直接分配给虚拟机或容器使用，提高性能并提供更接近原生硬件的体验。例如，使用 KVM (Kernel-based Virtual Machine) 在 Android 上运行虚拟机，可以通过 VFIO 将 GPU 透传给虚拟机，让虚拟机可以利用 GPU 进行图形渲染或计算。
* **安全隔离 (Security Isolation):** VFIO 结合 IOMMU 可以确保分配给虚拟机或容器的硬件只能访问分配给它的内存区域，防止虚拟机或容器恶意访问宿主机或其他虚拟机的内存，提高系统安全性。
* **用户空间驱动 (Userspace Drivers):**  VFIO 允许将硬件设备的控制逻辑放在用户空间程序中，而不是传统的内核驱动。这为开发和调试驱动程序提供了更大的灵活性。

**libc 函数功能实现解释:**

这个头文件本身并没有定义 libc 函数的具体实现。它只是定义了与 VFIO 内核模块交互的接口（通过 ioctl 系统调用）。用户空间的程序需要使用标准 libc 函数，例如：

* **`open()`:**  用于打开 VFIO 相关的设备文件，例如 `/dev/vfio/vfio` (VFIO 框架设备) 或 `/dev/vfio/<group_id>` (特定的 VFIO 设备组)。
* **`ioctl()`:**  用于向打开的 VFIO 设备文件发送控制命令，这些命令对应于头文件中定义的 `VFIO_*` 宏。`ioctl()` 函数的实现位于 Bionic 库中，它会将用户空间的请求转换为内核能够理解的格式，并通过系统调用传递给内核。
* **`mmap()`:**  用于将设备内存区域映射到用户空间的地址空间，允许用户空间程序直接访问设备内存。这通常与 `VFIO_DEVICE_GET_REGION_INFO` 获取到的区域信息配合使用。
* **`close()`:**  用于关闭打开的 VFIO 设备文件。

**dynamic linker 功能说明 (如果涉及):**

这个头文件本身不直接涉及 dynamic linker 的功能。然而，如果一个 Android 应用或库使用了 VFIO，那么 dynamic linker 会在运行时加载必要的共享库，这些库可能包含与 VFIO 交互的代码。

**so 布局样本:**

假设一个名为 `libvfio_client.so` 的共享库封装了与 VFIO 交互的逻辑：

```
libvfio_client.so:
    .init          # 初始化代码段
    .plt           # 过程链接表 (Procedure Linkage Table)
    .text          # 代码段 (包含与 VFIO 交互的函数，例如封装了 ioctl 调用)
    .rodata        # 只读数据段
    .data          # 数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
    .symtab        # 符号表
    .strtab        # 字符串表
    ... 其他段 ...
```

**链接的处理过程:**

1. **编译时:**  当应用或库链接 `libvfio_client.so` 时，链接器会记录所需的符号（例如，`vfio_open_device`、`vfio_map_region` 等）。
2. **加载时:**  当 Android 系统启动应用或加载库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载共享库:**  将 `libvfio_client.so` 加载到内存中。
    * **符号解析 (Symbol Resolution):**  查找应用或库中使用的 `libvfio_client.so` 提供的符号在内存中的地址。这通常通过 `.plt` 和 `.got` (全局偏移量表, Global Offset Table) 完成。
    * **重定位 (Relocation):**  调整代码和数据中的地址引用，使其指向加载后的正确内存位置。
3. **运行时:**  当应用调用 `libvfio_client.so` 中的函数时，程序会跳转到 `.plt` 中的条目，该条目会通过 `.got` 中缓存的地址跳转到实际的函数代码。如果 `.got` 中没有缓存地址（第一次调用），则会触发 dynamic linker 解析符号并更新 `.got`。

**逻辑推理 (假设输入与输出):**

假设我们想要获取一个 VFIO 设备的 `vfio_device_info`:

**假设输入:**

* `vfio_fd`:  通过 `open("/dev/vfio/<device_group_id>")` 获取的 VFIO 设备组的文件描述符。
* `device_info`: 一个 `vfio_device_info` 结构体变量，用于存储结果。

**代码片段:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "vfio.handroid" // 包含 VFIO 头文件

int main() {
    int vfio_fd = open("/dev/vfio/10", O_RDWR); // 假设设备组 ID 为 10
    if (vfio_fd < 0) {
        perror("open /dev/vfio/10 failed");
        return 1;
    }

    struct vfio_device_info device_info;
    device_info.argsz = sizeof(device_info);

    if (ioctl(vfio_fd, VFIO_DEVICE_GET_INFO, &device_info) < 0) {
        perror("ioctl VFIO_DEVICE_GET_INFO failed");
        close(vfio_fd);
        return 1;
    }

    printf("Device flags: 0x%x\n", device_info.flags);
    printf("Number of regions: %u\n", device_info.num_regions);
    printf("Number of IRQs: %u\n", device_info.num_irqs);

    close(vfio_fd);
    return 0;
}
```

**预期输出:**

输出会包含设备的标志、区域数量和中断数量等信息，具体数值取决于实际的 VFIO 设备。例如：

```
Device flags: 0x2  // VFIO_DEVICE_FLAGS_PCI
Number of regions: 9
Number of IRQs: 5
```

**用户或编程常见的使用错误举例:**

1. **未检查 `ioctl` 返回值:**  `ioctl` 调用失败时会返回 -1，并设置 `errno`。如果程序没有检查返回值，可能会导致难以调试的错误。
2. **`argsz` 字段设置错误:**  很多 VFIO 结构体都有 `argsz` 字段，必须设置为结构体的大小。如果设置错误，`ioctl` 调用可能会失败或返回不正确的结果。
3. **权限问题:**  访问 VFIO 设备通常需要 root 权限或特定的用户组权限。如果权限不足，`open` 或 `ioctl` 调用会失败。
4. **操作顺序错误:**  VFIO 的操作通常有特定的顺序要求，例如必须先设置容器才能获取设备 FD。如果操作顺序错误，会导致 `ioctl` 调用失败。
5. **内存映射错误:**  使用 `mmap` 映射设备内存时，需要确保映射的大小和偏移量与设备区域信息一致。映射错误的区域可能导致程序崩溃或数据损坏。
6. **资源泄漏:**  打开的 VFIO 设备文件描述符需要在使用完毕后关闭，否则可能导致资源泄漏。
7. **中断处理不当:**  设置中断时，需要正确处理中断事件，例如通过 `read` 事件 FD 来接收通知。处理不当可能导致程序阻塞或无法响应设备事件。

**Android Framework 或 NDK 如何到达这里:**

Android Framework 或 NDK 应用通常不会直接调用这些底层的 VFIO ioctl。 它们通常会通过以下方式间接使用 VFIO：

1. **虚拟化框架 (例如, `VirtualizationService`):** Android 系统可能内置了虚拟化框架，这些框架会使用 VFIO 来实现硬件透传功能。Framework 会通过 Binder IPC 与运行在更高权限级别的进程通信，该进程会执行底层的 VFIO 操作。
2. **用户空间驱动框架 (例如, 通过 HAL 接口):**  某些硬件设备的驱动可能实现为用户空间驱动，利用 VFIO 与硬件交互。NDK 应用可以通过 HAL (Hardware Abstraction Layer) 接口与这些用户空间驱动进行通信。HAL 接口的实现可能会使用 VFIO。
3. **容器化技术 (例如, 通过 Docker 或类似方案):** 如果在 Android 上运行容器，容器运行时可能会使用 VFIO 将宿主机的硬件设备暴露给容器。

**Frida Hook 示例调试步骤:**

假设我们想观察 Android 系统中某个进程如何获取 VFIO 设备信息 (`VFIO_DEVICE_GET_INFO`)。

**Frida Hook 代码示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['value']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python frida_vfio_hook.py <process_name_or_pid>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    const VFIO_DEVICE_GET_INFO = 0xC0043B07; // 根据架构和内核版本可能不同，需要查找

    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            if (request === VFIO_DEVICE_GET_INFO) {
                send({ name: "ioctl", value: `VFIO_DEVICE_GET_INFO called on fd: ${fd}` });
                const device_info_ptr = ptr(args[2]);
                send({ name: "ioctl_args", value: `device_info struct size: ${device_info_ptr.readU32()}` });
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Waiting for messages...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**调试步骤:**

1. **查找 `VFIO_DEVICE_GET_INFO` 的 ioctl 号码:**  你需要根据目标 Android 设备的架构和内核版本找到 `VFIO_DEVICE_GET_INFO` 宏对应的实际数值。这可以通过查看内核源代码或使用其他工具（例如 `auscan`) 来获取。
2. **运行 Frida 脚本:**  使用 `python frida_vfio_hook.py <目标进程名或 PID>` 运行脚本。将 `<目标进程名或 PID>` 替换为你想要监控的进程的名称或 PID。
3. **触发 VFIO 操作:**  在目标进程中触发执行可能调用 VFIO 相关功能的代码。例如，如果目标进程是虚拟机管理器，可以启动一个虚拟机。
4. **观察 Frida 输出:**  Frida 脚本会在 `ioctl` 系统调用被调用时拦截，并检查 `request` 参数是否为 `VFIO_DEVICE_GET_INFO`。如果匹配，它会打印相关信息，例如文件描述符和 `vfio_device_info` 结构体的大小。

**注意:**  直接 Hook 系统调用可能需要 root 权限，并且可能受到 SELinux 等安全机制的限制。在进行此类调试时需要谨慎。

通过这些步骤，你可以观察到 Android 系统或 NDK 应用在底层是如何使用 VFIO 与硬件设备进行交互的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/vfio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPIVFIO_H
#define _UAPIVFIO_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define VFIO_API_VERSION 0
#define VFIO_TYPE1_IOMMU 1
#define VFIO_SPAPR_TCE_IOMMU 2
#define VFIO_TYPE1v2_IOMMU 3
#define VFIO_DMA_CC_IOMMU 4
#define VFIO_EEH 5
#define VFIO_TYPE1_NESTING_IOMMU 6
#define VFIO_SPAPR_TCE_v2_IOMMU 7
#define VFIO_NOIOMMU_IOMMU 8
#define VFIO_UNMAP_ALL 9
#define VFIO_UPDATE_VADDR 10
#define VFIO_TYPE (';')
#define VFIO_BASE 100
struct vfio_info_cap_header {
  __u16 id;
  __u16 version;
  __u32 next;
};
#define VFIO_GET_API_VERSION _IO(VFIO_TYPE, VFIO_BASE + 0)
#define VFIO_CHECK_EXTENSION _IO(VFIO_TYPE, VFIO_BASE + 1)
#define VFIO_SET_IOMMU _IO(VFIO_TYPE, VFIO_BASE + 2)
struct vfio_group_status {
  __u32 argsz;
  __u32 flags;
#define VFIO_GROUP_FLAGS_VIABLE (1 << 0)
#define VFIO_GROUP_FLAGS_CONTAINER_SET (1 << 1)
};
#define VFIO_GROUP_GET_STATUS _IO(VFIO_TYPE, VFIO_BASE + 3)
#define VFIO_GROUP_SET_CONTAINER _IO(VFIO_TYPE, VFIO_BASE + 4)
#define VFIO_GROUP_UNSET_CONTAINER _IO(VFIO_TYPE, VFIO_BASE + 5)
#define VFIO_GROUP_GET_DEVICE_FD _IO(VFIO_TYPE, VFIO_BASE + 6)
struct vfio_device_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_DEVICE_FLAGS_RESET (1 << 0)
#define VFIO_DEVICE_FLAGS_PCI (1 << 1)
#define VFIO_DEVICE_FLAGS_PLATFORM (1 << 2)
#define VFIO_DEVICE_FLAGS_AMBA (1 << 3)
#define VFIO_DEVICE_FLAGS_CCW (1 << 4)
#define VFIO_DEVICE_FLAGS_AP (1 << 5)
#define VFIO_DEVICE_FLAGS_FSL_MC (1 << 6)
#define VFIO_DEVICE_FLAGS_CAPS (1 << 7)
#define VFIO_DEVICE_FLAGS_CDX (1 << 8)
  __u32 num_regions;
  __u32 num_irqs;
  __u32 cap_offset;
  __u32 pad;
};
#define VFIO_DEVICE_GET_INFO _IO(VFIO_TYPE, VFIO_BASE + 7)
#define VFIO_DEVICE_API_PCI_STRING "vfio-pci"
#define VFIO_DEVICE_API_PLATFORM_STRING "vfio-platform"
#define VFIO_DEVICE_API_AMBA_STRING "vfio-amba"
#define VFIO_DEVICE_API_CCW_STRING "vfio-ccw"
#define VFIO_DEVICE_API_AP_STRING "vfio-ap"
#define VFIO_DEVICE_INFO_CAP_ZPCI_BASE 1
#define VFIO_DEVICE_INFO_CAP_ZPCI_GROUP 2
#define VFIO_DEVICE_INFO_CAP_ZPCI_UTIL 3
#define VFIO_DEVICE_INFO_CAP_ZPCI_PFIP 4
#define VFIO_DEVICE_INFO_CAP_PCI_ATOMIC_COMP 5
struct vfio_device_info_cap_pci_atomic_comp {
  struct vfio_info_cap_header header;
  __u32 flags;
#define VFIO_PCI_ATOMIC_COMP32 (1 << 0)
#define VFIO_PCI_ATOMIC_COMP64 (1 << 1)
#define VFIO_PCI_ATOMIC_COMP128 (1 << 2)
  __u32 reserved;
};
struct vfio_region_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_REGION_INFO_FLAG_READ (1 << 0)
#define VFIO_REGION_INFO_FLAG_WRITE (1 << 1)
#define VFIO_REGION_INFO_FLAG_MMAP (1 << 2)
#define VFIO_REGION_INFO_FLAG_CAPS (1 << 3)
  __u32 index;
  __u32 cap_offset;
  __aligned_u64 size;
  __aligned_u64 offset;
};
#define VFIO_DEVICE_GET_REGION_INFO _IO(VFIO_TYPE, VFIO_BASE + 8)
#define VFIO_REGION_INFO_CAP_SPARSE_MMAP 1
struct vfio_region_sparse_mmap_area {
  __aligned_u64 offset;
  __aligned_u64 size;
};
struct vfio_region_info_cap_sparse_mmap {
  struct vfio_info_cap_header header;
  __u32 nr_areas;
  __u32 reserved;
  struct vfio_region_sparse_mmap_area areas[];
};
#define VFIO_REGION_INFO_CAP_TYPE 2
struct vfio_region_info_cap_type {
  struct vfio_info_cap_header header;
  __u32 type;
  __u32 subtype;
};
#define VFIO_REGION_TYPE_PCI_VENDOR_TYPE (1 << 31)
#define VFIO_REGION_TYPE_PCI_VENDOR_MASK (0xffff)
#define VFIO_REGION_TYPE_GFX (1)
#define VFIO_REGION_TYPE_CCW (2)
#define VFIO_REGION_TYPE_MIGRATION_DEPRECATED (3)
#define VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION (1)
#define VFIO_REGION_SUBTYPE_INTEL_IGD_HOST_CFG (2)
#define VFIO_REGION_SUBTYPE_INTEL_IGD_LPC_CFG (3)
#define VFIO_REGION_SUBTYPE_NVIDIA_NVLINK2_RAM (1)
#define VFIO_REGION_SUBTYPE_IBM_NVLINK2_ATSD (1)
#define VFIO_REGION_SUBTYPE_GFX_EDID (1)
struct vfio_region_gfx_edid {
  __u32 edid_offset;
  __u32 edid_max_size;
  __u32 edid_size;
  __u32 max_xres;
  __u32 max_yres;
  __u32 link_state;
#define VFIO_DEVICE_GFX_LINK_STATE_UP 1
#define VFIO_DEVICE_GFX_LINK_STATE_DOWN 2
};
#define VFIO_REGION_SUBTYPE_CCW_ASYNC_CMD (1)
#define VFIO_REGION_SUBTYPE_CCW_SCHIB (2)
#define VFIO_REGION_SUBTYPE_CCW_CRW (3)
#define VFIO_REGION_SUBTYPE_MIGRATION_DEPRECATED (1)
struct vfio_device_migration_info {
  __u32 device_state;
#define VFIO_DEVICE_STATE_V1_STOP (0)
#define VFIO_DEVICE_STATE_V1_RUNNING (1 << 0)
#define VFIO_DEVICE_STATE_V1_SAVING (1 << 1)
#define VFIO_DEVICE_STATE_V1_RESUMING (1 << 2)
#define VFIO_DEVICE_STATE_MASK (VFIO_DEVICE_STATE_V1_RUNNING | VFIO_DEVICE_STATE_V1_SAVING | VFIO_DEVICE_STATE_V1_RESUMING)
#define VFIO_DEVICE_STATE_VALID(state) (state & VFIO_DEVICE_STATE_V1_RESUMING ? (state & VFIO_DEVICE_STATE_MASK) == VFIO_DEVICE_STATE_V1_RESUMING : 1)
#define VFIO_DEVICE_STATE_IS_ERROR(state) ((state & VFIO_DEVICE_STATE_MASK) == (VFIO_DEVICE_STATE_V1_SAVING | VFIO_DEVICE_STATE_V1_RESUMING))
#define VFIO_DEVICE_STATE_SET_ERROR(state) ((state & ~VFIO_DEVICE_STATE_MASK) | VFIO_DEVICE_STATE_V1_SAVING | VFIO_DEVICE_STATE_V1_RESUMING)
  __u32 reserved;
  __aligned_u64 pending_bytes;
  __aligned_u64 data_offset;
  __aligned_u64 data_size;
};
#define VFIO_REGION_INFO_CAP_MSIX_MAPPABLE 3
#define VFIO_REGION_INFO_CAP_NVLINK2_SSATGT 4
struct vfio_region_info_cap_nvlink2_ssatgt {
  struct vfio_info_cap_header header;
  __aligned_u64 tgt;
};
#define VFIO_REGION_INFO_CAP_NVLINK2_LNKSPD 5
struct vfio_region_info_cap_nvlink2_lnkspd {
  struct vfio_info_cap_header header;
  __u32 link_speed;
  __u32 __pad;
};
struct vfio_irq_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_IRQ_INFO_EVENTFD (1 << 0)
#define VFIO_IRQ_INFO_MASKABLE (1 << 1)
#define VFIO_IRQ_INFO_AUTOMASKED (1 << 2)
#define VFIO_IRQ_INFO_NORESIZE (1 << 3)
  __u32 index;
  __u32 count;
};
#define VFIO_DEVICE_GET_IRQ_INFO _IO(VFIO_TYPE, VFIO_BASE + 9)
struct vfio_irq_set {
  __u32 argsz;
  __u32 flags;
#define VFIO_IRQ_SET_DATA_NONE (1 << 0)
#define VFIO_IRQ_SET_DATA_BOOL (1 << 1)
#define VFIO_IRQ_SET_DATA_EVENTFD (1 << 2)
#define VFIO_IRQ_SET_ACTION_MASK (1 << 3)
#define VFIO_IRQ_SET_ACTION_UNMASK (1 << 4)
#define VFIO_IRQ_SET_ACTION_TRIGGER (1 << 5)
  __u32 index;
  __u32 start;
  __u32 count;
  __u8 data[];
};
#define VFIO_DEVICE_SET_IRQS _IO(VFIO_TYPE, VFIO_BASE + 10)
#define VFIO_IRQ_SET_DATA_TYPE_MASK (VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_DATA_BOOL | VFIO_IRQ_SET_DATA_EVENTFD)
#define VFIO_IRQ_SET_ACTION_TYPE_MASK (VFIO_IRQ_SET_ACTION_MASK | VFIO_IRQ_SET_ACTION_UNMASK | VFIO_IRQ_SET_ACTION_TRIGGER)
#define VFIO_DEVICE_RESET _IO(VFIO_TYPE, VFIO_BASE + 11)
enum {
  VFIO_PCI_BAR0_REGION_INDEX,
  VFIO_PCI_BAR1_REGION_INDEX,
  VFIO_PCI_BAR2_REGION_INDEX,
  VFIO_PCI_BAR3_REGION_INDEX,
  VFIO_PCI_BAR4_REGION_INDEX,
  VFIO_PCI_BAR5_REGION_INDEX,
  VFIO_PCI_ROM_REGION_INDEX,
  VFIO_PCI_CONFIG_REGION_INDEX,
  VFIO_PCI_VGA_REGION_INDEX,
  VFIO_PCI_NUM_REGIONS = 9
};
enum {
  VFIO_PCI_INTX_IRQ_INDEX,
  VFIO_PCI_MSI_IRQ_INDEX,
  VFIO_PCI_MSIX_IRQ_INDEX,
  VFIO_PCI_ERR_IRQ_INDEX,
  VFIO_PCI_REQ_IRQ_INDEX,
  VFIO_PCI_NUM_IRQS
};
enum {
  VFIO_CCW_CONFIG_REGION_INDEX,
  VFIO_CCW_NUM_REGIONS
};
enum {
  VFIO_CCW_IO_IRQ_INDEX,
  VFIO_CCW_CRW_IRQ_INDEX,
  VFIO_CCW_REQ_IRQ_INDEX,
  VFIO_CCW_NUM_IRQS
};
enum {
  VFIO_AP_REQ_IRQ_INDEX,
  VFIO_AP_NUM_IRQS
};
struct vfio_pci_dependent_device {
  union {
    __u32 group_id;
    __u32 devid;
#define VFIO_PCI_DEVID_OWNED 0
#define VFIO_PCI_DEVID_NOT_OWNED - 1
  };
  __u16 segment;
  __u8 bus;
  __u8 devfn;
};
struct vfio_pci_hot_reset_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_PCI_HOT_RESET_FLAG_DEV_ID (1 << 0)
#define VFIO_PCI_HOT_RESET_FLAG_DEV_ID_OWNED (1 << 1)
  __u32 count;
  struct vfio_pci_dependent_device devices[];
};
#define VFIO_DEVICE_GET_PCI_HOT_RESET_INFO _IO(VFIO_TYPE, VFIO_BASE + 12)
struct vfio_pci_hot_reset {
  __u32 argsz;
  __u32 flags;
  __u32 count;
  __s32 group_fds[];
};
#define VFIO_DEVICE_PCI_HOT_RESET _IO(VFIO_TYPE, VFIO_BASE + 13)
struct vfio_device_gfx_plane_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_GFX_PLANE_TYPE_PROBE (1 << 0)
#define VFIO_GFX_PLANE_TYPE_DMABUF (1 << 1)
#define VFIO_GFX_PLANE_TYPE_REGION (1 << 2)
  __u32 drm_plane_type;
  __u32 drm_format;
  __aligned_u64 drm_format_mod;
  __u32 width;
  __u32 height;
  __u32 stride;
  __u32 size;
  __u32 x_pos;
  __u32 y_pos;
  __u32 x_hot;
  __u32 y_hot;
  union {
    __u32 region_index;
    __u32 dmabuf_id;
  };
  __u32 reserved;
};
#define VFIO_DEVICE_QUERY_GFX_PLANE _IO(VFIO_TYPE, VFIO_BASE + 14)
#define VFIO_DEVICE_GET_GFX_DMABUF _IO(VFIO_TYPE, VFIO_BASE + 15)
struct vfio_device_ioeventfd {
  __u32 argsz;
  __u32 flags;
#define VFIO_DEVICE_IOEVENTFD_8 (1 << 0)
#define VFIO_DEVICE_IOEVENTFD_16 (1 << 1)
#define VFIO_DEVICE_IOEVENTFD_32 (1 << 2)
#define VFIO_DEVICE_IOEVENTFD_64 (1 << 3)
#define VFIO_DEVICE_IOEVENTFD_SIZE_MASK (0xf)
  __aligned_u64 offset;
  __aligned_u64 data;
  __s32 fd;
  __u32 reserved;
};
#define VFIO_DEVICE_IOEVENTFD _IO(VFIO_TYPE, VFIO_BASE + 16)
struct vfio_device_feature {
  __u32 argsz;
  __u32 flags;
#define VFIO_DEVICE_FEATURE_MASK (0xffff)
#define VFIO_DEVICE_FEATURE_GET (1 << 16)
#define VFIO_DEVICE_FEATURE_SET (1 << 17)
#define VFIO_DEVICE_FEATURE_PROBE (1 << 18)
  __u8 data[];
};
#define VFIO_DEVICE_FEATURE _IO(VFIO_TYPE, VFIO_BASE + 17)
struct vfio_device_bind_iommufd {
  __u32 argsz;
  __u32 flags;
  __s32 iommufd;
  __u32 out_devid;
};
#define VFIO_DEVICE_BIND_IOMMUFD _IO(VFIO_TYPE, VFIO_BASE + 18)
struct vfio_device_attach_iommufd_pt {
  __u32 argsz;
  __u32 flags;
  __u32 pt_id;
};
#define VFIO_DEVICE_ATTACH_IOMMUFD_PT _IO(VFIO_TYPE, VFIO_BASE + 19)
struct vfio_device_detach_iommufd_pt {
  __u32 argsz;
  __u32 flags;
};
#define VFIO_DEVICE_DETACH_IOMMUFD_PT _IO(VFIO_TYPE, VFIO_BASE + 20)
#define VFIO_DEVICE_FEATURE_PCI_VF_TOKEN (0)
struct vfio_device_feature_migration {
  __aligned_u64 flags;
#define VFIO_MIGRATION_STOP_COPY (1 << 0)
#define VFIO_MIGRATION_P2P (1 << 1)
#define VFIO_MIGRATION_PRE_COPY (1 << 2)
};
#define VFIO_DEVICE_FEATURE_MIGRATION 1
struct vfio_device_feature_mig_state {
  __u32 device_state;
  __s32 data_fd;
};
#define VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE 2
enum vfio_device_mig_state {
  VFIO_DEVICE_STATE_ERROR = 0,
  VFIO_DEVICE_STATE_STOP = 1,
  VFIO_DEVICE_STATE_RUNNING = 2,
  VFIO_DEVICE_STATE_STOP_COPY = 3,
  VFIO_DEVICE_STATE_RESUMING = 4,
  VFIO_DEVICE_STATE_RUNNING_P2P = 5,
  VFIO_DEVICE_STATE_PRE_COPY = 6,
  VFIO_DEVICE_STATE_PRE_COPY_P2P = 7,
  VFIO_DEVICE_STATE_NR,
};
struct vfio_precopy_info {
  __u32 argsz;
  __u32 flags;
  __aligned_u64 initial_bytes;
  __aligned_u64 dirty_bytes;
};
#define VFIO_MIG_GET_PRECOPY_INFO _IO(VFIO_TYPE, VFIO_BASE + 21)
#define VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY 3
struct vfio_device_low_power_entry_with_wakeup {
  __s32 wakeup_eventfd;
  __u32 reserved;
};
#define VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY_WITH_WAKEUP 4
#define VFIO_DEVICE_FEATURE_LOW_POWER_EXIT 5
struct vfio_device_feature_dma_logging_control {
  __aligned_u64 page_size;
  __u32 num_ranges;
  __u32 __reserved;
  __aligned_u64 ranges;
};
struct vfio_device_feature_dma_logging_range {
  __aligned_u64 iova;
  __aligned_u64 length;
};
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_START 6
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_STOP 7
struct vfio_device_feature_dma_logging_report {
  __aligned_u64 iova;
  __aligned_u64 length;
  __aligned_u64 page_size;
  __aligned_u64 bitmap;
};
#define VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT 8
struct vfio_device_feature_mig_data_size {
  __aligned_u64 stop_copy_length;
};
#define VFIO_DEVICE_FEATURE_MIG_DATA_SIZE 9
struct vfio_device_feature_bus_master {
  __u32 op;
#define VFIO_DEVICE_FEATURE_CLEAR_MASTER 0
#define VFIO_DEVICE_FEATURE_SET_MASTER 1
};
#define VFIO_DEVICE_FEATURE_BUS_MASTER 10
struct vfio_iommu_type1_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_IOMMU_INFO_PGSIZES (1 << 0)
#define VFIO_IOMMU_INFO_CAPS (1 << 1)
  __aligned_u64 iova_pgsizes;
  __u32 cap_offset;
  __u32 pad;
};
#define VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE 1
struct vfio_iova_range {
  __u64 start;
  __u64 end;
};
struct vfio_iommu_type1_info_cap_iova_range {
  struct vfio_info_cap_header header;
  __u32 nr_iovas;
  __u32 reserved;
  struct vfio_iova_range iova_ranges[];
};
#define VFIO_IOMMU_TYPE1_INFO_CAP_MIGRATION 2
struct vfio_iommu_type1_info_cap_migration {
  struct vfio_info_cap_header header;
  __u32 flags;
  __u64 pgsize_bitmap;
  __u64 max_dirty_bitmap_size;
};
#define VFIO_IOMMU_TYPE1_INFO_DMA_AVAIL 3
struct vfio_iommu_type1_info_dma_avail {
  struct vfio_info_cap_header header;
  __u32 avail;
};
#define VFIO_IOMMU_GET_INFO _IO(VFIO_TYPE, VFIO_BASE + 12)
struct vfio_iommu_type1_dma_map {
  __u32 argsz;
  __u32 flags;
#define VFIO_DMA_MAP_FLAG_READ (1 << 0)
#define VFIO_DMA_MAP_FLAG_WRITE (1 << 1)
#define VFIO_DMA_MAP_FLAG_VADDR (1 << 2)
  __u64 vaddr;
  __u64 iova;
  __u64 size;
};
#define VFIO_IOMMU_MAP_DMA _IO(VFIO_TYPE, VFIO_BASE + 13)
struct vfio_bitmap {
  __u64 pgsize;
  __u64 size;
  __u64  * data;
};
struct vfio_iommu_type1_dma_unmap {
  __u32 argsz;
  __u32 flags;
#define VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP (1 << 0)
#define VFIO_DMA_UNMAP_FLAG_ALL (1 << 1)
#define VFIO_DMA_UNMAP_FLAG_VADDR (1 << 2)
  __u64 iova;
  __u64 size;
  __u8 data[];
};
#define VFIO_IOMMU_UNMAP_DMA _IO(VFIO_TYPE, VFIO_BASE + 14)
#define VFIO_IOMMU_ENABLE _IO(VFIO_TYPE, VFIO_BASE + 15)
#define VFIO_IOMMU_DISABLE _IO(VFIO_TYPE, VFIO_BASE + 16)
struct vfio_iommu_type1_dirty_bitmap {
  __u32 argsz;
  __u32 flags;
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_START (1 << 0)
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP (1 << 1)
#define VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP (1 << 2)
  __u8 data[];
};
struct vfio_iommu_type1_dirty_bitmap_get {
  __u64 iova;
  __u64 size;
  struct vfio_bitmap bitmap;
};
#define VFIO_IOMMU_DIRTY_PAGES _IO(VFIO_TYPE, VFIO_BASE + 17)
struct vfio_iommu_spapr_tce_ddw_info {
  __u64 pgsizes;
  __u32 max_dynamic_windows_supported;
  __u32 levels;
};
struct vfio_iommu_spapr_tce_info {
  __u32 argsz;
  __u32 flags;
#define VFIO_IOMMU_SPAPR_INFO_DDW (1 << 0)
  __u32 dma32_window_start;
  __u32 dma32_window_size;
  struct vfio_iommu_spapr_tce_ddw_info ddw;
};
#define VFIO_IOMMU_SPAPR_TCE_GET_INFO _IO(VFIO_TYPE, VFIO_BASE + 12)
struct vfio_eeh_pe_err {
  __u32 type;
  __u32 func;
  __u64 addr;
  __u64 mask;
};
struct vfio_eeh_pe_op {
  __u32 argsz;
  __u32 flags;
  __u32 op;
  union {
    struct vfio_eeh_pe_err err;
  };
};
#define VFIO_EEH_PE_DISABLE 0
#define VFIO_EEH_PE_ENABLE 1
#define VFIO_EEH_PE_UNFREEZE_IO 2
#define VFIO_EEH_PE_UNFREEZE_DMA 3
#define VFIO_EEH_PE_GET_STATE 4
#define VFIO_EEH_PE_STATE_NORMAL 0
#define VFIO_EEH_PE_STATE_RESET 1
#define VFIO_EEH_PE_STATE_STOPPED 2
#define VFIO_EEH_PE_STATE_STOPPED_DMA 4
#define VFIO_EEH_PE_STATE_UNAVAIL 5
#define VFIO_EEH_PE_RESET_DEACTIVATE 5
#define VFIO_EEH_PE_RESET_HOT 6
#define VFIO_EEH_PE_RESET_FUNDAMENTAL 7
#define VFIO_EEH_PE_CONFIGURE 8
#define VFIO_EEH_PE_INJECT_ERR 9
#define VFIO_EEH_PE_OP _IO(VFIO_TYPE, VFIO_BASE + 21)
struct vfio_iommu_spapr_register_memory {
  __u32 argsz;
  __u32 flags;
  __u64 vaddr;
  __u64 size;
};
#define VFIO_IOMMU_SPAPR_REGISTER_MEMORY _IO(VFIO_TYPE, VFIO_BASE + 17)
#define VFIO_IOMMU_SPAPR_UNREGISTER_MEMORY _IO(VFIO_TYPE, VFIO_BASE + 18)
struct vfio_iommu_spapr_tce_create {
  __u32 argsz;
  __u32 flags;
  __u32 page_shift;
  __u32 __resv1;
  __u64 window_size;
  __u32 levels;
  __u32 __resv2;
  __u64 start_addr;
};
#define VFIO_IOMMU_SPAPR_TCE_CREATE _IO(VFIO_TYPE, VFIO_BASE + 19)
struct vfio_iommu_spapr_tce_remove {
  __u32 argsz;
  __u32 flags;
  __u64 start_addr;
};
#define VFIO_IOMMU_SPAPR_TCE_REMOVE _IO(VFIO_TYPE, VFIO_BASE + 20)
#endif
```