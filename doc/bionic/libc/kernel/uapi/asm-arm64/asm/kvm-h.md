Response:
Let's break down the thought process to answer the request about the `kvm.handroid` file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of a specific kernel header file (`kvm.handroid`). Key aspects include:

* **Functionality:** What does this file *do*?  What are its purposes?
* **Relationship to Android:** How does it connect to the Android ecosystem? Provide concrete examples.
* **Libc Function Implementation:** How are the libc functions defined in this file implemented?  (This requires careful examination of the contents and understanding of header files).
* **Dynamic Linker (if applicable):** If the file involves the dynamic linker, explain the linking process and provide a sample SO layout.
* **Logical Reasoning:**  If there's any logic or decision-making, illustrate it with input/output examples.
* **Common Errors:** What are potential mistakes developers might make when interacting with concepts in this file?
* **Android Framework/NDK Path:** How does code from higher layers reach this file? Provide a Frida hook example.

**2. Initial Analysis of the File Contents:**

The first step is to carefully read the provided code. Key observations include:

* **Header Guard:** `#ifndef __ARM_KVM_H__ ... #endif` - This is a standard C/C++ header guard, preventing multiple inclusions.
* **Auto-generated Comment:**  The "auto-generated" comment strongly suggests this file isn't manually written and is derived from a more authoritative source. The link to `android.googlesource.com` confirms its origin.
* **Includes:**  `<linux/psci.h>`, `<linux/types.h>`, `<asm/ptrace.h>`, `<asm/sve_context.h>` indicate this file interacts directly with the Linux kernel and architecture-specific features (ARM64).
* **Macros and Defines:**  There are numerous `#define` statements defining constants and bit flags. These are crucial for understanding the file's purpose. Look for patterns like `KVM_SPSR_`, `KVM_ARM_TARGET_`, `KVM_REG_ARM_`, etc. These prefixes give hints about the related concepts (KVM status registers, ARM target architectures, KVM register definitions).
* **Structures:**  `struct kvm_regs`, `struct kvm_vcpu_init`, etc., define data structures used to interact with the KVM hypervisor. The names are descriptive and suggest their purpose (e.g., `kvm_regs` likely holds register state).
* **Enums:** `enum kvm_smccc_filter_action` defines a set of related constants.
* **Comments:** While sparse, some comments like `/* This file is auto-generated... */` are very informative.

**3. Identifying Key Concepts and Functionality:**

Based on the initial analysis, several key areas of functionality emerge:

* **KVM (Kernel-based Virtual Machine):**  The filename and the prevalence of `KVM_` prefixes strongly point to this file defining interfaces and constants for interacting with the KVM hypervisor on ARM64.
* **ARM64 Architecture:** The `asm-arm64` path and the inclusion of architecture-specific headers like `asm/ptrace.h` confirm that this is specific to the ARM64 architecture.
* **Virtualization:**  The structures and constants relate to virtual CPUs (`kvm_vcpu_init`), registers (`kvm_regs`), and device emulation (VGIC - Virtual GIC).
* **PSCI (Power State Coordination Interface):** The inclusion of `linux/psci.h` and defines like `KVM_PSCI_FN_CPU_ON` indicate support for managing the power states of virtual CPUs.
* **SVE (Scalable Vector Extension):**  The presence of `KVM_REG_ARM64_SVE` and related definitions suggests support for the ARM SVE instruction set.
* **Guest Debugging:** Structures like `kvm_guest_debug_arch` and constants related to breakpoints indicate support for debugging guest operating systems.

**4. Relating to Android:**

Knowing that KVM is a common virtualization technology and Android supports virtualization (especially for Android Virtual Devices and potentially containerization), the connection becomes clear. This file defines the low-level interface between the Android kernel and the KVM hypervisor for ARM64.

* **Examples:**  AVD uses KVM to run emulated Android instances. Containerization technologies on Android might also leverage KVM.

**5. Addressing Libc Functions and Dynamic Linking:**

* **Libc Functions:** This file is a *header file*. It *declares* structures and constants, but it *doesn't implement* libc functions. The included headers (`linux/types.h`) define basic types, but actual libc functions reside in other parts of Bionic. It's crucial to understand the difference between declaration and implementation.
* **Dynamic Linking:** This file doesn't directly involve dynamic linking. It's a kernel header used by kernel modules or potentially by userspace code interacting directly with the `/dev/kvm` interface. Dynamic linking happens when userspace applications load shared libraries (.so files).

**6. Logical Reasoning and Assumptions:**

The definitions in the file represent a set of rules and constants for communication with the KVM hypervisor. There isn't complex "logic" within the *header file* itself. The logic resides in the kernel code that *uses* these definitions.

* **Example (Hypothetical):**  If the kernel needs to set the state of a virtual CPU's System Program Status Register (SPSR), it would use the `KVM_SPSR_EL1` constant to identify the correct SPSR index in the `kvm_regs.spsr` array. The *logic* of *when* and *why* to set the SPSR is outside this file's scope.

**7. Common Errors:**

* **Incorrect Register Access:** Using the wrong `KVM_REG_*` constant when trying to read or write guest registers.
* **Feature Bit Misconfiguration:**  Setting incorrect feature flags in `kvm_vcpu_init`, leading to unexpected behavior in the guest.
* **Interrupt Handling Issues:**  Misconfiguring the virtual GIC (VGIC) through the defined structures, resulting in incorrect interrupt delivery.

**8. Android Framework/NDK Path and Frida Hook:**

* **Path:** The journey starts with userspace applications (AVD, container runtimes) making system calls (e.g., `ioctl`) on the `/dev/kvm` device. These system calls are handled by the kernel's KVM module. The KVM module uses the definitions in `kvm.handroid.h` to structure its communication with the underlying hardware virtualization extensions.
* **Frida Hook:**  We can use Frida to intercept `ioctl` calls to `/dev/kvm` and examine the data being passed, revealing how the framework or NDK interacts with the KVM interface.

**9. Structuring the Answer:**

Finally, organize the information logically, starting with a general overview, then diving into specifics for each part of the request. Use clear headings and examples to make the explanation easy to understand. Emphasize the distinction between declaration and implementation, and be precise in the terminology. For example, avoid saying "libc functions are implemented here" when it's a header file.
这个文件 `bionic/libc/kernel/uapi/asm-arm64/asm/kvm.handroid` 是 Android Bionic 库中，针对 ARM64 架构下与 KVM (Kernel-based Virtual Machine) 相关的用户空间 API 头文件。它的主要功能是定义了一系列常量、数据结构和宏，用于用户空间程序（如虚拟机管理器）与 Linux 内核中的 KVM 模块进行交互。

**主要功能列举：**

1. **定义 KVM 状态寄存器 (SPSR) 的索引：**  `KVM_SPSR_EL1`, `KVM_SPSR_SVC`, `KVM_SPSR_ABT` 等定义了不同异常级别和模式下的 SPSR 寄存器的索引，用于访问虚拟机 CPU 的状态。
2. **定义 KVM 特性标志：**  如 `__KVM_HAVE_IRQ_LINE`, `__KVM_HAVE_VCPU_EVENTS`，表示内核 KVM 模块支持的特定功能。
3. **定义内存映射偏移量：** `KVM_COALESCED_MMIO_PAGE_OFFSET`, `KVM_DIRTY_LOG_PAGE_OFFSET` 定义了在 KVM 内存映射中特定功能的偏移量。
4. **定义 `kvm_regs` 结构体：**  描述了虚拟机 CPU 的通用寄存器、SP、ELR 和 SPSR 的状态，以及浮点/SIMD 寄存器的状态。这是用户空间读取和设置虚拟机 CPU 状态的关键数据结构。
5. **定义 ARM 目标架构类型：** `KVM_ARM_TARGET_AEM_V8`, `KVM_ARM_TARGET_FOUNDATION_V8` 等定义了虚拟机可以模拟的不同 ARM 处理器架构。
6. **定义虚拟 GIC (VGIC) 相关的常量：**  如 `KVM_ARM_DEVICE_VGIC_V2`, `KVM_VGIC_V2_ADDR_TYPE_DIST` 等，用于配置和控制虚拟中断控制器。
7. **定义 VCPU 初始化标志：** `KVM_ARM_VCPU_POWER_OFF`, `KVM_ARM_VCPU_EL1_32BIT` 等用于设置虚拟机 CPU 的初始状态和特性。
8. **定义调试相关的结构体和常量：** `struct kvm_guest_debug_arch`, `KVM_DEBUG_ARCH_HSR_HIGH_VALID` 等用于支持虚拟机内的调试。
9. **定义同步寄存器结构体：** `struct kvm_sync_regs` 用于同步虚拟机 CPU 的状态。
10. **定义设备相关的常量：** `KVM_ARM_DEV_EL1_VTIMER`, `KVM_ARM_DEV_EL1_PTIMER` 等用于标识虚拟设备。
11. **定义 PMU (Performance Monitoring Unit) 相关的结构体和常量：** `struct kvm_pmu_event_filter` 用于配置虚拟 PMU 的事件过滤。
12. **定义 VCPU 事件结构体：** `struct kvm_vcpu_events` 用于获取虚拟机 CPU 发生的事件，如SError。
13. **定义 MTE (Memory Tagging Extension) 相关的结构体：** `struct kvm_arm_copy_mte_tags` 用于在客户机和宿主机之间复制 MTE 标签。
14. **定义计数器偏移量结构体：** `struct kvm_arm_counter_offset` 用于获取虚拟计数器的偏移量。
15. **定义访问寄存器的宏：**  如 `KVM_REG_ARM_CORE_REG`, `ARM64_SYS_REG` 等，方便用户空间程序访问虚拟机 CPU 的各种寄存器。
16. **定义 PSCI (Power State Coordination Interface) 相关的常量：** `KVM_PSCI_FN_CPU_ON`, `KVM_PSCI_RET_SUCCESS` 等，用于控制虚拟机 CPU 的电源状态。
17. **定义 SMCCC (Secure Monitor Call Calling Convention) 过滤器相关的结构体和常量：** `struct kvm_smccc_filter`, `KVM_SMCCC_FILTER_HANDLE` 等，用于控制对 Secure Monitor Call 的处理。
18. **定义 Hypercall 退出的常量：** `KVM_HYPERCALL_EXIT_SMC`, `KVM_HYPERCALL_EXIT_16BIT` 表示虚拟机可以通过 Hypercall 指令退出到宿主机。
19. **定义特性 ID 范围相关的宏和常量：** `KVM_ARM_FEATURE_ID_RANGE_IDX`, `KVM_ARM_FEATURE_ID_RANGE` 用于查询 KVM 支持的特性。
20. **定义寄存器掩码范围结构体：** `struct reg_mask_range` 用于定义寄存器访问的掩码范围。

**与 Android 功能的关系及举例说明：**

这个文件直接关联到 Android 平台上的 **虚拟化支持**。Android 可以使用 KVM 来运行虚拟机，例如：

* **Android Virtual Device (AVD):** Android Studio 使用 AVD 来模拟不同的 Android 设备。AVD 底层就依赖于 KVM 来创建和管理虚拟机。这个头文件中定义的结构体和常量被 AVD 的相关工具使用，例如 `qemu-system-aarch64`，它通过 `/dev/kvm` 接口与内核 KVM 模块通信，设置虚拟机 CPU 的寄存器状态、内存映射、中断控制器等。
    * **举例：** AVD 在启动虚拟机时，会使用 `kvm_regs` 结构体来设置虚拟机 CPU 的初始寄存器值，例如通过 `KVM_SET_REGS` ioctl 命令。
* **容器化技术：** 一些 Android 上的容器化解决方案也可能使用 KVM 来提供硬件级别的隔离。
* **Guest OS 开发和测试：** 开发者可以使用 KVM 来运行和调试不同的操作系统镜像。

**libc 函数的功能及其实现：**

这个文件本身是 **内核 UAPI (用户空间 API) 头文件**，它 **不包含任何 libc 函数的实现**。它只是定义了数据结构和常量，供用户空间的 C/C++ 程序使用。用户空间程序会使用标准的 libc 函数（如 `open`, `ioctl`, `mmap` 等）来与 KVM 模块进行交互。

* **`ioctl` 函数：**  是用户空间程序与设备驱动程序（包括 KVM 模块）通信的主要方式。用户空间程序会使用 `ioctl` 函数，并传入这个头文件中定义的常量（如 `KVM_CREATE_VM`, `KVM_CREATE_VCPU`, `KVM_SET_REGS` 等）作为命令，以及相应的结构体（如 `kvm_regs`, `kvm_vcpu_init` 等）作为参数，来控制虚拟机。
* **`mmap` 函数：**  用于将 KVM 提供的虚拟机内存映射到用户空间程序的地址空间，从而可以直接访问虚拟机内存。`KVM_COALESCED_MMIO_PAGE_OFFSET` 和 `KVM_DIRTY_LOG_PAGE_OFFSET` 等常量会影响 `mmap` 的使用。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程：**

这个文件 **不直接涉及 dynamic linker 的功能**。Dynamic linker (如 Android 的 `linker64`) 的主要职责是在程序启动时加载和链接共享库。这个头文件是用于与内核 KVM 模块交互的，属于系统调用层面，早于动态链接的发生。

**逻辑推理、假设输入与输出：**

这个文件主要定义了数据结构和常量，**不包含复杂的逻辑推理**。其“逻辑”体现在内核 KVM 模块中，用户空间程序通过这个头文件中定义的接口与 KVM 模块进行交互。

* **假设输入：** 用户空间程序想要读取虚拟机 CPU 的程序计数器 (PC)。
* **对应操作：** 程序会使用 `KVM_GET_REGS` 的 `ioctl` 命令，并将一个 `kvm_regs` 结构体的地址传递给内核。
* **输出：**  内核 KVM 模块会将虚拟机 CPU 的当前寄存器状态填充到 `kvm_regs` 结构体中，用户空间程序可以从中读取 `regs.pc` 字段。

**用户或编程常见的使用错误：**

1. **使用错误的 ioctl 命令码：**  例如，尝试使用针对其他 KVM 扩展的 ioctl 命令。
2. **传递不正确的结构体大小或内容：**  例如，`kvm_regs` 结构体中的字段顺序或大小与内核期望的不符。
3. **权限问题：**  访问 `/dev/kvm` 设备需要相应的权限。
4. **未检查 ioctl 的返回值：**  `ioctl` 调用失败时会返回错误码，未检查返回值可能导致程序出现未定义的行为。
5. **不理解各个标志位的含义：**  例如，在设置 VCPU 初始化标志时，错误地配置 `kvm_vcpu_init.features` 数组。
6. **直接修改 auto-generated 文件：**  这个文件明确声明是自动生成的，任何修改都会丢失。如果需要修改 KVM 接口，应该修改生成源文件。

**Android Framework 或 NDK 如何一步步到达这里，给出 frida hook 示例调试这些步骤：**

1. **Android Framework/NDK 调用:**  通常不会直接调用 KVM 接口。而是通过更上层的抽象层，例如：
    * **AVD (通过 emulator 程序):**  Android Studio 启动 AVD 时，会运行 `emulator` 程序（基于 QEMU 修改）。
    * **容器化运行时 (例如 `libvirt` 或其他):**  某些容器化解决方案可能在 Android 上运行，并使用 KVM。

2. **用户空间程序交互:**  `emulator` 或容器化运行时等程序会使用 libc 函数（如 `open`, `ioctl`, `mmap`）与内核 `/dev/kvm` 设备进行交互。

3. **系统调用:**  libc 函数最终会触发系统调用，进入内核空间。

4. **KVM 内核模块:**  内核中的 KVM 模块接收到系统调用，并根据 ioctl 命令码和参数执行相应的操作，例如创建虚拟机、创建 VCPU、设置寄存器等。在这个过程中，KVM 模块会使用 `bionic/libc/kernel/uapi/asm-arm64/asm/kvm.handroid` 中定义的常量和结构体。

**Frida Hook 示例：**

可以使用 Frida Hook `ioctl` 系统调用来观察用户空间程序如何与 KVM 模块交互。以下是一个简单的 Frida 脚本示例：

```javascript
function hook_ioctl() {
  const ioctlPtr = Module.getExportByName(null, "ioctl");
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const pathname = getPathForFd(fd);

        if (pathname && pathname.includes("/dev/kvm")) {
          console.log("\nioctl called on /dev/kvm");
          console.log("  fd:", fd);
          console.log("  request:", request, "(0x" + request.toString(16) + ")");
          // 可以根据 request 的值进一步解析 argp 指针指向的数据
          if (request === 0xae80) { // 假设 0xae80 是 KVM_CREATE_VM
            console.log("  KVM_CREATE_VM");
          } else if (request === 0xae81) { // 假设 0xae81 是 KVM_CREATE_VCPU
            console.log("  KVM_CREATE_VCPU");
          } else if (request === 0xc010ae42) { // 假设 0xc010ae42 是 KVM_SET_REGS
            console.log("  KVM_SET_REGS");
            // 这里可以进一步解析 args[2] 指针指向的 kvm_regs 结构体
            const kvm_regs_ptr = ptr(args[2]);
            // 注意：需要知道 kvm_regs 结构体的布局才能正确解析
            // 示例：假设 regs 是 user_pt_regs 的偏移量
            // const pc = kvm_regs_ptr.add(offsetof_regs_pc).readU64();
            // console.log("    PC:", pc.toString(16));
          }
        }
      },
      onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
      },
    });
  } else {
    console.log("Failed to find ioctl function.");
  }
}

function getPathForFd(fd) {
  try {
    const pathBuf = Memory.alloc(256);
    const bytesRead = recv('realpath', fd).wait().data;
    if (bytesRead > 0) {
      Memory.copy(pathBuf, bytesRead, bytesRead.length);
      return pathBuf.readCString();
    }
    return null;
  } catch (e) {
    return null;
  }
}

rpc.exports = {
  hook_ioctl: hook_ioctl,
};
```

**使用方法：**

1. 将以上代码保存为 `hook_kvm.js`。
2. 找到运行 AVD 或容器化应用的进程 PID。
3. 使用 Frida 连接到目标进程：`frida -U -f <your_app_package_name> -l hook_kvm.js --no-pause` 或者 `frida -p <pid> -l hook_kvm.js --no-pause`
4. 在 Frida 控制台中调用 `rpc.exports.hook_ioctl()`。
5. 观察控制台输出，可以看到对 `/dev/kvm` 的 `ioctl` 调用及其参数。

**注意：**  解析 `ioctl` 的参数（例如 `kvm_regs` 结构体）需要知道结构体的内存布局，这可以通过查看内核源码或相关的头文件来获取。上面的 Frida 示例代码只是一个框架，需要根据具体的 `ioctl` 命令和数据结构进行更详细的解析。

通过 Frida Hook，你可以详细观察 Android Framework 或 NDK 背后的用户空间程序是如何一步步调用 `ioctl`，并使用 `kvm.handroid` 中定义的常量和结构体与内核 KVM 模块进行交互的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-arm64/asm/kvm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __ARM_KVM_H__
#define __ARM_KVM_H__
#define KVM_SPSR_EL1 0
#define KVM_SPSR_SVC KVM_SPSR_EL1
#define KVM_SPSR_ABT 1
#define KVM_SPSR_UND 2
#define KVM_SPSR_IRQ 3
#define KVM_SPSR_FIQ 4
#define KVM_NR_SPSR 5
#ifndef __ASSEMBLY__
#include <linux/psci.h>
#include <linux/types.h>
#include <asm/ptrace.h>
#include <asm/sve_context.h>
#define __KVM_HAVE_IRQ_LINE
#define __KVM_HAVE_VCPU_EVENTS
#define KVM_COALESCED_MMIO_PAGE_OFFSET 1
#define KVM_DIRTY_LOG_PAGE_OFFSET 64
#define KVM_REG_SIZE(id) (1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
struct kvm_regs {
  struct user_pt_regs regs;
  __u64 sp_el1;
  __u64 elr_el1;
  __u64 spsr[KVM_NR_SPSR];
  struct user_fpsimd_state fp_regs;
};
#define KVM_ARM_TARGET_AEM_V8 0
#define KVM_ARM_TARGET_FOUNDATION_V8 1
#define KVM_ARM_TARGET_CORTEX_A57 2
#define KVM_ARM_TARGET_XGENE_POTENZA 3
#define KVM_ARM_TARGET_CORTEX_A53 4
#define KVM_ARM_TARGET_GENERIC_V8 5
#define KVM_ARM_NUM_TARGETS 6
#define KVM_ARM_DEVICE_TYPE_SHIFT 0
#define KVM_ARM_DEVICE_TYPE_MASK __GENMASK(KVM_ARM_DEVICE_TYPE_SHIFT + 15, KVM_ARM_DEVICE_TYPE_SHIFT)
#define KVM_ARM_DEVICE_ID_SHIFT 16
#define KVM_ARM_DEVICE_ID_MASK __GENMASK(KVM_ARM_DEVICE_ID_SHIFT + 15, KVM_ARM_DEVICE_ID_SHIFT)
#define KVM_ARM_DEVICE_VGIC_V2 0
#define KVM_VGIC_V2_ADDR_TYPE_DIST 0
#define KVM_VGIC_V2_ADDR_TYPE_CPU 1
#define KVM_VGIC_V2_DIST_SIZE 0x1000
#define KVM_VGIC_V2_CPU_SIZE 0x2000
#define KVM_VGIC_V3_ADDR_TYPE_DIST 2
#define KVM_VGIC_V3_ADDR_TYPE_REDIST 3
#define KVM_VGIC_ITS_ADDR_TYPE 4
#define KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION 5
#define KVM_VGIC_V3_DIST_SIZE SZ_64K
#define KVM_VGIC_V3_REDIST_SIZE (2 * SZ_64K)
#define KVM_VGIC_V3_ITS_SIZE (2 * SZ_64K)
#define KVM_ARM_VCPU_POWER_OFF 0
#define KVM_ARM_VCPU_EL1_32BIT 1
#define KVM_ARM_VCPU_PSCI_0_2 2
#define KVM_ARM_VCPU_PMU_V3 3
#define KVM_ARM_VCPU_SVE 4
#define KVM_ARM_VCPU_PTRAUTH_ADDRESS 5
#define KVM_ARM_VCPU_PTRAUTH_GENERIC 6
#define KVM_ARM_VCPU_HAS_EL2 7
struct kvm_vcpu_init {
  __u32 target;
  __u32 features[7];
};
struct kvm_sregs {
};
struct kvm_fpu {
};
#define KVM_ARM_MAX_DBG_REGS 16
struct kvm_guest_debug_arch {
  __u64 dbg_bcr[KVM_ARM_MAX_DBG_REGS];
  __u64 dbg_bvr[KVM_ARM_MAX_DBG_REGS];
  __u64 dbg_wcr[KVM_ARM_MAX_DBG_REGS];
  __u64 dbg_wvr[KVM_ARM_MAX_DBG_REGS];
};
#define KVM_DEBUG_ARCH_HSR_HIGH_VALID (1 << 0)
struct kvm_debug_exit_arch {
  __u32 hsr;
  __u32 hsr_high;
  __u64 far;
};
#define KVM_GUESTDBG_USE_SW_BP (1 << 16)
#define KVM_GUESTDBG_USE_HW (1 << 17)
struct kvm_sync_regs {
  __u64 device_irq_level;
};
#define KVM_ARM_DEV_EL1_VTIMER (1 << 0)
#define KVM_ARM_DEV_EL1_PTIMER (1 << 1)
#define KVM_ARM_DEV_PMU (1 << 2)
struct kvm_pmu_event_filter {
  __u16 base_event;
  __u16 nevents;
#define KVM_PMU_EVENT_ALLOW 0
#define KVM_PMU_EVENT_DENY 1
  __u8 action;
  __u8 pad[3];
};
struct kvm_vcpu_events {
  struct {
    __u8 serror_pending;
    __u8 serror_has_esr;
    __u8 ext_dabt_pending;
    __u8 pad[5];
    __u64 serror_esr;
  } exception;
  __u32 reserved[12];
};
struct kvm_arm_copy_mte_tags {
  __u64 guest_ipa;
  __u64 length;
  void  * addr;
  __u64 flags;
  __u64 reserved[2];
};
struct kvm_arm_counter_offset {
  __u64 counter_offset;
  __u64 reserved;
};
#define KVM_ARM_TAGS_TO_GUEST 0
#define KVM_ARM_TAGS_FROM_GUEST 1
#define KVM_REG_ARM_COPROC_MASK 0x000000000FFF0000
#define KVM_REG_ARM_COPROC_SHIFT 16
#define KVM_REG_ARM_CORE (0x0010 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM_CORE_REG(name) (offsetof(struct kvm_regs, name) / sizeof(__u32))
#define KVM_REG_ARM_DEMUX (0x0011 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM_DEMUX_ID_MASK 0x000000000000FF00
#define KVM_REG_ARM_DEMUX_ID_SHIFT 8
#define KVM_REG_ARM_DEMUX_ID_CCSIDR (0x00 << KVM_REG_ARM_DEMUX_ID_SHIFT)
#define KVM_REG_ARM_DEMUX_VAL_MASK 0x00000000000000FF
#define KVM_REG_ARM_DEMUX_VAL_SHIFT 0
#define KVM_REG_ARM64_SYSREG (0x0013 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM64_SYSREG_OP0_MASK 0x000000000000c000
#define KVM_REG_ARM64_SYSREG_OP0_SHIFT 14
#define KVM_REG_ARM64_SYSREG_OP1_MASK 0x0000000000003800
#define KVM_REG_ARM64_SYSREG_OP1_SHIFT 11
#define KVM_REG_ARM64_SYSREG_CRN_MASK 0x0000000000000780
#define KVM_REG_ARM64_SYSREG_CRN_SHIFT 7
#define KVM_REG_ARM64_SYSREG_CRM_MASK 0x0000000000000078
#define KVM_REG_ARM64_SYSREG_CRM_SHIFT 3
#define KVM_REG_ARM64_SYSREG_OP2_MASK 0x0000000000000007
#define KVM_REG_ARM64_SYSREG_OP2_SHIFT 0
#define ARM64_SYS_REG_SHIFT_MASK(x,n) (((x) << KVM_REG_ARM64_SYSREG_ ##n ##_SHIFT) & KVM_REG_ARM64_SYSREG_ ##n ##_MASK)
#define __ARM64_SYS_REG(op0,op1,crn,crm,op2) (KVM_REG_ARM64 | KVM_REG_ARM64_SYSREG | ARM64_SYS_REG_SHIFT_MASK(op0, OP0) | ARM64_SYS_REG_SHIFT_MASK(op1, OP1) | ARM64_SYS_REG_SHIFT_MASK(crn, CRN) | ARM64_SYS_REG_SHIFT_MASK(crm, CRM) | ARM64_SYS_REG_SHIFT_MASK(op2, OP2))
#define ARM64_SYS_REG(...) (__ARM64_SYS_REG(__VA_ARGS__) | KVM_REG_SIZE_U64)
#define KVM_REG_ARM_PTIMER_CTL ARM64_SYS_REG(3, 3, 14, 2, 1)
#define KVM_REG_ARM_PTIMER_CVAL ARM64_SYS_REG(3, 3, 14, 2, 2)
#define KVM_REG_ARM_PTIMER_CNT ARM64_SYS_REG(3, 3, 14, 0, 1)
#define KVM_REG_ARM_TIMER_CTL ARM64_SYS_REG(3, 3, 14, 3, 1)
#define KVM_REG_ARM_TIMER_CVAL ARM64_SYS_REG(3, 3, 14, 0, 2)
#define KVM_REG_ARM_TIMER_CNT ARM64_SYS_REG(3, 3, 14, 3, 2)
#define KVM_REG_ARM_FW (0x0014 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM_FW_REG(r) (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW | ((r) & 0xffff))
#define KVM_REG_ARM_PSCI_VERSION KVM_REG_ARM_FW_REG(0)
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1 KVM_REG_ARM_FW_REG(1)
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_NOT_AVAIL 0
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_AVAIL 1
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_1_NOT_REQUIRED 2
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2 KVM_REG_ARM_FW_REG(2)
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_NOT_AVAIL 0
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_UNKNOWN 1
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_AVAIL 2
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_NOT_REQUIRED 3
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_ENABLED (1U << 4)
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3 KVM_REG_ARM_FW_REG(3)
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_NOT_AVAIL 0
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_AVAIL 1
#define KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_3_NOT_REQUIRED 2
#define KVM_REG_ARM64_SVE (0x15 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM64_SVE_ZREG_BASE 0
#define KVM_REG_ARM64_SVE_PREG_BASE 0x400
#define KVM_REG_ARM64_SVE_FFR_BASE 0x600
#define KVM_ARM64_SVE_NUM_ZREGS __SVE_NUM_ZREGS
#define KVM_ARM64_SVE_NUM_PREGS __SVE_NUM_PREGS
#define KVM_ARM64_SVE_MAX_SLICES 32
#define KVM_REG_ARM64_SVE_ZREG(n,i) (KVM_REG_ARM64 | KVM_REG_ARM64_SVE | KVM_REG_ARM64_SVE_ZREG_BASE | KVM_REG_SIZE_U2048 | (((n) & (KVM_ARM64_SVE_NUM_ZREGS - 1)) << 5) | ((i) & (KVM_ARM64_SVE_MAX_SLICES - 1)))
#define KVM_REG_ARM64_SVE_PREG(n,i) (KVM_REG_ARM64 | KVM_REG_ARM64_SVE | KVM_REG_ARM64_SVE_PREG_BASE | KVM_REG_SIZE_U256 | (((n) & (KVM_ARM64_SVE_NUM_PREGS - 1)) << 5) | ((i) & (KVM_ARM64_SVE_MAX_SLICES - 1)))
#define KVM_REG_ARM64_SVE_FFR(i) (KVM_REG_ARM64 | KVM_REG_ARM64_SVE | KVM_REG_ARM64_SVE_FFR_BASE | KVM_REG_SIZE_U256 | ((i) & (KVM_ARM64_SVE_MAX_SLICES - 1)))
#define KVM_ARM64_SVE_VQ_MIN __SVE_VQ_MIN
#define KVM_ARM64_SVE_VQ_MAX __SVE_VQ_MAX
#define KVM_REG_ARM64_SVE_VLS (KVM_REG_ARM64 | KVM_REG_ARM64_SVE | KVM_REG_SIZE_U512 | 0xffff)
#define KVM_ARM64_SVE_VLS_WORDS ((KVM_ARM64_SVE_VQ_MAX - KVM_ARM64_SVE_VQ_MIN) / 64 + 1)
#define KVM_REG_ARM_FW_FEAT_BMAP (0x0016 << KVM_REG_ARM_COPROC_SHIFT)
#define KVM_REG_ARM_FW_FEAT_BMAP_REG(r) (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW_FEAT_BMAP | ((r) & 0xffff))
#define KVM_REG_ARM_STD_BMAP KVM_REG_ARM_FW_FEAT_BMAP_REG(0)
enum {
  KVM_REG_ARM_STD_BIT_TRNG_V1_0 = 0,
};
#define KVM_REG_ARM_STD_HYP_BMAP KVM_REG_ARM_FW_FEAT_BMAP_REG(1)
enum {
  KVM_REG_ARM_STD_HYP_BIT_PV_TIME = 0,
};
#define KVM_REG_ARM_VENDOR_HYP_BMAP KVM_REG_ARM_FW_FEAT_BMAP_REG(2)
enum {
  KVM_REG_ARM_VENDOR_HYP_BIT_FUNC_FEAT = 0,
  KVM_REG_ARM_VENDOR_HYP_BIT_PTP = 1,
};
#define KVM_ARM_VM_SMCCC_CTRL 0
#define KVM_ARM_VM_SMCCC_FILTER 0
#define KVM_DEV_ARM_VGIC_GRP_ADDR 0
#define KVM_DEV_ARM_VGIC_GRP_DIST_REGS 1
#define KVM_DEV_ARM_VGIC_GRP_CPU_REGS 2
#define KVM_DEV_ARM_VGIC_CPUID_SHIFT 32
#define KVM_DEV_ARM_VGIC_CPUID_MASK (0xffULL << KVM_DEV_ARM_VGIC_CPUID_SHIFT)
#define KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT 32
#define KVM_DEV_ARM_VGIC_V3_MPIDR_MASK (0xffffffffULL << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT)
#define KVM_DEV_ARM_VGIC_OFFSET_SHIFT 0
#define KVM_DEV_ARM_VGIC_OFFSET_MASK (0xffffffffULL << KVM_DEV_ARM_VGIC_OFFSET_SHIFT)
#define KVM_DEV_ARM_VGIC_SYSREG_INSTR_MASK (0xffff)
#define KVM_DEV_ARM_VGIC_GRP_NR_IRQS 3
#define KVM_DEV_ARM_VGIC_GRP_CTRL 4
#define KVM_DEV_ARM_VGIC_GRP_REDIST_REGS 5
#define KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS 6
#define KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO 7
#define KVM_DEV_ARM_VGIC_GRP_ITS_REGS 8
#define KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT 10
#define KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_MASK (0x3fffffULL << KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT)
#define KVM_DEV_ARM_VGIC_LINE_LEVEL_INTID_MASK 0x3ff
#define VGIC_LEVEL_INFO_LINE_LEVEL 0
#define KVM_DEV_ARM_VGIC_CTRL_INIT 0
#define KVM_DEV_ARM_ITS_SAVE_TABLES 1
#define KVM_DEV_ARM_ITS_RESTORE_TABLES 2
#define KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES 3
#define KVM_DEV_ARM_ITS_CTRL_RESET 4
#define KVM_ARM_VCPU_PMU_V3_CTRL 0
#define KVM_ARM_VCPU_PMU_V3_IRQ 0
#define KVM_ARM_VCPU_PMU_V3_INIT 1
#define KVM_ARM_VCPU_PMU_V3_FILTER 2
#define KVM_ARM_VCPU_PMU_V3_SET_PMU 3
#define KVM_ARM_VCPU_TIMER_CTRL 1
#define KVM_ARM_VCPU_TIMER_IRQ_VTIMER 0
#define KVM_ARM_VCPU_TIMER_IRQ_PTIMER 1
#define KVM_ARM_VCPU_TIMER_IRQ_HVTIMER 2
#define KVM_ARM_VCPU_TIMER_IRQ_HPTIMER 3
#define KVM_ARM_VCPU_PVTIME_CTRL 2
#define KVM_ARM_VCPU_PVTIME_IPA 0
#define KVM_ARM_IRQ_VCPU2_SHIFT 28
#define KVM_ARM_IRQ_VCPU2_MASK 0xf
#define KVM_ARM_IRQ_TYPE_SHIFT 24
#define KVM_ARM_IRQ_TYPE_MASK 0xf
#define KVM_ARM_IRQ_VCPU_SHIFT 16
#define KVM_ARM_IRQ_VCPU_MASK 0xff
#define KVM_ARM_IRQ_NUM_SHIFT 0
#define KVM_ARM_IRQ_NUM_MASK 0xffff
#define KVM_ARM_IRQ_TYPE_CPU 0
#define KVM_ARM_IRQ_TYPE_SPI 1
#define KVM_ARM_IRQ_TYPE_PPI 2
#define KVM_ARM_IRQ_CPU_IRQ 0
#define KVM_ARM_IRQ_CPU_FIQ 1
#define KVM_ARM_IRQ_GIC_MAX 127
#define KVM_NR_IRQCHIPS 1
#define KVM_PSCI_FN_BASE 0x95c1ba5e
#define KVM_PSCI_FN(n) (KVM_PSCI_FN_BASE + (n))
#define KVM_PSCI_FN_CPU_SUSPEND KVM_PSCI_FN(0)
#define KVM_PSCI_FN_CPU_OFF KVM_PSCI_FN(1)
#define KVM_PSCI_FN_CPU_ON KVM_PSCI_FN(2)
#define KVM_PSCI_FN_MIGRATE KVM_PSCI_FN(3)
#define KVM_PSCI_RET_SUCCESS PSCI_RET_SUCCESS
#define KVM_PSCI_RET_NI PSCI_RET_NOT_SUPPORTED
#define KVM_PSCI_RET_INVAL PSCI_RET_INVALID_PARAMS
#define KVM_PSCI_RET_DENIED PSCI_RET_DENIED
#define KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2 (1ULL << 0)
#define KVM_EXIT_FAIL_ENTRY_CPU_UNSUPPORTED (1ULL << 0)
enum kvm_smccc_filter_action {
  KVM_SMCCC_FILTER_HANDLE = 0,
  KVM_SMCCC_FILTER_DENY,
  KVM_SMCCC_FILTER_FWD_TO_USER,
};
struct kvm_smccc_filter {
  __u32 base;
  __u32 nr_functions;
  __u8 action;
  __u8 pad[15];
};
#define KVM_HYPERCALL_EXIT_SMC (1U << 0)
#define KVM_HYPERCALL_EXIT_16BIT (1U << 1)
#define KVM_ARM_FEATURE_ID_RANGE_IDX(op0,op1,crn,crm,op2) ({ __u64 __op1 = (op1) & 3; __op1 -= (__op1 == 3); (__op1 << 6 | ((crm) & 7) << 3 | (op2)); })
#define KVM_ARM_FEATURE_ID_RANGE 0
#define KVM_ARM_FEATURE_ID_RANGE_SIZE (3 * 8 * 8)
struct reg_mask_range {
  __u64 addr;
  __u32 range;
  __u32 reserved[13];
};
#endif
#endif

"""

```