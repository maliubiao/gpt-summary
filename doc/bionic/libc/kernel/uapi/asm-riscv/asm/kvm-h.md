Response:
Let's break down the thought process for answering the request about the `kvm.handroid` header file.

**1. Understanding the Context:**

The first and most crucial step is to understand *what* this file is and *where* it comes from. The prompt clearly states:

* **Location:** `bionic/libc/kernel/uapi/asm-riscv/asm/kvm.handroid`
* **Purpose:** Part of Android's Bionic library, specifically related to the kernel's userspace API (`uapi`) for RISC-V architecture and the KVM (Kernel Virtual Machine).

This tells us several important things:

* **Low-level:** This isn't application-level code. It's about interacting directly with the kernel's virtualization features.
* **RISC-V specific:** The content will be tailored to the RISC-V architecture.
* **KVM related:**  The focus is on how userspace (like a virtual machine monitor) can control and interact with KVM on a RISC-V system.
* **Auto-generated:**  Modifications should be avoided, suggesting it reflects the kernel's internal structures.

**2. Initial Scan for Key Information:**

Next, I'd quickly scan the file for prominent keywords and structures. I'd be looking for things like:

* **`struct` definitions:** These are data structures used to pass information between userspace and the kernel. `kvm_regs`, `kvm_fpu`, `kvm_riscv_config`, `kvm_riscv_core`, `kvm_riscv_csr`, `kvm_riscv_timer`, etc., immediately stand out.
* **`#define` macros:** These often define constants, flags, or helper functions. `KVM_COALESCED_MMIO_PAGE_OFFSET`, `KVM_INTERRUPT_SET`, `KVM_REG_RISCV_TYPE_MASK`, and the various `KVM_REG_RISCV_*` definitions are important.
* **`enum` definitions:** These define sets of named constants, like the `KVM_RISCV_ISA_EXT_ID` and `KVM_RISCV_SBI_EXT_ID`.

**3. Categorizing the Functionality:**

Based on the identified structures and macros, I'd start to categorize the file's functionality. The prominent themes are:

* **CPU State Management:**  Structures like `kvm_regs`, `kvm_fpu`, `kvm_sregs`, `kvm_riscv_core`, and `kvm_riscv_csr` clearly relate to managing the state of virtual CPUs (registers, floating-point unit, control and status registers).
* **RISC-V Specific Configuration:** The `kvm_riscv_config` structure and the `KVM_RISCV_ISA_EXT_ID` enum deal with the specific features and extensions of the RISC-V architecture that KVM needs to be aware of.
* **SBI (Supervisor Binary Interface):** The `KVM_RISCV_SBI_EXT_ID` enum and `kvm_riscv_sbi_sta` structure point to interactions with the SBI, which is a standard interface between the hypervisor and the guest OS.
* **Interrupts:**  The definitions related to `KVM_INTERRUPT_SET`, `KVM_INTERRUPT_UNSET`, and the AIA (Advanced Interrupt Architecture) related structures (`kvm_riscv_aia_csr`, `KVM_DEV_RISCV_APLIC_*`, `KVM_DEV_RISCV_IMSIC_*`) indicate functionality for managing interrupts in the virtualized environment.
* **Timers:** The `kvm_riscv_timer` structure is responsible for managing the virtual timer for the guest.
* **Register Access:** The `KVM_REG_RISCV_*` macros provide a structured way to identify and access different registers and configuration parameters.

**4. Connecting to Android:**

The prompt specifically asks about the connection to Android. The key here is understanding that Android can run virtual machines (e.g., using the built-in virtualization framework or third-party apps). This header file provides the *interface* for the Android kernel to support RISC-V virtualization using KVM. Examples of how Android might use this:

* **Running Android in a VM:**  While less common on physical Android devices, this header would be essential if Android itself were running as a guest OS under a hypervisor.
* **Running other operating systems in VMs on Android:**  Android devices (or emulators) can host VMs running other OSes. This header provides the low-level KVM interface for such VMs.
* **Containerization technologies:** Although not directly KVM, container runtimes might leverage some of the underlying kernel features related to virtualization.

**5. Explaining libc Functions (Tricky Part):**

The prompt asks to explain the implementation of each libc function. This is where careful reading and understanding of the file's nature are crucial. **This header file *itself* does *not* contain libc function implementations.** It defines *data structures and constants* used by the kernel and by userspace programs (like VM monitors) that interact with the kernel via system calls.

Therefore, the explanation needs to clarify this distinction. The "libc functions" being *used* are the *system calls* that would use the structures defined in this header to communicate with the KVM kernel module. Examples include `ioctl()` with specific KVM request codes.

**6. Dynamic Linker and SO Layout (Not Directly Applicable):**

The prompt asks about the dynamic linker. This header file is a kernel header, not a userspace library. It doesn't directly involve the dynamic linker's operation in the way a shared library (`.so`) would.

The explanation should state this clearly. While the KVM module *is* part of the kernel, which is linked, this header focuses on the *userspace interface* to that kernel functionality.

**7. Logical Reasoning and Examples:**

For logical reasoning, consider how the different parts of the header relate to each other. For example, how the `KVM_REG_RISCV_*` macros are used to identify specific registers within the `kvm_regs` or `kvm_csr` structures. A simple example would be showing how to construct the ID for a specific CSR.

For user errors, focus on misuse of the KVM API. This might involve:

* Incorrectly setting register values.
* Trying to access features not supported by the underlying hardware or KVM implementation.
* Not handling KVM errors properly.

**8. Android Framework/NDK to Kernel:**

This part requires explaining the path from higher-level Android components to the low-level kernel interface. The general flow is:

* **Android Framework/NDK:**  Applications or NDK modules might use APIs related to virtualization (though direct KVM access from apps is less common for security reasons).
* **System Services:** Framework components might interact with system services responsible for managing VMs.
* **Binder:** Communication between processes often uses Binder.
* **System Calls:** Ultimately, interacting with the kernel (like KVM) involves making system calls. The structures defined in this header are used in the arguments of these system calls (often `ioctl`).

**9. Frida Hook Example:**

A Frida hook example should target the system calls that would interact with KVM. Since `ioctl` is a common way to interact with device drivers, hooking `ioctl` and filtering for KVM-related file descriptors and request codes would be a good starting point. The example should demonstrate how to inspect the arguments (which would include structures defined in `kvm.handroid`).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file contains some inline assembly or helper functions.
* **Correction:**  Realizing it's a `uapi` header, the focus is on *declarations* and *definitions* for userspace, not implementations.
* **Initial thought:** Directly explain libc function implementations.
* **Correction:** Realizing the file defines structures, the explanation needs to focus on the *system calls* that *use* these structures, not standard libc functions.
* **Ensuring clarity:** Double-checking that the explanation clearly distinguishes between userspace and kernel space, and the role of this header file as an interface.

By following this thought process, which involves understanding the context, identifying key information, categorizing functionality, and carefully considering the relationships between different components, a comprehensive and accurate answer can be constructed.
这是一个定义了 Linux KVM (Kernel-based Virtual Machine) 中 RISC-V 架构特定结构的头文件。它位于 Android Bionic 库的内核头文件路径下，这意味着 Android 系统在需要与 RISC-V 虚拟化硬件进行交互时会使用到这些定义。

**功能列举:**

该头文件主要定义了以下功能相关的结构体、枚举和宏：

1. **虚拟机寄存器状态:**
   - `struct kvm_regs`:  定义了通用寄存器的状态。虽然在这个文件中为空，但通常会包含 RISC-V 的通用寄存器信息（例如 x0-x31）。
   - `struct kvm_fpu`: 定义了浮点寄存器的状态。在这个文件中为空，但在实际实现中会包含浮点寄存器信息。
   - `struct user_regs_struct`:  通常用于表示用户态的寄存器状态，被包含在 `kvm_riscv_core` 中。
   - `struct kvm_sync_regs`: 用于同步寄存器状态。
   - `struct kvm_sregs`:  用于表示特殊的系统寄存器状态。

2. **RISC-V 特有配置:**
   - `struct kvm_riscv_config`:  定义了 RISC-V 架构的配置信息，例如 ISA (指令集架构) 扩展、缓存块大小、厂商 ID 等。这使得 KVM 能够了解 Guest 虚拟机的 RISC-V 硬件特性。
   - `enum KVM_RISCV_ISA_EXT_ID`:  枚举了各种 RISC-V ISA 扩展，如原子操作 (A)、压缩指令 (C)、双精度浮点 (D) 等。KVM 可以使用这些信息来确定 Guest 虚拟机支持哪些指令集。

3. **RISC-V 核心状态:**
   - `struct kvm_riscv_core`: 定义了 RISC-V 核心的状态，包括通用寄存器 (`regs`) 和当前运行模式 (`mode`) (例如 Supervisor 模式或 User 模式)。

4. **RISC-V 控制和状态寄存器 (CSR):**
   - `struct kvm_riscv_csr`: 定义了 RISC-V 的控制和状态寄存器，如状态寄存器 (sstatus)、中断使能 (sie)、陷入向量基址寄存器 (stvec) 等。这些寄存器控制着处理器的行为和状态。
   - `struct kvm_riscv_aia_csr`: 定义了与 AIA (Advanced Interrupt Architecture) 相关的 CSR，用于更精细的中断管理。
   - `struct kvm_riscv_smstateen_csr`: 定义了用于管理状态机状态使能的 CSR。

5. **RISC-V 定时器:**
   - `struct kvm_riscv_timer`: 定义了 Guest 虚拟机的定时器状态，包括频率、当前时间和比较值。这允许 KVM 模拟硬件定时器。

6. **SBI (Supervisor Binary Interface) 支持:**
   - `enum KVM_RISCV_SBI_EXT_ID`: 枚举了支持的 SBI 扩展，SBI 是 hypervisor 和 Guest OS 之间的标准接口。
   - `struct kvm_riscv_sbi_sta`: 定义了 SBI 特定的状态信息。

7. **中断控制:**
   - `#define KVM_INTERRUPT_SET`, `#define KVM_INTERRUPT_UNSET`: 定义了设置和取消中断的常量。
   - 与 `KVM_DEV_RISCV_APLIC_*` 和 `KVM_DEV_RISCV_IMSIC_*` 相关的宏定义了与 RISC-V 的 APLIC (Advanced PLIC) 和 IMSIC (Interrupt Manager for Single Core) 中断控制器交互的常量和结构。

8. **寄存器访问宏:**
   - `KVM_REG_SIZE`, `KVM_REG_RISCV_TYPE_MASK` 等宏定义了用于访问和操作虚拟机寄存器的位掩码和偏移量。这提供了一种结构化的方式来访问不同类型的寄存器 (例如通用寄存器、CSR、浮点寄存器)。

**与 Android 功能的关系及举例:**

这个头文件直接关系到 Android 系统作为 Hypervisor 运行 RISC-V 虚拟机的能力。

**举例说明:**

* **运行 Android Emulator (模拟器):** 当你在 x86 或 ARM 架构的机器上运行 Android Emulator 并选择模拟 RISC-V 架构时，底层的虚拟化技术 (很可能基于 KVM) 会使用到这些定义。例如，当模拟器需要设置 Guest 虚拟机的某个 CSR 寄存器的值时，会使用到 `struct kvm_riscv_csr` 中的字段定义。
* **容器化技术 (如在 Android 上运行容器):** 虽然不是直接的 KVM，但某些容器化技术也可能利用 Linux 内核的虚拟化特性。如果容器内部模拟了一个简单的 RISC-V 环境，这个头文件中的定义可能会被相关的底层库使用。
* **未来 Android 设备支持 RISC-V 虚拟化:** 如果未来的 Android 设备采用 RISC-V 架构并需要支持运行其他操作系统或虚拟机，这个头文件将是关键的组成部分。

**libc 函数的功能实现:**

这个头文件本身 **不包含 libc 函数的实现**。它定义的是内核 KVM 接口的数据结构。userspace 程序 (如虚拟机管理器) 会使用系统调用 (如 `ioctl`) 与内核 KVM 模块进行交互，传递或获取与这些结构体相关的信息。

例如，一个虚拟机管理器可能需要设置 Guest 虚拟机的程序计数器 (PC)。它会构造一个包含目标 PC 值的 `kvm_regs` 结构体，然后通过 `ioctl` 系统调用，并使用特定的 KVM 请求码 (未在此头文件中定义，而是在 `linux/kvm.h` 中)，将这个结构体传递给内核。内核 KVM 模块会解析这个结构体，并更新 Guest 虚拟机的相应状态。

**涉及 dynamic linker 的功能:**

这个头文件 **不直接涉及 dynamic linker 的功能**。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责加载和链接共享库 (`.so` 文件)。这个头文件定义的是内核接口，与 userspace 程序的链接过程是不同的层面。

**so 布局样本及链接处理过程 (不适用):**

由于这个头文件不涉及 dynamic linker，因此没有相关的 `.so` 布局样本或链接处理过程需要说明。

**逻辑推理、假设输入与输出:**

假设一个虚拟机管理器想要读取 Guest 虚拟机的 `sstatus` 寄存器的值。

**假设输入:**

1. 一个打开的 KVM 设备文件描述符 (`fd`).
2. 指定目标 vCPU 的 ID。
3. 表示要读取 `sstatus` 寄存器的请求。这通常是通过一个 KVM 定义的宏 (例如 `KVM_GET_ONE_REG`) 和一个表示 `sstatus` 寄存器的 ID (基于 `KVM_REG_RISCV_CSR_REG(sstatus)`) 来实现的。

**处理过程:**

1. 虚拟机管理器会构造一个 `kvm_one_reg` 结构体 (这个结构体定义在 `linux/kvm.h` 中，不是此文件)，其中包含 vCPU ID 和 `sstatus` 寄存器的 ID。
2. 调用 `ioctl(fd, KVM_GET_ONE_REG, &one_reg)`。

**假设输出:**

1. `ioctl` 调用成功返回 0。
2. `one_reg.val` 字段中包含了 Guest 虚拟机 `sstatus` 寄存器的值。

**用户或编程常见的使用错误:**

1. **类型不匹配:** 传递给 `ioctl` 的数据结构大小或类型与内核期望的不符，可能导致内核崩溃或数据损坏。例如，错误地将一个 `unsigned int` 的值赋给一个需要 `unsigned long` 的字段。
2. **寄存器 ID 错误:** 使用了错误的寄存器 ID 尝试访问寄存器，可能导致 `ioctl` 调用失败。
3. **权限问题:** 尝试访问需要特权才能访问的寄存器或功能，如果没有足够的权限，`ioctl` 调用会失败。
4. **未检查返回值:** 没有检查 `ioctl` 的返回值，可能导致程序在操作失败后继续执行，产生不可预测的结果。
5. **并发访问问题:**  在多线程或多进程环境下，如果多个实体同时尝试修改同一个 Guest 虚拟机的状态，可能会导致数据竞争和不一致性。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**  如果开发者使用 NDK 编写需要直接与 KVM 交互的应用 (这种情况比较少见，因为通常虚拟机管理是由系统服务处理的)，他们可能会直接包含这些头文件，并使用 `ioctl` 系统调用。
2. **Android Framework 的虚拟机管理服务:** Android Framework 中负责虚拟机管理 (例如 `VirtualizationService`) 的系统服务可能会使用到这些定义。这些服务通常是用 Java 或 C++ 编写的。
3. **JNI 调用:** 如果 Framework 的 Java 代码需要与底层的 C++ 代码交互 (例如，调用 Native 代码来配置虚拟机)，会使用 JNI (Java Native Interface)。
4. **系统调用:**  最终，无论是 NDK 应用还是 Framework 服务，与 KVM 的交互都需要通过系统调用 `ioctl` 来完成。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook 调试与 KVM 交互的步骤示例，假设我们想观察虚拟机管理器在设置 Guest 虚拟机的 `sstatus` 寄存器时传递的数据：

```javascript
// 连接到目标进程 (虚拟机管理器进程)
const processName = "com.example.virtualmachinemanager"; // 替换为实际进程名
const session = await frida.attach(processName);

// 监听 ioctl 系统调用
const ioctlPtr = Module.findExportByName(null, "ioctl");

Interceptor.attach(ioctlPtr, {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    // 假设 KVM 相关的 ioctl 请求码通常是正数且比较大
    if (request > 0x4000 && request < 0xC000) {
      console.log("ioctl called with fd:", fd, "request:", request);

      // 检查是否是设置寄存器的请求 (假设 KVM_SET_ONE_REG 是相关的请求码)
      const KVM_SET_ONE_REG = 0xAE82; // 替换为实际的请求码
      if (request === KVM_SET_ONE_REG) {
        // 读取 kvm_one_reg 结构体 (假设其定义与内核一致)
        const kvm_one_reg_ptr = argp;
        const cpu_id = kvm_one_reg_ptr.readU64();
        const reg_id = kvm_one_reg_ptr.add(8).readU64();
        const val = kvm_one_reg_ptr.add(16).readU64();

        // 检查是否是 sstatus 寄存器 (假设 KVM_REG_RISCV_CSR 和 KVM_REG_RISCV_CSR_REG(sstatus) 是正确的值)
        const KVM_REG_RISCV_CSR = 0x03000000; // 替换为实际值
        const SSTATUS_OFFSET = 0; // 替换为 offsetof(struct kvm_riscv_csr, sstatus) / sizeof(unsigned long) 的值
        const SSTATUS_REG_ID = KVM_REG_RISCV_CSR | (SSTATUS_OFFSET << 16);

        if (reg_id.equals(ptr(SSTATUS_REG_ID))) {
          console.log("Setting sstatus register of CPU:", cpu_id, "to:", val.toString(16));
          // 你可以进一步检查 val 的值，看是否符合预期
        }
      }
    }
  },
});
```

**解释 Frida Hook 代码:**

1. **`frida.attach(processName)`:** 连接到目标虚拟机管理器进程。
2. **`Module.findExportByName(null, "ioctl")`:** 找到 `ioctl` 系统调用的地址。
3. **`Interceptor.attach(ioctlPtr, { ... })`:**  拦截 `ioctl` 函数的调用。
4. **`onEnter`:**  在 `ioctl` 函数执行前被调用。
5. **参数解析:**  获取 `ioctl` 的文件描述符 (`fd`)、请求码 (`request`) 和参数指针 (`argp`).
6. **过滤 KVM 请求:**  通过简单的范围判断来初步筛选可能是 KVM 相关的 `ioctl` 调用。你需要根据实际情况调整过滤条件。
7. **特定请求码检查:**  检查 `request` 是否是设置寄存器的请求码 (你需要查找内核头文件或 KVM 文档来获取正确的请求码，这里假设是 `KVM_SET_ONE_REG`)。
8. **读取数据结构:**  根据 `kvm_one_reg` 结构体的布局，从 `argp` 指针读取 CPU ID、寄存器 ID 和要设置的值。
9. **检查目标寄存器:**  判断要设置的寄存器是否是 `sstatus` 寄存器。你需要根据 `KVM_REG_RISCV_CSR` 和 `KVM_REG_RISCV_CSR_REG(sstatus)` 的实际值来构建正确的 `reg_id`。
10. **打印信息:**  如果满足条件，则打印出设置 `sstatus` 寄存器的相关信息。

**注意:**

* 上述 Frida Hook 代码只是一个示例，你需要根据实际的 KVM 请求码、数据结构布局和你的调试目标进行调整。
* 你需要了解 KVM 相关的 `ioctl` 请求码和数据结构定义 (通常在 `linux/kvm.h` 中)。
* 调试内核相关的操作可能需要 root 权限。

通过 Frida Hook，你可以动态地观察 userspace 程序如何与内核 KVM 模块交互，从而更好地理解 Android 系统中虚拟化的工作原理。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-riscv/asm/kvm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_KVM_RISCV_H
#define __LINUX_KVM_RISCV_H
#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <asm/bitsperlong.h>
#include <asm/ptrace.h>
#define __KVM_HAVE_IRQ_LINE
#define KVM_COALESCED_MMIO_PAGE_OFFSET 1
#define KVM_INTERRUPT_SET - 1U
#define KVM_INTERRUPT_UNSET - 2U
struct kvm_regs {
};
struct kvm_fpu {
};
struct kvm_debug_exit_arch {
};
struct kvm_guest_debug_arch {
};
struct kvm_sync_regs {
};
struct kvm_sregs {
};
struct kvm_riscv_config {
  unsigned long isa;
  unsigned long zicbom_block_size;
  unsigned long mvendorid;
  unsigned long marchid;
  unsigned long mimpid;
  unsigned long zicboz_block_size;
  unsigned long satp_mode;
};
struct kvm_riscv_core {
  struct user_regs_struct regs;
  unsigned long mode;
};
#define KVM_RISCV_MODE_S 1
#define KVM_RISCV_MODE_U 0
struct kvm_riscv_csr {
  unsigned long sstatus;
  unsigned long sie;
  unsigned long stvec;
  unsigned long sscratch;
  unsigned long sepc;
  unsigned long scause;
  unsigned long stval;
  unsigned long sip;
  unsigned long satp;
  unsigned long scounteren;
  unsigned long senvcfg;
};
struct kvm_riscv_aia_csr {
  unsigned long siselect;
  unsigned long iprio1;
  unsigned long iprio2;
  unsigned long sieh;
  unsigned long siph;
  unsigned long iprio1h;
  unsigned long iprio2h;
};
struct kvm_riscv_smstateen_csr {
  unsigned long sstateen0;
};
struct kvm_riscv_timer {
  __u64 frequency;
  __u64 time;
  __u64 compare;
  __u64 state;
};
enum KVM_RISCV_ISA_EXT_ID {
  KVM_RISCV_ISA_EXT_A = 0,
  KVM_RISCV_ISA_EXT_C,
  KVM_RISCV_ISA_EXT_D,
  KVM_RISCV_ISA_EXT_F,
  KVM_RISCV_ISA_EXT_H,
  KVM_RISCV_ISA_EXT_I,
  KVM_RISCV_ISA_EXT_M,
  KVM_RISCV_ISA_EXT_SVPBMT,
  KVM_RISCV_ISA_EXT_SSTC,
  KVM_RISCV_ISA_EXT_SVINVAL,
  KVM_RISCV_ISA_EXT_ZIHINTPAUSE,
  KVM_RISCV_ISA_EXT_ZICBOM,
  KVM_RISCV_ISA_EXT_ZICBOZ,
  KVM_RISCV_ISA_EXT_ZBB,
  KVM_RISCV_ISA_EXT_SSAIA,
  KVM_RISCV_ISA_EXT_V,
  KVM_RISCV_ISA_EXT_SVNAPOT,
  KVM_RISCV_ISA_EXT_ZBA,
  KVM_RISCV_ISA_EXT_ZBS,
  KVM_RISCV_ISA_EXT_ZICNTR,
  KVM_RISCV_ISA_EXT_ZICSR,
  KVM_RISCV_ISA_EXT_ZIFENCEI,
  KVM_RISCV_ISA_EXT_ZIHPM,
  KVM_RISCV_ISA_EXT_SMSTATEEN,
  KVM_RISCV_ISA_EXT_ZICOND,
  KVM_RISCV_ISA_EXT_ZBC,
  KVM_RISCV_ISA_EXT_ZBKB,
  KVM_RISCV_ISA_EXT_ZBKC,
  KVM_RISCV_ISA_EXT_ZBKX,
  KVM_RISCV_ISA_EXT_ZKND,
  KVM_RISCV_ISA_EXT_ZKNE,
  KVM_RISCV_ISA_EXT_ZKNH,
  KVM_RISCV_ISA_EXT_ZKR,
  KVM_RISCV_ISA_EXT_ZKSED,
  KVM_RISCV_ISA_EXT_ZKSH,
  KVM_RISCV_ISA_EXT_ZKT,
  KVM_RISCV_ISA_EXT_ZVBB,
  KVM_RISCV_ISA_EXT_ZVBC,
  KVM_RISCV_ISA_EXT_ZVKB,
  KVM_RISCV_ISA_EXT_ZVKG,
  KVM_RISCV_ISA_EXT_ZVKNED,
  KVM_RISCV_ISA_EXT_ZVKNHA,
  KVM_RISCV_ISA_EXT_ZVKNHB,
  KVM_RISCV_ISA_EXT_ZVKSED,
  KVM_RISCV_ISA_EXT_ZVKSH,
  KVM_RISCV_ISA_EXT_ZVKT,
  KVM_RISCV_ISA_EXT_ZFH,
  KVM_RISCV_ISA_EXT_ZFHMIN,
  KVM_RISCV_ISA_EXT_ZIHINTNTL,
  KVM_RISCV_ISA_EXT_ZVFH,
  KVM_RISCV_ISA_EXT_ZVFHMIN,
  KVM_RISCV_ISA_EXT_ZFA,
  KVM_RISCV_ISA_EXT_ZTSO,
  KVM_RISCV_ISA_EXT_ZACAS,
  KVM_RISCV_ISA_EXT_SSCOFPMF,
  KVM_RISCV_ISA_EXT_ZIMOP,
  KVM_RISCV_ISA_EXT_ZCA,
  KVM_RISCV_ISA_EXT_ZCB,
  KVM_RISCV_ISA_EXT_ZCD,
  KVM_RISCV_ISA_EXT_ZCF,
  KVM_RISCV_ISA_EXT_ZCMOP,
  KVM_RISCV_ISA_EXT_ZAWRS,
  KVM_RISCV_ISA_EXT_MAX,
};
enum KVM_RISCV_SBI_EXT_ID {
  KVM_RISCV_SBI_EXT_V01 = 0,
  KVM_RISCV_SBI_EXT_TIME,
  KVM_RISCV_SBI_EXT_IPI,
  KVM_RISCV_SBI_EXT_RFENCE,
  KVM_RISCV_SBI_EXT_SRST,
  KVM_RISCV_SBI_EXT_HSM,
  KVM_RISCV_SBI_EXT_PMU,
  KVM_RISCV_SBI_EXT_EXPERIMENTAL,
  KVM_RISCV_SBI_EXT_VENDOR,
  KVM_RISCV_SBI_EXT_DBCN,
  KVM_RISCV_SBI_EXT_STA,
  KVM_RISCV_SBI_EXT_MAX,
};
struct kvm_riscv_sbi_sta {
  unsigned long shmem_lo;
  unsigned long shmem_hi;
};
#define KVM_RISCV_TIMER_STATE_OFF 0
#define KVM_RISCV_TIMER_STATE_ON 1
#define KVM_REG_SIZE(id) (1U << (((id) & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT))
#define KVM_REG_RISCV_TYPE_MASK 0x00000000FF000000
#define KVM_REG_RISCV_TYPE_SHIFT 24
#define KVM_REG_RISCV_SUBTYPE_MASK 0x0000000000FF0000
#define KVM_REG_RISCV_SUBTYPE_SHIFT 16
#define KVM_REG_RISCV_CONFIG (0x01 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_CONFIG_REG(name) (offsetof(struct kvm_riscv_config, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_CORE (0x02 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_CORE_REG(name) (offsetof(struct kvm_riscv_core, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_CSR (0x03 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_CSR_GENERAL (0x0 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_CSR_AIA (0x1 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_CSR_SMSTATEEN (0x2 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_CSR_REG(name) (offsetof(struct kvm_riscv_csr, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_CSR_AIA_REG(name) (offsetof(struct kvm_riscv_aia_csr, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_CSR_SMSTATEEN_REG(name) (offsetof(struct kvm_riscv_smstateen_csr, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_TIMER (0x04 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_TIMER_REG(name) (offsetof(struct kvm_riscv_timer, name) / sizeof(__u64))
#define KVM_REG_RISCV_FP_F (0x05 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_FP_F_REG(name) (offsetof(struct __riscv_f_ext_state, name) / sizeof(__u32))
#define KVM_REG_RISCV_FP_D (0x06 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_FP_D_REG(name) (offsetof(struct __riscv_d_ext_state, name) / sizeof(__u64))
#define KVM_REG_RISCV_ISA_EXT (0x07 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_ISA_SINGLE (0x0 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_ISA_MULTI_EN (0x1 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_ISA_MULTI_DIS (0x2 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_ISA_MULTI_REG(__ext_id) ((__ext_id) / __BITS_PER_LONG)
#define KVM_REG_RISCV_ISA_MULTI_MASK(__ext_id) (1UL << ((__ext_id) % __BITS_PER_LONG))
#define KVM_REG_RISCV_ISA_MULTI_REG_LAST KVM_REG_RISCV_ISA_MULTI_REG(KVM_RISCV_ISA_EXT_MAX - 1)
#define KVM_REG_RISCV_SBI_EXT (0x08 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_SBI_SINGLE (0x0 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_SBI_MULTI_EN (0x1 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_SBI_MULTI_DIS (0x2 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_SBI_MULTI_REG(__ext_id) ((__ext_id) / __BITS_PER_LONG)
#define KVM_REG_RISCV_SBI_MULTI_MASK(__ext_id) (1UL << ((__ext_id) % __BITS_PER_LONG))
#define KVM_REG_RISCV_SBI_MULTI_REG_LAST KVM_REG_RISCV_SBI_MULTI_REG(KVM_RISCV_SBI_EXT_MAX - 1)
#define KVM_REG_RISCV_VECTOR (0x09 << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_VECTOR_CSR_REG(name) (offsetof(struct __riscv_v_ext_state, name) / sizeof(unsigned long))
#define KVM_REG_RISCV_VECTOR_REG(n) ((n) + sizeof(struct __riscv_v_ext_state) / sizeof(unsigned long))
#define KVM_REG_RISCV_SBI_STATE (0x0a << KVM_REG_RISCV_TYPE_SHIFT)
#define KVM_REG_RISCV_SBI_STA (0x0 << KVM_REG_RISCV_SUBTYPE_SHIFT)
#define KVM_REG_RISCV_SBI_STA_REG(name) (offsetof(struct kvm_riscv_sbi_sta, name) / sizeof(unsigned long))
#define KVM_DEV_RISCV_APLIC_ALIGN 0x1000
#define KVM_DEV_RISCV_APLIC_SIZE 0x4000
#define KVM_DEV_RISCV_APLIC_MAX_HARTS 0x4000
#define KVM_DEV_RISCV_IMSIC_ALIGN 0x1000
#define KVM_DEV_RISCV_IMSIC_SIZE 0x1000
#define KVM_DEV_RISCV_AIA_GRP_CONFIG 0
#define KVM_DEV_RISCV_AIA_CONFIG_MODE 0
#define KVM_DEV_RISCV_AIA_CONFIG_IDS 1
#define KVM_DEV_RISCV_AIA_CONFIG_SRCS 2
#define KVM_DEV_RISCV_AIA_CONFIG_GROUP_BITS 3
#define KVM_DEV_RISCV_AIA_CONFIG_GROUP_SHIFT 4
#define KVM_DEV_RISCV_AIA_CONFIG_HART_BITS 5
#define KVM_DEV_RISCV_AIA_CONFIG_GUEST_BITS 6
#define KVM_DEV_RISCV_AIA_MODE_EMUL 0
#define KVM_DEV_RISCV_AIA_MODE_HWACCEL 1
#define KVM_DEV_RISCV_AIA_MODE_AUTO 2
#define KVM_DEV_RISCV_AIA_IDS_MIN 63
#define KVM_DEV_RISCV_AIA_IDS_MAX 2048
#define KVM_DEV_RISCV_AIA_SRCS_MAX 1024
#define KVM_DEV_RISCV_AIA_GROUP_BITS_MAX 8
#define KVM_DEV_RISCV_AIA_GROUP_SHIFT_MIN 24
#define KVM_DEV_RISCV_AIA_GROUP_SHIFT_MAX 56
#define KVM_DEV_RISCV_AIA_HART_BITS_MAX 16
#define KVM_DEV_RISCV_AIA_GUEST_BITS_MAX 8
#define KVM_DEV_RISCV_AIA_GRP_ADDR 1
#define KVM_DEV_RISCV_AIA_ADDR_APLIC 0
#define KVM_DEV_RISCV_AIA_ADDR_IMSIC(__vcpu) (1 + (__vcpu))
#define KVM_DEV_RISCV_AIA_ADDR_MAX (1 + KVM_DEV_RISCV_APLIC_MAX_HARTS)
#define KVM_DEV_RISCV_AIA_GRP_CTRL 2
#define KVM_DEV_RISCV_AIA_CTRL_INIT 0
#define KVM_DEV_RISCV_AIA_GRP_APLIC 3
#define KVM_DEV_RISCV_AIA_GRP_IMSIC 4
#define KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS 12
#define KVM_DEV_RISCV_AIA_IMSIC_ISEL_MASK ((1U << KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS) - 1)
#define KVM_DEV_RISCV_AIA_IMSIC_MKATTR(__vcpu,__isel) (((__vcpu) << KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS) | ((__isel) & KVM_DEV_RISCV_AIA_IMSIC_ISEL_MASK))
#define KVM_DEV_RISCV_AIA_IMSIC_GET_ISEL(__attr) ((__attr) & KVM_DEV_RISCV_AIA_IMSIC_ISEL_MASK)
#define KVM_DEV_RISCV_AIA_IMSIC_GET_VCPU(__attr) ((__attr) >> KVM_DEV_RISCV_AIA_IMSIC_ISEL_BITS)
#define KVM_NR_IRQCHIPS 1
#endif
#endif
```