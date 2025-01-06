Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided `kvm.handroid` header file and explain its purpose, relation to Android, function implementations (specifically libc and dynamic linker), potential usage errors, and how Android frameworks access it. The key is to break down this complex request into smaller, manageable parts.

2. **Identify the File's Nature:**  The header comment clearly states it's auto-generated and related to the Linux kernel's KVM (Kernel-based Virtual Machine) interface for x86 architecture. The path `bionic/libc/kernel/uapi/asm-x86/asm/kvm.handroid` confirms it's part of Android's Bionic library, specifically for interacting with the kernel's KVM functionality. The "uapi" indicates it's part of the user-kernel API.

3. **Extract Key Information:** I scanned the file for significant elements:
    * **Includes:**  `<linux/const.h>`, `<linux/bits.h>`, `<linux/types.h>`, `<linux/ioctl.h>`, `<linux/stddef.h>` – These point to the file's role in defining kernel interfaces.
    * **Defines:**  A large number of `#define` statements. These represent constants and macros used to interact with the KVM interface. I categorized them:
        * Offsets (`KVM_PIO_PAGE_OFFSET`, etc.)
        * Interrupt Vectors (`DE_VECTOR`, etc.)
        * Feature Flags (`__KVM_HAVE_PIT`, etc.)
        * Bitmasks and Flags (`KVM_RUN_X86_SMM`, `KVM_SREGS2_FLAGS_PDPTRS_VALID`, etc.)
        * Constants related to nested virtualization, security features (SEV), etc.
    * **Structs:** Definitions of various structures (`kvm_pic_state`, `kvm_ioapic_state`, `kvm_regs`, etc.). These structures represent the data exchanged between user-space and the kernel to control and monitor the virtual machine.
    * **Enums:**  The `sev_cmd_id` enum, defining commands for Secure Encrypted Virtualization.

4. **Determine the File's Functionality:** Based on the extracted information, the file's core function is to provide the necessary definitions (constants, data structures) for user-space programs (like the Android runtime or virtualization frameworks) to interact with the Linux kernel's KVM interface. It essentially defines the API for controlling and managing virtual machines.

5. **Address Android Relevance:**  I considered how KVM is used in Android. The primary connection is through the Android Emulator and potentially through containerization technologies (though less directly through *this* specific header). The emulator relies heavily on KVM for hardware virtualization to provide a performant environment for running Android on a host machine.

6. **Handle Libc and Dynamic Linker:**
    * **Libc:**  This header *itself* doesn't contain libc function *implementations*. It's a header file. However, the definitions it provides are used by libc functions (or functions in libraries built on top of libc) that *do* interact with the kernel via `ioctl` calls using the constants and structures defined here. I needed to explain this indirect relationship and illustrate with a hypothetical `ioctl` example.
    * **Dynamic Linker:** This header doesn't directly involve the dynamic linker. It's about kernel interfaces. However, libraries using these definitions would be linked dynamically. I needed to create a simple scenario to demonstrate the dynamic linking of a hypothetical library interacting with KVM.

7. **Consider Logic and Assumptions:**  Since it's a header file, direct "input and output" in the traditional sense doesn't apply. The "input" is the definition itself, and the "output" is the ability for other code to use those definitions. My assumption was that the user understands the basic concept of header files in C/C++.

8. **Identify Potential Usage Errors:**  Common mistakes when working with kernel interfaces like this include:
    * Incorrect `ioctl` numbers.
    * Incorrectly sized or formatted data structures.
    * Privilege issues (needing appropriate permissions to interact with `/dev/kvm`).

9. **Explain Android Framework Interaction:** I traced the path from the Android Framework down to this header file:
    * Framework (e.g., ActivityManager) might request the creation of an emulator instance.
    * This request goes down to the Android Runtime (ART).
    * ART or a dedicated virtualization service uses NDK libraries.
    * These NDK libraries make system calls (often involving `ioctl`) using the definitions in this header to interact with the `/dev/kvm` device.

10. **Provide Frida Hook Examples:** I designed Frida hooks to illustrate how one could intercept calls related to KVM, focusing on:
    * Opening the `/dev/kvm` device.
    * Making `ioctl` calls with KVM-related commands.
    * Potentially hooking functions that set up KVM structures.

11. **Structure and Language:** I organized the answer logically, using clear headings and bullet points. I used simplified language while still being technically accurate. I paid attention to phrasing to ensure the explanations were understandable to someone with some programming knowledge but perhaps less familiarity with kernel internals. The request specifically asked for a Chinese response, so all explanations were provided in Chinese.

**Self-Correction/Refinement during the process:**

* Initially, I considered diving deeper into the specifics of each struct member. However, given the sheer number of them, I decided to focus on the *purpose* of the structs and provide a few representative examples rather than a comprehensive breakdown.
* I realized the dynamic linker aspect was tangential but still needed to be addressed by demonstrating how a hypothetical KVM-interacting library would be linked.
* I made sure to emphasize that this header file *defines* interfaces, rather than *implementing* functions itself. This distinction is crucial for understanding its role.
* I kept the Frida examples relatively simple to demonstrate the core concept of hooking kernel interactions. More complex hooks could be created, but the goal was to provide a starting point.

By following these steps and iterating on my approach, I aimed to provide a comprehensive and understandable answer to the complex request.
这个目录 `bionic/libc/kernel/uapi/asm-x86/asm/kvm.handroid` 下的源代码文件 `kvm.handroid` 是 Android Bionic C 库中用于定义与 Linux 内核 KVM (Kernel-based Virtual Machine) 接口相关的常量、结构体和宏的文件。由于它位于 `uapi` 目录下，这意味着它定义了用户空间程序可以使用的应用程序接口 (API) 来与内核中的 KVM 模块进行交互。

**文件功能列表:**

1. **定义 KVM 相关的ioctl命令和参数:**  文件中定义了大量的宏，如 `KVM_PIO_PAGE_OFFSET`、`KVM_COALESCED_MMIO_PAGE_OFFSET` 等，这些很可能被用作 `ioctl` 系统调用的参数，用于控制和配置虚拟机。
2. **定义虚拟机异常和中断向量:**  `DE_VECTOR`, `DB_VECTOR` 等宏定义了虚拟机中发生的各种异常和中断的向量号。这些对于虚拟机监控器 (VMM) 处理虚拟机事件至关重要。
3. **声明 KVM 特性支持:** `__KVM_HAVE_PIT`, `__KVM_HAVE_IOAPIC` 等宏表示内核 KVM 模块支持的硬件特性，例如 Programmable Interval Timer (PIT), I/O Advanced Programmable Interrupt Controller (IOAPIC) 等。
4. **定义 KVM 内部状态的数据结构:** 文件中定义了大量的结构体，如 `kvm_pic_state`, `kvm_ioapic_state`, `kvm_regs`, `kvm_sregs` 等。这些结构体描述了虚拟机的各种硬件组件和寄存器的状态，用户空间程序可以通过这些结构体来读取或修改虚拟机的状态。
5. **定义 CPUID 相关结构:** `kvm_cpuid_entry`, `kvm_cpuid`, `kvm_cpuid_entry2`, `kvm_cpuid2` 等结构体用于获取和设置虚拟机所模拟的 CPU 的特性信息 (CPUID)。
6. **定义调试相关的结构:** `kvm_debug_exit_arch`, `kvm_guest_debug_arch`, `kvm_debugregs` 等结构体用于配置和获取虚拟机的调试信息，例如断点、寄存器值等。
7. **定义与安全加密虚拟化 (SEV) 相关的结构和枚举:**  文件中包含了 `kvm_sev_cmd` 以及 `kvm_sev_init`, `kvm_sev_launch_start` 等结构体，以及 `sev_cmd_id` 枚举，这些都与 AMD 的安全加密虚拟化技术有关，允许加密虚拟机内存。
8. **定义嵌套虚拟化相关的结构:**  `kvm_nested_state`, `kvm_vmx_nested_state_data`, `kvm_svm_nested_state_data` 等结构体与嵌套虚拟化技术相关，允许在一个虚拟机内运行另一个虚拟机。

**与 Android 功能的关系及举例:**

这个文件直接服务于 Android 操作系统中需要使用虚拟化技术的组件。最直接的例子是 **Android 模拟器 (Emulator)**。

* **Android 模拟器:**  Android 模拟器使用 KVM 来加速虚拟机的运行，提供接近原生设备的性能。模拟器通过 `/dev/kvm` 设备与内核中的 KVM 模块交互。这个文件定义的结构体和常量会被模拟器的代码使用，例如：
    * **创建虚拟机:** 模拟器可能会使用 `ioctl` 和 `KVM_CREATE_VM` 命令（虽然这个常量可能定义在其他 KVM 头文件中，但其交互的数据结构会受到这里定义的影响）来创建虚拟机实例。
    * **创建 VCPU:**  使用 `ioctl` 和 `KVM_CREATE_VCPU` 命令来创建虚拟 CPU，并使用 `kvm_regs` 和 `kvm_sregs` 结构体来设置 VCPU 的初始寄存器状态。
    * **内存管理:**  使用 `ioctl` 和相关的命令以及数据结构来为虚拟机分配和管理内存。
    * **设备模拟:**  文件中定义的 `kvm_pic_state` 和 `kvm_ioapic_state` 等结构体用于模拟 PIC 和 IOAPIC，这是模拟器中设备仿真的关键部分。
    * **安全虚拟化 (SEV):** 如果 Android 设备或运行环境支持 AMD SEV，模拟器可以使用这里定义的 `kvm_sev_cmd` 等结构体来利用硬件安全特性，例如加密虚拟机内存。

**libc 函数的功能实现:**

这个文件本身是头文件，并不包含 libc 函数的实现。它定义了与内核交互的数据结构。用户空间的程序（包括 libc 中的某些函数，或者基于 libc 构建的库）会使用这些定义来构建与内核 KVM 模块交互的数据。

例如，假设有一个 libc 函数或者 Android runtime 中的函数需要设置虚拟机的寄存器状态。它可能会执行以下步骤：

1. **打开 `/dev/kvm` 设备:** 使用 `open()` 系统调用打开 KVM 设备文件。
2. **创建虚拟机:** 使用 `ioctl()` 系统调用，并可能使用一个指向包含虚拟机配置信息的结构体的指针作为参数。
3. **创建 VCPU:** 使用 `ioctl()` 系统调用，并获取 VCPU 的文件描述符。
4. **设置寄存器:**
   * 声明一个 `kvm_regs` 结构体变量。
   * 填充这个结构体的成员，例如 `rax`, `rbx`, `rip` 等，设置所需的寄存器值。
   * 使用 `ioctl()` 系统调用，命令可能是 `KVM_SET_REGS`，并将指向填充好的 `kvm_regs` 结构体的指针作为参数传递给内核。

内核中的 KVM 模块会解析传递过来的 `kvm_regs` 结构体，并将这些值应用到相应的虚拟 CPU 上。

**dynamic linker 的功能和 so 布局样本及链接处理过程:**

这个头文件本身不直接涉及动态链接器的功能。动态链接器负责在程序启动时加载所需的共享库 (`.so` 文件) 并解析符号引用。

然而，如果某个 `.so` 库 (例如，模拟器使用的库) 需要与 KVM 交互，那么它会包含或依赖于使用了这个头文件中定义的结构体和常量的代码。

**so 布局样本:**

假设有一个名为 `libkvm_helper.so` 的共享库，它封装了与 KVM 交互的一些功能。其布局可能如下：

```
libkvm_helper.so:
    .text          # 代码段，包含函数实现
        kvm_init_vm()
        kvm_create_vcpu()
        kvm_set_registers()
        ...
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .plt           # Procedure Linkage Table (过程链接表)
    .got.plt       # Global Offset Table (全局偏移表)
```

**链接的处理过程:**

1. **编译时:** 当编译依赖于 `libkvm_helper.so` 的代码时，编译器会解析头文件 (`kvm.handroid`) 中定义的结构体和常量，确保代码正确地使用了这些定义。
2. **链接时:** 静态链接器会将代码中对 `libkvm_helper.so` 中函数的引用记录在生成的可执行文件或共享库的 `.rel.dyn` 段中。
3. **运行时:** 当程序启动时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会：
   * 加载 `libkvm_helper.so` 到内存中。
   * 解析 `.rel.dyn` 段中的重定位信息。
   * 根据 `.dynsym` 和 `.dynstr` 中的信息，找到被引用的函数的实际地址。
   * 更新 `.got.plt` 中的条目，使得对 `libkvm_helper.so` 中函数的调用能够跳转到正确的地址。

**假设输入与输出 (针对使用了此头文件的代码):**

假设有一个函数 `setup_vm_registers`，它使用 `kvm_regs` 结构体来设置虚拟机的寄存器：

**假设输入:**

* 一个 KVM 虚拟 CPU 的文件描述符 `vcpu_fd`。
* 一个 `kvm_regs` 结构体实例，其成员被设置为期望的寄存器值，例如：
  ```c
  struct kvm_regs regs;
  regs.rip = 0x1000;
  regs.rax = 0x2000;
  // ... 其他寄存器
  ```

**预期输出:**

* `ioctl(vcpu_fd, KVM_SET_REGS, &regs)` 调用成功返回 0。
* 虚拟机的 CPU 在执行时，其指令指针 (RIP) 将被设置为 `0x1000`，通用寄存器 RAX 的值将被设置为 `0x2000`。

**用户或编程常见的使用错误:**

1. **头文件包含错误:**  没有正确包含 `kvm.handroid` 头文件，导致编译器无法识别相关的结构体和常量。
2. **`ioctl` 命令错误:**  使用了错误的 `ioctl` 命令号，导致内核无法识别用户的意图。
3. **数据结构填充错误:**  没有正确地填充 `kvm_regs` 或其他 KVM 相关的结构体，例如，结构体的大小不匹配，或者成员的值超出预期范围。
4. **权限问题:**  尝试操作 `/dev/kvm` 设备的用户或进程没有足够的权限。通常需要 `root` 权限或特定的组权限。
5. **多线程竞争:**  在多线程环境下，多个线程同时尝试操作同一个虚拟机或 VCPU 的状态，可能导致数据竞争和状态不一致。
6. **内核版本不兼容:**  用户空间代码使用的 KVM API 与当前运行的 Linux 内核的 KVM 模块版本不兼容。

**Android framework 或 NDK 如何到达这里，给出 frida hook 示例调试这些步骤:**

Android Framework 中，与虚拟化相关的操作通常发生在较低层次，例如在模拟器进程中。Framework 本身不会直接使用这个头文件，而是通过 NDK (Native Development Kit) 提供的库来间接使用。

**步骤:**

1. **Android Framework 请求启动虚拟机:** 例如，用户启动 Android 模拟器。
2. **Emulator 进程启动:**  一个 QEMU 或类似的虚拟机监控器进程被启动。
3. **Emulator 使用 NDK 库:**  Emulator 的代码会使用 NDK 提供的库，这些库封装了与 KVM 交互的逻辑。
4. **NDK 库调用系统调用:**  NDK 库中的代码会使用 `open()` 打开 `/dev/kvm`，并使用 `ioctl()` 系统调用与 KVM 模块通信。
5. **`ioctl` 调用中使用 `kvm.handroid` 定义的结构体和常量:**  在 `ioctl()` 调用中，会传递使用 `kvm.handroid` 中定义的结构体填充的数据。

**Frida Hook 示例:**

可以使用 Frida 来 hook 与 KVM 相关的系统调用，以观察这些步骤。以下是一个简单的 Frida hook 示例，用于拦截对 `ioctl` 系统调用且 `fd` 指向 `/dev/kvm` 时的操作：

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        try {
          const path = Socket.peerPath(fd);
          if (path && path.includes('/dev/kvm')) {
            console.log('[KVM IOCTL] FD:', fd, 'Request:', request);
            // 可以进一步解析 args[2] 指向的数据，根据 request 的值来判断具体的操作和数据结构
          }
        } catch (e) {
          // ignore if fd is not a socket or error occurs
        }
      },
      onLeave: function (retval) {
        // console.log('[KVM IOCTL] Return:', retval.toInt32());
      }
    });
    console.log('[Frida] Hooked ioctl');
  } else {
    console.log('[Frida] ioctl not found');
  }
} else {
  console.log('[Frida] Not running on Linux');
}
```

**更详细的 Hook 示例 (针对特定的 KVM 命令):**

要 hook 特定 KVM 命令，需要分析 `ioctl` 的第二个参数 (`request`) 的值，并根据该值来解析第三个参数 (`argp`) 指向的数据。例如，要 hook `KVM_SET_REGS` 命令：

1. **找到 `KVM_SET_REGS` 的定义:**  通常在 `<linux/kvm.h>` 或相关的内核头文件中。假设其值为 `_IOW('k', 0x81, struct kvm_regs)`.
2. **在 Frida hook 中检查 `request` 的值:**

```javascript
if (Process.platform === 'linux') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  const KVM_SET_REGS = 0xae81; // 假设这是 KVM_SET_REGS 的值

  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        try {
          const path = Socket.peerPath(fd);
          if (path && path.includes('/dev/kvm') && request === KVM_SET_REGS) {
            console.log('[KVM IOCTL] KVM_SET_REGS called, FD:', fd);
            const regsPtr = ptr(args[2]);
            const kvm_regs = {
              rax:    regsPtr.readU64(),
              rbx:    regsPtr.add(8).readU64(),
              rcx:    regsPtr.add(16).readU64(),
              rdx:    regsPtr.add(24).readU64(),
              rsi:    regsPtr.add(32).readU64(),
              rdi:    regsPtr.add(40).readU64(),
              rsp:    regsPtr.add(48).readU64(),
              rbp:    regsPtr.add(56).readU64(),
              r8:     regsPtr.add(64).readU64(),
              r9:     regsPtr.add(72).readU64(),
              r10:    regsPtr.add(80).readU64(),
              r11:    regsPtr.add(88).readU64(),
              r12:    regsPtr.add(96).readU64(),
              r13:    regsPtr.add(104).readU64(),
              r14:    regsPtr.add(112).readU64(),
              r15:    regsPtr.add(120).readU64(),
              rip:    regsPtr.add(128).readU64(),
              rflags: regsPtr.add(136).readU64()
            };
            console.log('  Registers:', kvm_regs);
          }
        } catch (e) {
          // ignore
        }
      },
      onLeave: function (retval) {
        // ...
      }
    });
    console.log('[Frida] Hooked ioctl for KVM_SET_REGS');
  } else {
    console.log('[Frida] ioctl not found');
  }
} else {
  console.log('[Frida] Not running on Linux');
}
```

这个 Frida 脚本会拦截对 `ioctl` 的调用，检查 `fd` 是否指向 `/dev/kvm`，并且 `request` 的值是否等于 `KVM_SET_REGS`。如果是，它会读取 `args[2]` 指向的 `kvm_regs` 结构体的数据并打印出来，从而帮助调试虚拟机寄存器的设置过程。

请注意，具体的 `KVM_SET_REGS` 的值可能需要根据你的内核头文件进行调整。 你可以使用 `grep KVM_SET_REGS /usr/include/linux/kvm.h` 或类似的命令来查找其确切定义。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/kvm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _ASM_X86_KVM_H
#define _ASM_X86_KVM_H
#include <linux/const.h>
#include <linux/bits.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/stddef.h>
#define KVM_PIO_PAGE_OFFSET 1
#define KVM_COALESCED_MMIO_PAGE_OFFSET 2
#define KVM_DIRTY_LOG_PAGE_OFFSET 64
#define DE_VECTOR 0
#define DB_VECTOR 1
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define AC_VECTOR 17
#define MC_VECTOR 18
#define XM_VECTOR 19
#define VE_VECTOR 20
#define __KVM_HAVE_PIT
#define __KVM_HAVE_IOAPIC
#define __KVM_HAVE_IRQ_LINE
#define __KVM_HAVE_MSI
#define __KVM_HAVE_USER_NMI
#define __KVM_HAVE_MSIX
#define __KVM_HAVE_MCE
#define __KVM_HAVE_PIT_STATE2
#define __KVM_HAVE_XEN_HVM
#define __KVM_HAVE_VCPU_EVENTS
#define __KVM_HAVE_DEBUGREGS
#define __KVM_HAVE_XSAVE
#define __KVM_HAVE_XCRS
#define KVM_NR_INTERRUPTS 256
struct kvm_pic_state {
  __u8 last_irr;
  __u8 irr;
  __u8 imr;
  __u8 isr;
  __u8 priority_add;
  __u8 irq_base;
  __u8 read_reg_select;
  __u8 poll;
  __u8 special_mask;
  __u8 init_state;
  __u8 auto_eoi;
  __u8 rotate_on_auto_eoi;
  __u8 special_fully_nested_mode;
  __u8 init4;
  __u8 elcr;
  __u8 elcr_mask;
};
#define KVM_IOAPIC_NUM_PINS 24
struct kvm_ioapic_state {
  __u64 base_address;
  __u32 ioregsel;
  __u32 id;
  __u32 irr;
  __u32 pad;
  union {
    __u64 bits;
    struct {
      __u8 vector;
      __u8 delivery_mode : 3;
      __u8 dest_mode : 1;
      __u8 delivery_status : 1;
      __u8 polarity : 1;
      __u8 remote_irr : 1;
      __u8 trig_mode : 1;
      __u8 mask : 1;
      __u8 reserve : 7;
      __u8 reserved[4];
      __u8 dest_id;
    } fields;
  } redirtbl[KVM_IOAPIC_NUM_PINS];
};
#define KVM_IRQCHIP_PIC_MASTER 0
#define KVM_IRQCHIP_PIC_SLAVE 1
#define KVM_IRQCHIP_IOAPIC 2
#define KVM_NR_IRQCHIPS 3
#define KVM_RUN_X86_SMM (1 << 0)
#define KVM_RUN_X86_BUS_LOCK (1 << 1)
#define KVM_RUN_X86_GUEST_MODE (1 << 2)
struct kvm_regs {
  __u64 rax, rbx, rcx, rdx;
  __u64 rsi, rdi, rsp, rbp;
  __u64 r8, r9, r10, r11;
  __u64 r12, r13, r14, r15;
  __u64 rip, rflags;
};
#define KVM_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
  char regs[KVM_APIC_REG_SIZE];
};
struct kvm_segment {
  __u64 base;
  __u32 limit;
  __u16 selector;
  __u8 type;
  __u8 present, dpl, db, s, l, g, avl;
  __u8 unusable;
  __u8 padding;
};
struct kvm_dtable {
  __u64 base;
  __u16 limit;
  __u16 padding[3];
};
struct kvm_sregs {
  struct kvm_segment cs, ds, es, fs, gs, ss;
  struct kvm_segment tr, ldt;
  struct kvm_dtable gdt, idt;
  __u64 cr0, cr2, cr3, cr4, cr8;
  __u64 efer;
  __u64 apic_base;
  __u64 interrupt_bitmap[(KVM_NR_INTERRUPTS + 63) / 64];
};
struct kvm_sregs2 {
  struct kvm_segment cs, ds, es, fs, gs, ss;
  struct kvm_segment tr, ldt;
  struct kvm_dtable gdt, idt;
  __u64 cr0, cr2, cr3, cr4, cr8;
  __u64 efer;
  __u64 apic_base;
  __u64 flags;
  __u64 pdptrs[4];
};
#define KVM_SREGS2_FLAGS_PDPTRS_VALID 1
struct kvm_fpu {
  __u8 fpr[8][16];
  __u16 fcw;
  __u16 fsw;
  __u8 ftwx;
  __u8 pad1;
  __u16 last_opcode;
  __u64 last_ip;
  __u64 last_dp;
  __u8 xmm[16][16];
  __u32 mxcsr;
  __u32 pad2;
};
struct kvm_msr_entry {
  __u32 index;
  __u32 reserved;
  __u64 data;
};
struct kvm_msrs {
  __u32 nmsrs;
  __u32 pad;
  struct kvm_msr_entry entries[];
};
struct kvm_msr_list {
  __u32 nmsrs;
  __u32 indices[];
};
#define KVM_MSR_FILTER_MAX_BITMAP_SIZE 0x600
struct kvm_msr_filter_range {
#define KVM_MSR_FILTER_READ (1 << 0)
#define KVM_MSR_FILTER_WRITE (1 << 1)
#define KVM_MSR_FILTER_RANGE_VALID_MASK (KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE)
  __u32 flags;
  __u32 nmsrs;
  __u32 base;
  __u8 * bitmap;
};
#define KVM_MSR_FILTER_MAX_RANGES 16
struct kvm_msr_filter {
#define KVM_MSR_FILTER_DEFAULT_ALLOW (0 << 0)
#define KVM_MSR_FILTER_DEFAULT_DENY (1 << 0)
#define KVM_MSR_FILTER_VALID_MASK (KVM_MSR_FILTER_DEFAULT_DENY)
  __u32 flags;
  struct kvm_msr_filter_range ranges[KVM_MSR_FILTER_MAX_RANGES];
};
struct kvm_cpuid_entry {
  __u32 function;
  __u32 eax;
  __u32 ebx;
  __u32 ecx;
  __u32 edx;
  __u32 padding;
};
struct kvm_cpuid {
  __u32 nent;
  __u32 padding;
  struct kvm_cpuid_entry entries[];
};
struct kvm_cpuid_entry2 {
  __u32 function;
  __u32 index;
  __u32 flags;
  __u32 eax;
  __u32 ebx;
  __u32 ecx;
  __u32 edx;
  __u32 padding[3];
};
#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX (1 << 0)
#define KVM_CPUID_FLAG_STATEFUL_FUNC (1 << 1)
#define KVM_CPUID_FLAG_STATE_READ_NEXT (1 << 2)
struct kvm_cpuid2 {
  __u32 nent;
  __u32 padding;
  struct kvm_cpuid_entry2 entries[];
};
struct kvm_pit_channel_state {
  __u32 count;
  __u16 latched_count;
  __u8 count_latched;
  __u8 status_latched;
  __u8 status;
  __u8 read_state;
  __u8 write_state;
  __u8 write_latch;
  __u8 rw_mode;
  __u8 mode;
  __u8 bcd;
  __u8 gate;
  __s64 count_load_time;
};
struct kvm_debug_exit_arch {
  __u32 exception;
  __u32 pad;
  __u64 pc;
  __u64 dr6;
  __u64 dr7;
};
#define KVM_GUESTDBG_USE_SW_BP 0x00010000
#define KVM_GUESTDBG_USE_HW_BP 0x00020000
#define KVM_GUESTDBG_INJECT_DB 0x00040000
#define KVM_GUESTDBG_INJECT_BP 0x00080000
#define KVM_GUESTDBG_BLOCKIRQ 0x00100000
struct kvm_guest_debug_arch {
  __u64 debugreg[8];
};
struct kvm_pit_state {
  struct kvm_pit_channel_state channels[3];
};
#define KVM_PIT_FLAGS_HPET_LEGACY 0x00000001
#define KVM_PIT_FLAGS_SPEAKER_DATA_ON 0x00000002
struct kvm_pit_state2 {
  struct kvm_pit_channel_state channels[3];
  __u32 flags;
  __u32 reserved[9];
};
struct kvm_reinject_control {
  __u8 pit_reinject;
  __u8 reserved[31];
};
#define KVM_VCPUEVENT_VALID_NMI_PENDING 0x00000001
#define KVM_VCPUEVENT_VALID_SIPI_VECTOR 0x00000002
#define KVM_VCPUEVENT_VALID_SHADOW 0x00000004
#define KVM_VCPUEVENT_VALID_SMM 0x00000008
#define KVM_VCPUEVENT_VALID_PAYLOAD 0x00000010
#define KVM_VCPUEVENT_VALID_TRIPLE_FAULT 0x00000020
#define KVM_X86_SHADOW_INT_MOV_SS 0x01
#define KVM_X86_SHADOW_INT_STI 0x02
struct kvm_vcpu_events {
  struct {
    __u8 injected;
    __u8 nr;
    __u8 has_error_code;
    __u8 pending;
    __u32 error_code;
  } exception;
  struct {
    __u8 injected;
    __u8 nr;
    __u8 soft;
    __u8 shadow;
  } interrupt;
  struct {
    __u8 injected;
    __u8 pending;
    __u8 masked;
    __u8 pad;
  } nmi;
  __u32 sipi_vector;
  __u32 flags;
  struct {
    __u8 smm;
    __u8 pending;
    __u8 smm_inside_nmi;
    __u8 latched_init;
  } smi;
  struct {
    __u8 pending;
  } triple_fault;
  __u8 reserved[26];
  __u8 exception_has_payload;
  __u64 exception_payload;
};
struct kvm_debugregs {
  __u64 db[4];
  __u64 dr6;
  __u64 dr7;
  __u64 flags;
  __u64 reserved[9];
};
struct kvm_xsave {
  __u32 region[1024];
  __u32 extra[];
};
#define KVM_MAX_XCRS 16
struct kvm_xcr {
  __u32 xcr;
  __u32 reserved;
  __u64 value;
};
struct kvm_xcrs {
  __u32 nr_xcrs;
  __u32 flags;
  struct kvm_xcr xcrs[KVM_MAX_XCRS];
  __u64 padding[16];
};
#define KVM_SYNC_X86_REGS (1UL << 0)
#define KVM_SYNC_X86_SREGS (1UL << 1)
#define KVM_SYNC_X86_EVENTS (1UL << 2)
#define KVM_SYNC_X86_VALID_FIELDS (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS)
struct kvm_sync_regs {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_vcpu_events events;
};
#define KVM_X86_QUIRK_LINT0_REENABLED (1 << 0)
#define KVM_X86_QUIRK_CD_NW_CLEARED (1 << 1)
#define KVM_X86_QUIRK_LAPIC_MMIO_HOLE (1 << 2)
#define KVM_X86_QUIRK_OUT_7E_INC_RIP (1 << 3)
#define KVM_X86_QUIRK_MISC_ENABLE_NO_MWAIT (1 << 4)
#define KVM_X86_QUIRK_FIX_HYPERCALL_INSN (1 << 5)
#define KVM_X86_QUIRK_MWAIT_NEVER_UD_FAULTS (1 << 6)
#define KVM_X86_QUIRK_SLOT_ZAP_ALL (1 << 7)
#define KVM_STATE_NESTED_FORMAT_VMX 0
#define KVM_STATE_NESTED_FORMAT_SVM 1
#define KVM_STATE_NESTED_GUEST_MODE 0x00000001
#define KVM_STATE_NESTED_RUN_PENDING 0x00000002
#define KVM_STATE_NESTED_EVMCS 0x00000004
#define KVM_STATE_NESTED_MTF_PENDING 0x00000008
#define KVM_STATE_NESTED_GIF_SET 0x00000100
#define KVM_STATE_NESTED_SMM_GUEST_MODE 0x00000001
#define KVM_STATE_NESTED_SMM_VMXON 0x00000002
#define KVM_STATE_NESTED_VMX_VMCS_SIZE 0x1000
#define KVM_STATE_NESTED_SVM_VMCB_SIZE 0x1000
#define KVM_STATE_VMX_PREEMPTION_TIMER_DEADLINE 0x00000001
#define KVM_X86_GRP_SYSTEM 0
#define KVM_X86_XCOMP_GUEST_SUPP 0
#define KVM_X86_GRP_SEV 1
#define KVM_X86_SEV_VMSA_FEATURES 0
struct kvm_vmx_nested_state_data {
  __u8 vmcs12[KVM_STATE_NESTED_VMX_VMCS_SIZE];
  __u8 shadow_vmcs12[KVM_STATE_NESTED_VMX_VMCS_SIZE];
};
struct kvm_vmx_nested_state_hdr {
  __u64 vmxon_pa;
  __u64 vmcs12_pa;
  struct {
    __u16 flags;
  } smm;
  __u16 pad;
  __u32 flags;
  __u64 preemption_timer_deadline;
};
struct kvm_svm_nested_state_data {
  __u8 vmcb12[KVM_STATE_NESTED_SVM_VMCB_SIZE];
};
struct kvm_svm_nested_state_hdr {
  __u64 vmcb_pa;
};
struct kvm_nested_state {
  __u16 flags;
  __u16 format;
  __u32 size;
  union {
    struct kvm_vmx_nested_state_hdr vmx;
    struct kvm_svm_nested_state_hdr svm;
    __u8 pad[120];
  } hdr;
  union {
    __DECLARE_FLEX_ARRAY(struct kvm_vmx_nested_state_data, vmx);
    __DECLARE_FLEX_ARRAY(struct kvm_svm_nested_state_data, svm);
  } data;
};
struct kvm_pmu_event_filter {
  __u32 action;
  __u32 nevents;
  __u32 fixed_counter_bitmap;
  __u32 flags;
  __u32 pad[4];
  __u64 events[];
};
#define KVM_PMU_EVENT_ALLOW 0
#define KVM_PMU_EVENT_DENY 1
#define KVM_PMU_EVENT_FLAG_MASKED_EVENTS _BITUL(0)
#define KVM_PMU_EVENT_FLAGS_VALID_MASK (KVM_PMU_EVENT_FLAG_MASKED_EVENTS)
struct kvm_x86_mce {
  __u64 status;
  __u64 addr;
  __u64 misc;
  __u64 mcg_status;
  __u8 bank;
  __u8 pad1[7];
  __u64 pad2[3];
};
#define KVM_XEN_HVM_CONFIG_HYPERCALL_MSR (1 << 0)
#define KVM_XEN_HVM_CONFIG_INTERCEPT_HCALL (1 << 1)
#define KVM_XEN_HVM_CONFIG_SHARED_INFO (1 << 2)
#define KVM_XEN_HVM_CONFIG_RUNSTATE (1 << 3)
#define KVM_XEN_HVM_CONFIG_EVTCHN_2LEVEL (1 << 4)
#define KVM_XEN_HVM_CONFIG_EVTCHN_SEND (1 << 5)
#define KVM_XEN_HVM_CONFIG_RUNSTATE_UPDATE_FLAG (1 << 6)
#define KVM_XEN_HVM_CONFIG_PVCLOCK_TSC_UNSTABLE (1 << 7)
#define KVM_XEN_HVM_CONFIG_SHARED_INFO_HVA (1 << 8)
struct kvm_xen_hvm_config {
  __u32 flags;
  __u32 msr;
  __u64 blob_addr_32;
  __u64 blob_addr_64;
  __u8 blob_size_32;
  __u8 blob_size_64;
  __u8 pad2[30];
};
struct kvm_xen_hvm_attr {
  __u16 type;
  __u16 pad[3];
  union {
    __u8 long_mode;
    __u8 vector;
    __u8 runstate_update_flag;
    union {
      __u64 gfn;
#define KVM_XEN_INVALID_GFN ((__u64) - 1)
      __u64 hva;
    } shared_info;
    struct {
      __u32 send_port;
      __u32 type;
      __u32 flags;
#define KVM_XEN_EVTCHN_DEASSIGN (1 << 0)
#define KVM_XEN_EVTCHN_UPDATE (1 << 1)
#define KVM_XEN_EVTCHN_RESET (1 << 2)
      union {
        struct {
          __u32 port;
          __u32 vcpu;
          __u32 priority;
        } port;
        struct {
          __u32 port;
          __s32 fd;
        } eventfd;
        __u32 padding[4];
      } deliver;
    } evtchn;
    __u32 xen_version;
    __u64 pad[8];
  } u;
};
#define KVM_XEN_ATTR_TYPE_LONG_MODE 0x0
#define KVM_XEN_ATTR_TYPE_SHARED_INFO 0x1
#define KVM_XEN_ATTR_TYPE_UPCALL_VECTOR 0x2
#define KVM_XEN_ATTR_TYPE_EVTCHN 0x3
#define KVM_XEN_ATTR_TYPE_XEN_VERSION 0x4
#define KVM_XEN_ATTR_TYPE_RUNSTATE_UPDATE_FLAG 0x5
#define KVM_XEN_ATTR_TYPE_SHARED_INFO_HVA 0x6
struct kvm_xen_vcpu_attr {
  __u16 type;
  __u16 pad[3];
  union {
    __u64 gpa;
#define KVM_XEN_INVALID_GPA ((__u64) - 1)
    __u64 hva;
    __u64 pad[8];
    struct {
      __u64 state;
      __u64 state_entry_time;
      __u64 time_running;
      __u64 time_runnable;
      __u64 time_blocked;
      __u64 time_offline;
    } runstate;
    __u32 vcpu_id;
    struct {
      __u32 port;
      __u32 priority;
      __u64 expires_ns;
    } timer;
    __u8 vector;
  } u;
};
#define KVM_XEN_VCPU_ATTR_TYPE_VCPU_INFO 0x0
#define KVM_XEN_VCPU_ATTR_TYPE_VCPU_TIME_INFO 0x1
#define KVM_XEN_VCPU_ATTR_TYPE_RUNSTATE_ADDR 0x2
#define KVM_XEN_VCPU_ATTR_TYPE_RUNSTATE_CURRENT 0x3
#define KVM_XEN_VCPU_ATTR_TYPE_RUNSTATE_DATA 0x4
#define KVM_XEN_VCPU_ATTR_TYPE_RUNSTATE_ADJUST 0x5
#define KVM_XEN_VCPU_ATTR_TYPE_VCPU_ID 0x6
#define KVM_XEN_VCPU_ATTR_TYPE_TIMER 0x7
#define KVM_XEN_VCPU_ATTR_TYPE_UPCALL_VECTOR 0x8
#define KVM_XEN_VCPU_ATTR_TYPE_VCPU_INFO_HVA 0x9
enum sev_cmd_id {
  KVM_SEV_INIT = 0,
  KVM_SEV_ES_INIT,
  KVM_SEV_LAUNCH_START,
  KVM_SEV_LAUNCH_UPDATE_DATA,
  KVM_SEV_LAUNCH_UPDATE_VMSA,
  KVM_SEV_LAUNCH_SECRET,
  KVM_SEV_LAUNCH_MEASURE,
  KVM_SEV_LAUNCH_FINISH,
  KVM_SEV_SEND_START,
  KVM_SEV_SEND_UPDATE_DATA,
  KVM_SEV_SEND_UPDATE_VMSA,
  KVM_SEV_SEND_FINISH,
  KVM_SEV_RECEIVE_START,
  KVM_SEV_RECEIVE_UPDATE_DATA,
  KVM_SEV_RECEIVE_UPDATE_VMSA,
  KVM_SEV_RECEIVE_FINISH,
  KVM_SEV_GUEST_STATUS,
  KVM_SEV_DBG_DECRYPT,
  KVM_SEV_DBG_ENCRYPT,
  KVM_SEV_CERT_EXPORT,
  KVM_SEV_GET_ATTESTATION_REPORT,
  KVM_SEV_SEND_CANCEL,
  KVM_SEV_INIT2,
  KVM_SEV_SNP_LAUNCH_START = 100,
  KVM_SEV_SNP_LAUNCH_UPDATE,
  KVM_SEV_SNP_LAUNCH_FINISH,
  KVM_SEV_NR_MAX,
};
struct kvm_sev_cmd {
  __u32 id;
  __u32 pad0;
  __u64 data;
  __u32 error;
  __u32 sev_fd;
};
struct kvm_sev_init {
  __u64 vmsa_features;
  __u32 flags;
  __u16 ghcb_version;
  __u16 pad1;
  __u32 pad2[8];
};
struct kvm_sev_launch_start {
  __u32 handle;
  __u32 policy;
  __u64 dh_uaddr;
  __u32 dh_len;
  __u32 pad0;
  __u64 session_uaddr;
  __u32 session_len;
  __u32 pad1;
};
struct kvm_sev_launch_update_data {
  __u64 uaddr;
  __u32 len;
  __u32 pad0;
};
struct kvm_sev_launch_secret {
  __u64 hdr_uaddr;
  __u32 hdr_len;
  __u32 pad0;
  __u64 guest_uaddr;
  __u32 guest_len;
  __u32 pad1;
  __u64 trans_uaddr;
  __u32 trans_len;
  __u32 pad2;
};
struct kvm_sev_launch_measure {
  __u64 uaddr;
  __u32 len;
  __u32 pad0;
};
struct kvm_sev_guest_status {
  __u32 handle;
  __u32 policy;
  __u32 state;
};
struct kvm_sev_dbg {
  __u64 src_uaddr;
  __u64 dst_uaddr;
  __u32 len;
  __u32 pad0;
};
struct kvm_sev_attestation_report {
  __u8 mnonce[16];
  __u64 uaddr;
  __u32 len;
  __u32 pad0;
};
struct kvm_sev_send_start {
  __u32 policy;
  __u32 pad0;
  __u64 pdh_cert_uaddr;
  __u32 pdh_cert_len;
  __u32 pad1;
  __u64 plat_certs_uaddr;
  __u32 plat_certs_len;
  __u32 pad2;
  __u64 amd_certs_uaddr;
  __u32 amd_certs_len;
  __u32 pad3;
  __u64 session_uaddr;
  __u32 session_len;
  __u32 pad4;
};
struct kvm_sev_send_update_data {
  __u64 hdr_uaddr;
  __u32 hdr_len;
  __u32 pad0;
  __u64 guest_uaddr;
  __u32 guest_len;
  __u32 pad1;
  __u64 trans_uaddr;
  __u32 trans_len;
  __u32 pad2;
};
struct kvm_sev_receive_start {
  __u32 handle;
  __u32 policy;
  __u64 pdh_uaddr;
  __u32 pdh_len;
  __u32 pad0;
  __u64 session_uaddr;
  __u32 session_len;
  __u32 pad1;
};
struct kvm_sev_receive_update_data {
  __u64 hdr_uaddr;
  __u32 hdr_len;
  __u32 pad0;
  __u64 guest_uaddr;
  __u32 guest_len;
  __u32 pad1;
  __u64 trans_uaddr;
  __u32 trans_len;
  __u32 pad2;
};
struct kvm_sev_snp_launch_start {
  __u64 policy;
  __u8 gosvw[16];
  __u16 flags;
  __u8 pad0[6];
  __u64 pad1[4];
};
#define KVM_SEV_SNP_PAGE_TYPE_NORMAL 0x1
#define KVM_SEV_SNP_PAGE_TYPE_ZERO 0x3
#define KVM_SEV_SNP_PAGE_TYPE_UNMEASURED 0x4
#define KVM_SEV_SNP_PAGE_TYPE_SECRETS 0x5
#define KVM_SEV_SNP_PAGE_TYPE_CPUID 0x6
struct kvm_sev_snp_launch_update {
  __u64 gfn_start;
  __u64 uaddr;
  __u64 len;
  __u8 type;
  __u8 pad0;
  __u16 flags;
  __u32 pad1;
  __u64 pad2[4];
};
#define KVM_SEV_SNP_ID_BLOCK_SIZE 96
#define KVM_SEV_SNP_ID_AUTH_SIZE 4096
#define KVM_SEV_SNP_FINISH_DATA_SIZE 32
struct kvm_sev_snp_launch_finish {
  __u64 id_block_uaddr;
  __u64 id_auth_uaddr;
  __u8 id_block_en;
  __u8 auth_key_en;
  __u8 vcek_disabled;
  __u8 host_data[KVM_SEV_SNP_FINISH_DATA_SIZE];
  __u8 pad0[3];
  __u16 flags;
  __u64 pad1[4];
};
#define KVM_X2APIC_API_USE_32BIT_IDS (1ULL << 0)
#define KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK (1ULL << 1)
struct kvm_hyperv_eventfd {
  __u32 conn_id;
  __s32 fd;
  __u32 flags;
  __u32 padding[3];
};
#define KVM_HYPERV_CONN_ID_MASK 0x00ffffff
#define KVM_HYPERV_EVENTFD_DEASSIGN (1 << 0)
#define KVM_PMU_ENCODE_MASKED_ENTRY(event_select,mask,match,exclude) (((event_select) & 0xFFULL) | (((event_select) & 0XF00ULL) << 24) | (((mask) & 0xFFULL) << 56) | (((match) & 0xFFULL) << 8) | ((__u64) (! ! (exclude)) << 55))
#define KVM_PMU_MASKED_ENTRY_EVENT_SELECT (__GENMASK_ULL(7, 0) | __GENMASK_ULL(35, 32))
#define KVM_PMU_MASKED_ENTRY_UMASK_MASK (__GENMASK_ULL(63, 56))
#define KVM_PMU_MASKED_ENTRY_UMASK_MATCH (__GENMASK_ULL(15, 8))
#define KVM_PMU_MASKED_ENTRY_EXCLUDE (_BITULL(55))
#define KVM_PMU_MASKED_ENTRY_UMASK_MASK_SHIFT (56)
#define KVM_VCPU_TSC_CTRL 0
#define KVM_VCPU_TSC_OFFSET 0
#define KVM_EXIT_HYPERCALL_LONG_MODE _BITULL(0)
#define KVM_X86_DEFAULT_VM 0
#define KVM_X86_SW_PROTECTED_VM 1
#define KVM_X86_SEV_VM 2
#define KVM_X86_SEV_ES_VM 3
#define KVM_X86_SNP_VM 4
#endif

"""

```