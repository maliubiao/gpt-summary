Response:
Let's break down the thought process for analyzing this header file and generating the detailed response.

**1. Understanding the Context:**

The initial prompt clearly states the file's location: `bionic/libc/kernel/uapi/rdma/hns-abi.handroid`. This immediately tells us several key things:

* **bionic:** This is related to Android's core libraries. This means the file likely defines interfaces for interacting with the Linux kernel from userspace on Android.
* **libc/kernel/uapi:** This strongly suggests these are user-space Application Binary Interface (ABI) definitions that mirror structures and enums in the Linux kernel. `uapi` specifically signifies user-space facing definitions.
* **rdma:** This points to Remote Direct Memory Access technology. RDMA allows direct memory access between computers over a network, bypassing the operating system's kernel for data transfer, which improves performance.
* **hns-abi.handroid:**  The "hns" likely stands for a specific hardware Network System, and "handroid" suggests this is a variant or adaptation for Android. The `.handroid` suffix implies this might be a customized version of a standard RDMA ABI.

**2. Deconstructing the File Contents:**

The file is a C header file (`.h`). The core components are:

* **Include Guard:** `#ifndef HNS_ABI_USER_H`, `#define HNS_ABI_USER_H`, `#endif` prevents multiple inclusions.
* **Includes:** `#include <linux/types.h>` pulls in standard Linux type definitions (`__u32`, `__aligned_u64`, etc.). This confirms the close relationship with the Linux kernel.
* **Structures (`struct`)**: These define data layouts for passing information between user-space and the kernel. The names (`hns_roce_ib_create_cq`, `hns_roce_ib_create_srq`, etc.) strongly suggest the *operations* these structures are used for (create completion queue, create shared receive queue, etc.). The `ib` prefix likely stands for InfiniBand, a common RDMA technology.
* **Enumerations (`enum`)**: These define sets of named constants. The names often end in `_flags` or `_mask`, indicating they are used for setting or checking bit flags. The prefixes (`HNS_ROCE_CQ_FLAG_`, `HNS_ROCE_SRQ_CAP_`, etc.) further categorize these flags.

**3. Identifying Functionality:**

By examining the structure and enum names, we can infer the file's purpose: defining the ABI for a hardware-specific RDMA implementation (likely by "hns") on Android. The specific functionalities include:

* **Completion Queues (CQ):**  Structures and enums related to creating and managing CQs (`hns_roce_ib_create_cq`, `hns_roce_cq_cap_flags`). CQs are used to notify user-space applications when RDMA operations are complete.
* **Shared Receive Queues (SRQ):**  Structures and enums related to creating and managing SRQs (`hns_roce_ib_create_srq`, `hns_roce_srq_cap_flags`). SRQs allow multiple queue pairs (QPs) to share a single receive queue.
* **Queue Pairs (QP):** Structures and enums related to creating and modifying QPs (`hns_roce_ib_create_qp`, `hns_roce_qp_cap_flags`, `hns_roce_ib_modify_qp_resp`). QPs are the fundamental communication endpoints in RDMA.
* **User Context Management:** Structures related to allocating and managing user-space context for RDMA (`hns_roce_ib_alloc_ucontext`, `hns_roce_ib_alloc_ucontext_resp`).
* **Protection Domain (PD):** Structures related to allocating protection domains (`hns_roce_ib_alloc_pd_resp`). PDs are used for memory protection in RDMA.
* **Address Handle (AH):** Structures related to creating address handles (`hns_roce_ib_create_ah_resp`). AHs store network addressing information for remote peers.
* **Congestion Control:** Enums related to configuring congestion control mechanisms (`hns_roce_congest_type_flags`, `hns_roce_create_qp_comp_mask`).

**4. Connecting to Android:**

Since this file resides within the bionic library, it's used by Android components that need to interact with RDMA hardware. The most likely scenarios involve:

* **HAL (Hardware Abstraction Layer):**  A HAL implementation for the specific "hns" RDMA hardware would use these structures to communicate with the kernel driver.
* **NDK Libraries:**  While less common, certain advanced NDK libraries or frameworks might expose RDMA functionality to applications.
* **System Services:**  Potentially, low-level system services might leverage RDMA for inter-process communication or hardware acceleration.

**5. Addressing Specific Requirements of the Prompt:**

* **libc Function Details:** This file *doesn't* define libc functions. It defines data structures used *by* system calls (likely within the kernel) that libc might wrap. Therefore, a direct explanation of libc function implementation isn't applicable here. The focus is on the ABI.
* **Dynamic Linker:** This file is a header file defining data structures. It doesn't directly involve the dynamic linker. The `.so` layout and linking process are not relevant to this specific file. However, if a user-space library *using* these structures were dynamically linked, standard Android dynamic linking processes would apply.
* **Logical Reasoning/Assumptions:**  The primary assumption is that the "hns" prefix refers to a specific hardware vendor or technology. The naming conventions strongly suggest the purpose of each structure and enum.
* **User/Programming Errors:**  Common errors would involve:
    * Incorrectly sizing or populating the structures.
    * Using incorrect flag combinations.
    * Mismatches between user-space and kernel expectations regarding the ABI.
* **Android Framework/NDK Path:**  The path would involve:
    1. **Application/Service:**  Code needing RDMA functionality.
    2. **NDK or Android Framework API:** (Potentially) calls into a higher-level abstraction.
    3. **HAL Implementation:**  Uses these structures to interact with the kernel driver.
    4. **Kernel Driver:** Interprets these structures and interacts with the hardware.
* **Frida Hooking:**  Hooking would typically target system calls related to RDMA (e.g., `ioctl`) or functions within the HAL implementation that use these structures.

**6. Structuring the Response:**

The generated response logically organizes the information:

* **Purpose:**  Starts with a clear summary.
* **Functionality Breakdown:**  Categorizes the structures and enums by their logical RDMA components.
* **Relationship to Android:** Provides concrete examples of how this ABI might be used.
* **libc Function Explanation:**  Correctly states that this file doesn't define libc functions.
* **Dynamic Linker:** Explains why dynamic linking isn't directly relevant but provides context if user-space libraries were involved.
* **Logical Reasoning:**  Explicitly states the assumptions made.
* **Common Errors:** Provides practical examples of potential mistakes.
* **Android Framework/NDK Path:**  Outlines the call chain.
* **Frida Hook Example:** Offers a basic example for debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Might initially focus too much on libc functions. Correction: Realize this is an ABI definition, not libc implementation.
* **Dynamic linking:**  Might try to force a connection to the dynamic linker. Correction: Acknowledge it's not directly involved but explain the standard process if user-space libraries were built on this.
* **Specificity of "hns":**  Recognize that the exact "hns" hardware is unknown but the general RDMA principles still apply. Focus on the generic RDMA concepts exposed by the ABI.

By following this structured thought process, combining domain knowledge (RDMA, Android, Linux kernel), and carefully analyzing the file contents, we arrive at a comprehensive and accurate explanation.
这个文件 `bionic/libc/kernel/uapi/rdma/hns-abi.handroid` 是 Android Bionic 库中定义的一个头文件，它定义了用户空间程序与 Linux 内核中 `hns` (可能是某个硬件供应商的缩写，例如华为网络系统) 提供的 RDMA (Remote Direct Memory Access，远程直接内存访问) 功能进行交互的接口。由于它位于 `uapi` 目录下，这意味着它定义的是用户空间可访问的应用程序二进制接口 (ABI)。

**功能列举:**

这个头文件定义了用于配置和管理 RDMA 资源的结构体和枚举类型，主要涉及以下功能：

1. **Completion Queue (CQ) 的创建和管理:**
   - `hns_roce_ib_create_cq`: 定义了创建 CQ 所需的参数，例如缓冲区地址 (`buf_addr`)、门铃地址 (`db_addr`)、完成队列条目大小 (`cqe_size`)。
   - `hns_roce_cq_cap_flags`: 定义了 CQ 的能力标志，例如 `HNS_ROCE_CQ_FLAG_RECORD_DB`，可能表示记录门铃更新。
   - `hns_roce_ib_create_cq_resp`: 定义了创建 CQ 后的响应，包含 CQ 的句柄 (`cqn`) 和能力标志。

2. **Shared Receive Queue (SRQ) 的创建和管理:**
   - `hns_roce_ib_create_srq`: 定义了创建 SRQ 所需的参数，例如缓冲区地址、门铃地址、队列地址、请求的能力标志等。
   - `hns_roce_srq_cap_flags` 和 `hns_roce_srq_cap_flags_resp`: 定义了 SRQ 的能力标志。
   - `hns_roce_ib_create_srq_resp`: 定义了创建 SRQ 后的响应，包含 SRQ 的句柄 (`srqn`) 和能力标志。

3. **Queue Pair (QP) 的创建和管理:**
   - `hns_roce_ib_create_qp`: 定义了创建 QP 所需的参数，例如缓冲区地址、门铃地址、发送队列的日志大小、步长、是否预取、共享门铃地址、补偿掩码、创建标志、拥塞类型标志等。
   - `hns_roce_create_qp_comp_mask`: 定义了创建 QP 的补偿掩码，例如 `HNS_ROCE_CREATE_QP_MASK_CONGEST_TYPE` 用于指示拥塞类型。
   - `hns_roce_congest_type_flags`: 定义了不同的拥塞控制类型，例如 DCQCN、LDCP、HC3、DIP。
   - `hns_roce_qp_cap_flags`: 定义了 QP 的能力标志，例如记录接收队列门铃、发送队列门铃、所有者门铃、直接 WQE 等。
   - `hns_roce_ib_create_qp_resp`: 定义了创建 QP 后的响应，包含能力标志和直接 WQE 的内存映射键。
   - `hns_roce_ib_modify_qp_resp`: 定义了修改 QP 后的响应，包含流量类别模式和优先级。

4. **用户上下文 (User Context) 的分配:**
   - `hns_roce_ib_alloc_ucontext`: 定义了分配用户上下文的请求，包含配置信息。
   - `hns_roce_ib_alloc_ucontext_resp`: 定义了分配用户上下文的响应，包含 QP 表大小、CQE 大小、SRQ 表大小、配置、最大内联数据大小、拥塞类型等。

5. **保护域 (Protection Domain, PD) 的分配:**
   - `hns_roce_ib_alloc_pd_resp`: 定义了分配保护域的响应，包含保护域编号 (`pdn`)。

6. **地址句柄 (Address Handle, AH) 的创建:**
   - `hns_roce_ib_create_ah_resp`: 定义了创建地址句柄的响应，包含目标 MAC 地址、优先级和流量类别模式。

7. **其他标志位:**
   - 一些枚举类型定义了额外的标志位，例如 `HNS_ROCE_EXSGE_FLAGS`、`HNS_ROCE_RQ_INLINE_FLAGS`、`HNS_ROCE_CQE_INLINE_FLAGS`，以及它们的响应版本，可能与 scatter-gather entries、内联数据等特性相关。

**与 Android 功能的关系及举例:**

这个头文件定义了与特定硬件 (很可能是华为的网络设备) 相关的 RDMA 功能接口，这些功能主要在底层硬件加速和高性能网络通信场景中使用。在 Android 上，这些功能不太可能直接暴露给普通的应用程序开发者。更可能的是，它们被用于 Android 系统的某些底层服务或驱动程序中，以提升特定的网络性能。

**举例:**

假设 Android 设备使用了支持 `hns` RDMA 的硬件，那么以下场景可能与此相关：

* **HAL (Hardware Abstraction Layer) 实现:** Android 的 HAL 层会封装与硬件交互的细节。一个针对 `hns` RDMA 硬件的 HAL 实现可能会使用这些结构体来调用内核驱动提供的 RDMA 功能。例如，一个 HAL 函数可能调用内核的 `ioctl` 系统调用，并将 `hns_roce_ib_create_qp` 结构体作为参数传递，以创建一个 QP。

* **特定厂商的定制化服务:** 某些 Android 设备制造商可能会开发利用 RDMA 功能的定制化系统服务，以实现高性能的网络数据传输，例如用于高速数据同步或媒体流传输。

**libc 函数的功能实现:**

这个头文件本身**不定义 libc 函数**。它定义的是数据结构和枚举类型，这些是用于与内核 RDMA 子系统交互的 ABI。实际调用这些功能的通常是通过系统调用 (system calls)。

例如，创建一个 QP 的过程可能涉及以下步骤：

1. **用户空间程序:** 填充 `hns_roce_ib_create_qp` 结构体的成员，指定所需的 QP 参数。
2. **系统调用:** 用户空间程序调用一个系统调用，例如 `ioctl`，并将 `hns_roce_ib_create_qp` 结构体的指针作为参数传递给内核。系统调用的具体编号和参数定义在内核头文件中。
3. **内核处理:** 内核的 RDMA 子系统接收到系统调用后，会解析 `hns_roce_ib_create_qp` 结构体中的数据，并根据这些参数配置硬件，创建一个新的 QP。
4. **返回结果:** 内核将创建结果填充到 `hns_roce_ib_create_qp_resp` 结构体中，并通过系统调用的返回值返回给用户空间程序。

Bionic 的 libc 库可能会提供一些封装系统调用的函数，例如 `ioctl` 函数本身，但它不会直接实现 `hns_roce_ib_create_qp` 结构体中描述的功能。这些功能的实现位于 Linux 内核中相应的 RDMA 驱动程序中。

**涉及 dynamic linker 的功能:**

这个头文件本身与 dynamic linker **没有直接关系**。它定义的是内核 ABI，在编译时被用户空间程序包含，以便正确地构建与内核通信的数据结构。

如果用户空间程序需要使用 RDMA 功能，它可能会链接到一些共享库 (`.so`)，这些库封装了与内核交互的细节。这些共享库的加载和链接由 dynamic linker 负责。

**so 布局样本：**

假设存在一个名为 `libhnsrdma.so` 的共享库，用于封装 `hns` RDMA 功能。其布局可能如下：

```
libhnsrdma.so:
  .init       # 初始化段
  .plt        # 过程链接表
  .text       # 代码段，包含封装 RDMA 操作的函数，例如 create_qp, create_cq 等
  .rodata     # 只读数据段
  .data       # 可读写数据段
  .bss        # 未初始化数据段
  .dynamic    # 动态链接信息
  ...

  # 导出符号 (例如)
  create_qp:
    # 封装了调用 ioctl 并传递 hns_roce_ib_create_qp 结构体的逻辑
    ...
  create_cq:
    # 封装了调用 ioctl 并传递 hns_roce_ib_create_cq 结构体的逻辑
    ...
  ...
```

**链接的处理过程：**

1. **编译时：** 用户空间的 C/C++ 代码包含了 `hns-abi.handroid` 头文件，编译器知道如何布局与内核通信的数据结构。
2. **链接时：** 链接器将用户空间程序与 `libhnsrdma.so` 链接在一起。链接器会解析 `libhnsrdma.so` 的符号表，找到用户程序中调用的 RDMA 相关函数的地址。
3. **运行时：** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载 `libhnsrdma.so` 到内存中，并解析其依赖项。
4. **符号解析：** dynamic linker 会将用户程序中对 `libhnsrdma.so` 中函数的调用，重定向到 `libhnsrdma.so` 在内存中的实际地址。这通常通过 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 实现。

**假设输入与输出 (逻辑推理):**

假设我们有一个用户程序想要创建一个 CQ。

**输入:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <rdma/hns-abi.handroid> // 假设此文件已正确包含

#define HNS_ROCE_CREATE_CQ_IOC 0xAB01 // 假设的 ioctl 命令

int main() {
  int fd = open("/dev/hns_rdma", O_RDWR); // 假设的 RDMA 设备文件
  if (fd < 0) {
    perror("open");
    return 1;
  }

  struct hns_roce_ib_create_cq create_cq_args = {
    .buf_addr = 0x1000,
    .db_addr = 0x2000,
    .cqe_size = 256,
    .reserved = 0,
  };

  struct hns_roce_ib_create_cq_resp create_cq_resp;

  if (ioctl(fd, HNS_ROCE_CREATE_CQ_IOC, &create_cq_args, &create_cq_resp) < 0) {
    perror("ioctl");
    close(fd);
    return 1;
  }

  printf("Created CQ with cqn: %llu, cap_flags: %llu\n",
         create_cq_resp.cqn, create_cq_resp.cap_flags);

  close(fd);
  return 0;
}
```

**输出 (假设 ioctl 调用成功):**

```
Created CQ with cqn: <某个内核分配的 CQ 句柄值>, cap_flags: <根据内核配置的标志位>
```

如果 ioctl 调用失败，输出将是 `perror("ioctl")` 产生的错误信息。

**用户或编程常见的使用错误:**

1. **结构体成员未正确初始化:** 例如，`buf_addr` 或 `db_addr` 指向无效的内存地址，导致内核访问错误。
2. **ioctl 命令错误:** 使用了错误的 `ioctl` 命令编号，导致内核无法识别请求。
3. **权限不足:** 用户空间程序可能没有足够的权限访问 RDMA 设备文件 (`/dev/hns_rdma`)。
4. **内核驱动未加载或硬件故障:** 如果内核中没有加载相应的 `hns` RDMA 驱动，或者硬件存在故障，ioctl 调用会失败。
5. **ABI 不兼容:** 如果用户空间程序使用的头文件版本与内核驱动期望的版本不一致，可能会导致结构体布局不匹配，从而引发错误。
6. **内存管理错误:** 例如，用于 CQ 的缓冲区没有正确分配或映射到用户空间。

**Android Framework 或 NDK 如何到达这里:**

通常，普通的 Android 应用程序开发者不会直接使用这些底层的 RDMA 接口。更可能是通过以下路径：

1. **Android Framework (罕见直接使用):** Android Framework 自身可能在某些非常底层的网络或硬件加速服务中使用 RDMA，但这通常对上层应用是透明的。Framework 可能会通过 JNI 调用 native 代码，而 native 代码会使用这些结构体与内核交互。

2. **NDK (Native Development Kit):**  如果开发者需要进行高性能的网络编程，并且目标设备支持 `hns` RDMA，他们可能会使用 NDK 来编写 C/C++ 代码。

   - **NDK 库封装:** 可能会有第三方或设备制造商提供的 NDK 库，这些库封装了底层的 RDMA 操作，并提供了更易于使用的 API。这些库的实现会涉及到包含 `hns-abi.handroid` 并调用相应的系统调用。

   - **直接系统调用 (不推荐):**  开发者理论上可以直接使用 NDK 调用 `ioctl` 等系统调用，并使用 `hns-abi.handroid` 中定义的结构体。但这通常很复杂且容易出错，不推荐这样做。

**Frida Hook 示例调试步骤:**

假设我们要 hook 用户空间程序调用 `ioctl` 来创建 CQ 的过程。

```python
import frida
import sys

# 要 hook 的进程名称
process_name = "your_rdma_app"

# 要 hook 的 ioctl 系统调用地址或符号名 (需要根据目标设备确定)
# 这里假设已经找到了 ioctl 的地址
ioctl_address = 0x12345678  # 替换为实际地址

# 假设的 HNS_ROCE_CREATE_CQ_IOC 值
HNS_ROCE_CREATE_CQ_IOC = 0xAB01

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")

def main():
    try:
        session = frida.attach(process_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{process_name}' 未找到，请先启动应用。")
        sys.exit(1)

    script = session.create_script("""
        const ioctl_ptr = ptr('%s');
        const HNS_ROCE_CREATE_CQ_IOC = %d;

        Interceptor.attach(ioctl_ptr, {
            onEnter: function (args) {
                const req = args[1].toInt32();
                if (req === HNS_ROCE_CREATE_CQ_IOC) {
                    console.log("[*] ioctl called with HNS_ROCE_CREATE_CQ_IOC");
                    const create_cq_ptr = ptr(args[2]);
                    const buf_addr = create_cq_ptr.readU64();
                    const db_addr = create_cq_ptr.add(8).readU64();
                    const cqe_size = create_cq_ptr.add(16).readU32();
                    console.log("[*] hns_roce_ib_create_cq:");
                    console.log("    buf_addr:", buf_addr.toString(16));
                    console.log("    db_addr:", db_addr.toString(16));
                    console.log("    cqe_size:", cqe_size);
                }
            },
            onLeave: function (retval) {
                if (this.req === HNS_ROCE_CREATE_CQ_IOC && retval.toInt32() === 0) {
                    const create_cq_resp_ptr = ptr(this.args[3]);
                    const cqn = create_cq_resp_ptr.readU64();
                    const cap_flags = create_cq_resp_ptr.add(8).readU64();
                    console.log("[*] hns_roce_ib_create_cq_resp:");
                    console.log("    cqn:", cqn.toString(16));
                    console.log("    cap_flags:", cap_flags.toString(16));
                }
            }
        });
    """ % (hex(ioctl_address), HNS_ROCE_CREATE_CQ_IOC))

    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**步骤解释:**

1. **确定目标进程:** 将 `your_rdma_app` 替换为实际使用 RDMA 的进程名称。
2. **找到 `ioctl` 地址:** 你需要找到目标进程中 `ioctl` 函数的地址。这可以通过 `frida-ps -a` 列出进程和模块，然后使用 `frida-trace` 或其他工具来确定。
3. **Hook `ioctl`:** 使用 `Interceptor.attach` hook `ioctl` 函数。
4. **检查 `ioctl` 命令:** 在 `onEnter` 中，读取 `ioctl` 的第二个参数，判断是否为 `HNS_ROCE_CREATE_CQ_IOC`。
5. **读取结构体参数:** 如果是创建 CQ 的请求，读取 `hns_roce_ib_create_cq` 结构体的成员，并打印出来。
6. **读取响应:** 在 `onLeave` 中，如果 `ioctl` 调用成功，读取 `hns_roce_ib_create_cq_resp` 结构体的成员，并打印出来。

**注意:**

* 上述 Frida 脚本只是一个示例，你需要根据实际情况调整 `ioctl_address` 和 `HNS_ROCE_CREATE_CQ_IOC` 的值。
* 你可能需要 root 权限才能 hook 其他进程。
* 调试内核相关的操作可能需要更深入的了解内核和驱动程序的实现。

总而言之，`bionic/libc/kernel/uapi/rdma/hns-abi.handroid` 定义了 Android 用户空间程序与内核 `hns` RDMA 子系统交互的接口，主要用于高性能网络通信。虽然普通应用开发者不直接使用，但它可能被 Android 系统的底层服务或特定厂商的 HAL 实现所采用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/hns-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef HNS_ABI_USER_H
#define HNS_ABI_USER_H
#include <linux/types.h>
struct hns_roce_ib_create_cq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u32 cqe_size;
  __u32 reserved;
};
enum hns_roce_cq_cap_flags {
  HNS_ROCE_CQ_FLAG_RECORD_DB = 1 << 0,
};
struct hns_roce_ib_create_cq_resp {
  __aligned_u64 cqn;
  __aligned_u64 cap_flags;
};
enum hns_roce_srq_cap_flags {
  HNS_ROCE_SRQ_CAP_RECORD_DB = 1 << 0,
};
enum hns_roce_srq_cap_flags_resp {
  HNS_ROCE_RSP_SRQ_CAP_RECORD_DB = 1 << 0,
};
struct hns_roce_ib_create_srq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __aligned_u64 que_addr;
  __u32 req_cap_flags;
  __u32 reserved;
};
struct hns_roce_ib_create_srq_resp {
  __u32 srqn;
  __u32 cap_flags;
};
enum hns_roce_congest_type_flags {
  HNS_ROCE_CREATE_QP_FLAGS_DCQCN,
  HNS_ROCE_CREATE_QP_FLAGS_LDCP,
  HNS_ROCE_CREATE_QP_FLAGS_HC3,
  HNS_ROCE_CREATE_QP_FLAGS_DIP,
};
enum hns_roce_create_qp_comp_mask {
  HNS_ROCE_CREATE_QP_MASK_CONGEST_TYPE = 1 << 0,
};
struct hns_roce_ib_create_qp {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u8 log_sq_bb_count;
  __u8 log_sq_stride;
  __u8 sq_no_prefetch;
  __u8 reserved[5];
  __aligned_u64 sdb_addr;
  __aligned_u64 comp_mask;
  __aligned_u64 create_flags;
  __aligned_u64 cong_type_flags;
};
enum hns_roce_qp_cap_flags {
  HNS_ROCE_QP_CAP_RQ_RECORD_DB = 1 << 0,
  HNS_ROCE_QP_CAP_SQ_RECORD_DB = 1 << 1,
  HNS_ROCE_QP_CAP_OWNER_DB = 1 << 2,
  HNS_ROCE_QP_CAP_DIRECT_WQE = 1 << 5,
};
struct hns_roce_ib_create_qp_resp {
  __aligned_u64 cap_flags;
  __aligned_u64 dwqe_mmap_key;
};
struct hns_roce_ib_modify_qp_resp {
  __u8 tc_mode;
  __u8 priority;
  __u8 reserved[6];
};
enum {
  HNS_ROCE_EXSGE_FLAGS = 1 << 0,
  HNS_ROCE_RQ_INLINE_FLAGS = 1 << 1,
  HNS_ROCE_CQE_INLINE_FLAGS = 1 << 2,
};
enum {
  HNS_ROCE_RSP_EXSGE_FLAGS = 1 << 0,
  HNS_ROCE_RSP_RQ_INLINE_FLAGS = 1 << 1,
  HNS_ROCE_RSP_CQE_INLINE_FLAGS = 1 << 2,
};
struct hns_roce_ib_alloc_ucontext_resp {
  __u32 qp_tab_size;
  __u32 cqe_size;
  __u32 srq_tab_size;
  __u32 reserved;
  __u32 config;
  __u32 max_inline_data;
  __u8 congest_type;
  __u8 reserved0[7];
};
struct hns_roce_ib_alloc_ucontext {
  __u32 config;
  __u32 reserved;
};
struct hns_roce_ib_alloc_pd_resp {
  __u32 pdn;
};
struct hns_roce_ib_create_ah_resp {
  __u8 dmac[6];
  __u8 priority;
  __u8 tc_mode;
};
#endif
```