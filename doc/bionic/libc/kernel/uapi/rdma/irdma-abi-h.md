Response:
Let's break down the thought process for analyzing the provided C header file `irdma-abi.handroid`.

**1. Understanding the Context:**

The first and most crucial step is understanding the context. The prompt clearly states:

* **Location:** `bionic/libc/kernel/uapi/rdma/irdma-abi.handroid`
* **Purpose of Bionic:** Android's C library, math library, and dynamic linker.
* **File Type:** C header file (`.h`).
* **Naming Convention:**  The `uapi` directory strongly suggests this is a user-space API definition for interacting with a kernel module. The `rdma` part immediately signals Remote Direct Memory Access. The `irdma` prefix likely denotes a specific implementation or driver related to RDMA. The "handroid" suffix hints at Android-specific adaptations or configurations.

**2. Initial Scan and Structure Identification:**

A quick scan reveals several key C language constructs:

* **`#ifndef`, `#define`, `#endif`:** Standard include guards to prevent multiple inclusions.
* **`#include <linux/types.h>`:**  Indicates interaction with the Linux kernel. This is a strong confirmation that this header defines an interface between user-space and the kernel.
* **`#define IRDMA_ABI_VER 5`:** Defines a version number for the ABI (Application Binary Interface). This is important for compatibility.
* **`enum irdma_memreg_type`:** Defines an enumeration for memory registration types, suggesting different ways memory can be registered for RDMA operations.
* **Unnamed `enum`:** Defines flags related to allocating user context, providing options for the allocation.
* **`struct irdma_...` definitions:**  These are the core of the file. They define the structures used for communication between user-space and the kernel driver. The names like `irdma_alloc_ucontext_req` and `irdma_alloc_ucontext_resp` clearly indicate request and response structures for specific RDMA operations.

**3. Analyzing Individual Structures and Enums (Functionality Deduction):**

Now, we go through each structure and enum and try to deduce its purpose based on the member names.

* **`irdma_memreg_type`:**  `MEM`, `QP`, `CQ` likely correspond to Memory, Queue Pair, and Completion Queue, fundamental RDMA concepts.

* **Unnamed `enum`:** `IRDMA_ALLOC_UCTX_USE_RAW_ATTR` and `IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE` are flags influencing user context allocation.

* **`irdma_alloc_ucontext_req`:** Contains a version number (`userspace_ver`) and a `comp_mask`. This suggests a handshake process where the user-space application declares its supported version and potentially some capabilities.

* **`irdma_alloc_ucontext_resp`:** This is the kernel's response to the allocation request. It provides critical information like maximum limits (`max_pds`, `max_qps`), buffer sizes (`wq_size`), feature flags, memory map keys (`db_mmap_key`), and hardware capabilities. This structure is crucial for the user-space application to understand the RDMA capabilities of the underlying hardware and driver.

* **`irdma_alloc_pd_resp`:**  A simple response indicating the ID of a Protection Domain (PD), another core RDMA concept.

* **`irdma_resize_cq_req`:**  Allows the user-space application to request resizing a Completion Queue.

* **`irdma_create_cq_req`:** Requests the creation of a Completion Queue, providing the user-space buffer addresses.

* **`irdma_create_qp_req`:**  Requests the creation of a Queue Pair, specifying buffers for work queue entries and completion context.

* **`irdma_mem_reg_req`:** Requests memory registration, specifying the type and number of pages for different RDMA resources.

* **`irdma_modify_qp_req`:** Allows modification of a Queue Pair, including flushing the send and receive queues.

* **`irdma_create_cq_resp`:**  Response to CQ creation, providing the CQ ID and size.

* **`irdma_create_qp_resp`:** Response to QP creation, containing the QP ID, actual queue sizes, driver options, and memory mapping information.

* **`irdma_modify_qp_resp`:** Response to QP modification, providing memory map keys and offsets for push mechanisms.

* **`irdma_create_ah_resp`:** Response to Address Handle (AH) creation, providing the AH ID.

**4. Connecting to Android and Libc:**

The file's location within the Bionic tree is the primary connection to Android. This header file defines the interface that user-space Android processes (potentially through the NDK) will use to interact with the RDMA subsystem. Since it's in `libc`,  these structures are likely used by functions within Bionic that wrap the underlying system calls or ioctl calls to the RDMA driver.

**5. Dynamic Linker Considerations:**

While the header file itself doesn't directly *implement* dynamic linking, the presence of `db_mmap_key` in several response structures suggests memory mapping, which is often tied to dynamic linking and shared memory. The `mmap_key` likely represents a shared memory region used for communication between the user-space library and the kernel driver. This is where the dynamic linker plays a role in setting up the address space and mappings.

**6. Hypothetical Input/Output (Logical Reasoning):**

For structures like `irdma_alloc_ucontext_req`, we can imagine a user-space application setting `userspace_ver` to match its supported ABI version. The kernel's response in `irdma_alloc_ucontext_resp` would then dictate the available features and limits. If the versions don't match, the allocation might fail or have limited functionality.

**7. Common Usage Errors:**

Based on the structure definitions, potential errors include:

* **Incorrect buffer sizes:** Providing insufficient buffer space for CQs or QPs.
* **Version mismatch:** Using an incompatible ABI version.
* **Invalid flags:** Setting incorrect flags during allocation or other operations.
* **Memory access violations:** Incorrectly using the `mmap_key` to access shared memory.

**8. Android Framework/NDK and Frida Hooking:**

To trace how this header is used in Android, we'd look for:

* **NDK APIs:**  Are there NDK functions that expose RDMA capabilities?
* **Android Framework:** Does the framework interact with RDMA for specific features (e.g., high-performance networking)?
* **System Calls/IOCTLs:**  Ultimately, these structures will be used in system calls (likely `ioctl`) to communicate with the RDMA kernel driver.

Frida can be used to hook these system calls or functions within Bionic that use these structures. We could set hooks on `ioctl` and examine the arguments to see when structures defined in `irdma-abi.handroid` are being passed. We could also hook specific functions within Bionic that are likely to interact with RDMA.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the individual structures without fully grasping the overarching purpose – defining the user-space API for an RDMA driver on Android. Realizing this helps connect the individual pieces together and understand the bigger picture. Also, recognizing the `uapi` directory's significance is key to understanding the user-kernel interaction. The "handroid" suffix is a valuable clue, suggesting Android-specific modifications or constraints.
这个C头文件 `irdma-abi.handroid` 定义了用户空间程序与 Linux 内核中 `irdma` (可能是 InfiniBand RDMA driver for Android) 子系统进行交互的接口。它属于 Android 的 Bionic 库，位于 `libc/kernel/uapi/rdma/` 目录下，这表明它是用户空间 API 的一部分，用于与内核驱动程序通信。

**功能列举:**

这个头文件定义了一系列数据结构（`struct`）和枚举类型（`enum`），用于在用户空间和内核之间传递 RDMA (Remote Direct Memory Access) 操作的请求和响应。其主要功能可以概括为：

1. **定义 ABI 版本:**  `#define IRDMA_ABI_VER 5` 定义了 Application Binary Interface 的版本号，确保用户空间程序和内核驱动程序之间的兼容性。

2. **定义内存注册类型:** `enum irdma_memreg_type` 定义了内存注册的类型，例如注册普通内存、队列对 (QP) 相关的内存、完成队列 (CQ) 相关的内存。

3. **定义用户上下文分配的标志:**  匿名 `enum` 定义了分配用户上下文时的可选标志，例如 `IRDMA_ALLOC_UCTX_USE_RAW_ATTR` 和 `IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE`，用于指定分配行为。

4. **定义分配用户上下文的请求和响应结构:**
   - `struct irdma_alloc_ucontext_req`: 用户空间程序向内核请求分配用户上下文时发送的请求结构。包含用户空间 ABI 版本号 (`userspace_ver`) 和一个能力掩码 (`comp_mask`)。
   - `struct irdma_alloc_ucontext_resp`: 内核响应用户上下文分配请求时返回的结构。包含了诸如最大 PD (Protection Domain) 数量、最大 QP 数量、工作队列大小 (`wq_size`)、内核版本号、特性标志 (`feature_flags`)、数据库内存映射的键值 (`db_mmap_key`) 等信息。这些信息对于用户空间程序了解硬件和驱动程序的能力至关重要。

5. **定义分配保护域 (PD) 的响应结构:** `struct irdma_alloc_pd_resp` 包含分配的 PD 的 ID (`pd_id`)。

6. **定义调整完成队列 (CQ) 大小的请求结构:** `struct irdma_resize_cq_req` 允许用户空间指定新的完成队列缓冲区地址。

7. **定义创建完成队列 (CQ) 的请求和响应结构:**
   - `struct irdma_create_cq_req`: 用户空间请求创建 CQ 时发送的请求结构，包含用户空间提供的 CQ 缓冲区地址 (`user_cq_buf`) 和影子区域地址 (`user_shadow_area`)。
   - `struct irdma_create_cq_resp`: 内核响应 CQ 创建请求时返回的结构，包含分配的 CQ 的 ID (`cq_id`) 和大小 (`cq_size`)。

8. **定义创建队列对 (QP) 的请求和响应结构:**
   - `struct irdma_create_qp_req`: 用户空间请求创建 QP 时发送的请求结构，包含用户空间提供的 WQE (Work Queue Entry) 缓冲区地址 (`user_wqe_bufs`) 和完成上下文地址 (`user_compl_ctx`)。
   - `struct irdma_create_qp_resp`: 内核响应 QP 创建请求时返回的结构，包含分配的 QP 的 ID (`qp_id`)、实际的发送队列和接收队列大小 (`actual_sq_size`, `actual_rq_size`)、驱动程序选项 (`irdma_drv_opt`)、推送索引 (`push_idx`) 等信息。

9. **定义内存注册的请求结构:** `struct irdma_mem_reg_req` 用于请求注册内存，包含注册类型 (`reg_type`) 以及 CQ、RQ、SQ 所需的页数。

10. **定义修改队列对 (QP) 的请求和响应结构:**
    - `struct irdma_modify_qp_req`: 用户空间请求修改 QP 属性时发送的请求结构，例如刷新发送队列 (`sq_flush`) 或接收队列 (`rq_flush`)。
    - `struct irdma_modify_qp_resp`: 内核响应 QP 修改请求时返回的结构，包含用于推送 WQE 和数据库更新的内存映射键值 (`push_wqe_mmap_key`, `push_db_mmap_key`) 和偏移量 (`push_offset`)。

11. **定义创建地址句柄 (AH) 的响应结构:** `struct irdma_create_ah_resp` 包含分配的 AH 的 ID (`ah_id`)。

**与 Android 功能的关系及举例说明:**

这个头文件直接与 Android 系统底层的硬件加速和高性能网络相关。RDMA 技术允许网络适配器直接访问服务器的内存，而无需 CPU 的参与，从而显著降低延迟并提高吞吐量。

**举例说明:**

* **高性能网络应用:** Android 设备如果需要运行对网络延迟和带宽有较高要求的应用，例如高性能计算、数据中心应用或者一些特定的游戏场景，可能会利用 RDMA 技术来提升网络性能。
* **存储访问:**  Android 系统可能使用 RDMA 来加速访问远程存储设备，例如通过 NVMe over Fabrics (NVMe-oF) 连接的存储阵列。
* **进程间通信 (IPC):** 在某些高级场景下，Android 系统内部的某些服务或组件可能会利用 RDMA 进行更高效的进程间通信。

**详细解释 libc 函数的功能实现:**

这个头文件本身不是 libc 函数的实现，而是定义了与内核交互的数据结构。libc 中与 RDMA 相关的函数（如果有）会使用这些结构体来构建系统调用或 ioctl 请求，从而与内核中的 RDMA 驱动程序进行通信。

**例如，假设 libc 中有一个函数 `irdma_alloc_ucontext()`，它的功能可能是:**

1. **构建 `irdma_alloc_ucontext_req` 结构体:** 根据用户提供的参数（例如所需的 ABI 版本），填充 `irdma_alloc_ucontext_req` 结构体的成员。
2. **发起系统调用或 ioctl:**  使用系统调用接口（例如 `syscall(__NR_ioctl, ...)`）将构建好的请求结构体传递给内核中负责处理 RDMA 相关操作的驱动程序。
3. **接收内核响应:**  内核处理请求后，会将响应数据填充到 `irdma_alloc_ucontext_resp` 结构体中返回给用户空间。
4. **解析和返回结果:** `irdma_alloc_ucontext()` 函数会解析响应结构体中的数据，并将有用的信息（例如分配到的最大 QP 数量）返回给调用者。

**涉及 dynamic linker 的功能，对应的 so 布局样本和链接处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 负责加载和链接共享库 (`.so` 文件)。

**如果 RDMA 功能被封装在一个共享库中，例如 `librdma.so`，那么它的布局样本可能如下：**

```
librdma.so:
    .text          # 代码段，包含 RDMA 相关的函数实现 (例如上面假设的 irdma_alloc_ucontext)
    .rodata        # 只读数据段，包含常量
    .data          # 可读写数据段，包含全局变量
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .plt           # 程序链接表
    .got           # 全局偏移表
```

**链接处理过程:**

1. **加载:** 当一个应用程序需要使用 `librdma.so` 中的功能时，dynamic linker 会将 `librdma.so` 加载到进程的地址空间。
2. **符号解析:** Dynamic linker 会解析应用程序和 `librdma.so` 中的动态符号表，找到应用程序调用的 `librdma.so` 中函数的地址。
3. **重定位:**  由于共享库加载到内存的地址可能每次都不同，dynamic linker 需要修改代码和数据段中的地址，使其指向正确的内存位置。这主要通过 `.rel.dyn` 表完成。
4. **PLT/GOT:**  对于外部函数的调用，通常会使用 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT)。PLT 中的条目会跳转到 GOT 中对应的地址，GOT 中的地址在首次调用时会被 dynamic linker 解析并更新为实际的函数地址。

**假设输入与输出（逻辑推理）：**

**假设场景：** 用户空间程序尝试分配一个用户上下文。

**假设输入 (`irdma_alloc_ucontext_req`):**

```c
struct irdma_alloc_ucontext_req req;
req.rsvd32 = 0;
req.userspace_ver = 5; // 假设用户空间支持 ABI 版本 5
req.rsvd8[0] = 0;
req.rsvd8[1] = 0;
req.rsvd8[2] = 0;
req.comp_mask = 0x0000000000000001; // 假设请求使用 raw attribute
```

**假设输出 (`irdma_alloc_ucontext_resp`):**

```c
struct irdma_alloc_ucontext_resp resp;
resp.max_pds = 16;
resp.max_qps = 1024;
resp.wq_size = 65536;
resp.kernel_ver = 5; // 假设内核也支持 ABI 版本 5
resp.rsvd[0] = 0;
resp.rsvd[1] = 0;
resp.rsvd[2] = 0;
resp.feature_flags = 0x0000000000000003; // 假设支持某些特性
resp.db_mmap_key = 0x1234567890abcdef; // 假设数据库内存映射的键值
// ... 其他字段
```

**逻辑推理:** 用户空间程序发送了一个版本号为 5，并请求使用 raw attribute 的用户上下文分配请求。内核响应指示分配成功，并返回了硬件和驱动程序的相关能力信息，例如最大 PD 和 QP 数量，以及用于共享内存的映射键值。

**用户或编程常见的使用错误:**

1. **ABI 版本不匹配:** 用户空间程序使用的 ABI 版本与内核驱动程序支持的版本不一致。这会导致请求被内核拒绝或行为不符合预期。例如，如果用户空间程序使用 `IRDMA_ABI_VER 6`，但内核只支持到 `IRDMA_ABI_VER 5`，分配用户上下文可能会失败。

2. **缓冲区大小不足:** 在创建 CQ 或 QP 时，提供的用户空间缓冲区大小不足以容纳所需的条目数量。例如，`irdma_create_cq_req` 中的 `user_cq_buf` 指向的缓冲区太小，无法容纳内核分配的 CQ。

3. **非法参数:** 传递给请求结构体的参数值超出有效范围或不符合内核的要求。例如，`irdma_mem_reg_req` 中的页数设置过大，超过系统限制。

4. **内存管理错误:**  不正确地管理用于 RDMA 操作的内存，例如在使用完后过早释放，或者在多个操作中使用了错误的内存地址。

5. **竞争条件:**  在多线程或多进程环境下，如果没有适当的同步机制，多个线程或进程可能同时尝试访问或修改 RDMA 资源，导致数据损坏或程序崩溃。

**Android framework 或 ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK API (假设存在):**  Android NDK 可能会提供一些用于访问底层硬件加速功能的 API，其中可能包括 RDMA 相关的接口。开发者可以使用这些 NDK API 来编写 C/C++ 代码，利用 RDMA 功能。

2. **用户空间库 (假设存在):** NDK API 可能会封装在一些共享库中，例如上面提到的 `librdma.so`。这些库会使用头文件 `irdma-abi.handroid` 中定义的结构体来构建与内核通信的请求。

3. **系统调用或 ioctl:** 用户空间库最终会通过系统调用（例如 `ioctl`）与内核驱动程序进行交互。`ioctl` 调用的命令参数会指示要执行的 RDMA 操作，而请求和响应数据会通过 `ioctl` 调用的参数传递。

4. **内核驱动程序 (`irdma`):**  内核中的 `irdma` 驱动程序会接收到用户空间的请求，解析请求结构体中的数据，执行相应的 RDMA 操作，并将结果填充到响应结构体中返回给用户空间。

**Frida Hook 示例调试步骤:**

假设我们要观察用户空间程序分配用户上下文的过程。我们可以 hook `ioctl` 系统调用，并过滤出与 `irdma` 相关的操作。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

def main():
    package_name = "your.target.app" # 替换为你的目标应用包名
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Error: Process '{package_name}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            // 这里需要根据实际的 ioctl 命令号判断是否是与 irdma 相关的操作
            // 具体的命令号需要查看内核驱动程序的定义
            const IRDMA_ALLOC_UCONTEXT_CMD = 0xABCD1234; // 替换为实际的 ioctl 命令号

            if (request === IRDMA_ALLOC_UCONTEXT_CMD) {
                console.log("[*] ioctl called with IRDMA_ALLOC_UCONTEXT_CMD");

                // 读取 irdma_alloc_ucontext_req 结构体的内容
                const reqPtr = ptr(argp);
                const rsvd32 = reqPtr.readU32();
                const userspace_ver = reqPtr.add(4).readU8();
                const comp_mask_low = reqPtr.add(8).readU32();
                const comp_mask_high = reqPtr.add(12).readU32();
                const comp_mask = BigInt(comp_mask_high) << BigInt(32) | BigInt(comp_mask_low);

                console.log("[*]   rsvd32:", rsvd32);
                console.log("[*]   userspace_ver:", userspace_ver);
                console.log("[*]   comp_mask:", comp_mask.toString(16));
            }
        },
        onLeave: function(retval) {
            // 可以观察 ioctl 的返回值
            // console.log("[*] ioctl returned:", retval.toInt32());
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 示例解释:**

1. **Attach 到目标进程:** 使用 Frida attach 到目标 Android 应用的进程。
2. **Hook `ioctl`:**  拦截 `libc.so` 中的 `ioctl` 函数调用。
3. **过滤 RDMA 相关操作:** 在 `onEnter` 函数中，检查 `ioctl` 的 `request` 参数（命令号），判断是否是与 `irdma` 相关的操作。你需要替换示例代码中的 `IRDMA_ALLOC_UCONTEXT_CMD` 为实际的 ioctl 命令号。
4. **读取请求结构体:** 如果是相关的 `ioctl` 调用，则读取 `argp` 指向的内存，解析出 `irdma_alloc_ucontext_req` 结构体中的成员值，例如 `userspace_ver` 和 `comp_mask`。
5. **打印信息:** 将解析出的信息打印到控制台。
6. **观察返回值 (可选):** 在 `onLeave` 函数中可以观察 `ioctl` 的返回值，判断操作是否成功。

**注意:**

* 你需要找到实际用于 `irdma` 相关操作的 ioctl 命令号，这通常需要在内核驱动程序的源代码中查找。
* 这个 Frida 脚本只是一个示例，可能需要根据具体的调试需求进行修改。
* 调试系统底层的 API 可能需要 root 权限或者在模拟器上进行。

通过以上步骤，你可以使用 Frida 逐步跟踪 Android Framework 或 NDK 如何调用到定义在 `irdma-abi.handroid` 中的接口，并观察传递的参数和内核的响应。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/irdma-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef IRDMA_ABI_H
#define IRDMA_ABI_H
#include <linux/types.h>
#define IRDMA_ABI_VER 5
enum irdma_memreg_type {
  IRDMA_MEMREG_TYPE_MEM = 0,
  IRDMA_MEMREG_TYPE_QP = 1,
  IRDMA_MEMREG_TYPE_CQ = 2,
};
enum {
  IRDMA_ALLOC_UCTX_USE_RAW_ATTR = 1 << 0,
  IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE = 1 << 1,
};
struct irdma_alloc_ucontext_req {
  __u32 rsvd32;
  __u8 userspace_ver;
  __u8 rsvd8[3];
  __aligned_u64 comp_mask;
};
struct irdma_alloc_ucontext_resp {
  __u32 max_pds;
  __u32 max_qps;
  __u32 wq_size;
  __u8 kernel_ver;
  __u8 rsvd[3];
  __aligned_u64 feature_flags;
  __aligned_u64 db_mmap_key;
  __u32 max_hw_wq_frags;
  __u32 max_hw_read_sges;
  __u32 max_hw_inline;
  __u32 max_hw_rq_quanta;
  __u32 max_hw_wq_quanta;
  __u32 min_hw_cq_size;
  __u32 max_hw_cq_size;
  __u16 max_hw_sq_chunk;
  __u8 hw_rev;
  __u8 rsvd2;
  __aligned_u64 comp_mask;
  __u16 min_hw_wq_size;
  __u8 rsvd3[6];
};
struct irdma_alloc_pd_resp {
  __u32 pd_id;
  __u8 rsvd[4];
};
struct irdma_resize_cq_req {
  __aligned_u64 user_cq_buffer;
};
struct irdma_create_cq_req {
  __aligned_u64 user_cq_buf;
  __aligned_u64 user_shadow_area;
};
struct irdma_create_qp_req {
  __aligned_u64 user_wqe_bufs;
  __aligned_u64 user_compl_ctx;
};
struct irdma_mem_reg_req {
  __u16 reg_type;
  __u16 cq_pages;
  __u16 rq_pages;
  __u16 sq_pages;
};
struct irdma_modify_qp_req {
  __u8 sq_flush;
  __u8 rq_flush;
  __u8 rsvd[6];
};
struct irdma_create_cq_resp {
  __u32 cq_id;
  __u32 cq_size;
};
struct irdma_create_qp_resp {
  __u32 qp_id;
  __u32 actual_sq_size;
  __u32 actual_rq_size;
  __u32 irdma_drv_opt;
  __u16 push_idx;
  __u8 lsmm;
  __u8 rsvd;
  __u32 qp_caps;
};
struct irdma_modify_qp_resp {
  __aligned_u64 push_wqe_mmap_key;
  __aligned_u64 push_db_mmap_key;
  __u16 push_offset;
  __u8 push_valid;
  __u8 rsvd[5];
};
struct irdma_create_ah_resp {
  __u32 ah_id;
  __u8 rsvd[4];
};
#endif
```