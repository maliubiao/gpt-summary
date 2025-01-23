Response:
Let's break down the thought process for analyzing the given C header file.

1. **Initial Understanding - Context is Key:** The prompt clearly states this is a kernel UAPI header file (`bionic/libc/kernel/uapi/rdma/bnxt_re-abi.handroid`). This immediately tells us several things:
    * **Kernel Interface:** It defines structures and constants used for communication *between* user-space applications (likely through a C library like bionic) and the Linux kernel.
    * **UAPI (User-space API):**  This means it's a stable interface that shouldn't change without careful consideration to avoid breaking user applications.
    * **RDMA (Remote Direct Memory Access):** This is the core functionality. The file will define structures and constants related to RDMA operations.
    * **`bnxt_re`:**  This likely refers to a specific RDMA hardware/driver, probably Broadcom's NetXtreme-E family. The "re" might stand for "Reliable Ethernet" or something similar.
    * **`-abi.handroid`:** This suffix signifies it's part of the Android's UAPI, potentially with Android-specific additions or adaptations, though this file seems standard.

2. **High-Level Structure Scan:**  I would quickly scan the file for major elements:
    * **Includes:** `<linux/types.h>` and `<rdma/ib_user_ioctl_cmds.h>` are crucial. They tell us we're dealing with standard Linux types and RDMA-specific ioctl commands.
    * **Macros:**  `BNXT_RE_ABI_VERSION` and the `BNXT_RE_CHIP_ID0_*` macros hint at versioning and hardware identification.
    * **Enums:**  These define sets of named constants. I'd group them mentally by their likely purpose (e.g., WQE modes, completion masks, object types).
    * **Structs:** These define data structures for exchanging information. I'd look for patterns in their names (e.g., `*_req`, `*_resp`) suggesting request/response structures.
    * **`__attribute__((packed, aligned(4)))`:** This is important for understanding memory layout and potential inter-process communication.

3. **Functional Grouping and Keyword Analysis:** Now I'd go through each section in more detail, looking for keywords and trying to infer the purpose:
    * **`BNXT_RE_UCNTX_*`:**  "UCNTX" likely stands for "User Context." The constants relate to enabling/disabling features for this context.
    * **`bnxt_re_wqe_mode`:** "WQE" is almost certainly "Work Queue Entry." This defines the modes for work requests.
    * **`BNXT_RE_COMP_MASK_*`:** "COMP" refers to "Completion."  These masks indicate supported features for completion processing.
    * **`bnxt_re_uctx_req`/`resp`:** Request and response structures for creating/querying a user context. Fields like `max_qp`, `cqe_sz`, `chip_id` provide context information.
    * **`bnxt_re_pd_resp`:** "PD" is likely "Protection Domain." This provides information about the protection domain. `dbr` probably means "Doorbell Register."
    * **`bnxt_re_cq_req`/`resp`:** "CQ" is "Completion Queue." These structures handle creation/querying of completion queues. `tail`, `phase` are common for managing circular buffers.
    * **`bnxt_re_resize_cq_req`:**  Self-explanatory.
    * **`bnxt_re_qp_req`/`resp`:** "QP" is "Queue Pair." These structures handle creation/querying of queue pairs, essential for RDMA communication.
    * **`bnxt_re_srq_req`/`resp`:** "SRQ" is "Shared Receive Queue."
    * **`bnxt_re_shpg_offt`:** "SHPG" might relate to "Shared Page" and defines offsets within it.
    * **`BNXT_RE_OBJECT_*`:**  These enums seem to define different types of RDMA objects that can be allocated or managed. The `UVERBS_ID_NS_SHIFT` suggests a namespacing mechanism.
    * **`BNXT_RE_ALLOC_PAGE_*`:** Functions related to allocating memory pages for different purposes (WC, DBR).
    * **`BNXT_RE_NOTIFY_DRV_*`:** Mechanism to notify the driver.
    * **`BNXT_RE_GET_TOGGLE_MEM_*`:**  Managing "toggle memory," likely used for synchronization.

4. **Connecting to Android (Conceptual):** At this stage, I'd think about how these low-level RDMA concepts relate to Android. While typical Android app developers don't interact with these directly, they are crucial for:
    * **High-Performance Networking:** If Android devices need ultra-fast networking (e.g., for some server-like applications or specialized hardware), RDMA might be used.
    * **Underlying Infrastructure:**  Android's framework might utilize RDMA internally for certain system services or hardware interactions.
    * **NDK (Native Development Kit):**  Advanced NDK developers *could* potentially use RDMA if they have the necessary hardware and driver support.

5. **Libc and Dynamic Linker:** The prompt specifically asks about `libc` and the dynamic linker.
    * **Libc Connection:**  The structures defined here are likely used by a higher-level RDMA library within Android's `libc`. This library would provide a more user-friendly API on top of these kernel structures, handling the necessary ioctls.
    * **Dynamic Linker (Conceptual):**  The dynamic linker isn't directly involved in the *functionality* of these structures. However, if a user-space library interacting with the RDMA driver is dynamically linked (common in Android), the linker would be responsible for loading that library and resolving its symbols.

6. **Illustrative Examples (Mental Simulation):** I would think of simple scenarios to illustrate the use of these structures:
    * **Creating a User Context:** A user-space program would need to fill a `bnxt_re_uctx_req` structure and issue an ioctl to the RDMA device. The kernel would respond with a `bnxt_re_uctx_resp` containing information about the created context.
    * **Allocating a Completion Queue:** Similar process using `bnxt_re_cq_req` and `bnxt_re_cq_resp`.

7. **Error Handling and Common Mistakes:** I'd consider potential pitfalls:
    * **Incorrect Structure Size/Alignment:**  Mismatched sizes or alignment between user-space and kernel can lead to crashes or data corruption. The `packed` and `aligned` attributes are important here.
    * **Invalid Parameter Values:**  Passing incorrect values in the request structures can lead to errors.
    * **Resource Exhaustion:** Trying to allocate too many QPs or CQs.
    * **Incorrect ioctl Usage:**  Using the wrong ioctl commands or sequence.

8. **Frida Hooking (Conceptual):** I would think about *where* to hook with Frida to observe these interactions:
    * **ioctl Calls:** Hooking the `ioctl` system call would be the most direct way to see the structures being passed between user-space and the kernel.
    * **Functions in the RDMA Library:** If I knew the name of the RDMA library functions in `libc`, I could hook those to see how they populate these kernel structures.

9. **Refinement and Organization:**  Finally, I would organize my thoughts into a coherent response, explaining each part clearly and providing examples where appropriate. The goal is to be comprehensive but also understandable. I would use headings and bullet points to structure the information.

This systematic approach allows me to dissect the header file, understand its purpose, connect it to the broader Android context, and address all aspects of the prompt.
这是一个定义了 Broadcom NetXtreme-E (bnxt_re) RDMA 驱动用户空间 API 的头文件。它位于 Android 的 Bionic C 库的内核头文件目录下，这意味着它定义了用户空间程序与内核中的 bnxt_re RDMA 驱动进行交互的接口。

**功能列举:**

这个头文件定义了用于与 bnxt_re RDMA 驱动交互的数据结构和常量，主要涉及以下功能：

1. **ABI 版本定义:**  `BNXT_RE_ABI_VERSION` 定义了此 API 的版本号，用于兼容性检查。
2. **芯片信息:** `BNXT_RE_CHIP_ID0_*` 定义了用于提取芯片 ID、修订号和元信息的位移常量。
3. **用户上下文 (User Context):**
    * `BNXT_RE_UCNTX_CMASK_*`: 定义了用户上下文的配置掩码，例如是否启用 CCTX、工作队列条目 (WQE) 的各种特性等。
4. **工作队列条目 (Work Queue Entry) 模式:**
    * `enum bnxt_re_wqe_mode`: 定义了 WQE 的模式，例如静态、可变或无效。
5. **完成 (Completion) 掩码:**
    * `BNXT_RE_COMP_MASK_*`: 定义了完成操作相关的特性支持，例如是否支持用户上下文的 2 的幂次方大小或可变大小 WQE。
6. **用户上下文请求和响应:**
    * `struct bnxt_re_uctx_req`: 定义了创建或查询用户上下文的请求结构。
    * `struct bnxt_re_uctx_resp`: 定义了用户上下文的响应结构，包含设备 ID、最大队列对 (QP) 数量、页大小、完成队列条目 (CQE) 大小等信息。
7. **保护域 (Protection Domain) 响应:**
    * `struct bnxt_re_pd_resp`: 定义了保护域的响应结构，包含保护域 ID (pdid)、域进程隔离 (dpi) 和门铃寄存器 (dbr) 地址。
8. **完成队列 (Completion Queue) 请求和响应:**
    * `struct bnxt_re_cq_req`: 定义了创建完成队列的请求结构，包含完成队列的虚拟地址 (cq_va) 和句柄 (cq_handle)。
    * `enum bnxt_re_cq_mask`: 定义了完成队列的掩码，例如是否支持翻页。
    * `struct bnxt_re_cq_resp`: 定义了完成队列的响应结构，包含完成队列 ID (cqid)、尾指针 (tail)、相位 (phase) 和能力掩码。
9. **调整完成队列大小请求:**
    * `struct bnxt_re_resize_cq_req`: 定义了调整完成队列大小的请求结构。
10. **队列对 (Queue Pair) 请求和响应:**
    * `enum bnxt_re_qp_mask`: 定义了队列对的掩码，例如是否需要可变大小 WQE 的发送队列槽位。
    * `struct bnxt_re_qp_req`: 定义了创建队列对的请求结构，包含发送和接收队列的虚拟地址、句柄、能力掩码和发送队列槽位数。
    * `struct bnxt_re_qp_resp`: 定义了队列对的响应结构，包含队列对 ID (qpid)。
11. **共享接收队列 (Shared Receive Queue) 请求和响应:**
    * `struct bnxt_re_srq_req`: 定义了创建共享接收队列的请求结构，包含 SRQ 的虚拟地址和句柄。
    * `enum bnxt_re_srq_mask`: 定义了共享接收队列的掩码，例如是否支持翻页。
    * `struct bnxt_re_srq_resp`: 定义了共享接收队列的响应结构，包含共享接收队列 ID (srqid) 和能力掩码。
12. **共享页偏移量:**
    * `enum bnxt_re_shpg_offt`: 定义了共享页内的不同偏移量，例如保留区域的起始和结束偏移，以及可用 ID (AVID) 的偏移和大小。
13. **对象类型:**
    * `enum bnxt_re_objects`: 定义了不同类型的 RDMA 对象，例如分配页、通知驱动和获取翻页内存。
14. **分配页相关:**
    * `enum bnxt_re_alloc_page_type`: 定义了分配页的类型，例如工作完成页、门铃寄存器 BAR 页和门铃寄存器页。
    * `enum bnxt_re_var_alloc_page_attrs`: 定义了可变分配页的属性，例如句柄、类型、DPI、mmap 偏移和长度。
    * `enum bnxt_re_alloc_page_attrs`: 定义了分配页的属性，例如销毁页句柄。
    * `enum bnxt_re_alloc_page_methods`: 定义了分配页的方法，例如分配页和销毁页。
15. **通知驱动方法:**
    * `enum bnxt_re_notify_drv_methods`: 定义了通知驱动的方法。
16. **获取翻页内存相关:**
    * `enum bnxt_re_get_toggle_mem_type`: 定义了获取翻页内存的类型，例如 CQ 和 SRQ 的翻页内存。
    * `enum bnxt_re_var_toggle_mem_attrs`: 定义了可变翻页内存的属性，例如句柄、类型、资源 ID、mmap 页号、偏移和长度。
    * `enum bnxt_re_toggle_mem_attrs`: 定义了翻页内存的属性，例如释放翻页内存句柄。
    * `enum bnxt_re_toggle_mem_methods`: 定义了翻页内存的方法，例如获取和释放翻页内存。

**与 Android 功能的关系及举例说明:**

这个头文件定义的是底层的 RDMA 接口，通常不会被直接用于上层 Android 应用开发。它更多地服务于需要高性能网络通信的场景。

**举例说明:**

* **Android 设备的硬件加速:** 如果 Android 设备使用了支持 RDMA 的网卡 (例如 Broadcom 的 NetXtreme-E 系列)，那么 Android Framework 或者特定的系统服务可能会利用这些接口来实现更高效的网络数据传输。例如，在某些数据中心或高性能计算场景下的 Android 设备，可能会使用 RDMA 进行节点间的高速通信。
* **NDK 开发:**  虽然不常见，但理论上，使用 Android NDK 进行底层开发的程序员，如果需要直接操作支持 RDMA 的硬件，可能会涉及到这些接口。他们可以通过 NDK 调用 Linux 内核提供的 RDMA 相关系统调用，而这些系统调用会使用到这里定义的结构体。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**没有定义任何 libc 函数**。它定义的是内核 UAPI，即用户空间程序与内核驱动程序交互的数据结构。用户空间程序需要通过系统调用 (例如 `ioctl`) 来使用这些结构体，与内核中的 bnxt_re 驱动进行通信。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**动态链接器与此头文件直接关联不大。**  动态链接器负责加载和链接动态链接库 (`.so` 文件)。

如果用户空间的应用程序或者一个共享库需要使用 RDMA 功能，它可能会链接到一个提供 RDMA 功能抽象的库。这个库内部可能会使用到这里定义的内核接口。

**SO 布局样本 (假设存在一个提供 bnxt_re RDMA 抽象的库 `libbnxtrdma.so`):**

```
libbnxtrdma.so:
    OFFSET  SIZE   ALIGN   SECTION
    ......
    0x1000  0x200   16      .text       # 代码段
    0x1200  0x100   8       .rodata     # 只读数据段
    0x1300  0x80    8       .data       # 已初始化数据段
    0x1380  0x40    8       .bss        # 未初始化数据段
    ......
    0x2000  0x50    8       .dynsym     # 动态符号表
    0x2050  0x30    8       .dynstr     # 动态字符串表
    0x2080  0x20    8       .rel.dyn    # 动态重定位表
    ......
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序或共享库编译时，链接器会记录下需要 `libbnxtrdma.so` 提供的符号 (例如函数)。
2. **运行时加载:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libbnxtrdma.so`。
3. **符号解析:** 动态链接器会遍历所有已加载的共享库的动态符号表 (`.dynsym`)，找到应用程序或共享库中未定义的符号，并在 `libbnxtrdma.so` 中找到对应的符号地址。
4. **重定位:** 动态链接器会修改应用程序或共享库的代码和数据段，将对外部符号的引用指向 `libbnxtrdma.so` 中解析到的地址。

**与本头文件的关系:** `libbnxtrdma.so` 内部的代码会包含使用 `ioctl` 系统调用并传递此处定义的结构体的逻辑，以便与内核中的 bnxt_re 驱动进行通信。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要创建一个完成队列。

**假设输入 (填充 `bnxt_re_cq_req` 结构体):**

```c
struct bnxt_re_cq_req req;
req.cq_va = 0x10000000; // 完成队列的虚拟地址
req.cq_handle = 0xABCDEF0123456789; // 用户空间的句柄
```

**系统调用:**  用户空间程序会调用 `ioctl` 系统调用，并将 `req` 结构体作为参数传递给内核的 bnxt_re 驱动。

**假设输出 (内核返回的 `bnxt_re_cq_resp` 结构体):**

```c
struct bnxt_re_cq_resp resp;
// 假设内核成功创建了完成队列
resp.cqid = 123; // 分配的完成队列 ID
resp.tail = 0;   // 初始尾指针
resp.phase = 1;  // 初始相位
resp.rsvd = 0;
resp.comp_mask = BNXT_RE_CQ_TOGGLE_PAGE_SUPPORT; // 支持翻页
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **内存分配错误:** 用户空间程序可能没有为完成队列分配足够的内存，或者提供的虚拟地址无效，导致内核访问错误。
2. **句柄管理错误:**  句柄 (例如 `cq_handle`) 是用户空间的概念，用于标识资源。如果句柄管理不当，可能会导致重复释放或使用无效句柄。
3. **ioctl 调用错误:**  使用了错误的 `ioctl` 命令号或者传递了错误大小的结构体，导致内核无法正确解析请求。
4. **并发访问问题:**  多个线程或进程同时操作同一个 RDMA 资源，可能导致数据竞争和状态不一致。
5. **参数校验不足:**  传递给 `ioctl` 的结构体中的某些字段可能超出有效范围，但用户空间程序没有进行必要的校验。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的路径非常间接，并且通常不会直接涉及。**  Framework 更倾向于使用更高层次的网络抽象。

**NDK 到达这里的路径:**

1. **NDK 应用开发:** 开发者使用 NDK 编写 C/C++ 代码。
2. **调用标准 Linux 系统调用:** 开发者需要使用 `syscall()` 函数直接调用 Linux 内核提供的 RDMA 相关系统调用，例如 `ioctl`。
3. **包含头文件:** 开发者需要在代码中包含 `<linux/rdma/bnxt_re-abi.h>` (或其在 Android 系统中的路径)。
4. **填充结构体:** 开发者需要按照此头文件定义的格式填充相应的结构体，例如 `bnxt_re_cq_req`。
5. **发起 ioctl 调用:** 开发者调用 `ioctl` 系统调用，将填充好的结构体传递给内核驱动。

**Frida Hook 示例:**

假设我们想 hook `ioctl` 系统调用，查看传递给 bnxt_re 驱动的 `bnxt_re_cq_req` 结构体内容。

```javascript
// Frida 脚本
const ioctl = Module.findExportByName(null, "ioctl");
if (ioctl) {
  Interceptor.attach(ioctl, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();
      const argp = args[2];

      // 假设 bnxt_re 驱动的 ioctl 命令号在某个范围内，例如这里假设为 0xC000 ~ 0xCFFF
      if (request >= 0xC000 && request <= 0xCFFF) {
        console.log("ioctl called with fd:", fd, "request:", request);

        // 这里需要根据具体的 ioctl 命令号来判断 argp 指向的结构体类型
        // 假设 request 是创建 CQ 的命令 (需要查阅 bnxt_re 驱动的定义)
        // 并且 argp 指向 bnxt_re_cq_req 结构体
        if (request == /* 假设的创建 CQ 命令号 */) {
          const cq_req = Memory.readByteArray(argp, /* sizeof(struct bnxt_re_cq_req) */);
          console.log("bnxt_re_cq_req:", hexdump(cq_req, { ansi: true }));
        }
      }
    },
  });
} else {
  console.log("Error: ioctl symbol not found.");
}
```

**调试步骤:**

1. **找到目标进程:**  运行需要调试的 Android 应用或服务。
2. **使用 Frida 连接:** 使用 `frida -U -f <package_name> -l script.js` 或 `frida -U <process_id> -l script.js` 将 Frida 脚本注入到目标进程。
3. **观察输出:** 当目标进程调用 `ioctl` 系统调用且命令号在指定范围内时，Frida 脚本会在控制台打印相关信息，包括传递给 `ioctl` 的参数，以及 `bnxt_re_cq_req` 结构体的内存内容。

**注意:**  要准确 hook 和解析 bnxt_re 相关的 `ioctl` 调用，需要：

* **确定 bnxt_re 驱动的设备文件描述符 (fd) 的范围或特征。**
* **查阅 bnxt_re 驱动的源代码或文档，找到相关的 ioctl 命令号以及对应结构体的定义。** 上述示例中的命令号是假设的。
* **确保 Frida 运行在具有足够权限的环境中，以便 hook 系统调用。**

这个头文件是 Android 系统中与特定硬件 (Broadcom NetXtreme-E 网卡) 的 RDMA 功能交互的底层接口，主要服务于高性能网络需求，并且通常只会被底层的系统组件或者使用 NDK 进行开发的应用程序直接使用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/bnxt_re-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __BNXT_RE_UVERBS_ABI_H__
#define __BNXT_RE_UVERBS_ABI_H__
#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>
#define BNXT_RE_ABI_VERSION 1
#define BNXT_RE_CHIP_ID0_CHIP_NUM_SFT 0x00
#define BNXT_RE_CHIP_ID0_CHIP_REV_SFT 0x10
#define BNXT_RE_CHIP_ID0_CHIP_MET_SFT 0x18
enum {
  BNXT_RE_UCNTX_CMASK_HAVE_CCTX = 0x1ULL,
  BNXT_RE_UCNTX_CMASK_HAVE_MODE = 0x02ULL,
  BNXT_RE_UCNTX_CMASK_WC_DPI_ENABLED = 0x04ULL,
  BNXT_RE_UCNTX_CMASK_DBR_PACING_ENABLED = 0x08ULL,
  BNXT_RE_UCNTX_CMASK_POW2_DISABLED = 0x10ULL,
  BNXT_RE_UCNTX_CMASK_MSN_TABLE_ENABLED = 0x40,
};
enum bnxt_re_wqe_mode {
  BNXT_QPLIB_WQE_MODE_STATIC = 0x00,
  BNXT_QPLIB_WQE_MODE_VARIABLE = 0x01,
  BNXT_QPLIB_WQE_MODE_INVALID = 0x02,
};
enum {
  BNXT_RE_COMP_MASK_REQ_UCNTX_POW2_SUPPORT = 0x01,
  BNXT_RE_COMP_MASK_REQ_UCNTX_VAR_WQE_SUPPORT = 0x02,
};
struct bnxt_re_uctx_req {
  __aligned_u64 comp_mask;
};
struct bnxt_re_uctx_resp {
  __u32 dev_id;
  __u32 max_qp;
  __u32 pg_size;
  __u32 cqe_sz;
  __u32 max_cqd;
  __u32 rsvd;
  __aligned_u64 comp_mask;
  __u32 chip_id0;
  __u32 chip_id1;
  __u32 mode;
  __u32 rsvd1;
};
struct bnxt_re_pd_resp {
  __u32 pdid;
  __u32 dpi;
  __u64 dbr;
} __attribute__((packed, aligned(4)));
struct bnxt_re_cq_req {
  __aligned_u64 cq_va;
  __aligned_u64 cq_handle;
};
enum bnxt_re_cq_mask {
  BNXT_RE_CQ_TOGGLE_PAGE_SUPPORT = 0x1,
};
struct bnxt_re_cq_resp {
  __u32 cqid;
  __u32 tail;
  __u32 phase;
  __u32 rsvd;
  __aligned_u64 comp_mask;
};
struct bnxt_re_resize_cq_req {
  __aligned_u64 cq_va;
};
enum bnxt_re_qp_mask {
  BNXT_RE_QP_REQ_MASK_VAR_WQE_SQ_SLOTS = 0x1,
};
struct bnxt_re_qp_req {
  __aligned_u64 qpsva;
  __aligned_u64 qprva;
  __aligned_u64 qp_handle;
  __aligned_u64 comp_mask;
  __u32 sq_slots;
};
struct bnxt_re_qp_resp {
  __u32 qpid;
  __u32 rsvd;
};
struct bnxt_re_srq_req {
  __aligned_u64 srqva;
  __aligned_u64 srq_handle;
};
enum bnxt_re_srq_mask {
  BNXT_RE_SRQ_TOGGLE_PAGE_SUPPORT = 0x1,
};
struct bnxt_re_srq_resp {
  __u32 srqid;
  __u32 rsvd;
  __aligned_u64 comp_mask;
};
enum bnxt_re_shpg_offt {
  BNXT_RE_BEG_RESV_OFFT = 0x00,
  BNXT_RE_AVID_OFFT = 0x10,
  BNXT_RE_AVID_SIZE = 0x04,
  BNXT_RE_END_RESV_OFFT = 0xFF0
};
enum bnxt_re_objects {
  BNXT_RE_OBJECT_ALLOC_PAGE = (1U << UVERBS_ID_NS_SHIFT),
  BNXT_RE_OBJECT_NOTIFY_DRV,
  BNXT_RE_OBJECT_GET_TOGGLE_MEM,
};
enum bnxt_re_alloc_page_type {
  BNXT_RE_ALLOC_WC_PAGE = 0,
  BNXT_RE_ALLOC_DBR_BAR_PAGE,
  BNXT_RE_ALLOC_DBR_PAGE,
};
enum bnxt_re_var_alloc_page_attrs {
  BNXT_RE_ALLOC_PAGE_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
  BNXT_RE_ALLOC_PAGE_TYPE,
  BNXT_RE_ALLOC_PAGE_DPI,
  BNXT_RE_ALLOC_PAGE_MMAP_OFFSET,
  BNXT_RE_ALLOC_PAGE_MMAP_LENGTH,
};
enum bnxt_re_alloc_page_attrs {
  BNXT_RE_DESTROY_PAGE_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};
enum bnxt_re_alloc_page_methods {
  BNXT_RE_METHOD_ALLOC_PAGE = (1U << UVERBS_ID_NS_SHIFT),
  BNXT_RE_METHOD_DESTROY_PAGE,
};
enum bnxt_re_notify_drv_methods {
  BNXT_RE_METHOD_NOTIFY_DRV = (1U << UVERBS_ID_NS_SHIFT),
};
enum bnxt_re_get_toggle_mem_type {
  BNXT_RE_CQ_TOGGLE_MEM = 0,
  BNXT_RE_SRQ_TOGGLE_MEM,
};
enum bnxt_re_var_toggle_mem_attrs {
  BNXT_RE_TOGGLE_MEM_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
  BNXT_RE_TOGGLE_MEM_TYPE,
  BNXT_RE_TOGGLE_MEM_RES_ID,
  BNXT_RE_TOGGLE_MEM_MMAP_PAGE,
  BNXT_RE_TOGGLE_MEM_MMAP_OFFSET,
  BNXT_RE_TOGGLE_MEM_MMAP_LENGTH,
};
enum bnxt_re_toggle_mem_attrs {
  BNXT_RE_RELEASE_TOGGLE_MEM_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};
enum bnxt_re_toggle_mem_methods {
  BNXT_RE_METHOD_GET_TOGGLE_MEM = (1U << UVERBS_ID_NS_SHIFT),
  BNXT_RE_METHOD_RELEASE_TOGGLE_MEM,
};
#endif
```