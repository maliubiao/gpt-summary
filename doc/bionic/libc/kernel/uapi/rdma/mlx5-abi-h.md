Response:
My thought process for analyzing the provided C header file and generating the comprehensive response involved the following steps:

1. **Understanding the Context:**  The initial prompt clearly states this is a header file (`mlx5-abi.handroid`) located within the Android Bionic library, specifically related to RDMA (Remote Direct Memory Access) and the Mellanox ConnectX-5 (mlx5) network adapter. The "uapi" in the path indicates it's a user-space API for interacting with the kernel.

2. **High-Level Overview:** I first skimmed the code to get a general understanding. I noticed a lot of `enum` definitions, `struct` definitions, and `#define` statements. This immediately suggested that the file defines constants, data structures, and flags for interacting with the mlx5 RDMA driver.

3. **Categorizing the Content:** I mentally started grouping the definitions by their purpose:
    * **Flags:**  Definitions like `MLX5_QP_FLAG_SIGNATURE`, `MLX5_SRQ_FLAG_SIGNATURE`, `MLX5_WQ_FLAG_SIGNATURE` seemed to be boolean indicators for various QP (Queue Pair), SRQ (Shared Receive Queue), and WQ (Work Queue) features.
    * **Enums:**  Enumerated types like `mlx5_lib_caps`, `mlx5_ib_alloc_uctx_v2_flags`, `mlx5_user_inline_mode`, etc., clearly define sets of related named constants, often representing different options or states.
    * **Structures:**  Structures like `mlx5_ib_alloc_ucontext_req`, `mlx5_ib_create_cq`, `mlx5_ib_query_device_resp`, etc., define the layout of data exchanged between user-space and the kernel, typically for making requests or receiving responses.
    * **Versioning:** The `MLX5_IB_UVERBS_ABI_VERSION` definition indicated an API version.

4. **Identifying Core RDMA Concepts:** I recognized terms like "QP," "CQ," "SRQ," "WQ," "UAR," "PD," "MR," which are fundamental to RDMA programming. This helped me understand the file's domain.

5. **Analyzing Individual Components:**  I started examining each `enum` and `struct` more closely. For each:
    * **Function/Purpose:** I tried to infer its role based on its name and the names of its members. For example, `mlx5_ib_alloc_ucontext_req` clearly relates to allocating a user context, and its members `total_num_bfregs` and `num_low_latency_bfregs` suggested control over buffer regions.
    * **Relationship to RDMA:** I linked each definition back to core RDMA concepts. For instance, `mlx5_ib_create_cq` is obviously about creating a Completion Queue.
    * **Potential Android Relevance:**  I considered how these RDMA features might be used within Android. The possibility of high-performance networking for features like inter-process communication, storage access, or even advanced networking applications came to mind.

6. **Focusing on Android Integration (Hypothesizing):**  Since the file is in Bionic, the Android C library, I reasoned that Android likely uses these definitions to interact with mlx5-based network hardware. I hypothesized that the Android framework or NDK might provide higher-level APIs that eventually translate into these low-level ioctl calls defined by these structures.

7. **Considering the Dynamic Linker:** The prompt specifically mentioned the dynamic linker. I noted that this header file *itself* doesn't directly involve the dynamic linker. However, *using* the RDMA functionality described here would involve shared libraries and thus the dynamic linker. I prepared to discuss how shared libraries containing RDMA code would be laid out in memory and how linking would occur.

8. **Thinking about Errors:**  Based on my understanding of system programming and interacting with hardware, I anticipated common errors like providing incorrect buffer addresses, sizes, or flags, or failing to properly manage resources.

9. **Structuring the Response:** I organized the information logically to address all parts of the prompt:
    * **功能 (Functions):** A high-level summary of the file's purpose.
    * **与 Android 的关系 (Relationship with Android):**  Hypothesizing potential use cases and the role of Bionic.
    * **libc 函数解释 (libc Function Explanation):**  Emphasizing that this file *defines* structures, not libc functions. The *use* of these structures would involve system calls, which *are* part of libc. I planned to explain the relevant system call (ioctl).
    * **Dynamic Linker:** Explaining the indirect relationship and providing a typical SO layout example.
    * **逻辑推理 (Logical Inference):** Using `mlx5_ib_alloc_ucontext_req` as an example.
    * **常见错误 (Common Errors):**  Listing potential pitfalls for developers.
    * **Android Framework/NDK 和 Frida Hook:**  Describing a hypothetical path and providing a Frida hook example for `ioctl`.

10. **Refining and Detailing:** I went back through each section, adding more specific details and examples. For instance, when discussing the dynamic linker, I included a sample SO memory layout. For the Frida hook, I provided a concrete code snippet.

11. **Language and Tone:** I maintained a clear and informative tone throughout the response, using appropriate technical terminology in Chinese.

By following these steps, I could dissect the provided header file, understand its purpose within the Android ecosystem, and generate a comprehensive and helpful answer that addresses all aspects of the user's request. The key was to connect the low-level definitions to higher-level concepts in Android and RDMA.
这是一个定义了 Mellanox ConnectX-5 (mlx5) 网卡用户态 API 的头文件，用于在用户空间程序中配置和控制 mlx5 网卡进行 RDMA (Remote Direct Memory Access) 操作。 由于它位于 `bionic/libc/kernel/uapi/rdma/` 目录下，可以推断这是 Android 系统中用于支持 RDMA 功能的底层接口定义。

**它的功能:**

这个头文件定义了用于与 mlx5 RDMA 驱动进行交互的各种数据结构和常量。主要功能包括：

1. **定义了各种标志 (Flags):** 例如 `MLX5_QP_FLAG_SIGNATURE`，用于配置 Queue Pair (QP)、Shared Receive Queue (SRQ) 和 Work Queue (WQ) 的特定属性，如是否启用签名、是否支持 Scatter CQE 等。

2. **定义了枚举类型 (Enums):** 例如 `mlx5_lib_caps` 定义了 mlx5 库支持的功能，如是否支持 4K UAR (User Access Region) 或动态 UAR。`mlx5_ib_alloc_uctx_v2_flags` 定义了分配用户上下文的标志。

3. **定义了请求和响应结构体 (Structs):**  这些结构体用于在用户空间程序和内核驱动之间传递控制信息和数据。例如：
    * `mlx5_ib_alloc_ucontext_req`: 定义了分配用户上下文的请求参数，如需要的 BFR (Buffer Region) 数量。
    * `mlx5_ib_alloc_ucontext_resp`: 定义了分配用户上下文的响应信息，如 QP 表大小、BFR 大小等。
    * `mlx5_ib_create_cq`: 定义了创建 Completion Queue (CQ) 的请求参数。
    * `mlx5_ib_create_qp`: 定义了创建 Queue Pair (QP) 的请求参数。
    * `mlx5_ib_query_device_resp`: 定义了查询设备能力的响应信息，如支持的 TSO (TCP Segmentation Offload) 大小、RSS (Receive Side Scaling) 能力等。

4. **定义了常量 (Defines):** 例如 `MLX5_IB_UVERBS_ABI_VERSION` 定义了用户态动词 API 的版本。

**它与 Android 的功能关系及举例说明:**

这个文件是 Android 系统底层支持 RDMA 功能的关键组成部分。RDMA 允许应用程序直接访问远程主机的内存，而无需操作系统内核的参与，从而实现高性能的网络通信。

**举例说明:**

* **高性能网络库:** Android 应用程序如果需要实现高性能的网络通信，例如在数据中心环境中进行分布式计算或存储访问，可以使用基于 RDMA 的网络库。这些库会利用这里定义的接口与 mlx5 网卡驱动进行交互。
* **存储访问:**  某些高性能存储解决方案可能使用 RDMA 进行数据传输。Android 设备作为客户端可能需要访问这些存储，这时就需要用到相关的 RDMA 功能。
* **虚拟化:** 在 Android 运行在虚拟化环境中的场景下，RDMA 可以用于虚拟机和宿主机之间的高效通信。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **没有定义任何 libc 函数**。它定义的是 **数据结构和常量**，用于与内核驱动进行交互。实际与内核交互通常会使用 **ioctl 系统调用**。

当用户空间程序需要执行 RDMA 操作时，例如创建 QP、注册内存等，它会填充这里定义的请求结构体，并通过 `ioctl` 系统调用将请求传递给 mlx5 RDMA 驱动。驱动程序会解析这些请求，配置硬件，并将结果返回给用户空间程序。

**例如，创建一个 Queue Pair (QP) 的过程可能涉及以下步骤:**

1. 用户空间程序分配一个 `mlx5_ib_create_qp` 结构体的内存。
2. 用户空间程序根据需要设置结构体中的各个字段，例如指定 SQ (Send Queue) 和 RQ (Receive Queue) 的大小、关联的 CQ 等。
3. 用户空间程序调用 `ioctl` 系统调用，并将 `mlx5_ib_create_qp` 结构体的地址和相应的 ioctl 命令码传递给内核。
4. 内核中的 mlx5 RDMA 驱动接收到 ioctl 请求，解析 `mlx5_ib_create_qp` 结构体中的参数，并在硬件上创建 QP。
5. 驱动程序将创建成功的 QP 的相关信息（例如 QP 编号）填充到相应的响应结构体中，并通过 ioctl 返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker。然而，如果用户空间程序需要使用 RDMA 功能，它很可能会链接到包含 RDMA 相关功能的共享库 (.so)。

**so 布局样本 (假设存在一个名为 `librdma_mlx5.so` 的共享库):**

```
librdma_mlx5.so:
    .text          # 代码段，包含实现 RDMA 相关功能的函数
    .rodata        # 只读数据段，包含常量等
    .data          # 可读写数据段，包含全局变量等
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表，包含导出的符号信息
    .dynstr        # 动态字符串表，包含符号名称字符串
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
    ...
```

**链接的处理过程:**

1. **编译时链接:**  在编译应用程序时，链接器会记录应用程序需要 `librdma_mlx5.so` 提供的符号 (例如函数)。
2. **运行时加载:** 当应用程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，包括 `librdma_mlx5.so`。
3. **符号解析和重定位:** dynamic linker 会解析应用程序和 `librdma_mlx5.so` 的动态符号表，找到应用程序引用的符号在 `librdma_mlx5.so` 中的地址。然后，它会更新应用程序代码中的相应地址，这个过程称为重定位。
4. **PLT 的使用:** 对于外部函数调用，通常会使用 PLT。第一次调用外部函数时，PLT 会将控制权转移到 dynamic linker，dynamic linker 找到函数的实际地址并更新 PLT 表项。后续调用将直接通过 PLT 跳转到函数的实际地址。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序需要分配一个用户上下文。

**假设输入:**

* `total_num_bfregs` (总的 BFR 数量): 16
* `num_low_latency_bfregs` (低延迟 BFR 数量): 4

**逻辑推理:**

用户空间程序会填充 `mlx5_ib_alloc_ucontext_req` 结构体，设置 `total_num_bfregs` 为 16，`num_low_latency_bfregs` 为 4。然后通过 `ioctl` 系统调用传递给内核驱动。内核驱动会根据这些参数分配相应的资源。

**假设输出 (ioctl 返回的 `mlx5_ib_alloc_ucontext_resp` 结构体中的部分字段):**

* `qp_tab_size`:  例如 4096 (QP 表的大小)
* `bf_reg_size`: 例如 65536 (单个 BFR 的大小)
* `tot_bfregs`: 16 (与输入一致)
* `cache_line_size`: 例如 64 (缓存行大小)

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的内存地址:**  在调用 ioctl 创建 QP、CQ 等资源时，如果提供的用于存储数据的缓冲区地址是无效的或者未注册的，会导致内核访问错误。
    ```c
    struct mlx5_ib_create_cq create_cq;
    create_cq.buf_addr = 0xdeadbeef; // 错误的地址
    // ... 其他字段设置
    ioctl(fd, MLX5_IB_CREATE_CQ, &create_cq); // 可能导致错误
    ```
2. **缓冲区大小不足:**  例如，创建 CQ 时指定的 `cqe_size` 不足以容纳 Completion Queue Entry (CQE)。
3. **标志位设置错误:**  例如，创建 QP 时设置了不支持的标志位，或者遗漏了必要的标志位。
4. **资源泄漏:**  创建了 QP、CQ 等资源后，没有及时释放，导致系统资源耗尽。
5. **并发访问冲突:**  多个线程或进程同时访问和修改同一个 RDMA 资源，可能导致数据不一致或程序崩溃。
6. **权限不足:**  执行某些 RDMA 操作可能需要特定的权限。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 和 NDK 通常不会直接使用这些底层的 mlx5 RDMA 接口。相反，它们可能会提供更高层次的抽象 API。 例如，如果 Android 应用程序需要使用高性能网络，它可能会使用 NDK 中的网络相关的 API，而这些 API 的底层实现可能会在某些特定硬件平台上使用 RDMA。

**假设的调用路径:**

1. **NDK 应用:**  一个使用 NDK 开发的应用程序，需要进行高性能网络通信。
2. **NDK 网络 API:** 应用程序调用 NDK 提供的网络相关的 API，例如用于创建 socket 或进行数据传输的函数。
3. **Android Framework (可选):** 在某些情况下，NDK API 的实现可能会依赖于 Android Framework 提供的服务。
4. **HAL (Hardware Abstraction Layer):**  Android Framework 或 NDK 的底层实现可能会调用 HAL 接口，以便与硬件进行交互。
5. **Kernel Driver (mlx5 RDMA Driver):**  HAL 的实现会调用内核提供的驱动程序接口，这最终会涉及到对 mlx5 RDMA 驱动的 ioctl 调用，而这些 ioctl 调用的参数结构体就是在这个头文件中定义的。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 mlx5 RDMA 相关的 ioctl 命令码，来观察参数的传递。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

try:
    process = frida.spawn(["/path/to/your/app"], stdio='pipe',
                           on_message=on_message)
    session = frida.attach(process.pid)
except frida.ProcessNotFoundError:
    print("Process not found. Please specify a running process or a path to spawn.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        // 定义 mlx5 RDMA 相关的 ioctl 命令码 (需要根据实际情况添加)
        const MLX5_IB_ALLOC_UCONTEXT = 0x40086900; // 示例，需要替换为实际值
        const MLX5_IB_CREATE_QP = 0x40306906;      // 示例，需要替换为实际值
        const MLX5_IB_CREATE_CQ = 0x40186908;      // 示例，需要替换为实际值

        if (request === MLX5_IB_ALLOC_UCONTEXT) {
            send({ tag: "ioctl", data: "MLX5_IB_ALLOC_UCONTEXT called with fd: " + fd });
            // 可以进一步读取 argp 指向的结构体内容
        } else if (request === MLX5_IB_CREATE_QP) {
            send({ tag: "ioctl", data: "MLX5_IB_CREATE_QP called with fd: " + fd });
        } else if (request === MLX5_IB_CREATE_CQ) {
            send({ tag: "ioctl", data: "MLX5_IB_CREATE_CQ called with fd: " + fd });
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

frida.resume(process.pid)
sys.stdin.read()
```

**使用说明:**

1. **替换路径:** 将 `/path/to/your/app` 替换为你要调试的 Android 应用程序的路径。
2. **查找 ioctl 命令码:** 你需要找到与 mlx5 RDMA 操作相关的实际 ioctl 命令码。这些命令码通常在内核头文件中定义 (例如 `uapi/rdma/mlx5_user_ioctl_verbs.h`)。
3. **读取结构体内容:** 在 `onEnter` 函数中，你可以使用 `Memory.readByteArray(argp, size)` 等 Frida API 读取 `argp` 指向的结构体内容，并解析其中的字段值。你需要知道结构体的大小。
4. **运行 Frida:**  确保你的 Android 设备已 root，并安装了 Frida 服务。运行这个 Python 脚本。

通过 Frida hook，你可以观察应用程序在执行 RDMA 相关操作时，`ioctl` 系统调用传递的参数，从而理解 Android Framework 或 NDK 是如何一步步到达这个底层接口的。请注意，直接使用这些底层接口的情况可能比较少见，通常会被封装在更高层次的库中。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/mlx5-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef MLX5_ABI_USER_H
#define MLX5_ABI_USER_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/mlx5_user_ioctl_verbs.h>
enum {
  MLX5_QP_FLAG_SIGNATURE = 1 << 0,
  MLX5_QP_FLAG_SCATTER_CQE = 1 << 1,
  MLX5_QP_FLAG_TUNNEL_OFFLOADS = 1 << 2,
  MLX5_QP_FLAG_BFREG_INDEX = 1 << 3,
  MLX5_QP_FLAG_TYPE_DCT = 1 << 4,
  MLX5_QP_FLAG_TYPE_DCI = 1 << 5,
  MLX5_QP_FLAG_TIR_ALLOW_SELF_LB_UC = 1 << 6,
  MLX5_QP_FLAG_TIR_ALLOW_SELF_LB_MC = 1 << 7,
  MLX5_QP_FLAG_ALLOW_SCATTER_CQE = 1 << 8,
  MLX5_QP_FLAG_PACKET_BASED_CREDIT_MODE = 1 << 9,
  MLX5_QP_FLAG_UAR_PAGE_INDEX = 1 << 10,
  MLX5_QP_FLAG_DCI_STREAM = 1 << 11,
};
enum {
  MLX5_SRQ_FLAG_SIGNATURE = 1 << 0,
};
enum {
  MLX5_WQ_FLAG_SIGNATURE = 1 << 0,
};
#define MLX5_IB_UVERBS_ABI_VERSION 1
struct mlx5_ib_alloc_ucontext_req {
  __u32 total_num_bfregs;
  __u32 num_low_latency_bfregs;
};
enum mlx5_lib_caps {
  MLX5_LIB_CAP_4K_UAR = (__u64) 1 << 0,
  MLX5_LIB_CAP_DYN_UAR = (__u64) 1 << 1,
};
enum mlx5_ib_alloc_uctx_v2_flags {
  MLX5_IB_ALLOC_UCTX_DEVX = 1 << 0,
};
struct mlx5_ib_alloc_ucontext_req_v2 {
  __u32 total_num_bfregs;
  __u32 num_low_latency_bfregs;
  __u32 flags;
  __u32 comp_mask;
  __u8 max_cqe_version;
  __u8 reserved0;
  __u16 reserved1;
  __u32 reserved2;
  __aligned_u64 lib_caps;
};
enum mlx5_ib_alloc_ucontext_resp_mask {
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_CORE_CLOCK_OFFSET = 1UL << 0,
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_DUMP_FILL_MKEY = 1UL << 1,
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_ECE = 1UL << 2,
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_SQD2RTS = 1UL << 3,
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_REAL_TIME_TS = 1UL << 4,
  MLX5_IB_ALLOC_UCONTEXT_RESP_MASK_MKEY_UPDATE_TAG = 1UL << 5,
};
enum mlx5_user_cmds_supp_uhw {
  MLX5_USER_CMDS_SUPP_UHW_QUERY_DEVICE = 1 << 0,
  MLX5_USER_CMDS_SUPP_UHW_CREATE_AH = 1 << 1,
};
enum mlx5_user_inline_mode {
  MLX5_USER_INLINE_MODE_NA,
  MLX5_USER_INLINE_MODE_NONE,
  MLX5_USER_INLINE_MODE_L2,
  MLX5_USER_INLINE_MODE_IP,
  MLX5_USER_INLINE_MODE_TCP_UDP,
};
enum {
  MLX5_USER_ALLOC_UCONTEXT_FLOW_ACTION_FLAGS_ESP_AES_GCM = 1 << 0,
  MLX5_USER_ALLOC_UCONTEXT_FLOW_ACTION_FLAGS_ESP_AES_GCM_REQ_METADATA = 1 << 1,
  MLX5_USER_ALLOC_UCONTEXT_FLOW_ACTION_FLAGS_ESP_AES_GCM_SPI_STEERING = 1 << 2,
  MLX5_USER_ALLOC_UCONTEXT_FLOW_ACTION_FLAGS_ESP_AES_GCM_FULL_OFFLOAD = 1 << 3,
  MLX5_USER_ALLOC_UCONTEXT_FLOW_ACTION_FLAGS_ESP_AES_GCM_TX_IV_IS_ESN = 1 << 4,
};
struct mlx5_ib_alloc_ucontext_resp {
  __u32 qp_tab_size;
  __u32 bf_reg_size;
  __u32 tot_bfregs;
  __u32 cache_line_size;
  __u16 max_sq_desc_sz;
  __u16 max_rq_desc_sz;
  __u32 max_send_wqebb;
  __u32 max_recv_wr;
  __u32 max_srq_recv_wr;
  __u16 num_ports;
  __u16 flow_action_flags;
  __u32 comp_mask;
  __u32 response_length;
  __u8 cqe_version;
  __u8 cmds_supp_uhw;
  __u8 eth_min_inline;
  __u8 clock_info_versions;
  __aligned_u64 hca_core_clock_offset;
  __u32 log_uar_size;
  __u32 num_uars_per_page;
  __u32 num_dyn_bfregs;
  __u32 dump_fill_mkey;
};
struct mlx5_ib_alloc_pd_resp {
  __u32 pdn;
};
struct mlx5_ib_tso_caps {
  __u32 max_tso;
  __u32 supported_qpts;
};
struct mlx5_ib_rss_caps {
  __aligned_u64 rx_hash_fields_mask;
  __u8 rx_hash_function;
  __u8 reserved[7];
};
enum mlx5_ib_cqe_comp_res_format {
  MLX5_IB_CQE_RES_FORMAT_HASH = 1 << 0,
  MLX5_IB_CQE_RES_FORMAT_CSUM = 1 << 1,
  MLX5_IB_CQE_RES_FORMAT_CSUM_STRIDX = 1 << 2,
};
struct mlx5_ib_cqe_comp_caps {
  __u32 max_num;
  __u32 supported_format;
};
enum mlx5_ib_packet_pacing_cap_flags {
  MLX5_IB_PP_SUPPORT_BURST = 1 << 0,
};
struct mlx5_packet_pacing_caps {
  __u32 qp_rate_limit_min;
  __u32 qp_rate_limit_max;
  __u32 supported_qpts;
  __u8 cap_flags;
  __u8 reserved[3];
};
enum mlx5_ib_mpw_caps {
  MPW_RESERVED = 1 << 0,
  MLX5_IB_ALLOW_MPW = 1 << 1,
  MLX5_IB_SUPPORT_EMPW = 1 << 2,
};
enum mlx5_ib_sw_parsing_offloads {
  MLX5_IB_SW_PARSING = 1 << 0,
  MLX5_IB_SW_PARSING_CSUM = 1 << 1,
  MLX5_IB_SW_PARSING_LSO = 1 << 2,
};
struct mlx5_ib_sw_parsing_caps {
  __u32 sw_parsing_offloads;
  __u32 supported_qpts;
};
struct mlx5_ib_striding_rq_caps {
  __u32 min_single_stride_log_num_of_bytes;
  __u32 max_single_stride_log_num_of_bytes;
  __u32 min_single_wqe_log_num_of_strides;
  __u32 max_single_wqe_log_num_of_strides;
  __u32 supported_qpts;
  __u32 reserved;
};
struct mlx5_ib_dci_streams_caps {
  __u8 max_log_num_concurent;
  __u8 max_log_num_errored;
};
enum mlx5_ib_query_dev_resp_flags {
  MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_COMP = 1 << 0,
  MLX5_IB_QUERY_DEV_RESP_FLAGS_CQE_128B_PAD = 1 << 1,
  MLX5_IB_QUERY_DEV_RESP_PACKET_BASED_CREDIT_MODE = 1 << 2,
  MLX5_IB_QUERY_DEV_RESP_FLAGS_SCAT2CQE_DCT = 1 << 3,
};
enum mlx5_ib_tunnel_offloads {
  MLX5_IB_TUNNELED_OFFLOADS_VXLAN = 1 << 0,
  MLX5_IB_TUNNELED_OFFLOADS_GRE = 1 << 1,
  MLX5_IB_TUNNELED_OFFLOADS_GENEVE = 1 << 2,
  MLX5_IB_TUNNELED_OFFLOADS_MPLS_GRE = 1 << 3,
  MLX5_IB_TUNNELED_OFFLOADS_MPLS_UDP = 1 << 4,
};
struct mlx5_ib_query_device_resp {
  __u32 comp_mask;
  __u32 response_length;
  struct mlx5_ib_tso_caps tso_caps;
  struct mlx5_ib_rss_caps rss_caps;
  struct mlx5_ib_cqe_comp_caps cqe_comp_caps;
  struct mlx5_packet_pacing_caps packet_pacing_caps;
  __u32 mlx5_ib_support_multi_pkt_send_wqes;
  __u32 flags;
  struct mlx5_ib_sw_parsing_caps sw_parsing_caps;
  struct mlx5_ib_striding_rq_caps striding_rq_caps;
  __u32 tunnel_offloads_caps;
  struct mlx5_ib_dci_streams_caps dci_streams_caps;
  __u16 reserved;
  struct mlx5_ib_uapi_reg reg_c0;
};
enum mlx5_ib_create_cq_flags {
  MLX5_IB_CREATE_CQ_FLAGS_CQE_128B_PAD = 1 << 0,
  MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX = 1 << 1,
  MLX5_IB_CREATE_CQ_FLAGS_REAL_TIME_TS = 1 << 2,
};
struct mlx5_ib_create_cq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u32 cqe_size;
  __u8 cqe_comp_en;
  __u8 cqe_comp_res_format;
  __u16 flags;
  __u16 uar_page_index;
  __u16 reserved0;
  __u32 reserved1;
};
struct mlx5_ib_create_cq_resp {
  __u32 cqn;
  __u32 reserved;
};
struct mlx5_ib_resize_cq {
  __aligned_u64 buf_addr;
  __u16 cqe_size;
  __u16 reserved0;
  __u32 reserved1;
};
struct mlx5_ib_create_srq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u32 flags;
  __u32 reserved0;
  __u32 uidx;
  __u32 reserved1;
};
struct mlx5_ib_create_srq_resp {
  __u32 srqn;
  __u32 reserved;
};
struct mlx5_ib_create_qp_dci_streams {
  __u8 log_num_concurent;
  __u8 log_num_errored;
};
struct mlx5_ib_create_qp {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u32 sq_wqe_count;
  __u32 rq_wqe_count;
  __u32 rq_wqe_shift;
  __u32 flags;
  __u32 uidx;
  __u32 bfreg_index;
  union {
    __aligned_u64 sq_buf_addr;
    __aligned_u64 access_key;
  };
  __u32 ece_options;
  struct mlx5_ib_create_qp_dci_streams dci_streams;
  __u16 reserved;
};
enum mlx5_rx_hash_function_flags {
  MLX5_RX_HASH_FUNC_TOEPLITZ = 1 << 0,
};
enum mlx5_rx_hash_fields {
  MLX5_RX_HASH_SRC_IPV4 = 1 << 0,
  MLX5_RX_HASH_DST_IPV4 = 1 << 1,
  MLX5_RX_HASH_SRC_IPV6 = 1 << 2,
  MLX5_RX_HASH_DST_IPV6 = 1 << 3,
  MLX5_RX_HASH_SRC_PORT_TCP = 1 << 4,
  MLX5_RX_HASH_DST_PORT_TCP = 1 << 5,
  MLX5_RX_HASH_SRC_PORT_UDP = 1 << 6,
  MLX5_RX_HASH_DST_PORT_UDP = 1 << 7,
  MLX5_RX_HASH_IPSEC_SPI = 1 << 8,
  MLX5_RX_HASH_INNER = (1UL << 31),
};
struct mlx5_ib_create_qp_rss {
  __aligned_u64 rx_hash_fields_mask;
  __u8 rx_hash_function;
  __u8 rx_key_len;
  __u8 reserved[6];
  __u8 rx_hash_key[128];
  __u32 comp_mask;
  __u32 flags;
};
enum mlx5_ib_create_qp_resp_mask {
  MLX5_IB_CREATE_QP_RESP_MASK_TIRN = 1UL << 0,
  MLX5_IB_CREATE_QP_RESP_MASK_TISN = 1UL << 1,
  MLX5_IB_CREATE_QP_RESP_MASK_RQN = 1UL << 2,
  MLX5_IB_CREATE_QP_RESP_MASK_SQN = 1UL << 3,
  MLX5_IB_CREATE_QP_RESP_MASK_TIR_ICM_ADDR = 1UL << 4,
};
struct mlx5_ib_create_qp_resp {
  __u32 bfreg_index;
  __u32 ece_options;
  __u32 comp_mask;
  __u32 tirn;
  __u32 tisn;
  __u32 rqn;
  __u32 sqn;
  __u32 reserved1;
  __u64 tir_icm_addr;
};
struct mlx5_ib_alloc_mw {
  __u32 comp_mask;
  __u8 num_klms;
  __u8 reserved1;
  __u16 reserved2;
};
enum mlx5_ib_create_wq_mask {
  MLX5_IB_CREATE_WQ_STRIDING_RQ = (1 << 0),
};
struct mlx5_ib_create_wq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u32 rq_wqe_count;
  __u32 rq_wqe_shift;
  __u32 user_index;
  __u32 flags;
  __u32 comp_mask;
  __u32 single_stride_log_num_of_bytes;
  __u32 single_wqe_log_num_of_strides;
  __u32 two_byte_shift_en;
};
struct mlx5_ib_create_ah_resp {
  __u32 response_length;
  __u8 dmac[ETH_ALEN];
  __u8 reserved[6];
};
struct mlx5_ib_burst_info {
  __u32 max_burst_sz;
  __u16 typical_pkt_sz;
  __u16 reserved;
};
struct mlx5_ib_modify_qp {
  __u32 comp_mask;
  struct mlx5_ib_burst_info burst_info;
  __u32 ece_options;
};
struct mlx5_ib_modify_qp_resp {
  __u32 response_length;
  __u32 dctn;
  __u32 ece_options;
  __u32 reserved;
};
struct mlx5_ib_create_wq_resp {
  __u32 response_length;
  __u32 reserved;
};
struct mlx5_ib_create_rwq_ind_tbl_resp {
  __u32 response_length;
  __u32 reserved;
};
struct mlx5_ib_modify_wq {
  __u32 comp_mask;
  __u32 reserved;
};
struct mlx5_ib_clock_info {
  __u32 sign;
  __u32 resv;
  __aligned_u64 nsec;
  __aligned_u64 cycles;
  __aligned_u64 frac;
  __u32 mult;
  __u32 shift;
  __aligned_u64 mask;
  __aligned_u64 overflow_period;
};
enum mlx5_ib_mmap_cmd {
  MLX5_IB_MMAP_REGULAR_PAGE = 0,
  MLX5_IB_MMAP_GET_CONTIGUOUS_PAGES = 1,
  MLX5_IB_MMAP_WC_PAGE = 2,
  MLX5_IB_MMAP_NC_PAGE = 3,
  MLX5_IB_MMAP_CORE_CLOCK = 5,
  MLX5_IB_MMAP_ALLOC_WC = 6,
  MLX5_IB_MMAP_CLOCK_INFO = 7,
  MLX5_IB_MMAP_DEVICE_MEM = 8,
};
enum {
  MLX5_IB_CLOCK_INFO_KERNEL_UPDATING = 1,
};
enum {
  MLX5_IB_CLOCK_INFO_V1 = 0,
};
struct mlx5_ib_flow_counters_desc {
  __u32 description;
  __u32 index;
};
struct mlx5_ib_flow_counters_data {
  RDMA_UAPI_PTR(struct mlx5_ib_flow_counters_desc *, counters_data);
  __u32 ncounters;
  __u32 reserved;
};
struct mlx5_ib_create_flow {
  __u32 ncounters_data;
  __u32 reserved;
  struct mlx5_ib_flow_counters_data data[];
};
#endif

"""

```