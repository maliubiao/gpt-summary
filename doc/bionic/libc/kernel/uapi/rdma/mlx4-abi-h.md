Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C header file (`mlx4-abi.handroid`), its relation to Android, detailed explanations of its components, and how Android leverages it. They also want to know about potential errors and debugging techniques.

2. **Identify the Subject:** The file is named `mlx4-abi.handroid` and located within the Android Bionic library (`bionic/libc/kernel/uapi/rdma/`). This immediately tells me the file defines the ABI (Application Binary Interface) for interacting with a Mellanox ConnectX-4 (or later) network adapter (indicated by "mlx4") using RDMA (Remote Direct Memory Access) within the Android kernel. The "handroid" likely signifies modifications or specific adaptations for Android.

3. **Break Down the File's Content:** I'll go through the header file section by section:

    * **Header Guards:** `#ifndef MLX4_ABI_USER_H`, `#define MLX4_ABI_USER_H`, `#endif` are standard header guards to prevent multiple inclusions. No direct functional significance, but crucial for correct compilation.

    * **Include:** `#include <linux/types.h>` indicates reliance on standard Linux kernel data types. This means the code interacts directly with kernel structures and definitions.

    * **Version Definitions:** `MLX4_IB_UVERBS_NO_DEV_CAPS_ABI_VERSION` and `MLX4_IB_UVERBS_ABI_VERSION` define the ABI versions. This is important for compatibility between user-space libraries and the kernel module.

    * **Structures:** The majority of the file defines structures like `mlx4_ib_alloc_ucontext_resp_v3`, `mlx4_ib_alloc_ucontext_resp`, `mlx4_ib_alloc_pd_resp`, etc. These structures represent data exchanged between user-space and the kernel during RDMA operations. I need to analyze what each structure represents based on its name and member variables. For example, `mlx4_ib_alloc_ucontext_resp` clearly deals with the response to allocating a user context.

    * **Enums:** Enums like the anonymous one with `MLX4_USER_DEV_CAP_LARGE_CQE`, `mlx4_ib_rx_hash_function_flags`, `mlx4_ib_rx_hash_fields`, and `query_device_resp_mask` define sets of related constants used as flags or options in the structures and underlying kernel calls.

4. **Determine the Functionality:** Based on the structures and enums, I can infer the core functionalities:

    * **Context Management:** Allocating and managing user contexts (`mlx4_ib_alloc_ucontext_resp`).
    * **Protection Domain Management:** Allocating protection domains (`mlx4_ib_alloc_pd_resp`).
    * **Completion Queue (CQ) Management:** Creating, resizing (`mlx4_ib_create_cq`, `mlx4_ib_create_cq_resp`, `mlx4_ib_resize_cq`). CQs are used to signal the completion of RDMA operations.
    * **Shared Receive Queue (SRQ) Management:** Creating SRQs (`mlx4_ib_create_srq`, `mlx4_ib_create_srq_resp`). SRQs allow multiple Queue Pairs (QPs) to share a receive queue.
    * **Queue Pair (QP) Management:** Creating QPs, specifically with RSS (Receive Side Scaling) support (`mlx4_ib_create_qp_rss`, `mlx4_ib_create_qp`). QPs are the core communication endpoints in RDMA.
    * **Work Queue (WQ) Management:** Creating and modifying Work Queues (`mlx4_ib_create_wq`, `mlx4_ib_modify_wq`). Work Queues hold the work requests (send, receive, etc.).
    * **Receive Work Queue Indirection Table Management:** Creating receive work queue indirection tables (`mlx4_ib_create_rwq_ind_tbl_resp`). This is related to advanced routing and load balancing.
    * **Device Capabilities Querying:** Querying device capabilities, including RSS and TSO (TCP Segmentation Offload) support (`mlx4_uverbs_ex_query_device_resp`).
    * **Receive Side Scaling (RSS):** Configuring and querying RSS parameters (`mlx4_ib_create_qp_rss`, `mlx4_ib_rss_caps`, `mlx4_ib_rx_hash_function_flags`, `mlx4_ib_rx_hash_fields`). RSS distributes incoming network traffic across multiple receive queues.
    * **TCP Segmentation Offload (TSO):** Querying TSO capabilities (`mlx4_ib_tso_caps`). TSO offloads TCP segmentation to the network adapter.

5. **Connect to Android Functionality:** RDMA is typically used in high-performance computing and data center environments. In Android, its presence suggests that it might be used for:

    * **High-Performance Networking:**  For applications requiring very low latency and high bandwidth, such as advanced network services or perhaps even internal system communication within a specialized Android device (like a server appliance running Android).
    * **Storage Access:** Accessing high-performance storage over RDMA fabrics.

6. **Explain Libc Functions (Conceptual):** This header file *defines* the ABI. It doesn't contain the *implementation* of libc functions. The *actual* interaction with the kernel happens through system calls. I need to explain that the structures defined here are used to marshal data for these system calls (likely through `ioctl` in this case, as RDMA often uses device-specific control mechanisms).

7. **Dynamic Linker (SO Layout and Linking):** This header file is a `.h` file. It's not directly linked by the dynamic linker. However, libraries that *use* these definitions would be linked. I need to provide a conceptual example of an SO using these definitions and how the linker would resolve dependencies. The key is that the library using these definitions needs to communicate with the kernel module providing the RDMA functionality.

8. **Logic Reasoning and Examples:**  For each structure, I can provide a brief explanation of its purpose and how the fields are used. For example, explaining that `buf_addr` in `mlx4_ib_create_cq` is the memory address of the completion queue buffer.

9. **Common Usage Errors:**  I need to think about common pitfalls when working with RDMA, such as:

    * **Incorrect buffer sizes:**  Providing wrong sizes for CQs or other resources.
    * **Memory access issues:**  Providing invalid memory addresses.
    * **ABI mismatches:** Using a user-space library compiled with a different ABI version than the kernel module expects.
    * **Privilege issues:**  Not having sufficient permissions to perform RDMA operations.

10. **Android Framework/NDK Path and Frida Hooking:** I need to outline the hypothetical path from an Android application to using these RDMA structures. This would likely involve:

    * **NDK:**  An NDK library wrapping the necessary system calls or `ioctl` commands.
    * **System Service:** A system service with the necessary privileges to interact with the RDMA driver.
    * **HAL (Hardware Abstraction Layer):** Potentially a HAL implementation for the RDMA device.

    For Frida hooking, I need to provide examples of hooking the relevant system calls or functions within the NDK library or system service.

11. **Structure the Answer:** Finally, I need to organize the information logically, using clear headings and explanations. I'll start with the core functionality, then delve into details, Android integration, potential errors, and debugging.

By following this thought process, I can systematically analyze the provided header file and generate a comprehensive and informative answer to the user's request. The key is to understand the context (Android Bionic, RDMA, Mellanox), break down the components, infer functionality, connect it to the Android ecosystem, and then address the specific points raised in the request (libc functions, dynamic linker, errors, debugging).
## 针对 bionic/libc/kernel/uapi/rdma/mlx4-abi.handroid 的功能分析

你提供的源代码文件 `mlx4-abi.handroid` 是 Android Bionic 库中用于定义与 Mellanox ConnectX-4 (或更新型号) 网络适配器进行 RDMA (Remote Direct Memory Access) 交互的 Application Binary Interface (ABI) 的头文件。它并不包含具体的 C 函数实现，而是定义了数据结构、枚举常量等，用于用户空间程序和内核驱动程序之间传递信息。

**功能列表:**

该文件定义了与以下 RDMA 相关操作的数据结构和常量：

1. **上下文管理 (Context Management):**
   - 定义了用于分配用户上下文的响应结构体 `mlx4_ib_alloc_ucontext_resp_v3` 和 `mlx4_ib_alloc_ucontext_resp`，包含队列对表大小 (`qp_tab_size`)、批量缓冲区寄存器大小和每页寄存器数 (`bf_reg_size`, `bf_regs_per_page`) 以及完成队列条目大小 (`cqe_size`) 等信息。

2. **保护域管理 (Protection Domain Management):**
   - 定义了分配保护域的响应结构体 `mlx4_ib_alloc_pd_resp`，包含保护域号 (`pdn`)。

3. **完成队列 (Completion Queue - CQ) 管理:**
   - 定义了创建 CQ 的请求结构体 `mlx4_ib_create_cq`，包含缓冲区地址 (`buf_addr`) 和门铃地址 (`db_addr`)。
   - 定义了创建 CQ 的响应结构体 `mlx4_ib_create_cq_resp`，包含 CQ 号 (`cqn`).
   - 定义了调整 CQ 大小的请求结构体 `mlx4_ib_resize_cq`，包含新的缓冲区地址 (`buf_addr`).

4. **共享接收队列 (Shared Receive Queue - SRQ) 管理:**
   - 定义了创建 SRQ 的请求结构体 `mlx4_ib_create_srq`，包含缓冲区地址 (`buf_addr`) 和门铃地址 (`db_addr`)。
   - 定义了创建 SRQ 的响应结构体 `mlx4_ib_create_srq_resp`，包含 SRQ 号 (`srqn`).

5. **队列对 (Queue Pair - QP) 管理:**
   - 定义了创建支持 RSS (Receive Side Scaling) 的 QP 的请求结构体 `mlx4_ib_create_qp_rss`，包含接收哈希字段掩码 (`rx_hash_fields_mask`)、哈希函数 (`rx_hash_function`)、哈希密钥 (`rx_hash_key`) 和比较掩码 (`comp_mask`)。
   - 定义了创建 QP 的请求结构体 `mlx4_ib_create_qp`，包含缓冲区地址 (`buf_addr`)、门铃地址 (`db_addr`)、发送队列后端计数对数 (`log_sq_bb_count`)、发送队列步幅对数 (`log_sq_stride`)、是否禁用发送队列预取 (`sq_no_prefetch`) 和内联接收大小 (`inl_recv_sz`)。

6. **工作队列 (Work Queue - WQ) 管理:**
   - 定义了创建 WQ 的请求结构体 `mlx4_ib_create_wq`，包含缓冲区地址 (`buf_addr`)、门铃地址 (`db_addr`)、范围大小对数 (`log_range_size`) 和比较掩码 (`comp_mask`)。
   - 定义了修改 WQ 的请求结构体 `mlx4_ib_modify_wq`，包含比较掩码 (`comp_mask`)。

7. **接收工作队列间接表 (Receive Work Queue Indirection Table) 管理:**
   - 定义了创建接收工作队列间接表的响应结构体 `mlx4_ib_create_rwq_ind_tbl_resp`，包含响应长度 (`response_length`).

8. **枚举常量:**
   - 定义了设备能力标志 `MLX4_USER_DEV_CAP_LARGE_CQE` (支持更大的 CQE)。
   - 定义了接收哈希函数标志 `MLX4_IB_RX_HASH_FUNC_TOEPLITZ` (使用 Toeplitz 哈希算法)。
   - 定义了接收哈希字段 `MLX4_IB_RX_HASH_SRC_IPV4` 等，用于指定 RSS 计算中使用的 IP 地址和端口。
   - 定义了查询设备响应掩码 `MLX4_IB_QUERY_DEV_RESP_MASK_CORE_CLOCK_OFFSET`，用于指示响应中包含核心时钟偏移。

9. **设备能力查询 (Device Capabilities Query):**
   - 定义了 RSS 能力结构体 `mlx4_ib_rss_caps`，包含接收哈希字段掩码和哈希函数。
   - 定义了 TSO (TCP Segmentation Offload) 能力结构体 `mlx4_ib_tso_caps`，包含最大 TSO 大小和支持的 QP 类型。
   - 定义了扩展的查询设备响应结构体 `mlx4_uverbs_ex_query_device_resp`，包含各种设备能力信息，如核心时钟偏移、最大内联接收大小、RSS 和 TSO 能力。

**与 Android 功能的关系及举例说明:**

通常情况下，RDMA 技术主要应用于高性能计算、数据中心等场景，在移动设备上的应用相对较少。 然而，如果特定的 Android 设备（例如服务器设备或嵌入式系统）配备了支持 RDMA 的 Mellanox 网卡，那么该文件定义的 ABI 就会被使用。

**可能的应用场景：**

* **高速网络通信:**  Android 系统可能需要与支持 RDMA 的服务器或存储设备进行高速数据传输，例如用于集群计算、分布式存储等场景。
* **虚拟化/容器化:**  在运行虚拟化或容器化环境的 Android 系统中，虚拟机或容器可能利用 RDMA 进行高性能的网络通信。

**举例说明：**

假设一个 Android 服务器应用需要将大量数据高速传输到一个支持 RDMA 的存储设备。这个应用可能会通过 NDK 调用底层的 RDMA 用户空间库 (例如 `libibverbs`)，而这个库会使用此头文件中定义的结构体，例如 `mlx4_ib_create_qp` 来创建 QP，并通过 `ioctl` 系统调用与内核中的 Mellanox RDMA 驱动进行交互。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了数据结构和常量。

实际的 RDMA 操作是通过用户空间库（如 `libibverbs`）调用系统调用 (例如 `ioctl`) 来完成的。这些系统调用会将请求传递给内核中的 Mellanox RDMA 驱动。驱动程序会解析用户空间传递的结构体（如 `mlx4_ib_create_qp`），并执行相应的硬件操作。

例如，当用户空间程序调用 `ibv_create_qp()` 函数（来自 `libibverbs`）来创建 QP 时，该函数最终会构造一个 `mlx4_ib_create_qp` 结构体，并将相关参数填入其中。然后，它会调用 `ioctl` 系统调用，并将这个结构体的地址作为参数传递给内核驱动。内核驱动接收到 `ioctl` 请求后，会读取 `mlx4_ib_create_qp` 结构体中的信息，配置 Mellanox 网卡的硬件资源，并返回一个表示 QP 的句柄。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

此头文件是 C 头文件，在编译时会被包含到使用它的 C/C++ 代码中。它本身 **不参与动态链接过程**。

然而，用户空间程序会链接到提供 RDMA 功能的动态链接库，例如 `libibverbs.so`。`libibverbs.so` 内部会使用此头文件中定义的结构体与内核驱动交互。

**`libibverbs.so` 的布局样本 (简化)：**

```
libibverbs.so:
    .text          # 包含函数代码，例如 ibv_create_qp, ibv_post_send 等
    .rodata        # 包含只读数据，例如字符串常量
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .symtab        # 符号表，记录导出的函数和变量
    .strtab        # 字符串表，存储符号名称
    ...           # 其他 section

    # 导出的符号 (部分)
    ibv_create_qp
    ibv_post_send
    ibv_reg_mr
    ...
```

**链接处理过程：**

1. **编译时：** 当编译使用 RDMA 功能的应用程序时，编译器会找到 `#include <rdma/mlx4-abi.h>` 并将该头文件包含进来。这使得应用程序代码可以使用其中定义的结构体和常量。

2. **链接时：** 链接器会将应用程序的目标文件与 `libibverbs.so` 链接在一起。链接器会解析应用程序中对 `libibverbs.so` 中函数的调用（例如 `ibv_create_qp()`），并在 `libibverbs.so` 的符号表中查找对应的函数地址。

3. **运行时：** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载 `libibverbs.so` 到内存中，并解析所有未决的符号引用，将应用程序中对 `ibv_create_qp()` 的调用指向 `libibverbs.so` 中该函数的实际地址。

**假设输入与输出 (逻辑推理):**

由于此文件仅定义数据结构，我们无法直接进行逻辑推理并给出具体的输入输出。 但是，我们可以以 `mlx4_ib_create_qp` 结构体为例进行说明：

**假设输入：**

一个用户空间程序想要创建一个 QP，并填充了 `mlx4_ib_create_qp` 结构体：

```c
struct mlx4_ib_create_qp create_qp_params;
create_qp_params.buf_addr = 0x10000000; // 指向发送/接收队列的内存地址
create_qp_params.db_addr = 0x20000000;  // 指向门铃的内存地址
create_qp_params.log_sq_bb_count = 4;
create_qp_params.log_sq_stride = 2;
// ... 其他字段
```

**预期输出 (内核驱动角度):**

内核驱动程序接收到包含上述 `create_qp_params` 数据的 `ioctl` 请求后，会解析这些参数，并据此配置 Mellanox 网卡的硬件资源。成功创建 QP 后，驱动程序可能会返回一个表示 QP 句柄的整数给用户空间。如果创建失败，则会返回一个错误码。

**用户或编程常见的使用错误，举例说明:**

1. **ABI 不兼容：** 用户空间的 `libibverbs.so` 版本与内核驱动程序的版本不兼容，导致结构体定义不一致，传递错误的数据。例如，内核驱动期望 `mlx4_ib_alloc_ucontext_resp` 结构体包含 `cqe_size` 字段，而用户空间的库使用的头文件没有定义该字段。

2. **内存地址错误：** 在 `mlx4_ib_create_cq` 或 `mlx4_ib_create_qp` 中提供的 `buf_addr` 或 `db_addr` 指向无效的内存地址，导致内核访问错误。

3. **权限不足：** 用户空间程序没有足够的权限执行 RDMA 操作，例如创建 QP 需要特定的设备权限。

4. **资源耗尽：** 尝试创建过多的 CQ 或 QP，导致 Mellanox 网卡的资源耗尽。

5. **配置错误：**  例如，在 `mlx4_ib_create_qp_rss` 中提供了错误的哈希字段掩码或哈希密钥，导致 RSS 功能无法正常工作。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

在典型的 Android 应用开发中，开发者通常不会直接接触到像 `mlx4-abi.h` 这样的底层内核头文件。 这通常涉及到 NDK 开发，并且是针对具有特定硬件 (支持 RDMA 的 Mellanox 网卡) 的 Android 设备。

**可能的路径：**

1. **NDK 应用开发:** 开发者使用 NDK 开发一个 C/C++ 应用程序，该应用程序需要使用 RDMA 功能。

2. **引入 RDMA 库:**  开发者需要在 NDK 项目中链接到提供 RDMA 用户空间 API 的库，例如 `libibverbs`。 这可能需要手动编译或移植该库到 Android 环境。

3. **使用 RDMA API:**  NDK 应用调用 `libibverbs` 提供的 API 函数，例如 `ibv_open_device()`, `ibv_alloc_pd()`, `ibv_create_cq()`, `ibv_create_qp()` 等。

4. **`libibverbs` 内部操作:**  `libibverbs` 内部会包含或引用 `<rdma/mlx4-abi.h>` 头文件，使用其中定义的结构体来构建与内核通信的数据。

5. **系统调用 (`ioctl`):**  `libibverbs` 最终会通过 `ioctl` 系统调用与内核中的 Mellanox RDMA 驱动程序进行交互。传递给 `ioctl` 的数据会基于 `mlx4-abi.h` 中定义的结构体。

6. **内核驱动处理:**  内核中的 Mellanox RDMA 驱动程序接收到 `ioctl` 调用，解析传递过来的结构体，并执行相应的硬件操作。

**Frida Hook 示例:**

假设我们想要 hook `libibverbs.so` 中的 `ibv_create_qp` 函数，以查看传递给它的参数。

```python
import frida
import sys

package_name = "your.rdma.app" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行，请先启动应用")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libibverbs.so", "ibv_create_qp"), {
    onEnter: function(args) {
        send("[+] Called ibv_create_qp");
        // 假设第二个参数是指向 mlx4_ib_create_qp 结构体的指针
        var create_qp_ptr = ptr(args[1]);
        send("[+] mlx4_ib_create_qp struct address: " + create_qp_ptr);

        // 读取结构体成员 (需要根据实际结构体定义调整偏移)
        send("[+] buf_addr: " + create_qp_ptr.readU64());
        send("[+] db_addr: " + create_qp_ptr.add(8).readU64());
        send("[+] log_sq_bb_count: " + create_qp_ptr.add(16).readU8());
        // ... 读取其他成员
    },
    onLeave: function(retval) {
        send("[+] ibv_create_qp returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释：**

1. **连接到目标应用:**  使用 Frida 连接到指定的 Android 应用进程。
2. **查找 `ibv_create_qp` 函数:**  使用 `Module.findExportByName` 找到 `libibverbs.so` 中 `ibv_create_qp` 函数的地址。
3. **Hook `onEnter`:**  在 `ibv_create_qp` 函数被调用时执行 `onEnter` 函数。
4. **读取参数:**  `args` 数组包含了传递给 `ibv_create_qp` 函数的参数。我们假设第二个参数是指向 `mlx4_ib_create_qp` 结构体的指针，并读取该结构体的成员，例如 `buf_addr`, `db_addr`, `log_sq_bb_count` 等。  **注意：结构体成员的偏移需要根据实际的结构体定义进行调整。**
5. **Hook `onLeave`:** 在 `ibv_create_qp` 函数返回后执行 `onLeave` 函数，可以查看返回值。
6. **发送消息:**  使用 `send()` 函数将信息发送到 Frida 客户端。

通过运行这个 Frida 脚本，你可以观察到 `ibv_create_qp` 函数何时被调用，以及传递给它的 `mlx4_ib_create_qp` 结构体的具体内容，从而调试 RDMA 相关的操作。

**总结:**

`bionic/libc/kernel/uapi/rdma/mlx4-abi.handroid` 是一个关键的头文件，定义了 Android 系统中与 Mellanox RDMA 设备交互的 ABI。它不包含函数实现，而是定义了数据结构和常量，供用户空间程序 (通常通过 `libibverbs`) 和内核驱动程序之间传递信息。理解此文件的内容对于开发需要使用 RDMA 功能的 Android 应用至关重要。 使用 Frida 可以帮助开发者动态地分析和调试涉及这些数据结构的 RDMA 操作。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/mlx4-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef MLX4_ABI_USER_H
#define MLX4_ABI_USER_H
#include <linux/types.h>
#define MLX4_IB_UVERBS_NO_DEV_CAPS_ABI_VERSION 3
#define MLX4_IB_UVERBS_ABI_VERSION 4
struct mlx4_ib_alloc_ucontext_resp_v3 {
  __u32 qp_tab_size;
  __u16 bf_reg_size;
  __u16 bf_regs_per_page;
};
enum {
  MLX4_USER_DEV_CAP_LARGE_CQE = 1L << 0,
};
struct mlx4_ib_alloc_ucontext_resp {
  __u32 dev_caps;
  __u32 qp_tab_size;
  __u16 bf_reg_size;
  __u16 bf_regs_per_page;
  __u32 cqe_size;
};
struct mlx4_ib_alloc_pd_resp {
  __u32 pdn;
  __u32 reserved;
};
struct mlx4_ib_create_cq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
};
struct mlx4_ib_create_cq_resp {
  __u32 cqn;
  __u32 reserved;
};
struct mlx4_ib_resize_cq {
  __aligned_u64 buf_addr;
};
struct mlx4_ib_create_srq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
};
struct mlx4_ib_create_srq_resp {
  __u32 srqn;
  __u32 reserved;
};
struct mlx4_ib_create_qp_rss {
  __aligned_u64 rx_hash_fields_mask;
  __u8 rx_hash_function;
  __u8 reserved[7];
  __u8 rx_hash_key[40];
  __u32 comp_mask;
  __u32 reserved1;
};
struct mlx4_ib_create_qp {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u8 log_sq_bb_count;
  __u8 log_sq_stride;
  __u8 sq_no_prefetch;
  __u8 reserved;
  __u32 inl_recv_sz;
};
struct mlx4_ib_create_wq {
  __aligned_u64 buf_addr;
  __aligned_u64 db_addr;
  __u8 log_range_size;
  __u8 reserved[3];
  __u32 comp_mask;
};
struct mlx4_ib_modify_wq {
  __u32 comp_mask;
  __u32 reserved;
};
struct mlx4_ib_create_rwq_ind_tbl_resp {
  __u32 response_length;
  __u32 reserved;
};
enum mlx4_ib_rx_hash_function_flags {
  MLX4_IB_RX_HASH_FUNC_TOEPLITZ = 1 << 0,
};
enum mlx4_ib_rx_hash_fields {
  MLX4_IB_RX_HASH_SRC_IPV4 = 1 << 0,
  MLX4_IB_RX_HASH_DST_IPV4 = 1 << 1,
  MLX4_IB_RX_HASH_SRC_IPV6 = 1 << 2,
  MLX4_IB_RX_HASH_DST_IPV6 = 1 << 3,
  MLX4_IB_RX_HASH_SRC_PORT_TCP = 1 << 4,
  MLX4_IB_RX_HASH_DST_PORT_TCP = 1 << 5,
  MLX4_IB_RX_HASH_SRC_PORT_UDP = 1 << 6,
  MLX4_IB_RX_HASH_DST_PORT_UDP = 1 << 7,
  MLX4_IB_RX_HASH_INNER = 1ULL << 31,
};
struct mlx4_ib_rss_caps {
  __aligned_u64 rx_hash_fields_mask;
  __u8 rx_hash_function;
  __u8 reserved[7];
};
enum query_device_resp_mask {
  MLX4_IB_QUERY_DEV_RESP_MASK_CORE_CLOCK_OFFSET = 1UL << 0,
};
struct mlx4_ib_tso_caps {
  __u32 max_tso;
  __u32 supported_qpts;
};
struct mlx4_uverbs_ex_query_device_resp {
  __u32 comp_mask;
  __u32 response_length;
  __aligned_u64 hca_core_clock_offset;
  __u32 max_inl_recv_sz;
  __u32 reserved;
  struct mlx4_ib_rss_caps rss_caps;
  struct mlx4_ib_tso_caps tso_caps;
};
#endif

"""

```