Response:
Let's break down the thought process for analyzing the `efa-abi.handroid` header file.

**1. Understanding the Context:**

The first thing I noted was the file path: `bionic/libc/kernel/uapi/rdma/efa-abi.handroid`. This immediately tells me:

* **`bionic`**: This is an Android-specific component, the standard C library and related parts. This is crucial for connecting it to Android.
* **`libc`**: Indicates involvement with core system calls and library functions.
* **`kernel`**:  Suggests this file defines an interface between user-space code (like applications or libraries) and the Linux kernel.
* **`uapi`**: Confirms it's a user-space API definition. Kernel headers intended for user-space use are often placed here.
* **`rdma`**: This is the key technology. Remote Direct Memory Access. This means this file is about high-performance networking, allowing direct memory access between machines.
* **`efa-abi.handroid`**:  "efa" likely stands for Elastic Fabric Adapter, an AWS networking technology. "abi" stands for Application Binary Interface, indicating this file defines how user-space programs interact with the EFA driver in the kernel. The ".handroid" likely signifies it's a version or customization for Android.

**2. Initial Analysis of the Content:**

I scanned the content for keywords and structural patterns:

* **`#ifndef EFA_ABI_USER_H`, `#define EFA_ABI_USER_H`, `#endif`**: This is a standard header guard, preventing multiple inclusions.
* **`#include <linux/types.h>`, `#include <rdma/ib_user_ioctl_cmds.h>`**:  These include standard Linux types and RDMA-related ioctl command definitions. This reinforces the kernel interface aspect.
* **`#define EFA_UVERBS_ABI_VERSION 1`**: Defines an ABI version, indicating potential for future changes and backward compatibility considerations.
* **`enum` and `struct` declarations**: These are the core of the file, defining constants and data structures used for communication between user space and the kernel. I started to categorize them mentally:
    * Structures ending in `_cmd` seem to be requests from user space to the kernel.
    * Structures ending in `_resp` seem to be responses from the kernel to user space.
    * Enums define sets of flags or options for the commands.
* **Bitwise operations (`<<`)**:  Used extensively in enums, indicating these are flags that can be combined.
* **`__u32`, `__u16`, `__u8`, `__aligned_u64`**: These are type definitions, likely standard Linux types for specific sized integers and aligned 64-bit integers.

**3. Inferring Functionality from Structures and Enums:**

I went through each structure and enum, trying to deduce its purpose based on the naming and members:

* **`efa_ibv_alloc_ucontext_cmd`/`resp`**: "alloc ucontext" suggests allocating a user context for EFA operations. The `comp_mask` likely indicates which capabilities are requested or supported. The `cmds_supp_udata_mask` hints at supported user data commands.
* **`efa_ibv_alloc_pd_resp`**: "alloc pd" suggests allocating a Protection Domain, a fundamental concept in RDMA for memory protection.
* **`efa_ibv_create_cq`/`resp`**: "create cq" clearly means creating a Completion Queue, used to receive notifications about completed RDMA operations. The `q_mmap_key` and `db_mmap_key` strongly suggest memory mapping for efficient communication.
* **`efa_ibv_create_qp`/`resp`**: "create qp" signifies creating a Queue Pair, the core communication endpoint in RDMA. The `rq_ring_size`, `sq_ring_size` suggest circular buffers for send and receive operations. The numerous `mmap_key` members again point to memory mapping.
* **`efa_ibv_create_ah_resp`**: "create ah" likely refers to creating an Address Handle, used to specify the destination for RDMA operations.
* **`efa_ibv_ex_query_device_resp`**: "query device" suggests querying the capabilities of the EFA device. The members list various features like RDMA read/write, retry mechanisms, etc.
* **`efa_query_mr_attrs`/`methods`**:  "query mr" relates to querying Memory Regions, which are registered memory areas that can be accessed via RDMA. The `IC_ID` members likely relate to identifiers for different types of access.

**4. Connecting to Android and Identifying Potential Usage:**

Knowing this is in `bionic`, the question is *how* does Android use RDMA/EFA?  My reasoning went like this:

* **High-Performance Networking:** RDMA is all about performance. Android devices themselves might not directly use high-end RDMA hardware like EFA.
* **Emulation/Virtualization:** Android *could* be running as a guest OS in a virtualized environment where the host system has EFA. In this case, the Android kernel would need to interact with the host's EFA hardware.
* **Specialized Android Deployments:** There might be specific Android deployments in data centers or research environments where high-performance networking is required.
* **NDK and Native Code:**  The most likely scenario is that this interface is used by native code (accessed via the NDK) that needs to interact with EFA hardware. This could be for applications doing high-performance computing, storage, or networking tasks.

**5. Considering the Dynamic Linker and libc:**

* **libc Functions:**  The structures and enums defined here are *data definitions*. They don't directly represent libc *functions*. However, libc functions would be used to *interact* with the kernel using these definitions. The primary mechanism would be system calls, particularly `ioctl`. The `ib_user_ioctl_cmds.h` inclusion confirms the use of `ioctl` for sending these commands to the EFA kernel driver.
* **Dynamic Linker:** The dynamic linker is responsible for loading shared libraries. If an NDK library uses EFA functionality, it would link against libraries that make use of these definitions and interact with the EFA driver. The SO layout would be typical for NDK libraries.

**6. Predicting Usage Errors and Frida Hooking:**

* **Usage Errors:**  Common errors in such low-level APIs involve incorrect parameter passing, race conditions in multithreaded access, memory management issues, and failure to handle errors from `ioctl` calls.
* **Frida:** Frida is a powerful tool for dynamic instrumentation. Hooking `ioctl` would be the key to observing the interaction with the EFA driver. I focused on hooking `ioctl` with the specific `RDMA_USER_IOCTL` command and filtering based on the `cmd` parameter to target EFA-related ioctls.

**7. Structuring the Response:**

Finally, I organized the information into a logical flow:

* **Core Functionality:**  Describing the purpose of the header file and the EFA ABI.
* **Android Relevance:** Explaining how this relates to Android, focusing on the NDK use case.
* **libc Function Implementation:** Clarifying that this file defines data structures, not libc functions, but explaining how libc interacts via `ioctl`.
* **Dynamic Linker:** Providing a sample SO layout and describing the linking process.
* **Logic and Assumptions:**  Presenting a hypothetical scenario of allocating a user context.
* **Common Errors:**  Listing potential programming mistakes.
* **Android Framework/NDK Path:**  Tracing how an NDK application would reach this code.
* **Frida Hook Example:** Providing a practical Frida script to demonstrate debugging.

This systematic approach of understanding the context, analyzing the content, inferring functionality, connecting to the target environment, and considering related aspects like the dynamic linker and debugging techniques allowed for a comprehensive and accurate response.
这个文件 `bionic/libc/kernel/uapi/rdma/efa-abi.handroid` 定义了用户空间程序与 Linux 内核中 Elastic Fabric Adapter (EFA) 驱动程序进行交互的应用程序二进制接口 (ABI)。EFA 是 AWS 提供的一种网络接口，旨在加速高性能计算 (HPC) 和机器学习应用程序。

**功能列表:**

该文件定义了一系列结构体 (struct) 和枚举 (enum)，用于在用户空间和内核空间之间传递参数和状态信息，主要涵盖以下功能：

1. **用户上下文管理:**
   - `efa_ibv_alloc_ucontext_cmd`:  分配用户上下文的命令。用户上下文是跟踪用户空间 EFA 资源的数据结构。
   - `efa_ibv_alloc_ucontext_resp`: 分配用户上下文的响应，包含分配结果和设备能力信息。
   - 定义了分配用户上下文命令的可选标志，例如 `EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH` 和 `EFA_ALLOC_UCONTEXT_CMD_COMP_MIN_SQ_WR`，可能用于请求特定的功能或优化。

2. **保护域管理:**
   - `efa_ibv_alloc_pd_resp`: 分配保护域的响应。保护域 (Protection Domain) 用于隔离不同进程或用户对内存的访问。

3. **完成队列 (CQ) 管理:**
   - `efa_ibv_create_cq`: 创建完成队列的命令。完成队列用于接收已完成的 EFA 操作的通知。
   - `efa_ibv_create_cq_resp`: 创建完成队列的响应，包含完成队列的内存映射信息和数据库偏移量。
   - 定义了创建完成队列的可选标志，例如 `EFA_CREATE_CQ_WITH_COMPLETION_CHANNEL` 和 `EFA_CREATE_CQ_WITH_SGID`，可能用于指定通知机制或共享组 ID。

4. **队列对 (QP) 管理:**
   - `efa_ibv_create_qp`: 创建队列对的命令。队列对是 EFA 中进行数据传输的基本单元，包含发送队列 (SQ) 和接收队列 (RQ)。
   - `efa_ibv_create_qp_resp`: 创建队列对的响应，包含队列对的内存映射信息和数据库偏移量。
   - 定义了创建队列对的可选标志，例如 `EFA_CREATE_QP_WITH_UNSOLICITED_WRITE_RECV`。

5. **地址句柄 (AH) 管理:**
   - `efa_ibv_create_ah_resp`: 创建地址句柄的响应。地址句柄用于指定远程节点的网络地址信息。

6. **设备查询:**
   - `efa_ibv_ex_query_device_resp`: 查询 EFA 设备能力的响应，包含设备支持的最大发送/接收队列大小、Scatter/Gather Entry 数量、RDMA 大小以及其他能力标志。
   - 定义了各种设备能力标志，例如 `EFA_QUERY_DEVICE_CAPS_RDMA_READ`，指示设备是否支持 RDMA 读取操作。

7. **内存区域 (MR) 查询:**
   - 定义了查询内存区域属性的枚举 `efa_query_mr_attrs` 和方法 `efa_mr_methods`，用于查询已注册内存区域的属性信息，例如句柄和不同类型访问的 IC ID (可能与一致性或缓存相关)。

**与 Android 功能的关系及举例说明:**

直接地看，这个文件定义的 EFA 功能与典型的移动 Android 设备的功能没有直接关系。移动设备通常不配备 EFA 硬件。

**但是，它可能在以下 Android 应用场景中发挥作用：**

1. **Android 作为虚拟机或容器的 Guest OS:**  如果 Android 作为虚拟机运行在支持 EFA 的主机上，或者在容器化环境中运行，那么 Android 内核可能需要与底层的 EFA 硬件交互。`efa-abi.handroid` 就定义了这种交互的接口。在这种情况下，Android 应用程序可以通过特定的驱动程序或库来利用 EFA 的高性能网络能力。

2. **特定领域的 Android 设备或服务器:**  可能存在一些定制的 Android 设备或基于 Android 的服务器，用于高性能计算、数据中心等领域，这些设备可能配备了 EFA 硬件。

3. **NDK 开发高性能网络应用:**  开发者可以使用 Android NDK (Native Development Kit) 编写 C/C++ 代码，这些代码可以通过 `ioctl` 系统调用与 EFA 驱动程序进行交互，从而利用 EFA 的功能。例如，一个使用 NDK 开发的分布式计算应用程序，如果运行在配备 EFA 的 Android 系统上，就可以使用这些接口来加速节点间的通信。

**举例说明 (假设场景):**

假设一个 NDK 应用程序需要使用 EFA 进行高性能数据传输：

1. 应用程序首先通过 `open()` 系统调用打开 EFA 设备节点 (例如 `/dev/infiniband/uverbs0`)。
2. 应用程序使用 `ioctl()` 系统调用，并传递 `efa_ibv_alloc_ucontext_cmd` 结构体，请求分配一个用户上下文。
3. 内核 EFA 驱动程序接收到 `ioctl` 调用，分配用户上下文，并将包含分配结果的 `efa_ibv_alloc_ucontext_resp` 结构体返回给应用程序。
4. 应用程序根据返回的信息，继续使用 `ioctl()` 调用创建保护域、完成队列、队列对等 EFA 资源，并进行数据传输操作。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件中定义的是 **数据结构和常量**，**不是 libc 函数**。它定义了用户空间程序如何构造与内核通信的数据。

用户空间程序需要使用 **libc 提供的系统调用** (例如 `ioctl`) 来与内核中的 EFA 驱动程序进行交互。

例如，如果要分配一个用户上下文，用户空间的程序不会直接调用一个名为 `efa_alloc_ucontext` 的 libc 函数 (这个函数不存在)。而是会：

1. **构造一个 `efa_ibv_alloc_ucontext_cmd` 结构体**，设置相应的参数 (例如 `comp_mask`)。
2. **调用 `ioctl()` 系统调用**，指定 EFA 设备的文件描述符、一个表示执行 EFA 特定操作的命令 (这部分信息通常定义在 `<rdma/ib_user_ioctl_cmds.h>` 或 EFA 驱动程序自己的头文件中)，以及指向构造好的 `efa_ibv_alloc_ucontext_cmd` 结构体的指针。
3. 内核 EFA 驱动程序接收到 `ioctl` 调用，解析命令和参数，执行相应的操作 (分配用户上下文)，并将结果填充到用户空间传递的 `efa_ibv_alloc_ucontext_resp` 结构体中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接器的功能。但是，如果一个 NDK 库需要使用 EFA 功能，那么它会：

1. **链接到提供与 EFA 驱动程序交互的库**。这个库可能是 AWS 提供的 EFA 用户空间库 (例如 `libefa`)，或者是一个自定义的库。

**SO 布局样本 (假设使用 `libefa`):**

```
libmynetwork.so:
  NEEDED libefa.so
  ... 其他依赖 ...
  ... 使用 EFA 功能的代码 ...
```

**链接处理过程:**

1. **编译时链接:** 当编译 `libmynetwork.so` 时，链接器会记录它依赖于 `libefa.so`。这个信息存储在 `libmynetwork.so` 的动态链接段中。
2. **运行时链接:** 当 Android 系统加载 `libmynetwork.so` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会读取 `libmynetwork.so` 的动态链接段，发现它依赖于 `libefa.so`。
3. **查找 `libefa.so`:** 动态链接器会在系统预定义的路径 (例如 `/vendor/lib64`, `/system/lib64` 等) 中查找 `libefa.so`。
4. **加载 `libefa.so`:** 如果找到 `libefa.so`，动态链接器会将其加载到内存中。
5. **符号解析:** 动态链接器会解析 `libmynetwork.so` 中对 `libefa.so` 提供的符号 (例如函数) 的引用，将这些引用指向 `libefa.so` 中对应的函数地址。
6. **重定位:** 动态链接器会根据加载地址调整 `libmynetwork.so` 和 `libefa.so` 中的一些地址信息。

**假设输入与输出 (逻辑推理):**

**场景:** 用户空间程序尝试分配一个用户上下文，并请求支持发送批处理完成事件 (`EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH`)。

**假设输入 (`efa_ibv_alloc_ucontext_cmd`):**

```c
struct efa_ibv_alloc_ucontext_cmd cmd;
cmd.comp_mask = EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH;
memset(cmd.reserved_20, 0, sizeof(cmd.reserved_20));
```

**可能的输出 (`efa_ibv_alloc_ucontext_resp`):**

* **成功分配，设备支持该特性:**

```c
struct efa_ibv_alloc_ucontext_resp resp;
resp.comp_mask = EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH; // 可能会返回请求的标志
resp.cmds_supp_udata_mask = ...; // 其他支持的 UDATA 命令掩码
resp.sub_cqs_per_cq = ...;
resp.inline_buf_size = ...;
resp.max_llq_size = ...;
resp.max_tx_batch = ...;
resp.min_sq_wr = ...;
memset(resp.reserved_a0, 0, sizeof(resp.reserved_a0));
```

* **成功分配，但设备不支持该特性:**

```c
struct efa_ibv_alloc_ucontext_resp resp;
resp.comp_mask = 0; // 不会返回请求的标志
resp.cmds_supp_udata_mask = ...;
resp.sub_cqs_per_cq = ...;
resp.inline_buf_size = ...;
resp.max_llq_size = ...;
resp.max_tx_batch = ...;
resp.min_sq_wr = ...;
memset(resp.reserved_a0, 0, sizeof(resp.reserved_a0));
```

* **分配失败 (例如，资源不足):** `ioctl()` 系统调用可能会返回一个错误代码 (例如 -1)，并且 `errno` 会被设置为相应的错误值 (例如 `ENOMEM`)。

**用户或编程常见的使用错误举例说明:**

1. **未正确初始化结构体:**  忘记设置必要的字段，或者保留了未初始化的值。例如，`comp_mask` 设置错误可能导致请求的功能未被激活。
2. **大小端问题:**  如果用户空间和内核空间运行在不同大小端的架构上，可能会导致数据解析错误。虽然 Android 通常是小端架构，但在跨平台开发中需要注意。
3. **内存管理错误:**  传递给 `ioctl` 的结构体需要在调用期间保持有效。如果过早释放或修改，会导致内核访问无效内存。
4. **不正确的 `ioctl` 命令:**  使用错误的 `ioctl` 命令值会导致内核执行错误的操作或返回错误。
5. **权限问题:**  访问 EFA 设备节点可能需要特定的权限。用户程序可能由于权限不足而无法打开设备或执行 `ioctl` 调用。
6. **资源泄漏:**  分配了 EFA 资源 (如用户上下文、队列对) 但没有正确释放，会导致系统资源耗尽。
7. **并发问题:**  在多线程程序中，如果没有采取适当的同步措施，多个线程同时访问 EFA 资源可能导致竞争条件和数据损坏。
8. **错误处理不当:**  `ioctl` 调用可能会失败，应用程序需要检查返回值并处理错误情况，例如重试或退出。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 `efa-abi.handroid` 的步骤 (以 NDK 应用为例):**

1. **NDK 应用程序代码:** 开发者使用 NDK 编写 C/C++ 代码，这些代码需要利用 EFA 的功能。
2. **调用 EFA 用户空间库:** 应用程序通常会链接到一个专门用于与 EFA 驱动程序交互的用户空间库 (例如 `libefa`)。这个库封装了底层的 `ioctl` 调用和数据结构操作。
3. **EFA 用户空间库:**  `libefa` 内部会根据应用程序的请求，构造相应的 `efa_ibv_*` 结构体 (这些结构体的定义就来自于 `efa-abi.handroid`)。
4. **`ioctl` 系统调用:** `libefa` 最终会调用 Linux 的 `ioctl` 系统调用，将构造好的结构体和相应的命令传递给内核。
5. **内核 EFA 驱动程序:**  内核接收到 `ioctl` 调用，解析命令和数据，执行相应的 EFA 操作。
6. **`efa-abi.handroid` 作为接口:**  `efa-abi.handroid` 定义的结构体和常量是用户空间库和内核驱动程序之间沟通的桥梁，确保双方对数据的格式和含义有相同的理解。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `ioctl` 调用，并分析与 EFA 相关的操作的示例：

```javascript
function hookEFAIoctl() {
  const ioctlPtr = Module.getExportByName(null, "ioctl");

  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();
      const argp = args[2];

      // 检查文件描述符是否与 EFA 设备相关 (需要根据实际情况判断)
      // 例如，可以检查 /dev/infiniband/uverbsX
      const fdPath = getFdPath(fd);
      if (fdPath && fdPath.includes("infiniband")) {
        console.log("[EFA Hook] ioctl called with fd:", fd, "request:", request);

        // 可以进一步判断 request 是否是与 EFA 相关的 ioctl 命令
        // 这需要参考 EFA 驱动程序的头文件或文档

        // 如果是 EFA 相关的 ioctl，可以尝试解析参数
        // 例如，假设 request 是分配用户上下文的命令
        // 可以根据 efa-abi.handroid 中的定义解析 argp 指向的结构体
        if (request === 0xCAFE /* 假设的 EFA 分配用户上下文的 ioctl 命令 */) {
          const cmd = Memory.readByteArray(argp, 8); // 假设 efa_ibv_alloc_ucontext_cmd 大小为 8 字节
          console.log("[EFA Hook] efa_ibv_alloc_ucontext_cmd:", hexdump(cmd));
        }
      }
    },
    onLeave: function (retval) {
      if (this.fdPath && this.fdPath.includes("infiniband")) {
        console.log("[EFA Hook] ioctl returned:", retval.toInt32());
      }
    },
  });
}

function getFdPath(fd) {
  try {
    const pathBuf = Memory.allocUtf8String(256);
    const result = recv(unixRpc({ recvFunctionName: 'fcntl', args: [fd, 1023, pathBuf] })); // F_GETPATH = 1023
    if (result.error) {
      return null;
    }
    return pathBuf.readUtf8String();
  } catch (e) {
    return null;
  }
}

setImmediate(hookEFAIoctl);
```

**Frida Hook 的作用:**

* **监控 `ioctl` 调用:**  可以捕获所有 `ioctl` 系统调用，并过滤出与 EFA 设备相关的调用。
* **分析 `ioctl` 命令:**  可以检查 `ioctl` 的 `request` 参数，判断正在执行的 EFA 操作类型.
* **解析参数:**  可以根据 `efa-abi.handroid` 中定义的结构体，解析传递给 `ioctl` 的参数，了解用户空间程序正在请求什么操作，以及传递了哪些数据。
* **查看返回值:**  可以查看 `ioctl` 调用的返回值，判断操作是否成功。

通过使用 Frida Hook，开发者可以动态地观察 NDK 应用程序与 EFA 驱动程序之间的交互，从而进行调试、性能分析或安全研究。记住，上述 Frida 代码只是一个基本示例，实际应用中可能需要根据具体的 EFA 驱动程序和用户空间库进行调整。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/efa-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef EFA_ABI_USER_H
#define EFA_ABI_USER_H
#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>
#define EFA_UVERBS_ABI_VERSION 1
enum {
  EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH = 1 << 0,
  EFA_ALLOC_UCONTEXT_CMD_COMP_MIN_SQ_WR = 1 << 1,
};
struct efa_ibv_alloc_ucontext_cmd {
  __u32 comp_mask;
  __u8 reserved_20[4];
};
enum efa_ibv_user_cmds_supp_udata {
  EFA_USER_CMDS_SUPP_UDATA_QUERY_DEVICE = 1 << 0,
  EFA_USER_CMDS_SUPP_UDATA_CREATE_AH = 1 << 1,
};
struct efa_ibv_alloc_ucontext_resp {
  __u32 comp_mask;
  __u32 cmds_supp_udata_mask;
  __u16 sub_cqs_per_cq;
  __u16 inline_buf_size;
  __u32 max_llq_size;
  __u16 max_tx_batch;
  __u16 min_sq_wr;
  __u8 reserved_a0[4];
};
struct efa_ibv_alloc_pd_resp {
  __u32 comp_mask;
  __u16 pdn;
  __u8 reserved_30[2];
};
enum {
  EFA_CREATE_CQ_WITH_COMPLETION_CHANNEL = 1 << 0,
  EFA_CREATE_CQ_WITH_SGID = 1 << 1,
};
struct efa_ibv_create_cq {
  __u32 comp_mask;
  __u32 cq_entry_size;
  __u16 num_sub_cqs;
  __u8 flags;
  __u8 reserved_58[5];
};
enum {
  EFA_CREATE_CQ_RESP_DB_OFF = 1 << 0,
};
struct efa_ibv_create_cq_resp {
  __u32 comp_mask;
  __u8 reserved_20[4];
  __aligned_u64 q_mmap_key;
  __aligned_u64 q_mmap_size;
  __u16 cq_idx;
  __u8 reserved_d0[2];
  __u32 db_off;
  __aligned_u64 db_mmap_key;
};
enum {
  EFA_QP_DRIVER_TYPE_SRD = 0,
};
enum {
  EFA_CREATE_QP_WITH_UNSOLICITED_WRITE_RECV = 1 << 0,
};
struct efa_ibv_create_qp {
  __u32 comp_mask;
  __u32 rq_ring_size;
  __u32 sq_ring_size;
  __u32 driver_qp_type;
  __u16 flags;
  __u8 reserved_90[6];
};
struct efa_ibv_create_qp_resp {
  __u32 comp_mask;
  __u32 rq_db_offset;
  __u32 sq_db_offset;
  __u32 llq_desc_offset;
  __aligned_u64 rq_mmap_key;
  __aligned_u64 rq_mmap_size;
  __aligned_u64 rq_db_mmap_key;
  __aligned_u64 sq_db_mmap_key;
  __aligned_u64 llq_desc_mmap_key;
  __u16 send_sub_cq_idx;
  __u16 recv_sub_cq_idx;
  __u8 reserved_1e0[4];
};
struct efa_ibv_create_ah_resp {
  __u32 comp_mask;
  __u16 efa_address_handle;
  __u8 reserved_30[2];
};
enum {
  EFA_QUERY_DEVICE_CAPS_RDMA_READ = 1 << 0,
  EFA_QUERY_DEVICE_CAPS_RNR_RETRY = 1 << 1,
  EFA_QUERY_DEVICE_CAPS_CQ_NOTIFICATIONS = 1 << 2,
  EFA_QUERY_DEVICE_CAPS_CQ_WITH_SGID = 1 << 3,
  EFA_QUERY_DEVICE_CAPS_DATA_POLLING_128 = 1 << 4,
  EFA_QUERY_DEVICE_CAPS_RDMA_WRITE = 1 << 5,
  EFA_QUERY_DEVICE_CAPS_UNSOLICITED_WRITE_RECV = 1 << 6,
};
struct efa_ibv_ex_query_device_resp {
  __u32 comp_mask;
  __u32 max_sq_wr;
  __u32 max_rq_wr;
  __u16 max_sq_sge;
  __u16 max_rq_sge;
  __u32 max_rdma_size;
  __u32 device_caps;
};
enum {
  EFA_QUERY_MR_VALIDITY_RECV_IC_ID = 1 << 0,
  EFA_QUERY_MR_VALIDITY_RDMA_READ_IC_ID = 1 << 1,
  EFA_QUERY_MR_VALIDITY_RDMA_RECV_IC_ID = 1 << 2,
};
enum efa_query_mr_attrs {
  EFA_IB_ATTR_QUERY_MR_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
  EFA_IB_ATTR_QUERY_MR_RESP_IC_ID_VALIDITY,
  EFA_IB_ATTR_QUERY_MR_RESP_RECV_IC_ID,
  EFA_IB_ATTR_QUERY_MR_RESP_RDMA_READ_IC_ID,
  EFA_IB_ATTR_QUERY_MR_RESP_RDMA_RECV_IC_ID,
};
enum efa_mr_methods {
  EFA_IB_METHOD_MR_QUERY = (1U << UVERBS_ID_NS_SHIFT),
};
#endif
```