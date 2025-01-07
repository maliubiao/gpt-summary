Response:
Let's break down the thought process for analyzing this `ib_user_verbs.h` file and generating the detailed Chinese response.

**1. Understanding the Core Purpose:**

The first and most crucial step is to recognize that this is a header file defining the user-space interface to InfiniBand (IB) verbs. The path `bionic/libc/kernel/uapi/rdma/ib_user_verbs.handroid` strongly suggests this is specifically for Android's Bionic libc, bridging the gap between user applications and the kernel's RDMA (Remote Direct Memory Access) subsystem. The auto-generated comment confirms this.

**2. Deconstructing the File's Contents:**

Next, systematically go through the different sections of the header file:

* **Includes and Defines:**  Note the inclusion of `<linux/types.h>` and the definition of `IB_USER_VERBS_ABI_VERSION` and `IB_USER_VERBS_CMD_THRESHOLD`. These are important for understanding the context and potential versioning issues.

* **Enums for Commands (`ib_uverbs_write_cmds`, `IB_USER_VERBS_EX_CMD_...`):** These are the heart of the interface. Each enum member represents a specific operation a user application can request from the kernel. It's important to list and briefly describe the function of each command. Look for patterns and groupings (e.g., context management, memory region management, queue pair management, etc.).

* **Enums for Flags and Types (`ib_placement_type`, `ib_selectivity_level`, etc.):** These define options and settings for the various commands. Understand their purpose and potential impact.

* **Structures (`ib_uverbs_...`):**  The majority of the file consists of structure definitions. These structures represent the data exchanged between user space and the kernel for each command. Key observations:
    * **Request and Response Structures:** Many commands have corresponding request and response structures (e.g., `ib_uverbs_get_context` and `ib_uverbs_get_context_resp`). This is a common pattern for system calls or ioctl-like interfaces.
    * **Handles:**  Notice the prevalence of `_handle` fields (e.g., `pd_handle`, `cq_handle`, `qp_handle`). These are likely kernel-managed identifiers for resources.
    * **Embedded Structures:** Some structures contain other structures (e.g., `ib_uverbs_ex_query_device_resp` containing `ib_uverbs_query_device_resp`). This indicates a hierarchical organization or extensions to the basic functionality.
    * **Unions:**  Understand the purpose of unions, like in `ib_uverbs_wc`. They allow different interpretations of the same memory region based on the context.
    * **`driver_data`:**  The presence of `driver_data` arrays suggests a mechanism for vendor-specific extensions or private data passing.

**3. Connecting to Android Functionality:**

This is where the context of "Android's Bionic libc" becomes important. RDMA is a high-performance networking technology. Consider where such performance is critical in Android:

* **High-performance networking applications:**  While less common directly for typical user apps, this could be used in specialized scenarios or by system services.
* **Inter-process communication (IPC):**  RDMA's zero-copy capabilities could theoretically be leveraged for very efficient IPC, although this file doesn't directly expose such mechanisms. The abstraction layer would likely be higher.
* **Hardware acceleration/offloading:**  Android devices might have specialized hardware that uses RDMA for communication or data transfer.

It's crucial to acknowledge that while the *interface* is defined in Bionic, the actual *implementation* resides in the Linux kernel. Therefore, direct usage by typical Android applications is unlikely.

**4. Explaining libc Functions:**

The prompt asks about libc functions. This header file *defines* the interface, but the *implementation* of how user-space applications interact with these definitions (e.g., using system calls or ioctls) is within the broader Bionic libc. Focus on the *purpose* of each defined command and structure, as they represent the functionality exposed by the underlying kernel. Avoid going into low-level libc implementation details unless directly related to this file (e.g., how a command is translated into a system call).

**5. Dynamic Linker and SO Layout:**

Since this is a *header file*, it doesn't directly involve the dynamic linker. However, if a user-space library *implemented* the usage of these verbs, it would be a shared object (.so). Provide a basic example of a typical .so layout in Android and the general linking process. Emphasize that this *header* provides the *interface* that a .so library would *use*.

**6. Logic Reasoning and Examples:**

For the logical reasoning and input/output examples, choose a simple, illustrative command. `IB_USER_VERBS_CMD_GET_CONTEXT` is a good choice as it's foundational. Create a hypothetical input scenario (though the actual interaction is through system calls/ioctls, not direct function calls) and describe the expected output based on the structure definition.

**7. Common Usage Errors:**

Think about typical mistakes when interacting with low-level APIs:

* **Incorrect handle usage:**  Using an invalid or already freed handle.
* **Mismatched parameters:** Providing incorrect sizes, flags, or addresses.
* **Resource leaks:** Failing to deallocate resources (e.g., memory regions, queue pairs).
* **Concurrency issues:** Improper synchronization when multiple threads access RDMA resources.

**8. Android Framework/NDK and Frida Hooking:**

This is a more advanced part. Recognize that direct framework usage is unlikely. Focus on how an NDK application *could* potentially use a hypothetical library that wraps these verbs. Provide a conceptual path from the NDK to this header file.

For the Frida hook, choose a representative command (`IB_USER_VERBS_CMD_GET_CONTEXT` again is a good starting point). Demonstrate how to hook a function that would *call* into the kernel using this interface (though the exact function might be in a hypothetical RDMA library). The hook should illustrate how to inspect arguments and the return value.

**9. Language and Tone:**

Maintain a clear, concise, and technically accurate tone throughout the response. Use appropriate terminology and explain concepts thoroughly. Since the request is in Chinese, the entire response should be in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this header file is directly used by some high-performance Android services.
* **Correction:**  While possible, it's more likely that a lower-level library (potentially a vendor-provided one) would interact with these kernel interfaces, and then higher-level Android components might use *that* library. Focus on the interface definition and potential uses rather than direct framework calls.

* **Initial thought:**  Explain the specific system calls used to invoke these verbs.
* **Correction:** The header file doesn't specify the system call mechanism. Focus on the *defined interface* and the structures involved in the communication, rather than the underlying system call implementation details, which might vary.

By following this structured approach and continuously refining the understanding, we can generate a comprehensive and accurate response to the prompt.
这个文件 `bionic/libc/kernel/uapi/rdma/ib_user_verbs.handroid` 是 Android Bionic C 库的一部分，专门定义了用户空间程序与 InfiniBand (IB) 内核驱动交互的接口。它本质上定义了一组结构体、枚举和宏，用于封装用户态对 RDMA (Remote Direct Memory Access) 操作的请求。

**功能列举:**

这个头文件定义了用户空间可以向 InfiniBand 内核驱动发出的各种命令，主要围绕以下功能：

1. **上下文管理 (Context Management):**
   - `IB_USER_VERBS_CMD_GET_CONTEXT`: 获取 IB 设备上下文信息。

2. **设备查询 (Device Query):**
   - `IB_USER_VERBS_CMD_QUERY_DEVICE`: 查询 IB 设备的能力和属性。
   - `IB_USER_VERBS_CMD_QUERY_PORT`: 查询 IB 设备端口的属性。

3. **保护域 (Protection Domain) 管理:**
   - `IB_USER_VERBS_CMD_ALLOC_PD`: 分配保护域。
   - `IB_USER_VERBS_CMD_DEALLOC_PD`: 释放保护域。

4. **地址句柄 (Address Handle) 管理:**
   - `IB_USER_VERBS_CMD_CREATE_AH`: 创建地址句柄。
   - `IB_USER_VERBS_CMD_MODIFY_AH`: 修改地址句柄。
   - `IB_USER_VERBS_CMD_QUERY_AH`: 查询地址句柄属性。
   - `IB_USER_VERBS_CMD_DESTROY_AH`: 销毁地址句柄。

5. **内存区域 (Memory Region) 管理:**
   - `IB_USER_VERBS_CMD_REG_MR`: 注册内存区域。
   - `IB_USER_VERBS_CMD_REG_SMR`: 注册共享内存区域。
   - `IB_USER_VERBS_CMD_REREG_MR`: 重新注册内存区域。
   - `IB_USER_VERBS_CMD_QUERY_MR`: 查询内存区域属性。
   - `IB_USER_VERBS_CMD_DEREG_MR`: 注销内存区域。

6. **内存窗口 (Memory Window) 管理:**
   - `IB_USER_VERBS_CMD_ALLOC_MW`: 分配内存窗口。
   - `IB_USER_VERBS_CMD_BIND_MW`: 绑定内存窗口到内存区域。
   - `IB_USER_VERBS_CMD_DEALLOC_MW`: 释放内存窗口。

7. **完成通道 (Completion Channel) 管理:**
   - `IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL`: 创建完成通道。

8. **完成队列 (Completion Queue) 管理:**
   - `IB_USER_VERBS_CMD_CREATE_CQ`: 创建完成队列。
   - `IB_USER_VERBS_CMD_RESIZE_CQ`: 调整完成队列大小。
   - `IB_USER_VERBS_CMD_DESTROY_CQ`: 销毁完成队列。
   - `IB_USER_VERBS_CMD_POLL_CQ`: 轮询完成队列以获取完成事件。
   - `IB_USER_VERBS_CMD_PEEK_CQ`: 窥视完成队列。
   - `IB_USER_VERBS_CMD_REQ_NOTIFY_CQ`: 请求完成队列通知。
   - `IB_USER_VERBS_EX_CMD_MODIFY_CQ`: 修改完成队列属性 (扩展命令)。

9. **队列对 (Queue Pair) 管理:**
   - `IB_USER_VERBS_CMD_CREATE_QP`: 创建队列对。
   - `IB_USER_VERBS_CMD_QUERY_QP`: 查询队列对属性。
   - `IB_USER_VERBS_CMD_MODIFY_QP`: 修改队列对属性。
   - `IB_USER_VERBS_CMD_DESTROY_QP`: 销毁队列对。
   - `IB_USER_VERBS_CMD_OPEN_QP`: 打开已存在的队列对。

10. **发送和接收操作 (Send and Receive Operations):**
    - `IB_USER_VERBS_CMD_POST_SEND`: 提交发送请求。
    - `IB_USER_VERBS_CMD_POST_RECV`: 提交接收请求。

11. **多播 (Multicast) 管理:**
    - `IB_USER_VERBS_CMD_ATTACH_MCAST`: 加入多播组。
    - `IB_USER_VERBS_CMD_DETACH_MCAST`: 离开多播组。

12. **共享接收队列 (Shared Receive Queue) 管理:**
    - `IB_USER_VERBS_CMD_CREATE_SRQ`: 创建共享接收队列。
    - `IB_USER_VERBS_CMD_MODIFY_SRQ`: 修改共享接收队列属性。
    - `IB_USER_VERBS_CMD_QUERY_SRQ`: 查询共享接收队列属性。
    - `IB_USER_VERBS_CMD_DESTROY_SRQ`: 销毁共享接收队列。
    - `IB_USER_VERBS_CMD_POST_SRQ_RECV`: 向共享接收队列提交接收请求。
    - `IB_USER_VERBS_CMD_CREATE_XSRQ`: 创建扩展共享接收队列。

13. **扩展远程互连描述符 (Extended Remote Connection Descriptor) 管理:**
    - `IB_USER_VERBS_CMD_OPEN_XRCD`: 打开 XRCD。
    - `IB_USER_VERBS_CMD_CLOSE_XRCD`: 关闭 XRCD。

14. **流控制 (Flow Control) (扩展命令):**
    - `IB_USER_VERBS_EX_CMD_CREATE_FLOW`: 创建流。
    - `IB_USER_VERBS_EX_CMD_DESTROY_FLOW`: 销毁流。

15. **工作队列 (Work Queue) 管理 (扩展命令):**
    - `IB_USER_VERBS_EX_CMD_CREATE_WQ`: 创建工作队列。
    - `IB_USER_VERBS_EX_CMD_MODIFY_WQ`: 修改工作队列属性。
    - `IB_USER_VERBS_EX_CMD_DESTROY_WQ`: 销毁工作队列。

16. **重定向接收工作队列索引表 (Redirected Receive Work Queue Indirection Table) 管理 (扩展命令):**
    - `IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL`: 创建重定向接收工作队列索引表。
    - `IB_USER_VERBS_EX_CMD_DESTROY_RWQ_IND_TBL`: 销毁重定向接收工作队列索引表。

**与 Android 功能的关系及举例:**

虽然 InfiniBand 通常用于高性能计算和数据中心环境，但在 Android 中直接使用的情况相对较少。其存在于 Bionic 中，可能主要出于以下考虑：

* **硬件支持:** 某些特定的 Android 设备或开发板可能集成了支持 InfiniBand 的硬件。
* **特殊应用场景:** 某些需要极高带宽和低延迟的 Android 应用，例如某些类型的服务器应用或高性能数据处理应用，可能会利用 InfiniBand。
* **驱动框架:** Android 的硬件抽象层 (HAL) 或内核驱动框架可能需要与 InfiniBand 硬件交互，而这个头文件定义了用户空间与内核驱动交互的标准方式。

**举例说明:**

假设某个 Android 设备配备了 InfiniBand 适配器。一个高性能的存储服务应用可能使用这些 verbs 来实现远程内存访问，以提高数据传输效率。

1. **初始化:** 应用首先使用 `IB_USER_VERBS_CMD_GET_CONTEXT` 获取 IB 设备上下文。
2. **内存注册:** 使用 `IB_USER_VERBS_CMD_ALLOC_PD` 分配保护域，然后使用 `IB_USER_VERBS_CMD_REG_MR` 注册一块用于数据传输的内存区域。
3. **队列对创建:** 创建发送和接收所需的队列对，使用 `IB_USER_VERBS_CMD_CREATE_CQ` 创建完成队列，并使用 `IB_USER_VERBS_CMD_CREATE_QP` 创建队列对。
4. **数据传输:** 使用 `IB_USER_VERBS_CMD_POST_SEND` 和 `IB_USER_VERBS_CMD_POST_RECV` 进行数据发送和接收操作。
5. **资源释放:** 在完成操作后，使用相应的 `DESTROY` 命令释放分配的资源，例如 `IB_USER_VERBS_CMD_DESTROY_QP`, `IB_USER_VERBS_CMD_DEREG_MR`, `IB_USER_VERBS_CMD_DEALLOC_PD` 等。

**libc 函数功能实现详细解释:**

这个头文件本身定义的是数据结构和常量，**并没有直接实现 libc 函数**。 实际的 libc 函数，例如 `ibv_open_device`, `ibv_reg_mr`, `ibv_post_send` 等，会在 Bionic 的 `libinfiniband.so` 或类似的库中实现。 这些库函数会根据这里定义的结构体和命令，将用户空间的请求打包成特定的格式，然后通过 **ioctl 系统调用** 与内核中的 InfiniBand 驱动进行通信。

**例如，对于 `IB_USER_VERBS_CMD_GET_CONTEXT`:**

1. 用户空间的 `libinfiniband.so` 中的 `ibv_open_device` 函数会被调用。
2. 该函数会填充一个 `ib_uverbs_cmd_hdr` 结构体，并将 `command` 字段设置为 `IB_USER_VERBS_CMD_GET_CONTEXT`。
3. 接着，可能会填充一个 `ib_uverbs_get_context` 结构体，用于传递额外的参数 (虽然在这个命令中可能没有)。
4. `ibv_open_device` 函数会调用 `ioctl` 系统调用，将构建好的命令数据传递给 InfiniBand 内核驱动。
5. 内核驱动接收到 `ioctl` 请求后，会解析命令和参数，执行相应的操作 (例如获取设备信息)。
6. 内核驱动会将结果填充到相应的响应结构体中，例如 `ib_uverbs_get_context_resp`。
7. `ioctl` 系统调用返回，`ibv_open_device` 函数解析响应数据，并将结果返回给用户空间程序。

**dynamic linker 的功能和 so 布局样本及链接处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 负责在程序启动时加载和链接共享库 (`.so` 文件)。

**SO 布局样本 (例如 `libinfiniband.so`):**

```
libinfiniband.so:
    .init       # 初始化代码段
    .plt        # 程序链接表
    .text       # 代码段 (包含 ibv_open_device, ibv_reg_mr, ibv_post_send 等函数的实现)
    .rodata     # 只读数据段
    .data       # 已初始化数据段
    .bss        # 未初始化数据段
    .dynsym     # 动态符号表
    .dynstr     # 动态字符串表
    .rel.plt    # PLT 重定位表
    .rel.dyn    # 动态重定位表
    ...
```

**链接处理过程:**

1. 当一个使用了 InfiniBand 功能的 Android 应用启动时，dynamic linker 会解析其 ELF 头部的依赖信息，发现需要加载 `libinfiniband.so`。
2. Dynamic linker 会在预定义的路径 (例如 `/system/lib64`, `/vendor/lib64` 等) 中查找 `libinfiniband.so` 文件。
3. 找到文件后，dynamic linker 会将其加载到内存中。
4. Dynamic linker 会解析 `libinfiniband.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，了解其导出的函数和全局变量。
5. Dynamic linker 会处理应用程序和 `libinfiniband.so` 之间的符号引用关系。例如，如果应用程序调用了 `ibv_open_device`，dynamic linker 会将应用程序中对该符号的引用地址修改为 `libinfiniband.so` 中 `ibv_open_device` 函数的实际地址。这个过程涉及到程序链接表 (`.plt`) 和重定位表 (`.rel.plt`, `.rel.dyn`)。
6. 完成链接后，应用程序才能正常调用 `libinfiniband.so` 中提供的 InfiniBand 功能。

**逻辑推理、假设输入与输出:**

以 `IB_USER_VERBS_CMD_QUERY_DEVICE` 为例：

**假设输入:** 用户空间程序调用 `libinfiniband.so` 中的 `ibv_query_device` 函数，该函数内部构建了一个 `ib_uverbs_query_device` 结构体，并将其 `command` 字段设置为 `IB_USER_VERBS_CMD_QUERY_DEVICE`。然后通过 `ioctl` 系统调用发送给内核。

**预期输出:** 内核驱动收到请求后，会查询 InfiniBand 设备的信息，并将结果填充到一个 `ib_uverbs_query_device_resp` 结构体中。这个结构体包含例如固件版本 (`fw_ver`)、节点 GUID (`node_guid`)、系统镜像 GUID (`sys_image_guid`)、最大内存区域大小 (`max_mr_size`) 等信息。`ioctl` 系统调用返回后，`ibv_query_device` 函数会解析这个响应结构体，并将设备信息返回给用户空间程序。

**涉及用户或编程常见的使用错误:**

1. **忘记初始化或释放资源:**  例如，分配了保护域或队列对，但在使用完毕后忘记释放，导致资源泄漏。
2. **使用无效的句柄:**  尝试使用一个已经销毁的或者未正确获取的句柄 (例如 `pd_handle`, `qp_handle`, `cq_handle`)，会导致内核错误。
3. **参数错误:**  传递给 ioctl 的参数不符合预期，例如内存地址无效、长度错误、标志位设置不正确等。
4. **竞态条件:**  在多线程环境下，如果没有正确的同步机制，多个线程同时访问或修改 InfiniBand 资源可能导致数据不一致或程序崩溃。
5. **错误处理不当:**  ioctl 系统调用可能返回错误码，用户程序需要检查返回值并进行相应的错误处理。忽略错误可能导致程序行为异常。
6. **ABI 版本不匹配:**  用户空间的库和内核驱动的 ABI 版本不一致可能导致兼容性问题。`IB_USER_VERBS_ABI_VERSION` 定义了 ABI 版本，需要确保用户空间和内核驱动的版本匹配。

**Android framework 或 NDK 如何一步步到达这里，给出 frida hook 示例调试这些步骤:**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，其中可能包含使用 InfiniBand 功能的逻辑。
2. **链接库:** NDK 代码会链接到 Bionic 提供的 `libinfiniband.so` (或者其他封装了 InfiniBand 功能的第三方库)。
3. **调用 `libinfiniband.so` 函数:**  NDK 代码中会调用 `libinfiniband.so` 中提供的函数，例如 `ibv_open_device`, `ibv_reg_mr`, `ibv_post_send` 等。
4. **`libinfiniband.so` 内部实现:** 这些函数内部会使用此头文件中定义的结构体和常量来构建与内核通信的数据。
5. **ioctl 系统调用:** `libinfiniband.so` 会通过 `ioctl` 系统调用将请求发送到内核。
6. **内核驱动处理:** Linux 内核中的 InfiniBand 驱动接收到 `ioctl` 请求后，会解析命令和参数，执行相应的硬件操作。

**Frida Hook 示例:**

假设我们要 hook `ibv_open_device` 函数，它可以间接地触发对 `IB_USER_VERBS_CMD_GET_CONTEXT` 的调用。

```javascript
function hook_ibv_open_device() {
  const ibv_open_device = Module.findExportByName("libinfiniband.so", "ibv_open_device");
  if (ibv_open_device) {
    Interceptor.attach(ibv_open_device, {
      onEnter: function (args) {
        console.log("[+] Called ibv_open_device");
        // 可以查看传入的参数，例如设备名
        console.log("    Device Name:", Memory.readUtf8String(args[0]));
      },
      onLeave: function (retval) {
        console.log("[+] ibv_open_device returned:", retval);
        // 可以查看返回值，通常是一个设备上下文的指针
        if (!retval.isNull()) {
          // 进一步 hook 与该上下文相关的操作
        }
      },
    });
  } else {
    console.log("[-] ibv_open_device not found");
  }
}

function hook_ioctl() {
  const ioctl = Module.findExportByName(null, "ioctl");
  if (ioctl) {
    Interceptor.attach(ioctl, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        // 可以根据 request 的值判断是哪个 IB verb 命令
        if (request === 0xC0186900) { // 假设 IB_USER_VERBS_CMD_GET_CONTEXT 对应的 ioctl 请求码
          console.log("[+] ioctl called with IB_USER_VERBS_CMD_GET_CONTEXT");
          // 可以进一步解析 args[2] 指向的数据，查看具体的命令结构体
          const cmd_hdr_ptr = args[2];
          const command = cmd_hdr_ptr.readU32();
          const in_words = cmd_hdr_ptr.add(4).readU16();
          const out_words = cmd_hdr_ptr.add(6).readU16();
          console.log("    Command:", command);
          console.log("    In Words:", in_words);
          console.log("    Out Words:", out_words);
        }
      },
      onLeave: function (retval) {
        // 查看 ioctl 的返回值
      },
    });
  } else {
    console.log("[-] ioctl not found");
  }
}

function main() {
  console.log("Attaching Frida...");
  hook_ibv_open_device();
  hook_ioctl();
}

setImmediate(main);
```

**说明:**

* `hook_ibv_open_device`:  Hook 了 `libinfiniband.so` 中的 `ibv_open_device` 函数，可以查看其参数和返回值。
* `hook_ioctl`: Hook 了 `ioctl` 系统调用。通过检查 `request` 参数，可以判断是否是与 InfiniBand 相关的 ioctl 调用。示例中假设 `0xC0186900` 是 `IB_USER_VERBS_CMD_GET_CONTEXT` 对应的 ioctl 请求码 (实际值需要根据内核驱动定义确定)。你可以进一步解析 `args[2]` 指向的内存，查看 `ib_uverbs_cmd_hdr` 结构体的内容。

通过结合 hook 用户空间库函数和底层的 `ioctl` 系统调用，可以逐步追踪 Android 应用使用 InfiniBand 功能的流程，并观察用户空间和内核之间的数据交互。

请注意，InfiniBand 在典型的 Android 应用中并不常见。这个头文件更多的是为特定硬件和高性能应用场景提供的接口。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/ib_user_verbs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef IB_USER_VERBS_H
#define IB_USER_VERBS_H
#include <linux/types.h>
#define IB_USER_VERBS_ABI_VERSION 6
#define IB_USER_VERBS_CMD_THRESHOLD 50
enum ib_uverbs_write_cmds {
  IB_USER_VERBS_CMD_GET_CONTEXT,
  IB_USER_VERBS_CMD_QUERY_DEVICE,
  IB_USER_VERBS_CMD_QUERY_PORT,
  IB_USER_VERBS_CMD_ALLOC_PD,
  IB_USER_VERBS_CMD_DEALLOC_PD,
  IB_USER_VERBS_CMD_CREATE_AH,
  IB_USER_VERBS_CMD_MODIFY_AH,
  IB_USER_VERBS_CMD_QUERY_AH,
  IB_USER_VERBS_CMD_DESTROY_AH,
  IB_USER_VERBS_CMD_REG_MR,
  IB_USER_VERBS_CMD_REG_SMR,
  IB_USER_VERBS_CMD_REREG_MR,
  IB_USER_VERBS_CMD_QUERY_MR,
  IB_USER_VERBS_CMD_DEREG_MR,
  IB_USER_VERBS_CMD_ALLOC_MW,
  IB_USER_VERBS_CMD_BIND_MW,
  IB_USER_VERBS_CMD_DEALLOC_MW,
  IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,
  IB_USER_VERBS_CMD_CREATE_CQ,
  IB_USER_VERBS_CMD_RESIZE_CQ,
  IB_USER_VERBS_CMD_DESTROY_CQ,
  IB_USER_VERBS_CMD_POLL_CQ,
  IB_USER_VERBS_CMD_PEEK_CQ,
  IB_USER_VERBS_CMD_REQ_NOTIFY_CQ,
  IB_USER_VERBS_CMD_CREATE_QP,
  IB_USER_VERBS_CMD_QUERY_QP,
  IB_USER_VERBS_CMD_MODIFY_QP,
  IB_USER_VERBS_CMD_DESTROY_QP,
  IB_USER_VERBS_CMD_POST_SEND,
  IB_USER_VERBS_CMD_POST_RECV,
  IB_USER_VERBS_CMD_ATTACH_MCAST,
  IB_USER_VERBS_CMD_DETACH_MCAST,
  IB_USER_VERBS_CMD_CREATE_SRQ,
  IB_USER_VERBS_CMD_MODIFY_SRQ,
  IB_USER_VERBS_CMD_QUERY_SRQ,
  IB_USER_VERBS_CMD_DESTROY_SRQ,
  IB_USER_VERBS_CMD_POST_SRQ_RECV,
  IB_USER_VERBS_CMD_OPEN_XRCD,
  IB_USER_VERBS_CMD_CLOSE_XRCD,
  IB_USER_VERBS_CMD_CREATE_XSRQ,
  IB_USER_VERBS_CMD_OPEN_QP,
};
enum {
  IB_USER_VERBS_EX_CMD_QUERY_DEVICE = IB_USER_VERBS_CMD_QUERY_DEVICE,
  IB_USER_VERBS_EX_CMD_CREATE_CQ = IB_USER_VERBS_CMD_CREATE_CQ,
  IB_USER_VERBS_EX_CMD_CREATE_QP = IB_USER_VERBS_CMD_CREATE_QP,
  IB_USER_VERBS_EX_CMD_MODIFY_QP = IB_USER_VERBS_CMD_MODIFY_QP,
  IB_USER_VERBS_EX_CMD_CREATE_FLOW = IB_USER_VERBS_CMD_THRESHOLD,
  IB_USER_VERBS_EX_CMD_DESTROY_FLOW,
  IB_USER_VERBS_EX_CMD_CREATE_WQ,
  IB_USER_VERBS_EX_CMD_MODIFY_WQ,
  IB_USER_VERBS_EX_CMD_DESTROY_WQ,
  IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL,
  IB_USER_VERBS_EX_CMD_DESTROY_RWQ_IND_TBL,
  IB_USER_VERBS_EX_CMD_MODIFY_CQ
};
enum ib_placement_type {
  IB_FLUSH_GLOBAL = 1U << 0,
  IB_FLUSH_PERSISTENT = 1U << 1,
};
enum ib_selectivity_level {
  IB_FLUSH_RANGE = 0,
  IB_FLUSH_MR,
};
struct ib_uverbs_async_event_desc {
  __aligned_u64 element;
  __u32 event_type;
  __u32 reserved;
};
struct ib_uverbs_comp_event_desc {
  __aligned_u64 cq_handle;
};
struct ib_uverbs_cq_moderation_caps {
  __u16 max_cq_moderation_count;
  __u16 max_cq_moderation_period;
  __u32 reserved;
};
#define IB_USER_VERBS_CMD_COMMAND_MASK 0xff
#define IB_USER_VERBS_CMD_FLAG_EXTENDED 0x80000000u
struct ib_uverbs_cmd_hdr {
  __u32 command;
  __u16 in_words;
  __u16 out_words;
};
struct ib_uverbs_ex_cmd_hdr {
  __aligned_u64 response;
  __u16 provider_in_words;
  __u16 provider_out_words;
  __u32 cmd_hdr_reserved;
};
struct ib_uverbs_get_context {
  __aligned_u64 response;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_get_context_resp {
  __u32 async_fd;
  __u32 num_comp_vectors;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_device {
  __aligned_u64 response;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_device_resp {
  __aligned_u64 fw_ver;
  __be64 node_guid;
  __be64 sys_image_guid;
  __aligned_u64 max_mr_size;
  __aligned_u64 page_size_cap;
  __u32 vendor_id;
  __u32 vendor_part_id;
  __u32 hw_ver;
  __u32 max_qp;
  __u32 max_qp_wr;
  __u32 device_cap_flags;
  __u32 max_sge;
  __u32 max_sge_rd;
  __u32 max_cq;
  __u32 max_cqe;
  __u32 max_mr;
  __u32 max_pd;
  __u32 max_qp_rd_atom;
  __u32 max_ee_rd_atom;
  __u32 max_res_rd_atom;
  __u32 max_qp_init_rd_atom;
  __u32 max_ee_init_rd_atom;
  __u32 atomic_cap;
  __u32 max_ee;
  __u32 max_rdd;
  __u32 max_mw;
  __u32 max_raw_ipv6_qp;
  __u32 max_raw_ethy_qp;
  __u32 max_mcast_grp;
  __u32 max_mcast_qp_attach;
  __u32 max_total_mcast_qp_attach;
  __u32 max_ah;
  __u32 max_fmr;
  __u32 max_map_per_fmr;
  __u32 max_srq;
  __u32 max_srq_wr;
  __u32 max_srq_sge;
  __u16 max_pkeys;
  __u8 local_ca_ack_delay;
  __u8 phys_port_cnt;
  __u8 reserved[4];
};
struct ib_uverbs_ex_query_device {
  __u32 comp_mask;
  __u32 reserved;
};
struct ib_uverbs_odp_caps {
  __aligned_u64 general_caps;
  struct {
    __u32 rc_odp_caps;
    __u32 uc_odp_caps;
    __u32 ud_odp_caps;
  } per_transport_caps;
  __u32 reserved;
};
struct ib_uverbs_rss_caps {
  __u32 supported_qpts;
  __u32 max_rwq_indirection_tables;
  __u32 max_rwq_indirection_table_size;
  __u32 reserved;
};
struct ib_uverbs_tm_caps {
  __u32 max_rndv_hdr_size;
  __u32 max_num_tags;
  __u32 flags;
  __u32 max_ops;
  __u32 max_sge;
  __u32 reserved;
};
struct ib_uverbs_ex_query_device_resp {
  struct ib_uverbs_query_device_resp base;
  __u32 comp_mask;
  __u32 response_length;
  struct ib_uverbs_odp_caps odp_caps;
  __aligned_u64 timestamp_mask;
  __aligned_u64 hca_core_clock;
  __aligned_u64 device_cap_flags_ex;
  struct ib_uverbs_rss_caps rss_caps;
  __u32 max_wq_type_rq;
  __u32 raw_packet_caps;
  struct ib_uverbs_tm_caps tm_caps;
  struct ib_uverbs_cq_moderation_caps cq_moderation_caps;
  __aligned_u64 max_dm_size;
  __u32 xrc_odp_caps;
  __u32 reserved;
};
struct ib_uverbs_query_port {
  __aligned_u64 response;
  __u8 port_num;
  __u8 reserved[7];
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_port_resp {
  __u32 port_cap_flags;
  __u32 max_msg_sz;
  __u32 bad_pkey_cntr;
  __u32 qkey_viol_cntr;
  __u32 gid_tbl_len;
  __u16 pkey_tbl_len;
  __u16 lid;
  __u16 sm_lid;
  __u8 state;
  __u8 max_mtu;
  __u8 active_mtu;
  __u8 lmc;
  __u8 max_vl_num;
  __u8 sm_sl;
  __u8 subnet_timeout;
  __u8 init_type_reply;
  __u8 active_width;
  __u8 active_speed;
  __u8 phys_state;
  __u8 link_layer;
  __u8 flags;
  __u8 reserved;
};
struct ib_uverbs_alloc_pd {
  __aligned_u64 response;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_alloc_pd_resp {
  __u32 pd_handle;
  __u32 driver_data[];
};
struct ib_uverbs_dealloc_pd {
  __u32 pd_handle;
};
struct ib_uverbs_open_xrcd {
  __aligned_u64 response;
  __u32 fd;
  __u32 oflags;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_open_xrcd_resp {
  __u32 xrcd_handle;
  __u32 driver_data[];
};
struct ib_uverbs_close_xrcd {
  __u32 xrcd_handle;
};
struct ib_uverbs_reg_mr {
  __aligned_u64 response;
  __aligned_u64 start;
  __aligned_u64 length;
  __aligned_u64 hca_va;
  __u32 pd_handle;
  __u32 access_flags;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_reg_mr_resp {
  __u32 mr_handle;
  __u32 lkey;
  __u32 rkey;
  __u32 driver_data[];
};
struct ib_uverbs_rereg_mr {
  __aligned_u64 response;
  __u32 mr_handle;
  __u32 flags;
  __aligned_u64 start;
  __aligned_u64 length;
  __aligned_u64 hca_va;
  __u32 pd_handle;
  __u32 access_flags;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_rereg_mr_resp {
  __u32 lkey;
  __u32 rkey;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_dereg_mr {
  __u32 mr_handle;
};
struct ib_uverbs_alloc_mw {
  __aligned_u64 response;
  __u32 pd_handle;
  __u8 mw_type;
  __u8 reserved[3];
  __aligned_u64 driver_data[];
};
struct ib_uverbs_alloc_mw_resp {
  __u32 mw_handle;
  __u32 rkey;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_dealloc_mw {
  __u32 mw_handle;
};
struct ib_uverbs_create_comp_channel {
  __aligned_u64 response;
};
struct ib_uverbs_create_comp_channel_resp {
  __u32 fd;
};
struct ib_uverbs_create_cq {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 cqe;
  __u32 comp_vector;
  __s32 comp_channel;
  __u32 reserved;
  __aligned_u64 driver_data[];
};
enum ib_uverbs_ex_create_cq_flags {
  IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION = 1 << 0,
  IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN = 1 << 1,
};
struct ib_uverbs_ex_create_cq {
  __aligned_u64 user_handle;
  __u32 cqe;
  __u32 comp_vector;
  __s32 comp_channel;
  __u32 comp_mask;
  __u32 flags;
  __u32 reserved;
};
struct ib_uverbs_create_cq_resp {
  __u32 cq_handle;
  __u32 cqe;
  __aligned_u64 driver_data[0];
};
struct ib_uverbs_ex_create_cq_resp {
  struct ib_uverbs_create_cq_resp base;
  __u32 comp_mask;
  __u32 response_length;
};
struct ib_uverbs_resize_cq {
  __aligned_u64 response;
  __u32 cq_handle;
  __u32 cqe;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_resize_cq_resp {
  __u32 cqe;
  __u32 reserved;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_poll_cq {
  __aligned_u64 response;
  __u32 cq_handle;
  __u32 ne;
};
enum ib_uverbs_wc_opcode {
  IB_UVERBS_WC_SEND = 0,
  IB_UVERBS_WC_RDMA_WRITE = 1,
  IB_UVERBS_WC_RDMA_READ = 2,
  IB_UVERBS_WC_COMP_SWAP = 3,
  IB_UVERBS_WC_FETCH_ADD = 4,
  IB_UVERBS_WC_BIND_MW = 5,
  IB_UVERBS_WC_LOCAL_INV = 6,
  IB_UVERBS_WC_TSO = 7,
  IB_UVERBS_WC_FLUSH = 8,
  IB_UVERBS_WC_ATOMIC_WRITE = 9,
};
struct ib_uverbs_wc {
  __aligned_u64 wr_id;
  __u32 status;
  __u32 opcode;
  __u32 vendor_err;
  __u32 byte_len;
  union {
    __be32 imm_data;
    __u32 invalidate_rkey;
  } ex;
  __u32 qp_num;
  __u32 src_qp;
  __u32 wc_flags;
  __u16 pkey_index;
  __u16 slid;
  __u8 sl;
  __u8 dlid_path_bits;
  __u8 port_num;
  __u8 reserved;
};
struct ib_uverbs_poll_cq_resp {
  __u32 count;
  __u32 reserved;
  struct ib_uverbs_wc wc[];
};
struct ib_uverbs_req_notify_cq {
  __u32 cq_handle;
  __u32 solicited_only;
};
struct ib_uverbs_destroy_cq {
  __aligned_u64 response;
  __u32 cq_handle;
  __u32 reserved;
};
struct ib_uverbs_destroy_cq_resp {
  __u32 comp_events_reported;
  __u32 async_events_reported;
};
struct ib_uverbs_global_route {
  __u8 dgid[16];
  __u32 flow_label;
  __u8 sgid_index;
  __u8 hop_limit;
  __u8 traffic_class;
  __u8 reserved;
};
struct ib_uverbs_ah_attr {
  struct ib_uverbs_global_route grh;
  __u16 dlid;
  __u8 sl;
  __u8 src_path_bits;
  __u8 static_rate;
  __u8 is_global;
  __u8 port_num;
  __u8 reserved;
};
struct ib_uverbs_qp_attr {
  __u32 qp_attr_mask;
  __u32 qp_state;
  __u32 cur_qp_state;
  __u32 path_mtu;
  __u32 path_mig_state;
  __u32 qkey;
  __u32 rq_psn;
  __u32 sq_psn;
  __u32 dest_qp_num;
  __u32 qp_access_flags;
  struct ib_uverbs_ah_attr ah_attr;
  struct ib_uverbs_ah_attr alt_ah_attr;
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 max_recv_sge;
  __u32 max_inline_data;
  __u16 pkey_index;
  __u16 alt_pkey_index;
  __u8 en_sqd_async_notify;
  __u8 sq_draining;
  __u8 max_rd_atomic;
  __u8 max_dest_rd_atomic;
  __u8 min_rnr_timer;
  __u8 port_num;
  __u8 timeout;
  __u8 retry_cnt;
  __u8 rnr_retry;
  __u8 alt_port_num;
  __u8 alt_timeout;
  __u8 reserved[5];
};
struct ib_uverbs_create_qp {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 send_cq_handle;
  __u32 recv_cq_handle;
  __u32 srq_handle;
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 max_recv_sge;
  __u32 max_inline_data;
  __u8 sq_sig_all;
  __u8 qp_type;
  __u8 is_srq;
  __u8 reserved;
  __aligned_u64 driver_data[];
};
enum ib_uverbs_create_qp_mask {
  IB_UVERBS_CREATE_QP_MASK_IND_TABLE = 1UL << 0,
};
enum {
  IB_UVERBS_CREATE_QP_SUP_COMP_MASK = IB_UVERBS_CREATE_QP_MASK_IND_TABLE,
};
struct ib_uverbs_ex_create_qp {
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 send_cq_handle;
  __u32 recv_cq_handle;
  __u32 srq_handle;
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 max_recv_sge;
  __u32 max_inline_data;
  __u8 sq_sig_all;
  __u8 qp_type;
  __u8 is_srq;
  __u8 reserved;
  __u32 comp_mask;
  __u32 create_flags;
  __u32 rwq_ind_tbl_handle;
  __u32 source_qpn;
};
struct ib_uverbs_open_qp {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 qpn;
  __u8 qp_type;
  __u8 reserved[7];
  __aligned_u64 driver_data[];
};
struct ib_uverbs_create_qp_resp {
  __u32 qp_handle;
  __u32 qpn;
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 max_recv_sge;
  __u32 max_inline_data;
  __u32 reserved;
  __u32 driver_data[0];
};
struct ib_uverbs_ex_create_qp_resp {
  struct ib_uverbs_create_qp_resp base;
  __u32 comp_mask;
  __u32 response_length;
};
struct ib_uverbs_qp_dest {
  __u8 dgid[16];
  __u32 flow_label;
  __u16 dlid;
  __u16 reserved;
  __u8 sgid_index;
  __u8 hop_limit;
  __u8 traffic_class;
  __u8 sl;
  __u8 src_path_bits;
  __u8 static_rate;
  __u8 is_global;
  __u8 port_num;
};
struct ib_uverbs_query_qp {
  __aligned_u64 response;
  __u32 qp_handle;
  __u32 attr_mask;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_qp_resp {
  struct ib_uverbs_qp_dest dest;
  struct ib_uverbs_qp_dest alt_dest;
  __u32 max_send_wr;
  __u32 max_recv_wr;
  __u32 max_send_sge;
  __u32 max_recv_sge;
  __u32 max_inline_data;
  __u32 qkey;
  __u32 rq_psn;
  __u32 sq_psn;
  __u32 dest_qp_num;
  __u32 qp_access_flags;
  __u16 pkey_index;
  __u16 alt_pkey_index;
  __u8 qp_state;
  __u8 cur_qp_state;
  __u8 path_mtu;
  __u8 path_mig_state;
  __u8 sq_draining;
  __u8 max_rd_atomic;
  __u8 max_dest_rd_atomic;
  __u8 min_rnr_timer;
  __u8 port_num;
  __u8 timeout;
  __u8 retry_cnt;
  __u8 rnr_retry;
  __u8 alt_port_num;
  __u8 alt_timeout;
  __u8 sq_sig_all;
  __u8 reserved[5];
  __aligned_u64 driver_data[];
};
struct ib_uverbs_modify_qp {
  struct ib_uverbs_qp_dest dest;
  struct ib_uverbs_qp_dest alt_dest;
  __u32 qp_handle;
  __u32 attr_mask;
  __u32 qkey;
  __u32 rq_psn;
  __u32 sq_psn;
  __u32 dest_qp_num;
  __u32 qp_access_flags;
  __u16 pkey_index;
  __u16 alt_pkey_index;
  __u8 qp_state;
  __u8 cur_qp_state;
  __u8 path_mtu;
  __u8 path_mig_state;
  __u8 en_sqd_async_notify;
  __u8 max_rd_atomic;
  __u8 max_dest_rd_atomic;
  __u8 min_rnr_timer;
  __u8 port_num;
  __u8 timeout;
  __u8 retry_cnt;
  __u8 rnr_retry;
  __u8 alt_port_num;
  __u8 alt_timeout;
  __u8 reserved[2];
  __aligned_u64 driver_data[0];
};
struct ib_uverbs_ex_modify_qp {
  struct ib_uverbs_modify_qp base;
  __u32 rate_limit;
  __u32 reserved;
};
struct ib_uverbs_ex_modify_qp_resp {
  __u32 comp_mask;
  __u32 response_length;
};
struct ib_uverbs_destroy_qp {
  __aligned_u64 response;
  __u32 qp_handle;
  __u32 reserved;
};
struct ib_uverbs_destroy_qp_resp {
  __u32 events_reported;
};
struct ib_uverbs_sge {
  __aligned_u64 addr;
  __u32 length;
  __u32 lkey;
};
enum ib_uverbs_wr_opcode {
  IB_UVERBS_WR_RDMA_WRITE = 0,
  IB_UVERBS_WR_RDMA_WRITE_WITH_IMM = 1,
  IB_UVERBS_WR_SEND = 2,
  IB_UVERBS_WR_SEND_WITH_IMM = 3,
  IB_UVERBS_WR_RDMA_READ = 4,
  IB_UVERBS_WR_ATOMIC_CMP_AND_SWP = 5,
  IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD = 6,
  IB_UVERBS_WR_LOCAL_INV = 7,
  IB_UVERBS_WR_BIND_MW = 8,
  IB_UVERBS_WR_SEND_WITH_INV = 9,
  IB_UVERBS_WR_TSO = 10,
  IB_UVERBS_WR_RDMA_READ_WITH_INV = 11,
  IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP = 12,
  IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13,
  IB_UVERBS_WR_FLUSH = 14,
  IB_UVERBS_WR_ATOMIC_WRITE = 15,
};
struct ib_uverbs_send_wr {
  __aligned_u64 wr_id;
  __u32 num_sge;
  __u32 opcode;
  __u32 send_flags;
  union {
    __be32 imm_data;
    __u32 invalidate_rkey;
  } ex;
  union {
    struct {
      __aligned_u64 remote_addr;
      __u32 rkey;
      __u32 reserved;
    } rdma;
    struct {
      __aligned_u64 remote_addr;
      __aligned_u64 compare_add;
      __aligned_u64 swap;
      __u32 rkey;
      __u32 reserved;
    } atomic;
    struct {
      __u32 ah;
      __u32 remote_qpn;
      __u32 remote_qkey;
      __u32 reserved;
    } ud;
  } wr;
};
struct ib_uverbs_post_send {
  __aligned_u64 response;
  __u32 qp_handle;
  __u32 wr_count;
  __u32 sge_count;
  __u32 wqe_size;
  struct ib_uverbs_send_wr send_wr[];
};
struct ib_uverbs_post_send_resp {
  __u32 bad_wr;
};
struct ib_uverbs_recv_wr {
  __aligned_u64 wr_id;
  __u32 num_sge;
  __u32 reserved;
};
struct ib_uverbs_post_recv {
  __aligned_u64 response;
  __u32 qp_handle;
  __u32 wr_count;
  __u32 sge_count;
  __u32 wqe_size;
  struct ib_uverbs_recv_wr recv_wr[];
};
struct ib_uverbs_post_recv_resp {
  __u32 bad_wr;
};
struct ib_uverbs_post_srq_recv {
  __aligned_u64 response;
  __u32 srq_handle;
  __u32 wr_count;
  __u32 sge_count;
  __u32 wqe_size;
  struct ib_uverbs_recv_wr recv[];
};
struct ib_uverbs_post_srq_recv_resp {
  __u32 bad_wr;
};
struct ib_uverbs_create_ah {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 reserved;
  struct ib_uverbs_ah_attr attr;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_create_ah_resp {
  __u32 ah_handle;
  __u32 driver_data[];
};
struct ib_uverbs_destroy_ah {
  __u32 ah_handle;
};
struct ib_uverbs_attach_mcast {
  __u8 gid[16];
  __u32 qp_handle;
  __u16 mlid;
  __u16 reserved;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_detach_mcast {
  __u8 gid[16];
  __u32 qp_handle;
  __u16 mlid;
  __u16 reserved;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_flow_spec_hdr {
  __u32 type;
  __u16 size;
  __u16 reserved;
  __aligned_u64 flow_spec_data[0];
};
struct ib_uverbs_flow_eth_filter {
  __u8 dst_mac[6];
  __u8 src_mac[6];
  __be16 ether_type;
  __be16 vlan_tag;
};
struct ib_uverbs_flow_spec_eth {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_eth_filter val;
  struct ib_uverbs_flow_eth_filter mask;
};
struct ib_uverbs_flow_ipv4_filter {
  __be32 src_ip;
  __be32 dst_ip;
  __u8 proto;
  __u8 tos;
  __u8 ttl;
  __u8 flags;
};
struct ib_uverbs_flow_spec_ipv4 {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_ipv4_filter val;
  struct ib_uverbs_flow_ipv4_filter mask;
};
struct ib_uverbs_flow_tcp_udp_filter {
  __be16 dst_port;
  __be16 src_port;
};
struct ib_uverbs_flow_spec_tcp_udp {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_tcp_udp_filter val;
  struct ib_uverbs_flow_tcp_udp_filter mask;
};
struct ib_uverbs_flow_ipv6_filter {
  __u8 src_ip[16];
  __u8 dst_ip[16];
  __be32 flow_label;
  __u8 next_hdr;
  __u8 traffic_class;
  __u8 hop_limit;
  __u8 reserved;
};
struct ib_uverbs_flow_spec_ipv6 {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_ipv6_filter val;
  struct ib_uverbs_flow_ipv6_filter mask;
};
struct ib_uverbs_flow_spec_action_tag {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  __u32 tag_id;
  __u32 reserved1;
};
struct ib_uverbs_flow_spec_action_drop {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
};
struct ib_uverbs_flow_spec_action_handle {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  __u32 handle;
  __u32 reserved1;
};
struct ib_uverbs_flow_spec_action_count {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  __u32 handle;
  __u32 reserved1;
};
struct ib_uverbs_flow_tunnel_filter {
  __be32 tunnel_id;
};
struct ib_uverbs_flow_spec_tunnel {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_tunnel_filter val;
  struct ib_uverbs_flow_tunnel_filter mask;
};
struct ib_uverbs_flow_spec_esp_filter {
  __u32 spi;
  __u32 seq;
};
struct ib_uverbs_flow_spec_esp {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_spec_esp_filter val;
  struct ib_uverbs_flow_spec_esp_filter mask;
};
struct ib_uverbs_flow_gre_filter {
  __be16 c_ks_res0_ver;
  __be16 protocol;
  __be32 key;
};
struct ib_uverbs_flow_spec_gre {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_gre_filter val;
  struct ib_uverbs_flow_gre_filter mask;
};
struct ib_uverbs_flow_mpls_filter {
  __be32 label;
};
struct ib_uverbs_flow_spec_mpls {
  union {
    struct ib_uverbs_flow_spec_hdr hdr;
    struct {
      __u32 type;
      __u16 size;
      __u16 reserved;
    };
  };
  struct ib_uverbs_flow_mpls_filter val;
  struct ib_uverbs_flow_mpls_filter mask;
};
struct ib_uverbs_flow_attr {
  __u32 type;
  __u16 size;
  __u16 priority;
  __u8 num_of_specs;
  __u8 reserved[2];
  __u8 port;
  __u32 flags;
  struct ib_uverbs_flow_spec_hdr flow_specs[];
};
struct ib_uverbs_create_flow {
  __u32 comp_mask;
  __u32 qp_handle;
  struct ib_uverbs_flow_attr flow_attr;
};
struct ib_uverbs_create_flow_resp {
  __u32 comp_mask;
  __u32 flow_handle;
};
struct ib_uverbs_destroy_flow {
  __u32 comp_mask;
  __u32 flow_handle;
};
struct ib_uverbs_create_srq {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 max_wr;
  __u32 max_sge;
  __u32 srq_limit;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_create_xsrq {
  __aligned_u64 response;
  __aligned_u64 user_handle;
  __u32 srq_type;
  __u32 pd_handle;
  __u32 max_wr;
  __u32 max_sge;
  __u32 srq_limit;
  __u32 max_num_tags;
  __u32 xrcd_handle;
  __u32 cq_handle;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_create_srq_resp {
  __u32 srq_handle;
  __u32 max_wr;
  __u32 max_sge;
  __u32 srqn;
  __u32 driver_data[];
};
struct ib_uverbs_modify_srq {
  __u32 srq_handle;
  __u32 attr_mask;
  __u32 max_wr;
  __u32 srq_limit;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_srq {
  __aligned_u64 response;
  __u32 srq_handle;
  __u32 reserved;
  __aligned_u64 driver_data[];
};
struct ib_uverbs_query_srq_resp {
  __u32 max_wr;
  __u32 max_sge;
  __u32 srq_limit;
  __u32 reserved;
};
struct ib_uverbs_destroy_srq {
  __aligned_u64 response;
  __u32 srq_handle;
  __u32 reserved;
};
struct ib_uverbs_destroy_srq_resp {
  __u32 events_reported;
};
struct ib_uverbs_ex_create_wq {
  __u32 comp_mask;
  __u32 wq_type;
  __aligned_u64 user_handle;
  __u32 pd_handle;
  __u32 cq_handle;
  __u32 max_wr;
  __u32 max_sge;
  __u32 create_flags;
  __u32 reserved;
};
struct ib_uverbs_ex_create_wq_resp {
  __u32 comp_mask;
  __u32 response_length;
  __u32 wq_handle;
  __u32 max_wr;
  __u32 max_sge;
  __u32 wqn;
};
struct ib_uverbs_ex_destroy_wq {
  __u32 comp_mask;
  __u32 wq_handle;
};
struct ib_uverbs_ex_destroy_wq_resp {
  __u32 comp_mask;
  __u32 response_length;
  __u32 events_reported;
  __u32 reserved;
};
struct ib_uverbs_ex_modify_wq {
  __u32 attr_mask;
  __u32 wq_handle;
  __u32 wq_state;
  __u32 curr_wq_state;
  __u32 flags;
  __u32 flags_mask;
};
#define IB_USER_VERBS_MAX_LOG_IND_TBL_SIZE 0x0d
struct ib_uverbs_ex_create_rwq_ind_table {
  __u32 comp_mask;
  __u32 log_ind_tbl_size;
  __u32 wq_handles[];
};
struct ib_uverbs_ex_create_rwq_ind_table_resp {
  __u32 comp_mask;
  __u32 response_length;
  __u32 ind_tbl_handle;
  __u32 ind_tbl_num;
};
struct ib_uverbs_ex_destroy_rwq_ind_table {
  __u32 comp_mask;
  __u32 ind_tbl_handle;
};
struct ib_uverbs_cq_moderation {
  __u16 cq_count;
  __u16 cq_period;
};
struct ib_uverbs_ex_modify_cq {
  __u32 cq_handle;
  __u32 attr_mask;
  struct ib_uverbs_cq_moderation attr;
  __u32 reserved;
};
#define IB_DEVICE_NAME_MAX 64
enum ib_uverbs_device_cap_flags {
  IB_UVERBS_DEVICE_RESIZE_MAX_WR = 1 << 0,
  IB_UVERBS_DEVICE_BAD_PKEY_CNTR = 1 << 1,
  IB_UVERBS_DEVICE_BAD_QKEY_CNTR = 1 << 2,
  IB_UVERBS_DEVICE_RAW_MULTI = 1 << 3,
  IB_UVERBS_DEVICE_AUTO_PATH_MIG = 1 << 4,
  IB_UVERBS_DEVICE_CHANGE_PHY_PORT = 1 << 5,
  IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE = 1 << 6,
  IB_UVERBS_DEVICE_CURR_QP_STATE_MOD = 1 << 7,
  IB_UVERBS_DEVICE_SHUTDOWN_PORT = 1 << 8,
  IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT = 1 << 10,
  IB_UVERBS_DEVICE_SYS_IMAGE_GUID = 1 << 11,
  IB_UVERBS_DEVICE_RC_RNR_NAK_GEN = 1 << 12,
  IB_UVERBS_DEVICE_SRQ_RESIZE = 1 << 13,
  IB_UVERBS_DEVICE_N_NOTIFY_CQ = 1 << 14,
  IB_UVERBS_DEVICE_MEM_WINDOW = 1 << 17,
  IB_UVERBS_DEVICE_UD_IP_CSUM = 1 << 18,
  IB_UVERBS_DEVICE_XRC = 1 << 20,
  IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS = 1 << 21,
  IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A = 1 << 23,
  IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B = 1 << 24,
  IB_UVERBS_DEVICE_RC_IP_CSUM = 1 << 25,
  IB_UVERBS_DEVICE_RAW_IP_CSUM = 1 << 26,
  IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING = 1 << 29,
  IB_UVERBS_DEVICE_RAW_SCATTER_FCS = 1ULL << 34,
  IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING = 1ULL << 36,
  IB_UVERBS_DEVICE_FLUSH_GLOBAL = 1ULL << 38,
  IB_UVERBS_DEVICE_FLUSH_PERSISTENT = 1ULL << 39,
  IB_UVERBS_DEVICE_ATOMIC_WRITE = 1ULL << 40,
};
enum ib_uverbs_raw_packet_caps {
  IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING = 1 << 0,
  IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS = 1 << 1,
  IB_UVERBS_RAW_PACKET_CAP_IP_CSUM = 1 << 2,
  IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP = 1 << 3,
};
#endif

"""

```