Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of the provided C header file (`vmw_pvrdma-abi.h`), its relation to Android, detailed explanations of any libc functions, details on dynamic linking (if applicable), potential usage errors, and how to trace its usage in Android.

2. **Initial Scan and Identification:** I first scanned the header file to identify key elements:
    * **`#ifndef`, `#define`, `#include`:** Standard C preprocessor directives for header guards and including other headers. This points to it being a C header file defining an interface.
    * **`linux/types.h`:** Inclusion of standard Linux types, indicating this header is likely part of a kernel-level interface.
    * **`PVRDMA_` prefixes:**  The consistent prefix strongly suggests this header defines an ABI (Application Binary Interface) for a specific technology named "PVRDMA." The "VMW" likely indicates VMware's involvement.
    * **Macros (`#define`):**  Definitions for versioning (`PVRDMA_UVERBS_ABI_VERSION`) and bitmasks/offsets related to "UAR" (likely User Address Region).
    * **Enums (`enum pvrdma_...`):** Enumerated types defining opcodes (for work requests and completion queues), status codes, and flags. These are core to defining the communication protocol.
    * **Structs (`struct pvrdma_...`):** Structures defining data layouts for requests, responses, and control blocks (like work queue entries and completion queue entries). These define the exact format of data exchanged.

3. **High-Level Functionality Deduction:** Based on the identified elements, I concluded that the header defines the ABI for a userspace interface to the PVRDMA (Paravirtualized RDMA) device. RDMA (Remote Direct Memory Access) allows for direct memory access between machines, bypassing the CPU for data transfers. The "paravirtualized" aspect suggests it's designed for virtualized environments.

4. **Android Relevance:** I considered how this might relate to Android. Android's base is the Linux kernel. While not a core Android feature like UI rendering, RDMA is relevant for performance-critical networking scenarios, particularly in data centers or virtualized environments where Android might run as a guest OS. I hypothesized its use could be in:
    * **Virtualization Platforms:** Android running within a VM using PVRDMA for efficient communication with the hypervisor.
    * **High-Performance Networking:**  Specialized Android applications needing low-latency, high-bandwidth communication might utilize it.

5. **libc Function Analysis:** I examined the header for direct usage of standard libc functions. The `#include <linux/types.h>` is the closest, but it's not a direct libc function call. It's a Linux kernel header, and the `types.h` it includes might even be a kernel-specific version, though it often overlaps with libc types. Therefore, I concluded this header *primarily defines data structures and constants* and doesn't directly *call* libc functions. The actual implementation using these definitions would likely reside in other parts of the Android system.

6. **Dynamic Linker Analysis:**  Since this is a header file defining an ABI, it doesn't contain executable code that would be linked. The *usage* of this ABI might involve dynamic linking if there's a shared library implementing the PVRDMA userspace interface. I conceptualized a hypothetical scenario with a `.so` library and described the dynamic linking process. I created a sample `so` layout and explained the steps of resolving symbols.

7. **Logical Inference (Example):** To illustrate how the data structures are used, I chose the `pvrdma_create_qp` structure as an example. I provided hypothetical input values and described what these values likely represent in the context of creating a Queue Pair (QP) for RDMA communication.

8. **Common Usage Errors:** I thought about potential pitfalls when using an RDMA interface:
    * **Incorrect Buffer Sizes:** Mismatches between allocated buffer sizes and the values provided in the structures.
    * **Invalid Addresses:**  Providing incorrect memory addresses.
    * **Incorrect Flags/Opcodes:** Using the wrong values for enums, leading to incorrect operation.
    * **Resource Exhaustion:**  Trying to create more resources (QPs, CQs, etc.) than available.

9. **Android Framework/NDK Path and Frida Hooking:**  This required a bit of speculation, as the header itself doesn't reveal the exact path. I reasoned:
    * **Kernel Module:**  The core PVRDMA functionality would be a kernel module.
    * **Userspace Library:** An NDK library (or potentially part of the Android framework) would provide a higher-level interface to interact with the kernel module.
    * **System Calls/ioctl:** Communication between the userspace library and the kernel module would likely involve system calls (like `ioctl`).

    I then outlined the potential steps: NDK app -> JNI bridge -> NDK library -> system call -> kernel module.

    For Frida hooking, I focused on hooking the potential `ioctl` calls within the userspace library as a way to observe the interaction with the PVRDMA driver. I provided a basic Frida script example.

10. **Structure and Language:** Finally, I organized the information logically, using clear headings and explanations. I made sure to use Chinese as requested. I also included disclaimers where I was making educated guesses due to the limited information available in the header file itself. For instance, the exact location of the userspace library or the specific system calls used would require further investigation of the Android source code.

By following these steps, I could generate a comprehensive answer addressing the various aspects of the user's request, even when some information required logical deduction and informed speculation.
这个文件 `bionic/libc/kernel/uapi/rdma/vmw_pvrdma-abi.handroid` 定义了 **VMware Paravirtual RDMA (PVRDMA) 的用户空间应用程序二进制接口 (ABI)**。 简单来说，它规定了用户空间程序如何与运行在虚拟机中的 PVRDMA 设备驱动程序进行通信。由于它位于 `bionic/libc/kernel/uapi` 目录下，这意味着它是内核定义的接口，供用户空间的库（如 `bionic`）使用。 `handroid` 后缀可能表示这是针对 Android 平台的特定版本或变体。

**功能列举：**

这个头文件定义了以下主要功能和数据结构：

1. **ABI 版本定义 (`PVRDMA_UVERBS_ABI_VERSION`)**:  定义了 PVRDMA 用户空间接口的版本号，用于确保用户空间库和内核驱动程序之间的兼容性。

2. **用户地址区域 (UAR) 相关定义 (`PVRDMA_UAR_HANDLE_MASK`, `PVRDMA_UAR_QP_OFFSET` 等)**: 定义了用于访问用户地址区域的偏移和掩码。UAR 是用户空间进程映射到设备内存的区域，用于控制和管理 PVRDMA 设备。这些定义指定了 UAR 中不同功能（如队列对 (QP)、完成队列 (CQ)、共享接收队列 (SRQ)）的布局。

3. **工作请求 (Work Request) 操作码枚举 (`enum pvrdma_wr_opcode`)**: 定义了用户空间可以提交给 PVRDMA 设备的各种操作类型，例如：
    * `PVRDMA_WR_RDMA_WRITE`:  远程直接内存写入。
    * `PVRDMA_WR_RDMA_WRITE_WITH_IMM`:  带有立即数的远程直接内存写入。
    * `PVRDMA_WR_SEND`: 发送消息。
    * `PVRDMA_WR_SEND_WITH_IMM`: 带有立即数的消息发送。
    * `PVRDMA_WR_RDMA_READ`: 远程直接内存读取。
    * `PVRDMA_WR_ATOMIC_CMP_AND_SWP`: 原子比较并交换。
    * `PVRDMA_WR_ATOMIC_FETCH_AND_ADD`: 原子取数并加。
    * `PVRDMA_WR_LSO`: 大段卸载 (Large Segment Offload)。
    * 其他诸如局部失效、快速注册内存区域等操作。

4. **工作完成 (Work Completion) 状态枚举 (`enum pvrdma_wc_status`)**: 定义了 PVRDMA 设备操作完成后的各种状态码，指示操作是否成功或失败，以及失败的原因。

5. **工作完成操作码枚举 (`enum pvrdma_wc_opcode`)**: 定义了在工作完成条目中指示完成的操作类型。

6. **工作完成标志枚举 (`enum pvrdma_wc_flags`)**: 定义了工作完成条目的附加信息，例如是否包含全局路由头 (GRH)、立即数等。

7. **网络类型枚举 (`enum pvrdma_network_type`)**: 定义了 PVRDMA 可以使用的网络类型，例如 InfiniBand 或 RoCE。

8. **各种数据结构 (`struct pvrdma_alloc_ucontext_resp`, `struct pvrdma_create_cq`, 等)**: 定义了用于与 PVRDMA 设备驱动程序进行通信的各种请求和响应的数据结构，包括：
    * 分配用户上下文、保护域、创建完成队列、创建共享接收队列、创建队列对等。
    * 定义了原子操作、地址向量 (AV)、散布/聚集条目 (SGE)、工作队列条目头、完成队列条目 (CQE) 等的数据结构。

**与 Android 功能的关系及举例说明：**

PVRDMA 并不是 Android 核心功能。它主要用于提升虚拟机中网络性能的场景。因此，这个头文件在 Android 中的作用主要是 **支持 Android 作为虚拟机 Guest 操作系统在 VMware 虚拟化平台上运行时，利用 PVRDMA 技术进行高性能网络通信。**

**举例说明：**

假设一个在 VMware 虚拟机上运行的 Android 系统需要进行高性能的网络数据传输，例如：

* **容器化应用的网络加速:**  如果 Android 内部运行着容器，这些容器之间的网络通信可以通过 PVRDMA 加速。
* **虚拟化网络功能 (VNF):**  Android 可能被用作运行特定网络功能的虚拟机，PVRDMA 可以提高其网络吞吐量和降低延迟。
* **存储访问加速:**  虚拟机中的 Android 可以通过 PVRDMA 高效地访问共享存储。

在这种情况下，Android 系统中的某些组件（可能是系统服务或特定的网络库）会使用这个头文件中定义的接口，通过系统调用与底层的 PVRDMA 内核驱动程序进行交互，从而利用硬件加速的 RDMA 功能。

**详细解释每一个 libc 函数的功能是如何实现的：**

**这个头文件本身并不包含任何 libc 函数的实现。** 它只是一个定义了数据结构和常量的头文件。  实际使用这些定义的代码会调用底层的系统调用来与内核驱动程序交互。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件定义的是内核接口，通常 **不直接涉及动态链接器**。  然而，如果用户空间有一个库（比如一个 `.so` 文件）封装了对 PVRDMA 接口的调用，那么动态链接器就会参与其中。

**假设的 `.so` 布局样本：**

```
libpvrdma_user.so:
    .text          # 包含代码段
        pvrdma_create_qp()  # 封装创建 QP 的函数
        pvrdma_post_send()  # 封装发送操作的函数
        ...
    .rodata        # 包含只读数据
        ...
    .data          # 包含可写数据
        ...
    .dynsym        # 动态符号表
        pvrdma_create_qp
        pvrdma_post_send
        ...
    .dynstr        # 动态字符串表
        ...
    .rel.dyn       # 动态重定位表
        ...
```

**链接处理过程：**

1. **应用程序请求使用 PVRDMA 功能:**  Android 应用程序或系统服务可能会调用 `libpvrdma_user.so` 中提供的函数，例如 `pvrdma_create_qp()`。
2. **动态链接器介入:**  当应用程序启动或首次调用 `libpvrdma_user.so` 中的函数时，动态链接器（在 Android 中通常是 `linker` 或 `linker64`）会负责加载 `libpvrdma_user.so` 到进程的地址空间。
3. **符号解析:**  动态链接器会查找 `pvrdma_create_qp()` 等符号在 `libpvrdma_user.so` 中的地址。
4. **重定位:**  如果 `libpvrdma_user.so` 依赖于其他共享库，动态链接器还会加载这些依赖并进行符号的重定位，确保函数调用指向正确的地址。
5. **执行:**  一旦链接完成，应用程序就可以成功调用 `libpvrdma_user.so` 中封装的 PVRDMA 相关函数。这些函数内部会使用该头文件中定义的结构体和常量，构建与内核 PVRDMA 驱动程序通信的请求，并通过系统调用发送到内核。

**如果做了逻辑推理，请给出假设输入与输出：**

**假设输入 (针对 `pvrdma_create_qp` 结构体)：**

```c
struct pvrdma_create_qp create_qp_params = {
    .rbuf_addr = 0x10000000,  // 接收缓冲区地址
    .sbuf_addr = 0x20000000,  // 发送缓冲区地址
    .rbuf_size = 4096,        // 接收缓冲区大小
    .sbuf_size = 4096,        // 发送缓冲区大小
    .qp_addr = 0x30000000     // QP 控制结构地址
};
```

**逻辑推理：**

当用户空间的库使用上述参数填充 `pvrdma_create_qp` 结构体后，它会将这个结构体作为参数传递给一个系统调用（例如 `ioctl`），该系统调用由 PVRDMA 内核驱动程序处理。

**假设输出 (来自内核驱动程序的 `pvrdma_create_qp_resp` 结构体)：**

```c
struct pvrdma_create_qp_resp create_qp_response = {
    .qpn = 123,           // 分配的队列对号
    .qp_handle = 456       // 队列对句柄
};
```

**解释：**

内核驱动程序成功创建了一个队列对，并返回了分配的队列对号 (QPN) 和一个用于后续操作的句柄。用户空间的库会使用这些信息来发送和接收数据。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **缓冲区大小错误:** 用户在 `pvrdma_create_qp` 中指定的 `rbuf_size` 或 `sbuf_size` 与实际分配的缓冲区大小不符，可能导致内存访问越界。
2. **地址无效:**  提供的 `rbuf_addr`、`sbuf_addr` 或 `qp_addr` 指向无效的内存区域，导致程序崩溃。
3. **操作码错误:** 在填充工作请求结构体时，使用了错误的 `pvrdma_wr_opcode`，导致内核驱动程序无法正确处理请求。
4. **标志位错误:**  在设置工作请求或完成队列条目的标志位时出现错误，可能导致功能异常。例如，忘记设置 `PVRDMA_WC_WITH_IMM` 标志位，但尝试读取立即数。
5. **资源泄漏:**  创建了 PVRDMA 资源（如 QP、CQ）后，忘记释放，最终导致系统资源耗尽。
6. **并发访问冲突:**  多个线程或进程同时访问和修改共享的 PVRDMA 资源，可能导致数据竞争和状态不一致。
7. **未处理错误:**  忽略了 PVRDMA 操作返回的错误状态 (`pvrdma_wc_status`)，导致程序在出现错误后继续执行，产生不可预测的结果。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 PVRDMA 主要用于虚拟机环境，直接在 Android Framework 或 NDK 中使用的情况可能比较少见。更可能的是，某个运行在 Android 虚拟机中的特定应用或服务会通过 NDK 与底层的 PVRDMA 驱动进行交互。

**可能的路径：**

1. **NDK 应用:** 一个使用 NDK 开发的 C/C++ 应用需要进行高性能网络通信。
2. **自定义库封装:**  该应用可能会链接到一个自定义的共享库（例如上面提到的 `libpvrdma_user.so`），这个库封装了对 PVRDMA 接口的调用。
3. **系统调用 (ioctl):**  `libpvrdma_user.so` 中的函数会使用 `ioctl` 等系统调用，并将上面头文件中定义的数据结构作为参数传递给内核 PVRDMA 驱动程序。
4. **内核 PVRDMA 驱动:**  内核驱动程序接收到系统调用后，会解析参数，执行相应的 PVRDMA 操作，并返回结果。

**Frida Hook 示例：**

假设我们想要 hook `libpvrdma_user.so` 中封装的创建队列对的函数，该函数最终会调用 `ioctl` 系统调用。

```python
import frida
import sys

# 目标进程名称
process_name = "your_app_process_name"

# 要 hook 的共享库名称
lib_name = "libpvrdma_user.so"

# 要 hook 的函数名称 (假设封装了 ioctl 调用)
function_name = "_ZN12pvrdma_user10create_qpEPNS_16pvrdma_create_qp_tE" # 假设这是一个 C++ 函数名，需要根据实际情况调整

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("%s", "%s"), {
    onEnter: function(args) {
        console.log("[*] Hooked %s!");
        // 打印传入的参数 (假设第二个参数是指向 pvrdma_create_qp 结构体的指针)
        var create_qp_ptr = ptr(args[1]);
        console.log("[*] pvrdma_create_qp struct address: " + create_qp_ptr);

        // 读取并打印结构体内容 (需要根据实际结构体定义调整偏移)
        console.log("[*] rbuf_addr: " + create_qp_ptr.readU64());
        console.log("[*] sbuf_addr: " + create_qp_ptr.add(8).readU64());
        console.log("[*] rbuf_size: " + create_qp_ptr.add(16).readU32());
        console.log("[*] sbuf_size: " + create_qp_ptr.add(20).readU32());
        console.log("[*] qp_addr:   " + create_qp_ptr.add(24).readU64());
    },
    onLeave: function(retval) {
        console.log("[*] %s returned: " + retval);
    }
});
""" % (lib_name, function_name, function_name, function_name)

def on_message(message, data):
    if message['type'] == 'send':
        print("[Frida]:", message['payload'])
    elif message['type'] == 'error':
        print(message)

try:
    session = frida.attach(process_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"Process '{process_name}' not found.")
except Exception as e:
    print(e)
```

**步骤解释：**

1. **确定目标进程和库:**  首先需要知道哪个 Android 进程可能使用了 PVRDMA，以及哪个共享库封装了相关的调用。
2. **查找函数:**  使用 `adb shell` 和 `grep` 或 `pidof` 命令找到目标进程的 PID，然后使用 `maps` 命令查看进程加载的库，并尝试确定 PVRDMA 相关的函数。可以使用 `objdump -T` 或 `readelf -s` 查看共享库的符号表。
3. **编写 Frida 脚本:**  上面的 Python 脚本使用 Frida 提供的 API 来 attach 到目标进程，并 hook 指定的函数。
4. **`onEnter`:** 在函数执行前，`onEnter` 回调函数会被调用，我们可以在这里打印函数的参数，例如指向 `pvrdma_create_qp` 结构体的指针，并读取结构体的内容。
5. **`onLeave`:** 在函数执行后，`onLeave` 回调函数会被调用，我们可以在这里打印函数的返回值。
6. **运行 Frida 脚本:**  在 PC 上运行 Frida 脚本，它会连接到 Android 设备上的目标进程，并执行 hook 操作。

**注意：**

* 上面的 Frida 示例代码是基于假设的函数名和结构体布局，实际情况可能需要根据具体的库实现进行调整。
* Hook 系统调用（例如 `ioctl`) 也是一种调试方法，可以使用 `Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)` 来 hook `ioctl`，并检查其参数来判断是否与 PVRDMA 相关。你需要分析 `ioctl` 的第一个参数（文件描述符）和第二个参数（请求码）来识别 PVRDMA 相关的调用。

总而言之，`bionic/libc/kernel/uapi/rdma/vmw_pvrdma-abi.handroid` 定义了 Android 虚拟机 Guest 操作系统与 VMware Hypervisor 提供的 PVRDMA 功能进行交互的接口，用于提升网络性能。 虽然不是 Android 核心功能，但在特定的虚拟化场景下发挥着重要作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/vmw_pvrdma-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __VMW_PVRDMA_ABI_H__
#define __VMW_PVRDMA_ABI_H__
#include <linux/types.h>
#define PVRDMA_UVERBS_ABI_VERSION 3
#define PVRDMA_UAR_HANDLE_MASK 0x00FFFFFF
#define PVRDMA_UAR_QP_OFFSET 0
#define PVRDMA_UAR_QP_SEND (1 << 30)
#define PVRDMA_UAR_QP_RECV (1 << 31)
#define PVRDMA_UAR_CQ_OFFSET 4
#define PVRDMA_UAR_CQ_ARM_SOL (1 << 29)
#define PVRDMA_UAR_CQ_ARM (1 << 30)
#define PVRDMA_UAR_CQ_POLL (1 << 31)
#define PVRDMA_UAR_SRQ_OFFSET 8
#define PVRDMA_UAR_SRQ_RECV (1 << 30)
enum pvrdma_wr_opcode {
  PVRDMA_WR_RDMA_WRITE,
  PVRDMA_WR_RDMA_WRITE_WITH_IMM,
  PVRDMA_WR_SEND,
  PVRDMA_WR_SEND_WITH_IMM,
  PVRDMA_WR_RDMA_READ,
  PVRDMA_WR_ATOMIC_CMP_AND_SWP,
  PVRDMA_WR_ATOMIC_FETCH_AND_ADD,
  PVRDMA_WR_LSO,
  PVRDMA_WR_SEND_WITH_INV,
  PVRDMA_WR_RDMA_READ_WITH_INV,
  PVRDMA_WR_LOCAL_INV,
  PVRDMA_WR_FAST_REG_MR,
  PVRDMA_WR_MASKED_ATOMIC_CMP_AND_SWP,
  PVRDMA_WR_MASKED_ATOMIC_FETCH_AND_ADD,
  PVRDMA_WR_BIND_MW,
  PVRDMA_WR_REG_SIG_MR,
  PVRDMA_WR_ERROR,
};
enum pvrdma_wc_status {
  PVRDMA_WC_SUCCESS,
  PVRDMA_WC_LOC_LEN_ERR,
  PVRDMA_WC_LOC_QP_OP_ERR,
  PVRDMA_WC_LOC_EEC_OP_ERR,
  PVRDMA_WC_LOC_PROT_ERR,
  PVRDMA_WC_WR_FLUSH_ERR,
  PVRDMA_WC_MW_BIND_ERR,
  PVRDMA_WC_BAD_RESP_ERR,
  PVRDMA_WC_LOC_ACCESS_ERR,
  PVRDMA_WC_REM_INV_REQ_ERR,
  PVRDMA_WC_REM_ACCESS_ERR,
  PVRDMA_WC_REM_OP_ERR,
  PVRDMA_WC_RETRY_EXC_ERR,
  PVRDMA_WC_RNR_RETRY_EXC_ERR,
  PVRDMA_WC_LOC_RDD_VIOL_ERR,
  PVRDMA_WC_REM_INV_RD_REQ_ERR,
  PVRDMA_WC_REM_ABORT_ERR,
  PVRDMA_WC_INV_EECN_ERR,
  PVRDMA_WC_INV_EEC_STATE_ERR,
  PVRDMA_WC_FATAL_ERR,
  PVRDMA_WC_RESP_TIMEOUT_ERR,
  PVRDMA_WC_GENERAL_ERR,
};
enum pvrdma_wc_opcode {
  PVRDMA_WC_SEND,
  PVRDMA_WC_RDMA_WRITE,
  PVRDMA_WC_RDMA_READ,
  PVRDMA_WC_COMP_SWAP,
  PVRDMA_WC_FETCH_ADD,
  PVRDMA_WC_BIND_MW,
  PVRDMA_WC_LSO,
  PVRDMA_WC_LOCAL_INV,
  PVRDMA_WC_FAST_REG_MR,
  PVRDMA_WC_MASKED_COMP_SWAP,
  PVRDMA_WC_MASKED_FETCH_ADD,
  PVRDMA_WC_RECV = 1 << 7,
  PVRDMA_WC_RECV_RDMA_WITH_IMM,
};
enum pvrdma_wc_flags {
  PVRDMA_WC_GRH = 1 << 0,
  PVRDMA_WC_WITH_IMM = 1 << 1,
  PVRDMA_WC_WITH_INVALIDATE = 1 << 2,
  PVRDMA_WC_IP_CSUM_OK = 1 << 3,
  PVRDMA_WC_WITH_SMAC = 1 << 4,
  PVRDMA_WC_WITH_VLAN = 1 << 5,
  PVRDMA_WC_WITH_NETWORK_HDR_TYPE = 1 << 6,
  PVRDMA_WC_FLAGS_MAX = PVRDMA_WC_WITH_NETWORK_HDR_TYPE,
};
enum pvrdma_network_type {
  PVRDMA_NETWORK_IB,
  PVRDMA_NETWORK_ROCE_V1 = PVRDMA_NETWORK_IB,
  PVRDMA_NETWORK_IPV4,
  PVRDMA_NETWORK_IPV6
};
struct pvrdma_alloc_ucontext_resp {
  __u32 qp_tab_size;
  __u32 reserved;
};
struct pvrdma_alloc_pd_resp {
  __u32 pdn;
  __u32 reserved;
};
struct pvrdma_create_cq {
  __aligned_u64 buf_addr;
  __u32 buf_size;
  __u32 reserved;
};
struct pvrdma_create_cq_resp {
  __u32 cqn;
  __u32 reserved;
};
struct pvrdma_resize_cq {
  __aligned_u64 buf_addr;
  __u32 buf_size;
  __u32 reserved;
};
struct pvrdma_create_srq {
  __aligned_u64 buf_addr;
  __u32 buf_size;
  __u32 reserved;
};
struct pvrdma_create_srq_resp {
  __u32 srqn;
  __u32 reserved;
};
struct pvrdma_create_qp {
  __aligned_u64 rbuf_addr;
  __aligned_u64 sbuf_addr;
  __u32 rbuf_size;
  __u32 sbuf_size;
  __aligned_u64 qp_addr;
};
struct pvrdma_create_qp_resp {
  __u32 qpn;
  __u32 qp_handle;
};
struct pvrdma_ex_cmp_swap {
  __aligned_u64 swap_val;
  __aligned_u64 compare_val;
  __aligned_u64 swap_mask;
  __aligned_u64 compare_mask;
};
struct pvrdma_ex_fetch_add {
  __aligned_u64 add_val;
  __aligned_u64 field_boundary;
};
struct pvrdma_av {
  __u32 port_pd;
  __u32 sl_tclass_flowlabel;
  __u8 dgid[16];
  __u8 src_path_bits;
  __u8 gid_index;
  __u8 stat_rate;
  __u8 hop_limit;
  __u8 dmac[6];
  __u8 reserved[6];
};
struct pvrdma_sge {
  __aligned_u64 addr;
  __u32 length;
  __u32 lkey;
};
struct pvrdma_rq_wqe_hdr {
  __aligned_u64 wr_id;
  __u32 num_sge;
  __u32 total_len;
};
struct pvrdma_sq_wqe_hdr {
  __aligned_u64 wr_id;
  __u32 num_sge;
  __u32 total_len;
  __u32 opcode;
  __u32 send_flags;
  union {
    __be32 imm_data;
    __u32 invalidate_rkey;
  } ex;
  __u32 reserved;
  union {
    struct {
      __aligned_u64 remote_addr;
      __u32 rkey;
      __u8 reserved[4];
    } rdma;
    struct {
      __aligned_u64 remote_addr;
      __aligned_u64 compare_add;
      __aligned_u64 swap;
      __u32 rkey;
      __u32 reserved;
    } atomic;
    struct {
      __aligned_u64 remote_addr;
      __u32 log_arg_sz;
      __u32 rkey;
      union {
        struct pvrdma_ex_cmp_swap cmp_swap;
        struct pvrdma_ex_fetch_add fetch_add;
      } wr_data;
    } masked_atomics;
    struct {
      __aligned_u64 iova_start;
      __aligned_u64 pl_pdir_dma;
      __u32 page_shift;
      __u32 page_list_len;
      __u32 length;
      __u32 access_flags;
      __u32 rkey;
      __u32 reserved;
    } fast_reg;
    struct {
      __u32 remote_qpn;
      __u32 remote_qkey;
      struct pvrdma_av av;
    } ud;
  } wr;
};
struct pvrdma_cqe {
  __aligned_u64 wr_id;
  __aligned_u64 qp;
  __u32 opcode;
  __u32 status;
  __u32 byte_len;
  __be32 imm_data;
  __u32 src_qp;
  __u32 wc_flags;
  __u32 vendor_err;
  __u16 pkey_index;
  __u16 slid;
  __u8 sl;
  __u8 dlid_path_bits;
  __u8 port_num;
  __u8 smac[6];
  __u8 network_hdr_type;
  __u8 reserved2[6];
};
#endif

"""

```