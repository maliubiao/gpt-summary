Response:
Let's break down the thought process for analyzing this SIW header file and generating the detailed response.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of a C header file related to RDMA (Remote Direct Memory Access) in the context of Android's Bionic library. The core requirements are:

* **Functionality Listing:** Identify the purpose of the structures, enums, and macros.
* **Android Relevance:** Connect these elements to Android's functionality where applicable.
* **libc Function Explanation:**  Since it's in `bionic/libc/kernel/uapi`,  consider *how* the C library interacts with these kernel structures. It's not about implementing these structures *within* libc, but rather *using* them for system calls.
* **Dynamic Linker (if applicable):** Analyze any dynamic linking implications (less likely for pure kernel headers).
* **Logic and Examples:** Provide hypothetical scenarios and common usage errors.
* **Android Framework/NDK Path:** Trace the path from higher-level Android layers to this low-level header.
* **Frida Hooking:** Demonstrate how to intercept interactions.

**2. Initial Scan and Keyword Identification:**

First, I'd quickly scan the file, looking for key terms and patterns:

* **`siw` prefix:**  This immediately points to Software iWARP.
* **`RDMA`:**  The directory structure confirms this.
* **`struct`, `enum`, `define`:**  Standard C declarations.
* **`_uresp_`, `_ureq_`:** Likely indicate user-space requests and responses to the kernel.
* **`cq`, `qp`, `mr`, `srq`, `wqe`, `cqe`:**  Common RDMA terminology (Completion Queue, Queue Pair, Memory Region, Shared Receive Queue, Work Queue Entry, Completion Queue Entry).
* **`opcode`:** Operations that can be performed.
* **`flags`:**  Various control and status flags.
* **`key`, `id`:** Identifiers for resources.
* **`laddr`, `length`, `lkey`, `raddr`, `rkey`:** Addresses and keys for memory access.

**3. Deconstructing the File – Piece by Piece:**

I'd then go through the file section by section, analyzing each declaration:

* **Macros (`#define`):**
    * `SIW_NODE_DESC_COMMON`:  Looks like a descriptive string.
    * `SIW_ABI_VERSION`:  Important for compatibility.
    * `SIW_MAX_SGE`:  Maximum Scatter/Gather Entries.
    * `SIW_UOBJ_MAX_KEY`, `SIW_INVAL_UOBJ_KEY`:  Limits for user object keys.
    * `SIW_MAX_INLINE`: Calculation related to inline data.
* **Structures (`struct`):**
    * **Request/Response Pairs:**  Pay close attention to `_ureq_` and `_uresp_` pairs, as these represent the interface between user-space and the kernel. Identify the data being exchanged (e.g., IDs, keys, sizes).
    * **Core RDMA Structures:** `siw_sqe`, `siw_rqe`, `siw_cqe` are fundamental to RDMA operations. Understand their components (opcode, flags, SGEs, IDs, status).
    * **Control Structures:** `siw_cq_ctrl`.
* **Enums (`enum`):**
    * **`siw_opcode`:** List the available RDMA operations.
    * **`siw_wqe_flags`:**  Flags for work queue entries.
    * **`siw_notify_flags`:**  Flags for event notification.
    * **`siw_wc_status`:**  Completion status codes.

**4. Connecting to Android:**

This is where domain knowledge is crucial. RDMA is a hardware acceleration technique often used for high-performance networking and storage. Think about where Android might need such capabilities:

* **Inter-process communication (IPC):** Although less common than other methods.
* **Storage access:**  Potentially for very high-speed storage solutions.
* **Networking:**  For very low-latency, high-bandwidth network communication.

Crucially, recognize that this header file is part of the *kernel interface*. User-space Android apps don't directly interact with these structures. Instead, the *NDK libraries* might wrap or utilize kernel features related to RDMA.

**5. libc Function Explanation:**

The key insight here is that these structures define the data format for *system calls*. libc doesn't implement RDMA; the *kernel* does. libc provides wrapper functions (system call wrappers) that take user-space data, format it according to these structures, and pass it to the kernel. The explanation should focus on this interaction. Give examples of hypothetical system calls and how the structures are used as arguments.

**6. Dynamic Linker:**

For this specific file, dynamic linking is less relevant. Kernel headers don't contain executable code that needs linking. Briefly mention this and move on.

**7. Logic, Assumptions, and Examples:**

Create simple scenarios to illustrate how the structures are used. For example, the creation of a Completion Queue or the submission of a Work Queue Entry. Highlight common errors, such as incorrect flag settings or buffer overflows (though less directly applicable here, as the structures define the *interface*, not the implementation).

**8. Android Framework/NDK Path:**

Trace the call flow from a high-level Android API down to the kernel. This requires understanding the Android architecture. Start with a potential use case (e.g., a network operation requiring low latency) and explain how the NDK might expose relevant APIs that eventually lead to system calls using these RDMA structures. This part involves some informed speculation, as direct RDMA usage in standard Android APIs might be limited.

**9. Frida Hooking:**

Identify the system calls that would likely use these structures. Then, demonstrate how Frida can be used to intercept these calls and inspect the data being passed, including the fields defined in the header file.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on libc Implementation:**  Realize that the focus should be on libc as an *interface* to the kernel, not as the implementer of RDMA.
* **Overly Technical RDMA Details:**  Keep the explanation accessible without delving into the intricacies of the iWARP protocol itself, unless specifically requested.
* **Balancing Specificity and Generality:** Provide concrete examples but also explain the general principles.
* **Clarity and Structure:** Organize the information logically using headings and bullet points for readability.

By following this systematic approach, breaking down the problem, and connecting the technical details to the broader Android context, a comprehensive and accurate response can be generated.
这是一个描述 Software iWARP (SIW) 用户空间接口的 C 头文件，用于 Android Bionic 库中与 RDMA（Remote Direct Memory Access，远程直接内存访问）相关的操作。

**它的功能:**

该头文件定义了用户空间程序与 Linux 内核中 SIW RDMA 子系统交互所需的数据结构、常量和枚举。 具体来说，它描述了以下功能：

1. **定义常量和版本信息:**
   - `SIW_NODE_DESC_COMMON`:  定义了 SIW 节点的通用描述字符串 "Software iWARP stack"。
   - `SIW_ABI_VERSION`:  定义了 SIW 应用程序二进制接口 (ABI) 的版本号，当前为 1。
   - `SIW_MAX_SGE`:  定义了 Scatter/Gather Entry (SGE) 的最大数量，为 6。SGE 用于描述内存操作中涉及的数据块。
   - `SIW_UOBJ_MAX_KEY`: 定义了用户对象（例如，Completion Queue, Queue Pair）的最大密钥值。
   - `SIW_INVAL_UOBJ_KEY`: 定义了一个无效的用户对象密钥值。

2. **定义请求和响应的数据结构:** 这些结构体定义了用户空间程序向内核发送请求和接收内核响应的数据格式。
   - `siw_uresp_create_cq`: 创建 Completion Queue (CQ) 的响应，包含 CQ 的 ID、包含的 Completion Queue Entry (CQE) 数量和 CQ 的密钥。
   - `siw_uresp_create_qp`: 创建 Queue Pair (QP) 的响应，包含 QP 的 ID、发送队列元素 (SQE) 数量、接收队列元素 (RQE) 数量以及发送和接收队列的密钥。
   - `siw_ureq_reg_mr`: 注册 Memory Region (MR) 的请求，包含用于标识 MR 的密钥。
   - `siw_uresp_reg_mr`: 注册 MR 的响应，包含分配的 Memory Region Token (stag)。
   - `siw_uresp_create_srq`: 创建 Shared Receive Queue (SRQ) 的响应，包含 RQE 数量和 SRQ 的密钥。
   - `siw_uresp_alloc_ctx`: 分配上下文的响应，包含设备 ID。

3. **定义操作码 (opcode):**  `siw_opcode` 枚举定义了 SIW 支持的各种操作类型，例如：
   - `SIW_OP_WRITE`: 远程写操作。
   - `SIW_OP_READ`: 远程读操作。
   - `SIW_OP_READ_LOCAL_INV`: 带本地失效的远程读操作。
   - `SIW_OP_SEND`: 发送操作。
   - `SIW_OP_SEND_WITH_IMM`: 发送操作，带有立即数。
   - `SIW_OP_SEND_REMOTE_INV`: 发送操作，带有远程失效。
   - `SIW_OP_FETCH_AND_ADD`: 原子取数并加操作。
   - `SIW_OP_COMP_AND_SWAP`: 原子比较并交换操作。
   - `SIW_OP_RECEIVE`: 接收操作。
   - `SIW_OP_READ_RESPONSE`: 读操作的响应。
   - `SIW_OP_INVAL_STAG`: 使内存区域令牌失效。
   - `SIW_OP_REG_MR`: 注册内存区域。

4. **定义 Scatter/Gather Entry (SGE):** `siw_sge` 结构体描述了内存操作中涉及的单个数据块，包含本地地址、长度和本地密钥。

5. **定义 Work Queue Entry (WQE) 的标志:** `siw_wqe_flags` 枚举定义了 WQE 的各种标志，例如：
   - `SIW_WQE_VALID`:  表示 WQE 有效。
   - `SIW_WQE_INLINE`: 表示数据内联在 WQE 中。
   - `SIW_WQE_SIGNALLED`: 表示操作完成后会产生信号。
   - `SIW_WQE_SOLICITED`: 表示需要请求通知。
   - `SIW_WQE_READ_FENCE`: 表示读栅栏。
   - `SIW_WQE_REM_INVAL`: 表示远程失效。
   - `SIW_WQE_COMPLETED`: 表示操作已完成。

6. **定义 Send Queue Entry (SQE) 和 Receive Queue Entry (RQE):**
   - `siw_sqe`: 定义了发送队列中的条目，包含 ID、标志、SGE 数量、操作码、远程密钥、远程地址或基础内存区域以及 SGE 数组或访问权限。
   - `siw_rqe`: 定义了接收队列中的条目，包含 ID、标志、SGE 数量、操作码、未使用字段和 SGE 数组。

7. **定义通知标志:** `siw_notify_flags` 枚举定义了事件通知的各种标志。

8. **定义 Work Completion (WC) 状态:** `siw_wc_status` 枚举定义了操作完成时的状态码，例如成功、本地长度错误、本地协议错误等。

9. **定义 Completion Queue Entry (CQE):** `siw_cqe` 结构体描述了完成队列中的条目，包含 ID、标志、操作码、状态、传输的字节数、立即数或失效的 stag，以及基础 QP 指针或 QP ID。

10. **定义 Completion Queue 控制结构:** `siw_cq_ctrl` 结构体用于控制完成队列。

**与 Android 功能的关系及举例说明:**

SIW (Software iWARP) 是一种基于软件实现的 iWARP (Internet Wide Area RDMA Protocol)。RDMA 技术允许应用程序直接访问远程计算机的内存，而无需涉及远程主机的操作系统内核，从而显著提高网络通信的性能和效率，降低延迟。

在 Android 中，虽然直接使用 RDMA 的场景相对较少，但在以下一些高性能计算或特定应用场景中可能会涉及到：

* **高性能网络库或服务:**  一些需要极低延迟和高带宽的网络库或服务，例如用于分布式计算、存储或消息传递的中间件，可能会利用 RDMA 技术。
* **特定的硬件加速场景:** 如果 Android 设备配备了支持 RDMA 的硬件（例如，支持 RoCE 或 InfiniBand 的网卡），系统可能会利用这些硬件能力来提升性能。
* **虚拟化或容器化环境:** 在 Android 运行在虚拟化或容器化环境中的情况下，宿主机可能支持 RDMA，而容器内的 Android 系统可能通过某种方式利用这些资源。

**举例说明:**

假设 Android 系统中运行一个需要与远程服务器进行大量数据交换的应用程序，例如一个分布式数据库客户端。如果底层网络和硬件支持 RDMA，并且内核中配置了 SIW 模块，那么这个应用程序可能会使用 NDK 提供的相关接口（如果存在）来利用 SIW 进行数据传输。

1. 应用程序首先调用 NDK 提供的 RDMA 相关接口，这些接口最终会调用到 Bionic 库中的系统调用包装函数。
2. 这些系统调用包装函数会将应用程序提供的数据（例如，要写入的远程内存地址、本地数据缓冲区等）填充到类似于 `siw_sqe` 这样的结构体中。
3. 内核接收到系统调用后，SIW 模块会解析这些结构体，执行相应的 RDMA 操作。
4. 操作完成后，内核会将完成信息填充到 `siw_cqe` 结构体中，并通过完成队列通知应用程序。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含 libc 函数的实现代码**，它只是定义了内核接口的数据结构。libc 在这里的作用是提供 **系统调用包装函数**，使得用户空间程序可以通过标准 C 函数调用来与内核中的 SIW 模块交互。

例如，如果有一个创建 Completion Queue 的系统调用（假设名为 `siw_create_cq`），libc 中会有一个名为 `syscall(SYS_siw_create_cq, ...)` 的包装函数。这个包装函数会将用户提供的参数（例如，需要的 CQE 数量）填充到 `siw_uresp_create_cq` 结构体中，然后调用内核的 `siw_create_cq` 系统调用。内核执行完操作后，会将结果写回用户空间提供的结构体，libc 包装函数再将结果返回给应用程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件是内核头文件，主要用于定义内核接口，**不直接涉及动态链接器的功能**。动态链接器主要负责将共享库加载到进程的地址空间并解析符号引用。与此相关的共享库可能是提供 RDMA 用户空间接口的库（如果 Android 提供了这样的库），而不是这个定义内核接口的头文件。

如果 Android 提供了使用 SIW 的用户空间库（例如 `libsiw.so`），其布局可能如下：

```
libsiw.so:
    .text         # 代码段，包含 RDMA 相关函数的实现
    .rodata       # 只读数据段，包含常量等
    .data         # 已初始化数据段
    .bss          # 未初始化数据段
    .symtab       # 符号表，记录导出的函数和变量
    .strtab       # 字符串表，记录符号名称
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .rel.dyn      # 动态重定位表
    .rel.plt      # PLT 重定位表
```

链接处理过程：

1. **编译时:** 编译器会检查应用程序代码中使用的 `libsiw.so` 提供的函数，并在生成的目标文件中记录对这些函数的未解析引用。
2. **链接时:** 链接器将应用程序的目标文件与 `libsiw.so` 链接在一起。链接器会根据 `libsiw.so` 的符号表解析应用程序中对 RDMA 函数的引用，并将这些引用指向 `libsiw.so` 中对应的函数地址。
3. **运行时:** 当应用程序启动时，动态链接器 (如 `linker64` 或 `linker`) 会负责加载 `libsiw.so` 到进程的地址空间，并根据重定位表调整代码和数据中的地址，确保函数调用和数据访问的正确性。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要创建一个 Completion Queue (CQ)。

**假设输入:**

* 需要的 CQE 数量: 1024

**逻辑推理:**

1. 用户空间程序会调用一个封装了 `siw_create_cq` 系统调用的 libc 函数（假设名为 `siw_create_cq_wrapper`）。
2. `siw_create_cq_wrapper` 函数会将 CQE 数量 1024 填充到适当的结构体中（可能不是 `siw_uresp_create_cq`，而是另一个请求结构体，这里头文件定义的是响应结构体）。
3. 系统调用进入内核。
4. 内核 SIW 模块会分配一个 CQ，大小能容纳 1024 个 CQE，并生成一个唯一的 CQ ID 和一个密钥。
5. 内核会将生成的 CQ ID 和密钥填充到 `siw_uresp_create_cq` 结构体中。

**假设输出:**

* `siw_uresp_create_cq.cq_id`:  一个内核分配的唯一的 CQ ID，例如 `0x12345678`。
* `siw_uresp_create_cq.num_cqe`:  1024 (与输入相同)。
* `siw_uresp_create_cq.cq_key`:  内核为该 CQ 生成的密钥，例如 `0xAABBCCDD00112233`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的密钥 (Key):**  在访问或操作 RDMA 资源（例如，内存区域、队列对）时，需要提供正确的密钥。如果提供了错误的密钥，内核会拒绝操作，导致 `SIW_WC_LOC_PROT_ERR` 或 `SIW_WC_REM_ACCESS_ERR` 等错误。
   ```c
   // 假设 stag 是通过注册内存区域获得的正确密钥
   struct siw_sqe sqe;
   sqe.rkey = incorrect_stag; // 使用错误的 stag
   // ... 提交 SQE 的代码 ...
   ```

2. **超出范围的内存访问:**  在执行 RDMA 读写操作时，指定的远程地址和长度必须在已注册的内存区域范围内。超出范围的访问会导致 `SIW_WC_LOC_LEN_ERR` 或 `SIW_WC_REM_ACCESS_ERR` 等错误。
   ```c
   struct siw_sge sge;
   sge.laddr = local_buffer;
   sge.length = very_large_number; // 长度超过本地缓冲区大小
   // ... 提交使用此 SGE 的 SQE 的代码 ...
   ```

3. **错误的标志设置:**  在创建或操作 RDMA 资源时，需要设置正确的标志。例如，在创建 QP 时，需要根据预期的操作类型设置合适的属性。错误的标志设置可能导致操作失败或行为异常。

4. **资源泄漏:**  忘记释放已分配的 RDMA 资源（例如，Completion Queue、Queue Pair、Memory Region）会导致资源泄漏。

5. **并发问题:**  在多线程或多进程环境中使用 RDMA 资源时，需要进行适当的同步，以避免竞争条件和数据不一致。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 和 NDK **通常不会直接使用 SIW 这样的低级 RDMA 接口**。Android Framework 提供了更高层次的网络和 IPC 机制，例如 Socket、Binder、AIDL 等。NDK 允许开发者使用 C/C++ 开发，但通常也通过封装好的库来访问系统功能。

**如果存在使用场景，可能的路径如下：**

1. **NDK 自定义库:** 开发者可能使用 NDK 开发了一个自定义的库，该库内部使用了 Linux 的 RDMA API（包括 SIW），并将其封装成更易于使用的接口供 Android 应用调用。
2. **内核驱动或 HAL 接口:** 某些特定的硬件或系统服务可能通过内核驱动或硬件抽象层 (HAL) 接口暴露了与 RDMA 相关的能力。NDK 库可能会通过这些接口与内核交互。

**Frida Hook 示例:**

由于标准 Android Framework 和 NDK 不直接使用 SIW，直接 hook 这个头文件中定义的结构体可能不太有效。更有效的方法是 hook **可能与 SIW 交互的系统调用**。

假设内核中有一个系统调用 `sys_siw_create_cq` 用于创建 CQ。我们可以使用 Frida hook 这个系统调用，查看其参数和返回值。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
    session = device.attach(pid)
except frida.TimedOutError:
    print("[-] 无法找到 USB 设备或超时")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print("[-] 无法找到指定的进程")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "syscall"), {
  onEnter: function (args) {
    var syscall_number = args[0].toInt32();
    // 假设 sys_siw_create_cq 的系统调用号是某个值，需要根据实际情况确定
    if (syscall_number == SYS_SIW_CREATE_CQ) {
      console.log("[*] syscall: sys_siw_create_cq");
      // 可以进一步解析参数，例如 args[1] 指向的 siw_uresp_create_cq 结构体
      // var num_cqe = Memory.readU32(ptr(args[1]));
      // console.log("    num_cqe: " + num_cqe);
    }
  },
  onLeave: function (retval) {
    // 可以查看返回值
    // console.log("    retval: " + retval);
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)
sys.stdin.read()
```

**需要注意的是:**

*  `SYS_SIW_CREATE_CQ` 需要替换为实际的 `siw_create_cq` 系统调用号，这通常需要查看内核源代码或使用工具进行分析。
*  要 hook 系统调用，你需要 root 权限或在模拟器上运行。
*  如果 Android 应用是通过 NDK 使用自定义库间接调用 SIW，你可能需要 hook 该自定义库中调用系统调用的地方。

总而言之，`bionic/libc/kernel/uapi/rdma/siw-abi.h` 定义了 Android (基于 Linux 内核) 中 Software iWARP 的用户空间接口，用于高性能网络通信。虽然 Android Framework 和 NDK 通常不直接使用它，但在特定的高性能或硬件加速场景下可能会被间接使用。理解这个头文件对于理解 Android 系统底层 RDMA 功能至关重要。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/siw-abi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _SIW_USER_H
#define _SIW_USER_H
#include <linux/types.h>
#define SIW_NODE_DESC_COMMON "Software iWARP stack"
#define SIW_ABI_VERSION 1
#define SIW_MAX_SGE 6
#define SIW_UOBJ_MAX_KEY 0x08FFFF
#define SIW_INVAL_UOBJ_KEY (SIW_UOBJ_MAX_KEY + 1)
struct siw_uresp_create_cq {
  __u32 cq_id;
  __u32 num_cqe;
  __aligned_u64 cq_key;
};
struct siw_uresp_create_qp {
  __u32 qp_id;
  __u32 num_sqe;
  __u32 num_rqe;
  __u32 pad;
  __aligned_u64 sq_key;
  __aligned_u64 rq_key;
};
struct siw_ureq_reg_mr {
  __u8 stag_key;
  __u8 reserved[3];
  __u32 pad;
};
struct siw_uresp_reg_mr {
  __u32 stag;
  __u32 pad;
};
struct siw_uresp_create_srq {
  __u32 num_rqe;
  __u32 pad;
  __aligned_u64 srq_key;
};
struct siw_uresp_alloc_ctx {
  __u32 dev_id;
  __u32 pad;
};
enum siw_opcode {
  SIW_OP_WRITE,
  SIW_OP_READ,
  SIW_OP_READ_LOCAL_INV,
  SIW_OP_SEND,
  SIW_OP_SEND_WITH_IMM,
  SIW_OP_SEND_REMOTE_INV,
  SIW_OP_FETCH_AND_ADD,
  SIW_OP_COMP_AND_SWAP,
  SIW_OP_RECEIVE,
  SIW_OP_READ_RESPONSE,
  SIW_OP_INVAL_STAG,
  SIW_OP_REG_MR,
  SIW_NUM_OPCODES
};
struct siw_sge {
  __aligned_u64 laddr;
  __u32 length;
  __u32 lkey;
};
#define SIW_MAX_INLINE (sizeof(struct siw_sge) * (SIW_MAX_SGE - 1))
#if SIW_MAX_SGE < 2
#error "SIW_MAX_SGE must be at least 2"
#endif
enum siw_wqe_flags {
  SIW_WQE_VALID = 1,
  SIW_WQE_INLINE = (1 << 1),
  SIW_WQE_SIGNALLED = (1 << 2),
  SIW_WQE_SOLICITED = (1 << 3),
  SIW_WQE_READ_FENCE = (1 << 4),
  SIW_WQE_REM_INVAL = (1 << 5),
  SIW_WQE_COMPLETED = (1 << 6)
};
struct siw_sqe {
  __aligned_u64 id;
  __u16 flags;
  __u8 num_sge;
  __u8 opcode;
  __u32 rkey;
  union {
    __aligned_u64 raddr;
    __aligned_u64 base_mr;
  };
  union {
    struct siw_sge sge[SIW_MAX_SGE];
    __aligned_u64 access;
  };
};
struct siw_rqe {
  __aligned_u64 id;
  __u16 flags;
  __u8 num_sge;
  __u8 opcode;
  __u32 unused;
  struct siw_sge sge[SIW_MAX_SGE];
};
enum siw_notify_flags {
  SIW_NOTIFY_NOT = (0),
  SIW_NOTIFY_SOLICITED = (1 << 0),
  SIW_NOTIFY_NEXT_COMPLETION = (1 << 1),
  SIW_NOTIFY_MISSED_EVENTS = (1 << 2),
  SIW_NOTIFY_ALL = SIW_NOTIFY_SOLICITED | SIW_NOTIFY_NEXT_COMPLETION | SIW_NOTIFY_MISSED_EVENTS
};
enum siw_wc_status {
  SIW_WC_SUCCESS,
  SIW_WC_LOC_LEN_ERR,
  SIW_WC_LOC_PROT_ERR,
  SIW_WC_LOC_QP_OP_ERR,
  SIW_WC_WR_FLUSH_ERR,
  SIW_WC_BAD_RESP_ERR,
  SIW_WC_LOC_ACCESS_ERR,
  SIW_WC_REM_ACCESS_ERR,
  SIW_WC_REM_INV_REQ_ERR,
  SIW_WC_GENERAL_ERR,
  SIW_NUM_WC_STATUS
};
struct siw_cqe {
  __aligned_u64 id;
  __u8 flags;
  __u8 opcode;
  __u16 status;
  __u32 bytes;
  union {
    __aligned_u64 imm_data;
    __u32 inval_stag;
  };
  union {
    struct ib_qp * base_qp;
    __aligned_u64 qp_id;
  };
};
struct siw_cq_ctrl {
  __u32 flags;
  __u32 pad;
};
#endif
```