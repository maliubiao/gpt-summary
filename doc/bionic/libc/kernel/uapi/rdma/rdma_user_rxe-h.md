Response:
Let's break down the thought process for generating the comprehensive answer.

1. **Understand the Core Request:** The request asks for a detailed explanation of the provided C header file (`rdma_user_rxe.h`), focusing on its functionality, relationship to Android, implementation details (especially libc and dynamic linker), error scenarios, and how it's accessed in Android. It also requests Frida hooking examples.

2. **Initial Analysis of the Header File:**

   * **Filename and Path:** `bionic/libc/kernel/uapi/rdma/rdma_user_rxe.handroid`. Key takeaways: This is part of Android's Bionic libc, relates to the kernel's UAPI (User API), specifically deals with RDMA (Remote Direct Memory Access), and has a "handroid" suffix suggesting Android-specific adjustments.
   * **Autogenerated Notice:**  Highlights that manual modifications will be lost. This is important context.
   * **Includes:** `<linux/types.h>`, `<linux/socket.h>`, `<linux/in.h>`, `<linux/in6.h>`. These are standard Linux kernel headers, indicating this code interfaces directly with kernel RDMA functionality.
   * **Data Structures:** A series of `struct` and `union` definitions. These represent data structures used for RDMA operations. Names like `rxe_av`, `rxe_send_wr`, `rxe_sge` are indicative of RDMA concepts.
   * **Enums:**  `RXE_NETWORK_TYPE_IPV4`, `RXE_NETWORK_TYPE_IPV6`. Clearly defines supported network types.

3. **Categorizing Functionality:**  Based on the data structures, I can deduce the high-level functionalities:

   * **Addressing:** `rxe_gid`, `rxe_global_route`, `rxe_av`. These structures deal with defining network addresses and routing information for RDMA connections.
   * **Sending Data:** `rxe_send_wr`, `rxe_sge`, `rxe_send_wqe`, `rxe_dma_info`. These are involved in constructing and managing RDMA send operations. Key concepts here are work requests (WRs), scatter-gather entries (SGEs), and work queue entries (WQEs).
   * **Receiving Data:** `rxe_recv_wqe`. Manages RDMA receive operations.
   * **Resource Management:** `rxe_create_ah_resp`, `rxe_create_cq_resp`, `rxe_resize_cq_resp`, `rxe_create_qp_resp`, `rxe_create_srq_resp`, `rxe_modify_srq_cmd`. These structures deal with creating and managing RDMA resources like Address Handles (AH), Completion Queues (CQ), Queue Pairs (QP), and Shared Receive Queues (SRQ).
   * **Queue Buffers:** `rxe_queue_buf`. Likely used for managing the underlying data structures for queues.

4. **Relating to Android:**

   * **Kernel Interface:**  The "uapi" directory strongly suggests this is a user-space interface to kernel functionality. Android, being Linux-based, utilizes kernel features extensively.
   * **Potential Use Cases:** Consider where high-performance networking is needed in Android:
      * **High-Performance Computing/Server Apps:**  While less common on typical phones, specialized Android devices or emulators might use RDMA.
      * **Inter-Process Communication (IPC):** Although Binder is the primary IPC mechanism, RDMA could be used for very low-latency, high-bandwidth IPC in specific scenarios.
      * **Networking Infrastructure:**  Less likely directly in apps, but perhaps in Android's network stack or related system services.

5. **Libc Function Implementation:**

   * **Header File, Not Implementation:** The key realization is that this is a *header file*. It *declares* structures and enums but *doesn't contain the actual C code* that implements RDMA operations.
   * **Kernel Responsibility:**  The implementation resides within the Linux kernel's RDMA subsystem. Libc functions (if they directly used these structures) would make system calls to interact with the kernel.
   * **Focus on Data Structures:** Therefore, the explanation focuses on *how the structures are used to represent RDMA concepts*.

6. **Dynamic Linker (and SO Layout):**

   * **Header File, No Linking:**  Again, this is a header file. It doesn't get linked directly.
   * **SO Involvement (Indirect):** If user-space libraries *used* these structures, those libraries would be compiled and linked.
   * **Hypothetical Scenario:**  Imagine a hypothetical `librdma_android.so` that provides a user-friendly API around these kernel structures. The explanation provides a basic SO layout and describes the dynamic linking process conceptually (symbol resolution, GOT, PLT).

7. **Logical Reasoning and Examples:**

   * **Assumptions:**  For things like network type, the assumptions are straightforward based on the enum values. For work requests, the assumption is the user wants to send data.
   * **Input/Output:**  Illustrate how data would be populated in the structures for specific operations (e.g., sending data to a specific IP address).

8. **User/Programming Errors:**

   * **Common RDMA Pitfalls:** Think about common issues in network programming and RDMA specifically: incorrect addresses, invalid keys, buffer overflows, resource management errors. Relate these back to the specific fields in the structures.

9. **Android Framework/NDK Access:**

   * **Kernel Layer:** The starting point is the kernel.
   * **System Calls:** User-space interacts with the kernel via system calls (even if indirectly).
   * **NDK (Possible):**  While less likely for direct RDMA access in typical apps, it's conceivable that an NDK library could wrap these structures for advanced use cases.
   * **Framework (Less Likely):** Direct framework usage is improbable for such a low-level networking feature.

10. **Frida Hooking:**

    * **Targeting System Calls (Likely):** Since the core functionality is in the kernel, hooking the relevant RDMA system calls would be the most direct approach. Identifying those system calls (e.g., `ib_post_send`, `ib_post_recv`) is crucial.
    * **Hooking Library Functions (Hypothetical):** If a user-space library like `librdma_android.so` existed, its functions could be hooked as well.
    * **Focus on Key Structures:** Demonstrate how to access and print the contents of the relevant data structures being passed to the kernel or library functions.

11. **Language and Formatting:**

    * **Chinese Response:**  Adhere strictly to the requirement for a Chinese response.
    * **Clear and Organized:** Use headings, bullet points, and code formatting to make the explanation easy to understand.
    * **Address All Parts of the Request:**  Ensure each aspect of the prompt is addressed thoroughly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Perhaps these structures are directly used by some libc functions. **Correction:** Realized this is a `uapi` header, meaning it defines the interface for user-space to talk to the kernel. Libc might provide wrappers around the underlying system calls, but doesn't directly implement the RDMA logic defined here.
* **Considered providing specific system call numbers.** **Decision:**  While helpful, focusing on the *names* of the relevant system calls is more generally understandable and less dependent on specific kernel versions.
* **Initially focused too much on direct NDK usage.** **Refinement:** Broadened the explanation to include the possibility of NDK libraries *wrapping* this functionality, rather than direct use within most NDK apps.

By following this thought process, breaking down the problem into smaller parts, and constantly referring back to the original request, a comprehensive and accurate answer can be constructed. The key is to understand the *nature* of the provided code (a kernel UAPI header) and its implications.
这个文件 `bionic/libc/kernel/uapi/rdma/rdma_user_rxe.handroid` 是 Android Bionic libc 中定义的一个头文件，用于定义用户空间程序与内核 RDMA (Remote Direct Memory Access) 子系统交互时使用的数据结构。由于它位于 `uapi` 目录下，这意味着它定义的是用户空间程序可以直接使用的接口，与内核的 RDMA 实现细节相分离。 "handroid" 后缀可能表明这是 Android 对标准 Linux RDMA 接口的特定修改或扩展。

**它的功能：**

该头文件定义了一系列 C 结构体和枚举，用于描述 RDMA 操作的各种参数和数据结构，主要功能包括：

1. **定义 RDMA 网络类型：**  `RXE_NETWORK_TYPE_IPV4` 和 `RXE_NETWORK_TYPE_IPV6` 定义了支持的 IP 网络类型。
2. **定义 RDMA 全局标识符 (GID)：** `union rxe_gid` 用于表示 IPv6 的全局地址，包括子网前缀和接口 ID。
3. **定义 RDMA 全局路由头 (GRH)：** `struct rxe_global_route` 描述了 RDMA 数据包的全局路由信息，如目标 GID、流标签、源 GID 索引、跳数限制和流量类别。
4. **定义 RDMA 寻址向量 (AV)：** `struct rxe_av` 包含了 RDMA 连接的寻址信息，如端口号、网络类型、目标 MAC 地址、全局路由头，以及源和目标 GID 的地址信息（可以是 IPv4 或 IPv6）。
5. **定义 RDMA 发送工作请求 (WR)：** `struct rxe_send_wr` 描述了一个 RDMA 发送操作的细节，包括工作请求 ID、操作码（如 SEND、RDMA_WRITE、RDMA_READ、ATOMIC）、发送标志，以及不同操作类型的特定参数，如：
    * **flush:** 用于刷新操作。
    * **rdma:** 用于 RDMA 读写操作，包含远程地址、长度和密钥 (RKey)。
    * **atomic:** 用于原子操作，如比较并交换 (CAS) 和原子加。
    * **ud:** 用于不可靠数据报 (Unreliable Datagram) 操作，包含远程队列对号 (QPN)、队列密钥 (QKey) 和寻址向量。
    * **mw:**  用于内存窗口 (Memory Window) 操作，包含本地地址、长度、本地密钥 (LKey)、内存窗口密钥 (MW_RKey) 和访问权限。
6. **定义 RDMA 散列表元素 (SGE)：** `struct rxe_sge` 用于描述 RDMA 操作中的数据缓冲区，包含地址、长度和本地密钥。
7. **定义内存映射信息 (mminfo)：** `struct mminfo` 用于描述内存映射的偏移量和大小，通常用于共享内存或内存注册。
8. **定义 RDMA DMA 信息：** `struct rxe_dma_info` 描述了 RDMA 操作中的 DMA 传输信息，如长度、剩余长度、当前 SGE 索引、SGE 数量、SGE 偏移量，以及用于内联数据、原子操作数据或 SGE 数组的联合体。
9. **定义 RDMA 发送工作队列元素 (WQE)：** `struct rxe_send_wqe` 包含了发送工作请求的详细信息以及操作状态、IOVA 地址等。
10. **定义 RDMA 接收工作队列元素 (WQE)：** `struct rxe_recv_wqe` 描述了接收工作请求的信息。
11. **定义创建资源的响应结构：**  例如 `struct rxe_create_ah_resp` (创建地址句柄)、`struct rxe_create_cq_resp` (创建完成队列)、`struct rxe_create_qp_resp` (创建队列对) 和 `struct rxe_create_srq_resp` (创建共享接收队列)。
12. **定义修改共享接收队列的命令结构：** `struct rxe_modify_srq_cmd`。
13. **定义队列缓冲区结构：** `struct rxe_queue_buf` 描述了一个通用的队列缓冲区结构，可能用于实现用户空间队列。

**它与 Android 功能的关系：**

RDMA 是一种高性能的网络技术，允许应用程序直接访问远程机器的内存，绕过传统网络协议栈，从而实现低延迟和高带宽的数据传输。在 Android 中，直接使用 RDMA 的场景可能相对较少，但并非没有：

* **高性能计算 (HPC) 和服务器应用：**  如果 Android 设备被用作集群的一部分或运行需要高性能网络的应用，RDMA 可以提供显著的性能提升。例如，在特定的科学计算、数据分析或某些类型的服务器应用中。
* **虚拟化和容器化：**  在 Android 平台上运行虚拟机或容器时，RDMA 可以用于虚拟机或容器之间的快速通信。
* **存储访问：**  某些高性能存储解决方案可能使用 RDMA 进行数据传输。
* **未来可能的应用场景：**  随着 Android 设备性能的提升和新的应用场景出现，RDMA 的应用可能会更加广泛。例如，在需要极低延迟的实时应用或高带宽数据传输的应用中。

**举例说明：**

假设有一个运行在 Android 上的高性能数据库应用，需要与远程服务器进行大量的数据交互。使用 RDMA 可以显著减少数据传输的延迟，提高数据库的响应速度。应用程序可以使用该头文件中定义的结构体，例如 `rxe_send_wr` 来构造 RDMA 写请求，将数据直接写入远程服务器的内存，而无需经过传统的 TCP/IP 协议栈。

**详细解释每一个 libc 函数的功能是如何实现的：**

需要明确的是，这个头文件本身**并没有定义任何 libc 函数**。它定义的是数据结构，用于用户空间程序和内核 RDMA 子系统之间传递信息。 用户空间程序需要通过**系统调用**与内核 RDMA 子系统交互，例如 `ioctl` 系统调用，传递这些结构体定义的参数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身**不直接涉及 dynamic linker 的功能**。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是加载共享库，并解析库之间的符号依赖关系。

但是，如果用户空间的某个共享库（例如，一个提供 RDMA 功能封装的库）使用了这些头文件中定义的数据结构，那么该共享库的布局会受到 dynamic linker 的影响。

**SO 布局样本（假设存在一个使用这些结构的 `librdma_android.so`）：**

```
librdma_android.so:
    .text          # 代码段
        rdma_init:  # 初始化 RDMA 的函数
            ...     # 使用了 rxe_av, rxe_send_wr 等结构体
        rdma_send:  # 发送 RDMA 消息的函数
            ...
        ...

    .rodata        # 只读数据段
        ...

    .data          # 可读写数据段
        ...

    .bss           # 未初始化数据段
        ...

    .dynamic       # 动态链接信息
        NEEDED   libc.so
        SONAME   librdma_android.so
        ...

    .symtab        # 符号表
        rdma_init
        rdma_send
        ...

    .strtab        # 字符串表
        ...

    .rel.dyn       # 动态重定位表
        ...

    .plt           # 过程链接表 (Procedure Linkage Table)
        ...

    .got           # 全局偏移表 (Global Offset Table)
        ...
```

**链接的处理过程：**

1. **加载 SO：** 当一个应用程序需要使用 `librdma_android.so` 时，dynamic linker 会将其加载到进程的地址空间。
2. **符号解析：** 如果 `librdma_android.so` 依赖于 libc.so 中的函数（例如，用于内存分配的 `malloc`），dynamic linker 会在 libc.so 中查找这些符号的地址，并更新 `librdma_android.so` 的 GOT 表，使其指向正确的地址。
3. **重定位：**  `.rel.dyn` 段包含重定位信息，指示哪些地址需要根据库加载的实际地址进行调整。Dynamic linker 会根据这些信息修改代码和数据段中的地址。
4. **PLT 的使用：**  如果 `librdma_android.so` 调用了外部库的函数，它会通过 PLT 中的条目进行调用。第一次调用时，PLT 条目会跳转到 dynamic linker，dynamic linker 会解析目标函数的地址并更新 GOT 表，后续调用将直接跳转到目标函数。

**由于 `rdma_user_rxe.h` 是一个头文件，它本身不参与动态链接的过程。但是，任何使用了这个头文件中定义的数据结构的共享库，都会受到动态链接的影响。**

**如果做了逻辑推理，请给出假设输入与输出：**

假设用户空间程序想要创建一个 RDMA 寻址向量 (AV) 并发送一个 RDMA 写请求。

**假设输入：**

* **目标 IPv4 地址：** `192.168.1.100`
* **目标端口号：** `12345`
* **本地端口号：**  由内核分配
* **要发送的数据缓冲区地址：** `0x1000`
* **要发送的数据长度：** `1024` 字节
* **远程内存地址：** `0x2000`
* **远程内存 RKey：** `0xABCDEF01`

**逻辑推理：**

1. 用户空间程序会填充 `struct rxe_av` 结构体，设置 `network_type` 为 `RXE_NETWORK_TYPE_IPV4`，填充 `_sockaddr_in` 联合体以指定目标 IP 地址和端口。
2. 程序会填充 `struct rxe_send_wr` 结构体，设置 `opcode` 为 RDMA 写操作对应的枚举值，设置 `wr.rdma.remote_addr` 为 `0x2000`，`wr.rdma.length` 为 `1024`，`wr.rdma.rkey` 为 `0xABCDEF01`。
3. 程序可能会填充 `struct rxe_sge` 结构体，描述本地数据缓冲区的信息。
4. 程序使用系统调用（例如，通过一个 RDMA 用户空间库提供的接口）将包含这些结构体的请求传递给内核。

**假设输出（内核行为）：**

1. 内核 RDMA 子系统接收到请求，验证参数的有效性。
2. 内核根据提供的 AV 信息，将数据包发送到目标机器。
3. 远程机器的 RDMA 子系统接收到数据包，根据 RKey 验证权限，并将数据写入指定的内存地址 `0x2000`。
4. 如果是可靠连接，内核会发送确认消息。
5. 用户空间程序可能会收到一个完成事件，表明发送操作已完成。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **地址信息错误：**  在填充 `struct rxe_av` 时，如果目标 IP 地址或端口号错误，会导致连接失败或数据发送到错误的目标。
   ```c
   struct rxe_av av;
   av.network_type = RXE_NETWORK_TYPE_IPV4;
   av.sgid_addr._sockaddr_in.sin_family = AF_INET;
   av.sgid_addr._sockaddr_in.sin_port = htons(12345); // 正确
   av.dgid_addr._sockaddr_in.sin_family = AF_INET;
   av.dgid_addr._sockaddr_in.sin_addr.s_addr = inet_addr("192.168.1.100"); // 正确
   av.dgid_addr._sockaddr_in.sin_port = htons(54321); // 错误的目标端口
   ```
2. **RKey 无效：**  在 RDMA 读写操作中，如果提供的远程内存 RKey 无效或与目标内存区域不匹配，会导致权限错误或访问失败。
   ```c
   struct rxe_send_wr wr;
   wr.opcode = /* RDMA 写操作 */;
   wr.wr.rdma.remote_addr = 0x2000;
   wr.wr.rdma.length = 1024;
   wr.wr.rdma.rkey = 0x12345678; // 假设这是无效的 RKey
   ```
3. **缓冲区长度错误：**  在 RDMA 读写操作中，指定的缓冲区长度超过了实际的缓冲区大小，可能导致内存访问越界。
   ```c
   char local_buffer[512];
   struct rxe_sge sge;
   sge.addr = (uintptr_t)local_buffer;
   sge.length = 1024; // 错误：缓冲区只有 512 字节
   ```
4. **资源泄漏：**  如果创建了 RDMA 资源（如队列对、完成队列、内存区域）但没有正确释放，会导致资源泄漏。
5. **并发问题：**  在多线程环境中使用 RDMA 时，如果没有适当的同步机制，可能会导致数据竞争或状态不一致。
6. **操作码错误：**  使用错误的 `opcode` 会导致执行错误的操作。例如，尝试在未建立连接的情况下发送数据。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `rdma_user_rxe.handroid` 是内核 UAPI 头文件，Android Framework 通常不会直接使用它。更常见的情况是，用户空间的 native 代码（通过 NDK 开发）会使用 RDMA 功能。

**步骤：**

1. **NDK 应用开发：** 开发者使用 NDK 编写 C/C++ 代码，其中包含了使用 `rdma_user_rxe.h` 中定义的结构体的代码。
2. **系统调用封装库：**  NDK 应用通常不会直接进行原始的系统调用。而是使用一些用户空间库（可能是 Android 平台提供的，也可能是第三方库）来封装 RDMA 相关的系统调用。这些库会处理与内核的交互细节。
3. **系统调用：**  这些封装库最终会通过系统调用（例如 `ioctl`）与内核的 RDMA 子系统通信，传递以 `rdma_user_rxe.h` 中定义的结构体为参数的数据。
4. **内核 RDMA 子系统：**  内核接收到系统调用请求，解析其中的数据结构，执行相应的 RDMA 操作。

**Frida Hook 示例：**

假设我们想 hook 一个名为 `librdma_wrapper.so` 的共享库中的 `send_rdma_message` 函数，该函数使用了 `rxe_send_wr` 结构体。

**C++ 代码示例 (假设的 NDK 代码):**

```c++
// 在 librdma_wrapper.so 中
#include <rdma/rdma_user_rxe.h>
#include <sys/ioctl.h>
#include <unistd.h>

int send_rdma_message(int fd, struct rxe_send_wr *wr) {
  // ... 其他代码 ...
  return ioctl(fd, /* RDMA 发送操作的 ioctl 命令 */, wr);
}
```

**Frida Hook 脚本 (JavaScript):**

```javascript
// 找到 librdma_wrapper.so 的基地址
const base = Module.findBaseAddress("librdma_wrapper.so");
if (base) {
  // 找到 send_rdma_message 函数的地址 (需要根据实际符号表或反汇编获取偏移)
  const sendRdmaMessageAddr = base.add(/* send_rdma_message 函数的偏移 */);

  if (sendRdmaMessageAddr) {
    Interceptor.attach(sendRdmaMessageAddr, {
      onEnter: function(args) {
        console.log("send_rdma_message called!");
        const fd = args[0].toInt32();
        const wrPtr = ptr(args[1]);
        console.log("File Descriptor:", fd);

        // 读取 rxe_send_wr 结构体的内容
        const wr = wrPtr.readStruct({
          wr_id: 'uint64',
          reserved: 'uint32',
          opcode: 'uint32',
          send_flags: 'uint32',
          ex: {
            imm_data: 'uint32' // 假设是立即数据的情况
          },
          wr: {
            rdma: { // 假设是 RDMA 写操作
              remote_addr: 'uint64',
              length: 'uint32',
              rkey: 'uint32',
              reserved: 'uint32'
            }
          }
        });
        console.log("rxe_send_wr:", wr);
      },
      onLeave: function(retval) {
        console.log("send_rdma_message returned:", retval);
      }
    });
    console.log("Hooked send_rdma_message");
  } else {
    console.error("Failed to find send_rdma_message address");
  }
} else {
  console.error("Failed to find librdma_wrapper.so");
}
```

**调试步骤：**

1. **找到目标进程：** 使用 `frida-ps -U` 找到运行目标 NDK 应用的进程 ID。
2. **运行 Frida 脚本：** 使用 `frida -U -f <package_name> -l your_frida_script.js` 或 `frida -U <process_id> -l your_frida_script.js` 启动 Frida 并加载脚本。
3. **触发 RDMA 操作：**  在 Android 应用中触发执行 `send_rdma_message` 函数的操作。
4. **查看 Frida 输出：** Frida 会在控制台输出 hook 到的函数调用信息，包括参数值（例如 `rxe_send_wr` 结构体的内容）。

**更底层的 Hook (Hook 系统调用)：**

如果你想更深入地调试，可以尝试 hook 与 RDMA 相关的系统调用，例如 `ioctl`，并检查其参数。你需要知道用于 RDMA 操作的 `ioctl` 命令的值。

```javascript
const ioctlPtr = Module.findExportByName(null, "ioctl");
if (ioctlPtr) {
  Interceptor.attach(ioctlPtr, {
    onEnter: function(args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();
      const argp = args[2];

      // 判断是否是 RDMA 相关的 ioctl 命令 (需要根据实际情况判断)
      if (request === /* RDMA 发送操作的 ioctl 命令 */) {
        console.log("ioctl called for RDMA send!");
        console.log("File Descriptor:", fd);
        console.log("ioctl request:", request);

        // 根据 ioctl 命令的定义，解析 argp 指向的结构体 (可能是 rxe_send_wr)
        const wrPtr = ptr(argp);
        // ... 读取并打印 rxe_send_wr 结构体的内容 ...
      }
    },
    onLeave: function(retval) {
      // ...
    }
  });
}
```

请注意，实际的库名称、函数名称、`ioctl` 命令值以及结构体偏移量需要根据具体的 Android 版本、RDMA 库实现以及反汇编分析来确定。 这些 Frida 示例提供了调试 RDMA 相关代码的基本思路。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/rdma_user_rxe.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef RDMA_USER_RXE_H
#define RDMA_USER_RXE_H
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
enum {
  RXE_NETWORK_TYPE_IPV4 = 1,
  RXE_NETWORK_TYPE_IPV6 = 2,
};
union rxe_gid {
  __u8 raw[16];
  struct {
    __be64 subnet_prefix;
    __be64 interface_id;
  } global;
};
struct rxe_global_route {
  union rxe_gid dgid;
  __u32 flow_label;
  __u8 sgid_index;
  __u8 hop_limit;
  __u8 traffic_class;
};
struct rxe_av {
  __u8 port_num;
  __u8 network_type;
  __u8 dmac[6];
  struct rxe_global_route grh;
  union {
    struct sockaddr_in _sockaddr_in;
    struct sockaddr_in6 _sockaddr_in6;
  } sgid_addr, dgid_addr;
};
struct rxe_send_wr {
  __aligned_u64 wr_id;
  __u32 reserved;
  __u32 opcode;
  __u32 send_flags;
  union {
    __be32 imm_data;
    __u32 invalidate_rkey;
  } ex;
  union {
    struct {
      __aligned_u64 remote_addr;
      __u32 length;
      __u32 rkey;
      __u8 type;
      __u8 level;
    } flush;
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
      __u32 remote_qpn;
      __u32 remote_qkey;
      __u16 pkey_index;
      __u16 reserved;
      __u32 ah_num;
      __u32 pad[4];
      struct rxe_av av;
    } ud;
    struct {
      __aligned_u64 addr;
      __aligned_u64 length;
      __u32 mr_lkey;
      __u32 mw_rkey;
      __u32 rkey;
      __u32 access;
    } mw;
  } wr;
};
struct rxe_sge {
  __aligned_u64 addr;
  __u32 length;
  __u32 lkey;
};
struct mminfo {
  __aligned_u64 offset;
  __u32 size;
  __u32 pad;
};
struct rxe_dma_info {
  __u32 length;
  __u32 resid;
  __u32 cur_sge;
  __u32 num_sge;
  __u32 sge_offset;
  __u32 reserved;
  union {
    __DECLARE_FLEX_ARRAY(__u8, inline_data);
    __DECLARE_FLEX_ARRAY(__u8, atomic_wr);
    __DECLARE_FLEX_ARRAY(struct rxe_sge, sge);
  };
};
struct rxe_send_wqe {
  struct rxe_send_wr wr;
  __u32 status;
  __u32 state;
  __aligned_u64 iova;
  __u32 mask;
  __u32 first_psn;
  __u32 last_psn;
  __u32 ack_length;
  __u32 ssn;
  __u32 has_rd_atomic;
  struct rxe_dma_info dma;
};
struct rxe_recv_wqe {
  __aligned_u64 wr_id;
  __u32 reserved;
  __u32 padding;
  struct rxe_dma_info dma;
};
struct rxe_create_ah_resp {
  __u32 ah_num;
  __u32 reserved;
};
struct rxe_create_cq_resp {
  struct mminfo mi;
};
struct rxe_resize_cq_resp {
  struct mminfo mi;
};
struct rxe_create_qp_resp {
  struct mminfo rq_mi;
  struct mminfo sq_mi;
};
struct rxe_create_srq_resp {
  struct mminfo mi;
  __u32 srq_num;
  __u32 reserved;
};
struct rxe_modify_srq_cmd {
  __aligned_u64 mmap_info_addr;
};
struct rxe_queue_buf {
  __u32 log2_elem_size;
  __u32 index_mask;
  __u32 pad_1[30];
  __u32 producer_index;
  __u32 pad_2[31];
  __u32 consumer_index;
  __u32 pad_3[31];
  __u8 data[];
};
#endif

"""

```