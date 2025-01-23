Response:
Let's break down the thought process to answer the user's request about the `mlx5_user_ioctl_verbs.handroid` header file.

**1. Initial Understanding and Goal:**

The user provided a header file and wants to know its function, its relationship to Android, implementation details of related libc functions, dynamic linker aspects, potential errors, and how Android frameworks reach this level. The core task is to analyze the header and extrapolate its purpose within the Android ecosystem.

**2. High-Level Analysis of the Header:**

* **Filename and Location:** `bionic/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.handroid`. This immediately signals a few things:
    * `bionic`:  It's part of Android's core C library.
    * `libc`:  Indicates it's a system-level interface.
    * `kernel/uapi`:  This signifies a user-space API definition that mirrors or interacts with kernel structures. `uapi` is crucial.
    * `rdma`:  Stands for Remote Direct Memory Access. This is a key technology for high-performance networking.
    * `mlx5`:  Refers to a specific family of Mellanox (now NVIDIA) network interface cards (NICs).
    * `ioctl_verbs`:  Indicates this file defines structures and enums used with the `ioctl` system call to interact with the MLX5 driver. "Verbs" is a common term in RDMA programming.
    * `.handroid`:  The `.handroid` extension suggests this is a modified or Android-specific version of a standard kernel header.

* **Content:** The header mainly defines `enums` and `structs`. These are data type definitions. The presence of `__u8`, `__u16`, `__u32`, `__aligned_u64` suggests it's intended for low-level communication with the kernel.

**3. Deconstructing the Functionality:**

Based on the high-level analysis, the primary function is to define the interface for user-space programs to interact with the MLX5 RDMA driver in the Linux kernel *within the Android environment*.

* **RDMA Concepts:**  The enums hint at core RDMA concepts:
    * Flow tables (`mlx5_ib_uapi_flow_table_type`): Used for packet filtering and steering.
    * Flow actions (`mlx5_ib_uapi_flow_action_flags`, `mlx5_ib_uapi_flow_action_packet_reformat_type`):  What to do with matched packets.
    * DMA buffer registration (`mlx5_ib_uapi_reg_dmabuf_flags`): For direct memory access by the NIC.
    * Asynchronous commands/events (`mlx5_ib_uapi_devx_async_cmd_hdr`, `mlx5_ib_uapi_devx_async_event_hdr`, `mlx5_ib_uapi_devx_create_event_channel_flags`):  Non-blocking communication with the driver.
    * Direct Memory (`mlx5_ib_uapi_dm_type`): Types of directly accessible memory.
    * Protection Domains/User Access Regions (`mlx5_ib_uapi_uar_alloc_type`):  Security and access control.
    * Port querying (`mlx5_ib_uapi_query_port_flags`, `mlx5_ib_uapi_query_port`): Getting information about the network port.

**4. Android Relevance and Examples:**

The key is to connect RDMA to potential Android use cases. High-performance networking is the clue.

* **High-Performance Networking:**  Android devices might need fast networking for:
    * **Server Applications:**  An Android device acting as a server (less common, but possible in embedded scenarios).
    * **Data Centers/Clusters:**  Android might be used in custom hardware within data centers.
    * **Specialized Hardware:** Devices requiring very low latency communication.
    * **Virtualization:** (Implied by the "vport" mentions).

* **Specific Examples:**  Connecting the enums to actions:
    * `MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX`: Filtering incoming network traffic. Android firewall or network monitoring apps could potentially use this (though direct usage is unlikely, more likely through higher-level APIs).
    * `MLX5_IB_UAPI_REG_DMABUF_ACCESS_DATA_DIRECT`:  Efficiently transferring large data buffers, relevant for multimedia processing or high-throughput data applications.

**5. libc Function Details:**

The core libc function involved here is `ioctl`.

* **`ioctl` Function:** Explained its purpose (device-specific control), arguments (file descriptor, request code, optional argument), and how it bridges user-space to kernel drivers.

**6. Dynamic Linker Aspects:**

While this header file *itself* isn't directly involved in dynamic linking, the *libraries that use it* would be.

* **SO Layout:** Provided a typical SO layout with `.text`, `.data`, `.bss`, etc.
* **Linking Process:**  Described the steps: finding the library, symbol resolution, relocation. Emphasized that *this specific header* influences what symbols might be present in a library that interacts with the MLX5 driver.

**7. Logical Reasoning and Examples:**

Focused on the `mlx5_ib_uapi_query_port` structure as an example of input/output. Hypothesized a scenario where you query the port and receive back flags, vport ID, etc.

**8. Common User Errors:**

Focused on the `ioctl` system call and its potential pitfalls:

* **Incorrect `ioctl` Request:** Using the wrong command code.
* **Incorrect Data Structures:**  Passing the wrong data structure or size.
* **Permissions Issues:** Not having the necessary permissions to access the device.
* **Invalid File Descriptor:**  Using a closed or invalid file descriptor.

**9. Android Framework and NDK Path:**

This requires thinking about the layers of Android.

* **Kernel:** The MLX5 driver resides here.
* **HAL (Hardware Abstraction Layer):** A potential intermediate layer, but less likely for low-level RDMA access. More likely that direct access occurs for performance reasons.
* **NDK:**  Likely entry point for developers wanting to use RDMA. They would use the NDK to write C/C++ code that includes this header.
* **Framework (Java/Kotlin):** Less likely to directly use these low-level interfaces. Higher-level Java APIs would abstract this complexity if needed.

* **Frida Hook Example:** Provided a concrete example of how to hook the `ioctl` call, filter for the relevant request code, and inspect the data structures.

**10. Language and Tone:**

Maintaining a clear and informative tone throughout, using Chinese as requested.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Could this be related to Android's network stack in general?  *Correction:*  While related to networking, RDMA is a very specific technology for high-performance scenarios, not general network usage.
* **Initial thought:** Are there many libc functions directly used in this header? *Correction:* No, the header primarily defines data structures. The *usage* of these structures would involve libc functions like `open`, `close`, `ioctl`, and memory management functions. Focus on `ioctl` as the most relevant.
* **Initial thought:** How deep should I go into RDMA specifics? *Correction:* Provide enough context to understand the purpose of the enums and structs, but avoid becoming a full RDMA tutorial. The focus should be on its role *within Android*.

By following this structured approach, combining knowledge of Android architecture, kernel interfaces, and RDMA concepts, it's possible to generate a comprehensive and accurate answer to the user's request.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.handroid` 这个头文件。

**文件功能概述**

这个头文件 `mlx5_user_ioctl_verbs.handroid` 定义了一系列用于与 Mellanox ConnectX 系列网卡 (mlx5) 的 RDMA (Remote Direct Memory Access) 驱动进行用户空间交互的常量、枚举和结构体。这些定义主要用于 `ioctl` 系统调用，允许用户空间程序配置和控制 mlx5 设备的 RDMA 功能。

**与 Android 功能的关系及举例**

虽然 Android 作为一个移动操作系统，其核心应用场景并不直接涉及高性能 RDMA 网络，但它仍然可能在以下一些场景中与此文件产生关联：

1. **服务器或嵌入式设备上的 Android:** 如果 Android 被用在需要高性能网络通信的服务器或嵌入式设备上（例如，某些数据中心或高性能计算场景），那么可能会使用到 RDMA 技术。

2. **特定的硬件加速:**  某些 Android 设备可能集成了支持 RDMA 的硬件（虽然非常罕见）。在这种情况下，系统级的服务或驱动程序可能会使用这些接口。

3. **虚拟化环境:**  在 Android 虚拟机或容器环境中，底层硬件可能支持 RDMA，而虚拟机/容器需要与宿主机或网络进行高性能通信。

**具体举例:**

假设一个场景，Android 被用在一个定制的存储设备上，该设备使用 Mellanox 网卡进行高速数据传输。

* **`MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX`:**  这个枚举定义了网络接口卡接收 (NIC RX) 的流表类型。  在 Android 存储设备中，可能需要配置流表来过滤或重定向特定的网络数据包，例如，区分不同的存储协议流量。

* **`MLX5_IB_UAPI_REG_DMABUF_ACCESS_DATA_DIRECT`:** 这个标志用于注册 DMA (Direct Memory Access) 缓冲区。Android 系统中的某些高性能数据处理服务，可能需要直接将数据从网络卡传输到内存中的特定区域，而无需 CPU 的过多干预，以提高效率。

**详细解释每一个 libc 函数的功能是如何实现的**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了一些常量、枚举和结构体，作为与内核驱动交互的接口规范。

真正与此头文件关联的 libc 函数是 **`ioctl`**。

**`ioctl` 函数的功能和实现:**

`ioctl` (input/output control) 是一个 Unix/Linux 系统调用，允许用户空间程序向设备驱动程序发送控制命令并获取状态信息。

**功能:**

* **设备特定控制:** `ioctl` 的主要目的是提供一种通用的机制，用于执行设备驱动程序特定的操作，这些操作无法通过标准的 `read` 和 `write` 系统调用完成。
* **配置设备:**  例如，配置网卡的 IP 地址、MAC 地址、传输速率等。
* **获取设备状态:**  例如，获取网卡的统计信息、错误状态等。
* **执行特定操作:**  例如，触发硬件事件、控制 DMA 传输等。

**实现:**

1. **系统调用入口:** 用户空间程序调用 `ioctl` 函数，提供文件描述符 (`fd`)、请求代码 (`request`) 和可选的参数 (`...`)。

2. **内核处理:**  `ioctl` 系统调用进入内核空间。内核根据文件描述符找到对应的设备驱动程序。

3. **驱动程序处理:**  设备驱动程序会实现一个 `ioctl` 函数，该函数接收用户空间传递的请求代码和参数。驱动程序根据请求代码执行相应的操作，这通常涉及到与硬件设备的交互。

4. **数据传递:** 用户空间传递的参数会被复制到内核空间，驱动程序处理后，可能会将结果复制回用户空间。

**在这个 `mlx5_user_ioctl_verbs.handroid` 文件的上下文中，`ioctl` 的使用方式如下：**

用户空间程序会打开一个代表 mlx5 设备的设备文件（例如 `/dev/infiniband/rdma_cm` 或其他相关设备），然后调用 `ioctl`，并使用此头文件中定义的常量作为 `request` 参数，结构体作为参数传递给驱动程序。

**例如：**

```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/types.h>
#include "mlx5_user_ioctl_verbs.handroid" // 包含此头文件

int main() {
  int fd = open("/dev/infiniband/rdma_cm", O_RDWR);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  struct mlx5_ib_uapi_query_port query_port;
  query_port.flags = MLX5_IB_UAPI_QUERY_PORT_VPORT; // 设置查询标志
  query_port.vport = 0; // 查询哪个虚拟端口

  if (ioctl(fd, /* 某个定义好的 ioctl 请求码，例如 MLX5_IB_UAPI_QUERY_PORT_CMD */, &query_port) < 0) {
    perror("ioctl");
    close(fd);
    return 1;
  }

  // 处理返回的端口信息
  printf("vport_vhca_id: %u\n", query_port.vport_vhca_id);

  close(fd);
  return 0;
}
```

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

这个头文件本身并不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的作用是加载共享库 (`.so` 文件) 到进程的地址空间，并解析库之间的依赖关系。

但是，如果一个共享库使用了 `mlx5_user_ioctl_verbs.handroid` 中定义的接口，那么这个共享库的布局和链接过程与普通共享库类似。

**SO 布局样本:**

一个使用了 mlx5 RDMA 功能的 `.so` 文件，其布局可能如下：

```
my_rdma_lib.so:
  .text         # 代码段 (函数指令)
  .rodata       # 只读数据段 (常量字符串等)
  .data         # 已初始化数据段 (全局变量)
  .bss          # 未初始化数据段 (全局变量)
  .plt          # 程序链接表 (用于延迟绑定)
  .got          # 全局偏移表 (用于访问全局变量)
  .dynsym       # 动态符号表 (导出的符号)
  .dynstr       # 动态字符串表 (符号名称)
  .rel.dyn      # 动态重定位表 (需要运行时重定位的项)
  .rel.plt      # PLT 重定位表
  ... 其他段 ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译一个使用了 `my_rdma_lib.so` 的可执行文件或共享库时，链接器会记录对 `my_rdma_lib.so` 中符号的引用。

2. **运行时加载:** 当程序启动或动态加载使用了 `my_rdma_lib.so` 的库时，dynamic linker 会执行以下操作：
   * **加载 SO:** 将 `my_rdma_lib.so` 加载到进程的地址空间。
   * **依赖解析:** 检查 `my_rdma_lib.so` 的依赖项，并加载这些依赖库。
   * **符号解析:**  将程序中对 `my_rdma_lib.so` 中符号的引用，解析到 `my_rdma_lib.so` 中实际的函数或变量地址。这通常涉及查找 `.dynsym` 和 `.dynstr` 表。
   * **重定位:**  根据 `.rel.dyn` 和 `.rel.plt` 表中的信息，修改代码和数据段中的地址，使其指向正确的内存位置。例如，更新全局变量的地址或函数调用的目标地址。

**由于 `mlx5_user_ioctl_verbs.handroid` 是一个头文件，它本身不会被动态链接。但是，使用了这个头文件的代码会被编译到某个 `.so` 文件中，而这个 `.so` 文件会经历上述的动态链接过程。**

**如果做了逻辑推理，请给出假设输入与输出**

假设我们使用 `mlx5_ib_uapi_query_port` 结构体来查询一个 mlx5 设备的端口信息。

**假设输入:**

* 文件描述符 `fd` 指向一个打开的 mlx5 设备文件。
* `ioctl` 的请求码设置为查询端口信息的常量（假设为 `MLX5_IB_UAPI_QUERY_PORT_CMD`）。
* `mlx5_ib_uapi_query_port` 结构体初始化如下：
    ```c
    struct mlx5_ib_uapi_query_port query_port;
    query_port.flags = MLX5_IB_UAPI_QUERY_PORT_VPORT; // 查询虚拟端口信息
    query_port.vport = 0; // 查询虚拟端口 0
    ```

**预期输出:**

`ioctl` 调用成功返回 0，并且 `query_port` 结构体中的其他字段会被 mlx5 驱动程序填充，包含关于虚拟端口 0 的信息，例如：

* `query_port.vport_vhca_id`:  虚拟端口所属的 VHCA (Virtual HCA) 的 ID。
* `query_port.esw_owner_vhca_id`: 如果是交换机端口，拥有该端口的 VHCA 的 ID。
* 其他与端口配置相关的参数。

**如果涉及用户或者编程常见的使用错误，请举例说明**

1. **错误的 `ioctl` 请求码:**  使用了错误的 `ioctl` 请求码，导致驱动程序无法识别用户的意图，可能返回错误码。

   ```c
   ioctl(fd, WRONG_IOCTL_COMMAND, &query_port); // WRONG_IOCTL_COMMAND 是一个错误的请求码
   ```

2. **传递了不正确的数据结构或大小:** `ioctl` 需要传递特定类型的结构体。如果传递了错误类型的结构体或大小不匹配，会导致数据解析错误或崩溃。

   ```c
   int some_integer;
   ioctl(fd, MLX5_IB_UAPI_QUERY_PORT_CMD, &some_integer); // 应该传递 struct mlx5_ib_uapi_query_port
   ```

3. **没有足够的权限:**  访问某些设备或执行某些 `ioctl` 操作可能需要特定的用户权限。如果没有足够的权限，`ioctl` 调用会失败。

4. **使用了无效的文件描述符:**  如果 `fd` 是一个无效的文件描述符（例如，文件已关闭），`ioctl` 调用会失败。

5. **结构体成员初始化不正确:** 某些 `ioctl` 命令可能依赖于输入结构体中某些字段的正确初始化。如果初始化不正确，驱动程序可能无法正确处理请求。

   ```c
   struct mlx5_ib_uapi_query_port query_port; // 未初始化
   ioctl(fd, MLX5_IB_UAPI_QUERY_PORT_CMD, &query_port); // 某些驱动可能期望 flags 被初始化
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `mlx5_user_ioctl_verbs.handroid` 定义的是 Linux 内核接口，Android Framework (通常是 Java/Kotlin 代码) 不会直接使用这些接口。只有当 Native 代码（C/C++）需要与底层的 mlx5 RDMA 硬件交互时，才会涉及到这个头文件。这通常发生在以下情况：

1. **NDK 开发:**  开发者使用 Android NDK (Native Development Kit) 编写 C/C++ 代码，并且他们的应用需要直接控制 RDMA 硬件。

2. **系统级服务或驱动:** Android 系统中某些底层的 Native 服务或硬件抽象层 (HAL) 实现可能会使用这些接口。

**步骤：**

1. **NDK 代码:** 开发者在 NDK 代码中包含 `mlx5_user_ioctl_verbs.handroid` 头文件。

2. **调用 `ioctl`:** NDK 代码中会调用 `ioctl` 系统调用，并将此头文件中定义的常量和结构体作为参数传递给内核驱动。

3. **内核驱动:** Linux 内核中的 mlx5 RDMA 驱动程序接收到 `ioctl` 请求，并根据请求码和参数执行相应的操作。

**Frida Hook 示例：**

假设我们想 hook 一个使用了 `ioctl` 系统调用来查询 mlx5 端口信息的 Native 函数。

**目标：** 捕获 `ioctl` 调用，查看传递的请求码和 `mlx5_ib_uapi_query_port` 结构体的内容。

**Frida Script:**

```javascript
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    // 假设 MLX5_IB_UAPI_QUERY_PORT_CMD 的值是 0xABCD (需要根据实际情况替换)
    const MLX5_IB_UAPI_QUERY_PORT_CMD = 0xABCD;

    if (request === MLX5_IB_UAPI_QUERY_PORT_CMD) {
      console.log("ioctl called with MLX5_IB_UAPI_QUERY_PORT_CMD");
      console.log("File descriptor:", fd);
      console.log("Request code:", request);

      // 读取 mlx5_ib_uapi_query_port 结构体的内容
      const queryPortPtr = argp;
      const flags = queryPortPtr.readU64();
      const vport = queryPortPtr.add(8).readU16();
      // ... 读取其他结构体成员 ...

      console.log("mlx5_ib_uapi_query_port:");
      console.log("  flags:", flags);
      console.log("  vport:", vport);
      // ... 打印其他成员 ...
    }
  },
  onLeave: function (retval) {
    // console.log("ioctl returned:", retval);
  }
});
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `hook.js`。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l hook.js --no-pause` (替换 `<package_name>` 为目标应用的包名，如果是一个 Native 服务，则替换为服务进程名)。
3. 当目标应用执行到调用 `ioctl` 且请求码为 `MLX5_IB_UAPI_QUERY_PORT_CMD` 时，Frida 会拦截该调用，并打印出相关信息。

**注意：**

* 你需要知道 `MLX5_IB_UAPI_QUERY_PORT_CMD` 在目标系统上的实际值，才能正确过滤 `ioctl` 调用。这通常需要在目标系统的头文件中查找或通过反汇编来确定。
* 你需要根据 `mlx5_ib_uapi_query_port` 结构体的定义，正确地从内存中读取其成员。
* hook 系统调用需要 root 权限或在可调试的进程中进行。

希望以上详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.handroid` 文件的功能及其在 Android 系统中的潜在应用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/rdma/mlx5_user_ioctl_verbs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef MLX5_USER_IOCTL_VERBS_H
#define MLX5_USER_IOCTL_VERBS_H
#include <linux/types.h>
enum mlx5_ib_uapi_flow_action_flags {
  MLX5_IB_UAPI_FLOW_ACTION_FLAGS_REQUIRE_METADATA = 1 << 0,
};
enum mlx5_ib_uapi_flow_table_type {
  MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX = 0x0,
  MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX = 0x1,
  MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB = 0x2,
  MLX5_IB_UAPI_FLOW_TABLE_TYPE_RDMA_RX = 0x3,
  MLX5_IB_UAPI_FLOW_TABLE_TYPE_RDMA_TX = 0x4,
};
enum mlx5_ib_uapi_flow_action_packet_reformat_type {
  MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2 = 0x0,
  MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL = 0x1,
  MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2 = 0x2,
  MLX5_IB_UAPI_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL = 0x3,
};
enum mlx5_ib_uapi_reg_dmabuf_flags {
  MLX5_IB_UAPI_REG_DMABUF_ACCESS_DATA_DIRECT = 1 << 0,
};
struct mlx5_ib_uapi_devx_async_cmd_hdr {
  __aligned_u64 wr_id;
  __u8 out_data[];
};
enum mlx5_ib_uapi_dm_type {
  MLX5_IB_UAPI_DM_TYPE_MEMIC,
  MLX5_IB_UAPI_DM_TYPE_STEERING_SW_ICM,
  MLX5_IB_UAPI_DM_TYPE_HEADER_MODIFY_SW_ICM,
  MLX5_IB_UAPI_DM_TYPE_HEADER_MODIFY_PATTERN_SW_ICM,
  MLX5_IB_UAPI_DM_TYPE_ENCAP_SW_ICM,
};
enum mlx5_ib_uapi_devx_create_event_channel_flags {
  MLX5_IB_UAPI_DEVX_CR_EV_CH_FLAGS_OMIT_DATA = 1 << 0,
};
struct mlx5_ib_uapi_devx_async_event_hdr {
  __aligned_u64 cookie;
  __u8 out_data[];
};
enum mlx5_ib_uapi_pp_alloc_flags {
  MLX5_IB_UAPI_PP_ALLOC_FLAGS_DEDICATED_INDEX = 1 << 0,
};
enum mlx5_ib_uapi_uar_alloc_type {
  MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF = 0x0,
  MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC = 0x1,
};
enum mlx5_ib_uapi_query_port_flags {
  MLX5_IB_UAPI_QUERY_PORT_VPORT = 1 << 0,
  MLX5_IB_UAPI_QUERY_PORT_VPORT_VHCA_ID = 1 << 1,
  MLX5_IB_UAPI_QUERY_PORT_VPORT_STEERING_ICM_RX = 1 << 2,
  MLX5_IB_UAPI_QUERY_PORT_VPORT_STEERING_ICM_TX = 1 << 3,
  MLX5_IB_UAPI_QUERY_PORT_VPORT_REG_C0 = 1 << 4,
  MLX5_IB_UAPI_QUERY_PORT_ESW_OWNER_VHCA_ID = 1 << 5,
};
struct mlx5_ib_uapi_reg {
  __u32 value;
  __u32 mask;
};
struct mlx5_ib_uapi_query_port {
  __aligned_u64 flags;
  __u16 vport;
  __u16 vport_vhca_id;
  __u16 esw_owner_vhca_id;
  __u16 rsvd0;
  __aligned_u64 vport_steering_icm_rx;
  __aligned_u64 vport_steering_icm_tx;
  struct mlx5_ib_uapi_reg reg_c0;
};
#endif
```