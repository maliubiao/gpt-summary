Response:
Let's break down the thought process for answering the request about the `fc_gs.h` header file.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`fc_gs.h`) and explain its functionality within the Android/Bionic context. The request has several specific sub-points to address.

**2. Initial Analysis of the Header File:**

* **File Information:** The comments clearly state it's auto-generated, related to the Linux kernel's SCSI FC (Fibre Channel) subsystem, and located within Bionic. This immediately tells us it's an interface to kernel functionality. The "uapi" in the path reinforces that it's part of the user-space API interacting with the kernel.
* **Header Guards:** `#ifndef _FC_GS_H_` and `#define _FC_GS_H_` are standard header guards, preventing multiple inclusions.
* **Includes:** `#include <linux/types.h>` indicates reliance on fundamental Linux data types.
* **`fc_ct_hdr` Structure:** This is the core data structure. It represents the common transport (CT) header for Fibre Channel Generic Services (GS). The member names provide clues about its content (revision, IDs, types, commands, etc.). The `__be16` suggests big-endian representation.
* **Enums:**  The various `enum` definitions (`fc_ct_rev`, `fc_ct_fs_type`, `fc_ct_cmd`, `fc_ct_reason`, `fc_ct_explan`) define symbolic constants for different fields within the `fc_ct_hdr`. These improve readability and maintainability.
* **Macro:** `#define FC_CT_HDR_LEN 16` defines the size of the header structure.

**3. Addressing the Specific Questions (Iterative Process):**

* **Functionality:** The primary function is defining the data structures and constants needed to interact with the Fibre Channel Generic Services protocol as implemented in the Linux kernel. It's a *definition*, not an implementation.

* **Relationship to Android:** Since Bionic is Android's C library, this header file provides a user-space interface for Android components (likely at a lower level, possibly in the HAL or kernel drivers) to interact with Fibre Channel devices if the hardware supports it. The example of storage access is a good concrete illustration.

* **Libc Function Details:**  This is a *header file*, not a libc implementation file. It *defines* data structures, not the *implementation* of libc functions. It's important to distinguish between declarations and definitions. Therefore, the answer focuses on the *purpose* of the types and how they would be used *if* there were functions using them. The concept of system calls like `ioctl` is relevant here as it's a common way for user-space to interact with kernel drivers.

* **Dynamic Linker:** This header file itself doesn't directly involve the dynamic linker. It's a compile-time artifact. However, *if* there were a shared library that used these definitions, then the dynamic linker would be involved in loading that library. The explanation and SO layout example illustrate this indirect relationship. The linking process explanation clarifies how symbols are resolved.

* **Logical Reasoning (Hypothetical Input/Output):**  Since this is a header file defining data structures, direct input/output in the traditional sense isn't applicable. The example of constructing an `fc_ct_hdr` with specific values serves as a way to demonstrate how these definitions would be used in practice. The output is the resulting byte sequence of the filled structure.

* **Common Usage Errors:**  Incorrectly setting the header fields, especially the command, reason, and explanation codes, could lead to communication failures with the FC device. Forgetting byte order (big-endian) is another potential issue.

* **Android Framework/NDK Path and Frida Hook:**  This is a crucial part. The path starts from the application using NDK, goes through the NDK bindings, potentially to the HAL, and finally interacts with the kernel driver, which uses these header definitions. The Frida example provides a practical way to intercept and inspect the `fc_ct_hdr` structure at runtime, illustrating how these definitions are used in actual interactions.

**4. Structuring the Answer:**

The answer is structured logically to address each part of the request systematically:

* **功能介绍:** Start with a high-level overview.
* **与 Android 的关系:** Provide specific examples.
* **libc 函数的实现:** Clarify that it's a header and focus on the *purpose* of the definitions, mentioning relevant syscalls.
* **动态链接器:** Explain the indirect connection and provide the SO layout and linking process.
* **逻辑推理:** Offer a concrete example of data structure usage.
* **常见错误:** Highlight potential pitfalls.
* **Android Framework/NDK 路径和 Frida Hook:**  Trace the execution flow and give a practical debugging example.

**5. Refinement and Language:**

Using clear and concise Chinese is essential. Explaining technical concepts in an accessible way, even for those who might not be deeply familiar with Fibre Channel, is important. The use of code blocks and formatting enhances readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe I should explain how the `fc_ct_hdr` structure is *used* in kernel code.
* **Correction:** The request is about the *header file* within Bionic. Focus on its role in defining the *interface* for user-space interaction, not the kernel implementation details.
* **Initial thought:**  Go into great detail about Fibre Channel protocols.
* **Correction:**  Keep the explanation focused on the header file and its role in Android. Avoid unnecessary deep dives into FC specifics unless directly relevant to illustrating a point.
* **Ensure consistent terminology:** Use accurate terms like "header file," "data structure," "symbol," "dynamic linker," etc.

By following this structured thought process, addressing each point systematically, and refining the explanations, the comprehensive answer provided can be generated.
这是一个定义了与光纤通道（Fibre Channel，简称FC）通用服务（Generic Services，简称GS）相关的头文件的源代码。它属于Android Bionic库的一部分，用于在用户空间和内核空间之间传递关于FC设备的信息。

**它的功能:**

该文件定义了以下内容，用于描述和操作FC通用服务协议：

1. **`struct fc_ct_hdr` 结构体:**  定义了 FC 通用传输命令（Common Transport command，简称CT command）的头部结构。这个结构体包含了命令的版本、ID、功能集类型和子类型、选项、命令代码、最大响应大小、原因码、解释码和厂商 ID 等字段。它是进行FC通用服务通信的基础数据结构。

2. **`FC_CT_HDR_LEN` 宏:** 定义了 `fc_ct_hdr` 结构体的长度，方便在程序中计算和分配内存。

3. **`enum fc_ct_rev` 枚举:** 定义了 CT 命令头的版本号，目前只有一个值 `FC_CT_REV = 1`。

4. **`enum fc_ct_fs_type` 枚举:** 定义了 FC 功能集（Feature Set）的类型，包括别名服务 (`FC_FST_ALIAS`)、管理服务 (`FC_FST_MGMT`)、时间服务 (`FC_FST_TIME`) 和目录服务 (`FC_FST_DIR`)。

5. **`enum fc_ct_cmd` 枚举:** 定义了 CT 命令代码，包括拒绝命令 (`FC_FS_RJT`) 和接受命令 (`FC_FS_ACC`)。

6. **`enum fc_ct_reason` 枚举:** 定义了拒绝命令的原因码，例如命令不支持 (`FC_FS_RJT_CMD`)、版本不匹配 (`FC_FS_RJT_VER`)、逻辑错误 (`FC_FS_RJT_LOG`)、IU大小错误 (`FC_FS_RJT_IUSIZ`)、忙 (`FC_FS_RJT_BSY`)、协议错误 (`FC_FS_RJT_PROTO`)、不可用 (`FC_FS_RJT_UNABL`) 和不支持 (`FC_FS_RJT_UNSUP`)。

7. **`enum fc_ct_explan` 枚举:** 定义了拒绝命令的解释码，提供了关于拒绝原因的更详细信息，例如端口ID (`FC_FS_EXP_PID`)、端口名称 (`FC_FS_EXP_PNAM`)、节点名称 (`FC_FS_EXP_NNAM`)、服务类别 (`FC_FS_EXP_COS`) 和特性不可用 (`FC_FS_EXP_FTNR`)。

**它与 Android 功能的关系及举例说明:**

这个头文件定义了与底层硬件交互的接口，通常不会被直接用于上层 Android 应用开发。它的主要用途在于：

* **硬件抽象层 (HAL):**  Android 的 HAL 负责将硬件相关的操作抽象出来，为上层提供统一的接口。如果 Android 设备支持 FC 存储或网络设备，那么相关的 HAL 模块可能会使用这些定义来与内核中的 FC 驱动进行通信。
* **内核驱动程序:** 内核中的 FC 设备驱动程序会使用这些定义来构建和解析 FC 通用服务命令。
* **系统服务:** 某些系统服务可能需要与 FC 设备进行交互，例如管理存储或网络连接的服务。

**举例说明:**

假设 Android 设备连接了一个 FC 存储阵列。当 Android 系统需要访问该存储阵列时，可能发生以下过程：

1. **上层请求:**  Android 的存储框架（例如 MediaStore 或 DownloadManager）发起一个存储操作请求。
2. **HAL 调用:**  存储框架将请求传递给负责 FC 存储的 HAL 模块。
3. **构造 FC 命令:**  HAL 模块根据请求构建一个 FC 通用服务命令。这可能涉及到填充 `fc_ct_hdr` 结构体的各个字段，例如设置命令代码为特定的操作（假设有一个操作对应于读取数据）。
4. **系统调用:** HAL 模块通过系统调用（例如 `ioctl`）将构造好的 FC 命令发送给内核中的 FC 设备驱动程序。
5. **内核处理:** 内核驱动程序解析接收到的 FC 命令头，并根据命令内容与 FC 存储阵列进行通信。
6. **数据传输:**  如果命令是读取数据，内核驱动程序将从存储阵列接收数据。
7. **返回结果:**  内核驱动程序将结果数据或错误信息返回给 HAL 模块。
8. **HAL 返回:** HAL 模块将结果传递回上层存储框架。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要明确的是，这个文件中并没有定义任何 libc 函数的实现。** 它只是一个头文件，用于定义数据结构和常量。这些定义会被其他的 C/C++ 代码使用，包括内核驱动程序、HAL 模块以及可能存在的用户空间工具。

`libc` (Bionic) 提供了诸如内存分配、线程管理、文件操作等核心功能。这个头文件定义的数据结构会被使用 `libc` 提供的函数进行操作，例如：

* **内存分配 (`malloc`, `calloc`, `free`):**  用于分配 `fc_ct_hdr` 结构体的内存空间。
* **数据拷贝 (`memcpy`, `memmove`):** 用于填充 `fc_ct_hdr` 结构体的各个字段。
* **字节序转换函数 (`htobe16`, `be16toh` 等):** 虽然在这个头文件中没有直接使用，但在实际操作中，由于 `ct_cmd` 和 `ct_mr_size` 字段是 `__be16` 类型（big-endian），可能需要使用字节序转换函数来确保数据在不同架构之间的正确传输。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及动态链接器。它定义的数据结构会被编译成目标代码，并最终链接到可执行文件或共享库 (`.so`) 中。

**SO 布局样本 (假设有一个名为 `libfc_hal.so` 的共享库使用了这些定义):**

```
libfc_hal.so:
    .text          # 代码段
        fc_hal_init:  # HAL 初始化函数
            ... 使用 fc_ct_hdr ...
        fc_hal_send_command: # 发送 FC 命令的函数
            ... 使用 fc_ct_hdr ...
    .rodata        # 只读数据段
        # 可能包含一些与 FC 相关的常量
    .data          # 可读写数据段
        # 可能包含一些全局变量
    .bss           # 未初始化数据段
    .symtab        # 符号表
        fc_hal_init  (GLOBAL, FUNC)
        fc_hal_send_command (GLOBAL, FUNC)
        # ... 其他符号 ...
    .strtab        # 字符串表
    .dynsym        # 动态符号表
        # ... 需要动态链接的符号 ...
    .dynstr        # 动态字符串表
    .plt           # 过程链接表 (Procedure Linkage Table)
    .got.plt       # 全局偏移表 (Global Offset Table)
```

**链接的处理过程:**

1. **编译:**  包含 `fc_gs.h` 的源文件被编译成目标文件 (`.o`)。编译器会记录下对 `fc_ct_hdr` 结构体和枚举常量的引用。
2. **静态链接 (对于静态库):** 如果 `libfc_hal.so` 是静态链接的，链接器会将所有需要的代码和数据从目标文件以及静态库中复制到最终的可执行文件中。`fc_ct_hdr` 的定义会被直接包含进去。
3. **动态链接 (对于共享库):** 如果 `libfc_hal.so` 是动态链接的：
    * **编译时:** 编译器会在目标文件中生成重定位信息，指示哪些地方使用了外部符号（例如 `fc_ct_hdr` 的定义，虽然它是一个结构体定义，但其布局信息是重要的）。
    * **链接时:** 链接器会将来自不同目标文件的代码和数据段合并，并生成动态链接所需的元数据，例如 `.dynsym` 和 `.rel.dyn` (重定位表)。
    * **运行时:** 当 Android 系统加载 `libfc_hal.so` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
        * **加载共享库:** 将 `libfc_hal.so` 的代码和数据段加载到内存中。
        * **符号解析:**  动态链接器会查找 `libfc_hal.so` 中对外部符号的引用，并将其地址解析到定义这些符号的库中（在这个例子中，`fc_ct_hdr` 的定义通常会在内核头文件中，但在用户空间编译时，编译器需要知道其布局）。
        * **重定位:**  动态链接器会根据重定位表中的信息，修改 `libfc_hal.so` 代码和数据段中对外部符号的引用，使其指向正确的内存地址。

**由于 `fc_gs.h` 是内核 UAPI 头文件，它的定义会被编译到用户空间的代码中。动态链接器主要负责链接函数和全局变量的符号。结构体定义本身并不作为单独的符号进行动态链接，而是其布局信息被编译器使用。**

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们有一个 HAL 模块的函数，用于发送一个查询 FC 设备信息的命令。

**假设输入:**

* 要查询的 FC 设备端口 ID: `0x123456` (存储在 `target_port_id` 变量中)

**代码片段:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fc_gs.h"
#include <arpa/inet.h> // for htons

int send_fc_info_query(unsigned int target_port_id) {
    struct fc_ct_hdr hdr;

    // 初始化头部
    hdr.ct_rev = FC_CT_REV;
    hdr.ct_fs_type = FC_FST_MGMT; // 假设查询信息是管理服务的一部分
    hdr.ct_fs_subtype = 0x01;     // 假设 0x01 代表查询信息子类型
    hdr.ct_options = 0;
    memset(hdr.ct_in_id, 0, sizeof(hdr.ct_in_id)); // 设置为 0
    hdr.ct_cmd = htons(0x0001); // 假设 0x0001 是查询信息的命令代码，需要转换为网络字节序
    hdr.ct_mr_size = htons(256); // 假设最大响应大小为 256 字节
    hdr._ct_resvd2 = 0;
    hdr.ct_reason = 0;
    hdr.ct_explan = 0;
    hdr.ct_vendor = 0;

    // 在实际场景中，这里会通过系统调用将 hdr 发送到内核驱动

    printf("发送的 FC 命令头:\n");
    printf("  ct_rev: 0x%x\n", hdr.ct_rev);
    printf("  ct_in_id: 0x%02x%02x%02x\n", hdr.ct_in_id[0], hdr.ct_in_id[1], hdr.ct_in_id[2]);
    printf("  ct_fs_type: 0x%x\n", hdr.ct_fs_type);
    printf("  ct_fs_subtype: 0x%x\n", hdr.ct_fs_subtype);
    printf("  ct_options: 0x%x\n", hdr.ct_options);
    printf("  ct_cmd: 0x%x\n", ntohs(hdr.ct_cmd)); // 转换回主机字节序打印
    printf("  ct_mr_size: %d\n", ntohs(hdr.ct_mr_size));
    printf("  ct_reason: 0x%x\n", hdr.ct_reason);
    printf("  ct_explan: 0x%x\n", hdr.ct_explan);
    printf("  ct_vendor: 0x%x\n", hdr.ct_vendor);

    return 0;
}

int main() {
    unsigned int port_id = 0x123456;
    send_fc_info_query(port_id);
    return 0;
}
```

**假设输出 (运行上述代码):**

```
发送的 FC 命令头:
  ct_rev: 0x1
  ct_in_id: 0x000000
  ct_fs_type: 0xfa
  ct_fs_subtype: 0x1
  ct_options: 0x0
  ct_cmd: 0x1
  ct_mr_size: 256
  ct_reason: 0x0
  ct_explan: 0x0
  ct_vendor: 0x0
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **字节序错误:**  `ct_cmd` 和 `ct_mr_size` 是 `__be16` 类型，表示 big-endian。如果在填充这些字段时没有进行字节序转换，在某些 little-endian 架构的 Android 设备上可能会导致内核驱动程序解析错误。

   ```c
   // 错误示例：没有进行字节序转换
   hdr.ct_cmd = 0x0001;
   hdr.ct_mr_size = 256;

   // 正确示例：使用 htons 进行字节序转换
   hdr.ct_cmd = htons(0x0001);
   hdr.ct_mr_size = htons(256);
   ```

2. **结构体字段赋值错误:**  错误地设置 `ct_fs_type`、`ct_cmd`、`ct_reason` 或 `ct_explan` 的值，导致发送了内核驱动程序无法识别或不支持的命令。

   ```c
   // 错误示例：使用了未定义的命令代码
   hdr.ct_cmd = htons(0xFFFF);
   ```

3. **缓冲区溢出:**  如果在构造 FC 命令的后续数据部分时，没有正确计算缓冲区大小，可能会导致缓冲区溢出。虽然 `fc_ct_hdr` 本身大小固定，但在实际的 FC 通信中，通常会在头部之后附加数据。

4. **忘记初始化:**  在使用 `fc_ct_hdr` 结构体之前，忘记初始化某些关键字段，导致发送的数据不完整或无效。

   ```c
   struct fc_ct_hdr hdr;
   // 错误示例：直接使用未初始化的结构体
   // ... 将 hdr 发送 ...

   // 正确示例：先初始化结构体
   memset(&hdr, 0, sizeof(hdr));
   hdr.ct_rev = FC_CT_REV;
   // ... 其他字段赋值 ...
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `fc_gs.h` 定义的是内核 UAPI，Android Framework 或 NDK 应用本身通常不会直接包含或使用这个头文件。交互通常发生在更低的层次，例如 HAL 或内核驱动中。

**大致路径:**

1. **Android Framework:**  上层应用通过 Android Framework 的 API 发起存储或网络相关的操作 (例如，读写文件，建立网络连接)。
2. **System Services:** Framework 将请求传递给相应的系统服务，例如 `StorageManagerService` 或 `ConnectivityService`.
3. **HAL (Hardware Abstraction Layer):** 系统服务调用相关的 HAL 模块的接口。例如，对于 FC 存储，可能会调用一个负责 FC 设备操作的 HAL 模块。
4. **HAL Implementation:**  HAL 模块的实现代码（通常是 C/C++）可能会包含 `fc_gs.h` 头文件，并使用其中定义的结构体和常量来构建与内核驱动程序通信的消息。
5. **Kernel Driver:** HAL 模块通过系统调用（例如 `ioctl`) 将构建好的消息发送给内核中的 FC 设备驱动程序。内核驱动程序会解析这些消息，并与底层的 FC 硬件进行交互。

**Frida Hook 示例:**

假设我们想 hook 一个名为 `libfc_hal.so` 的 HAL 库中的函数 `send_fc_command`，该函数负责发送 FC 命令，并检查发送的 `fc_ct_hdr` 结构体的内容。

**Frida 脚本 (`hook_fc.js`):**

```javascript
rpc.exports = {
  hookSendCommand: function() {
    const moduleName = "libfc_hal.so";
    const functionName = "send_fc_command";
    const moduleBase = Module.findBaseAddress(moduleName);

    if (moduleBase) {
      const sendCommandAddress = Module.getExportByName(moduleName, functionName);
      if (sendCommandAddress) {
        Interceptor.attach(sendCommandAddress, {
          onEnter: function(args) {
            // 假设 send_fc_command 的第一个参数是指向 fc_ct_hdr 的指针
            const ctHdrPtr = ptr(args[0]);

            // 读取 fc_ct_hdr 的字段
            const ctRev = ctHdrPtr.readU8();
            const ctInId = ctHdrPtr.add(1).readByteArray(3);
            const ctFsType = ctHdrPtr.add(4).readU8();
            const ctFsSubtype = ctHdrPtr.add(5).readU8();
            const ctOptions = ctHdrPtr.add(6).readU8();
            const ctCmd = ctHdrPtr.add(8).readU16(); // 注意字节序
            const ctMrSize = ctHdrPtr.add(10).readU16(); // 注意字节序
            const ctReason = ctHdrPtr.add(12).readU8();
            const ctExplan = ctHdrPtr.add(13).readU8();
            const ctVendor = ctHdrPtr.add(14).readU8();

            console.log("Hooked send_fc_command!");
            console.log("  ct_rev: 0x" + ctRev.toString(16));
            console.log("  ct_in_id: " + Array.from(ctInId).map(b => ("0" + b.toString(16)).slice(-2)).join(""));
            console.log("  ct_fs_type: 0x" + ctFsType.toString(16));
            console.log("  ct_fs_subtype: 0x" + ctFsSubtype.toString(16));
            console.log("  ct_options: 0x" + ctOptions.toString(16));
            console.log("  ct_cmd: 0x" + ctCmd.toString(16));
            console.log("  ct_mr_size: " + ctMrSize);
            console.log("  ct_reason: 0x" + ctReason.toString(16));
            console.log("  ct_explan: 0x" + ctExplan.toString(16));
            console.log("  ct_vendor: 0x" + ctVendor.toString(16));
          }
        });
        console.log("Hooked " + moduleName + "!" + functionName);
      } else {
        console.log("Function " + functionName + " not found in " + moduleName);
      }
    } else {
      console.log("Module " + moduleName + " not found");
    }
  }
};
```

**运行 Frida Hook:**

1. 将 Frida 脚本 `hook_fc.js` 推送到 Android 设备。
2. 找到目标进程的进程 ID (PID)。
3. 使用 Frida 连接到目标进程并加载脚本：

   ```bash
   frida -U -f <目标应用包名> -l hook_fc.js --no-pause
   # 或者，如果进程已经在运行
   frida -U <目标进程PID> -l hook_fc.js
   ```

4. 在 Frida Console 中调用 `hookSendCommand` 函数：

   ```javascript
   rpc.exports.hookSendCommand();
   ```

当目标应用执行到 `libfc_hal.so` 中的 `send_fc_command` 函数时，Frida 脚本会拦截执行，并打印出 `fc_ct_hdr` 结构体的各个字段的值，从而帮助调试和理解 FC 通信过程。

**请注意:**

* 上述 Frida 示例是基于假设的 HAL 库名和函数名，实际情况可能需要根据具体的 Android 设备和 HAL 实现进行调整。
* 你需要 root 权限才能在 Android 设备上使用 Frida hook 系统进程或 HAL 库。
* 理解 HAL 模块的参数传递约定非常重要，才能正确地从 `args` 中读取 `fc_ct_hdr` 结构体的指针。

通过 Frida 这样的动态调试工具，我们可以深入了解 Android 系统底层与硬件的交互过程，包括对内核 UAPI 头文件中定义的数据结构的使用情况。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/scsi/fc/fc_gs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _FC_GS_H_
#define _FC_GS_H_
#include <linux/types.h>
struct fc_ct_hdr {
  __u8 ct_rev;
  __u8 ct_in_id[3];
  __u8 ct_fs_type;
  __u8 ct_fs_subtype;
  __u8 ct_options;
  __u8 _ct_resvd1;
  __be16 ct_cmd;
  __be16 ct_mr_size;
  __u8 _ct_resvd2;
  __u8 ct_reason;
  __u8 ct_explan;
  __u8 ct_vendor;
};
#define FC_CT_HDR_LEN 16
enum fc_ct_rev {
  FC_CT_REV = 1
};
enum fc_ct_fs_type {
  FC_FST_ALIAS = 0xf8,
  FC_FST_MGMT = 0xfa,
  FC_FST_TIME = 0xfb,
  FC_FST_DIR = 0xfc,
};
enum fc_ct_cmd {
  FC_FS_RJT = 0x8001,
  FC_FS_ACC = 0x8002,
};
enum fc_ct_reason {
  FC_FS_RJT_CMD = 0x01,
  FC_FS_RJT_VER = 0x02,
  FC_FS_RJT_LOG = 0x03,
  FC_FS_RJT_IUSIZ = 0x04,
  FC_FS_RJT_BSY = 0x05,
  FC_FS_RJT_PROTO = 0x07,
  FC_FS_RJT_UNABL = 0x09,
  FC_FS_RJT_UNSUP = 0x0b,
};
enum fc_ct_explan {
  FC_FS_EXP_NONE = 0x00,
  FC_FS_EXP_PID = 0x01,
  FC_FS_EXP_PNAM = 0x02,
  FC_FS_EXP_NNAM = 0x03,
  FC_FS_EXP_COS = 0x04,
  FC_FS_EXP_FTNR = 0x07,
};
#endif

"""

```