Response:
My thought process to answer the request goes through these stages:

1. **Understanding the Core Request:** The user wants to understand the functionality of a specific C header file (`fc_els.h`) within the Android Bionic library. They also want to know its relation to Android, how its functions are implemented (even though it's a header!), how the dynamic linker is involved, common errors, and how to trace its usage from Android frameworks.

2. **Initial File Analysis:** I first read through the header file carefully. I identify the key elements:
    * **Header Guards:** `#ifndef _FC_ELS_H_`, `#define _FC_ELS_H_`, `#endif` - These are standard C header file practices to prevent multiple inclusions.
    * **Includes:** `#include <linux/types.h>` and `#include <asm/byteorder.h>` -  These indicate that the file deals with low-level data types and byte ordering, suggesting it's related to hardware interaction, specifically SCSI.
    * **Enums:**  A large number of `enum fc_els_cmd` values like `ELS_LS_RJT`, `ELS_PLOGI`, etc. and other enums like `fc_els_rjt_reason`. This strongly suggests this header defines constants and types related to a specific protocol, likely Fiber Channel (FC) Link Services (ELS).
    * **Structures:** Several `struct fc_els_*` definitions, containing `__u8`, `__be16`, `__be32`, `__be64` members. These likely represent the data structures used in the Fiber Channel ELS protocol messages. The `__be` prefix suggests big-endian byte order, common in networking protocols.
    * **Macros:** `#define` directives like `FC_ELS_CMDS_INIT` and others. These are used to define constants, initialize arrays, and sometimes perform simple calculations.

3. **Identifying the Main Purpose:** Based on the enums and structures, I conclude that this header file defines the data structures and command codes for the Fiber Channel ELS protocol. This protocol is used for managing the communication and state of devices in a Fiber Channel network.

4. **Addressing Specific Questions:**  Now, I go through each part of the user's request systematically:

    * **功能 (Functionality):** I summarize the purpose: defining data structures and commands for the Fiber Channel ELS protocol, used for low-level communication in storage networks.

    * **与 Android 的关系 (Relationship with Android):** This is crucial. Since it's in Bionic and specifically under `scsi/fc/`, it implies Android *can* interact with Fiber Channel devices. However, it's not a core Android feature used by most apps. The most likely scenario is for specialized hardware or server-side components that Android devices might connect to in enterprise or data center environments. I emphasize it's *not* typical for regular Android app development.

    * **libc 函数的实现 (Implementation of libc functions):**  This is a trick question! The header file itself *doesn't contain function implementations*. It *defines* data structures and constants that *other* C code (likely in kernel drivers or related libraries) would use. I clarify this distinction, explaining that `libc` provides fundamental functions, but this header defines data structures used *with* those functions.

    * **dynamic linker 的功能 (Dynamic Linker Functionality):**  Again, this header itself doesn't directly involve the dynamic linker. Header files are used at compile time. However, I explain the *potential* connection. If code using these structures is in a shared library (`.so`), the dynamic linker would be involved in loading that library. I provide a simplified example of a hypothetical `.so` containing functions using these structures and explain the linking process. I also give an example of how a program might link against this hypothetical library.

    * **逻辑推理 (Logical Reasoning):** I choose a simple scenario – sending a `PLOGI` (Port Login) request. I create a hypothetical input (values for the `fc_els_flogi` structure) and describe the expected output (an `ELS_LS_ACC` or `ELS_LS_RJT`). This illustrates how the defined structures are used in practice.

    * **用户或编程常见的使用错误 (Common User/Programming Errors):** I focus on common C-related errors when working with such structures: incorrect byte order, incorrect structure sizes, and forgetting to initialize fields.

    * **Android framework or ndk 如何一步步的到达这里 (How Android framework/NDK reaches here):** This requires a step-by-step breakdown. I explain that typical Android apps don't directly use this. I then illustrate the path from a hypothetical NDK module that interacts with a Fiber Channel device, going through system calls and potentially kernel drivers, where these structures would be used.

    * **frida hook 示例调试这些步骤 (Frida hook example):** I provide Frida code to hook the `send` or `write` system calls, as these are the most likely points where the raw data structures defined in the header would be transmitted. I explain *what* the hook does (printing the data) and *why* it's useful for debugging.

5. **Language and Formatting:** Finally, I ensure the entire response is in Chinese and well-formatted for readability. I use code blocks for code snippets and clear headings for each section.

By following these steps, I aim to provide a comprehensive and accurate answer that addresses all aspects of the user's request, even clarifying potential misunderstandings about the role of header files and the dynamic linker.
## 针对 `bionic/libc/kernel/uapi/scsi/fc/fc_els.handroid` 源代码文件的功能分析

这个头文件 `fc_els.h` 定义了 **光纤通道（Fibre Channel, FC）链路服务（Link Services, ELS）协议**相关的常量、枚举和数据结构。它是 Linux 内核 UAPI（用户空间应用程序接口）的一部分，被 Bionic C 库收录，以便用户空间的程序能够与内核中的光纤通道驱动进行交互。

**功能列举：**

1. **定义 ELS 命令码 (ELS Command Codes):**  `enum fc_els_cmd` 定义了各种光纤通道链路服务命令，例如：
    * `ELS_LS_RJT`: 链路服务拒绝 (Link Service Reject)
    * `ELS_LS_ACC`: 链路服务接受 (Link Service Accept)
    * `ELS_PLOGI`: 端口登录 (Port Login)
    * `ELS_FLOGI`: 光纤通道登录 (Fabric Login)
    * `ELS_LOGO`: 注销 (Logout)
    * ... 等等，涵盖了光纤通道设备之间建立连接、交换信息、管理状态等各种操作。

2. **定义 ELS 拒绝原因码 (ELS Reject Reason Codes):** `enum fc_els_rjt_reason` 和 `enum fc_els_rjt_explan` 定义了当链路服务请求被拒绝时，用于说明拒绝原因的详细代码。

3. **定义类型长度值 (TLV) 标签 (Type-Length-Value Tags):** `enum fc_ls_tlv_dtag` 定义了用于在 ELS 消息中携带可选信息的 TLV 结构的标签。TLV 结构允许在消息中包含可变长度的数据。

4. **定义各种 ELS 数据结构 (ELS Data Structures):**  `struct fc_els_*` 定义了与各种 ELS 命令和响应相关的 C 结构体。这些结构体描述了消息的格式和包含的字段，例如：
    * `struct fc_els_ls_acc`: 链路服务接受消息的结构
    * `struct fc_els_ls_rjt`: 链路服务拒绝消息的结构
    * `struct fc_els_flogi`: 光纤通道登录请求的结构
    * `struct fc_els_csp`:  通用服务参数 (Common Service Parameters)
    * `struct fc_els_cssp`:  类特定服务参数 (Class Specific Service Parameters)
    * ... 等等，涵盖了各种 ELS 命令和响应的格式。

5. **定义辅助宏 (Helper Macros):** 例如 `FC_TLV_DESC_HDR_SZ`, `FC_TLV_DESC_LENGTH_FROM_SZ`, `FC_TLV_DESC_SZ_FROM_LENGTH` 等，用于方便地处理 TLV 结构的大小和长度。

**与 Android 功能的关系及举例说明：**

此头文件主要用于 Android 系统中需要与光纤通道存储设备或网络进行交互的底层驱动程序或服务。**普通 Android 应用程序（包括通过 NDK 开发的应用程序）通常不会直接使用这些定义。**

**举例说明：**

假设 Android 设备连接到一个光纤通道存储阵列，例如一个高性能的 SAN (存储区域网络)。Android 系统可能包含一个内核驱动程序（或其他系统服务）负责与这个存储阵列通信。

1. 当 Android 设备需要访问存储阵列上的 LUN (逻辑单元号) 时，底层的光纤通道驱动程序可能需要发送一个 `ELS_PLOGI` 命令来登录到光纤通道网络中的交换机或存储控制器。
2. 驱动程序会使用 `struct fc_els_flogi` 结构体来构造登录请求消息，填充必要的字段，例如设备的 WWPN (全球端口名称) 和 WWNN (全球节点名称)。
3. 如果登录被接受，存储控制器会发送一个包含 `ELS_LS_ACC` 命令的响应，驱动程序会解析 `struct fc_els_ls_acc` 结构体来确认。
4. 如果登录被拒绝，存储控制器会发送一个包含 `ELS_LS_RJT` 命令的响应，驱动程序会解析 `struct fc_els_ls_rjt` 结构体，并根据 `er_reason` 和 `er_explan` 字段来判断拒绝的原因。

**详细解释每一个 libc 函数的功能是如何实现的：**

**这个头文件本身 *不包含* libc 函数的实现。** 它只是定义了常量、枚举和数据结构。这些定义会被其他的 C 代码文件（例如内核驱动程序、Bionic 库的其他部分）包含和使用。

libc (Bionic) 提供了各种各样的标准 C 库函数，例如内存管理 (malloc, free)、字符串操作 (strcpy, strlen)、输入/输出 (printf, read, write) 等。**这里的 `fc_els.h` 文件定义的数据结构会被传递给或接收自某些 libc 函数（例如 `write` 和 `read` 系统调用），以便与内核驱动程序进行数据交换。**

例如，当驱动程序准备好发送一个 ELS 命令时，它可能会使用 `write` 系统调用，将填充好的 `struct fc_els_flogi` 结构体的数据写入到与光纤通道设备关联的文件描述符中。`write` 函数的实现位于 Bionic 的源代码中，它负责将用户空间的数据拷贝到内核空间，并通知内核驱动程序进行处理。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件主要用于内核空间和用户空间驱动程序之间的接口。**通常情况下，它不会直接涉及到用户空间的共享库 (.so) 的动态链接。**

但是，如果用户空间存在一个库（例如一个与光纤通道相关的用户空间工具库），它需要使用这里定义的结构体与内核驱动进行交互，那么这个库可能会包含这个头文件。

**so 布局样本（假设存在一个名为 `libfchelper.so` 的库）：**

```
libfchelper.so:
    .text:  # 包含函数代码，例如发送和接收 ELS 命令的辅助函数
        send_plogi:
            # ... 使用 struct fc_els_flogi 构建 PLOGI 命令的代码 ...
            # ... 调用 write 系统调用发送数据 ...
        receive_response:
            # ... 调用 read 系统调用接收数据 ...
            # ... 解析接收到的数据，可能涉及到 struct fc_els_ls_acc 或 struct fc_els_ls_rjt ...
    .rodata: # 包含只读数据，例如一些固定的 ELS 消息模板
    .data:   # 包含全局变量
    .bss:    # 包含未初始化的全局变量

```

**链接的处理过程：**

1. **编译时：** 当一个应用程序或库需要使用 `libfchelper.so` 中的函数时，编译器会读取 `fc_els.h` 头文件，了解其中定义的结构体和常量。
2. **链接时：** 链接器会将应用程序或库的目标文件与 `libfchelper.so` 库链接起来。这包括解析符号引用，确保应用程序可以找到 `libfchelper.so` 中定义的函数。
3. **运行时：** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `libfchelper.so` 库到进程的内存空间。
4. **符号解析：** 动态链接器会解析应用程序中对 `libfchelper.so` 中函数的调用，并将这些调用地址指向库中实际的函数地址。

**假设输入与输出（逻辑推理 - 假设一个用户空间程序使用 `libfchelper.so`）：**

**假设输入：**

* 用户空间程序调用 `libfchelper.so` 中的 `send_plogi` 函数，并传递了设备的 WWPN 和 WWNN。

**预期输出：**

* `send_plogi` 函数会构建一个 `struct fc_els_flogi` 结构体，并通过 `write` 系统调用发送到内核驱动程序。
* 内核驱动程序会将该 PLOGI 命令发送到光纤通道网络。
* 光纤通道网络中的目标设备（例如存储控制器）会响应一个包含 `ELS_LS_ACC` 或 `ELS_LS_RJT` 命令的消息。
* 内核驱动程序会将响应传递回用户空间。
* `libfchelper.so` 中的 `receive_response` 函数会接收并解析响应。
* 如果响应是 `ELS_LS_ACC`，则 `receive_response` 函数可能返回成功状态。
* 如果响应是 `ELS_LS_RJT`，则 `receive_response` 函数可能返回错误状态，并提供拒绝原因码。

**用户或编程常见的使用错误，举例说明：**

1. **字节序错误：** 光纤通道协议通常使用大端字节序（Big-Endian）。如果用户空间程序或驱动程序在填充或解析结构体时没有考虑字节序，可能会导致数据解释错误。例如，将一个多字节的整数值直接赋值，而不是使用 `htobe16`, `htobe32` 等函数进行转换。

   ```c
   struct fc_els_flogi flogi;
   flogi.fl_csp.sp_bb_cred = 0x0010; // 错误：假设系统是小端字节序
   flogi.fl_csp.sp_bb_cred = htobe16(0x0010); // 正确：使用 htobe16 转换为大端字节序
   ```

2. **结构体大小错误：** 在进行数据发送或接收时，需要确保发送或接收的字节数与结构体的大小一致。如果大小不匹配，可能会导致数据截断或读取越界。

   ```c
   struct fc_els_flogi flogi;
   // ... 填充 flogi ...
   write(fd, &flogi, sizeof(flogi) - 1); // 错误：发送的字节数小于结构体大小
   write(fd, &flogi, sizeof(flogi));     // 正确
   ```

3. **未初始化结构体字段：**  在使用结构体之前，必须确保所有相关的字段都已正确初始化。未初始化的字段可能包含随机值，导致发送错误的消息。

   ```c
   struct fc_els_flogi flogi;
   flogi.fl_cmd = ELS_FLOGI;
   // 忘记初始化其他字段
   write(fd, &flogi, sizeof(flogi)); // 可能发送不完整的 FLOGI 命令
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

**典型的 Android Framework 或 NDK 应用程序通常不会直接到达这里。**  `fc_els.h` 定义的是非常底层的光纤通道协议相关的结构体，主要用于内核驱动程序或非常底层的系统服务。

但是，**假设** 存在一个使用 NDK 开发的应用程序，它需要与连接到 Android 设备的外部光纤通道设备进行通信（这是一种非常特殊的情况），那么可能的路径如下：

1. **NDK 应用程序：**  使用 C/C++ 代码，可能包含自定义的逻辑来处理光纤通道通信。
2. **调用系统调用：**  NDK 应用程序需要通过系统调用与内核驱动程序进行交互。最相关的系统调用可能是 `open`, `close`, `read`, `write`, `ioctl` 等。
3. **内核驱动程序：**  Android 设备上的光纤通道 HBA (主机总线适配器) 会有对应的内核驱动程序。NDK 应用程序的系统调用最终会到达这个驱动程序。
4. **驱动程序使用 `fc_els.h`：**  光纤通道驱动程序会包含 `fc_els.h` 头文件，并使用其中定义的结构体来构造和解析 ELS 协议消息。
5. **硬件交互：**  驱动程序会通过 HBA 硬件与光纤通道网络进行实际的通信。

**Frida Hook 示例调试步骤：**

可以使用 Frida Hook 来监控 NDK 应用程序与内核驱动程序之间的交互，特别是涉及 `write` 系统调用的情况。

**Frida Hook 代码 (JavaScript):**

```javascript
// 假设我们的 NDK 应用程序打开了一个与光纤通道设备关联的文件描述符
// 我们需要找到这个文件描述符

// 监控 write 系统调用
Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter: function(args) {
    const fd = args[0].toInt32();
    const buf = args[1];
    const count = args[2].toInt32();

    // 这里需要根据实际情况判断 fd 是否是与光纤通道设备相关的
    // 可以通过进程中打开的文件描述符列表进行判断，或者根据一些特征值

    // 假设我们已经确定了这个 fd 是我们关注的
    console.log("write() called");
    console.log("  File Descriptor:", fd);
    console.log("  Count:", count);

    // 读取发送的数据并打印 (假设发送的是 fc_els_flogi 结构体)
    if (count >= 24) { // sizeof(struct fc_els_flogi)
      const cmd = buf.readU8();
      if (cmd === 0x04) { // ELS_FLOGI 的值
        console.log("  疑似 FLOGI 命令");
        const flogi = buf.readByteArray(count);
        console.log("  Data:", hexdump(flogi, { ansi: true }));
      }
    }
  },
  onLeave: function(retval) {
    console.log("write() returned:", retval);
  }
});
```

**调试步骤：**

1. **运行 Frida Server：** 在 Android 设备上运行 Frida Server。
2. **运行 NDK 应用程序：** 启动需要调试的 NDK 应用程序。
3. **执行 Frida Hook 脚本：** 使用 Frida 客户端工具 (例如 Python) 运行上述 JavaScript Hook 脚本，Attach 到 NDK 应用程序的进程。
4. **触发光纤通道通信：** 在 NDK 应用程序中触发执行与光纤通道设备通信的代码。
5. **查看 Frida 输出：** Frida Hook 脚本会在 `write` 系统调用被调用时打印相关信息，包括文件描述符、发送的字节数以及数据内容（如果疑似是 FLOGI 命令）。通过分析这些输出，可以了解 NDK 应用程序是如何构造 ELS 命令并发送到内核驱动程序的。

**总结：**

`bionic/libc/kernel/uapi/scsi/fc/fc_els.handroid` 是一个定义光纤通道链路服务协议相关常量、枚举和数据结构的头文件，主要用于 Android 系统中与光纤通道设备进行交互的底层驱动程序或服务。普通 Android 应用程序通常不会直接使用它。可以通过 Frida Hook 监控系统调用来调试涉及这些数据结构的操作。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/scsi/fc/fc_els.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _FC_ELS_H_
#define _FC_ELS_H_
#include <linux/types.h>
#include <asm/byteorder.h>
enum fc_els_cmd {
  ELS_LS_RJT = 0x01,
  ELS_LS_ACC = 0x02,
  ELS_PLOGI = 0x03,
  ELS_FLOGI = 0x04,
  ELS_LOGO = 0x05,
  ELS_ABTX = 0x06,
  ELS_RCS = 0x07,
  ELS_RES = 0x08,
  ELS_RSS = 0x09,
  ELS_RSI = 0x0a,
  ELS_ESTS = 0x0b,
  ELS_ESTC = 0x0c,
  ELS_ADVC = 0x0d,
  ELS_RTV = 0x0e,
  ELS_RLS = 0x0f,
  ELS_ECHO = 0x10,
  ELS_TEST = 0x11,
  ELS_RRQ = 0x12,
  ELS_REC = 0x13,
  ELS_SRR = 0x14,
  ELS_FPIN = 0x16,
  ELS_EDC = 0x17,
  ELS_RDP = 0x18,
  ELS_RDF = 0x19,
  ELS_PRLI = 0x20,
  ELS_PRLO = 0x21,
  ELS_SCN = 0x22,
  ELS_TPLS = 0x23,
  ELS_TPRLO = 0x24,
  ELS_LCLM = 0x25,
  ELS_GAID = 0x30,
  ELS_FACT = 0x31,
  ELS_FDACDT = 0x32,
  ELS_NACT = 0x33,
  ELS_NDACT = 0x34,
  ELS_QOSR = 0x40,
  ELS_RVCS = 0x41,
  ELS_PDISC = 0x50,
  ELS_FDISC = 0x51,
  ELS_ADISC = 0x52,
  ELS_RNC = 0x53,
  ELS_FARP_REQ = 0x54,
  ELS_FARP_REPL = 0x55,
  ELS_RPS = 0x56,
  ELS_RPL = 0x57,
  ELS_RPBC = 0x58,
  ELS_FAN = 0x60,
  ELS_RSCN = 0x61,
  ELS_SCR = 0x62,
  ELS_RNFT = 0x63,
  ELS_CSR = 0x68,
  ELS_CSU = 0x69,
  ELS_LINIT = 0x70,
  ELS_LSTS = 0x72,
  ELS_RNID = 0x78,
  ELS_RLIR = 0x79,
  ELS_LIRR = 0x7a,
  ELS_SRL = 0x7b,
  ELS_SBRP = 0x7c,
  ELS_RPSC = 0x7d,
  ELS_QSA = 0x7e,
  ELS_EVFP = 0x7f,
  ELS_LKA = 0x80,
  ELS_AUTH_ELS = 0x90,
};
#define FC_ELS_CMDS_INIT {[ELS_LS_RJT] = "LS_RJT",[ELS_LS_ACC] = "LS_ACC",[ELS_PLOGI] = "PLOGI",[ELS_FLOGI] = "FLOGI",[ELS_LOGO] = "LOGO",[ELS_ABTX] = "ABTX",[ELS_RCS] = "RCS",[ELS_RES] = "RES",[ELS_RSS] = "RSS",[ELS_RSI] = "RSI",[ELS_ESTS] = "ESTS",[ELS_ESTC] = "ESTC",[ELS_ADVC] = "ADVC",[ELS_RTV] = "RTV",[ELS_RLS] = "RLS",[ELS_ECHO] = "ECHO",[ELS_TEST] = "TEST",[ELS_RRQ] = "RRQ",[ELS_REC] = "REC",[ELS_SRR] = "SRR",[ELS_FPIN] = "FPIN",[ELS_EDC] = "EDC",[ELS_RDP] = "RDP",[ELS_RDF] = "RDF",[ELS_PRLI] = "PRLI",[ELS_PRLO] = "PRLO",[ELS_SCN] = "SCN",[ELS_TPLS] = "TPLS",[ELS_TPRLO] = "TPRLO",[ELS_LCLM] = "LCLM",[ELS_GAID] = "GAID",[ELS_FACT] = "FACT",[ELS_FDACDT] = "FDACDT",[ELS_NACT] = "NACT",[ELS_NDACT] = "NDACT",[ELS_QOSR] = "QOSR",[ELS_RVCS] = "RVCS",[ELS_PDISC] = "PDISC",[ELS_FDISC] = "FDISC",[ELS_ADISC] = "ADISC",[ELS_RNC] = "RNC",[ELS_FARP_REQ] = "FARP_REQ",[ELS_FARP_REPL] = "FARP_REPL",[ELS_RPS] = "RPS",[ELS_RPL] = "RPL",[ELS_RPBC] = "RPBC",[ELS_FAN] = "FAN",[ELS_RSCN] = "RSCN",[ELS_SCR] = "SCR",[ELS_RNFT] = "RNFT",[ELS_CSR] = "CSR",[ELS_CSU] = "CSU",[ELS_LINIT] = "LINIT",[ELS_LSTS] = "LSTS",[ELS_RNID] = "RNID",[ELS_RLIR] = "RLIR",[ELS_LIRR] = "LIRR",[ELS_SRL] = "SRL",[ELS_SBRP] = "SBRP",[ELS_RPSC] = "RPSC",[ELS_QSA] = "QSA",[ELS_EVFP] = "EVFP",[ELS_LKA] = "LKA",[ELS_AUTH_ELS] = "AUTH_ELS", \
}
struct fc_els_ls_acc {
  __u8 la_cmd;
  __u8 la_resv[3];
};
struct fc_els_ls_rjt {
  __u8 er_cmd;
  __u8 er_resv[4];
  __u8 er_reason;
  __u8 er_explan;
  __u8 er_vendor;
};
enum fc_els_rjt_reason {
  ELS_RJT_NONE = 0,
  ELS_RJT_INVAL = 0x01,
  ELS_RJT_LOGIC = 0x03,
  ELS_RJT_BUSY = 0x05,
  ELS_RJT_PROT = 0x07,
  ELS_RJT_UNAB = 0x09,
  ELS_RJT_UNSUP = 0x0b,
  ELS_RJT_INPROG = 0x0e,
  ELS_RJT_FIP = 0x20,
  ELS_RJT_VENDOR = 0xff,
};
enum fc_els_rjt_explan {
  ELS_EXPL_NONE = 0x00,
  ELS_EXPL_SPP_OPT_ERR = 0x01,
  ELS_EXPL_SPP_ICTL_ERR = 0x03,
  ELS_EXPL_AH = 0x11,
  ELS_EXPL_AH_REQ = 0x13,
  ELS_EXPL_SID = 0x15,
  ELS_EXPL_OXID_RXID = 0x17,
  ELS_EXPL_INPROG = 0x19,
  ELS_EXPL_PLOGI_REQD = 0x1e,
  ELS_EXPL_INSUF_RES = 0x29,
  ELS_EXPL_UNAB_DATA = 0x2a,
  ELS_EXPL_UNSUPR = 0x2c,
  ELS_EXPL_INV_LEN = 0x2d,
  ELS_EXPL_NOT_NEIGHBOR = 0x62,
};
enum fc_ls_tlv_dtag {
  ELS_DTAG_LS_REQ_INFO = 0x00000001,
  ELS_DTAG_LNK_FAULT_CAP = 0x0001000D,
  ELS_DTAG_CG_SIGNAL_CAP = 0x0001000F,
  ELS_DTAG_LNK_INTEGRITY = 0x00020001,
  ELS_DTAG_DELIVERY = 0x00020002,
  ELS_DTAG_PEER_CONGEST = 0x00020003,
  ELS_DTAG_CONGESTION = 0x00020004,
  ELS_DTAG_FPIN_REGISTER = 0x00030001,
};
#define FC_LS_TLV_DTAG_INIT { { ELS_DTAG_LS_REQ_INFO, "Link Service Request Information" }, { ELS_DTAG_LNK_FAULT_CAP, "Link Fault Capability" }, { ELS_DTAG_CG_SIGNAL_CAP, "Congestion Signaling Capability" }, { ELS_DTAG_LNK_INTEGRITY, "Link Integrity Notification" }, { ELS_DTAG_DELIVERY, "Delivery Notification Present" }, { ELS_DTAG_PEER_CONGEST, "Peer Congestion Notification" }, { ELS_DTAG_CONGESTION, "Congestion Notification" }, { ELS_DTAG_FPIN_REGISTER, "FPIN Registration" }, \
}
struct fc_tlv_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __u8 desc_value[];
};
#define FC_TLV_DESC_HDR_SZ sizeof(struct fc_tlv_desc)
#define FC_TLV_DESC_LENGTH_FROM_SZ(desc) (sizeof(desc) - FC_TLV_DESC_HDR_SZ)
#define FC_TLV_DESC_SZ_FROM_LENGTH(tlv) (__be32_to_cpu((tlv)->desc_len) + FC_TLV_DESC_HDR_SZ)
struct fc_els_lsri_desc {
  __be32 desc_tag;
  __be32 desc_len;
  struct {
    __u8 cmd;
    __u8 bytes[3];
  } rqst_w0;
};
struct fc_els_csp {
  __u8 sp_hi_ver;
  __u8 sp_lo_ver;
  __be16 sp_bb_cred;
  __be16 sp_features;
  __be16 sp_bb_data;
  union {
    struct {
      __be16 _sp_tot_seq;
      __be16 _sp_rel_off;
    } sp_plogi;
    struct {
      __be32 _sp_r_a_tov;
    } sp_flogi_acc;
  } sp_u;
  __be32 sp_e_d_tov;
};
#define sp_tot_seq sp_u.sp_plogi._sp_tot_seq
#define sp_rel_off sp_u.sp_plogi._sp_rel_off
#define sp_r_a_tov sp_u.sp_flogi_acc._sp_r_a_tov
#define FC_SP_BB_DATA_MASK 0xfff
#define FC_SP_MIN_MAX_PAYLOAD FC_MIN_MAX_PAYLOAD
#define FC_SP_MAX_MAX_PAYLOAD FC_MAX_PAYLOAD
#define FC_SP_FT_NPIV 0x8000
#define FC_SP_FT_CIRO 0x8000
#define FC_SP_FT_CLAD 0x8000
#define FC_SP_FT_RAND 0x4000
#define FC_SP_FT_VAL 0x2000
#define FC_SP_FT_NPIV_ACC 0x2000
#define FC_SP_FT_FPORT 0x1000
#define FC_SP_FT_ABB 0x0800
#define FC_SP_FT_EDTR 0x0400
#define FC_SP_FT_MCAST 0x0200
#define FC_SP_FT_BCAST 0x0100
#define FC_SP_FT_HUNT 0x0080
#define FC_SP_FT_SIMP 0x0040
#define FC_SP_FT_SEC 0x0020
#define FC_SP_FT_CSYN 0x0010
#define FC_SP_FT_RTTOV 0x0008
#define FC_SP_FT_HALF 0x0004
#define FC_SP_FT_SEQC 0x0002
#define FC_SP_FT_PAYL 0x0001
struct fc_els_cssp {
  __be16 cp_class;
  __be16 cp_init;
  __be16 cp_recip;
  __be16 cp_rdfs;
  __be16 cp_con_seq;
  __be16 cp_ee_cred;
  __u8 cp_resv1;
  __u8 cp_open_seq;
  __u8 _cp_resv2[2];
};
#define FC_CPC_VALID 0x8000
#define FC_CPC_IMIX 0x4000
#define FC_CPC_SEQ 0x0800
#define FC_CPC_CAMP 0x0200
#define FC_CPC_PRI 0x0080
#define FC_CPI_CSYN 0x0010
#define FC_CPR_CSYN 0x0008
struct fc_els_flogi {
  __u8 fl_cmd;
  __u8 _fl_resvd[3];
  struct fc_els_csp fl_csp;
  __be64 fl_wwpn;
  __be64 fl_wwnn;
  struct fc_els_cssp fl_cssp[4];
  __u8 fl_vend[16];
} __attribute__((__packed__));
struct fc_els_spp {
  __u8 spp_type;
  __u8 spp_type_ext;
  __u8 spp_flags;
  __u8 _spp_resvd;
  __be32 spp_orig_pa;
  __be32 spp_resp_pa;
  __be32 spp_params;
};
#define FC_SPP_OPA_VAL 0x80
#define FC_SPP_RPA_VAL 0x40
#define FC_SPP_EST_IMG_PAIR 0x20
#define FC_SPP_RESP_MASK 0x0f
enum fc_els_spp_resp {
  FC_SPP_RESP_ACK = 1,
  FC_SPP_RESP_RES = 2,
  FC_SPP_RESP_INIT = 3,
  FC_SPP_RESP_NO_PA = 4,
  FC_SPP_RESP_CONF = 5,
  FC_SPP_RESP_COND = 6,
  FC_SPP_RESP_MULT = 7,
  FC_SPP_RESP_INVL = 8,
};
struct fc_els_rrq {
  __u8 rrq_cmd;
  __u8 rrq_zero[3];
  __u8 rrq_resvd;
  __u8 rrq_s_id[3];
  __be16 rrq_ox_id;
  __be16 rrq_rx_id;
};
struct fc_els_rec {
  __u8 rec_cmd;
  __u8 rec_zero[3];
  __u8 rec_resvd;
  __u8 rec_s_id[3];
  __be16 rec_ox_id;
  __be16 rec_rx_id;
};
struct fc_els_rec_acc {
  __u8 reca_cmd;
  __u8 reca_zero[3];
  __be16 reca_ox_id;
  __be16 reca_rx_id;
  __u8 reca_resvd1;
  __u8 reca_ofid[3];
  __u8 reca_resvd2;
  __u8 reca_rfid[3];
  __be32 reca_fc4value;
  __be32 reca_e_stat;
};
struct fc_els_prli {
  __u8 prli_cmd;
  __u8 prli_spp_len;
  __be16 prli_len;
};
struct fc_els_prlo {
  __u8 prlo_cmd;
  __u8 prlo_obs;
  __be16 prlo_len;
};
struct fc_els_adisc {
  __u8 adisc_cmd;
  __u8 adisc_resv[3];
  __u8 adisc_resv1;
  __u8 adisc_hard_addr[3];
  __be64 adisc_wwpn;
  __be64 adisc_wwnn;
  __u8 adisc_resv2;
  __u8 adisc_port_id[3];
} __attribute__((__packed__));
struct fc_els_logo {
  __u8 fl_cmd;
  __u8 fl_zero[3];
  __u8 fl_resvd;
  __u8 fl_n_port_id[3];
  __be64 fl_n_port_wwn;
};
struct fc_els_rtv {
  __u8 rtv_cmd;
  __u8 rtv_zero[3];
};
struct fc_els_rtv_acc {
  __u8 rtv_cmd;
  __u8 rtv_zero[3];
  __be32 rtv_r_a_tov;
  __be32 rtv_e_d_tov;
  __be32 rtv_toq;
};
#define FC_ELS_RTV_EDRES (1 << 26)
#define FC_ELS_RTV_RTTOV (1 << 19)
struct fc_els_scr {
  __u8 scr_cmd;
  __u8 scr_resv[6];
  __u8 scr_reg_func;
};
enum fc_els_scr_func {
  ELS_SCRF_FAB = 1,
  ELS_SCRF_NPORT = 2,
  ELS_SCRF_FULL = 3,
  ELS_SCRF_CLEAR = 255,
};
struct fc_els_rscn {
  __u8 rscn_cmd;
  __u8 rscn_page_len;
  __be16 rscn_plen;
};
struct fc_els_rscn_page {
  __u8 rscn_page_flags;
  __u8 rscn_fid[3];
};
#define ELS_RSCN_EV_QUAL_BIT 2
#define ELS_RSCN_EV_QUAL_MASK 0xf
#define ELS_RSCN_ADDR_FMT_BIT 0
#define ELS_RSCN_ADDR_FMT_MASK 0x3
enum fc_els_rscn_ev_qual {
  ELS_EV_QUAL_NONE = 0,
  ELS_EV_QUAL_NS_OBJ = 1,
  ELS_EV_QUAL_PORT_ATTR = 2,
  ELS_EV_QUAL_SERV_OBJ = 3,
  ELS_EV_QUAL_SW_CONFIG = 4,
  ELS_EV_QUAL_REM_OBJ = 5,
};
enum fc_els_rscn_addr_fmt {
  ELS_ADDR_FMT_PORT = 0,
  ELS_ADDR_FMT_AREA = 1,
  ELS_ADDR_FMT_DOM = 2,
  ELS_ADDR_FMT_FAB = 3,
};
struct fc_els_rnid {
  __u8 rnid_cmd;
  __u8 rnid_resv[3];
  __u8 rnid_fmt;
  __u8 rnid_resv2[3];
};
enum fc_els_rnid_fmt {
  ELS_RNIDF_NONE = 0,
  ELS_RNIDF_GEN = 0xdf,
};
struct fc_els_rnid_resp {
  __u8 rnid_cmd;
  __u8 rnid_resv[3];
  __u8 rnid_fmt;
  __u8 rnid_cid_len;
  __u8 rnid_resv2;
  __u8 rnid_sid_len;
};
struct fc_els_rnid_cid {
  __be64 rnid_wwpn;
  __be64 rnid_wwnn;
};
struct fc_els_rnid_gen {
  __u8 rnid_vend_id[16];
  __be32 rnid_atype;
  __be32 rnid_phys_port;
  __be32 rnid_att_nodes;
  __u8 rnid_node_mgmt;
  __u8 rnid_ip_ver;
  __be16 rnid_prot_port;
  __be32 rnid_ip_addr[4];
  __u8 rnid_resvd[2];
  __be16 rnid_vend_spec;
};
enum fc_els_rnid_atype {
  ELS_RNIDA_UNK = 0x01,
  ELS_RNIDA_OTHER = 0x02,
  ELS_RNIDA_HUB = 0x03,
  ELS_RNIDA_SWITCH = 0x04,
  ELS_RNIDA_GATEWAY = 0x05,
  ELS_RNIDA_CONV = 0x06,
  ELS_RNIDA_HBA = 0x07,
  ELS_RNIDA_PROXY = 0x08,
  ELS_RNIDA_STORAGE = 0x09,
  ELS_RNIDA_HOST = 0x0a,
  ELS_RNIDA_SUBSYS = 0x0b,
  ELS_RNIDA_ACCESS = 0x0e,
  ELS_RNIDA_NAS = 0x11,
  ELS_RNIDA_BRIDGE = 0x12,
  ELS_RNIDA_VIRT = 0x13,
  ELS_RNIDA_MF = 0xff,
  ELS_RNIDA_MF_HUB = 1UL << 31,
  ELS_RNIDA_MF_SW = 1UL << 30,
  ELS_RNIDA_MF_GW = 1UL << 29,
  ELS_RNIDA_MF_ST = 1UL << 28,
  ELS_RNIDA_MF_HOST = 1UL << 27,
  ELS_RNIDA_MF_SUB = 1UL << 26,
  ELS_RNIDA_MF_ACC = 1UL << 25,
  ELS_RNIDA_MF_WDM = 1UL << 24,
  ELS_RNIDA_MF_NAS = 1UL << 23,
  ELS_RNIDA_MF_BR = 1UL << 22,
  ELS_RNIDA_MF_VIRT = 1UL << 21,
};
enum fc_els_rnid_mgmt {
  ELS_RNIDM_SNMP = 0,
  ELS_RNIDM_TELNET = 1,
  ELS_RNIDM_HTTP = 2,
  ELS_RNIDM_HTTPS = 3,
  ELS_RNIDM_XML = 4,
};
enum fc_els_rnid_ipver {
  ELS_RNIDIP_NONE = 0,
  ELS_RNIDIP_V4 = 1,
  ELS_RNIDIP_V6 = 2,
};
struct fc_els_rpl {
  __u8 rpl_cmd;
  __u8 rpl_resv[5];
  __be16 rpl_max_size;
  __u8 rpl_resv1;
  __u8 rpl_index[3];
};
struct fc_els_pnb {
  __be32 pnb_phys_pn;
  __u8 pnb_resv;
  __u8 pnb_port_id[3];
  __be64 pnb_wwpn;
};
struct fc_els_rpl_resp {
  __u8 rpl_cmd;
  __u8 rpl_resv1;
  __be16 rpl_plen;
  __u8 rpl_resv2;
  __u8 rpl_llen[3];
  __u8 rpl_resv3;
  __u8 rpl_index[3];
  struct fc_els_pnb rpl_pnb[1];
};
struct fc_els_lesb {
  __be32 lesb_link_fail;
  __be32 lesb_sync_loss;
  __be32 lesb_sig_loss;
  __be32 lesb_prim_err;
  __be32 lesb_inv_word;
  __be32 lesb_inv_crc;
};
struct fc_els_rps {
  __u8 rps_cmd;
  __u8 rps_resv[2];
  __u8 rps_flag;
  __be64 rps_port_spec;
};
enum fc_els_rps_flag {
  FC_ELS_RPS_DID = 0x00,
  FC_ELS_RPS_PPN = 0x01,
  FC_ELS_RPS_WWPN = 0x02,
};
struct fc_els_rps_resp {
  __u8 rps_cmd;
  __u8 rps_resv[2];
  __u8 rps_flag;
  __u8 rps_resv2[2];
  __be16 rps_status;
  struct fc_els_lesb rps_lesb;
};
enum fc_els_rps_resp_flag {
  FC_ELS_RPS_LPEV = 0x01,
};
enum fc_els_rps_resp_status {
  FC_ELS_RPS_PTP = 1 << 5,
  FC_ELS_RPS_LOOP = 1 << 4,
  FC_ELS_RPS_FAB = 1 << 3,
  FC_ELS_RPS_NO_SIG = 1 << 2,
  FC_ELS_RPS_NO_SYNC = 1 << 1,
  FC_ELS_RPS_RESET = 1 << 0,
};
struct fc_els_lirr {
  __u8 lirr_cmd;
  __u8 lirr_resv[3];
  __u8 lirr_func;
  __u8 lirr_fmt;
  __u8 lirr_resv2[2];
};
enum fc_els_lirr_func {
  ELS_LIRR_SET_COND = 0x01,
  ELS_LIRR_SET_UNCOND = 0x02,
  ELS_LIRR_CLEAR = 0xff
};
struct fc_els_srl {
  __u8 srl_cmd;
  __u8 srl_resv[3];
  __u8 srl_flag;
  __u8 srl_flag_param[3];
};
enum fc_els_srl_flag {
  FC_ELS_SRL_ALL = 0x00,
  FC_ELS_SRL_ONE = 0x01,
  FC_ELS_SRL_EN_PER = 0x02,
  FC_ELS_SRL_DIS_PER = 0x03,
};
struct fc_els_rls {
  __u8 rls_cmd;
  __u8 rls_resv[4];
  __u8 rls_port_id[3];
};
struct fc_els_rls_resp {
  __u8 rls_cmd;
  __u8 rls_resv[3];
  struct fc_els_lesb rls_lesb;
};
struct fc_els_rlir {
  __u8 rlir_cmd;
  __u8 rlir_resv[3];
  __u8 rlir_fmt;
  __u8 rlir_clr_len;
  __u8 rlir_cld_len;
  __u8 rlir_slr_len;
};
struct fc_els_clir {
  __be64 clir_wwpn;
  __be64 clir_wwnn;
  __u8 clir_port_type;
  __u8 clir_port_id[3];
  __be64 clir_conn_wwpn;
  __be64 clir_conn_wwnn;
  __be64 clir_fab_name;
  __be32 clir_phys_port;
  __be32 clir_trans_id;
  __u8 clir_resv[3];
  __u8 clir_ts_fmt;
  __be64 clir_timestamp;
};
enum fc_els_clir_ts_fmt {
  ELS_CLIR_TS_UNKNOWN = 0,
  ELS_CLIR_TS_SEC_FRAC = 1,
  ELS_CLIR_TS_CSU = 2,
};
struct fc_els_clid {
  __u8 clid_iq;
  __u8 clid_ic;
  __be16 clid_epai;
};
enum fc_els_clid_iq {
  ELS_CLID_SWITCH = 0x20,
  ELS_CLID_E_PORT = 0x10,
  ELS_CLID_SEV_MASK = 0x0c,
  ELS_CLID_SEV_INFO = 0x00,
  ELS_CLID_SEV_INOP = 0x08,
  ELS_CLID_SEV_DEG = 0x04,
  ELS_CLID_LASER = 0x02,
  ELS_CLID_FRU = 0x01,
};
enum fc_els_clid_ic {
  ELS_CLID_IC_IMPL = 1,
  ELS_CLID_IC_BER = 2,
  ELS_CLID_IC_LOS = 3,
  ELS_CLID_IC_NOS = 4,
  ELS_CLID_IC_PST = 5,
  ELS_CLID_IC_INVAL = 6,
  ELS_CLID_IC_LOOP_TO = 7,
  ELS_CLID_IC_LIP = 8,
};
enum fc_fpin_li_event_types {
  FPIN_LI_UNKNOWN = 0x0,
  FPIN_LI_LINK_FAILURE = 0x1,
  FPIN_LI_LOSS_OF_SYNC = 0x2,
  FPIN_LI_LOSS_OF_SIG = 0x3,
  FPIN_LI_PRIM_SEQ_ERR = 0x4,
  FPIN_LI_INVALID_TX_WD = 0x5,
  FPIN_LI_INVALID_CRC = 0x6,
  FPIN_LI_DEVICE_SPEC = 0xF,
};
#define FC_FPIN_LI_EVT_TYPES_INIT { { FPIN_LI_UNKNOWN, "Unknown" }, { FPIN_LI_LINK_FAILURE, "Link Failure" }, { FPIN_LI_LOSS_OF_SYNC, "Loss of Synchronization" }, { FPIN_LI_LOSS_OF_SIG, "Loss of Signal" }, { FPIN_LI_PRIM_SEQ_ERR, "Primitive Sequence Protocol Error" }, { FPIN_LI_INVALID_TX_WD, "Invalid Transmission Word" }, { FPIN_LI_INVALID_CRC, "Invalid CRC" }, { FPIN_LI_DEVICE_SPEC, "Device Specific" }, \
}
enum fc_fpin_deli_event_types {
  FPIN_DELI_UNKNOWN = 0x0,
  FPIN_DELI_TIMEOUT = 0x1,
  FPIN_DELI_UNABLE_TO_ROUTE = 0x2,
  FPIN_DELI_DEVICE_SPEC = 0xF,
};
#define FC_FPIN_DELI_EVT_TYPES_INIT { { FPIN_DELI_UNKNOWN, "Unknown" }, { FPIN_DELI_TIMEOUT, "Timeout" }, { FPIN_DELI_UNABLE_TO_ROUTE, "Unable to Route" }, { FPIN_DELI_DEVICE_SPEC, "Device Specific" }, \
}
enum fc_fpin_congn_event_types {
  FPIN_CONGN_CLEAR = 0x0,
  FPIN_CONGN_LOST_CREDIT = 0x1,
  FPIN_CONGN_CREDIT_STALL = 0x2,
  FPIN_CONGN_OVERSUBSCRIPTION = 0x3,
  FPIN_CONGN_DEVICE_SPEC = 0xF,
};
#define FC_FPIN_CONGN_EVT_TYPES_INIT { { FPIN_CONGN_CLEAR, "Clear" }, { FPIN_CONGN_LOST_CREDIT, "Lost Credit" }, { FPIN_CONGN_CREDIT_STALL, "Credit Stall" }, { FPIN_CONGN_OVERSUBSCRIPTION, "Oversubscription" }, { FPIN_CONGN_DEVICE_SPEC, "Device Specific" }, \
}
enum fc_fpin_congn_severity_types {
  FPIN_CONGN_SEVERITY_WARNING = 0xF1,
  FPIN_CONGN_SEVERITY_ERROR = 0xF7,
};
struct fc_fn_li_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be64 detecting_wwpn;
  __be64 attached_wwpn;
  __be16 event_type;
  __be16 event_modifier;
  __be32 event_threshold;
  __be32 event_count;
  __be32 pname_count;
  __be64 pname_list[];
};
struct fc_fn_deli_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be64 detecting_wwpn;
  __be64 attached_wwpn;
  __be32 deli_reason_code;
};
struct fc_fn_peer_congn_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be64 detecting_wwpn;
  __be64 attached_wwpn;
  __be16 event_type;
  __be16 event_modifier;
  __be32 event_period;
  __be32 pname_count;
  __be64 pname_list[];
};
struct fc_fn_congn_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be16 event_type;
  __be16 event_modifier;
  __be32 event_period;
  __u8 severity;
  __u8 resv[3];
};
struct fc_els_fpin {
  __u8 fpin_cmd;
  __u8 fpin_zero[3];
  __be32 desc_len;
  struct fc_tlv_desc fpin_desc[];
};
struct fc_df_desc_fpin_reg {
  __be32 desc_tag;
  __be32 desc_len;
  __be32 count;
  __be32 desc_tags[];
};
struct fc_els_rdf {
  __u8 fpin_cmd;
  __u8 fpin_zero[3];
  __be32 desc_len;
  struct fc_tlv_desc desc[];
};
struct fc_els_rdf_resp {
  struct fc_els_ls_acc acc_hdr;
  __be32 desc_list_len;
  struct fc_els_lsri_desc lsri;
  struct fc_tlv_desc desc[];
};
struct fc_diag_lnkflt_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be32 degrade_activate_threshold;
  __be32 degrade_deactivate_threshold;
  __be32 fec_degrade_interval;
};
enum fc_edc_cg_signal_cap_types {
  EDC_CG_SIG_NOTSUPPORTED = 0x00,
  EDC_CG_SIG_WARN_ONLY = 0x01,
  EDC_CG_SIG_WARN_ALARM = 0x02,
};
#define FC_EDC_CG_SIGNAL_CAP_TYPES_INIT { { EDC_CG_SIG_NOTSUPPORTED, "Signaling Not Supported" }, { EDC_CG_SIG_WARN_ONLY, "Warning Signal" }, { EDC_CG_SIG_WARN_ALARM, "Warning and Alarm Signals" }, \
}
enum fc_diag_cg_sig_freq_types {
  EDC_CG_SIGFREQ_CNT_MIN = 1,
  EDC_CG_SIGFREQ_CNT_MAX = 999,
  EDC_CG_SIGFREQ_SEC = 0x1,
  EDC_CG_SIGFREQ_MSEC = 0x2,
};
struct fc_diag_cg_sig_freq {
  __be16 count;
  __be16 units;
};
struct fc_diag_cg_sig_desc {
  __be32 desc_tag;
  __be32 desc_len;
  __be32 xmt_signal_capability;
  struct fc_diag_cg_sig_freq xmt_signal_frequency;
  __be32 rcv_signal_capability;
  struct fc_diag_cg_sig_freq rcv_signal_frequency;
};
struct fc_els_edc {
  __u8 edc_cmd;
  __u8 edc_zero[3];
  __be32 desc_len;
  struct fc_tlv_desc desc[];
};
struct fc_els_edc_resp {
  struct fc_els_ls_acc acc_hdr;
  __be32 desc_list_len;
  struct fc_els_lsri_desc lsri;
  struct fc_tlv_desc desc[];
};
#endif

"""

```