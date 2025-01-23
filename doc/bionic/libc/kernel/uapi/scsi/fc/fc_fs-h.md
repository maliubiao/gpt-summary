Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding and Context:**

* **Identify the Purpose:** The file name `fc_fs.h` and the directory `bionic/libc/kernel/uapi/scsi/fc/` strongly suggest this file defines structures and constants related to Fibre Channel (FC) framing and protocol, specifically within the Linux kernel's userspace API (uapi). The comment confirms it's auto-generated kernel headers for Android's Bionic library.
* **Target Audience:** This file is not meant for direct application developers. It's a low-level interface for drivers and potentially some system daemons interacting with Fibre Channel hardware.
* **Key Technologies:**  Fibre Channel (FC) and SCSI are the core technologies involved. Understanding their basic concepts is crucial (though the file itself defines the structures, not the high-level protocols).
* **Android Relevance:** The location within Bionic indicates it's used somewhere within the Android operating system, likely for hardware abstraction or specific peripheral support.

**2. Deconstructing the Header File:**

* **Ignore Auto-generation Comments:** The "auto-generated" comment is important for understanding the source of the file but doesn't directly contribute to its functionality.
* **Preprocessor Directives:** `#ifndef _FC_FS_H_`, `#define _FC_FS_H_`, and `#include <linux/types.h>` are standard C header file guards and a necessary inclusion for basic Linux data types. Recognize their purpose immediately.
* **Structures:** Focus on the `struct fc_frame_header`. Analyze each member:
    * `__u8`, `__be16`, `__be32`:  These are Linux-specific types representing unsigned 8-bit, big-endian 16-bit, and big-endian 32-bit integers. Endianness is significant in networking protocols.
    * Member names like `fh_r_ctl`, `fh_d_id`, etc., hint at their function within a Fibre Channel frame header. Even without deep FC knowledge, one can infer they represent control information, IDs, and offsets.
* **Macros/Constants:**  Examine the `#define` statements:
    * `FC_FRAME_HEADER_LEN`, `FC_MAX_PAYLOAD`, etc.: These define the size limits of FC frames and their components. These are fundamental parameters for the protocol.
    * `FC_RCTL_DD_UNCAT`, `FC_RCTL_DD_SOL_DATA`, etc.: The `enum fc_rctl` and these macros define different request/response control codes within the FC protocol. Notice the `#define` aliases like `FC_RCTL_ILS_REQ`.
    * `FC_FID_NONE`, `FC_FID_BCAST`, etc.: The `enum fc_well_known_fid` defines well-known Fibre Channel identifiers.
    * `FC_TYPE_BLS`, `FC_TYPE_ELS`, etc.: The `enum fc_fh_type` defines different types of Fibre Channel frames.
    * `FC_XID_UNKNOWN`, `FC_XID_MIN`, `FC_XID_MAX`: These define transaction ID ranges.
    * `FC_FC_EX_CTX`, `FC_FC_SEQ_CTX`, etc.: These are bit flags likely used within control words for managing sequences and exchanges.
* **Enums:** The `enum` declarations (`fc_rctl`, `fc_well_known_fid`, `fc_fh_type`, `fc_ba_rjt_reason`, `fc_ba_rjt_explan`, `fc_pf_rjt_reason`) define sets of named constants, improving code readability and maintainability. The comments like `FC_RCTL_NAMES_INIT` indicate a potential way to map these values to human-readable strings.
* **Other Structures:** Analyze `struct fc_ba_acc`, `struct fc_ba_rjt`, and `struct fc_pf_rjt`. These represent specific control frame structures (Accept, Reject).

**3. Inferring Functionality and Android Relevance:**

* **Core Functionality:**  Based on the structures and constants, the primary function is clearly defining the structure of Fibre Channel frames and related control information. This is fundamental for any software interacting with FC hardware.
* **Android Connection:**  Since it's in Bionic, some part of Android must use Fibre Channel. The most likely scenario is support for Fibre Channel-based storage solutions. Think about enterprise-level Android devices or potentially specialized hardware. It's less likely to be directly exposed to typical Android app developers.

**4. Addressing Specific Questions (Mental Checklist):**

* **List Functions:**  The file *defines* data structures and constants; it doesn't contain function definitions. This is a key distinction.
* **Android Examples:**  Consider where FC might be used in Android (storage, potentially some server-like functionality).
* **libc Function Implementation:** This file is a header file; it declares structures, not implements libc functions.
* **Dynamic Linker:** This header file is not directly involved in dynamic linking. It defines data structures that *might* be used by code that is dynamically linked, but the header itself doesn't perform linking.
* **Logical Reasoning (Hypothetical Input/Output):**  While you can't execute this code directly, you can imagine how these structures would be used. For example, when receiving an FC frame, the header would be parsed according to the `fc_frame_header` structure.
* **User/Programming Errors:** Misinterpreting the meaning of the constants or incorrectly packing/unpacking the frame header would be common errors.
* **Android Framework/NDK Path:** Trace backward from the kernel. A kernel driver interacts directly with the hardware. A userspace service or library would interact with that driver, potentially using these structures. NDK developers would likely not interact with this directly, unless writing very low-level system components.
* **Frida Hooking:**  You'd need to hook functions that *use* these structures. Focus on potential kernel modules or system services involved in FC communication.

**5. Structuring the Response:**

Organize the information logically, addressing each part of the prompt clearly. Use headings and bullet points for readability. Be precise about what the file *does* (defines data structures) and what it *doesn't* do (implement functions, handle dynamic linking directly). Provide concrete examples where possible, even if they are somewhat speculative based on the limited information in the header file. Acknowledge limitations in your knowledge (e.g., not knowing the exact Android use case).
这是一个定义了与光纤通道（Fibre Channel, FC）文件系统相关的常量、结构体和枚举类型的C头文件。它属于Android的Bionic库，用于在用户空间（userspace）与Linux内核中处理FC文件系统交互。

**功能列举:**

1. **定义光纤通道帧头结构体 (`struct fc_frame_header`):**  定义了FC帧头的布局，包含了控制信息、源/目的ID、类型、序列号等关键字段。这是所有FC通信的基础。
2. **定义帧的最大/最小有效载荷和帧大小:**  `FC_MAX_PAYLOAD`, `FC_MIN_MAX_PAYLOAD`, `FC_MAX_FRAME`, `FC_MIN_MAX_FRAME` 定义了FC数据传输的限制。
3. **定义各种FC控制代码 (`enum fc_rctl`):**  枚举了不同的控制帧类型，如数据帧、控制帧、扩展链路服务请求/响应（ELS）、基本链路服务（BLS）等。这些代码用于指示帧的目的和类型。
4. **定义预定义的FC Fabric ID (`enum fc_well_known_fid`):**  列出了一些在FC网络中具有特殊用途的ID，例如广播地址、登录服务、目录服务等。
5. **定义FC帧类型 (`enum fc_fh_type`):**  枚举了不同的上层协议类型，例如BLS、ELS、IP、FCP（用于SCSI over FC）、通用传输（CT）、隐式链路服务（ILS）、NVMe over Fabrics (NVMe)。
6. **定义交换ID (XID) 相关常量:**  `FC_XID_UNKNOWN`, `FC_XID_MIN`, `FC_XID_MAX` 定义了用于标识FC交换的ID范围。
7. **定义帧控制字段（F_CTL）的位掩码:**  `FC_FC_EX_CTX`, `FC_FC_SEQ_CTX` 等宏定义了帧控制字段中各个比特位的含义，用于管理交换、序列和帧的传输。
8. **定义基本链路服务接受/拒绝帧结构体 (`struct fc_ba_acc`, `struct fc_ba_rjt`):** 定义了BLS请求的接受和拒绝消息的格式。
9. **定义端口/Fabric拒绝帧结构体 (`struct fc_pf_rjt`):** 定义了端口或Fabric拒绝消息的格式。
10. **定义超时时间常量:** `FC_DEF_E_D_TOV` 和 `FC_DEF_R_A_TOV` 定义了错误检测和资源分配的默认超时时间。

**与Android功能的关系及举例说明:**

此头文件直接与Android系统中对光纤通道存储的支持相关。Android设备通常不直接作为FC存储网络的节点，但Android可以通过以下方式间接涉及：

* **硬件抽象层 (HAL):**  如果Android设备连接到FC存储阵列（例如，某些企业级Android服务器或特殊用途设备），则可能存在一个HAL层来与底层的FC驱动程序交互。这个头文件中定义的结构体和常量会被HAL层用来构造和解析FC帧。
* **内核驱动程序:**  Android的内核需要支持FC硬件。这个头文件会被内核中的FC驱动程序使用，以便正确地处理FC协议。
* **用户空间工具/守护进程:**  可能存在一些用户空间的工具或守护进程，用于管理或监控FC连接。这些程序可能会间接地使用到这里定义的结构体，例如通过系统调用与内核交互。

**举例说明:**

假设一个Android设备通过一个FC Host Bus Adapter (HBA) 连接到一个FC存储阵列。当Android上的一个应用程序需要访问FC存储上的数据时，底层的处理流程可能如下：

1. 应用程序发起一个存储请求（例如，读取一个文件）。
2. Android文件系统层将该请求转换为SCSI命令。
3. 一个位于内核中的FC驱动程序会将该SCSI命令封装到FC协议数据单元（PDU）中。
4. 驱动程序会使用 `struct fc_frame_header` 结构体来构建FC帧头，设置源/目的ID、控制代码（可能使用 `FC_RCTL_DD_SOL_DATA` 表示这是一个包含请求数据的帧）、帧类型（可能使用 `FC_TYPE_FCP` 表示这是FCP帧）等字段。
5. 构建好的FC帧会被发送到FC网络。
6. 存储阵列接收到帧并处理请求，然后将响应数据封装到另一个FC帧中发送回Android设备。
7. Android设备的FC驱动程序接收到响应帧，并使用 `struct fc_frame_header` 解析帧头，确定帧的类型和内容。
8. 驱动程序将FC帧中的数据解封装出来，传递给上层的SCSI层，最终将数据返回给应用程序。

**libc 函数的功能实现:**

这个头文件本身并没有定义任何libc函数，它只是定义了数据结构和常量。libc函数是在Bionic库的其他源文件中实现的。此头文件中定义的结构体会被libc中与底层I/O操作相关的函数使用，例如 `read`, `write`, `ioctl` 等，用于在用户空间和内核空间之间传递与FC通信相关的数据。

**涉及dynamic linker的功能:**

这个头文件不直接涉及dynamic linker的功能。Dynamic linker的主要职责是加载共享库（.so文件）并在程序启动或运行时解析符号引用。

虽然此头文件定义的数据结构可能会被编译到使用了FC功能的共享库中，但它本身并不参与链接过程。

**so布局样本以及链接的处理过程 (假设一个使用了此头文件的共享库):**

假设我们有一个名为 `libfchelper.so` 的共享库，它使用了 `fc_fs.h` 中定义的结构体来处理FC通信。

**so布局样本:**

```
libfchelper.so:
    .text           # 包含代码段
        fchelper_send_frame:  # 一个发送FC帧的函数
            # ... 使用 struct fc_frame_header 构建帧 ...
        fchelper_receive_frame: # 一个接收FC帧的函数
            # ... 使用 struct fc_frame_header 解析帧 ...
        ...

    .rodata         # 包含只读数据，可能包含一些 FC 相关的常量字符串等
        fc_error_messages:
            # ...

    .data           # 包含可读写数据

    .bss            # 包含未初始化的静态变量

    .symtab         # 符号表，包含导出的和导入的符号
        fchelper_send_frame (global, function)
        fchelper_receive_frame (global, function)
        # ... 其他符号 ...

    .dynsym         # 动态符号表，用于动态链接

    .rel.dyn        # 动态重定位表
    .rel.plt        # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程:**

1. **编译时:** 当编译 `libfchelper.so` 的源代码时，编译器会读取 `fc_fs.h` 头文件，了解 `struct fc_frame_header` 的结构。如果在 `libfchelper.so` 的代码中使用了这个结构体，编译器会根据定义为其分配内存。
2. **链接时:**  静态链接器（如果进行静态链接，通常不用于共享库）或动态链接器会处理符号引用。如果 `libfchelper.so` 导出了 `fchelper_send_frame` 函数，则该符号会被添加到其符号表中。如果它使用了其他库的函数（例如libc的函数），则会记录对这些外部符号的引用。
3. **运行时 (动态链接):** 当一个应用程序加载 `libfchelper.so` 时，Android的dynamic linker (`/system/bin/linker` 或 `linker64`) 会执行以下步骤：
    * **加载共享库:** 将 `libfchelper.so` 的代码段和数据段加载到内存中。
    * **解析符号:** 遍历 `libfchelper.so` 的动态符号表和重定位表。
    * **重定位:**  对于需要重定位的符号引用，dynamic linker 会查找这些符号的实际地址。
        * 如果引用的符号是 `libfchelper.so` 内部的，则直接更新地址。
        * 如果引用的符号来自其他共享库（例如libc），则 dynamic linker 会在已加载的其他共享库中查找该符号，并更新地址。这通常通过GOT (Global Offset Table) 和 PLT 实现。
    * **执行初始化代码:**  如果 `libfchelper.so` 有初始化函数（通过 `__attribute__((constructor))` 定义），dynamic linker 会执行这些函数。

**假设输入与输出 (逻辑推理):**

虽然这个头文件本身没有可执行的逻辑，但我们可以假设一个使用了这个头文件的函数，例如 `fchelper_send_frame`。

**假设输入:**

* `dest_id`: 目标FC ID (3字节) - 例如: `\x01\x02\x03`
* `source_id`: 源FC ID (3字节) - 例如: `\x04\x05\x06`
* `payload`: 要发送的数据的指针和长度

**假设输出:**

* 构建好的 `struct fc_frame_header` 结构体，其成员被填充了相应的值。
* 包含完整FC帧的数据缓冲区，包括帧头和有效载荷。

**用户或编程常见的使用错误:**

1. **字节序错误:** FC协议通常使用大端字节序（Big-Endian），而不同的处理器架构可能使用不同的字节序。如果在填充 `__be16` 或 `__be32` 类型的字段时没有进行字节序转换，可能会导致通信错误。
2. **帧头字段设置错误:**  错误地设置帧头中的控制代码、ID或类型字段会导致接收方无法正确解析或处理帧。例如，使用了错误的 `fc_rctl` 值。
3. **帧大小超出限制:**  构建的帧大小超过 `FC_MAX_FRAME` 或有效载荷大小超过 `FC_MAX_PAYLOAD` 会导致传输失败。
4. **未初始化结构体:**  在使用 `struct fc_frame_header` 之前，没有正确地初始化其成员，可能导致发送错误的帧数据。
5. **内存管理错误:**  在分配和释放用于存储FC帧的内存时出现错误，例如内存泄漏或访问越界。

**Android Framework 或 NDK 如何一步步到达这里:**

由于这是一个底层的内核头文件，Android Framework 或 NDK 通常不会直接使用它。 访问路径通常会经过以下层次：

1. **应用程序 (Java/Kotlin 或 NDK C/C++):**  应用程序发起一个需要访问FC存储的操作。
2. **Android Framework (Java/Kotlin):** Framework层（例如，StorageManager、MediaProvider 等）接收到应用程序的请求，并将其抽象为更底层的操作。
3. **System Services (Java/Kotlin 或 Native):** Framework层可能会调用一些系统服务来处理存储相关的操作。这些服务可能使用JNI（Java Native Interface）调用到 Native 代码。
4. **HAL (Hardware Abstraction Layer) (C/C++):**  如果涉及到特定的硬件（例如，FC HBA），系统服务可能会通过HAL层与硬件驱动程序交互。HAL层会定义一些接口，供上层调用。
5. **内核驱动程序 (C):**  HAL层最终会调用到内核中的FC驱动程序。驱动程序会直接使用 `bionic/libc/kernel/uapi/scsi/fc/fc_fs.h` 中定义的结构体和常量来构建和解析FC帧，与FC硬件进行通信。

**Frida Hook 示例调试步骤:**

要使用 Frida Hook 调试这些步骤，你需要在可能使用到这些结构体的地方进行 Hook。由于直接在 Framework 或 NDK 中使用这个头文件的情况较少，Hook 的目标更可能是内核模块或与 FC 硬件直接交互的 HAL 层或 Native 服务。

**假设我们想 Hook 一个内核模块中的函数，该函数负责发送 FC 帧。**

1. **确定目标函数:** 使用 `adb shell` 和 `lsmod` 命令找到与 FC 相关的内核模块名称。然后，可能需要使用 `readelf` 或 `objdump` 等工具查看模块的符号表，找到负责发送 FC 帧的函数名称（这通常需要root权限和对内核的了解）。 假设找到了一个名为 `fc_hba_send_frame` 的函数。

2. **编写 Frida 脚本:**

```python
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

try:
    session = frida.get_usb_device().attach("com.example.your_app") # 或者系统进程名称
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行或使用 'spawn' 模式")
    sys.exit()

# 假设内核模块已加载，需要找到函数的基地址
# 通常需要一些技巧来获取内核模块的基地址，例如读取 /proc/modules

# 假设我们已经知道 fc_hba_send_frame 函数的地址
# 请替换为实际地址
target_address = 0xffffffffa0123456

# 定义 struct fc_frame_header 的结构
fc_frame_header_struct = """
struct fc_frame_header {
  unsigned char fh_r_ctl;
  unsigned char fh_d_id[3];
  unsigned char fh_cs_ctl;
  unsigned char fh_s_id[3];
  unsigned char fh_type;
  unsigned char fh_f_ctl[3];
  unsigned char fh_seq_id;
  unsigned char fh_df_ctl;
  unsigned short fh_seq_cnt;
  unsigned short fh_ox_id;
  unsigned short fh_rx_id;
  unsigned int fh_parm_offset;
};
"""

# Hook 内核函数
script_code = """
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        console.log("进入 fc_hba_send_frame");
        // args[0] 可能指向 fc_frame_header 结构体
        var frame_header_ptr = ptr(args[0]);
        if (frame_header_ptr) {
            console.log("frame_header 地址:", frame_header_ptr);
            var fc_frame_header = Memory.readStruct(frame_header_ptr, '%s');
            console.log("frame_header 内容:", JSON.stringify(fc_frame_header));
            // 你可以进一步打印有效载荷等信息
        }
    },
    onLeave: function(retval) {
        console.log("离开 fc_hba_send_frame, 返回值:", retval);
    }
});
""" % (hex(target_address), fc_frame_header_struct)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

3. **运行 Frida 脚本:**  在你的 PC 上运行该 Frida 脚本，并在 Android 设备上触发相关的 FC 通信操作。Frida 会拦截对 `fc_hba_send_frame` 函数的调用，并打印出 `struct fc_frame_header` 的内容，从而帮助你调试 FC 帧的构建过程。

**注意:**

* Hook 内核函数需要 root 权限。
* 查找内核函数的地址可能比较复杂，可能需要借助一些工具和技术，例如 KASLR 绕过等。
* 实际的函数名称和参数可能因内核版本和驱动程序实现而异。
* Hook HAL 层或 Native 服务中的函数会更容易一些，可以使用 `Module.findExportByName` 等 Frida API 来查找函数地址。

这个头文件是 Android 系统中处理光纤通道通信的重要组成部分，但它处于非常底层的地位，通常不会被普通的应用程序开发者直接使用。理解它的功能对于理解 Android 如何与 FC 存储设备交互至关重要。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/scsi/fc/fc_fs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _FC_FS_H_
#define _FC_FS_H_
#include <linux/types.h>
struct fc_frame_header {
  __u8 fh_r_ctl;
  __u8 fh_d_id[3];
  __u8 fh_cs_ctl;
  __u8 fh_s_id[3];
  __u8 fh_type;
  __u8 fh_f_ctl[3];
  __u8 fh_seq_id;
  __u8 fh_df_ctl;
  __be16 fh_seq_cnt;
  __be16 fh_ox_id;
  __be16 fh_rx_id;
  __be32 fh_parm_offset;
};
#define FC_FRAME_HEADER_LEN 24
#define FC_MAX_PAYLOAD 2112U
#define FC_MIN_MAX_PAYLOAD 256U
#define FC_MAX_FRAME (FC_MAX_PAYLOAD + FC_FRAME_HEADER_LEN)
#define FC_MIN_MAX_FRAME (FC_MIN_MAX_PAYLOAD + FC_FRAME_HEADER_LEN)
enum fc_rctl {
  FC_RCTL_DD_UNCAT = 0x00,
  FC_RCTL_DD_SOL_DATA = 0x01,
  FC_RCTL_DD_UNSOL_CTL = 0x02,
  FC_RCTL_DD_SOL_CTL = 0x03,
  FC_RCTL_DD_UNSOL_DATA = 0x04,
  FC_RCTL_DD_DATA_DESC = 0x05,
  FC_RCTL_DD_UNSOL_CMD = 0x06,
  FC_RCTL_DD_CMD_STATUS = 0x07,
#define FC_RCTL_ILS_REQ FC_RCTL_DD_UNSOL_CTL
#define FC_RCTL_ILS_REP FC_RCTL_DD_SOL_CTL
  FC_RCTL_ELS_REQ = 0x22,
  FC_RCTL_ELS_REP = 0x23,
  FC_RCTL_ELS4_REQ = 0x32,
  FC_RCTL_ELS4_REP = 0x33,
  FC_RCTL_VFTH = 0x50,
  FC_RCTL_IFRH = 0x51,
  FC_RCTL_ENCH = 0x52,
  FC_RCTL_BA_NOP = 0x80,
  FC_RCTL_BA_ABTS = 0x81,
  FC_RCTL_BA_RMC = 0x82,
  FC_RCTL_BA_ACC = 0x84,
  FC_RCTL_BA_RJT = 0x85,
  FC_RCTL_BA_PRMT = 0x86,
  FC_RCTL_ACK_1 = 0xc0,
  FC_RCTL_ACK_0 = 0xc1,
  FC_RCTL_P_RJT = 0xc2,
  FC_RCTL_F_RJT = 0xc3,
  FC_RCTL_P_BSY = 0xc4,
  FC_RCTL_F_BSY = 0xc5,
  FC_RCTL_F_BSYL = 0xc6,
  FC_RCTL_LCR = 0xc7,
  FC_RCTL_END = 0xc9,
};
#define FC_RCTL_NAMES_INIT {[FC_RCTL_DD_UNCAT] = "uncat",[FC_RCTL_DD_SOL_DATA] = "sol data",[FC_RCTL_DD_UNSOL_CTL] = "unsol ctl",[FC_RCTL_DD_SOL_CTL] = "sol ctl/reply",[FC_RCTL_DD_UNSOL_DATA] = "unsol data",[FC_RCTL_DD_DATA_DESC] = "data desc",[FC_RCTL_DD_UNSOL_CMD] = "unsol cmd",[FC_RCTL_DD_CMD_STATUS] = "cmd status",[FC_RCTL_ELS_REQ] = "ELS req",[FC_RCTL_ELS_REP] = "ELS rep",[FC_RCTL_ELS4_REQ] = "FC-4 ELS req",[FC_RCTL_ELS4_REP] = "FC-4 ELS rep",[FC_RCTL_BA_NOP] = "BLS NOP",[FC_RCTL_BA_ABTS] = "BLS abort",[FC_RCTL_BA_RMC] = "BLS remove connection",[FC_RCTL_BA_ACC] = "BLS accept",[FC_RCTL_BA_RJT] = "BLS reject",[FC_RCTL_BA_PRMT] = "BLS dedicated connection preempted",[FC_RCTL_ACK_1] = "LC ACK_1",[FC_RCTL_ACK_0] = "LC ACK_0",[FC_RCTL_P_RJT] = "LC port reject",[FC_RCTL_F_RJT] = "LC fabric reject",[FC_RCTL_P_BSY] = "LC port busy",[FC_RCTL_F_BSY] = "LC fabric busy to data frame",[FC_RCTL_F_BSYL] = "LC fabric busy to link control frame",[FC_RCTL_LCR] = "LC link credit reset",[FC_RCTL_END] = "LC end", \
}
enum fc_well_known_fid {
  FC_FID_NONE = 0x000000,
  FC_FID_BCAST = 0xffffff,
  FC_FID_FLOGI = 0xfffffe,
  FC_FID_FCTRL = 0xfffffd,
  FC_FID_DIR_SERV = 0xfffffc,
  FC_FID_TIME_SERV = 0xfffffb,
  FC_FID_MGMT_SERV = 0xfffffa,
  FC_FID_QOS = 0xfffff9,
  FC_FID_ALIASES = 0xfffff8,
  FC_FID_SEC_KEY = 0xfffff7,
  FC_FID_CLOCK = 0xfffff6,
  FC_FID_MCAST_SERV = 0xfffff5,
};
#define FC_FID_WELL_KNOWN_MAX 0xffffff
#define FC_FID_WELL_KNOWN_BASE 0xfffff5
#define FC_FID_DOM_MGR 0xfffc00
#define FC_FID_DOMAIN 0
#define FC_FID_PORT 1
#define FC_FID_LINK 2
enum fc_fh_type {
  FC_TYPE_BLS = 0x00,
  FC_TYPE_ELS = 0x01,
  FC_TYPE_IP = 0x05,
  FC_TYPE_FCP = 0x08,
  FC_TYPE_CT = 0x20,
  FC_TYPE_ILS = 0x22,
  FC_TYPE_NVME = 0x28,
};
#define FC_TYPE_NAMES_INIT {[FC_TYPE_BLS] = "BLS",[FC_TYPE_ELS] = "ELS",[FC_TYPE_IP] = "IP",[FC_TYPE_FCP] = "FCP",[FC_TYPE_CT] = "CT",[FC_TYPE_ILS] = "ILS",[FC_TYPE_NVME] = "NVME", \
}
#define FC_XID_UNKNOWN 0xffff
#define FC_XID_MIN 0x0
#define FC_XID_MAX 0xfffe
#define FC_FC_EX_CTX (1 << 23)
#define FC_FC_SEQ_CTX (1 << 22)
#define FC_FC_FIRST_SEQ (1 << 21)
#define FC_FC_LAST_SEQ (1 << 20)
#define FC_FC_END_SEQ (1 << 19)
#define FC_FC_END_CONN (1 << 18)
#define FC_FC_RES_B17 (1 << 17)
#define FC_FC_SEQ_INIT (1 << 16)
#define FC_FC_X_ID_REASS (1 << 15)
#define FC_FC_X_ID_INVAL (1 << 14)
#define FC_FC_ACK_1 (1 << 12)
#define FC_FC_ACK_N (2 << 12)
#define FC_FC_ACK_0 (3 << 12)
#define FC_FC_RES_B11 (1 << 11)
#define FC_FC_RES_B10 (1 << 10)
#define FC_FC_RETX_SEQ (1 << 9)
#define FC_FC_UNI_TX (1 << 8)
#define FC_FC_CONT_SEQ(i) ((i) << 6)
#define FC_FC_ABT_SEQ(i) ((i) << 4)
#define FC_FC_REL_OFF (1 << 3)
#define FC_FC_RES2 (1 << 2)
#define FC_FC_FILL(i) ((i) & 3)
struct fc_ba_acc {
  __u8 ba_seq_id_val;
#define FC_BA_SEQ_ID_VAL 0x80
  __u8 ba_seq_id;
  __u8 ba_resvd[2];
  __be16 ba_ox_id;
  __be16 ba_rx_id;
  __be16 ba_low_seq_cnt;
  __be16 ba_high_seq_cnt;
};
struct fc_ba_rjt {
  __u8 br_resvd;
  __u8 br_reason;
  __u8 br_explan;
  __u8 br_vendor;
};
enum fc_ba_rjt_reason {
  FC_BA_RJT_NONE = 0,
  FC_BA_RJT_INVL_CMD = 0x01,
  FC_BA_RJT_LOG_ERR = 0x03,
  FC_BA_RJT_LOG_BUSY = 0x05,
  FC_BA_RJT_PROTO_ERR = 0x07,
  FC_BA_RJT_UNABLE = 0x09,
  FC_BA_RJT_VENDOR = 0xff,
};
enum fc_ba_rjt_explan {
  FC_BA_RJT_EXP_NONE = 0x00,
  FC_BA_RJT_INV_XID = 0x03,
  FC_BA_RJT_ABT = 0x05,
};
struct fc_pf_rjt {
  __u8 rj_action;
  __u8 rj_reason;
  __u8 rj_resvd;
  __u8 rj_vendor;
};
enum fc_pf_rjt_reason {
  FC_RJT_NONE = 0,
  FC_RJT_INVL_DID = 0x01,
  FC_RJT_INVL_SID = 0x02,
  FC_RJT_P_UNAV_T = 0x03,
  FC_RJT_P_UNAV = 0x04,
  FC_RJT_CLS_UNSUP = 0x05,
  FC_RJT_DEL_USAGE = 0x06,
  FC_RJT_TYPE_UNSUP = 0x07,
  FC_RJT_LINK_CTL = 0x08,
  FC_RJT_R_CTL = 0x09,
  FC_RJT_F_CTL = 0x0a,
  FC_RJT_OX_ID = 0x0b,
  FC_RJT_RX_ID = 0x0c,
  FC_RJT_SEQ_ID = 0x0d,
  FC_RJT_DF_CTL = 0x0e,
  FC_RJT_SEQ_CNT = 0x0f,
  FC_RJT_PARAM = 0x10,
  FC_RJT_EXCH_ERR = 0x11,
  FC_RJT_PROTO = 0x12,
  FC_RJT_LEN = 0x13,
  FC_RJT_UNEXP_ACK = 0x14,
  FC_RJT_FAB_CLASS = 0x15,
  FC_RJT_LOGI_REQ = 0x16,
  FC_RJT_SEQ_XS = 0x17,
  FC_RJT_EXCH_EST = 0x18,
  FC_RJT_FAB_UNAV = 0x1a,
  FC_RJT_VC_ID = 0x1b,
  FC_RJT_CS_CTL = 0x1c,
  FC_RJT_INSUF_RES = 0x1d,
  FC_RJT_INVL_CLS = 0x1f,
  FC_RJT_PREEMT_RJT = 0x20,
  FC_RJT_PREEMT_DIS = 0x21,
  FC_RJT_MCAST_ERR = 0x22,
  FC_RJT_MCAST_ET = 0x23,
  FC_RJT_PRLI_REQ = 0x24,
  FC_RJT_INVL_ATT = 0x25,
  FC_RJT_VENDOR = 0xff,
};
#define FC_DEF_E_D_TOV 2000UL
#define FC_DEF_R_A_TOV 10000UL
#endif
```