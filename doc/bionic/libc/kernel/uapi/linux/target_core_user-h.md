Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding and Context:**

* **File Name and Location:** `bionic/libc/kernel/uapi/linux/target_core_user.handroid`. This immediately tells us several things:
    * `bionic`: It's part of Android's core C library.
    * `libc`:  Implies it's related to system-level interfaces.
    * `kernel/uapi`:  Crucially indicates it's a *user-space* interface to the Linux kernel. The `uapi` directory is specifically for headers that define structures and constants used for communication between user-space programs and the kernel.
    * `linux`: Confirms it's a Linux-specific interface.
    * `target_core_user.handroid`: This suggests it's related to the Linux Target Core subsystem (used for exposing storage devices) and might have Android-specific extensions or configurations ("handroid").

* **Auto-generated Comment:** The "auto-generated" comment is a strong indicator that manual modification is discouraged. This means the content is likely derived from a more authoritative source, probably within the Linux kernel source.

* **Include Headers:**  `linux/types.h` and `linux/uio.h` are standard Linux kernel headers, suggesting basic data types and I/O vector operations are involved.

**2. Dissecting the Definitions:**

The core of the analysis involves systematically going through each macro, structure, and enum.

* **Macros (`#define`):**
    * `TCMU_VERSION`, `TCMU_MAILBOX_VERSION`:  Versioning information, important for compatibility.
    * `ALIGN_SIZE`: Defines memory alignment, crucial for performance and sometimes correctness.
    * `TCMU_MAILBOX_FLAG_*`: Bit flags for capabilities, suggesting feature negotiation or indication.

* **Structures (`struct`):**  These are the key data structures used for communication.
    * `tcmu_mailbox`:  Looks like a control structure for the communication channel. The `cmdr_off`, `cmdr_size`, `cmd_head`, `cmd_tail` members strongly suggest a command queue or ring buffer mechanism. The `__aligned__` attribute reinforces the `ALIGN_SIZE` macro. The `__packed__` attribute means no padding is inserted between members, ensuring the structure's binary layout is precise.
    * `tcmu_cmd_entry_hdr`: A header for command entries, containing length, opcode, and flags.
    * `tcmu_cmd_entry`:  Represents a single command. The `union` is interesting – it means a command can either be a request (`req`) or a response (`rsp`). The `req` part involves I/O vectors (`iovec`), suggesting scatter/gather I/O. The `rsp` part has status and a sense buffer (for SCSI error information). The `__DECLARE_FLEX_ARRAY` is a common Linux kernel idiom for a variable-length array at the end of a structure.
    * `tcmu_tmr_entry`:  Seems to represent Task Management Request (TMR) entries, used for controlling or resetting storage targets. The defined `TCMU_TMR_*` values enumerate the different types of TMRs. The `cmd_ids` looks like an array of command IDs associated with the TMR.

* **Enums (`enum`):** These define sets of related constants.
    * `tcmu_opcode`:  Specifies the type of operation (PAD, CMD, TMR).
    * `tcmu_genl_cmd`:  Appears related to Generic Netlink commands, likely used for asynchronous notifications or control plane communication related to device management.
    * `tcmu_genl_attr`: Attributes associated with the Generic Netlink commands, providing details like device information, status, etc.

**3. Identifying Functionality and Android Relevance:**

Based on the structure names and members, the core functionality is clearly related to interacting with a storage target (likely via the Linux Target Core subsystem).

* **Key Features:**
    * **Command Submission:** `tcmu_mailbox`, `tcmu_cmd_entry` indicate a mechanism for sending commands to the target.
    * **Response Handling:** The `rsp` part of `tcmu_cmd_entry` is for receiving responses.
    * **Task Management:** `tcmu_tmr_entry` handles asynchronous operations like aborting or resetting tasks.
    * **Device Management:** `tcmu_genl_cmd` and `tcmu_genl_attr` point to a control interface for managing storage devices (adding, removing, reconfiguring).

* **Android Relevance:** Android uses the Linux kernel extensively for storage. This header likely defines the interface used by user-space components (possibly in the Android framework or NDK) to interact with software-defined storage targets, such as:
    * **iSCSI targets:**  Android devices might act as clients to iSCSI targets.
    * **FUSE filesystems:**  While not directly target core, FUSE also involves user-space/kernel interaction for storage.
    * **Virtual devices:** Android might use target core to create virtual block devices.

**4. Addressing Specific Questions from the Prompt:**

* **libc Function Implementation:** This header *defines data structures*, not libc functions. The *implementation* of functions that use these structures would be in other parts of bionic (or potentially kernel modules). Therefore, a detailed explanation of libc function implementation is not applicable here.

* **Dynamic Linker:** The header itself doesn't directly involve the dynamic linker. However, if a user-space library or application uses these structures, the dynamic linker would be involved in loading that library. A sample SO layout and linking process would be generic Android SO loading, not specific to this header.

* **Logical Reasoning, Assumptions, Inputs/Outputs:**  We can infer the *intent* and *potential use cases* based on the structures. For example, we can assume a process would write a command into the `tcmu_mailbox`, the kernel would process it, and the response would be written back. However, without seeing the actual code that *uses* these structures, concrete input/output examples are speculative.

* **User/Programming Errors:**
    * **Incorrect structure packing:**  Forgetting `__attribute__((__packed__))` could lead to incorrect data interpretation.
    * **Mismatched versions:**  Using incompatible versions of the mailbox protocol could cause errors.
    * **Incorrect flag usage:**  Setting incorrect flags might lead to unexpected behavior.
    * **Buffer overflows:** Incorrectly calculating buffer sizes when dealing with I/O vectors could be a security risk.

* **Android Framework/NDK Path:**  This is harder without specific code examples. The thought process would be:
    1. **Identify potential user-space components:** What parts of Android deal with storage at a low level? (Vold, storage daemons, maybe even some framework services).
    2. **Search for usage:** Look for these structure names (`tcmu_mailbox`, etc.) in the Android source code.
    3. **Trace calls:** Once usage is found, trace the call flow backward to see how data gets to this point.

* **Frida Hook Example:** The Frida example demonstrates how to intercept calls involving these structures. The key is to identify a function that *takes* or *returns* these structures or their members as arguments.

**5. Structuring the Response:**

Finally, the information needs to be organized clearly, addressing each point in the prompt logically and providing relevant examples and explanations where possible. Using headings, bullet points, and code blocks enhances readability.

This structured approach, combining understanding the context, dissecting the definitions, inferring functionality, and addressing the specific questions, leads to a comprehensive analysis of the provided C header file.
这是一个定义了用户空间与 Linux Kernel Target Core (TCMU) 子系统交互接口的 C 头文件。Target Core 是 Linux 内核中用于创建软件定义的存储目标的框架。这个头文件定义了用于发送命令、接收响应以及管理这些存储目标的各种数据结构和常量。因为文件名包含 `handroid`，这表明它是 Android 对 Target Core 用户接口的定制或扩展。

**功能列举:**

1. **定义了与 Linux Kernel TCMU 子系统通信的数据结构:**  这是核心功能。它定义了用户空间程序如何向内核发送命令，以及内核如何向用户空间返回响应。
2. **定义了 TCMU 邮箱结构 (`tcmu_mailbox`):**  该结构体用于管理命令队列，包含版本信息、标志、命令读写指针等。
3. **定义了 TCMU 命令条目结构 (`tcmu_cmd_entry`):**  用于封装具体的 SCSI 命令或数据传输请求。它包含请求部分（`req`）用于发送命令，以及响应部分（`rsp`）用于接收执行结果和状态信息。
4. **定义了 TCMU 任务管理请求条目结构 (`tcmu_tmr_entry`):** 用于发送任务管理请求，例如中止任务、清除队列、重置 LUN 等。
5. **定义了 TCMU 操作码枚举 (`tcmu_opcode`):**  指定了操作类型，例如普通命令、任务管理请求等。
6. **定义了与 Generic Netlink 相关的枚举 (`tcmu_genl_cmd`, `tcmu_genl_attr`):**  这允许内核异步地通知用户空间关于设备添加、删除、重配置等事件。
7. **定义了各种标志和常量:**  例如，用于指示功能支持 (`TCMU_MAILBOX_FLAG_*`)，用户空间标志 (`TCMU_UFLAG_*`)，和缓冲区大小 (`TCMU_SENSE_BUFFERSIZE`)。

**与 Android 功能的关系及举例说明:**

此文件与 Android 的存储功能密切相关。Android 可能使用 Target Core 来实现以下功能：

* **USB Mass Storage (UMS) 或 Media Transfer Protocol (MTP):** 当 Android 设备作为 USB 存储设备连接到电脑时，Target Core 可以用来模拟这个存储设备。用户空间程序可以使用这里定义的结构体与内核中的 Target Core 通信，处理来自主机的 SCSI 命令，并将设备的内部存储暴露出去。
* **软件定义的存储:** Android 可能会使用 Target Core 来创建虚拟的存储设备，这些设备可能由文件、网络存储或其他后端提供支持。例如，某些虚拟化或容器化方案可能会用到。
* **存储性能分析和调试:** 开发者可能通过与 Target Core 交互来监控和分析存储设备的行为。

**举例说明 (USB Mass Storage):**

假设 Android 设备作为 USB Mass Storage 连接到 PC。

1. PC 发送一个 SCSI 读取命令给 Android 设备。
2. Android 内核的 USB 子系统接收到该命令。
3. 内核的 Target Core 子系统将该 SCSI 命令封装成一个 `tcmu_cmd_entry` 结构体。
4. 用户空间的一个守护进程（可能由 Android Framework 启动）会读取 TCMU 邮箱 (`tcmu_mailbox`) 中的命令队列。
5. 该守护进程解析 `tcmu_cmd_entry` 结构体，提取出 SCSI 读取命令的细节，例如 LUN、起始扇区、读取长度等。
6. 守护进程访问 Android 设备的实际存储介质，读取相应的数据。
7. 守护进程创建一个 `tcmu_cmd_entry` 响应结构体，包含读取到的数据和状态信息。
8. 该响应被写回 TCMU 邮箱。
9. 内核的 Target Core 子系统读取响应，并将数据通过 USB 发送回 PC。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要注意的是，这个文件本身 *不是* libc 函数的实现，而是定义了内核接口的数据结构。**  libc 函数，例如 `read()`, `write()`, `ioctl()` 等，可能会被用于与 Target Core 通信，但这些函数的具体实现位于 bionic 的其他源文件中。

* **`read()`/`write()`:** 用户空间程序可能使用 `read()` 系统调用从 TCMU 邮箱的命令队列中读取新的命令，或者使用 `write()` 系统调用将响应写回邮箱。这些系统调用会触发内核态的相应处理函数，涉及设备驱动和内存管理。
* **`ioctl()`:**  `ioctl()` 系统调用可能被用于执行与 TCMU 设备相关的控制操作，例如设备添加、删除、配置等。这会调用内核中 TCMU 驱动的 `ioctl` 实现。
* **涉及 `linux/uio.h` 的功能 (例如在 `tcmu_cmd_entry` 中使用的 `iovec`):** `iovec` 结构体用于描述分散/聚集 I/O 操作。这意味着数据可以从多个不连续的内存缓冲区读取，或者写入到多个不连续的缓冲区。libc 中的相关函数，如 `readv()` 和 `writev()`, 会使用 `iovec` 结构体来执行这些操作。内核会遍历 `iovec` 数组，依次处理每个缓冲区。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker。但是，如果用户空间的库或应用程序使用了这些结构体来与内核 Target Core 交互，那么 dynamic linker 会负责加载这些库。

**so 布局样本 (通用 Android shared library):**

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x...
  Start of program headers:          64 (bytes into file)
  Start of section headers:          ...(bytes into file)
  Flags:                             0x...
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         ...
  Size of section headers:           64 (bytes)
  Number of section headers:         ...
  Section header string table index: ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags  Align
  LOAD           0x0000000000000000 0x...              0x...              0x...              0x...              R E    0x1000
  LOAD           0x...              0x...              0x...              0x...              0x...              RWE    0x1000
  DYNAMIC        0x...              0x...              0x...              0x...              0x...              RW     0x8
  NOTE           0x...              0x...              0x...              0x...              0x...              R      0x8
  ...

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]
  [ 1] .init            PROGBITS         ...              ...
       ...              ...              AX       0     0     8
  [ 2] .text            PROGBITS         ...              ...
       ...              ...              AX       0     0     16
  [ 3] .fini            PROGBITS         ...              ...
       ...              ...              AX       0     0     8
  [ 4] .rodata          PROGBITS         ...              ...
       ...              ...              A        0     0     8
  [ 5] .data            PROGBITS         ...              ...
       ...              ...              WA       0     0     8
  [ 6] .bss             NOBITS           ...              ...
       ...              ...              WA       0     0     8
  [ 7] .dynamic         DYNAMIC          ...              ...
       ...              ...              WA       6     0     8
  [ 8] .dynsym          DYNSYM           ...              ...
       ...              ...              A        9     1     8
  [ 9] .dynstr          STRTAB           ...              ...
       ...              ...              MSHA     0     0     1
  [10] .hash            HASH             ...              ...
       ...              ...              A        8     0     8
  [11] .plt             PROGBITS         ...              ...
       ...              ...              AX       0     0     16
  [12] .got             PROGBITS         ...              ...
       ...              ...              AW       0     0     8
  ...
```

**链接的处理过程:**

1. **加载:** 当一个使用了包含这些结构体的库的进程启动时，Android 的 `/system/bin/linker64` (或 `linker`) 会被调用。
2. **解析 ELF 头:** linker 解析 shared library (SO) 的 ELF 头，获取加载信息，如程序头表的位置和大小。
3. **加载段 (Segments):**  根据程序头表的指示，linker 将 SO 的各个段（如 `.text`, `.rodata`, `.data`）加载到内存中的指定地址。
4. **处理依赖:** linker 检查 SO 的 `DYNAMIC` 段，查找其依赖的其他 SO 库。
5. **递归加载依赖:** linker 递归地加载所有依赖的 SO 库。
6. **符号解析 (Symbol Resolution):** linker 解析 SO 的 `.dynsym` 和 `.dynstr` 段，找到 SO 需要的外部符号（例如，libc 中的函数）。
7. **重定位 (Relocation):** linker 修改 SO 中对外部符号的引用，将其指向内存中实际加载的符号地址。这通常涉及到修改 `.got` (Global Offset Table) 和 `.plt` (Procedure Linkage Table)。
8. **执行:**  加载和链接完成后，系统将控制权转移到应用程序的入口点。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要发送一个 SCSI 读命令到 Target Core。

**假设输入:**

* **命令类型:** SCSI 读命令
* **LUN:** 0
* **起始 LBA:** 100
* **传输长度:** 512 字节
* **用户空间缓冲区地址:** `0x12345678`
* **用户空间缓冲区大小:** 512 字节

**逻辑推理:**

1. 用户空间程序会填充一个 `tcmu_cmd_entry` 结构体。
2. `hdr.len_op` 会被设置为命令的总长度加上操作码的大小 (`sizeof(tcmu_cmd_entry) | TCMU_OP_CMD`).
3. `hdr.cmd_id` 会被分配一个唯一的命令 ID。
4. `req.iov_cnt` 会设置为 1。
5. `req.iov[0].iov_base` 会设置为用户空间缓冲区地址 `0x12345678`。
6. `req.iov[0].iov_len` 会设置为 512。
7. `req.cdb_off` 会指向包含 SCSI 命令描述符块 (CDB) 的内存区域。CDB 中会编码读取命令的 LUN、起始 LBA 和传输长度。

**假设输出 (内核处理后):**

1. 内核的 Target Core 驱动程序会接收到 `tcmu_cmd_entry` 结构体。
2. 驱动程序会解析 CDB，提取出读取请求的信息。
3. 驱动程序会从相应的存储设备读取 512 字节的数据，存储到内核缓冲区。
4. 驱动程序会创建一个 `tcmu_cmd_entry` 响应结构体。
5. `rsp.scsi_status` 会被设置为 0 (表示成功) 或其他非零值 (表示错误)。
6. 如果成功，读取到的数据可能通过 DMA 或其他机制复制到用户空间提供的缓冲区 `0x12345678`（但这通常发生在系统调用层面，而不是在这个结构体直接定义的范围内）。或者，`rsp` 可能会包含指向内核缓冲区的指针，用户空间需要通过其他方式访问。
7. 如果发生错误，`rsp.sense_buffer` 会包含 SCSI Sense 数据，提供更详细的错误信息。
8. 响应结构体会被写回 TCMU 邮箱。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **缓冲区溢出:** 在填充 `tcmu_cmd_entry` 结构体时，如果没有正确计算缓冲区大小，可能会导致溢出，覆盖其他内存区域。例如，`iov` 数组的大小是动态的，需要仔细管理。
2. **错误的标志设置:**  不正确地设置 `uflags` 可能会导致内核以错误的方式处理命令。例如，错误地设置 `TCMU_UFLAG_READ_LEN` 可能会导致内核在响应中返回错误的读取长度。
3. **竞争条件:** 如果多个用户空间线程或进程同时访问 TCMU 邮箱，可能会发生竞争条件，导致数据损坏或程序崩溃。需要适当的同步机制（例如互斥锁）。
4. **内存泄漏:** 如果在分配和释放与 TCMU 命令相关的内存时出现错误，可能会导致内存泄漏。
5. **不正确的结构体对齐或填充:** 虽然这里使用了 `__attribute__((__packed__))`, 但如果用户空间和内核对结构体的理解不一致（例如，在不同的架构或内核版本上），可能会导致数据解析错误。
6. **未处理错误:** 用户空间程序应该检查内核返回的响应状态 (`rsp.scsi_status`) 和 Sense 数据，并妥善处理错误情况。忽略错误可能导致数据不一致或其他问题。
7. **版本不兼容:** 如果用户空间程序使用的 TCMU 接口版本与内核版本不兼容，可能会导致通信失败。`TCMU_VERSION` 和 `TCMU_MAILBOX_VERSION` 的匹配很重要。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

到达这个头文件的路径通常涉及 Android 的存储栈。

1. **Android Framework (Java 层):**  应用程序通常通过 StorageManager 或 MediaStore 等 Android Framework API 与存储交互。
2. **System Server (Java/Native):**  Framework API 的请求会被传递到 System Server 中的服务，例如 `vold` (Volume Daemon)。`vold` 是一个 native 守护进程，负责管理 Android 的存储设备。
3. **Native 代码 (C/C++):** `vold` 或其他存储相关的 native 组件 (例如，实现 MTP 功能的组件) 会使用底层的 Linux 系统调用与内核交互。
4. **系统调用:** 这些 native 代码会使用诸如 `read()`, `write()`, `ioctl()` 等系统调用来与内核中的 Target Core 子系统进行通信。
5. **TCMU 驱动:** 内核中的 Target Core 驱动程序会处理这些系统调用，并使用这里定义的 `tcmu_mailbox`, `tcmu_cmd_entry` 等结构体来接收和发送命令和响应。

**Frida Hook 示例:**

假设你想 hook 用户空间程序发送 SCSI 读取命令到 Target Core 的过程。你可以 hook 一个发送命令的函数，该函数会填充 `tcmu_cmd_entry` 结构体。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

# 目标进程的名称或 PID
package_name = "com.example.my_storage_app"  # 替换为实际进程名

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
// 假设目标进程中有一个名为 send_tcmu_command 的函数，
// 该函数接收一个指向 tcmu_cmd_entry 结构体的指针作为参数
Interceptor.attach(Module.findExportByName(null, "send_tcmu_command"), {
    onEnter: function(args) {
        console.log("[*] send_tcmu_command called!");
        const cmd_entry_ptr = ptr(args[0]); // 获取 tcmu_cmd_entry 结构体的指针

        // 读取 tcmu_cmd_entry 结构体的成员
        const hdr_len_op = cmd_entry_ptr.readU32();
        const hdr_cmd_id = cmd_entry_ptr.add(4).readU16();
        const opcode = hdr_len_op & 0x7; // 提取操作码

        console.log("  [*] hdr.len_op:", hdr_len_op);
        console.log("  [*] hdr.cmd_id:", hdr_cmd_id);
        console.log("  [*] Opcode:", opcode);

        if (opcode === 1) { // TCMU_OP_CMD
            console.log("  [*] This is a TCMU_OP_CMD");
            const iov_cnt = cmd_entry_ptr.add(8).readU32();
            const cdb_off = cmd_entry_ptr.add(24).readU64();
            console.log("  [*] req.iov_cnt:", iov_cnt);
            console.log("  [*] req.cdb_off:", cdb_off);

            // 可以进一步读取 iovec 数组和 CDB 的内容
        }
    },
    onLeave: function(retval) {
        console.log("  [*] send_tcmu_command returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**解释 Frida Hook 示例:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 进程。
2. **`Interceptor.attach(...)`:**  Hook 目标进程中的 `send_tcmu_command` 函数。你需要替换 `send_tcmu_command` 为实际被调用的函数名。可以使用 `frida-ps -U` 找到目标进程，然后使用 `frida-trace -U -n <进程名> -I "send*"` 或其他模式来查找可能的函数名。
3. **`onEnter`:**  在目标函数执行前被调用。`args` 数组包含了函数的参数。假设第一个参数是指向 `tcmu_cmd_entry` 结构体的指针。
4. **读取结构体成员:** 使用 `ptr(args[0])` 获取指针，然后使用 `readU32()`, `readU16()`, `readU64()` 等方法读取结构体的成员。需要根据结构体的布局计算偏移量。
5. **检查操作码:** 判断是否是 `TCMU_OP_CMD`。
6. **读取请求信息:** 如果是命令，则读取 `iov_cnt` 和 `cdb_off` 等信息。
7. **`onLeave`:** 在目标函数执行后被调用，可以查看返回值。

**注意:**

* 你需要找到实际负责发送 TCMU 命令的函数名，这可能需要一些逆向分析或动态调试。
* 结构体的布局和成员可能会因 Android 版本和内核版本而异。
*  可能需要 root 权限才能 attach 到目标进程。

通过 Frida hook，你可以动态地观察用户空间程序如何构造和发送 TCMU 命令，从而深入理解 Android 存储栈的运作方式。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/target_core_user.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __TARGET_CORE_USER_H
#define __TARGET_CORE_USER_H
#include <linux/types.h>
#include <linux/uio.h>
#define TCMU_VERSION "2.0"
#define TCMU_MAILBOX_VERSION 2
#define ALIGN_SIZE 64
#define TCMU_MAILBOX_FLAG_CAP_OOOC (1 << 0)
#define TCMU_MAILBOX_FLAG_CAP_READ_LEN (1 << 1)
#define TCMU_MAILBOX_FLAG_CAP_TMR (1 << 2)
#define TCMU_MAILBOX_FLAG_CAP_KEEP_BUF (1 << 3)
struct tcmu_mailbox {
  __u16 version;
  __u16 flags;
  __u32 cmdr_off;
  __u32 cmdr_size;
  __u32 cmd_head;
  __u32 cmd_tail __attribute__((__aligned__(ALIGN_SIZE)));
} __attribute__((__packed__));
enum tcmu_opcode {
  TCMU_OP_PAD = 0,
  TCMU_OP_CMD,
  TCMU_OP_TMR,
};
struct tcmu_cmd_entry_hdr {
  __u32 len_op;
  __u16 cmd_id;
  __u8 kflags;
#define TCMU_UFLAG_UNKNOWN_OP 0x1
#define TCMU_UFLAG_READ_LEN 0x2
#define TCMU_UFLAG_KEEP_BUF 0x4
  __u8 uflags;
} __attribute__((__packed__));
#define TCMU_OP_MASK 0x7
#define TCMU_SENSE_BUFFERSIZE 96
struct tcmu_cmd_entry {
  struct tcmu_cmd_entry_hdr hdr;
  union {
    struct {
      __u32 iov_cnt;
      __u32 iov_bidi_cnt;
      __u32 iov_dif_cnt;
      __u64 cdb_off;
      __u64 __pad1;
      __u64 __pad2;
      __DECLARE_FLEX_ARRAY(struct iovec, iov);
    } req;
    struct {
      __u8 scsi_status;
      __u8 __pad1;
      __u16 __pad2;
      __u32 read_len;
      char sense_buffer[TCMU_SENSE_BUFFERSIZE];
    } rsp;
  };
} __attribute__((__packed__));
struct tcmu_tmr_entry {
  struct tcmu_cmd_entry_hdr hdr;
#define TCMU_TMR_UNKNOWN 0
#define TCMU_TMR_ABORT_TASK 1
#define TCMU_TMR_ABORT_TASK_SET 2
#define TCMU_TMR_CLEAR_ACA 3
#define TCMU_TMR_CLEAR_TASK_SET 4
#define TCMU_TMR_LUN_RESET 5
#define TCMU_TMR_TARGET_WARM_RESET 6
#define TCMU_TMR_TARGET_COLD_RESET 7
#define TCMU_TMR_LUN_RESET_PRO 128
  __u8 tmr_type;
  __u8 __pad1;
  __u16 __pad2;
  __u32 cmd_cnt;
  __u64 __pad3;
  __u64 __pad4;
  __u16 cmd_ids[];
} __attribute__((__packed__));
#define TCMU_OP_ALIGN_SIZE sizeof(__u64)
enum tcmu_genl_cmd {
  TCMU_CMD_UNSPEC,
  TCMU_CMD_ADDED_DEVICE,
  TCMU_CMD_REMOVED_DEVICE,
  TCMU_CMD_RECONFIG_DEVICE,
  TCMU_CMD_ADDED_DEVICE_DONE,
  TCMU_CMD_REMOVED_DEVICE_DONE,
  TCMU_CMD_RECONFIG_DEVICE_DONE,
  TCMU_CMD_SET_FEATURES,
  __TCMU_CMD_MAX,
};
#define TCMU_CMD_MAX (__TCMU_CMD_MAX - 1)
enum tcmu_genl_attr {
  TCMU_ATTR_UNSPEC,
  TCMU_ATTR_DEVICE,
  TCMU_ATTR_MINOR,
  TCMU_ATTR_PAD,
  TCMU_ATTR_DEV_CFG,
  TCMU_ATTR_DEV_SIZE,
  TCMU_ATTR_WRITECACHE,
  TCMU_ATTR_CMD_STATUS,
  TCMU_ATTR_DEVICE_ID,
  TCMU_ATTR_SUPP_KERN_CMD_REPLY,
  __TCMU_ATTR_MAX,
};
#define TCMU_ATTR_MAX (__TCMU_ATTR_MAX - 1)
#endif

"""

```