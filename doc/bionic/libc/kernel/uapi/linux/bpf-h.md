Response:
Let's break down the thought process for analyzing this C header file and generating the detailed explanation.

**1. Initial Understanding and Goal:**

The request is to understand the functionality of the provided C header file (`bpf.h`), which is part of Android's Bionic library and specifically resides within the kernel UAPI (User API) for Linux BPF (Berkeley Packet Filter). The key is to explain its purpose, relate it to Android, dissect individual components, and cover aspects like dynamic linking, error handling, and how Android utilizes this interface. The request also asks for a summary as the first part.

**2. Deconstructing the File:**

The first step is to recognize the core purpose of the file. The comments at the top clearly state it's an auto-generated file related to the Linux kernel's BPF functionality. This immediately tells us it's *not* about general Android libc functionality, but specifically the interface that Android uses to interact with the kernel's BPF system.

**3. Identifying Key Concepts:**

Scanning the file reveals several recurring themes and data structures:

* **BPF Opcodes and Instructions:**  The `#define` statements like `BPF_JMP32`, `BPF_ALU64`, and the `bpf_insn` struct immediately point to the instruction set of the BPF virtual machine.
* **BPF Maps:**  Structures like `bpf_lpm_trie_key`, `bpf_cgroup_storage_key`, and enums like `bpf_map_type` suggest a key-value store mechanism within BPF.
* **BPF Programs:** Enums like `bpf_prog_type` and the `BPF_PROG_LOAD` command indicate the ability to load and manage BPF programs.
* **BPF Commands:** The `bpf_cmd` enum lists the various operations that can be performed via the `syscall`.
* **BPF Attach Types and Link Types:** These enums (`bpf_attach_type`, `bpf_link_type`) reveal how BPF programs are attached to different kernel events or functionalities.
* **BPF Attributes:** The large `bpf_attr` union is the central structure for passing arguments to the BPF system call.
* **BPF Helper Functions:** The `bpf_func_id` enum and the extensive `___BPF_FUNC_MAPPER` macro define the functions that BPF programs can call.
* **BPF Context Structures:** Structures like `__sk_buff`, `xdp_md`, and `bpf_sock` represent the data that BPF programs operate on.

**4. Functionality Deduction:**

Based on these key concepts, we can deduce the main functions of this header file:

* **Defining the BPF ABI:** It establishes the Application Binary Interface (ABI) for interacting with the Linux BPF subsystem. This includes data structures, constants, and enumerations used in system calls related to BPF.
* **Enabling BPF Program Definition:** It provides the `bpf_insn` structure to define the instructions of a BPF program.
* **Facilitating BPF Map Management:** It defines structures and commands for creating, accessing, and managing BPF maps, which are used for storing and sharing data between BPF programs and the kernel/userspace.
* **Supporting BPF Program Lifecycle Management:** It includes commands for loading, attaching, detaching, and testing BPF programs.
* **Defining BPF Hook Points:** The attach types and link types specify where BPF programs can be hooked into the kernel.
* **Exposing BPF Helper Functions:**  It lists the helper functions that BPF programs can invoke to interact with the kernel.

**5. Relating to Android:**

The crucial connection to Android is that this header file defines the *interface* that Android's BPF tools and libraries (likely within the NDK) use to leverage the Linux kernel's BPF functionality. Android, being built on the Linux kernel, can utilize BPF for various purposes like networking, security, and performance monitoring.

* **Examples:**  Traffic shaping, network monitoring, security policy enforcement, performance analysis.

**6. Dissecting Individual Components:**

For each major structure, enum, and macro, a detailed explanation is required. This involves:

* **Stating its Purpose:** What does this specific component represent?
* **Explaining its Members:**  What are the individual fields or values, and what do they mean?
* **Providing Context:** How is this component used within the larger BPF framework?

**7. Addressing Dynamic Linking:**

Since the file is within `bionic`, the dynamic linker aspect needs to be considered. However, this *specific* header file doesn't directly involve dynamic linking in the traditional sense of linking against shared libraries. Instead, it defines the *interface* for a kernel feature. The linking happens conceptually when Android's userspace BPF libraries make system calls that the kernel interprets based on this ABI.

* **SO Layout Sample (Conceptual):**  The SO would contain code that uses the structures and constants defined in this header to construct BPF commands and interact with the kernel.
* **Linking Process (Conceptual):**  The userspace library uses the system call interface, which relies on the kernel's understanding of the BPF ABI defined here.

**8. Handling Errors and Usage Mistakes:**

This involves thinking about common errors when programming with BPF:

* **Invalid Opcodes or Instructions:**  Using incorrect BPF instructions.
* **Incorrect Map Types or Configurations:**  Mismatched key/value sizes, exceeding max entries.
* **Invalid Program Types or Attach Points:**  Trying to attach a program to an incompatible event.
* **Security Issues:**  BPF can be powerful, so incorrect usage can lead to vulnerabilities.

**9. Tracing the Path from Framework/NDK:**

This requires understanding the layers of Android:

* **Android Framework:** High-level Java APIs.
* **NDK (Native Development Kit):** C/C++ libraries for interacting with lower-level features.
* **Bionic:** Android's C library, providing the necessary system call wrappers.
* **Linux Kernel:** The core operating system with the BPF implementation.

The path involves the framework (if a BPF-related API exists there), the NDK (which would contain the C/C++ BPF libraries), Bionic (which handles the system call), and finally the kernel.

**10. Frida Hook Example:**

A Frida hook needs to target the `syscall` function with the correct BPF command number to intercept BPF interactions. Showing how to examine the `bpf_attr` structure is essential.

**11. Iteration and Refinement:**

Throughout the process, there's likely to be iteration. For example, realizing that the dynamic linking aspect is more conceptual in this case, or needing to research specific BPF concepts to provide accurate explanations.

**12. Structuring the Output:**

Finally, organizing the information logically is crucial. Starting with a summary, then going into detailed explanations of each area, covering the Android connection, and addressing the other specific points in the request makes the explanation clear and comprehensive.
好的，让我们来分析一下 `bionic/libc/kernel/uapi/linux/bpf.handroid` 这个头文件 (`bpf.h`) 的功能。

**文件功能归纳（第一部分）：**

这个 `bpf.h` 头文件的主要功能是**定义了 Linux 内核 BPF (Berkeley Packet Filter) 子系统的用户空间 API (UAPI) 的各种常量、数据结构和枚举类型**。它充当了用户空间程序（例如 Android 上的应用程序或守护进程）与 Linux 内核中 BPF 功能进行交互的桥梁。

具体来说，它定义了：

* **BPF 指令集:**  定义了 BPF 虚拟机可以执行的各种指令的操作码（例如 `BPF_JMP32`, `BPF_ALU64`）。
* **BPF 寄存器:**  定义了 BPF 虚拟机中可用的寄存器（例如 `BPF_REG_0` 到 `BPF_REG_10`）。
* **BPF 指令结构体 (`bpf_insn`)**:  定义了表示单个 BPF 指令的结构，包括操作码、寄存器和立即数。
* **BPF Map 相关结构体和枚举:** 定义了用于创建和操作 BPF Map 的结构体（例如 `bpf_lpm_trie_key`，`bpf_cgroup_storage_key`）和类型（例如 `bpf_map_type`）。BPF Map 是一种内核数据结构，用于在 BPF 程序和内核空间或用户空间之间共享数据。
* **BPF 命令枚举 (`bpf_cmd`)**:  定义了可以传递给 `syscall` 系统调用的各种 BPF 操作命令，例如创建 Map (`BPF_MAP_CREATE`)、加载程序 (`BPF_PROG_LOAD`)、附加程序 (`BPF_PROG_ATTACH`) 等。
* **BPF 程序类型枚举 (`bpf_prog_type`)**:  定义了不同类型的 BPF 程序，例如用于网络包过滤 (`BPF_PROG_TYPE_SOCKET_FILTER`)、内核探针 (`BPF_PROG_TYPE_KPROBE`) 等。
* **BPF 附加类型枚举 (`bpf_attach_type`)**:  定义了 BPF 程序可以附加到的不同内核事件或功能点。
* **BPF Link 类型枚举 (`bpf_link_type`)**: 定义了用于将 BPF 程序连接到内核事件或对象的不同类型的 Link。
* **BPF 性能事件类型枚举 (`bpf_perf_event_type`)**:  定义了可以与 BPF 程序关联的性能事件类型。
* **BPF 标志位 (`#define BPF_F_...`)**:  定义了用于控制 BPF 操作行为的各种标志位。
* **BPF 助手函数 ID 枚举 (`bpf_func_id`)**: 定义了 BPF 程序可以调用的内核提供的辅助函数的 ID。
* **BPF 返回码枚举 (`bpf_ret_code`)**: 定义了 BPF 程序执行后可能返回的各种代码，例如允许包通过 (`BPF_OK`) 或丢弃包 (`BPF_DROP`)。
* **BPF 上下文结构体 (`__sk_buff`, `xdp_md` 等)**: 定义了 BPF 程序执行时可以访问的上下文信息，例如网络包数据 (`__sk_buff`) 或 XDP 包元数据 (`xdp_md`)。
* **BPF 信息结构体 (`bpf_prog_info`, `bpf_map_info`, `bpf_link_info`)**: 定义了用于获取 BPF 对象（程序、Map、Link）信息的结构体。
* **`bpf_attr` 联合体**:  这是一个核心的联合体，用于在用户空间和内核空间之间传递 BPF 系统调用的参数。它的成员对应于不同的 BPF 命令，并包含执行该命令所需的各种参数。

**与 Android 功能的关系及举例说明：**

虽然这个头文件本身是 Linux 内核的一部分，但由于 Android 基于 Linux 内核，Android 框架和 NDK 可以利用 BPF 的强大功能。

**举例说明:**

1. **网络监控和流量控制:** Android 可以使用 BPF 程序来监控网络流量，例如统计特定应用程序的网络使用情况，或者根据自定义规则来控制网络流量的转发和丢弃。例如，可以使用 `BPF_PROG_TYPE_SOCKET_FILTER` 类型的程序附加到 socket 上，分析或修改网络包。
2. **安全增强:** BPF 可以用于实现更精细的安全策略。例如，可以使用 `BPF_PROG_TYPE_CGROUP_SKB` 类型的程序附加到 cgroup 上，限制特定进程或进程组的网络访问行为。
3. **性能分析和跟踪:** Android 可以利用 BPF 的跟踪能力来收集内核事件和应用程序行为，进行性能分析和故障排除。例如，可以使用 `BPF_PROG_TYPE_KPROBE` 或 `BPF_PROG_TYPE_TRACEPOINT` 类型的程序来跟踪内核函数的调用或特定的内核事件。
4. **容器化和资源隔离:**  BPF 可以与 cgroup 结合使用，实现更精细的容器资源管理和隔离。例如，可以使用 BPF 程序来限制容器的网络带宽或 CPU 使用率。
5. **Android Runtime (ART) 的优化:**  理论上，BPF 也可以用于监控和优化 ART 的行为，尽管这可能比较复杂。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要注意的是，这个 `bpf.h` 文件本身** **不包含任何 libc 函数的实现代码**。它只是定义了与 Linux 内核 BPF 功能交互所需的接口。

用户空间程序（包括 Android 的 libc）通过 **`syscall` 系统调用** 与内核的 BPF 子系统进行交互。 libc 提供的与 BPF 相关的函数（例如 `bpf()` 函数，虽然在这个头文件中没有直接定义，但会使用这里定义的常量和结构体）实际上是对 `syscall` 的封装。

当用户空间的程序调用类似 `bpf(BPF_MAP_CREATE, ...)` 的函数时，libc 会将这些参数打包成 `bpf_attr` 结构体，然后通过 `syscall` 系统调用传递给内核。内核接收到系统调用后，会根据 `bpf_cmd` 的值执行相应的 BPF 操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个 `bpf.h` 文件本身不直接涉及 dynamic linker 的功能。它定义的是内核接口。

然而，用户空间的 BPF 工具或库（例如 Android NDK 中可能提供的 libbpf 的 Android 版本）会被编译成共享库 (`.so` 文件)。这些共享库会使用 `bpf.h` 中定义的接口来与内核交互。

**SO 布局样本 (假设一个名为 libandroidbpf.so 的库):**

```
libandroidbpf.so:
    .interp         # 指向动态链接器的路径
    .note.android.ident
    .note.gnu.build-id
    .dynsym         # 动态符号表
    .symtab         # 符号表
    .gnu.hash       # GNU hash 表
    .gnu.version_r  # 版本依赖信息
    .rela.dyn       # 动态重定位表
    .rela.plt       # PLT 重定位表
    .plt            # 程序链接表 (Procedure Linkage Table)
    .text           # 代码段 (包含使用 bpf() 系统调用的函数)
    .rodata         # 只读数据段
    .data           # 数据段
    .bss            # 未初始化数据段

```

**链接的处理过程:**

1. **编译时:** 使用 NDK 编译 C/C++ 代码时，会包含 `bpf.h` 头文件。编译器会识别其中定义的常量、结构体等。
2. **链接时:**  链接器会将用户代码与所需的库（例如 `libandroidbpf.so`）链接在一起。链接器会解析符号依赖关系，确保用户代码中调用的 `libandroidbpf.so` 中的函数能够正确找到。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载所有需要的共享库。
4. **符号解析:**  动态链接器会解析应用程序和其依赖库之间的符号引用。例如，如果应用程序调用了 `libandroidbpf.so` 中封装 `bpf()` 系统调用的函数，动态链接器会确保这个函数能够被正确调用。
5. **重定位:** 动态链接器会根据库加载的地址来调整代码和数据中的地址引用，确保代码能够正确执行。

**如果做了逻辑推理，请给出假设输入与输出:**

这里的文件主要是定义，不涉及复杂的逻辑推理。但是，当我们使用这些定义去编写 BPF 程序或用户空间工具时，就会涉及到逻辑推理。

**假设输入 (用户空间程序创建 BPF Map):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#define BPF_CALL_SYS(cmd, attr, size) syscall(__NR_bpf, cmd, attr, size)

int main() {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(long long);
    attr.max_entries = 10;

    int fd = BPF_CALL_SYS(BPF_MAP_CREATE, &attr, sizeof(attr));

    if (fd < 0) {
        perror("BPF_MAP_CREATE failed");
        return 1;
    }

    printf("BPF Map created successfully with FD: %d\n", fd);
    close(fd);
    return 0;
}
```

**假设输出:**

如果内核支持 BPF 并且参数正确，程序将输出类似：

```
BPF Map created successfully with FD: 3
```

如果创建失败，例如由于权限问题或内核不支持，程序可能会输出类似：

```
BPF_MAP_CREATE failed: Operation not permitted
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的 BPF 命令或参数:**  例如，尝试使用一个只适用于特定程序类型的命令加载到错误的程序类型，或者提供了不兼容的 `key_size` 或 `value_size` 来创建 Map。
2. **权限不足:**  大多数 BPF 操作需要 root 权限或具有 `CAP_SYS_ADMIN` 能力的进程才能执行。普通应用程序直接调用 BPF 系统调用通常会失败。
3. **内核版本不兼容:**  新的 BPF 功能和命令可能会在较新的内核版本中引入。在旧内核上使用新的 BPF 特性会导致错误。
4. **内存访问错误:**  在 BPF 程序中访问超出边界的内存会导致程序被内核拒绝或崩溃。
5. **BPF 程序逻辑错误:**  编写的 BPF 程序逻辑不正确，导致无法达到预期效果或引入安全漏洞。
6. **忘记关闭 BPF 对象的文件描述符:**  创建的 BPF 对象（例如 Map 或程序）会返回文件描述符。忘记关闭这些描述符可能会导致资源泄漏。
7. **不正确地使用 `bpf_attr` 结构体:**  例如，没有正确初始化结构体，或者为特定的 BPF 命令设置了错误的字段。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android 应用程序不会直接调用 BPF 系统调用。Android Framework 或 NDK 会提供更高层次的抽象来使用 BPF。

**Android Framework 到 BPF 的路径 (示例 - NetworkStatsManager):**

1. **Java Framework API:** Android Framework 提供了 Java API，例如 `NetworkStatsManager`，用于查询网络统计信息。
2. **System Service:** `NetworkStatsManager` 会与 System Server 中的 `NetworkStatsService` 通信。
3. **Native Code in System Server:** `NetworkStatsService` 的某些关键功能可能由 C++ 代码实现。
4. **NDK 库 (可能):** 这些 C++ 代码可能会使用 NDK 提供的库（例如 libbpf 或自己封装的库）来与 BPF 交互。
5. **BPF 系统调用:** NDK 库最终会调用 `syscall(__NR_bpf, ...)` 来执行 BPF 操作。

**NDK 到 BPF 的路径 (示例 - 自定义 BPF 工具):**

1. **NDK C/C++ 代码:** 开发者可以使用 NDK 编写 C/C++ 代码。
2. **libbpf 或自定义封装:** NDK 代码可以使用 libbpf 这样的库来简化 BPF 操作，或者直接使用 `syscall`。
3. **`bpf.h` 头文件:**  libbpf 或自定义代码会包含 `<linux/bpf.h>` 头文件（可能在 NDK 中提供或需要手动包含）。
4. **BPF 系统调用:**  最终通过 `syscall` 与内核的 BPF 子系统通信。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida Hook `syscall` 函数，并检查第一个参数（系统调用号）是否为 `__NR_bpf`，以及第二个参数指向的 `bpf_attr` 结构体的内容。

```python
import frida
import sys

# 获取系统调用号 __NR_bpf (不同的架构可能不同)
# 在 Android 设备上可以使用 getconf syscall bpf
# 假设 __NR_bpf 为 388 (ARM64 上的一个常见值)
BPF_SYSCALL_NUMBER = 388

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print("Process not found")
        sys.exit(1)

    script_code = """
    const BPF_SYSCALL_NUMBER = %d;

    Interceptor.attach(Module.findExportByName(null, "syscall"), {
        onEnter: function(args) {
            const syscall_number = args[0].toInt();
            if (syscall_number === BPF_SYSCALL_NUMBER) {
                console.log("[*] BPF Syscall detected!");
                const cmd = args[1].readU32();
                console.log("[*] BPF Command:", cmd);

                // 读取 bpf_attr 结构体 (需要根据具体的命令和结构体定义来解析)
                // 这里只是一个简单的示例，假设是 BPF_MAP_CREATE
                if (cmd === 0) { // BPF_MAP_CREATE
                    const attrPtr = ptr(args[1]);
                    const map_type = attrPtr.readU32();
                    const key_size = attrPtr.add(4).readU32();
                    const value_size = attrPtr.add(8).readU32();
                    const max_entries = attrPtr.add(12).readU32();
                    console.log("[*] BPF Map Attributes:");
                    console.log("    Map Type:", map_type);
                    console.log("    Key Size:", key_size);
                    console.log("    Value Size:", value_size);
                    console.log("    Max Entries:", max_entries);
                }
            }
        }
    });
    """ % BPF_SYSCALL_NUMBER

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将以上 Python 代码保存为 `frida_bpf_hook.py`。
2. 找到你想要监控的 Android 进程的名称或 PID。
3. 运行 Frida： `frida -U -f <进程名称>` 或 `frida -U <PID>`
4. 在另一个终端运行 Hook 脚本： `python frida_bpf_hook.py <进程名称 or PID>`

当目标进程执行 BPF 系统调用时，Frida 脚本将会拦截并打印相关信息，包括 BPF 命令和部分 `bpf_attr` 结构体的内容。你需要根据具体的 BPF 命令和 `bpf_attr` 联合体的定义，在 Frida 脚本中添加相应的解析代码来查看更详细的参数。

希望以上详细的解释对您有所帮助！

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/bpf.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__
#include <linux/types.h>
#include <linux/bpf_common.h>
#define BPF_JMP32 0x06
#define BPF_ALU64 0x07
#define BPF_DW 0x18
#define BPF_MEMSX 0x80
#define BPF_ATOMIC 0xc0
#define BPF_XADD 0xc0
#define BPF_MOV 0xb0
#define BPF_ARSH 0xc0
#define BPF_END 0xd0
#define BPF_TO_LE 0x00
#define BPF_TO_BE 0x08
#define BPF_FROM_LE BPF_TO_LE
#define BPF_FROM_BE BPF_TO_BE
#define BPF_JNE 0x50
#define BPF_JLT 0xa0
#define BPF_JLE 0xb0
#define BPF_JSGT 0x60
#define BPF_JSGE 0x70
#define BPF_JSLT 0xc0
#define BPF_JSLE 0xd0
#define BPF_JCOND 0xe0
#define BPF_CALL 0x80
#define BPF_EXIT 0x90
#define BPF_FETCH 0x01
#define BPF_XCHG (0xe0 | BPF_FETCH)
#define BPF_CMPXCHG (0xf0 | BPF_FETCH)
enum bpf_cond_pseudo_jmp {
  BPF_MAY_GOTO = 0,
};
enum {
  BPF_REG_0 = 0,
  BPF_REG_1,
  BPF_REG_2,
  BPF_REG_3,
  BPF_REG_4,
  BPF_REG_5,
  BPF_REG_6,
  BPF_REG_7,
  BPF_REG_8,
  BPF_REG_9,
  BPF_REG_10,
  __MAX_BPF_REG,
};
#define MAX_BPF_REG __MAX_BPF_REG
struct bpf_insn {
  __u8 code;
  __u8 dst_reg : 4;
  __u8 src_reg : 4;
  __s16 off;
  __s32 imm;
};
struct bpf_lpm_trie_key {
  __u32 prefixlen;
  __u8 data[0];
};
struct bpf_lpm_trie_key_hdr {
  __u32 prefixlen;
};
struct bpf_lpm_trie_key_u8 {
  union {
    struct bpf_lpm_trie_key_hdr hdr;
    __u32 prefixlen;
  };
  __u8 data[];
};
struct bpf_cgroup_storage_key {
  __u64 cgroup_inode_id;
  __u32 attach_type;
};
enum bpf_cgroup_iter_order {
  BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
  BPF_CGROUP_ITER_SELF_ONLY,
  BPF_CGROUP_ITER_DESCENDANTS_PRE,
  BPF_CGROUP_ITER_DESCENDANTS_POST,
  BPF_CGROUP_ITER_ANCESTORS_UP,
};
union bpf_iter_link_info {
  struct {
    __u32 map_fd;
  } map;
  struct {
    enum bpf_cgroup_iter_order order;
    __u32 cgroup_fd;
    __u64 cgroup_id;
  } cgroup;
  struct {
    __u32 tid;
    __u32 pid;
    __u32 pid_fd;
  } task;
};
enum bpf_cmd {
  BPF_MAP_CREATE,
  BPF_MAP_LOOKUP_ELEM,
  BPF_MAP_UPDATE_ELEM,
  BPF_MAP_DELETE_ELEM,
  BPF_MAP_GET_NEXT_KEY,
  BPF_PROG_LOAD,
  BPF_OBJ_PIN,
  BPF_OBJ_GET,
  BPF_PROG_ATTACH,
  BPF_PROG_DETACH,
  BPF_PROG_TEST_RUN,
  BPF_PROG_RUN = BPF_PROG_TEST_RUN,
  BPF_PROG_GET_NEXT_ID,
  BPF_MAP_GET_NEXT_ID,
  BPF_PROG_GET_FD_BY_ID,
  BPF_MAP_GET_FD_BY_ID,
  BPF_OBJ_GET_INFO_BY_FD,
  BPF_PROG_QUERY,
  BPF_RAW_TRACEPOINT_OPEN,
  BPF_BTF_LOAD,
  BPF_BTF_GET_FD_BY_ID,
  BPF_TASK_FD_QUERY,
  BPF_MAP_LOOKUP_AND_DELETE_ELEM,
  BPF_MAP_FREEZE,
  BPF_BTF_GET_NEXT_ID,
  BPF_MAP_LOOKUP_BATCH,
  BPF_MAP_LOOKUP_AND_DELETE_BATCH,
  BPF_MAP_UPDATE_BATCH,
  BPF_MAP_DELETE_BATCH,
  BPF_LINK_CREATE,
  BPF_LINK_UPDATE,
  BPF_LINK_GET_FD_BY_ID,
  BPF_LINK_GET_NEXT_ID,
  BPF_ENABLE_STATS,
  BPF_ITER_CREATE,
  BPF_LINK_DETACH,
  BPF_PROG_BIND_MAP,
  BPF_TOKEN_CREATE,
  __MAX_BPF_CMD,
};
enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_STACK_TRACE,
  BPF_MAP_TYPE_CGROUP_ARRAY,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LPM_TRIE,
  BPF_MAP_TYPE_ARRAY_OF_MAPS,
  BPF_MAP_TYPE_HASH_OF_MAPS,
  BPF_MAP_TYPE_DEVMAP,
  BPF_MAP_TYPE_SOCKMAP,
  BPF_MAP_TYPE_CPUMAP,
  BPF_MAP_TYPE_XSKMAP,
  BPF_MAP_TYPE_SOCKHASH,
  BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
  BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
  BPF_MAP_TYPE_QUEUE,
  BPF_MAP_TYPE_STACK,
  BPF_MAP_TYPE_SK_STORAGE,
  BPF_MAP_TYPE_DEVMAP_HASH,
  BPF_MAP_TYPE_STRUCT_OPS,
  BPF_MAP_TYPE_RINGBUF,
  BPF_MAP_TYPE_INODE_STORAGE,
  BPF_MAP_TYPE_TASK_STORAGE,
  BPF_MAP_TYPE_BLOOM_FILTER,
  BPF_MAP_TYPE_USER_RINGBUF,
  BPF_MAP_TYPE_CGRP_STORAGE,
  BPF_MAP_TYPE_ARENA,
  __MAX_BPF_MAP_TYPE
};
enum bpf_prog_type {
  BPF_PROG_TYPE_UNSPEC,
  BPF_PROG_TYPE_SOCKET_FILTER,
  BPF_PROG_TYPE_KPROBE,
  BPF_PROG_TYPE_SCHED_CLS,
  BPF_PROG_TYPE_SCHED_ACT,
  BPF_PROG_TYPE_TRACEPOINT,
  BPF_PROG_TYPE_XDP,
  BPF_PROG_TYPE_PERF_EVENT,
  BPF_PROG_TYPE_CGROUP_SKB,
  BPF_PROG_TYPE_CGROUP_SOCK,
  BPF_PROG_TYPE_LWT_IN,
  BPF_PROG_TYPE_LWT_OUT,
  BPF_PROG_TYPE_LWT_XMIT,
  BPF_PROG_TYPE_SOCK_OPS,
  BPF_PROG_TYPE_SK_SKB,
  BPF_PROG_TYPE_CGROUP_DEVICE,
  BPF_PROG_TYPE_SK_MSG,
  BPF_PROG_TYPE_RAW_TRACEPOINT,
  BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
  BPF_PROG_TYPE_LWT_SEG6LOCAL,
  BPF_PROG_TYPE_LIRC_MODE2,
  BPF_PROG_TYPE_SK_REUSEPORT,
  BPF_PROG_TYPE_FLOW_DISSECTOR,
  BPF_PROG_TYPE_CGROUP_SYSCTL,
  BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
  BPF_PROG_TYPE_CGROUP_SOCKOPT,
  BPF_PROG_TYPE_TRACING,
  BPF_PROG_TYPE_STRUCT_OPS,
  BPF_PROG_TYPE_EXT,
  BPF_PROG_TYPE_LSM,
  BPF_PROG_TYPE_SK_LOOKUP,
  BPF_PROG_TYPE_SYSCALL,
  BPF_PROG_TYPE_NETFILTER,
  __MAX_BPF_PROG_TYPE
};
enum bpf_attach_type {
  BPF_CGROUP_INET_INGRESS,
  BPF_CGROUP_INET_EGRESS,
  BPF_CGROUP_INET_SOCK_CREATE,
  BPF_CGROUP_SOCK_OPS,
  BPF_SK_SKB_STREAM_PARSER,
  BPF_SK_SKB_STREAM_VERDICT,
  BPF_CGROUP_DEVICE,
  BPF_SK_MSG_VERDICT,
  BPF_CGROUP_INET4_BIND,
  BPF_CGROUP_INET6_BIND,
  BPF_CGROUP_INET4_CONNECT,
  BPF_CGROUP_INET6_CONNECT,
  BPF_CGROUP_INET4_POST_BIND,
  BPF_CGROUP_INET6_POST_BIND,
  BPF_CGROUP_UDP4_SENDMSG,
  BPF_CGROUP_UDP6_SENDMSG,
  BPF_LIRC_MODE2,
  BPF_FLOW_DISSECTOR,
  BPF_CGROUP_SYSCTL,
  BPF_CGROUP_UDP4_RECVMSG,
  BPF_CGROUP_UDP6_RECVMSG,
  BPF_CGROUP_GETSOCKOPT,
  BPF_CGROUP_SETSOCKOPT,
  BPF_TRACE_RAW_TP,
  BPF_TRACE_FENTRY,
  BPF_TRACE_FEXIT,
  BPF_MODIFY_RETURN,
  BPF_LSM_MAC,
  BPF_TRACE_ITER,
  BPF_CGROUP_INET4_GETPEERNAME,
  BPF_CGROUP_INET6_GETPEERNAME,
  BPF_CGROUP_INET4_GETSOCKNAME,
  BPF_CGROUP_INET6_GETSOCKNAME,
  BPF_XDP_DEVMAP,
  BPF_CGROUP_INET_SOCK_RELEASE,
  BPF_XDP_CPUMAP,
  BPF_SK_LOOKUP,
  BPF_XDP,
  BPF_SK_SKB_VERDICT,
  BPF_SK_REUSEPORT_SELECT,
  BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
  BPF_PERF_EVENT,
  BPF_TRACE_KPROBE_MULTI,
  BPF_LSM_CGROUP,
  BPF_STRUCT_OPS,
  BPF_NETFILTER,
  BPF_TCX_INGRESS,
  BPF_TCX_EGRESS,
  BPF_TRACE_UPROBE_MULTI,
  BPF_CGROUP_UNIX_CONNECT,
  BPF_CGROUP_UNIX_SENDMSG,
  BPF_CGROUP_UNIX_RECVMSG,
  BPF_CGROUP_UNIX_GETPEERNAME,
  BPF_CGROUP_UNIX_GETSOCKNAME,
  BPF_NETKIT_PRIMARY,
  BPF_NETKIT_PEER,
  BPF_TRACE_KPROBE_SESSION,
  __MAX_BPF_ATTACH_TYPE
};
#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
enum bpf_link_type {
  BPF_LINK_TYPE_UNSPEC = 0,
  BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
  BPF_LINK_TYPE_TRACING = 2,
  BPF_LINK_TYPE_CGROUP = 3,
  BPF_LINK_TYPE_ITER = 4,
  BPF_LINK_TYPE_NETNS = 5,
  BPF_LINK_TYPE_XDP = 6,
  BPF_LINK_TYPE_PERF_EVENT = 7,
  BPF_LINK_TYPE_KPROBE_MULTI = 8,
  BPF_LINK_TYPE_STRUCT_OPS = 9,
  BPF_LINK_TYPE_NETFILTER = 10,
  BPF_LINK_TYPE_TCX = 11,
  BPF_LINK_TYPE_UPROBE_MULTI = 12,
  BPF_LINK_TYPE_NETKIT = 13,
  BPF_LINK_TYPE_SOCKMAP = 14,
  __MAX_BPF_LINK_TYPE,
};
#define MAX_BPF_LINK_TYPE __MAX_BPF_LINK_TYPE
enum bpf_perf_event_type {
  BPF_PERF_EVENT_UNSPEC = 0,
  BPF_PERF_EVENT_UPROBE = 1,
  BPF_PERF_EVENT_URETPROBE = 2,
  BPF_PERF_EVENT_KPROBE = 3,
  BPF_PERF_EVENT_KRETPROBE = 4,
  BPF_PERF_EVENT_TRACEPOINT = 5,
  BPF_PERF_EVENT_EVENT = 6,
};
#define BPF_F_ALLOW_OVERRIDE (1U << 0)
#define BPF_F_ALLOW_MULTI (1U << 1)
#define BPF_F_REPLACE (1U << 2)
#define BPF_F_BEFORE (1U << 3)
#define BPF_F_AFTER (1U << 4)
#define BPF_F_ID (1U << 5)
#define BPF_F_LINK BPF_F_LINK
#define BPF_F_STRICT_ALIGNMENT (1U << 0)
#define BPF_F_ANY_ALIGNMENT (1U << 1)
#define BPF_F_TEST_RND_HI32 (1U << 2)
#define BPF_F_TEST_STATE_FREQ (1U << 3)
#define BPF_F_SLEEPABLE (1U << 4)
#define BPF_F_XDP_HAS_FRAGS (1U << 5)
#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)
#define BPF_F_TEST_REG_INVARIANTS (1U << 7)
enum {
  BPF_F_KPROBE_MULTI_RETURN = (1U << 0)
};
enum {
  BPF_F_UPROBE_MULTI_RETURN = (1U << 0)
};
#define BPF_F_NETFILTER_IP_DEFRAG (1U << 0)
#define BPF_PSEUDO_MAP_FD 1
#define BPF_PSEUDO_MAP_IDX 5
#define BPF_PSEUDO_MAP_VALUE 2
#define BPF_PSEUDO_MAP_IDX_VALUE 6
#define BPF_PSEUDO_BTF_ID 3
#define BPF_PSEUDO_FUNC 4
#define BPF_PSEUDO_CALL 1
#define BPF_PSEUDO_KFUNC_CALL 2
enum bpf_addr_space_cast {
  BPF_ADDR_SPACE_CAST = 1,
};
enum {
  BPF_ANY = 0,
  BPF_NOEXIST = 1,
  BPF_EXIST = 2,
  BPF_F_LOCK = 4,
};
enum {
  BPF_F_NO_PREALLOC = (1U << 0),
  BPF_F_NO_COMMON_LRU = (1U << 1),
  BPF_F_NUMA_NODE = (1U << 2),
  BPF_F_RDONLY = (1U << 3),
  BPF_F_WRONLY = (1U << 4),
  BPF_F_STACK_BUILD_ID = (1U << 5),
  BPF_F_ZERO_SEED = (1U << 6),
  BPF_F_RDONLY_PROG = (1U << 7),
  BPF_F_WRONLY_PROG = (1U << 8),
  BPF_F_CLONE = (1U << 9),
  BPF_F_MMAPABLE = (1U << 10),
  BPF_F_PRESERVE_ELEMS = (1U << 11),
  BPF_F_INNER_MAP = (1U << 12),
  BPF_F_LINK = (1U << 13),
  BPF_F_PATH_FD = (1U << 14),
  BPF_F_VTYPE_BTF_OBJ_FD = (1U << 15),
  BPF_F_TOKEN_FD = (1U << 16),
  BPF_F_SEGV_ON_FAULT = (1U << 17),
  BPF_F_NO_USER_CONV = (1U << 18),
};
#define BPF_F_QUERY_EFFECTIVE (1U << 0)
#define BPF_F_TEST_RUN_ON_CPU (1U << 0)
#define BPF_F_TEST_XDP_LIVE_FRAMES (1U << 1)
#define BPF_F_TEST_SKB_CHECKSUM_COMPLETE (1U << 2)
enum bpf_stats_type {
  BPF_STATS_RUN_TIME = 0,
};
enum bpf_stack_build_id_status {
  BPF_STACK_BUILD_ID_EMPTY = 0,
  BPF_STACK_BUILD_ID_VALID = 1,
  BPF_STACK_BUILD_ID_IP = 2,
};
#define BPF_BUILD_ID_SIZE 20
struct bpf_stack_build_id {
  __s32 status;
  unsigned char build_id[BPF_BUILD_ID_SIZE];
  union {
    __u64 offset;
    __u64 ip;
  };
};
#define BPF_OBJ_NAME_LEN 16U
union bpf_attr {
  struct {
    __u32 map_type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_fd;
    __u32 numa_node;
    char map_name[BPF_OBJ_NAME_LEN];
    __u32 map_ifindex;
    __u32 btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 btf_vmlinux_value_type_id;
    __u64 map_extra;
    __s32 value_type_btf_obj_fd;
    __s32 map_token_fd;
  };
  struct {
    __u32 map_fd;
    __aligned_u64 key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    __u64 flags;
  };
  struct {
    __aligned_u64 in_batch;
    __aligned_u64 out_batch;
    __aligned_u64 keys;
    __aligned_u64 values;
    __u32 count;
    __u32 map_fd;
    __u64 elem_flags;
    __u64 flags;
  } batch;
  struct {
    __u32 prog_type;
    __u32 insn_cnt;
    __aligned_u64 insns;
    __aligned_u64 license;
    __u32 log_level;
    __u32 log_size;
    __aligned_u64 log_buf;
    __u32 kern_version;
    __u32 prog_flags;
    char prog_name[BPF_OBJ_NAME_LEN];
    __u32 prog_ifindex;
    __u32 expected_attach_type;
    __u32 prog_btf_fd;
    __u32 func_info_rec_size;
    __aligned_u64 func_info;
    __u32 func_info_cnt;
    __u32 line_info_rec_size;
    __aligned_u64 line_info;
    __u32 line_info_cnt;
    __u32 attach_btf_id;
    union {
      __u32 attach_prog_fd;
      __u32 attach_btf_obj_fd;
    };
    __u32 core_relo_cnt;
    __aligned_u64 fd_array;
    __aligned_u64 core_relos;
    __u32 core_relo_rec_size;
    __u32 log_true_size;
    __s32 prog_token_fd;
  };
  struct {
    __aligned_u64 pathname;
    __u32 bpf_fd;
    __u32 file_flags;
    __s32 path_fd;
  };
  struct {
    union {
      __u32 target_fd;
      __u32 target_ifindex;
    };
    __u32 attach_bpf_fd;
    __u32 attach_type;
    __u32 attach_flags;
    __u32 replace_bpf_fd;
    union {
      __u32 relative_fd;
      __u32 relative_id;
    };
    __u64 expected_revision;
  };
  struct {
    __u32 prog_fd;
    __u32 retval;
    __u32 data_size_in;
    __u32 data_size_out;
    __aligned_u64 data_in;
    __aligned_u64 data_out;
    __u32 repeat;
    __u32 duration;
    __u32 ctx_size_in;
    __u32 ctx_size_out;
    __aligned_u64 ctx_in;
    __aligned_u64 ctx_out;
    __u32 flags;
    __u32 cpu;
    __u32 batch_size;
  } test;
  struct {
    union {
      __u32 start_id;
      __u32 prog_id;
      __u32 map_id;
      __u32 btf_id;
      __u32 link_id;
    };
    __u32 next_id;
    __u32 open_flags;
  };
  struct {
    __u32 bpf_fd;
    __u32 info_len;
    __aligned_u64 info;
  } info;
  struct {
    union {
      __u32 target_fd;
      __u32 target_ifindex;
    };
    __u32 attach_type;
    __u32 query_flags;
    __u32 attach_flags;
    __aligned_u64 prog_ids;
    union {
      __u32 prog_cnt;
      __u32 count;
    };
    __u32 : 32;
    __aligned_u64 prog_attach_flags;
    __aligned_u64 link_ids;
    __aligned_u64 link_attach_flags;
    __u64 revision;
  } query;
  struct {
    __u64 name;
    __u32 prog_fd;
    __u32 : 32;
    __aligned_u64 cookie;
  } raw_tracepoint;
  struct {
    __aligned_u64 btf;
    __aligned_u64 btf_log_buf;
    __u32 btf_size;
    __u32 btf_log_size;
    __u32 btf_log_level;
    __u32 btf_log_true_size;
    __u32 btf_flags;
    __s32 btf_token_fd;
  };
  struct {
    __u32 pid;
    __u32 fd;
    __u32 flags;
    __u32 buf_len;
    __aligned_u64 buf;
    __u32 prog_id;
    __u32 fd_type;
    __u64 probe_offset;
    __u64 probe_addr;
  } task_fd_query;
  struct {
    union {
      __u32 prog_fd;
      __u32 map_fd;
    };
    union {
      __u32 target_fd;
      __u32 target_ifindex;
    };
    __u32 attach_type;
    __u32 flags;
    union {
      __u32 target_btf_id;
      struct {
        __aligned_u64 iter_info;
        __u32 iter_info_len;
      };
      struct {
        __u64 bpf_cookie;
      } perf_event;
      struct {
        __u32 flags;
        __u32 cnt;
        __aligned_u64 syms;
        __aligned_u64 addrs;
        __aligned_u64 cookies;
      } kprobe_multi;
      struct {
        __u32 target_btf_id;
        __u64 cookie;
      } tracing;
      struct {
        __u32 pf;
        __u32 hooknum;
        __s32 priority;
        __u32 flags;
      } netfilter;
      struct {
        union {
          __u32 relative_fd;
          __u32 relative_id;
        };
        __u64 expected_revision;
      } tcx;
      struct {
        __aligned_u64 path;
        __aligned_u64 offsets;
        __aligned_u64 ref_ctr_offsets;
        __aligned_u64 cookies;
        __u32 cnt;
        __u32 flags;
        __u32 pid;
      } uprobe_multi;
      struct {
        union {
          __u32 relative_fd;
          __u32 relative_id;
        };
        __u64 expected_revision;
      } netkit;
    };
  } link_create;
  struct {
    __u32 link_fd;
    union {
      __u32 new_prog_fd;
      __u32 new_map_fd;
    };
    __u32 flags;
    union {
      __u32 old_prog_fd;
      __u32 old_map_fd;
    };
  } link_update;
  struct {
    __u32 link_fd;
  } link_detach;
  struct {
    __u32 type;
  } enable_stats;
  struct {
    __u32 link_fd;
    __u32 flags;
  } iter_create;
  struct {
    __u32 prog_fd;
    __u32 map_fd;
    __u32 flags;
  } prog_bind_map;
  struct {
    __u32 flags;
    __u32 bpffs_fd;
  } token_create;
} __attribute__((aligned(8)));
#define ___BPF_FUNC_MAPPER(FN,ctx...) FN(unspec, 0, ##ctx) FN(map_lookup_elem, 1, ##ctx) FN(map_update_elem, 2, ##ctx) FN(map_delete_elem, 3, ##ctx) FN(probe_read, 4, ##ctx) FN(ktime_get_ns, 5, ##ctx) FN(trace_printk, 6, ##ctx) FN(get_prandom_u32, 7, ##ctx) FN(get_smp_processor_id, 8, ##ctx) FN(skb_store_bytes, 9, ##ctx) FN(l3_csum_replace, 10, ##ctx) FN(l4_csum_replace, 11, ##ctx) FN(tail_call, 12, ##ctx) FN(clone_redirect, 13, ##ctx) FN(get_current_pid_tgid, 14, ##ctx) FN(get_current_uid_gid, 15, ##ctx) FN(get_current_comm, 16, ##ctx) FN(get_cgroup_classid, 17, ##ctx) FN(skb_vlan_push, 18, ##ctx) FN(skb_vlan_pop, 19, ##ctx) FN(skb_get_tunnel_key, 20, ##ctx) FN(skb_set_tunnel_key, 21, ##ctx) FN(perf_event_read, 22, ##ctx) FN(redirect, 23, ##ctx) FN(get_route_realm, 24, ##ctx) FN(perf_event_output, 25, ##ctx) FN(skb_load_bytes, 26, ##ctx) FN(get_stackid, 27, ##ctx) FN(csum_diff, 28, ##ctx) FN(skb_get_tunnel_opt, 29, ##ctx) FN(skb_set_tunnel_opt, 30, ##ctx) FN(skb_change_proto, 31, ##ctx) FN(skb_change_type, 32, ##ctx) FN(skb_under_cgroup, 33, ##ctx) FN(get_hash_recalc, 34, ##ctx) FN(get_current_task, 35, ##ctx) FN(probe_write_user, 36, ##ctx) FN(current_task_under_cgroup, 37, ##ctx) FN(skb_change_tail, 38, ##ctx) FN(skb_pull_data, 39, ##ctx) FN(csum_update, 40, ##ctx) FN(set_hash_invalid, 41, ##ctx) FN(get_numa_node_id, 42, ##ctx) FN(skb_change_head, 43, ##ctx) FN(xdp_adjust_head, 44, ##ctx) FN(probe_read_str, 45, ##ctx) FN(get_socket_cookie, 46, ##ctx) FN(get_socket_uid, 47, ##ctx) FN(set_hash, 48, ##ctx) FN(setsockopt, 49, ##ctx) FN(skb_adjust_room, 50, ##ctx) FN(redirect_map, 51, ##ctx) FN(sk_redirect_map, 52, ##ctx) FN(sock_map_update, 53, ##ctx) FN(xdp_adjust_meta, 54, ##ctx) FN(perf_event_read_value, 55, ##ctx) FN(perf_prog_read_value, 56, ##ctx) FN(getsockopt, 57, ##ctx) FN(override_return, 58, ##ctx) FN(sock_ops_cb_flags_set, 59, ##ctx) FN(msg_redirect_map, 60, ##ctx) FN(msg_apply_bytes, 61, ##ctx) FN(msg_cork_bytes, 62, ##ctx) FN(msg_pull_data, 63, ##ctx) FN(bind, 64, ##ctx) FN(xdp_adjust_tail, 65, ##ctx) FN(skb_get_xfrm_state, 66, ##ctx) FN(get_stack, 67, ##ctx) FN(skb_load_bytes_relative, 68, ##ctx) FN(fib_lookup, 69, ##ctx) FN(sock_hash_update, 70, ##ctx) FN(msg_redirect_hash, 71, ##ctx) FN(sk_redirect_hash, 72, ##ctx) FN(lwt_push_encap, 73, ##ctx) FN(lwt_seg6_store_bytes, 74, ##ctx) FN(lwt_seg6_adjust_srh, 75, ##ctx) FN(lwt_seg6_action, 76, ##ctx) FN(rc_repeat, 77, ##ctx) FN(rc_keydown, 78, ##ctx) FN(skb_cgroup_id, 79, ##ctx) FN(get_current_cgroup_id, 80, ##ctx) FN(get_local_storage, 81, ##ctx) FN(sk_select_reuseport, 82, ##ctx) FN(skb_ancestor_cgroup_id, 83, ##ctx) FN(sk_lookup_tcp, 84, ##ctx) FN(sk_lookup_udp, 85, ##ctx) FN(sk_release, 86, ##ctx) FN(map_push_elem, 87, ##ctx) FN(map_pop_elem, 88, ##ctx) FN(map_peek_elem, 89, ##ctx) FN(msg_push_data, 90, ##ctx) FN(msg_pop_data, 91, ##ctx) FN(rc_pointer_rel, 92, ##ctx) FN(spin_lock, 93, ##ctx) FN(spin_unlock, 94, ##ctx) FN(sk_fullsock, 95, ##ctx) FN(tcp_sock, 96, ##ctx) FN(skb_ecn_set_ce, 97, ##ctx) FN(get_listener_sock, 98, ##ctx) FN(skc_lookup_tcp, 99, ##ctx) FN(tcp_check_syncookie, 100, ##ctx) FN(sysctl_get_name, 101, ##ctx) FN(sysctl_get_current_value, 102, ##ctx) FN(sysctl_get_new_value, 103, ##ctx) FN(sysctl_set_new_value, 104, ##ctx) FN(strtol, 105, ##ctx) FN(strtoul, 106, ##ctx) FN(sk_storage_get, 107, ##ctx) FN(sk_storage_delete, 108, ##ctx) FN(send_signal, 109, ##ctx) FN(tcp_gen_syncookie, 110, ##ctx) FN(skb_output, 111, ##ctx) FN(probe_read_user, 112, ##ctx) FN(probe_read_kernel, 113, ##ctx) FN(probe_read_user_str, 114, ##ctx) FN(probe_read_kernel_str, 115, ##ctx) FN(tcp_send_ack, 116, ##ctx) FN(send_signal_thread, 117, ##ctx) FN(jiffies64, 118, ##ctx) FN(read_branch_records, 119, ##ctx) FN(get_ns_current_pid_tgid, 120, ##ctx) FN(xdp_output, 121, ##ctx) FN(get_netns_cookie, 122, ##ctx) FN(get_current_ancestor_cgroup_id, 123, ##ctx) FN(sk_assign, 124, ##ctx) FN(ktime_get_boot_ns, 125, ##ctx) FN(seq_printf, 126, ##ctx) FN(seq_write, 127, ##ctx) FN(sk_cgroup_id, 128, ##ctx) FN(sk_ancestor_cgroup_id, 129, ##ctx) FN(ringbuf_output, 130, ##ctx) FN(ringbuf_reserve, 131, ##ctx) FN(ringbuf_submit, 132, ##ctx) FN(ringbuf_discard, 133, ##ctx) FN(ringbuf_query, 134, ##ctx) FN(csum_level, 135, ##ctx) FN(skc_to_tcp6_sock, 136, ##ctx) FN(skc_to_tcp_sock, 137, ##ctx) FN(skc_to_tcp_timewait_sock, 138, ##ctx) FN(skc_to_tcp_request_sock, 139, ##ctx) FN(skc_to_udp6_sock, 140, ##ctx) FN(get_task_stack, 141, ##ctx) FN(load_hdr_opt, 142, ##ctx) FN(store_hdr_opt, 143, ##ctx) FN(reserve_hdr_opt, 144, ##ctx) FN(inode_storage_get, 145, ##ctx) FN(inode_storage_delete, 146, ##ctx) FN(d_path, 147, ##ctx) FN(copy_from_user, 148, ##ctx) FN(snprintf_btf, 149, ##ctx) FN(seq_printf_btf, 150, ##ctx) FN(skb_cgroup_classid, 151, ##ctx) FN(redirect_neigh, 152, ##ctx) FN(per_cpu_ptr, 153, ##ctx) FN(this_cpu_ptr, 154, ##ctx) FN(redirect_peer, 155, ##ctx) FN(task_storage_get, 156, ##ctx) FN(task_storage_delete, 157, ##ctx) FN(get_current_task_btf, 158, ##ctx) FN(bprm_opts_set, 159, ##ctx) FN(ktime_get_coarse_ns, 160, ##ctx) FN(ima_inode_hash, 161, ##ctx) FN(sock_from_file, 162, ##ctx) FN(check_mtu, 163, ##ctx) FN(for_each_map_elem, 164, ##ctx) FN(snprintf, 165, ##ctx) FN(sys_bpf, 166, ##ctx) FN(btf_find_by_name_kind, 167, ##ctx) FN(sys_close, 168, ##ctx) FN(timer_init, 169, ##ctx) FN(timer_set_callback, 170, ##ctx) FN(timer_start, 171, ##ctx) FN(timer_cancel, 172, ##ctx) FN(get_func_ip, 173, ##ctx) FN(get_attach_cookie, 174, ##ctx) FN(task_pt_regs, 175, ##ctx) FN(get_branch_snapshot, 176, ##ctx) FN(trace_vprintk, 177, ##ctx) FN(skc_to_unix_sock, 178, ##ctx) FN(kallsyms_lookup_name, 179, ##ctx) FN(find_vma, 180, ##ctx) FN(loop, 181, ##ctx) FN(strncmp, 182, ##ctx) FN(get_func_arg, 183, ##ctx) FN(get_func_ret, 184, ##ctx) FN(get_func_arg_cnt, 185, ##ctx) FN(get_retval, 186, ##ctx) FN(set_retval, 187, ##ctx) FN(xdp_get_buff_len, 188, ##ctx) FN(xdp_load_bytes, 189, ##ctx) FN(xdp_store_bytes, 190, ##ctx) FN(copy_from_user_task, 191, ##ctx) FN(skb_set_tstamp, 192, ##ctx) FN(ima_file_hash, 193, ##ctx) FN(kptr_xchg, 194, ##ctx) FN(map_lookup_percpu_elem, 195, ##ctx) FN(skc_to_mptcp_sock, 196, ##ctx) FN(dynptr_from_mem, 197, ##ctx) FN(ringbuf_reserve_dynptr, 198, ##ctx) FN(ringbuf_submit_dynptr, 199, ##ctx) FN(ringbuf_discard_dynptr, 200, ##ctx) FN(dynptr_read, 201, ##ctx) FN(dynptr_write, 202, ##ctx) FN(dynptr_data, 203, ##ctx) FN(tcp_raw_gen_syncookie_ipv4, 204, ##ctx) FN(tcp_raw_gen_syncookie_ipv6, 205, ##ctx) FN(tcp_raw_check_syncookie_ipv4, 206, ##ctx) FN(tcp_raw_check_syncookie_ipv6, 207, ##ctx) FN(ktime_get_tai_ns, 208, ##ctx) FN(user_ringbuf_drain, 209, ##ctx) FN(cgrp_storage_get, 210, ##ctx) FN(cgrp_storage_delete, 211, ##ctx)
#define __BPF_FUNC_MAPPER_APPLY(name,value,FN) FN(name),
#define __BPF_FUNC_MAPPER(FN) ___BPF_FUNC_MAPPER(__BPF_FUNC_MAPPER_APPLY, FN)
#define __BPF_ENUM_FN(x,y) BPF_FUNC_ ##x = y,
enum bpf_func_id {
  ___BPF_FUNC_MAPPER(__BPF_ENUM_FN) __BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN
enum {
  BPF_F_RECOMPUTE_CSUM = (1ULL << 0),
  BPF_F_INVALIDATE_HASH = (1ULL << 1),
};
enum {
  BPF_F_HDR_FIELD_MASK = 0xfULL,
};
enum {
  BPF_F_PSEUDO_HDR = (1ULL << 4),
  BPF_F_MARK_MANGLED_0 = (1ULL << 5),
  BPF_F_MARK_ENFORCE = (1ULL << 6),
};
enum {
  BPF_F_TUNINFO_IPV6 = (1ULL << 0),
};
enum {
  BPF_F_SKIP_FIELD_MASK = 0xffULL,
  BPF_F_USER_STACK = (1ULL << 8),
  BPF_F_FAST_STACK_CMP = (1ULL << 9),
  BPF_F_REUSE_STACKID = (1ULL << 10),
  BPF_F_USER_BUILD_ID = (1ULL << 11),
};
enum {
  BPF_F_ZERO_CSUM_TX = (1ULL << 1),
  BPF_F_DONT_FRAGMENT = (1ULL << 2),
  BPF_F_SEQ_NUMBER = (1ULL << 3),
  BPF_F_NO_TUNNEL_KEY = (1ULL << 4),
};
enum {
  BPF_F_TUNINFO_FLAGS = (1ULL << 4),
};
enum {
  BPF_F_INDEX_MASK = 0xffffffffULL,
  BPF_F_CURRENT_CPU = BPF_F_INDEX_MASK,
  BPF_F_CTXLEN_MASK = (0xfffffULL << 32),
};
enum {
  BPF_F_CURRENT_NETNS = (- 1L),
};
enum {
  BPF_CSUM_LEVEL_QUERY,
  BPF_CSUM_LEVEL_INC,
  BPF_CSUM_LEVEL_DEC,
  BPF_CSUM_LEVEL_RESET,
};
enum {
  BPF_F_ADJ_ROOM_FIXED_GSO = (1ULL << 0),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = (1ULL << 1),
  BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = (1ULL << 2),
  BPF_F_ADJ_ROOM_ENCAP_L4_GRE = (1ULL << 3),
  BPF_F_ADJ_ROOM_ENCAP_L4_UDP = (1ULL << 4),
  BPF_F_ADJ_ROOM_NO_CSUM_RESET = (1ULL << 5),
  BPF_F_ADJ_ROOM_ENCAP_L2_ETH = (1ULL << 6),
  BPF_F_ADJ_ROOM_DECAP_L3_IPV4 = (1ULL << 7),
  BPF_F_ADJ_ROOM_DECAP_L3_IPV6 = (1ULL << 8),
};
enum {
  BPF_ADJ_ROOM_ENCAP_L2_MASK = 0xff,
  BPF_ADJ_ROOM_ENCAP_L2_SHIFT = 56,
};
#define BPF_F_ADJ_ROOM_ENCAP_L2(len) (((__u64) len & BPF_ADJ_ROOM_ENCAP_L2_MASK) << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)
enum {
  BPF_F_SYSCTL_BASE_NAME = (1ULL << 0),
};
enum {
  BPF_LOCAL_STORAGE_GET_F_CREATE = (1ULL << 0),
  BPF_SK_STORAGE_GET_F_CREATE = BPF_LOCAL_STORAGE_GET_F_CREATE,
};
enum {
  BPF_F_GET_BRANCH_RECORDS_SIZE = (1ULL << 0),
};
enum {
  BPF_RB_NO_WAKEUP = (1ULL << 0),
  BPF_RB_FORCE_WAKEUP = (1ULL << 1),
};
enum {
  BPF_RB_AVAIL_DATA = 0,
  BPF_RB_RING_SIZE = 1,
  BPF_RB_CONS_POS = 2,
  BPF_RB_PROD_POS = 3,
};
enum {
  BPF_RINGBUF_BUSY_BIT = (1U << 31),
  BPF_RINGBUF_DISCARD_BIT = (1U << 30),
  BPF_RINGBUF_HDR_SZ = 8,
};
enum {
  BPF_SK_LOOKUP_F_REPLACE = (1ULL << 0),
  BPF_SK_LOOKUP_F_NO_REUSEPORT = (1ULL << 1),
};
enum bpf_adj_room_mode {
  BPF_ADJ_ROOM_NET,
  BPF_ADJ_ROOM_MAC,
};
enum bpf_hdr_start_off {
  BPF_HDR_START_MAC,
  BPF_HDR_START_NET,
};
enum bpf_lwt_encap_mode {
  BPF_LWT_ENCAP_SEG6,
  BPF_LWT_ENCAP_SEG6_INLINE,
  BPF_LWT_ENCAP_IP,
};
enum {
  BPF_F_BPRM_SECUREEXEC = (1ULL << 0),
};
enum {
  BPF_F_INGRESS = (1ULL << 0),
  BPF_F_BROADCAST = (1ULL << 3),
  BPF_F_EXCLUDE_INGRESS = (1ULL << 4),
#define BPF_F_REDIRECT_FLAGS (BPF_F_INGRESS | BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS)
};
#define __bpf_md_ptr(type,name) union { type name; __u64 : 64; \
} __attribute__((aligned(8)))
enum {
  BPF_SKB_TSTAMP_UNSPEC = 0,
  BPF_SKB_TSTAMP_DELIVERY_MONO = 1,
  BPF_SKB_CLOCK_REALTIME = 0,
  BPF_SKB_CLOCK_MONOTONIC = 1,
  BPF_SKB_CLOCK_TAI = 2,
};
struct __sk_buff {
  __u32 len;
  __u32 pkt_type;
  __u32 mark;
  __u32 queue_mapping;
  __u32 protocol;
  __u32 vlan_present;
  __u32 vlan_tci;
  __u32 vlan_proto;
  __u32 priority;
  __u32 ingress_ifindex;
  __u32 ifindex;
  __u32 tc_index;
  __u32 cb[5];
  __u32 hash;
  __u32 tc_classid;
  __u32 data;
  __u32 data_end;
  __u32 napi_id;
  __u32 family;
  __u32 remote_ip4;
  __u32 local_ip4;
  __u32 remote_ip6[4];
  __u32 local_ip6[4];
  __u32 remote_port;
  __u32 local_port;
  __u32 data_meta;
  __bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
  __u64 tstamp;
  __u32 wire_len;
  __u32 gso_segs;
  __bpf_md_ptr(struct bpf_sock *, sk);
  __u32 gso_size;
  __u8 tstamp_type;
  __u32 : 24;
  __u64 hwtstamp;
};
struct bpf_tunnel_key {
  __u32 tunnel_id;
  union {
    __u32 remote_ipv4;
    __u32 remote_ipv6[4];
  };
  __u8 tunnel_tos;
  __u8 tunnel_ttl;
  union {
    __u16 tunnel_ext;
    __be16 tunnel_flags;
  };
  __u32 tunnel_label;
  union {
    __u32 local_ipv4;
    __u32 local_ipv6[4];
  };
};
struct bpf_xfrm_state {
  __u32 reqid;
  __u32 spi;
  __u16 family;
  __u16 ext;
  union {
    __u32 remote_ipv4;
    __u32 remote_ipv6[4];
  };
};
enum bpf_ret_code {
  BPF_OK = 0,
  BPF_DROP = 2,
  BPF_REDIRECT = 7,
  BPF_LWT_REROUTE = 128,
  BPF_FLOW_DISSECTOR_CONTINUE = 129,
};
struct bpf_sock {
  __u32 bound_dev_if;
  __u32 family;
  __u32 type;
  __u32 protocol;
  __u32 mark;
  __u32 priority;
  __u32 src_ip4;
  __u32 src_ip6[4];
  __u32 src_port;
  __be16 dst_port;
  __u16 : 16;
  __u32 dst_ip4;
  __u32 dst_ip6[4];
  __u32 state;
  __s32 rx_queue_mapping;
};
struct bpf_tcp_sock {
  __u32 snd_cwnd;
  __u32 srtt_us;
  __u32 rtt_min;
  __u32 snd_ssthresh;
  __u32 rcv_nxt;
  __u32 snd_nxt;
  __u32 snd_una;
  __u32 mss_cache;
  __u32 ecn_flags;
  __u32 rate_delivered;
  __u32 rate_interval_us;
  __u32 packets_out;
  __u32 retrans_out;
  __u32 total_retrans;
  __u32 segs_in;
  __u32 data_segs_in;
  __u32 segs_out;
  __u32 data_segs_out;
  __u32 lost_out;
  __u32 sacked_out;
  __u64 bytes_received;
  __u64 bytes_acked;
  __u32 dsack_dups;
  __u32 delivered;
  __u32 delivered_ce;
  __u32 icsk_retransmits;
};
struct bpf_sock_tuple {
  union {
    struct {
      __be32 saddr;
      __be32 daddr;
      __be16 sport;
      __be16 dport;
    } ipv4;
    struct {
      __be32 saddr[4];
      __be32 daddr[4];
      __be16 sport;
      __be16 dport;
    } ipv6;
  };
};
enum tcx_action_base {
  TCX_NEXT = - 1,
  TCX_PASS = 0,
  TCX_DROP = 2,
  TCX_REDIRECT = 7,
};
struct bpf_xdp_sock {
  __u32 queue_id;
};
#define XDP_PACKET_HEADROOM 256
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
};
struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  __u32 ingress_ifindex;
  __u32 rx_queue_index;
  __u32 egress_ifindex;
};
struct bpf_devmap_val {
  __u32 ifindex;
  union {
    int fd;
    __u32 id;
  } bpf_prog;
};
struct bpf_cpumap_val {
  __u32 qsize;
  union {
    int fd;
    __u32 id;
  } bpf_prog;
};
enum sk_action {
  SK_DROP = 0,
  SK_PASS,
};
struct sk_msg_md {
  __bpf_md_ptr(void *, data);
  __bpf_md_ptr(void *, data_end);
  __u32 family;
  __u32 remote_ip4;
  __u32 local_ip4;
  __u32 remote_ip6[4];
  __u32 local_ip6[4];
  __u32 remote_port;
  __u32 local_port;
  __u32 size;
  __bpf_md_ptr(struct bpf_sock *, sk);
};
struct sk_reuseport_md {
  __bpf_md_ptr(void *, data);
  __bpf_md_ptr(void *, data_end);
  __u32 len;
  __u32 eth_protocol;
  __u32 ip_protocol;
  __u32 bind_inany;
  __u32 hash;
  __bpf_md_ptr(struct bpf_sock *, sk);
  __bpf_md_ptr(struct bpf_sock *, migrating_sk);
};
#define BPF_TAG_SIZE 8
struct bpf_prog_info {
  __u32 type;
  __u32 id;
  __u8 tag[BPF_TAG_SIZE];
  __u32 jited_prog_len;
  __u32 xlated_prog_len;
  __aligned_u64 jited_prog_insns;
  __aligned_u64 xlated_prog_insns;
  __u64 load_time;
  __u32 created_by_uid;
  __u32 nr_map_ids;
  __aligned_u64 map_ids;
  char name[BPF_OBJ_NAME_LEN];
  __u32 ifindex;
  __u32 gpl_compatible : 1;
  __u32 : 31;
  __u64 netns_dev;
  __u64 netns_ino;
  __u32 nr_jited_ksyms;
  __u32 nr_jited_func_lens;
  __aligned_u64 jited_ksyms;
  __aligned_u64 jited_func_lens;
  __u32 btf_id;
  __u32 func_info_rec_size;
  __aligned_u64 func_info;
  __u32 nr_func_info;
  __u32 nr_line_info;
  __aligned_u64 line_info;
  __aligned_u64 jited_line_info;
  __u32 nr_jited_line_info;
  __u32 line_info_rec_size;
  __u32 jited_line_info_rec_size;
  __u32 nr_prog_tags;
  __aligned_u64 prog_tags;
  __u64 run_time_ns;
  __u64 run_cnt;
  __u64 recursion_misses;
  __u32 verified_insns;
  __u32 attach_btf_obj_id;
  __u32 attach_btf_id;
} __attribute__((aligned(8)));
struct bpf_map_info {
  __u32 type;
  __u32 id;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  char name[BPF_OBJ_NAME_LEN];
  __u32 ifindex;
  __u32 btf_vmlinux_value_type_id;
  __u64 netns_dev;
  __u64 netns_ino;
  __u32 btf_id;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 btf_vmlinux_id;
  __u64 map_extra;
} __attribute__((aligned(8)));
struct bpf_btf_info {
  __aligned_u64 btf;
  __u32 btf_size;
  __u32 id;
  __aligned_u64 name;
  __u32 name_len;
  __u32 kernel_btf;
} __attribute__((aligned(8)));
struct bpf_link_info {
  __u32 type;
  __u32 id;
  __u32 prog_id;
  union {
    struct {
      __aligned_u64 tp_name;
      __u32 tp_name_len;
    } raw_tracepoint;
    struct {
      __u32 attach_type;
      __u32 target_obj_id;
      __u32 target_btf_id;
    } tracing;
    struct {
      __u64 cgroup_id;
      __u32 attach_type;
    } cgroup;
    struct {
      __aligned_u64 target_name;
      __u32 target_name_len;
      union {
        struct {
          __u32 map_id;
        } map;
      };
      union {
        struct {
          __u64 cgroup_id;
          __u32 order;
        } cgroup;
        struct {
          __u32 tid;
          __u32 pid;
        } task;
      };
    } iter;
    struct {
      __u32 netns_ino;
      __u32 attach_type;
    } netns;
    struct {
      __u32 ifindex;
    } xdp;
    struct {
      __u32 map_id;
    } struct_ops;
    struct {
      __u32 pf;
      __u32 hooknum;
      __s32 priority;
      __u32 flags;
    } netfilter;
    struct {
      __aligned_u64 addrs;
      __u32 count;
      __u32 flags;
      __u64 missed;
      __aligned_u64 cookies;
    } kprobe_multi;
    struct {
      __aligned_u64 path;
      __aligned_u64 offsets;
      __aligned_u64 ref_ctr_offsets;
      __aligned_u64 cookies;
      __u32 path_size;
      __u32 count;
      __u32 flags;
      __u32 pid;
    } uprobe_multi;
    struct {
      __u32 type;
      __u32 : 32;
      union {
        struct {
          __aligned_u64 file_name;
          __u32 name_len;
          __u32 offset;
          __u64 cookie;
        } uprobe;
        struct {
          __aligned_u64 func_name;
          __u32 name_len;
          __u32 offset;
          __u64 addr;
          __u64 missed;
          __u64 cookie;
        } kprobe;
        struct {
          __aligned_u64 tp_name;
          __u32 name_len;
          __u32 : 32;
          __u64 cookie;
        } tracepoint;
        struct {
          __u64 config;
          __u32 type;
          __u32 : 32;
          __u64 cookie;
        } event;
      };
    } perf_event;
    struct {
      __u32 ifindex;
      __u32 attach_type;
    } tcx;
    struct {
      __u32 ifindex;
      __u32 attach_type;
    } netkit;
    struct {
      __u32 map_id;
      __u32 attach_type;
    } sockmap;
  };
} __attribute__((aligned(8)));
struct bpf_sock_addr {
  __u32 user_family;
  __u32 user_ip4;
  __u32 user_ip6[4];
  __u32 user_port;
  __u32 family;
  __u32 type;
  __u32 protocol;
  __u32 msg_src_ip4;
  __u32 msg_src_ip6[4];
  __bpf_md_ptr(struct bpf_sock *, sk);
};
struct bpf_sock_ops {
  __u32 op;
  union {
    __u32 args[4];
    __u32 reply;
    __u32 replylong[4];
  };
  __u32 family;
  __u32 remote_ip4;
  __u32 local_ip4;
  __u32 remote_ip6[4];
  __u32 local_ip6[4];
  __u32 remote_port;
  __u32 local_port;
  __u32 is_fullsock;
  __u32 snd_cwnd;
  __u32 srtt_us;
  __u32 bpf_sock_ops_cb_flags;
  __u32 state;
  __u32 rtt
"""


```