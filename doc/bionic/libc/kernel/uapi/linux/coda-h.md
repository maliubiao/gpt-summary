Response:
Let's break down the thought process to answer the user's request about the `coda.h` file.

**1. Understanding the Request:**

The user wants to understand the functionality of the `coda.h` header file within the context of Android's Bionic library. The request is multi-faceted, asking for:

* **Functionality Listing:** What does this file *do* or represent?
* **Android Relevance:** How does it connect to Android's features?
* **libc Function Implementation:**  Detailed explanation of the *implementation* of libc functions defined here.
* **Dynamic Linker Aspects:**  Information on dynamic linking, including SO layout and linking process.
* **Logic and Examples:**  Hypothetical inputs and outputs to illustrate logic.
* **Common Errors:**  Examples of mistakes users might make.
* **Android Framework/NDK Flow:** How code reaches this header and how to debug it with Frida.

**2. Initial Analysis of the Header File:**

A quick scan reveals several key characteristics:

* **`#ifndef _UAPI_CODA_HEADER_`:** This indicates a header guard, preventing multiple inclusions. The `_UAPI` prefix suggests it's part of the user-space API interacting with the kernel.
* **Auto-generated comment:**  This is crucial. It tells us this file isn't meant for manual editing and is likely derived from kernel sources.
* **Includes:**  `<sys/types.h>`, `<sys/time.h>`, `<linux/time.h>`. These point to system-level definitions related to types and time. The `linux/time.h` specifically indicates a Linux kernel dependency.
* **Constants:**  `CODA_MAXSYMLINKS`, `CODA_MAXNAMLEN`, `CODA_MAXPATHLEN`, file access flags (`C_O_READ`, `C_O_WRITE`, etc.), file mode bits (`C_M_READ`, `C_M_WRITE`), and access check flags (`C_A_C_OK`, etc.).
* **Data Structures:** `venus_dirent`, `CodaFid`, `coda_timespec`, `coda_vattr`, `coda_statfs`, `coda_in_hdr`, `coda_out_hdr`, and many more structures representing the data exchanged during Coda file system operations.
* **Opcode Definitions:** `CODA_ROOT`, `CODA_OPEN`, `CODA_CLOSE`, etc. These are clearly operation codes for interacting with the Coda file system.
* **`DOWNCALL` Macro:**  Suggests a mechanism for the Coda server to make calls back to the client.
* **`union inputArgs` and `union outputArgs`:** These unions define the possible structures for input and output arguments to the Coda operations, based on the opcode.
* **`union coda_downcalls`:** Structures for the server-initiated calls.
* **`ViceIoctl` and `PioctlData`:** Structures likely related to ioctl operations for the Coda file system.
* **`coda_mount_data`:**  Structure for mounting the Coda file system.

**3. Deductions and Inferences:**

Based on the content, I can infer the following:

* **Coda File System:** The file is defining data structures and constants for interacting with a file system called "Coda."
* **Kernel Interface:** The `_UAPI` prefix and inclusion of `<linux/time.h>` strongly indicate this is part of the user-space API for a kernel-level Coda file system implementation.
* **RPC-like Communication:** The structures for input and output headers (`coda_in_hdr`, `coda_out_hdr`), opcodes, and argument unions suggest a remote procedure call (RPC) mechanism for interacting with the Coda server.
* **Android's Role:**  Since this is in Android's Bionic library, Android likely has (or had) support for mounting and using Coda file systems. This is probably for accessing remote files.

**4. Addressing Specific Parts of the Request:**

* **Functionality:**  The core functionality is defining the interface for interacting with the Coda distributed file system. This includes operations for file access, manipulation, and management.
* **Android Relevance:** Coda allows Android devices to access files hosted on a remote Coda server. This is analogous to NFS or other network file systems. *Example: Accessing shared project files in a development environment.*
* **libc Functions:** This is where it's important to realize the header *defines* structures and constants, but it doesn't *implement* libc functions in the traditional sense (like `malloc`, `printf`). The *syscalls* to interact with the Coda file system in the kernel would be implemented elsewhere in Bionic. I need to clarify this distinction.
* **Dynamic Linker:**  This header file itself doesn't directly involve the dynamic linker. However, the Coda client code *using* these definitions would be linked. I need to explain the general linking process and provide a hypothetical SO layout for a Coda client library.
* **Logic and Examples:**  For each major Coda operation (open, read, write, etc.), I can describe the input structures, the expected processing, and the output structures. This involves mapping the opcodes to their corresponding structures.
* **Common Errors:**  Focus on errors related to incorrect usage of the Coda API, such as invalid flags, incorrect file IDs, or permission issues.
* **Android Framework/NDK Flow:**  Trace how a file access request from an Android application might eventually lead to interaction with the Coda file system through these structures. This likely involves VFS layer in the Linux kernel. Frida hooks can be used to intercept system calls or function calls in the Coda client library.

**5. Structuring the Answer:**

Organize the information clearly according to the user's request. Use headings and bullet points for readability. Provide code snippets (like the Frida hook example) to illustrate the concepts.

**6. Refinement and Review:**

* Double-check the interpretation of the header file. Ensure the distinction between definitions and implementations is clear.
* Verify the accuracy of the Android-specific examples and the linking process explanation.
* Make sure the Frida hook example is practical and demonstrates how to intercept relevant calls.
* Review the language for clarity and conciseness.

By following this thought process, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request about the `coda.h` header file. The key is to carefully analyze the content of the file, make logical deductions, and connect it to the broader context of Android and Linux system programming.
这是一个定义了与 Coda 分布式文件系统进行交互的接口的头文件。它为用户空间程序提供了与运行在内核中的 Coda 文件系统客户端进行通信所需的常量、数据结构和宏定义。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它是用户空间程序可以通过系统调用等方式与内核 Coda 模块交互的接口。

**功能列举:**

该头文件定义了以下功能：

1. **数据结构定义:** 定义了用于在用户空间和内核空间之间传递 Coda 文件系统操作相关数据的结构体，例如：
    * `CodaFid`:  表示 Coda 文件系统中文件或目录的唯一标识符。
    * `coda_vattr`:  表示 Coda 文件系统中文件或目录的属性信息（如类型、权限、大小、时间戳等）。
    * `venus_dirent`:  表示目录项信息。
    * `coda_statfs`:  表示文件系统的统计信息（如总块数、可用块数等）。
    * `coda_in_hdr` 和 `coda_out_hdr`:  定义了请求和响应的头部信息，包含操作码、唯一标识符、进程/线程 ID 等。
    * `coda_*_in` 和 `coda_*_out`:  定义了各种 Coda 操作的输入和输出参数结构体，例如 `coda_open_in`, `coda_open_out`, `coda_getattr_in`, `coda_getattr_out` 等。
    * `union inputArgs` 和 `union outputArgs`:  用作封装不同 Coda 操作的输入和输出参数的联合体。

2. **常量定义:** 定义了与 Coda 文件系统操作相关的常量，例如：
    * `CODA_MAXNAMLEN`, `CODA_MAXPATHLEN`:  定义了文件名和路径名的最大长度。
    * `C_O_READ`, `C_O_WRITE`, `C_O_CREAT` 等:  定义了文件打开标志。
    * `C_M_READ`, `C_M_WRITE` 等:  定义了文件访问权限。
    * `CODA_ROOT`, `CODA_OPEN`, `CODA_CLOSE` 等:  定义了 Coda 操作码，用于标识要执行的具体操作。
    * `CDT_UNKNOWN`, `CDT_FIFO`, `CDT_DIR` 等:  定义了目录项类型。

3. **宏定义:** 提供了一些辅助宏，例如：
    * `DIRSIZ(dp)`:  计算目录项的大小。
    * `IFTOCDT(mode)` 和 `CDTTOIF(dirtype)`:  在文件模式和目录项类型之间进行转换。
    * `coda_f2i(fid)`:  将 `CodaFid` 结构体转换为一个整数值。
    * `DOWNCALL(opcode)`:  判断一个操作码是否是服务器发起的调用（downcall）。

**与 Android 功能的关系及举例说明:**

Coda 文件系统是一种分布式文件系统，它允许用户访问远程服务器上的文件，就像访问本地文件一样。在 Android 中，Coda 的支持可能用于以下场景：

* **访问网络共享文件:** Android 设备可以作为 Coda 客户端挂载远程 Coda 服务器上的共享目录，从而访问共享的文件资源。
* **特定应用场景:** 某些特定的 Android 应用或环境可能依赖 Coda 文件系统来进行文件管理和数据同步。

**举例说明:**

假设一个 Android 应用需要访问远程 Coda 服务器上的一个文件 `/project/data.txt`。应用可能会使用标准的 POSIX 文件 I/O API (例如 `open`, `read`, `write`) 来操作这个文件。当这些操作涉及到挂载的 Coda 文件系统时，Android 的 VFS (Virtual File System) 层会将这些操作转换为相应的 Coda 操作，并通过定义在 `coda.h` 中的数据结构和操作码，与内核中的 Coda 客户端模块进行通信。

例如，当应用调用 `open("/mnt/coda/project/data.txt", O_RDONLY)` 时，如果 `/mnt/coda` 是一个 Coda 文件系统的挂载点，内核的 Coda 客户端会构建一个 `coda_open_in` 结构体，其中包含：

* `ih.opcode = CODA_OPEN`
* `VFid`:  表示 `/mnt/coda/project` 目录的 `CodaFid`。
* `flags`:  包含 `C_O_READ` 标志。

然后，内核会将这个请求发送到 Coda 服务器。服务器处理请求后，会返回一个包含文件 `data.txt` 的 `CodaFid` 以及其他信息的 `coda_open_out` 结构体。

**libc 函数的实现 (此头文件不包含 libc 函数的实现):**

需要注意的是，`coda.h` 文件本身**不包含任何 libc 函数的实现**。它仅仅是定义了与 Coda 文件系统交互所需的数据结构和常量。 实际的 libc 函数（例如 `open`, `read`, `write`）的实现在 Bionic 库的其他源文件中。

当 libc 函数操作一个位于 Coda 文件系统上的文件时，它们最终会通过系统调用（例如 `ioctl`）与内核中的 Coda 客户端模块进行交互。内核模块会使用 `coda.h` 中定义的结构体来构建和解析与 Coda 服务器通信的消息。

**涉及 dynamic linker 的功能 (此头文件不直接涉及 dynamic linker):**

`coda.h` 文件本身**不直接涉及 dynamic linker 的功能**。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号引用。

然而，如果有一个用户空间的 Coda 客户端库 (`.so` 文件)，它使用了 `coda.h` 中定义的接口来与内核 Coda 模块交互，那么 dynamic linker 会负责加载这个库。

**so 布局样本 (假设存在 Coda 客户端库):**

假设存在一个名为 `libcoda_client.so` 的 Coda 客户端库：

```
libcoda_client.so:
    .init          // 初始化代码段
    .plt           // 过程链接表 (Procedure Linkage Table)
    .text          // 代码段，包含 Coda 客户端库的实现
    .rodata        // 只读数据段，包含常量字符串等
    .data          // 可读写数据段，包含全局变量
    .bss           // 未初始化数据段
    .dynamic       // 动态链接信息
    .symtab        // 符号表
    .strtab        // 字符串表
    .rela.dyn      // 动态重定位表
    ...
```

**链接的处理过程 (假设存在 Coda 客户端库):**

1. **编译时链接:** 当开发者编译链接一个使用了 Coda 客户端库的应用时，链接器会将应用的目标文件与 `libcoda_client.so` 中导出的符号进行链接。这会在应用的可执行文件中生成对 `libcoda_client.so` 中函数的未解析引用。

2. **运行时链接:** 当应用启动时，dynamic linker 会执行以下操作：
    * **加载共享库:** 找到并加载 `libcoda_client.so` 到进程的地址空间。这可能涉及到搜索预定义的路径（如 `/system/lib64`, `/vendor/lib64` 等）。
    * **符号解析:** 解析应用中对 `libcoda_client.so` 中函数的未解析引用。dynamic linker 会查找 `libcoda_client.so` 的符号表，找到匹配的符号，并将应用的调用地址重定向到 `libcoda_client.so` 中相应的函数地址。
    * **重定位:**  处理共享库中的重定位信息，调整代码和数据中需要修改的地址，以适应其在进程地址空间中的实际加载位置。

**逻辑推理、假设输入与输出 (针对 Coda 操作):**

**假设输入:**

* **操作:** `CODA_LOOKUP` (查找目录项)
* **输入结构体:** `coda_lookup_in`
    * `ih.opcode`: `CODA_LOOKUP`
    * `VFid`:  表示要查找的目录的 `CodaFid` (假设值为 `{1, 2, 3, 4}`)
    * `name`:  要查找的目录项的名字 (假设为字符串 "myfile.txt")
    * `flags`:  查找标志 (假设为 0)

**逻辑推理:**

内核中的 Coda 客户端会将 `coda_lookup_in` 结构体发送到 Coda 服务器。服务器会在 `VFid` 指代的目录中查找名为 "myfile.txt" 的条目。

**假设输出:**

* **输出结构体:** `coda_lookup_out`
    * `oh.opcode`: `CODA_LOOKUP`
    * `oh.result`: 0 (假设查找成功)
    * `VFid`:  表示 "myfile.txt" 的 `CodaFid` (假设值为 `{5, 6, 7, 8}`)
    * `vtype`:  "myfile.txt" 的类型 (假设为 `C_VREG`，表示普通文件)

**用户或编程常见的使用错误:**

1. **未挂载 Coda 文件系统就尝试访问:**  如果用户尝试访问位于 Coda 文件系统上的路径，但该文件系统尚未挂载，会导致 "No such file or directory" 错误。

   ```c
   // 假设 /mnt/coda 是 Coda 文件系统的挂载点
   int fd = open("/mnt/coda/some_file.txt", O_RDONLY);
   if (fd == -1) {
       perror("open"); // 可能输出 "No such file or directory"
   }
   ```

2. **使用错误的权限打开文件:**  如果用户尝试以只写模式打开一个只读文件，或者尝试打开一个自己没有权限访问的文件，会导致权限错误。

   ```c
   // 假设 user 不具有访问 /mnt/coda/protected_file.txt 的权限
   int fd = open("/mnt/coda/protected_file.txt", O_RDONLY);
   if (fd == -1) {
       perror("open"); // 可能输出 "Permission denied"
   }
   ```

3. **操作已失效的 Fid:**  如果在服务器端文件被删除或移动，而客户端仍然持有该文件的 `CodaFid`，尝试使用该 `Fid` 进行操作可能会导致错误，例如 "Stale file handle"。

4. **不正确地处理错误返回值:**  Coda 操作可能会失败，应用程序需要检查系统调用的返回值（通常为 -1 表示错误）并根据 `errno` 的值来处理错误。

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **应用发起文件操作:**  一个 Android 应用（使用 Java 或 Kotlin）通过 `java.io.File`, `FileInputStream`, `FileOutputStream` 等 API 发起文件操作，例如读取或写入位于 Coda 文件系统上的文件。

2. **Framework 层处理:** Android Framework 会将这些高级文件操作转换为底层的系统调用。例如，`FileInputStream.read()` 最终会调用到 native 代码，并执行 `read()` 系统调用。

3. **VFS 层转发:** Linux 内核的 VFS (Virtual File System) 层会根据文件路径识别出该文件位于 Coda 文件系统上，并将系统调用转发给 Coda 文件系统模块。

4. **Coda 客户端模块处理:** 内核中的 Coda 客户端模块会根据接收到的系统调用，构建相应的 `coda_*_in` 结构体，并使用 `coda.h` 中定义的操作码。

5. **与 Coda 服务器通信:** Coda 客户端模块会通过网络将请求发送到 Coda 服务器。

6. **服务器处理并返回:** Coda 服务器处理请求后，将结果封装到 `coda_*_out` 结构体中返回给客户端。

7. **内核返回结果:** Coda 客户端模块将服务器的响应解析出来，并将结果返回给 VFS 层，最终传递回应用。

**Frida hook 示例调试步骤:**

假设你想 hook `open` 系统调用，查看当打开 Coda 文件系统上的文件时，内核传递给 Coda 客户端模块的 `coda_open_in` 结构体内容。

```python
import frida
import sys

# 要 hook 的系统调用
syscall_name = "openat"  # or "open" depending on the architecture

# Coda open 输入结构体定义 (根据 coda.h)
coda_open_in_struct = """
struct coda_open_in {
  uint32_t opcode;
  uint32_t unique;
  uint32_t pid;
  uint32_t pgid;
  uint32_t uid;
  uint32_t VFid_opaque[4];
  int flags;
};
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

def main():
    package_name = "your.target.package"  # 替换为你要调试的应用包名
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
    device.resume(pid)

    script_code = """
    // 定义 Coda open 输入结构体
    const coda_open_in_struct = %s;
    const coda_open_in_size = %d;

    Interceptor.attach(Module.findExportByName(null, "%s"), {
        onEnter: function (args) {
            const pathname = Memory.readUtf8String(args[0]); // 对于 openat, 是 args[1]
            const flags = args[1].toInt32(); // 对于 openat, 是 args[2]

            // 检查是否是 Coda 文件系统上的路径 (你需要根据实际情况判断)
            if (pathname.startsWith("/mnt/coda")) {
                console.log("[*] Calling open on Coda path:", pathname, "flags:", flags.toString(16));

                // 读取传递给内核的结构体 (这部分需要更深入的内核调用分析来确定准确的位置)
                // 这里只是一个假设，实际内核传递参数的方式可能不同
                const coda_input_ptr = args[5]; // 假设输入参数在第 6 个参数
                if (coda_input_ptr) {
                    const coda_input_data = Memory.readByteArray(coda_input_ptr, coda_open_in_size);
                    const coda_input = new NativePointer(coda_input_data.buffer);

                    const opcode = coda_input.readU32();
                    const VFid_opaque = [
                        coda_input.add(20).readU32(),
                        coda_input.add(24).readU32(),
                        coda_input.add(28).readU32(),
                        coda_input.add(32).readU32()
                    ];
                    const coda_flags = coda_input.add(36).readS32();

                    console.log("[*] coda_open_in.opcode:", opcode);
                    console.log("[*] coda_open_in.VFid:", VFid_opaque);
                    console.log("[*] coda_open_in.flags:", coda_flags.toString(16));
                }
            }
        }
    });
    """ % (coda_open_in_struct, 40, syscall_name) # 假设 coda_open_in 大小为 40 字节

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**说明:**

1. **确定目标应用和系统调用:**  替换 `your.target.package` 为你要调试的应用的包名，并确定相关的系统调用 (`open` 或 `openat`)。

2. **定义 Coda 结构体:**  在 Frida 脚本中定义 `coda_open_in` 结构体，以便解析内存中的数据。

3. **Hook 系统调用:** 使用 `Interceptor.attach` hook `open` 或 `openat` 系统调用。

4. **检查 Coda 路径:** 在 `onEnter` 函数中，检查打开的文件路径是否位于 Coda 文件系统的挂载点。

5. **读取内存:**  **关键且复杂的一步。** 你需要确定传递给内核的 `open` 系统调用的参数中，哪个参数指向了与 Coda 相关的输入结构体。这通常需要结合内核源代码或者进行更深入的分析才能确定。 上面的代码中 `args[5]` 只是一个假设的例子。

6. **解析结构体:** 如果找到了指向 Coda 输入结构体的指针，使用 `Memory.readByteArray` 读取内存，并使用 `NativePointer` 解析结构体中的字段。

7. **打印信息:** 将解析出的 Coda 相关信息打印到控制台。

**重要提示:**  Frida hook 内核级别的行为可能非常复杂，需要对内核的系统调用机制和参数传递方式有深入的了解。上述 Frida 代码只是一个概念性的示例，实际操作中可能需要进行大量的调整和调试才能成功 hook 到目标信息。你需要根据你具体的 Android 版本和内核实现来调整代码。

总而言之，`bionic/libc/kernel/uapi/linux/coda.h` 是一个定义了用户空间程序与 Linux 内核中 Coda 分布式文件系统客户端交互接口的关键头文件。理解这个文件的内容有助于理解 Android 如何支持 Coda 文件系统以及如何在底层进行相关的操作。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/coda.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_CODA_HEADER_
#define _UAPI_CODA_HEADER_
#if defined(__NetBSD__) || (defined(DJGPP) || defined(__CYGWIN32__)) && !defined(KERNEL)
#include <sys/types.h>
#endif
#ifndef CODA_MAXSYMLINKS
#define CODA_MAXSYMLINKS 10
#endif
#if defined(DJGPP) || defined(__CYGWIN32__)
#ifdef KERNEL
typedef unsigned long u_long;
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef u_long ino_t;
typedef u_long dev_t;
typedef void * caddr_t;
#ifdef DOS
typedef unsigned __int64 u_quad_t;
#else
typedef unsigned long long u_quad_t;
#endif
#define inline
#else
#include <sys/time.h>
typedef unsigned long long u_quad_t;
#endif
#endif
#ifdef __linux__
#include <linux/time.h>
#define cdev_t u_quad_t
#if !defined(_UQUAD_T_) && (!defined(__GLIBC__) || __GLIBC__ < 2)
#define _UQUAD_T_ 1
typedef unsigned long long u_quad_t;
#endif
#else
#define cdev_t dev_t
#endif
#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__
typedef signed char int8_t;
typedef unsigned char u_int8_t;
typedef short int16_t;
typedef unsigned short u_int16_t;
typedef int int32_t;
typedef unsigned int u_int32_t;
#endif
#define CODA_MAXNAMLEN 255
#define CODA_MAXPATHLEN 1024
#define CODA_MAXSYMLINK 10
#define C_O_READ 0x001
#define C_O_WRITE 0x002
#define C_O_TRUNC 0x010
#define C_O_EXCL 0x100
#define C_O_CREAT 0x200
#define C_M_READ 00400
#define C_M_WRITE 00200
#define C_A_C_OK 8
#define C_A_R_OK 4
#define C_A_W_OK 2
#define C_A_X_OK 1
#define C_A_F_OK 0
#ifndef _VENUS_DIRENT_T_
#define _VENUS_DIRENT_T_ 1
struct venus_dirent {
  u_int32_t d_fileno;
  u_int16_t d_reclen;
  u_int8_t d_type;
  u_int8_t d_namlen;
  char d_name[CODA_MAXNAMLEN + 1];
};
#undef DIRSIZ
#define DIRSIZ(dp) ((sizeof(struct venus_dirent) - (CODA_MAXNAMLEN + 1)) + (((dp)->d_namlen + 1 + 3) & ~3))
#define CDT_UNKNOWN 0
#define CDT_FIFO 1
#define CDT_CHR 2
#define CDT_DIR 4
#define CDT_BLK 6
#define CDT_REG 8
#define CDT_LNK 10
#define CDT_SOCK 12
#define CDT_WHT 14
#define IFTOCDT(mode) (((mode) & 0170000) >> 12)
#define CDTTOIF(dirtype) ((dirtype) << 12)
#endif
#ifndef _VUID_T_
#define _VUID_T_
typedef u_int32_t vuid_t;
typedef u_int32_t vgid_t;
#endif
struct CodaFid {
  u_int32_t opaque[4];
};
#define coda_f2i(fid) (fid ? (fid->opaque[3] ^ (fid->opaque[2] << 10) ^ (fid->opaque[1] << 20) ^ fid->opaque[0]) : 0)
#ifndef _VENUS_VATTR_T_
#define _VENUS_VATTR_T_
enum coda_vtype {
  C_VNON,
  C_VREG,
  C_VDIR,
  C_VBLK,
  C_VCHR,
  C_VLNK,
  C_VSOCK,
  C_VFIFO,
  C_VBAD
};
struct coda_timespec {
  int64_t tv_sec;
  long tv_nsec;
};
struct coda_vattr {
  long va_type;
  u_short va_mode;
  short va_nlink;
  vuid_t va_uid;
  vgid_t va_gid;
  long va_fileid;
  u_quad_t va_size;
  long va_blocksize;
  struct coda_timespec va_atime;
  struct coda_timespec va_mtime;
  struct coda_timespec va_ctime;
  u_long va_gen;
  u_long va_flags;
  cdev_t va_rdev;
  u_quad_t va_bytes;
  u_quad_t va_filerev;
};
#endif
struct coda_statfs {
  int32_t f_blocks;
  int32_t f_bfree;
  int32_t f_bavail;
  int32_t f_files;
  int32_t f_ffree;
};
#define CODA_ROOT 2
#define CODA_OPEN_BY_FD 3
#define CODA_OPEN 4
#define CODA_CLOSE 5
#define CODA_IOCTL 6
#define CODA_GETATTR 7
#define CODA_SETATTR 8
#define CODA_ACCESS 9
#define CODA_LOOKUP 10
#define CODA_CREATE 11
#define CODA_REMOVE 12
#define CODA_LINK 13
#define CODA_RENAME 14
#define CODA_MKDIR 15
#define CODA_RMDIR 16
#define CODA_SYMLINK 18
#define CODA_READLINK 19
#define CODA_FSYNC 20
#define CODA_VGET 22
#define CODA_SIGNAL 23
#define CODA_REPLACE 24
#define CODA_FLUSH 25
#define CODA_PURGEUSER 26
#define CODA_ZAPFILE 27
#define CODA_ZAPDIR 28
#define CODA_PURGEFID 30
#define CODA_OPEN_BY_PATH 31
#define CODA_RESOLVE 32
#define CODA_REINTEGRATE 33
#define CODA_STATFS 34
#define CODA_STORE 35
#define CODA_RELEASE 36
#define CODA_ACCESS_INTENT 37
#define CODA_NCALLS 38
#define DOWNCALL(opcode) (opcode >= CODA_REPLACE && opcode <= CODA_PURGEFID)
#define VC_MAXDATASIZE 8192
#define VC_MAXMSGSIZE sizeof(union inputArgs) + sizeof(union outputArgs) + VC_MAXDATASIZE
#define CIOC_KERNEL_VERSION _IOWR('c', 10, size_t)
#define CODA_KERNEL_VERSION 5
struct coda_in_hdr {
  u_int32_t opcode;
  u_int32_t unique;
  __kernel_pid_t pid;
  __kernel_pid_t pgid;
  vuid_t uid;
};
struct coda_out_hdr {
  u_int32_t opcode;
  u_int32_t unique;
  u_int32_t result;
};
struct coda_root_out {
  struct coda_out_hdr oh;
  struct CodaFid VFid;
};
struct coda_root_in {
  struct coda_in_hdr in;
};
struct coda_open_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_open_out {
  struct coda_out_hdr oh;
  cdev_t dev;
  ino_t inode;
};
struct coda_store_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_store_out {
  struct coda_out_hdr out;
};
struct coda_release_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_release_out {
  struct coda_out_hdr out;
};
struct coda_close_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_close_out {
  struct coda_out_hdr out;
};
struct coda_ioctl_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int cmd;
  int len;
  int rwflag;
  char * data;
};
struct coda_ioctl_out {
  struct coda_out_hdr oh;
  int len;
  caddr_t data;
};
struct coda_getattr_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
};
struct coda_getattr_out {
  struct coda_out_hdr oh;
  struct coda_vattr attr;
};
struct coda_setattr_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  struct coda_vattr attr;
};
struct coda_setattr_out {
  struct coda_out_hdr out;
};
struct coda_access_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_access_out {
  struct coda_out_hdr out;
};
#define CLU_CASE_SENSITIVE 0x01
#define CLU_CASE_INSENSITIVE 0x02
struct coda_lookup_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int name;
  int flags;
};
struct coda_lookup_out {
  struct coda_out_hdr oh;
  struct CodaFid VFid;
  int vtype;
};
struct coda_create_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  struct coda_vattr attr;
  int excl;
  int mode;
  int name;
};
struct coda_create_out {
  struct coda_out_hdr oh;
  struct CodaFid VFid;
  struct coda_vattr attr;
};
struct coda_remove_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int name;
};
struct coda_remove_out {
  struct coda_out_hdr out;
};
struct coda_link_in {
  struct coda_in_hdr ih;
  struct CodaFid sourceFid;
  struct CodaFid destFid;
  int tname;
};
struct coda_link_out {
  struct coda_out_hdr out;
};
struct coda_rename_in {
  struct coda_in_hdr ih;
  struct CodaFid sourceFid;
  int srcname;
  struct CodaFid destFid;
  int destname;
};
struct coda_rename_out {
  struct coda_out_hdr out;
};
struct coda_mkdir_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  struct coda_vattr attr;
  int name;
};
struct coda_mkdir_out {
  struct coda_out_hdr oh;
  struct CodaFid VFid;
  struct coda_vattr attr;
};
struct coda_rmdir_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int name;
};
struct coda_rmdir_out {
  struct coda_out_hdr out;
};
struct coda_symlink_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int srcname;
  struct coda_vattr attr;
  int tname;
};
struct coda_symlink_out {
  struct coda_out_hdr out;
};
struct coda_readlink_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
};
struct coda_readlink_out {
  struct coda_out_hdr oh;
  int count;
  caddr_t data;
};
struct coda_fsync_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
};
struct coda_fsync_out {
  struct coda_out_hdr out;
};
struct coda_vget_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
};
struct coda_vget_out {
  struct coda_out_hdr oh;
  struct CodaFid VFid;
  int vtype;
};
struct coda_purgeuser_out {
  struct coda_out_hdr oh;
  vuid_t uid;
};
struct coda_zapfile_out {
  struct coda_out_hdr oh;
  struct CodaFid CodaFid;
};
struct coda_zapdir_out {
  struct coda_out_hdr oh;
  struct CodaFid CodaFid;
};
struct coda_purgefid_out {
  struct coda_out_hdr oh;
  struct CodaFid CodaFid;
};
struct coda_replace_out {
  struct coda_out_hdr oh;
  struct CodaFid NewFid;
  struct CodaFid OldFid;
};
struct coda_open_by_fd_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_open_by_fd_out {
  struct coda_out_hdr oh;
  int fd;
};
struct coda_open_by_path_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int flags;
};
struct coda_open_by_path_out {
  struct coda_out_hdr oh;
  int path;
};
struct coda_statfs_in {
  struct coda_in_hdr in;
};
struct coda_statfs_out {
  struct coda_out_hdr oh;
  struct coda_statfs stat;
};
#define CODA_ACCESS_TYPE_READ 1
#define CODA_ACCESS_TYPE_WRITE 2
#define CODA_ACCESS_TYPE_MMAP 3
#define CODA_ACCESS_TYPE_READ_FINISH 4
#define CODA_ACCESS_TYPE_WRITE_FINISH 5
struct coda_access_intent_in {
  struct coda_in_hdr ih;
  struct CodaFid VFid;
  int count;
  int pos;
  int type;
};
struct coda_access_intent_out {
  struct coda_out_hdr out;
};
#define CODA_NOCACHE 0x80000000
union inputArgs {
  struct coda_in_hdr ih;
  struct coda_open_in coda_open;
  struct coda_store_in coda_store;
  struct coda_release_in coda_release;
  struct coda_close_in coda_close;
  struct coda_ioctl_in coda_ioctl;
  struct coda_getattr_in coda_getattr;
  struct coda_setattr_in coda_setattr;
  struct coda_access_in coda_access;
  struct coda_lookup_in coda_lookup;
  struct coda_create_in coda_create;
  struct coda_remove_in coda_remove;
  struct coda_link_in coda_link;
  struct coda_rename_in coda_rename;
  struct coda_mkdir_in coda_mkdir;
  struct coda_rmdir_in coda_rmdir;
  struct coda_symlink_in coda_symlink;
  struct coda_readlink_in coda_readlink;
  struct coda_fsync_in coda_fsync;
  struct coda_vget_in coda_vget;
  struct coda_open_by_fd_in coda_open_by_fd;
  struct coda_open_by_path_in coda_open_by_path;
  struct coda_statfs_in coda_statfs;
  struct coda_access_intent_in coda_access_intent;
};
union outputArgs {
  struct coda_out_hdr oh;
  struct coda_root_out coda_root;
  struct coda_open_out coda_open;
  struct coda_ioctl_out coda_ioctl;
  struct coda_getattr_out coda_getattr;
  struct coda_lookup_out coda_lookup;
  struct coda_create_out coda_create;
  struct coda_mkdir_out coda_mkdir;
  struct coda_readlink_out coda_readlink;
  struct coda_vget_out coda_vget;
  struct coda_purgeuser_out coda_purgeuser;
  struct coda_zapfile_out coda_zapfile;
  struct coda_zapdir_out coda_zapdir;
  struct coda_purgefid_out coda_purgefid;
  struct coda_replace_out coda_replace;
  struct coda_open_by_fd_out coda_open_by_fd;
  struct coda_open_by_path_out coda_open_by_path;
  struct coda_statfs_out coda_statfs;
};
union coda_downcalls {
  struct coda_purgeuser_out purgeuser;
  struct coda_zapfile_out zapfile;
  struct coda_zapdir_out zapdir;
  struct coda_purgefid_out purgefid;
  struct coda_replace_out replace;
};
#define PIOCPARM_MASK 0x0000ffff
struct ViceIoctl {
  void  * in;
  void  * out;
  u_short in_size;
  u_short out_size;
};
struct PioctlData {
  const char  * path;
  int follow;
  struct ViceIoctl vi;
};
#define CODA_CONTROL ".CONTROL"
#define CODA_CONTROLLEN 8
#define CTL_INO - 1
#define CODA_MOUNT_VERSION 1
struct coda_mount_data {
  int version;
  int fd;
};
#endif

"""

```