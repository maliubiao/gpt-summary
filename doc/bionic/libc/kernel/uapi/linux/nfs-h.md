Response:
Let's break down the thought process for answering this complex request about the `nfs.h` file.

**1. Understanding the Core Request:**

The central request is to analyze a header file (`nfs.h`) located within the Bionic library (Android's libc). The goal is to understand its purpose, relation to Android, implementation details (where applicable), dynamic linking aspects, potential errors, and how Android components interact with it.

**2. Initial Examination of the Header File:**

The first step is to carefully read the provided code. Key observations:

* **Auto-generated:** The header explicitly states it's auto-generated. This immediately tells us it's likely derived from a more central definition (probably in the Linux kernel). We shouldn't expect to find complex function implementations *here*.
* **`#ifndef _UAPI_LINUX_NFS_H`:** Standard header guard to prevent multiple inclusions.
* **Includes `<linux/types.h>`:** This indicates it relies on basic Linux type definitions.
* **`#define` constants:**  A large number of `#define` directives define constants like port numbers (`NFS_PORT`), maximum lengths (`NFS_MAXDATA`, `NFS_MAXPATHLEN`), file handle size (`NFS_FHSIZE`), and file mode masks (`NFSMODE_DIR`, `NFSMODE_REG`). These are clearly related to the Network File System (NFS) protocol.
* **`enum nfs_stat`:**  Defines an enumeration of NFS status codes (error codes) like `NFSERR_PERM` (Permission denied), `NFSERR_NOENT` (No such file or directory), etc.
* **`enum nfs_ftype`:** Defines an enumeration of NFS file types like `NFREG` (Regular file), `NFDIR` (Directory), `NFLNK` (Symbolic link).

**3. Determining the File's Function:**

Based on the content, it's clear this header file defines constants and data types related to the **NFS protocol**. Specifically, it provides definitions that are used when interacting with an NFS server. The "uapi" in the path suggests it's part of the user-space API for interacting with the kernel's NFS implementation.

**4. Connecting to Android Functionality:**

The core of the connection is that **Android devices can act as NFS clients**. While not a core, universally used feature in typical Android usage, the underlying kernel supports NFS, and applications *could* potentially use it.

* **Example:** Imagine an Android application designed to manage files on a network attached storage (NAS) device that uses NFS. Such an app would need to use these constants and data types to interact correctly with the NFS server.

**5. Addressing the Libc Function Question:**

The header file itself **does not contain libc function implementations**. It only contains definitions. The *actual implementation* of NFS client functionality would reside in other parts of the operating system, likely within the kernel. The libc provides system call wrappers that applications use to interact with the kernel. So, while this header defines *what* the constants and types are, the *how* of using them involves system calls managed by the kernel and potentially wrapped by libc functions.

**6. Addressing Dynamic Linking:**

Since this header file primarily defines constants and enums, it doesn't directly involve dynamic linking in the typical sense of linking against a shared object (`.so`). However, the *usage* of these definitions in an Android app might involve dynamic linking.

* **Hypothetical Scenario:** An Android app using a third-party library to interact with NFS would have that library linked dynamically. The library, in turn, might use the definitions from `nfs.h`.
* **SO Layout:**  A typical `.so` would contain: `.text` (executable code), `.data` (initialized data), `.bss` (uninitialized data), `.rodata` (read-only data), symbol tables, relocation information, etc. The definitions from `nfs.h` would likely end up as constants in the `.rodata` section of the library (or potentially inlined directly in the code).
* **Linking Process:** The dynamic linker (`linker64` or `linker`) resolves symbols at runtime. If the app uses an NFS library, the linker would load that `.so` and resolve any external symbols the library depends on.

**7. Common Usage Errors:**

This section focuses on how developers might misuse the *concepts* represented in the header, even though they aren't directly calling functions *in* the header.

* **Incorrect status code handling:**  Failing to check the `nfs_stat` return value after an NFS operation.
* **Mismatched versions:**  Assuming a specific NFS version when the server uses a different one.
* **Path length issues:**  Exceeding `NFS_MAXPATHLEN`.

**8. Android Framework/NDK Path and Frida Hooking:**

This is about tracing the flow of control.

* **Framework:**  It's less likely that high-level Android framework APIs directly expose NFS interactions. It's more probable at the NDK level or through specialized libraries.
* **NDK:** An NDK developer could use standard C/C++ system calls (like `mount`, potentially through libraries like `libnfs`) that would eventually interact with the kernel's NFS implementation, which in turn relies on these definitions.
* **Frida Hooking:** The example shows how to intercept a system call (`syscall`) with a specific number (e.g., `SYS_openat`) and print arguments. This demonstrates how to observe low-level interactions related to file system operations, which *could* be related to NFS if the path points to an NFS-mounted directory.

**9. Refinement and Structure:**

The final step is to organize the information logically, using clear headings and bullet points for readability. It's important to address each part of the original prompt comprehensively and provide concrete examples where appropriate. The language should be clear and precise, explaining technical concepts in an accessible way. Acknowledging the limitations (like the absence of function implementations in the header itself) is also crucial.
## 对 bionic/libc/kernel/uapi/linux/nfs.h 的源代码分析

你提供的 `bionic/libc/kernel/uapi/linux/nfs.h` 文件是 Android Bionic 库中的一个头文件，它定义了与 Linux 内核中网络文件系统（NFS）相关的用户空间 API (uapi)。由于它是 `uapi` 目录下的文件，这意味着它是用户空间程序可以直接使用的接口定义，用于与内核中的 NFS 功能进行交互。

**功能列举:**

这个头文件主要定义了以下功能：

1. **NFS 协议相关的常量:**
   - `NFS_PROGRAM`: NFS 服务的程序号。
   - `NFS_PORT`: NFS 服务监听的默认 TCP 端口号。
   - `NFS_RDMA_PORT`: NFS over RDMA 使用的端口号。
   - `NFS_MAXDATA`: NFS 传输的最大数据块大小。
   - `NFS_MAXPATHLEN`: NFS 文件路径的最大长度。
   - `NFS_MAXNAMLEN`: NFS 文件名的最大长度。
   - `NFS_MAXGROUPS`: NFS 用户所属的最大组数。
   - `NFS_FHSIZE`: NFS 文件句柄的大小。
   - `NFS_COOKIESIZE`: NFS 目录操作中 cookie 的大小。
   - `NFS_FIFO_DEV`:  表示 FIFO 设备的特殊设备号。

2. **文件模式 (File Mode) 相关的宏定义:**
   - `NFSMODE_FMT`: 文件模式的掩码。
   - `NFSMODE_DIR`, `NFSMODE_CHR`, `NFSMODE_BLK`, `NFSMODE_REG`, `NFSMODE_LNK`, `NFSMODE_SOCK`, `NFSMODE_FIFO`: 分别表示目录、字符设备、块设备、普通文件、符号链接、套接字和命名管道的文件类型。

3. **NFS Mount 协议相关的常量:**
   - `NFS_MNT_PROGRAM`: NFS Mount 服务的程序号。
   - `NFS_MNT_VERSION`: NFS Mount 协议的版本号 1。
   - `NFS_MNT3_VERSION`: NFS Mount 协议的版本号 3。
   - `NFS_PIPE_DIRNAME`: 用于创建 NFS 管道的目录名 "nfs"。

4. **NFS 状态码 (Status Codes) 枚举 `nfs_stat`:**
   - 定义了 NFS 操作可能返回的各种错误状态码，例如 `NFS_OK` (成功), `NFSERR_PERM` (权限被拒绝), `NFSERR_NOENT` (文件或目录不存在) 等。这些状态码对应着 Linux 系统调用的 `errno` 值或 NFS 协议本身定义的错误码。

5. **NFS 文件类型 (File Types) 枚举 `nfs_ftype`:**
   - 定义了 NFS 可以识别的文件类型，例如 `NFNON` (未知), `NFREG` (普通文件), `NFDIR` (目录), `NFBLK` (块设备), `NFCHR` (字符设备), `NFLNK` (符号链接), `NFSOCK` (套接字), `NFBAD` (坏的文件句柄), `NFFIFO` (命名管道)。

**与 Android 功能的关系及其举例说明:**

虽然 NFS 在普通的 Android 手机用户中并不常见，但它在一些特定的 Android 应用场景中仍然可能被使用，例如：

* **企业级应用和文件共享:** 某些企业可能会使用 NFS 服务器来共享文件，Android 设备可以作为 NFS 客户端访问这些共享文件。
* **嵌入式 Android 设备:**  在一些嵌入式系统中，Android 设备可能需要与运行 Linux 的服务器或其他设备通过 NFS 共享数据。
* **开发和测试:**  Android 开发者可能会在本地搭建 NFS 服务器，用于测试 Android 应用与网络文件系统的交互。

**举例说明:**

假设一个 Android 应用需要读取 NFS 服务器上的一个文件。该应用可能会使用如下步骤（简化）：

1. **Mount NFS 文件系统:** 使用 `mount` 系统调用，指定 NFS 服务器的地址、共享目录和本地挂载点。`nfs.h` 中定义的 `NFS_PROGRAM` 和 `NFS_PORT` 等常量可能会被底层的 `mount` 实现使用。
2. **打开文件:** 使用 `open` 系统调用打开本地挂载点下的文件。内核会识别这是一个 NFS 文件系统上的文件，并将请求转发给 NFS 服务器。
3. **读取文件:** 使用 `read` 系统调用读取文件内容。内核会通过 NFS 协议与服务器交互，`NFS_MAXDATA` 可能会影响每次读取的数据量。
4. **处理错误:**  如果 NFS 服务器返回错误，内核会将错误码转换为相应的 `errno` 值。应用可以通过检查 `errno` 来判断操作是否成功，并根据 `nfs_stat` 枚举中定义的错误码进行更细致的错误处理。例如，如果 `errno` 对应 `NFSERR_NOENT`，则表示文件不存在。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个 `nfs.h` 文件本身** **不包含任何 libc 函数的实现**。它只是定义了一些常量和数据结构。  实际的 NFS 客户端功能实现是在 Linux 内核中完成的。

当 Android 应用调用与文件系统操作相关的 libc 函数（例如 `open`, `read`, `write`, `stat`, `mkdir` 等）时，如果这些操作的目标是 NFS 文件系统上的文件，那么 Bionic libc 会将这些调用转换为相应的 Linux 系统调用。内核接收到这些系统调用后，会识别出目标文件系统是 NFS，并使用内核中 NFS 客户端的实现与 NFS 服务器进行通信。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

由于 `nfs.h` 主要定义常量和数据结构，它本身不涉及 dynamic linker 的直接链接。然而，当一个 Android 应用使用与 NFS 相关的库（例如，如果存在一个专门用于 NFS 交互的第三方库）时，dynamic linker 会参与链接过程。

**SO 布局样本 (假设存在一个名为 `libnfsclient.so` 的 NFS 客户端库):**

```
libnfsclient.so:
    .interp         // 指示动态链接器路径
    .note.android.ident
    .android_metadata
    .dynsym         // 动态符号表
    .symtab         // 符号表
    .strtab         // 字符串表
    .dynstr         // 动态字符串表
    .hash           // 哈希表
    .plt            // 过程链接表
    .got.plt        // 全局偏移量表 (PLT)
    .text           // 代码段
    .rodata         // 只读数据段 (可能包含 nfs.h 中定义的常量)
    .data           // 已初始化数据段
    .bss            // 未初始化数据段
    .dynamic        // 动态链接信息
    .gnu.hash
    ...
```

**链接的处理过程:**

1. **加载器启动:** 当 Android 系统启动一个使用了 `libnfsclient.so` 的应用时，加载器 (通常是 `linker64` 或 `linker`) 会被调用。
2. **加载 SO 文件:** 加载器会根据应用的依赖关系加载 `libnfsclient.so` 到内存中。
3. **解析动态链接信息:** 加载器会解析 `.dynamic` 段，获取链接所需的各种信息，例如依赖的库、符号表位置等。
4. **重定位:** 加载器会根据 `.rel.plt` 和 `.rel.dyn` 等重定位段的信息，修改代码和数据段中的地址，使其指向正确的内存位置。例如，如果 `libnfsclient.so` 中调用了 libc 中的函数，加载器会更新 GOT 表中的条目，指向 libc 中对应函数的地址。
5. **符号解析:** 加载器会使用 `.dynsym` 和 `.hash` 等信息，解析 `libnfsclient.so` 中引用的外部符号，例如 libc 中的函数或系统调用。
6. **执行:** 完成链接后，应用的代码开始执行，`libnfsclient.so` 中的代码就可以调用 libc 中的函数或发起系统调用，最终可能涉及到与 NFS 服务器的交互。

**对于涉及 dynamic linker 的功能，`nfs.h` 本身并不直接参与动态链接过程，它只是定义了可能被其他动态链接库使用的常量和数据结构。**

**如果做了逻辑推理，请给出假设输入与输出:**

`nfs.h` 文件主要是定义，不涉及复杂的逻辑推理。但可以假设一个使用该头文件的场景：

**假设输入:**

一个 Android 应用尝试打开一个 NFS 挂载点下的文件 `/mnt/nfs_share/my_file.txt`，该文件实际存在于 NFS 服务器上。

**逻辑推理:**

1. 应用调用 `open("/mnt/nfs_share/my_file.txt", O_RDONLY)`。
2. Bionic libc 将该调用转换为 `openat` 系统调用。
3. Linux 内核的文件系统层识别出 `/mnt/nfs_share` 是一个 NFS 挂载点。
4. 内核 NFS 客户端会根据 NFS 协议与 NFS 服务器通信，请求打开该文件。
5. 服务器返回成功状态（`NFS_OK` 对应的内核成功状态）。

**假设输出:**

`open` 系统调用返回一个非负的文件描述符，表示文件打开成功。如果服务器返回错误，例如文件不存在，则 `open` 系统调用会返回 -1，并设置 `errno` 为 `ENOENT` (或者对应的 NFS 错误码，例如 `NFSERR_NOENT`)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误地解释 NFS 状态码:**  开发者可能没有正确地映射 `nfs_stat` 枚举中的错误码到相应的用户可见的错误信息，导致用户看到的错误信息不够准确。
2. **假设 NFS 服务器总是可用:** 应用可能没有处理 NFS 服务器不可用或网络连接中断的情况，导致程序崩溃或无响应。
3. **路径长度超出限制:** 尝试创建或访问路径长度超过 `NFS_MAXPATHLEN` 的文件，导致操作失败。
4. **文件名长度超出限制:** 尝试创建文件名长度超过 `NFS_MAXNAMLEN` 的文件，导致操作失败。
5. **权限问题:**  Android 应用运行在特定的用户上下文中，可能由于权限不足无法访问 NFS 服务器上的文件，导致返回 `NFSERR_PERM`。
6. **NFS 版本不兼容:**  如果客户端和服务器使用的 NFS 版本不兼容，可能会导致一些操作失败。虽然 `nfs.h` 中定义了版本号，但具体的版本协商和处理是在内核层面完成的。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `nfs.h` 的路径（可能性较低）：**

通常情况下，Android Framework 自身很少直接操作底层的 NFS 协议。Framework 更多地关注于提供更高级别的抽象，例如 Content Providers, MediaStore 等。然而，在某些特定的定制化 ROM 或企业级应用中，可能会有 Framework 组件需要与 NFS 服务器交互。

如果 Framework 需要操作 NFS，它可能会：

1. **调用 NDK 中的 C/C++ 代码:** Framework 可以通过 JNI (Java Native Interface) 调用 NDK 中编写的 C/C++ 代码。
2. **NDK 代码使用 libc 函数:** NDK 代码可以使用 Bionic libc 提供的文件操作函数，例如 `open`, `read`, `write` 等。
3. **libc 函数转换为系统调用:** 当操作目标是 NFS 文件系统时，libc 函数会将操作转换为相应的 Linux 系统调用。
4. **内核处理 NFS 系统调用:** Linux 内核接收到系统调用后，会识别出目标是 NFS 文件系统，并使用内核的 NFS 客户端实现与 NFS 服务器通信。在这个过程中，内核会使用到 `nfs.h` 中定义的常量和数据结构。

**NDK 到达 `nfs.h` 的路径（更常见）：**

使用 NDK 开发的应用可以直接调用 Bionic libc 提供的函数，因此路径更直接：

1. **NDK 代码调用 libc 函数:** NDK 开发的应用可以直接使用 `<fcntl.h>`, `<unistd.h>` 等头文件中声明的 libc 函数进行文件操作。
2. **libc 函数转换为系统调用:**  如果操作的是 NFS 挂载点下的文件，libc 函数会将调用转换为相应的系统调用。
3. **内核处理 NFS 系统调用:**  与上述步骤相同。

**Frida Hook 示例调试步骤:**

假设你想观察一个使用了 NFS 的 Android 应用在打开文件时的系统调用：

```python
import frida
import sys

package_name = "your.nfs.app"  # 替换为你的应用包名
file_path_to_monitor = "/mnt/nfs_share/target_file.txt" # 你要监控的文件路径

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "openat"), {
    onEnter: function(args) {
        const dirfd = args[0].toInt32();
        const pathnamePtr = args[1];
        const flags = args[2].toInt32();
        const pathname = pathnamePtr.readUtf8String();

        if (pathname.includes("%s")) {
            send({
                "type": "syscall",
                "name": "openat",
                "dirfd": dirfd,
                "pathname": pathname,
                "flags": flags
            });
        }
    },
    onLeave: function(retval) {
        send({
            "type": "syscall_ret",
            "name": "openat",
            "retval": retval.toInt32()
        });
    }
});
""" % file_path_to_monitor

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例解释:**

1. **导入 Frida 库:** 导入必要的 Frida 库。
2. **指定包名和监控路径:** 设置要监控的应用包名和 NFS 文件路径。
3. **连接到应用进程:** 使用 Frida 连接到目标 Android 应用进程。
4. **Frida Script:**
   - 使用 `Interceptor.attach` hook 了 `openat` 函数。`openat` 是 `open` 的一个变体，更常用。
   - `onEnter` 函数在 `openat` 被调用时执行，它读取函数参数，包括目录文件描述符 `dirfd`，文件路径 `pathname`，和打开标志 `flags`。
   - 代码检查 `pathname` 是否包含我们要监控的目标 NFS 文件路径。
   - 如果路径匹配，则通过 `send` 函数发送一个消息，包含系统调用名称和参数。
   - `onLeave` 函数在 `openat` 调用返回时执行，发送返回值。
5. **加载和运行 Script:** 将 Frida script 加载到目标进程并开始运行。
6. **观察输出:** 当应用尝试打开指定 NFS 文件时，Frida 会拦截到 `openat` 调用，并打印出相关信息，包括调用的路径和返回值。

通过这个 Frida Hook 示例，你可以观察到 Android 应用（无论是 Framework 还是 NDK 应用）在访问 NFS 文件时，底层是如何调用 `openat` 系统调用的。你可以进一步 hook 与 NFS 相关的其他系统调用或内核函数来更深入地调试。

请注意，直接 hook 内核函数通常需要 root 权限和更高级的 Frida 使用技巧。 hook libc 函数通常更容易实现。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/nfs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_NFS_H
#define _UAPI_LINUX_NFS_H
#include <linux/types.h>
#define NFS_PROGRAM 100003
#define NFS_PORT 2049
#define NFS_RDMA_PORT 20049
#define NFS_MAXDATA 8192
#define NFS_MAXPATHLEN 1024
#define NFS_MAXNAMLEN 255
#define NFS_MAXGROUPS 16
#define NFS_FHSIZE 32
#define NFS_COOKIESIZE 4
#define NFS_FIFO_DEV (- 1)
#define NFSMODE_FMT 0170000
#define NFSMODE_DIR 0040000
#define NFSMODE_CHR 0020000
#define NFSMODE_BLK 0060000
#define NFSMODE_REG 0100000
#define NFSMODE_LNK 0120000
#define NFSMODE_SOCK 0140000
#define NFSMODE_FIFO 0010000
#define NFS_MNT_PROGRAM 100005
#define NFS_MNT_VERSION 1
#define NFS_MNT3_VERSION 3
#define NFS_PIPE_DIRNAME "nfs"
enum nfs_stat {
  NFS_OK = 0,
  NFSERR_PERM = 1,
  NFSERR_NOENT = 2,
  NFSERR_IO = 5,
  NFSERR_NXIO = 6,
  NFSERR_EAGAIN = 11,
  NFSERR_ACCES = 13,
  NFSERR_EXIST = 17,
  NFSERR_XDEV = 18,
  NFSERR_NODEV = 19,
  NFSERR_NOTDIR = 20,
  NFSERR_ISDIR = 21,
  NFSERR_INVAL = 22,
  NFSERR_FBIG = 27,
  NFSERR_NOSPC = 28,
  NFSERR_ROFS = 30,
  NFSERR_MLINK = 31,
  NFSERR_NAMETOOLONG = 63,
  NFSERR_NOTEMPTY = 66,
  NFSERR_DQUOT = 69,
  NFSERR_STALE = 70,
  NFSERR_REMOTE = 71,
  NFSERR_WFLUSH = 99,
  NFSERR_BADHANDLE = 10001,
  NFSERR_NOT_SYNC = 10002,
  NFSERR_BAD_COOKIE = 10003,
  NFSERR_NOTSUPP = 10004,
  NFSERR_TOOSMALL = 10005,
  NFSERR_SERVERFAULT = 10006,
  NFSERR_BADTYPE = 10007,
  NFSERR_JUKEBOX = 10008,
  NFSERR_SAME = 10009,
  NFSERR_DENIED = 10010,
  NFSERR_EXPIRED = 10011,
  NFSERR_LOCKED = 10012,
  NFSERR_GRACE = 10013,
  NFSERR_FHEXPIRED = 10014,
  NFSERR_SHARE_DENIED = 10015,
  NFSERR_WRONGSEC = 10016,
  NFSERR_CLID_INUSE = 10017,
  NFSERR_RESOURCE = 10018,
  NFSERR_MOVED = 10019,
  NFSERR_NOFILEHANDLE = 10020,
  NFSERR_MINOR_VERS_MISMATCH = 10021,
  NFSERR_STALE_CLIENTID = 10022,
  NFSERR_STALE_STATEID = 10023,
  NFSERR_OLD_STATEID = 10024,
  NFSERR_BAD_STATEID = 10025,
  NFSERR_BAD_SEQID = 10026,
  NFSERR_NOT_SAME = 10027,
  NFSERR_LOCK_RANGE = 10028,
  NFSERR_SYMLINK = 10029,
  NFSERR_RESTOREFH = 10030,
  NFSERR_LEASE_MOVED = 10031,
  NFSERR_ATTRNOTSUPP = 10032,
  NFSERR_NO_GRACE = 10033,
  NFSERR_RECLAIM_BAD = 10034,
  NFSERR_RECLAIM_CONFLICT = 10035,
  NFSERR_BAD_XDR = 10036,
  NFSERR_LOCKS_HELD = 10037,
  NFSERR_OPENMODE = 10038,
  NFSERR_BADOWNER = 10039,
  NFSERR_BADCHAR = 10040,
  NFSERR_BADNAME = 10041,
  NFSERR_BAD_RANGE = 10042,
  NFSERR_LOCK_NOTSUPP = 10043,
  NFSERR_OP_ILLEGAL = 10044,
  NFSERR_DEADLOCK = 10045,
  NFSERR_FILE_OPEN = 10046,
  NFSERR_ADMIN_REVOKED = 10047,
  NFSERR_CB_PATH_DOWN = 10048,
};
enum nfs_ftype {
  NFNON = 0,
  NFREG = 1,
  NFDIR = 2,
  NFBLK = 3,
  NFCHR = 4,
  NFLNK = 5,
  NFSOCK = 6,
  NFBAD = 7,
  NFFIFO = 8
};
#endif
```