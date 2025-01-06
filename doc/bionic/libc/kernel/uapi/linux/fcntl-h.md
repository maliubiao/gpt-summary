Response:
Let's break down the thought process for answering the user's request about `fcntl.handroid`.

**1. Understanding the Context:**

The very first thing to recognize is the file path: `bionic/libc/kernel/uapi/linux/fcntl.handroid`. This tells us several crucial things:

* **`bionic`:** This is Android's C library. So, the contents are related to low-level system calls and functionality used by Android.
* **`libc`:**  It's part of the C library, meaning it likely defines constants and structures used by system calls related to file control.
* **`kernel`:** This indicates it's a *header* file that defines the interface between user-space (like `libc`) and the Linux kernel. The "uapi" further reinforces this (User-space API).
* **`linux`:**  These are Linux kernel definitions, although Android's kernel is based on Linux.
* **`fcntl.handroid`:** The `fcntl` part strongly suggests this file deals with file control related system calls. The `.handroid` suffix implies Android-specific additions or customizations to the standard Linux `fcntl.h`.

**2. Initial Analysis of the File Content:**

Scanning the content, the prominent features are:

* **`#ifndef _UAPI_LINUX_FCNTL_H` and `#define _UAPI_LINUX_FCNTL_H`:**  This is a standard header guard, preventing multiple inclusions.
* **`#include <asm/fcntl.h>` and `#include <linux/openat2.h>`:**  It includes other header files, indicating dependencies on core `fcntl` definitions and the `openat2` system call. This suggests that `fcntl.handroid` builds upon existing Linux functionality.
* **`#define F_SETLEASE ...` and similar `#define` statements starting with `F_`:**  These are likely definitions of flags or commands used with the `fcntl()` system call. The `F_LINUX_SPECIFIC_BASE` strongly suggests these are additions specific to the Linux kernel (or its Android adaptation).
* **`#define F_SEAL_SEAL ...` and similar `#define` statements starting with `F_SEAL_`:** These look like specific flags related to file sealing functionality.
* **`#define RWH_WRITE_LIFE_NOT_SET ...` and similar `#define` statements starting with `RWH_` and `RWF_`:** These seem related to read/write hints or lifetime management for file operations.
* **`#define DN_ACCESS ...` and similar `#define` statements starting with `DN_`:** These likely define flags for directory notification mechanisms.
* **`#define AT_FDCWD ...` and similar `#define` statements starting with `AT_`:** These are flags used with "at" family of system calls like `openat`, `fstatat`, etc., which allow specifying file paths relative to directory file descriptors.

**3. Answering the User's Questions Systematically:**

Now, let's address each part of the user's request:

* **功能列表 (List of Functions):** The file doesn't define *functions* in the traditional sense of code blocks. It defines *constants* (macros). So, the "functionality" is the *set of operations and options* these constants represent, which are used with the `fcntl()` and related system calls. I listed the broad categories of these constants (file leases, notifications, seals, read/write hints, etc.).

* **与 Android 功能的关系 (Relationship to Android Functionality):** This requires connecting the defined constants to how Android uses file system features. Examples are crucial here:
    * **`F_NOTIFY`:**  Linking this to file system monitoring used by file managers or media scanners.
    * **`F_OFD_SETLK` (implicitly included via `<asm/fcntl.h>`):**  Illustrating file locking used for synchronization.
    * **`AT_FDCWD` and `AT_RECURSIVE`:** Explaining how "at" family calls improve security and efficiency in app development.

* **libc 函数实现 (Implementation of libc Functions):**  This is a key point of potential confusion. This file *doesn't implement libc functions*. It *defines constants* that are *used by* libc functions like `fcntl()`, `openat()`, etc. The implementation of these functions resides in the `bionic` library's source code (not this header file) and eventually makes system calls to the kernel. The explanation needs to clarify this distinction.

* **dynamic linker 功能 (Dynamic Linker Functionality):** This file has *no direct* relationship to the dynamic linker. It defines constants for kernel system calls. The dynamic linker is involved in loading and linking shared libraries. It doesn't directly use these `fcntl` constants for its primary tasks. It's important to state this clearly and avoid making false connections.

* **逻辑推理 (Logical Inference):** Since the file primarily defines constants, there isn't much "logical inference" to be done in the sense of a function taking input and producing output. The "inference" lies in understanding the *purpose* of these constants within the broader context of file system operations. I provided examples of how these flags *might* be used with `fcntl()`.

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  This focuses on how developers might misuse the *libc functions* that *use* these constants. Examples include incorrect flag combinations, ignoring return values, and race conditions with file locking.

* **Android Framework/NDK 到达这里的步骤 (How Android Framework/NDK Reaches Here):** This involves tracing the call stack from a high-level Android API down to the system call level. The example with `FileOutputStream` is a good illustration:  Java -> NDK (JNI) -> libc (`open`, `fcntl`) -> kernel (using the constants defined here).

* **Frida Hook 示例 (Frida Hook Example):**  A practical example of how to intercept calls to `fcntl` and examine the flags being used, which could include the constants defined in this header. This demonstrates how to debug and observe the usage of these constants.

**4. Refinement and Language:**

Throughout the process, the language used needs to be clear, concise, and accurate. Explaining technical concepts requires avoiding jargon where possible or defining it when necessary. Using examples helps to make the abstract concepts more concrete. The request was in Chinese, so the final answer should also be in Chinese.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The key is to understand the context, analyze the content, and address each part of the user's request systematically, paying attention to the relationships between the header file, libc functions, the kernel, and the Android framework.
这个文件 `bionic/libc/kernel/uapi/linux/fcntl.handroid` 是 Android Bionic C 库中一个用于定义文件控制相关常量和宏的头文件。它主要定义了用于 `fcntl()` 系统调用以及其他相关系统调用的用户空间 API（UAPI）。这些定义与 Linux 内核中的定义相对应，并且可能包含 Android 特有的扩展或修改。

**它的功能：**

这个文件的主要功能是定义一系列宏常量，这些常量用于：

1. **文件锁 (File Locks):** 虽然这个文件中没有显式定义 `F_GETLK`, `F_SETLK`, `F_SETLKW` 等传统的锁操作，但它包含了可能与其他锁机制相关的常量，例如 `F_CANCELLK`。  传统的锁操作定义通常在 `<asm/fcntl.h>` 中，这个文件包含了它。
2. **文件租借 (File Leases):** 定义了与文件租借相关的操作，允许进程请求对文件的某种访问权限，内核会在其他进程尝试冲突访问时通知租借者。`F_SETLEASE` 和 `F_GETLEASE` 用于设置和获取租借。
3. **文件通知 (File Notification):** 定义了与文件事件通知相关的操作 `F_NOTIFY`，允许进程监控目录或文件中的特定事件（例如，创建、删除、修改）。
4. **文件描述符复制查询 (File Descriptor Duplication Query):** 定义了 `F_DUPFD_QUERY` 和 `F_DUPFD_CLOEXEC`，用于查询可用的文件描述符或者创建设置了 `FD_CLOEXEC` 标志的重复文件描述符。
5. **文件创建查询 (File Created Query):** 定义了 `F_CREATED_QUERY`，其具体用途可能与查询文件是否是新创建的有关。
6. **取消锁 (Cancel Lock):** 定义了 `F_CANCELLK`，用于取消文件锁。
7. **管道缓冲区大小 (Pipe Buffer Size):** 定义了 `F_SETPIPE_SZ` 和 `F_GETPIPE_SZ`，用于设置和获取管道的缓冲区大小。
8. **文件密封 (File Seals):** 定义了与文件密封相关的操作 `F_ADD_SEALS` 和 `F_GET_SEALS` 以及具体的 seal 类型（`F_SEAL_SEAL`, `F_SEAL_SHRINK`, `F_SEAL_GROW`, `F_SEAL_WRITE`, `F_SEAL_FUTURE_WRITE`, `F_SEAL_EXEC`）。文件密封允许限制对文件的进一步操作，例如防止写入、收缩或执行。
9. **读写提示 (Read/Write Hints):** 定义了 `F_GET_RW_HINT`, `F_SET_RW_HINT`, `F_GET_FILE_RW_HINT`, `F_SET_FILE_RW_HINT` 以及相关的 hint 值（`RWH_WRITE_LIFE_NOT_SET` 等），允许程序向内核提供关于文件读写模式的提示，以优化性能。
10. **目录通知标志 (Directory Notification Flags):** 定义了 `DN_ACCESS`, `DN_MODIFY` 等用于 `F_NOTIFY` 的标志，指定需要监控的目录事件类型。
11. **`*at` 系统调用标志 (Flags for `*at` System Calls):** 定义了诸如 `AT_FDCWD`, `AT_SYMLINK_NOFOLLOW`, `AT_RECURSIVE` 等标志，这些标志用于像 `openat`, `mkdirat`, `unlinkat` 这样的系统调用，允许操作相对于目录文件描述符的文件路径。

**与 Android 功能的关系及举例说明：**

这些定义直接影响 Android 系统中文件操作的各个方面。

* **文件锁：** Android 系统中的进程可以使用文件锁来同步对共享文件的访问，避免数据竞争。例如，一个应用可能使用文件锁来确保只有一个进程可以同时写入数据库文件。
* **文件租借：** Android 的文件系统服务可能会使用文件租借来优化缓存和同步。例如，媒体服务器可能租借对媒体文件的读取权限，内核可以在其他进程尝试修改该文件时通知媒体服务器。
* **文件通知：** Android 的文件系统监控服务 (如 `FileSystemObserver`) 和媒体扫描器会使用 `F_NOTIFY` 来监听文件系统的变化，以便及时更新文件索引或触发相应的操作。例如，当用户下载了一个新的图片，媒体扫描器可以通过文件通知知道，并将其添加到媒体库中。
* **管道缓冲区大小：** Android 中的进程间通信 (IPC) 机制可能会用到管道。通过 `F_SETPIPE_SZ` 可以调整管道缓冲区的大小，以优化数据传输效率。
* **文件密封：** Android 可以使用文件密封来增强安全性。例如，系统应用的关键配置文件可能会被密封，防止被恶意应用修改。`F_SEAL_WRITE` 可以阻止对文件的写入。
* **读写提示：** Android 的文件系统层可能会利用读写提示来优化 I/O 调度。例如，在顺序读取大文件时，可以设置相应的提示，让内核预取更多数据。
* **`*at` 系统调用：**  Android 应用和服务可以使用 `openat` 等系统调用来避免 TOCTOU (Time-of-check Time-of-use) 漏洞，并简化相对路径操作。例如，一个应用可以使用 `openat(dirfd, "relative_path", ...)` 来安全地打开相对于 `dirfd` 指向的目录的文件。

**每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **不包含 libc 函数的实现**，它只定义了传递给 `fcntl()` 和其他相关系统调用的常量。libc 中的 `fcntl()` 函数是一个包装器，它将用户空间的参数传递给内核的 `sys_fcntl` 系统调用。

`fcntl()` 函数的基本实现流程如下：

1. **用户空间调用 `fcntl(fd, cmd, arg)`:** 用户程序调用 `bionic` 提供的 `fcntl` 函数，传递文件描述符 `fd`，命令 `cmd`（例如，`F_SETLK`，`F_GETFL`），以及可选的参数 `arg`。
2. **libc 包装器:** `bionic` 中的 `fcntl` 函数会将这些参数打包，并使用系统调用指令（例如，`syscall`）陷入内核。
3. **内核处理:** Linux 内核接收到系统调用请求，根据系统调用号（`fcntl` 对应一个特定的号码）和传递的命令 `cmd`，执行相应的内核逻辑。
4. **内核操作:** 内核会根据 `cmd` 执行不同的操作，例如：
   - `F_GETFL`: 获取文件描述符的状态标志。
   - `F_SETFL`: 设置文件描述符的状态标志（例如，非阻塞 I/O）。
   - `F_SETLK`, `F_GETLK`: 执行或查询文件锁。
   - `F_NOTIFY`: 设置文件通知。
   - 其他在此文件中定义的 `F_*` 命令。
5. **返回结果:** 内核操作完成后，将结果返回给 `bionic` 的 `fcntl` 包装器。
6. **返回用户空间:** `bionic` 的 `fcntl` 包装器将内核返回的结果传递给调用它的用户程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件 **不直接涉及 dynamic linker 的功能**。 dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的地址空间，并解析库之间的符号依赖关系。

尽管如此，`fcntl()` 系统调用本身可能会在 dynamic linker 的某些操作中使用，例如，在加载共享库时可能会需要操作文件描述符。

**SO 布局样本：**

一个典型的 Android `.so` 文件布局包含以下部分：

```
ELF Header:
  ...
Program Headers:
  LOAD ... R E ... (可读可执行段，通常包含 .text 代码段)
  LOAD ... R   ... (可读数据段，通常包含 .rodata 只读数据段)
  LOAD ... RW  ... (可读写数据段, 通常包含 .data 和 .bss 段)
  DYNAMIC ...       (动态链接信息)
  ...
Section Headers:
  .text ...        (代码段)
  .rodata ...      (只读数据段)
  .data ...        (已初始化数据段)
  .bss ...         (未初始化数据段)
  .symtab ...      (符号表)
  .strtab ...      (字符串表)
  .dynsym ...      (动态符号表)
  .dynstr ...      (动态字符串表)
  .rel.dyn ...     (动态重定位表)
  .rel.plt ...     (PLT 重定位表)
  ...
```

**链接的处理过程：**

1. **加载 SO 文件:** 当程序需要使用一个共享库时，内核会将控制权交给 dynamic linker。dynamic linker 打开 `.so` 文件，读取其 ELF header 和 program headers，确定需要加载到内存的段及其地址。
2. **内存映射:** dynamic linker 使用 `mmap()` 系统调用将 `.so` 文件的各个段映射到进程的地址空间。这可能涉及到操作文件描述符，虽然 `fcntl` 不一定直接参与这个过程，但文件描述符是 `mmap` 的必要参数。
3. **符号解析:** dynamic linker 遍历 `.so` 文件的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，找到需要解析的外部符号。
4. **重定位:** dynamic linker 根据重定位表 (`.rel.dyn`, `.rel.plt`) 中的信息，修改代码和数据段中的地址，使其指向正确的符号地址。这个过程也可能需要读取和写入内存，但通常不涉及 `fcntl`。
5. **依赖库加载:** 如果被加载的 `.so` 文件依赖于其他共享库，dynamic linker 会递归地加载这些依赖库。
6. **执行初始化代码:** dynamic linker 执行 `.init` 段中的初始化代码，并调用构造函数 (`.ctors`)。

**逻辑推理、假设输入与输出：**

由于这个文件主要定义常量，没有可执行的逻辑，所以在这里进行逻辑推理意义不大。  但是，我们可以假设一个使用这些常量的场景：

**假设输入：**

一个程序想要监控目录 `/sdcard/Download` 下的所有创建事件。

**逻辑推理：**

1. 程序需要打开 `/sdcard/Download` 目录以获取其文件描述符。
2. 程序需要使用 `fcntl()` 系统调用，命令设置为 `F_NOTIFY`。
3. `F_NOTIFY` 的参数需要包含要监控的事件类型，这里是 `DN_CREATE`。

**假设输出（通过 `fcntl` 设置通知后）：**

当有新的文件在 `/sdcard/Download` 目录下被创建时，程序会收到一个内核信号（通常是 `SIGIO` 或 `SIGEV_SIGNAL`），通知它发生了指定类型的事件。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **不正确的标志组合：** 例如，在调用 `fcntl(fd, F_SETFL, O_NONBLOCK)` 时，如果错误地使用了其他不相关的标志，可能会导致意外的行为。
2. **忘记检查返回值：** `fcntl()` 调用可能会失败，例如，由于无效的命令或参数。忽略返回值可能导致程序逻辑错误或崩溃。
3. **文件锁的死锁：** 如果多个进程以不一致的顺序请求文件锁，可能会导致死锁。
4. **滥用 `F_NOTIFY`：** 监控大量目录或监控过于频繁的事件可能导致性能问题。
5. **错误地使用 `*at` 系统调用：** 例如，忘记 `AT_FDCWD` 的含义，或者在多线程环境下不正确地管理目录文件描述符，可能导致安全漏洞或逻辑错误。
6. **不理解文件密封的限制：** 尝试对已密封的文件执行被禁止的操作会导致错误，如果没有正确处理这些错误，可能会导致程序异常。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

**Android Framework 到达这里的步骤：**

1. **Java Framework API 调用：**  Android Framework 中的某些 Java API 最终会涉及到文件操作。例如，`java.io.FileOutputStream` 用于写入文件，`java.nio.channels.FileChannel` 可以执行更底层的 I/O 操作，包括文件锁。
2. **JNI 调用：** 这些 Java API 的底层实现通常会通过 JNI (Java Native Interface) 调用到 Android 运行库 (ART) 中的本地代码。
3. **NDK (Native Development Kit) 或 Bionic libc：** ART 中的本地代码会调用 NDK 提供的 C/C++ 接口，或者直接调用 Bionic libc 中的函数，例如 `open()`, `write()`, `close()`, `fcntl()`, 等。
4. **系统调用：** Bionic libc 中的这些函数是系统调用的包装器，它们会将参数传递给 Linux 内核。例如，`fcntl()` 函数会最终调用到内核的 `sys_fcntl` 系统调用。
5. **内核处理：** 内核接收到 `sys_fcntl` 系统调用，根据传递的命令和参数，执行相应的操作，这些操作的参数和行为受到 `bionic/libc/kernel/uapi/linux/fcntl.handroid` 中定义的常量的影响。

**NDK 到达这里的步骤：**

1. **NDK 代码调用 libc 函数：** 使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic libc 提供的函数，例如 `fcntl()`, `openat()`, 等。
2. **系统调用：** 这些 libc 函数会执行相应的系统调用，最终到达内核。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `fcntl()` 系统调用并打印其参数的示例：

```javascript
// attach 到目标进程
function hook_fcntl() {
    const fcntlPtr = Module.findExportByName("libc.so", "fcntl");
    if (fcntlPtr) {
        Interceptor.attach(fcntlPtr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const cmd = args[1].toInt32();
                const arg = args[2];

                console.log("fcntl called");
                console.log("  fd:", fd);
                console.log("  cmd:", cmd, "(0x" + cmd.toString(16) + ")");
                // 根据 cmd 的值，尝试解析 arg
                if (cmd === /* 例如 F_SETFL 的值 */ 4) {
                    console.log("  arg (flags):", arg.toInt32(), "(0x" + arg.toInt32().toString(16) + ")");
                } else if (cmd === /* 例如 F_SETLK 的值 */ 14) {
                    // 解析 struct flock
                    const type = arg.readInt16();
                    const whence = arg.add(2).readInt16();
                    const start = arg.add(4).readInt64();
                    const len = arg.add(12).readInt64();
                    const pid = arg.add(20).readInt32();
                    console.log("  arg (flock):");
                    console.log("    l_type:", type);
                    console.log("    l_whence:", whence);
                    console.log("    l_start:", start.toString());
                    console.log("    l_len:", len.toString());
                    console.log("    l_pid:", pid);
                } else if (cmd >= 1024) { // F_LINUX_SPECIFIC_BASE 开始的命令
                    console.log("  arg:", arg.toInt32(), "(0x" + arg.toInt32().toString(16) + ")");
                }
            },
            onLeave: function (retval) {
                console.log("fcntl returned:", retval.toInt32());
            }
        });
    } else {
        console.log("Failed to find fcntl in libc.so");
    }
}

rpc.exports = {
    hook_fcntl: hook_fcntl
};
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_fcntl.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_fcntl.js --no-pause
   ```
   或者，如果进程已经运行：
   ```bash
   frida -U <package_name> -l hook_fcntl.js
   ```
3. 在 Frida 控制台中调用 `hook_fcntl()` 函数：
   ```
   frida> rpc.exports.hook_fcntl()
   ```

这样，当目标进程调用 `fcntl()` 时，Frida 会拦截该调用并打印出文件描述符、命令以及参数的值。你可以根据 `cmd` 的值来判断使用了哪个 `F_*` 宏，从而了解 Android Framework 或 NDK 如何使用这些文件控制机制。  你需要根据具体的 `cmd` 值来解析 `arg` 参数，因为 `arg` 的类型和含义取决于 `cmd` 的值。 这个头文件中的常量可以帮助你理解 `cmd` 的具体含义。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/fcntl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_FCNTL_H
#define _UAPI_LINUX_FCNTL_H
#include <asm/fcntl.h>
#include <linux/openat2.h>
#define F_SETLEASE (F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE + 1)
#define F_NOTIFY (F_LINUX_SPECIFIC_BASE + 2)
#define F_DUPFD_QUERY (F_LINUX_SPECIFIC_BASE + 3)
#define F_CREATED_QUERY (F_LINUX_SPECIFIC_BASE + 4)
#define F_CANCELLK (F_LINUX_SPECIFIC_BASE + 5)
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#define F_SEAL_FUTURE_WRITE 0x0010
#define F_SEAL_EXEC 0x0020
#define F_GET_RW_HINT (F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT (F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT (F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT (F_LINUX_SPECIFIC_BASE + 14)
#define RWH_WRITE_LIFE_NOT_SET 0
#define RWH_WRITE_LIFE_NONE 1
#define RWH_WRITE_LIFE_SHORT 2
#define RWH_WRITE_LIFE_MEDIUM 3
#define RWH_WRITE_LIFE_LONG 4
#define RWH_WRITE_LIFE_EXTREME 5
#define RWF_WRITE_LIFE_NOT_SET RWH_WRITE_LIFE_NOT_SET
#define DN_ACCESS 0x00000001
#define DN_MODIFY 0x00000002
#define DN_CREATE 0x00000004
#define DN_DELETE 0x00000008
#define DN_RENAME 0x00000010
#define DN_ATTRIB 0x00000020
#define DN_MULTISHOT 0x80000000
#define AT_FDCWD - 100
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_SYMLINK_FOLLOW 0x400
#define AT_NO_AUTOMOUNT 0x800
#define AT_EMPTY_PATH 0x1000
#define AT_STATX_SYNC_TYPE 0x6000
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC 0x2000
#define AT_STATX_DONT_SYNC 0x4000
#define AT_RECURSIVE 0x8000
#define AT_RENAME_NOREPLACE 0x0001
#define AT_RENAME_EXCHANGE 0x0002
#define AT_RENAME_WHITEOUT 0x0004
#define AT_EACCESS 0x200
#define AT_REMOVEDIR 0x200
#define AT_HANDLE_FID 0x200
#define AT_HANDLE_MNT_ID_UNIQUE 0x001
#endif

"""

```