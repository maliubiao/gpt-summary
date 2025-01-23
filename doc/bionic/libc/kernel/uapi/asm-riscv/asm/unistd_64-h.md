Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The fundamental request is to analyze a header file (`unistd_64.h`) containing system call numbers for RISC-V 64-bit architecture on Android (bionic). The key is to explain the *purpose* of this file and connect it to the broader Android system.

**2. Initial Analysis of the File:**

The first thing I notice is the structure: `#define __NR_... <number>`. This clearly indicates that this file defines constants representing system call numbers. The comment at the top reinforces this by stating it's auto-generated and modifications will be lost.

**3. Identifying Key Concepts:**

From this initial analysis, several key concepts emerge:

* **System Calls:** The file defines system call numbers. I need to explain what system calls are and their role in an operating system.
* **RISC-V 64-bit:** This specifies the architecture. It's important to mention this context.
* **Android (bionic):**  This tells me the specific environment. I need to connect the system calls to Android's functioning.
* **`unistd.h` (or its variants):**  I recognize the naming convention and know this file provides the interface for user-space programs to access kernel functionality.
* **Auto-generated:**  This hints that there's a build process involved, but I don't need to delve into the details of that process unless specifically asked.

**4. Structuring the Answer:**

Given the multi-faceted nature of the request, I decide to structure the answer into logical sections to address each point clearly:

* **文件功能:**  Start with the most basic purpose of the file.
* **与 Android 功能的关系:** Explain how these system calls relate to Android's operation, providing concrete examples.
* **libc 函数实现:**  This requires careful wording. The header file *doesn't* implement libc functions. It provides the *numbers* that libc uses to *make* system calls. It's crucial to clarify this distinction. I need to describe the typical mechanism of how a libc function interacts with the kernel using these numbers.
* **Dynamic Linker 功能:**  This is tricky because this file doesn't directly contain dynamic linker code. However, the system calls *are used* by the dynamic linker. I need to explain how `execve` (and related calls) are relevant to the dynamic linker's job of loading shared libraries. I should provide a simple SO layout and describe the linking process at a high level.
* **逻辑推理 (Assumption/Output):**  Since the file primarily defines constants, the logical inference is about how those constants are used. I can create a simple example where a program uses `openat` and explain the system call number lookup.
* **用户/编程常见错误:**  Focus on common errors related to system calls, such as incorrect error handling or using the wrong system call.
* **Android Framework/NDK 到达这里:**  Describe the path from application code to the kernel, emphasizing the role of the NDK, libc, and finally the system call.
* **Frida Hook 示例:** Provide a basic Frida script that intercepts a system call and logs its number and arguments.

**5. Fleshing out each section:**

* **文件功能:** State clearly that it defines system call numbers for the RISC-V 64-bit architecture on Android.
* **与 Android 功能的关系:**  Provide diverse examples like file access (`openat`), process management (`fork`, `execve`), networking (`socket`), and memory management (`mmap`). For each, briefly explain how the corresponding system call is used in Android.
* **libc 函数实现:**  Explain the wrapper function concept. Emphasize that the libc function sets up arguments, places the system call number in a register, and triggers a software interrupt (or similar mechanism). The kernel then handles the call.
* **Dynamic Linker 功能:**
    * **SO 布局:** Provide a simplified example of an SO with a header, code section, and dynamic symbol table.
    * **链接过程:** Describe the high-level steps: `execve`, dynamic linker loading, symbol resolution, and relocation. Connect `execve` as the initial system call that starts the process.
* **逻辑推理 (Assumption/Output):**  Create a simple scenario like calling `openat("myfile", O_RDONLY, 0)`. The *assumption* is the system call number for `openat` is `__NR_openat`. The *output* is that the kernel will receive this number and the arguments.
* **用户/编程常见错误:** Focus on practical errors like neglecting error checking (`errno`), using incorrect arguments, or making assumptions about system call behavior.
* **Android Framework/NDK 到达这里:**  Trace the path: Java code -> Android Runtime (ART) -> Native code (via JNI) -> NDK (libc wrappers) -> System call.
* **Frida Hook 示例:**  Write a basic JavaScript Frida script using `Interceptor.attach` to hook a system call (e.g., `openat`) and log its arguments. Include clear comments explaining the code.

**6. Refinement and Language:**

* **Clarity:**  Use clear and concise language. Avoid jargon where possible or explain it.
* **Accuracy:** Ensure the technical details are correct.
* **Completeness:**  Address all aspects of the prompt.
* **Chinese:**  Provide the entire answer in Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Should I explain the entire system call mechanism in detail?  **Correction:**  Focus on the relevant parts and avoid going too deep into kernel implementation unless explicitly asked. The focus is on the *header file* and its connection to the user-space.
* **Initial thought:**  This file *is* part of libc. **Correction:**  While located within the bionic tree, this specific header file is *used by* libc, but it's more accurately described as providing the kernel-userspace interface definition. Libc provides the wrapper functions.
* **Initial thought:**  Explain every system call. **Correction:** That's not feasible. Focus on providing examples of different categories of system calls (file I/O, process, etc.).

By following these steps, breaking down the problem, and refining the approach, I can construct a comprehensive and accurate answer that addresses all parts of the user's request.## 对 `bionic/libc/kernel/uapi/asm-riscv/asm/unistd_64.handroid` 的源代码文件分析

这个文件 `unistd_64.handroid` 是 Android Bionic C 库中，针对 RISC-V 64 位架构的系统调用号定义头文件。它定义了一系列宏，每个宏都以 `__NR_` 开头，后跟系统调用名称，并赋值一个唯一的数字。

**它的主要功能是:**

1. **定义系统调用号:**  为 RISC-V 64 位架构上的 Android 系统定义了内核提供的各种系统调用的唯一标识符（数字）。这些数字是用户空间程序通过 Bionic C 库向内核发出服务请求的关键。
2. **作为用户空间和内核之间的接口桥梁:**  虽然用户程序不会直接包含这个头文件，但 Bionic C 库中的函数会使用这些宏定义的系统调用号来构建系统调用指令。这使得用户程序能够间接地与内核交互。
3. **保持系统调用号的稳定性和一致性:** 通过定义这些宏，可以确保在不同的 Bionic 版本中，只要系统调用名称不变，其对应的系统调用号也保持一致。这对于保证应用程序的兼容性至关重要。

**它与 Android 功能的关系，并举例说明:**

这个文件直接关系到 Android 操作系统提供的各种核心功能。Android 的许多基础操作，例如文件操作、进程管理、网络通信等，都依赖于这些系统调用。

**举例说明:**

* **文件操作:**
    * `__NR_openat` (56):  用于打开或创建文件。例如，当一个 Android 应用需要读取一个本地文件时，Bionic C 库中的 `open()` 或 `openat()` 函数最终会使用这个系统调用号来请求内核打开该文件。
    * `__NR_read` (63): 用于从文件描述符中读取数据。Android 应用读取文件内容时，会调用 Bionic 的 `read()` 函数，该函数最终会使用 `__NR_read`。
    * `__NR_write` (64): 用于向文件描述符写入数据。Android 应用保存文件时，会调用 Bionic 的 `write()` 函数，使用 `__NR_write`。
* **进程管理:**
    * `__NR_fork` (在 RISC-V 64 位上可能没有直接的 `fork`，而是使用 `clone`): 用于创建新的进程。Android 系统启动新的应用进程时，会使用相关的系统调用，例如 `clone`，其调用号在这个文件中也会有定义（虽然此文件中未直接列出 `fork`，但可以看到 `__NR_clone` (220)）。
    * `__NR_execve` (221): 用于执行新的程序。Android 系统启动应用时，新进程会调用 `execve` 来执行应用的 APK 包中的代码。
    * `__NR_exit` (93):  用于终止进程。Android 应用正常退出或发生错误退出时，会调用 `exit()` 函数，最终使用 `__NR_exit`。
* **网络通信:**
    * `__NR_socket` (198): 用于创建套接字。Android 应用进行网络请求时，会调用 Bionic 的 `socket()` 函数，使用 `__NR_socket` 来创建网络连接的基础。
    * `__NR_connect` (203): 用于连接到远程主机。Android 应用连接到服务器时，会调用 Bionic 的 `connect()` 函数，使用 `__NR_connect`。
* **内存管理:**
    * `__NR_mmap` (222): 用于将文件或设备映射到内存。Android 系统加载库文件、分配内存等操作会使用 `mmap`。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个 `unistd_64.handroid` 文件本身**并不包含任何 libc 函数的实现代码**。它只是定义了系统调用号。

**libc 函数的实现原理通常如下:**

1. **参数准备:** 用户程序调用 libc 函数（例如 `openat("path", O_RDONLY, 0)`）。libc 函数会负责处理用户提供的参数，并将它们整理成内核期望的格式。
2. **系统调用号加载:** libc 函数会根据调用的功能，从类似 `unistd_64.handroid` 这样的头文件中获取对应的系统调用号 (`__NR_openat` 在这里是 56)。
3. **陷入内核 (System Call):**  libc 函数会使用特定的汇编指令（在 RISC-V 上可能是 `ecall` 指令）触发一个软中断或异常，将控制权转移到内核。
4. **系统调用处理:** 内核接收到中断后，会根据系统调用号在系统调用表中查找对应的内核函数。
5. **执行内核函数:** 内核函数会根据用户提供的参数执行相应的操作，例如打开文件、创建进程等。
6. **结果返回:** 内核函数执行完毕后，会将结果（包括成功或失败的状态码以及可能的返回值）写入特定的寄存器。
7. **返回用户空间:** 内核将控制权返回给用户空间的 libc 函数。
8. **错误处理和返回值:** libc 函数会检查内核返回的状态码，如果发生错误，会将错误码设置到全局变量 `errno` 中，并返回一个表示错误的值（通常是 -1）。如果成功，则返回相应的结果（例如，`openat` 返回文件描述符）。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`unistd_64.handroid` 文件中涉及 dynamic linker 的关键系统调用是 `__NR_execve` (221)。当 Android 系统启动一个新的可执行文件（例如应用的主进程）时，会调用 `execve`。内核会加载该可执行文件，并识别出它依赖于动态链接库。这时，内核会启动 dynamic linker (`/system/bin/linker64` 或类似路径)。

**SO 布局样本 (简化版):**

```
ELF Header:
  e_entry:  0x... (入口地址，通常是 _start 函数)
  ...

Program Headers:
  LOAD: (加载段，包含代码和数据)
    p_vaddr: 0x... (加载到内存的起始地址)
    p_filesz: ...
    p_memsz: ...
  INTERP: (指定解释器，对于动态链接的可执行文件，指向 dynamic linker 的路径)
    p_vaddr: ...
    p_filesz: ...
    p_memsz: ...
    p_pdata: "/system/bin/linker64"

Dynamic Section:
  DT_NEEDED: libfoo.so  (依赖的共享库)
  DT_NEEDED: libbar.so
  DT_SYMTAB: 0x... (符号表地址)
  DT_STRTAB: 0x... (字符串表地址)
  DT_PLTGOT: 0x... (PLT/GOT 表地址)
  ...

.text section: (代码段)
  ...

.data section: (数据段)
  ...

.dynamic section: (动态链接信息)
  ...

.plt section: (Procedure Linkage Table, 过程链接表)
  ...

.got section: (Global Offset Table, 全局偏移表)
  ...

Symbol Table:
  ... (包含导出的和导入的符号)
```

**链接的处理过程:**

1. **`execve` 系统调用:**  当调用 `execve` 时，内核加载可执行文件的头部，发现 `INTERP` 段指向 dynamic linker。
2. **加载 Dynamic Linker:** 内核将 dynamic linker 加载到内存中。
3. **Dynamic Linker 初始化:** Dynamic linker 开始执行，解析可执行文件的头部和动态段。
4. **加载依赖库:** Dynamic linker 根据 `DT_NEEDED` 条目，找到并加载可执行文件依赖的共享库 (`libfoo.so`, `libbar.so` 等)。这个过程可能涉及再次调用 `openat` 等系统调用来打开 SO 文件。
5. **符号解析:** Dynamic linker 遍历加载的共享库的符号表，解析可执行文件和各个共享库之间的符号引用。这包括：
    * **重定位:** 修改代码段和数据段中对外部符号的引用，使其指向正确的内存地址。
    * **PLT/GOT 的填充:**  对于延迟绑定的符号（lazy binding），dynamic linker 会初始化 PLT 和 GOT 表，使得第一次调用外部函数时才会进行实际的符号查找和重定位。后续调用会直接通过 GOT 表跳转。
6. **执行可执行文件:**  完成所有链接操作后，dynamic linker 将控制权转移到可执行文件的入口点（`e_entry`）。

**假设输入与输出 (针对 `execve`):**

**假设输入:**

* `pathname`:  要执行的可执行文件的路径，例如 `/system/bin/app_process64`。
* `argv`:  传递给新程序的命令行参数数组，例如 `{"app_process64", "--application", ...}`。
* `envp`:  环境变量数组，例如 `{"PATH=/system/bin", "LD_LIBRARY_PATH=/system/lib64", ...}`。

**输出:**

* **成功:**  新的进程被创建并开始执行指定的程序。原调用 `execve` 的进程空间被新程序覆盖。
* **失败:**  `execve` 返回 -1，并设置 `errno` 来指示错误原因，例如文件不存在 (ENOENT)，权限不足 (EACCES) 等。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个文件本身不涉及用户编程错误，但与之相关的系统调用使用中常见的错误包括：

* **忘记检查返回值和 `errno`:**  例如，调用 `openat` 后没有检查返回值是否为 -1，以及 `errno` 的值，就直接使用返回的文件描述符，可能导致程序崩溃或行为异常。
* **使用了错误的系统调用号:**  这种情况通常不会发生在通过 Bionic C 库间接调用系统调用的情况下。但如果直接使用汇编进行系统调用，可能会因为使用了错误的系统调用号而导致未知的行为或程序崩溃。
* **传递了错误的参数给系统调用:**  例如，`openat` 的 `flags` 参数指定了文件的打开模式，如果使用了无效的标志，系统调用会失败。
* **文件权限问题:**  尝试打开没有读取权限的文件，或者尝试写入只读文件，会导致 `openat` 或 `write` 系统调用失败。
* **资源耗尽:**  例如，尝试创建过多的进程或打开过多的文件，可能会导致 `fork` 或 `openat` 等系统调用失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (以打开文件为例):**

1. **Java 代码:** Android Framework 中的 Java 代码（例如 `FileInputStream` 或 `FileOutputStream`）调用了 Java Native Interface (JNI) 方法。
2. **JNI 调用:**  JNI 方法会将调用转发到 Android Runtime (ART) 中对应的 native 代码。
3. **NDK/Bionic C 库:** ART 的 native 代码通常会调用 NDK 提供的 C/C++ 接口，这些接口是 Bionic C 库的封装。例如，Java 的 `FileInputStream` 最终会调用 NDK 中的 `open()` 函数。
4. **Bionic C 库函数:** NDK 中的 `open()` 函数实际上是 Bionic C 库提供的函数。这个函数会根据传入的参数，构建系统调用所需的参数，并从类似 `unistd_64.handroid` 的头文件中获取 `__NR_openat` 的值。
5. **系统调用:** Bionic C 库函数使用汇编指令 (`ecall` 在 RISC-V 上) 触发系统调用，将控制权和参数传递给 Linux 内核。
6. **内核处理:** Linux 内核接收到系统调用请求，根据 `__NR_openat` 的值调用内核中对应的 `sys_openat` 函数，执行实际的文件打开操作。

**Frida Hook 示例 (Hook `openat` 系统调用):**

```javascript
// Frida JavaScript 代码

function hook_openat() {
    const openatPtr = Module.findExportByName(null, "syscall"); // syscall 是 libc 中执行系统调用的通用入口点

    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter: function(args) {
                const syscallNumber = this.context.a7.toInt(); // RISC-V 64-bit 中系统调用号通常在 a7 寄存器
                if (syscallNumber === 56) { // __NR_openat 的值
                    const dirfd = args[0].toInt();
                    const pathnamePtr = args[1];
                    const flags = args[2].toInt();
                    const mode = args[3].toInt();

                    const pathname = pathnamePtr.readCString();

                    console.log("openat(" + dirfd + ", \"" + pathname + "\", " + flags + ", " + mode + ")");
                }
            },
            onLeave: function(retval) {
                if (this.context.a7.toInt() === 56) {
                    console.log("openat 返回值: " + retval);
                }
            }
        });
        console.log("成功 Hook openat 系统调用");
    } else {
        console.error("找不到 syscall 函数");
    }
}

setImmediate(hook_openat);
```

**代码解释:**

1. **`Module.findExportByName(null, "syscall")`:**  查找 libc 库中 `syscall` 函数的地址。`syscall` 通常是 Bionic C 库中执行系统调用的通用入口点。
2. **`Interceptor.attach(openatPtr, ...)`:**  使用 Frida 的 `Interceptor` API 拦截 `syscall` 函数的调用。
3. **`onEnter: function(args)`:**  在 `syscall` 函数被调用之前执行。
4. **`this.context.a7.toInt()`:** 获取 RISC-V 64 位架构中存储系统调用号的 `a7` 寄存器的值。
5. **`if (syscallNumber === 56)`:** 检查系统调用号是否是 `openat` 的值。
6. **`args[0]`, `args[1]`, `args[2]`, `args[3]`:** 获取 `openat` 系统调用的参数（`dirfd`, `pathname`, `flags`, `mode`）。
7. **`pathnamePtr.readCString()`:** 读取路径名字符串。
8. **`console.log(...)`:**  打印 `openat` 调用的参数。
9. **`onLeave: function(retval)`:** 在 `syscall` 函数返回之后执行，打印返回值。
10. **`setImmediate(hook_openat)`:**  确保在脚本加载后立即执行 hook 函数。

**使用 Frida 调试步骤:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_openat.js`）。
2. 找到要调试的 Android 进程的进程 ID 或包名。
3. 使用 Frida 命令运行 Hook 脚本：
   ```bash
   frida -U -f <包名> -l hook_openat.js --no-pause
   # 或者
   frida -U <进程ID> -l hook_openat.js
   ```
   （将 `<包名>` 替换为目标应用的包名，`<进程ID>` 替换为进程 ID）。
4. 当目标应用执行 `openat` 系统调用时，Frida 会拦截该调用，并在控制台上打印出 `openat` 的参数和返回值。

通过这种方式，可以追踪 Android Framework 或 NDK 如何一步步调用到内核的系统调用，并观察传递的参数，有助于理解系统底层的运作机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-riscv/asm/unistd_64.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_64_H
#define _UAPI_ASM_UNISTD_64_H
#define __NR_io_setup 0
#define __NR_io_destroy 1
#define __NR_io_submit 2
#define __NR_io_cancel 3
#define __NR_io_getevents 4
#define __NR_setxattr 5
#define __NR_lsetxattr 6
#define __NR_fsetxattr 7
#define __NR_getxattr 8
#define __NR_lgetxattr 9
#define __NR_fgetxattr 10
#define __NR_listxattr 11
#define __NR_llistxattr 12
#define __NR_flistxattr 13
#define __NR_removexattr 14
#define __NR_lremovexattr 15
#define __NR_fremovexattr 16
#define __NR_getcwd 17
#define __NR_lookup_dcookie 18
#define __NR_eventfd2 19
#define __NR_epoll_create1 20
#define __NR_epoll_ctl 21
#define __NR_epoll_pwait 22
#define __NR_dup 23
#define __NR_dup3 24
#define __NR_fcntl 25
#define __NR_inotify_init1 26
#define __NR_inotify_add_watch 27
#define __NR_inotify_rm_watch 28
#define __NR_ioctl 29
#define __NR_ioprio_set 30
#define __NR_ioprio_get 31
#define __NR_flock 32
#define __NR_mknodat 33
#define __NR_mkdirat 34
#define __NR_unlinkat 35
#define __NR_symlinkat 36
#define __NR_linkat 37
#define __NR_umount2 39
#define __NR_mount 40
#define __NR_pivot_root 41
#define __NR_nfsservctl 42
#define __NR_statfs 43
#define __NR_fstatfs 44
#define __NR_truncate 45
#define __NR_ftruncate 46
#define __NR_fallocate 47
#define __NR_faccessat 48
#define __NR_chdir 49
#define __NR_fchdir 50
#define __NR_chroot 51
#define __NR_fchmod 52
#define __NR_fchmodat 53
#define __NR_fchownat 54
#define __NR_fchown 55
#define __NR_openat 56
#define __NR_close 57
#define __NR_vhangup 58
#define __NR_pipe2 59
#define __NR_quotactl 60
#define __NR_getdents64 61
#define __NR_lseek 62
#define __NR_read 63
#define __NR_write 64
#define __NR_readv 65
#define __NR_writev 66
#define __NR_pread64 67
#define __NR_pwrite64 68
#define __NR_preadv 69
#define __NR_pwritev 70
#define __NR_sendfile 71
#define __NR_pselect6 72
#define __NR_ppoll 73
#define __NR_signalfd4 74
#define __NR_vmsplice 75
#define __NR_splice 76
#define __NR_tee 77
#define __NR_readlinkat 78
#define __NR_newfstatat 79
#define __NR_fstat 80
#define __NR_sync 81
#define __NR_fsync 82
#define __NR_fdatasync 83
#define __NR_sync_file_range 84
#define __NR_timerfd_create 85
#define __NR_timerfd_settime 86
#define __NR_timerfd_gettime 87
#define __NR_utimensat 88
#define __NR_acct 89
#define __NR_capget 90
#define __NR_capset 91
#define __NR_personality 92
#define __NR_exit 93
#define __NR_exit_group 94
#define __NR_waitid 95
#define __NR_set_tid_address 96
#define __NR_unshare 97
#define __NR_futex 98
#define __NR_set_robust_list 99
#define __NR_get_robust_list 100
#define __NR_nanosleep 101
#define __NR_getitimer 102
#define __NR_setitimer 103
#define __NR_kexec_load 104
#define __NR_init_module 105
#define __NR_delete_module 106
#define __NR_timer_create 107
#define __NR_timer_gettime 108
#define __NR_timer_getoverrun 109
#define __NR_timer_settime 110
#define __NR_timer_delete 111
#define __NR_clock_settime 112
#define __NR_clock_gettime 113
#define __NR_clock_getres 114
#define __NR_clock_nanosleep 115
#define __NR_syslog 116
#define __NR_ptrace 117
#define __NR_sched_setparam 118
#define __NR_sched_setscheduler 119
#define __NR_sched_getscheduler 120
#define __NR_sched_getparam 121
#define __NR_sched_setaffinity 122
#define __NR_sched_getaffinity 123
#define __NR_sched_yield 124
#define __NR_sched_get_priority_max 125
#define __NR_sched_get_priority_min 126
#define __NR_sched_rr_get_interval 127
#define __NR_restart_syscall 128
#define __NR_kill 129
#define __NR_tkill 130
#define __NR_tgkill 131
#define __NR_sigaltstack 132
#define __NR_rt_sigsuspend 133
#define __NR_rt_sigaction 134
#define __NR_rt_sigprocmask 135
#define __NR_rt_sigpending 136
#define __NR_rt_sigtimedwait 137
#define __NR_rt_sigqueueinfo 138
#define __NR_rt_sigreturn 139
#define __NR_setpriority 140
#define __NR_getpriority 141
#define __NR_reboot 142
#define __NR_setregid 143
#define __NR_setgid 144
#define __NR_setreuid 145
#define __NR_setuid 146
#define __NR_setresuid 147
#define __NR_getresuid 148
#define __NR_setresgid 149
#define __NR_getresgid 150
#define __NR_setfsuid 151
#define __NR_setfsgid 152
#define __NR_times 153
#define __NR_setpgid 154
#define __NR_getpgid 155
#define __NR_getsid 156
#define __NR_setsid 157
#define __NR_getgroups 158
#define __NR_setgroups 159
#define __NR_uname 160
#define __NR_sethostname 161
#define __NR_setdomainname 162
#define __NR_getrlimit 163
#define __NR_setrlimit 164
#define __NR_getrusage 165
#define __NR_umask 166
#define __NR_prctl 167
#define __NR_getcpu 168
#define __NR_gettimeofday 169
#define __NR_settimeofday 170
#define __NR_adjtimex 171
#define __NR_getpid 172
#define __NR_getppid 173
#define __NR_getuid 174
#define __NR_geteuid 175
#define __NR_getgid 176
#define __NR_getegid 177
#define __NR_gettid 178
#define __NR_sysinfo 179
#define __NR_mq_open 180
#define __NR_mq_unlink 181
#define __NR_mq_timedsend 182
#define __NR_mq_timedreceive 183
#define __NR_mq_notify 184
#define __NR_mq_getsetattr 185
#define __NR_msgget 186
#define __NR_msgctl 187
#define __NR_msgrcv 188
#define __NR_msgsnd 189
#define __NR_semget 190
#define __NR_semctl 191
#define __NR_semtimedop 192
#define __NR_semop 193
#define __NR_shmget 194
#define __NR_shmctl 195
#define __NR_shmat 196
#define __NR_shmdt 197
#define __NR_socket 198
#define __NR_socketpair 199
#define __NR_bind 200
#define __NR_listen 201
#define __NR_accept 202
#define __NR_connect 203
#define __NR_getsockname 204
#define __NR_getpeername 205
#define __NR_sendto 206
#define __NR_recvfrom 207
#define __NR_setsockopt 208
#define __NR_getsockopt 209
#define __NR_shutdown 210
#define __NR_sendmsg 211
#define __NR_recvmsg 212
#define __NR_readahead 213
#define __NR_brk 214
#define __NR_munmap 215
#define __NR_mremap 216
#define __NR_add_key 217
#define __NR_request_key 218
#define __NR_keyctl 219
#define __NR_clone 220
#define __NR_execve 221
#define __NR_mmap 222
#define __NR_fadvise64 223
#define __NR_swapon 224
#define __NR_swapoff 225
#define __NR_mprotect 226
#define __NR_msync 227
#define __NR_mlock 228
#define __NR_munlock 229
#define __NR_mlockall 230
#define __NR_munlockall 231
#define __NR_mincore 232
#define __NR_madvise 233
#define __NR_remap_file_pages 234
#define __NR_mbind 235
#define __NR_get_mempolicy 236
#define __NR_set_mempolicy 237
#define __NR_migrate_pages 238
#define __NR_move_pages 239
#define __NR_rt_tgsigqueueinfo 240
#define __NR_perf_event_open 241
#define __NR_accept4 242
#define __NR_recvmmsg 243
#define __NR_riscv_hwprobe 258
#define __NR_riscv_flush_icache 259
#define __NR_wait4 260
#define __NR_prlimit64 261
#define __NR_fanotify_init 262
#define __NR_fanotify_mark 263
#define __NR_name_to_handle_at 264
#define __NR_open_by_handle_at 265
#define __NR_clock_adjtime 266
#define __NR_syncfs 267
#define __NR_setns 268
#define __NR_sendmmsg 269
#define __NR_process_vm_readv 270
#define __NR_process_vm_writev 271
#define __NR_kcmp 272
#define __NR_finit_module 273
#define __NR_sched_setattr 274
#define __NR_sched_getattr 275
#define __NR_renameat2 276
#define __NR_seccomp 277
#define __NR_getrandom 278
#define __NR_memfd_create 279
#define __NR_bpf 280
#define __NR_execveat 281
#define __NR_userfaultfd 282
#define __NR_membarrier 283
#define __NR_mlock2 284
#define __NR_copy_file_range 285
#define __NR_preadv2 286
#define __NR_pwritev2 287
#define __NR_pkey_mprotect 288
#define __NR_pkey_alloc 289
#define __NR_pkey_free 290
#define __NR_statx 291
#define __NR_io_pgetevents 292
#define __NR_rseq 293
#define __NR_kexec_file_load 294
#define __NR_pidfd_send_signal 424
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#define __NR_open_tree 428
#define __NR_move_mount 429
#define __NR_fsopen 430
#define __NR_fsconfig 431
#define __NR_fsmount 432
#define __NR_fspick 433
#define __NR_pidfd_open 434
#define __NR_clone3 435
#define __NR_close_range 436
#define __NR_openat2 437
#define __NR_pidfd_getfd 438
#define __NR_faccessat2 439
#define __NR_process_madvise 440
#define __NR_epoll_pwait2 441
#define __NR_mount_setattr 442
#define __NR_quotactl_fd 443
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#define __NR_memfd_secret 447
#define __NR_process_mrelease 448
#define __NR_futex_waitv 449
#define __NR_set_mempolicy_home_node 450
#define __NR_cachestat 451
#define __NR_fchmodat2 452
#define __NR_map_shadow_stack 453
#define __NR_futex_wake 454
#define __NR_futex_wait 455
#define __NR_futex_requeue 456
#define __NR_statmount 457
#define __NR_listmount 458
#define __NR_lsm_get_self_attr 459
#define __NR_lsm_set_self_attr 460
#define __NR_lsm_list_modules 461
#define __NR_mseal 462
#endif
```