Response:
Let's break down the thought process to answer the request about `unistd_32.h`.

**1. Understanding the Core Purpose:**

The first thing to recognize is the nature of this file. The comment clearly states it's auto-generated and relates to system calls for a 32-bit architecture. The `#define __NR_*` lines are the key – they define numerical identifiers for system calls. This immediately tells us its primary function: to provide a mapping between symbolic names and their corresponding numbers, which the kernel uses to identify which system call to execute.

**2. Identifying the Target Audience and Context:**

The file is located within Android's Bionic library. Bionic is Android's C library, so this file is primarily for internal use by Bionic and NDK applications. It's the low-level bridge between user-space programs and the Linux kernel. The `uapi` in the path signifies "user-space API," further reinforcing this.

**3. Listing the Basic Functionality:**

Based on the above, the most straightforward function is providing system call numbers. This is its direct purpose.

**4. Connecting to Android Functionality:**

Since these are *the* system calls available on the 32-bit Android kernel, *every* action an Android app takes that requires kernel interaction goes through this list. The key is to provide concrete examples. Think about common Android operations:

*   **File access:** Opening a file (camera, document), reading a file, writing data. This maps to `open`, `read`, `write`, `close`.
*   **Process management:** Starting an app, killing an app. This relates to `fork`, `execve`, `exit`, `waitpid`.
*   **Networking:** Connecting to a server, sending data. This maps to `socket`, `connect`, `sendto`, `recvfrom`.
*   **Memory management:** Allocating memory. This involves `mmap`, `munmap`, `brk`.

**5. Explaining libc Function Implementation (Core Concept):**

This is where the explanation gets a bit more involved. It's crucial to explain the role of the C library as a wrapper around system calls. The typical flow is:

1. A programmer calls a standard C library function (e.g., `open()`).
2. The C library function performs some setup and argument validation.
3. The C library function then makes a system call using the correct number from this header file. This is usually done through an assembly instruction (like `int 0x80` on older 32-bit x86).
4. The kernel handles the system call.
5. The kernel returns a result.
6. The C library function processes the result and returns it to the programmer.

It's important to emphasize that the *kernel* implements the core logic of the system calls, not the C library. The C library just provides a convenient interface.

**6. Dynamic Linker and SO Layout (Key Distinction):**

This requires careful distinction. While system calls are fundamental, the *dynamic linker* has a different role. It's responsible for loading shared libraries (.so files) into a process's memory at runtime and resolving symbols.

*   **SO Layout:**  Visualize the memory of a process. It has sections for code, data, and dynamically loaded libraries. Explain how the linker maps these libraries into memory. A simple example with `libc.so`, `libm.so`, and a custom library is sufficient.
*   **Linking Process:** Describe the steps:
    1. The executable has a list of required libraries.
    2. The dynamic linker (`/system/bin/linker` on Android) is invoked.
    3. The linker loads the required SOs.
    4. The linker resolves symbols (functions and variables) between the executable and the SOs. This involves looking up symbol tables.
    5. The linker relocates code and data within the SOs.

It's vital to note that the `unistd_32.h` file itself *doesn't directly implement dynamic linking*. However, the `execve` system call is what *starts* a process, and the dynamic linker is an integral part of that process startup.

**7. Logic Reasoning with Assumptions:**

For demonstrating logic, choose a simple system call. `read` is a good example.

*   **Input:** File descriptor, buffer, number of bytes to read.
*   **Process:** The kernel checks permissions, reads from the file, copies data to the buffer.
*   **Output:** Number of bytes actually read (or an error).

**8. Common User Errors:**

Think about common mistakes programmers make when interacting with these low-level functions.

*   **Incorrect file descriptor:** Trying to read from a closed file.
*   **Invalid memory address:** Passing a bad pointer to `read` or `write`.
*   **Permissions issues:** Trying to open a file without the necessary permissions.
*   **Buffer overflow:** Trying to write more data than the buffer can hold (though this is less directly related to the *syscall* itself and more about how the programmer uses the `write` function).

**9. Android Framework/NDK Path and Frida Hooking:**

This requires understanding the layers of Android.

*   **Android Framework:**  Start with a high-level framework API (e.g., `FileInputStream`). Trace it down through the Java Native Interface (JNI) to native code in Bionic. The `open()` call within Bionic will eventually use the `__NR_open` number.
*   **NDK:**  NDK apps directly call Bionic functions, making the path shorter. A simple `open()` call in NDK will directly lead to the system call.
*   **Frida Hooking:**  Provide a concrete example of hooking the `open` system call. Explain the Frida script's purpose: intercepting the call, logging arguments, and potentially modifying behavior. Mention the importance of root access for system-level hooking.

**10. Language and Structure:**

Use clear, concise Chinese. Organize the answer logically with headings and bullet points for readability. Ensure that technical terms are explained adequately. Avoid jargon where possible, or provide definitions.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:**  Focus heavily on the C library function implementations.
*   **Correction:** Realize the core of this file is about system calls. Shift focus to the kernel's role and how the C library acts as an intermediary.
*   **Initial thought:** Explain dynamic linking in great detail with complex scenarios.
*   **Correction:** Keep the dynamic linking explanation focused and relevant to the context of process startup and shared library loading. A simple example suffices.
*   **Initial thought:** Just list the system call names.
*   **Correction:** Provide brief explanations of what each major category of system calls does (file I/O, process management, etc.) to give more context.

By following these steps, breaking down the request into smaller parts, and constantly checking the relevance and accuracy of the information, a comprehensive and informative answer can be generated.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/asm-x86/asm/unistd_32.handroid` 这个文件。

**功能列举:**

这个文件定义了 32 位 x86 架构 Linux 系统调用的编号（system call numbers）。它的核心功能是将每个系统调用关联到一个唯一的数字常量。

具体来说，它完成了以下功能：

1. **定义系统调用号:** 为每一个 Linux 系统调用（如 `read`, `write`, `open`, `fork` 等）定义了一个以 `__NR_` 开头的宏，并将该宏赋值为一个整数。这个整数就是该系统调用的编号。
2. **提供用户空间访问内核的接口:** 这些宏定义被用户空间的程序（通过 Bionic C 库）使用，以便在需要执行内核操作时，告知内核具体需要执行哪个系统调用。

**与 Android 功能的关系及举例:**

这个文件是 Android 系统底层运行的关键组成部分。Android 应用（无论是 Java/Kotlin 编写还是 C/C++ 编写）最终都需要通过系统调用来请求操作系统内核执行某些操作。

以下是一些例子：

* **文件操作:** 当 Android 应用需要打开一个文件（例如读取图片或保存数据），它会调用 Bionic C 库提供的 `open()` 函数。Bionic 的 `open()` 函数最终会使用 `__NR_open` 这个宏定义的值（也就是 5）来发起系统调用，请求内核打开文件。
* **网络通信:** 当应用需要建立网络连接，它会调用 Bionic 的 `socket()`, `connect()` 等函数。这些函数会分别使用 `__NR_socket` (359), `__NR_connect` (362) 等系统调用号。
* **进程管理:**  启动一个新的 Activity 或 Service 可能会涉及到进程的创建，这会调用 `fork()` 或 `clone()`，对应着 `__NR_fork` (2) 和 `__NR_clone` (120)。
* **内存管理:**  应用进行内存分配（例如使用 `malloc()`）背后可能涉及到 `mmap()` 系统调用 (`__NR_mmap` 为 90) 来向内核申请内存。

**libc 函数的功能实现:**

Bionic C 库中的函数通常是对系统调用的封装。以 `open()` 函数为例：

1. **用户调用:** 用户空间的程序调用 `open(pathname, flags, mode)`。
2. **参数准备:** Bionic 的 `open()` 函数接收这些参数，并进行一些必要的处理和验证。
3. **系统调用:**  `open()` 函数会使用汇编指令（在 32 位 x86 上通常是 `int 0x80`）触发一个软中断，进入内核态。同时，会将系统调用号 (`__NR_open` 的值，即 5) 和参数（`pathname`, `flags`, `mode` 的地址或值）放入特定的寄存器中。
4. **内核处理:** Linux 内核接收到中断后，会根据系统调用号找到对应的内核函数（与 `open` 系统调用相关的内核代码）。内核代码会执行真正的打开文件操作，包括权限检查、文件描述符分配等。
5. **返回结果:** 内核操作完成后，会将结果（通常是新的文件描述符，或者错误代码）放入某个寄存器中。
6. **libc 处理:**  Bionic 的 `open()` 函数从寄存器中获取内核返回的结果，并将其作为 `open()` 函数的返回值返回给用户程序。如果内核返回了错误，Bionic 会设置全局变量 `errno`。

**涉及 dynamic linker 的功能及处理过程:**

这个 `unistd_32.h` 文件本身并不直接实现 dynamic linker 的功能。Dynamic Linker (在 Android 中通常是 `/system/bin/linker` 或 `/system/bin/linker64`) 是一个独立的程序，负责在程序启动时加载所需的共享库（.so 文件）并解析符号。

但是，`execve` 系统调用 (`__NR_execve` 为 11) 与 dynamic linker 的启动密切相关。

**SO 布局样本:**

假设一个简单的 Android 应用依赖于 `libc.so`, `libm.so` 和一个自定义的共享库 `libmy.so`。当该应用启动时，其进程的内存布局可能如下所示（简化）：

```
+-----------------+  <- 用户栈
|     Stack       |
+-----------------+
|       ...       |
+-----------------+
|       Heap      |  <- 堆
+-----------------+
|  libmy.so code  |
+-----------------+
|  libmy.so data  |
+-----------------+
|   libm.so code  |
+-----------------+
|   libm.so data  |
+-----------------+
|   libc.so code  |
+-----------------+
|   libc.so data  |
+-----------------+
| 可执行文件代码  |
+-----------------+
| 可执行文件数据  |
+-----------------+
```

**链接的处理过程:**

1. **`execve` 调用:** 当系统需要启动一个新的程序时，会调用 `execve` 系统调用，并指定要执行的可执行文件路径。
2. **内核加载器:** 内核会加载可执行文件的头部信息，发现它是一个动态链接的可执行文件。
3. **Dynamic Linker 启动:** 内核会启动 Dynamic Linker (`/system/bin/linker`)，并将控制权交给它。Dynamic Linker 会作为新进程的一部分运行。
4. **加载共享库:** Dynamic Linker 解析可执行文件的头部信息，找到它依赖的共享库列表 (`libc.so`, `libm.so`, `libmy.so`)。然后，它会按照一定的搜索路径（通常由 `LD_LIBRARY_PATH` 环境变量指定，以及系统默认路径）找到这些共享库文件，并将它们加载到进程的内存空间中。
5. **符号解析 (Symbol Resolution):**  这是链接的关键步骤。可执行文件和共享库中会引用一些外部函数和变量。Dynamic Linker 会遍历这些引用，并在已加载的共享库的符号表（Symbol Table）中查找这些符号的地址。例如，如果可执行文件调用了 `printf` 函数，Dynamic Linker 会在 `libc.so` 的符号表中找到 `printf` 的地址。
6. **重定位 (Relocation):**  共享库在编译时并不知道最终会被加载到哪个内存地址。Dynamic Linker 需要修改共享库和可执行文件中的某些指令和数据，使其指向正确的内存地址。例如，将对 `printf` 函数的调用指令中的占位符地址替换为 `printf` 函数实际加载的内存地址。
7. **执行程序:**  完成所有共享库的加载、符号解析和重定位后，Dynamic Linker 会将控制权交给可执行文件的入口点，程序开始真正执行。

**逻辑推理 (假设输入与输出):**

假设我们调用 `open("/sdcard/test.txt", O_RDONLY)`：

* **假设输入:**
    * `pathname`: 指向字符串 "/sdcard/test.txt" 的指针。
    * `flags`: `O_RDONLY` 的值（通常是 0）。
    * `mode`: 此参数对于 `O_RDONLY` 通常被忽略。
* **过程:**
    1. Bionic 的 `open()` 函数会被调用，它会准备系统调用参数。
    2. 系统调用号 `__NR_open` (5) 和参数会被传递给内核。
    3. 内核会尝试打开位于 "/sdcard/test.txt" 的文件，以只读模式打开。内核会进行权限检查。
* **假设输出:**
    * **成功:** 如果文件存在且有读取权限，内核会返回一个新的非负整数，表示文件描述符（例如 3）。
    * **失败:** 如果文件不存在或没有读取权限，内核会返回 -1，并且 Bionic 会设置 `errno` 变量为相应的错误代码（例如 `ENOENT` 或 `EACCES`）。

**用户或编程常见的使用错误:**

1. **错误的系统调用号:**  虽然用户通常不会直接使用 `__NR_` 宏，但在某些底层编程或内核开发中，如果使用了错误的系统调用号，会导致程序崩溃或行为异常。
2. **传递错误的参数给 libc 函数:** 例如，传递一个空指针作为 `read()` 函数的缓冲区，或者传递一个负数的长度给 `read()`，会导致程序崩溃或未定义行为。
3. **忘记检查系统调用的返回值:**  系统调用可能会失败。如果程序不检查返回值（通常是 -1 表示错误），并根据 `errno` 进行错误处理，可能会导致程序逻辑错误。例如，`open()` 返回 -1 时，应该检查 `errno` 来判断是文件不存在还是权限不足。
4. **文件描述符泄漏:**  如果打开了文件或 socket，但忘记调用 `close()` 关闭，会导致文件描述符资源耗尽。
5. **缓冲区溢出:**  在使用 `read()` 或 `write()` 等操作时，如果缓冲区大小设置不当，可能会导致缓冲区溢出，覆盖其他内存区域。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例:**

**Android Framework 到 `unistd_32.h` 的路径:**

1. **Java 代码:**  例如，使用 `FileInputStream` 读取文件：
   ```java
   FileInputStream fis = new FileInputStream("/sdcard/test.txt");
   ```
2. **Framework 层:** `FileInputStream` 最终会调用 Native 方法。
3. **JNI (Java Native Interface):**  Framework 层会通过 JNI 调用到 Android 运行时 (ART) 或 Dalvik 虚拟机中的 native 代码。
4. **Bionic C 库:** ART 或 Dalvik 的 native 代码会调用 Bionic C 库的函数，例如 `open()`。
5. **系统调用:** Bionic 的 `open()` 函数会使用 `__NR_open` 这个宏定义的值发起系统调用。

**NDK 到 `unistd_32.h` 的路径:**

1. **C/C++ 代码:** NDK 开发中可以直接调用 Bionic C 库的函数：
   ```c++
   #include <fcntl.h>
   #include <unistd.h>

   int fd = open("/sdcard/test.txt", O_RDONLY);
   ```
2. **系统调用:** `open()` 函数会直接使用 `__NR_open` 发起系统调用。

**Frida Hook 示例:**

可以使用 Frida 来 hook `open` 系统调用，观察参数和返回值。以下是一个简单的 Frida 脚本示例：

```javascript
if (Process.arch === 'ia32') {
  const openPtr = Module.findExportByName(null, '__syscall'); // 32-bit architecture often uses __syscall as a wrapper
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        const syscallNumber = this.context.eax.toInt(); // 系统调用号通常在 eax 寄存器中
        if (syscallNumber === 5) { // __NR_open 的值是 5
          const pathname = Memory.readUtf8String(ptr(this.context.ebx)); // 第一个参数（路径名）通常在 ebx 寄存器中
          const flags = this.context.ecx.toInt(); // 第二个参数（flags）通常在 ecx 寄存器中
          console.log(`[Open Hook] Pathname: ${pathname}, Flags: ${flags}`);
        }
      },
      onLeave: function (retval) {
        if (this.context.eax.toInt() === 5) {
          console.log(`[Open Hook] Return value: ${retval}`);
        }
      }
    });
  } else {
    console.log("Could not find __syscall export.");
  }
} else {
  console.log("This script is for 32-bit processes.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_open.js`。
2. 运行 Frida 并指定要 hook 的进程：
   ```bash
   frida -U -f <your_app_package_name> -l hook_open.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_open.js
   ```

**示例解释:**

* **`Process.arch === 'ia32'`:**  检查当前进程的架构是否是 32 位。
* **`Module.findExportByName(null, '__syscall')`:**  在所有已加载的模块中查找名为 `__syscall` 的导出函数。在 32 位系统上，libc 通常会有一个 `__syscall` 函数作为系统调用的通用入口点。
* **`Interceptor.attach(...)`:** 使用 Frida 的拦截器来 hook `__syscall` 函数。
* **`onEnter`:** 在 `__syscall` 函数执行前被调用。
    * **`this.context.eax.toInt()`:** 获取 `eax` 寄存器的值，通常系统调用号会放在这里。
    * **`syscallNumber === 5`:**  检查是否是 `open` 系统调用。
    * **`Memory.readUtf8String(ptr(this.context.ebx))`:** 读取 `ebx` 寄存器指向的内存地址的 UTF-8 字符串（通常是 `open` 的路径名参数）。
    * **`this.context.ecx.toInt()`:** 获取 `ecx` 寄存器的值（通常是 `open` 的 flags 参数）。
    * **`console.log(...)`:** 打印 hook 到的信息。
* **`onLeave`:** 在 `__syscall` 函数执行后被调用。
    * **`retval`:**  系统调用的返回值。

通过运行这个 Frida 脚本，当目标应用调用 `open` 系统调用时，你将在 Frida 的控制台中看到 `open` 调用的路径名、flags 以及返回值。这可以帮助你调试 Android 应用的底层行为。

希望以上详细的解释能够帮助你理解 `unistd_32.handroid` 文件的功能、它在 Android 系统中的作用以及如何进行调试。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/unistd_32.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_32_H
#define _UAPI_ASM_UNISTD_32_H
#define __NR_restart_syscall 0
#define __NR_exit 1
#define __NR_fork 2
#define __NR_read 3
#define __NR_write 4
#define __NR_open 5
#define __NR_close 6
#define __NR_waitpid 7
#define __NR_creat 8
#define __NR_link 9
#define __NR_unlink 10
#define __NR_execve 11
#define __NR_chdir 12
#define __NR_time 13
#define __NR_mknod 14
#define __NR_chmod 15
#define __NR_lchown 16
#define __NR_break 17
#define __NR_oldstat 18
#define __NR_lseek 19
#define __NR_getpid 20
#define __NR_mount 21
#define __NR_umount 22
#define __NR_setuid 23
#define __NR_getuid 24
#define __NR_stime 25
#define __NR_ptrace 26
#define __NR_alarm 27
#define __NR_oldfstat 28
#define __NR_pause 29
#define __NR_utime 30
#define __NR_stty 31
#define __NR_gtty 32
#define __NR_access 33
#define __NR_nice 34
#define __NR_ftime 35
#define __NR_sync 36
#define __NR_kill 37
#define __NR_rename 38
#define __NR_mkdir 39
#define __NR_rmdir 40
#define __NR_dup 41
#define __NR_pipe 42
#define __NR_times 43
#define __NR_prof 44
#define __NR_brk 45
#define __NR_setgid 46
#define __NR_getgid 47
#define __NR_signal 48
#define __NR_geteuid 49
#define __NR_getegid 50
#define __NR_acct 51
#define __NR_umount2 52
#define __NR_lock 53
#define __NR_ioctl 54
#define __NR_fcntl 55
#define __NR_mpx 56
#define __NR_setpgid 57
#define __NR_ulimit 58
#define __NR_oldolduname 59
#define __NR_umask 60
#define __NR_chroot 61
#define __NR_ustat 62
#define __NR_dup2 63
#define __NR_getppid 64
#define __NR_getpgrp 65
#define __NR_setsid 66
#define __NR_sigaction 67
#define __NR_sgetmask 68
#define __NR_ssetmask 69
#define __NR_setreuid 70
#define __NR_setregid 71
#define __NR_sigsuspend 72
#define __NR_sigpending 73
#define __NR_sethostname 74
#define __NR_setrlimit 75
#define __NR_getrlimit 76
#define __NR_getrusage 77
#define __NR_gettimeofday 78
#define __NR_settimeofday 79
#define __NR_getgroups 80
#define __NR_setgroups 81
#define __NR_select 82
#define __NR_symlink 83
#define __NR_oldlstat 84
#define __NR_readlink 85
#define __NR_uselib 86
#define __NR_swapon 87
#define __NR_reboot 88
#define __NR_readdir 89
#define __NR_mmap 90
#define __NR_munmap 91
#define __NR_truncate 92
#define __NR_ftruncate 93
#define __NR_fchmod 94
#define __NR_fchown 95
#define __NR_getpriority 96
#define __NR_setpriority 97
#define __NR_profil 98
#define __NR_statfs 99
#define __NR_fstatfs 100
#define __NR_ioperm 101
#define __NR_socketcall 102
#define __NR_syslog 103
#define __NR_setitimer 104
#define __NR_getitimer 105
#define __NR_stat 106
#define __NR_lstat 107
#define __NR_fstat 108
#define __NR_olduname 109
#define __NR_iopl 110
#define __NR_vhangup 111
#define __NR_idle 112
#define __NR_vm86old 113
#define __NR_wait4 114
#define __NR_swapoff 115
#define __NR_sysinfo 116
#define __NR_ipc 117
#define __NR_fsync 118
#define __NR_sigreturn 119
#define __NR_clone 120
#define __NR_setdomainname 121
#define __NR_uname 122
#define __NR_modify_ldt 123
#define __NR_adjtimex 124
#define __NR_mprotect 125
#define __NR_sigprocmask 126
#define __NR_create_module 127
#define __NR_init_module 128
#define __NR_delete_module 129
#define __NR_get_kernel_syms 130
#define __NR_quotactl 131
#define __NR_getpgid 132
#define __NR_fchdir 133
#define __NR_bdflush 134
#define __NR_sysfs 135
#define __NR_personality 136
#define __NR_afs_syscall 137
#define __NR_setfsuid 138
#define __NR_setfsgid 139
#define __NR__llseek 140
#define __NR_getdents 141
#define __NR__newselect 142
#define __NR_flock 143
#define __NR_msync 144
#define __NR_readv 145
#define __NR_writev 146
#define __NR_getsid 147
#define __NR_fdatasync 148
#define __NR__sysctl 149
#define __NR_mlock 150
#define __NR_munlock 151
#define __NR_mlockall 152
#define __NR_munlockall 153
#define __NR_sched_setparam 154
#define __NR_sched_getparam 155
#define __NR_sched_setscheduler 156
#define __NR_sched_getscheduler 157
#define __NR_sched_yield 158
#define __NR_sched_get_priority_max 159
#define __NR_sched_get_priority_min 160
#define __NR_sched_rr_get_interval 161
#define __NR_nanosleep 162
#define __NR_mremap 163
#define __NR_setresuid 164
#define __NR_getresuid 165
#define __NR_vm86 166
#define __NR_query_module 167
#define __NR_poll 168
#define __NR_nfsservctl 169
#define __NR_setresgid 170
#define __NR_getresgid 171
#define __NR_prctl 172
#define __NR_rt_sigreturn 173
#define __NR_rt_sigaction 174
#define __NR_rt_sigprocmask 175
#define __NR_rt_sigpending 176
#define __NR_rt_sigtimedwait 177
#define __NR_rt_sigqueueinfo 178
#define __NR_rt_sigsuspend 179
#define __NR_pread64 180
#define __NR_pwrite64 181
#define __NR_chown 182
#define __NR_getcwd 183
#define __NR_capget 184
#define __NR_capset 185
#define __NR_sigaltstack 186
#define __NR_sendfile 187
#define __NR_getpmsg 188
#define __NR_putpmsg 189
#define __NR_vfork 190
#define __NR_ugetrlimit 191
#define __NR_mmap2 192
#define __NR_truncate64 193
#define __NR_ftruncate64 194
#define __NR_stat64 195
#define __NR_lstat64 196
#define __NR_fstat64 197
#define __NR_lchown32 198
#define __NR_getuid32 199
#define __NR_getgid32 200
#define __NR_geteuid32 201
#define __NR_getegid32 202
#define __NR_setreuid32 203
#define __NR_setregid32 204
#define __NR_getgroups32 205
#define __NR_setgroups32 206
#define __NR_fchown32 207
#define __NR_setresuid32 208
#define __NR_getresuid32 209
#define __NR_setresgid32 210
#define __NR_getresgid32 211
#define __NR_chown32 212
#define __NR_setuid32 213
#define __NR_setgid32 214
#define __NR_setfsuid32 215
#define __NR_setfsgid32 216
#define __NR_pivot_root 217
#define __NR_mincore 218
#define __NR_madvise 219
#define __NR_getdents64 220
#define __NR_fcntl64 221
#define __NR_gettid 224
#define __NR_readahead 225
#define __NR_setxattr 226
#define __NR_lsetxattr 227
#define __NR_fsetxattr 228
#define __NR_getxattr 229
#define __NR_lgetxattr 230
#define __NR_fgetxattr 231
#define __NR_listxattr 232
#define __NR_llistxattr 233
#define __NR_flistxattr 234
#define __NR_removexattr 235
#define __NR_lremovexattr 236
#define __NR_fremovexattr 237
#define __NR_tkill 238
#define __NR_sendfile64 239
#define __NR_futex 240
#define __NR_sched_setaffinity 241
#define __NR_sched_getaffinity 242
#define __NR_set_thread_area 243
#define __NR_get_thread_area 244
#define __NR_io_setup 245
#define __NR_io_destroy 246
#define __NR_io_getevents 247
#define __NR_io_submit 248
#define __NR_io_cancel 249
#define __NR_fadvise64 250
#define __NR_exit_group 252
#define __NR_lookup_dcookie 253
#define __NR_epoll_create 254
#define __NR_epoll_ctl 255
#define __NR_epoll_wait 256
#define __NR_remap_file_pages 257
#define __NR_set_tid_address 258
#define __NR_timer_create 259
#define __NR_timer_settime 260
#define __NR_timer_gettime 261
#define __NR_timer_getoverrun 262
#define __NR_timer_delete 263
#define __NR_clock_settime 264
#define __NR_clock_gettime 265
#define __NR_clock_getres 266
#define __NR_clock_nanosleep 267
#define __NR_statfs64 268
#define __NR_fstatfs64 269
#define __NR_tgkill 270
#define __NR_utimes 271
#define __NR_fadvise64_64 272
#define __NR_vserver 273
#define __NR_mbind 274
#define __NR_get_mempolicy 275
#define __NR_set_mempolicy 276
#define __NR_mq_open 277
#define __NR_mq_unlink 278
#define __NR_mq_timedsend 279
#define __NR_mq_timedreceive 280
#define __NR_mq_notify 281
#define __NR_mq_getsetattr 282
#define __NR_kexec_load 283
#define __NR_waitid 284
#define __NR_add_key 286
#define __NR_request_key 287
#define __NR_keyctl 288
#define __NR_ioprio_set 289
#define __NR_ioprio_get 290
#define __NR_inotify_init 291
#define __NR_inotify_add_watch 292
#define __NR_inotify_rm_watch 293
#define __NR_migrate_pages 294
#define __NR_openat 295
#define __NR_mkdirat 296
#define __NR_mknodat 297
#define __NR_fchownat 298
#define __NR_futimesat 299
#define __NR_fstatat64 300
#define __NR_unlinkat 301
#define __NR_renameat 302
#define __NR_linkat 303
#define __NR_symlinkat 304
#define __NR_readlinkat 305
#define __NR_fchmodat 306
#define __NR_faccessat 307
#define __NR_pselect6 308
#define __NR_ppoll 309
#define __NR_unshare 310
#define __NR_set_robust_list 311
#define __NR_get_robust_list 312
#define __NR_splice 313
#define __NR_sync_file_range 314
#define __NR_tee 315
#define __NR_vmsplice 316
#define __NR_move_pages 317
#define __NR_getcpu 318
#define __NR_epoll_pwait 319
#define __NR_utimensat 320
#define __NR_signalfd 321
#define __NR_timerfd_create 322
#define __NR_eventfd 323
#define __NR_fallocate 324
#define __NR_timerfd_settime 325
#define __NR_timerfd_gettime 326
#define __NR_signalfd4 327
#define __NR_eventfd2 328
#define __NR_epoll_create1 329
#define __NR_dup3 330
#define __NR_pipe2 331
#define __NR_inotify_init1 332
#define __NR_preadv 333
#define __NR_pwritev 334
#define __NR_rt_tgsigqueueinfo 335
#define __NR_perf_event_open 336
#define __NR_recvmmsg 337
#define __NR_fanotify_init 338
#define __NR_fanotify_mark 339
#define __NR_prlimit64 340
#define __NR_name_to_handle_at 341
#define __NR_open_by_handle_at 342
#define __NR_clock_adjtime 343
#define __NR_syncfs 344
#define __NR_sendmmsg 345
#define __NR_setns 346
#define __NR_process_vm_readv 347
#define __NR_process_vm_writev 348
#define __NR_kcmp 349
#define __NR_finit_module 350
#define __NR_sched_setattr 351
#define __NR_sched_getattr 352
#define __NR_renameat2 353
#define __NR_seccomp 354
#define __NR_getrandom 355
#define __NR_memfd_create 356
#define __NR_bpf 357
#define __NR_execveat 358
#define __NR_socket 359
#define __NR_socketpair 360
#define __NR_bind 361
#define __NR_connect 362
#define __NR_listen 363
#define __NR_accept4 364
#define __NR_getsockopt 365
#define __NR_setsockopt 366
#define __NR_getsockname 367
#define __NR_getpeername 368
#define __NR_sendto 369
#define __NR_sendmsg 370
#define __NR_recvfrom 371
#define __NR_recvmsg 372
#define __NR_shutdown 373
#define __NR_userfaultfd 374
#define __NR_membarrier 375
#define __NR_mlock2 376
#define __NR_copy_file_range 377
#define __NR_preadv2 378
#define __NR_pwritev2 379
#define __NR_pkey_mprotect 380
#define __NR_pkey_alloc 381
#define __NR_pkey_free 382
#define __NR_statx 383
#define __NR_arch_prctl 384
#define __NR_io_pgetevents 385
#define __NR_rseq 386
#define __NR_semget 393
#define __NR_semctl 394
#define __NR_shmget 395
#define __NR_shmctl 396
#define __NR_shmat 397
#define __NR_shmdt 398
#define __NR_msgget 399
#define __NR_msgsnd 400
#define __NR_msgrcv 401
#define __NR_msgctl 402
#define __NR_clock_gettime64 403
#define __NR_clock_settime64 404
#define __NR_clock_adjtime64 405
#define __NR_clock_getres_time64 406
#define __NR_clock_nanosleep_time64 407
#define __NR_timer_gettime64 408
#define __NR_timer_settime64 409
#define __NR_timerfd_gettime64 410
#define __NR_timerfd_settime64 411
#define __NR_utimensat_time64 412
#define __NR_pselect6_time64 413
#define __NR_ppoll_time64 414
#define __NR_io_pgetevents_time64 416
#define __NR_recvmmsg_time64 417
#define __NR_mq_timedsend_time64 418
#define __NR_mq_timedreceive_time64 419
#define __NR_semtimedop_time64 420
#define __NR_rt_sigtimedwait_time64 421
#define __NR_futex_time64 422
#define __NR_sched_rr_get_interval_time64 423
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

"""

```