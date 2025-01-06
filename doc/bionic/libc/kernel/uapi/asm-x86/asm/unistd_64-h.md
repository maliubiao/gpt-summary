Response:
Let's break down the thought process for answering the user's request. The request is quite comprehensive, asking for various aspects related to the provided header file.

**1. Understanding the Core Request:**

The user has provided a header file (`unistd_64.handroid`) and wants to know its functionality, its relationship to Android, implementation details (specifically libc functions), dynamic linker implications, potential errors, and how to trace its usage.

**2. Initial Assessment of the File:**

The first thing I notice is the `#define __NR_*` lines. These clearly represent system call numbers. The comment at the top confirms it's auto-generated and related to bionic (Android's C library). The filename `unistd_64` suggests it's for 64-bit architectures. The `.handroid` part indicates it's specific to the Android build.

**3. Categorizing the Functionality:**

The core functionality is clear: mapping symbolic names (like `__NR_read`) to their corresponding numerical system call IDs. This is crucial for any program interacting directly with the Linux kernel.

**4. Connecting to Android:**

The filename and the "bionic" reference are the primary links to Android. I need to explain *why* these system call numbers are important in the Android context. The key is that Android applications (through the NDK and even framework calls) ultimately rely on these system calls to perform low-level operations.

**5. Addressing Libc Function Implementations:**

This is a key part of the request. The header file *doesn't implement* libc functions. It merely defines the system call numbers that libc functions will eventually use. I need to be very clear about this distinction. I'll pick a few examples (like `read`, `write`, `open`) and explain the general process: the libc function wraps the system call, handles error checking, etc.

**6. Considering the Dynamic Linker:**

The provided file itself doesn't directly involve the dynamic linker. However, the *use* of these system calls does. When a program uses a libc function, the dynamic linker is responsible for loading the libc library. I need to provide a conceptual understanding of this, including the role of shared objects (.so files) and how the linker resolves symbols.

**7. Anticipating User Errors:**

Users generally won't directly use these `__NR_*` defines. The errors will occur at a higher level (using incorrect arguments to libc functions, permission problems, file not found, etc.). I need to frame the examples in terms of how these underlying system calls can lead to these user-visible errors.

**8. Tracing the Path from Android Framework/NDK:**

This requires outlining the layers involved:
    * **Android Framework (Java/Kotlin):**  High-level APIs.
    * **Native Code (C/C++ via NDK):** Uses libc functions.
    * **Bionic Libc:**  Implements standard C functions, which then make system calls.
    * **Kernel:**  Executes the system call.

I need to provide a concrete example to illustrate this flow. File I/O is a good choice.

**9. Frida Hooking:**

To demonstrate how to intercept these system calls, Frida is a suitable tool. I need to show how to hook a libc function (like `open`) and observe the system call number being used. This requires a simple Frida script.

**10. Structuring the Answer:**

I need to organize the information logically, following the points in the user's request. Using headings and bullet points will make the answer easier to read and understand.

**11. Refining the Language:**

The language should be clear, concise, and technically accurate, but also understandable to someone who might not be deeply familiar with low-level details. Avoiding jargon where possible or explaining it is important.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the dynamic linker is directly involved in this header file because system calls are part of the ABI.
* **Correction:**  No, the header file just *defines* the system call numbers. The dynamic linker's role is in loading the libraries that *use* these numbers.

* **Initial thought:** Provide very specific examples of every libc function implementation.
* **Correction:**  That would be too long and not very useful. Focus on the *general* implementation pattern.

* **Initial thought:**  Give very complex Frida examples.
* **Correction:** A simple `Interceptor.attach` example targeting `open` will be more effective for demonstrating the concept.

By following this systematic process and continuously refining the approach, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这个 `bionic/libc/kernel/uapi/asm-x86/asm/unistd_64.handroid` 文件是 Android Bionic C 库的一部分，它定义了 **64 位 x86 架构**下 Linux 系统调用的编号。简单来说，它就像一个“号码簿”，记录了每个系统调用对应的数字。

**功能:**

1. **定义系统调用号 (System Call Numbers):**  这是该文件的核心功能。每个 `#define __NR_* 数字` 的宏定义都将一个人类可读的系统调用名称（例如 `__NR_read`，代表读取文件）关联到一个唯一的数字（例如 `0`）。

**与 Android 功能的关系及举例:**

这个文件是 Android 系统底层运行的基础。所有的用户态程序（包括 Java 框架、NDK 应用以及系统服务）需要与 Linux 内核交互时，最终都要通过系统调用来完成。

* **文件操作:**
    * 当你在 Java 代码中使用 `FileInputStream` 或 `FileOutputStream` 时，底层的 Native 代码会调用 `open()`, `read()`, `write()`, `close()` 等 libc 函数。这些 libc 函数最终会通过对应的系统调用（`__NR_open`, `__NR_read`, `__NR_write`, `__NR_close`）来请求内核执行实际的文件操作。
    * **例子:** 你在 Android 应用中保存一张图片到存储，涉及 `open()` (创建或打开文件), `write()` (写入图片数据), `close()` (关闭文件) 这些操作，它们最终会对应到 `__NR_open`、`__NR_write`、`__NR_close` 系统调用。

* **进程管理:**
    * 当 Android 系统启动一个新的应用进程时，Zygote 进程会使用 `fork()` 或 `clone()` 系统调用来创建子进程。
    * **例子:**  `ActivityManagerService` 启动一个新的 Activity 时，会涉及进程的创建，这最终会用到 `__NR_fork` 或 `__NR_clone` 系统调用。

* **网络通信:**
    * 当你的 Android 应用需要访问网络时，会使用 Socket API。例如，创建一个 socket 连接需要调用 `socket()`，连接到服务器需要 `connect()`，发送数据需要 `sendto()` 或 `sendmsg()`。这些操作都对应着 `__NR_socket`, `__NR_connect`, `__NR_sendto`, `__NR_sendmsg` 等系统调用。
    * **例子:**  一个网络请求库 (如 OkHttp) 发起一个 HTTP 请求，其底层会使用 socket 相关的系统调用进行网络通信。

* **内存管理:**
    * Android 使用 `mmap()` 系统调用进行内存映射，例如将文件映射到内存中，或者在进程间共享内存。
    * **例子:**  SurfaceFlinger 使用 `mmap()` 来管理图形缓冲区。

* **线程同步:**
    *  `futex()` 系统调用是用户态线程同步机制的基础，例如实现互斥锁、条件变量等。
    * **例子:**  Java 的 `synchronized` 关键字或 `java.util.concurrent` 包中的锁，底层在某些情况下会使用 `futex` 系统调用。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它仅仅定义了系统调用的编号。 libc 函数的实现位于 bionic 的其他源文件中。

一个典型的 libc 函数（例如 `read()`）的实现流程如下：

1. **参数处理和校验:** libc 函数接收用户提供的参数（例如文件描述符 `fd`，缓冲区 `buf`，读取字节数 `count`）。它会对这些参数进行基本的校验，例如检查 `fd` 是否有效，`buf` 是否为空等。
2. **系统调用封装:** libc 函数会将用户提供的参数转换为系统调用所需的格式，并将系统调用号（从 `unistd_64.handroid` 中获取）放入特定的寄存器（通常是 `rax` 寄存器）。
3. **触发软中断 (syscall instruction):** libc 函数执行一条特殊的汇编指令（通常是 `syscall`）来触发一个软中断。这个软中断会将 CPU 的控制权转移到 Linux 内核。
4. **内核处理:** Linux 内核接收到软中断后，会根据 `rax` 寄存器中的系统调用号找到对应的内核函数。
5. **执行内核函数:** 内核执行相应的操作，例如从文件中读取数据，将数据写入缓冲区。
6. **返回结果:** 内核将执行结果（例如读取的字节数，错误码）写入特定的寄存器（通常是 `rax` 寄存器）。
7. **libc 函数处理返回值:** libc 函数从寄存器中获取内核的返回值，并将其作为函数的返回值返回给用户程序。如果内核返回了错误，libc 函数通常会将错误码设置到全局变量 `errno` 中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。但是，libc 本身是一个动态链接库 (`.so` 文件)，因此它与 dynamic linker 的工作密不可分。

**so 布局样本 (libgcc.so 为例，libc.so 类似):**

```
libgcc.so:
  - .text:  代码段，包含函数指令
  - .data:  已初始化的全局变量和静态变量
  - .bss:   未初始化的全局变量和静态变量
  - .rodata: 只读数据，例如字符串常量
  - .dynamic:  动态链接信息，包含符号表、重定位表等
  - .dynsym:  动态符号表，列出导出的符号（函数、变量）
  - .dynstr:  动态符号表字符串表
  - .rel.dyn:  数据段的重定位信息
  - .rel.plt:  PLT (Procedure Linkage Table) 的重定位信息
  - .plt:   Procedure Linkage Table，用于延迟绑定
  - ... 其他段 ...
```

**链接的处理过程:**

1. **编译时链接 (Static Linking, 不常用):**  编译器将所有依赖的库的代码复制到最终的可执行文件中。这会导致可执行文件很大。
2. **运行时链接 (Dynamic Linking, 常用):**
   * **编译阶段:** 编译器生成包含符号引用的可执行文件，但并不将库的代码直接链接进去。而是生成一个 **重定位表**，记录了哪些符号需要在运行时解析。
   * **加载阶段:** 当系统加载可执行文件时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 也被加载。
   * **符号解析:** dynamic linker 检查可执行文件依赖的共享库，并在内存中加载这些库。然后，它会遍历可执行文件的重定位表，找到需要解析的符号（例如 libc 中的 `read` 函数）。
   * **重定位:** dynamic linker 在已加载的共享库中查找对应的符号，并将符号的地址填入可执行文件的相应位置。这通常通过 **PLT (Procedure Linkage Table)** 和 **GOT (Global Offset Table)** 完成。
   * **延迟绑定 (Lazy Binding):**  为了提高启动速度，dynamic linker 默认采用延迟绑定。这意味着在第一次调用某个外部函数时才进行符号解析和重定位。PLT 中的代码会先跳转到 dynamic linker 的一个辅助函数，进行符号解析和重定位，然后跳转到目标函数。后续调用会直接跳转到目标函数。

**假设输入与输出 (逻辑推理):**

这个文件定义的是常量，没有实际的输入输出逻辑。 它的作用是提供一个映射关系。

* **假设输入:**  用户态程序想要执行文件读取操作。
* **逻辑推理:**  libc 的 `read()` 函数会使用 `__NR_read` (其值为 0) 作为系统调用号。
* **输出:**  当 `syscall` 指令执行时，内核会根据 `rax` 寄存器中的值 0，找到并执行处理文件读取的内核函数。

**用户或编程常见的使用错误 (不直接涉及此文件，而是使用系统调用的函数):**

* **使用未初始化的文件描述符:** 在调用 `read()` 或 `write()` 等函数时，使用了未经过 `open()` 或 `socket()` 等函数成功返回的文件描述符。
    * **例子:**
    ```c
    #include <unistd.h>
    #include <stdio.h>

    int main() {
        int fd; // 未初始化
        char buffer[100];
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read == -1) {
            perror("read"); // 可能会输出 "Bad file descriptor"
        }
        return 0;
    }
    ```
* **缓冲区溢出:** 在使用 `read()` 或 `recv()` 等函数时，提供的缓冲区太小，导致读取的数据超出缓冲区大小。
    * **例子:**
    ```c
    #include <unistd.h>
    #include <stdio.h>
    #include <fcntl.h>

    int main() {
        int fd = open("my_file.txt", O_RDONLY);
        if (fd == -1) {
            perror("open");
            return 1;
        }
        char buffer[5]; // 缓冲区很小
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
        // 如果 my_file.txt 内容超过 5 个字节，就会发生缓冲区溢出
        printf("Read %zd bytes: %s\n", bytes_read, buffer);
        close(fd);
        return 0;
    }
    ```
* **权限不足:** 尝试访问没有权限的文件或执行没有权限的操作。这会导致相应的系统调用返回错误，例如 `EACCES` (Permission denied)。
    * **例子:**  尝试读取一个只有 root 用户才能访问的文件。
* **文件不存在:** 尝试 `open()` 一个不存在的文件，并且没有指定 `O_CREAT` 标志。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `unistd_64.handroid` 的路径 (以文件读取为例):**

1. **Android Framework (Java/Kotlin):**  你可能在 Java 代码中使用 `FileInputStream`:
   ```java
   FileInputStream fis = new FileInputStream("/sdcard/test.txt");
   byte[] buffer = new byte[1024];
   int bytesRead = fis.read(buffer);
   fis.close();
   ```
2. **Android Framework (Native Code):** `FileInputStream` 的 `read()` 方法最终会调用到 Android 运行时 (ART) 中的 Native 方法。
3. **Bionic Libc:** ART 的 Native 方法会调用 Bionic Libc 提供的 `read()` 函数。
4. **System Call:** Bionic Libc 的 `read()` 函数会将系统调用号 `__NR_read` (值为 0) 放入 `rax` 寄存器，并通过 `syscall` 指令触发系统调用。
5. **Kernel:** Linux 内核接收到系统调用，根据 `rax` 的值 (0)，调用内核中处理 `read` 系统调用的函数。

**NDK 到达 `unistd_64.handroid` 的路径:**

1. **NDK 代码 (C/C++):** 你在 NDK 代码中直接调用标准的 C 库函数，例如 `read()`:
   ```c++
   #include <unistd.h>
   #include <fcntl.h>

   int main() {
       int fd = open("/sdcard/test.txt", O_RDONLY);
       if (fd != -1) {
           char buffer[1024];
           ssize_t bytesRead = read(fd, buffer, sizeof(buffer));
           close(fd);
       }
       return 0;
   }
   ```
2. **Bionic Libc:** NDK 代码链接到 Bionic Libc，直接调用其提供的 `read()` 函数。
3. **System Call 和 Kernel:** 后续步骤与 Framework 类似。

**Frida Hook 示例调试:**

我们可以使用 Frida hook Bionic Libc 的 `open()` 函数，来观察它如何使用 `unistd_64.handroid` 中定义的系统调用号。

```python
import frida
import sys

# 要 hook 的进程名称
package_name = "com.example.myapp"  # 替换成你的应用包名

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var pathname = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        console.log("[open] Pathname:", pathname);
        console.log("[open] Flags:", flags);
        console.log("[open] __NR_open:", Process.getModuleByName("libc.so").findExportByName("open").syscallNumber);
    },
    onLeave: function(retval) {
        console.log("[open] Return Value:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # Keep the script running
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(f"发生错误: {e}")
```

**使用方法:**

1. **安装 Frida 和 Frida-tools:**  `pip install frida frida-tools`
2. **在 Android 设备或模拟器上运行 Frida Server:**  将与你的设备架构匹配的 Frida Server 推送到设备并运行。
3. **替换脚本中的 `package_name` 为你的应用包名。**
4. **运行 Python 脚本:** `python your_frida_script.py`
5. **在你的 Android 应用中执行会调用 `open()` 的操作 (例如打开一个文件)。**

**Frida Hook 脚本解释:**

* `Interceptor.attach(Module.findExportByName("libc.so", "open"), ...)`:  这段代码会 hook Bionic Libc 中的 `open()` 函数。
* `onEnter: function(args)`:  在 `open()` 函数被调用之前执行。
    * `args[0]`: 指向文件路径名的指针。
    * `args[1]`: 打开文件的标志。
    * `Process.getModuleByName("libc.so").findExportByName("open").syscallNumber`:  获取 `open()` 函数对应的系统调用号 (这会查阅类似 `unistd_64.handroid` 这样的文件)。
* `onLeave: function(retval)`: 在 `open()` 函数返回之后执行，`retval` 是函数的返回值（文件描述符）。

当你运行这个脚本并在你的 Android 应用中触发文件打开操作时，Frida 会拦截 `open()` 函数的调用，并打印出文件路径、打开标志以及 `open()` 函数对应的系统调用号（应该就是 `__NR_open` 的值，即 2）。

这个例子演示了如何使用 Frida 来追踪 Android 应用如何通过 Libc 函数最终到达系统调用层。 类似的方法可以用于 hook 其他 Libc 函数，观察它们对应的系统调用号，从而理解 Android Framework 和 NDK 如何与 Linux 内核进行交互。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/unistd_64.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_64_H
#define _UAPI_ASM_UNISTD_64_H
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_stat 4
#define __NR_fstat 5
#define __NR_lstat 6
#define __NR_poll 7
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_munmap 11
#define __NR_brk 12
#define __NR_rt_sigaction 13
#define __NR_rt_sigprocmask 14
#define __NR_rt_sigreturn 15
#define __NR_ioctl 16
#define __NR_pread64 17
#define __NR_pwrite64 18
#define __NR_readv 19
#define __NR_writev 20
#define __NR_access 21
#define __NR_pipe 22
#define __NR_select 23
#define __NR_sched_yield 24
#define __NR_mremap 25
#define __NR_msync 26
#define __NR_mincore 27
#define __NR_madvise 28
#define __NR_shmget 29
#define __NR_shmat 30
#define __NR_shmctl 31
#define __NR_dup 32
#define __NR_dup2 33
#define __NR_pause 34
#define __NR_nanosleep 35
#define __NR_getitimer 36
#define __NR_alarm 37
#define __NR_setitimer 38
#define __NR_getpid 39
#define __NR_sendfile 40
#define __NR_socket 41
#define __NR_connect 42
#define __NR_accept 43
#define __NR_sendto 44
#define __NR_recvfrom 45
#define __NR_sendmsg 46
#define __NR_recvmsg 47
#define __NR_shutdown 48
#define __NR_bind 49
#define __NR_listen 50
#define __NR_getsockname 51
#define __NR_getpeername 52
#define __NR_socketpair 53
#define __NR_setsockopt 54
#define __NR_getsockopt 55
#define __NR_clone 56
#define __NR_fork 57
#define __NR_vfork 58
#define __NR_execve 59
#define __NR_exit 60
#define __NR_wait4 61
#define __NR_kill 62
#define __NR_uname 63
#define __NR_semget 64
#define __NR_semop 65
#define __NR_semctl 66
#define __NR_shmdt 67
#define __NR_msgget 68
#define __NR_msgsnd 69
#define __NR_msgrcv 70
#define __NR_msgctl 71
#define __NR_fcntl 72
#define __NR_flock 73
#define __NR_fsync 74
#define __NR_fdatasync 75
#define __NR_truncate 76
#define __NR_ftruncate 77
#define __NR_getdents 78
#define __NR_getcwd 79
#define __NR_chdir 80
#define __NR_fchdir 81
#define __NR_rename 82
#define __NR_mkdir 83
#define __NR_rmdir 84
#define __NR_creat 85
#define __NR_link 86
#define __NR_unlink 87
#define __NR_symlink 88
#define __NR_readlink 89
#define __NR_chmod 90
#define __NR_fchmod 91
#define __NR_chown 92
#define __NR_fchown 93
#define __NR_lchown 94
#define __NR_umask 95
#define __NR_gettimeofday 96
#define __NR_getrlimit 97
#define __NR_getrusage 98
#define __NR_sysinfo 99
#define __NR_times 100
#define __NR_ptrace 101
#define __NR_getuid 102
#define __NR_syslog 103
#define __NR_getgid 104
#define __NR_setuid 105
#define __NR_setgid 106
#define __NR_geteuid 107
#define __NR_getegid 108
#define __NR_setpgid 109
#define __NR_getppid 110
#define __NR_getpgrp 111
#define __NR_setsid 112
#define __NR_setreuid 113
#define __NR_setregid 114
#define __NR_getgroups 115
#define __NR_setgroups 116
#define __NR_setresuid 117
#define __NR_getresuid 118
#define __NR_setresgid 119
#define __NR_getresgid 120
#define __NR_getpgid 121
#define __NR_setfsuid 122
#define __NR_setfsgid 123
#define __NR_getsid 124
#define __NR_capget 125
#define __NR_capset 126
#define __NR_rt_sigpending 127
#define __NR_rt_sigtimedwait 128
#define __NR_rt_sigqueueinfo 129
#define __NR_rt_sigsuspend 130
#define __NR_sigaltstack 131
#define __NR_utime 132
#define __NR_mknod 133
#define __NR_uselib 134
#define __NR_personality 135
#define __NR_ustat 136
#define __NR_statfs 137
#define __NR_fstatfs 138
#define __NR_sysfs 139
#define __NR_getpriority 140
#define __NR_setpriority 141
#define __NR_sched_setparam 142
#define __NR_sched_getparam 143
#define __NR_sched_setscheduler 144
#define __NR_sched_getscheduler 145
#define __NR_sched_get_priority_max 146
#define __NR_sched_get_priority_min 147
#define __NR_sched_rr_get_interval 148
#define __NR_mlock 149
#define __NR_munlock 150
#define __NR_mlockall 151
#define __NR_munlockall 152
#define __NR_vhangup 153
#define __NR_modify_ldt 154
#define __NR_pivot_root 155
#define __NR__sysctl 156
#define __NR_prctl 157
#define __NR_arch_prctl 158
#define __NR_adjtimex 159
#define __NR_setrlimit 160
#define __NR_chroot 161
#define __NR_sync 162
#define __NR_acct 163
#define __NR_settimeofday 164
#define __NR_mount 165
#define __NR_umount2 166
#define __NR_swapon 167
#define __NR_swapoff 168
#define __NR_reboot 169
#define __NR_sethostname 170
#define __NR_setdomainname 171
#define __NR_iopl 172
#define __NR_ioperm 173
#define __NR_create_module 174
#define __NR_init_module 175
#define __NR_delete_module 176
#define __NR_get_kernel_syms 177
#define __NR_query_module 178
#define __NR_quotactl 179
#define __NR_nfsservctl 180
#define __NR_getpmsg 181
#define __NR_putpmsg 182
#define __NR_afs_syscall 183
#define __NR_tuxcall 184
#define __NR_security 185
#define __NR_gettid 186
#define __NR_readahead 187
#define __NR_setxattr 188
#define __NR_lsetxattr 189
#define __NR_fsetxattr 190
#define __NR_getxattr 191
#define __NR_lgetxattr 192
#define __NR_fgetxattr 193
#define __NR_listxattr 194
#define __NR_llistxattr 195
#define __NR_flistxattr 196
#define __NR_removexattr 197
#define __NR_lremovexattr 198
#define __NR_fremovexattr 199
#define __NR_tkill 200
#define __NR_time 201
#define __NR_futex 202
#define __NR_sched_setaffinity 203
#define __NR_sched_getaffinity 204
#define __NR_set_thread_area 205
#define __NR_io_setup 206
#define __NR_io_destroy 207
#define __NR_io_getevents 208
#define __NR_io_submit 209
#define __NR_io_cancel 210
#define __NR_get_thread_area 211
#define __NR_lookup_dcookie 212
#define __NR_epoll_create 213
#define __NR_epoll_ctl_old 214
#define __NR_epoll_wait_old 215
#define __NR_remap_file_pages 216
#define __NR_getdents64 217
#define __NR_set_tid_address 218
#define __NR_restart_syscall 219
#define __NR_semtimedop 220
#define __NR_fadvise64 221
#define __NR_timer_create 222
#define __NR_timer_settime 223
#define __NR_timer_gettime 224
#define __NR_timer_getoverrun 225
#define __NR_timer_delete 226
#define __NR_clock_settime 227
#define __NR_clock_gettime 228
#define __NR_clock_getres 229
#define __NR_clock_nanosleep 230
#define __NR_exit_group 231
#define __NR_epoll_wait 232
#define __NR_epoll_ctl 233
#define __NR_tgkill 234
#define __NR_utimes 235
#define __NR_vserver 236
#define __NR_mbind 237
#define __NR_set_mempolicy 238
#define __NR_get_mempolicy 239
#define __NR_mq_open 240
#define __NR_mq_unlink 241
#define __NR_mq_timedsend 242
#define __NR_mq_timedreceive 243
#define __NR_mq_notify 244
#define __NR_mq_getsetattr 245
#define __NR_kexec_load 246
#define __NR_waitid 247
#define __NR_add_key 248
#define __NR_request_key 249
#define __NR_keyctl 250
#define __NR_ioprio_set 251
#define __NR_ioprio_get 252
#define __NR_inotify_init 253
#define __NR_inotify_add_watch 254
#define __NR_inotify_rm_watch 255
#define __NR_migrate_pages 256
#define __NR_openat 257
#define __NR_mkdirat 258
#define __NR_mknodat 259
#define __NR_fchownat 260
#define __NR_futimesat 261
#define __NR_newfstatat 262
#define __NR_unlinkat 263
#define __NR_renameat 264
#define __NR_linkat 265
#define __NR_symlinkat 266
#define __NR_readlinkat 267
#define __NR_fchmodat 268
#define __NR_faccessat 269
#define __NR_pselect6 270
#define __NR_ppoll 271
#define __NR_unshare 272
#define __NR_set_robust_list 273
#define __NR_get_robust_list 274
#define __NR_splice 275
#define __NR_tee 276
#define __NR_sync_file_range 277
#define __NR_vmsplice 278
#define __NR_move_pages 279
#define __NR_utimensat 280
#define __NR_epoll_pwait 281
#define __NR_signalfd 282
#define __NR_timerfd_create 283
#define __NR_eventfd 284
#define __NR_fallocate 285
#define __NR_timerfd_settime 286
#define __NR_timerfd_gettime 287
#define __NR_accept4 288
#define __NR_signalfd4 289
#define __NR_eventfd2 290
#define __NR_epoll_create1 291
#define __NR_dup3 292
#define __NR_pipe2 293
#define __NR_inotify_init1 294
#define __NR_preadv 295
#define __NR_pwritev 296
#define __NR_rt_tgsigqueueinfo 297
#define __NR_perf_event_open 298
#define __NR_recvmmsg 299
#define __NR_fanotify_init 300
#define __NR_fanotify_mark 301
#define __NR_prlimit64 302
#define __NR_name_to_handle_at 303
#define __NR_open_by_handle_at 304
#define __NR_clock_adjtime 305
#define __NR_syncfs 306
#define __NR_sendmmsg 307
#define __NR_setns 308
#define __NR_getcpu 309
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311
#define __NR_kcmp 312
#define __NR_finit_module 313
#define __NR_sched_setattr 314
#define __NR_sched_getattr 315
#define __NR_renameat2 316
#define __NR_seccomp 317
#define __NR_getrandom 318
#define __NR_memfd_create 319
#define __NR_kexec_file_load 320
#define __NR_bpf 321
#define __NR_execveat 322
#define __NR_userfaultfd 323
#define __NR_membarrier 324
#define __NR_mlock2 325
#define __NR_copy_file_range 326
#define __NR_preadv2 327
#define __NR_pwritev2 328
#define __NR_pkey_mprotect 329
#define __NR_pkey_alloc 330
#define __NR_pkey_free 331
#define __NR_statx 332
#define __NR_io_pgetevents 333
#define __NR_rseq 334
#define __NR_uretprobe 335
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