Response:
Let's break down the thought process to answer the request about `bionic/libc/include/sys/uio.h`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided header file. Key aspects include:

* **Functionality:** What do the functions in this file do?
* **Android Relation:** How do these functions tie into the Android operating system? Provide concrete examples.
* **Implementation:** How are these `libc` functions implemented *at a high level*? (The request doesn't expect the assembly code.)
* **Dynamic Linker:** How do functions in this file relate to the dynamic linker?  Provide SO layout and linking process.
* **Logical Reasoning:**  If the answer involves deductions or assumptions, clarify the input and expected output.
* **Common Errors:** What are typical mistakes programmers make when using these functions?
* **Android Framework/NDK Path:** How does a call from the Android framework or NDK eventually reach these functions? Provide a Frida hook example.

**2. Initial Analysis of the Header File:**

* **File Name and Location:** `bionic/libc/include/sys/uio.h`. This immediately tells us it's part of Bionic (Android's libc), deals with system-level I/O, and is a header file defining interfaces.
* **Copyright Notice:** Standard boilerplate, not directly relevant to the technical functionality.
* **`#pragma once`:**  Standard header guard to prevent multiple inclusions.
* **`@file`, `@brief`:** Documentation providing a high-level description: "Multi-buffer ('vector') I/O operations using `struct iovec`." This is the core concept.
* **Includes:** `<sys/cdefs.h>`, `<sys/types.h>`, `<linux/uio.h>`. These are standard system header files providing basic definitions and types. Crucially, it includes `<linux/uio.h>`, suggesting these functions are thin wrappers around Linux system calls.
* **`__BEGIN_DECLS`, `__END_DECLS`:** Standard C idiom for marking declarations for potential C++ compatibility.
* **Function Declarations:** The meat of the file. Each function is clearly documented with a link to its man page. This is a huge clue!  The documentation mentions "vector I/O," "multiple buffers," and the `iovec` structure.

**3. Categorizing and Understanding the Functions:**

The functions can be grouped:

* **Basic Vector I/O:** `readv`, `writev`. These are the foundation. They read/write from/to a file descriptor using multiple buffers.
* **Positioned Vector I/O:** `preadv`, `pwritev`, `preadv64`, `pwritev64`. These add the ability to specify an offset without modifying the file pointer. The `64` variants handle larger offsets.
* **Advanced Positioned Vector I/O with Flags:** `preadv2`, `pwritev2`, `preadv64v2`, `pwritev64v2`. These introduce flags for more control over the I/O operation (e.g., `RWF_NOWAIT`).
* **Cross-Process Vector I/O:** `process_vm_readv`, `process_vm_writev`. These allow reading/writing to the memory of another process.

**4. Addressing Specific Parts of the Request:**

* **Functionality:**  Summarize the purpose of each function, focusing on the "vector" aspect (multiple buffers) and any specific features (offset, flags, cross-process).
* **Android Relation and Examples:** Think about common Android use cases for efficient I/O. Examples include:
    * Network operations (receiving/sending data in chunks).
    * File operations (reading/writing structured data).
    * Inter-process communication (though the `process_vm_*` functions are more direct for this).
* **Implementation:** Since the header includes `<linux/uio.h>`, the core implementation likely relies on the corresponding Linux system calls. Bionic provides the C library wrappers. The internal details of the kernel syscall aren't required.
* **Dynamic Linker:**  These are standard `libc` functions. They are part of `libc.so`. The linking process is standard: when an application uses these functions, the dynamic linker resolves the symbols to the addresses within `libc.so`. Provide a basic SO layout example.
* **Logical Reasoning:** For functions like `readv`, illustrate with a simple example of reading into two buffers.
* **Common Errors:** Focus on typical mistakes like incorrect buffer sizes, null pointers, invalid file descriptors, and misunderstanding the behavior of the offset in positioned I/O.
* **Android Framework/NDK Path and Frida Hook:**  Trace a typical I/O operation from a high-level Android API down to these functions. File reading/writing is a good example. Show how to use Frida to intercept these calls. This requires knowing how the framework interacts with the NDK and then the underlying system calls.

**5. Structuring the Answer:**

Organize the answer logically, addressing each point of the request. Use headings and bullet points for clarity. Provide code examples where necessary. Explain terminology clearly (e.g., "file descriptor," "iovec").

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the low-level kernel implementation. **Correction:**  Remember the request is about the `libc` *interface*. The kernel implementation is generally hidden.
* **Initial thought:**  Overcomplicate the dynamic linker explanation. **Correction:** Keep it concise and focused on the basic symbol resolution.
* **Initial thought:**  Not enough concrete Android examples. **Correction:** Brainstorm common I/O scenarios in Android.
* **Initial thought:**  Frida hook example too complex. **Correction:** Start with a simple interception of `readv` or `writev`.

By following these steps and constantly refining the approach, the comprehensive and accurate answer provided in the example can be constructed. The key is to understand the request thoroughly, break it down into manageable parts, and leverage the information provided in the header file itself (especially the man page links).
好的，让我们详细分析一下 `bionic/libc/include/sys/uio.h` 这个文件。

**功能列举:**

这个头文件定义了一组用于执行**多缓冲区 (或称为 "vector") I/O 操作**的函数。这些函数允许你通过一次系统调用，将数据从多个缓冲区读取到一个文件描述符，或者将数据从一个文件描述符写入到多个缓冲区。核心的概念是使用 `struct iovec` 结构体数组来描述这些缓冲区。

具体来说，它声明了以下函数：

* **`readv(int __fd, const struct iovec* _Nonnull __iov, int __count)`:** 从文件描述符 `__fd` 读取数据到 `__iov` 指向的 `__count` 个缓冲区中。
* **`writev(int __fd, const struct iovec* _Nonnull __iov, int __count)`:** 从 `__iov` 指向的 `__count` 个缓冲区中写入数据到文件描述符 `__fd`。
* **`preadv(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset)`:**  类似于 `readv`，但是允许在指定的文件偏移量 `__offset` 处开始读取，而不会改变文件描述符的当前偏移量。
* **`pwritev(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset)`:** 类似于 `writev`，但是允许在指定的文件偏移量 `__offset` 处开始写入，而不会改变文件描述符的当前偏移量。
* **`preadv64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset)`:** 与 `preadv` 相同，但使用 64 位的文件偏移量，即使在 32 位进程中也能处理更大的文件。
* **`pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset)`:** 与 `pwritev` 相同，但使用 64 位的文件偏移量。
* **`preadv2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags)`:**  类似于 `preadv`，但增加了 `__flags` 参数，允许指定额外的操作标志，例如 `RWF_NOWAIT` (非阻塞 I/O)。
* **`pwritev2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags)`:** 类似于 `pwritev`，但增加了 `__flags` 参数。
* **`preadv64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags)`:** 与 `preadv2` 相同，但使用 64 位的文件偏移量。
* **`pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags)`:** 与 `pwritev2` 相同，但使用 64 位的文件偏移量。
* **`process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags)`:** 从另一个进程 (进程 ID 为 `__pid`) 的地址空间读取数据到当前进程的缓冲区中。
* **`process_vm_writev(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags)`:** 将当前进程的缓冲区中的数据写入到另一个进程的地址空间中。

**与 Android 功能的关系及举例说明:**

这些函数是底层系统调用在 C 库中的封装，对于 Android 的各种功能至关重要，因为它们提供了高效的 I/O 操作方式。

* **网络编程:**  当应用程序需要接收或发送网络数据时，可以使用 `readv` 和 `writev` 来处理接收到的多个数据包或构造需要发送的多个数据段。例如，一个 HTTP 服务器可能使用 `writev` 将 HTTP 响应的头部和主体部分一次性发送出去，而无需多次 `write` 调用。
* **文件操作:**  在处理复杂的文件格式时，可能需要将文件的不同部分读取到不同的缓冲区中，或者将来自不同缓冲区的片段写入到文件中。例如，一个视频解码器可以使用 `readv` 一次性读取视频帧的头部和数据部分。
* **进程间通信 (IPC):** `process_vm_readv` 和 `process_vm_writev` 提供了在不同进程之间直接读写内存的能力，这对于某些特定的 IPC 场景非常有用，例如调试器读取目标进程的内存。
* **Binder 机制:** Android 的 Binder 机制在底层进行数据传输时，可能会使用到这些高效的 I/O 函数来传输跨进程的数据。

**libc 函数的功能实现:**

这些函数在 `bionic` 中通常是对应 Linux 系统调用的薄封装。这意味着，它们的主要工作是将 C 库中的参数转换为系统调用所需的格式，然后通过 `syscall` 指令陷入内核，执行实际的 I/O 操作。

例如，对于 `readv` 函数，其实现大致如下：

1. **参数验证:**  检查文件描述符 `__fd` 是否有效，`__iov` 是否为 NULL，`__count` 是否为非负数等。
2. **系统调用准备:** 将 `__fd`，`__iov` 的地址，以及 `__count` 作为参数放入 CPU 寄存器中，以供系统调用使用。
3. **执行系统调用:** 使用 `syscall` 指令触发内核态切换，执行 `readv` 系统调用。
4. **处理返回值:** 内核完成读取操作后，会将读取的字节数或者错误码返回给用户态。`readv` 函数接收这个返回值，并根据返回值设置 `errno` (如果发生错误)，然后将读取的字节数返回给调用者。

**动态链接器功能及 SO 布局样本和链接处理过程:**

这些函数是标准 C 库 (`libc.so`) 的一部分，因此它们的链接由动态链接器 (`linker`) 负责。

**SO 布局样本 (简化版):**

```
libc.so:
    .text:  <可执行代码段>
        ...
        readv:  <readv 函数的机器码>
        writev: <writev 函数的机器码>
        ...
    .data:  <已初始化数据段>
        ...
    .bss:   <未初始化数据段>
        ...
    .dynsym: <动态符号表>
        readv
        writev
        ...
    .dynstr: <动态字符串表>
        readv
        writev
        ...
    .plt:   <过程链接表>
        readv@plt:
            jmp *GOT[entry_readv]
        writev@plt:
            jmp *GOT[entry_writev]
    .got:   <全局偏移表>
        entry_readv: 0  // 初始值为 0，由 linker 填充
        entry_writev: 0 // 初始值为 0，由 linker 填充
```

**链接处理过程:**

1. **编译时:** 当应用程序的代码中调用了 `readv` 或 `writev` 时，编译器会在可执行文件的 `.plt` (Procedure Linkage Table) 节生成相应的条目，并在 `.got` (Global Offset Table) 节生成对应的占位符。
2. **加载时:**  当 Android 系统加载应用程序时，动态链接器会将 `libc.so` 也加载到内存中。
3. **符号解析:** 动态链接器会遍历应用程序的依赖关系，找到所需的共享库 (`libc.so`)。然后，它会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `readv` 和 `writev` 的实际地址。
4. **重定位:** 动态链接器会将找到的 `readv` 和 `writev` 的实际地址填充到应用程序的 `.got` 表中对应的条目 (`entry_readv` 和 `entry_writev`)。
5. **运行时:** 当应用程序第一次调用 `readv` 或 `writev` 时，程序会跳转到 `.plt` 表中的对应条目。`.plt` 表中的指令会首先跳转到 `.got` 表中存储的地址。由于链接器已经填充了正确的地址，所以程序最终会执行 `libc.so` 中 `readv` 或 `writev` 的实际代码。

**逻辑推理的假设输入与输出 (以 `readv` 为例):**

**假设输入:**

* `__fd`: 一个已经打开的文件描述符，例如，打开文件 "test.txt" 得到的文件描述符 3。
* `__iov`: 一个包含两个 `iovec` 结构体的数组：
    * `iov[0].iov_base`: 指向一个 10 字节的缓冲区 `buf1`。
    * `iov[0].iov_len`: 10。
    * `iov[1].iov_base`: 指向一个 20 字节的缓冲区 `buf2`。
    * `iov[1].iov_len`: 20。
* `__count`: 2。

**假设 "test.txt" 文件内容为 "abcdefghijklmnopqrstuvwxyz"。**

**输出:**

* `readv` 函数返回 26 (成功读取的字节数)。
* `buf1` 的内容变为 "abcdefghij"。
* `buf2` 的内容变为 "klmnopqrstuvwxyz"。

**常见的使用错误:**

* **`iovec` 结构体设置错误:**
    * `iov_base` 指向无效的内存地址 (例如，NULL 或已释放的内存)。
    * `iov_len` 设置为负数或者过大的值，导致访问越界。
* **`__count` 值错误:** `__count` 大于 `iov` 数组的实际大小，导致访问越界。
* **文件描述符无效:** `__fd` 是一个无效的或者未打开的文件描述符。
* **缓冲区大小不足:**  提供的缓冲区总大小小于要读取或写入的数据大小，可能导致数据截断。
* **权限问题:**  尝试读取没有读取权限的文件或写入没有写入权限的文件。
* **并发问题:**  在多线程环境下，如果多个线程同时操作同一个文件描述符，可能会出现数据竞争和不一致的情况。

**示例:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main() {
    int fd = open("test.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    char buf1[10];
    char buf2[20];
    struct iovec iov[2];

    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);

    ssize_t bytes_read = readv(fd, iov, 2);
    if (bytes_read == -1) {
        perror("readv");
        close(fd);
        return 1;
    }

    printf("Bytes read: %zd\n", bytes_read);
    printf("buf1: %.*s\n", (int)sizeof(buf1), buf1);
    printf("buf2: %.*s\n", (int)sizeof(buf2), buf2);

    close(fd);
    return 0;
}
```

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 层):** 应用程序通常通过 Android Framework 提供的 Java API 来进行文件或网络操作。例如，使用 `FileInputStream` 或 `Socket` 类进行数据读取。
2. **Framework Native 代码:**  这些 Java API 在底层会调用对应的 Native 代码 (通常是 C++ 代码)，这些 Native 代码是 Android Framework 的一部分。
3. **NDK (Native Development Kit) (可选):** 如果应用程序使用了 NDK 开发，那么应用程序的 Native 代码可以直接调用 Bionic 提供的 C 库函数，包括 `readv` 和 `writev`。
4. **Bionic (libc):** Framework 的 Native 代码或 NDK 开发的应用程序最终会调用到 Bionic 提供的 C 库函数，例如 `readv`。
5. **系统调用:** Bionic 的 `readv` 函数会将参数传递给内核，触发 `readv` 系统调用。
6. **Linux 内核:**  Linux 内核接收到系统调用请求后，会执行实际的读取操作，将数据从文件或网络缓冲区读取到用户空间的指定缓冲区。

**Frida Hook 示例调试步骤:**

假设我们要 Hook `readv` 函数来查看其参数和返回值。

1. **准备 Frida 环境:** 确保你的设备已 root，并且安装了 Frida 和 Frida Server。
2. **编写 Frida 脚本 (JavaScript):**

```javascript
if (Java.available) {
    Java.perform(function() {
        const libc = Process.getModuleByName("libc.so");
        const readvPtr = libc.getExportByName("readv");

        if (readvPtr) {
            Interceptor.attach(readvPtr, {
                onEnter: function(args) {
                    const fd = args[0].toInt32();
                    const iovPtr = ptr(args[1]);
                    const count = args[2].toInt32();

                    console.log("readv called");
                    console.log("  fd:", fd);
                    console.log("  count:", count);

                    for (let i = 0; i < count; i++) {
                        const iovEntry = iovPtr.add(i * Process.pointerSize * 2); // 每个 iovec 结构体两个指针大小
                        const basePtr = Memory.readPointer(iovEntry);
                        const len = Memory.readUInt(iovEntry.add(Process.pointerSize));
                        console.log(`  iov[${i}].iov_base:`, basePtr);
                        console.log(`  iov[${i}].iov_len:`, len);
                        // 可以选择读取缓冲区内容进行查看
                        // if (len > 0) {
                        //     console.log(`  iov[${i}] data:`, Memory.readByteArray(basePtr, len));
                        // }
                    }
                },
                onLeave: function(retval) {
                    console.log("readv returned:", retval.toInt32());
                }
            });
            console.log("Hooked readv");
        } else {
            console.error("Failed to find readv in libc.so");
        }
    });
} else {
    console.log("Java is not available.");
}
```

3. **运行 Frida 脚本:**

   ```bash
   frida -U -f <你的应用包名> -l your_frida_script.js
   ```

   或者，如果你的应用程序已经在运行：

   ```bash
   frida -U <你的应用包名> -l your_frida_script.js
   ```

4. **操作应用程序:**  执行一些会导致文件或网络 I/O 的操作。
5. **查看 Frida 输出:**  Frida 会在控制台中打印出 `readv` 函数被调用时的参数 (文件描述符，`iovec` 数组的地址和大小) 以及返回值。

通过这种方式，你可以观察应用程序在底层是如何使用这些 I/O 函数的，以及传递了哪些参数，这对于调试和理解 Android 系统的运行机制非常有帮助。

希望这个详细的解释能够帮助你理解 `bionic/libc/include/sys/uio.h` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/sys/uio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

/**
 * @file sys/uio.h
 * @brief Multi-buffer ("vector") I/O operations using `struct iovec`.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <linux/uio.h>

__BEGIN_DECLS

/**
 * [readv(2)](https://man7.org/linux/man-pages/man2/readv.2.html) reads
 * from an fd into the `__count` buffers described by `__iov`.
 *
 * Returns the number of bytes read on success,
 * and returns -1 and sets `errno` on failure.
 */
ssize_t readv(int __fd, const struct iovec* _Nonnull __iov, int __count);

/**
 * [writev(2)](https://man7.org/linux/man-pages/man2/writev.2.html) writes
 * to an fd from the `__count` buffers described by `__iov`.
 *
 * Returns the number of bytes written on success,
 * and returns -1 and sets `errno` on failure.
 */
ssize_t writev(int __fd, const struct iovec* _Nonnull __iov, int __count);

#if defined(__USE_GNU)

/**
 * [preadv(2)](https://man7.org/linux/man-pages/man2/preadv.2.html) reads
 * from an fd into the `__count` buffers described by `__iov`, starting at
 * offset `__offset` into the file.
 *
 * Returns the number of bytes read on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 24.
 */

#if __BIONIC_AVAILABILITY_GUARD(24)
ssize_t preadv(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset) __RENAME_IF_FILE_OFFSET64(preadv64) __INTRODUCED_IN(24);

/**
 * [pwritev(2)](https://man7.org/linux/man-pages/man2/pwritev.2.html) writes
 * to an fd from the `__count` buffers described by `__iov`, starting at offset
 * `__offset` into the file.
 *
 * Returns the number of bytes written on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 24.
 */
ssize_t pwritev(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset) __RENAME_IF_FILE_OFFSET64(pwritev64) __INTRODUCED_IN(24);

/**
 * Like preadv() but with a 64-bit offset even in a 32-bit process.
 *
 * Available since API level 24.
 */
ssize_t preadv64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset) __INTRODUCED_IN(24);

/**
 * Like pwritev() but with a 64-bit offset even in a 32-bit process.
 *
 * Available since API level 24.
 */
ssize_t pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


/**
 * [preadv2(2)](https://man7.org/linux/man-pages/man2/preadv2.2.html) reads
 * from an fd into the `__count` buffers described by `__iov`, starting at
 * offset `__offset` into the file, with the given flags.
 *
 * Returns the number of bytes read on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 33.
 */

#if __BIONIC_AVAILABILITY_GUARD(33)
ssize_t preadv2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags) __RENAME_IF_FILE_OFFSET64(preadv64v2) __INTRODUCED_IN(33);

/**
 * [pwritev2(2)](https://man7.org/linux/man-pages/man2/pwritev2.2.html) writes
 * to an fd from the `__count` buffers described by `__iov`, starting at offset
 * `__offset` into the file, with the given flags.
 *
 * Returns the number of bytes written on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 33.
 */
ssize_t pwritev2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags) __RENAME_IF_FILE_OFFSET64(pwritev64v2) __INTRODUCED_IN(33);

/**
 * Like preadv2() but with a 64-bit offset even in a 32-bit process.
 *
 * Available since API level 33.
 */
ssize_t preadv64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags) __INTRODUCED_IN(33);

/**
 * Like pwritev2() but with a 64-bit offset even in a 32-bit process.
 *
 * Available since API level 33.
 */
ssize_t pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags) __INTRODUCED_IN(33);
#endif /* __BIONIC_AVAILABILITY_GUARD(33) */


/**
 * [process_vm_readv(2)](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
 * reads from the address space of another process.
 *
 * Returns the number of bytes read on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 23.
 */

#if __BIONIC_AVAILABILITY_GUARD(23)
ssize_t process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);

/**
 * [process_vm_writev(2)](https://man7.org/linux/man-pages/man2/process_vm_writev.2.html)
 * writes to the address space of another process.
 *
 * Returns the number of bytes read on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 23.
 */
ssize_t process_vm_writev(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#endif

__END_DECLS

"""

```