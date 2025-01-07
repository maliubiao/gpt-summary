Response:
My thinking process to answer the request went something like this:

1. **Understand the Core Request:** The user wants a comprehensive analysis of the `mman.handroid` header file from Android's Bionic library. This includes functionality, Android relevance, implementation details, dynamic linking aspects, error handling, usage in the Android framework/NDK, and debugging examples.

2. **Break Down the Header File:** I mentally scanned the header file, identifying the key components:
    * Includes (other header files)
    * Macros (`MAP_ANON`, `MAP_FAILED`, `MREMAP_MAYMOVE`, `MREMAP_FIXED`, `POSIX_MADV_*`)
    * Function declarations (`mmap`, `mmap64`, `munmap`, `msync`, `mprotect`, `mremap`, `mlockall`, `munlockall`, `mlock`, `mlock2`, `munlock`, `mincore`, `madvise`, `process_madvise`, `memfd_create`, `posix_madvise`, `mseal`)
    * Availability guards (`__BIONIC_AVAILABILITY_GUARD`, `__INTRODUCED_IN`)

3. **Categorize Functionality:** I grouped the functions based on their purpose:
    * **Memory Mapping:** `mmap`, `mmap64`, `munmap`
    * **Memory Protection:** `mprotect`
    * **Memory Remapping:** `mremap`
    * **Memory Locking:** `mlock`, `mlock2`, `mlockall`, `munlock`, `munlockall`
    * **Memory Synchronization:** `msync`
    * **Memory Information:** `mincore`
    * **Memory Advice:** `madvise`, `process_madvise`, `posix_madvise`
    * **Anonymous File Creation:** `memfd_create`
    * **Memory Sealing:** `mseal`

4. **Address Each Part of the Request:**  I systematically went through each requirement of the prompt:

    * **Functionality Listing:**  This was straightforward, listing each function and its purpose as described in the comments. I aimed for concise descriptions.

    * **Android Relevance:** This required connecting the functions to real-world Android scenarios. I thought about:
        * **`mmap`:**  Core to Dalvik/ART, shared memory, file access.
        * **`munmap`:**  Releasing resources, preventing leaks.
        * **`mprotect`:**  Security (W^X), sandboxing.
        * **`madvise`:**  Performance optimization.
        * **`memfd_create`:**  Ashmem replacement, secure memory sharing.

    * **Libc Function Implementation:** This is tricky because the *header file* doesn't contain the implementation. I focused on explaining the *system calls* that these libc functions wrap. I described the general mechanism of a system call (user space -> kernel space).

    * **Dynamic Linker:** I looked for functions with a strong connection to loading and managing shared libraries. `mmap` is key here. I described how the dynamic linker uses `mmap` to load `.so` files. For the `.so` layout, I provided a typical structure (ELF header, program headers, sections). For the linking process, I outlined the steps: loading, symbol resolution, relocation.

    * **Logic Inference (Hypothetical Input/Output):**  I chose `mmap` as it's fundamental. I created a simple scenario of mapping an anonymous region and described the expected return value and potential errors.

    * **Common Usage Errors:**  I considered typical mistakes programmers make with these functions, like incorrect size calculations, permission issues, and forgetting to `munmap`.

    * **Android Framework/NDK Usage:** This required thinking about higher-level Android components that rely on these low-level functions. I mentioned:
        * **Framework:**  ART, Binder (using shared memory), resource loading.
        * **NDK:** Direct access to these functions for native developers.

    * **Frida Hooking:**  I provided practical Frida examples for hooking `mmap` and `mprotect`, showing how to intercept calls, inspect arguments, and even modify behavior.

5. **Structure and Language:** I organized the answer into clear sections with headings. I used Chinese as requested and aimed for precise but understandable language. I tried to avoid overly technical jargon where possible, or explained it when necessary.

6. **Refinement and Review:** After drafting the initial response, I reviewed it to ensure accuracy, completeness, and clarity. I checked for any inconsistencies or areas where more detail might be needed. For instance, I initially focused heavily on `mmap` for the dynamic linker part and then broadened it to the general concept of shared library loading.

Essentially, my approach was to decompose the request, analyze the provided code, connect it to the broader Android ecosystem, and explain the concepts in a structured and informative way. Since direct implementation details weren't in the header file, I focused on the underlying system calls and the purposes of the libc wrappers. The Frida examples required understanding how hooking works and selecting relevant functions to demonstrate.

这是一个关于Android Bionic库中 `bionic/libc/include/sys/mman.handroid` 文件的分析。这个文件定义了与内存管理相关的系统调用包装器函数和宏定义。

**功能列举:**

这个头文件定义了以下与内存管理相关的功能：

1. **内存映射 (Memory Mapping):**
   - `mmap()`:  在进程的地址空间中创建一个新的内存映射。可以将文件的一部分或者匿名内存区域映射到进程的地址空间。
   - `mmap64()`: `mmap()` 的变体，即使在32位系统上也能接受64位的偏移量。
   - `munmap()`:  删除一个已创建的内存映射。

2. **内存保护 (Memory Protection):**
   - `mprotect()`: 修改一个内存区域的访问权限（例如，只读、只写、可执行）。

3. **内存重映射 (Memory Remapping):**
   - `mremap()`:  改变一个现有内存映射的大小和/或位置。

4. **内存锁定 (Memory Locking):**
   - `mlockall()`: 锁定调用进程的所有映射内存页到物理内存中，防止被交换到磁盘。
   - `munlockall()`: 解锁调用进程的所有映射内存页。
   - `mlock()`: 锁定指定地址范围的内存页。
   - `mlock2()`:  `mlock()` 的变体，可以指定额外的标志。
   - `munlock()`: 解锁指定地址范围的内存页。

5. **内存同步 (Memory Synchronization):**
   - `msync()`:  将内存映射区域的修改刷新到磁盘上的文件。

6. **内存状态查询 (Memory State Query):**
   - `mincore()`: 查询指定内存区域的页是否在物理内存中。

7. **内存建议 (Memory Advice):**
   - `madvise()`:  向内核提供关于内存区域使用模式的建议，以帮助内核优化内存管理。
   - `process_madvise()`:  类似于 `madvise()`，但作用于由 PID 文件描述符指定的进程。
   - `posix_madvise()`: `madvise()` 的POSIX标准版本。

8. **匿名文件创建 (Anonymous File Creation):**
   - `memfd_create()`: 创建一个匿名的、基于内存的文件。

9. **内存密封 (Memory Sealing):**
   - `mseal()`: 密封一个内存区域，防止对其进行进一步的修改，如 `mprotect()` 调用。

**与 Android 功能的关系及举例说明:**

这些功能在 Android 系统中扮演着至关重要的角色，涉及进程管理、内存优化、安全性和文件访问等方面。

* **`mmap()` 和 `munmap()`:**
    * **Dalvik/ART 虚拟机:**  Android Runtime (ART) 使用 `mmap()` 来加载 DEX 文件、共享对象库 (.so 文件) 以及进行堆内存管理。例如，当一个应用启动时，ART 会使用 `mmap()` 将其 DEX 代码映射到内存中执行。释放不再使用的资源时，会使用 `munmap()`。
    * **共享内存 (Shared Memory):**  进程间通信 (IPC) 中常用的技术，例如 `ashmem` (Android Shared Memory) 底层就使用了 `mmap()` 来创建可在多个进程间共享的内存区域。Binder 机制也可能涉及到共享内存的映射。
    * **文件访问:**  读取或写入文件时，可以将文件的一部分映射到内存中，直接操作内存即可访问文件内容，提高了效率。

* **`mprotect()`:**
    * **安全性:**  用于设置内存区域的访问权限，例如可以将代码段设置为只读和可执行，数据段设置为可读写但不可执行，防止缓冲区溢出等安全漏洞。Android 的 W^X (Write XOR Execute) 安全机制就依赖于 `mprotect()` 来实现。
    * **沙箱 (Sandboxing):**  限制进程对内存的访问，增强系统的安全性。

* **`madvise()` 和 `posix_madvise()`:**
    * **性能优化:**  Android 系统可以使用这些函数向内核提供关于内存使用模式的建议。例如，如果知道某个内存区域将要顺序访问，可以使用 `MADV_SEQUENTIAL` 提示内核进行预读。如果知道某个内存区域不再需要，可以使用 `MADV_DONTNEED` 释放内存资源。

* **`memfd_create()`:**
    * **Ashmem 的替代:**  用于创建匿名内存区域，可以像文件一样操作，并可以通过文件描述符在进程间传递。相比传统的 `ashmem`，`memfd_create` 提供了更好的安全性和功能。

**libc 函数的功能实现 (简要说明):**

这些函数是 C 标准库 (libc) 提供的接口，它们是对 Linux 系统调用的封装。当一个程序调用这些 libc 函数时，实际上会触发一个系统调用，进入内核态执行相应的内存管理操作。

例如，`mmap()` 的实现大致步骤如下：

1. **参数校验:** libc 函数会首先检查传入的参数是否合法。
2. **系统调用:**  libc 函数会调用相应的 Linux 系统调用 (`syscall(__NR_mmap)` 等)，将参数传递给内核。
3. **内核处理:** Linux 内核接收到 `mmap` 系统调用后，会进行以下操作：
   - 分配虚拟地址空间。
   - 如果映射的是文件，则建立虚拟地址和文件页的映射关系。如果是匿名映射，则分配物理内存。
   - 设置内存区域的保护属性。
   - 返回映射后的地址。
4. **返回用户空间:** 系统调用返回，libc 函数将内核返回的地址传递给调用者。

其他函数的实现类似，都是通过相应的系统调用与内核交互完成内存管理任务。

**涉及 dynamic linker 的功能:**

`mmap()` 是与动态链接器 (dynamic linker) 关系最密切的函数。动态链接器在加载共享对象库 (`.so` 文件) 时，会使用 `mmap()` 将这些库的代码段、数据段等映射到进程的地址空间。

**so 布局样本:**

一个典型的 `.so` 文件（例如 `libfoo.so`）的内存布局大致如下：

```
----------------------  <-- 加载基址 (Load Address)
| ELF Header         |
----------------------
| Program Headers    |
----------------------
| .text (代码段)     |  <-- 通常是只读和可执行的
----------------------
| .rodata (只读数据) |  <-- 通常是只读的
----------------------
| .data (已初始化数据) | <-- 通常是可读写的
----------------------
| .bss (未初始化数据)| <-- 通常是可读写的，加载时清零
----------------------
| ... 其他 section   |
----------------------
```

**链接的处理过程:**

1. **加载共享库:** 当程序需要使用一个共享库时，动态链接器（在 Android 上通常是 `linker64` 或 `linker`）会首先被加载和执行。
2. **查找依赖:** 动态链接器会解析程序的可执行文件头，找到其依赖的共享库。
3. **`mmap()` 映射:**  对于每个依赖的共享库，动态链接器会使用 `mmap()` 将其加载到内存中的某个地址。这个地址可能是固定的，也可能是根据地址空间布局随机化 (ASLR) 确定的。
4. **符号解析 (Symbol Resolution):** 动态链接器会遍历所有加载的共享库，解析未定义的符号引用。例如，如果程序中调用了一个在 `libfoo.so` 中定义的函数，动态链接器会找到该函数的地址。
5. **重定位 (Relocation):**  由于共享库被加载到内存的地址可能不是编译时预期的地址，动态链接器需要修改代码和数据中的地址引用，使其指向正确的内存位置。这涉及到修改 `.text` 和 `.data` 段中的内容。
6. **执行程序:**  完成所有依赖库的加载、符号解析和重定位后，动态链接器会将控制权交给程序的入口点。

**假设输入与输出 (针对 `mmap`):**

**假设输入:**

* `__addr`: `NULL` (由系统决定映射地址)
* `__size`: 4096 字节 (一个页)
* `__prot`: `PROT_READ | PROT_WRITE` (可读写)
* `__flags`: `MAP_ANONYMOUS | MAP_PRIVATE` (匿名私有映射)
* `__fd`: -1 (匿名映射，无需文件描述符)
* `__offset`: 0

**预期输出:**

* **成功:** 返回一个指向新映射内存区域的指针，例如 `0x7b40000000` (具体的地址会因系统和 ASLR 而异)。
* **失败:** 返回 `MAP_FAILED`，并设置 `errno` 以指示错误原因，例如 `ENOMEM` (内存不足)。

**用户或编程常见的使用错误:**

* **忘记 `munmap()`:**  使用 `mmap()` 分配的内存需要手动使用 `munmap()` 释放，否则会导致内存泄漏。
* **`size` 参数错误:**  `size` 参数通常需要是系统页大小的整数倍。
* **`prot` 参数设置错误:**  例如，尝试写入一个只读映射的内存区域会导致段错误 (Segmentation Fault)。
* **`offset` 参数越界:**  当映射文件时，`offset + size` 不能超过文件的大小。
* **并发访问问题:**  在多线程或多进程环境下，对共享的内存映射进行并发访问时，需要进行适当的同步，否则可能导致数据竞争。
* **对 `MAP_PRIVATE` 映射的写入预期:**  对 `MAP_PRIVATE` 映射的修改不会反映到原始文件，这与 `MAP_SHARED` 不同。初学者可能会混淆这两种模式。

**Android framework 或 ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework:**

1. **Java 代码调用:** Android Framework 中的 Java 代码，例如 `FileOutputStream` 或 `MappedByteBuffer`，在底层会调用 Native 代码。
2. **JNI 调用:**  Java 代码通过 Java Native Interface (JNI) 调用到 Android Runtime (ART) 或 Dalvik 虚拟机的 Native 代码。
3. **Native 方法:**  ART 或 Dalvik 的 Native 代码中会调用 Bionic 库提供的函数，例如 `mmap()`。

**Android NDK:**

1. **NDK 代码直接调用:**  使用 NDK 开发的 Native 代码可以直接调用 Bionic 库中的函数，例如 `mmap()`, `mprotect()` 等。

**Frida Hook 示例:**

假设我们想 hook `mmap` 函数，查看其参数和返回值：

```python
import frida
import sys

package_name = "你的应用包名" # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "mmap"), {
    onEnter: function(args) {
        console.log("[+] mmap called");
        console.log("    addr: " + args[0]);
        console.log("    length: " + args[1]);
        console.log("    prot: " + args[2]);
        console.log("    flags: " + args[3]);
        console.log("    fd: " + args[4]);
        console.log("    offset: " + args[5]);
    },
    onLeave: function(retval) {
        console.log("[+] mmap returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

1. **导入 Frida:** 导入 Frida 库。
2. **指定包名:** 设置要 hook 的应用程序的包名。
3. **连接到进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到目标 Android 设备的进程。
4. **Frida Script:**
   - `Interceptor.attach()`:  用于 hook 指定的函数。
   - `Module.findExportByName("libc.so", "mmap")`:  查找 `libc.so` 库中的 `mmap` 函数。
   - `onEnter()`:  在 `mmap` 函数调用之前执行。`args` 数组包含了 `mmap` 函数的参数。
   - `onLeave()`:  在 `mmap` 函数返回之后执行。`retval` 包含了 `mmap` 函数的返回值。
   - `console.log()`:  用于在 Frida 控制台中打印信息。
5. **加载 Script:** 将 Frida script 加载到目标进程中。
6. **保持运行:** `sys.stdin.read()` 使脚本保持运行状态，以便持续监控 `mmap` 函数的调用。

运行这个 Frida 脚本后，每当目标应用程序调用 `mmap` 函数时，你将在 Frida 控制台中看到相关的参数信息和返回值。你可以根据需要 hook 其他函数，例如 `mprotect`，方法类似。只需要将 `Module.findExportByName` 中的函数名替换即可。

这个分析涵盖了 `bionic/libc/include/sys/mman.handroid` 文件中定义的功能，并详细解释了它们在 Android 系统中的作用、实现方式以及如何使用 Frida 进行调试。

Prompt: 
```
这是目录为bionic/libc/include/sys/mman.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <linux/memfd.h>
#include <linux/mman.h>
#include <linux/uio.h>

__BEGIN_DECLS

/** Alternative spelling of the `MAP_ANONYMOUS` flag for mmap(). */
#define MAP_ANON MAP_ANONYMOUS

/** Return value for mmap(). */
#define MAP_FAILED __BIONIC_CAST(reinterpret_cast, void*, -1)

/**
 * [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html)
 * creates a memory mapping for the given range.
 *
 * Returns the address of the mapping on success,
 * and returns `MAP_FAILED` and sets `errno` on failure.
 */
#if defined(__USE_FILE_OFFSET64)
void* _Nonnull mmap(void* _Nullable __addr, size_t __size, int __prot, int __flags, int __fd, off_t __offset) __RENAME(mmap64);
#else
void* _Nonnull mmap(void* _Nullable __addr, size_t __size, int __prot, int __flags, int __fd, off_t __offset);
#endif

/**
 * mmap64() is a variant of mmap() that takes a 64-bit offset even on LP32.
 *
 * See https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md
 */
void* _Nonnull mmap64(void* _Nullable __addr, size_t __size, int __prot, int __flags, int __fd, off64_t __offset);

/**
 * [munmap(2)](https://man7.org/linux/man-pages/man2/munmap.2.html)
 * deletes a memory mapping for the given range.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int munmap(void* _Nonnull __addr, size_t __size);

/**
 * [msync(2)](https://man7.org/linux/man-pages/man2/msync.2.html)
 * flushes changes to a memory-mapped file to disk.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int msync(void* _Nonnull __addr, size_t __size, int __flags);

/**
 * [mprotect(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html)
 * sets the protection on a memory region.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int mprotect(void* _Nonnull __addr, size_t __size, int __prot);

/** Flag for mremap(). */
#define MREMAP_MAYMOVE  1

/** Flag for mremap(). */
#define MREMAP_FIXED    2

/**
 * [mremap(2)](https://man7.org/linux/man-pages/man2/mremap.2.html)
 * expands or shrinks an existing memory mapping.
 *
 * Returns the address of the mapping on success,
 * and returns `MAP_FAILED` and sets `errno` on failure.
 */
void* _Nonnull mremap(void* _Nonnull __old_addr, size_t __old_size, size_t __new_size, int __flags, ...);

/**
 * [mlockall(2)](https://man7.org/linux/man-pages/man2/mlockall.2.html)
 * locks pages (preventing swapping).
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int mlockall(int __flags);

/**
 * [munlockall(2)](https://man7.org/linux/man-pages/man2/munlockall.2.html)
 * unlocks pages (allowing swapping).
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int munlockall(void);

/**
 * [mlock(2)](https://man7.org/linux/man-pages/man2/mlock.2.html)
 * locks pages (preventing swapping).
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int mlock(const void* _Nonnull __addr, size_t __size);

/**
 * [mlock2(2)](https://man7.org/linux/man-pages/man2/mlock.2.html)
 * locks pages (preventing swapping), with optional flags.
 *
 * Available since API level 30.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(30)
int mlock2(const void* _Nonnull __addr, size_t __size, int __flags) __INTRODUCED_IN(30);
#endif /* __BIONIC_AVAILABILITY_GUARD(30) */


/**
 * [munlock(2)](https://man7.org/linux/man-pages/man2/munlock.2.html)
 * unlocks pages (allowing swapping).
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int munlock(const void* _Nonnull __addr, size_t __size);

/**
 * [mincore(2)](https://man7.org/linux/man-pages/man2/mincore.2.html)
 * tests whether pages are resident in memory.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int mincore(void* _Nonnull __addr, size_t __size, unsigned char* _Nonnull __vector);

/**
 * [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html)
 * gives the kernel advice about future usage patterns.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int madvise(void* _Nonnull __addr, size_t __size, int __advice);

/**
 * [process_madvise(2)](https://man7.org/linux/man-pages/man2/process_madvise.2.html)
 * works just like madvise(2) but applies to the process specified by the given
 * PID file descriptor.
 *
 * Available since API level 31. Its sibling process_mrelease() does not have a
 * libc wrapper and should be called using syscall() instead. Given the lack of
 * widespread applicability of this system call and the absence of wrappers in
 * other libcs, it was probably a mistake to have added this wrapper to bionic.
 *
 * Returns the number of bytes advised on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(31)
ssize_t process_madvise(int __pid_fd, const struct iovec* _Nonnull __iov, size_t __count, int __advice, unsigned __flags) __INTRODUCED_IN(31);
#endif /* __BIONIC_AVAILABILITY_GUARD(31) */


#if defined(__USE_GNU)

/**
 * [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
 * creates an anonymous file.
 *
 * Available since API level 30.
 *
 * Returns an fd on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(30)
int memfd_create(const char* _Nonnull __name, unsigned __flags) __INTRODUCED_IN(30);
#endif /* __BIONIC_AVAILABILITY_GUARD(30) */


#endif

#if __ANDROID_API__ >= 23

/*
 * Some third-party code uses the existence of POSIX_MADV_NORMAL to detect the
 * availability of posix_madvise. This is not correct, since having up-to-date
 * UAPI headers says nothing about the C library, but for the time being we
 * don't want to harm adoption of the unified headers.
 *
 * https://github.com/android-ndk/ndk/issues/395
 */

/** Flag for posix_madvise(). */
#define POSIX_MADV_NORMAL     MADV_NORMAL
/** Flag for posix_madvise(). */
#define POSIX_MADV_RANDOM     MADV_RANDOM
/** Flag for posix_madvise(). */
#define POSIX_MADV_SEQUENTIAL MADV_SEQUENTIAL
/** Flag for posix_madvise(). */
#define POSIX_MADV_WILLNEED   MADV_WILLNEED
/** Flag for posix_madvise(). */
#define POSIX_MADV_DONTNEED   MADV_DONTNEED

#endif

/**
 * [posix_madvise(3)](https://man7.org/linux/man-pages/man3/posix_madvise.3.html)
 * gives the kernel advice about future usage patterns.
 *
 * Available since API level 23.
 * See also madvise() which is available at all API levels.
 *
 * Returns 0 on success, and returns a positive error number on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(23)
int posix_madvise(void* _Nonnull __addr, size_t __size, int __advice) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


/**
 * [mseal(2)](https://man7.org/linux/man-pages/man2/mseal.2.html)
 * seals the given range to prevent modifications such as mprotect() calls.
 *
 * Available since API level 36.
 * Requires a Linux 6.10 or newer kernel.
 * Always fails for 32-bit processes.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(36)
int mseal(void* _Nonnull __addr, size_t __size, unsigned long __flags) __INTRODUCED_IN(36);
#endif /* __BIONIC_AVAILABILITY_GUARD(36) */


__END_DECLS

"""

```