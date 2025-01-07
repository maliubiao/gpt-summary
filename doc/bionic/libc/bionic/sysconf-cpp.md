Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/sysconf.cpp`.

**1. Understanding the Core Function:**

The first step is to recognize that `sysconf.cpp` implements the `sysconf()` function. This function is defined by POSIX and is used to retrieve system configuration information at runtime. The key is to understand *what kind* of information it provides.

**2. Identifying the Information Sources:**

The code itself reveals the different ways it gathers information:

* **Constants:** Many `case` statements directly return predefined constants (e.g., `_POSIX2_BC_BASE_MAX`). These are usually limits or feature flags defined by POSIX standards.
* **Kernel Information via `getauxval`:** The code uses `getauxval` to retrieve values from the auxiliary vector. This is a mechanism for the kernel to pass information to user-space processes at startup. Cache information (size, associativity, line size) is often obtained this way on RISC-V and some ARM architectures.
* **File System Access (`/sys`):** For other architectures, the code reads files under `/sys/devices/system/cpu/cpu0/cache/` to get cache parameters. This indicates a platform-dependent approach.
* **`getrlimit`:**  This system call is used to get resource limits, such as the maximum number of processes or open files.
* **Direct System Calls:**  Functions like `getpagesize()`, `get_nprocs_conf()`, `get_nprocs()`, `get_avphys_pages()`, and `get_phys_pages()` directly interact with the kernel to get specific system properties.
* **Hardcoded Defaults/Calculations:**  In some cases, the values are derived or have default values (e.g., the complex logic for `_SC_ARG_MAX`).

**3. Categorizing Functionality:**

Based on the information sources, we can categorize the functionalities:

* **System Limits:** Maximum values for various resources (arguments, child processes, open files, etc.).
* **POSIX Feature Support:**  Indicates whether certain POSIX features are supported by the system.
* **Hardware Information:**  Details about the CPU cache hierarchy (size, associativity, line size).
* **System Properties:** Number of processors, page size, amount of physical/available memory.

**4. Linking to Android:**

The next step is to connect these functionalities to Android specifics. Since Bionic is Android's C library, `sysconf()` is fundamental. Examples include:

* **Resource Limits:**  Android imposes limits on apps for stability and resource management. `sysconf()` helps apps query these.
* **Cache Information:**  Knowing cache parameters can be crucial for performance optimization, though this is less commonly done directly by applications and more by system libraries.
* **Processor Count:**  Used for multithreading and process affinity.
* **Page Size:**  Important for memory management.

**5. Explaining Implementation Details:**

For each libc function used, a brief explanation of its purpose and how it achieves it is needed. Focus on the underlying system calls or mechanisms. For instance:

* `getrlimit`: Retrieves resource limits set by the kernel.
* `getauxval`: Accesses the auxiliary vector populated by the kernel.
* `fopen`/`fscanf`/`fclose`: Standard C file I/O operations to read files under `/sys`.
* `getpagesize`:  A system call to get the memory page size.
* `get_nprocs_conf`/`get_nprocs`: System calls to retrieve CPU core information.
* `get_avphys_pages`/`get_phys_pages`: System calls for memory statistics.

**6. Addressing Dynamic Linking (if relevant):**

While `sysconf.cpp` itself doesn't directly handle dynamic linking, the request asks about its relation to it. The connection is indirect: the values returned by `sysconf()` might influence how dynamic linking behaves (e.g., setting resource limits that could affect loading libraries). A sample SO layout and a simplified description of the linking process are necessary to fulfill this part. Crucially, emphasize that `sysconf.cpp` *provides information* used by the dynamic linker and other parts of the system, but doesn't perform the linking itself.

**7. Providing Examples (Input/Output, Errors):**

Illustrative examples are crucial for understanding:

* **Input/Output:** Show how to call `sysconf()` and the expected output for different `name` values.
* **Common Errors:** Explain when `sysconf()` might return -1 and set `errno`. Incorrect `name` is the primary case.

**8. Tracing from Framework/NDK:**

This requires outlining the call chain:

* **Android Framework (Java):**  Methods in `java.lang.System` or `android.os.Process` can eventually call native methods.
* **NDK (C/C++):**  Directly calling `sysconf()` is possible in NDK code.
* **Bionic (C Library):** The `sysconf()` implementation in `sysconf.cpp` is the target.

A Frida hook example helps demonstrate how to intercept calls to `sysconf()`. Focus on demonstrating the interception and logging of arguments and return values.

**9. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use formatting (like bold text and code blocks) to improve readability. Start with a summary of the file's purpose and then delve into the details.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the constants. **Correction:** Realize the dynamic information gathering via `/sys` and `getauxval` is also significant and platform-dependent.
* **Initial thought:**  Overcomplicate the dynamic linking explanation within the context of `sysconf.cpp`. **Correction:** Clarify that `sysconf.cpp` provides *information* used by the dynamic linker, rather than being part of the linking process itself. Keep the SO layout and linking explanation concise and relevant to how `sysconf` might indirectly influence it.
* **Initial thought:** Provide extremely detailed code walkthroughs of the helper functions. **Correction:**  Focus on the *purpose* of these functions rather than a line-by-line analysis, unless explicitly requested and directly relevant to the core functionality of `sysconf()`.

By following this structured approach and constantly refining the information, a comprehensive and accurate answer can be generated. The key is to understand the core function, identify the sources of information, categorize the functionality, and then connect it to the broader Android ecosystem.
好的，让我们详细分析一下 `bionic/libc/bionic/sysconf.cpp` 这个文件。

**功能概述:**

`sysconf.cpp` 文件实现了 C 标准库函数 `sysconf(int name)`。这个函数用于获取系统相关的配置信息。这些信息通常是与操作系统或硬件相关的常量、限制或特征。

**与 Android 功能的关系及举例说明:**

`sysconf()` 在 Android 系统中扮演着重要的角色，它允许应用程序在运行时查询系统的各种属性，从而编写更健壮和适应性更强的代码。以下是一些例子：

* **获取页面大小 (`_SC_PAGESIZE` / `_SC_PAGE_SIZE`):** Android 的内存管理依赖于页面。应用程序可以使用 `sysconf(_SC_PAGESIZE)` 来获取系统使用的内存页大小，这对于进行内存映射（`mmap`）等操作至关重要。例如，在分配缓冲区时，可以利用页面大小来对齐，提高效率。

   ```c++
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       long page_size = sysconf(_SC_PAGESIZE);
       if (page_size > 0) {
           printf("系统页面大小: %ld 字节\n", page_size);
       } else {
           perror("sysconf");
       }
       return 0;
   }
   ```

* **获取最大打开文件数 (`_SC_OPEN_MAX`):**  Android 系统对单个进程可以打开的文件描述符数量有限制。应用程序可以使用 `sysconf(_SC_OPEN_MAX)` 来查询这个限制，避免因超出限制而导致错误。例如，服务器应用程序需要管理多个连接时，需要考虑这个限制。

   ```c++
   #include <unistd.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       long open_max = sysconf(_SC_OPEN_MAX);
       if (open_max > 0) {
           printf("最大打开文件数: %ld\n", open_max);
       } else {
           perror("sysconf");
       }
       return 0;
   }
   ```

* **获取 CPU 核心数 (`_SC_NPROCESSORS_CONF` / `_SC_NPROCESSORS_ONLN`):**  应用程序可以利用 CPU 核心数来优化多线程任务。`_SC_NPROCESSORS_CONF` 返回配置的处理器数量，而 `_SC_NPROCESSORS_ONLN` 返回当前在线的处理器数量。例如，一个图像处理应用可以根据核心数将图像分割成多个部分并行处理。

   ```c++
   #include <unistd.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       long nprocs_conf = sysconf(_SC_NPROCESSORS_CONF);
       if (nprocs_conf > 0) {
           printf("配置的处理器数量: %ld\n", nprocs_conf);
       } else {
           perror("sysconf");
       }

       long nprocs_onln = sysconf(_SC_NPROCESSORS_ONLN);
       if (nprocs_onln > 0) {
           printf("当前在线的处理器数量: %ld\n", nprocs_onln);
       } else {
           perror("sysconf");
       }
       return 0;
   }
   ```

* **获取 CPU 缓存信息 (`_SC_LEVEL1_ICACHE_SIZE`, `_SC_LEVEL1_DCACHE_SIZE` 等):**  高级应用程序或库可以利用 CPU 缓存信息进行更底层的优化，例如数据布局优化以提高缓存命中率。

**libc 函数的实现细节:**

`sysconf()` 函数的实现方式取决于它要查询的配置项 (`name`)。

1. **常量值:** 对于许多标准 POSIX 定义的常量限制或特征（例如 `_SC_BC_BASE_MAX`, `_SC_POSIX_JOB_CONTROL`），`sysconf()` 直接返回预定义的宏常量。这些宏通常在 `<limits.h>` 或其他头文件中定义。

2. **通过 `getauxval` 获取:**  `getauxval(unsigned long type)` 是一个 Bionic 提供的函数，用于从 auxiliary vector 中获取信息。auxiliary vector 是内核在进程启动时传递给进程的信息数组，包含了诸如页面大小、时钟频率等系统信息。`sysconf()` 使用 `getauxval` 来获取一些硬件或内核配置信息，例如时钟节拍数 (`AT_CLKTCK`) 和 CPU 缓存信息 (`AT_L1I_CACHESIZE`, `AT_L1D_CACHESIZE` 等)。

   ```c++
   case _SC_CLK_TCK:
       return static_cast<long>(getauxval(AT_CLKTCK));
   ```

   ```c++
   struct sysconf_cache {
     long size, assoc, linesize;

     static sysconf_cache from_size_and_geometry(int size_id, int geometry_id) {
       sysconf_cache result;
       result.size = getauxval(size_id);
       unsigned long geometry = getauxval(geometry_id);
       result.assoc = geometry >> 16;
       result.linesize = geometry & 0xffff;
       return result;
     }
   };
   ```
   例如，对于 RISC-V 架构，缓存信息直接通过 `getauxval` 获取。

3. **读取 `/sys` 文件系统:** 对于一些架构（如非 RISC-V 和部分 ARM），缓存信息可能无法通过 auxiliary vector 直接获取。此时，`sysconf()` 会尝试读取 `/sys` 文件系统下的特定文件来获取这些信息。例如，`/sys/devices/system/cpu/cpu0/cache/index0/size` 包含了 L1 缓存的大小。

   ```c++
   static long __sysconf_fread_long(const char* path) {
     long result = 0;
     FILE* fp = fopen(path, "re");
     if (fp != nullptr) {
       fscanf(fp, "%ld", &result);
       fclose(fp);
     }
     return result;
   }
   ```
   `__sysconf_fread_long` 函数用于读取这些文件中的数值。

4. **使用 `getrlimit` 获取:**  `getrlimit(int resource, struct rlimit *rlim)` 是一个系统调用，用于获取或设置进程的资源限制。`sysconf()` 使用 `getrlimit` 来获取诸如最大子进程数 (`RLIMIT_NPROC`) 和最大打开文件数 (`RLIMIT_NOFILE`) 等限制。

   ```c++
   static long __sysconf_rlimit(int resource) {
     rlimit rl;
     getrlimit(resource, &rl);
     return rl.rlim_cur;
   }
   ```

5. **调用其他系统调用:**  对于一些特定的配置项，`sysconf()` 会直接调用相应的系统调用，例如：
   * `getpagesize()` 获取页面大小。
   * `get_nprocs_conf()` 和 `get_nprocs()` 获取 CPU 核心数。
   * `get_avphys_pages()` 和 `get_phys_pages()` 获取可用和总物理内存页数。

6. **复杂计算和逻辑:** 对于某些配置项，例如 `_SC_ARG_MAX`（命令行参数的最大长度），其计算逻辑较为复杂，涉及到堆栈大小限制等因素。

**涉及 dynamic linker 的功能:**

`sysconf.cpp` 本身**不直接**涉及 dynamic linker 的核心功能（如符号解析、重定位）。然而，`sysconf()` 提供的信息可能会被 dynamic linker 在其运行过程中使用，或者影响其行为。

例如，`sysconf(_SC_PAGE_SIZE)` 返回的页面大小可能会影响 dynamic linker 在进行内存映射（例如加载共享库）时的操作。资源限制（如 `_SC_OPEN_MAX`) 也可能影响 dynamic linker 加载依赖库的能力。

**SO 布局样本和链接处理过程 (假设性关联):**

虽然 `sysconf.cpp` 不直接处理链接，但为了说明 `sysconf` 返回的信息可能如何与动态链接相关，我们可以假设一个场景：动态链接器需要分配一段内存来加载一个共享库。

**SO 布局样本:**

假设我们有一个名为 `libexample.so` 的共享库：

```
libexample.so:
    .text          # 代码段
    .rodata        # 只读数据段
    .data          # 可写数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
    .symtab        # 符号表
    .strtab        # 字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT 重定位表
```

**链接处理过程 (简化):**

1. **加载 SO:** 当程序需要使用 `libexample.so` 中的函数时，动态链接器（例如 `linker64` 或 `linker`）会找到该 SO 文件。
2. **内存映射:** 动态链接器使用 `mmap` 系统调用将 SO 文件的各个段映射到进程的地址空间。`sysconf(_SC_PAGE_SIZE)` 返回的页面大小会影响 `mmap` 的粒度。例如，映射的地址需要是页面大小的整数倍。
3. **符号解析:** 动态链接器需要解析程序中引用的 `libexample.so` 中的符号。符号表（`.symtab`）和字符串表（`.strtab`）用于查找符号的地址。
4. **重定位:**  由于共享库被加载到进程的任意地址，需要进行重定位，调整代码和数据中的地址引用。动态重定位表（`.rel.dyn` 和 `.rel.plt`）包含了重定位信息。
5. **执行:** 一旦链接完成，程序就可以调用 `libexample.so` 中的函数了。

**假设输入与输出 (针对 `sysconf` 函数):**

* **假设输入:** `name = _SC_NPROCESSORS_ONLN`
* **假设输出:** (假设系统有 4 个在线 CPU 核心) `4`

* **假设输入:** `name = _SC_PAGESIZE`
* **假设输出:** (假设系统页面大小为 4096 字节) `4096`

* **假设输入:** `name = _SC_OPEN_MAX`
* **假设输出:** (假设系统限制为 1024 个打开文件) `1024`

**用户或编程常见的使用错误:**

1. **使用无效的 `name` 值:**  如果传递给 `sysconf()` 的 `name` 参数不是标准定义的或当前系统不支持的值，`sysconf()` 将返回 `-1` 并设置 `errno` 为 `EINVAL`.

   ```c++
   #include <unistd.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       long result = sysconf(99999); // 假设 99999 是一个无效的 name
       if (result == -1) {
           perror("sysconf"); // 输出类似 "sysconf: Invalid argument"
       }
       return 0;
   }
   ```

2. **未检查返回值:** 程序员可能会忘记检查 `sysconf()` 的返回值是否为 `-1`，从而在使用返回的（可能无效的）值时导致错误。

   ```c++
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       long open_max = sysconf(_SC_OPEN_MAX);
       // 错误：假设 open_max 总是有效
       int fd[open_max]; // 如果 sysconf 返回 -1，则会创建负大小的数组
       return 0;
   }
   ```

3. **过度依赖 `sysconf` 的返回值进行硬编码:** 虽然 `sysconf` 提供了运行时的信息，但在某些情况下，过度依赖其返回值进行硬编码可能会导致可移植性问题。例如，假设一个程序始终假设最大打开文件数是 `sysconf(_SC_OPEN_MAX)`，而没有处理获取失败的情况，或者在不同的系统上该值差异很大时没有做相应的调整。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java):**
   - 在 Java 代码中，可能需要获取一些系统配置信息。例如，`java.lang.System` 类或 `android.os.Process` 类的一些方法可能会间接地调用 Native 代码来获取这些信息.
   - 这些 Native 方法最终会调用到 Bionic 库中的函数。例如，`java.lang.System.getProperty()` 可能会调用到 Native 层，而 Native 层可能会使用 `sysconf()` 获取某些属性。

2. **Android NDK (C/C++):**
   - 使用 NDK 开发的应用程序可以直接调用 C 标准库函数，包括 `sysconf()`.

**Frida Hook 示例调试步骤:**

假设我们要 hook `sysconf` 函数，查看它的调用和参数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['type'], message['payload']['data']))
    else:
        print(message)

package_name = "your.target.package"  # 替换为你的目标应用的包名

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
    'use strict';

    // 获取 sysconf 函数的地址
    const sysconfPtr = Module.findExportByName(null, "sysconf");

    if (sysconfPtr) {
        Interceptor.attach(sysconfPtr, {
            onEnter: function(args) {
                const name = args[0].toInt32();
                let nameStr = 'UNKNOWN';
                switch (name) {
                    case _SC_ARG_MAX: nameStr = '_SC_ARG_MAX'; break;
                    case _SC_AVPHYS_PAGES: nameStr = '_SC_AVPHYS_PAGES'; break;
                    case _SC_CHILD_MAX: nameStr = '_SC_CHILD_MAX'; break;
                    case _SC_CLK_TCK: nameStr = '_SC_CLK_TCK'; break;
                    // ... 添加其他你关心的 _SC_ 常量
                    default: nameStr = 'UNKNOWN (' + name + ')'; break;
                }
                send({ type: "sysconf", data: "Calling sysconf with name: " + nameStr });
                this.name = nameStr;
            },
            onLeave: function(retval) {
                send({ type: "sysconf", data: "sysconf(" + this.name + ") returned: " + retval });
            }
        });
        send({ type: "status", data: "sysconf hook installed successfully." });
    } else {
        send({ type: "error", data: "sysconf function not found." });
    }
"""

# 从 Bionic 的头文件中获取 _SC_ 常量的定义
# 为了方便，这里硬编码了一些常用的，实际使用中需要包含 bionic 的头文件或者手动添加
_SC_ARG_MAX = 0
_SC_AVPHYS_PAGES = 209
_SC_CHILD_MAX = 2
_SC_CLK_TCK = 3
# ... 添加更多常量 ...

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释:**

1. **引入 Frida:**  导入 `frida` 库。
2. **定义消息处理函数:** `on_message` 函数用于处理来自 Frida Hook 的消息。
3. **连接目标应用:**  使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的目标 Android 应用。
4. **编写 Frida Script:**
   - 使用 `Module.findExportByName(null, "sysconf")` 找到 `sysconf` 函数的地址。
   - 使用 `Interceptor.attach` hook `sysconf` 函数。
   - `onEnter`: 在 `sysconf` 函数调用前执行，记录传入的 `name` 参数。为了方便理解，将 `name` 的整数值转换为对应的 `_SC_` 常量字符串。
   - `onLeave`: 在 `sysconf` 函数返回后执行，记录返回值。
5. **加载并运行 Script:**  创建 Frida Script 并加载到目标进程中。
6. **执行操作:**  在 Android 设备上操作目标应用，触发对 `sysconf` 函数的调用。
7. **查看输出:**  Frida 会在控制台输出 `sysconf` 函数的调用信息，包括 `name` 参数和返回值。

通过这个 Frida Hook 示例，你可以动态地观察 Android 应用在运行时如何调用 `sysconf` 函数，以及它查询了哪些系统配置信息。

希望这个详细的解答能够帮助你理解 `bionic/libc/bionic/sysconf.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/sysconf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>  // For FOPEN_MAX.
#include <sys/auxv.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#include "platform/bionic/page.h"
#include "private/bionic_tls.h"

struct sysconf_cache {
  long size, assoc, linesize;

  static sysconf_cache from_size_and_geometry(int size_id, int geometry_id) {
    sysconf_cache result;
    result.size = getauxval(size_id);
    unsigned long geometry = getauxval(geometry_id);
    result.assoc = geometry >> 16;
    result.linesize = geometry & 0xffff;
    return result;
  }
};

struct sysconf_caches {
  sysconf_cache l1_i, l1_d, l2, l3, l4;
};

#if defined(__riscv)

static sysconf_caches* __sysconf_caches() {
  static sysconf_caches cached = []{
    sysconf_caches info = {};
    // riscv64 kernels conveniently hand us all this information.
    info.l1_i = sysconf_cache::from_size_and_geometry(AT_L1I_CACHESIZE, AT_L1I_CACHEGEOMETRY);
    info.l1_d = sysconf_cache::from_size_and_geometry(AT_L1D_CACHESIZE, AT_L1D_CACHEGEOMETRY);
    info.l2 = sysconf_cache::from_size_and_geometry(AT_L2_CACHESIZE, AT_L2_CACHEGEOMETRY);
    info.l3 = sysconf_cache::from_size_and_geometry(AT_L3_CACHESIZE, AT_L3_CACHEGEOMETRY);
    return info;
  }();
  return &cached;
}

#elif defined(__aarch64__)

static sysconf_caches* __sysconf_caches() {
  static sysconf_caches cached = []{
    sysconf_caches info = {};
    // arm64 is especially limited. We can infer the L1 line sizes, but that's it.
    uint64_t ctr_el0;
    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr_el0));
    info.l1_i.linesize = 4 << (ctr_el0 & 0xf);
    info.l1_d.linesize = 4 << ((ctr_el0 >> 16) & 0xf);
    return info;
  }();
  return &cached;
}

#else

static long __sysconf_fread_long(const char* path) {
  long result = 0;
  FILE* fp = fopen(path, "re");
  if (fp != nullptr) {
    fscanf(fp, "%ld", &result);
    fclose(fp);
  }
  return result;
}

static sysconf_caches* __sysconf_caches() {
  static sysconf_caches cached = []{
    sysconf_caches info = {};
    char path[64];
    for (int i = 0; i < 4; i++) {
      sysconf_cache c;

      snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cache/index%d/size", i);
      c.size = __sysconf_fread_long(path) * 1024;
      if (c.size == 0) break;

      snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cache/index%d/ways_of_associativity", i);
      c.assoc = __sysconf_fread_long(path);

      snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cache/index%d/coherency_line_size", i);
      c.linesize = __sysconf_fread_long(path);

      snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cache/index%d/level", i);
      int level = __sysconf_fread_long(path);
      if (level == 1) {
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu0/cache/index%d/type", i);
        FILE* fp = fopen(path, "re");
        char type = fgetc(fp);
        fclose(fp);
        if (type == 'D') {
          info.l1_d = c;
        } else if (type == 'I') {
          info.l1_i = c;
        }
      } else if (level == 2) {
        info.l2 = c;
      } else if (level == 3) {
        info.l3 = c;
      }
    }
    return info;
  }();
  return &cached;
}

#endif

static long __sysconf_rlimit(int resource) {
  rlimit rl;
  getrlimit(resource, &rl);
  return rl.rlim_cur;
}

long sysconf(int name) {
  switch (name) {
    //
    // Things we actually have to calculate...
    //
    case _SC_ARG_MAX:
      // You might think that just returning a constant 128KiB (ARG_MAX) would
      // make sense, as this guy did:
      //
      //   https://lkml.org/lkml/2017/11/15/813...
      //
      //   I suspect a 128kB sysconf(_SC_ARG_MAX) is the sanest bet, simply
      //   because of that "conservative is better than aggressive".
      //
      //   Especially since _technically_ we're still limiting things to that
      //   128kB due to the single-string limit.
      //
      //                 Linus
      //
      // In practice that caused us trouble with toybox tests for xargs edge
      // cases. The tests assume that they can at least reach the kernel's
      // "minimum maximum" of 128KiB, but if we report 128KiB for _SC_ARG_MAX
      // and xargs starts subtracting the environment space and so on from that,
      // then xargs will think it's run out of space when given 128KiB of data,
      // which should always work. See this thread for more:
      //
      // http://lists.landley.net/pipermail/toybox-landley.net/2019-November/011229.html
      //
      // So let's resign ourselves to tracking what the kernel actually does.
      // Right now (2019, Linux 5.3) that amounts to:
      return MAX(MIN(__sysconf_rlimit(RLIMIT_STACK) / 4, 3 * _STK_LIM / 4), ARG_MAX);

    case _SC_AVPHYS_PAGES:      return get_avphys_pages();
    case _SC_CHILD_MAX:         return __sysconf_rlimit(RLIMIT_NPROC);
    case _SC_CLK_TCK:
      return static_cast<long>(getauxval(AT_CLKTCK));
    case _SC_NPROCESSORS_CONF:  return get_nprocs_conf();
    case _SC_NPROCESSORS_ONLN:  return get_nprocs();
    case _SC_OPEN_MAX:          return __sysconf_rlimit(RLIMIT_NOFILE);

    case _SC_PAGESIZE:
    case _SC_PAGE_SIZE:
      // _SC_PAGESIZE and _SC_PAGE_SIZE are distinct, but return the same value.
      return getpagesize();

    case _SC_PHYS_PAGES:        return get_phys_pages();

    //
    // Constants...
    //
    case _SC_BC_BASE_MAX:       return _POSIX2_BC_BASE_MAX;   // Minimum requirement.
    case _SC_BC_DIM_MAX:        return _POSIX2_BC_DIM_MAX;    // Minimum requirement.
    case _SC_BC_SCALE_MAX:      return _POSIX2_BC_SCALE_MAX;  // Minimum requirement.
    case _SC_BC_STRING_MAX:     return _POSIX2_BC_STRING_MAX; // Minimum requirement.
    case _SC_COLL_WEIGHTS_MAX:  return _POSIX2_COLL_WEIGHTS_MAX;  // Minimum requirement.
    case _SC_EXPR_NEST_MAX:     return _POSIX2_EXPR_NEST_MAX;     // Minimum requirement.
    case _SC_LINE_MAX:          return _POSIX2_LINE_MAX;          // Minimum requirement.
    case _SC_NGROUPS_MAX:
      // Only root can read /proc/sys/kernel/ngroups_max on Android, and groups
      // are vestigial anyway, so the "maximum maximum" of NGROUPS_MAX is a good
      // enough answer for _SC_NGROUPS_MAX...
      return NGROUPS_MAX;
    case _SC_PASS_MAX:          return PASS_MAX;
    case _SC_2_C_BIND:          return _POSIX2_C_BIND;
    case _SC_2_C_DEV:           return _POSIX2_C_DEV;
    case _SC_2_CHAR_TERM:       return _POSIX2_CHAR_TERM;
    case _SC_2_FORT_DEV:        return -1;
    case _SC_2_FORT_RUN:        return -1;
    case _SC_2_LOCALEDEF:       return _POSIX2_LOCALEDEF;
    case _SC_2_SW_DEV:          return _POSIX2_SW_DEV;
    case _SC_2_UPE:             return _POSIX2_UPE;
    case _SC_2_VERSION:         return _POSIX2_VERSION;
    case _SC_JOB_CONTROL:       return _POSIX_JOB_CONTROL;
    case _SC_SAVED_IDS:         return _POSIX_SAVED_IDS;
    case _SC_VERSION:           return _POSIX_VERSION;
    case _SC_RE_DUP_MAX:        return _POSIX_RE_DUP_MAX;         // Minimum requirement.
    case _SC_STREAM_MAX:        return FOPEN_MAX;
    case _SC_TZNAME_MAX:        return _POSIX_TZNAME_MAX;         // Minimum requirement.
    case _SC_XOPEN_CRYPT:       return _XOPEN_CRYPT;
    case _SC_XOPEN_ENH_I18N:    return _XOPEN_ENH_I18N;
    case _SC_XOPEN_SHM:         return _XOPEN_SHM;
    case _SC_XOPEN_VERSION:     return _XOPEN_VERSION;
    case _SC_XOPEN_REALTIME:    return _XOPEN_REALTIME;
    case _SC_XOPEN_REALTIME_THREADS: return _XOPEN_REALTIME_THREADS;
    case _SC_XOPEN_LEGACY:      return _XOPEN_LEGACY;
    case _SC_ATEXIT_MAX:        return LONG_MAX;    // Unlimited.
    case _SC_IOV_MAX:           return IOV_MAX;

    case _SC_XOPEN_UNIX:        return _XOPEN_UNIX;
    case _SC_AIO_LISTIO_MAX:    return _POSIX_AIO_LISTIO_MAX;     // Minimum requirement.
    case _SC_AIO_MAX:           return _POSIX_AIO_MAX;            // Minimum requirement.
    case _SC_AIO_PRIO_DELTA_MAX:return 0;                         // Minimum requirement.
    case _SC_DELAYTIMER_MAX:    return _POSIX_DELAYTIMER_MAX;
    case _SC_MQ_OPEN_MAX:       return _POSIX_MQ_OPEN_MAX;        // Minimum requirement.
    case _SC_MQ_PRIO_MAX:       return _POSIX_MQ_PRIO_MAX;        // Minimum requirement.
    case _SC_RTSIG_MAX:         return RTSIG_MAX;
    case _SC_SEM_NSEMS_MAX:     return _POSIX_SEM_NSEMS_MAX;      // Minimum requirement.
    case _SC_SEM_VALUE_MAX:     return SEM_VALUE_MAX;
    case _SC_SIGQUEUE_MAX:      return _POSIX_SIGQUEUE_MAX;       // Minimum requirement.
    case _SC_TIMER_MAX:         return _POSIX_TIMER_MAX;          // Minimum requirement.
    case _SC_ASYNCHRONOUS_IO:   return _POSIX_ASYNCHRONOUS_IO;
    case _SC_FSYNC:             return _POSIX_FSYNC;
    case _SC_MAPPED_FILES:      return _POSIX_MAPPED_FILES;
    case _SC_MEMLOCK:           return _POSIX_MEMLOCK;
    case _SC_MEMLOCK_RANGE:     return _POSIX_MEMLOCK_RANGE;
    case _SC_MEMORY_PROTECTION: return _POSIX_MEMORY_PROTECTION;
    case _SC_MESSAGE_PASSING:   return _POSIX_MESSAGE_PASSING;
    case _SC_PRIORITIZED_IO:    return _POSIX_PRIORITIZED_IO;
    case _SC_PRIORITY_SCHEDULING:  return _POSIX_PRIORITY_SCHEDULING;
    case _SC_REALTIME_SIGNALS:  return _POSIX_REALTIME_SIGNALS;
    case _SC_SEMAPHORES:        return _POSIX_SEMAPHORES;
    case _SC_SHARED_MEMORY_OBJECTS:  return _POSIX_SHARED_MEMORY_OBJECTS;
    case _SC_SYNCHRONIZED_IO:   return _POSIX_SYNCHRONIZED_IO;
    case _SC_TIMERS:            return _POSIX_TIMERS;
    case _SC_GETGR_R_SIZE_MAX:  return 1024;
    case _SC_GETPW_R_SIZE_MAX:  return 1024;
    case _SC_LOGIN_NAME_MAX:    return LOGIN_NAME_MAX;
    case _SC_THREAD_DESTRUCTOR_ITERATIONS: return PTHREAD_DESTRUCTOR_ITERATIONS;
    case _SC_THREAD_KEYS_MAX:   return PTHREAD_KEYS_MAX;
    case _SC_THREAD_STACK_MIN:    return PTHREAD_STACK_MIN;
    case _SC_THREAD_THREADS_MAX:  return -1; // No specific limit.
    case _SC_TTY_NAME_MAX:        return TTY_NAME_MAX;
    case _SC_THREADS:             return _POSIX_THREADS;
    case _SC_THREAD_ATTR_STACKADDR:   return _POSIX_THREAD_ATTR_STACKADDR;
    case _SC_THREAD_ATTR_STACKSIZE:   return _POSIX_THREAD_ATTR_STACKSIZE;
    case _SC_THREAD_PRIORITY_SCHEDULING:  return _POSIX_THREAD_PRIORITY_SCHEDULING;
    case _SC_THREAD_PRIO_INHERIT: return _POSIX_THREAD_PRIO_INHERIT;
    case _SC_THREAD_PRIO_PROTECT: return _POSIX_THREAD_PRIO_PROTECT;
    case _SC_THREAD_SAFE_FUNCTIONS:  return _POSIX_THREAD_SAFE_FUNCTIONS;
    case _SC_MONOTONIC_CLOCK:   return _POSIX_MONOTONIC_CLOCK;

    case _SC_2_PBS:             return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_2_PBS_ACCOUNTING:  return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_2_PBS_CHECKPOINT:  return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_2_PBS_LOCATE:      return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_2_PBS_MESSAGE:     return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_2_PBS_TRACK:       return -1;     // Obsolescent in POSIX.1-2008.
    case _SC_ADVISORY_INFO:     return _POSIX_ADVISORY_INFO;
    case _SC_BARRIERS:          return _POSIX_BARRIERS;
    case _SC_CLOCK_SELECTION:   return _POSIX_CLOCK_SELECTION;
    case _SC_CPUTIME:           return _POSIX_CPUTIME;

    case _SC_HOST_NAME_MAX:     return _POSIX_HOST_NAME_MAX;    // Minimum requirement.
    case _SC_IPV6:              return _POSIX_IPV6;
    case _SC_RAW_SOCKETS:       return _POSIX_RAW_SOCKETS;
    case _SC_READER_WRITER_LOCKS: return _POSIX_READER_WRITER_LOCKS;
    case _SC_REGEXP:            return _POSIX_REGEXP;
    case _SC_SHELL:             return _POSIX_SHELL;
    case _SC_SPAWN:             return _POSIX_SPAWN;
    case _SC_SPIN_LOCKS:        return _POSIX_SPIN_LOCKS;
    case _SC_SPORADIC_SERVER:   return _POSIX_SPORADIC_SERVER;
    case _SC_SS_REPL_MAX:       return -1;
    case _SC_SYMLOOP_MAX:       return _POSIX_SYMLOOP_MAX;      // Minimum requirement.
    case _SC_THREAD_CPUTIME:    return _POSIX_THREAD_CPUTIME;

    case _SC_THREAD_PROCESS_SHARED: return _POSIX_THREAD_PROCESS_SHARED;
    case _SC_THREAD_ROBUST_PRIO_INHERIT:  return _POSIX_THREAD_ROBUST_PRIO_INHERIT;
    case _SC_THREAD_ROBUST_PRIO_PROTECT:  return _POSIX_THREAD_ROBUST_PRIO_PROTECT;
    case _SC_THREAD_SPORADIC_SERVER:      return _POSIX_THREAD_SPORADIC_SERVER;
    case _SC_TIMEOUTS:          return _POSIX_TIMEOUTS;
    case _SC_TRACE:             return -1;
    case _SC_TRACE_EVENT_FILTER:      return -1;
    case _SC_TRACE_EVENT_NAME_MAX:    return -1;
    case _SC_TRACE_INHERIT:     return -1;
    case _SC_TRACE_LOG:         return -1;
    case _SC_TRACE_NAME_MAX:    return -1;
    case _SC_TRACE_SYS_MAX:     return -1;
    case _SC_TRACE_USER_EVENT_MAX:    return -1;
    case _SC_TYPED_MEMORY_OBJECTS:    return _POSIX_TYPED_MEMORY_OBJECTS;
    case _SC_V7_ILP32_OFF32:    return _POSIX_V7_ILP32_OFF32;
    case _SC_V7_ILP32_OFFBIG:   return _POSIX_V7_ILP32_OFFBIG;
    case _SC_V7_LP64_OFF64:     return _POSIX_V7_LP64_OFF64;
    case _SC_V7_LPBIG_OFFBIG:   return _POSIX_V7_LPBIG_OFFBIG;
    case _SC_XOPEN_STREAMS:     return -1;
    case _SC_XOPEN_UUCP:        return -1;

    case _SC_LEVEL1_ICACHE_SIZE:      return __sysconf_caches()->l1_i.size;
    case _SC_LEVEL1_ICACHE_ASSOC:     return __sysconf_caches()->l1_i.assoc;
    case _SC_LEVEL1_ICACHE_LINESIZE:  return __sysconf_caches()->l1_i.linesize;
    case _SC_LEVEL1_DCACHE_SIZE:      return __sysconf_caches()->l1_d.size;
    case _SC_LEVEL1_DCACHE_ASSOC:     return __sysconf_caches()->l1_d.assoc;
    case _SC_LEVEL1_DCACHE_LINESIZE:  return __sysconf_caches()->l1_d.linesize;
    case _SC_LEVEL2_CACHE_SIZE:       return __sysconf_caches()->l2.size;
    case _SC_LEVEL2_CACHE_ASSOC:      return __sysconf_caches()->l2.assoc;
    case _SC_LEVEL2_CACHE_LINESIZE:   return __sysconf_caches()->l2.linesize;
    case _SC_LEVEL3_CACHE_SIZE:       return __sysconf_caches()->l3.size;
    case _SC_LEVEL3_CACHE_ASSOC:      return __sysconf_caches()->l3.assoc;
    case _SC_LEVEL3_CACHE_LINESIZE:   return __sysconf_caches()->l3.linesize;
    case _SC_LEVEL4_CACHE_SIZE:       return __sysconf_caches()->l4.size;
    case _SC_LEVEL4_CACHE_ASSOC:      return __sysconf_caches()->l4.assoc;
    case _SC_LEVEL4_CACHE_LINESIZE:   return __sysconf_caches()->l4.linesize;

    default:
      errno = EINVAL;
      return -1;
  }
}

"""

```