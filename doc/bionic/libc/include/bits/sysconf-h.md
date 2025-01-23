Response:
Here's a breakdown of the thinking process to generate the comprehensive answer:

1. **Understand the Core Request:** The initial request asks for an explanation of the provided C header file (`bionic/libc/include/bits/sysconf.handroid`). The key is to identify its function, relationship to Android, implementation details (especially for `sysconf`), dynamic linker aspects, potential errors, and how it's accessed from higher layers (Android Framework/NDK).

2. **Initial Analysis of the File:**  The first step is to read through the header file. It's immediately apparent that it defines a series of preprocessor macros starting with `_SC_`. These macros represent symbolic constants used with the `sysconf()` function. The comments associated with each macro provide a brief description of what system configuration value they represent (e.g., maximum number of open files, page size, etc.).

3. **Identify the Central Function:** The file itself doesn't *implement* functions. It defines constants used *by* functions. The primary function these constants relate to is clearly `sysconf()`, as stated in the comments. This becomes the focal point of the explanation.

4. **Categorize Functionality:**  To provide a structured answer, categorize the purpose of the header file. It's essentially defining constants for querying system configurations.

5. **Explain `sysconf()`:** Describe the purpose of the `sysconf()` function. Emphasize that it retrieves system configuration values at runtime. Mention the importance of the `_SC_` constants as arguments to this function.

6. **Relate to Android Functionality:**  Connect the defined constants to Android-specific features or limitations where possible. This involves thinking about how these configurations impact application behavior on Android. Examples:
    * `_SC_OPEN_MAX`:  Impacts the number of files an app can open simultaneously, which can affect database operations, networking, etc.
    * `_SC_PAGE_SIZE`:  Fundamental to memory management and used by functions like `mmap`.
    * Thread-related constants:  Influence multithreading capabilities.

7. **Implementation of `sysconf()`:**  Since the file doesn't contain the *implementation*, explain that the *actual* logic resides elsewhere in bionic's source code. Speculate on the implementation strategy: likely a large `switch` statement or a lookup table based on the `__name` argument. Mention potential system calls involved in fetching the underlying information. Acknowledge that the header file merely defines the *interface*.

8. **Dynamic Linker Relevance:**  Consider if any of the constants directly relate to the dynamic linker. While not explicitly obvious, some limits (like argument size `_SC_ARG_MAX`) *could* indirectly influence how the linker loads shared libraries. However, the connection isn't strong in this *particular* header. It's important not to overstate the dynamic linker's direct involvement here. Focus on the *broader* context of system configuration.

9. **User/Programming Errors:**  Think about common mistakes developers might make related to these constants and `sysconf()`:
    * Assuming portability of specific `_SC_` constants or their return values across different Android versions or even other operating systems.
    * Ignoring the return value of `sysconf()` (which can be -1 on error).
    * Misinterpreting the meaning of certain constants.

10. **Android Framework/NDK Pathway:**  Trace the path from the Android application level down to the `sysconf()` call.
    * **Framework:** High-level Java APIs (e.g., related to file I/O, process management) might eventually call native methods.
    * **NDK:** Direct C/C++ code can use `sysconf()` directly.
    * System Calls:  Ultimately, `sysconf()` will often lead to system calls to the kernel to retrieve the information.

11. **Frida Hooking:** Provide a practical example of using Frida to intercept `sysconf()`. Show how to:
    * Attach to a process.
    * Hook the function.
    * Log the arguments and return value. This demonstrates how to observe the function's behavior.

12. **Structure and Language:** Organize the information logically with clear headings. Use precise language, explaining technical terms. Provide code examples where appropriate. Maintain a helpful and informative tone.

13. **Review and Refine:** After drafting the answer, review it for accuracy, completeness, and clarity. Ensure all parts of the original request have been addressed. For instance, initially, I might not have emphasized the *interface* nature of the header file strongly enough regarding implementation. A review would catch this. Also, double-check the accuracy of the Frida script.

By following these steps, a comprehensive and accurate answer can be constructed, addressing all aspects of the original prompt. The process involves understanding the provided code, connecting it to broader system concepts, and providing practical examples.
## 对 bionic/libc/include/bits/sysconf.handroid 源代码文件的分析

这个文件 `bionic/libc/include/bits/sysconf.handroid` 是 Android Bionic C 库的一部分，它定义了一系列预处理器宏，这些宏代表了可以传递给 `sysconf()` 函数的参数。`sysconf()` 函数用于在运行时获取系统配置信息。

**功能:**

这个文件的主要功能是定义了 `sysconf()` 函数可以查询的各种系统配置选项的符号常量。每个宏都以 `_SC_` 开头，后面跟着一个描述该配置项的名称。

**与 Android 功能的关系及举例说明:**

这些常量直接关联着 Android 操作系统及其运行环境的配置信息。`sysconf()` 函数允许应用程序在运行时查询这些信息，从而根据不同的系统环境进行调整或获取必要的限制。以下是一些具体的例子：

* **`_SC_ARG_MAX`**:  获取传递给 `exec()` 函数的最大参数字节数。这限制了可以传递给新启动进程的命令行参数的总大小。在 Android 中，如果应用程序尝试使用过长的命令行参数启动新进程，将会失败。例如，使用 `Runtime.getRuntime().exec(commandArray)` 启动进程时，`commandArray` 的总长度会受到这个限制。

* **`_SC_OPEN_MAX`**: 获取单个进程可以同时打开的最大文件数。这影响着应用程序可以同时处理的文件、套接字等资源的数量。在 Android 中，如果应用程序打开的文件句柄超过这个限制，将会抛出 "Too many open files" 错误。例如，网络应用同时监听多个端口或者数据库应用同时打开大量数据库连接时会受到影响。

* **`_SC_PAGE_SIZE`**: 获取系统页面的大小。这是内存管理的基础单位。Android 的内存管理系统（包括 Dalvik/ART 虚拟机）会使用这个值进行内存分配和映射。例如，使用 `mmap()` 系统调用进行内存映射时，映射的粒度通常是页面的大小。

* **`_SC_NPROCESSORS_CONF` 和 `_SC_NPROCESSORS_ONLN`**: 分别获取配置的处理器数量和当前在线的处理器数量。应用程序可以根据这些信息来调整其多线程策略，例如设置合适的线程池大小，以充分利用多核处理器的性能。

* **与 POSIX 标准相关的常量 (例如 `_SC_VERSION`, `_SC_POSIX_THREADS`)**:  这些常量表明 Android 对 POSIX 标准的兼容程度。应用程序可以通过查询这些值来判断当前系统是否支持特定的 POSIX 功能，从而编写更具移植性的代码。

**libc 函数 `sysconf()` 的功能实现:**

`sysconf()` 函数的实现通常涉及以下步骤：

1. **接收参数:** 接收一个整数参数 `__name`，这个参数对应于 `sysconf.handroid` 中定义的 `_SC_` 常量之一。

2. **参数校验:** 检查 `__name` 是否是有效的常量。

3. **系统调用或内部查找:** 根据 `__name` 的值，`sysconf()` 函数会采取不同的方法获取配置信息：
    * **直接映射到系统调用:** 对于某些基本配置项（例如 `_SC_PAGE_SIZE`），`sysconf()` 可能会直接调用相应的系统调用（如 `getpagesize()`）。
    * **读取 `/proc` 文件系统:** 许多系统信息可以通过读取 `/proc` 文件系统中的特定文件获得。例如，处理器数量信息可能来自 `/proc/cpuinfo`。
    * **读取 `sysfs` 文件系统:** 类似于 `/proc`，`sysfs` 也提供了访问内核对象属性的接口。
    * **硬编码或预定义值:** 某些常量的值可能是硬编码的或者在编译时就已经确定。
    * **条件编译:** 根据不同的 Android 版本或硬件架构，`sysconf()` 的实现可能有所不同。

4. **返回结果:** 将获取到的配置信息以 `long` 类型的值返回。如果发生错误，通常返回 -1 并设置 `errno`。

**由于这个文件只定义了常量，`sysconf()` 函数的具体实现代码位于 Bionic 库的其他源文件中，例如 `bionic/libc/bionic/sysconf.cpp`。**

**涉及 dynamic linker 的功能:**

这个文件本身并不直接涉及 dynamic linker 的功能。它定义的是系统配置信息，这些信息可能会被应用程序和动态链接器在运行时使用。

**so 布局样本及链接的处理过程:**

假设我们有一个简单的共享库 `libexample.so`，它使用了 `sysconf()` 函数来获取系统页面大小：

```c
// libexample.c
#include <unistd.h>
#include <stdio.h>

void print_page_size() {
    long page_size = sysconf(_SC_PAGE_SIZE);
    printf("Page size: %ld\n", page_size);
}
```

编译生成 `libexample.so`：

```bash
clang -shared -o libexample.so libexample.c
```

另一个应用程序 `app` 使用了这个共享库：

```c
// app.c
#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle = dlopen("./libexample.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Cannot open library: %s\n", dlerror());
        return 1;
    }

    typedef void (*print_page_size_func)();
    print_page_size_func print_func = (print_page_size_func) dlsym(handle, "print_page_size");
    if (!print_func) {
        fprintf(stderr, "Cannot find symbol: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    print_func();
    dlclose(handle);
    return 0;
}
```

编译生成可执行文件 `app`:

```bash
clang -o app app.c -ldl
```

**so 布局样本 (`libexample.so`):**

```
libexample.so:
    LOAD           0x0000000000000000  0x0000000000000000  0x0000000000000000  0x1078  R E
    LOAD           0x0000000000001078  0x0000000000002078  0x0000000000002078   0x170  RW
 DYNAMIC        0x0000000000001088
 NOTE           0x0000000000000290  0x00000000000002b4  0x0000000000000024
 GNU_HASH       0x00000000000002b8  0x000000000000021c
 STRTAB         0x00000000000004d8  0x0000000000000087
 SYMTAB         0x0000000000000560  0x0000000000000050
 RELA           0x00000000000005b0  0x0000000000000030  0x0000000000000018
 RELA           0x00000000000005e0  0x0000000000000018  0x0000000000000018
 JUMP_SLOT      0x0000000000000600  0x0000000000000018
 STRSZ          0x000000000000068f
 SYMENT         0x0000000000000018
 RELASZ         0x0000000000000048
 RELAENT        0x0000000000000018
 FLAGS          0x0000000000000006
```

**链接的处理过程:**

1. 当 `app` 启动并执行到 `dlopen("./libexample.so", RTLD_LAZY)` 时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。

2. Linker 会加载 `libexample.so` 到内存中，根据其 ELF 头部信息确定加载地址。

3. 由于 `libexample.so` 调用了 `sysconf()` 函数，这是一个外部符号，需要进行符号解析。Linker 会在系统中已加载的共享库（包括 `libc.so`）中查找 `sysconf()` 的定义。

4. 找到 `sysconf()` 的定义后，Linker 会建立 `libexample.so` 中 `sysconf()` 调用地址到 `libc.so` 中 `sysconf()` 实现地址的链接关系。这通常通过修改 GOT (Global Offset Table) 表项来实现。

5. 当 `app` 调用 `libexample.so` 中的 `print_page_size()` 函数时，函数内部会调用 `sysconf(_SC_PAGE_SIZE)`。由于链接已经建立，实际执行的是 `libc.so` 中的 `sysconf()` 实现。

**逻辑推理、假设输入与输出:**

假设 `sysconf(_SC_PAGE_SIZE)` 的实现通过读取 `/proc/meminfo` 文件并解析 "PageSize" 行来获取页面大小。

* **假设输入:** `/proc/meminfo` 文件包含一行 `PageSize:           4096 kB`
* **逻辑推理:** `sysconf()` 函数会读取该文件，提取 "4096"，并将其转换为字节数，即 4096 * 1024 = 4194304。
* **输出:** `sysconf(_SC_PAGE_SIZE)` 将返回 `4194304`。

**用户或编程常见的使用错误:**

* **假设 `sysconf()` 在所有 Android 版本或设备上返回相同的值:**  某些系统配置参数可能会因 Android 版本、设备硬件或内核配置而异。例如，处理器数量、可用内存等。因此，不应硬编码依赖 `sysconf()` 返回的特定值。

* **忽略 `sysconf()` 的返回值:** 如果 `sysconf()` 调用失败，它会返回 -1 并设置 `errno`。程序员应该检查返回值并处理错误情况。例如：

```c
long arg_max = sysconf(_SC_ARG_MAX);
if (arg_max == -1) {
    perror("sysconf"); // 打印错误信息
    // 处理错误
} else {
    // 使用 arg_max
}
```

* **使用未定义的 `_SC_` 常量:**  传递给 `sysconf()` 的参数必须是有效的 `_SC_` 常量。使用未定义的常量会导致未定义的行为。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 代码):**
   - 应用程序可能调用 Java Framework 提供的 API，例如与文件 I/O、进程管理、线程相关的类。
   - Framework 的某些实现细节可能会调用到 Native 代码 (C/C++)。
   - 例如，`java.lang.ProcessBuilder` 用于创建新的进程，其内部实现可能会涉及到对进程参数大小的限制，最终可能通过 JNI 调用到 Bionic 库的函数，而这些函数可能会间接使用 `sysconf(_SC_ARG_MAX)` 来检查参数限制。

2. **NDK (Native 代码):**
   - NDK 开发者可以直接在 C/C++ 代码中调用 `sysconf()` 函数。
   - 例如，一个需要根据系统处理器数量创建线程池的 NDK 模块会直接调用 `sysconf(_SC_NPROCESSORS_ONLN)`。

**Frida Hook 示例调试这些步骤:**

假设我们要 hook `sysconf()` 函数并观察应用程序如何调用它：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['value']))
    else:
        print(message)

def main(target_process):
    session = frida.attach(target_process)

    script_code = """
    var sysconf = Module.findExportByName("libc.so", "sysconf");
    if (sysconf) {
        Interceptor.attach(sysconf, {
            onEnter: function(args) {
                var name = args[0].toInt();
                var nameStr = "";
                // 根据 sysconf.handroid 中的定义，将数字映射到常量名
                // 这里需要添加所有可能的映射
                if (name === 0x0000) nameStr = "_SC_ARG_MAX";
                else if (name === 0x000b) nameStr = "_SC_OPEN_MAX";
                else if (name === 0x0028) nameStr = "_SC_PAGE_SIZE";
                else if (name === 0x0060) nameStr = "_SC_NPROCESSORS_CONF";
                else if (name === 0x0061) nameStr = "_SC_NPROCESSORS_ONLN";
                else nameStr = "Unknown (" + name + ")";

                this.name = nameStr;
                console.log("[Sysconf] Calling sysconf with name: " + nameStr);
            },
            onLeave: function(retval) {
                console.log("[Sysconf] sysconf(" + this.name + ") returned: " + retval);
                send({ name: this.name, value: retval.toString() });
            }
        });
        console.log("[*] Hooked sysconf at " + sysconf);
    } else {
        console.log("[!] Could not find sysconf in libc.so");
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    target = sys.argv[1]
    main(target)
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_sysconf.py`。
2. 运行你要调试的 Android 应用程序。
3. 找到应用程序的进程名或 PID。
4. 在电脑上运行 Frida hook 脚本：`python hook_sysconf.py <应用程序的进程名或 PID>`。

**Frida Hook 脚本的工作原理:**

- **连接目标进程:** 使用 Frida 连接到指定的 Android 应用程序进程。
- **查找 `sysconf` 函数:** 在 `libc.so` 库中查找 `sysconf` 函数的地址。
- **Hook `sysconf`:** 使用 `Interceptor.attach` 拦截 `sysconf` 函数的调用。
- **`onEnter`:** 在 `sysconf` 函数被调用之前执行。记录传入的参数 `__name`，并将其映射到对应的 `_SC_` 常量名。
- **`onLeave`:** 在 `sysconf` 函数执行完毕后执行。记录返回值，并将常量名和返回值通过 `send()` 函数发送回 Python 脚本。
- **Python 接收消息:** Python 脚本的 `on_message` 函数接收来自 Frida 的消息，并打印出 `sysconf` 的调用信息和返回值。

通过这个 Frida hook 示例，你可以观察到应用程序在运行时调用 `sysconf` 函数的情况，包括它查询了哪些系统配置信息以及返回的值。这有助于理解应用程序如何利用这些系统信息以及排查相关问题。

### 提示词
```
这是目录为bionic/libc/include/bits/sysconf.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

/** sysconf() query for the maximum number of bytes of exec() arguments. */
#define _SC_ARG_MAX 0x0000
/** sysconf() query for bc(1) behavior equivalent to _POSIX2_BC_BASE_MAX. */
#define _SC_BC_BASE_MAX 0x0001
/** sysconf() query for bc(1) behavior equivalent to _POSIX2_BC_DIM_MAX. */
#define _SC_BC_DIM_MAX 0x0002
/** sysconf() query for bc(1) behavior equivalent to _POSIX2_BC_SCALE_MAX. */
#define _SC_BC_SCALE_MAX 0x0003
/** sysconf() query for bc(1) behavior equivalent to _POSIX2_BC_STRING_MAX. */
#define _SC_BC_STRING_MAX 0x0004
/** sysconf() query equivalent to RLIMIT_NPROC. */
#define _SC_CHILD_MAX 0x0005
/** sysconf() query equivalent to AT_CLKTCK. */
#define _SC_CLK_TCK 0x0006
/** sysconf() query for collation behavior equivalent to _POSIX2_COLL_WEIGHTS_MAX. */
#define _SC_COLL_WEIGHTS_MAX 0x0007
/** sysconf() query for expr(1) behavior equivalent to _POSIX2_EXPR_NEST_MAX. */
#define _SC_EXPR_NEST_MAX 0x0008
/** sysconf() query for command-line tool behavior equivalent to _POSIX2_LINE_MAX. */
#define _SC_LINE_MAX 0x0009
/** sysconf() query equivalent to NGROUPS_MAX. */
#define _SC_NGROUPS_MAX 0x000a
/** sysconf() query equivalent to RLIMIT_NOFILE. */
#define _SC_OPEN_MAX 0x000b
/** sysconf() query equivalent to PASS_MAX. */
#define _SC_PASS_MAX 0x000c
/** sysconf() query equivalent to _POSIX2_C_BIND. */
#define _SC_2_C_BIND 0x000d
/** sysconf() query equivalent to _POSIX2_C_DEV. */
#define _SC_2_C_DEV 0x000e
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_C_VERSION 0x000f
/** sysconf() query equivalent to _POSIX2_CHAR_TERM. */
#define _SC_2_CHAR_TERM 0x0010
/** sysconf() query equivalent to _POSIX2_FORT_DEV. */
#define _SC_2_FORT_DEV 0x0011
/** sysconf() query equivalent to _POSIX2_FORT_RUN. */
#define _SC_2_FORT_RUN 0x0012
/** sysconf() query equivalent to _POSIX2_LOCALEDEF. */
#define _SC_2_LOCALEDEF 0x0013
/** sysconf() query equivalent to _POSIX2_SW_DEV. */
#define _SC_2_SW_DEV 0x0014
/** sysconf() query equivalent to _POSIX2_UPE. */
#define _SC_2_UPE 0x0015
/** sysconf() query equivalent to _POSIX2_VERSION. */
#define _SC_2_VERSION 0x0016
/** sysconf() query equivalent to _POSIX_JOB_CONTROL. */
#define _SC_JOB_CONTROL 0x0017
/** sysconf() query equivalent to _POSIX_SAVED_IDS. */
#define _SC_SAVED_IDS 0x0018
/** sysconf() query equivalent to _POSIX_VERSION. */
#define _SC_VERSION 0x0019
/** sysconf() query equivalent to _POSIX_RE_DUP_MAX. */
#define _SC_RE_DUP_MAX 0x001a
/** sysconf() query equivalent to FOPEN_MAX. */
#define _SC_STREAM_MAX 0x001b
/** sysconf() query equivalent to _POSIX_TZNAME_MAX. */
#define _SC_TZNAME_MAX 0x001c
/** sysconf() query equivalent to _XOPEN_CRYPT. */
#define _SC_XOPEN_CRYPT 0x001d
/** sysconf() query equivalent to _XOPEN_ENH_I18N. */
#define _SC_XOPEN_ENH_I18N 0x001e
/** sysconf() query equivalent to _XOPEN_SHM. */
#define _SC_XOPEN_SHM 0x001f
/** sysconf() query equivalent to _XOPEN_VERSION. */
#define _SC_XOPEN_VERSION 0x0020
/** Obsolescent in POSIX.1-2008. */
#define _SC_XOPEN_XCU_VERSION 0x0021
/** sysconf() query equivalent to _XOPEN_REALTIME. */
#define _SC_XOPEN_REALTIME 0x0022
/** sysconf() query equivalent to _XOPEN_REALTIME_THREADS. */
#define _SC_XOPEN_REALTIME_THREADS 0x0023
/** sysconf() query equivalent to _XOPEN_LEGACY. */
#define _SC_XOPEN_LEGACY 0x0024
/** sysconf() query for the maximum number of atexit() handlers. Unlimited on Android. */
#define _SC_ATEXIT_MAX 0x0025
/** sysconf() query equivalent to IOV_MAX. */
#define _SC_IOV_MAX 0x0026
/** Same as _SC_IOV_MAX. */
#define _SC_UIO_MAXIOV _SC_IOV_MAX
/** Same as _SC_PAGE_SIZE. */
#define _SC_PAGESIZE 0x0027
/** sysconf() query equivalent to getpagesize(). */
#define _SC_PAGE_SIZE 0x0028
/** sysconf() query equivalent to _XOPEN_UNIX. */
#define _SC_XOPEN_UNIX 0x0029
/** Obsolescent in POSIX.1-2008. */
#define _SC_XBS5_ILP32_OFF32 0x002a
/** Obsolescent in POSIX.1-2008. */
#define _SC_XBS5_ILP32_OFFBIG 0x002b
/** Obsolescent in POSIX.1-2008. */
#define _SC_XBS5_LP64_OFF64 0x002c
/** Obsolescent in POSIX.1-2008. */
#define _SC_XBS5_LPBIG_OFFBIG 0x002d
/** sysconf() query equivalent to _POSIX_AIO_LISTIO_MAX. */
#define _SC_AIO_LISTIO_MAX 0x002e
/** sysconf() query equivalent to _POSIX_AIO_MAX. */
#define _SC_AIO_MAX 0x002f
/** Unimplemented on Android. */
#define _SC_AIO_PRIO_DELTA_MAX  0x0030
/** sysconf() query equivalent to _POSIX_DELAYTIMER_MAX. */
#define _SC_DELAYTIMER_MAX 0x0031
/** sysconf() query equivalent to _POSIX_MQ_OPEN_MAX. */
#define _SC_MQ_OPEN_MAX 0x0032
/** sysconf() query equivalent to _POSIX_MQ_PRIO_MAX. */
#define _SC_MQ_PRIO_MAX 0x0033
/** sysconf() query equivalent to RTSIG_MAX. Constant on Android. */
#define _SC_RTSIG_MAX 0x0034
/** sysconf() query equivalent to _POSIX_SEM_NSEMS_MAX. Constant on Android. */
#define _SC_SEM_NSEMS_MAX 0x0035
/** sysconf() query equivalent to SEM_VALUE_MAX. Constant on Android. */
#define _SC_SEM_VALUE_MAX 0x0036
/** sysconf() query equivalent to _POSIX_SIGQUEUE_MAX. */
#define _SC_SIGQUEUE_MAX 0x0037
/** sysconf() query equivalent to _POSIX_TIMER_MAX. */
#define _SC_TIMER_MAX 0x0038
/** sysconf() query equivalent to _POSIX_ASYNCHRONOUS_IO. */
#define _SC_ASYNCHRONOUS_IO 0x0039
/** sysconf() query equivalent to _POSIX_FSYNC. */
#define _SC_FSYNC 0x003a
/** sysconf() query equivalent to _POSIX_MAPPED_FILES. */
#define _SC_MAPPED_FILES 0x003b
/** sysconf() query equivalent to _POSIX_MEMLOCK. */
#define _SC_MEMLOCK 0x003c
/** sysconf() query equivalent to _POSIX_MEMLOCK_RANGE. */
#define _SC_MEMLOCK_RANGE 0x003d
/** sysconf() query equivalent to _POSIX_MEMORY_PROTECTION. */
#define _SC_MEMORY_PROTECTION 0x003e
/** sysconf() query equivalent to _POSIX_MESSAGE_PASSING. */
#define _SC_MESSAGE_PASSING 0x003f
/** sysconf() query equivalent to _POSIX_PRIORITIZED_IO. */
#define _SC_PRIORITIZED_IO 0x0040
/** sysconf() query equivalent to _POSIX_PRIORITY_SCHEDULING. */
#define _SC_PRIORITY_SCHEDULING 0x0041
/** sysconf() query equivalent to _POSIX_REALTIME_SIGNALS. */
#define _SC_REALTIME_SIGNALS 0x0042
/** sysconf() query equivalent to _POSIX_SEMAPHORES. */
#define _SC_SEMAPHORES 0x0043
/** sysconf() query equivalent to _POSIX_SHARED_MEMORY_OBJECTS. */
#define _SC_SHARED_MEMORY_OBJECTS 0x0044
/** sysconf() query equivalent to _POSIX_SYNCHRONIZED_IO. */
#define _SC_SYNCHRONIZED_IO 0x0045
/** sysconf() query equivalent to _POSIX_TIMERS. */
#define _SC_TIMERS 0x0046
/** sysconf() query for an initial size for getgrgid_r() and getgrnam_r() buffers. */
#define _SC_GETGR_R_SIZE_MAX 0x0047
/** sysconf() query for an initial size for getpwuid_r() and getpwnam_r() buffers. */
#define _SC_GETPW_R_SIZE_MAX 0x0048
/** sysconf() query equivalent to LOGIN_NAME_MAX. */
#define _SC_LOGIN_NAME_MAX 0x0049
/** sysconf() query equivalent to PTHREAD_DESTRUCTOR_ITERATIONS. */
#define _SC_THREAD_DESTRUCTOR_ITERATIONS 0x004a
/** sysconf() query equivalent to PTHREAD_KEYS_MAX. */
#define _SC_THREAD_KEYS_MAX 0x004b
/** sysconf() query equivalent to PTHREAD_STACK_MIN. */
#define _SC_THREAD_STACK_MIN 0x004c
/** sysconf() query for a maximum number of threads. Unlimited on Android. */
#define _SC_THREAD_THREADS_MAX 0x004d
/** sysconf() query equivalent to TTY_NAME_MAX. */
#define _SC_TTY_NAME_MAX 0x004e
/** sysconf() query equivalent to _POSIX_THREADS. */
#define _SC_THREADS 0x004f
/** sysconf() query equivalent to _POSIX_THREAD_ATTR_STACKADDR. */
#define _SC_THREAD_ATTR_STACKADDR 0x0050
/** sysconf() query equivalent to _POSIX_THREAD_ATTR_STACKSIZE. */
#define _SC_THREAD_ATTR_STACKSIZE 0x0051
/** sysconf() query equivalent to _POSIX_THREAD_PRIORITY_SCHEDULING. */
#define _SC_THREAD_PRIORITY_SCHEDULING 0x0052
/** sysconf() query equivalent to _POSIX_THREAD_PRIO_INHERIT. */
#define _SC_THREAD_PRIO_INHERIT 0x0053
/** sysconf() query equivalent to _POSIX_THREAD_PRIO_PROTECT. */
#define _SC_THREAD_PRIO_PROTECT 0x0054
/** sysconf() query equivalent to _POSIX_THREAD_SAFE_FUNCTIONS. */
#define _SC_THREAD_SAFE_FUNCTIONS 0x0055
/** sysconf() query equivalent to get_nprocs_conf(). */
#define _SC_NPROCESSORS_CONF 0x0060
/** sysconf() query equivalent to get_nprocs(). */
#define _SC_NPROCESSORS_ONLN 0x0061
/** sysconf() query equivalent to get_phys_pages(). */
#define _SC_PHYS_PAGES 0x0062
/** sysconf() query equivalent to get_avphys_pages(). */
#define _SC_AVPHYS_PAGES 0x0063
/** sysconf() query equivalent to _POSIX_MONOTONIC_CLOCK. */
#define _SC_MONOTONIC_CLOCK 0x0064
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS 0x0065
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS_ACCOUNTING 0x0066
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS_CHECKPOINT 0x0067
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS_LOCATE 0x0068
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS_MESSAGE 0x0069
/** Obsolescent in POSIX.1-2008. */
#define _SC_2_PBS_TRACK 0x006a
/** sysconf() query equivalent to _POSIX_ADVISORY_INFO. */
#define _SC_ADVISORY_INFO 0x006b
/** sysconf() query equivalent to _POSIX_BARRIERS. */
#define _SC_BARRIERS 0x006c
/** sysconf() query equivalent to _POSIX_CLOCK_SELECTION. */
#define _SC_CLOCK_SELECTION 0x006d
/** sysconf() query equivalent to _POSIX_CPUTIME. */
#define _SC_CPUTIME 0x006e
/** sysconf() query equivalent to _POSIX_HOST_NAME_MAX. */
#define _SC_HOST_NAME_MAX 0x006f
/** sysconf() query equivalent to _POSIX_IPV6. */
#define _SC_IPV6 0x0070
/** sysconf() query equivalent to _POSIX_RAW_SOCKETS. */
#define _SC_RAW_SOCKETS 0x0071
/** sysconf() query equivalent to _POSIX_READER_WRITER_LOCKS. */
#define _SC_READER_WRITER_LOCKS 0x0072
/** sysconf() query equivalent to _POSIX_REGEXP. */
#define _SC_REGEXP 0x0073
/** sysconf() query equivalent to _POSIX_SHELL. */
#define _SC_SHELL 0x0074
/** sysconf() query equivalent to _POSIX_SPAWN. */
#define _SC_SPAWN 0x0075
/** sysconf() query equivalent to _POSIX_SPIN_LOCKS. */
#define _SC_SPIN_LOCKS 0x0076
/** sysconf() query equivalent to _POSIX_SPORADIC_SERVER. */
#define _SC_SPORADIC_SERVER 0x0077
/** sysconf() query equivalent to _POSIX_SS_REPL_MAX. */
#define _SC_SS_REPL_MAX 0x0078
/** sysconf() query equivalent to _POSIX_SYMLOOP_MAX. */
#define _SC_SYMLOOP_MAX 0x0079
/** sysconf() query equivalent to _POSIX_THREAD_CPUTIME. */
#define _SC_THREAD_CPUTIME 0x007a
/** sysconf() query equivalent to _POSIX_THREAD_PROCESS_SHARED. */
#define _SC_THREAD_PROCESS_SHARED 0x007b
/** sysconf() query equivalent to _POSIX_THREAD_ROBUST_PRIO_INHERIT. */
#define _SC_THREAD_ROBUST_PRIO_INHERIT 0x007c
/** sysconf() query equivalent to _POSIX_THREAD_ROBUST_PRIO_PROTECT. */
#define _SC_THREAD_ROBUST_PRIO_PROTECT 0x007d
/** sysconf() query equivalent to _POSIX_THREAD_SPORADIC_SERVER. */
#define _SC_THREAD_SPORADIC_SERVER 0x007e
/** sysconf() query equivalent to _POSIX_TIMEOUTS. */
#define _SC_TIMEOUTS 0x007f
/** Unimplemented. */
#define _SC_TRACE 0x0080
/** Unimplemented. */
#define _SC_TRACE_EVENT_FILTER 0x0081
/** Unimplemented. */
#define _SC_TRACE_EVENT_NAME_MAX 0x0082
/** Unimplemented. */
#define _SC_TRACE_INHERIT 0x0083
/** Unimplemented. */
#define _SC_TRACE_LOG 0x0084
/** Unimplemented. */
#define _SC_TRACE_NAME_MAX 0x0085
/** Unimplemented. */
#define _SC_TRACE_SYS_MAX 0x0086
/** Unimplemented. */
#define _SC_TRACE_USER_EVENT_MAX 0x0087
/** sysconf() query equivalent to _POSIX_TYPED_MEMORY_OBJECTS. */
#define _SC_TYPED_MEMORY_OBJECTS 0x0088
/** sysconf() query equivalent to _POSIX_V7_ILP32_OFF32. */
#define _SC_V7_ILP32_OFF32 0x0089
/** sysconf() query equivalent to _POSIX_V7_ILP32_OFFBIG. */
#define _SC_V7_ILP32_OFFBIG 0x008a
/** sysconf() query equivalent to _POSIX_V7_ILP64_OFF64. */
#define _SC_V7_LP64_OFF64 0x008b
/** sysconf() query equivalent to _POSIX_V7_ILP64_OFFBIG. */
#define _SC_V7_LPBIG_OFFBIG 0x008c
/** Unimplemented. */
#define _SC_XOPEN_STREAMS 0x008d
/** Meaningless in Android, unsupported in every other libc (but defined by POSIX). */
#define _SC_XOPEN_UUCP 0x008e
/** sysconf() query for the L1 instruction cache size. Not available on all architectures. */
#define _SC_LEVEL1_ICACHE_SIZE 0x008f
/** sysconf() query for the L1 instruction cache associativity. Not available on all architectures. */
#define _SC_LEVEL1_ICACHE_ASSOC 0x0090
/** sysconf() query for the L1 instruction cache line size. Not available on all architectures. */
#define _SC_LEVEL1_ICACHE_LINESIZE 0x0091
/** sysconf() query for the L1 data cache size. Not available on all architectures. */
#define _SC_LEVEL1_DCACHE_SIZE 0x0092
/** sysconf() query for the L1 data cache associativity. Not available on all architectures. */
#define _SC_LEVEL1_DCACHE_ASSOC 0x0093
/** sysconf() query for the L1 data cache line size. Not available on all architectures. */
#define _SC_LEVEL1_DCACHE_LINESIZE 0x0094
/** sysconf() query for the L2 cache size. Not available on all architectures. */
#define _SC_LEVEL2_CACHE_SIZE 0x0095
/** sysconf() query for the L2 cache associativity. Not available on all architectures. */
#define _SC_LEVEL2_CACHE_ASSOC 0x0096
/** sysconf() query for the L2 cache line size. Not available on all architectures. */
#define _SC_LEVEL2_CACHE_LINESIZE 0x0097
/** sysconf() query for the L3 cache size. Not available on all architectures. */
#define _SC_LEVEL3_CACHE_SIZE 0x0098
/** sysconf() query for the L3 cache associativity. Not available on all architectures. */
#define _SC_LEVEL3_CACHE_ASSOC 0x0099
/** sysconf() query for the L3 cache line size. Not available on all architectures. */
#define _SC_LEVEL3_CACHE_LINESIZE 0x009a
/** sysconf() query for the L4 cache size. Not available on all architectures. */
#define _SC_LEVEL4_CACHE_SIZE 0x009b
/** sysconf() query for the L4 cache associativity. Not available on all architectures. */
#define _SC_LEVEL4_CACHE_ASSOC 0x009c
/** sysconf() query for the L4 cache line size. Not available on all architectures. */
#define _SC_LEVEL4_CACHE_LINESIZE 0x009d

__BEGIN_DECLS

/**
 * [sysconf(3)](https://man7.org/linux/man-pages/man3/sysconf.3.html)
 * gets system configuration at runtime, corresponding to the given
 * `_SC_` constant. See the man page for details on how to interpret
 * the results.
 *
 * For `_SC_` constants where an equivalent is given, it's cheaper on Android
 * to go straight to that function call --- sysconf() is just a multiplexer.
 * This may not be true on other systems, and other systems may not support the
 * direct function, so sysconf() can be useful for portability, though despite
 * POSIX's best efforts, the exact set of constants that return useful results
 * will also vary by system.
 */
long sysconf(int __name);

__END_DECLS
```