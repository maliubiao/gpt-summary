Response:
Let's break down the thought process for analyzing the `ndk_cruft.cpp` file.

**1. Understanding the Context:**

The first step is to understand the file's purpose and location. The prompt clearly states it's `bionic/libc/bionic/ndk_cruft.cpp` and belongs to Android's bionic library. The term "cruft" itself hints at legacy or compatibility-related code. This immediately suggests the file's primary function is likely to maintain backward compatibility with older NDK (Native Development Kit) releases.

**2. Initial Code Scan and Structure Observation:**

A quick scan reveals several key features:

* **Copyright and License:** Standard boilerplate, not directly relevant to functionality but important for understanding its legal status.
* **Includes:**  A wide range of standard C library headers (`ctype.h`, `dirent.h`, `errno.h`, etc.) and some Android-specific ones (`platform/bionic/macros.h`). This indicates the file interacts with various parts of the C library and system calls.
* **`extern "C"` blocks:**  This is a strong indicator of C++ code providing C-compatible interfaces, which is crucial for the NDK's C API.
* **`#if !defined(__LP64__)` block:** This immediately tells us a significant portion of the code is *only* relevant for 32-bit architectures. This reinforces the backward compatibility theme.
* **Function definitions with names prefixed by `__`:** This is a common convention for internal or non-standard functions, further supporting the "cruft" idea.
* **Comments like "TODO: remove this backward compatibility hack" and mentions of specific Android releases (jb-mr1):** These are direct confirmations of the file's purpose.
* **Specific functions related to threading (`pthread_attr_setstackaddr`), memory management (`memswap`, `dlmalloc_usable_size`, `dlmalloc`), time (`strtotimeval`, `ftime`), signals (`bsd_signal`, `sysv_signal`), directory access (`getdents`), and I/O (`fdprintf`, `vfdprintf`, `putw`).** This gives us concrete areas to investigate.
* **Functions related to atomics/futexes (`__futex_wake`, `__futex_wait`):** This hints at low-level synchronization primitives.

**3. Focused Analysis of Individual Functions (Iterative Process):**

For each function, the thought process goes something like this:

* **Identify the function name and signature:** This is the starting point.
* **Read the code and comments:** The comments are often the most direct explanation of *why* a function exists.
* **Determine its purpose:** What problem does it solve? Why is it needed?
* **Relate it to Android/NDK:**  Is it for backward compatibility? Does it expose a system call? Is it used by specific Android components?
* **Explain its implementation (briefly):** A high-level understanding is usually sufficient. No need for deep dives into assembly unless it's absolutely critical.
* **Identify potential usage errors:**  What could go wrong if a developer uses this function?  Are there better alternatives?
* **Consider dynamic linking implications (if relevant):** Does this function interact with shared libraries?
* **Think about tracing/debugging:** How could a developer use tools like Frida to observe this function in action?

**Example: Analyzing `__wait4`:**

1. **Name:** `__wait4`
2. **Code/Comments:** The comment says "TODO: remove this backward compatibility hack (for jb-mr1 strace binaries)." and the implementation simply calls `wait4`.
3. **Purpose:** Backward compatibility for older `strace` binaries built against a specific Android release.
4. **Android/NDK:** Directly related to NDK compatibility. Older NDK-built binaries expected this function.
5. **Implementation:** A simple wrapper around the standard `wait4` system call.
6. **Usage Errors:**  Developers shouldn't use this directly in new code; they should use `wait4`.
7. **Dynamic Linking:**  No specific dynamic linking concerns here; it's a direct system call wrapper.
8. **Frida:**  You could hook this function to see if older binaries are indeed calling it.

**4. Identifying Key Themes:**

As you analyze more functions, recurring themes emerge:

* **Backward Compatibility (the dominant theme):**  Many functions exist solely to maintain compatibility with older NDK versions.
* **Non-Standard Functions:** Several functions are identified as "non-standard" and were included in older Android headers for various reasons (sometimes mistakes).
* **System Call Wrappers:** Some functions directly wrap system calls.
* **Removals from POSIX:** Several functions were removed from POSIX standards, but Android had to keep them for compatibility.

**5. Dynamic Linking Considerations:**

The prompt specifically asks about the dynamic linker. While `ndk_cruft.cpp` doesn't directly implement the dynamic linker, it provides functions that *interact* with it (albeit indirectly). The key here is to understand *why* these compatibility functions matter in a dynamic linking context:

* **Symbol Resolution:** When an older NDK-built shared library is loaded, the dynamic linker needs to find the symbols it references. If a library was built against an older Bionic where `__wait4` existed, the linker needs to find that symbol. `ndk_cruft.cpp` provides it.
* **ABI Stability:**  Maintaining a stable Application Binary Interface (ABI) is crucial for preventing older apps from breaking on newer Android versions. These "cruft" functions help maintain that ABI.

**6. Structuring the Response:**

The final step is to organize the information logically:

* **Overall Function:** Start with a high-level summary of the file's purpose.
* **Categorize Functions:** Group functions by their type (libc functions, dynamic linker related, etc.).
* **Explain Each Function:** Provide a detailed explanation for each function, covering its purpose, implementation, Android relevance, potential errors, etc.
* **Dynamic Linking Details:**  Explain how the file relates to dynamic linking, provide an example SO layout, and describe the linking process.
* **Frida Hook Examples:** Give concrete examples of how to use Frida to observe these functions.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:**  The sheer number of functions can be overwhelming. Focus on understanding the *categories* first, then dive into the details.
* **Ambiguity:** Some comments might be terse. You might need to infer the exact reason for a function's existence based on its name, implementation, and the surrounding code.
* **Dynamic Linking Complexity:**  Dynamic linking is a complex topic. Focus on the core concepts of symbol resolution and ABI stability in the context of this file. Avoid getting bogged down in the low-level details of the linker implementation itself.

By following this structured approach, you can effectively analyze a complex source code file like `ndk_cruft.cpp` and provide a comprehensive explanation of its functionality and significance.
这个 `bionic/libc/bionic/ndk_cruft.cpp` 文件是 Android Bionic 库中的一个特殊文件，它的主要功能是**为了向后兼容旧版本的 Android NDK (Native Development Kit)**。  “cruft” 这个词本身就暗示了它是为了处理一些历史遗留问题或者不再推荐使用但为了兼容性而保留的代码。

下面将详细列举它的功能，并解释其与 Android 功能的关系、实现方式、动态链接处理、常见错误以及如何使用 Frida 进行调试。

**1. 功能列举与 Android 功能的关系举例：**

该文件主要包含以下几种类型的功能：

* **为旧版 NDK 应用提供兼容性支持的函数:** 这些函数可能在旧版本的 Android 系统中存在，但已经从 POSIX 标准中移除，或者在新的 Bionic 库中不再提供或实现方式有所改变。为了保证旧版 NDK 构建的应用在新版本的 Android 系统上仍然能够运行，需要提供这些函数的兼容性实现。

    * **`__isthreaded`:**  这是一个全局变量，在旧版本中可能被 NDK 构建的代码使用来判断是否是多线程环境。现在 Android 系统基本上都是多线程的，所以直接设置为 `1`。
    * **`__page_size` 和 `__page_shift`:**  这两个变量在旧版本中直接暴露出来，但在新版本中应该使用 `getpagesize()` 函数。为了兼容旧代码，这里直接定义了这两个变量。
    * **`__wait4`:**  旧版本的 `strace` 工具可能使用了这个函数，但标准是 `wait4`。这里提供了一个简单的包装。
    * **`__open`:**  这是一个应该永远不会被调用的函数，可能是一些更早期版本的遗留。直接 `abort()` 表明如果被调用就是错误。
    * **`__get_tls`:**  用于获取线程本地存储 (Thread Local Storage)。这是底层机制，但为了兼容性而保留。
    * **`memswap`:**  一个非标准的内存交换函数，在旧版本的 `<string.h>` 中存在。
    * **`pthread_attr_setstackaddr` 和 `pthread_attr_getstackaddr`:**  这两个函数在 POSIX.1-2008 中被移除，但为了 NDK 的 ABI 兼容性而保留。
    * **`strtotimeval`:**  一个非标准的字符串转换为 `timeval` 结构的函数，可能被 `system/core/toolbox` 中的工具使用。
    * **`strntoumax` 和 `strntoimax`:**  非标准的带长度限制的字符串转换为无符号/有符号最大整数的函数，可能在旧版本的 `<inttypes.h>` 中。
    * **`fdprintf` 和 `vfdprintf`:**  在 LP32 (32 位) Android 中使用，对应标准的 `dprintf` 和 `vdprintf`。
    * **`__futex_wake` 和 `__futex_wait`:**  原子操作相关的函数，在旧版本中可能在 `<sys/atomics.h>` 中。
    * **`tkill`:**  向指定线程发送信号，在 POSIX 中没有，可能被 Unity 的 libmono 使用。
    * **`wcswcs`:**  在 POSIX 2008 中被移除，对应 `wcsstr`。
    * **`bsd_signal`:**  在 POSIX 2008 中被移除，对应 `signal`。
    * **`bcopy` 和 `bzero`:**  在 POSIX 2008 中被移除，分别对应 `memmove` 和 `memset`。
    * **`sysv_signal`:**  非 POSIX 标准的信号处理函数。
    * **`getdents`:**  一个 BSD 风格的系统调用，应该使用 `readdir`。
    * **`issetugid`:**  BSD 特有的函数，这里返回 `0`，表明进程没有设置 UID 或 GID。
    * **`wait3`:**  在 POSIX 2004 中被移除，对应 `wait4`。
    * **`getdtablesize`:**  获取文件描述符表的大小，在 POSIX 2004 中被移除。
    * **`__sinit` 和 `__sdidinit`:**  与 BSD stdio 实现相关的细节，现在是空操作。
    * **`timeb` 和 `ftime`:**  在 POSIX 2008 中被移除的时间相关结构体和函数。
    * **`index`:**  在 POSIX 2008 中被移除，对应 `strchr`。
    * **`arc4random_stir` 和 `arc4random_addrandom`:**  BSD 随机数生成器相关的函数。
    * **`dlmalloc_usable_size`:**  旧版本 NDK 可能导出了 `dlmalloc_usable_size`，现在统一使用 `malloc_usable_size`。
    * **`__pthread_gettid`:**  旧版本 App 可能使用了私有 API，现在应该使用 `pthread_gettid_np`。
    * **`dlmalloc`:**  旧版本 Apportable 可能直接使用 `dlmalloc`，这里提供一个兼容层，直接调用 `malloc`。
    * **`__get_thread`:**  用于获取线程内部结构的指针，被一些第三方库（如使用自定义 `pthread_rwlock` 实现的库）使用。
    * **`__set_errno`:**  设置 `errno` 的内部函数。
    * **`dlmalloc_inspect_all` 和 `dlmalloc_trim`:**  如果系统使用 `dlmalloc`，则导出这些函数。
    * **`putw`:**  旧版本 `<stdio.h>` 中的输出 `int` 的函数。

* **内部辅助函数:** 比如 `digitval` 用于辅助 `strntoumax` 等函数进行字符到数字的转换。

**2. libc 函数的功能实现解释：**

这里挑选几个具有代表性的 libc 函数进行解释：

* **`memswap(void* m1, void* m2, size_t n)`:**
    * **功能:**  交换两块内存区域 `m1` 和 `m2` 的内容，交换的字节数为 `n`。
    * **实现:**  它使用一个简单的循环，逐字节地交换两个内存区域的内容。使用一个临时变量 `tmp` 来保存其中一个字节的值，避免数据丢失。
    * **示例:** 如果 `m1` 指向 "abc"，`m2` 指向 "xyz"，`n` 为 3，则执行后 `m1` 指向 "xyz"，`m2` 指向 "abc"。
    * **常见错误:**  `m1` 和 `m2` 指向的内存区域重叠时，结果是未定义的。程序员需要确保这两个区域不重叠，或者使用 `memmove` 代替。

* **`strtotimeval(const char* str, struct timeval* ts)`:**
    * **功能:**  将一个字符串转换为 `struct timeval` 结构，该结构包含秒和微秒。字符串的格式通常是 "<秒数>.<微秒数>"。
    * **实现:**  首先使用 `strtoumax` 解析整数部分的秒数。然后检查是否有小数点，如果有，则解析小数点后的数字作为微秒数。最多读取 6 位小数。
    * **假设输入与输出:**
        * **输入:** `"123.456"`, `ts` 指向一个未初始化的 `timeval` 结构。
        * **输出:** `ts->tv_sec` 为 123，`ts->tv_usec` 为 456000。 返回值是指向小数点后第一个非数字字符的指针。
    * **常见错误:**  输入的字符串格式不正确，例如缺少小数点，或者小数点后有非数字字符。这会导致解析错误。

* **`strntoumax(const char *nptr, char **endptr, int base, size_t n)`:**
    * **功能:**  将一个字符串的一部分转换为无符号的最大整数类型 (`uintmax_t`)。与 `strtoumax` 类似，但多了长度限制 `n`。
    * **实现:**  首先跳过前导空格，然后处理可选的正负号。根据 `base` 的值判断进制（0 表示自动判断，可以是 8, 10 或 16）。如果是 16 进制，允许有 "0x" 或 "0X" 前缀。然后循环遍历字符串，将字符转换为数字，直到遇到非数字字符或达到长度限制 `n`。
    * **假设输入与输出:**
        * **输入:** `"  123abc"`, `endptr` 指向一个未初始化的 `char*`，`base` 为 10，`n` 为 5。
        * **输出:** 返回值 123，`*endptr` 指向 'a' 的地址。
    * **常见错误:**  `base` 的值不在允许的范围内（0 或 2-36）。字符串中包含对于指定进制无效的字符。

**3. 涉及 dynamic linker 的功能：**

`ndk_cruft.cpp` 本身不直接实现 dynamic linker 的功能，但它提供的兼容性函数与 dynamic linker 的工作息息相关。当一个旧版本的 NDK 构建的动态链接库 (SO 文件) 被加载时，dynamic linker 需要解析该库中引用的符号。如果该库引用了 `ndk_cruft.cpp` 中提供的兼容性函数，dynamic linker 必须能够找到这些函数的实现。

**SO 布局样本：**

假设有一个名为 `liblegacy.so` 的旧版 NDK 构建的共享库，它引用了 `__wait4` 函数。其布局可能如下：

```
liblegacy.so:
    .text:  # 代码段
        ...
        call    __wait4  # 调用 __wait4 函数
        ...
    .rodata: # 只读数据段
        ...
    .data:  # 数据段
        ...
    .dynsym: # 动态符号表
        ...
        __wait4 (UND)  # 表明需要从其他库中找到 __wait4 的定义
        ...
    .dynstr: # 动态字符串表
        ...
        __wait4
        ...
    .plt:   # Procedure Linkage Table (过程链接表)
        ...
    .got:   # Global Offset Table (全局偏移表)
        ...
```

**链接的处理过程：**

1. **加载 SO 文件:** 当系统尝试加载 `liblegacy.so` 时，dynamic linker 会被调用。
2. **解析依赖:** Dynamic linker 会解析 `liblegacy.so` 的依赖库。
3. **符号查找:** Dynamic linker 扫描已加载的共享库，查找 `liblegacy.so` 中未定义的符号，例如 `__wait4`。
4. **符号绑定:**  由于 `__wait4` 在 `bionic/libc.so` (即 Bionic 库) 中通过 `ndk_cruft.cpp` 提供，dynamic linker 会将 `liblegacy.so` 中对 `__wait4` 的引用绑定到 `bionic/libc.so` 中的 `__wait4` 实现。
5. **PLT/GOT 条目更新:**  Dynamic linker 会更新 `liblegacy.so` 的 PLT 和 GOT，使得对 `__wait4` 的调用能够跳转到正确的地址。

**假设输入与输出（针对 dynamic linker）：**

* **输入:** 系统尝试加载 `liblegacy.so`，该库依赖于 Bionic 库并引用了 `__wait4`。
* **输出:** `liblegacy.so` 成功加载，其中对 `__wait4` 的调用被正确链接到 Bionic 库中 `ndk_cruft.cpp` 提供的 `__wait4` 实现。

**4. 用户或编程常见的使用错误：**

* **直接使用 `ndk_cruft.cpp` 中的函数:**  普通开发者不应该直接调用这些 `ndk_cruft.cpp` 中的函数。这些函数主要是为了内部兼容性。应该使用标准的 POSIX 函数或者 Android SDK 提供的 API。
    * **错误示例:** 在新的代码中使用 `bcopy` 而不是 `memmove`。
* **假设这些函数是标准或最新的:**  不要假设 `ndk_cruft.cpp` 中的函数是标准或者最佳实践。它们可能性能较差或者存在已知的问题。
* **依赖这些函数的行为不会改变:**  这些兼容性函数的存在是为了向后兼容，但在未来的 Android 版本中可能会被移除或其行为可能会发生变化。不应该过度依赖它们。

**5. Android framework 或 ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

以下是一个简化的说明，描述了 Android framework 或 NDK 构建的应用如何间接到达 `ndk_cruft.cpp` 中的代码：

1. **NDK 应用构建:** 开发者使用旧版本的 NDK 构建了一个使用了 `__wait4` 函数的应用或共享库。
2. **应用安装和启动:** 用户安装并启动该应用。
3. **加载共享库:** 当应用需要使用该共享库时，Android 的动态链接器 `linker` (或 `linker64` for 64-bit) 会负责加载该 SO 文件。
4. **符号解析:**  `linker` 在解析该 SO 文件时，会发现它引用了 `__wait4` 符号。
5. **查找符号定义:** `linker` 会在系统库中查找 `__wait4` 的定义。
6. **找到兼容性实现:**  `linker` 会在 `bionic/libc.so` 中找到 `ndk_cruft.cpp` 提供的 `__wait4` 函数。
7. **链接和执行:** `linker` 将 SO 文件中对 `__wait4` 的调用链接到 `ndk_cruft.cpp` 中的实现，并在运行时执行该代码。

**Frida Hook 示例：**

可以使用 Frida 来 hook `ndk_cruft.cpp` 中的函数，以观察它们是否被调用以及它们的参数和返回值。

```javascript
// Hook __wait4 函数
Interceptor.attach(Module.findExportByName("libc.so", "__wait4"), {
  onEnter: function(args) {
    console.log("__wait4 called");
    console.log("  pid:", args[0]);
    console.log("  status:", args[1]);
    console.log("  options:", args[2]);
    console.log("  rusage:", args[3]);
  },
  onLeave: function(retval) {
    console.log("__wait4 returned:", retval);
  }
});

// Hook strtotimeval 函数
Interceptor.attach(Module.findExportByName("libc.so", "strtotimeval"), {
  onEnter: function(args) {
    console.log("strtotimeval called");
    console.log("  str:", args[0].readCString());
    console.log("  ts:", args[1]);
  },
  onLeave: function(retval) {
    console.log("strtotimeval returned:", retval);
  }
});
```

**使用步骤：**

1. **确保设备已 root 并安装了 Frida Server。**
2. **将上述 JavaScript 代码保存为 `hook_cruft.js`。**
3. **运行目标应用 (使用旧 NDK 构建的或可能调用这些函数的应用)。**
4. **使用 Frida 连接到目标进程并执行 hook 脚本:**

   ```bash
   frida -U -f <package_name> -l hook_cruft.js --no-pause
   ```

   或者，如果目标进程已经在运行：

   ```bash
   frida -U <package_name> -l hook_cruft.js
   ```

通过 Frida hook，你可以观察到旧版本的 NDK 构建的应用是否调用了 `ndk_cruft.cpp` 中提供的兼容性函数，以及它们的调用参数和返回值，从而验证这些兼容性代码是否正在被使用。

总而言之，`bionic/libc/bionic/ndk_cruft.cpp` 文件是 Android Bionic 库中一个至关重要的组成部分，它通过提供一系列兼容性函数，确保了旧版本的 NDK 构建的应用能够在新的 Android 系统上正常运行，体现了 Android 平台对向后兼容性的重视。虽然这些函数是为了解决历史遗留问题，但了解它们的存在和作用对于理解 Android 的发展演变以及处理旧代码的兼容性问题非常有帮助。

Prompt: 
```
这是目录为bionic/libc/bionic/ndk_cruft.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

// This file perpetuates the mistakes of the past.

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

#include "platform/bionic/macros.h"

extern "C" {

// LP64 doesn't need to support any legacy cruft.
#if !defined(__LP64__)

// By the time any NDK-built code is running, there are plenty of threads.
int __isthreaded = 1;

// These were accidentally declared in <unistd.h> because we used to inline
// getpagesize() and __getpageshift(). Needed for backwards compatibility
// with old NDK apps.
unsigned int __page_size = PAGE_SIZE;
unsigned int __page_shift = 12;

// TODO: remove this backward compatibility hack (for jb-mr1 strace binaries).
pid_t __wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  return wait4(pid, status, options, rusage);
}

// TODO: does anything still need this?
int __open() {
  abort();
}

// TODO: does anything still need this?
void** __get_tls() {
#include "platform/bionic/tls.h"
  return __get_tls();
}

// This non-standard function was in our <string.h> for some reason.
void memswap(void* m1, void* m2, size_t n) {
  char* p = reinterpret_cast<char*>(m1);
  char* p_end = p + n;
  char* q = reinterpret_cast<char*>(m2);
  while (p < p_end) {
    char tmp = *p;
    *p = *q;
    *q = tmp;
    p++;
    q++;
  }
}

int pthread_attr_setstackaddr(pthread_attr_t*, void*) {
  // This was removed from POSIX.1-2008, and is not implemented on bionic.
  // Needed for ABI compatibility with the NDK.
  return ENOSYS;
}

int pthread_attr_getstackaddr(const pthread_attr_t* attr, void** stack_addr) {
  // This was removed from POSIX.1-2008.
  // Needed for ABI compatibility with the NDK.
  *stack_addr = (char*)attr->stack_base + attr->stack_size;
  return 0;
}

// Non-standard cruft that should only ever have been in system/core/toolbox.
char* strtotimeval(const char* str, struct timeval* ts) {
  char* s;
  ts->tv_sec = strtoumax(str, &s, 10);

  long fractional_seconds = 0;
  if (*s == '.') {
    s++;
    int count = 0;

    // Read up to 6 digits (microseconds).
    while (*s && isdigit(*s)) {
      if (++count < 7) {
        fractional_seconds = fractional_seconds*10 + (*s - '0');
      }
      s++;
    }

    for (; count < 6; count++) {
      fractional_seconds *= 10;
    }
  }

  ts->tv_usec = fractional_seconds;
  return s;
}

static inline int digitval(int ch) {
  unsigned d;

  d = (unsigned)(ch - '0');
  if (d < 10) return (int)d;

  d = (unsigned)(ch - 'a');
  if (d < 6) return (int)(d+10);

  d = (unsigned)(ch - 'A');
  if (d < 6) return (int)(d+10);

  return -1;
}

// This non-standard function was in our <inttypes.h> for some reason.
uintmax_t strntoumax(const char *nptr, char **endptr, int base, size_t n) {
  const unsigned char*  p   = (const unsigned char *)nptr;
  const unsigned char*  end = p + n;
  int                   minus = 0;
  uintmax_t             v = 0;
  int                   d;

  while (p < end && isspace(*p)) {
    p++;
  }

  if (p < end) {
    char c = p[0];
    if (c == '-' || c == '+') {
      minus = (c == '-');
      p++;
    }
  }

  if (base == 0) {
    if (p+2 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
      p += 2;
      base = 16;
    } else if (p+1 < end && p[0] == '0') {
      p   += 1;
      base = 8;
    } else {
      base = 10;
    }
  } else if (base == 16) {
    if (p+2 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
      p += 2;
    }
  }

  while (p < end && (d = digitval(*p)) >= 0 && d < base) {
    v = v*base + d;
    p += 1;
  }

  if (endptr) {
    *endptr = (char*) p;
  }

  return minus ? -v : v;
}

// This non-standard function was in our <inttypes.h> for some reason.
intmax_t strntoimax(const char* nptr, char** endptr, int base, size_t n) {
  return (intmax_t) strntoumax(nptr, endptr, base, n);
}

// POSIX calls this dprintf, but LP32 Android had fdprintf instead.
int fdprintf(int fd, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int rc = vdprintf(fd, fmt, ap);
  va_end(ap);
  return rc;
}

// POSIX calls this vdprintf, but LP32 Android had fdprintf instead.
int vfdprintf(int fd, const char* fmt, va_list ap) {
  return vdprintf(fd, fmt, ap);
}

#define __futex_wake __real_futex_wake
#define __futex_wait __real_futex_wait
#include "private/bionic_futex.h"
#undef __futex_wake
#undef __futex_wait

// This used to be in <sys/atomics.h>.
int __futex_wake(volatile void* ftx, int count) {
  return __real_futex_wake(ftx, count);
}

// This used to be in <sys/atomics.h>.
int __futex_wait(volatile void* ftx, int value, const struct timespec* timeout) {
  return __real_futex_wait(ftx, value, timeout);
}

// Unity's libmono uses this.
int tkill(pid_t tid, int sig) {
  return syscall(__NR_tkill, tid, sig);
}

// This was removed from POSIX 2008.
wchar_t* wcswcs(wchar_t* haystack, wchar_t* needle) {
  return wcsstr(haystack, needle);
}

// This was removed from POSIX 2008.
sighandler_t bsd_signal(int signum, sighandler_t handler) {
  return signal(signum, handler);
}

// This was removed from POSIX 2008.
#undef bcopy
void bcopy(const void* src, void* dst, size_t n) {
  memmove(dst, src, n);
}

// This was removed from POSIX 2008.
#undef bzero
void bzero(void* dst, size_t n) {
  memset(dst, 0, n);
}

// sysv_signal() was never in POSIX.
extern "C++" sighandler_t _signal(int signum, sighandler_t handler, int flags);
sighandler_t sysv_signal(int signum, sighandler_t handler) {
  return _signal(signum, handler, SA_RESETHAND);
}

// This is a system call that was never in POSIX. Use readdir(3) instead.
int __getdents64(unsigned int, dirent*, unsigned int);
int getdents(unsigned int fd, dirent* dirp, unsigned int count) {
  return __getdents64(fd, dirp, count);
}

// This is a BSDism that we never implemented correctly. Used by Firefox.
int issetugid() {
  return 0;
}

// This was removed from POSIX 2004.
pid_t wait3(int* status, int options, struct rusage* rusage) {
  return wait4(-1, status, options, rusage);
}

// This was removed from POSIX 2004.
int getdtablesize() {
  struct rlimit r;

  if (getrlimit(RLIMIT_NOFILE, &r) < 0) {
    return sysconf(_SC_OPEN_MAX);
  }

  return r.rlim_cur;
}

// A leaked BSD stdio implementation detail that's now a no-op.
void __sinit() {}
int __sdidinit = 1;

// Only used by ftime, which was removed from POSIX 2008.
struct timeb {
  time_t          time;
  unsigned short  millitm;
  short           timezone;
  short           dstflag;
};

// This was removed from POSIX 2008.
int ftime(struct timeb* tb) {
  struct timeval  tv;
  struct timezone tz;

  if (gettimeofday(&tv, &tz) < 0)
    return -1;

  tb->time    = tv.tv_sec;
  tb->millitm = (tv.tv_usec + 500) / 1000;

  if (tb->millitm == 1000) {
    ++tb->time;
    tb->millitm = 0;
  }

  tb->timezone = tz.tz_minuteswest;
  tb->dstflag  = tz.tz_dsttime;

  return 0;
}

// This was removed from POSIX 2008.
char* index(const char* str, int ch) {
  return const_cast<char*>(strchr(str, ch));
}

// This was removed from BSD.
void arc4random_stir(void) {
  // The current implementation stirs itself as needed.
}

// This was removed from BSD.
void arc4random_addrandom(unsigned char*, int) {
  // The current implementation adds randomness as needed.
}

// Old versions of the NDK did not export malloc_usable_size, but did
// export dlmalloc_usable_size. We are moving away from dlmalloc in L
// so make this call malloc_usable_size.
size_t dlmalloc_usable_size(void* ptr) {
  return malloc_usable_size(ptr);
}

// In L we added a public pthread_gettid_np, but some apps were using the private API.
pid_t __pthread_gettid(pthread_t t) {
  return pthread_gettid_np(t);
}

// Older versions of apportable used dlmalloc directly instead of malloc,
// so export this compatibility shim that simply calls malloc.
void* dlmalloc(size_t size) {
  return malloc(size);
}

} // extern "C"

#define __get_thread __real_get_thread
#include "pthread_internal.h"
#undef __get_thread

extern "C" {

// Various third-party apps contain a backport of our pthread_rwlock implementation that uses this.
pthread_internal_t* __get_thread() {
  return __real_get_thread();
}

// This one exists only for the LP32 NDK and is not present anywhere else.
extern long __set_errno_internal(int);
long __set_errno(int n) {
  return __set_errno_internal(n);
}

// Since dlmalloc_inspect_all and dlmalloc_trim are exported for systems
// that use dlmalloc, be consistent and export them everywhere.
void dlmalloc_inspect_all(void (*)(void*, void*, size_t, void*), void*) {
}
int dlmalloc_trim(size_t) {
    return 0;
}

// LP32's <stdio.h> had putw (but not getw).
int putw(int value, FILE* fp) {
    return fwrite(&value, sizeof(value), 1, fp) == 1 ? 0 : EOF;
}

#endif // !defined (__LP64__)

} // extern "C"

"""

```