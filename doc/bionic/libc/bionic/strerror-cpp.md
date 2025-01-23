Response:
Let's break down the thought process for generating the comprehensive answer about `strerror.cpp`.

**1. Understanding the Request:**

The request asks for a detailed analysis of the `strerror.cpp` file in Android's Bionic library. The key requirements are:

* **Functionality:** What does the code do?
* **Android Relevance:** How does it relate to the Android system?
* **Implementation Details:**  Explain how each function works internally.
* **Dynamic Linking:** Address aspects related to dynamic linking (though this file is primarily about error messages, it's important to consider how Bionic fits in).
* **Logic Inference:**  Provide examples of input and output (where applicable).
* **Common Errors:**  Illustrate typical usage mistakes.
* **Framework/NDK Path:**  Explain how the code is reached from higher levels of Android.
* **Frida Hook:** Demonstrate how to intercept function calls using Frida.
* **Chinese Response:** The entire response needs to be in Chinese.

**2. Initial Code Analysis (Skimming and Identifying Key Components):**

The first step is to read through the code, identifying the main parts:

* **Copyright and License:** Standard boilerplate, not directly relevant to the functionality.
* **Includes:**  Headers like `<string.h>`, `<errno.h>`, `<limits.h>`, `async_safe/log.h`, and Bionic-specific headers provide clues about dependencies and functionality.
* **`__sys_error_descriptions` and `__sys_error_names`:** These are clearly the core data structures, holding the textual representations of error numbers and their symbolic names. The `#include "private/bionic_errdefs.h"` indicates that the actual error definitions are elsewhere.
* **`strerrorname_np`:**  A function to get the *name* of an error (e.g., "EPERM").
* **`__strerror_lookup`:** A helper function to retrieve the *description* of an error.
* **`strerror_r`:** The thread-safe version of `strerror`, taking a buffer as input.
* **`__gnu_strerror_r`:**  A GNU-compatible version of `strerror_r`.
* **`strerror`:** The standard `strerror` function.
* **`__strong_alias(strerror_l, strerror)`:**  Indicates `strerror_l` is an alias for `strerror`.

**3. Deconstructing Function by Function (Detailed Analysis):**

Now, focus on each function and explain its workings:

* **`strerrorname_np`:** Check bounds, return the error name from the `__sys_error_names` array. Handle out-of-bounds cases.
* **`__strerror_lookup`:**  Similar to `strerrorname_np`, but retrieves the description from `__sys_error_descriptions`.
* **`strerror_r`:**  The core logic. Look up the error description. If found, copy it into the provided buffer using `strlcpy` (important for buffer overflow prevention). If not found, format an "Unknown error" message. Check for buffer truncation and return `ERANGE` if needed. Emphasize the thread-safety aspect (using a provided buffer).
* **`__gnu_strerror_r`:**  A simple wrapper around `strerror_r`, primarily for compatibility with GNU libc. Note the difference in how it handles truncation (not setting `errno`).
* **`strerror`:**  The standard function. First, try the fast path (returning a constant string if available). If not, use thread-local storage (`bionic_tls`) to store the error string and call `strerror_r` to populate it. Explain the use of thread-local storage for thread safety without requiring the caller to provide a buffer.

**4. Addressing Android Relevance and Examples:**

Think about how error handling is crucial in Android:

* **System Calls:**  Many system calls return error codes, which are then translated to human-readable messages using `strerror`.
* **Networking:** Errors during network operations are common.
* **File I/O:** Errors related to file access need to be reported.
* **General Programming:**  Developers use `errno` and `strerror` for their own error handling.

Provide concrete examples for each function, demonstrating typical usage scenarios and potential issues.

**5. Dynamic Linking Considerations:**

While `strerror.cpp` itself doesn't directly handle dynamic linking, Bionic as a whole does. Explain the role of the dynamic linker (`linker64` or `linker`) in loading shared libraries and resolving symbols. Illustrate a simple SO layout and the linking process. Emphasize that `strerror` is part of `libc.so`, which is loaded early.

**6. User Errors and Best Practices:**

Highlight common mistakes developers make:

* **Insufficient Buffer Size:**  Not allocating enough space for the error message in `strerror_r`.
* **Ignoring Return Values:**  Not checking the return value of `strerror_r` for `ERANGE`.
* **Misunderstanding Thread Safety:** Incorrectly assuming `strerror` is always thread-safe without understanding the underlying mechanism.

**7. Framework/NDK Path and Frida Hook:**

Trace the execution flow from a high-level Android component (like a Java method that makes a native call) down to the `strerror` function. This involves understanding JNI and how native code interacts with the Android runtime.

Provide a practical Frida script to hook `strerror`, demonstrating how to intercept calls, inspect arguments, and potentially modify behavior.

**8. Structuring the Response (Chinese Translation and Organization):**

Translate the entire analysis into clear and accurate Chinese. Organize the information logically with headings and subheadings to make it easy to read and understand. Use code blocks for code snippets.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the array lookups. **Correction:** Realize the importance of explaining the different `strerror` variants and thread safety.
* **Initial thought:** Briefly mention dynamic linking. **Correction:**  Elaborate on the role of the dynamic linker in the broader context of Bionic.
* **Initial thought:**  Provide simple usage examples. **Correction:**  Include examples that illustrate potential errors and best practices.
* **Initial thought:**  Describe the NDK path vaguely. **Correction:**  Be more specific about the JNI boundary and the role of system calls.

By following these steps and iterating through the analysis, the comprehensive and accurate answer provided in the example can be constructed. The key is to break down the problem into smaller, manageable parts and address each aspect of the request systematically.
好的，让我们深入分析一下 `bionic/libc/bionic/strerror.cpp` 这个文件。

**功能概述**

`strerror.cpp` 文件的核心功能是提供将错误码（通常是 `errno` 的值）转换为人类可读的错误信息字符串的能力。它实现了以下几个与错误处理相关的函数：

* **`strerror(int errnum)`:**  这是最常用的函数，它接受一个错误码 `errnum` 作为参数，并返回指向描述该错误的字符串的指针。这个字符串通常是静态分配的，但也可能使用线程局部存储。
* **`strerror_r(int errnum, char *buf, size_t buflen)`:**  这是一个线程安全的版本，它将错误信息写入到用户提供的缓冲区 `buf` 中，`buflen` 指定了缓冲区的大小。它返回 0 表示成功，返回 `ERANGE` 表示提供的缓冲区太小。
* **`__gnu_strerror_r(int errnum, char *buf, size_t buflen)`:**  这是 `strerror_r` 的 GNU 扩展版本，行为略有不同，特别是当缓冲区不足以容纳错误信息时。
* **`strerrorname_np(int errnum)`:**  这是一个非标准的函数，用于返回错误码的符号名称（例如，`EPERM`、`ENOENT`）。

**与 Android 功能的关系及举例说明**

错误处理是任何操作系统和应用程序的基础组成部分，Android 也不例外。`strerror` 系列函数在 Android 系统中扮演着至关重要的角色，帮助开发者理解系统调用或其他操作失败的原因。

**举例说明:**

1. **系统调用失败:** 当应用程序进行系统调用（例如打开文件 `open()`, 创建进程 `fork()`，发送网络数据 `send()`）失败时，内核会设置全局变量 `errno` 来指示错误类型。应用程序可以通过调用 `strerror(errno)` 来获取关于该错误的描述信息，例如 "Permission denied" (EACCES) 或者 "No such file or directory" (ENOENT)。

   ```c++
   #include <stdio.h>
   #include <fcntl.h>
   #include <errno.h>
   #include <string.h>

   int main() {
       int fd = open("/nonexistent_file", O_RDONLY);
       if (fd == -1) {
           fprintf(stderr, "Error opening file: %s\n", strerror(errno));
           return 1;
       }
       // ...
       return 0;
   }
   ```
   在 Android 设备上运行这段代码，如果 `/nonexistent_file` 不存在，`strerror(errno)` 将会返回类似于 "No such file or directory" 的字符串。

2. **NDK 开发:** 使用 Android NDK 进行原生开发时，开发者可以直接调用这些 C 标准库函数。当 NDK 代码中发生错误时，可以使用 `strerror` 来获取错误描述，方便调试。

3. **Android Framework:**  虽然 Android Framework 主要使用 Java 编写，但在底层，很多操作最终会调用到 Native 层，即 Bionic 提供的函数。Framework 内部可能会间接地使用 `strerror` 来记录错误信息或者向用户展示更友好的错误提示。例如，当应用尝试访问没有权限的资源时，Framework 可能会捕获底层的 `errno` 并使用 `strerror` 生成日志信息。

**libc 函数的实现细节**

现在我们来详细解释每个 libc 函数的实现：

**1. `strerrorname_np(int error_number)`**

* **功能:**  返回给定错误码的符号名称。
* **实现:**
    * 它首先检查 `error_number` 是否在有效范围内（0 到 `__sys_error_names` 数组的大小减 1）。
    * `__sys_error_names` 是一个静态字符指针数组，每个元素存储一个错误码的名称字符串（例如 "EPERM"）。这个数组的内容由 `private/bionic_errdefs.h` 定义的宏展开生成。
    * 如果 `error_number` 有效，则返回 `__sys_error_names[error_number]`，否则返回 `nullptr`。

**2. `__strerror_lookup(int error_number)`**

* **功能:**  一个内部辅助函数，用于查找给定错误码的描述字符串。
* **实现:**
    * 它与 `strerrorname_np` 的实现类似，首先检查 `error_number` 是否在有效范围内。
    * `__sys_error_descriptions` 是另一个静态字符指针数组，每个元素存储一个错误码的描述字符串（例如 "Operation not permitted"）。这个数组的内容也由 `private/bionic_errdefs.h` 定义的宏展开生成。
    * 如果 `error_number` 有效，则返回 `__sys_error_descriptions[error_number]`，否则返回 `nullptr`。

**3. `strerror_r(int error_number, char* buf, size_t buf_len)`**

* **功能:**  线程安全地将错误码转换为错误描述字符串，并存储到用户提供的缓冲区中。
* **实现:**
    * 首先创建一个 `ErrnoRestorer` 对象。这是一个 RAII (Resource Acquisition Is Initialization) 风格的类，用于在函数退出时恢复 `errno` 的值，避免 `strerror_r` 的操作意外修改了 `errno`。
    * 调用内部函数 `__strerror_lookup(error_number)` 获取错误描述字符串。
    * 如果找到对应的描述字符串（`error_name != nullptr`）：
        * 使用 `strlcpy(buf, error_name, buf_len)` 将描述字符串复制到 `buf` 中。`strlcpy` 是一个安全的字符串复制函数，可以防止缓冲区溢出，它总是以 null 字符结尾，并返回要复制的字符串的长度（不包括 null 字符）。
    * 如果没有找到对应的描述字符串：
        * 使用 `async_safe_format_buffer(buf, buf_len, "Unknown error %d", error_number)` 格式化一个 "Unknown error" 消息并存储到 `buf` 中。`async_safe_format_buffer` 是一个异步信号安全的格式化函数，用于在信号处理程序等特殊上下文中安全地格式化字符串。
    * 检查复制的字符串长度 `length` 是否大于或等于缓冲区大小 `buf_len`。如果发生截断，则返回 `ERANGE`，表示缓冲区太小。
    * 否则，返回 0 表示成功。

**4. `__gnu_strerror_r(int error_number, char* buf, size_t buf_len)`**

* **功能:**  `strerror_r` 的 GNU 兼容版本。
* **实现:**
    * 同样创建一个 `ErrnoRestorer` 对象。
    * 直接调用 `strerror_r(error_number, buf, buf_len)` 来执行实际的错误描述获取和复制操作。
    * **关键区别:** GNU 版本的 `strerror_r` 在缓冲区太小时不会设置 `errno` 为 `ERANGE`，而是直接返回指向 `buf` 的指针，即使 `buf` 中的字符串被截断了。Bionic 的 `__gnu_strerror_r` 遵循了这个行为。

**5. `strerror(int error_number)`**

* **功能:**  返回指向描述错误码的字符串的指针。
* **实现:**
    * 首先尝试快速路径：调用 `__strerror_lookup(error_number)` 获取静态分配的错误描述字符串。如果找到了（`result != nullptr`），则直接返回该字符串。这种情况下，不需要额外的内存分配或复制，性能更高。
    * 如果 `__strerror_lookup` 返回 `nullptr`，表示该错误码没有预定义的静态描述字符串。这时，需要使用线程局部存储来保存错误信息：
        * 调用 `__get_bionic_tls()` 获取当前线程的线程局部存储结构 `bionic_tls` 的引用。
        * 从 `bionic_tls` 结构中获取 `strerror_buf` 成员。`strerror_buf` 是一个字符数组，用于存储当前线程的错误描述字符串。
        * 调用 `strerror_r(error_number, result, sizeof(tls.strerror_buf))` 将错误描述信息格式化并复制到 `strerror_buf` 中。
        * 返回指向 `strerror_buf` 的指针。

* **线程安全性:**  `strerror` 通过使用线程局部存储来保证线程安全性。每个线程都有自己的 `strerror_buf`，因此并发调用 `strerror` 不会互相干扰。

* **`__strong_alias(strerror_l, strerror)`:**  这行代码使用了一个编译器指令（通常是 GCC 或 Clang 的扩展），将 `strerror_l` 定义为 `strerror` 的别名。`strerror_l` 是 POSIX 标准中支持本地化错误消息的版本，但在 Bionic 中，它被简单地实现为 `strerror`。

**涉及 dynamic linker 的功能**

`strerror.cpp` 本身的代码主要关注错误码到错误信息的转换，并没有直接涉及 dynamic linker 的具体操作。然而，`strerror` 函数以及它所在的 `libc.so` 库是所有动态链接的 Android 程序的基础。

**so 布局样本:**

假设我们有一个简单的应用程序 `my_app`，它链接了 `libc.so`。`libc.so` 中包含了 `strerror` 函数。

```
/system/bin/linker64 (或 /system/bin/linker)
/system/lib64/libc.so (或 /system/lib/libc.so)
/system/bin/my_app
```

当 `my_app` 启动时，dynamic linker（`linker64` 或 `linker`，取决于设备架构）会执行以下步骤：

1. **加载可执行文件:** 加载 `my_app` 到内存。
2. **解析依赖:** 解析 `my_app` 的 ELF 头，找到其依赖的共享库，其中就包括 `libc.so`。
3. **加载共享库:** 加载 `libc.so` 到内存中的某个地址空间。
4. **符号解析 (Symbol Resolution):**  遍历 `my_app` 中所有未定义的符号（例如 `strerror`），并在其依赖的共享库（`libc.so`）中查找这些符号的定义。
5. **重定位 (Relocation):**  一旦找到符号的定义，dynamic linker 会修改 `my_app` 中对这些符号的引用，使其指向 `libc.so` 中实际的函数地址。

**链接的处理过程:**

当 `my_app` 中的代码调用 `strerror` 时，实际上是跳转到 `libc.so` 中 `strerror` 函数的地址。这个地址是在程序加载时由 dynamic linker 解析和重定位的。

**假设输入与输出 (针对 `strerror` 函数)**

* **假设输入:** `error_number = 2` (对应 `ENOENT`)
* **输出:**  指向字符串 "No such file or directory" 的指针。

* **假设输入:** `error_number = 13` (对应 `EACCES`)
* **输出:** 指向字符串 "Permission denied" 的指针。

* **假设输入:** `error_number = 999` (一个未知的错误码)
* **输出:** 指向字符串 "Unknown error 999" 的指针 (使用线程局部存储)。

**用户或编程常见的使用错误**

1. **`strerror_r` 缓冲区太小:**

   ```c++
   char buf[10];
   int err = EACCES;
   if (strerror_r(err, buf, sizeof(buf)) == ERANGE) {
       fprintf(stderr, "Buffer too small for error message.\n");
   } else {
       printf("Error message: %s\n", buf); // 可能被截断
   }
   ```
   在这个例子中，如果错误消息的长度超过 9 个字符（留一个给 null 终止符），`strerror_r` 会返回 `ERANGE`，并且 `buf` 中的内容可能被截断。正确的做法是检查返回值并使用足够大的缓冲区。

2. **混淆 `strerror` 和 `strerror_r` 的线程安全性:**

   错误地认为 `strerror` 在所有情况下都是线程安全的，可能会导致问题。在多线程环境下，如果多个线程同时调用 `strerror`，并且错误码对应的是动态生成的错误消息（需要使用线程局部存储），则可能会出现数据竞争，尽管 Bionic 的实现已经通过线程局部存储缓解了这个问题。始终推荐在多线程环境中使用 `strerror_r` 并提供自己的缓冲区。

3. **没有正确处理 `strerror_r` 的返回值:**

   开发者可能忘记检查 `strerror_r` 的返回值，没有处理缓冲区太小的情况，导致程序输出截断的错误消息或者产生其他未预期的行为。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java):**
   * 应用程序执行某些操作，例如访问文件、网络请求等，可能会导致底层的系统调用失败。
   * Android Framework 中的 Java 代码（例如在 `FileOutputStream` 或 `Socket` 等类的实现中）会捕获这些失败，并获取对应的 `errno` 值。
   * Framework 可能会将这些 `errno` 值转换为更友好的 Java 异常或错误码。
   * 在某些情况下，为了记录日志或生成错误报告，Framework 可能会调用 Native 层的代码，并在 Native 代码中使用 `strerror(errno)` 获取错误描述。
   * **路径示例:**  `java.io.FileOutputStream.open0()` (native method) -> JNI 调用 -> Bionic 的 `open()` 系统调用封装 -> 内核返回错误码 -> Bionic 的 `open()` 封装返回错误并设置 `errno` -> Framework 的 Native 代码调用 `strerror(errno)`。

2. **NDK 开发 (C/C++):**
   * NDK 开发者可以直接调用 Bionic 提供的 libc 函数，包括 `strerror`。
   * 当 NDK 代码中发生错误（例如系统调用失败），可以通过检查返回值并调用 `strerror(errno)` 或 `strerror_r` 来获取错误描述。
   * **路径示例:**  NDK 代码调用 `open()` -> Bionic 的 `open()` 系统调用封装 -> 内核返回错误码 -> Bionic 的 `open()` 封装返回错误并设置 `errno` -> NDK 代码调用 `strerror(errno)`。

**Frida Hook 示例调试步骤**

我们可以使用 Frida 来 Hook `strerror` 函数，观察其输入和输出，以便调试相关问题。

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const strerror = libc.getExportByName("strerror");

  if (strerror) {
    Interceptor.attach(strerror, {
      onEnter: function (args) {
        const errorNumber = args[0].toInt32();
        console.log("[strerror] Called with error number:", errorNumber);
      },
      onLeave: function (retval) {
        const errorMessage = Memory.readUtf8String(retval);
        console.log("[strerror] Returned message:", errorMessage);
      }
    });
    console.log("[Frida] Hooked strerror");
  } else {
    console.error("[Frida] strerror not found in libc.so");
  }
} else {
  console.log("[Frida] Not running on Android");
}
```

**步骤说明:**

1. **获取 `libc.so` 模块:** 使用 `Process.getModuleByName("libc.so")` 获取 libc 库的句柄。
2. **获取 `strerror` 函数地址:** 使用 `libc.getExportByName("strerror")` 获取 `strerror` 函数的地址。
3. **附加 Interceptor:** 使用 `Interceptor.attach` 拦截对 `strerror` 函数的调用。
4. **`onEnter` 回调:** 在 `strerror` 函数被调用之前执行。我们在这里获取传入的错误码参数 (`args[0]`) 并打印到控制台。
5. **`onLeave` 回调:** 在 `strerror` 函数执行完毕并即将返回时执行。我们在这里读取返回值（指向错误消息字符串的指针）并打印到控制台。
6. **运行 Frida 脚本:**  将此脚本保存为 `.js` 文件，并使用 Frida 连接到 Android 设备上的目标进程。

**调试示例:**

假设你的 Android 应用中有一段代码会因为权限问题导致 `open()` 系统调用失败。当你运行这个应用并使用上述 Frida 脚本时，你可能会在 Frida 控制台中看到类似以下的输出：

```
[Frida] Hooked strerror
[strerror] Called with error number: 13
[strerror] Returned message: Permission denied
```

这表明 `strerror` 函数被调用，传入的错误码是 13 (`EACCES`)，并且返回的错误消息是 "Permission denied"。这可以帮助你确认错误的原因并进行调试。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/strerror.cpp` 的功能、实现以及在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/strerror.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2012 The Android Open Source Project
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

// -std=gnu++XX automatically defines _GNU_SOURCE, which then means that <string.h>
// gives us the GNU variant, which is not what we're defining here.
#undef _GNU_SOURCE

#include <string.h>

#include <errno.h>
#include <limits.h>

#include <async_safe/log.h>

#include "private/ErrnoRestorer.h"

#include <string.h>

#include "bionic/pthread_internal.h"

static const char* __sys_error_descriptions[] = {
#define __BIONIC_ERRDEF(error_number, error_description) [error_number] = error_description,
#include "private/bionic_errdefs.h"
};

static const char* __sys_error_names[] = {
#define __BIONIC_ERRDEF(error_number, error_description) [error_number] = #error_number,
#include "private/bionic_errdefs.h"
};

extern "C" const char* strerrorname_np(int error_number) {
  if (error_number < 0 || error_number >= static_cast<int>(arraysize(__sys_error_names))) {
    return nullptr;
  }
  return __sys_error_names[error_number];
}

static inline const char* __strerror_lookup(int error_number) {
  if (error_number < 0 || error_number >= static_cast<int>(arraysize(__sys_error_descriptions))) {
    return nullptr;
  }
  return __sys_error_descriptions[error_number];
}

int strerror_r(int error_number, char* buf, size_t buf_len) {
  ErrnoRestorer errno_restorer;
  size_t length;

  const char* error_name = __strerror_lookup(error_number);
  if (error_name != nullptr) {
    length = strlcpy(buf, error_name, buf_len);
  } else {
    length = async_safe_format_buffer(buf, buf_len, "Unknown error %d", error_number);
  }
  if (length >= buf_len) {
    return ERANGE;
  }

  return 0;
}

extern "C" char* __gnu_strerror_r(int error_number, char* buf, size_t buf_len) {
  ErrnoRestorer errno_restorer; // The glibc strerror_r doesn't set errno if it truncates...
  strerror_r(error_number, buf, buf_len);
  return buf; // ...and just returns whatever fit.
}

char* strerror(int error_number) {
  // Just return the original constant in the easy cases.
  char* result = const_cast<char*>(__strerror_lookup(error_number));
  if (result != nullptr) {
    return result;
  }

  bionic_tls& tls = __get_bionic_tls();
  result = tls.strerror_buf;
  strerror_r(error_number, result, sizeof(tls.strerror_buf));
  return result;
}
__strong_alias(strerror_l, strerror);
```