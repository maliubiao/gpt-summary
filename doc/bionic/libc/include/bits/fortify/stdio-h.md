Response:
Let's break down the thought process for analyzing this `stdio.handroid` file.

**1. Initial Understanding and Context:**

The prompt clearly states this is a source file within Android's Bionic library, specifically related to `stdio` and `fortify`. The filename `stdio.handroid` hints at Android-specific modifications or enhancements to standard `stdio` functions. The copyright notice confirms it's part of the Android Open Source Project.

**2. Identifying the Core Theme: Buffer Overflow Protection:**

The presence of `__fgets_chk`, `__fread_chk`, `__fwrite_chk`, `__BIONIC_FORTIFY`, `__bos`, `__pass_object_size`, `__builtin___vsnprintf_chk`, and the various `__clang_error_if` statements immediately signals that the primary purpose of this file is to provide *compile-time* and *runtime* buffer overflow protection for standard C `stdio` functions. The "fortify" in the path strongly reinforces this.

**3. Analyzing the Individual Components:**

* **Include Guard (`#ifndef _STDIO_H_`):** This is standard practice to prevent multiple inclusions of the header file, causing compilation errors. The error message clarifies its intended usage: include `<stdio.h>` instead.

* **Function Declarations (`__fgets_chk`, `__fread_chk`, `__fwrite_chk`):** These declarations introduce "checked" versions of common `stdio` functions (`fgets`, `fread`, `fwrite`). The `_chk` suffix is a strong indicator of added security checks. The `__INTRODUCED_IN(24)` suggests these were added in Android API level 24 (Nougat). The `_Nullable` and `_Nonnull` annotations relate to static analysis and null safety.

* **`__BIONIC_AVAILABILITY_GUARD(24)`:** This conditional compilation ensures that `__fread_chk` and `__fwrite_chk` are only defined for API level 24 and above, reflecting Android's versioning system.

* **`__BIONIC_FORTIFY` and `__BIONIC_NO_STDIO_FORTIFY`:**  These macros control whether the fortification mechanisms are enabled. This allows for different build configurations.

* **`vsnprintf` and `vsprintf` (within `#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED`):** These are inline functions that wrap the compiler built-in checked versions (`__builtin___vsnprintf_chk`, `__builtin___vsprintf_chk`). They take `__pass_object_size dest` as an argument, which is crucial for buffer size checking. The `__diagnose_as_builtin` attributes link these functions to compiler-level diagnostics.

* **`sprintf` (with `__bos_unevaluated_lt`):** This version of `sprintf` uses a compile-time check (`__bos_unevaluated_lt`) to see if the format string's length *itself* exceeds the destination buffer. This is a powerful compile-time error detection.

* **`sprintf`, `snprintf` (within `#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED`):** These versions use `__builtin___vsprintf_chk` and `__builtin___vsnprintf_chk` respectively, similar to `vsnprintf` and `vsprintf`. They use variable arguments (`...`) and `va_list` for processing format strings.

* **`__bos_trivially_ge_mul` macro:** This macro defines a safe way to compare the buffer object size (`bos_val`) with the product of `size` and `count`, specifically handling potential multiplication overflows using `__unsafe_check_mul_overflow`.

* **`fread` and `fwrite`:** These are inline functions that implement *both* compile-time and runtime checks.
    * **Compile-time checks:** `__clang_error_if` detects potential multiplication overflows and if the calculated size is definitely too large for the buffer.
    * **Runtime checks (within `#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED`):** They use `__bos_trivially_ge_mul` to perform a runtime size check. If the check fails, they call the "checked" versions (`__fread_chk`, `__fwrite_chk`). Otherwise, they call the original, un-checked `fread`/`fwrite` via `__call_bypassing_fortify`.

* **`fgets`:** Similar to `fread` and `fwrite`, it has compile-time checks for negative size and size exceeding the buffer, and runtime checks using `__bos_dynamic_check_impl_and` before potentially calling `__fgets_chk`.

* **`__call_bypassing_fortify`:**  This is likely a macro or inline function that resolves to the original, un-fortified versions of the `stdio` functions. This is crucial for performance when the fortify checks are unnecessary or have already passed.

**4. Answering the Specific Questions:**

Now that the functionality is understood, addressing the prompt's questions becomes straightforward:

* **Functionality:** List the guarded `stdio` functions and their core purpose (buffer overflow protection).
* **Android Relevance:** Explain that Bionic is Android's libc, so these fortifications are directly relevant to Android's security and stability. Give examples of buffer overflows being a common security vulnerability.
* **Libc Function Implementation:** Explain that these are *inline wrappers*. The real implementation is in the compiler built-ins (`__builtin___vsnprintf_chk`, etc.) or in the underlying libc implementation of `fread`, `fwrite`, `fgets`. The "chk" functions are likely implemented in separate source files within Bionic.
* **Dynamic Linker:**  The file *itself* doesn't directly involve the dynamic linker. However, *using* these fortified functions within an Android app does involve the dynamic linker. Explain the basic SO layout and linking process. Emphasize that the dynamic linker resolves the fortified function calls to the Bionic library at runtime.
* **Logic Reasoning:**  Provide simple examples for `fread`, `fwrite`, and `fgets` demonstrating the buffer overflow checks (both compile-time and runtime).
* **Common Errors:**  Give examples of how developers might cause buffer overflows with these functions.
* **Android Framework/NDK Flow:**  Describe how a call from Java (via JNI) or native code eventually leads to these fortified `stdio` functions in Bionic.
* **Frida Hooking:** Show examples of how to use Frida to intercept calls to both the fortified and un-fortified versions of the functions.

**5. Structuring the Response:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level overview and then delve into specifics. Use code blocks for the Frida examples and SO layout.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `_chk` functions are implemented directly in this file.
* **Correction:**  Realized they are likely declared here and implemented elsewhere within Bionic, as this file is a header.
* **Initial thought:**  Focus heavily on the low-level details of the `__builtin` functions.
* **Correction:**  Keep the explanation focused on the purpose and usage of the fortified functions within the context of Bionic. Briefly mention the compiler built-ins but don't get lost in their implementation details.
* **Initial thought:** Overlook the compile-time checks.
* **Correction:** Recognize the importance of the `__clang_error_if` statements and explain how they contribute to early error detection.

By following this structured thought process, breaking down the code into smaller pieces, and connecting the individual components to the overall goal of buffer overflow protection, a comprehensive and accurate analysis of the `stdio.handroid` file can be achieved.
这是一个定义在 `bionic/libc/include/bits/fortify/stdio.handroid` 的 C 源代码文件，属于 Android 的 Bionic C 库。它的主要目的是为标准 C 库的 `stdio.h` 中的一些函数提供 **编译时和运行时的安全检查 (fortification)**，以防止缓冲区溢出等安全漏洞。这个文件本身并不是实现这些 `stdio` 函数，而是定义了一些内联函数和宏，用于在编译和运行时插入检查代码。

**功能列举:**

1. **提供强化版本的 `fgets` 函数:**  定义了 `fgets` 的强化版本，名为 `fgets`，它在运行时检查目标缓冲区的大小，防止写入超出缓冲区。
2. **提供强化版本的 `fread` 函数:** 定义了 `fread` 的强化版本，名为 `fread`，它在编译时和运行时检查读取的数据量是否会超过目标缓冲区的大小。
3. **提供强化版本的 `fwrite` 函数:** 定义了 `fwrite` 的强化版本，名为 `fwrite`，它在编译时和运行时检查写入的数据量是否会超过源缓冲区的大小。
4. **提供强化版本的 `sprintf` 和 `snprintf` 函数:** 定义了 `sprintf` 和 `snprintf` 的强化版本，它们在编译时和运行时检查格式化后的字符串是否会超出目标缓冲区的大小。
5. **定义用于缓冲区大小检查的宏和内联函数:**  例如 `__bos` (Buffer Object Size) 用于获取缓冲区的大小，以及一些用于进行大小比较和溢出检查的宏（如 `__bos_trivially_ge_mul`）。
6. **使用 Clang 的编译时检查功能:**  利用 `__clang_error_if` 在编译时检测潜在的缓冲区溢出风险。
7. **使用 Bionic 特有的宏和属性:** 例如 `__BIONIC_FORTIFY`，`__INTRODUCED_IN`，`__pass_object_size` 等，用于控制强化功能的开启、标记 API 引入版本和传递缓冲区大小信息。

**与 Android 功能的关系及举例:**

Bionic 是 Android 系统的核心 C 库，所有 Android 应用（包括使用 Java/Kotlin 开发的和使用 C/C++ NDK 开发的）在底层都会使用到 Bionic 提供的 C 标准库函数。`stdio.handroid` 中定义的强化版本函数，直接增强了 Android 系统的安全性。

**举例说明:**

* **防止恶意应用读取或写入不属于它的内存:**  如果一个应用尝试使用 `fread` 读取超出它分配的缓冲区的数据，强化版本的 `fread` 会在运行时检测到这个错误，并可能终止程序，防止敏感信息泄露或程序崩溃。
* **防止格式化字符串漏洞:**  `sprintf` 的强化版本可以检测格式化字符串是否会导致写入超出目标缓冲区，避免恶意用户利用格式化字符串漏洞执行任意代码。

**libc 函数的实现细节:**

这个文件本身 **不直接实现** 这些 `stdio` 函数的功能。它定义的是 **内联包装器 (inline wrappers)**，这些包装器在调用实际的 `stdio` 函数之前或之后插入安全检查代码。

* **`__fgets_chk`，`__fread_chk`，`__fwrite_chk`:** 这些带有 `_chk` 后缀的函数很可能是在 Bionic 库的其他源文件中实现的，它们包含了具体的运行时检查逻辑。这些函数会在运行时获取目标缓冲区的大小，并与尝试写入的数据量进行比较，如果超出则会报告错误或终止程序。
* **`sprintf`，`snprintf`，`vsprintf`，`vsnprintf` 的强化版本:** 这些内联函数使用了 Clang 提供的内置函数，例如 `__builtin___sprintf_chk`，`__builtin___vsnprintf_chk` 等。这些内置函数由编译器提供，它们会在编译时或运行时执行缓冲区大小检查。`__bos(dest)` 用于获取编译器记录的 `dest` 缓冲区的大小。
* **`fread`，`fwrite`，`fgets` 的强化版本:**  这些内联函数会根据编译配置和 Android API 版本，决定是否调用 `_chk` 版本的函数进行运行时检查。 `__call_bypassing_fortify` 宏很可能用于在不需要强化检查时直接调用原始的 `stdio` 函数，以避免额外的性能开销。

**涉及 dynamic linker 的功能:**

这个文件本身 **不直接涉及** dynamic linker 的功能。但是，当一个 Android 应用使用这些强化版本的 `stdio` 函数时，dynamic linker 在运行时会负责将应用的代码链接到 Bionic 库中对应的函数实现。

**SO 布局样本:**

```
# 假设一个使用了 printf 的简单 native 代码库 (libmylib.so)

.dynamic:  # 动态链接信息
    NEEDED      libc.so  # 依赖 libc.so
    ...

.plt:       # 程序链接表 (Procedure Linkage Table)
    printf@plt:
        jmp *GOT[printf_offset]

.got:       # 全局偏移量表 (Global Offset Table)
    printf_offset:  # 初始值为 dynamic linker 的解析器地址

.text:      # 代码段
    my_function:
        mov     r0, format_string
        bl      printf@plt  # 调用 printf
        ...

.rodata:   # 只读数据段
    format_string: .asciz "Hello, world!\n"
```

**链接的处理过程:**

1. **加载时:** 当 `libmylib.so` 被加载到内存时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会解析其 `.dynamic` 段，发现它依赖 `libc.so`。
2. **查找依赖:** dynamic linker 会在系统预定义的一些路径中查找 `libc.so`。
3. **符号解析:** 对于 `libmylib.so` 中调用的 `printf` 函数，dynamic linker 会在 `libc.so` 的符号表中查找 `printf` 的地址。
4. **GOT 重写:** 找到 `printf` 的地址后，dynamic linker 会将 `libmylib.so` 的 `.got` 段中 `printf_offset` 的值更新为 `libc.so` 中 `printf` 函数的实际地址。
5. **首次调用:** 当 `libmylib.so` 的 `my_function` 首次调用 `printf` 时，会跳转到 `.plt` 段的 `printf@plt`，该指令会间接地跳转到 `.got` 段中 `printf_offset` 指向的地址，此时 dynamic linker 的解析器会介入，找到 `printf` 的实际地址并更新 `printf_offset`。
6. **后续调用:**  后续对 `printf` 的调用将直接跳转到 `libc.so` 中 `printf` 的实际地址。

**对于使用了强化的 `printf` 的情况:**

如果 `libmylib.so` 间接地调用了 `stdio.handroid` 中定义的强化版本的 `printf` (例如，通过 `stdio.h` 头文件)，dynamic linker 的过程类似，只是最终解析到的地址是 Bionic 库中强化版本 `printf` 的实现地址。

**逻辑推理，假设输入与输出:**

**示例: `fread`**

**假设输入:**

* `buf`: 指向一个大小为 10 字节的缓冲区。
* `size`: 1
* `count`: 15
* `stream`: 指向一个已打开的文件。

**逻辑推理:**

强化版本的 `fread` 会检查 `size * count` (1 * 15 = 15) 是否大于缓冲区 `buf` 的大小 (10)。

**输出:**

由于 `15 > 10`，`fread` 会检测到潜在的缓冲区溢出。在启用了运行时检查的情况下，`__fread_chk` 函数会被调用，该函数可能会返回一个错误值（例如，读取的字节数小于请求的字节数）或者直接终止程序。在编译时，如果使用了 Clang 的静态分析，可能会发出警告。

**涉及用户或编程常见的使用错误:**

1. **`sprintf` 或 `snprintf` 的目标缓冲区太小:**
   ```c
   char buf[10];
   sprintf(buf, "This string is longer than 10 bytes"); // 缓冲区溢出
   ```
   强化版本会在运行时或编译时检测到这个问题。

2. **`fread` 或 `fwrite` 读取或写入超过缓冲区大小的数据:**
   ```c
   char buf[10];
   FILE *fp = fopen("data.txt", "rb");
   fread(buf, 1, 20, fp); // 尝试读取 20 字节到 10 字节的缓冲区
   ```
   强化版本会检测到缓冲区溢出。

3. **`fgets` 的 `size` 参数大于目标缓冲区的大小:**
   ```c
   char buf[10];
   fgets(buf, 20, stdin); // 请求读取最多 19 个字符到 10 字节的缓冲区
   ```
   强化版本会检测到这个问题。

**Android Framework 或 NDK 如何到达这里:**

**Android Framework (Java/Kotlin):**

1. **应用层调用:**  Android 应用（Java/Kotlin 代码）可能需要进行文件读写或字符串格式化操作。
2. **Framework API 调用:** 应用会调用 Android Framework 提供的相关 API (例如，`java.io.FileInputStream`, `java.lang.String.format`)。
3. **JNI 调用:**  Framework 的底层实现通常会调用 Native 代码（C/C++）来执行这些操作。例如，`FileInputStream` 的底层实现会调用 Bionic 提供的文件操作函数。
4. **Bionic Libc 调用:**  Native 代码最终会调用 Bionic 库中的 `stdio` 函数，如果启用了强化功能，则会调用 `stdio.handroid` 中定义的强化版本。

**NDK (C/C++):**

1. **NDK 代码调用:** 使用 NDK 开发的应用可以直接调用 Bionic 提供的标准 C 库函数，例如 `fopen`, `fread`, `fwrite`, `sprintf` 等。
2. **Bionic Libc 调用:**  这些调用会直接链接到 Bionic 库中相应的函数实现，如果是强化版本，则会调用 `stdio.handroid` 中定义的强化版本。

**Frida Hook 示例调试这些步骤:**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

session = frida.attach(package_name)
script = session.create_script("""
    // Hook fgets
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    if (fgetsPtr) {
        Interceptor.attach(fgetsPtr, {
            onEnter: function(args) {
                console.log("[fgets] onEnter");
                console.log("  buf: " + args[0]);
                console.log("  size: " + args[1]);
                console.log("  stream: " + args[2]);
            },
            onLeave: function(retval) {
                console.log("[fgets] onLeave");
                console.log("  retval: " + retval);
            }
        });
    } else {
        console.log("[-] fgets not found");
    }

    // Hook fortified fgets (__fgets_chk in Android >= N)
    var fgetsChkPtr = Module.findExportByName("libc.so", "__fgets_chk");
    if (fgetsChkPtr) {
        Interceptor.attach(fgetsChkPtr, {
            onEnter: function(args) {
                console.log("[__fgets_chk] onEnter");
                console.log("  buf: " + args[0]);
                console.log("  size: " + args[1]);
                console.log("  stream: " + args[2]);
                console.log("  buf_size: " + args[3]); // 强化版本会传递缓冲区大小
            },
            onLeave: function(retval) {
                console.log("[__fgets_chk] onLeave");
                console.log("  retval: " + retval);
            }
        });
    } else {
        console.log("[-] __fgets_chk not found");
    }

    // 类似地可以 hook fread, fwrite, sprintf, snprintf 等函数及其强化版本
""");
script.on('message', on_message)
script.load()
sys.stdin.read()
""")
```

**使用说明:**

1. 将上面的 Python 代码保存为 `hook_stdio.py`。
2. 确保你的 Android 设备或模拟器上运行了目标应用（将 `your.app.package.name` 替换为实际的应用包名）。
3. 运行 Frida：`frida -U -f your.app.package.name hook_stdio.py` (如果应用没有运行，使用 `-f` 启动) 或 `frida -U your.app.package.name -l hook_stdio.py` (如果应用已经运行)。
4. 当应用调用 `fgets` 或其强化版本 `__fgets_chk` 时，Frida 会拦截并打印出函数的参数和返回值，你可以观察到缓冲区地址、请求的大小以及实际的缓冲区大小。

**注意:**

* 需要根据 Android 版本来判断是否会调用强化版本的函数（例如，`__fgets_chk` 在 Android N (API 级别 24) 及更高版本中引入）。
* Hook 系统库函数需要 root 权限或使用特定的 Frida 配置。
* 可以使用类似的方法 Hook 其他 `stdio` 函数及其强化版本，例如 `fread`, `fwrite`, `sprintf`, `snprintf` 及其对应的 `_chk` 版本。

通过 Frida Hook，你可以清晰地观察到 Android Framework 或 NDK 代码在底层是如何调用这些强化版本的 `stdio` 函数，以及这些强化检查是如何工作的。

Prompt: 
```
这是目录为bionic/libc/include/bits/fortify/stdio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _STDIO_H_
#error "Never include this file directly; instead, include <stdio.h>"
#endif

char* _Nullable __fgets_chk(char* _Nonnull, int, FILE* _Nonnull, size_t);

#if __BIONIC_AVAILABILITY_GUARD(24)
size_t __fread_chk(void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
size_t __fwrite_chk(const void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


#if defined(__BIONIC_FORTIFY) && !defined(__BIONIC_NO_STDIO_FORTIFY)

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE __printflike(3, 0)
int vsnprintf(char* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size dest, size_t size, const char* _Nonnull format, va_list ap)
        __diagnose_as_builtin(__builtin_vsnprintf, 1, 2, 3, 4)
        __overloadable {
    return __builtin___vsnprintf_chk(dest, size, 0, __bos(dest), format, ap);
}

__BIONIC_FORTIFY_INLINE __printflike(2, 0)
int vsprintf(char* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size dest, const char* _Nonnull format, va_list ap) __overloadable {
    return __builtin___vsprintf_chk(dest, 0, __bos(dest), format, ap);
}
#endif

__BIONIC_ERROR_FUNCTION_VISIBILITY
int sprintf(char* __BIONIC_COMPLICATED_NULLNESS dest, const char* _Nonnull format)
    __overloadable
    __enable_if(__bos_unevaluated_lt(__bos(dest), __builtin_strlen(format)),
                "format string will always overflow destination buffer")
    __errorattr("format string will always overflow destination buffer");

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
__BIONIC_FORTIFY_VARIADIC __printflike(2, 3)
int sprintf(char* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size dest, const char* _Nonnull format, ...) __overloadable {
    va_list va;
    va_start(va, format);
    int result = __builtin___vsprintf_chk(dest, 0, __bos(dest), format, va);
    va_end(va);
    return result;
}

/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_VARIADIC __printflike(3, 4)
int snprintf(char* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size dest, size_t size, const char* _Nonnull format, ...)
        __diagnose_as_builtin(__builtin_snprintf, 1, 2, 3)
        __overloadable {
    va_list va;
    va_start(va, format);
    int result = __builtin___vsnprintf_chk(dest, size, 0, __bos(dest), format, va);
    va_end(va);
    return result;
}
#endif

#define __bos_trivially_ge_mul(bos_val, size, count) \
  __bos_dynamic_check_impl_and(bos_val, >=, (size) * (count), \
                               !__unsafe_check_mul_overflow(size, count))

__BIONIC_FORTIFY_INLINE
size_t fread(void* const _Nonnull __pass_object_size0 buf, size_t size, size_t count, FILE* _Nonnull stream)
        __overloadable
        __clang_error_if(__unsafe_check_mul_overflow(size, count),
                         "in call to 'fread', size * count overflows")
        __clang_error_if(__bos_unevaluated_lt(__bos0(buf), size * count),
                         "in call to 'fread', size * count is too large for the given buffer") {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_mul(bos, size, count)) {
        return __fread_chk(buf, size, count, stream, bos);
    }
#endif
    return __call_bypassing_fortify(fread)(buf, size, count, stream);
}

__BIONIC_FORTIFY_INLINE
size_t fwrite(const void* const _Nonnull __pass_object_size0 buf, size_t size, size_t count, FILE* _Nonnull stream)
        __overloadable
        __clang_error_if(__unsafe_check_mul_overflow(size, count),
                         "in call to 'fwrite', size * count overflows")
        __clang_error_if(__bos_unevaluated_lt(__bos0(buf), size * count),
                         "in call to 'fwrite', size * count is too large for the given buffer") {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_mul(bos, size, count)) {
        return __fwrite_chk(buf, size, count, stream, bos);
    }
#endif
    return __call_bypassing_fortify(fwrite)(buf, size, count, stream);
}
#undef __bos_trivially_ge_mul

__BIONIC_FORTIFY_INLINE
char* _Nullable fgets(char* const _Nonnull __pass_object_size dest, int size, FILE* _Nonnull stream)
        __overloadable
        __clang_error_if(size < 0, "in call to 'fgets', size should not be negative")
        __clang_error_if(__bos_unevaluated_lt(__bos(dest), size),
                         "in call to 'fgets', size is larger than the destination buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(dest);

    if (!__bos_dynamic_check_impl_and(bos, >=, (size_t)size, size >= 0)) {
        return __fgets_chk(dest, size, stream, bos);
    }
#endif
    return __call_bypassing_fortify(fgets)(dest, size, stream);
}

#endif /* defined(__BIONIC_FORTIFY) */

"""

```