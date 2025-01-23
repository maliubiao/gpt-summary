Response:
Let's break down the thought process to answer the request about `string.handroid.h`.

**1. Understanding the Context:**

The first step is to understand the file's location and purpose. It's in `bionic/libc/include/bits/fortify/`, specifically for `string.h`, and within the `fortify` directory. This immediately signals that the file is related to security and buffer overflow protection in string manipulation functions. The "handroid" suffix likely indicates Android-specific modifications or enhancements.

**2. Initial Code Scan and Keyword Recognition:**

A quick scan of the code reveals several key elements:

* `#ifndef _STRING_H`: This confirms it's a header file designed to be included by `string.h`.
* `#error "Never include this file directly..."`:  This is crucial!  It means this file isn't meant for direct inclusion by developers.
* `__memchr_chk`, `__memrchr_chk`, `__stpncpy_chk2`, `__strncpy_chk2`, `__strlcpy_chk`, `__strlcat_chk`: The `_chk` suffix strongly suggests these are "checked" versions of standard C string functions. The `2` suffix on `stpncpy` and `strncpy` hints at different argument handling or versions.
* `#if __BIONIC_AVAILABILITY_GUARD(23)` and `#if defined(__BIONIC_FORTIFY)`: These preprocessor directives indicate conditional compilation based on Android API levels and whether the "fortify" feature is enabled.
* `__memrchr_real`: The `_real` suffix suggests this is the un-fortified, "real" implementation.
* `__BIONIC_FORTIFY_INLINE`: This macro is used extensively, indicating these functions are intended to be inlined for performance.
* `__builtin___memcpy_chk`, `__builtin___memmove_chk`, etc.: These are calls to compiler built-in functions, which are often optimized or have special handling.
* `__pass_object_size`, `__pass_object_size0`, `__bos`, `__bos0`:  These are clearly related to tracking buffer sizes, a key aspect of buffer overflow protection.
* `__clang_error_if`, `__clang_warning_if`: These are Clang-specific attributes used for static analysis and compile-time error/warning generation.
* `__call_bypassing_fortify`:  This indicates a way to call the original, un-fortified function.
* `extern __always_inline __inline__ __attribute__((gnu_inline)) size_t strlen(const char* _Nonnull s)`: This is a fortified inline version of `strlen`.

**3. Deducing Functionality (Core Logic):**

Based on the keywords and structure, the core functionality emerges:

* **Buffer Overflow Protection:** The primary goal is to prevent buffer overflows in common string manipulation functions.
* **Checked Versions:** The `_chk` functions likely perform runtime checks to ensure operations don't exceed buffer boundaries.
* **Conditional Compilation:**  Fortification is enabled or disabled based on build configurations and API levels.
* **Inlining for Performance:**  Fortified checks are often inlined to minimize the performance overhead of the checks.
* **Compiler Assistance:** Clang attributes are used to leverage static analysis for compile-time error detection.
* **Fallback to Real Implementations:** When fortification isn't strictly necessary (e.g., when buffer sizes are known at compile time), the code might bypass the checks or call the original functions.

**4. Answering Specific Questions:**

Now, address each part of the request systematically:

* **功能 (Functions):** List the fortified versions of the standard `libc` string functions.
* **与 Android 功能的关系 (Relationship with Android Features):** Explain that this is a security feature of Android, protecting against vulnerabilities. Give an example of how an overflow could be exploited.
* **详细解释 libc 函数的功能实现 (Detailed Explanation of libc Function Implementations):** For each function, explain the core functionality (e.g., `memcpy` copies memory) and then detail how the fortified version adds checks using the `__bos` (buffer object size) mechanism. Explain the `_chk` suffix and the compiler built-ins.
* **涉及 dynamic linker 的功能 (Dynamic Linker Functionality):**  This is where careful thought is needed. The file *itself* doesn't directly interact with the dynamic linker. However, the *libc* where these functions reside *is* linked dynamically. Explain the concept of shared libraries (`.so`), the linking process, and provide a simplified example of `.so` layout. Explain that when a program calls a fortified function, it's calling the version within `libc.so`. Mention PLT/GOT as an optimization the linker might employ.
* **逻辑推理 (Logical Reasoning):** Provide simple examples of how the fortified functions would behave with valid and invalid inputs, illustrating the buffer overflow protection.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Give examples of typical buffer overflow scenarios that these fortified functions are designed to catch.
* **说明 Android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK Reaches Here):**  Explain the path from Java/Kotlin code in the framework, down to native code via JNI, and how the NDK allows direct use of `libc` functions.
* **给出 frida hook 示例调试这些步骤 (Frida Hook Example):** Provide a basic Frida script to intercept calls to a fortified function, demonstrating how to observe the arguments and return value.

**5. Refinement and Language:**

Finally, review the entire answer, ensuring clarity, accuracy, and proper use of Chinese. Pay attention to technical terms and explanations, making them accessible. Use formatting (like bullet points and code blocks) to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file implements the standard string functions."  **Correction:**  "No, it *fortifies* the standard string functions. It's not a full implementation."
* **Initial thought:** "The dynamic linker is heavily involved in this specific file." **Correction:** "While `libc` is dynamically linked, this *specific* header file primarily deals with compile-time and runtime checks. The dynamic linker's role is more about making `libc` available to the application."
* **Ensuring accurate technical details:** Double-check the meaning of `__pass_object_size`, `__bos`, and the workings of compiler built-ins.

By following this systematic approach, breaking down the problem, and understanding the context and keywords, a comprehensive and accurate answer can be constructed.
这是一个定义了Bionic C库中字符串操作函数的强化 (fortified) 版本的头文件。它的主要目的是通过在编译时和运行时添加额外的安全检查，来防止常见的缓冲区溢出漏洞。

**功能列表:**

该文件定义或声明了以下函数的强化版本：

* **`__memchr_chk` 和 `__memrchr_chk`:**  分别是 `memchr` 和 `memrchr` 的带有大小检查的版本，用于在内存块中查找指定字符。
* **`__stpncpy_chk2`:**  `stpncpy` 的带有更详细大小检查的版本，用于将一个字符串复制到另一个字符串，最多复制指定数量的字符，并返回指向目标字符串末尾的指针。
* **`__strncpy_chk2`:**  `strncpy` 的带有更详细大小检查的版本，用于将一个字符串复制到另一个字符串，最多复制指定数量的字符。
* **`__strlcpy_chk`:**  `strlcpy` 的带有大小检查的版本，用于将一个字符串复制到另一个字符串，并保证目标字符串以空字符结尾。
* **`__strlcat_chk`:**  `strlcat` 的带有大小检查的版本，用于将一个字符串追加到另一个字符串的末尾，并保证目标字符串以空字符结尾。
* **重定义的标准 C 库字符串函数 (带有 `__BIONIC_FORTIFY_INLINE` 宏):**
    * `memcpy`: 内存复制。
    * `memmove`: 内存移动（允许源和目标区域重叠）。
    * `mempcpy` (如果定义了 `__USE_GNU` 且 Android API >= 30): 内存复制，并返回指向目标区域末尾的指针。
    * `stpcpy`: 字符串复制，并返回指向目标字符串末尾的指针。
    * `strcpy`: 字符串复制。
    * `strcat`: 字符串拼接。
    * `strncat`: 限制长度的字符串拼接。
    * `memset`: 将内存块设置为指定的值。
    * `memchr` (如果 Android API >= 23 且启用了运行时检查): 在内存块中查找指定字符。
    * `memrchr` (如果 Android API >= 23 且启用了运行时检查): 在内存块中反向查找指定字符。
    * `stpncpy` (如果启用了运行时检查): 限制长度的字符串复制，并返回指向目标字符串末尾的指针。
    * `strncpy` (如果启用了运行时检查): 限制长度的字符串复制。
    * `strlcpy`: 限制目标大小的字符串复制。
    * `strlcat`: 限制目标大小的字符串拼接。
    * `strlen` (如果启用了运行时检查): 计算字符串的长度。
    * `strchr`: 在字符串中查找指定字符。
    * `strrchr`: 在字符串中反向查找指定字符。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 安全特性的重要组成部分。Android 作为一个广泛使用的移动操作系统，需要高度关注安全性。缓冲区溢出是常见的安全漏洞，攻击者可以利用这些漏洞执行恶意代码或导致程序崩溃。

**例子:**

假设一个 Android 应用需要将用户输入的用户名复制到一个固定大小的缓冲区中：

```c
char username_buffer[32];
strcpy(username_buffer, user_input); // 潜在的缓冲区溢出风险
```

如果 `user_input` 的长度超过 31 个字符，`strcpy` 会导致缓冲区溢出，覆盖 `username_buffer` 之后的内存区域。

通过使用强化版本的 `strcpy` (即该文件中定义的版本)，Bionic 可以在运行时检查目标缓冲区的大小，并在发生溢出时阻止操作，从而避免安全问题。

**详细解释每一个 libc 函数的功能是如何实现的:**

该文件本身并不是直接实现这些 libc 函数，而是定义了它们的强化版本。这些强化版本通常通过以下方式工作：

1. **大小检查 (`_chk` 后缀):** 带有 `_chk` 后缀的函数（如 `__strncpy_chk2`）会接收额外的参数，用于指定目标缓冲区的大小。在执行复制操作之前，它们会检查源字符串的长度是否超过目标缓冲区的大小。如果超过，则会触发错误处理（通常是中止程序）。

2. **内联和编译器内置函数:**  对于没有 `_chk` 后缀的函数，该文件通常使用 `__BIONIC_FORTIFY_INLINE` 宏定义了内联函数。这些内联函数会调用编译器提供的内置函数（例如 `__builtin___memcpy_chk`）。这些内置函数在编译时或运行时进行大小检查。

3. **`__pass_object_size` 和 `__bos` 宏:**  这些宏用于获取目标缓冲区的大小信息。`__pass_object_size`  通常用于声明函数参数时，指示编译器传递缓冲区的大小。`__bos` 宏则用于在函数内部获取该大小。

**例如，`strcpy` 的强化版本可能如下工作:**

```c
__BIONIC_FORTIFY_INLINE
char* _Nonnull strcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src) {
    // ... 其他代码 ...
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___strcpy_chk(dst, src, __bos(dst)); // 调用带检查的内置函数
#else
    return __builtin_strcpy(dst, src); // 调用标准的内置函数 (无额外检查)
#endif
    // ... 其他代码 ...
}
```

在这个例子中，`__pass_object_size` 让编译器知道 `dst` 参数的大小信息。 `__bos(dst)` 在运行时获取这个大小。`__builtin___strcpy_chk` 是一个编译器提供的内置函数，它会使用这个大小信息来检查是否会发生缓冲区溢出。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及动态链接器的功能。它定义的是 C 库中的函数。然而，这些强化版本的函数最终会被编译到 `libc.so` (Bionic C 库的共享对象文件) 中。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:
        memcpy (强化版本)
        strcpy (强化版本)
        // ... 其他函数实现 ...
    .rodata:
        // ... 只读数据 ...
    .data:
        // ... 全局变量 ...
    .bss:
        // ... 未初始化的全局变量 ...
    .dynamic:
        // ... 动态链接信息 ...
    .symtab:
        memcpy  (指向 .text 中的 memcpy 实现)
        strcpy  (指向 .text 中的 strcpy 实现)
        // ... 其他符号 ...
    .strtab:
        "memcpy"
        "strcpy"
        // ... 其他字符串 ...
```

**链接的处理过程:**

1. **编译时:** 当开发者使用 NDK 或 Android SDK 编译包含字符串操作的代码时，编译器会识别到对 `strcpy` 等函数的调用。

2. **链接时:**  链接器 (通常是 `lld` 在 Android 上) 会查找这些符号的定义。对于 Android 应用，大部分标准 C 库函数的定义都在 `libc.so` 中。链接器会将应用的可执行文件或共享库与 `libc.so` 链接起来。

3. **运行时:** 当应用加载时，Android 的动态链接器 (`linker64` 或 `linker`) 会将 `libc.so` 加载到进程的内存空间中。

4. **符号解析:**  当应用调用 `strcpy` 时，动态链接器会根据应用的导入表（Import Table）和 `libc.so` 的符号表（Symbol Table）来解析符号 `strcpy` 的地址，并跳转到 `libc.so` 中 `strcpy` 强化版本的实现。

**假设输入与输出 (逻辑推理):**

**假设 `strcpy` 的强化版本被调用:**

* **假设输入:**
    * `dst`: 指向一个大小为 10 字节的缓冲区。
    * `src`: 指向一个内容为 "hello" (5 字节 + 1 空字符) 的字符串。
* **输出:** "hello" 被成功复制到 `dst` 缓冲区。

* **假设输入 (潜在错误):**
    * `dst`: 指向一个大小为 10 字节的缓冲区。
    * `src`: 指向一个内容为 "thisisaverylongstring" (超过 10 字节) 的字符串。
* **输出:**  强化版本的 `strcpy` 检测到缓冲区溢出，程序可能会中止执行，并可能输出错误日志。具体的行为取决于 Bionic 的错误处理机制。

**用户或者编程常见的使用错误:**

1. **不检查缓冲区大小:** 这是最常见的错误。程序员可能会假设目标缓冲区足够大，而没有进行显式的长度检查。

   ```c
   char buffer[10];
   const char* input = get_user_input(); // 用户输入可能很长
   strcpy(buffer, input); // 如果 input 很长，就会溢出
   ```

2. **`strncpy` 的误用:**  `strncpy` 不保证目标字符串以空字符结尾。如果源字符串的长度大于或等于指定的 `n`，目标字符串将不会以空字符结尾，这可能会导致后续的字符串操作出现问题。

   ```c
   char buffer[10];
   const char* input = "longstring";
   strncpy(buffer, input, sizeof(buffer)); // buffer 没有以空字符结尾
   printf("%s\n", buffer); // 可能读取到 buffer 之外的内存
   ```

3. **`strcat` 的滥用:**  `strcat` 会从目标字符串的末尾开始追加，但如果没有正确计算目标缓冲区的剩余空间，很容易导致溢出。

   ```c
   char buffer[20] = "hello";
   const char* suffix = "world! this is a long suffix";
   strcat(buffer, suffix); // 可能溢出
   ```

**Android framework or ndk 是如何一步步的到达这里:**

1. **Android Framework (Java/Kotlin):**  Android Framework 通常使用 Java 或 Kotlin 编写。在需要执行底层操作时，Framework 会通过 Java Native Interface (JNI) 调用 Native 代码 (C/C++)。

2. **NDK (Native Development Kit):**  NDK 允许开发者使用 C 和 C++ 编写 Android 应用的一部分。通过 NDK，开发者可以直接调用 Bionic C 库提供的函数。

3. **JNI 调用:** 当 Framework 需要执行一个需要使用 C 库字符串操作的 native 方法时，会发生以下过程：
   * Java/Kotlin 代码调用一个声明为 `native` 的方法。
   * Android 运行时环境 (ART) 会查找并执行与该 native 方法关联的 C/C++ 函数。
   * 这个 C/C++ 函数可能会调用 `strcpy`, `memcpy` 等标准 C 库函数。
   * 由于启用了 fortify，实际调用的是该文件中定义的强化版本。

**Frida hook 示例调试这些步骤:**

你可以使用 Frida 来 hook 这些强化版本的函数，以观察它们的行为和参数。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[*] 找不到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), {
    onEnter: function(args) {
        console.log("[*] strcpy called");
        console.log("[*] Destination: " + args[0]);
        console.log("[*] Source: " + Memory.readUtf8String(args[1]));
        console.log("[*] Destination buffer size (需要进一步确定如何获取): "); // 获取缓冲区大小可能需要更复杂的方法
    },
    onLeave: function(retval) {
        console.log("[*] strcpy returned: " + retval);
    }
});

// Hook 强化版本的 __strcpy_chk (可能需要根据 Bionic 版本调整符号名)
Interceptor.attach(Module.findExportByName("libc.so", "__strcpy_chk"), {
    onEnter: function(args) {
        console.log("[*] __strcpy_chk called");
        console.log("[*] Destination: " + args[0]);
        console.log("[*] Source: " + Memory.readUtf8String(args[1]));
        console.log("[*] Size: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("[*] __strcpy_chk returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到通过 USB 连接的 Android 设备上的指定应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), ...)`:**  Hook `libc.so` 中的 `strcpy` 函数。`onEnter` 函数在 `strcpy` 被调用时执行，可以打印参数信息。
3. **`Interceptor.attach(Module.findExportByName("libc.so", "__strcpy_chk"), ...)`:** Hook 强化版本的 `strcpy` 函数（名称可能略有不同，需要根据具体的 Bionic 版本确定）。
4. **`Memory.readUtf8String(args[1])`:** 读取 `strcpy` 的源字符串参数。
5. **`args[2]` (在 `__strcpy_chk` 中):**  强化版本的函数通常会将目标缓冲区的大小作为参数传递。

**注意:**

* 你可能需要 root 权限的设备才能 hook 目标应用。
* 查找强化版本函数的确切名称可能需要一些实验，因为它可能因 Android 版本和 Bionic 的具体实现而异。可以使用 `frida-trace` 工具来帮助查找这些符号。
* 获取目标缓冲区的确切大小可能需要更复杂的 Frida 脚本，例如分析调用栈或使用 `Memory.readUsize()` 读取大小信息（如果大小信息在附近）。

通过使用 Frida，你可以动态地观察这些强化版本的字符串函数在 Android 系统中的行为，验证它们是否如预期地进行了安全检查。

### 提示词
```
这是目录为bionic/libc/include/bits/fortify/string.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _STRING_H
#error "Never include this file directly; instead, include <string.h>"
#endif


#if __BIONIC_AVAILABILITY_GUARD(23)
void* _Nullable __memchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
void* _Nullable __memrchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

char* _Nonnull __stpncpy_chk2(char* _Nonnull, const char* _Nonnull, size_t, size_t, size_t);
char* _Nonnull __strncpy_chk2(char* _Nonnull, const char* _Nonnull, size_t, size_t, size_t);
size_t __strlcpy_chk(char* _Nonnull, const char* _Nonnull, size_t, size_t);
size_t __strlcat_chk(char* _Nonnull, const char* _Nonnull, size_t, size_t);

#if defined(__BIONIC_FORTIFY)
void* _Nullable __memrchr_real(const void* _Nonnull, int, size_t) __RENAME(memrchr);

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
void* _Nonnull memcpy(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t copy_amount)
        __diagnose_as_builtin(__builtin_memcpy, 1, 2, 3)
        __overloadable {
    return __builtin___memcpy_chk(dst, src, copy_amount, __bos0(dst));
}

/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
void* _Nonnull memmove(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t len)
        __diagnose_as_builtin(__builtin_memmove, 1, 2, 3)
        __overloadable {
    return __builtin___memmove_chk(dst, src, len, __bos0(dst));
}
#endif

#if defined(__USE_GNU)
#if __ANDROID_API__ >= 30
__BIONIC_FORTIFY_INLINE
void* _Nonnull mempcpy(void* _Nonnull const dst __pass_object_size0, const void* _Nonnull src, size_t copy_amount)
        __diagnose_as_builtin(__builtin_mempcpy, 1, 2, 3)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos0(dst), copy_amount),
                         "'mempcpy' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos_dst = __bos0(dst);
    if (!__bos_trivially_ge(bos_dst, copy_amount)) {
        return __builtin___mempcpy_chk(dst, src, copy_amount, bos_dst);
    }
#endif
    return __builtin_mempcpy(dst, src, copy_amount);
}
#endif /* __ANDROID_API__ >= 30 */
#endif /* __USE_GNU */

__BIONIC_FORTIFY_INLINE
char* _Nonnull stpcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src)
        __overloadable
        __clang_error_if(__bos_unevaluated_le(__bos(dst), __builtin_strlen(src)),
                         "'stpcpy' called with string bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___stpcpy_chk(dst, src, __bos(dst));
#else
    return __builtin_stpcpy(dst, src);
#endif
}

__BIONIC_FORTIFY_INLINE
char* _Nonnull strcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src)
        __diagnose_as_builtin(__builtin_strcpy, 1, 2)
        __overloadable
        __clang_error_if(__bos_unevaluated_le(__bos(dst), __builtin_strlen(src)),
                         "'strcpy' called with string bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___strcpy_chk(dst, src, __bos(dst));
#else
    return __builtin_strcpy(dst, src);
#endif
}

__BIONIC_FORTIFY_INLINE
char* _Nonnull strcat(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src)
        __overloadable
        __clang_error_if(__bos_unevaluated_le(__bos(dst), __builtin_strlen(src)),
                         "'strcat' called with string bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___strcat_chk(dst, src, __bos(dst));
#else
    return __builtin_strcat(dst, src);
#endif
}

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
char* _Nonnull strncat(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src, size_t n)
       __diagnose_as_builtin(__builtin_strncat, 1, 2, 3)
       __overloadable {
    return __builtin___strncat_chk(dst, src, n, __bos(dst));
}
#endif

/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
void* _Nonnull memset(void* _Nonnull const s __pass_object_size0, int c, size_t n) __overloadable
        __diagnose_as_builtin(__builtin_memset, 1, 2, 3)
        /* If you're a user who wants this warning to go away: use `(&memset)(foo, bar, baz)`. */
        __clang_warning_if(c && !n, "'memset' will set 0 bytes; maybe the arguments got flipped?") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __builtin___memset_chk(s, c, n, __bos0(s));
#else
    return __builtin_memset(s, c, n);
#endif
}

#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
__BIONIC_FORTIFY_INLINE
void* _Nullable memchr(const void* _Nonnull const s __pass_object_size, int c, size_t n) __overloadable {
    size_t bos = __bos(s);

    if (__bos_trivially_ge(bos, n)) {
        return __builtin_memchr(s, c, n);
    }

    return __memchr_chk(s, c, n, bos);
}

__BIONIC_FORTIFY_INLINE
void* _Nullable __memrchr_fortify(const void* _Nonnull const __pass_object_size s, int c, size_t n) __overloadable {
    size_t bos = __bos(s);

    if (__bos_trivially_ge(bos, n)) {
        return __memrchr_real(s, c, n);
    }

    return __memrchr_chk(s, c, n, bos);
}
#endif

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
char* _Nonnull stpncpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull const src __pass_object_size, size_t n)
        __diagnose_as_builtin(__builtin_stpncpy, 1, 2, 3)
        __overloadable {
    size_t bos_dst = __bos(dst);
    size_t bos_src = __bos(src);

    /* Ignore dst size checks; they're handled in strncpy_chk */
    if (bos_src == __BIONIC_FORTIFY_UNKNOWN_SIZE) {
        return __builtin___stpncpy_chk(dst, src, n, bos_dst);
    }

    return __stpncpy_chk2(dst, src, n, bos_dst, bos_src);
}

/* No diag -- clang diagnoses misuses of this on its own.  */
__BIONIC_FORTIFY_INLINE
char* _Nonnull strncpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull const src __pass_object_size, size_t n)
        __diagnose_as_builtin(__builtin_strncpy, 1, 2, 3)
        __overloadable {
    size_t bos_dst = __bos(dst);
    size_t bos_src = __bos(src);

    /* Ignore dst size checks; they're handled in strncpy_chk */
    if (bos_src == __BIONIC_FORTIFY_UNKNOWN_SIZE) {
        return __builtin___strncpy_chk(dst, src, n, bos_dst);
    }

    return __strncpy_chk2(dst, src, n, bos_dst, bos_src);
}
#endif

__BIONIC_FORTIFY_INLINE
size_t strlcpy(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src, size_t size)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos(dst), size),
                         "'strlcpy' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __strlcpy_chk(dst, src, size, __bos(dst));
#else
    return __call_bypassing_fortify(strlcpy)(dst, src, size);
#endif
}

__BIONIC_FORTIFY_INLINE
size_t strlcat(char* _Nonnull const dst __pass_object_size, const char* _Nonnull src, size_t size)
        __overloadable
        __clang_error_if(__bos_unevaluated_lt(__bos(dst), size),
                         "'strlcat' called with size bigger than buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    return __strlcat_chk(dst, src, size, __bos(dst));
#else
    return __call_bypassing_fortify(strlcat)(dst, src, size);
#endif
}

#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
/*
 * Clang, when parsing C, can fold strlen to a constant without LLVM's help.
 * This doesn't apply to overloads of strlen, so write this differently. We
 * can't use `__pass_object_size0` here, but that's fine: it doesn't help much
 * on __always_inline functions.
 */
extern __always_inline __inline__ __attribute__((gnu_inline)) size_t strlen(const char* _Nonnull s) {
    return __strlen_chk(s, __bos0(s));
}
#endif

__BIONIC_FORTIFY_INLINE
char* _Nullable strchr(const char* _Nonnull const s __pass_object_size, int c) __overloadable {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(s);

    if (bos != __BIONIC_FORTIFY_UNKNOWN_SIZE) {
        return __strchr_chk(s, c, bos);
    }
#endif
    return __builtin_strchr(s, c);
}

__BIONIC_FORTIFY_INLINE
char* _Nullable strrchr(const char* _Nonnull const s __pass_object_size, int c) __overloadable {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(s);

    if (bos != __BIONIC_FORTIFY_UNKNOWN_SIZE) {
        return __strrchr_chk(s, c, bos);
    }
#endif
    return __builtin_strrchr(s, c);
}

#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
#if defined(__cplusplus)
extern "C++" {
__BIONIC_FORTIFY_INLINE
void* _Nullable memrchr(void* _Nonnull const __pass_object_size s, int c, size_t n) {
    return __memrchr_fortify(s, c, n);
}

__BIONIC_FORTIFY_INLINE
const void* _Nullable memrchr(const void* _Nonnull const __pass_object_size s, int c, size_t n) {
    return __memrchr_fortify(s, c, n);
}
}
#else
__BIONIC_FORTIFY_INLINE
void* _Nullable memrchr(const void* _Nonnull const __pass_object_size s, int c, size_t n) __overloadable {
    return __memrchr_fortify(s, c, n);
}
#endif
#endif /* __ANDROID_API__ >= 23 */

#endif /* defined(__BIONIC_FORTIFY) */
```