Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Context:**

The first crucial step is recognizing the file's location and the surrounding comment. It's in `bionic/libc/include/bits/fortify/unistd.handroid`, indicating this is part of Android's C library (`bionic`), specifically dealing with the `unistd.h` header and the "fortify" mechanism. The "handroid" suffix suggests Android-specific augmentations.

**2. Initial Scan for Function Declarations:**

A quick scan reveals function declarations like `__getcwd_chk`, `__pread_chk`, `__pread_real`, etc. The naming convention `__<function>_chk` and `__<function>_real` immediately suggests the "fortify" mechanism. The "chk" versions likely involve extra checks, while the "real" versions are the underlying system calls.

**3. Deciphering the `#ifdef` and Availability Guards:**

The code uses preprocessor directives like `#ifndef _UNISTD_H_`, `#if __BIONIC_AVAILABILITY_GUARD(24)`, and `#if defined(__BIONIC_FORTIFY)`.

*   `#ifndef _UNISTD_H_`: This is a standard header guard, preventing multiple inclusions. The `#error` directive enforces that this file should not be included directly.
*   `__BIONIC_AVAILABILITY_GUARD(N)`: This is an Android-specific macro. It indicates that the enclosed code is available only on Android API level `N` and above. This is crucial for understanding Android's API evolution.
*   `#if defined(__BIONIC_FORTIFY)`: This section is the core of the "fortify" mechanism. It means these definitions and inline functions are only active when the `__BIONIC_FORTIFY` macro is defined during compilation (likely in debug or hardening builds).

**4. Analyzing the "chk" and "real" Functions:**

The pattern of `__<function>_chk` and `__<function>_real` strongly suggests a security mechanism. The "chk" versions likely perform bounds checking to prevent buffer overflows and other security vulnerabilities. The `__RENAME` macro confirms that the "real" versions are just aliases for the standard POSIX functions (e.g., `pread`).

**5. Examining the Fortify Section in Detail:**

This is where the core functionality lies. Key observations:

*   **Macros for Overflow Checks:**  Macros like `__error_if_overflows_ssizet` and `__error_if_overflows_objectsize` are defined. These use `__clang_error_if` to generate compile-time errors if the size arguments could lead to issues.
*   **Inline Wrapper Functions:**  The code defines inline functions like `getcwd`, `pread`, `pwrite`, `read`, `write`, and `readlink`. These are the functions that application code will call.
*   **`__pass_object_size` and `__bos`:**  These annotations and macros are the heart of the fortify mechanism. `__pass_object_size` indicates that the size of the buffer is being passed, and `__bos(buf)` likely retrieves the actual allocated size of the buffer at compile time (or sometimes at runtime).
*   **Runtime Checks:** The `#if __ANDROID_API__ >= ... && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` blocks show that runtime checks are also performed when the API level is sufficient and runtime checks are enabled.
*   **`__bos_trivially_ge_no_overflow`:** This macro appears to optimize the checks. If the size is statically known and within limits, it avoids calling the "chk" function.
*   **`__call_bypassing_fortify`:**  This indicates that in some cases (likely when runtime checks aren't needed or enabled), the code directly calls the underlying "real" function.

**6. Connecting to Android Functionality:**

The file's location within Bionic clearly ties it to Android. The API level guards (`__BIONIC_AVAILABILITY_GUARD`) are direct evidence of its integration with the Android platform. The fortify mechanism itself is a security feature heavily used in Android.

**7. Considering Dynamic Linking (Limited Information):**

While this file itself doesn't directly demonstrate dynamic linking, the fact that it's part of Bionic, the Android C library, implies that these functions will be part of `libc.so`. The user's application will dynamically link against this shared library.

**8. Thinking About Usage and Errors:**

The fortify mechanism is designed to catch common programming errors, especially buffer overflows. This leads to examples of providing incorrect buffer sizes to functions.

**9. Planning the Frida Hook Example:**

To hook these functions, the key is to target the "chk" versions, as these are where the extra checks occur. The example should demonstrate how to intercept the function call and inspect its arguments.

**10. Structuring the Response:**

Finally, organize the information logically, covering the requested aspects: functionality, Android relevance, implementation details, dynamic linking (to the extent possible with this file), example usage errors, and the Frida hook example. Use clear headings and explanations. Use the provided code snippets to illustrate the points.

**Self-Correction/Refinement During the Process:**

*   Initially, I might just focus on the function declarations. However, realizing the importance of the `#ifdef` blocks and the `__BIONIC_FORTIFY` section is crucial.
*   Understanding the purpose of "fortify" requires some background knowledge about security hardening in C/C++. If I didn't know, I'd research "C library fortify" or similar terms.
*   While the file doesn't show *how* the dynamic linker works, recognizing that these functions will be in `libc.so` is important for addressing the dynamic linking aspect.
*   When explaining the Frida hook, focusing on the "chk" functions is key to demonstrating the fortify mechanism in action.

By following these steps, and continuously refining the understanding as I go through the code, I can arrive at a comprehensive and accurate explanation of the provided header file.
这个文件 `bionic/libc/include/bits/fortify/unistd.handroid` 是 Android Bionic C 库中用于实现 **编译时和运行时安全检查（fortification）** 的一部分，特别是针对 `unistd.h` 中定义的 POSIX 标准函数。它并不是一个包含实际函数实现的文件，而是一个 **头文件**，其主要作用是 **定义了经过安全增强的函数接口，并在编译时进行静态检查，在运行时进行动态检查**。

**功能列举:**

1. **提供安全增强的 `unistd.h` 函数接口:**  该文件定义了一系列以 `__<函数名>_chk` 命名的函数，这些函数是对标准 `unistd.h` 中函数的安全增强版本。例如，`__getcwd_chk` 是 `getcwd` 的增强版本，`__pread_chk` 是 `pread` 的增强版本。

2. **实现编译时缓冲区溢出检查:**  通过使用 `__pass_object_size` 宏和一些编译器内置的特性（如 `__builtin_object_size`，尽管在这个文件中没有直接看到，但它是 `__bos` 宏的底层实现原理），在编译时尝试推断目标缓冲区的大小。然后，通过 `__error_if_overflows_objectsize` 和 `__error_if_overflows_ssizet` 宏，如果传递给函数的尺寸参数明显超过了缓冲区大小，则会产生编译错误。

3. **实现运行时缓冲区溢出检查:**  当定义了 `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` 宏并且 Android API 版本满足要求时，会使用 `__<函数名>_chk` 函数进行运行时的边界检查。这些 `_chk` 函数会在内部检查传入的尺寸参数是否超过了实际的缓冲区大小，如果超过，则可能触发错误或终止程序，从而防止缓冲区溢出。

4. **提供绕过安全检查的机制:**  定义了 `__<函数名>_real` 形式的函数，这些函数实际上是标准 POSIX 函数的别名 (通过 `__RENAME` 宏实现)。在某些情况下，安全检查可能是不必要的或者会带来性能损耗，可以直接调用 `_real` 版本绕过检查。

5. **根据 Android API 版本启用不同的功能:**  使用 `__BIONIC_AVAILABILITY_GUARD(N)` 宏来控制特定函数或功能的可用性，这意味着某些安全增强的函数可能只在特定的 Android API 版本中才存在。

**与 Android 功能的关系及举例:**

这个文件是 Bionic C 库的一部分，而 Bionic 是 Android 系统的核心组件，为应用程序和系统服务提供了底层的 C 运行时环境。安全增强的 `unistd.h` 函数对于提高 Android 系统的安全性至关重要。

**举例说明:**

* **防止应用程序读取超出分配内存的范围:**  比如，`getcwd` 函数用于获取当前工作目录。一个常见的错误是提供的缓冲区太小，导致 `getcwd` 写入超出缓冲区边界。`__getcwd_chk` 版本会检查提供的缓冲区大小，如果太小，在编译时或运行时会发出警告或错误。
    * **错误代码示例:**
      ```c
      #include <unistd.h>
      #include <stdio.h>
      #include <stdlib.h>

      int main() {
          char buf[10]; // 故意分配一个很小的缓冲区
          if (getcwd(buf, sizeof(buf)) == NULL) {
              perror("getcwd");
              return 1;
          }
          printf("Current working directory: %s\n", buf);
          return 0;
      }
      ```
      在开启 fortify 的情况下编译并运行这段代码，`__getcwd_chk` 可能会在运行时检测到缓冲区溢出，并终止程序或报告错误。

* **提高文件操作的安全性:**  `pread` 和 `pwrite` 函数用于在指定偏移量读取或写入文件，而不会改变文件指针。 `__pread_chk` 和 `__pwrite_chk` 版本会检查读取或写入的字节数是否超过提供的缓冲区大小，防止缓冲区溢出。

**详细解释 libc 函数的功能是如何实现的:**

这个 `.handroid` 文件本身并没有包含 `libc` 函数的实际实现。它只是定义了安全增强的接口。

* **`__getcwd_chk(char* _Nullable, size_t, size_t)`:**
    * **功能:** 安全增强的 `getcwd`。尝试获取当前工作目录并存储到提供的缓冲区中。
    * **实现原理:**  当启用 fortify 时，编译器会将对 `getcwd` 的调用替换为对 `__getcwd_chk` 的调用。 `__getcwd_chk` 的实现（在 Bionic 的其他源文件中）会首先检查第三个参数（即通过 `__bos(buf)` 获取的缓冲区实际大小）是否足够容纳第二个参数指定的尺寸。如果不足，则会报告错误。如果检查通过，则会调用底层的 `__getcwd_real` (即标准的 `getcwd`) 来执行实际操作。

* **`__pread_chk(int, void* _Nonnull, size_t, off_t, size_t)` / `__pread64_chk`:**
    * **功能:** 安全增强的 `pread` 和 `pread64`。从文件描述符 `fd` 的指定偏移量 `offset` 读取最多 `count` 字节到缓冲区 `buf` 中。
    * **实现原理:**  类似于 `__getcwd_chk`，它会检查第五个参数（缓冲区大小）是否足够容纳第三个参数指定的读取字节数。

* **`__pwrite_chk(int, const void* _Nonnull, size_t, off_t, size_t)` / `__pwrite64_chk`:**
    * **功能:** 安全增强的 `pwrite` 和 `pwrite64`。将缓冲区 `buf` 中的最多 `count` 字节写入到文件描述符 `fd` 的指定偏移量 `offset`。
    * **实现原理:**  同样会检查第五个参数（缓冲区大小）是否大于等于第三个参数指定的写入字节数。

* **`__read_chk(int, void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t)`:**
    * **功能:** 安全增强的 `read`。从文件描述符 `fd` 读取最多 `size` 字节到缓冲区 `buf` 中。
    * **实现原理:** 检查第四个参数（缓冲区大小）是否足够容纳第三个参数指定的读取字节数。

* **`__write_chk(int, const void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t)`:**
    * **功能:** 安全增强的 `write`。将缓冲区 `buf` 中的最多 `size` 字节写入到文件描述符 `fd`。
    * **实现原理:** 检查第四个参数（缓冲区大小）是否大于等于第三个参数指定的写入字节数。

* **`__readlink_chk(const char* _Nonnull, char* _Nonnull, size_t, size_t)` / `__readlinkat_chk`:**
    * **功能:** 安全增强的 `readlink` 和 `readlinkat`。读取符号链接的内容到缓冲区中。
    * **实现原理:** 检查第四个参数（缓冲区大小）是否足够容纳符号链接的内容。

**对于涉及 dynamic linker 的功能:**

这个文件本身不直接涉及 dynamic linker 的核心功能。它的作用是在编译时和运行时进行安全检查，这些检查是在代码执行到这些 `libc` 函数时发生的。

**SO 布局样本:**

这些安全增强的函数最终会被编译到 `libc.so` 中。一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text:  // 代码段
        getcwd:           // 指向 __getcwd_chk 或 __getcwd_real
        __getcwd_chk:     // 安全增强的 getcwd 实现
        __getcwd_real:    // 标准的 getcwd 实现
        pread:            // 指向 __pread_chk 或 __pread_real
        __pread_chk:      // 安全增强的 pread 实现
        __pread_real:     // 标准的 pread 实现
        ...其他 unistd.h 函数...
    .data:  // 数据段
        ...全局变量...
    .bss:   // 未初始化数据段
        ...
    .dynamic: // 动态链接信息
        ...
    .symtab:  // 符号表
        getcwd
        __getcwd_chk
        __getcwd_real
        pread
        __pread_chk
        __pread_real
        ...
    .strtab:  // 字符串表
        ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序调用 `getcwd` 等函数时，编译器会根据是否启用了 fortify 和 Android API 版本，将其链接到 `libc.so` 中的 `__getcwd_chk` 或 `__getcwd_real`。这通常通过链接器在生成可执行文件或共享库时完成。
2. **运行时:** 当程序加载时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载 `libc.so` 到进程的地址空间。当程序执行到 `getcwd` 调用时，如果链接的是 `__getcwd_chk`，则会执行安全检查逻辑；如果链接的是 `__getcwd_real`，则会直接执行底层的系统调用。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `__getcwd_chk`):**

* `buf`: 一个指向字符数组的指针。
* `size`:  调用者提供的缓冲区大小。
* `bos`: 通过 `__bos(buf)` 获取的缓冲区实际大小。

**逻辑推理:**

`__getcwd_chk` 的内部逻辑大致如下：

```c
char* __getcwd_chk(char* buf, size_t size, size_t bos) {
    if (size > bos) {
        // 缓冲区溢出，报告错误或终止程序
        // (具体的错误处理方式取决于 Bionic 的实现)
        errno = ERANGE; // 或其他合适的错误码
        return NULL;
    }
    return __getcwd_real(buf, size);
}
```

**输出:**

* 如果 `size <= bos`，则返回 `__getcwd_real` 的返回值（通常是指向 `buf` 的指针，或在出错时返回 `NULL` 并设置 `errno`）。
* 如果 `size > bos`，则返回 `NULL` 并设置 `errno` 为 `ERANGE` (或其他表示缓冲区太小的错误码)。

**用户或编程常见的使用错误及举例:**

1. **提供的缓冲区大小不足:** 这是最常见的错误，导致缓冲区溢出。
   ```c
   char cwd[5]; // 缓冲区太小
   if (getcwd(cwd, sizeof(cwd)) == NULL) {
       perror("getcwd");
   }
   ```
   在开启 fortify 的情况下，编译时或运行时会捕获到这个错误。

2. **错误地计算缓冲区大小:**
   ```c
   char *path = malloc(10); // 分配了 10 字节
   if (readlink("/proc/self/exe", path, 100)) { // 期望读取最多 100 字节，但缓冲区只有 10 字节
       perror("readlink");
   }
   free(path);
   ```
   `__readlink_chk` 会检测到 `size` (100) 大于缓冲区的实际大小 (10)。

**说明 android framework or ndk 是如何一步步的到达这里:**

1. **Android Framework 或 NDK 调用 C 标准库函数:**  无论是 Java 代码通过 JNI 调用 NDK 中的 C/C++ 代码，还是 Android Framework 的原生组件，最终都会调用 Bionic 提供的 C 标准库函数，例如 `getcwd`, `read`, `write` 等。

2. **编译器和链接器的处理:** 当编译 NDK 代码或 Android Framework 的原生代码时，编译器会根据编译选项（是否启用 fortify）和目标 Android API 版本，将对标准 C 库函数的调用链接到相应的安全增强版本 (`_chk`) 或原始版本 (`_real`)。

3. **Bionic 的实现:** Bionic 实现了这些安全增强的函数。当程序执行到这些函数时，会执行相应的检查逻辑。

**Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 拦截 `getcwd` 的示例，展示如何观察 fortify 机制的影响：

```python
import frida
import sys

# 要 Hook 的进程名
package_name = "com.example.myapp" # 替换为你的应用包名

# Frida Script
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "getcwd"), {
    onEnter: function(args) {
        console.log("[getcwd] onEnter");
        this.buf = args[0];
        this.size = args[1].toInt();
        console.log("  buf:", this.buf);
        console.log("  size:", this.size);
        console.log("  __bos(buf):", Memory.readUSize(this.buf.sub(Process.pointerSize * 2))); // 尝试读取 __bos 信息 (取决于具体实现)
    },
    onLeave: function(retval) {
        console.log("[getcwd] onLeave");
        console.log("  retval:", retval);
        if (retval.isNull() === false) {
            console.log("  Current working directory:", Memory.readUtf8String(this.buf));
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__getcwd_chk"), {
    onEnter: function(args) {
        console.log("[__getcwd_chk] onEnter");
        console.log("  buf:", args[0]);
        console.log("  size:", args[1].toInt());
        console.log("  bos:", args[2].toInt());
    },
    onLeave: function(retval) {
        console.log("[__getcwd_chk] onLeave");
        console.log("  retval:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(e)
```

**使用步骤:**

1. **确保目标 Android 设备已 root，并且安装了 Frida Server。**
2. **安装 Python 和 Frida：** `pip install frida frida-tools`
3. **将 `package_name` 替换为你要调试的 Android 应用的包名。**
4. **运行 Python 脚本。**
5. **在被 Hook 的应用中触发调用 `getcwd` 的操作。**

**预期输出:**

Frida Hook 会拦截对 `getcwd` 和 `__getcwd_chk` 的调用，并打印出它们的参数和返回值。你可以观察到：

* 如果 fortify 被启用，`getcwd` 的调用会跳转到 `__getcwd_chk`。
* `__getcwd_chk` 的 `onEnter` 中会打印出 `buf` 指针、`size` (调用者提供的缓冲区大小) 和 `bos` (实际缓冲区大小)。
* 通过比较 `size` 和 `bos`，你可以了解 fortify 机制是否会检测到潜在的缓冲区溢出。

通过类似的方法，你可以 Hook 其他安全增强的函数，观察 Android Framework 或 NDK 代码如何与这些函数交互，并验证 fortify 机制是否按预期工作。

总而言之，`bionic/libc/include/bits/fortify/unistd.handroid` 是 Bionic C 库中用于提升安全性的关键部分，它通过定义安全增强的函数接口，并在编译时和运行时进行缓冲区溢出检查，来保护 Android 系统和应用程序免受潜在的安全漏洞影响。

### 提示词
```
这是目录为bionic/libc/include/bits/fortify/unistd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UNISTD_H_
#error "Never include this file directly; instead, include <unistd.h>"
#endif


#if __BIONIC_AVAILABILITY_GUARD(24)
char* _Nullable __getcwd_chk(char* _Nullable, size_t, size_t) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */



#if __BIONIC_AVAILABILITY_GUARD(23)
ssize_t __pread_chk(int, void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

ssize_t __pread_real(int, void* _Nonnull, size_t, off_t) __RENAME(pread);


#if __BIONIC_AVAILABILITY_GUARD(23)
ssize_t __pread64_chk(int, void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

ssize_t __pread64_real(int, void* _Nonnull, size_t, off64_t) __RENAME(pread64);


#if __BIONIC_AVAILABILITY_GUARD(24)
ssize_t __pwrite_chk(int, const void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

ssize_t __pwrite_real(int, const void* _Nonnull, size_t, off_t) __RENAME(pwrite);


#if __BIONIC_AVAILABILITY_GUARD(24)
ssize_t __pwrite64_chk(int, const void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

ssize_t __pwrite64_real(int, const void* _Nonnull, size_t, off64_t) __RENAME(pwrite64);

ssize_t __read_chk(int, void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t);

#if __BIONIC_AVAILABILITY_GUARD(24)
ssize_t __write_chk(int, const void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


#if __BIONIC_AVAILABILITY_GUARD(23)
ssize_t __readlink_chk(const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
ssize_t __readlinkat_chk(int dirfd, const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if defined(__BIONIC_FORTIFY)

#if defined(__USE_FILE_OFFSET64)
#define __PREAD_PREFIX(x) __pread64_ ## x
#define __PWRITE_PREFIX(x) __pwrite64_ ## x
#else
#define __PREAD_PREFIX(x) __pread_ ## x
#define __PWRITE_PREFIX(x) __pwrite_ ## x
#endif

#define __error_if_overflows_ssizet(what, fn) \
    __clang_error_if((what) > SSIZE_MAX, "in call to '" #fn "', '" #what "' must be <= SSIZE_MAX")

#define __error_if_overflows_objectsize(what, objsize, fn) \
    __clang_error_if(__bos_unevaluated_lt((objsize), (what)), \
                     "in call to '" #fn "', '" #what "' bytes overflows the given object")

#define __bos_trivially_ge_no_overflow(bos_val, index)  \
      ((__bos_dynamic_check_impl_and((bos_val), >=, (index), (bos_val) <= SSIZE_MAX) && \
        __builtin_constant_p(index) && (index) <= SSIZE_MAX))

__BIONIC_FORTIFY_INLINE
char* _Nullable getcwd(char* const _Nullable __pass_object_size buf, size_t size)
        __overloadable
        __error_if_overflows_objectsize(size, __bos(buf), getcwd) {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(buf);

    if (!__bos_trivially_ge(bos, size)) {
        return __getcwd_chk(buf, size, bos);
    }
#endif
    return __call_bypassing_fortify(getcwd)(buf, size);
}

#if !defined(__USE_FILE_OFFSET64)
__BIONIC_FORTIFY_INLINE
ssize_t pread(int fd, void* const _Nonnull __pass_object_size0 buf, size_t count, off_t offset)
        __overloadable
        __error_if_overflows_ssizet(count, pread)
        __error_if_overflows_objectsize(count, __bos0(buf), pread) {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __PREAD_PREFIX(chk)(fd, buf, count, offset, bos);
    }
#endif
    return __PREAD_PREFIX(real)(fd, buf, count, offset);
}
#endif /* !defined(__USE_FILE_OFFSET64) */

__BIONIC_FORTIFY_INLINE
ssize_t pread64(int fd, void* const _Nonnull __pass_object_size0 buf, size_t count, off64_t offset)
        __overloadable
        __error_if_overflows_ssizet(count, pread64)
        __error_if_overflows_objectsize(count, __bos0(buf), pread64) {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __pread64_chk(fd, buf, count, offset, bos);
    }
#endif
    return __pread64_real(fd, buf, count, offset);
}

#if !defined(__USE_FILE_OFFSET64)
__BIONIC_FORTIFY_INLINE
ssize_t pwrite(int fd, const void* const _Nonnull __pass_object_size0 buf, size_t count, off_t offset)
        __overloadable
        __error_if_overflows_ssizet(count, pwrite)
        __error_if_overflows_objectsize(count, __bos0(buf), pwrite) {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __PWRITE_PREFIX(chk)(fd, buf, count, offset, bos);
    }
#endif
    return __PWRITE_PREFIX(real)(fd, buf, count, offset);
}
#endif /* !defined(__USE_FILE_OFFSET64) */

__BIONIC_FORTIFY_INLINE
ssize_t pwrite64(int fd, const void* const _Nonnull __pass_object_size0 buf, size_t count, off64_t offset)
        __overloadable
        __error_if_overflows_ssizet(count, pwrite64)
        __error_if_overflows_objectsize(count, __bos0(buf), pwrite64) {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __pwrite64_chk(fd, buf, count, offset, bos);
    }
#endif
    return __pwrite64_real(fd, buf, count, offset);
}

__BIONIC_FORTIFY_INLINE
ssize_t read(int fd, void* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size0 buf, size_t count)
        __overloadable
        __error_if_overflows_ssizet(count, read)
        __error_if_overflows_objectsize(count, __bos0(buf), read) {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __read_chk(fd, buf, count, bos);
    }
#endif
    return __call_bypassing_fortify(read)(fd, buf, count);
}

__BIONIC_FORTIFY_INLINE
ssize_t write(int fd, const void* const __BIONIC_COMPLICATED_NULLNESS __pass_object_size0 buf, size_t count)
        __overloadable
        __error_if_overflows_ssizet(count, write)
        __error_if_overflows_objectsize(count, __bos0(buf), write) {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos0(buf);

    if (!__bos_trivially_ge_no_overflow(bos, count)) {
        return __write_chk(fd, buf, count, bos);
    }
#endif
    return __call_bypassing_fortify(write)(fd, buf, count);
}

__BIONIC_FORTIFY_INLINE
ssize_t readlink(const char* _Nonnull path, char* _Nonnull const __pass_object_size buf, size_t size)
        __overloadable
        __error_if_overflows_ssizet(size, readlink)
        __error_if_overflows_objectsize(size, __bos(buf), readlink) {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(buf);

    if (!__bos_trivially_ge_no_overflow(bos, size)) {
        return __readlink_chk(path, buf, size, bos);
    }
#endif
    return __call_bypassing_fortify(readlink)(path, buf, size);
}

__BIONIC_FORTIFY_INLINE
ssize_t readlinkat(int dirfd, const char* _Nonnull path, char* const _Nonnull __pass_object_size buf, size_t size)
        __overloadable
        __error_if_overflows_ssizet(size, readlinkat)
        __error_if_overflows_objectsize(size, __bos(buf), readlinkat) {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
    size_t bos = __bos(buf);

    if (!__bos_trivially_ge_no_overflow(bos, size)) {
        return __readlinkat_chk(dirfd, path, buf, size, bos);
    }
#endif
    return __call_bypassing_fortify(readlinkat)(dirfd, path, buf, size);
}

#undef __bos_trivially_ge_no_overflow
#undef __enable_if_no_overflow_ssizet
#undef __error_if_overflows_objectsize
#undef __error_if_overflows_ssizet
#undef __PREAD_PREFIX
#undef __PWRITE_PREFIX
#endif /* defined(__BIONIC_FORTIFY) */
```