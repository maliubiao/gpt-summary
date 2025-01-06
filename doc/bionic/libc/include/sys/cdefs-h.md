Response:
My thought process to answer the request about `bionic/libc/include/sys/cdefs.handroid` goes like this:

1. **Understand the Goal:** The user wants a detailed explanation of the C preprocessor definitions in this header file, focusing on their functionality, relationship to Android, implementation details (where applicable), dynamic linking implications, common errors, and how Android frameworks/NDK reach this point. Frida hooking examples are also requested.

2. **Break Down the File:** I'll go through the `cdefs.h` file line by line (or block by block for related definitions). For each definition, I'll ask myself:

    * **What does it do?** (Basic functionality)
    * **Why is it used?** (Purpose and context)
    * **Is it Android-specific?** (Look for `__BIONIC__`, `ANDROID_`, or other Android-related keywords)
    * **How is it implemented (if it's a function-like macro)?**  (Explain the macro expansion)
    * **Does it relate to libc functions?** (Often, these macros are used to define or modify libc function behavior)
    * **Does it relate to dynamic linking?** (Less likely in this file, but worth considering for alias definitions)
    * **Are there potential user errors?** (Misuse of macros, misunderstanding their purpose)

3. **Address Specific Requirements:**

    * **List functionalities:** This will be a summary of what each macro achieves (e.g., defining compiler attributes, creating aliases, handling conditional compilation).
    * **Relationship to Android:**  Focus on macros like `__BIONIC__`, `ANDROID_STRICT`, and versioning-related includes. Explain how they tailor the build for Android.
    * **libc function implementation:**  Since this file *defines* macros, it doesn't *implement* libc functions. I need to clarify this distinction. However, I can explain how these macros *influence* the compilation of libc functions (e.g., through function attributes).
    * **Dynamic linker:** Look for `__strong_alias`. Explain how aliases work at the dynamic linking stage. Provide a simplified SO layout and explain the linking process for aliases.
    * **Logical reasoning (input/output):** For macros like `__BIONIC_ALIGN`, provide an example with input values and the expected output.
    * **User/programming errors:**  Examples could include misusing `__predict_true`/`__predict_false`, or misunderstanding the impact of `_FORTIFY_SOURCE`.
    * **Android framework/NDK path:**  Explain the general compilation process, starting from source code, going through the NDK/SDK, and ending with the use of these header files during the build.
    * **Frida hook examples:**  Focus on how to hook functions that are potentially affected by these macros (e.g., a fortified function or an aliased function).

4. **Structure the Answer:**  I'll organize the information logically:

    * **Introduction:** Briefly explain the purpose of `cdefs.h`.
    * **Functionality Listing:** Provide a concise list of the major categories of definitions.
    * **Detailed Explanation of Macros:** Go through the macros in a logical order, explaining each one according to the points in step 2.
    * **Android Relationship:** Group together the Android-specific aspects.
    * **libc Functions:** Explain how these definitions affect libc compilation, but clarify that they don't *implement* the functions.
    * **Dynamic Linker:** Detail the `__strong_alias` mechanism.
    * **User Errors:** Provide concrete examples.
    * **Android Framework/NDK Path:** Explain the build process.
    * **Frida Hook Examples:** Give practical code snippets.
    * **Conclusion:** Summarize the importance of `cdefs.h`.

5. **Refine and Elaborate:** After the initial draft, I'll review and expand on certain points:

    * **Clarity:** Ensure the explanations are easy to understand, avoiding jargon where possible.
    * **Completeness:**  Make sure I've addressed all parts of the request.
    * **Accuracy:** Double-check the information about macro behavior and Android specifics.
    * **Examples:**  Provide clear and concise examples to illustrate concepts.

**Pre-computation/Pre-analysis (Internal):**

* **Recognize the Purpose:** I know `cdefs.h` is a common header file pattern for defining compiler-specific and platform-specific macros.
* **Identify Key Macro Categories:** I can quickly categorize the macros into groups like conditional compilation, function attributes, aliasing, and compiler-specific extensions.
* **Recall Android-Specific Knowledge:** I have background knowledge about Bionic, the NDK, and Android's build system.
* **Consider Dynamic Linking:**  I understand the concept of symbol resolution and how aliases play a role.

By following these steps, I can create a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to break down the problem into smaller, manageable parts and systematically address each requirement.
好的，让我们来详细分析一下 `bionic/libc/include/sys/cdefs.handroid` 这个头文件。这个文件在 Bionic C 库中扮演着非常重要的角色，它定义了一些用于条件编译、声明别名、以及提供各种编译器属性的宏。

**文件功能列表:**

这个头文件的主要功能可以概括为以下几点：

1. **标识 Bionic 环境:**  定义了 `__BIONIC__` 宏，用于标识代码正在 Bionic C 库的环境下编译。
2. **处理 C 与 C++ 的声明兼容性:**  定义了 `__BEGIN_DECLS` 和 `__END_DECLS` 宏，用于在 C++ 代码中声明 C 风格的外部链接。
3. **定义强符号别名:**  提供了 `__strong_alias` 宏，用于在编译时创建一个符号的别名。
4. **提供类型转换宏:** 定义了 `__BIONIC_CAST` 宏，用于在 C 和 C++ 中进行类型转换。
5. **提供内存对齐宏:** 定义了 `__BIONIC_ALIGN` 宏，用于计算内存对齐后的地址。
6. **标记复杂的 NULL 性:** 定义了 `__BIONIC_COMPLICATED_NULLNESS` 宏，用于标记参数或返回值的 NULL 性质比较复杂的情况。
7. **字符串连接宏:**  提供了 `__CONCAT` 系列宏，用于在预处理阶段连接字符串。
8. **字符串化宏:** 提供了 `__STRING` 系列宏，用于将宏参数转换为字符串字面量。
9. **内联函数定义:** 定义了 `__inline` 宏，用于声明内联函数。
10. **提供各种 GCC 属性宏:**  定义了诸如 `__always_inline`、`__attribute_const__`、`__noreturn` 等宏，用于向编译器传递关于函数的各种属性，以进行优化或静态检查。
11. **提供分支预测宏:** 定义了 `__predict_true` 和 `__predict_false` 宏，用于向编译器提供分支预测信息。
12. **标记不应丢弃的返回值:** 定义了 `__nodiscard` 和 `__wur` 宏，提示编译器如果函数的返回值被忽略则发出警告。
13. **提供错误和警告属性宏:** 定义了 `__errorattr`、`__warnattr` 等宏，用于在编译时生成错误或警告信息。
14. **处理 BSD 和 GNU 扩展:** 定义了与 `_BSD_SOURCE` 和 `_GNU_SOURCE` 相关的宏，用于控制是否启用 BSD 或 GNU 的扩展功能。
15. **处理大文件偏移:** 定义了与 `_FILE_OFFSET_BITS` 相关的宏，用于支持 64 位文件偏移。
16. **定义字长:** 定义了 `__WORDSIZE` 宏，表示目标平台的字长（32 位或 64 位）。
17. **支持 FORTIFY_SOURCE:** 定义了与 `_FORTIFY_SOURCE` 相关的宏，用于启用编译时的缓冲区溢出检测。
18. **对象大小检查宏:** 提供了 `__bos` 系列宏，用于在编译时获取对象的大小，用于安全检查。
19. **可重载函数宏:** 定义了 `__overloadable` 宏，用于标记可以重载的函数。
20. **诊断为内置函数宏:** 定义了 `__diagnose_as_builtin` 宏。
21. **控制符号可见性:** 定义了 `__LIBC_HIDDEN__` 和 `__LIBC32_LEGACY_PUBLIC__` 宏，用于控制符号在动态链接时的可见性。
22. **函数重命名宏:** 定义了 `__RENAME` 宏，用于在编译时将函数名替换为指定的名称。
23. **提供不安全乘法溢出检查宏:** 定义了 `__unsafe_check_mul_overflow` 宏。
24. **包含 Android 特有的头文件:**  包含了 `<android/versioning.h>`、`<android/api-level.h>` 和 `<android/ndk-version.h>`，提供了 Android 相关的版本信息。

**与 Android 功能的关系及举例说明:**

这个头文件与 Android 功能有着非常紧密的联系，因为它直接属于 Bionic C 库，而 Bionic 是 Android 系统的重要组成部分。以下是一些具体的例子：

* **`__BIONIC__` 宏:**  这个宏的存在直接标识了当前代码正在为 Android 的 Bionic 库编译。Android 平台自身的代码，以及通过 NDK 开发的原生代码，在编译时都会定义这个宏。例如，某些只在 Android 上可用的功能，可以通过 `#ifdef __BIONIC__` 来进行条件编译。

* **`__android_api__` (包含在 `android/api-level.h` 中):** 这个宏定义了当前编译的目标 Android API 级别。Bionic 库会根据这个 API 级别来决定暴露哪些 API，以及如何实现某些功能以保持兼容性。例如，在较新的 API 级别中引入的函数，在较低的 API 级别中可能不可用或使用不同的实现。

* **`__strong_alias` 宏:** 这个宏在 Bionic 中被广泛用于提供 API 的别名，以便在不同的 Android 版本中保持二进制兼容性。例如，旧版本的函数名可能被新的函数名取代，但旧的函数名仍然作为一个别名存在，指向新的实现。这样可以避免应用程序因为链接到旧的符号而无法在新版本的 Android 上运行。

* **`_FORTIFY_SOURCE` 相关的宏:** Android 引入了 `_FORTIFY_SOURCE` 机制来增强安全性，防止缓冲区溢出等漏洞。这个头文件中的相关宏控制了该机制的启用和行为。

**libc 函数功能实现详解:**

这个 `cdefs.h` 文件本身 **并不实现** 任何 libc 函数的功能。它只是定义了一些预处理宏，这些宏会在编译时被展开，从而影响编译器如何处理代码。

例如，`__always_inline` 宏指示编译器尽可能地将函数内联展开，这是一种优化手段，可以提高性能。`__noreturn` 宏告诉编译器某个函数不会返回，这可以帮助编译器进行更好的代码分析和优化。

真正实现 libc 函数功能的是 Bionic 库中的 `.c` 或 `.cpp` 源文件。`cdefs.h` 中定义的宏被这些源文件包含，从而影响这些函数的编译方式。

**涉及 dynamic linker 的功能，SO 布局样本及链接处理过程:**

`cdefs.h` 文件中与动态链接器直接相关的功能主要是 `__strong_alias` 宏。

**SO 布局样本:**

假设我们有一个共享库 `libexample.so`，其中定义了一个函数 `old_function`，现在我们想将其重命名为 `new_function`，但为了兼容性，仍然保留 `old_function` 作为别名。

```c
// libexample.c
#include <sys/cdefs.h>

int new_function(int arg) {
    // 新的实现
    return arg * 2;
}

__strong_alias(old_function, new_function)
```

编译并链接生成 `libexample.so` 后，其符号表（可以使用 `readelf -s libexample.so` 查看）可能会包含类似以下的信息：

```
Symbol table '.symtab' contains N entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    ...
   10: 0000000000001000    20 FUNC    GLOBAL DEFAULT   13 new_function
   11: 0000000000001000    20 FUNC    GLOBAL DEFAULT   13 old_function
    ...
```

可以看到，`old_function` 和 `new_function` 拥有相同的地址（Value）和类型，这表明它们指向同一个函数实现。

**链接处理过程:**

当另一个程序（例如 `app`）链接到 `libexample.so` 时，无论程序中调用的是 `old_function` 还是 `new_function`，动态链接器在加载时都会将这两个符号解析到 `libexample.so` 中 `new_function` 的地址。

1. **编译时:** 应用程序 `app.c` 中可能调用了 `old_function`。编译器在编译 `app.c` 时，会生成对 `old_function` 的未定义符号引用。

2. **链接时:** 链接器将 `app.o` 和 `libexample.so` 链接在一起。链接器会查找 `libexample.so` 的符号表，找到 `old_function` 这个符号。

3. **运行时 (动态链接):** 当应用程序运行时，动态链接器加载 `libexample.so`，并解析应用程序中对 `old_function` 的引用。由于 `__strong_alias` 的作用，`old_function` 被解析到 `new_function` 的地址。

**逻辑推理的假设输入与输出:**

对于 `__BIONIC_ALIGN` 宏，假设输入：

* `__value` = 7
* `__alignment` = 4

宏展开为 `(((7) + (4)-1) & ~((4)-1))`，即 `((10) & ~(3))`，也就是 `10 & ~00000011`，即 `10 & 11111100`，结果为 `8`。

因此，`__BIONIC_ALIGN(7, 4)` 的输出是 `8`，它将 7 向上对齐到 4 的倍数。

**用户或编程常见的使用错误:**

* **滥用分支预测宏 `__predict_true` 和 `__predict_false`:**  如果错误地预测了分支的走向，可能会导致性能下降，因为处理器会错误地进行推测执行。只有在对分支的发生概率有充分了解的情况下才应该使用这些宏。

* **误解 `__strong_alias` 的作用域:**  `__strong_alias` 定义的是全局符号的别名。如果在静态函数或局部作用域内使用，可能不会达到预期的效果。

* **不理解编译器属性宏的含义:**  错误地使用像 `__noreturn` 或 `__attribute_const__` 这样的宏可能会导致编译器优化不当，甚至产生错误的行为。例如，如果一个实际上会返回的函数被标记为 `__noreturn`，编译器可能会跳过后续的代码。

* **`_FORTIFY_SOURCE` 的误用:**  过度依赖 `_FORTIFY_SOURCE` 进行安全检查，而忽略了代码本身的安全性设计，可能会导致性能损失，并且不能完全防止所有类型的安全漏洞。

**Android framework 或 NDK 如何一步步到达这里:**

1. **Android Framework/NDK 开发:**  开发者使用 Java/Kotlin (Framework) 或 C/C++ (NDK) 编写应用程序或库。

2. **NDK 构建系统:** 如果使用 NDK，构建系统（通常是 CMake 或 ndk-build）会根据 `Android.mk` 或 `CMakeLists.txt` 文件中的配置，决定如何编译 C/C++ 代码。

3. **包含头文件:** 在 C/C++ 代码中，会包含需要的系统头文件，例如 `<stdio.h>`, `<unistd.h>`, 或者 `<sys/types.h>` 等。当包含这些头文件时，最终会间接地包含到 Bionic 库的头文件，包括 `sys/cdefs.handroid`。

4. **编译器预处理:** 编译器在编译代码的第一步是预处理。预处理器会处理 `#include` 指令，将头文件的内容插入到源文件中。此时，`sys/cdefs.handroid` 中定义的宏会被展开。

5. **条件编译:**  根据预定义的宏（例如 `__BIONIC__`, `__android_api__`, `_FORTIFY_SOURCE` 等），编译器会决定编译哪些代码段。

6. **生成机器码:** 编译器将预处理后的代码编译成目标平台的机器码。

7. **链接:** 链接器将编译生成的目标文件和需要的库（包括 Bionic 库）链接在一起，生成最终的可执行文件或共享库。

**Frida Hook 示例调试步骤:**

假设我们想观察 `__BIONIC_ALIGN` 宏在一个函数中的作用。我们可以 hook 使用了这个宏的函数。由于 `__BIONIC_ALIGN` 通常用于内存分配相关的操作，我们可以选择 hook `malloc` 函数（虽然 `malloc` 本身可能不直接使用这个宏，但其内部实现可能会用到）。

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.InvalidArgumentError:
    print(f"找不到应用: {package_name}")
    sys.exit(1)
except frida.TimedOutError:
    print(f"连接设备超时")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt32();
        console.log("[Malloc] Allocating size: " + size);
    },
    onLeave: function(retval) {
        console.log("[Malloc] Allocated at: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

try:
    sys.stdin.read()
except KeyboardInterrupt:
    session.detach()
    sys.exit()
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **安装目标应用:** 将你需要调试的应用安装到 Android 设备上。
3. **获取应用包名:** 找到你要调试的应用的包名。
4. **运行 Frida 脚本:** 运行上面的 Python Frida 脚本，并将 `package_name` 替换为你应用的包名。
5. **触发 `malloc` 调用:** 在你的 Android 应用中执行一些操作，这些操作会导致 `malloc` 函数被调用（例如，创建对象、加载资源等）。
6. **观察输出:** Frida 脚本会在控制台输出 `malloc` 函数被调用时的参数（分配的大小）和返回值（分配的内存地址）。

**更深入的 Hook (Hook 使用了 `__BIONIC_ALIGN` 的函数):**

要直接观察 `__BIONIC_ALIGN` 的作用，你需要找到 Bionic 库中实际使用了这个宏的函数并 hook 它。这可能需要一些代码分析。例如，你可以搜索 Bionic 的源代码，找到使用了 `__BIONIC_ALIGN` 的函数，然后 hook 该函数。

假设我们找到了一个 Bionic 内部函数 `_bionic_alloc_aligned`（这只是一个假设的函数名，实际可能不同），它使用了 `__BIONIC_ALIGN`。

```python
import frida
import sys

# ... (前面相同的代码)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_bionic_alloc_aligned"), {
    onEnter: function(args) {
        var size = args[0].toInt32();
        var alignment = args[1].toInt32();
        console.log("[_bionic_alloc_aligned] Requesting size: " + size + ", alignment: " + alignment);
    },
    onLeave: function(retval) {
        console.log("[_bionic_alloc_aligned] Allocated at: " + retval);
    }
});
"""

# ... (后面相同的代码)
```

你需要将 `"libc.so"` 替换为实际包含目标函数的库名，并将 `"_bionic_alloc_aligned"` 替换为实际的函数名。这种方法需要你对 Bionic 的内部实现有一定的了解。

总结来说，`bionic/libc/include/sys/cdefs.handroid` 是一个基础性的头文件，它通过定义各种宏来影响 Bionic C 库和使用它的代码的编译和行为，是理解 Android 底层机制的重要组成部分。

Prompt: 
```
这是目录为bionic/libc/include/sys/cdefs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: cdefs.h,v 1.58 2004/12/11 05:59:00 christos Exp $	*/

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)cdefs.h	8.8 (Berkeley) 1/9/95
 */

#pragma once

/**
 * `__BIONIC__` is always defined if you're building with bionic. See
 * https://android.googlesource.com/platform/bionic/+/main/docs/defines.md.
 */
#define __BIONIC__ 1

#if defined(__cplusplus)
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif

#define __strong_alias(alias, sym) \
    __asm__(".global " #alias "\n" \
            #alias " = " #sym);

#if defined(__cplusplus)
#define __BIONIC_CAST(_k,_t,_v) (_k<_t>(_v))
#else
#define __BIONIC_CAST(_k,_t,_v) ((_t) (_v))
#endif

#define __BIONIC_ALIGN(__value, __alignment) (((__value) + (__alignment)-1) & ~((__alignment)-1))

/*
 * The nullness constraints of this parameter or return value are
 * quite complex. This is used to highlight spots where developers
 * are encouraged to read relevant manuals or code to understand
 * the full picture of nullness for this pointer.
 */
#define __BIONIC_COMPLICATED_NULLNESS _Null_unspecified

/*
 * The __CONCAT macro is used to concatenate parts of symbol names, e.g.
 * with "#define OLD(foo) __CONCAT(old,foo)", OLD(foo) produces oldfoo.
 * The __CONCAT macro is a bit tricky -- make sure you don't put spaces
 * in between its arguments.  __CONCAT can also concatenate double-quoted
 * strings produced by the __STRING macro, but this only works with ANSI C.
 */

#define	__P(protos)	protos		/* full-blown ANSI C */

#define	__CONCAT1(x,y)	x ## y
#define	__CONCAT(x,y)	__CONCAT1(x,y)
#define	___CONCAT(x,y)	__CONCAT(x,y)

#define	__STRING(x)	#x
#define	___STRING(x)	__STRING(x)

// C++ has `inline` as a keyword, as does C99, but ANSI C (aka C89 aka C90)
// does not. Everything accepts the `__inline__` extension though. We could
// just use that directly in our own code, but there's historical precedent
// for `__inline` meaning it's still used in upstream BSD code (and potentially
// downstream in vendor or app code).
#define	__inline __inline__

#define __always_inline __attribute__((__always_inline__))
#define __attribute_const__ __attribute__((__const__))
#define __attribute_pure__ __attribute__((__pure__))
#define __dead __attribute__((__noreturn__))
#define __noreturn __attribute__((__noreturn__))
#define __mallocfunc  __attribute__((__malloc__))
#define __packed __attribute__((__packed__))
#define __returns_twice __attribute__((__returns_twice__))
#define __unused __attribute__((__unused__))
#define __used __attribute__((__used__))

#define __printflike(x, y) __attribute__((__format__(printf, x, y)))
#define __scanflike(x, y) __attribute__((__format__(scanf, x, y)))
#define __strftimelike(x) __attribute__((__format__(strftime, x, 0)))

/*
 * GNU C version 2.96 added explicit branch prediction so that
 * the CPU back-end can hint the processor and also so that
 * code blocks can be reordered such that the predicted path
 * sees a more linear flow, thus improving cache behavior, etc.
 *
 * The following two macros provide us with a way to use this
 * compiler feature.  Use __predict_true() if you expect the expression
 * to evaluate to true, and __predict_false() if you expect the
 * expression to evaluate to false.
 *
 * A few notes about usage:
 *
 *	* Generally, __predict_false() error condition checks (unless
 *	  you have some _strong_ reason to do otherwise, in which case
 *	  document it), and/or __predict_true() `no-error' condition
 *	  checks, assuming you want to optimize for the no-error case.
 *
 *	* Other than that, if you don't know the likelihood of a test
 *	  succeeding from empirical or other `hard' evidence, don't
 *	  make predictions.
 *
 *	* These are meant to be used in places that are run `a lot'.
 *	  It is wasteful to make predictions in code that is run
 *	  seldomly (e.g. at subsystem initialization time) as the
 *	  basic block reordering that this affects can often generate
 *	  larger code.
 */
#define	__predict_true(exp)	__builtin_expect((exp) != 0, 1)
#define	__predict_false(exp)	__builtin_expect((exp) != 0, 0)

#define __nodiscard __attribute__((__warn_unused_result__))
#define __wur __nodiscard

#define __errorattr(msg) __attribute__((__unavailable__(msg)))
#define __warnattr(msg) __attribute__((__deprecated__(msg)))
#define __warnattr_real(msg) __attribute__((__deprecated__(msg)))
#define __enable_if(cond, msg) __attribute__((__enable_if__(cond, msg)))
#define __clang_error_if(cond, msg) __attribute__((__diagnose_if__(cond, msg, "error")))
#define __clang_warning_if(cond, msg) __attribute__((__diagnose_if__(cond, msg, "warning")))

#if defined(ANDROID_STRICT)
/*
 * For things that are sketchy, but not necessarily an error. FIXME: Enable
 * this.
 */
#  define __warnattr_strict(msg) /* __warnattr(msg) */
#else
#  define __warnattr_strict(msg)
#endif

/*
 * Some BSD source needs these macros.
 * Originally they embedded the rcs versions of each source file
 * in the generated binary. We strip strings during build anyway,.
 */
#define __IDSTRING(_prefix,_s) /* nothing */
#define __COPYRIGHT(_s) /* nothing */
#define __FBSDID(_s) /* nothing */
#define __RCSID(_s) /* nothing */
#define __SCCSID(_s) /* nothing */

/*
 * With bionic, you always get all C and POSIX API.
 *
 * If you want BSD and/or GNU extensions, _BSD_SOURCE and/or _GNU_SOURCE are
 * expected to be defined by callers before *any* standard header file is
 * included.
 *
 * In our header files we test against __USE_BSD and __USE_GNU.
 */
#if defined(_GNU_SOURCE)
#  define __USE_BSD 1
#  define __USE_GNU 1
#endif

#if defined(_BSD_SOURCE)
#  define __USE_BSD 1
#endif

/*
 * _FILE_OFFSET_BITS 64 support.
 * See https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md
 */
#if !defined(__LP64__) && defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
#  define __USE_FILE_OFFSET64 1
/*
 * Note that __RENAME_IF_FILE_OFFSET64 is only valid if the off_t and off64_t
 * functions were both added at the same API level because if you use this,
 * you only have one declaration to attach __INTRODUCED_IN to.
 */
#  define __RENAME_IF_FILE_OFFSET64(func) __RENAME(func)
#else
#  define __RENAME_IF_FILE_OFFSET64(func)
#endif

/* glibc compatibility. */
#if defined(__LP64__)
#define __WORDSIZE 64
#else
#define __WORDSIZE 32
#endif

/*
 * When _FORTIFY_SOURCE is defined, automatic bounds checking is
 * added to commonly used libc functions. If a buffer overrun is
 * detected, the program is safely aborted.
 *
 * https://android-developers.googleblog.com/2017/04/fortify-in-android.html
 */

#define __BIONIC_FORTIFY_UNKNOWN_SIZE ((size_t) -1)

#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE > 0
/* FORTIFY can interfere with pattern-matching of clang-tidy/the static analyzer.  */
#  if !defined(__clang_analyzer__)
#    define __BIONIC_FORTIFY 1
/* ASAN has interceptors that FORTIFY's _chk functions can break.  */
#    if __has_feature(address_sanitizer)
#      define __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED 0
#    else
#      define __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED 1
#    endif
#  endif
#endif

// As we move some FORTIFY checks to be always on, __bos needs to be
// always available.
#if defined(__BIONIC_FORTIFY)
#  if _FORTIFY_SOURCE == 2
#    define __bos_level 1
#  else
#    define __bos_level 0
#  endif
#else
#  define __bos_level 0
#endif

#define __bosn(s, n) __builtin_object_size((s), (n))
#define __bos(s) __bosn((s), __bos_level)

#if defined(__BIONIC_FORTIFY)
#  define __bos0(s) __bosn((s), 0)
#  define __pass_object_size_n(n) __attribute__((__pass_object_size__(n)))
/*
 * FORTIFY'ed functions all have either enable_if or pass_object_size, which
 * makes taking their address impossible. Saying (&read)(foo, bar, baz); will
 * therefore call the unFORTIFYed version of read.
 */
#  define __call_bypassing_fortify(fn) (&fn)
/*
 * Because clang-FORTIFY uses overloads, we can't mark functions as `extern inline` without making
 * them available externally. FORTIFY'ed functions try to be as close to possible as 'invisible';
 * having stack protectors detracts from that (b/182948263).
 */
#  define __BIONIC_FORTIFY_INLINE static __inline __attribute__((__no_stack_protector__)) \
      __always_inline
/*
 * We should use __BIONIC_FORTIFY_VARIADIC instead of __BIONIC_FORTIFY_INLINE
 * for variadic functions because compilers cannot inline them.
 * The __always_inline attribute is useless, misleading, and could trigger
 * clang compiler bug to incorrectly inline variadic functions.
 */
#  define __BIONIC_FORTIFY_VARIADIC static __inline
/* Error functions don't have bodies, so they can just be static. */
#  define __BIONIC_ERROR_FUNCTION_VISIBILITY static __unused
#else
/* Further increase sharing for some inline functions */
#  define __pass_object_size_n(n)
#endif
#define __pass_object_size __pass_object_size_n(__bos_level)
#define __pass_object_size0 __pass_object_size_n(0)

/* Intended for use in unevaluated contexts, e.g. diagnose_if conditions. */
#define __bos_unevaluated_lt(bos_val, val) \
  ((bos_val) != __BIONIC_FORTIFY_UNKNOWN_SIZE && (bos_val) < (val))

#define __bos_unevaluated_le(bos_val, val) \
  ((bos_val) != __BIONIC_FORTIFY_UNKNOWN_SIZE && (bos_val) <= (val))

/* Intended for use in evaluated contexts. */
#define __bos_dynamic_check_impl_and(bos_val, op, index, cond) \
  ((bos_val) == __BIONIC_FORTIFY_UNKNOWN_SIZE ||                 \
   (__builtin_constant_p(index) && bos_val op index && (cond)))

#define __bos_dynamic_check_impl(bos_val, op, index) \
  __bos_dynamic_check_impl_and(bos_val, op, index, 1)

#define __bos_trivially_ge(bos_val, index) __bos_dynamic_check_impl((bos_val), >=, (index))
#define __bos_trivially_gt(bos_val, index) __bos_dynamic_check_impl((bos_val), >, (index))

#if defined(__BIONIC_FORTIFY) || defined(__BIONIC_DECLARE_FORTIFY_HELPERS)
#  define __BIONIC_INCLUDE_FORTIFY_HEADERS 1
#endif

#define __overloadable __attribute__((__overloadable__))

#define __diagnose_as_builtin(...) __attribute__((__diagnose_as_builtin__(__VA_ARGS__)))

/* Used to tag non-static symbols that are private and never exposed by the shared library. */
#define __LIBC_HIDDEN__ __attribute__((__visibility__("hidden")))

/*
 * Used to tag symbols that should be hidden for 64-bit,
 * but visible to preserve binary compatibility for LP32.
 */
#ifdef __LP64__
#define __LIBC32_LEGACY_PUBLIC__ __attribute__((__visibility__("hidden")))
#else
#define __LIBC32_LEGACY_PUBLIC__ __attribute__((__visibility__("default")))
#endif

/* Used to rename functions so that the compiler emits a call to 'x' rather than the function this was applied to. */
#define __RENAME(x) __asm__(#x)

/*
 * Used when we need to check for overflow when multiplying x and y. This
 * should only be used where __builtin_umull_overflow can not work, because it makes
 * assumptions that __builtin_umull_overflow doesn't (x and y are positive, ...),
 * *and* doesn't make use of compiler intrinsics, so it's probably slower than
 * __builtin_umull_overflow.
 */
#define __unsafe_check_mul_overflow(x, y) ((__SIZE_TYPE__)-1 / (x) < (y))

#include <android/versioning.h>
#include <android/api-level.h>
#if __has_include(<android/ndk-version.h>)
#include <android/ndk-version.h>
#endif

"""

```