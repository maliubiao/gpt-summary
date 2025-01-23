Response:
Let's break down the thought process for analyzing this C header file (`bionic_ifuncs.handroid.h`).

**1. Initial Understanding - The Big Picture**

The file name itself is very telling: `bionic_ifuncs.handroid.h`. This immediately suggests:

* **bionic:**  This is related to Android's core C library. Therefore, the contents likely involve low-level system functions.
* **ifuncs:** This is a strong indicator of "indirect functions."  Indirect functions are often used for optimization, allowing the dynamic linker to choose the best implementation of a function at runtime based on the hardware or other factors.
* **.handroid:** This suggests Android-specific customizations or configurations for these indirect functions.
* **.h:**  It's a header file, so it primarily contains declarations, macros, and type definitions.

**2. Analyzing the Header Inclusions**

The first few lines are `#include` directives:

* `<stdint.h>`: Standard integer types (like `uint64_t`). This is common in low-level code.
* `<sys/ifunc.h>`:  This confirms the "ifuncs" suspicion. It likely defines the basic structures and definitions related to indirect functions at the system level.
* `<private/bionic_call_ifunc_resolver.h>`:  This is a private Bionic header, suggesting internal mechanisms for resolving indirect function calls. The "resolver" part is key.

**3. Platform-Specific Definitions (`__aarch64__`, `__arm__`)**

The `#if defined(__aarch64__)` block tells us that this code adapts to different architectures. The `IFUNC_ARGS` macro is defined differently for AArch64 and ARM. This reinforces the idea of runtime selection based on hardware. The `__attribute__((unused))` is a compiler hint to avoid warnings about unused variables in cases where they aren't needed.

**4. Core Macros: `DECLARE_FUNC`, `RETURN_FUNC`**

These macros are for convenience and code clarity. `DECLARE_FUNC` adds the `__attribute__((visibility("hidden")))` which means these functions are internal to the library and not part of the public API. `RETURN_FUNC` combines declaration and return.

**5. The Heart of the Matter: `BIONIC_DYNAMIC_DISPATCH` and `BIONIC_STATIC_DISPATCH`**

This is the most crucial part. The code uses preprocessor directives (`#if`, `#elif`, `#else`) to handle two different dispatching mechanisms:

* **`BIONIC_DYNAMIC_DISPATCH`:** This indicates runtime resolution of the indirect function. The `DEFINE_IFUNC_FOR` macro defines a function pointer and a resolver function. The `__attribute__((ifunc(...)))` is the key here – it tells the compiler and linker that the function pointer will be resolved indirectly using the resolver function. The `__attribute__((no_sanitize("hwaddress")))` is important for security and performance, as resolvers might be called before memory sanitizers are fully initialized.
* **`BIONIC_STATIC_DISPATCH`:** This suggests resolution at link time. The `DEFINE_IFUNC_FOR` macro still defines a resolver function, but its purpose is different. The `FORWARD` macro uses `__bionic_call_ifunc_resolver` explicitly to get the function pointer. This likely happens once during library initialization.
* **Error Condition:** The `#else` triggers an error if neither of these is defined, ensuring a valid build configuration.

**6. The `FORWARD` Macro**

This macro is central to the static dispatch mechanism. It retrieves the actual function pointer by calling `__bionic_call_ifunc_resolver`. The `reinterpret_cast` is necessary to convert the result of the resolver to the correct function pointer type.

**7. Function-Specific Shims (`MEMCHR_SHIM`, `MEMCMP_SHIM`, etc.)**

These macros define type aliases (e.g., `memchr_func_t`) and then use the `DEFINE_STATIC_SHIM` macro. If `BIONIC_STATIC_DISPATCH` is enabled, `DEFINE_STATIC_SHIM` defines a standard function that calls the resolved indirect function via the `FORWARD` macro. If `BIONIC_DYNAMIC_DISPATCH` is enabled, `DEFINE_STATIC_SHIM` is empty.

**8. Specific libc Functions**

The code then defines shims for various common `libc` string and memory manipulation functions (`memchr`, `memcmp`, `memcpy`, `memset`, `strcpy`, `strlen`, etc.). The pattern is consistent: define a function pointer type, and then create a shim function (if static dispatch is used).

**9. Connecting to Android Functionality**

The key takeaway is *why* indirect functions are used in Android. The primary reason is optimization. Different Android devices have different CPU architectures and hardware capabilities. By using `ifuncs`, the dynamic linker can select the most efficient implementation of a function at runtime. For example, there might be optimized versions of `memcpy` that use SIMD instructions on certain processors.

**10. Dynamic Linker and SO Layout**

To understand the dynamic linker's role, it's crucial to visualize how shared libraries (`.so` files) are structured. The `.plt` (Procedure Linkage Table) and `.got.plt` (Global Offset Table for PLT) sections are key. When an indirect function is called for the first time, the PLT entry jumps to a resolver function (defined by the dynamic linker). This resolver then calls the appropriate `ifunc` resolver (like `memchr_resolver`) within the library. The `ifunc` resolver determines the best implementation and updates the GOT entry, so subsequent calls go directly to the optimized function.

**11. Considering Edge Cases and Errors**

The code itself doesn't explicitly *handle* errors, but it's part of a larger system where errors are managed. A common user error related to these functions is buffer overflows, which the `_chk` versions of functions like `strcpy` are designed to mitigate (though those shims still rely on the underlying ifunc).

**12. Tracing the Call Path with Frida**

The final step is thinking about how to observe this in action. Frida is a great tool for dynamic instrumentation. The key is to hook functions involved in the dynamic linking process and the `ifunc` resolvers themselves.

By following these steps – from understanding the basic purpose to analyzing the macros and finally considering the dynamic linking process and debugging – we can arrive at a comprehensive understanding of this header file and its role in Android's Bionic library.这是一个定义了用于 Android Bionic C 库中使用的间接函数 (ifuncs) 的头文件。ifuncs 允许在运行时根据硬件功能或其他条件选择函数的最佳实现。

**它的功能：**

1. **定义间接函数 (ifuncs) 的声明和定义机制:**  这个头文件定义了一系列宏 (`DECLARE_FUNC`, `RETURN_FUNC`, `DEFINE_IFUNC_FOR`, `DEFINE_STATIC_SHIM`)，用于声明和定义在运行时可以动态选择实现的函数。
2. **为常见的 libc 函数提供 ifunc 支持:**  文件中为诸如 `memchr`, `memcmp`, `memcpy`, `memset`, `strcpy`, `strlen` 等常用的 C 标准库函数定义了 ifunc 机制。这意味着对于这些函数，Android 系统可以根据运行设备的 CPU 特性（例如，是否支持特定的 CPU 指令集扩展）选择最优的实现版本。
3. **提供静态和动态分发两种机制:**  通过预编译宏 `BIONIC_DYNAMIC_DISPATCH` 和 `BIONIC_STATIC_DISPATCH`，可以选择 ifunc 的解析方式。
    * **动态分发 (BIONIC_DYNAMIC_DISPATCH):**  在第一次调用 ifunc 时，会调用一个 resolver 函数来确定实际要执行的函数地址。
    * **静态分发 (BIONIC_STATIC_DISPATCH):**  在库加载时，会调用 resolver 函数来确定实际要执行的函数地址，并将结果缓存起来。
4. **隐藏实现细节:**  使用 `__attribute__((visibility("hidden")))` 将 resolver 函数隐藏起来，使其不成为公共 API 的一部分。
5. **防止地址空间布局随机化 (ASLR) 相关问题:**  使用 `__attribute__((no_sanitize("hwaddress")))`  注解，表明 resolver 函数不应进行硬件地址消毒 (HWASAN) 的检查，因为它们可能在 HWASAN 初始化之前被调用。

**与 Android 功能的关系和举例说明:**

这个文件是 Android Bionic 库的核心组成部分，直接影响着应用程序的性能和兼容性。

* **CPU 优化:** Android 设备种类繁多，不同的 CPU 架构和特性（例如 ARMv7, ARMv8, NEON 指令集等）。使用 ifuncs 可以让 Bionic 库在运行时根据设备的 CPU 能力选择最佳的函数实现。
    * **例如 `memcpy`:**  在支持 NEON 指令集的 CPU 上，`memcpy` 的 ifunc resolver 可能会选择一个使用 NEON 指令优化的实现，从而提高内存拷贝的效率。而在不支持 NEON 的 CPU 上，则会选择一个通用的实现。
* **兼容性:**  通过 ifuncs，可以为不同的 Android 版本或设备提供不同的函数实现，以解决兼容性问题或利用新特性。
* **性能提升:** 针对特定硬件优化的函数实现通常比通用的实现具有更高的性能。

**详细解释 libc 函数的实现 (针对 ifuncs 的角度):**

这个头文件本身**没有实现** libc 函数的功能，它只是定义了如何**选择**实现。真正的函数实现位于 Bionic 库的其他源文件中。

以下以 `memcpy` 为例说明 ifunc 的工作流程：

1. **声明:** 在其他头文件中声明了 `memcpy` 函数。
2. **ifunc 定义:** 在 `bionic_ifuncs.handroid.h` 中，通过 `DEFINE_IFUNC_FOR(memcpy)` 定义了 `memcpy` 的 ifunc 机制。这会生成一个名为 `memcpy_resolver` 的函数。
3. **Resolver 函数 (`memcpy_resolver`):** 这个函数（在其他源文件中实现）会检查当前设备的硬件能力（例如，是否支持 NEON）。
4. **选择实现:** 根据硬件能力，`memcpy_resolver` 返回指向最佳 `memcpy` 实现的函数指针。可能有多个 `memcpy` 的实现，例如：
    * 一个通用的 C 实现。
    * 一个使用 NEON 指令优化的实现。
    * 其他针对特定架构或场景优化的实现。
5. **调用:** 当应用程序第一次调用 `memcpy` 时，动态链接器会调用 `memcpy_resolver` 获取实际的函数地址，并将这个地址记录下来。后续的 `memcpy` 调用将直接跳转到已确定的最佳实现。

**涉及 dynamic linker 的功能和说明:**

ifuncs 的核心功能依赖于 Android 的动态链接器 (linker)。

**SO 布局样本:**

假设有一个名为 `libc.so` 的共享库，其中包含了 `memcpy` 的 ifunc 定义：

```
libc.so:
    .text:
        memcpy:  // PLT 入口 (第一次调用时跳转到 resolver)
            ...
        memcpy_resolver:  // ifunc resolver 函数
            ...
        memcpy_generic: // 通用 memcpy 实现
            ...
        memcpy_neon:    // NEON 优化的 memcpy 实现
            ...
    .rodata:
        ...
    .got.plt:
        memcpy:  // GOT 表项 (初始时指向 PLT 入口，解析后指向实际函数)
            ...
```

**链接的处理过程 (以动态分发为例):**

1. **加载共享库:** 当 Android 系统加载包含 `memcpy` 的共享库 (`libc.so`) 时，动态链接器会解析库的符号表。
2. **创建 PLT 和 GOT 条目:** 对于需要动态链接的函数（包括 ifuncs），动态链接器会在 `.plt` (Procedure Linkage Table) 和 `.got.plt` (Global Offset Table for PLT) 中创建相应的条目。初始时，`memcpy` 在 GOT 中的条目会指向 PLT 中 `memcpy` 的入口。
3. **首次调用 `memcpy`:** 当应用程序第一次调用 `memcpy` 时，程序会跳转到 PLT 中 `memcpy` 的入口。
4. **跳转到 resolver:** PLT 中的代码会负责调用动态链接器的 resolver 例程。
5. **调用 ifunc resolver:** 动态链接器的 resolver 例程会查找与 `memcpy` 关联的 ifunc resolver 函数 (`memcpy_resolver`) 并调用它。
6. **解析函数地址:** `memcpy_resolver` 函数会根据当前的硬件环境选择合适的 `memcpy` 实现 (例如 `memcpy_neon`) 并返回其地址。
7. **更新 GOT:** 动态链接器会将 `memcpy` 在 GOT 中的条目更新为 `memcpy_neon` 的地址。
8. **执行实际函数:** 动态链接器会跳转到 `memcpy_neon` 的地址执行实际的内存拷贝操作。
9. **后续调用:** 后续对 `memcpy` 的调用将直接跳转到 GOT 中存储的 `memcpy_neon` 地址，避免了重复调用 resolver 的开销。

**逻辑推理、假设输入与输出 (针对 resolver 函数):**

假设 `memcpy_resolver` 函数的逻辑如下：

```c
void* memcpy_resolver(uint64_t hwcap, __ifunc_arg_t* arg) {
  if (hwcap & HWCAP_ARM64_NEON) { // 假设 HWCAP_ARM64_NEON 是 NEON 支持的标志
    return memcpy_neon;
  } else {
    return memcpy_generic;
  }
}
```

* **假设输入:**
    * `hwcap`:  当前 CPU 的硬件能力位掩码，例如 `0x400` (假设 `HWCAP_ARM64_NEON` 的值为 `0x400`)。
    * `arg`:  一些额外的参数 (在这个例子中未使用)。
* **输出:**
    * 如果 `hwcap` 中包含 `HWCAP_ARM64_NEON` 标志，则输出指向 `memcpy_neon` 函数的指针。
    * 否则，输出指向 `memcpy_generic` 函数的指针。

**用户或编程常见的使用错误:**

这个头文件定义的是库内部机制，普通用户或开发者一般不会直接与其交互。与这些 ifuncs 相关的常见错误通常发生在库的实现层面，例如：

* **Resolver 函数逻辑错误:**  如果 resolver 函数的判断逻辑有误，可能导致在支持特定特性的硬件上没有选择最优的实现。
* **多个实现版本之间的不一致性:**  不同的函数实现版本（例如 `memcpy_generic` 和 `memcpy_neon`）在行为上应该保持一致，如果存在差异可能导致程序出现意外行为。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例:**

1. **NDK 调用:**  当 NDK 开发者使用 C/C++ 代码调用标准的 C 库函数（例如 `memcpy`）时，这些调用最终会链接到 Bionic 库中的实现。
2. **Framework 调用:**  Android Framework 的底层也大量使用了 C/C++ 代码，这些代码同样会调用 Bionic 库提供的函数。
3. **动态链接:**  当应用程序或 Framework 组件加载时，动态链接器会负责解析对 Bionic 库中函数的引用。对于 ifuncs，动态链接器会按照上述流程调用 resolver 函数来确定实际执行的函数地址.

**Frida Hook 示例:**

可以使用 Frida hook `memcpy_resolver` 函数来观察其行为和选择结果：

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
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "memcpy_resolver"), {
    onEnter: function(args) {
        console.log("[+] memcpy_resolver called!");
        console.log("    hwcap: " + args[0]);
        // 可以进一步解析 hwcap 的值来判断具体的硬件特性
    },
    onLeave: function(retval) {
        console.log("[+] memcpy_resolver returned: " + retval);
        // 可以尝试解析返回值，查看返回的是哪个具体的 memcpy 实现
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**这个 Frida 脚本的功能：**

1. 连接到目标 Android 应用程序。
2. 使用 `Interceptor.attach` hook 了 `libc.so` 中的 `memcpy_resolver` 函数。
3. `onEnter` 函数在 `memcpy_resolver` 函数被调用时执行，打印日志信息，包括 `hwcap` 的值。
4. `onLeave` 函数在 `memcpy_resolver` 函数返回时执行，打印返回值，即实际选择的 `memcpy` 函数的地址。

通过运行这个脚本并在应用程序中触发对 `memcpy` 的调用，你可以观察到 `memcpy_resolver` 的执行过程以及它根据 `hwcap` 选择的 `memcpy` 实现。 这可以帮助理解 ifuncs 在 Android 系统中的工作方式。

总而言之，`bionic_ifuncs.handroid.h` 定义了 Android Bionic 库中用于实现函数动态分发的机制，它允许系统在运行时根据硬件特性选择最佳的函数实现，从而提高性能和兼容性。 开发者通常不需要直接操作这个文件，但了解其工作原理有助于理解 Android 系统底层的优化策略。

### 提示词
```
这是目录为bionic/libc/private/bionic_ifuncs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>
#include <sys/ifunc.h>

#include <private/bionic_call_ifunc_resolver.h>

#if defined(__aarch64__)
#define IFUNC_ARGS (uint64_t hwcap __attribute__((unused)), \
                    __ifunc_arg_t* arg __attribute__((unused)))
#elif defined(__arm__)
#define IFUNC_ARGS (unsigned long hwcap __attribute__((unused)))
#else
#define IFUNC_ARGS ()
#endif

#define DECLARE_FUNC(type, name) \
    __attribute__((visibility("hidden"))) \
    type name

#define RETURN_FUNC(type, name) { \
        DECLARE_FUNC(type, name); \
        return name; \
    }

#if defined(BIONIC_DYNAMIC_DISPATCH)

// We can't have HWASAN enabled in resolvers because they may be called before
// HWASAN is initialized.
#define DEFINE_IFUNC_FOR(name)                                  \
  name##_func_t name __attribute__((ifunc(#name "_resolver"))); \
  __attribute__((visibility("hidden")))                         \
  __attribute__((no_sanitize("hwaddress"))) name##_func_t* name##_resolver IFUNC_ARGS

#define DEFINE_STATIC_SHIM(x)

#elif defined(BIONIC_STATIC_DISPATCH)

#define DEFINE_IFUNC_FOR(name)               \
  name##_func_t* name##_resolver IFUNC_ARGS; \
  __attribute__((visibility("hidden")))      \
  __attribute__((no_sanitize("hwaddress"))) name##_func_t* name##_resolver IFUNC_ARGS

#define DEFINE_STATIC_SHIM(x) x

#define FORWARD(name)                                                               \
  static name##_func_t* fn = reinterpret_cast<name##_func_t*>(                      \
      __bionic_call_ifunc_resolver(reinterpret_cast<ElfW(Addr)>(name##_resolver))); \
  return fn

#else
#error neither dynamic nor static dispatch?!
#endif

typedef void* memchr_func_t(const void*, int, size_t);
#define MEMCHR_SHIM()                                                  \
  DEFINE_STATIC_SHIM(void* memchr(const void* src, int ch, size_t n) { \
    FORWARD(memchr)(src, ch, n);                                       \
  })

typedef int memcmp_func_t(const void*, const void*, size_t);
#define MEMCMP_SHIM()                                                         \
  DEFINE_STATIC_SHIM(int memcmp(const void* lhs, const void* rhs, size_t n) { \
    FORWARD(memcmp)(lhs, rhs, n);                                             \
  })

typedef void* memcpy_func_t(void*, const void*, size_t);
#define MEMCPY_SHIM()                                                     \
  DEFINE_STATIC_SHIM(void* memcpy(void* dst, const void* src, size_t n) { \
    FORWARD(memcpy)(dst, src, n);                                         \
  })

typedef void* memmove_func_t(void*, const void*, size_t);
#define MEMMOVE_SHIM()                                                     \
  DEFINE_STATIC_SHIM(void* memmove(void* dst, const void* src, size_t n) { \
    FORWARD(memmove)(dst, src, n);                                         \
  })

typedef int memrchr_func_t(const void*, int, size_t);
#define MEMRCHR_SHIM()                                                \
  DEFINE_STATIC_SHIM(int memrchr(const void* src, int ch, size_t n) { \
    FORWARD(memrchr)(src, ch, n);                                     \
  })

typedef void* memset_func_t(void*, int, size_t);
#define MEMSET_SHIM() \
  DEFINE_STATIC_SHIM(void* memset(void* dst, int ch, size_t n) { FORWARD(memset)(dst, ch, n); })

typedef void* __memset_chk_func_t(void*, int, size_t, size_t);
#define __MEMSET_CHK_SHIM()                                                       \
  DEFINE_STATIC_SHIM(void* __memset_chk(void* dst, int ch, size_t n, size_t n2) { \
    FORWARD(__memset_chk)(dst, ch, n, n2);                                        \
  })

typedef char* stpcpy_func_t(char*, const char*);
#define STPCPY_SHIM() \
  DEFINE_STATIC_SHIM(char* stpcpy(char* dst, const char* src) { FORWARD(stpcpy)(dst, src); })

typedef char* strcat_func_t(char*, const char*);
#define STRCAT_SHIM() \
  DEFINE_STATIC_SHIM(char* strcat(char* dst, const char* src) { FORWARD(strcat)(dst, src); })

typedef char* __strcat_chk_func_t(char*, const char*, size_t);
#define __STRCAT_CHK_SHIM()                                                                \
  DEFINE_STATIC_SHIM(char* __strcat_chk(char* dst, const char* src, size_t dst_buf_size) { \
    FORWARD(__strcat_chk)(dst, src, dst_buf_size);                                         \
  })

typedef char* strchr_func_t(const char*, int);
#define STRCHR_SHIM() \
  DEFINE_STATIC_SHIM(char* strchr(const char* src, int ch) { FORWARD(strchr)(src, ch); })

typedef char* strchrnul_func_t(const char*, int);
#define STRCHRNUL_SHIM() \
  DEFINE_STATIC_SHIM(char* strchrnul(const char* src, int ch) { FORWARD(strchrnul)(src, ch); })

typedef int strcmp_func_t(const char*, const char*);
#define STRCMP_SHIM() \
  DEFINE_STATIC_SHIM(int strcmp(char* lhs, const char* rhs) { FORWARD(strcmp)(lhs, rhs); })

typedef char* strcpy_func_t(char*, const char*);
#define STRCPY_SHIM() \
  DEFINE_STATIC_SHIM(char* strcpy(char* dst, const char* src) { FORWARD(strcpy)(dst, src); })

typedef char* __strcpy_chk_func_t(char*, const char*, size_t);
#define __STRCPY_CHK_SHIM()                                                           \
  DEFINE_STATIC_SHIM(char* __strcpy_chk(char* dst, const char* src, size_t dst_len) { \
    FORWARD(__strcpy_chk)(dst, src, dst_len);                                         \
  })

typedef size_t strlen_func_t(const char*);
#define STRLEN_SHIM() DEFINE_STATIC_SHIM(size_t strlen(const char* s) { FORWARD(strlen)(s); })

typedef char* strncat_func_t(char*, const char*, size_t);
#define STRNCAT_SHIM()                                                     \
  DEFINE_STATIC_SHIM(char* strncat(char* dst, const char* src, size_t n) { \
    FORWARD(strncat)(dst, src, n);                                         \
  })

typedef int strncmp_func_t(const char*, const char*, size_t);
#define STRNCMP_SHIM()                                                         \
  DEFINE_STATIC_SHIM(int strncmp(const char* lhs, const char* rhs, size_t n) { \
    FORWARD(strncmp)(lhs, rhs, n);                                             \
  })

typedef char* strncpy_func_t(char*, const char*, size_t);
#define STRNCPY_SHIM()                                                     \
  DEFINE_STATIC_SHIM(char* strncpy(char* dst, const char* src, size_t n) { \
    FORWARD(strncpy)(dst, src, n);                                         \
  })

typedef size_t strnlen_func_t(const char*, size_t);
#define STRNLEN_SHIM() \
  DEFINE_STATIC_SHIM(size_t strnlen(const char* s, size_t n) { FORWARD(strnlen)(s, n); })

typedef char* strrchr_func_t(const char*, int);
#define STRRCHR_SHIM() \
  DEFINE_STATIC_SHIM(char* strrchr(const char* src, int ch) { FORWARD(strrchr)(src, ch); })
```