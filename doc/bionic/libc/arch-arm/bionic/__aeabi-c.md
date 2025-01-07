Response:
Let's break down the thought process for answering the user's request about `bionic/__aeabi.c`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `bionic/__aeabi.c` within the context of Android Bionic. The request is quite comprehensive, asking for:

* **Functionality Listing:**  What does this file do?
* **Android Relevance:** How does it tie into Android?
* **Detailed Explanations:** How are the individual functions implemented?
* **Dynamic Linker Aspects:** How does it interact with the dynamic linker, including SO layout and linking process?
* **Logical Reasoning:**  Demonstrate understanding through hypothetical inputs/outputs (though the code itself doesn't lend itself strongly to direct input/output examples in the traditional sense).
* **Common Errors:** What mistakes do developers make when using these kinds of functions?
* **Tracing Execution:** How does execution reach this code from Android Framework/NDK, with Frida examples?

**2. Initial Analysis of the Code:**

The first step is to read the code and identify the key elements. I notice:

* **`#include` directives:** Standard headers like `stddef.h` and `string.h` suggest basic memory manipulation functions.
* **`extern int __cxa_atexit(...)`:** This immediately points to C++ exception handling and the registration of exit handlers.
* **`__attribute__((weak))`:** This is crucial. It means these functions can be overridden by other libraries (like `libstdc++`). This tells me these aren't the *primary* implementations, but rather provided as defaults or for compatibility.
* **Function naming convention:** `__aeabi_*` clearly indicates adherence to the ARM EABI (Embedded Application Binary Interface).
* **Implementation using standard C library functions:**  Functions like `__aeabi_memcpy*` simply call `memcpy`, `__aeabi_memmove*` call `memmove`, and `__aeabi_memset*` call `memset`. This suggests these `__aeabi_*` functions are thin wrappers.
* **`__aeabi_memclr*` implementation:** They call `__aeabi_memset*` with 0, indicating they are specifically for zeroing memory.
* **`__AEABI_SYMVERS` macro:**  This is important for versioning symbols, crucial for maintaining compatibility when libraries evolve. The `@LIBC_N` and `@LIBC_PRIVATE` suffixes are key to understanding how the linker resolves symbols.

**3. Categorizing and Answering Each Part of the Request:**

Now I can systematically address each point in the user's request:

* **功能列举 (Functionality Listing):** Based on the code, the primary function is providing ARM EABI compliant versions of memory manipulation functions (`memcpy`, `memmove`, `memset`, `memclr`) and atexit registration (`__aeabi_atexit`).

* **与 Android 功能的关系 (Relationship with Android):**  These functions are fundamental building blocks for any C/C++ code running on Android. I need to give specific examples of how they are used (e.g., copying data between buffers, initializing data structures, registering cleanup routines for C++ objects).

* **详细解释 libc 函数的实现 (Detailed Explanation of libc Function Implementation):** Since the `__aeabi_*` functions mostly call the standard C library functions, the explanation will focus on `memcpy`, `memmove`, and `memset`. I'll need to describe their basic behavior and the key difference between `memcpy` and `memmove` (handling overlapping memory regions). It's important to emphasize that the *implementation* of these core functions is often optimized at a lower level (assembly) for performance, even though the wrappers in this file use the standard C versions.

* **涉及 dynamic linker 的功能 (Dynamic Linker Functionality):**  `__aeabi_atexit` directly interacts with the dynamic linker by calling `__cxa_atexit`. I need to explain:
    * **SO Layout Sample:** A simplified example showing code, data, and GOT/PLT sections.
    * **Linking Process:** Focus on how the dynamic linker resolves symbols like `__cxa_atexit` at runtime, and how the `dso_handle` parameter is used. The versioning mechanism (`LIBC_N`, `LIBC_PRIVATE`) is crucial here.

* **逻辑推理 (Logical Reasoning):** While direct input/output for the memory functions is straightforward, for `__aeabi_atexit`, I can create a scenario where a static C++ object registers its destructor using this function.

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Focus on common mistakes with `memcpy`, `memmove`, and `memset`, such as buffer overflows, incorrect size parameters, and misunderstanding the behavior with overlapping memory. For `atexit`, forgetting to unregister or double registration could be mentioned.

* **说明 Android framework or ndk 是如何一步步的到达这里 (Tracing Execution from Framework/NDK):** This requires a high-level explanation of the call stack. Starting from Java in the Android Framework, down to native code via JNI, eventually leading to the execution of C/C++ code that might use these functions. For the Frida example, I need to show how to hook these functions and inspect their arguments and return values.

**4. Refining the Language and Structure:**

Finally, I'll organize the information logically, use clear and concise language, and ensure the Chinese translation is accurate and natural. I will use formatting (like bolding and bullet points) to improve readability. It's also important to be explicit about the "weak symbol" nature of these functions and the implications for overriding.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to break down the complex request into smaller, manageable parts, analyze the code thoroughly, and connect the individual components to the broader context of Android and the ARM EABI.
这个文件 `bionic/libc/arch-arm/bionic/__aeabi.c` 是 Android Bionic C 库中针对 ARM 架构的一个源文件。它主要提供了对 ARM EABI (Embedded Application Binary Interface) 标准中定义的一些函数的实现。这些函数通常是编译器在生成代码时，为了实现某些语言特性（例如 C++ 的全局对象的构造和析构），或者为了进行底层的内存操作而引入的。

**它的主要功能包括：**

1. **静态对象析构注册 (`__aeabi_atexit`)**: 用于注册在程序退出时需要执行的析构函数，主要用于 C++ 的全局或静态对象的销毁。

2. **内存操作函数 (`__aeabi_memcpy*`, `__aeabi_memmove*`, `__aeabi_memset*`, `__aeabi_memclr*`)**: 提供了一系列内存复制、移动和填充的函数。这些函数名带有 `_impl` 后缀，并且被声明为弱符号，这意味着如果有更强的定义（例如来自 `libc.so` 或其他库），链接器会优先选择更强的定义。

**与 Android 功能的关系及举例说明：**

* **C++ 静态对象的生命周期管理:** Android 系统中很多组件和服务是用 C++ 编写的。这些 C++ 代码中可能包含全局或静态对象。当这些对象需要析构时，编译器会生成调用 `__aeabi_atexit` 的代码来注册析构函数。例如，一个服务启动时创建了一个全局的单例对象，当服务关闭时，就需要调用该对象的析构函数释放资源。`__aeabi_atexit` 保证了这个析构函数在合适的时机被调用。

* **底层内存操作:**  在 Android 的各种库和组件中，经常需要进行内存的复制、移动和填充操作。虽然通常会直接使用 `memcpy`、`memmove` 和 `memset`，但编译器在某些情况下可能会生成对 `__aeabi_memcpy*` 等函数的调用。例如，在进行数据序列化和反序列化，或者在操作底层硬件缓冲区时，可能会用到这些内存操作函数。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个文件中的函数实现非常简单，它们实际上是对标准 C 库函数 (`memcpy`, `memmove`, `memset`) 的简单封装。

* **`__aeabi_atexit_impl` 和 `__aeabi_atexit_impl2`**: 这两个函数都调用了 `__cxa_atexit`。`__cxa_atexit` 是 C++ ABI 定义的用于注册退出函数的函数，它可以处理异常相关的清理工作。它的功能是将传入的析构函数及其对象信息添加到程序退出时需要执行的函数列表中。当程序正常退出或由于某些异常终止时，动态链接器会调用这些注册的函数。

* **`__aeabi_memcpy*_impl` 和 `__aeabi_memcpy*_impl2`**: 这些函数直接调用了 `memcpy`。`memcpy(dest, src, n)` 的功能是从源地址 `src` 复制 `n` 个字节的数据到目标地址 `dest`。它假设源和目标内存区域不重叠。

* **`__aeabi_memmove*_impl` 和 `__aeabi_memmove*_impl2`**: 这些函数直接调用了 `memmove`。`memmove(dest, src, n)` 的功能也是从源地址 `src` 复制 `n` 个字节的数据到目标地址 `dest`。与 `memcpy` 的区别在于，`memmove` 能够正确处理源和目标内存区域重叠的情况。

* **`__aeabi_memset*_impl` 和 `__aeabi_memset*_impl2`**: 这些函数直接调用了 `memset`。`memset(dest, c, n)` 的功能是将从地址 `dest` 开始的 `n` 个字节设置为字符 `c` 的值。

* **`__aeabi_memclr*_impl` 和 `__aeabi_memclr*_impl2`**: 这些函数调用了对应的 `__aeabi_memset*_impl` 函数，并将填充的字符设置为 0。因此，它们的功能是将指定的内存区域清零。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

* **SO 布局样本：**

```
.so 文件结构：

.text          # 代码段
.rodata        # 只读数据段
.data          # 初始化数据段
.bss           # 未初始化数据段
.init_array    # 初始化函数指针数组 (例如，全局对象的构造函数)
.fini_array    # 终止函数指针数组 (例如，全局对象的析构函数 - 通过 __aeabi_atexit 注册)
.dynamic       # 动态链接信息
.got.plt       # 全局偏移表和过程链接表
...           # 其他段
```

* **链接的处理过程：**

1. **编译时：** 当编译器遇到需要注册析构函数的 C++ 代码时，会生成类似以下的汇编指令（简化）：
   ```assembly
   ldr r0, =object_address
   ldr r1, =destructor_function
   ldr r2, =dso_handle_value
   bl __aeabi_atexit
   ```
   这里的 `dso_handle_value` 是动态链接器为当前共享对象生成的唯一标识。

2. **链接时：** 静态链接器在链接多个目标文件和库时，会将所有对 `__aeabi_atexit` 的引用指向这个 `bionic/__aeabi.c` 中定义的弱符号。

3. **加载时（动态链接）：** 当 Android 系统加载包含上述代码的 `.so` 文件时，动态链接器会执行以下操作：
   * **处理 `.init_array`**: 动态链接器会遍历 `.init_array` 段中的函数指针，并执行这些函数（通常是全局对象的构造函数）。
   * **处理 `__aeabi_atexit` 调用**: 当执行到调用 `__aeabi_atexit` 的代码时，实际上会调用 `bionic/__aeabi.c` 中的 `__aeabi_atexit_impl`，该函数会将析构函数和对象信息注册到动态链接器的内部数据结构中。`dso_handle` 用于标识析构函数属于哪个共享对象，以便在卸载共享对象时也能正确执行析构函数。
   * **符号解析**: 动态链接器会解析 `__cxa_atexit` 的符号，并找到 `libc.so` 中对应的实现。由于 `__aeabi_atexit` 是弱符号，如果 `libstdc++` 或 `compiler-rt` 提供了更强的定义，动态链接器会优先使用那些定义。

4. **程序退出时：** 当程序正常退出（调用 `exit`）或者某些异常发生时，动态链接器会遍历所有已加载的共享对象的 `.fini_array` 段，并执行其中的函数。此外，动态链接器还会遍历通过 `__cxa_atexit` 注册的析构函数列表，并调用这些函数来清理全局和静态对象。

**假设输入与输出（逻辑推理）：**

* **`__aeabi_atexit` 假设：**
    * **输入：**
        * `object`: 指向要销毁的对象的内存地址。
        * `destructor`: 指向析构函数的地址。
        * `dso_handle`: 当前共享对象的句柄。
    * **输出：** 注册成功（通常返回 0）或失败（返回非零值，虽然 `__cxa_atexit` 很少失败）。
    * **实际效果：** 在程序退出时，`destructor(object)` 会被调用。

* **`__aeabi_memcpy` 假设：**
    * **输入：**
        * `dest`: 目标内存地址。
        * `src`: 源内存地址。
        * `n`: 要复制的字节数。
    * **输出：** 返回 `dest`。
    * **实际效果：** `src` 指向的 `n` 个字节的数据被复制到 `dest` 指向的内存区域。

**用户或者编程常见的使用错误：**

* **`__aeabi_atexit` 相关的错误：**
    * **重复注册析构函数：** 如果同一个对象的析构函数被多次注册，程序退出时可能会多次调用析构函数，导致错误。
    * **`dso_handle` 错误：**  虽然 `dso_handle` 由链接器自动生成，但在一些特殊场景下（例如手动创建和加载共享对象），可能会出现 `dso_handle` 不正确的情况，导致析构函数无法正确关联到所属的共享对象。

* **`__aeabi_memcpy`, `__aeabi_memmove`, `__aeabi_memset`, `__aeabi_memclr` 相关的错误：**
    * **缓冲区溢出：** 复制或填充的数据量超过了目标缓冲区的容量。例如，`memcpy(dest, src, large_size)`，如果 `dest` 指向的缓冲区小于 `large_size`，就会发生溢出。
    * **源地址或目标地址无效：** 指针指向的内存区域未分配或已被释放。
    * **`memcpy` 用于重叠内存区域：** 当源和目标内存区域重叠时，使用 `memcpy` 可能会导致数据损坏。应该使用 `memmove` 来处理这种情况。
    * **`memset` 的参数顺序错误：**  `memset` 的参数顺序是 `dest`, `value`, `count`。容易与某些其他内存操作函数的参数顺序混淆。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

1. **Android Framework (Java 代码)：**
   * 在 Android Framework 的 Java 代码中，可能会通过 JNI (Java Native Interface) 调用 Native 代码。

2. **NDK (Native 代码)：**
   * NDK 开发的 C/C++ 代码可能会使用到需要注册析构函数的 C++ 对象，或者进行底层的内存操作。

3. **编译器生成代码：**
   * 当 C++ 代码中存在全局或静态对象时，编译器会自动生成调用 `__aeabi_atexit` 来注册析构函数的代码。
   * 当进行内存复制、移动或填充操作时，编译器可能会根据优化策略生成对 `__aeabi_memcpy*` 等函数的调用。

4. **动态链接器加载：**
   * 当包含这些 Native 代码的共享库被加载时，动态链接器会处理 `.init_array` 和 `__aeabi_atexit` 的调用。

5. **执行到 `bionic/__aeabi.c`：**
   * 最终，当程序执行到注册析构函数或执行内存操作的相关代码时，就会调用到 `bionic/__aeabi.c` 中定义的这些函数。

**Frida Hook 示例：**

假设我们要 hook `__aeabi_atexit` 函数来查看何时注册了析构函数：

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"找不到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__aeabi_atexit"), {
    onEnter: function(args) {
        console.log("[*] __aeabi_atexit called");
        console.log("    object: " + args[0]);
        console.log("    destructor: " + args[1]);
        console.log("    dso_handle: " + args[2]);
        // 可以进一步读取内存查看对象和析构函数的内容
    },
    onLeave: function(retval) {
        console.log("[*] __aeabi_atexit returned: " + retval);
    }
});

// Hook memcpy 作为示例
Interceptor.attach(Module.findExportByName("libc.so", "memcpy"), {
    onEnter: function(args) {
        console.log("[*] memcpy called");
        console.log("    dest: " + args[0]);
        console.log("    src: " + args[1]);
        console.log("    n: " + args[2]);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码：**

1. **`frida.get_usb_device().attach(package_name)`**: 连接到目标 Android 设备的指定进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "__aeabi_atexit"), ...)`**:  在 `libc.so` 中找到 `__aeabi_atexit` 函数的导出地址，并附加一个拦截器。
3. **`onEnter`**: 在 `__aeabi_atexit` 函数被调用之前执行的代码。我们打印了函数的参数：要销毁的对象地址、析构函数地址和共享对象句柄。
4. **`onLeave`**: 在 `__aeabi_atexit` 函数执行完毕后执行的代码。我们打印了返回值。
5. **Hook `memcpy`**:  作为另一个例子，展示如何 hook 标准的内存操作函数。

运行此 Frida 脚本，当目标应用执行到 `__aeabi_atexit` 或 `memcpy` 时，Frida 会拦截调用并打印相关信息，帮助我们调试和理解代码的执行流程。  你可以根据需要 hook 其他 `__aeabi_*` 函数来观察它们的行为。

Prompt: 
```
这是目录为bionic/libc/arch-arm/bionic/__aeabi.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

// clang interprets -fno-builtin more loosely than you might expect,
// and thinks it's okay to still substitute builtins as long as they're
// named __aeabi_* rather than __builtin_*, which causes infinite
// recursion if we have the fortified memcpy visible in this file.
#undef _FORTIFY_SOURCE

#include <stddef.h>
#include <string.h>

extern int __cxa_atexit(void (*)(void*), void*, void*);

// All of these are weak symbols to avoid multiple definition errors when
// linking with libstdc++-v3 or compiler-rt.

/* The "C++ ABI for ARM" document states that static C++ constructors,
 * which are called from the .init_array, should manually call
 * __aeabi_atexit() to register static destructors explicitly.
 *
 * Note that 'dso_handle' is the address of a magic linker-generate
 * variable from the shared object that contains the constructor/destructor
 */

int __attribute__((weak))
__aeabi_atexit_impl(void *object, void (*destructor) (void *), void *dso_handle) {
    return __cxa_atexit(destructor, object, dso_handle);
}

int __attribute__((weak))
__aeabi_atexit_impl2(void *object, void (*destructor) (void *), void *dso_handle) {
    return __cxa_atexit(destructor, object, dso_handle);
}


void __attribute__((weak)) __aeabi_memcpy8_impl(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __attribute__((weak)) __aeabi_memcpy4_impl(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __attribute__((weak)) __aeabi_memcpy_impl(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __attribute__((weak)) __aeabi_memcpy8_impl2(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __attribute__((weak)) __aeabi_memcpy4_impl2(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

void __attribute__((weak)) __aeabi_memcpy_impl2(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}


void __attribute__((weak)) __aeabi_memmove8_impl(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __attribute__((weak)) __aeabi_memmove4_impl(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __attribute__((weak)) __aeabi_memmove_impl(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __attribute__((weak)) __aeabi_memmove8_impl2(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __attribute__((weak)) __aeabi_memmove4_impl2(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

void __attribute__((weak)) __aeabi_memmove_impl2(void *dest, const void *src, size_t n) {
    memmove(dest, src, n);
}

/*
 * __aeabi_memset has the order of its second and third arguments reversed.
 *  This allows __aeabi_memclr to tail-call __aeabi_memset
 */

void __attribute__((weak)) __aeabi_memset8_impl(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __attribute__((weak)) __aeabi_memset4_impl(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __attribute__((weak)) __aeabi_memset_impl(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __attribute__((weak)) __aeabi_memset8_impl2(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __attribute__((weak)) __aeabi_memset4_impl2(void *dest, size_t n, int c) {
    memset(dest, c, n);
}

void __attribute__((weak)) __aeabi_memset_impl2(void *dest, size_t n, int c) {
    memset(dest, c, n);
}


void __attribute__((weak)) __aeabi_memclr8_impl(void *dest, size_t n) {
    __aeabi_memset8_impl(dest, n, 0);
}

void __attribute__((weak)) __aeabi_memclr4_impl(void *dest, size_t n) {
    __aeabi_memset4_impl(dest, n, 0);
}

void __attribute__((weak)) __aeabi_memclr_impl(void *dest, size_t n) {
    __aeabi_memset_impl(dest, n, 0);
}

void __attribute__((weak)) __aeabi_memclr8_impl2(void *dest, size_t n) {
    __aeabi_memset8_impl(dest, n, 0);
}

void __attribute__((weak)) __aeabi_memclr4_impl2(void *dest, size_t n) {
    __aeabi_memset4_impl(dest, n, 0);
}

void __attribute__((weak)) __aeabi_memclr_impl2(void *dest, size_t n) {
    __aeabi_memset_impl(dest, n, 0);
}

#define __AEABI_SYMVERS(fn_name) \
__asm__(".symver " #fn_name "_impl, " #fn_name "@@LIBC_N"); \
__asm__(".symver " #fn_name "_impl2, " #fn_name "@LIBC_PRIVATE")

__AEABI_SYMVERS(__aeabi_atexit);
__AEABI_SYMVERS(__aeabi_memcpy8);
__AEABI_SYMVERS(__aeabi_memcpy4);
__AEABI_SYMVERS(__aeabi_memcpy);
__AEABI_SYMVERS(__aeabi_memmove8);
__AEABI_SYMVERS(__aeabi_memmove4);
__AEABI_SYMVERS(__aeabi_memmove);
__AEABI_SYMVERS(__aeabi_memset8);
__AEABI_SYMVERS(__aeabi_memset4);
__AEABI_SYMVERS(__aeabi_memset);
__AEABI_SYMVERS(__aeabi_memclr8);
__AEABI_SYMVERS(__aeabi_memclr4);
__AEABI_SYMVERS(__aeabi_memclr);

#undef __AEABI_SYMVERS

"""

```