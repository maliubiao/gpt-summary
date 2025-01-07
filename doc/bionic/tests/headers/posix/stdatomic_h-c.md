Response:
Let's break down the thought process for answering the user's request about the `stdatomic_h.c` test file.

**1. Understanding the Core Question:**

The user wants to understand the *purpose* and *functionality* of the provided C code snippet. They specifically mention it's a test file for `stdatomic.h` in Android's Bionic library. This immediately signals that the code isn't about *implementing* atomic operations, but rather *verifying* their presence and basic properties.

**2. Initial Analysis of the Code:**

* **Includes:** The code includes `<stdatomic.h>` and `"header_checks.h"`. This confirms it's dealing with the standard atomic header and likely some internal Bionic testing utilities.
* **`stdatomic_h()` Function:** The majority of the code is within this function. This strongly suggests it's a single test case or a collection of related checks.
* **`TYPE()` Macro:** This macro is used extensively with various atomic types (e.g., `atomic_int`, `atomic_bool`). The most probable purpose is to check if these types are defined by `<stdatomic.h>`.
* **`memory_order` Variables:**  The code declares and initializes variables of type `memory_order`. This indicates testing the presence of the different memory ordering constants.
* **`MACRO()` Macro:** Similar to `TYPE()`, this likely checks for the definition of specific macros related to atomics (e.g., `ATOMIC_INT_LOCK_FREE`).
* **`ATOMIC_FLAG_INIT` and `ATOMIC_VAR_INIT`:** These are used to initialize atomic variables, suggesting a check for these initialization mechanisms.
* **`kill_dependency()`:** This function call hints at testing compiler optimizations or dependency breaking related to atomic operations.
* **Conditional `#error` Directives:** The numerous `#if !defined(...) #error ... #endif` blocks are crucial. They are designed to *fail compilation* if a particular atomic function is *not* defined. This is a primary way to verify the presence of the required atomic functions.
* **`FUNCTION()` Macro:** This is likely used to check the *type signature* of atomic functions (return type and argument types).

**3. Formulating the Core Functionality:**

Based on the above analysis, the primary function of this code is to **verify the presence and basic correctness of the `<stdatomic.h>` header file provided by Bionic.**  It checks for the definition of:

* Atomic types
* Memory ordering constants
* Lock-free guarantees macros
* Initialization macros
* Atomic operations functions

**4. Connecting to Android Functionality:**

The `stdatomic.h` header provides fundamental building blocks for concurrent programming. Android relies on concurrency extensively in its framework and native components. Therefore, the correct implementation of atomic operations is *essential* for thread safety and preventing race conditions.

**Examples in Android:**

* **Reference Counting:** Atomic counters are frequently used in Android's object management to track references and ensure objects are deallocated correctly.
* **Synchronization Primitives:**  Higher-level synchronization mechanisms (like mutexes and condition variables) often rely on atomic operations for their implementation.
* **Inter-Process Communication (IPC):** Atomic operations can be used to build lock-free data structures for efficient communication between processes.

**5. Explaining Libc Function Implementations:**

Since this is a *test* file, it doesn't *implement* the libc functions. The explanation should focus on the *purpose* of the functions being tested and how they are typically implemented at a lower level (e.g., using assembly instructions or compiler intrinsics). Emphasize that Bionic's implementation details are hidden and might vary by architecture.

**6. Addressing Dynamic Linker Aspects:**

This test file *doesn't directly involve the dynamic linker*. The focus is on the *header file*. Therefore, the response should acknowledge this and explain *why* it's not directly relevant. However, it's worth mentioning that `stdatomic.h` is part of libc, which *is* loaded by the dynamic linker. A brief, general explanation of the dynamic linking process can be included for context. A sample SO layout isn't really applicable here since we aren't looking at the *implementation* of the atomic functions within `libc.so`, but rather the *presence* of the declarations.

**7. Considering Logic, Assumptions, and Errors:**

* **Assumptions:** The primary assumption is that if the code compiles successfully, then the tested elements of `stdatomic.h` are present and correctly defined.
* **Common Errors:** Focus on common mistakes programmers make when using atomics, like incorrect memory ordering, forgetting to initialize atomic variables, or assuming atomicity where it doesn't exist.

**8. Tracing Back from Android Framework/NDK:**

The goal is to show how a developer's code might eventually lead to the usage of `stdatomic.h`. The path involves:

1. **NDK Usage:**  A developer writing native code using the NDK includes `<atomic>`.
2. **NDK's `<atomic>`:** The NDK's `<atomic>` header (or directly `<stdatomic.h>`) includes the Bionic's `<stdatomic.h>`.
3. **Bionic's Implementation:** Bionic provides the actual implementation of the atomic operations.

The Frida hook example should target a point where atomic operations are being used, demonstrating how to observe their behavior.

**9. Structuring the Response:**

Organize the answer clearly, addressing each part of the user's request:

* Functionality of the test file.
* Relationship to Android.
* Explanation of libc functions (focus on purpose, not implementation details in *this* file).
* Dynamic linker (explain lack of direct involvement).
* Logic/Assumptions/Errors.
* Android framework/NDK path.
* Frida hook example.

**Self-Correction/Refinement:**

During the thought process, I might initially think about explaining the assembly instructions for atomic operations. However, realizing this is a *test* file, I would shift the focus to the *declarations* and *verification* aspect. Similarly, I might initially overemphasize the dynamic linker, but then realize its indirect role and adjust the explanation accordingly. The key is to stay focused on what the *given code* is actually doing.
这个文件 `bionic/tests/headers/posix/stdatomic_h.c` 是 Android Bionic 库中的一个测试文件。它的主要功能是**检查 `<stdatomic.h>` 头文件是否按预期定义了各种原子类型、宏和函数**。 换句话说，它是一个**编译时测试**，用于确保 Bionic 提供的原子操作支持符合 C11 标准。

**功能列表:**

1. **检查原子类型定义:**  它使用 `TYPE()` 宏来检查诸如 `atomic_flag`, `atomic_int`, `atomic_bool` 等各种原子类型是否被正确定义。这包括不同大小的整数类型（`atomic_short`，`atomic_long`，`atomic_llong` 等），以及特定用途的类型（`atomic_size_t`，`atomic_ptrdiff_t`）。
2. **检查内存顺序宏定义:** 它检查 `memory_order_relaxed`, `memory_order_consume`, `memory_order_acquire`, `memory_order_release`, `memory_order_acq_rel`, `memory_order_seq_cst` 这些用于指定内存访问顺序的宏是否被定义。
3. **检查原子操作的锁自由宏定义:** 它检查 `ATOMIC_BOOL_LOCK_FREE`, `ATOMIC_CHAR_LOCK_FREE`, `ATOMIC_INT_LOCK_FREE` 等宏，这些宏指示了特定原子类型上的操作是否可以无锁实现。
4. **检查原子变量初始化宏定义:** 它检查 `ATOMIC_FLAG_INIT` 和 `ATOMIC_VAR_INIT` 这些用于初始化原子变量的宏是否被定义。
5. **检查 `kill_dependency` 函数的存在:** 尽管 `kill_dependency` 不是 `<stdatomic.h>` 标准的一部分，但 Bionic 可能会提供它作为优化或内部使用的工具。这个测试检查它的存在。
6. **检查原子比较交换函数的定义:**  它使用 `#if !defined(...) #error ... #endif` 预处理指令来检查诸如 `atomic_compare_exchange_strong`, `atomic_compare_exchange_weak` 及其显式版本等关键的原子比较交换函数是否被定义。如果这些函数未定义，编译将失败。
7. **检查其他原子操作函数的定义:** 类似地，它检查 `atomic_exchange`, `atomic_fetch_add`, `atomic_fetch_and`, `atomic_fetch_or`, `atomic_fetch_sub`, `atomic_fetch_xor`, `atomic_init`, `atomic_is_lock_free`, `atomic_load`, `atomic_store` 及其显式版本等其他重要的原子操作函数是否被定义。
8. **检查原子标志操作函数的定义:** 它使用 `FUNCTION()` 宏来检查 `atomic_flag_clear`, `atomic_flag_test_and_set` 及其显式版本等原子标志操作函数的类型签名是否正确。
9. **检查内存屏障函数的定义:** 它检查 `atomic_signal_fence` 和 `atomic_thread_fence` 这两个用于插入内存屏障的函数是否被定义。

**与 Android 功能的关系及举例:**

`stdatomic.h` 提供的原子操作是构建并发安全代码的基础。Android 作为一个多线程操作系统，其框架和应用程序的许多部分都依赖于原子操作来实现线程同步和避免数据竞争。

**举例:**

* **Android Framework 中的引用计数:**  许多 Android 系统服务和对象使用引用计数来管理内存。原子操作（例如 `atomic_fetch_add` 和 `atomic_fetch_sub`) 被用来安全地增加和减少引用计数，防止在多线程环境下的资源提前释放或内存泄漏。
* **Java 虚拟机 (Dalvik/ART) 的内部同步:**  Android 的 Java 虚拟机内部也使用原子操作来实现各种同步机制，例如对象锁的获取和释放。
* **NDK 开发中的并发编程:**  使用 NDK 进行原生开发的开发者可以使用 `<stdatomic.h>` 中提供的原子操作来编写高效且线程安全的并发代码，例如实现无锁数据结构。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件本身 **并不实现** 任何 libc 函数。它的目的是验证这些函数是否被定义。  `<stdatomic.h>` 中声明的原子操作函数的具体实现位于 Bionic 库的底层，通常会利用 CPU 提供的原子指令来实现。

例如：

* **`atomic_load`:**  它的功能是原子地读取一个原子变量的值。在底层，它可能会被编译成一条原子加载指令，例如 x86 架构上的 `MOV` 指令加上 `LOCK` 前缀，或者 ARM 架构上的 `LDADD` 或类似的原子加载指令。
* **`atomic_store`:**  它的功能是原子地将一个值存储到一个原子变量中。底层实现可能使用原子存储指令，例如 x86 的 `XCHG` 或 ARM 的 `STREX` 和 `STCLR` 指令序列。
* **`atomic_compare_exchange_strong` 和 `atomic_compare_exchange_weak`:**  这些函数尝试原子地比较原子变量的当前值和一个期望值，如果相等，则将原子变量的值设置为一个新值。  底层实现通常使用 CPU 提供的比较并交换指令（Compare-and-Swap, CAS），例如 x86 的 `CMPXCHG` 或 ARM 的 `LDREX` 和 `STREX` 指令序列。`strong` 版本保证在伪失败（spurious failure）时会重试，而 `weak` 版本可能不需要。
* **`atomic_fetch_add`:**  原子地将一个值加到原子变量上，并返回原始值。底层实现可能使用原子加法指令，例如 x86 的 `LOCK ADD` 或 ARM 的 `LDADD`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个测试文件本身 **并不直接涉及 dynamic linker 的功能**。 它测试的是 `<stdatomic.h>` 头文件的内容，而不是动态链接的过程。

然而，`stdatomic.h` 中声明的原子操作函数的实现最终会被链接到 `libc.so` 中。 当应用程序或库使用这些原子操作时，dynamic linker 负责在运行时将这些符号解析到 `libc.so` 中对应的函数地址。

**so 布局样本 (简化):**

```
libc.so:
    .text:
        atomic_load:  # 原子加载函数的代码
            ...
        atomic_store: # 原子存储函数的代码
            ...
        atomic_compare_exchange_strong: # 原子比较交换函数的代码
            ...
        ...
    .data:
        ...
    .dynamic:
        ...
        NEEDED    libm.so  # 可能依赖 math 库
        SONAME    libc.so
        ...
    .symtab:
        atomic_load  (address in .text)
        atomic_store (address in .text)
        atomic_compare_exchange_strong (address in .text)
        ...
    .strtab:
        atomic_load
        atomic_store
        atomic_compare_exchange_strong
        libm.so
        libc.so
        ...
```

**链接的处理过程 (简化):**

1. **编译时:** 编译器遇到使用原子操作的代码（例如调用 `atomic_load`）。它会生成对 `atomic_load` 符号的未解析引用。
2. **链接时:** 静态链接器将应用程序或库的目标文件链接在一起，仍然保留对 `atomic_load` 等符号的未解析引用。`.dynamic` 段会记录需要链接的共享库（例如 `libc.so`）。
3. **运行时:** 当程序被加载执行时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * 加载所有必要的共享库，包括 `libc.so`。
    * 遍历应用程序和共享库的 `.dynamic` 段，找到需要解析的符号。
    * 在已加载的共享库的符号表 (`.symtab`) 中查找这些符号的地址。例如，它会在 `libc.so` 的符号表中查找 `atomic_load` 的地址。
    * 将找到的地址填入应用程序或库中对这些符号的引用位置，完成符号解析或重定位。

**如果做了逻辑推理，请给出假设输入与输出:**

这个测试文件主要进行编译时检查，不涉及运行时输入和输出。它的 "输出" 是编译是否成功。

**假设输入:** 编译器尝试编译 `bionic/tests/headers/posix/stdatomic_h.c` 文件。

**可能的输出:**

* **成功:** 如果 `<stdatomic.h>` 文件正确定义了所有预期的类型、宏和函数，编译将成功完成，没有任何错误或警告。
* **失败:** 如果 `<stdatomic.h>` 文件缺少某些定义（例如某个原子类型或函数未声明），则编译器会因为 `#error` 指令而报错，指出缺少了哪个定义。例如，如果 `atomic_compare_exchange_strong` 未定义，编译器会输出包含 `"error: atomic_compare_exchange_strong"` 的错误信息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然此测试文件不直接展示用户错误，但了解 `<stdatomic.h>` 的常见使用错误有助于理解其重要性：

1. **不正确的内存顺序:**  错误地选择 `memory_order` 参数可能导致数据竞争或意外的程序行为。例如，如果多个线程修改同一个原子变量，而读取线程使用了 `memory_order_relaxed`，它可能观察到不一致的值。
2. **忘记初始化原子变量:** 像普通变量一样，原子变量也需要在使用前进行初始化。忘记初始化会导致未定义行为。应该使用 `ATOMIC_VAR_INIT` 或 `atomic_init` 进行初始化。
3. **误用非原子操作访问共享变量:**  即使程序中使用了原子操作，也需要确保对共享变量的其他访问也是线程安全的。混合使用原子和非原子操作可能会破坏原子操作提供的保障。
4. **ABA 问题:**  在使用 `atomic_compare_exchange_weak` 时需要注意 ABA 问题。如果一个原子变量的值从 A 变为 B，然后再变回 A，`weak` 比较交换可能会错误地认为值没有改变。
5. **过度使用顺序一致性 (`memory_order_seq_cst`):**  虽然顺序一致性提供了最强的保证，但它也可能带来性能开销。在不需要如此强的保证时，使用更宽松的内存顺序可以提高性能。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发:**  一个 Android 开发者使用 NDK 编写 C/C++ 代码，需要在多个线程之间共享数据并进行同步。他决定使用 `<stdatomic.h>` 提供的原子操作，例如 `atomic_int` 和 `atomic_fetch_add`。

   ```c++
   #include <stdatomic.h>
   #include <pthread.h>

   atomic_int counter = ATOMIC_VAR_INIT(0);

   void* thread_func(void*) {
       for (int i = 0; i < 10000; ++i) {
           atomic_fetch_add(&counter, 1);
       }
       return nullptr;
   }

   // ... 创建并启动多个线程 ...
   ```

2. **编译和链接:**  当使用 NDK 工具链编译这段代码时，编译器会找到并解析 `<stdatomic.h>` 头文件。链接器会将对 `atomic_fetch_add` 等函数的引用链接到 Bionic 库 (`libc.so`) 中提供的实现。

3. **运行时加载:** 当包含这段代码的应用程序在 Android 设备上运行时，Android 的 zygote 进程会 fork 出新的进程来运行该应用。dynamic linker 会加载应用程序依赖的共享库，包括 `libc.so`。

4. **符号解析:** dynamic linker 会解析应用程序中对 `atomic_fetch_add` 的调用，将其指向 `libc.so` 中 `atomic_fetch_add` 函数的实际地址。

**Frida Hook 示例:**

假设你想观察 `atomic_fetch_add` 函数被调用的情况和参数。可以使用 Frida hook 这个函数：

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "atomic_fetch_add"), {
    onEnter: function(args) {
        var atomic_ptr = ptr(args[0]);
        var increment = args[1].toInt32();
        var currentValue = atomic_ptr.readInt();
        console.log("[*] atomic_fetch_add called!");
        console.log("    Atomic Variable Address:", atomic_ptr);
        console.log("    Current Value:", currentValue);
        console.log("    Increment:", increment);
    },
    onLeave: function(retval) {
        console.log("    Previous Value returned:", retval.toInt32());
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

* **`frida.get_usb_device().attach(package_name)`:** 连接到目标 Android 设备上运行的指定包名的应用程序进程。
* **`Module.findExportByName("libc.so", "atomic_fetch_add")`:** 在 `libc.so` 模块中查找 `atomic_fetch_add` 函数的导出地址。
* **`Interceptor.attach(...)`:**  拦截 `atomic_fetch_add` 函数的调用。
* **`onEnter`:**  在 `atomic_fetch_add` 函数被调用之前执行。
    * `args[0]`：指向 `atomic_int` 变量的指针。
    * `args[1]`：要增加的值。
    * 代码读取原子变量的当前值并打印相关信息。
* **`onLeave`:** 在 `atomic_fetch_add` 函数执行完毕后执行。
    * `retval`：函数返回的原始值。
* **`script.load()`:** 加载并运行 Frida 脚本。

运行此 Frida 脚本后，每当目标应用程序调用 `atomic_fetch_add` 函数时，Frida 控制台将打印出调用信息，包括原子变量的地址、当前值、增量和函数返回的原始值。这可以帮助你调试和理解 Android 框架或 NDK 代码中原子操作的使用情况。

Prompt: 
```
这是目录为bionic/tests/headers/posix/stdatomic_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2024 The Android Open Source Project
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

#include <stdatomic.h>

#include "header_checks.h"

static void stdatomic_h() {
  TYPE(atomic_flag);
  TYPE(atomic_bool);
  TYPE(atomic_char);
  TYPE(atomic_schar);
  TYPE(atomic_uchar);
  TYPE(atomic_short);
  TYPE(atomic_ushort);
  TYPE(atomic_int);
  TYPE(atomic_uint);
  TYPE(atomic_long);
  TYPE(atomic_ulong);
  TYPE(atomic_llong);
  TYPE(atomic_ullong);
#if !defined(__GLIBC__)
  TYPE(atomic_char16_t);
  TYPE(atomic_char32_t);
#endif
  TYPE(atomic_wchar_t);
  TYPE(atomic_int_least8_t);
  TYPE(atomic_uint_least8_t);
  TYPE(atomic_int_least16_t);
  TYPE(atomic_uint_least16_t);
  TYPE(atomic_int_least32_t);
  TYPE(atomic_uint_least32_t);
  TYPE(atomic_int_least64_t);
  TYPE(atomic_uint_least64_t);
  TYPE(atomic_int_fast8_t);
  TYPE(atomic_uint_fast8_t);
  TYPE(atomic_int_fast16_t);
  TYPE(atomic_uint_fast16_t);
  TYPE(atomic_int_fast32_t);
  TYPE(atomic_uint_fast32_t);
  TYPE(atomic_int_fast64_t);
  TYPE(atomic_uint_fast64_t);
  TYPE(atomic_intptr_t);
  TYPE(atomic_uintptr_t);
  TYPE(atomic_size_t);
  TYPE(atomic_ptrdiff_t);
  TYPE(atomic_intmax_t);
  TYPE(atomic_uintmax_t);

  memory_order m1 = memory_order_relaxed;
  memory_order m2 = memory_order_consume;
  memory_order m3 = memory_order_acquire;
  memory_order m4 = memory_order_release;
  memory_order m5 = memory_order_acq_rel;
  memory_order m6 = memory_order_seq_cst;

  MACRO(ATOMIC_BOOL_LOCK_FREE);
  MACRO(ATOMIC_CHAR_LOCK_FREE);
  MACRO(ATOMIC_CHAR16_T_LOCK_FREE);
  MACRO(ATOMIC_CHAR32_T_LOCK_FREE);
  MACRO(ATOMIC_WCHAR_T_LOCK_FREE);
  MACRO(ATOMIC_SHORT_LOCK_FREE);
  MACRO(ATOMIC_INT_LOCK_FREE);
  MACRO(ATOMIC_LONG_LOCK_FREE);
  MACRO(ATOMIC_LLONG_LOCK_FREE);
  MACRO(ATOMIC_POINTER_LOCK_FREE);

  atomic_flag f = ATOMIC_FLAG_INIT;
  atomic_int i = ATOMIC_VAR_INIT(123);

  i = kill_dependency(i);

#if !defined(atomic_compare_exchange_strong)
#error atomic_compare_exchange_strong
#endif
#if !defined(atomic_compare_exchange_strong_explicit)
#error atomic_compare_exchange_strong_explicit
#endif
#if !defined(atomic_compare_exchange_weak)
#error atomic_compare_exchange_weak
#endif
#if !defined(atomic_compare_exchange_weak_explicit)
#error atomic_compare_exchange_weak_explicit
#endif
#if !defined(atomic_exchange)
#error atomic_exchange
#endif
#if !defined(atomic_exchange_explicit)
#error atomic_exchange_explicit
#endif
#if !defined(atomic_fetch_add)
#error atomic_fetch_add
#endif
#if !defined(atomic_fetch_add_explicit)
#error atomic_fetch_add_explicit
#endif
#if !defined(atomic_fetch_and)
#error atomic_fetch_and
#endif
#if !defined(atomic_fetch_and_explicit)
#error atomic_fetch_and_explicit
#endif
#if !defined(atomic_fetch_or)
#error atomic_fetch_or
#endif
#if !defined(atomic_fetch_or_explicit)
#error atomic_fetch_or_explicit
#endif
#if !defined(atomic_fetch_sub)
#error atomic_fetch_sub
#endif
#if !defined(atomic_fetch_sub_explicit)
#error atomic_fetch_sub_explicit
#endif
#if !defined(atomic_fetch_xor)
#error atomic_fetch_xor
#endif
#if !defined(atomic_fetch_xor_explicit)
#error atomic_fetch_xor_explicit
#endif
#if !defined(atomic_init)
#error atomic_init
#endif
#if !defined(atomic_is_lock_free)
#error atomic_is_lock_free
#endif
#if !defined(atomic_load)
#error atomic_load
#endif
#if !defined(atomic_load_explicit)
#error atomic_load_explicit
#endif
#if !defined(atomic_store)
#error atomic_store
#endif
#if !defined(atomic_store_explicit)
#error atomic_store_explicit
#endif

  FUNCTION(atomic_flag_clear, void (*f)(volatile atomic_flag*));
  FUNCTION(atomic_flag_clear_explicit, void (*f)(volatile atomic_flag*, memory_order));
  FUNCTION(atomic_flag_test_and_set, bool (*f)(volatile atomic_flag*));
  FUNCTION(atomic_flag_test_and_set_explicit, bool (*f)(volatile atomic_flag*, memory_order));

  FUNCTION(atomic_signal_fence, void (*f)(memory_order));
  FUNCTION(atomic_thread_fence, void (*f)(memory_order));
}

"""

```