Response:
Let's break down the thought process for analyzing the `stdatomic.handroid` header file.

**1. Initial Understanding of the Request:**

The request asks for a comprehensive analysis of the provided C header file, specifically focusing on:

* **Functionality:** What does the code do?
* **Android Relevance:** How does it relate to Android's inner workings?
* **Libc Function Implementation:** Detailed explanations of the functions.
* **Dynamic Linker Aspects:** How does it interact with the dynamic linker, including SO layout and linking process?
* **Logic and Assumptions:**  Hypothetical inputs/outputs (though this file is primarily definitions, not implementations, so this is less relevant).
* **Common Errors:** Potential pitfalls when using these features.
* **Android Framework/NDK Path:** How does execution reach this code, with Frida examples.

**2. High-Level Overview of `stdatomic.handroid`:**

The first step is to recognize that this is a header file (`.h`) defining *atomic operations*. Atomic operations are fundamental for concurrent programming, ensuring that operations on shared data are performed as a single, indivisible unit, preventing race conditions. The file name `stdatomic.handroid` strongly suggests it's Android's implementation of the C11 standard's `<stdatomic.h>`.

**3. Deconstructing the Header File - Section by Section:**

Now, go through the file logically, section by section, noting key information:

* **Copyright Notice:** Indicates the origin (FreeBSD) and licensing. This is useful background but not directly functional.
* **Includes:**  `sys/cdefs.h`, `sys/types.h`, `stdbool.h`, `stddef.h`, `stdint.h`, and conditionally `uchar.h`. These tell us about the dependencies and the kinds of data types being used. The conditional inclusion of `uchar.h` for Bionic is important to note for Android-specific behavior.
* **"C: Do it ourselves" Comment:**  This is a crucial hint. It suggests that, at least for some architectures or scenarios, Bionic implements atomics directly rather than relying solely on compiler intrinsics. It also mentions compatibility with C++.
* **Atomic Lock-Free Macros:** These `#ifdef` blocks define macros like `ATOMIC_BOOL_LOCK_FREE`. These macros are typically set by the compiler based on the target architecture and indicate whether atomic operations of a certain size can be implemented without using locks. This is a key performance aspect.
* **Initialization:** `ATOMIC_VAR_INIT` and `atomic_init`. These define how atomic variables are initialized.
* **Memory Ordering:** This section defines constants like `memory_order_relaxed`, `memory_order_acquire`, etc. Understanding memory ordering is critical for correctly using atomics in multithreaded programs. Note the mapping to `__ATOMIC_*` compiler built-ins.
* **Fences:** `atomic_thread_fence` and `atomic_signal_fence`. These are used to enforce ordering constraints between threads and between threads and signal handlers, respectively.
* **Lock-Free Property:** `atomic_is_lock_free`. This function checks if atomic operations on a given object are implemented without locks.
* **Atomic Integer Types:** This is a significant section, defining typedefs for various atomic integer types like `atomic_int`, `atomic_long`, etc. The `_Atomic()` type specifier is the C11 way to declare atomic variables. The conditional inclusion of `atomic_char16_t` and `atomic_char32_t` for Bionic/C++11 is another Android-specific detail.
* **Operations on Atomic Types:**  This section defines macros for performing atomic operations:
    * `atomic_compare_exchange_strong_explicit`, `atomic_compare_exchange_weak_explicit`:  Compare-and-swap operations.
    * `atomic_exchange_explicit`: Atomically exchange values.
    * `atomic_fetch_add_explicit`, etc.: Atomic arithmetic operations.
    * `atomic_load_explicit`, `atomic_store_explicit`: Atomic read and write.
    * Convenience functions without the `_explicit` suffix use sequential consistency (`memory_order_seq_cst`).
* **Atomic Flag Type and Operations:** Defines `atomic_flag` (a simple atomic boolean) and operations like `atomic_flag_test_and_set_explicit` and `atomic_flag_clear_explicit`.

**4. Addressing Specific Questions from the Request:**

* **Functionality:**  The file provides the basic building blocks for atomic operations in C on Android. It allows threads to safely access and modify shared data.
* **Android Relevance:** Atomic operations are crucial for multithreaded components in the Android framework and applications. Examples include managing shared state in system services, synchronization primitives, and concurrent data structures.
* **Libc Function Implementation:** The *header file itself doesn't contain the implementation*. The macros typically expand to compiler intrinsics or calls to library functions (likely within `libc.so`). The comment "C: Do it ourselves" suggests that for some cases, Bionic might provide its own optimized assembly implementations.
* **Dynamic Linker:** While `stdatomic.h` doesn't directly interact with the dynamic linker *during execution*, the presence of these atomic primitives is a requirement for many libraries that the dynamic linker loads. Libraries using threads often rely on atomics. The SO layout example would show `libc.so` containing the underlying implementations (if not using compiler intrinsics). The linking process would ensure that code using `stdatomic.h` can find the necessary symbols in `libc.so`.
* **Logic and Assumptions:** Not much complex logic in this header file, mostly definitions and macro expansions.
* **Common Errors:**  Incorrect memory ordering is a major source of errors. Forgetting atomicity when dealing with shared data in multithreaded contexts is another.
* **Android Framework/NDK Path:**  This requires tracing. The chain could be:  Java code in the Android Framework -> JNI call to native code -> NDK code using `<stdatomic.h>`. The Frida example would involve hooking functions within `libc.so` that implement the atomic operations or potentially directly within the application code.

**5. Structuring the Output:**

Organize the information logically, addressing each point in the request. Use clear headings and examples where appropriate. Explain the concepts of atomicity and memory ordering.

**6. Refining and Adding Detail:**

Review the generated output for accuracy and completeness. Add more specific examples and explanations where needed. For instance, when discussing memory ordering, give concrete examples of how different orderings affect visibility and ordering of operations. Explain the difference between strong and weak compare-and-swap.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focus heavily on the implementation details of each atomic operation.
* **Correction:** Realize that this is a header file, so the *implementation* isn't here. Shift focus to the *definitions* and how they map to underlying mechanisms (compiler intrinsics, potential libc implementations).
* **Initial thought:**  The dynamic linker interaction is direct.
* **Correction:** The interaction is more indirect. `stdatomic.h` defines functionalities needed by libraries that the dynamic linker loads. The dynamic linker itself doesn't directly *use* these functions in its linking process, but it loads libraries that do.
* **Initial thought:**  Provide a very detailed code walkthrough.
* **Correction:**  Focus on the *concepts* and the *purpose* of each section, as a detailed line-by-line walkthrough isn't as insightful for a header file.

By following this structured approach and iteratively refining the understanding, we arrive at the comprehensive and informative answer provided in the initial prompt.
这个目录 `bionic/libc/include/bits/stdatomic.handroid` 下的 `stdatomic.handroid` 文件是 Android Bionic C 库中关于原子操作的头文件。它提供了 C11 标准 `<stdatomic.h>` 中定义的原子类型和操作的声明和宏定义。这个文件是 Android 系统中实现并发和多线程编程的关键组成部分。

**它的功能:**

1. **定义原子类型:**  它定义了各种原子数据类型，例如 `atomic_bool`, `atomic_int`, `atomic_long`, `atomic_pointer` 等。原子类型保证了对这些类型的操作是不可分割的，即在多线程环境下不会发生数据竞争。
2. **提供原子操作宏和函数:** 它定义了用于执行原子操作的宏和内联函数，例如：
    * **原子加载和存储:** `atomic_load`, `atomic_store`, `atomic_load_explicit`, `atomic_store_explicit`。
    * **原子交换:** `atomic_exchange`, `atomic_exchange_explicit`。
    * **原子比较和交换 (CAS):** `atomic_compare_exchange_strong`, `atomic_compare_exchange_weak`, `atomic_compare_exchange_strong_explicit`, `atomic_compare_exchange_weak_explicit`。
    * **原子算术运算:** `atomic_fetch_add`, `atomic_fetch_sub`, `atomic_fetch_and`, `atomic_fetch_or`, `atomic_fetch_xor`，以及它们的 `_explicit` 版本。
    * **原子标志操作:** `atomic_flag`, `atomic_flag_test_and_set`, `atomic_flag_clear`，以及它们的 `_explicit` 版本。
3. **定义内存顺序 (Memory Order):** 它定义了 `memory_order` 枚举，用于指定原子操作的内存顺序，控制不同线程对内存的可见性。这些内存顺序包括 `memory_order_relaxed`, `memory_order_consume`, `memory_order_acquire`, `memory_order_release`, `memory_order_acq_rel`, `memory_order_seq_cst`。
4. **提供原子初始化宏:** `ATOMIC_VAR_INIT` 用于初始化静态的原子变量。 `atomic_init` 用于初始化动态分配的原子变量。
5. **提供查询原子操作是否无锁的函数:** `atomic_is_lock_free` 用于检查特定大小的原子类型是否可以在当前平台上以无锁的方式实现。
6. **提供内存屏障 (Memory Fence):** `atomic_thread_fence` 和 `atomic_signal_fence` 用于强制内存操作的顺序，防止编译器和处理器进行重排序。

**与 Android 功能的关系及举例说明:**

原子操作是构建并发安全代码的基础，在 Android 系统中被广泛使用：

* **Android Framework 中的并发控制:** Android Framework 的许多组件，如 ActivityManagerService (AMS)、WindowManagerService (WMS) 等，都需要处理多线程并发访问共享状态。原子操作被用于实现这些服务的内部同步机制，例如维护活动列表、窗口状态等。
    * **例子:**  在 AMS 中，当启动一个新的 Activity 时，可能需要原子地更新全局的 Activity 计数器和列表，以确保状态的一致性。
* **NDK 开发中的多线程编程:** 使用 NDK 进行原生开发的应用程序经常需要创建和管理线程。原子操作允许开发者安全地在多个线程之间共享数据，而无需显式地使用互斥锁等更重的同步原语。
    * **例子:**  一个图像处理 NDK 库可能使用多个线程并行处理图像的不同部分。原子计数器可以用来跟踪已完成的任务数量。
* **底层系统服务和驱动程序:**  Bionic 作为 Android 的 C 库，其提供的原子操作也被底层的系统服务和驱动程序使用，以确保内核态和用户态之间数据共享的安全性。
    * **例子:**  Binder 驱动程序在处理进程间通信时，可能使用原子操作来管理引用计数。

**libc 函数的功能及其实现:**

这个 `stdatomic.handroid` 文件本身是头文件，只包含声明和宏定义，并不包含实际的函数实现。原子操作的具体实现通常依赖于以下机制：

1. **编译器内置函数 (Compiler Intrinsics):** 现代编译器（如 GCC 和 Clang）提供了内置的原子操作指令，可以直接生成对应的机器码。例如，`__sync_fetch_and_add` 等 GCC 内置函数就被广泛使用。
2. **汇编代码实现:**  对于某些平台或特定的原子操作，Bionic 可能会提供高度优化的汇编代码实现，以确保性能。
3. **互斥锁 (Mutexes):** 在某些情况下，如果硬件不支持某些原子操作的无锁实现，或者为了保证跨平台的兼容性，原子操作可能会退化为使用互斥锁来保护临界区。这通常发生在 `atomic_is_lock_free` 返回 0 的情况下。

**举例说明 `atomic_fetch_add` 的可能实现 (简化版):**

```c
// 假设目标平台支持原子加指令
int atomic_fetch_add(volatile int *object, int operand, memory_order order) {
  int previous;
  // 根据内存顺序执行相应的内存屏障 (这里简化)
  __asm__ volatile (
    "lock; xaddl %1, %0" // x86 的原子加指令
    : "+m" (*object), "=r" (previous)
    : "1" (operand)
    : "memory"
  );
  return previous;
}
```

这个简化的例子展示了如何使用 x86 的 `xaddl` 指令来实现原子加操作。`lock` 前缀确保了指令的原子性。不同的架构会有不同的原子指令。

**涉及 dynamic linker 的功能，so 布局样本及链接处理过程:**

`stdatomic.handroid` 本身并不直接涉及 dynamic linker 的功能。然而，使用了原子操作的库（例如 `libc.so` 本身或其他 NDK 库）在加载时会通过 dynamic linker 进行链接。

**SO 布局样本 (`libc.so`):**

```
libc.so:
    .text:  // 代码段
        // ... 原子操作相关的函数实现 (如果不是完全依赖编译器 intrinsics) ...
    .data:  // 数据段
        // ... 全局变量 ...
    .bss:   // 未初始化数据段
        // ...
    .dynsym: // 动态符号表
        atomic_load
        atomic_store
        atomic_fetch_add
        // ... 其他原子操作相关的符号 ...
    .dynstr: // 动态字符串表
        // ... 包含符号名称的字符串 ...
    .plt:    // 过程链接表 (Procedure Linkage Table) - 如果有跨 SO 的原子操作调用
    .got:    // 全局偏移表 (Global Offset Table) - 如果有跨 SO 的原子操作调用
```

**链接的处理过程:**

1. **编译时:** 当编译器遇到使用了 `<stdatomic.h>` 中定义的原子操作的 C/C++ 代码时，它会生成对这些原子操作符号的引用（例如 `atomic_fetch_add`）。
2. **链接时:** 链接器（对于 Android 来说是 `lld`）会将这些符号引用标记为需要动态链接。
3. **运行时:** 当 Android 系统加载包含这些符号引用的共享库（例如 NDK 编译的 `.so` 文件）时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析这些符号引用。
4. **符号查找:** Dynamic linker 会在已加载的共享库中搜索这些符号的定义。对于原子操作，它们的实现通常位于 `libc.so` 中。
5. **重定位:** 一旦找到符号定义，dynamic linker 会更新调用点的地址，使其指向 `libc.so` 中对应的原子操作实现。

**假设输入与输出 (针对原子操作的例子):**

假设有一个全局原子整数变量 `atomic_int counter = ATOMIC_VAR_INIT(0);`，两个线程同时执行 `atomic_fetch_add(&counter, 1);`。

* **线程 1 执行:**
    * **输入:** `counter` 的当前值（假设为 0），操作数 1。
    * **输出:** 原子地将 `counter` 的值增加 1，并返回 `counter` 的旧值 0。
* **线程 2 执行 (可能在线程 1 执行过程中或之后):**
    * **输入:** `counter` 的当前值（假设线程 1 已经执行，值为 1），操作数 1。
    * **输出:** 原子地将 `counter` 的值增加 1，并返回 `counter` 的旧值 1。

最终，`counter` 的值将变为 2，并且两个线程都获得了它们执行 `atomic_fetch_add` 之前的 `counter` 值。原子性保证了不会出现丢失更新的情况。

**用户或编程常见的使用错误:**

1. **不一致的内存顺序:**  错误地选择或理解内存顺序可能导致数据竞争和未定义的行为。例如，在生产者-消费者模型中，如果生产者使用 `memory_order_relaxed` 存储数据，而消费者使用 `memory_order_relaxed` 加载数据，则消费者可能无法看到生产者写入的数据。
2. **非原子操作与原子操作混合使用:**  如果一个线程使用原子操作访问共享变量，而另一个线程使用非原子操作访问同一个变量，仍然会发生数据竞争。必须保证对共享变量的所有访问都是原子的，或者通过适当的同步机制（如互斥锁）保护。
3. **错误地使用 `atomic_compare_exchange_weak`:**  `atomic_compare_exchange_weak` 可能会虚假失败（即使 `expected` 值与当前值相等）。开发者必须在一个循环中使用它，并正确处理虚假失败的情况。
4. **过度依赖原子操作:**  在某些复杂的并发场景中，仅仅使用原子操作可能难以实现正确的同步逻辑，或者会导致代码过于复杂。有时使用更高级的同步原语（如互斥锁、条件变量、信号量）会更清晰和易于维护。
5. **忽略平台差异:**  虽然 C11 标准定义了原子操作，但不同平台对原子操作的支持程度可能不同。`atomic_is_lock_free` 可以帮助开发者了解当前平台是否提供了无锁的原子操作实现，但需要根据具体情况进行处理。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 示例 (Java 代码触发):**

1. **Java 代码:** Android Framework 的某个组件（例如 AMS）中的 Java 代码需要更新一个共享的状态。
2. **JNI 调用:** Java 代码通过 JNI (Java Native Interface) 调用到 Native 代码（C/C++）。
3. **Native 代码:** Native 代码中使用了 `<stdatomic.h>` 中定义的原子操作来更新共享状态。例如：

   ```c++
   #include <atomic>

   std::atomic_int activity_count = 0;

   void incrementActivityCount() {
       activity_count.fetch_add(1, std::memory_order_relaxed);
   }
   ```

**NDK 示例:**

1. **NDK 代码:**  开发者在 NDK 项目中使用了 `<stdatomic.h>` 进行多线程编程。

**Frida Hook 示例:**

假设我们要 hook `atomic_fetch_add` 函数，查看其参数和返回值。由于 `atomic_fetch_add` 通常会被编译器内联，我们可能需要 hook 更底层的实现，例如 `__atomic_fetch_add_4` (对于 `int`) 或类似的函数，具体取决于架构和编译器。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please ensure the app is running.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "__atomic_fetch_add_4"), {
    onEnter: function(args) {
        console.log("[+] __atomic_fetch_add_4 called");
        console.log("    Object address:", args[0]);
        console.log("    Operand:", args[1]);
        // 读取当前值 (需要注意内存访问)
        console.log("    Current value:", Memory.readU32(args[0]));
    },
    onLeave: function(retval) {
        console.log("    Return value (old value):", retval);
        console.log("    New value:", Memory.readU32(this.args[0]));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤解释:**

1. **找到目标函数:** 使用 `Module.findExportByName(null, "__atomic_fetch_add_4")` 查找 `__atomic_fetch_add_4` 函数的地址。`null` 表示在所有已加载的模块中搜索。
2. **Hook `onEnter`:**  在函数调用前执行 `onEnter` 代码。
    * `args[0]`：指向原子变量的指针。
    * `args[1]`：要添加的操作数。
    * `Memory.readU32(args[0])`：读取原子变量的当前值。
3. **Hook `onLeave`:** 在函数返回后执行 `onLeave` 代码。
    * `retval`：返回值，即原子加操作之前的旧值。
    * `Memory.readU32(this.args[0])`：读取原子操作后的新值。

**注意:**

* 实际需要 hook 的底层函数名称可能因架构和编译器而异。可以使用 `frida-trace` 工具来辅助查找实际调用的函数。
* 直接 hook 底层原子操作函数可能会受到编译器优化和内联的影响。
*  需要小心地处理内存访问，确保读取的地址是有效的。

通过 Frida hook，我们可以动态地观察原子操作的执行过程，包括参数、返回值以及原子变量的变化，从而更好地理解其行为和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/include/bits/stdatomic.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*-
 * Copyright (c) 2011 Ed Schouten <ed@FreeBSD.org>
 *                    David Chisnall <theraven@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdbool.h>

/*
 * C: Do it ourselves.
 * Note that the runtime representation defined here should be compatible
 * with the C++ one, i.e. an _Atomic(T) needs to contain the same
 * bits as a T.
 */

#include <stddef.h>  /* For ptrdiff_t. */
#include <stdint.h>
// Include uchar.h only when available.  Bionic's stdatomic.h is also used for
// the host (via a copy in prebuilts/clang) and uchar.h is not available in the
// glibc used for the host.
#if defined(__BIONIC__)
# include <uchar.h>  /* For char16_t and char32_t.              */
#endif

/*
 * 7.17.1 Atomic lock-free macros.
 */

#ifdef __GCC_ATOMIC_BOOL_LOCK_FREE
#define	ATOMIC_BOOL_LOCK_FREE		__GCC_ATOMIC_BOOL_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_CHAR_LOCK_FREE
#define	ATOMIC_CHAR_LOCK_FREE		__GCC_ATOMIC_CHAR_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_CHAR16_T_LOCK_FREE
#define	ATOMIC_CHAR16_T_LOCK_FREE	__GCC_ATOMIC_CHAR16_T_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_CHAR32_T_LOCK_FREE
#define	ATOMIC_CHAR32_T_LOCK_FREE	__GCC_ATOMIC_CHAR32_T_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_WCHAR_T_LOCK_FREE
#define	ATOMIC_WCHAR_T_LOCK_FREE	__GCC_ATOMIC_WCHAR_T_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_SHORT_LOCK_FREE
#define	ATOMIC_SHORT_LOCK_FREE		__GCC_ATOMIC_SHORT_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_INT_LOCK_FREE
#define	ATOMIC_INT_LOCK_FREE		__GCC_ATOMIC_INT_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_LONG_LOCK_FREE
#define	ATOMIC_LONG_LOCK_FREE		__GCC_ATOMIC_LONG_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_LLONG_LOCK_FREE
#define	ATOMIC_LLONG_LOCK_FREE		__GCC_ATOMIC_LLONG_LOCK_FREE
#endif
#ifdef __GCC_ATOMIC_POINTER_LOCK_FREE
#define	ATOMIC_POINTER_LOCK_FREE	__GCC_ATOMIC_POINTER_LOCK_FREE
#endif

/*
 * 7.17.2 Initialization.
 */

#define	ATOMIC_VAR_INIT(value)		(value)
#define	atomic_init(obj, value)		__c11_atomic_init(obj, value)

/*
 * Clang and recent GCC both provide predefined macros for the memory
 * orderings.  If we are using a compiler that doesn't define them, use the
 * clang values - these will be ignored in the fallback path.
 */

#ifndef __ATOMIC_RELAXED
#define __ATOMIC_RELAXED		0
#endif
#ifndef __ATOMIC_CONSUME
#define __ATOMIC_CONSUME		1
#endif
#ifndef __ATOMIC_ACQUIRE
#define __ATOMIC_ACQUIRE		2
#endif
#ifndef __ATOMIC_RELEASE
#define __ATOMIC_RELEASE		3
#endif
#ifndef __ATOMIC_ACQ_REL
#define __ATOMIC_ACQ_REL		4
#endif
#ifndef __ATOMIC_SEQ_CST
#define __ATOMIC_SEQ_CST		5
#endif

/*
 * 7.17.3 Order and consistency.
 *
 * The memory_order_* constants that denote the barrier behaviour of the
 * atomic operations.
 * The enum values must be identical to those used by the
 * C++ <atomic> header.
 */

typedef enum {
	memory_order_relaxed = __ATOMIC_RELAXED,
	memory_order_consume = __ATOMIC_CONSUME,
	memory_order_acquire = __ATOMIC_ACQUIRE,
	memory_order_release = __ATOMIC_RELEASE,
	memory_order_acq_rel = __ATOMIC_ACQ_REL,
	memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#define kill_dependency(y) (y)

/*
 * 7.17.4 Fences.
 */

static __inline void atomic_thread_fence(memory_order __order __attribute__((__unused__))) {
	__c11_atomic_thread_fence(__order);
}

static __inline void atomic_signal_fence(memory_order __order __attribute__((__unused__))) {
	__c11_atomic_signal_fence(__order);
}

/*
 * 7.17.5 Lock-free property.
 */

#define	atomic_is_lock_free(obj) __c11_atomic_is_lock_free(sizeof(*(obj)))

/*
 * 7.17.6 Atomic integer types.
 */

typedef _Atomic(bool)			atomic_bool;
typedef _Atomic(char)			atomic_char;
typedef _Atomic(signed char)		atomic_schar;
typedef _Atomic(unsigned char)		atomic_uchar;
typedef _Atomic(short)			atomic_short;
typedef _Atomic(unsigned short)		atomic_ushort;
typedef _Atomic(int)			atomic_int;
typedef _Atomic(unsigned int)		atomic_uint;
typedef _Atomic(long)			atomic_long;
typedef _Atomic(unsigned long)		atomic_ulong;
typedef _Atomic(long long)		atomic_llong;
typedef _Atomic(unsigned long long)	atomic_ullong;
#if defined(__BIONIC__) || (defined(__cplusplus) && __cplusplus >= 201103L)
  typedef _Atomic(char16_t)		atomic_char16_t;
  typedef _Atomic(char32_t)		atomic_char32_t;
#endif
typedef _Atomic(wchar_t)		atomic_wchar_t;
typedef _Atomic(int_least8_t)		atomic_int_least8_t;
typedef _Atomic(uint_least8_t)	atomic_uint_least8_t;
typedef _Atomic(int_least16_t)	atomic_int_least16_t;
typedef _Atomic(uint_least16_t)	atomic_uint_least16_t;
typedef _Atomic(int_least32_t)	atomic_int_least32_t;
typedef _Atomic(uint_least32_t)	atomic_uint_least32_t;
typedef _Atomic(int_least64_t)	atomic_int_least64_t;
typedef _Atomic(uint_least64_t)	atomic_uint_least64_t;
typedef _Atomic(int_fast8_t)		atomic_int_fast8_t;
typedef _Atomic(uint_fast8_t)		atomic_uint_fast8_t;
typedef _Atomic(int_fast16_t)		atomic_int_fast16_t;
typedef _Atomic(uint_fast16_t)	atomic_uint_fast16_t;
typedef _Atomic(int_fast32_t)		atomic_int_fast32_t;
typedef _Atomic(uint_fast32_t)	atomic_uint_fast32_t;
typedef _Atomic(int_fast64_t)		atomic_int_fast64_t;
typedef _Atomic(uint_fast64_t)	atomic_uint_fast64_t;
typedef _Atomic(intptr_t)		atomic_intptr_t;
typedef _Atomic(uintptr_t)		atomic_uintptr_t;
typedef _Atomic(size_t)		atomic_size_t;
typedef _Atomic(ptrdiff_t)		atomic_ptrdiff_t;
typedef _Atomic(intmax_t)		atomic_intmax_t;
typedef _Atomic(uintmax_t)		atomic_uintmax_t;

/*
 * 7.17.7 Operations on atomic types.
 */

/*
 * Compiler-specific operations.
 */

#define	atomic_compare_exchange_strong_explicit(object, expected,	\
    desired, success, failure)						\
	__c11_atomic_compare_exchange_strong(object, expected, desired,	\
	    success, failure)
#define	atomic_compare_exchange_weak_explicit(object, expected,		\
    desired, success, failure)						\
	__c11_atomic_compare_exchange_weak(object, expected, desired,	\
	    success, failure)
#define	atomic_exchange_explicit(object, desired, order)		\
	__c11_atomic_exchange(object, desired, order)
#define	atomic_fetch_add_explicit(object, operand, order)		\
	__c11_atomic_fetch_add(object, operand, order)
#define	atomic_fetch_and_explicit(object, operand, order)		\
	__c11_atomic_fetch_and(object, operand, order)
#define	atomic_fetch_or_explicit(object, operand, order)		\
	__c11_atomic_fetch_or(object, operand, order)
#define	atomic_fetch_sub_explicit(object, operand, order)		\
	__c11_atomic_fetch_sub(object, operand, order)
#define	atomic_fetch_xor_explicit(object, operand, order)		\
	__c11_atomic_fetch_xor(object, operand, order)
#define	atomic_load_explicit(object, order)				\
	__c11_atomic_load(object, order)
#define	atomic_store_explicit(object, desired, order)			\
	__c11_atomic_store(object, desired, order)

/*
 * Convenience functions.
 */

#define	atomic_compare_exchange_strong(object, expected, desired)	\
	atomic_compare_exchange_strong_explicit(object, expected,	\
	    desired, memory_order_seq_cst, memory_order_seq_cst)
#define	atomic_compare_exchange_weak(object, expected, desired)		\
	atomic_compare_exchange_weak_explicit(object, expected,		\
	    desired, memory_order_seq_cst, memory_order_seq_cst)
#define	atomic_exchange(object, desired)				\
	atomic_exchange_explicit(object, desired, memory_order_seq_cst)
#define	atomic_fetch_add(object, operand)				\
	atomic_fetch_add_explicit(object, operand, memory_order_seq_cst)
#define	atomic_fetch_and(object, operand)				\
	atomic_fetch_and_explicit(object, operand, memory_order_seq_cst)
#define	atomic_fetch_or(object, operand)				\
	atomic_fetch_or_explicit(object, operand, memory_order_seq_cst)
#define	atomic_fetch_sub(object, operand)				\
	atomic_fetch_sub_explicit(object, operand, memory_order_seq_cst)
#define	atomic_fetch_xor(object, operand)				\
	atomic_fetch_xor_explicit(object, operand, memory_order_seq_cst)
#define	atomic_load(object)						\
	atomic_load_explicit(object, memory_order_seq_cst)
#define	atomic_store(object, desired)					\
	atomic_store_explicit(object, desired, memory_order_seq_cst)

/*
 * 7.17.8 Atomic flag type and operations.
 *
 * XXX: Assume atomic_bool can be used as an atomic_flag. Is there some
 * kind of compiler built-in type we could use?
 */

typedef struct {
	atomic_bool	__flag;
} atomic_flag;

#define	ATOMIC_FLAG_INIT		{ ATOMIC_VAR_INIT(false) }

static __inline bool atomic_flag_test_and_set_explicit(volatile atomic_flag * _Nonnull __object, memory_order __order) {
	return (atomic_exchange_explicit(&__object->__flag, 1, __order));
}

static __inline void atomic_flag_clear_explicit(volatile atomic_flag * _Nonnull __object, memory_order __order) {
	atomic_store_explicit(&__object->__flag, 0, __order);
}

static __inline bool atomic_flag_test_and_set(volatile atomic_flag * _Nonnull __object) {
	return (atomic_flag_test_and_set_explicit(__object, memory_order_seq_cst));
}

static __inline void atomic_flag_clear(volatile atomic_flag * _Nonnull __object) {
	atomic_flag_clear_explicit(__object, memory_order_seq_cst);
}
```