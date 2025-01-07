Response:
Let's break down the thought process for answering the user's request about `bionic/tests/stdatomic_test.cpp`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the C++ source file `stdatomic_test.cpp` within the Android Bionic library. The key is to understand its *purpose* and how it relates to Bionic and Android. The prompt specifically asks for functionality, relationship to Android, detailed explanations of libc functions, dynamic linker aspects, logic/examples, common errors, and how the code is reached (including debugging).

**2. Initial Assessment of the Code:**

The first thing that jumps out is the `TEST` macros. This immediately identifies it as a unit test file, likely using the Google Test framework (`gtest`). The inclusion of `<bits/stdatomic.h>` (instead of just `<stdatomic.h>`) is significant and hints at testing the *specific* Bionic implementation of atomics. The tests themselves involve functions like `atomic_load`, `atomic_store`, `atomic_compare_exchange`, `atomic_flag`, and memory fences (`atomic_thread_fence`, `atomic_signal_fence`). These are all related to C11 atomic operations for concurrent programming.

**3. Deconstructing the Request - Creating a Mental Checklist:**

To ensure all parts of the request are addressed, I'd create a mental checklist or outline:

*   **Functionality:** What does this *test file* do? Not the functions being tested, but the overall purpose of the file itself.
*   **Android Relationship:** How do atomic operations benefit Android? Where are they likely used?
*   **libc Function Details:** For each `atomic_*` function used in the tests, explain its purpose and *how* it might be implemented in Bionic (considering it's likely using underlying kernel primitives or optimized assembly).
*   **Dynamic Linker:**  Do atomic operations have a direct connection to the dynamic linker? If so, how?  (This requires some deeper thinking – shared memory and synchronization across different loaded libraries comes to mind).
*   **Logic/Examples:** Provide concrete scenarios (input/output) for how some of the atomic operations work.
*   **Common Errors:**  What mistakes do developers often make when using atomics?
*   **Android Framework/NDK:** Trace the path from higher-level Android components down to this low-level testing.
*   **Frida Hook:** Demonstrate how to use Frida to inspect these atomic operations at runtime.

**4. Addressing Each Point Systematically:**

*   **Functionality:**  The core function is *testing*. Specifically, verifying the correctness of Bionic's implementation of C11 atomic operations. This includes checking for lock-free guarantees and the behavior of different atomic functions.

*   **Android Relationship:**  Concurrency is crucial for Android's responsiveness and performance. Atomic operations provide a low-level, efficient way to manage shared data between threads, especially in the framework, system services, and NDK applications. Examples include reference counting, managing thread states, and implementing concurrent data structures.

*   **libc Function Details:** This is where deeper knowledge of atomic operations is needed. For each function (e.g., `atomic_load`, `atomic_store`, `atomic_compare_exchange`), I'd describe its basic purpose and then speculate on potential implementation strategies in Bionic. For example, `atomic_compare_exchange_strong` likely uses a loop with a compare-and-swap (CAS) instruction at the hardware level. Memory fences are crucial for establishing ordering guarantees and often translate to compiler barriers or specific CPU instructions.

*   **Dynamic Linker:** The connection here is less direct but important. When multiple shared libraries are loaded, they might need to share data. Atomic operations provide the necessary synchronization primitives for this shared memory scenario. I'd create a simple example of two shared libraries accessing a shared atomic variable. The linker is responsible for placing these libraries in memory, and the atomics ensure consistent access.

*   **Logic/Examples:** For functions like `atomic_compare_exchange`, providing simple code snippets with expected outcomes clarifies their behavior, especially the difference between strong and weak versions.

*   **Common Errors:**  This requires thinking from a developer's perspective. Common mistakes include forgetting memory ordering, using relaxed ordering when stronger ordering is needed, and incorrect usage of compare-and-exchange.

*   **Android Framework/NDK:**  This involves tracing the call stack conceptually. A user-level action in an Android app (Java/Kotlin) might trigger operations that eventually lead to native code. NDK developers directly use these atomic operations. The key is to show the layered nature of Android.

*   **Frida Hook:**  This requires knowing how Frida works. The core idea is to intercept function calls at runtime. I'd select a few key atomic functions and show how to hook them using Frida to observe their arguments and return values.

**5. Structuring the Answer:**

Organizing the answer logically is essential for clarity. I would follow the structure requested by the user as closely as possible:

*   Start with a general overview of the file's purpose.
*   Address the relationship to Android with concrete examples.
*   Provide detailed explanations of the libc functions.
*   Discuss the dynamic linker aspects with an example.
*   Illustrate the logic with input/output scenarios.
*   Highlight common usage errors.
*   Explain the path from the Android framework/NDK to the code.
*   Provide Frida hook examples.

**6. Refining and Adding Details:**

After drafting the initial answer, I would review it for accuracy, completeness, and clarity. I'd add specific details about memory ordering, the implications of lock-free operations, and how the tests cover different aspects of the atomic API. For the dynamic linker section, elaborating on the role of symbol resolution and shared memory regions would be beneficial.

**Self-Correction/Refinement during the Process:**

*   Initially, I might focus too much on the individual test cases. It's crucial to step back and explain the broader purpose of the `stdatomic_test.cpp` file within the Bionic ecosystem.
*   The connection to the dynamic linker might not be immediately obvious. I need to think about scenarios where atomics are needed across shared library boundaries.
*   For the Frida hook examples, providing specific commands and explaining the output is more helpful than just saying "use Frida."

By following this systematic approach, breaking down the request, and iteratively refining the answer, I can address all aspects of the user's query comprehensively and accurately.
好的，让我们详细分析一下 `bionic/tests/stdatomic_test.cpp` 这个文件。

**功能列举:**

这个 `stdatomic_test.cpp` 文件的主要功能是 **测试 Android Bionic 库中 `<stdatomic.h>` 头文件提供的原子操作功能的正确性**。更具体地说，它使用 Google Test 框架来验证以下内容：

1. **原子操作的锁自由性 (Lock-Free):**  测试各种原子类型（如 `atomic_bool`, `atomic_int`, `atomic_pointer` 等）是否为无锁实现。`ATOMIC_*_LOCK_FREE` 宏用于检查这一点。
2. **原子变量的初始化:** 测试原子变量的初始化方式，以及使用 `atomic_load` 读取初始值。
3. **原子存储操作:** 测试 `atomic_store` 和 `atomic_store_explicit` 函数，验证向原子变量写入值的功能。
4. **原子标志 (Atomic Flag) 操作:** 测试 `atomic_flag` 类型的初始化、设置 (`atomic_flag_test_and_set`) 和清除 (`atomic_flag_clear`) 操作。
5. **内存屏障 (Memory Fence):** 测试 `atomic_thread_fence` 和 `atomic_signal_fence` 函数，验证内存屏障的功能，确保特定顺序的内存访问。
6. **检查是否无锁:** 测试 `atomic_is_lock_free` 函数，动态检查给定原子变量是否为无锁实现。
7. **原子交换操作:** 测试 `atomic_exchange` 和 `atomic_exchange_explicit` 函数，验证原子地交换原子变量的值并返回旧值的功能。
8. **原子比较和交换操作:** 测试 `atomic_compare_exchange_strong`、`atomic_compare_exchange_weak` 及其显式版本，验证原子地比较原子变量的值，并在相等时进行交换的功能。
9. **原子加法、减法、或、异或、与操作:** 测试 `atomic_fetch_add`、`atomic_fetch_sub`、`atomic_fetch_or`、`atomic_fetch_xor`、`atomic_fetch_and` 及其显式版本，验证原子地执行这些算术和位运算并返回操作前的值的功能。
10. **内存顺序 (Memory Ordering) 测试:**  通过创建读写线程，测试不同内存顺序 (`memory_order_relaxed`, `memory_order_acquire`, `memory_order_release`, `memory_order_acq_rel`, `memory_order_seq_cst`) 对多线程并发访问原子变量的影响，验证 acquire-release 语义。

**与 Android 功能的关系及举例说明:**

原子操作是构建并发安全代码的基础，在 Android 系统中被广泛使用：

1. **Android Framework:**
    *   **引用计数 (Reference Counting):**  Android Framework 中许多对象的生命周期管理依赖引用计数，原子操作确保了在多线程环境下增加和减少引用计数的安全性。例如，在 `android.os.Parcel` 类中，`nativeIncRefs` 和 `nativeDecRefs` 方法可能使用原子操作来更新引用计数。
    *   **状态管理:**  系统服务的状态（例如，ActivityManagerService 中的活动状态）可能使用原子变量来保证状态更新的原子性。
    *   **并发数据结构:**  某些并发数据结构（例如，用于缓存的结构）内部会使用原子操作来保证数据的一致性。

2. **NDK 开发:**
    *   **多线程应用程序:** NDK 开发者在编写多线程 C/C++ 代码时，经常需要使用原子操作来同步线程，避免数据竞争。
    *   **共享内存:** 当多个进程或线程共享内存时，原子操作是保证数据一致性的关键。例如，可以使用原子变量作为锁或信号量。

**libc 函数的功能及实现细节:**

该测试文件主要测试 `<bits/stdatomic.h>` 中定义的原子操作函数。  需要注意的是，直接包含 `<bits/stdatomic.h>` 是为了测试 Bionic 提供的 libc 实现，而不是 C++ 标准库中的原子操作（如果可用）。

以下是测试文件中涉及的主要 libc 原子操作函数及其实现原理（基于常见的实现方式，Bionic 的具体实现可能会有所不同）：

*   **`atomic_load(atomic_type *object)` 和 `atomic_load_explicit(atomic_type *object, memory_order order)`:**
    *   **功能:** 原子地读取原子变量的值。
    *   **实现:**  通常会使用 CPU 提供的原子加载指令 (例如，x86 的 `MOV` 指令，但在多核环境下需要保证缓存一致性)。 `atomic_load_explicit` 允许指定内存顺序，影响编译器和 CPU 如何处理内存访问的顺序。
*   **`atomic_store(atomic_type desired, atomic_type *object)` 和 `atomic_store_explicit(atomic_type desired, atomic_type *object, memory_order order)`:**
    *   **功能:** 原子地将 `desired` 值存储到原子变量中。
    *   **实现:**  通常使用 CPU 提供的原子存储指令 (例如，x86 的 `MOV` 指令，需要保证原子性和可见性)。  `atomic_store_explicit` 允许指定内存顺序。
*   **`atomic_exchange(atomic_type desired, atomic_type *object)` 和 `atomic_exchange_explicit(atomic_type desired, atomic_type *object, memory_order order)`:**
    *   **功能:** 原子地将 `desired` 值存储到原子变量中，并返回该变量的旧值。
    *   **实现:**  通常使用 CPU 提供的原子交换指令 (例如，x86 的 `XCHG` 或 `cmpxchg8b/16b` 与循环结合)。
*   **`atomic_compare_exchange_strong(atomic_type *object, atomic_type *expected, atomic_type desired)` 和相关函数:**
    *   **功能:** 原子地比较原子变量的值与 `*expected`。如果相等，则将 `desired` 存储到原子变量中，并将 `*expected` 的值保持不变（或更新为原子变量的当前值，取决于是否交换成功）。返回一个布尔值，指示是否交换成功。
    *   **实现:**  通常使用 CPU 提供的比较并交换 (Compare-and-Swap, CAS) 指令 (例如，x86 的 `CMPXCHG`)。 `_strong` 版本保证在伪失败（spurious failure，由于线程调度等原因导致 CAS 失败，即使值没有改变）的情况下也会失败。 `_weak` 版本可能出现伪失败，通常在循环中使用。
*   **`atomic_fetch_add(atomic_type value, atomic_type *object)` 和相关函数 (sub, or, xor, and):**
    *   **功能:** 原子地执行算术或位运算，并将结果存储回原子变量，返回操作前的值。
    *   **实现:**  通常使用 CPU 提供的原子 fetch-and-add 等指令 (例如，x86 的 `LOCK ADD`, `LOCK OR` 等)。 如果 CPU 没有直接支持，可能会使用循环的 CAS 操作来实现。
*   **`atomic_flag_test_and_set(atomic_flag *object)` 和相关函数:**
    *   **功能:** 原子地设置原子标志，并返回操作前的值。原子标志通常用于实现简单的互斥锁。
    *   **实现:**  通常使用 CPU 提供的原子交换或 CAS 指令来实现。
*   **`atomic_flag_clear(atomic_flag *object)` 和相关函数:**
    *   **功能:** 原子地清除原子标志。
    *   **实现:**  通常使用原子存储操作来实现。
*   **`atomic_thread_fence(memory_order order)` 和 `atomic_signal_fence(memory_order order)`:**
    *   **功能:**  插入内存屏障，强制编译器和 CPU 按照指定的内存顺序执行内存访问。
    *   **实现:**  在编译时，编译器会根据内存顺序插入特定的指令，例如内存栅栏指令 (memory barrier instruction) 或重排序限制。在某些架构上，某些内存顺序可能不需要显式的指令。`atomic_thread_fence` 用于线程间的同步，`atomic_signal_fence` 用于线程和信号处理程序之间的同步。
*   **`atomic_is_lock_free(const volatile atomic_type *object)`:**
    *   **功能:**  检查给定的原子类型是否使用无锁算法实现。
    *   **实现:**  通常在编译时确定。Bionic 可能会根据目标架构和原子类型的大小返回预定义的值 (`true` 或 `false`)。

**涉及 dynamic linker 的功能:**

原子操作本身并不是 dynamic linker 的核心功能，但它们在处理共享库之间的并发访问共享数据时非常重要。

**so 布局样本:**

假设我们有两个共享库 `libA.so` 和 `libB.so`，它们都链接到了包含原子操作实现的 libc (`libc.so`)。

```
Memory Map:

[程序代码段]
...
[libA.so 代码段]
...
[libB.so 代码段]
...
[libc.so 代码段 (包含原子操作的实现)]
...
[共享数据段]
  atomic_int shared_counter  // 可能位于某个共享库的数据段或匿名映射区
...
```

**链接的处理过程:**

1. **编译时:**  `libA.so` 和 `libB.so` 的代码中使用了原子操作，例如 `atomic_fetch_add`。编译器会将这些原子操作转换为对 libc 中相应函数的调用。
2. **链接时:**  Dynamic linker（例如，`linker64`）在加载 `libA.so` 和 `libB.so` 时，会解析对 libc 中原子操作函数的符号引用，并将它们链接到 `libc.so` 中对应的实现。这意味着 `libA.so` 和 `libB.so` 中的原子操作调用最终都会指向 `libc.so` 中的同一份代码。
3. **运行时:**  当 `libA.so` 和 `libB.so` 中的线程并发访问共享的原子变量 `shared_counter` 时，它们都会调用 `libc.so` 中实现的原子操作函数。`libc.so` 中的原子操作实现会利用底层的 CPU 指令来保证操作的原子性，从而避免数据竞争。

**逻辑推理、假设输入与输出:**

以 `atomic_compare_exchange_strong` 为例：

**假设输入:**

*   `atomic_int i` 的当前值为 10。
*   `expected` 指向的整数变量的值为 10。
*   `desired` 的值为 20。

**输出:**

*   `atomic_compare_exchange_strong(&i, &expected, 20)` 的返回值为 `true` (比较成功，交换发生)。
*   `i` 的新值为 20。
*   `expected` 指向的整数变量的值仍然为 10。

**假设输入:**

*   `atomic_int i` 的当前值为 15。
*   `expected` 指向的整数变量的值为 10。
*   `desired` 的值为 20。

**输出:**

*   `atomic_compare_exchange_strong(&i, &expected, 20)` 的返回值为 `false` (比较失败，交换未发生)。
*   `i` 的值仍然为 15。
*   `expected` 指向的整数变量的值会被更新为 `i` 的当前值，即 15。

**用户或编程常见的使用错误:**

1. **未正确理解内存顺序:**  使用 `memory_order_relaxed` 可能会导致意想不到的并发问题，因为它不提供任何同步保证。开发者需要根据具体的并发场景选择合适的内存顺序。
    ```c++
    // 错误示例：假设需要在 store 之后立即 load 看到 store 的结果，relaxed 无法保证
    atomic_int a = 0;
    atomic_store_explicit(&a, 1, memory_order_relaxed);
    int b = atomic_load_explicit(&a, memory_order_relaxed);
    // b 的值不一定是 1
    ```
2. **在需要强顺序时使用弱顺序的比较和交换:**  在某些需要原子更新多个相关变量的场景中，仅仅依赖 `atomic_compare_exchange_weak` 可能会导致活锁或意外行为。
3. **忘记在循环中使用 `atomic_compare_exchange_weak`:** 由于 `atomic_compare_exchange_weak` 可能出现伪失败，因此通常需要在循环中调用，直到成功为止。
    ```c++
    atomic_int value;
    int expected = atomic_load(&value);
    int desired = expected + 1;
    while (!atomic_compare_exchange_weak(&value, &expected, desired)) {
        expected = atomic_load(&value); // 重新加载当前值
        desired = expected + 1;
    }
    ```
4. **假设原子操作是所有问题的银弹:** 原子操作只是并发编程的工具之一。过度依赖原子操作可能会导致代码复杂且难以维护。在某些情况下，使用更高级的同步机制（如互斥锁、条件变量）可能更合适。
5. **数据竞争 (Data Race) 的误判:**  即使使用了原子操作，也并不意味着所有并发问题都消失了。如果多个原子操作之间存在依赖关系，仍然需要仔细考虑执行顺序和内存可见性。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java/Kotlin):**  Android Framework 的某些核心组件或服务（例如，ActivityManagerService, SurfaceFlinger）在内部的 native 代码实现中会使用 Bionic 提供的原子操作。例如，Java 层的 `synchronized` 关键字在底层可能会调用 native 层的互斥锁实现，而互斥锁的实现可能依赖原子操作。
2. **NDK 开发 (C/C++):**  NDK 开发者可以直接在 C/C++ 代码中使用 `<stdatomic.h>` 中定义的原子操作。当 NDK 代码被编译并链接到 Android 应用程序时，对原子操作函数的调用会被链接到 Bionic 的 libc。
3. **Bionic libc:**  当应用程序或 Framework 组件调用原子操作函数时，最终会执行 Bionic libc 中相应的实现。这些实现会利用底层的 CPU 指令来完成原子操作。

**Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 调试 `atomic_load` 函数的示例：

```javascript
// attach 到目标进程
function attach(processName) {
    try {
        return Process.get процессов().find(p => p.name === processName);
    } catch (e) {
        console.log("进程 " + processName + " 未找到，请确保进程正在运行。");
        return null;
    }
}

const targetProcessName = "com.example.myapp"; // 替换为你的应用进程名
const process = attach(targetProcessName);

if (process) {
    console.log("成功连接到进程: " + process.name);

    // Hook atomic_load 函数
    const atomic_load_ptr = Module.findExportByName("libc.so", "atomic_load");

    if (atomic_load_ptr) {
        Interceptor.attach(atomic_load_ptr, {
            onEnter: function (args) {
                console.log("[atomic_load] 参数:");
                console.log("  *object:", args[0]);
                // 可以尝试读取指针指向的内存
                try {
                    console.log("  value:", Memory.readInt(ptr(args[0])));
                } catch (e) {
                    console.log("  无法读取内存:", e);
                }
            },
            onLeave: function (retval) {
                console.log("[atomic_load] 返回值:", retval);
            }
        });
        console.log("成功 Hook atomic_load");
    } else {
        console.log("未找到 atomic_load 函数");
    }
}
```

**使用方法:**

1. 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. 将上述 JavaScript 代码保存到一个文件中（例如 `hook_atomic_load.js`）。
3. 替换 `targetProcessName` 为你要调试的 Android 应用程序的进程名。
4. 运行目标 Android 应用程序。
5. 在你的电脑上，使用 adb 连接到设备，然后在终端中运行以下命令：

    ```bash
    frida -U -f com.example.myapp -l hook_atomic_load.js --no-pause
    ```

    或者，如果应用已经在运行：

    ```bash
    frida -U com.example.myapp -l hook_atomic_load.js
    ```

   (将 `com.example.myapp` 替换为你的应用包名)

每当目标应用程序调用 `atomic_load` 函数时，Frida 都会拦截该调用，并打印出函数的参数（指向原子变量的指针）和返回值（加载的原子值）。你可以根据需要修改 Hook 代码来拦截其他原子操作函数，并查看它们的行为。

这个分析应该涵盖了 `bionic/tests/stdatomic_test.cpp` 文件的主要功能以及它在 Android 系统中的作用。希望对你有所帮助！

Prompt: 
```
这是目录为bionic/tests/stdatomic_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

// The real <stdatomic.h> checks for the availability of C++'s atomics and uses them if present. Since
// we want to test the libc versions, we instead include <bits/stdatomic.h> where they're actually defined.
#include <bits/stdatomic.h>

#include <pthread.h>
#include <stdint.h>

TEST(stdatomic, LOCK_FREE) {
  ASSERT_TRUE(ATOMIC_BOOL_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_CHAR16_T_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_CHAR32_T_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_CHAR_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_INT_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_LLONG_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_LONG_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_POINTER_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_SHORT_LOCK_FREE);
  ASSERT_TRUE(ATOMIC_WCHAR_T_LOCK_FREE);
}

TEST(stdatomic, init) {
  atomic_int v = 123;
  ASSERT_EQ(123, atomic_load(&v));

  atomic_store_explicit(&v, 456, memory_order_relaxed);
  ASSERT_EQ(456, atomic_load(&v));

  atomic_flag f = ATOMIC_FLAG_INIT;
  ASSERT_FALSE(atomic_flag_test_and_set(&f));
}

TEST(stdatomic, atomic_thread_fence) {
  atomic_thread_fence(memory_order_relaxed);
  atomic_thread_fence(memory_order_consume);
  atomic_thread_fence(memory_order_acquire);
  atomic_thread_fence(memory_order_release);
  atomic_thread_fence(memory_order_acq_rel);
  atomic_thread_fence(memory_order_seq_cst);
}

TEST(stdatomic, atomic_signal_fence) {
  atomic_signal_fence(memory_order_relaxed);
  atomic_signal_fence(memory_order_consume);
  atomic_signal_fence(memory_order_acquire);
  atomic_signal_fence(memory_order_release);
  atomic_signal_fence(memory_order_acq_rel);
  atomic_signal_fence(memory_order_seq_cst);
}

TEST(stdatomic, atomic_is_lock_free) {
  atomic_char small;
  ASSERT_TRUE(atomic_is_lock_free(&small));
  atomic_intmax_t big;
  ASSERT_TRUE(atomic_is_lock_free(&big));
}

TEST(stdatomic, atomic_flag) {
  atomic_flag f = ATOMIC_FLAG_INIT;
  ASSERT_FALSE(atomic_flag_test_and_set(&f));
  ASSERT_TRUE(atomic_flag_test_and_set(&f));

  atomic_flag_clear(&f);

  ASSERT_FALSE(atomic_flag_test_and_set_explicit(&f, memory_order_relaxed));
  ASSERT_TRUE(atomic_flag_test_and_set_explicit(&f, memory_order_relaxed));

  atomic_flag_clear_explicit(&f, memory_order_relaxed);
  ASSERT_FALSE(atomic_flag_test_and_set_explicit(&f, memory_order_relaxed));
}

TEST(stdatomic, atomic_store) {
  atomic_int i;
  atomic_store(&i, 123);
  ASSERT_EQ(123, atomic_load(&i));
  atomic_store_explicit(&i, 123, memory_order_relaxed);
  ASSERT_EQ(123, atomic_load_explicit(&i, memory_order_relaxed));
}

TEST(stdatomic, atomic_exchange) {
  atomic_int i;
  atomic_store(&i, 123);
  ASSERT_EQ(123, atomic_exchange(&i, 456));
  ASSERT_EQ(456, atomic_exchange_explicit(&i, 123, memory_order_relaxed));
}

TEST(stdatomic, atomic_compare_exchange) {
  atomic_int i;
  int expected;

  atomic_store(&i, 123);
  expected = 123;
  ASSERT_TRUE(atomic_compare_exchange_strong(&i, &expected, 456));
  ASSERT_FALSE(atomic_compare_exchange_strong(&i, &expected, 456));
  ASSERT_EQ(456, expected);

  atomic_store(&i, 123);
  expected = 123;
  ASSERT_TRUE(atomic_compare_exchange_strong_explicit(&i, &expected, 456, memory_order_relaxed,
          memory_order_relaxed));
  ASSERT_FALSE(atomic_compare_exchange_strong_explicit(&i, &expected, 456, memory_order_relaxed,
          memory_order_relaxed));
  ASSERT_EQ(456, expected);

  atomic_store(&i, 123);
  expected = 123;
  int iter_count = 0;
  do {
    ++iter_count;
    ASSERT_LT(iter_count, 100);  // Arbitrary limit on spurious compare_exchange failures.
    ASSERT_EQ(expected, 123);
  } while(!atomic_compare_exchange_weak(&i, &expected, 456));
  ASSERT_FALSE(atomic_compare_exchange_weak(&i, &expected, 456));
  ASSERT_EQ(456, expected);

  atomic_store(&i, 123);
  expected = 123;
  iter_count = 0;
  do {
    ++iter_count;
    ASSERT_LT(iter_count, 100);
    ASSERT_EQ(expected, 123);
  } while(!atomic_compare_exchange_weak_explicit(&i, &expected, 456, memory_order_relaxed,
          memory_order_relaxed));
  ASSERT_FALSE(atomic_compare_exchange_weak_explicit(&i, &expected, 456, memory_order_relaxed,
          memory_order_relaxed));
  ASSERT_EQ(456, expected);
}

TEST(stdatomic, atomic_fetch_add) {
  atomic_int i = 123;
  ASSERT_EQ(123, atomic_fetch_add(&i, 1));
  ASSERT_EQ(124, atomic_fetch_add_explicit(&i, 1, memory_order_relaxed));
  ASSERT_EQ(125, atomic_load(&i));
}

TEST(stdatomic, atomic_fetch_sub) {
  atomic_int i = 123;
  ASSERT_EQ(123, atomic_fetch_sub(&i, 1));
  ASSERT_EQ(122, atomic_fetch_sub_explicit(&i, 1, memory_order_relaxed));
  ASSERT_EQ(121, atomic_load(&i));
}

TEST(stdatomic, atomic_fetch_or) {
  atomic_int i = 0x100;
  ASSERT_EQ(0x100, atomic_fetch_or(&i, 0x020));
  ASSERT_EQ(0x120, atomic_fetch_or_explicit(&i, 0x003, memory_order_relaxed));
  ASSERT_EQ(0x123, atomic_load(&i));
}

TEST(stdatomic, atomic_fetch_xor) {
  atomic_int i = 0x100;
  ASSERT_EQ(0x100, atomic_fetch_xor(&i, 0x120));
  ASSERT_EQ(0x020, atomic_fetch_xor_explicit(&i, 0x103, memory_order_relaxed));
  ASSERT_EQ(0x123, atomic_load(&i));
}

TEST(stdatomic, atomic_fetch_and) {
  atomic_int i = 0x123;
  ASSERT_EQ(0x123, atomic_fetch_and(&i, 0x00f));
  ASSERT_EQ(0x003, atomic_fetch_and_explicit(&i, 0x2, memory_order_relaxed));
  ASSERT_EQ(0x002, atomic_load(&i));
}

// And a rudimentary test of acquire-release memory ordering:

static constexpr uint_least32_t BIG = 30'000'000ul;
static_assert((BIG % 2) == 0);  // Assumed below.

struct three_atomics {
  atomic_uint_least32_t x;
  char a[123];  // Everything in different cache lines,
                // increase chance of compiler getting alignment wrong.
  atomic_uint_least32_t y;
  char b[4013];
  atomic_uint_least32_t z;
};

atomic_bool read_enough(false);

// Very simple acquire/release memory ordering smoke test.
static void* writer(void* arg) {
  three_atomics* a = reinterpret_cast<three_atomics*>(arg);
  for (uint_least32_t i = 0; i <= BIG; i+=2) {
    atomic_store_explicit(&a->x, i, memory_order_relaxed);
    atomic_store_explicit(&a->z, i, memory_order_relaxed);
    atomic_store_explicit(&a->y, i, memory_order_release);

    // Force stores to be visible in spite of being overwritten below.
    asm volatile("" ::: "memory");

    atomic_store_explicit(&a->x, i+1, memory_order_relaxed);
    atomic_store_explicit(&a->z, i+1, memory_order_relaxed);
    atomic_store_explicit(&a->y, i+1, memory_order_release);
    if (i >= BIG - 1000 && !atomic_load(&read_enough)) {
      // Give reader a chance to catch up, at the expense of making the test
      // less effective.
      usleep(1000);
    }
  }
  return nullptr;
}

static void* reader(void* arg) {
  three_atomics* a = reinterpret_cast<three_atomics*>(arg);
  uint_least32_t xval = 0, yval = 0, zval = 0;
  size_t repeat = 0;
  size_t repeat_limit = 1000;
  while (yval != BIG + 1) {
    yval = atomic_load_explicit(&a->y, memory_order_acquire);
    zval = atomic_load_explicit(&a->z, memory_order_relaxed);
    xval = atomic_load_explicit(&a->x, memory_order_relaxed);
    // If we see a given value of y, the immediately preceding
    // stores to z and x, or later ones, should also be visible.
    if (zval < yval) {
      // Cant just ASSERT, since we are in a non-void function.
      ADD_FAILURE() << "acquire-release ordering violation: "
                    << zval << " < " << yval << ", " << xval << "\n";
      return nullptr; // Only report once.
    }
    if (xval < yval) {
      // Cant just ASSERT, since we are in a non-void function.
      ADD_FAILURE() << "acquire-release ordering violation: "
                    << xval << " < " << yval << ", " << zval <<  "\n";
      return nullptr; // Only report once.
    }
    if (repeat < repeat_limit) {
      ++repeat;
    } else if (!atomic_load_explicit(&read_enough, memory_order_relaxed)) {
      atomic_store_explicit(&read_enough, true, memory_order_relaxed);
    }
  }
  // The following assertion is not technically guaranteed to hold.
  // But if it fails to hold, this test was useless, and we have a
  // serious scheduling issue that we should probably know about.
  EXPECT_EQ(repeat, repeat_limit);
  return nullptr;
}

TEST(stdatomic, ordering) {
  // Run a memory ordering smoke test.
  void* result;
  three_atomics a;
  atomic_store_explicit(&a.x, 0ul, memory_order_relaxed);
  atomic_store_explicit(&a.y, 0ul, memory_order_relaxed);
  atomic_store_explicit(&a.z, 0ul, memory_order_relaxed);
  pthread_t t1,t2;
  ASSERT_EQ(0, pthread_create(&t1, nullptr, reader, &a));
  ASSERT_EQ(0, pthread_create(&t2, nullptr, writer, &a));
  ASSERT_EQ(0, pthread_join(t1, &result));
  EXPECT_EQ(nullptr, result);
  ASSERT_EQ(0, pthread_join(t2, &result));
  EXPECT_EQ(nullptr, result);
  EXPECT_EQ(atomic_load_explicit(&a.x, memory_order_consume), BIG + 1);
  EXPECT_EQ(atomic_load_explicit(&a.y, memory_order_seq_cst), BIG + 1);
  EXPECT_EQ(atomic_load(&a.z), BIG + 1);
}

"""

```