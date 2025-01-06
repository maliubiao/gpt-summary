Response:
Let's break down the thought process for answering the request about `bionic/tests/struct_layout_test.cpp`.

**1. Understanding the Core Purpose:**

The first step is to recognize that this is a *test file*. The name `struct_layout_test.cpp` is a huge clue. The code itself confirms this by using the `gtest` framework (`TEST(struct_layout, sizes_offsets)`). Therefore, the primary function isn't to *do* something in the runtime sense, but rather to *verify* something.

**2. Identifying the Target of the Verification:**

The code clearly focuses on `pthread_internal_t` and `bionic_tls`. The comments mention ensuring "the layout of these data structures is architecture independent". This immediately suggests the file's purpose is to check the size and offset of members within these structs.

**3. Differentiating Architectures:**

The `#ifdef __LP64__` block highlights that the layout differs between 32-bit and 64-bit architectures. This is a crucial detail for understanding the test's logic.

**4. Deconstructing the Test Logic:**

* **`CHECK_SIZE` and `CHECK_OFFSET` Macros:** These are simple macros that make the code more readable. They abstract away the `sizeof` and `offsetof` operations.
* **`tests` Function:** This template function encapsulates the core logic of checking sizes and offsets. It takes two function pointers (`check_size` and `check_offset`) as arguments, making it reusable with different checking/printing behaviors.
* **`TEST(struct_layout, sizes_offsets)`:** This is the actual test case.
    * It first defines lambda functions `check_size` and `check_offset` that use `EXPECT_EQ` to assert the correctness of sizes and offsets.
    * It calls the `tests` function with these lambda functions.
    * The `failed` flag and the subsequent `printf` block are for generating updated test code if the current layout differs from the expected one. This is a common practice in maintaining such tests.
* **`GTEST_SKIP()`:** This handles the case where the test is not being run on a bionic target, preventing irrelevant failures.

**5. Relating to Android/Bionic:**

Knowing that bionic is Android's C library, the significance of these tests becomes clear. The layout of `pthread_internal_t` and `bionic_tls` is fundamental for thread management and thread-local storage. Inconsistencies in these layouts across different architectures or bionic versions would lead to crashes and undefined behavior.

**6. Addressing Specific Request Points:**

Now, systematically address each part of the user's request:

* **功能 (Functionality):**  Summarize the core purpose: verifying struct layout for architecture independence.
* **与 Android 功能的关系 (Relationship to Android Functionality):** Explain how `pthread_internal_t` and `bionic_tls` are essential for threading and thread-local storage, which are core to Android's operation. Provide concrete examples like thread creation and accessing thread-local variables.
* **详细解释 libc 函数的功能是如何实现的 (Explanation of libc function implementations):**  This is where you need to be careful. The *test file itself* doesn't *implement* libc functions. It *checks* the layout of data structures used by them. Therefore, the answer should focus on how the *data structures* are used by functions like `pthread_create`, `pthread_join`, `pthread_getspecific`, etc. Mention that the *actual implementation* is in other bionic source files.
* **涉及 dynamic linker 的功能 (Dynamic linker functionality):**  `bionic_tls` is directly related to the dynamic linker's role in managing thread-local storage. Explain how the linker allocates and manages the TLS segment. Provide a simplified so layout example to illustrate TLS. Describe the linking process steps related to TLS.
* **逻辑推理，给出假设输入与输出 (Logical reasoning with input/output):** Since this is a test, the "input" is the current system's struct layout, and the "output" is either a pass (assertions succeed) or a fail (assertions fail, potentially with updated test code).
* **用户或编程常见的使用错误 (Common user/programming errors):** Focus on the *consequences* of incorrect struct layout if the test were to fail. This could include memory corruption, crashes, and unpredictable behavior when using threads or thread-local variables.
* **说明 android framework or ndk 是如何一步步的到达这里 (How Android framework/NDK reaches here):** Trace the path from an Android app using threads or thread-local storage, down to the NDK (if used), then the system calls that rely on bionic's threading implementation and TLS management.
* **给出 frida hook 示例调试这些步骤 (Frida hook example):**  Provide practical examples of using Frida to inspect the size and offset of the structures at runtime, or to intercept calls that interact with these structures. Focus on the relevant functions and data structures.

**7. Structuring the Answer:**

Organize the answer clearly using headings and bullet points to address each part of the request. Use precise language and avoid jargon where possible. Provide code examples for the Frida hooks.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Perhaps I should explain the implementation of `sizeof` and `offsetof`. **Correction:** While relevant, it's not the core focus. The test *uses* these, it doesn't define them. Keep the focus on what the test *does*.
* **Initial thought:** Should I go into detail about different threading models? **Correction:** Keep it focused on the specifics of this test file and the structures it checks. Broad threading concepts are less relevant here.
* **Realization:** The request asks for libc function *implementation*. **Correction:** The test doesn't implement them. Shift the focus to how the *data structures* being tested are *used* by those functions.

By following this systematic approach, breaking down the request, and focusing on the specific code provided, a comprehensive and accurate answer can be constructed.
这个文件 `bionic/tests/struct_layout_test.cpp` 的主要功能是**测试和验证 bionic 库中关键数据结构（特别是 `pthread_internal_t` 和 `bionic_tls`）的内存布局（大小和成员偏移量）在不同架构下的稳定性。**

**具体功能分解：**

1. **定义测试用例:** 使用 Google Test 框架 (gtest) 定义了一个名为 `struct_layout` 的测试用例，其中包含一个名为 `sizes_offsets` 的测试。
2. **架构条件编译:** 使用 `#ifdef __BIONIC__` 确保这个测试只在 bionic 环境下编译和运行。
3. **检查结构体大小和成员偏移量:**
   - 定义了两个模板函数 `tests`，它接收两个函数对象 `check_size` 和 `check_offset` 作为参数。
   - 在 `tests` 函数内部，使用宏 `CHECK_SIZE` 和 `CHECK_OFFSET` 来断言特定结构体的大小和成员偏移量是否与预期的值相等。
   - `#ifdef __LP64__` 用于区分 64 位和 32 位架构，因为结构体的布局可能会因为指针大小等因素而有所不同。
   - 针对 `pthread_internal_t` 和 `bionic_tls` 结构体的多个成员，硬编码了预期的大小和偏移量。
4. **动态生成测试代码（失败时）：**
   - 在 `TEST(struct_layout, sizes_offsets)` 中，定义了两个 lambda 函数 `check_size` 和 `check_offset` 来执行实际的断言。
   - 使用一个 `failed` 标志来记录是否有断言失败。
   - 如果有断言失败，代码会打印出一段 C++ 代码，可以直接复制粘贴到 `tests` 函数中，用于更新预期的大小和偏移量。这方便了在结构体布局发生变化时更新测试。

**与 Android 功能的关系及举例说明：**

这个测试文件与 Android 的核心功能紧密相关，因为它直接测试了 bionic 库中线程管理和线程本地存储 (TLS) 的关键数据结构。

* **`pthread_internal_t`:**  这个结构体是 bionic 内部用于管理线程的控制块。它包含了线程 ID、线程属性、栈信息、信号处理信息、TLS 指针等重要数据。
    * **关系:** Android 上的所有多线程操作，无论是 Java 层面的 `java.lang.Thread` 还是 Native 层面的 `pthread_create` 等，最终都会涉及到对 `pthread_internal_t` 结构体的操作。
    * **举例:** 当你创建一个新的线程时（例如，通过 Java 的 `new Thread(Runnable).start()` 或者 NDK 的 `pthread_create()`），bionic 内部会分配并初始化一个 `pthread_internal_t` 结构体来管理这个新线程的生命周期、状态以及资源。
* **`bionic_tls`:** 这个结构体存储了线程本地存储的数据。每个线程都有自己独立的 `bionic_tls` 实例。
    * **关系:** Android 应用和系统库广泛使用线程本地存储来保存一些线程私有的数据，例如 `errno` 的值、locale 信息、以及通过 `pthread_key_create` 创建的线程特定数据。
    * **举例:** 当你调用 `errno` 获取错误码时，实际上访问的是当前线程 `bionic_tls` 结构体中的 `errno_value` 字段。类似地，与 locale 相关的函数也会访问 `bionic_tls` 中的 `locale` 字段。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个测试文件本身**并没有实现任何 libc 函数**。它的目的是**验证** bionic 库中关键数据结构的布局是否符合预期。

然而，我们可以根据测试涉及的结构体来推断相关的 libc 函数是如何使用这些结构的：

* **`pthread_create()`:** 当创建一个新线程时，bionic 会：
    1. 分配一块内存用于新的线程栈。
    2. 分配一个 `pthread_internal_t` 结构体实例。
    3. 初始化 `pthread_internal_t` 的各个字段，例如设置 `tid` (线程 ID)、`start_routine` (线程执行的函数)、`start_routine_arg` (传递给线程函数的参数)、`stack_top` (栈顶地址) 等。
    4. 分配并初始化 `bionic_tls` 结构体，并将其地址存储在 `pthread_internal_t` 的 `bionic_tls` 字段中。
    5. 将新的线程添加到线程管理列表中。
* **`pthread_join()`:** 当一个线程等待另一个线程结束时：
    1. 调用 `pthread_join` 的线程会检查目标线程的 `pthread_internal_t` 结构体的 `join_state` 字段。
    2. 如果目标线程尚未结束，调用线程会进入等待状态，可能涉及到修改自身 `pthread_internal_t` 的状态。
    3. 当目标线程结束时，会设置其 `pthread_internal_t` 的 `return_value` 字段为返回值，并唤醒等待的线程。
* **`pthread_getspecific()` 和 `pthread_setspecific()`:**  这些函数用于访问和设置线程特定数据：
    1. 每个通过 `pthread_key_create()` 创建的 key 会关联一个在 `bionic_tls` 的 `key_data` 数组中的索引。
    2. `pthread_getspecific()` 通过 key 找到对应的索引，然后访问当前线程 `bionic_tls` 结构体 `key_data` 数组的相应元素。
    3. `pthread_setspecific()` 类似地设置 `key_data` 数组的元素。
* **`errno`:** 这是一个宏，通常会展开为访问当前线程 `bionic_tls` 结构体中的 `errno_value` 字段。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`bionic_tls` 的分配和管理与 dynamic linker (linker64/linker) 的功能密切相关，特别是**线程本地存储 (TLS)** 的处理。

**so 布局样本 (简化)：**

```
.text:  # 代码段
    ...
.rodata: # 只读数据段
    ...
.data:   # 初始化数据段
    ...
.bss:    # 未初始化数据段
    ...
.tdata:  # TLS 初始化数据段 (Thread Local Storage Initialized Data)
    my_tls_variable: .word 0  # 线程本地变量的初始值
.tbss:   # TLS 未初始化数据段 (Thread Local Storage Uninitialized Data)
    another_tls_variable: .space 4 # 线程本地变量
```

* **`.tdata`:** 包含带有初始值的线程本地变量。
* **`.tbss`:** 包含没有初始值的线程本地变量。

**链接的处理过程 (针对 TLS)：**

1. **编译时：** 编译器会识别带有 TLS 属性的变量（例如，使用 `__thread` 关键字声明的变量），并将它们放入 `.tdata` 或 `.tbss` 段。
2. **链接时：**
   - Linker 会收集所有依赖库的 `.tdata` 和 `.tbss` 段的信息，计算所需的 TLS 空间大小。
   - Linker 会在可执行文件或共享库的头部（例如，在 `PT_TLS` program header 中）记录 TLS 的大小和初始值地址。
3. **运行时 (Dynamic Linker)：**
   - 当加载一个包含 TLS 段的共享库时，dynamic linker 会读取 `PT_TLS` 信息。
   - **对于主线程：**  dynamic linker 会在进程的地址空间中分配一块 TLS 模板 (TLS Template)，大小足以容纳所有已加载库的 TLS 数据，并使用 `.tdata` 中的初始值进行初始化。主线程的 `bionic_tls` 结构体通常位于这个 TLS 模板的某个固定偏移位置。
   - **对于新创建的线程：**
     - 当 `pthread_create` 被调用时，bionic 内部会请求 dynamic linker 为新线程分配一块独立的 TLS 块。
     - dynamic linker 会分配一块与 TLS 模板大小相同的内存，并将 TLS 模板的内容复制到这个新的 TLS 块中。
     - 新线程的 `pthread_internal_t` 结构体的 `bionic_tls` 字段会指向这块新分配的 TLS 块。
   - **TLS 的访问：**  代码中访问线程本地变量时，编译器会生成特殊的指令 (例如，使用 `gs` 段寄存器在 x86-64 架构上)，这些指令会根据当前线程的 TLS 基地址加上变量的偏移量来访问数据。TLS 基地址通常存储在 CPU 的特定寄存器中，由操作系统或 dynamic linker 设置。

**逻辑推理，请给出假设输入与输出：**

* **假设输入：** 在一个 64 位 Android 系统上运行这个测试。当前 `pthread_internal_t` 结构体的布局与测试代码中硬编码的值不一致，例如 `tid` 字段的实际偏移量是 20，而不是预期的 16。
* **输出：**
   - 测试会失败，`EXPECT_EQ(16, offset)` 的断言会触发错误。
   - 控制台会输出类似以下的错误信息：
     ```
     Value of: offset
     Actual: 20
     Expected: 16
     Which is: offsetof(pthread_internal_t, tid)
     bionic/tests/struct_layout_test.cpp:40: Failure
     ```
   - 还会打印出需要更新的测试代码：
     ```
     Please update the tests function in bionic/tests/struct_layout_test.cpp with the following contents:
       CHECK_SIZE(pthread_internal_t, 824);
       CHECK_OFFSET(pthread_internal_t, next, 0);
       CHECK_OFFSET(pthread_internal_t, prev, 8);
       CHECK_OFFSET(pthread_internal_t, tid, 20); // 注意这里变成了 20
       CHECK_OFFSET(pthread_internal_t, attr, 24);
       ...
     ```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

虽然用户或程序员不会直接操作 `pthread_internal_t` 或 `bionic_tls` 结构体，但如果这些结构体的布局在 bionic 内部发生意外变化，会导致各种难以调试的问题。这个测试的目的就是防止这种情况发生。

常见的使用错误，以及如果布局错误可能引发的问题：

1. **假设了结构体布局进行不安全的类型转换或内存操作:**
   - **错误示例:**  假设开发者错误地认为 `pthread_internal_t` 的某个成员在特定偏移量，并进行指针运算。
   - **后果:** 如果实际布局不同，会导致访问错误的内存地址，可能导致数据损坏、崩溃或其他未定义行为。

2. **与旧版本库的二进制不兼容:**
   - **场景:**  一个应用依赖于某个共享库，该库在编译时假设了特定的 `pthread_internal_t` 或 `bionic_tls` 布局。如果系统更新导致 bionic 的布局发生变化，旧的共享库可能无法正常工作。
   - **后果:**  运行时出现段错误、不一致的行为或崩溃。

3. **错误地使用线程本地存储:**
   - **错误示例:**  如果 `bionic_tls` 的布局错误，导致 `pthread_getspecific` 或 `pthread_setspecific` 访问了错误的内存位置。
   - **后果:**  线程之间的数据污染、程序逻辑错误、难以追踪的 bug。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 层):**
   - 当 Android Framework 需要执行并发任务时，可能会使用 `java.lang.Thread` 或 `java.util.concurrent` 包中的类，例如 `ThreadPoolExecutor`。
   - 这些 Java 层面的线程机制最终会调用到 Native 层的线程创建函数。

2. **NDK (Native 层):**
   - 使用 NDK 的开发者可以直接调用 POSIX 线程 API，例如 `pthread_create()`, `pthread_join()`, `pthread_getspecific()`, `pthread_setspecific()` 等。
   - 当调用这些函数时，会进入 bionic 库的实现。

3. **Bionic 库:**
   - `pthread_create()` 的 bionic 实现会分配和初始化 `pthread_internal_t` 结构体，并调用内核的 `clone()` 系统调用来创建新的内核线程。
   - `pthread_getspecific()` 和 `pthread_setspecific()` 的 bionic 实现会访问当前线程的 `bionic_tls` 结构体。

**Frida Hook 示例调试步骤：**

我们可以使用 Frida Hook 来观察 `pthread_create` 函数的调用以及相关数据结构的布局。

```python
import frida
import sys

# 连接到目标进程
process = frida.get_usb_device().attach('目标进程')

# 定义脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
  onEnter: function (args) {
    console.log("pthread_create called");
    var thread_func = new NativeFunction(args[2], 'void', ['pointer']);
    var arg = args[3];
    console.log("  Thread function:", thread_func);
    console.log("  Argument:", arg);
  },
  onLeave: function (retval) {
    console.log("pthread_create returned:", retval);
    if (retval == 0) { // 成功创建线程
      var new_thread_id = Java.vm.getEnv().getTid();
      console.log("  New thread ID:", new_thread_id);

      // 读取新线程的 pthread_internal_t 结构体 (需要知道结构体地址，这里假设可以获取到)
      // 注意：直接获取 pthread_internal_t 地址比较复杂，通常需要一些技巧
      // 这里仅为演示概念

      // 假设我们知道 pthread_internal_t 的地址
      // var pthread_internal_ptr = ...;

      // console.log("  pthread_internal_t->tid:", pthread_internal_ptr.readU32());
    }
  }
});

// Hook pthread_getspecific 来查看 TLS 访问
Interceptor.attach(Module.findExportByName("libc.so", "pthread_getspecific"), {
  onEnter: function (args) {
    var key = args[0];
    console.log("pthread_getspecific called with key:", key);
  },
  onLeave: function (retval) {
    console.log("pthread_getspecific returned:", retval);
  }
});
"""

# 创建并加载脚本
script = process.create_script(script_code)
script.load()

# 等待程序运行
sys.stdin.read()
```

**解释 Frida Hook 代码：**

1. **连接进程:**  `frida.get_usb_device().attach('目标进程')` 连接到目标 Android 进程。你需要将 `'目标进程'` 替换为实际的进程名称或 PID。
2. **Hook `pthread_create`:**
   - `Interceptor.attach` 用于拦截 `pthread_create` 函数的调用。
   - `onEnter` 回调函数会在 `pthread_create` 函数执行前被调用，可以打印出线程函数和参数。
   - `onLeave` 回调函数会在 `pthread_create` 函数执行后被调用，可以获取返回值和新线程的 ID。
   - 注释部分演示了如何尝试读取 `pthread_internal_t` 结构体的成员，但这通常需要更高级的技巧来获取结构体的地址。
3. **Hook `pthread_getspecific`:**
   - 拦截 `pthread_getspecific` 函数的调用，打印出访问的 key 和返回值，可以帮助理解 TLS 的使用。

**注意:**  直接在运行时读取 `pthread_internal_t` 或 `bionic_tls` 结构体的成员需要知道这些结构体在内存中的确切地址。这通常需要一些技巧，例如：

* **通过符号查找:** 如果 bionic 库没有被 strip 掉符号，可以尝试找到这些结构体的地址。
* **通过调试信息:** 使用包含调试信息的 bionic 库进行调试。
* **通过内存扫描:** 在某些情况下，可以扫描进程内存来查找可能的结构体实例。

这个测试文件 `bionic/tests/struct_layout_test.cpp` 虽然看起来简单，但对于保证 Android 系统的稳定性和兼容性至关重要。它通过自动化测试来防止由于 bionic 库内部数据结构布局的意外变化而导致的问题。

Prompt: 
```
这是目录为bionic/tests/struct_layout_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stdio.h>

#if defined(__BIONIC__)
#include "bionic/pthread_internal.h"

// Ensure that the layout of these data structures is architecture independent and only depends on
// the bitness of the architecture.
template <typename CheckSize, typename CheckOffset>
void tests(CheckSize check_size, CheckOffset check_offset) {
#define CHECK_SIZE(name, size) \
    check_size(#name, sizeof(name), size);
#define CHECK_OFFSET(name, field, offset) \
    check_offset(#name, #field, offsetof(name, field), offset);
#ifdef __LP64__
  CHECK_SIZE(pthread_internal_t, 824);
  CHECK_OFFSET(pthread_internal_t, next, 0);
  CHECK_OFFSET(pthread_internal_t, prev, 8);
  CHECK_OFFSET(pthread_internal_t, tid, 16);
  CHECK_OFFSET(pthread_internal_t, attr, 24);
  CHECK_OFFSET(pthread_internal_t, join_state, 80);
  CHECK_OFFSET(pthread_internal_t, cleanup_stack, 88);
  CHECK_OFFSET(pthread_internal_t, start_routine, 96);
  CHECK_OFFSET(pthread_internal_t, start_routine_arg, 104);
  CHECK_OFFSET(pthread_internal_t, return_value, 112);
  CHECK_OFFSET(pthread_internal_t, start_mask, 120);
  CHECK_OFFSET(pthread_internal_t, alternate_signal_stack, 128);
  CHECK_OFFSET(pthread_internal_t, shadow_call_stack_guard_region, 136);
  CHECK_OFFSET(pthread_internal_t, stack_top, 144);
  CHECK_OFFSET(pthread_internal_t, startup_handshake_lock, 156);
  CHECK_OFFSET(pthread_internal_t, mmap_base, 168);
  CHECK_OFFSET(pthread_internal_t, mmap_size, 176);
  CHECK_OFFSET(pthread_internal_t, mmap_base_unguarded, 184);
  CHECK_OFFSET(pthread_internal_t, mmap_size_unguarded, 192);
  CHECK_OFFSET(pthread_internal_t, vma_name_buffer, 200);
  CHECK_OFFSET(pthread_internal_t, thread_local_dtors, 232);
  CHECK_OFFSET(pthread_internal_t, current_dlerror, 240);
  CHECK_OFFSET(pthread_internal_t, dlerror_buffer, 248);
  CHECK_OFFSET(pthread_internal_t, bionic_tls, 760);
  CHECK_OFFSET(pthread_internal_t, errno_value, 768);
  CHECK_OFFSET(pthread_internal_t, bionic_tcb, 776);
  CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 784);
  CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 816);
  CHECK_SIZE(bionic_tls, 12200);
  CHECK_OFFSET(bionic_tls, key_data, 0);
  CHECK_OFFSET(bionic_tls, locale, 2080);
  CHECK_OFFSET(bionic_tls, basename_buf, 2088);
  CHECK_OFFSET(bionic_tls, dirname_buf, 6184);
  CHECK_OFFSET(bionic_tls, mntent_buf, 10280);
  CHECK_OFFSET(bionic_tls, mntent_strings, 10320);
  CHECK_OFFSET(bionic_tls, ptsname_buf, 11344);
  CHECK_OFFSET(bionic_tls, ttyname_buf, 11376);
  CHECK_OFFSET(bionic_tls, strerror_buf, 11440);
  CHECK_OFFSET(bionic_tls, strsignal_buf, 11695);
  CHECK_OFFSET(bionic_tls, group, 11952);
  CHECK_OFFSET(bionic_tls, passwd, 12040);
  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 12192);
  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 12193);
  CHECK_OFFSET(bionic_tls, padding, 12194);
#else
  CHECK_SIZE(pthread_internal_t, 708);
  CHECK_OFFSET(pthread_internal_t, next, 0);
  CHECK_OFFSET(pthread_internal_t, prev, 4);
  CHECK_OFFSET(pthread_internal_t, tid, 8);
  CHECK_OFFSET(pthread_internal_t, attr, 16);
  CHECK_OFFSET(pthread_internal_t, join_state, 40);
  CHECK_OFFSET(pthread_internal_t, cleanup_stack, 44);
  CHECK_OFFSET(pthread_internal_t, start_routine, 48);
  CHECK_OFFSET(pthread_internal_t, start_routine_arg, 52);
  CHECK_OFFSET(pthread_internal_t, return_value, 56);
  CHECK_OFFSET(pthread_internal_t, start_mask, 60);
  CHECK_OFFSET(pthread_internal_t, alternate_signal_stack, 68);
  CHECK_OFFSET(pthread_internal_t, shadow_call_stack_guard_region, 72);
  CHECK_OFFSET(pthread_internal_t, stack_top, 76);
  CHECK_OFFSET(pthread_internal_t, startup_handshake_lock, 84);
  CHECK_OFFSET(pthread_internal_t, mmap_base, 92);
  CHECK_OFFSET(pthread_internal_t, mmap_size, 96);
  CHECK_OFFSET(pthread_internal_t, mmap_base_unguarded, 100);
  CHECK_OFFSET(pthread_internal_t, mmap_size_unguarded, 104);
  CHECK_OFFSET(pthread_internal_t, vma_name_buffer, 108);
  CHECK_OFFSET(pthread_internal_t, thread_local_dtors, 140);
  CHECK_OFFSET(pthread_internal_t, current_dlerror, 144);
  CHECK_OFFSET(pthread_internal_t, dlerror_buffer, 148);
  CHECK_OFFSET(pthread_internal_t, bionic_tls, 660);
  CHECK_OFFSET(pthread_internal_t, errno_value, 664);
  CHECK_OFFSET(pthread_internal_t, bionic_tcb, 668);
  CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 672);
  CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 704);
  CHECK_SIZE(bionic_tls, 11080);
  CHECK_OFFSET(bionic_tls, key_data, 0);
  CHECK_OFFSET(bionic_tls, locale, 1040);
  CHECK_OFFSET(bionic_tls, basename_buf, 1044);
  CHECK_OFFSET(bionic_tls, dirname_buf, 5140);
  CHECK_OFFSET(bionic_tls, mntent_buf, 9236);
  CHECK_OFFSET(bionic_tls, mntent_strings, 9260);
  CHECK_OFFSET(bionic_tls, ptsname_buf, 10284);
  CHECK_OFFSET(bionic_tls, ttyname_buf, 10316);
  CHECK_OFFSET(bionic_tls, strerror_buf, 10380);
  CHECK_OFFSET(bionic_tls, strsignal_buf, 10635);
  CHECK_OFFSET(bionic_tls, group, 10892);
  CHECK_OFFSET(bionic_tls, passwd, 10952);
  CHECK_OFFSET(bionic_tls, fdtrack_disabled, 11076);
  CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 11077);
  CHECK_OFFSET(bionic_tls, padding, 11078);
#endif  // __LP64__
#undef CHECK_SIZE
#undef CHECK_OFFSET
}
#endif  // defined(__BIONIC__)

TEST(struct_layout, sizes_offsets) {
#if defined(__BIONIC__)
  bool failed = false;

  auto check_size = [&](const char* name, size_t size, size_t expected_size) {
    EXPECT_EQ(expected_size, size) << "sizeof(" << name << ")";
    if (size != expected_size) {
      failed = true;
    }
  };
  auto check_offset = [&](const char* name, const char* field, size_t offset,
                          size_t expected_offset) {
    EXPECT_EQ(expected_offset, offset) << "offsetof(" << name << ", " << field << ")";
    if (offset != expected_offset) {
      failed = true;
    }
  };
  tests(check_size, check_offset);

  if (failed) {
    printf(
        "Please update the tests function in bionic/tests/struct_layout_test.cpp with the "
        "following contents:\n");

    auto print_size = [&](const char* name, size_t size, size_t expected_size) {
      (void)expected_size;
      printf("  CHECK_SIZE(%s, %zu);\n", name, size);
    };
    auto print_offset = [&](const char* name, const char* field, size_t offset,
                            size_t expected_offset) {
      (void)expected_offset;
      printf("  CHECK_OFFSET(%s, %s, %zu);\n", name, field, offset);
    };
    tests(print_size, print_offset);
  }
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

"""

```