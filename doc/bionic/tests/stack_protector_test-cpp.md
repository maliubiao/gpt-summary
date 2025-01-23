Response:
Let's break down the thought process for answering the user's request about `stack_protector_test.cpp`.

**1. Understanding the Core Purpose:**

The filename and the presence of `__stack_chk_guard` immediately flag this as a test for the stack protector mechanism. The comments and imports confirm this. The fundamental goal is to ensure the stack protector is functioning correctly in the Android bionic library.

**2. Deconstructing the Code:**

I go through the code section by section, identifying key components and their roles:

* **Includes:**  `gtest`, standard C/C++ headers (`pthread.h`, `stdint.h`, etc.), Android-specific headers (`android-base/silent_death_test.h`, `platform/bionic/mte.h`, `private/bionic_tls.h`). This signals testing infrastructure, threading, basic types, and features related to memory protection and thread-local storage.
* **External Declarations:** `gettid()`, `__stack_chk_guard`. These are vital for understanding what the tests are interacting with. `gettid()` points to thread identification, and `__stack_chk_guard` is the core of the stack protector.
* **`stack_protector_checker` struct:**  This is clearly a helper class for the tests. The `tids` and `guards` sets suggest verification of uniqueness and consistency of the stack guard across threads. The `Check()` method encapsulates the core assertion logic.
* **`TEST(stack_protector, same_guard_per_thread)`:** The name is self-explanatory. This test aims to confirm that all threads within a process share the same stack guard value. The loop creating and joining threads supports this.
* **`TEST(stack_protector, global_guard)`:**  This test verifies the existence and non-zero nature of the global `__stack_chk_guard` in bionic (and skips in glibc).
* **`escape_stack_safety_analysis` and related code:** This section is about Memory Tagging Extension (MTE) and Hardware Address Sanitizer (HWASan). The functions and conditional compilation show an awareness of alternative memory safety mechanisms and how they might interact with or replace the stack protector.
* **`stack_protector_DeathTest` and `modify_stack_protector`:** This uses Google Test's death test feature to check that deliberately corrupting the stack protector leads to a program termination with `SIGABRT`. The `modify_stack_protector_test()` function being external is crucial for preventing inlining.

**3. Answering the User's Questions Systematically:**

Now, I address each part of the user's prompt:

* **功能 (Functions):**  I list the main functionalities observed in the code: verifying per-thread guard uniqueness, checking guard initialization, validating the global guard (bionic specific), and testing the crash behavior upon stack protector corruption.
* **与 Android 功能的关系 (Relationship to Android Features):** I explain that this test is *part of* Android's bionic library and is crucial for security. I relate it to overall system stability and vulnerability prevention.
* **详细解释 libc 函数的功能是如何实现的 (Detailed Explanation of libc Functions):**  I focus on the libc functions used *within the test*:
    * `pthread_create/join`:  Standard threading primitives. I briefly explain their role in creating and waiting for threads.
    * `gettid`:  Retrieving the thread ID.
    * `printf`:  For outputting debugging information (within the test itself).
    * Assertions (`ASSERT_FALSE`, `ASSERT_NE`, `ASSERT_EQ`, `ASSERT_EXIT`):  These are from Google Test and are fundamental to how the tests verify correctness. I explain their purpose.
* **涉及 dynamic linker 的功能 (Dynamic Linker Functionality):**  This is where I need to connect the test to the dynamic linker.
    * **SO Layout Sample:** I provide a simplified example showing how `libc.so` (containing the stack protector implementation) would be loaded and its relationship to the application.
    * **链接的处理过程 (Linking Process):** I describe the dynamic linking process conceptually, focusing on symbol resolution (how the test finds `__stack_chk_guard` and `gettid`) and the role of the dynamic linker.
* **逻辑推理，给出假设输入与输出 (Logical Reasoning, Hypothetical Input/Output):**  I focus on the core logic within the `Check()` function. I create a scenario where the assertions *would* fail to illustrate the conditions being tested.
* **用户或者编程常见的使用错误 (Common User/Programming Errors):** I provide examples of stack buffer overflows as the primary scenario that the stack protector aims to prevent.
* **android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK Reaches Here):**  I trace a simplified path, starting from a high-level Android application using the NDK, through the compilation and linking stages, and how the bionic library is ultimately involved.
* **frida hook 示例调试这些步骤 (Frida Hook Example):**  I provide practical Frida snippets for hooking `gettid` and `__get_tls` to inspect the stack guard's value at runtime.

**4. Language and Tone:**

I ensure the response is in Chinese, as requested, and maintains a clear and informative tone. I avoid overly technical jargon where simpler explanations suffice.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Focus heavily on the stack protector's *implementation*.
* **Correction:**  Shift focus to explaining *how the test verifies* the stack protector's functionality. The user asked about the *test*, not the low-level implementation details of stack canaries. I still include some information about the guard, but the emphasis is on the test's logic.
* **Initial thought:**  Get bogged down in the details of TLS.
* **Correction:**  Provide a high-level explanation of TLS in the context of the test, specifically how `__get_tls()` provides access to the stack guard. Avoid overly technical details about TLS implementation.
* **Initial thought:**  Only discuss the bionic-specific parts.
* **Correction:**  Acknowledge the differences with glibc where relevant (e.g., the `global_guard` test).

By following this structured approach and iteratively refining my understanding of the code and the user's questions, I aim to provide a comprehensive and accurate answer.
这个 `bionic/tests/stack_protector_test.cpp` 文件是 Android Bionic 库中用于测试栈保护机制 (`stack protector`) 功能的单元测试文件。它的主要目的是验证 Bionic 库中栈保护机制的正确性和有效性。

以下是该文件的详细功能及其与 Android 功能的关系：

**1. 主要功能:**

* **验证每个线程是否拥有相同的栈保护金丝雀 (Stack Guard):**  `TEST(stack_protector, same_guard_per_thread)` 测试用例会创建多个线程，并检查每个线程的栈保护金丝雀值是否相同。这是栈保护机制的一个关键特性，即在同一进程内的所有线程都应该共享同一个全局金丝雀值。
* **验证是否存在全局栈保护金丝雀:** `TEST(stack_protector, global_guard)` 测试用例检查 Bionic 库中是否定义并初始化了全局的 `__stack_chk_guard` 变量。这个全局变量用于初始化每个线程的栈保护金丝雀。这个测试在 glibc 上会被跳过，因为 glibc 不一定有全局的 `__stack_chk_guard`。
* **测试栈溢出保护机制是否生效:** `TEST_F(stack_protector_DeathTest, modify_stack_protector)` 测试用例通过调用外部函数 `modify_stack_protector_test()` 来故意修改栈上的栈保护金丝雀值。预期结果是程序会因为检测到栈溢出而被终止 (收到 `SIGABRT` 信号)，并输出 "stack corruption detected" 的错误信息。这个测试验证了栈保护机制能够检测到并阻止栈溢出攻击。
* **检查 MTE 和 HWASan 的影响:** 代码中包含了对内存标记扩展 (MTE) 和硬件地址消毒器 (HWASan) 的检查。如果启用了 MTE 或 HWASan，则会跳过 `modify_stack_protector` 测试，因为这些更先进的内存安全机制可能会影响传统的栈保护机制的行为或使其变得不必要。
* **验证 TLS 槽位是否正确设置:** 测试用例 `same_guard_per_thread` 中使用了 `__get_tls()[TLS_SLOT_STACK_GUARD]` 来获取当前线程的栈保护金丝雀值，这隐含地验证了线程本地存储 (TLS) 中用于存储栈保护金丝雀的槽位是否被正确设置。

**2. 与 Android 功能的关系及举例说明:**

栈保护机制是 Android 系统安全性的重要组成部分，用于防止栈缓冲区溢出攻击。

* **防止应用崩溃和安全漏洞:** 当一个程序存在栈缓冲区溢出漏洞时，攻击者可以覆盖栈上的返回地址，从而在函数返回时执行恶意代码。栈保护机制通过在函数入口处将一个随机值（金丝雀）放置在返回地址之前，并在函数返回前检查该值是否被修改，来阻止这种攻击。如果金丝雀值被修改，则说明发生了栈溢出，程序会被立即终止，从而避免执行恶意代码。这提高了 Android 应用程序的稳定性和安全性。
* **NDK 开发的安全性:**  使用 Android NDK 进行原生代码开发时，更容易出现内存相关的错误，包括栈溢出。Bionic 库提供的栈保护机制可以帮助开发者在开发阶段尽早发现和修复这些漏洞，从而提高 NDK 应用的安全性。
* **系统服务的安全性:** Android 系统中的许多核心服务也是使用 C/C++ 编写的，并使用 Bionic 库。栈保护机制可以保护这些系统服务免受栈溢出攻击，从而确保系统的整体稳定性和安全性。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件中使用了一些 libc 函数，以下是它们的简要说明（更底层的实现会涉及汇编代码和操作系统内核）：

* **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`:**  用于创建一个新的线程。
    * **实现原理:**  `pthread_create` 会请求操作系统创建一个新的执行线程。这通常涉及分配新的栈空间，设置线程的入口函数 (`start_routine`)，并将其加入到操作系统的调度队列中。在 Bionic 中，`pthread_create` 的实现会处理与 TLS 相关的初始化，包括为新线程分配 TLS 块并设置栈保护金丝雀。
* **`pthread_join(pthread_t thread, void **retval)`:** 用于等待指定的线程结束。
    * **实现原理:** `pthread_join` 会阻塞调用线程，直到目标线程执行完毕。操作系统会维护线程的状态，当目标线程退出时，操作系统会唤醒等待的线程。
* **`gettid()`:** 用于获取当前线程的 ID (Thread ID)。
    * **实现原理:**  在 Linux 系统中，每个线程都有一个唯一的 TID。`gettid` 系统调用会直接从内核中获取当前线程的 TID。
* **`printf(const char *format, ...)`:**  用于格式化输出字符串到标准输出。
    * **实现原理:**  `printf` 会解析格式化字符串 (`format`)，并将后续的参数按照指定的格式转换为字符串，然后通过 `write` 系统调用将结果输出到标准输出文件描述符。
* **`unistd.h` 中的函数 (例如 `sleep`, `usleep` 等):** 这个测试中没有直接使用 `unistd.h` 中的函数，但 `pthread_create` 等函数的底层实现可能会用到。这些函数通常是与操作系统交互的系统调用包装器。
* **`ASSERT_*` (来自 Google Test):** 这些不是 libc 函数，而是 Google Test 框架提供的断言宏，用于在测试中检查条件是否成立。
* **`__get_tls()`:**  这是一个 Bionic 库内部的函数，用于获取当前线程的 TLS (Thread-Local Storage) 块的地址。
    * **实现原理:**  TLS 允许每个线程拥有自己独立的全局变量副本。`__get_tls()` 的实现通常依赖于特定的架构和编译器的约定，例如使用特定的寄存器来指向当前线程的 TLS 块。
* **`mte_supported()`:**  这是一个 Bionic 库内部的函数，用于检测当前硬件和内核是否支持内存标记扩展 (Memory Tagging Extension)。
* **`__has_feature(hwaddress_sanitizer)`:**  这是一个编译器内置的宏，用于检查编译时是否启用了 HWASan (Hardware Address Sanitizer)。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

该测试文件本身并没有直接涉及 dynamic linker 的复杂操作，但它依赖于 Bionic 库 (`libc.so`) 中实现的栈保护机制。

**SO 布局样本 (简化的 `libc.so` 布局):**

```
libc.so:
    .text:
        ; ... 一些函数代码 ...
        __stack_chk_fail:  ; 栈保护失败时的处理函数
            ; ... 终止程序的操作 ...
        __stack_chk_guard:  ; 全局栈保护金丝雀变量
            .quad 0  ; 实际值在运行时初始化
        ; ... 其他函数代码 ...
        pthread_create:
            ; ... 创建线程的实现 ...
            ; 在这里会设置新线程的栈保护金丝雀，通常从 __stack_chk_guard 获取
        __get_tls:
            ; ... 获取当前线程 TLS 块地址的实现 ...
    .data:
        ; ... 全局数据 ...
    .tbss:  ; 线程本地未初始化数据段
        ; ... TLS 相关的变量，可能包含用于存储栈保护金丝雀的槽位 ...
```

**链接的处理过程:**

1. **编译时链接:**  在编译 `stack_protector_test.cpp` 时，编译器会识别出对 `__stack_chk_guard` 和 `gettid` 等符号的引用。由于这些符号是在 `libc.so` 中定义的，链接器会将对这些符号的引用标记为需要在运行时进行动态链接。
2. **加载时链接 (Dynamic Linking):** 当运行测试程序时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** 动态链接器会遍历所有加载的共享库，查找未解析的符号。当找到 `__stack_chk_guard` 和 `gettid` 的定义时，会将测试程序中对这些符号的引用绑定到 `libc.so` 中的对应地址。
4. **TLS 初始化:**  在加载 `libc.so` 和创建线程的过程中，动态链接器和 Bionic 库会协同工作来初始化每个线程的 TLS 块，并在 TLS 块的特定槽位中存储栈保护金丝雀的值。这个值通常是从全局的 `__stack_chk_guard` 复制而来。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

该测试的核心逻辑在于验证栈保护机制的行为。以 `modify_stack_protector` 测试为例：

**假设输入:**  程序正常启动，栈保护机制已启用。`modify_stack_protector_test()` 函数被调用，并在其内部故意修改了当前函数栈帧上的栈保护金丝雀值。

**预期输出:**

* 程序会因为检测到栈溢出而调用 `__stack_chk_fail` 函数。
* `__stack_chk_fail` 函数通常会调用 `abort()` 或类似的机制来终止程序，并可能输出错误信息。
* `ASSERT_EXIT` 断言会捕获到程序被 `SIGABRT` 信号终止，并且输出信息中包含 "stack corruption detected"。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **栈缓冲区溢出:**  这是栈保护机制主要防御的目标。例如，使用 `strcpy` 将一个比目标缓冲区大的字符串复制到栈上的字符数组中，就会导致栈溢出，覆盖栈上的返回地址或栈保护金丝雀。

   ```c++
   void vulnerable_function(const char* input) {
       char buffer[10];
       strcpy(buffer, input); // 如果 input 长度超过 9，就会发生栈溢出
   }
   ```

   **预期行为 (有栈保护):**  程序会检测到栈金丝雀被修改，并终止。

   **预期行为 (无栈保护):**  程序可能会执行到返回指令时跳转到被覆盖的地址，导致不可预测的行为或安全漏洞。

* **错误地禁用栈保护:**  在某些情况下，开发者可能会错误地禁用栈保护，例如使用编译器选项 `-fno-stack-protector`。这会使程序容易受到栈溢出攻击。

* **与内联函数的交互:**  有时，编译器可能会内联一些函数，这可能会消除栈保护的效果。测试用例中的 `modify_stack_protector_test` 被声明为 `extern` 以防止内联，确保栈保护机制能够被测试到。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework/NDK 到 `stack_protector_test.cpp` 的路径 (逻辑上的，非实际执行路径):**

1. **NDK 开发:** 开发者使用 Android NDK 编写 C/C++ 代码。这些代码会链接到 Bionic 库提供的功能。
2. **编译 NDK 代码:** NDK 工具链 (包括编译器和链接器) 会将 C/C++ 代码编译成机器码，并链接到所需的库，包括 `libc.so` (Bionic 的 C 库)。
3. **动态链接:** 当 NDK 应用在 Android 设备上运行时，Android 的动态链接器会加载应用的依赖库，包括 `libc.so`。
4. **栈保护机制的应用:**  在应用执行过程中，每当调用一个函数时，如果启用了栈保护，编译器会在函数入口处插入代码来设置栈金丝雀，并在函数返回前插入代码来检查金丝雀是否被修改。这些机制由 `libc.so` 提供。
5. **`stack_protector_test.cpp` 的作用:**  `stack_protector_test.cpp` 不是应用运行时的代码路径，而是 Bionic 库自身的单元测试。它用于验证 Bionic 库中栈保护机制的实现是否正确。开发者或 Android 系统构建者会运行这些测试来确保 Bionic 库的质量。

**Frida Hook 示例调试步骤:**

假设你想观察栈保护金丝雀的值以及 `__stack_chk_fail` 函数的调用：

```python
import frida
import sys

# 要附加的目标进程，可以是进程名或进程 ID
package_name = "com.example.myndkapp"  # 替换为你的 NDK 应用包名

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit(1)

script_code = """
console.log("开始 Hook...");

// Hook __stack_chk_guard 的值 (注意：这可能需要在特定时机进行，例如线程创建后)
var stack_chk_guard_ptr = Module.findExportByName("libc.so", "__stack_chk_guard");
if (stack_chk_guard_ptr) {
    console.log("__stack_chk_guard 地址: " + stack_chk_guard_ptr);
    // 读取 __stack_chk_guard 的值
    var stack_chk_guard = ptr(stack_chk_guard_ptr).readU64();
    console.log("__stack_chk_guard 的值: " + stack_chk_guard.toString(16));
} else {
    console.log("未找到 __stack_chk_guard 符号");
}

// Hook __stack_chk_fail 函数
var stack_chk_fail_ptr = Module.findExportByName("libc.so", "__stack_chk_fail");
if (stack_chk_fail_ptr) {
    console.log("__stack_chk_fail 地址: " + stack_chk_fail_ptr);
    Interceptor.attach(stack_chk_fail_ptr, {
        onEnter: function(args) {
            console.warn("!!! 检测到栈溢出 !!!");
            // 可以进一步检查调用栈等信息
            console.log(Thread.backtrace().map(DebugSymbol.fromAddress).join('\\n'));
        }
    });
} else {
    console.log("未找到 __stack_chk_fail 符号");
}

// 还可以 Hook 与 TLS 相关的函数，例如 __get_tls
var get_tls_ptr = Module.findExportByName("libc.so", "__get_tls");
if (get_tls_ptr) {
    console.log("__get_tls 地址: " + get_tls_ptr);
    Interceptor.attach(get_tls_ptr, {
        onLeave: function(retval) {
            console.log("__get_tls 返回值 (TLS 块地址): " + retval);
            // 尝试读取 TLS 槽位中的栈保护金丝雀 (需要知道槽位的偏移)
            // 这部分比较复杂，可能需要分析 Bionic 的 TLS 实现
        }
    });
} else {
    console.log("未找到 __get_tls 符号");
}

console.log("Hook 完成.");
""";

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**使用 Frida Hook 的步骤:**

1. **安装 Frida:** 确保你的开发机器上安装了 Frida 和 Frida-tools。
2. **找到目标进程:** 确定你要调试的 NDK 应用的进程名或进程 ID。
3. **编写 Frida 脚本:**  如上面的示例代码，使用 Frida 的 JavaScript API 来 Hook 感兴趣的函数或变量。
4. **运行 Frida 脚本:** 使用 `frida -U -f com.example.myndkapp script.py` (如果附加到新启动的进程) 或 `frida -U <进程名或ID> script.py` (如果附加到正在运行的进程) 来运行脚本。
5. **触发栈溢出 (如果需要):**  在你的 NDK 应用中触发可能导致栈溢出的操作，观察 Frida 的输出。

通过 Frida Hook，你可以动态地观察栈保护机制的行为，例如查看金丝雀的值，以及在发生栈溢出时 `__stack_chk_fail` 函数是否被调用，从而更深入地理解其工作原理。

总而言之，`bionic/tests/stack_protector_test.cpp` 是一个关键的测试文件，用于验证 Android Bionic 库中栈保护机制的正确性，这对于确保 Android 系统的安全性和稳定性至关重要。它通过创建线程、检查金丝雀值、以及模拟栈溢出等方式来测试栈保护的各个方面。

### 提示词
```
这是目录为bionic/tests/stack_protector_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2012 The Android Open Source Project
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

/*
 * Contributed by: Intel Corporation
 */

#include <gtest/gtest.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <set>

#include <android-base/silent_death_test.h>

#include "platform/bionic/mte.h"
#include "private/bionic_tls.h"

extern "C" pid_t gettid(); // glibc defines this but doesn't declare it anywhere.

#if defined(__BIONIC__)
extern uintptr_t __stack_chk_guard;
#endif

struct stack_protector_checker {
  std::set<pid_t> tids;
  std::set<void*> guards;

  void Check() {
    pid_t tid = gettid();
    void* guard = __get_tls()[TLS_SLOT_STACK_GUARD];

    printf("[thread %d] TLS stack guard = %p\n", tid, guard);

    // Duplicate tid. gettid(2) bug? Seeing this would be very upsetting.
    ASSERT_FALSE(tids.contains(tid));

    // Uninitialized guard. Our bug. Note this is potentially flaky; we _could_
    // get four random zero bytes, but it should be vanishingly unlikely.
    ASSERT_NE(guard, nullptr);

#if defined(__BIONIC__)
    // bionic always has the global too.
    ASSERT_EQ(__stack_chk_guard, reinterpret_cast<uintptr_t>(guard));
#endif

    tids.insert(tid);
    guards.insert(guard);
  }
};

TEST(stack_protector, same_guard_per_thread) {
  // Everyone has the TLS slot set, even if their stack protector
  // implementation doesn't yet use it.
  stack_protector_checker checker;

  // Check the main thread.
  ASSERT_EQ(getpid(), gettid()); // We are the main thread, right?
  checker.Check();

  size_t thread_count = 9;
  for (size_t i = 1; i < thread_count; ++i) {
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, nullptr, [](void* arg) -> void* {
      stack_protector_checker* checker = reinterpret_cast<stack_protector_checker*>(arg);
      checker->Check();
      return nullptr;
    }, &checker));
    void* result;
    ASSERT_EQ(0, pthread_join(t, &result));
    ASSERT_EQ(nullptr, result);
  }
  ASSERT_EQ(thread_count, checker.tids.size());

  // Both bionic and glibc use the same guard for every thread.
  ASSERT_EQ(1U, checker.guards.size());
}

TEST(stack_protector, global_guard) {
#if defined(__BIONIC__)
  // Bionic always has a global, even if it's using TLS.
  ASSERT_NE(0, gettid());
  ASSERT_NE(0U, __stack_chk_guard);
#else
  GTEST_SKIP() << "glibc doesn't have a global __stack_chk_guard";
#endif
}

// Make sure that a stack variable (`*p`) is tagged under MTE, by forcing the
// stack safety analysis to fail.
int z;
__attribute__((noinline)) void escape_stack_safety_analysis(int* p) {
  *p = z;
}

bool stack_mte_enabled() {
  if (!mte_supported()) return false;
  int stack_variable;
  escape_stack_safety_analysis(&stack_variable);
#if defined(__aarch64__)
  return reinterpret_cast<uintptr_t>(&stack_variable) & (0xfull << 56);
#else   // !defined(__aarch64__)
  return false;
#endif  // defined(__aarch64__)
}

bool hwasan_enabled() {
#if __has_feature(hwaddress_sanitizer)
  return true;
#else
  return false;
#endif  // __has_feature(hwaddress_sanitizer)
}

using stack_protector_DeathTest = SilentDeathTest;

TEST_F(stack_protector_DeathTest, modify_stack_protector) {
  // In another file to prevent inlining, which removes stack protection.
  extern void modify_stack_protector_test();

  if (stack_mte_enabled()) {
    GTEST_SKIP() << "Stack MTE is enabled, stack protector is not available";
  } else if (hwasan_enabled()) {
    GTEST_SKIP() << "HWASan is enabled, stack protector is not testable";
  } else {
    ASSERT_EXIT(modify_stack_protector_test(), testing::KilledBySignal(SIGABRT),
                "stack corruption detected");
  }
}
```