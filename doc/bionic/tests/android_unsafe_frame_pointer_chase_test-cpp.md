Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The first step is to understand *why* this test file exists. The file name `android_unsafe_frame_pointer_chase_test.cpp` and the location `bionic/tests` immediately suggest it's testing a specific function within Android's core C library (bionic). The function name `android_unsafe_frame_pointer_chase` is a key piece of information. It hints at stack tracing or debugging capabilities, likely related to obtaining call stacks without relying on reliable frame pointers (which can be disabled for optimization).

**2. High-Level Overview of the Code:**

Quickly scan the file structure. We see:

* Includes: `gtest/gtest.h`, `sys/mman.h`, and the target header `platform/bionic/android_unsafe_frame_pointer_chase.h`. This tells us it's a unit test using Google Test and interacts with memory management.
* Conditional Compilation: `#if defined(__BIONIC__)` indicates this test is specific to the bionic environment.
* Helper Functions: `nop`, `recurse`, `CheckFrames`, `tester_func`, `BacktraceThread`, `BacktraceHandler`, `SignalBacktraceThread`, `SigaltstackOnCallerStack`. These functions are likely used to set up different test scenarios.
* `TEST` macros: These are the actual Google Test cases. We can see different scenarios being tested: `main_thread`, `pthread`, `sigaltstack`, `sigaltstack_on_main_thread`, `sigaltstack_on_pthread`.

**3. Deeper Dive into Key Functions:**

Now, focus on the core logic:

* **`android_unsafe_frame_pointer_chase`:**  This is the function under test. The name itself is quite descriptive. The test cases call it, so its purpose is to collect stack frames. The "unsafe" part suggests it might rely on heuristics or less precise methods than traditional frame pointer unwinding.
* **`recurse`:** This function creates a controlled stack depth. The `count` parameter determines how many times it calls itself. This is a common pattern for testing stack-related functions. The `noinline` attribute is important as it prevents the compiler from optimizing away the recursive calls, ensuring a deeper stack.
* **`CheckFrames`:** This function validates the collected stack frames. It has specific expectations about the order and repetition of the frames, based on how `recurse` is designed. This is where the assumptions about how `android_unsafe_frame_pointer_chase` should work are codified.
* **Test Cases (`TEST` macros):**  Each test case explores a different context in which `android_unsafe_frame_pointer_chase` might be used:
    * `main_thread`:  Simple case, calling it directly on the main thread.
    * `pthread`: Testing in a multithreaded environment.
    * `sigaltstack`: Testing within a signal handler that uses an alternate stack. This is crucial because signal handlers can interrupt normal execution and use a different stack, which needs to be handled correctly by stack unwinding mechanisms.

**4. Analyzing Test Scenarios:**

For each test case, try to understand the setup and the expected outcome:

* **`main_thread`:**  Calls `recurse` twice, once to get the expected stack size and once to actually collect the frames. `CheckFrames` verifies the results.
* **`pthread`:** Creates a new thread that calls `tester_func`, which internally uses `recurse` and `CheckFrames`. This verifies thread safety.
* **`sigaltstack`:** This is the most complex case. It sets up an alternate signal stack using `sigaltstack`. It then triggers a signal (`SIGRTMIN`). The signal handler (`BacktraceHandler`) calls `tester_func`. This test verifies that `android_unsafe_frame_pointer_chase` can correctly traverse the stack even when a signal handler is involved and using an alternate stack. The loop with `i` alternating the order of the regular and alternate stacks is a clever way to ensure robustness against different memory layouts.
* **`sigaltstack_on_main_thread` and `sigaltstack_on_pthread`:** These test calling the signal mechanism directly on the main thread and within a created thread, respectively, simplifying the setup compared to the full `sigaltstack` test but still exercising the alternate stack logic.

**5. Linking to Android Functionality:**

Think about where stack tracing is used in Android:

* **Debugging:**  Tools like `adb shell pstack`, crash dump analysis, and debuggers rely on stack traces.
* **Error Reporting:**  When an app crashes, the system logs a stack trace to help developers diagnose the problem.
* **Profiling:**  Performance profiling tools often use stack sampling to identify performance bottlenecks.
* **Security:** Stack canaries and other security features involve understanding stack layout.

**6. Considering Potential Issues:**

Think about the "unsafe" aspect. What could go wrong?

* **Compiler Optimizations:** Tail call optimization could interfere with the expected stack layout if `android_unsafe_frame_pointer_chase` relies on specific frame arrangements. The `noinline` attribute in `recurse` addresses this.
* **Signal Handlers:**  Signal handlers run asynchronously and might use different stacks, as explicitly tested here.
* **Threading:**  Each thread has its own stack. The function needs to work correctly in multithreaded scenarios.
* **Stack Overflow:** While not directly tested here, stack tracing is often needed when stack overflows occur.

**7. Dynamic Linker Aspects (Less Relevant Here):**

While the file is in the `bionic` directory, this specific test file doesn't heavily involve dynamic linking. However, *if* it were testing something like backtracing across shared library boundaries, the analysis would involve:

* **SO Layout:**  Understanding how shared libraries are loaded into memory and how their code and data segments are arranged.
* **Linkage:**  How function calls across SO boundaries are resolved by the dynamic linker (using GOT and PLT).
* **Unwinding Across Boundaries:** The stack unwinding mechanism needs to be able to traverse across these boundaries, potentially using information stored in the `.eh_frame` sections of the shared libraries.

**8. Frida Hooking (Conceptual):**

Imagine using Frida to inspect the execution:

* **Hooking `android_unsafe_frame_pointer_chase`:** You could hook the entry and exit of this function to see the input buffer and the number of frames returned.
* **Hooking `recurse`:**  Observe the stack depth during the recursive calls.
* **Examining Memory:**  Use Frida to inspect the contents of the `frames` buffer after `recurse` returns.
* **Hooking `pthread_create` and `pthread_join`:**  Track the creation and termination of threads in the `pthread` test.
* **Hooking Signal-Related Functions:** Intercept calls to `sigaltstack`, `sigaction`, and `raise` to understand the signal handling setup.

By following this systematic approach, we can thoroughly understand the purpose, functionality, and implications of this test file within the broader context of Android's bionic library. The process involves code reading, logical deduction, understanding system-level concepts (threading, signals, memory management), and thinking about potential issues and debugging techniques.
这个文件 `bionic/tests/android_unsafe_frame_pointer_chase_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 `android_unsafe_frame_pointer_chase` 函数的功能。这个函数旨在 **在没有可靠的帧指针信息的情况下，尝试追踪当前线程的调用栈**。

**功能列举:**

1. **测试 `android_unsafe_frame_pointer_chase` 函数的基本功能:**
   - 验证该函数能否在单线程环境下正确地获取调用栈信息。
   - 验证该函数返回的栈帧数量是否符合预期。
   - 验证获取到的栈帧地址是否合理。

2. **测试 `android_unsafe_frame_pointer_chase` 函数在多线程环境下的表现:**
   - 验证该函数在不同的线程中是否能独立且正确地获取调用栈信息。

3. **测试 `android_unsafe_frame_pointer_chase` 函数在使用了备用信号栈（sigaltstack）时的表现:**
   - 验证该函数能否正确处理使用备用信号栈的线程，并获取到正确的调用栈信息，包括信号处理函数的栈帧。
   - 涵盖备用信号栈在常规栈之前和之后两种内存布局的情况。

**与 Android 功能的关系及举例说明:**

`android_unsafe_frame_pointer_chase` 函数是 Android 系统底层调试和错误诊断的重要组成部分。在以下场景中会用到：

* **崩溃报告 (Crash Reporting):** 当应用程序或系统进程崩溃时，系统会尝试收集崩溃时的调用栈信息，以便开发者定位问题。`android_unsafe_frame_pointer_chase` 可以在没有可靠帧指针的情况下提供回溯信息。例如，在 Native Crash (JNI 或 C/C++ 代码崩溃) 时，系统会尝试获取调用栈并包含在 bugreport 中。
* **性能分析 (Profiling):** 一些性能分析工具会定期采样程序的调用栈，以分析 CPU 时间的消耗分布。即使程序没有启用帧指针，`android_unsafe_frame_pointer_chase` 也能提供一些帮助。
* **调试器 (Debugger):** 调试器在单步执行或查看调用栈时，也可能依赖类似的机制。虽然通常调试器会利用更精确的调试信息，但在某些情况下，`android_unsafe_frame_pointer_chase` 的思想可以作为补充。

**libc 函数的实现解释:**

这个测试文件主要涉及以下 libc 函数：

1. **`sys/mman.h` 中的 `mmap` 和 `munmap`:**
   - **`mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)`:**  用于在进程的地址空间中创建一个新的内存映射。
     - `addr`:  建议映射的起始地址，通常为 `nullptr`，让系统自动选择。
     - `len`:  映射区的长度（字节）。
     - `prot`:  内存保护标志，如 `PROT_READ` (可读), `PROT_WRITE` (可写), `PROT_EXEC` (可执行)。
     - `flags`:  映射类型标志，如 `MAP_ANON` (匿名映射，不与文件关联), `MAP_PRIVATE` (私有映射，修改不会影响其他进程)。
     - `fd`:  若为文件映射，则为文件描述符；对于匿名映射，通常为 -1。
     - `offset`:  文件映射的偏移量。
     - 在此测试中，`mmap` 用于分配一块内存作为备用信号栈。
   - **`munmap(void *addr, size_t len)`:**  用于解除之前由 `mmap` 创建的内存映射。
     - `addr`:  要解除映射的起始地址。
     - `len`:  要解除映射的长度。

2. **`pthread.h` 中的 `pthread_create`, `pthread_join`, `pthread_attr_init`, `pthread_attr_setstack`:**
   - **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`:**  创建一个新的线程。
     - `thread`:  指向 `pthread_t` 类型的指针，用于存储新创建线程的 ID。
     - `attr`:  指向线程属性对象的指针，可以为 `nullptr` 使用默认属性。
     - `start_routine`:  新线程要执行的函数。
     - `arg`:  传递给 `start_routine` 的参数。
   - **`pthread_join(pthread_t thread, void **retval)`:**  等待指定的线程结束。
     - `thread`:  要等待的线程的 ID。
     - `retval`:  指向指针的指针，用于接收线程的返回值（如果不需要可以传 `nullptr`）。
   - **`pthread_attr_init(pthread_attr_t *attr)`:**  初始化线程属性对象。
   - **`pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr, size_t stacksize)`:**  设置线程的栈地址和大小。在此测试中，用于显式地控制线程栈的位置。

3. **`signal.h` 中的 `sigaltstack`, `sigaction`, `raise`:**
   - **`sigaltstack(const stack_t *ss, stack_t *old_ss)`:**  设置或查询备用信号栈。
     - `ss`:  指向 `stack_t` 结构的指针，包含备用栈的起始地址 (`ss_sp`)、标志 (`ss_flags`) 和大小 (`ss_size`)。如果为 `nullptr`，则禁用备用栈。
     - `old_ss`:  如果非 `nullptr`，则用于存储之前的备用栈信息。
   - **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  设置对特定信号的处理方式。
     - `signum`:  要处理的信号编号。
     - `act`:  指向 `sigaction` 结构的指针，包含新的信号处理方式（例如，处理函数 `sa_handler`，标志 `sa_flags` 等）。
     - `oldact`:  如果非 `nullptr`，则用于存储之前的信号处理方式。
     - 在此测试中，`sigaction` 用于设置 `SIGRTMIN` 信号的处理函数为 `BacktraceHandler`，并指定在备用栈上执行 (`SA_ONSTACK`)。
   - **`raise(int sig)`:**  向当前进程发送一个信号。在此测试中，用于触发 `SIGRTMIN` 信号，从而调用 `BacktraceHandler`。

4. **其他:**
   - **`gtest/gtest.h` 中的 `TEST`, `EXPECT_EQ`, `ASSERT_EQ`, `EXPECT_TRUE`:**  Google Test 框架提供的宏，用于定义和执行测试用例，以及进行断言。

**dynamic linker 的功能和 so 布局样本及链接处理过程:**

虽然这个测试文件主要关注的是栈回溯，但 `android_unsafe_frame_pointer_chase` 函数的实现可能会间接地受到动态链接的影响。例如，当调用栈跨越不同的共享库（.so 文件）时，栈回溯机制需要能够识别和处理这些边界。

**SO 布局样本：**

假设一个简单的场景，有一个可执行文件 `app`，它链接了两个共享库 `liba.so` 和 `libc.so` (Bionic)。

```
Memory Map:

[可执行文件 app 的代码段和数据段]
...
[liba.so 的代码段] <--- 函数 func_a 定义在此
...
[liba.so 的数据段]
...
[libc.so (Bionic) 的代码段] <--- android_unsafe_frame_pointer_chase 定义在此
...
[libc.so (Bionic) 的数据段]
...
[栈内存 (Stack)]
```

**链接处理过程：**

1. **编译时链接：** 编译器和链接器在构建 `app` 时，会记录下 `app` 依赖的共享库 (`liba.so`, `libc.so`) 以及需要从这些库中引用的符号（例如，`func_a`）。
2. **运行时链接：** 当 `app` 运行时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责：
   - 加载所需的共享库到内存中的合适位置。
   - 解析符号引用：将 `app` 中对 `liba.so` 和 `libc.so` 中符号的引用，绑定到这些符号在内存中的实际地址。这通常通过 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 来实现。
   - 重定位：调整加载的共享库中的一些地址，以反映它们在内存中的实际位置。

**`android_unsafe_frame_pointer_chase` 的潜在关联：**

当 `android_unsafe_frame_pointer_chase` 尝试回溯栈帧时，如果当前栈帧属于 `app`，下一个栈帧属于 `liba.so`，再下一个属于 `libc.so`，它需要能够：

* **识别不同的代码段：**  通过栈帧中的返回地址，判断该地址属于哪个共享库。这通常需要访问进程的内存映射信息。
* **处理链接信息：**  虽然 `android_unsafe_frame_pointer_chase` 主要是基于栈内存的布局进行推断，但理解动态链接的原理有助于设计更健壮的栈回溯算法。例如，某些启发式方法可能会利用 GOT/PLT 的结构来辅助判断函数调用关系。

**逻辑推理、假设输入与输出:**

**以 `TEST(android_unsafe_frame_pointer_chase, main_thread)` 为例：**

**假设输入:**

* 启动一个进程，执行该测试用例。

**执行过程:**

1. `recurse(kNumFrames, 0, 0)` 被调用。由于 `buf` 为 0，`android_unsafe_frame_pointer_chase` 不会实际写入栈帧地址，但会返回预期的栈帧数量 `size`。
2. `recurse(kNumFrames, frames, kNumFrames + 2)` 被调用。这次 `buf` 指向 `frames` 数组，`android_unsafe_frame_pointer_chase` 会尝试将栈帧地址写入 `frames` 数组。
3. `CheckFrames(frames, size)` 被调用，检查 `frames` 数组中的内容。

**预期输出:**

* `size2` 的值应该等于 `size`。
* `CheckFrames` 函数应该返回 `true`，表明捕获到的栈帧符合预期模式：
    - `frames[0]` 是调用 `android_unsafe_frame_pointer_chase` 的 `recurse` 函数的返回地址。
    - `frames[1]` 到 `frames[kNumFrames]` 是递归调用 `recurse` 函数的返回地址（这些地址应该相同，因为是相同的函数）。
    - `frames[kNumFrames + 1]` 是最初调用 `recurse` 的 `TEST_F` 函数内部的返回地址。

**用户或编程常见的使用错误:**

* **缓冲区溢出:**  传递给 `android_unsafe_frame_pointer_chase` 的缓冲区 `buf` 不够大，无法容纳所有捕获到的栈帧地址。这可能导致内存错误或程序崩溃。
   ```c++
   uintptr_t small_frames[2];
   // 实际可能超过 2 个栈帧
   recurse(kNumFrames, small_frames, 2); // 潜在的缓冲区溢出
   ```
* **错误的 `num_entries` 值:**  传递给 `android_unsafe_frame_pointer_chase` 的 `num_entries` 参数与缓冲区大小不匹配。
   ```c++
   uintptr_t frames[10];
   recurse(kNumFrames, frames, 5); // 可能只写入前 5 个栈帧，后续的可能未初始化
   ```
* **在不安全的环境中使用:**  `android_unsafe_frame_pointer_chase` 的名字就暗示了其不安全性。它依赖于启发式方法，在某些优化或代码变换的情况下，可能无法得到正确的栈回溯信息。开发者不应该过分依赖其结果，尤其是在需要精确栈信息的场景中。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例调试步骤:**

1. **Native Crash 场景 (Android Framework):**
   - 当一个 Native (C/C++) 组件崩溃时，例如在 SurfaceFlinger 或 MediaCodec 等系统服务中，系统会捕获到 `SIGSEGV` 或其他导致崩溃的信号。
   - 系统的 Signal Handler (通常在 `libc.so` 中) 会被调用。
   - 这个 Signal Handler 可能会尝试获取崩溃时的调用栈信息。
   - 在没有可靠帧指针的情况下，可能会调用类似 `android_unsafe_frame_pointer_chase` 的函数来尝试回溯。
   - 获取到的栈信息会被包含在 `tombstone` 文件或 bugreport 中。

2. **NDK 开发 (应用程序):**
   - 如果 NDK 开发者编写的 C/C++ 代码崩溃，也会触发类似的流程。
   - 应用程序的进程会接收到信号。
   - 如果应用程序使用了 Breakpad 或其他崩溃报告库，这些库可能会内部使用类似的栈回溯机制。

**Frida Hook 示例:**

假设你想观察 `android_unsafe_frame_pointer_chase` 的调用和返回值。

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_unsafe_frame_pointer_chase"), {
    onEnter: function(args) {
        console.log("[*] Called android_unsafe_frame_pointer_chase");
        console.log("    buf: " + args[0]);
        console.log("    num_entries: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[*] android_unsafe_frame_pointer_chase returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **找到目标进程:** 运行你想要调试的应用。
3. **运行 Frida 脚本:** 运行上面的 Python 脚本，替换 `your.app.package` 为你的应用包名。
4. **触发调用:** 在你的应用中触发可能导致 `android_unsafe_frame_pointer_chase` 被调用的场景，例如，模拟一个 Native Crash 或者执行某些可能触发性能分析的代码。
5. **观察输出:** Frida 脚本会拦截对 `android_unsafe_frame_pointer_chase` 的调用，并打印出参数和返回值，帮助你理解其行为。

**更详细的 Frida Hook 可以包括：**

* **查看 `buf` 指向的内存:** 在 `onEnter` 中，可以读取 `args[0]` 指向的内存，查看缓冲区的内容。
* **栈回溯:** 在 `onLeave` 中，可以尝试基于返回的栈帧地址进行进一步的符号解析。

通过 Frida 这样的动态分析工具，开发者可以深入了解 Android 系统底层的运行机制，包括 `android_unsafe_frame_pointer_chase` 这样的内部函数的行为。

### 提示词
```
这是目录为bionic/tests/android_unsafe_frame_pointer_chase_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#if defined(__BIONIC__)

#include <sys/mman.h>

#include "platform/bionic/android_unsafe_frame_pointer_chase.h"

// Prevent tail calls inside recurse.
__attribute__((weak, noinline)) size_t nop(size_t val) {
  return val;
}

// Call android_unsafe_frame_pointer_chase inside count recurse stack frames.
__attribute__((weak, noinline)) int recurse(int count, uintptr_t* buf, size_t num_entries) {
  if (count != 0) return nop(recurse(count - 1, buf, num_entries));
  return nop(android_unsafe_frame_pointer_chase(buf, num_entries));
}

static constexpr size_t kNumFrames = 32;

static bool CheckFrames(uintptr_t* frames, size_t num_frames) {
  // We expect one recurse frame calling android_unsafe_frame_pointer_chase, followed by kNumFrames identical
  // recurse frames calling themselves, followed by at least one frame (the first caller of
  // recurse).
  if (num_frames < kNumFrames + 2) {
    printf("num_frames (0x%zu) < kNumFrames + 2", num_frames);
    return false;
  }

  if (frames[0] == frames[1]) {
    printf("frames[0] == frames[1] (0x%zx)", frames[0]);
    return false;
  }

  for (size_t i = 2; i <= kNumFrames; ++i) {
    if (frames[i] != frames[1]) {
      printf("frames[i] (0x%zx) != frames[1] (0x%zx)", frames[i], frames[1]);
      return false;
    }
  }

  if (frames[kNumFrames] == frames[kNumFrames + 1]) {
    printf("frames[kNumFrames] == frames[kNumFrames + 1] (0x%zx)", frames[kNumFrames]);
    return false;
  }

  return true;
}

TEST(android_unsafe_frame_pointer_chase, main_thread) {
  size_t size = recurse(kNumFrames, 0, 0);

  uintptr_t frames[kNumFrames + 2];
  size_t size2 = recurse(kNumFrames, frames, kNumFrames + 2);
  EXPECT_EQ(size2, size);

  EXPECT_TRUE(CheckFrames(frames, size));
}

static const char* tester_func() {
  size_t size = recurse(kNumFrames, 0, 0);

  uintptr_t frames[kNumFrames + 2];
  size_t size2 = recurse(kNumFrames, frames, kNumFrames + 2);
  if (size2 != size) {
    return "size2 != size";
  }

  if (!CheckFrames(frames, size)) {
    return "CheckFrames failed";
  }
  return nullptr;
}

static void* BacktraceThread(void*) {
  return (void*)tester_func();
}

TEST(android_unsafe_frame_pointer_chase, pthread) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, BacktraceThread, nullptr));
  void* retval;
  ASSERT_EQ(0, pthread_join(t, &retval));
  EXPECT_EQ(nullptr, reinterpret_cast<char*>(retval));
}

static bool g_handler_called;
static const char* g_handler_tester_result;

static void BacktraceHandler(int) {
  g_handler_called = true;
  g_handler_tester_result = tester_func();
}

static constexpr size_t kStackSize = 16384;

static void* SignalBacktraceThread(void* sp) {
  stack_t ss;
  ss.ss_sp = sp;
  ss.ss_flags = 0;
  ss.ss_size = kStackSize;
  sigaltstack(&ss, nullptr);

  struct sigaction s = {};
  s.sa_handler = BacktraceHandler;
  s.sa_flags = SA_ONSTACK;
  sigaction(SIGRTMIN, &s, nullptr);

  raise(SIGRTMIN);
  sigaltstack(nullptr, nullptr);
  return nullptr;
}

TEST(android_unsafe_frame_pointer_chase, sigaltstack) {
  // Create threads where the alternate stack appears both after and before the regular stack, and
  // call android_unsafe_frame_pointer_chase from a signal handler. Without handling for the
  // alternate signal stack, this would cause false negatives or potential false positives in the
  // android_unsafe_frame_pointer_chase function.
  void* stacks =
      mmap(nullptr, kStackSize * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

  for (unsigned i = 0; i != 2; ++i) {
    pthread_t t;
    pthread_attr_t attr;
    ASSERT_EQ(0, pthread_attr_init(&attr));
    ASSERT_EQ(0, pthread_attr_setstack(&attr, reinterpret_cast<char*>(stacks) + kStackSize * i,
                                       kStackSize));

    ASSERT_EQ(0, pthread_create(&t, &attr, SignalBacktraceThread,
                                reinterpret_cast<char*>(stacks) + kStackSize * (1 - i)));
    void* retval;
    ASSERT_EQ(0, pthread_join(t, &retval));

    EXPECT_TRUE(g_handler_called);
    EXPECT_EQ(nullptr, g_handler_tester_result);
    g_handler_called = false;
  }

  munmap(stacks, kStackSize * 2);
}

static void* SigaltstackOnCallerStack(void*) {
  char altstack[kStackSize];
  SignalBacktraceThread(altstack);
  EXPECT_TRUE(g_handler_called);
  EXPECT_EQ(nullptr, g_handler_tester_result);
  g_handler_called = false;
  return nullptr;
}

TEST(android_unsafe_frame_pointer_chase, sigaltstack_on_main_thread) {
  SigaltstackOnCallerStack(nullptr);
}

TEST(android_unsafe_frame_pointer_chase, sigaltstack_on_pthread) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, SigaltstackOnCallerStack, nullptr));
  void* retval;
  ASSERT_EQ(0, pthread_join(t, &retval));
  EXPECT_EQ(nullptr, retval);
}

#endif // __BIONIC__
```