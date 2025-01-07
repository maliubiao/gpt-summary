Response:
Let's break down the thought process for answering the request about `bionic/tests/utils.cpp`.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ source code (`utils.cpp`) within the context of Android's Bionic library and explain its functionality, its relationship to Android, and related technical details. The output should be in Chinese.

**2. Initial Code Scan and Identification of Key Components:**

The first step is to read through the code and identify the distinct functions and their purposes. Keywords like `RunGwpAsanTest`, `RunSubtestNoEnv`, `IsLowRamDevice`, `gettid` (conditionally defined), `PrintTo`, `NanoTime`, and the overloaded `operator==` for `Errno` stand out. Also, `#include` directives give clues about dependencies.

**3. Analyzing Each Function Individually:**

* **`RunGwpAsanTest`:** This function clearly sets up an environment to run a test with GWP-ASan (Guard Whale Protection - AddressSanitizer) enabled. It manipulates environment variables and uses `execve` to launch a sub-process for testing. The presence of `gtest_filter` suggests it interacts with Google Test.

* **`RunSubtestNoEnv`:** This is similar to `RunGwpAsanTest` but doesn't set any specific environment variables. It's a more basic way to run a test.

* **`IsLowRamDevice`:** This function checks system properties (`ro.config.low_ram`, `ro.debuggable`, `debug.force_low_ram`) to determine if the device is considered low-RAM. This directly relates to Android's resource management.

* **`gettid`:** This function, conditionally defined for older GLibc versions, retrieves the thread ID using the `syscall` mechanism. It's a low-level system interaction.

* **`PrintTo`:** This function customizes how an `Errno` object is printed. It prefers using `strerrorname_np` (Bionic-specific) if available, falling back to the standard `strerror`. This highlights a Bionic extension.

* **`NanoTime`:**  This function gets the current time with nanosecond precision using the standard C++ `<chrono>` library. It's a general-purpose utility.

* **`operator==` for `Errno`:** This provides a way to compare two `Errno` objects for equality, simply comparing their underlying `errno_` values.

**4. Connecting to Android Functionality:**

As each function is analyzed, it's crucial to connect it to broader Android concepts:

* **GWP-ASan:**  This is a memory safety feature in Android.
* **System Properties:**  `IsLowRamDevice` directly uses Android system properties.
* **Bionic's Role:**  The use of `strerrorname_np` highlights a Bionic-specific extension. The conditional `gettid` shows Bionic sometimes needs to provide functionality not available in all standard libraries.
* **Testing:** The presence of `RunGwpAsanTest` and `RunSubtestNoEnv` indicates this file is part of Bionic's testing infrastructure.

**5. Explaining libc Functions:**

The request asks for detailed explanations of libc functions. The key libc functions used here are:

* **`execve`:**  This is crucial for process creation and execution. The explanation should cover its parameters (path, arguments, environment).
* **`syscall`:** This provides a direct way to invoke system calls. The explanation needs to cover its general purpose and the use of `__NR_gettid`.
* **`strerror`:**  This standard library function translates error numbers to human-readable strings.
* **`strerrorname_np`:** This Bionic-specific function (non-portable) attempts to get the symbolic name of an error number.

**6. Addressing Dynamic Linker (Not Applicable Here):**

A careful review of the code reveals *no direct interaction* with the dynamic linker. While `execve` *will* involve the dynamic linker when launching the test executable, the `utils.cpp` file itself doesn't contain code to manipulate or inspect the linker. Therefore, the correct response is to state that this file doesn't directly deal with the dynamic linker and thus no sample SO layout or linking process description is applicable *for this specific file*. It's important not to invent information.

**7. Considering Common Errors:**

Think about how developers might misuse these utility functions or the concepts they represent:

* **Incorrect Environment Variables:**  Missetting or forgetting to set required environment variables for tests.
* **Incorrect Test Filters:**  Providing incorrect or malformed test names to the `--gtest_filter` option.
* **Misunderstanding `IsLowRamDevice`:**  Assuming it's the *only* factor in low-memory behavior (other factors exist).
* **Platform Dependence of `gettid`:**  Using the conditional `gettid` implementation outside of Bionic contexts.
* **Relying on `strerrorname_np` Portability:**  Expecting `strerrorname_np` to be available on non-Bionic systems.

**8. Tracing the Path from Android Framework/NDK:**

This requires understanding how Bionic is used.

* **NDK:** When an NDK application is built, it links against Bionic's libraries. Functions like `NanoTime` or the underlying system calls would be used.
* **Android Framework:** The Android framework itself heavily relies on Bionic. When a framework service or app process is launched, the dynamic linker loads Bionic. The framework uses Bionic's system call wrappers, memory management functions, etc. The `IsLowRamDevice` function is a good example of a utility used by higher layers.

**9. Frida Hooking:**

For each function, think about where a hook would be placed and what information could be logged. `execve`, `syscall`, `android::base::GetBoolProperty`, the `NanoTime` call, and even the `PrintTo` function are good candidates for demonstrating Frida usage. The Frida examples should be concise and illustrate how to intercept the function and log arguments or return values.

**10. Structuring the Output in Chinese:**

Finally, the response needs to be formatted clearly in Chinese, addressing each part of the original request systematically. Using headings and bullet points improves readability. Pay attention to accurate translation of technical terms.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I should explain how dynamic linking works in general. **Correction:** The prompt asks about *this specific file*. Since this file doesn't directly deal with the linker, I should state that clearly.
* **Initial thought:** Should I provide all possible error scenarios? **Correction:** Focus on common and relevant errors related to the functions in the file.
* **Initial thought:**  Should I delve deeply into the implementation details of `steady_clock`? **Correction:** The request focuses on `utils.cpp`. A brief explanation of `NanoTime`'s purpose is sufficient.

By following this structured approach and continually refining the understanding of the code and its context, a comprehensive and accurate answer can be generated.
好的，让我们详细分析一下 `bionic/tests/utils.cpp` 这个文件。

**文件功能概览**

`bionic/tests/utils.cpp` 文件是 Android Bionic 库测试框架的一部分，提供了一些用于辅助测试的通用工具函数。这些函数主要用于：

1. **运行带有特定环境或不带环境的子测试:**  方便地执行独立的测试用例，并可以设置环境变量来模拟不同的测试场景。
2. **判断设备是否为低内存设备:**  通过读取系统属性来确定设备是否被认为是低 RAM 设备。这在针对不同设备配置进行测试时非常有用。
3. **跨平台获取线程 ID:** 在某些旧版本的 GLibc 环境下提供获取线程 ID 的方法。
4. **自定义错误信息打印:**  提供一种更友好的方式来打印 `Errno` 对象，优先使用 Bionic 特有的错误名称，否则使用标准的错误描述。
5. **获取高精度时间戳:**  提供纳秒级别的时间戳。
6. **比较 `Errno` 对象:**  重载了 `==` 运算符，方便比较两个 `Errno` 对象是否表示相同的错误。

**与 Android 功能的关系及举例说明**

这个文件中的许多功能都直接或间接地与 Android 的功能相关：

* **运行测试 (`RunGwpAsanTest`, `RunSubtestNoEnv`):**  这是 Android 持续集成和质量保证的关键部分。Android 框架和各个系统组件的测试都依赖于类似的机制来运行和验证代码的正确性。例如，在编译 Android 系统时，会运行大量的 Bionic 单元测试来确保 Bionic 库的稳定性和可靠性。
* **判断低内存设备 (`IsLowRamDevice`):**  Android 系统需要根据设备的内存状况进行优化。这个函数提供的判断逻辑可以被测试代码用来模拟低内存环境下的行为，例如测试内存压力下的资源管理或性能表现。  **举例说明:**  某些 Bionic 的内存分配器或缓存机制可能在低内存设备上采取更激进的策略来回收内存，这个函数可以用来编写测试用例验证这些策略是否按预期工作。
* **获取线程 ID (`gettid`):** 线程是 Android 系统中并发执行的基本单元。获取线程 ID 对于调试和性能分析至关重要。虽然现在大多数 Android 设备使用较新的 GLibc 版本，但这个函数的存在表明 Bionic 需要处理不同环境的兼容性。 **举例说明:** Bionic 内部的某些锁机制或线程本地存储的实现可能需要获取线程 ID 来进行管理。
* **错误处理 (`PrintTo`):**  错误处理是任何健壮的软件系统的基础。Bionic 作为 Android 的底层库，其错误处理的质量直接影响到上层应用的稳定性。 `strerrorname_np` 是 Bionic 特有的函数，能够提供更详细的错误信息，这有助于开发者更快速地定位问题。 **举例说明:**  当系统调用失败时，Bionic 内部会记录错误码，并可能使用 `PrintTo` 或类似的机制将错误信息记录到日志中。
* **高精度时间戳 (`NanoTime`):**  性能测量和时间相关的操作在 Android 系统中非常常见。例如，测量应用启动时间、网络请求耗时、动画帧率等都需要高精度的时间戳。 **举例说明:**  Bionic 内部的某些性能敏感的函数，例如锁的竞争检测或调度器的实现，可能会使用 `NanoTime` 来进行更精细的计时。

**libc 函数功能详解**

这个文件中使用了一些标准的 libc 函数：

* **`strcmp` (包含在 `<string.h>` 中，虽然代码中没有直接调用，但 `std::string` 的比较操作可能会用到):**  用于比较两个字符串。它逐个字符地比较两个字符串，直到找到不同的字符或者遇到字符串的结尾。如果两个字符串完全相同，则返回 0；如果第一个字符串的字符在 ASCII 值上小于第二个字符串的字符，则返回负值；反之，则返回正值。
    * **实现原理:** 通常通过循环遍历两个字符串的字符，并比较它们的 ASCII 值来实现。
    * **用户常见错误:**  没有考虑到字符串可能为空指针，导致程序崩溃。错误地使用返回值，例如将非零值视为相等。
* **`execve` (包含在 `<unistd.h>` 中，通过 `ExecTestHelper` 间接使用):**  用于执行一个新的程序。它将当前进程替换为新的程序。
    * **参数:**
        * `pathname`: 要执行的程序的文件路径。
        * `argv`:  一个以 NULL 结尾的字符串指针数组，表示传递给新程序的命令行参数。
        * `envp`:  一个以 NULL 结尾的字符串指针数组，表示传递给新程序的环境变量。
    * **实现原理:**  这是一个系统调用，内核会创建一个新的进程上下文，加载指定的可执行文件，并设置好参数和环境变量。
    * **用户常见错误:**  `pathname` 路径错误或权限不足导致执行失败。 `argv` 或 `envp` 没有以 NULL 结尾，导致程序崩溃或行为异常。
* **`syscall` (包含在 `<syscall.h>` 中):**  用于直接进行系统调用。它允许程序调用操作系统内核提供的底层功能。
    * **参数:**  第一个参数是系统调用号，后面的参数是传递给系统调用的参数，参数的个数和类型取决于具体的系统调用。
    * **实现原理:**  这是一个非常底层的操作。它会触发一个软中断，将控制权交给内核，内核根据系统调用号执行相应的操作。
    * **用户常见错误:**  使用错误的系统调用号或传递错误的参数类型和数量，导致程序崩溃或行为不可预测。需要查阅系统调用手册才能正确使用。
* **`strerror` (包含在 `<string.h>` 中):**  用于将错误码（通常是 `errno` 的值）转换为对应的错误描述字符串。
    * **参数:**  一个整数类型的错误码。
    * **实现原理:**  通常会维护一个错误码到错误描述的映射表。根据传入的错误码，在表中查找对应的描述字符串并返回。
    * **用户常见错误:**  忘记检查系统调用的返回值是否出错就直接调用 `strerror`，导致打印错误的错误信息。
* **`strerrorname_np` (Bionic 特有，非标准):**  与 `strerror` 类似，但它尝试返回错误码的符号名称（例如 "EINVAL"）。如果找不到对应的符号名称，则返回 NULL。
    * **实现原理:**  Bionic 维护了一个错误码到错误符号名称的映射表。
    * **用户常见错误:**  假设所有错误码都有对应的符号名称，没有检查返回值是否为 NULL 就直接使用，可能导致程序崩溃。依赖于这个函数会使代码不具有跨平台性。

**涉及 dynamic linker 的功能**

在这个 `utils.cpp` 文件中，**没有直接涉及 dynamic linker 的功能**。

虽然 `RunGwpAsanTest` 和 `RunSubtestNoEnv` 函数使用了 `execve` 来执行新的测试进程，这个过程会涉及到 dynamic linker 来加载和链接测试程序所依赖的共享库，但是 `utils.cpp` 本身并没有直接操作 dynamic linker 的代码。

**如果代码中涉及 dynamic linker 的功能，例如：**

* **显式加载和卸载共享库 (`dlopen`, `dlclose`)**
* **查找符号地址 (`dlsym`)**
* **获取共享库信息 (`dladdr`, `dl_iterate_phdr`)**

**那么，会涉及以下内容：**

**SO 布局样本:**

假设我们有一个简单的共享库 `libtest.so`，它依赖于 `libc.so`：

```
libtest.so:
    0x... Text Section (.text)      # 代码段
    0x... Data Section (.data)      # 初始化数据段
    0x... BSS Section (.bss)       # 未初始化数据段
    0x... .dynsym                 # 动态符号表
    0x... .dynstr                 # 动态字符串表
    0x... .rel.dyn                # 重定位表（数据段）
    0x... .rel.plt                # 重定位表（PLT）
    0x... .plt                    # 过程链接表 (PLT)
    0x... .got.plt                # 全局偏移表 (GOT) 用于 PLT
```

**链接的处理过程:**

1. **加载:** 当程序（例如测试程序）调用 `dlopen("libtest.so", ...)` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被激活。
2. **查找:** linker 会在预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）中查找 `libtest.so`。
3. **依赖解析:** linker 会检查 `libtest.so` 的依赖关系，例如 `libc.so`。如果依赖的库还没有加载，linker 会先加载这些依赖库。
4. **地址分配:** linker 会为 `libtest.so` 及其依赖库在进程的地址空间中分配内存区域。为了实现地址无关代码 (Position Independent Code, PIC)，共享库通常会被加载到一个随机的基地址。
5. **符号解析 (Symbol Resolution):**
   * 当代码调用共享库中的函数时，会经过过程链接表 (PLT)。
   * 第一次调用时，PLT 条目会跳转到 linker 的一个辅助函数。
   * linker 会在所有已加载的共享库的动态符号表 (`.dynsym`) 中查找被调用函数的地址。
   * 找到地址后，linker 会更新全局偏移表 (GOT) 中对应的条目，使其指向函数的实际地址。
   * 后续的调用会直接通过 GOT 跳转到函数的实际地址，避免了重复的符号查找。
6. **重定位 (Relocation):**  由于共享库的加载地址是动态的，linker 需要修改代码和数据段中与绝对地址相关的部分，使其适应实际的加载地址。这通过重定位表 (`.rel.dyn`, `.rel.plt`) 来完成。

**逻辑推理、假设输入与输出 (本文件中不适用)**

由于 `utils.cpp` 主要提供辅助功能，而不是核心逻辑，因此这里没有明显的逻辑推理过程可以直接分析。 如果涉及到更复杂的算法或数据处理，可以考虑提供假设的输入和预期的输出进行分析。

**用户或编程常见的使用错误**

* **`RunGwpAsanTest` 和 `RunSubtestNoEnv`:**
    * **错误的测试名称:**  如果 `test_name` 参数拼写错误或不存在，测试将不会运行或运行错误的测试。
    * **环境变量设置错误 (`RunGwpAsanTest`):**  错误的环境变量设置可能导致测试无法正确模拟预期场景或产生误报。
* **`IsLowRamDevice`:**
    * **过度依赖:**  仅仅依赖这个函数来判断低内存环境可能不够全面，因为设备的实际内存压力是动态变化的。
* **`gettid` (条件编译):**
    * **平台依赖性:**  直接使用这个函数可能导致代码在非 Bionic 环境下编译失败或行为异常。应该使用平台无关的方式获取线程 ID，或者使用条件编译进行适配。
* **`PrintTo`:**
    * **错误的 `Errno` 对象:**  如果传递的 `Errno` 对象包含无效的 `errno_` 值，`strerror` 可能会返回 "Unknown error" 加上错误码的数字。
* **通用错误:**
    * **头文件包含错误:**  缺少必要的头文件可能导致编译失败。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例**

`bionic/tests/utils.cpp` 文件本身是 Bionic 库测试代码的一部分，通常不会被 Android Framework 或 NDK 直接调用。但是，它所提供的功能和它所测试的 Bionic 组件会被广泛使用。

**到达路径示例：**

1. **NDK 应用使用 Bionic 函数:**
   * 开发者使用 NDK 开发 C/C++ 应用。
   * 应用中可能会调用 Bionic 提供的系统调用封装、数学函数、字符串操作等。
   * 当测试这些 NDK 应用时，可能会使用类似 `RunSubtestNoEnv` 的机制来运行单元测试，而这些测试可能会间接使用到 `utils.cpp` 中的辅助函数。
2. **Android Framework 使用 Bionic 组件:**
   * Android Framework 的许多核心组件（例如 Binder、Zygote、各种系统服务）都链接到 Bionic 库。
   * 当 Framework 的开发者需要测试 Bionic 库的某个功能时，他们可能会运行 Bionic 的单元测试，这些测试会用到 `utils.cpp`。
   * 例如，测试 Bionic 的内存分配器时，可能会使用 `IsLowRamDevice` 来模拟低内存场景。

**Frida Hook 示例:**

假设我们想 Hook `RunGwpAsanTest` 函数，查看它运行的测试名称：

```javascript
if (Process.platform === 'android') {
  const utilsLib = Module.findBaseAddress("libutils.so"); // 假设 utils.cpp 编译到了 libutils.so 中

  if (utilsLib) {
    const runGwpAsanTest = utilsLib.base.add(0xXXXX); // 替换为 RunGwpAsanTest 函数的实际偏移

    if (runGwpAsanTest) {
      Interceptor.attach(runGwpAsanTest, {
        onEnter: function (args) {
          const testName = Memory.readUtf8String(args[0]);
          console.log(`[RunGwpAsanTest] Running test: ${testName}`);
        }
      });
    } else {
      console.log("[Frida] RunGwpAsanTest function not found.");
    }
  } else {
    console.log("[Frida] libutils.so not found.");
  }
}
```

**解释:**

1. **`Process.platform === 'android'`:**  确保只在 Android 平台上运行 Hook 代码。
2. **`Module.findBaseAddress("libutils.so")`:**  尝试找到包含 `utils.cpp` 代码的共享库的基地址。你需要根据实际的编译结果找到正确的库名称。
3. **`utilsLib.base.add(0xXXXX)`:**  计算 `RunGwpAsanTest` 函数的绝对地址。你需要使用反汇编工具（如 IDA Pro, Ghidra）或符号信息来找到 `RunGwpAsanTest` 在 `libutils.so` 中的偏移。
4. **`Interceptor.attach(runGwpAsanTest, ...)`:** 使用 Frida 的 `Interceptor` 来拦截 `RunGwpAsanTest` 函数的调用。
5. **`onEnter: function (args)`:**  在函数被调用时执行的代码。`args` 数组包含了函数的参数。
6. **`Memory.readUtf8String(args[0])`:**  读取第一个参数（`test_name`）指向的字符串。
7. **`console.log(...)`:**  将测试名称打印到 Frida 的控制台。

**Hook 其他函数的示例：**

* **Hook `IsLowRamDevice`:**  找到 `IsLowRamDevice` 的地址，并在 `onLeave` 中打印返回值。
* **Hook `execve` (需要找到 `execve` 的地址，通常在 `libc.so` 中):**  在 `onEnter` 中打印要执行的程序路径和参数。
* **Hook `android::base::GetBoolProperty`:** 找到这个函数的地址，并在 `onEnter` 中打印属性名称，在 `onLeave` 中打印返回值。

通过 Frida Hook，你可以动态地观察这些工具函数在 Android 系统中的行为，这对于调试和理解系统运行机制非常有帮助。

希望以上分析能够帮助你理解 `bionic/tests/utils.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/utils.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2022 The Android Open Source Project
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

#include "utils.h"

#include <string.h>
#include <syscall.h>

#include <string>

#include <android-base/properties.h>

void RunGwpAsanTest(const char* test_name) {
  ExecTestHelper eh;
  eh.SetEnv({"GWP_ASAN_SAMPLE_RATE=1", "GWP_ASAN_PROCESS_SAMPLING=1", "GWP_ASAN_MAX_ALLOCS=40000",
             nullptr});
  std::string filter_arg = "--gtest_filter=";
  filter_arg += test_name;
  std::string exec(testing::internal::GetArgvs()[0]);
  eh.SetArgs({exec.c_str(), "--gtest_also_run_disabled_tests", filter_arg.c_str(), nullptr});
  eh.Run([&]() { execve(exec.c_str(), eh.GetArgs(), eh.GetEnv()); },
         /* expected_exit_status */ 0,
         // |expected_output_regex|, ensure at least one test ran:
         R"(\[  PASSED  \] [1-9][0-9]* test)");
}

void RunSubtestNoEnv(const char* test_name) {
  ExecTestHelper eh;
  std::string filter_arg = "--gtest_filter=";
  filter_arg += test_name;
  std::string exec(testing::internal::GetArgvs()[0]);
  eh.SetArgs({exec.c_str(), "--gtest_also_run_disabled_tests", filter_arg.c_str(), nullptr});
  eh.Run([&]() { execve(exec.c_str(), eh.GetArgs(), eh.GetEnv()); },
         /* expected_exit_status */ 0,
         // |expected_output_regex|, ensure at least one test ran:
         R"(\[  PASSED  \] [1-9]+0? test)");
}

bool IsLowRamDevice() {
  return android::base::GetBoolProperty("ro.config.low_ram", false) ||
         (android::base::GetBoolProperty("ro.debuggable", false) &&
          android::base::GetBoolProperty("debug.force_low_ram", false));
}

#if defined(__GLIBC__) && __GLIBC_MINOR__ < 30
pid_t gettid() {
  return syscall(__NR_gettid);
}
#endif

void PrintTo(const Errno& e, std::ostream* os) {
  // Prefer EINVAL or whatever, but fall back to strerror() to print
  // "Unknown error 666" for bogus values. Not that I've ever seen one,
  // but we shouldn't be looking at an assertion failure unless something
  // weird has happened!
#if defined(__BIONIC__)
  const char* errno_name = strerrorname_np(e.errno_);
  if (errno_name != nullptr) {
    *os << errno_name;
  } else
#endif
  {
    *os << strerror(e.errno_);
  }
}

int64_t NanoTime() {
  auto t = std::chrono::time_point_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now());
  return t.time_since_epoch().count();
}

bool operator==(const Errno& lhs, const Errno& rhs) {
  return lhs.errno_ == rhs.errno_;
}

"""

```