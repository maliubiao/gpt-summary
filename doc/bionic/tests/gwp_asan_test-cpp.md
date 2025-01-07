Response:
Let's break down the thought process for analyzing this C++ test file for GWP-ASan in Android Bionic.

**1. Initial Understanding & Goal:**

The first step is to understand the overall purpose of the file. The filename `gwp_asan_test.cpp` and the directory `bionic/tests` immediately suggest it's a test file for the GWP-ASan feature within Android's Bionic libc. The comment at the top confirms this. The request asks for a breakdown of its functionality, connections to Android, detailed explanations of libc functions used, dynamic linker aspects, examples of usage errors, and how Android frameworks reach this point, along with Frida hooks.

**2. High-Level Functionality Identification:**

The core functionality is testing GWP-ASan. Scanning the code reveals `TEST` macros, indicating these are Google Test framework tests. The presence of `RunGwpAsanTest`, `RunSubtestNoEnv`, and checks on `/proc/self/maps` confirms this. The tests seem to focus on enabling, disabling, and configuring GWP-ASan via system properties and environment variables.

**3. Deeper Dive into Test Cases:**

I then examine each test case individually:

* **`malloc_tests_under_torture`:** This immediately suggests a test for GWP-ASan's behavior when sampling every allocation. The `SKIP_WITH_HWASAN` macro is important - it shows an interaction with another memory safety feature.
* **`SyspropRestorer`:** This class is clearly for managing system properties during testing. The locking mechanism (`flock`) highlights the need for synchronized access to global system properties during tests. The properties being manipulated are GWP-ASan related.
* **`DISABLED_assert_gwp_asan_enabled`:**  Checking for "GWP-ASan" in `/proc/self/maps` is a key way to verify GWP-ASan is active. The `EXPECT_DEATH` part suggests it's testing the detection of use-after-free errors when GWP-ASan is enabled. The `volatile` keyword is used to prevent compiler optimizations that might hide the bug.
* **`DISABLED_assert_gwp_asan_enabled_weaker`:** Similar to the above, but a "weaker" check, likely meaning it doesn't trigger an error itself, but just confirms GWP-ASan's presence. This hints at testing scenarios where GWP-ASan might be active for *some* allocations, but not necessarily the one the test itself is trying to trigger.
* **`DISABLED_assert_gwp_asan_disabled`:**  The opposite of the enabled tests, ensuring GWP-ASan is *not* active.
* **`sysprops_program_specific`:**  Tests setting GWP-ASan properties specific to the test program's name.
* **`sysprops_persist_program_specific`:** Tests setting persistent system properties for the test program.
* **`sysprops_non_persist_overrides_persist`:** Tests the precedence of non-persistent system properties over persistent ones.
* **`sysprops_program_specific_overrides_default`:** Tests the precedence of program-specific properties over default system-wide properties.
* **`sysprops_can_disable`:** Tests the ability to disable GWP-ASan via system properties.
* **`env_overrides_sysprop`:** Tests that environment variables can override system properties for GWP-ASan configuration.

**4. Identifying Key Libc and System Calls:**

As I analyze the test cases, I note the libc functions being used:

* `open`, `close`, `flock`: For file locking in `SyspropRestorer`.
* `__gnu_basename`:  Used to get the program's base name for program-specific properties.
* `__system_property_find`, `__system_property_read_callback`, `__system_property_set`: For interacting with Android's system properties.
* Standard memory allocation (`new`, `delete`) is implicitly used in the death tests.
* Functions related to reading files (`ReadFileToString`).

**5. Dynamic Linker Considerations:**

While the code doesn't directly call dynamic linker functions, the fact that GWP-ASan is a feature integrated into the memory allocator (which is part of libc, loaded by the dynamic linker) means the dynamic linker plays a role. The "GWP-ASan" string appearing in `/proc/self/maps` is a direct consequence of the dynamic linker mapping the GWP-ASan library (or code within libc) into the process's address space.

**6. Android Framework Integration:**

I consider how Android applications and the framework might trigger these tests or interact with GWP-ASan:

* **NDK Applications:** NDK apps using `malloc`/`new` will be subject to GWP-ASan if it's enabled.
* **Framework Processes:** Android framework processes also use `malloc`/`new`, so they are equally susceptible.
* **System Properties:** The Android system uses properties to configure various aspects, including debugging features like GWP-ASan. The `adb shell setprop` command is a key way to interact with these.

**7. Potential Usage Errors:**

Based on the nature of GWP-ASan (detecting memory errors), I think about common memory management mistakes:

* Use-after-free (demonstrated in the `EXPECT_DEATH` test).
* Double-free.
* Heap buffer overflows (while not directly tested here, GWP-ASan can detect them).

**8. Frida Hooking Strategy:**

To debug, I consider where Frida hooks would be useful:

* Hooking `__system_property_set` to see how GWP-ASan properties are being set.
* Hooking `malloc` and `free` to observe allocation patterns and GWP-ASan's behavior.
* Hooking the internal GWP-ASan initialization functions (if they were easily identifiable) for deeper inspection.

**9. Structuring the Response:**

Finally, I organize the gathered information into the requested categories: functionality, Android connections, libc function details, dynamic linker aspects, input/output examples, usage errors, and Android framework/NDK integration with Frida hooks. I use clear headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the specific test cases and forget the broader picture of GWP-ASan's role. I need to step back and remember its purpose.
* I might need to refine my understanding of how system properties work in Android (persistent vs. non-persistent).
* I'd double-check the exact semantics of the libc functions used (e.g., `flock` for exclusive locking).
* I would ensure my Frida hook examples are practical and target relevant functions.

By following this structured approach, I can systematically analyze the code and generate a comprehensive and accurate response to the request.
好的，让我们详细分析一下 `bionic/tests/gwp_asan_test.cpp` 这个文件。

**文件功能概述:**

该文件是 Android Bionic 库中的一个测试文件，专门用于测试 **GWP-ASan (Guard-Pages With ASan)** 功能的集成和行为。GWP-ASan 是一种内存安全工具，它通过随机地将分配的内存块放在受保护的“guard pages”附近来检测内存错误，例如 use-after-free。

简单来说，这个文件的主要功能是：

1. **验证 GWP-ASan 的启用和禁用机制：** 通过设置不同的系统属性和环境变量，测试 GWP-ASan 是否能够正确地被启用或禁用。
2. **测试 GWP-ASan 在不同配置下的行为：** 例如，测试在不同的采样率和最大分配数限制下，GWP-ASan 的检测能力。
3. **确保 GWP-ASan 与其他内存安全工具（如 HWASan）的兼容性：**  可以看到代码中使用了 `SKIP_WITH_HWASAN` 宏。
4. **提供一种“压力测试”模式：**  通过 `malloc_tests_under_torture` 测试，以高采样率运行内存分配操作，检验 GWP-ASan 的稳定性和性能。

**与 Android 功能的关系及举例说明:**

GWP-ASan 是 Android 系统的一个重要的内存安全特性，旨在提高 Android 平台的健壮性和安全性。它主要用于检测以下类型的内存错误：

* **Use-after-free (释放后使用):**  当程序尝试访问已经被 `free` 释放的内存时，GWP-ASan 会检测到并报告错误。
* **Heap buffer overflow (堆缓冲区溢出):** 虽然 GWP-ASan 不是专门为此设计的，但在某些情况下，溢出到 guard page 会被检测到。

**举例说明:**

假设一个 Android 应用在处理图片时，分配了一块内存用于存储图片数据，并在使用完毕后释放了这块内存。如果代码中存在 bug，导致在释放后仍然尝试访问这块内存，那么 GWP-ASan 就可以检测到这个错误，并阻止潜在的崩溃或安全漏洞。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件中使用了一些 libc 函数，我们来逐一解释：

1. **`stdio.h` 中的函数 (例如 `printf`, 虽然本文件中没有直接使用，但通常会引入):**
   - 这些函数提供标准的输入/输出功能，例如打印到控制台或读取用户输入。它们的实现涉及到操作系统提供的系统调用，例如 `write` 用于输出。

2. **`sys/file.h` 中的函数 (`open`, `close`, `flock`):**
   - **`open(const char *pathname, int flags, ...)`:** 打开一个文件。`pathname` 是文件路径，`flags` 指定打开模式（例如只读 `O_RDONLY`）。实现会调用底层的 `open` 系统调用，由内核处理文件描述符的分配和文件访问权限的检查。
   - **`close(int fd)`:** 关闭一个文件描述符。实现会调用底层的 `close` 系统调用，释放内核资源。
   - **`flock(int fd, int operation)`:** 对文件加锁或解锁。`fd` 是文件描述符，`operation` 指定锁的类型（例如排他锁 `LOCK_EX`）和操作（加锁或解锁）。实现会调用底层的 `flock` 系统调用，由内核管理文件锁。在这个测试中，`flock` 用于确保在修改系统属性时，不同的测试用例之间不会发生冲突。

3. **`string` (C++ 标准库):**
   - 提供了字符串操作的类和函数，例如字符串的创建、复制、比较、连接等。它的实现依赖于动态内存分配来管理字符串的存储。

4. **`__gnu_basename(const char* path)`:**
   - 这个函数用于提取文件路径的基本名称（不包含目录部分）。例如，对于路径 `/a/b/c.txt`，`__gnu_basename` 返回 `c.txt`。它的实现通常会从路径字符串的末尾开始查找最后一个斜杠 `/`，并返回斜杠之后的部分。

5. **`sys/system_properties.h` 中的函数 (`__system_property_find`, `__system_property_read_callback`, `__system_property_set`):**
   - 这些函数用于访问和修改 Android 的系统属性。系统属性是 Android 系统中用于存储配置信息的键值对。
   - **`__system_property_find(const char *name)`:**  查找指定名称的系统属性，返回一个指向 `prop_info` 结构的指针，如果找不到则返回 `nullptr`。它的实现涉及到访问系统属性服务的共享内存区域。
   - **`__system_property_read_callback(const prop_info *pi, void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial), void *cookie)`:** 读取系统属性的值，并通过回调函数返回。它的实现会从 `prop_info` 结构中获取属性值，并调用提供的回调函数。
   - **`__system_property_set(const char *name, const char *value)`:** 设置指定名称的系统属性的值。它的实现会调用系统属性服务，并通知其他进程属性的变更。

6. **`platform/bionic/malloc.h` 中的函数 (例如 `malloc`, `free`, 虽然本文件中没有直接调用，但与 GWP-ASan 相关):**
   - 这些函数是标准的内存分配和释放函数。GWP-ASan 是对 `malloc` 和 `free` 的一种扩展或包装，它会在分配的内存块周围设置 guard pages。当访问到 guard page 时，会触发一个错误信号。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然这个测试文件本身没有直接涉及到 dynamic linker 的 API 调用，但 GWP-ASan 功能的运行是依赖于 dynamic linker 的。

**so 布局样本:**

```
加载地址范围      权限     偏移量       设备号:Inode      路径
----------    ----    --------    ----------------    ---------------------------
...
000000xxxxxx-000000yyyyyy r-xp    00000000       fd:00     /system/lib64/libc.so  // libc.so 加载
...
000000zzzzzz-000000wwwwww rwxp    00000000       00:00     [anon:GWP-ASan metadata] // GWP-ASan 的元数据区域
...
```

当启用了 GWP-ASan 后，libc.so 中与 GWP-ASan 相关的代码会被激活。Dynamic linker 在加载 libc.so 时，会按照其 ELF 文件中的信息进行内存布局。GWP-ASan 可能需要在进程的地址空间中分配额外的内存区域来存储其元数据（例如哪些内存块被 GWP-ASan 保护）。 上面的 `[anon:GWP-ASan metadata]`  就是一个例子，这块匿名映射的内存可能用于存储 GWP-ASan 的内部状态。

**链接的处理过程:**

1. **编译链接:** 当编译包含内存分配的代码时，链接器会将代码链接到 libc.so。
2. **加载时链接:** 当 Android 启动一个进程时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载进程依赖的共享库，包括 libc.so。
3. **符号解析:** Dynamic linker 会解析 libc.so 中导出的符号，例如 `malloc` 和 `free`。
4. **重定位:** Dynamic linker 会根据加载地址调整代码中的地址引用。
5. **GWP-ASan 初始化:** 在 libc.so 初始化阶段，GWP-ASan 会根据系统属性或环境变量的配置进行初始化。这可能包括分配元数据内存，以及 hook 或包装原有的 `malloc` 和 `free` 函数。

**如果做了逻辑推理，请给出假设输入与输出:**

在 `sysprops_program_specific` 测试中，假设：

**假设输入:**

* 测试程序的可执行文件名为 `gwp_asan_test`。
* 初始状态下，与 GWP-ASan 相关的系统属性未设置。
* 测试代码执行了以下操作：
    ```c++
    std::string path = testing::internal::GetArgvs()[0]; // path 为 /path/to/gwp_asan_test
    const char* basename = __gnu_basename(path.c_str()); // basename 为 gwp_asan_test
    __system_property_set((std::string("libc.debug.gwp_asan.sample_rate.") + basename).c_str(), "1");
    __system_property_set((std::string("libc.debug.gwp_asan.process_sampling.") + basename).c_str(), "1");
    __system_property_set((std::string("libc.debug.gwp_asan.max_allocs.") + basename).c_str(), "40000");
    RunSubtestNoEnv("gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled");
    ```

**预期输出:**

* `__gnu_basename` 函数将返回 `gwp_asan_test`。
* `__system_property_set` 函数将设置以下系统属性：
    * `libc.debug.gwp_asan.sample_rate.gwp_asan_test = 1`
    * `libc.debug.gwp_asan.process_sampling.gwp_asan_test = 1`
    * `libc.debug.gwp_asan.max_allocs.gwp_asan_test = 40000`
* 当运行子测试 `gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled` 时，由于上述系统属性的设置，GWP-ASan 将被启用。该子测试会检查 `/proc/self/maps` 文件中是否包含 "GWP-ASan" 字符串，预期会找到。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确配置系统属性或环境变量:**  用户可能错误地设置了 GWP-ASan 的系统属性，例如将采样率设置为 0，导致 GWP-ASan 没有生效，从而无法检测到内存错误。

   ```bash
   # 错误地禁用 GWP-ASan
   adb shell setprop libc.debug.gwp_asan.sample_rate.my_app 0
   ```

2. **与其他内存安全工具冲突:** 虽然测试中考虑了与 HWASan 的兼容性，但在某些情况下，同时启用多个内存安全工具可能会导致冲突或性能问题。

3. **误解 GWP-ASan 的检测范围:** GWP-ASan 依赖于随机采样，因此并非每次内存错误都能被立即检测到。开发者可能会误认为没有检测到错误就表示代码没有问题。

4. **过度依赖 GWP-ASan 而忽视静态分析和其他测试方法:** GWP-ASan 是一种运行时检测工具，应该与其他代码审查、静态分析和单元测试等方法结合使用，以更全面地发现和修复内存错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 或 NDK 如何到达 GWP-ASan 代码:**

1. **NDK 应用调用 `malloc` 或 `new`:**  当一个使用 NDK 开发的 Android 应用调用标准 C/C++ 内存分配函数 `malloc` 或 `new` 时，这些调用最终会链接到 Bionic 库中的实现。

2. **Framework 进程的内存分配:** Android Framework 中的各种系统服务和应用进程也会进行内存分配，同样会调用 Bionic 库的 `malloc` 或 `new`。

3. **GWP-ASan 的介入:** 如果 GWP-ASan 被启用（通过系统属性或环境变量），Bionic 库中的 `malloc` 实现会被 GWP-ASan 的逻辑增强。当分配内存时，GWP-ASan 会有一定的概率将分配的内存块放置在 guard page 附近。

4. **内存错误触发:** 如果程序发生了 use-after-free 或其他内存访问错误，并且刚好访问到了 GWP-ASan 设置的 guard page，就会触发一个错误信号 (通常是 `SIGSEGV`)。

5. **错误报告:** GWP-ASan 的错误处理机制会捕获这个信号，并生成相应的错误报告，通常会包含崩溃的堆栈信息和相关的内存地址。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida hook Bionic 库中的关键函数，来观察 GWP-ASan 的行为。以下是一些示例：

**1. Hook `__system_property_set` 查看 GWP-ASan 相关属性的设置:**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_set"), {
    onEnter: function(args) {
        var name = Memory.readCString(args[0]);
        var value = Memory.readCString(args[1]);
        if (name.includes("gwp_asan")) {
            send(`__system_property_set called with name: ${name}, value: ${value}`);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个脚本会 hook `__system_property_set` 函数，并打印所有与 "gwp_asan" 相关的系统属性的设置。

**2. Hook `malloc` 查看 GWP-ASan 是否影响分配过程:**

```python
import frida
import sys

package_name = "your.app.package.name"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        send(`malloc called with size: ${size}`);
    },
    onLeave: function(retval) {
        send(`malloc returned address: ${retval}`);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个脚本会 hook `malloc` 函数，打印每次 `malloc` 调用的请求大小和返回的地址。通过观察 `malloc` 的调用，可以间接了解 GWP-ASan 是否以某种方式影响了内存分配的行为。

**3. 模拟触发 use-after-free 并观察 GWP-ASan 的反应 (需要一定的代码注入技巧):**

要更深入地调试 GWP-ASan，可以尝试在目标应用中注入代码，人为地触发 use-after-free 错误，并观察 GWP-ASan 是否能够检测到并报告。这通常需要更高级的 Frida 使用技巧，例如内存写入和函数调用。

**总结:**

`bionic/tests/gwp_asan_test.cpp` 是一个关键的测试文件，用于验证 Android Bionic 库中 GWP-ASan 功能的正确性和可靠性。它涵盖了 GWP-ASan 的启用、禁用、不同配置下的行为以及与其他内存安全工具的兼容性。理解这个测试文件有助于我们更好地理解 GWP-ASan 的工作原理以及如何在 Android 系统中使用它来提高内存安全性。 使用 Frida 可以帮助开发者在运行时动态地观察和调试 GWP-ASan 的行为。

Prompt: 
```
这是目录为bionic/tests/gwp_asan_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2021 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <stdio.h>
#include <sys/file.h>
#include <string>

#if defined(__BIONIC__)

#include "android-base/file.h"
#include "android-base/silent_death_test.h"
#include "android-base/test_utils.h"
#include "gwp_asan/options.h"
#include "platform/bionic/malloc.h"
#include "sys/system_properties.h"
#include "utils.h"

using gwp_asan_integration_DeathTest = SilentDeathTest;

// basename is a mess, use gnu basename explicitly to avoid the need for string
// mutation.
extern "C" const char* __gnu_basename(const char* path);

// GWP-ASan tests can run much slower, especially when combined with HWASan.
// Triple the deadline to avoid flakes (b/238585984).
extern "C" bool GetInitialArgs(const char*** args, size_t* num_args) {
  static const char* initial_args[] = {"--deadline_threshold_ms=270000"};
  *args = initial_args;
  *num_args = 1;
  return true;
}

// This file implements "torture testing" under GWP-ASan, where we sample every
// single allocation. The upper limit for the number of GWP-ASan allocations in
// the torture mode is is generally 40,000, so that svelte devices don't
// explode, as this uses ~163MiB RAM (4KiB per live allocation).
TEST(gwp_asan_integration, malloc_tests_under_torture) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  RunGwpAsanTest("malloc.*:-malloc.mallinfo*");
}

class SyspropRestorer {
 private:
  std::vector<std::pair<std::string, std::string>> props_to_restore_;
  // System properties are global for a device, so the tests that mutate the
  // GWP-ASan system properties must be run mutually exclusive. Because
  // bionic-unit-tests is run in an isolated gtest fashion (each test is run in
  // its own process), we have to use flocks to synchronise between tests.
  int flock_fd_;

 public:
  SyspropRestorer() {
    std::string path = testing::internal::GetArgvs()[0];
    flock_fd_ = open(path.c_str(), O_RDONLY);
    EXPECT_NE(flock_fd_, -1) << "failed to open self for a flock";
    EXPECT_NE(flock(flock_fd_, LOCK_EX), -1) << "failed to flock myself";

    const char* basename = __gnu_basename(path.c_str());
    std::vector<std::string> props = {
        std::string("libc.debug.gwp_asan.sample_rate.") + basename,
        std::string("libc.debug.gwp_asan.process_sampling.") + basename,
        std::string("libc.debug.gwp_asan.max_allocs.") + basename,
        "libc.debug.gwp_asan.sample_rate.system_default",
        "libc.debug.gwp_asan.sample_rate.app_default",
        "libc.debug.gwp_asan.process_sampling.system_default",
        "libc.debug.gwp_asan.process_sampling.app_default",
        "libc.debug.gwp_asan.max_allocs.system_default",
        "libc.debug.gwp_asan.max_allocs.app_default",
    };

    size_t base_props_size = props.size();
    for (size_t i = 0; i < base_props_size; ++i) {
      props.push_back("persist." + props[i]);
    }

    std::string reset_log;

    for (const std::string& prop : props) {
      std::string value = GetSysprop(prop);
      props_to_restore_.emplace_back(prop, value);
      if (!value.empty()) {
        __system_property_set(prop.c_str(), "");
      }
    }
  }

  ~SyspropRestorer() {
    for (const auto& kv : props_to_restore_) {
      if (kv.second != GetSysprop(kv.first)) {
        __system_property_set(kv.first.c_str(), kv.second.c_str());
      }
    }
    close(flock_fd_);
  }

  static std::string GetSysprop(const std::string& name) {
    std::string value;
    const prop_info* pi = __system_property_find(name.c_str());
    if (pi == nullptr) return value;
    __system_property_read_callback(
        pi,
        [](void* cookie, const char* /* name */, const char* value, uint32_t /* serial */) {
          std::string* v = static_cast<std::string*>(cookie);
          *v = value;
        },
        &value);
    return value;
  }
};

TEST_F(gwp_asan_integration_DeathTest, DISABLED_assert_gwp_asan_enabled) {
  std::string maps;
  EXPECT_TRUE(android::base::ReadFileToString("/proc/self/maps", &maps));
  EXPECT_TRUE(maps.find("GWP-ASan") != std::string::npos) << maps;

  volatile int* x = new int;
  delete x;
  EXPECT_DEATH({ *x = 7; }, "");
}

// A weaker version of the above tests, only checking that GWP-ASan is enabled
// for any pointer, not *our* pointer. This allows us to test the system_default
// sysprops without potentially OOM-ing other random processes:
// b/273904016#comment5
TEST(gwp_asan_integration, DISABLED_assert_gwp_asan_enabled_weaker) {
  std::string maps;
  EXPECT_TRUE(android::base::ReadFileToString("/proc/self/maps", &maps));
  EXPECT_TRUE(maps.find("GWP-ASan") != std::string::npos) << maps;
}

TEST(gwp_asan_integration, DISABLED_assert_gwp_asan_disabled) {
  std::string maps;
  EXPECT_TRUE(android::base::ReadFileToString("/proc/self/maps", &maps));
  EXPECT_TRUE(maps.find("GWP-ASan") == std::string::npos);
}

TEST(gwp_asan_integration, sysprops_program_specific) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  std::string path = testing::internal::GetArgvs()[0];
  const char* basename = __gnu_basename(path.c_str());
  __system_property_set((std::string("libc.debug.gwp_asan.sample_rate.") + basename).c_str(), "1");
  __system_property_set((std::string("libc.debug.gwp_asan.process_sampling.") + basename).c_str(),
                        "1");
  __system_property_set((std::string("libc.debug.gwp_asan.max_allocs.") + basename).c_str(),
                        "40000");

  RunSubtestNoEnv("gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled");
}

TEST(gwp_asan_integration, sysprops_persist_program_specific) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  std::string path = testing::internal::GetArgvs()[0];
  const char* basename = __gnu_basename(path.c_str());
  __system_property_set(
      (std::string("persist.libc.debug.gwp_asan.sample_rate.") + basename).c_str(), "1");
  __system_property_set(
      (std::string("persist.libc.debug.gwp_asan.process_sampling.") + basename).c_str(), "1");
  __system_property_set((std::string("persist.libc.debug.gwp_asan.max_allocs.") + basename).c_str(),
                        "40000");

  RunSubtestNoEnv("gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled");
}

TEST(gwp_asan_integration, sysprops_non_persist_overrides_persist) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  __system_property_set("libc.debug.gwp_asan.sample_rate.system_default", "1");
  __system_property_set("libc.debug.gwp_asan.process_sampling.system_default", "1");
  // Note, any processes launched elsewhere on the system right now will have
  // GWP-ASan enabled. Make sure that we only use a single slot, otherwise we
  // could end up causing said badly-timed processes to use up to 163MiB extra
  // penalty that 40,000 allocs would cause. See b/273904016#comment5 for more
  // context.
  __system_property_set("libc.debug.gwp_asan.max_allocs.system_default", "1");

  __system_property_set("persist.libc.debug.gwp_asan.sample_rate.system_default", "0");
  __system_property_set("persist.libc.debug.gwp_asan.process_sampling.system_default", "0");
  __system_property_set("persist.libc.debug.gwp_asan.max_allocs.system_default", "0");

  RunSubtestNoEnv("gwp_asan_integration.DISABLED_assert_gwp_asan_enabled_weaker");
}

TEST(gwp_asan_integration, sysprops_program_specific_overrides_default) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  std::string path = testing::internal::GetArgvs()[0];
  const char* basename = __gnu_basename(path.c_str());
  __system_property_set(
      (std::string("persist.libc.debug.gwp_asan.sample_rate.") + basename).c_str(), "1");
  __system_property_set(
      (std::string("persist.libc.debug.gwp_asan.process_sampling.") + basename).c_str(), "1");
  __system_property_set((std::string("persist.libc.debug.gwp_asan.max_allocs.") + basename).c_str(),
                        "40000");

  __system_property_set("libc.debug.gwp_asan.sample_rate.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.process_sampling.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.max_allocs.system_default", "0");

  RunSubtestNoEnv("gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled");
}

TEST(gwp_asan_integration, sysprops_can_disable) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  __system_property_set("libc.debug.gwp_asan.sample_rate.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.process_sampling.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.max_allocs.system_default", "0");

  RunSubtestNoEnv("gwp_asan_integration.DISABLED_assert_gwp_asan_disabled");
}

TEST(gwp_asan_integration, env_overrides_sysprop) {
  // Do not override HWASan with GWP ASan.
  SKIP_WITH_HWASAN;

  SyspropRestorer restorer;

  __system_property_set("libc.debug.gwp_asan.sample_rate.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.process_sampling.system_default", "0");
  __system_property_set("libc.debug.gwp_asan.max_allocs.system_default", "0");

  RunGwpAsanTest("gwp_asan_integration_DeathTest.DISABLED_assert_gwp_asan_enabled");
}

#endif  // defined(__BIONIC__)

"""

```