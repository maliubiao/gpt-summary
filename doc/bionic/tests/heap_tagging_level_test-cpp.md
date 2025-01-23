Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - The Big Picture:**

The first step is to read the initial comments and `#include` directives to understand the core purpose. Keywords like "heap_tagging_level," `malloc.h`, `sys/prctl.h`, and mentions of "MTE" and "HWASan" immediately suggest this code is about memory management, specifically how memory tagging (a security feature) is tested. The `gtest` framework indicates this is a unit test.

**2. Identifying Key Functionalities:**

Next, I scan the code for the most important functions and logic blocks. The functions `KernelSupportsTaggedPointers()`, `SetHeapTaggingLevel()`, and the various `TEST_F` and `TEST` blocks stand out. I would note these down as primary areas of focus.

*   `KernelSupportsTaggedPointers()`:  Checks if the underlying kernel supports tagged pointers. This is a platform dependency.
*   `SetHeapTaggingLevel()`: Uses `mallopt` to change the heap tagging behavior. This is a core function under test.
*   `TEST_F(heap_tagging_level_DeathTest, tagged_pointer_dies)`:  Tests the behavior when freeing a pointer with an incorrect tag. The `EXPECT_DEATH` macro signifies it's testing for program termination.
*   `TEST(heap_tagging_level, sync_async_bad_accesses_die)`: Tests how synchronous and asynchronous tagging modes handle bad memory accesses. The `EXPECT_EXIT` macro indicates this tests for specific exit codes.
*   `TEST(heap_tagging_level, none_pointers_untagged)`: Checks that when tagging is disabled, pointers are indeed untagged.
*   `TEST(heap_tagging_level, tagging_level_transitions)`: Verifies the allowed transitions between different heap tagging levels.
*   `TEST(heap_tagging_level, tagging_level_transition_sync_none)`: A specific test case for transitioning from synchronous tagging to none.
*   `TEST_P(MemtagNoteTest, SEGV)`: A parameterized test using external helper executables to test the impact of different tagging modes.

**3. Deeper Dive into Individual Functions:**

Once the major components are identified, I would delve into the details of each.

*   **`KernelSupportsTaggedPointers()`:** The `prctl` syscall is the key. I would research `PR_GET_TAGGED_ADDR_CTRL` and `PR_TAGGED_ADDR_ENABLE` to understand how the kernel exposes this information. The `#ifdef __aarch64__` is important, showing it's architecture-specific.

*   **`SetHeapTaggingLevel()`:**  The `mallopt` function is the focus. I would note that `M_BIONIC_SET_HEAP_TAGGING_LEVEL` is a Bionic-specific option. Understanding `mallopt`'s role in controlling the memory allocator is crucial.

*   **Test Cases:**  For each test case, I'd analyze the setup (what tagging level is set), the action being performed (allocation, freeing, memory access), and the expected outcome (`EXPECT_DEATH`, `EXPECT_EXIT`, `EXPECT_EQ`). The use of `untag_address` and the checks for MTE and HWASan are important details.

**4. Connecting to Android Functionality:**

Now, I would explicitly link these test cases to Android features:

*   **Memory Tagging:** This is a core Android security feature to detect memory corruption. The tests directly exercise this.
*   **HWASan/MTE:** These are memory safety tools used in Android development and on devices. The tests skip certain scenarios based on whether these are enabled.
*   **Bionic:**  As the test location indicates, these tests are for Bionic, Android's C library. The `mallopt` function is part of Bionic.
*   **Dynamic Linker (Indirect):** While not directly testing the dynamic linker in this specific file, memory allocation is fundamental to the dynamic linker's operation. When a shared library is loaded, the linker uses `malloc` (or a related function) to allocate memory for the library's code and data. Heap tagging would therefore affect these allocations.

**5. Addressing Specific Request Points:**

With a solid understanding of the code, I can now address the specific points raised in the prompt:

*   **Functionality:**  Summarize the purpose of each function and test case.
*   **Android Relationship:** Explicitly connect the code to Android features like memory tagging, HWASan, and Bionic.
*   **`libc` Function Details:**  Explain how `malloc`, `free`, `mallopt`, `prctl`, and `_exit` work.
*   **Dynamic Linker:** Explain the *implicit* relationship. This test file isn't directly about the linker, so a full SO layout isn't relevant here. Focus on how memory allocation relates to the linker's job.
*   **Logic Inference (Input/Output):** For the test cases, the input is the tagging level and the operations performed, and the output is whether the program crashes (and with what signal) or not.
*   **User/Programming Errors:**  Explain the dangers of freeing untagged pointers when tagging is enabled.
*   **Android Framework/NDK to Test:**  Describe the chain: NDK -> `malloc`/`free` -> Bionic's implementation -> these tests.
*   **Frida Hook Examples:** Provide concrete Frida snippets to intercept relevant functions.

**6. Structuring the Output:**

Finally, I organize the information logically, using headings and bullet points for clarity. I ensure to answer each part of the prompt comprehensively. I use clear and concise language and provide code examples where appropriate. The language should be Chinese, as requested.

**Self-Correction/Refinement During the Process:**

*   **Initial thought:** "This is just about `malloc` and `free`."  **Correction:** Realized the focus is on *tagged* pointers, a more specific feature.
*   **Initial thought:** "Let me explain dynamic linking in detail." **Correction:**  Recognized this file doesn't directly test the linker; the connection is through memory allocation. Adjusted the explanation accordingly.
*   **Checking for edge cases:**  Considered the `SKIP_WITH_NATIVE_BRIDGE` and the property check in `MemtagNoteTest`, realizing these are important for the test's context.

By following these steps, the comprehensive and accurate analysis of the `heap_tagging_level_test.cpp` file can be produced.
好的，让我们详细分析一下 `bionic/tests/heap_tagging_level_test.cpp` 这个文件。

**文件功能概述**

这个 C++ 文件是 Android Bionic 库中的一个测试文件，专门用于测试 **堆内存标签 (Heap Tagging)** 功能的各种场景和行为。堆内存标签是一种安全特性，旨在帮助检测和防止内存错误，例如 use-after-free 和 double-free。

**与 Android 功能的关系及举例**

这个测试文件直接关联到 Android 的内存管理和安全特性：

* **内存安全增强:** 堆内存标签是 Android 提高内存安全性的重要机制。通过在内存分配的指针中嵌入标签，并在访问时进行校验，可以及时发现潜在的内存错误。
* **Bionic 的 `malloc` 和 `free` 实现:**  这个测试文件直接测试了 Bionic 库中 `malloc` 和 `free` 函数在启用堆内存标签时的行为。
* **系统属性控制:** 代码中使用了 `android::base::GetProperty` 来检查系统属性 `persist.arm64.memtag.default`，这表明 Android 系统可以通过属性来控制堆内存标签的默认行为。
* **硬件加速 (MTE):** 测试中多次检查 `mte_supported()` 和 `running_with_mte()`，说明堆内存标签功能可以利用 ARMv8.5-A 引入的内存标签扩展 (Memory Tagging Extension, MTE) 硬件特性来提高效率和准确性。
* **地址空间布局随机化 (ASLR) 的补充:** 堆内存标签可以作为 ASLR 的补充，进一步提高内存攻击的难度。

**libc 函数功能详解**

这个测试文件中涉及的 `libc` 函数主要有：

1. **`malloc(size_t size)`:**
   * **功能:** 在堆上分配一块指定大小的内存。
   * **实现 (简述):** Bionic 的 `malloc` 实现（通常是 jemalloc 或 scudo）会维护一个堆的结构，记录哪些内存块是空闲的，哪些是被占用的。当调用 `malloc` 时，它会找到一块足够大的空闲内存块，将其标记为已占用，并返回指向该内存块起始地址的指针。
   * **堆内存标签的影响:** 当堆内存标签启用时，`malloc` 分配的内存块的指针的高位会包含一个标签值。这个标签值在分配时生成，并与内存块本身关联。

2. **`free(void* ptr)`:**
   * **功能:** 释放之前通过 `malloc`、`calloc` 或 `realloc` 分配的内存块。
   * **实现 (简述):** 当调用 `free` 时，Bionic 的内存分配器会检查传入的指针是否有效，然后将该指针指向的内存块标记为空闲，以便后续的 `malloc` 可以重新使用。
   * **堆内存标签的影响:** 当堆内存标签启用时，`free` 会检查传入指针的标签是否与分配时记录的标签一致。如果不一致，可能会触发错误，例如测试中的 `EXPECT_DEATH(free(x), "Pointer tag for 0x[a-zA-Z0-9]* was truncated")`。

3. **`mallopt(int cmd, int value)`:**
   * **功能:** 用于控制内存分配器的行为。
   * **实现 (简述):**  `mallopt` 接收命令 (`cmd`) 和值 (`value`) 作为参数，根据命令修改内存分配器的内部设置。
   * **在本文件中的作用:**  `SetHeapTaggingLevel` 函数封装了 `mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, level)`，用于设置堆内存标签的级别。 `M_BIONIC_SET_HEAP_TAGGING_LEVEL` 是 Bionic 特有的命令，用于控制堆内存标签的开启、关闭和模式（例如同步或异步）。

4. **`prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`:**
   * **功能:** 对进程或线程的行为进行控制。
   * **实现 (简述):** `prctl` 是一个系统调用，允许进程修改自身的一些属性或行为。
   * **在本文件中的作用:** `KernelSupportsTaggedPointers` 函数使用 `prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0)` 来查询内核是否支持 tagged pointers。`PR_GET_TAGGED_ADDR_CTRL` 是一个特定的 `option`，用于获取与 tagged address 功能相关的控制信息。

5. **`_exit(int status)`:**
   * **功能:** 立即终止当前进程，不执行任何清理操作（例如调用析构函数或刷新 I/O 缓冲区）。
   * **实现 (简述):**  `_exit` 是一个低级的系统调用，直接通知内核结束进程。
   * **在本文件中的作用:** `ExitWithSiCode` 函数作为信号处理函数，在收到 `SIGSEGV` 信号时调用 `_exit(info->si_code)`，使用导致错误的信号代码作为进程退出状态。

**涉及 dynamic linker 的功能及处理过程**

虽然这个测试文件本身没有直接测试 dynamic linker 的功能，但堆内存管理是 dynamic linker 工作的基础。

* **SO 布局样本 (理论上的):** 当动态链接器加载一个共享库 (.so) 时，它需要将库的代码、数据等段加载到内存中。一个简化的 SO 布局可能如下所示：

```
[加载地址]
+-----------------+
|     ELF Header    |
+-----------------+
| Program Header  |
| Table           |
+-----------------+
| Section Header  |
| Table           |
+-----------------+
|    .text (代码段)   |  <-- 需要分配内存
+-----------------+
|    .rodata (只读数据) |  <-- 需要分配内存
+-----------------+
|    .data (已初始化数据) |  <-- 需要分配内存
+-----------------+
|    .bss (未初始化数据) |  <-- 需要分配内存
+-----------------+
|  ... 其他段 ... |
+-----------------+
```

* **链接的处理过程 (与内存分配相关):**
    1. **加载 SO:** dynamic linker 读取 SO 文件的头部信息，确定需要加载的段及其大小。
    2. **内存分配:** 对于需要加载到内存的段（例如 `.text`, `.data`, `.bss`），dynamic linker 会调用内存分配函数（通常是通过 `mmap` 或 `malloc` 等底层机制）来分配相应的内存空间。
    3. **内容加载:** 将 SO 文件中对应段的内容复制到分配的内存中。
    4. **重定位:**  修改代码和数据段中的地址，使其指向正确的内存位置。这可能涉及到对全局变量、函数地址等的调整。

* **堆内存标签的影响:** 如果启用了堆内存标签，那么 dynamic linker 在为 SO 分配内存时，分配器返回的指针将会带有标签。任何对这些内存的访问，都会受到标签校验的保护。

**逻辑推理、假设输入与输出**

让我们以 `tagged_pointer_dies` 测试为例进行逻辑推理：

* **假设输入:**
    1. 内核支持 tagged pointers (`KernelSupportsTaggedPointers()` 返回 true)。
    2. 不在 MTE 硬件上运行 (`!mte_supported()`)。
    3. 未启用 HWASan (`!running_with_hwasan()`)。
    4. 初始堆内存标签级别未指定，默认为开启。

* **执行步骤:**
    1. `void *x = malloc(1);`  分配一个字节的内存，`x` 指向分配的内存，并且 `x` 的高位包含一个标签。
    2. `EXPECT_NE(reinterpret_cast<uintptr_t>(x) >> 56, 0u);`  断言 `x` 具有标签（高位不为 0）。
    3. `x = untag_address(x);`  移除 `x` 的标签。
    4. `EXPECT_DEATH(free(x), "Pointer tag for 0x[a-zA-Z0-9]* was truncated");` 尝试释放一个没有标签的指针。由于堆内存标签已启用，`free` 检测到标签缺失，导致程序异常终止 (death)。预期的错误消息包含 "Pointer tag was truncated"。
    5. `EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));`  显式设置堆内存标签级别为 `M_HEAP_TAGGING_LEVEL_TBI` (Tag-Based Invalidity)。
    6. `EXPECT_DEATH(free(untag_address(malloc(1))), "Pointer tag for 0x[a-zA-Z0-9]* was truncated");`  再次分配内存，移除标签，然后尝试释放。预期结果与步骤 4 相同。
    7. `x = malloc(1);` 分配内存给 `x` (带标签)。
    8. `void *y = malloc(1);` 分配内存给 `y` (带标签)。
    9. `EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));`  禁用堆内存标签。
    10. `free(x);` 释放之前分配的 `x`。即使 `x` 有标签，由于堆内存标签已禁用，`free` 也会成功执行。
    11. `free(untag_address(y));` 释放 `y` 的无标签版本。由于堆内存标签已禁用，`free` 也会成功执行，即使指针没有标签。

* **预期输出:**  在步骤 4 和 6 会触发断言失败，导致程序退出。其他操作应该正常执行。

**用户或编程常见的使用错误**

与堆内存标签相关的常见错误包括：

1. **忘记或错误地去除标签:**  当堆内存标签启用时，如果开发者手动去除了指针的标签，然后尝试使用该指针进行内存访问或释放，会导致错误。`untag_address` 函数应该谨慎使用，只在必要的时候进行。

   ```c++
   void* ptr = malloc(10);
   uintptr_t untagged_ptr = untag_address(ptr);
   free(reinterpret_cast<void*>(untagged_ptr)); // 错误：尝试释放一个没有标签的指针
   ```

2. **在启用了堆内存标签的环境中，与未适配的代码交互:** 如果一部分代码期望处理未标记的指针，而在启用了堆内存标签的环境中接收到了带标签的指针，可能会导致类型转换错误或访问错误。

3. **不理解不同的堆内存标签级别的影响:** 例如，在 `M_HEAP_TAGGING_LEVEL_SYNC` 模式下，访问带有错误标签的内存会立即导致崩溃，而在 `M_HEAP_TAGGING_LEVEL_ASYNC` 模式下，错误可能不会立即显现，而是在稍后的时间点报告。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:**  Android 开发者可以使用 NDK (Native Development Kit) 编写 C/C++ 代码。
2. **内存分配:**  在 NDK 代码中，开发者可以使用标准的 `malloc`、`free` 等函数进行内存管理。这些函数由 Bionic 库提供。
3. **Bionic 库:** 当 NDK 代码调用 `malloc` 时，实际上会调用 Bionic 库中的 `malloc` 实现。
4. **堆内存标签:** 如果 Android 系统启用了堆内存标签功能，Bionic 的 `malloc` 实现会在分配的指针中添加标签。
5. **运行时校验:** 当 NDK 代码尝试使用或释放这些指针时，Bionic 库会在运行时检查指针的标签是否有效。如果标签不匹配，会触发相应的错误信号 (例如 `SIGSEGV`)。
6. **测试:**  `heap_tagging_level_test.cpp` 文件就是 Bionic 库的开发者为了验证堆内存标签功能的正确性而编写的测试代码。

**Frida Hook 示例调试**

可以使用 Frida 来 hook 相关的函数，观察堆内存标签的行为：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

session = frida.attach(package_name)

script_code = """
console.log("Script loaded");

// Hook malloc
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        console.log("malloc(" + size + ")");
    },
    onLeave: function(retval) {
        console.log("malloc returns: " + retval);
        // 可以尝试读取返回值的高位，查看标签
        if (Process.pointerSize === 8) { // 64-bit
            var tag = retval.shr(56);
            console.log("  Tag: " + tag);
        }
    }
});

// Hook free
Interceptor.attach(Module.findExportByName("libc.so", "free"), {
    onEnter: function(args) {
        var ptr = args[0];
        console.log("free(" + ptr + ")");
        // 可以尝试读取传入指针的高位，查看标签
        if (Process.pointerSize === 8 && ptr.compare(ptr.xor(0)) !== 0) { // 检查指针是否为空
            var tag = ptr.shr(56);
            console.log("  Tag: " + tag);
        }
    }
});

// Hook mallopt (用于观察堆内存标签级别的设置)
Interceptor.attach(Module.findExportByName("libc.so", "mallopt"), {
    onEnter: function(args) {
        var cmd = args[0].toInt();
        var value = args[1].toInt();
        if (cmd === 125 /* M_BIONIC_SET_HEAP_TAGGING_LEVEL */) {
            console.log("mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, " + value + ")");
        }
    }
});
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[-] {message}")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook.py`。
2. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
3. 将 `your.app.package.name` 替换为你想要调试的应用程序的包名。
4. 运行 Python 脚本：`python hook.py`
5. 在目标应用程序中执行涉及内存分配和释放的操作。
6. Frida 会打印出 `malloc`、`free` 和 `mallopt` 调用的相关信息，包括指针的值和可能的标签。

通过 Frida hook，你可以实时观察应用程序的内存分配行为，验证堆内存标签是否被正确应用和校验。

希望这个详细的解释能够帮助你理解 `bionic/tests/heap_tagging_level_test.cpp` 文件的功能和相关概念。

### 提示词
```
这是目录为bionic/tests/heap_tagging_level_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <malloc.h>
#include <sys/prctl.h>

#include <android-base/silent_death_test.h>

#if defined(__BIONIC__)
#include "gtest_globals.h"
#include "platform/bionic/mte.h"
#include "utils.h"

#include "SignalUtils.h"

#include <android-base/properties.h>
#include <android-base/test_utils.h>
#include <bionic/malloc_tagged_pointers.h>

static bool KernelSupportsTaggedPointers() {
#ifdef __aarch64__
  int res = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  return res >= 0 && res & PR_TAGGED_ADDR_ENABLE;
#else
  return false;
#endif
}

static bool SetHeapTaggingLevel(HeapTaggingLevel level) {
  return mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, level);
}
#endif

using heap_tagging_level_DeathTest = SilentDeathTest;

TEST_F(heap_tagging_level_DeathTest, tagged_pointer_dies) {
#if defined(__BIONIC__)
  if (!KernelSupportsTaggedPointers()) {
    GTEST_SKIP() << "Kernel doesn't support tagged pointers.";
  }

#ifdef __aarch64__
  if (mte_supported()) {
    GTEST_SKIP() << "Tagged pointers are not used on MTE hardware.";
  }
  if (running_with_hwasan()) {
    GTEST_SKIP() << "Tagged heap pointers feature is disabled under HWASan.";
  }

  void *x = malloc(1);

  // Ensure that `x` has a pointer tag.
  EXPECT_NE(reinterpret_cast<uintptr_t>(x) >> 56, 0u);

  x = untag_address(x);
  EXPECT_DEATH(free(x), "Pointer tag for 0x[a-zA-Z0-9]* was truncated");

  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
  EXPECT_DEATH(free(untag_address(malloc(1))), "Pointer tag for 0x[a-zA-Z0-9]* was truncated");

  x = malloc(1);
  void *y = malloc(1);
  // Disable heap tagging.
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
  // Ensure an older tagged pointer can still be freed.
  free(x);
  // Tag mismatch is not detected on old pointers.
  free(untag_address(y));
#endif // defined(__aarch64__)
#else
  GTEST_SKIP() << "bionic-only test";
#endif // defined(__BIONIC__)
}

namespace {
#if defined(__BIONIC__) && defined(__aarch64__)
void ExitWithSiCode(int, siginfo_t* info, void*) {
  _exit(info->si_code);
}

template <typename Pred>
class Or {
  Pred A, B;

 public:
  Or(Pred A, Pred B) : A(A), B(B) {}
  bool operator()(int exit_status) { return A(exit_status) || B(exit_status); }
};
#endif

TEST(heap_tagging_level, sync_async_bad_accesses_die) {
#if defined(__BIONIC__) && defined(__aarch64__)
  if (!mte_supported() || !running_with_mte()) {
    GTEST_SKIP() << "requires MTE to be enabled";
  }

  std::unique_ptr<int[]> p = std::make_unique<int[]>(4);
  volatile int sink ATTRIBUTE_UNUSED;

  // We assume that scudo is used on all MTE enabled hardware; scudo inserts a header with a
  // mismatching tag before each allocation.
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
  EXPECT_EXIT(
      {
        ScopedSignalHandler ssh(SIGSEGV, ExitWithSiCode, SA_SIGINFO);
        p[-1] = 42;
      },
      testing::ExitedWithCode(SEGV_MTESERR), "");
  EXPECT_EXIT(
      {
        ScopedSignalHandler ssh(SIGSEGV, ExitWithSiCode, SA_SIGINFO);
        sink = p[-1];
      },
      testing::ExitedWithCode(SEGV_MTESERR), "");

  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
  EXPECT_EXIT(
      {
        ScopedSignalHandler ssh(SIGSEGV, ExitWithSiCode, SA_SIGINFO);
        p[-1] = 42;
      },
      Or(testing::ExitedWithCode(SEGV_MTESERR), testing::ExitedWithCode(SEGV_MTEAERR)), "");
  EXPECT_EXIT(
      {
        ScopedSignalHandler ssh(SIGSEGV, ExitWithSiCode, SA_SIGINFO);
        sink = p[-1];
      },
      Or(testing::ExitedWithCode(SEGV_MTESERR), testing::ExitedWithCode(SEGV_MTEAERR)), "");

  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
  sink = p[-1];
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}
}  // namespace

TEST(heap_tagging_level, none_pointers_untagged) {
#if defined(__BIONIC__)
  if (running_with_hwasan()) {
    GTEST_SKIP() << "HWASan is unaffected by heap tagging level.";
  }
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
  std::unique_ptr<int[]> p = std::make_unique<int[]>(4);
  EXPECT_EQ(untag_address(p.get()), p.get());
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(heap_tagging_level, tagging_level_transitions) {
#if defined(__BIONIC__) && defined(__aarch64__)
  if (!KernelSupportsTaggedPointers()) {
    GTEST_SKIP() << "Kernel doesn't support tagged pointers.";
  }

  EXPECT_FALSE(SetHeapTaggingLevel(static_cast<HeapTaggingLevel>(12345)));

  if (running_with_hwasan()) {
    // NONE -> ...
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
  } else if (mte_supported() && running_with_mte()) {
    // ASYNC -> ...
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));

    // SYNC -> ...
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
  } else if (!mte_supported()) {
    // TBI -> ...
    EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
    EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
  }

  // TBI -> NONE on non-MTE, ASYNC|SYNC|NONE -> NONE on MTE.
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));

  // NONE -> ...
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
  EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_TBI));
  EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_ASYNC));
  EXPECT_FALSE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

TEST(heap_tagging_level, tagging_level_transition_sync_none) {
#if defined(__BIONIC__) && defined(__aarch64__)
  // We can't test SYNC -> NONE in tagging_level_transitions because we can only make one transition
  // to NONE (which we use to test ASYNC -> NONE), so we test it here separately.
  if (!mte_supported() || !running_with_mte()) {
    GTEST_SKIP() << "requires MTE to be enabled";
  }

  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC));
  EXPECT_TRUE(SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_NONE));
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

enum class MemtagNote { NONE, ASYNC, SYNC };
class MemtagNoteTest : public testing::TestWithParam<std::tuple<MemtagNote, bool>> {};

static const char* kNoteSuffix[] = {"disabled", "async", "sync"};

TEST_P(MemtagNoteTest, SEGV) {
#if defined(__BIONIC__) && defined(__aarch64__)
  SKIP_WITH_NATIVE_BRIDGE;  // http://b/242170715
  if (android::base::GetProperty("persist.arm64.memtag.default", "") != "") {
    GTEST_SKIP() << "not supported when overriding memtag mode with property";
  }
  // Note that we do not check running_with_hwasan() - what matters here is whether the test binary
  // itself is built with HWASan.
  bool withMTE = getauxval(AT_HWCAP2) & HWCAP2_MTE;

  // Note that we do not check the exact si_code of the "async" variant, as it may be auto-upgraded
  // to asymm or even sync.
  const char* kExpectedOutputMTE[] = {"normal exit\n", "SEGV_MTE[AS]ERR\n", "SEGV_MTESERR\n"};
  const char* kExpectedOutputNonMTE[] = {"normal exit\n", "normal exit\n", "normal exit\n"};
  const char** kExpectedOutput = withMTE ? kExpectedOutputMTE : kExpectedOutputNonMTE;

  MemtagNote note = std::get<0>(GetParam());
  bool isStatic = std::get<1>(GetParam());
  std::string helper_base = std::string("heap_tagging_") + (isStatic ? "static_" : "") +
                            kNoteSuffix[static_cast<int>(note)] + "_helper";
  std::string helper = GetTestLibRoot() + "/" + helper_base;
  ExecTestHelper eth;
  eth.SetArgs({helper.c_str(), nullptr});
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0,
          kExpectedOutput[static_cast<int>(note)]);
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

INSTANTIATE_TEST_SUITE_P(, MemtagNoteTest,
                         testing::Combine(testing::Values(MemtagNote::NONE, MemtagNote::ASYNC,
                                                          MemtagNote::SYNC),
                                          testing::Bool()),
                         [](const ::testing::TestParamInfo<MemtagNoteTest::ParamType>& info) {
                           MemtagNote note = std::get<0>(info.param);
                           std::string s = kNoteSuffix[static_cast<int>(note)];
                           if (std::get<1>(info.param)) s += "_static";
                           return s;
                         });
```