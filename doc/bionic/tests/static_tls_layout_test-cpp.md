Response:
Let's break down the thought process to arrive at the comprehensive explanation of the C++ code.

1. **Understand the Goal:** The request asks for a detailed analysis of a C++ source file within the Android Bionic library, specifically focusing on its functionality, relationship to Android, libc function implementations (if any), dynamic linker aspects, potential errors, and its place in the Android framework/NDK.

2. **Initial File Examination:**  The first step is to read the code and understand its overall purpose. The `#define STATIC_TLS_LAYOUT_TEST` suggests this is a test file. The inclusion of `private/bionic_elf_tls.h` and `private/bionic_tls.h` strongly indicates the code is related to Thread Local Storage (TLS) layout within Bionic. The use of `gtest` confirms its testing nature.

3. **Identify Key Components:**  Look for the major building blocks of the code:
    * **`AlignedSizeFlat` struct:** This seems to represent a flattened structure for size, alignment, and skew.
    * **`unflatten_size` function:** This converts the flattened structure into a `TlsAlignedSize` structure, likely a more comprehensive representation of TLS alignment information used internally.
    * **`reserve_tp_pair` test:** This is the core functionality being tested. It appears to simulate the allocation of space for a thread pointer (TP) and surrounding memory regions (before and after the TP).
    * **`static_tls_layout` test suite (and specifically the `arm` test):** This tests the reservation of TLS space for an executable segment, considering alignment constraints related to ARM and ARM64 architectures.
    * **Helper functions/macros:**  `operator""_words`, `SilentDeathTest`, `EXPECT_EQ`, `EXPECT_DEATH`, `GTEST_SKIP`. These are part of the testing framework and utility functions.

4. **Deconstruct `reserve_tp_pair` Test:**  Analyze the different test cases within `reserve_tp_pair`:
    * **Simple Case:**  Basic allocation with defined sizes and alignment.
    * **Zero-sized `before` and `after`:**  Edge cases where one or both surrounding regions have zero size.
    * **`before` shifted forward:**  Demonstrates how the `before` allocation might be placed after the start of the layout to accommodate alignment.
    * **Alignment gaps:**  Shows how padding is added to meet alignment requirements.
    * **Skew-aligned `before` and `after`:** Tests how offsets within the alignment boundaries are handled.
    * **Preceding byte:**  Verifies that existing allocations in the layout are respected.

5. **Deconstruct `arm` Test:** Focus on the executable segment reservation:
    * **`reserve_exe` lambda:** Simulates reserving space for an executable's TLS segment.
    * **`underalign_error` lambda:**  Defines the expected error message for underalignment.
    * **`base8` and `base16`:**  Calculate the base offsets for negative TLS slots based on 8-word and 16-word alignment, respectively. This is crucial for understanding Android's TLS layout.
    * **Test cases:** Cover various scenarios, including basic allocation, underalignment errors, and different skew values with different alignments.

6. **Relate to Android Functionality:** Connect the concepts in the code to how TLS works in Android.
    * **Thread Local Storage (TLS):** Explain what TLS is and why it's needed.
    * **Bionic's Role:** Highlight that Bionic manages TLS for Android processes.
    * **Dynamic Linker's Involvement:** Explain how the dynamic linker allocates and initializes TLS blocks for shared libraries.
    * **`__thread` keyword:** Mention the C++ keyword for declaring thread-local variables.
    * **Negative TLS offsets:** Explain the concept of negative offsets for Bionic's internal TLS data.
    * **ARM/ARM64 Alignment:**  Emphasize the stricter alignment requirements on ARM architectures.

7. **Address Specific Questions:** Go through each point in the original request:
    * **Functionality:** Summarize the code's purpose (testing static TLS layout calculations).
    * **Relationship to Android:** Explain the connection to Bionic's TLS management.
    * **libc Function Implementations:** Note that this specific file doesn't *implement* libc functions but *tests* a low-level aspect of Bionic.
    * **Dynamic Linker:** Explain the dynamic linker's role in TLS allocation, provide a sample SO layout, and describe the linking process (even though this file doesn't directly demonstrate the linking *process*, the concepts are relevant).
    * **Logic Reasoning (Assumptions/Outputs):**  Use the test cases as examples of input and expected output.
    * **Common User/Programming Errors:**  Focus on alignment issues and potential crashes.
    * **Android Framework/NDK Path:** Describe the journey from application code to the dynamic linker and finally to Bionic's TLS management.

8. **Provide Frida Hook Examples:**  Think about how to inspect TLS-related data at runtime using Frida. Focus on accessing the thread pointer and potentially thread-local variables.

9. **Structure and Refine:** Organize the information logically with clear headings and subheadings. Use precise terminology. Ensure the language is clear and understandable. Review and refine the explanation for accuracy and completeness. For instance, initially, I might have focused too much on the `gtest` framework itself, but the request is more about the *Bionic TLS* aspect. Refocusing the explanation is key.

10. **Self-Correction/Double-Checking:** Review the code again and the generated explanation to make sure they align. Are there any discrepancies or missing pieces?  For example, ensure the alignment values and skew concepts are correctly explained. Make sure the explanation of the dynamic linker's role is accurate, even though this specific test file doesn't directly *execute* the linker. The *concepts* are being tested here.
好的，我们来详细分析一下 `bionic/tests/static_tls_layout_test.cpp` 这个文件。

**功能概要**

这个 C++ 源文件是 Android Bionic 库中的一个测试文件，其主要功能是**测试静态线程本地存储 (Thread-Local Storage, TLS) 的布局计算逻辑**。  更具体地说，它测试了 `StaticTlsLayout` 类中用于计算 TLS 区域大小、对齐方式和偏移量的功能。

**与 Android 功能的关系及举例说明**

TLS 是一个重要的操作系统特性，它允许每个线程拥有自己独立的变量副本。这在多线程编程中非常有用，可以避免竞态条件，并提高代码的可重入性。

在 Android 中，Bionic 作为底层的 C 库，负责管理进程和线程的创建和管理，自然也包括了 TLS 的管理。`static_tls_layout_test.cpp` 中测试的 `StaticTlsLayout` 类是 Bionic 内部用于计算和规划静态 TLS 区域布局的关键组件。

**举例说明：**

当一个 Android 应用（通过 Java 或 NDK）使用 `__thread` 关键字声明一个线程局部变量时，Bionic 的动态链接器 (linker) 需要在加载共享库时为每个线程分配一块独立的内存区域来存储这个变量。`StaticTlsLayout` 类就负责计算这块内存区域的大小、起始地址等信息。

例如，如果你的 NDK 代码中有以下声明：

```c++
__thread int my_thread_local_var = 0;
```

当包含这段代码的共享库被加载到 Android 进程中时，动态链接器会使用 `StaticTlsLayout` 计算出 `my_thread_local_var` 在每个线程的 TLS 区域中的偏移量。这样，不同的线程访问 `my_thread_local_var` 时，实际上访问的是各自 TLS 区域中的不同内存地址。

**详细解释每一个 libc 函数的功能是如何实现的**

这个测试文件本身**并没有直接调用或实现任何标准的 libc 函数**。它主要关注的是 Bionic 内部的 TLS 布局计算逻辑，这些逻辑是在 Bionic 库自身中实现的，而不是直接调用如 `malloc` 或 `pthread_create` 这样的 libc 函数。

不过，这个测试文件间接地涉及到 TLS 的实现，而 TLS 的实现通常会依赖一些底层的系统调用和 libc 函数，例如：

* **`pthread_key_create` 和 `pthread_getspecific`/`pthread_setspecific`:** 这些是 POSIX 线程 API 中用于管理线程特定数据的函数。虽然 `StaticTlsLayout` 主要关注静态 TLS，但动态 TLS 的实现会用到这些函数。
* **系统调用 (syscalls):**  线程的创建和管理，以及底层 TLS 区域的分配，最终会涉及到系统调用，例如 `clone` (用于创建线程)。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

`StaticTlsLayout` 类与动态链接器紧密相关。当动态链接器加载一个包含 TLS 变量的共享库 (`.so`) 时，它需要确定该库的 TLS 块在进程的 TLS 区域中的位置和大小。

**SO 布局样本 (简化)**

假设有一个名为 `libexample.so` 的共享库，其中定义了一个 `__thread` 变量：

```c++
// libexample.cpp
__thread int my_lib_var = 100;
```

当 `libexample.so` 被加载时，其 TLS 布局可能如下所示（这只是一个简化的例子，实际布局会更复杂）：

```
+----------------------+  <-- 进程 TLS 区域起始地址 (每个线程都有一个)
| Bionic 内部 TLS 数据  |  <-- 由 Bionic C 库自身使用的 TLS 数据
+----------------------+
| libdl.so TLS 数据    |  <-- 动态链接器自身的 TLS 数据
+----------------------+
| libexample.so TLS 数据 |  <-- 包含 my_lib_var
|  my_lib_var (int)    |
+----------------------+
| ... 其他共享库的 TLS 数据 ... |
+----------------------+
```

**链接的处理过程 (简化)**

1. **解析 ELF 文件:** 动态链接器会解析 `libexample.so` 的 ELF 文件头，查找与 TLS 相关的段 (segment) 和节 (section)，例如 `.tdata` (已初始化 TLS 数据) 和 `.tbss` (未初始化 TLS 数据)。

2. **计算 TLS 块大小和对齐:** 动态链接器会读取 `.tdata` 和 `.tbss` 段的大小和对齐要求。`StaticTlsLayout` 类（或类似功能的组件）会被用来计算 `libexample.so` 需要的 TLS 块的总大小和对齐方式。

3. **分配 TLS 空间:** 动态链接器会在进程的 TLS 区域中为 `libexample.so` 分配一块足够大的内存空间，并确保满足对齐要求。

4. **初始化 TLS 数据:** 对于 `.tdata` 段，动态链接器会将数据从 SO 文件中复制到新分配的 TLS 块中。`.tbss` 段会被清零。

5. **更新 TLS 偏移量:** 动态链接器会维护一个全局的 TLS 描述符表 (TLS descriptor table)，用于记录每个已加载共享库的 TLS 块信息，包括其在进程 TLS 区域中的偏移量。

6. **访问 TLS 变量:** 当程序代码访问 `my_lib_var` 时，编译器会生成特殊的指令，这些指令会利用当前线程的 TLS 寄存器（例如 x8 寄存器在 ARM64 上）加上 `my_lib_var` 的偏移量来访问正确的内存位置。这个偏移量是在链接时由动态链接器确定的。

**如果做了逻辑推理，请给出假设输入与输出**

`reserve_tp_pair` 测试函数就包含了逻辑推理。例如：

**假设输入：**

* `before`：`{.size = 8, .align = 2}` (需要 8 字节，2 字节对齐)
* `after`： `{.size = 16, .align = 2}` (需要 16 字节，2 字节对齐)

**预期输出：**

* `allocs.before`: `0u` (before 区域的起始偏移量)
* `allocs.tp`: `8u` (线程指针位置的偏移量)
* `allocs.after`: `8u` (after 区域相对于线程指针的偏移量)
* `layout.size()`: `24u` (总共分配的 TLS 空间大小)
* `layout.align_`: `2u` (整体布局的对齐方式)

**逻辑推理过程：**

1. 先分配 `before` 区域，起始偏移量为 0，占用 8 字节。
2. 线程指针 (TP) 紧随 `before` 区域之后，偏移量为 8。
3. `after` 区域相对于 TP 的偏移量为 0，因此其在整个布局中的起始偏移量也是 8。
4. `after` 区域占用 16 字节，所以总大小为 8 (before) + 16 (after) = 24 字节。
5. 最大的对齐要求是 2 字节，所以整体布局的对齐方式为 2。

另一个更复杂的例子，涉及到对齐调整：

**假设输入：**

* `before`：`{.size = 9, .align = 4}`
* `after`： `{.size = 1}`

**预期输出：**

* `allocs.before`: `0u`
* `allocs.tp`: `12u` (为了满足 `before` 的对齐要求，TP 需要向前移动)
* `allocs.after`: `12u`
* `layout.size()`: `13u`
* `layout.align_`: `4u`

**逻辑推理过程：**

1. `before` 区域需要 9 字节，4 字节对齐，从偏移量 0 开始。
2. 线程指针需要紧随 `before` 区域之后，并且要满足 `before` 的对齐要求。由于 `before` 的大小是 9 字节，下一个 4 字节对齐的位置是 12。所以 `tp` 的偏移量是 12。
3. `after` 区域相对于 TP 的偏移量为 0，所以其在整个布局中的偏移量也是 12。
4. 总大小为 12 (tp 偏移量) + 1 (after 大小) = 13 字节。
5. 最大的对齐要求是 4 字节。

**如果涉及用户或者编程常见的使用错误，请举例说明**

虽然这个测试文件本身不涉及用户代码，但它测试的 TLS 布局逻辑与用户可能遇到的 TLS 相关错误密切相关：

1. **未正确处理 TLS 变量的初始化顺序：**  静态 TLS 变量的初始化顺序可能很复杂，尤其是在涉及多个共享库时。如果代码依赖于特定的初始化顺序，可能会导致难以调试的错误。

2. **在不恰当的时机访问 TLS 变量：**  例如，在线程创建之前或线程销毁之后访问线程局部变量可能导致崩溃或未定义的行为。

3. **TLS 变量的过度使用：**  过多的 TLS 变量会增加内存消耗，尤其是在有大量线程的应用程序中。

4. **与动态 TLS (使用 `pthread_key_create` 等) 混淆：**  静态 TLS 和动态 TLS 是不同的机制，需要理解它们的区别和适用场景。

5. **在不支持 TLS 的平台上使用 TLS 变量：** 虽然现在大部分平台都支持 TLS，但在一些嵌入式或旧版本的系统中可能不支持，这会导致编译或链接错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

从 Android Framework 或 NDK 代码到达 Bionic 的 TLS 布局计算，通常经过以下步骤：

1. **NDK 代码使用 `__thread` 关键字:**  开发者在 C/C++ NDK 代码中使用 `__thread` 声明线程局部变量。

2. **编译和链接:** NDK 编译器 (Clang) 会识别 `__thread` 关键字，并在生成的 ELF 目标文件中标记这些变量。链接器 (lld) 在链接生成共享库或可执行文件时，会收集所有 TLS 变量的信息。

3. **应用程序启动和共享库加载:** 当 Android 应用程序启动时，`zygote` 进程会 fork 出新的应用进程。动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库。

4. **动态链接器处理 TLS:** 当动态链接器加载包含 TLS 变量的共享库时，它会执行以下操作：
   * 解析 ELF 文件，查找 TLS 相关的段 (`.tdata`, `.tbss`)。
   * 调用 Bionic 库中的函数（这些函数内部会使用 `StaticTlsLayout` 或类似机制）来计算该共享库的 TLS 块大小、对齐方式和在进程 TLS 区域中的偏移量。
   * 在每个线程的 TLS 区域中分配空间。
   * 初始化 TLS 数据。

5. **访问 TLS 变量:** 当应用程序线程执行到访问 `__thread` 变量的代码时，编译器生成的指令会利用当前线程的 TLS 寄存器和预先计算好的偏移量来访问正确的内存位置。

**Frida Hook 示例**

可以使用 Frida 来 hook 动态链接器中与 TLS 布局相关的函数，以观察其执行过程和参数。以下是一个示例，用于 hook `android_dlopen_ext` 函数（这是动态链接器中加载共享库的关键函数），并尝试访问与 TLS 相关的内部结构：

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        console.log("[+] android_dlopen_ext called with filename: " + filename);
    },
    onLeave: function(retval) {
        if (retval != 0) {
            console.log("[+] android_dlopen_ext returned: " + retval);
            // 这里可以尝试访问与 TLS 相关的结构，但需要对动态链接器的内部实现有深入了解
            // 例如，可以尝试读取 linker 的一些全局变量或结构体成员
            // 这部分代码会非常依赖于 Android 版本和架构
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**更精细的 Hook (需要更多 linker 内部知识)**

要更精确地调试 TLS 布局过程，可能需要 hook 动态链接器中负责处理 TLS 的特定函数，例如：

* **`_ZN3artLldb6soinfo19allocate_tls_regionEv` (Art 运行时):** 在 Art 运行时中，这个函数负责为共享库分配 TLS 区域。
* **与 `StaticTlsLayout` 类相关的方法:** 如果你知道 `StaticTlsLayout` 类在动态链接器中的使用方式，可以直接 hook 它的方法。

**注意：**  直接 hook 动态链接器的内部函数需要对 Android 的内部实现有深入的了解，并且这些实现可能会在不同的 Android 版本和架构上有所变化。

希望这个详细的解释能够帮助你理解 `bionic/tests/static_tls_layout_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/static_tls_layout_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#define STATIC_TLS_LAYOUT_TEST

#include "private/bionic_elf_tls.h"

#include <string>
#include <tuple>

#include <gtest/gtest.h>

#include <android-base/silent_death_test.h>

#include "private/bionic_tls.h"

using namespace std::string_literals;

struct AlignedSizeFlat {
  size_t size = 0;
  size_t align = 1;
  size_t skew = 0;
};

static TlsAlignedSize unflatten_size(AlignedSizeFlat flat) {
  return TlsAlignedSize{.size = flat.size,
                        .align = TlsAlign{
                            .value = flat.align,
                            .skew = flat.skew,
                        }};
}

TEST(static_tls_layout, reserve_tp_pair) {
  auto reserve_tp = [](const AlignedSizeFlat& before, const AlignedSizeFlat& after,
                       StaticTlsLayout layout = {}) {
    auto allocs = layout.reserve_tp_pair(unflatten_size(before), unflatten_size(after));
    return std::make_tuple(layout, allocs);
  };

  StaticTlsLayout layout;
  StaticTlsLayout::TpAllocations allocs;

  // Simple case.
  std::tie(layout, allocs) = reserve_tp({.size = 8, .align = 2}, {.size = 16, .align = 2});
  EXPECT_EQ(0u, allocs.before);
  EXPECT_EQ(8u, allocs.tp);
  EXPECT_EQ(8u, allocs.after);
  EXPECT_EQ(24u, layout.size());
  EXPECT_EQ(2u, layout.align_);

  // Zero-sized `before`
  std::tie(layout, allocs) = reserve_tp({.size = 0}, {.size = 64, .align = 8});
  EXPECT_EQ(0u, allocs.before);
  EXPECT_EQ(0u, allocs.tp);
  EXPECT_EQ(0u, allocs.after);

  // Zero-sized `after`
  std::tie(layout, allocs) = reserve_tp({.size = 64, .align = 8}, {.size = 0});
  EXPECT_EQ(0u, allocs.before);
  EXPECT_EQ(64u, allocs.tp);
  EXPECT_EQ(64u, allocs.after);

  // The `before` allocation is shifted forward to the TP.
  std::tie(layout, allocs) = reserve_tp({.size = 1}, {.size = 64, .align = 8});
  EXPECT_EQ(7u, allocs.before);
  EXPECT_EQ(8u, allocs.tp);
  EXPECT_EQ(8u, allocs.after);

  // Alignment gap between `before` and TP.
  std::tie(layout, allocs) = reserve_tp({.size = 9, .align = 4}, {.size = 1});
  EXPECT_EQ(0u, allocs.before);
  EXPECT_EQ(12u, allocs.tp);
  EXPECT_EQ(12u, allocs.after);
  EXPECT_EQ(13u, layout.size());
  EXPECT_EQ(4u, layout.align_);

  // Alignment gap between `before` and TP.
  std::tie(layout, allocs) = reserve_tp({.size = 9, .align = 4}, {.size = 128, .align = 64});
  EXPECT_EQ(52u, allocs.before);
  EXPECT_EQ(64u, allocs.tp);
  EXPECT_EQ(64u, allocs.after);
  EXPECT_EQ(192u, layout.size());
  EXPECT_EQ(64u, layout.align_);

  // Skew-aligned `before` with low alignment.
  std::tie(layout, allocs) =
      reserve_tp({.size = 1, .align = 4, .skew = 1}, {.size = 64, .align = 8});
  EXPECT_EQ(5u, allocs.before);
  EXPECT_EQ(8u, allocs.tp);

  // Skew-aligned `before` with high alignment.
  std::tie(layout, allocs) = reserve_tp({.size = 48, .align = 64, .skew = 17}, {.size = 1});
  EXPECT_EQ(17u, allocs.before);
  EXPECT_EQ(128u, allocs.tp);

  // An unrelated byte precedes the pair in the layout. Make sure `before` is
  // still aligned.
  layout = {};
  layout.reserve_type<char>();
  std::tie(layout, allocs) = reserve_tp({.size = 12, .align = 16}, {.size = 1}, layout);
  EXPECT_EQ(16u, allocs.before);
  EXPECT_EQ(32u, allocs.tp);

  // Skew-aligned `after`.
  std::tie(layout, allocs) =
      reserve_tp({.size = 32, .align = 8}, {.size = 16, .align = 4, .skew = 3});
  EXPECT_EQ(0u, allocs.before);
  EXPECT_EQ(32u, allocs.tp);
  EXPECT_EQ(35u, allocs.after);
  EXPECT_EQ(51u, layout.size());
}

// A "NUM_words" literal is the size in bytes of NUM words of memory.
static size_t operator""_words(unsigned long long i) {
  return i * sizeof(void*);
}

using static_tls_layout_DeathTest = SilentDeathTest;

TEST_F(static_tls_layout_DeathTest, arm) {
#if !defined(__arm__) && !defined(__aarch64__)
  GTEST_SKIP() << "test only applies to arm32/arm64 targets";
#endif

  auto reserve_exe = [](const AlignedSizeFlat& config) {
    StaticTlsLayout layout;
    TlsSegment seg = {.aligned_size = unflatten_size(config)};
    layout.reserve_exe_segment_and_tcb(&seg, "prog");
    return layout;
  };

  auto underalign_error = [](size_t align, size_t offset) {
    return R"(error: "prog": executable's TLS segment is underaligned: )"s
           R"(alignment is )"s +
           std::to_string(align) + R"( \(skew )" + std::to_string(offset) +
           R"(\), needs to be at least (32 for ARM|64 for ARM64) Bionic)"s;
  };

  // Amount of memory needed for negative TLS slots, given a segment p_align of
  // 8 or 16 words.
  const size_t base8 = __BIONIC_ALIGN(-MIN_TLS_SLOT, 8) * sizeof(void*);
  const size_t base16 = __BIONIC_ALIGN(-MIN_TLS_SLOT, 16) * sizeof(void*);

  StaticTlsLayout layout;

  // An executable with a single word.
  layout = reserve_exe({.size = 1_words, .align = 8_words});
  EXPECT_EQ(base8 + MIN_TLS_SLOT * sizeof(void*), layout.offset_bionic_tcb());
  EXPECT_EQ(base8, layout.offset_thread_pointer());
  EXPECT_EQ(base8 + 8_words, layout.offset_exe());
  EXPECT_EQ(base8 + 9_words, layout.size());
  EXPECT_EQ(8_words, layout.align_);

  // Simple underalignment case.
  EXPECT_DEATH(reserve_exe({.size = 1_words, .align = 1_words}), underalign_error(1_words, 0));

  // Skewed by 1 word is OK.
  layout = reserve_exe({.size = 1_words, .align = 8_words, .skew = 1_words});
  EXPECT_EQ(base8, layout.offset_thread_pointer());
  EXPECT_EQ(base8 + 9_words, layout.offset_exe());
  EXPECT_EQ(base8 + 10_words, layout.size());
  EXPECT_EQ(8_words, layout.align_);

  // Skewed by 2 words would overlap Bionic slots, regardless of the p_align
  // value.
  EXPECT_DEATH(reserve_exe({.size = 1_words, .align = 8_words, .skew = 2_words}),
               underalign_error(8_words, 2_words));
  EXPECT_DEATH(reserve_exe({.size = 1_words, .align = 0x1000, .skew = 2_words}),
               underalign_error(0x1000, 2_words));

  // Skewed by 8 words is OK again.
  layout = reserve_exe({.size = 1_words, .align = 16_words, .skew = 8_words});
  EXPECT_EQ(base16, layout.offset_thread_pointer());
  EXPECT_EQ(base16 + 8_words, layout.offset_exe());
  EXPECT_EQ(base16 + 9_words, layout.size());
  EXPECT_EQ(16_words, layout.align_);

  // Skewed by 9 words is also OK. (The amount of skew doesn't need to be a
  // multiple of anything.)
  layout = reserve_exe({.size = 1_words, .align = 16_words, .skew = 9_words});
  EXPECT_EQ(base16, layout.offset_thread_pointer());
  EXPECT_EQ(base16 + 9_words, layout.offset_exe());
  EXPECT_EQ(base16 + 10_words, layout.size());
  EXPECT_EQ(16_words, layout.align_);

  // Skew with large alignment.
  layout = reserve_exe({.size = 1_words, .align = 256_words, .skew = 8_words});
  EXPECT_EQ(256_words, layout.offset_thread_pointer());
  EXPECT_EQ(264_words, layout.offset_exe());
  EXPECT_EQ(265_words, layout.size());
  EXPECT_EQ(256_words, layout.align_);
}
```