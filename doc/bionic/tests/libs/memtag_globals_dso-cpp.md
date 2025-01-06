Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Context and Goal:**

The first step is to recognize the file path `bionic/tests/libs/memtag_globals_dso.cpp` and the description "bionic is Android's C library, math library, and dynamic linker."  This immediately tells us the code is a *test* for the bionic library, specifically related to memory tagging (memtag) and global variables within a dynamically shared object (DSO). The filename `memtag_globals_dso.cpp` is a strong hint.

The goal of the test is likely to verify that global variables in a DSO are tagged or untagged correctly according to their attributes and linker behavior.

**2. Initial Code Scan and Identification of Key Components:**

Next, I'd perform a quick scan of the code to identify the main parts:

* **Includes:** `<stdint.h>`, `<stdio.h>`, `<stdlib.h>`, `<vector>`, `"memtag_globals.h"` - These indicate basic C standard library functions, standard output, and a custom header (likely related to memtag definitions).
* **Global Variables:** `global_extern`, `global_extern_hidden`, `global_extern_untagged`, `global_extern_untagged_definition_but_tagged_import`. The `__attribute__((no_sanitize("memtag")))` is a crucial keyword indicating memtag behavior.
* **Assertion Functions:** `assertion_failure`, `check_tagged`, `check_untagged`, `check_matching_tags`, `check_eq`. These functions are clearly for validating conditions within the test. The names are self-explanatory.
* **Printing Functions:** `print_variable_address`, `dso_print_variables`, `print_variables`. These are for debugging and outputting information.
* **Getter Functions:** `get_expected_tagged_vars`, `get_expected_untagged_vars`. These define the *expected* state of the variables, which is then compared to the actual state.
* **Main Check Function:** `dso_check_assertions`. This is where the actual tagging checks happen.

**3. Focusing on Memtag-Specific Logic:**

The core of the test revolves around memory tagging. The `check_tagged` and `check_untagged` functions are central. Recognizing the `#if defined(__aarch64__)` block is important because memory tagging is primarily an ARM architecture feature. The shift operation `(a_uptr >> 56)` is the mechanism for extracting the memory tag (the top 8 bits in a 64-bit address).

* **`check_tagged`:** Verifies that the top 8 bits are *not* zero, indicating a tag is present.
* **`check_untagged`:** Verifies that the top 8 bits *are* zero, indicating no tag.
* **`check_matching_tags`:** Checks if two pointers have the same tag.

The `__attribute__((no_sanitize("memtag")))` is key. It tells the compiler to *not* apply memory tagging to these specific global variables.

**4. Analyzing Global Variable Declarations:**

* **`global_extern`:** A regular extern declaration. In the context of a DSO, it's likely to be tagged.
* **`global_extern_hidden`:**  `static` keyword makes it internal to the DSO. It's likely also tagged.
* **`global_extern_untagged`:**  Explicitly marked as untagged with `__attribute__((no_sanitize("memtag")))`.
* **`global_extern_untagged_definition_but_tagged_import`:** This is more complex. The name suggests it's defined in *this* DSO as untagged, but might be imported (used) in another DSO where it's treated as tagged. This tests inter-DSO linking behavior with memtag.

**5. Understanding the Test Flow:**

The `dso_check_assertions` function performs the core validation:

1. It first makes sure the non-constant global variables are writable (a basic sanity check).
2. If `check_pointers_are_tagged` is true (likely set by a caller from outside this DSO), it iterates through `get_expected_tagged_vars` and calls `check_tagged` on each pointer.
3. It iterates through `get_expected_untagged_vars` and calls `check_untagged` on each pointer.

The `dso_print_variables` function is for printing the addresses of the variables, useful for debugging.

**6. Relating to Android and Dynamic Linking:**

* **Android Bionic:**  The file is directly within bionic's test suite, so it's inherently related to Android's C library and dynamic linker.
* **Memory Tagging:** A security feature in newer ARM architectures, utilized by Android for detecting memory safety issues.
* **Dynamic Linker:** The test implicitly involves the dynamic linker because it's testing global variables in a DSO. The linker is responsible for resolving symbols and potentially applying tagging during the linking process.

**7. Inferring Functionality and Examples:**

Based on the code analysis, we can deduce the functionality: This code tests the memory tagging behavior of global variables defined within a dynamic shared object in Android. It verifies that variables are tagged or untagged as expected based on their attributes.

**8. Addressing the Prompt's Specific Questions:**

Now, systematically address each point in the prompt:

* **功能:** List the identified functionalities.
* **与 Android 的关系:** Explain the connection to bionic, memory tagging in Android, and the dynamic linker. Provide examples of how Android uses memory tagging (e.g., heap allocation tagging).
* **libc 函数功能:**  Explain the standard C library functions used (`stdint.h`, `stdio.h`, `stdlib.h`).
* **Dynamic Linker 功能:** Explain the role of the dynamic linker in symbol resolution and how it might interact with memory tagging. Create a sample SO layout and illustrate the linking process (symbol lookup, relocation, potential tagging).
* **逻辑推理 (Assumptions & Outputs):**  Illustrate the assertions with hypothetical addresses and tag values.
* **用户/编程错误:** Provide examples of common mistakes related to memory tagging or global variables.
* **Android Framework/NDK to this code:** Explain the path from an app/NDK to this kind of low-level DSO test (compilation, linking). Provide a Frida hook example targeting `check_tagged` or `check_untagged` to observe the tagging in action.

**9. Structuring the Answer:**

Organize the information logically with clear headings and explanations for each point in the prompt. Use code snippets where appropriate. Be detailed but also concise. Use Chinese as requested.

**Self-Correction/Refinement during the Process:**

* Initially, I might have overlooked the significance of `global_extern_untagged_definition_but_tagged_import`. Recognizing its purpose in testing inter-DSO linking is crucial.
* I need to ensure my explanation of dynamic linking is clear and accurate, including concepts like symbol tables and relocations.
* The Frida hook example should be practical and easy to understand.

By following these steps, the comprehensive and accurate answer provided in the initial example can be constructed. The key is to break down the code, understand its purpose within the larger Android ecosystem, and then systematically address each part of the prompt.
这个 C++ 文件 `memtag_globals_dso.cpp` 是 Android Bionic 库的一部分，专门用于测试**内存标签 (Memory Tagging)** 功能在动态共享对象 (DSO) 中对全局变量的影响。  Bionic 是 Android 的 C 库、数学库和动态链接器，因此这个测试直接关联着 Android 底层的内存管理和动态链接机制。

**功能列举:**

1. **声明不同类型的全局变量:**  文件中声明了多种具有不同属性的全局变量，用于测试内存标签的行为：
    * `global_extern`:  一个普通的外部全局变量。
    * `global_extern_hidden`: 一个静态（内部链接）的全局变量。
    * `global_extern_untagged`: 一个明确声明为不进行内存标签处理的外部全局变量。
    * `global_extern_untagged_definition_but_tagged_import`: 一个在本 DSO 中定义为不进行内存标签处理，但在其他 DSO 中可能被视为需要标签的外部全局变量。这用于测试跨 DSO 的链接行为。

2. **提供断言辅助函数:**  定义了一系列用于检查内存标签状态的辅助函数：
    * `assertion_failure()`:  当断言失败时调用，直接退出程序。
    * `check_tagged(const void* a)`:  检查给定指针 `a` 是否带有内存标签（高 8 位非零）。
    * `check_untagged(const void* a)`: 检查给定指针 `a` 是否没有内存标签（高 8 位为零）。
    * `check_matching_tags(const void* a, const void* b)`: 检查两个指针 `a` 和 `b` 是否具有相同的内存标签。
    * `check_eq(const void* a, const void* b)`: 检查两个指针是否相等。

3. **提供打印变量地址的函数:** `print_variable_address` 用于以格式化的方式打印变量的名称和地址，方便调试。

4. **定义预期标签状态的变量列表:**  `get_expected_tagged_vars` 和 `get_expected_untagged_vars` 函数分别返回预期带有和不带内存标签的全局变量列表。这用于与实际运行时的标签状态进行比较。

5. **提供打印变量信息的函数:** `print_variables` 函数接收带有标签和不带标签的变量列表，并格式化打印出来，用于输出测试结果。`dso_print_variables` 是一个便捷函数，用于打印当前 DSO 中定义的变量信息。

6. **执行断言检查:** `dso_check_assertions` 函数是测试的核心，它会执行以下操作：
    * 尝试写入所有非 `const` 的全局变量，以确保它们是可写的。
    * 根据 `check_pointers_are_tagged` 参数（通常由调用者传递），遍历预期带有标签的变量列表，并调用 `check_tagged` 进行断言。
    * 遍历预期不带标签的变量列表，并调用 `check_untagged` 进行断言。

**与 Android 功能的关系及举例说明:**

这个文件直接测试了 Android Bionic 的内存标签功能。内存标签是 ARMv8.5 架构引入的一种硬件特性，Android 利用它来提高内存安全性和检测内存错误，例如 use-after-free 和堆溢出。

**举例说明:**

* **堆分配的内存标签:** Android 的内存分配器 (如 jemalloc 或 scudo) 在分配堆内存时，会将内存地址的高 8 位设置为一个随机的标签。当代码尝试访问这块内存时，CPU 会检查访问指令中携带的标签是否与内存地址的标签匹配。如果不匹配，则会触发异常，从而及早发现内存错误。

* **全局变量的标签:** 这个测试文件关注的是全局变量的标签。根据链接器的配置和变量的属性，全局变量可能带有或不带标签。例如，默认情况下，Bionic 中的外部全局变量通常会被加上内存标签，以提供额外的保护。

* **`__attribute__((no_sanitize("memtag")))` 的作用:**  通过使用 `__attribute__((no_sanitize("memtag")))`，开发者可以显式地指示编译器或链接器不要对特定的全局变量应用内存标签。这在某些特定场景下可能是必要的，例如与不兼容内存标签的代码进行交互。

**详细解释每一个 libc 函数的功能是如何实现的:**

这里涉及到的 libc 函数主要是标准 C 库提供的基础功能，其实现细节比较复杂，通常由汇编代码和 C 代码混合实现。以下是简要说明：

* **`<stdint.h>`:**  定义了各种标准的整数类型，例如 `uintptr_t`。它的实现主要是在编译时根据目标架构定义相应的类型别名。

* **`<stdio.h>`:** 提供了标准输入输出功能，例如 `printf` 和 `fprintf`。
    * **`printf`:**  将格式化的输出发送到标准输出流。它的实现涉及解析格式字符串、获取可变参数、并调用底层的系统调用将数据写入文件描述符 1。
    * **`fprintf`:** 与 `printf` 类似，但允许指定输出流（例如，`stderr`）。它也需要解析格式字符串，并将输出写入指定的文件描述符。

* **`<stdlib.h>`:** 提供了一些通用工具函数，例如 `exit`。
    * **`exit`:**  终止程序的执行。它的实现通常会执行一些清理工作（例如，调用 `atexit` 注册的函数），然后调用底层的系统调用来终止进程。

* **`<vector>`:**  是 C++ 标准模板库 (STL) 中的一个容器，提供了动态数组的功能。它的实现涉及动态内存分配、内存管理、以及提供各种操作数组的方法 (如添加、删除元素)。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个测试文件直接关联着动态链接器的行为，因为它测试的是 DSO 中的全局变量。

**SO 布局样本:**

一个简单的 DSO（例如 `libmemtag_globals_dso.so`）的布局可能如下所示：

```
ELF Header
Program Headers
Section Headers

.text          # 代码段
   dso_print_variables
   dso_check_assertions
   check_tagged
   ...

.rodata        # 只读数据段
   字符串常量等

.data          # 已初始化的全局变量
   global_extern
   global_extern_hidden
   global_extern_untagged
   global_extern_untagged_definition_but_tagged_import

.bss           # 未初始化的全局变量

.symtab        # 符号表
   global_extern (GLOBAL, OBJECT, ...)
   global_extern_hidden (LOCAL, OBJECT, ...)
   global_extern_untagged (GLOBAL, OBJECT, ...)
   global_extern_untagged_definition_but_tagged_import (GLOBAL, OBJECT, ...)
   ...

.strtab        # 字符串表 (存储符号名称等)

.rela.dyn      # 动态重定位表 (用于在加载时修正地址)
   # 例如，如果其他 DSO 引用了 global_extern，这里会有相应的重定位条目

.rela.plt      # PLT (Procedure Linkage Table) 重定位表 (用于延迟绑定)
```

**链接的处理过程:**

1. **编译:**  编译器将 `memtag_globals_dso.cpp` 编译成目标文件 (`.o`)。此时，全局变量会被分配到相应的段（如 `.data` 或 `.bss`），符号信息会被记录在符号表中。

2. **链接:**  链接器将目标文件链接成共享对象 (`.so`)。
    * **符号解析:** 链接器会解析符号引用，确定每个符号的地址。对于 `global_extern` 这样的外部全局变量，如果它在其他 DSO 中被引用，链接器需要找到它的定义。
    * **重定位:** 由于共享对象在加载到内存的地址是不确定的，链接器需要生成重定位信息 (`.rela.dyn`)。当动态链接器加载 DSO 时，会根据这些信息修正代码和数据中的地址。
    * **内存标签处理:** 在支持内存标签的架构上，链接器会根据变量的属性和链接器的配置，决定是否为全局变量的地址添加内存标签。
        * 默认情况下，对于普通的外部全局变量，链接器通常会应用内存标签。
        * 使用 `__attribute__((no_sanitize("memtag")))` 修饰的变量，链接器会避免应用内存标签。
        * 对于 `static` 变量，其作用域限定在 DSO 内部，通常也会应用内存标签。

3. **动态加载:** 当 Android 系统加载一个使用 `libmemtag_globals_dso.so` 的应用时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载这个 DSO。
    * **加载到内存:** 动态链接器会将 DSO 的各个段加载到内存中的不同区域。
    * **执行重定位:**  动态链接器会根据 `.rela.dyn` 表中的信息，修改代码和数据中的地址，使其指向正确的内存位置。
    * **内存标签应用 (如果需要):** 动态链接器可能会进一步处理内存标签，确保全局变量的地址具有预期的标签状态。

**假设输入与输出 (逻辑推理):**

假设在 AArch64 架构上运行，并且启用了内存标签功能。

**假设输入:**

* `check_pointers_are_tagged` 参数为 `true`。

**预期输出:**

* `check_tagged(&global_extern)` 应该成功，因为 `global_extern` 是一个普通的外部全局变量，预计会被加上标签。
* `check_tagged(&global_extern_hidden)` 应该成功，因为 `global_extern_hidden` 是一个静态全局变量，预计也会被加上标签。
* `check_untagged(&global_extern_untagged)` 应该成功，因为使用了 `__attribute__((no_sanitize("memtag")))`，明确声明不加标签。
* `check_untagged(&global_extern_untagged_definition_but_tagged_import)` 应该成功，因为在本 DSO 中定义时明确声明不加标签。

**如果做了逻辑推理，请给出假设输入与输出:**

（见上文）

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **误解 `__attribute__((no_sanitize("memtag")))` 的作用域:**  开发者可能会错误地认为在一个 DSO 中使用 `no_sanitize("memtag")` 修饰的全局变量，在其他 DSO 中也一定没有标签。但实际上，如果其他 DSO 将这个变量视为需要标签的导入符号，那么在那个 DSO 中访问该变量时，仍然会进行标签检查。

2. **手动去除内存标签:**  在某些情况下，开发者可能会尝试通过位运算或其他方式手动去除指针上的内存标签。这种做法非常危险，可能导致内存安全漏洞，并且破坏内存标签机制的完整性。

   ```c++
   // 错误示例：手动去除标签
   uintptr_t untagged_ptr = reinterpret_cast<uintptr_t>(&global_extern) & ~0xff00000000000000;
   int* ptr = reinterpret_cast<int*>(untagged_ptr); // 这样做可能会导致崩溃
   *ptr = 10;
   ```

3. **在不支持内存标签的平台上编译带有内存标签相关的代码:**  如果在不支持内存标签的架构上编译使用了内存标签功能的代码，可能会导致编译错误或运行时错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 或 NDK 开发的应用不会直接调用到这个测试文件中的代码。这个文件是 Bionic 库的内部测试代码。但是，理解从应用到 Bionic 库的调用链有助于理解其工作原理。

1. **NDK 应用:** 如果是一个使用 NDK 开发的 C/C++ 应用：
   * **应用代码调用 libc 函数:** NDK 应用会调用标准的 C/C++ 库函数，例如 `malloc`, `free`, `printf` 等。这些函数的实现位于 Bionic 库中。
   * **动态链接:** 当应用启动时，Android 的动态链接器会将应用依赖的 Bionic 库（如 `libc.so`, `libm.so`, `libdl.so`) 加载到进程空间。
   * **libc 函数调用:**  应用调用的 libc 函数会直接跳转到 Bionic 库中对应的实现。例如，`malloc` 最终会调用 Bionic 的内存分配器。

2. **Android Framework 应用 (Java/Kotlin):**
   * **System Calls:** Android Framework 的应用通常通过 Java Native Interface (JNI) 与 Native 代码交互。许多 Framework 的底层操作最终会调用到 Linux 内核的系统调用。
   * **Bionic 作为系统库:** Bionic 库提供了许多系统调用的封装，以及更高级的 C 库函数。Framework 的 Native 组件（如 SurfaceFlinger, AudioFlinger 等）也依赖于 Bionic 库。

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 Hook 这个测试文件中的函数，观察内存标签的行为。假设你已经编译了包含这个测试的 Bionic 库，并且有一个可以运行它的测试程序。

**Frida Hook 脚本 (Python):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["/path/to/your/test/executable"]) # 替换为你的测试可执行文件路径
    session = device.attach(pid)
    script = session.create_script("""
        function untagPtr(ptr) {
            const mask = ptr.and(ptr.shrn(8).shl(8).not());
            return ptr.and(mask);
        }

        Interceptor.attach(Module.findExportByName(null, "check_tagged"), {
            onEnter: function(args) {
                const ptr = ptr(args[0]);
                const untaggedPtr = untagPtr(ptr);
                const tag = ptr.shr(56);
                send({
                    "function": "check_tagged",
                    "ptr": ptr.toString(),
                    "untaggedPtr": untaggedPtr.toString(),
                    "tag": tag.toString(16)
                });
            }
        });

        Interceptor.attach(Module.findExportByName(null, "check_untagged"), {
            onEnter: function(args) {
                const ptr = ptr(args[0]);
                const untaggedPtr = untagPtr(ptr);
                const tag = ptr.shr(56);
                send({
                    "function": "check_untagged",
                    "ptr": ptr.toString(),
                    "untaggedPtr": untaggedPtr.toString(),
                    "tag": tag.toString(16)
                });
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print("进程未找到，请确保测试程序正在运行。")
except Exception as e:
    print(e)
```

**使用步骤:**

1. **替换路径:** 将 `/path/to/your/test/executable` 替换为实际运行包含 `memtag_globals_dso.cpp` 代码的测试可执行文件的路径。
2. **运行 Frida 脚本:** 运行这个 Python 脚本。
3. **运行测试程序:** 确保你的测试程序在 Android 设备或模拟器上运行。

**Frida Hook 解释:**

* **`Interceptor.attach`:** 用于 Hook `check_tagged` 和 `check_untagged` 函数。
* **`onEnter`:**  在目标函数入口处执行的代码。
* **`args[0]`:** 获取 `check_tagged` 和 `check_untagged` 函数的第一个参数（即要检查的指针）。
* **`ptr()`:** 将参数转换为 Frida 的 NativePointer 对象。
* **`untagPtr()`:**  一个简单的 JavaScript 函数，用于去除指针上的内存标签（将高 8 位清零）。
* **`shr(56)`:**  右移 56 位，提取内存标签。
* **`send()`:**  将信息发送回 Frida 脚本。

**调试输出:**

当你运行测试程序时，Frida 脚本会拦截对 `check_tagged` 和 `check_untagged` 的调用，并打印出指针的值、去除标签后的值以及提取出的标签。通过观察这些输出，你可以验证全局变量是否被正确地加上或没有加上内存标签。

这个 Frida 示例提供了一种动态分析内存标签行为的方法，可以帮助你理解 Android 系统如何在运行时处理内存标签。

Prompt: 
```
这是目录为bionic/tests/libs/memtag_globals_dso.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "memtag_globals.h"

// Adapted from the LLD test suite: lld/test/ELF/Inputs/aarch64-memtag-globals.s

int global_extern;
static int global_extern_hidden;
__attribute__((no_sanitize("memtag"))) int global_extern_untagged;
__attribute__((no_sanitize("memtag"))) int global_extern_untagged_definition_but_tagged_import;

void assertion_failure() {
  exit(1);
}

void check_tagged(const void* a) {
  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
#if defined(__aarch64__)
  if ((a_uptr >> 56) == 0) {
    fprintf(stderr, "**********************************\n");
    fprintf(stderr, "Failed assertion:\n");
    fprintf(stderr, "  tag(0x%zx) != 0\n", a_uptr);
    fprintf(stderr, "**********************************\n");

    assertion_failure();
  }
#endif  // defined(__aarch64__)
}

void check_untagged(const void* a) {
  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
#if defined(__aarch64__)
  if ((a_uptr >> 56) != 0) {
    fprintf(stderr, "**********************************\n");
    fprintf(stderr, "Failed assertion:\n");
    fprintf(stderr, "  tag(0x%zx) == 0\n", a_uptr);
    fprintf(stderr, "**********************************\n");

    assertion_failure();
  }
#endif  // defined(__aarch64__)
}

void check_matching_tags(const void* a, const void* b) {
  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
  uintptr_t b_uptr = reinterpret_cast<uintptr_t>(b);
#if defined(__aarch64__)
  if (a_uptr >> 56 != b_uptr >> 56) {
    fprintf(stderr, "**********************************\n");
    fprintf(stderr, "Failed assertion:\n");
    fprintf(stderr, "  tag(0x%zx) != tag(0x%zx)\n", a_uptr, b_uptr);
    fprintf(stderr, "**********************************\n");

    assertion_failure();
  }
#endif  // defined(__aarch64__)
}

void check_eq(const void* a, const void* b) {
  if (a != b) {
    fprintf(stderr, "**********************************\n");
    fprintf(stderr, "Failed assertion:\n");
    fprintf(stderr, "  %p != %p\n", a, b);
    fprintf(stderr, "**********************************\n");

    assertion_failure();
  }
}

#define LONGEST_VARIABLE_NAME "51"
void print_variable_address(const char* name, const void* ptr) {
  printf("%" LONGEST_VARIABLE_NAME "s: %16p\n", name, ptr);
}

static const std::vector<std::pair<const char*, const void*>>& get_expected_tagged_vars() {
  static std::vector<std::pair<const char*, const void*>> expected_tagged_vars = {
      {"global_extern", &global_extern},
      {"global_extern_hidden", &global_extern_hidden},
  };
  return expected_tagged_vars;
}

static const std::vector<std::pair<const char*, const void*>>& get_expected_untagged_vars() {
  static std::vector<std::pair<const char*, const void*>> expected_untagged_vars = {
      {"global_extern_untagged", &global_extern_untagged},
      {"global_extern_untagged_definition_but_tagged_import",
       &global_extern_untagged_definition_but_tagged_import},
  };
  return expected_untagged_vars;
}

void dso_print_variables() {
  print_variables("  Variables declared in the DSO:\n", get_expected_tagged_vars(),
                  get_expected_untagged_vars());
}

void print_variables(const char* header,
                     const std::vector<std::pair<const char*, const void*>>& tagged_variables,
                     const std::vector<std::pair<const char*, const void*>>& untagged_variables) {
  printf("==========================================================\n");
  printf("%s", header);
  printf("==========================================================\n");
  printf(" Variables expected to be tagged:\n");
  printf("----------------------------------------------------------\n");
  for (const auto& [name, pointer] : tagged_variables) {
    print_variable_address(name, pointer);
  }

  printf("\n----------------------------------------------------------\n");
  printf(" Variables expected to be untagged:\n");
  printf("----------------------------------------------------------\n");
  for (const auto& [name, pointer] : untagged_variables) {
    print_variable_address(name, pointer);
  }
  printf("\n");
}

void dso_check_assertions(bool check_pointers_are_tagged) {
  // Check that non-const variables are writeable.
  global_extern = 0;
  global_extern_hidden = 0;
  global_extern_untagged = 0;
  global_extern_untagged_definition_but_tagged_import = 0;

  if (check_pointers_are_tagged) {
    for (const auto& [_, pointer] : get_expected_tagged_vars()) {
      check_tagged(pointer);
    }
  }

  for (const auto& [_, pointer] : get_expected_untagged_vars()) {
    check_untagged(pointer);
  }
}

"""

```