Response:
Let's break down the thought process to answer the user's request about `bionic/tests/cfi_test.cpp`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the `cfi_test.cpp` file within the Android Bionic library. This includes:

* **Functionality:** What does this test file do?
* **Android Relevance:** How does it relate to Android's features?
* **`libc` Function Details:**  Explanation of the `libc` functions used.
* **Dynamic Linker Aspects:** How does it interact with the dynamic linker, including SO layout and linking.
* **Logic/Assumptions:** If there's logic, what are the inputs and outputs?
* **Common Errors:** What mistakes could developers make related to this?
* **Android Framework/NDK Path:** How does one reach this code from higher levels?
* **Frida Hooking:**  Examples of using Frida for debugging.

**2. Initial Code Scan and Interpretation:**

First, I'd quickly scan the code to get a general idea:

* **Includes:** `dlfcn.h`, `sys/stat.h`, `vector`, `gtest/gtest.h`, custom headers (`gtest_globals.h`, `utils.h`), and a Bionic-specific header (`private/CFIShadow.h`). This immediately suggests it's a testing file related to dynamic linking and potentially CFI (Control Flow Integrity).
* **External "C" Block:** The presence of `__cfi_slowpath`, `__cfi_slowpath_diag`, and `__cfi_shadow_size` strongly indicates this file is directly testing CFI mechanisms. The `extern "C"` implies these are functions implemented elsewhere in Bionic, likely at a very low level.
* **`cfi_test_DeathTest` Class:**  This signals the use of "death tests" in Google Test, meaning the tests are designed to verify that the code behaves correctly when a crash or specific signal is expected. The signal handling (SIGILL, SIGSEGV, SIGTRAP) further reinforces the low-level, potentially error-inducing nature of the tested functionality.
* **`TEST_F(cfi_test_DeathTest, basic)`:** This test case seems to be the most substantial. It involves `dlopen`, `dlsym`, and calls to the `__cfi_slowpath` functions. It also re-opens the same library, suggesting a test for handling multiple loads.
* **`TEST(cfi_test, invalid)`:**  This likely checks how the system handles loading a library known to be invalid.
* **`TEST(cfi_test, early_init)` and `TEST(cfi_test, early_init2)`:** These tests involve executing helper executables, suggesting they're testing initialization behavior, potentially related to when CFI is set up.

**3. Detailed Analysis and Answering Each Point:**

Now, I'd go through each of the user's points systematically:

* **功能 (Functionality):** The tests are clearly designed to verify the correct operation of Bionic's Control Flow Integrity (CFI) implementation. This involves checking how CFI detects invalid indirect function calls.

* **与 Android 的关系 (Relationship with Android):** CFI is a crucial security feature in Android. It helps mitigate certain types of code injection attacks. I'd provide examples like preventing ROP/JOP attacks.

* **libc 函数 (libc Functions):** I'd explain `dlopen` (dynamic library loading), `dlsym` (finding symbols within a loaded library), and potentially `dlerror` (getting error information). I would detail *how* these are likely implemented at a lower level (interacting with the linker, file system, memory management).

* **Dynamic Linker 功能 (Dynamic Linker Features):** This is central. I'd focus on:
    * **SO Layout:**  Describe a typical SO layout with sections like `.text`, `.data`, `.bss`, and importantly, how CFI shadow memory might be arranged (potentially alongside the `.text` section or in a dedicated area).
    * **Linking Process:** Explain the steps involved in dynamic linking (symbol resolution, relocation) and *how CFI information is likely incorporated* during this process (perhaps the linker calculates and stores CFI metadata).
    * **`__cfi_slowpath`:** Emphasize that this function is a key part of the dynamic linker's CFI enforcement.

* **逻辑推理 (Logic/Inference):** The `basic` test has clear logic. I'd lay out the steps, the expected outcomes of calling `__cfi_slowpath` with valid and potentially invalid addresses, and what the counters (`get_count`, `get_last_type_id`, etc.) should reflect.

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Focus on mistakes related to function pointers, incorrect casting, and how CFI would detect these errors (leading to crashes or the `__cfi_slowpath` being called).

* **Android Framework/NDK 路径 (Android Framework/NDK Path):**  This requires tracing the call stack. Start with a high-level action (e.g., NDK call to a function using a virtual method or function pointer) and explain how it eventually reaches the Bionic dynamic linker and the CFI checks.

* **Frida Hook 示例 (Frida Hook Example):** Provide practical Frida snippets to intercept calls to `__cfi_slowpath` and related functions, allowing developers to observe CFI in action.

**4. Structuring the Answer and Language:**

* **Use Clear Headings:** Organize the answer with headings for each of the user's points.
* **Provide Concrete Examples:**  Instead of just stating facts, illustrate them with code snippets or scenarios.
* **Explain Technical Terms:** Define concepts like CFI, ROP, JOP, and dynamic linking clearly.
* **Maintain Accuracy:** Ensure the technical details are correct. If uncertain, admit limitations or make educated guesses with caveats.
* **Use Chinese:**  Adhere to the user's request for the response to be in Chinese.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focus heavily on the `dlopen`/`dlsym` part.
* **Correction:** Realize the core of the test is about *CFI*. Shift the emphasis to explaining CFI and how these functions are used to *test* CFI.
* **Initial thought:**  Describe the SO layout in general terms.
* **Refinement:** Focus on *how CFI metadata might be integrated* into the SO layout.
* **Initial thought:**  Give a generic Frida example.
* **Refinement:** Tailor the Frida example to specifically target the CFI functions being tested.

By following this structured approach, combining code analysis with knowledge of Android internals and dynamic linking, and iteratively refining the explanation, I can generate a comprehensive and accurate answer to the user's request.
好的，让我们一起深入分析 `bionic/tests/cfi_test.cpp` 这个文件。

**功能概要**

`bionic/tests/cfi_test.cpp` 的主要功能是 **测试 Android Bionic 库中控制流完整性 (Control Flow Integrity, CFI) 机制的正确性**。CFI 是一种安全机制，旨在防止攻击者通过篡改函数指针等方式劫持程序的控制流。这个测试文件通过一系列测试用例，验证 CFI 是否能够正确地检测和阻止非法的间接函数调用。

**与 Android 功能的关系及举例**

CFI 是 Android 安全框架的重要组成部分，用于提高系统的安全性。它主要用于防御以下类型的攻击：

* **返回导向编程 (ROP) 和跳转导向编程 (JOP) 攻击:**  攻击者通过构造精心设计的代码片段（gadget），利用程序中已有的指令序列来执行恶意代码。CFI 可以限制间接跳转的目标，使得攻击者难以跳转到这些 gadget。
* **函数指针劫持:**  攻击者通过覆盖函数指针的值，使其指向恶意代码。CFI 验证间接调用的目标地址是否合法，从而阻止这种攻击。

**举例说明:**

假设一个 Android 应用使用了第三方库，该库存在一个漏洞，允许攻击者覆盖一个函数指针。

* **没有 CFI 的情况:**  攻击者可以将该函数指针指向恶意代码的地址，当程序调用该函数指针时，就会执行恶意代码，导致应用被攻击。
* **有 CFI 的情况:**  当程序尝试调用被篡改的函数指针时，Bionic 的 CFI 机制会检测到目标地址与预期的函数签名不匹配，从而阻止这次调用，通常会触发程序崩溃或者终止，阻止恶意代码的执行。

**详细解释每一个 libc 函数的功能是如何实现的**

这个测试文件中主要使用了以下 `libc` 函数：

1. **`dlopen(const char *filename, int flag)`:**
   * **功能:**  打开一个动态链接库 (Shared Object, SO)。
   * **实现原理:**
     * **路径查找:** 根据 `filename` 查找 SO 文件。如果 `filename` 包含路径，则直接使用；否则，会在系统预定义的路径（例如 `/system/lib`, `/vendor/lib` 等）中搜索。
     * **加载 SO 文件:** 将 SO 文件加载到进程的地址空间。这涉及到内存映射 (mmap) 操作，将 SO 文件的不同段（例如 `.text` 代码段, `.data` 数据段, `.bss` 未初始化数据段）映射到内存的不同区域。
     * **符号解析和重定位:**  解析 SO 文件中的符号表，找到 SO 依赖的其他 SO 以及需要的函数和变量。进行重定位，将代码中对外部符号的引用修改为实际的内存地址。
     * **执行初始化代码:**  如果 SO 文件有初始化函数（通过 `__attribute__((constructor))` 定义），则执行这些函数。
     * **返回句柄:** 返回一个指向加载的 SO 的句柄（void*），用于后续的 `dlsym` 和 `dlclose` 操作。如果加载失败，返回 `nullptr`。

2. **`dlsym(void *handle, const char *symbol)`:**
   * **功能:**  在已加载的动态链接库中查找指定符号的地址。
   * **实现原理:**
     * **查找符号表:**  在 `handle` 指向的 SO 的符号表中查找名为 `symbol` 的符号。
     * **符号解析:** 如果找到符号，则返回该符号的地址。
     * **错误处理:** 如果未找到符号，则返回 `nullptr`，并可以通过 `dlerror()` 获取错误信息。

3. **`dlclose(void *handle)`:**
   * **功能:**  卸载之前通过 `dlopen` 加载的动态链接库。
   * **实现原理:**
     * **执行析构代码:** 如果 SO 文件有析构函数（通过 `__attribute__((destructor))` 定义），则执行这些函数。
     * **解除内存映射:**  解除 SO 文件占用的内存映射。
     * **更新引用计数:**  维护 SO 的引用计数，只有当引用计数为 0 时才真正卸载。
     * **释放句柄:**  释放 `handle`。

4. **`sigaction64(int signum, const struct sigaction64 *act, struct sigaction64 *oldact)`:**
   * **功能:**  检查或修改特定信号的处理方式。
   * **实现原理:**  这是一个系统调用，直接与内核交互。它允许进程定义接收到特定信号（如 `SIGILL`, `SIGSEGV`, `SIGTRAP`）时的行为。
     * `act`: 指向包含新信号处理方式的 `sigaction64` 结构体的指针。如果为 `nullptr`, 则不修改处理方式。
     * `oldact`: 指向用于存储之前信号处理方式的 `sigaction64` 结构体的指针。如果不需要获取之前的处理方式，可以为 `nullptr`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**SO 布局样本 (简化)**

一个典型的 SO 文件布局如下：

```
ELF Header:
  ...
Program Headers:
  LOAD: 可执行代码段 (.text), 只读
  LOAD: 可读写数据段 (.data, .bss)
  DYNAMIC: 动态链接信息
Section Headers:
  .text: 代码段 (包含函数指令)
  .rodata: 只读数据段 (例如字符串常量)
  .data: 初始化数据段
  .bss: 未初始化数据段
  .symtab: 符号表 (包含导出的和导入的符号)
  .strtab: 字符串表 (存储符号名称等字符串)
  .dynsym: 动态符号表 (动态链接时使用的符号)
  .dynstr: 动态字符串表
  .plt: 程序链接表 (用于延迟绑定)
  .got: 全局偏移表 (存储全局变量和函数的地址)
  .hash: 符号哈希表 (加速符号查找)
  .rel.dyn: 动态重定位表 (用于重定位数据段)
  .rel.plt: 动态重定位表 (用于重定位 PLT 条目)
  ...
```

**对于 CFI，可能还会包含额外的段或信息，例如：**

* **`.cfi_data` 或类似名称的段:** 存储 CFI 相关的元数据，例如函数签名的信息，用于验证间接调用的目标地址是否合法。
* **在 `.symtab` 或 `.dynsym` 中的额外信息:**  用于标记哪些函数是可以通过间接调用进入的，以及它们的预期签名。

**链接的处理过程 (动态链接)**

1. **加载器启动:** 当程序启动或使用 `dlopen` 加载 SO 时，动态链接器 (如 `/system/bin/linker64` 或 `/system/bin/linker`) 被调用。
2. **加载依赖库:** 动态链接器会根据 SO 的依赖关系，递归地加载所有需要的共享库。
3. **符号解析:** 动态链接器会解析 SO 中的符号引用。
   * **本地符号解析:**  首先在当前 SO 的符号表中查找。
   * **全局符号解析:**  如果在当前 SO 中未找到，则在已经加载的其他共享库的全局符号表中查找。
4. **重定位:**  将代码和数据段中对外部符号的引用修改为实际的内存地址。
   * **GOT (Global Offset Table):**  对于全局变量和函数，通常使用 GOT 和 PLT (Procedure Linkage Table) 进行延迟绑定。初始时，GOT 条目指向 PLT 中的一段代码，当第一次调用该函数时，PLT 代码会调用动态链接器来解析符号，并将实际地址写入 GOT 条目。后续调用将直接从 GOT 获取地址。
   * **重定位条目:**  `.rel.dyn` 和 `.rel.plt` 段包含重定位信息，指示哪些位置需要被修改，以及如何修改。
5. **CFI 相关处理:**
   * **加载 CFI 元数据:** 动态链接器会加载 SO 中与 CFI 相关的元数据（如果存在）。
   * **构建 CFI 检查结构:**  可能构建用于快速检查间接调用目标地址合法性的数据结构（例如哈希表或位图）。
   * **关联 CFI 信息:**  将 CFI 信息与代码中的间接调用点关联起来。

**假设输入与输出 (针对 `__cfi_slowpath` 函数)**

`__cfi_slowpath` 是 CFI 机制的核心部分，当发生潜在的非法间接调用时会被调用。

**假设输入:**

* `CallSiteTypeId`:  一个标识调用点的类型 ID，用于区分不同的间接调用场景。
* `Ptr`:  间接调用的目标地址。

**预期输出和逻辑推理:**

`__cfi_slowpath` 的主要逻辑是判断 `Ptr` 是否是一个合法的目标地址，对于给定的 `CallSiteTypeId`。

1. **查找 CFI 元数据:** 根据 `CallSiteTypeId` 找到对应的预期函数签名或目标地址范围信息.
2. **地址匹配:**  检查 `Ptr` 是否与预期的信息匹配。这可能包括：
   * **类型匹配:** 检查 `Ptr` 指向的函数的签名是否与预期匹配（例如，参数数量、返回类型等）。
   * **地址范围检查:** 检查 `Ptr` 是否在允许的目标地址范围内。
3. **处理结果:**
   * **如果匹配 (CFI 检测到合法调用):**  虽然名字叫 "slowpath"，但在某些优化实现中，对于已知合法的调用，可能直接放行，或者进行一些统计和日志记录。
   * **如果不匹配 (CFI 检测到非法调用):**
     * **记录日志:** 记录错误信息，包括调用点类型、目标地址等。
     * **触发错误处理:**  通常会调用 `abort()` 终止程序，或者抛出一个异常。在测试环境中，可能会设置特定的错误处理机制，例如设置全局变量来记录错误信息，如代码中的 `get_last_type_id` 和 `get_last_address` 所做的那样。

**示例 (`TEST_F(cfi_test_DeathTest, basic)`) 的逻辑推理:**

* `__cfi_slowpath_diag(42, code_ptr, diag_ptr);`:  假设 `code_ptr` 指向 `libcfi-test.so` 内部的代码，且类型 ID 为 42 的调用点预期可以跳转到 `code_ptr` 这样的代码地址。则 CFI 检查应该通过。测试代码通过 `get_last_type_id()` 等函数验证 `__cfi_slowpath_diag` 是否被调用，并且记录了正确的参数。
* `__cfi_slowpath(43, get_global_address());`: 假设类型 ID 为 43 的调用点预期可以跳转到 `get_global_address()` 返回的数据地址。CFI 检查应该通过。
* `__cfi_slowpath(44, reinterpret_cast<void*>(&f));`:  假设类型 ID 为 44 的调用点预期不能跳转到当前 DSO (`cfi_test.cpp` 所在的 SO) 的函数 `f`。如果 `libcfi-test.so` 的 CFI 配置不允许这种跨 DSO 的跳转，CFI 检查将会失败（或者被忽略，如注释所说），并且测试 lib 的计数器不会增加。

**用户或者编程常见的使用错误**

1. **错误的函数指针类型转换:**  将一个函数指针转换为不兼容的类型，然后进行调用。CFI 可以检测到这种类型不匹配。
   ```c++
   void foo(int x);
   void bar(char *s);

   void (*func_ptr_foo)(int) = foo;
   void (*func_ptr_bar)(char*) = (void (*)(char*))func_ptr_foo; // 错误的类型转换

   func_ptr_bar("hello"); // CFI 可能会检测到类型不匹配
   ```

2. **尝试调用空指针或非法地址:**  虽然这不是 CFI 主要关注的场景，但如果将空指针或随机地址作为间接调用的目标，CFI 通常会检测到目标地址不属于任何合法的代码或数据区域。

3. **在启用了 CFI 的情况下，尝试进行动态代码生成或修改:**  CFI 依赖于在链接时确定的代码布局。如果运行时动态生成或修改代码，CFI 的检查可能会失败。

4. **第三方库的兼容性问题:**  如果应用程序使用了没有正确编译以支持 CFI 的第三方库，可能会导致 CFI 误判或无法正常工作。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 CFI 的路径 (简化)**

1. **应用程序或 NDK 代码执行:** 应用程序或通过 NDK 调用的 native 代码执行，包含间接函数调用（例如，调用函数指针、虚函数、接口方法等）。
2. **编译器的 CFI 插桩:**  当代码编译时启用了 CFI，编译器会在每个间接调用点插入 CFI 检查代码。
3. **动态链接器介入:** 当包含间接调用的代码被执行时，如果目标函数不在当前 SO 中，或者需要进行 CFI 检查，控制权会转移到动态链接器。
4. **`__cfi_slowpath` 调用:** 如果 CFI 检查失败，或者需要进行更复杂的检查，动态链接器会调用 `__cfi_slowpath` 或 `__cfi_slowpath_diag` 函数。

**Frida Hook 示例**

可以使用 Frida 来 hook `__cfi_slowpath` 函数，观察其调用情况和参数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    process = frida.get_usb_device().attach('com.example.myapp') # 替换为你的应用包名
except frida.ProcessNotFoundError:
    print("应用未运行，请先启动应用")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "__cfi_slowpath"), {
    onEnter: function(args) {
        console.log("[CFI Slow Path]");
        console.log("  CallSiteTypeId:", args[0].toString());
        console.log("  Ptr:", args[1]);
        // 可以进一步检查 args[1] 指向的内存
    }
});

Interceptor.attach(Module.findExportByName(null, "__cfi_slowpath_diag"), {
    onEnter: function(args) {
        console.log("[CFI Slow Path Diag]");
        console.log("  CallSiteTypeId:", args[0].toString());
        console.log("  Ptr:", args[1]);
        console.log("  DiagData:", args[2]);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 确保你的 Android 设备已连接并通过 USB 调试。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 将上面的 Python 代码保存为 `cfi_hook.py`。
4. 将 `com.example.myapp` 替换为你想要调试的应用程序的包名。
5. 运行 `python cfi_hook.py`。
6. 在你的 Android 设备上操作应用程序，触发可能导致 CFI 检查的代码路径。
7. Frida 会打印出 `__cfi_slowpath` 和 `__cfi_slowpath_diag` 被调用时的信息，包括 `CallSiteTypeId` 和目标地址 `Ptr`。

**调试步骤:**

1. **确定目标应用:** 选择你想要分析的应用。
2. **运行 Frida 脚本:** 启动 Frida hook 脚本并运行目标应用。
3. **触发 CFI 检查:**  在应用中执行可能触发 CFI 检查的操作。例如，如果怀疑某个第三方库的函数指针被篡改，可以尝试调用该库中相关的函数。
4. **观察 Frida 输出:**  查看 Frida 的输出，看是否输出了 `__cfi_slowpath` 或 `__cfi_slowpath_diag` 的信息。
5. **分析参数:** 分析 `CallSiteTypeId` 和 `Ptr` 的值，结合应用的源代码和汇编代码，尝试理解为什么 CFI 认为这次调用是非法的。
6. **进一步分析:** 可以使用 Frida 读取 `Ptr` 指向的内存，查看目标地址的内容，以及回溯调用栈，定位到触发 CFI 检查的具体代码位置。

希望这个详细的分析能够帮助你理解 `bionic/tests/cfi_test.cpp` 的功能以及 Android CFI 的相关知识。

### 提示词
```
这是目录为bionic/tests/cfi_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#include <dlfcn.h>
#include <sys/stat.h>

#include <vector>

#include <gtest/gtest.h>

#include "gtest_globals.h"
#include "utils.h"

#if defined(__BIONIC__)
#include "private/CFIShadow.h"
#endif

// Private libdl interface.
extern "C" {
void __cfi_slowpath(uint64_t CallSiteTypeId, void* Ptr);
void __cfi_slowpath_diag(uint64_t CallSiteTypeId, void* Ptr, void* DiagData);
size_t __cfi_shadow_size();
}

// Disables debuggerd stack traces to speed up death tests, make them less
// noisy in logcat, and avoid expected deaths from showing up in stability
// metrics.
// We don't use the usual libbase class because (a) we don't care about most
// of the signals it blocks but (b) we do need to block SIGILL, which normal
// death tests shouldn't ever hit. (It's possible that a design where a
// deathtest always declares its expected signals up front is a better one,
// and maybe that's an interesting future direction for libbase.)
//
// We include SIGSEGV because there's a test that passes heap addresses to
// __cfi_slowpath and we only map the executable code shadow as readable.
// We don't always get SIGSEGV there though: if the heap allocation happens
// to be close enough to an executable mapping that its shadow is in the
// same page as the executable shadow, we'll get SIGILL/SIGTRAP.
class cfi_test_DeathTest : public testing::Test {
 protected:
  void SetUp() override {
    struct sigaction64 action = {.sa_handler = SIG_DFL};
    sigaction64(SIGILL, &action, &previous_sigill_);
    sigaction64(SIGSEGV, &action, &previous_sigsegv_);
    sigaction64(SIGTRAP, &action, &previous_sigtrap_);
  }

  void TearDown() override {
    sigaction64(SIGTRAP, &previous_sigtrap_, nullptr);
    sigaction64(SIGSEGV, &previous_sigsegv_, nullptr);
    sigaction64(SIGILL, &previous_sigill_, nullptr);
  }

 private:
  struct sigaction64 previous_sigill_;
  struct sigaction64 previous_sigsegv_;
  struct sigaction64 previous_sigtrap_;
};

static void f() {}

TEST_F(cfi_test_DeathTest, basic) {
#if defined(__BIONIC__)
  void* handle;
  handle = dlopen("libcfi-test.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  EXPECT_NE(0U, __cfi_shadow_size());

#define SYM(type, name) auto name = reinterpret_cast<type>(dlsym(handle, #name))
  SYM(size_t (*)(), get_count);
  SYM(uint64_t(*)(), get_last_type_id);
  SYM(void* (*)(), get_last_address);
  SYM(void* (*)(), get_last_diag);
  SYM(void* (*)(), get_global_address);
  SYM(void (*)(uint64_t, void*, void*), __cfi_check);
  SYM(char*, bss);
#undef SYM

  size_t c = get_count();

  // CFI check for code inside the DSO. Can't use just any function address - this is only
  // guaranteed to work for code addresses above __cfi_check.
  void* code_ptr = reinterpret_cast<char*>(__cfi_check) + 1234;
  void* diag_ptr = reinterpret_cast<void*>(5678);
  __cfi_slowpath_diag(42, code_ptr, diag_ptr);
  EXPECT_EQ(42U, get_last_type_id());
  EXPECT_EQ(code_ptr, get_last_address());
  EXPECT_EQ(diag_ptr, get_last_diag());
  EXPECT_EQ(++c, get_count());

  // __cfi_slowpath passes nullptr for the Diag argument.
  __cfi_slowpath(42, code_ptr);
  EXPECT_EQ(42U, get_last_type_id());
  EXPECT_EQ(code_ptr, get_last_address());
  EXPECT_EQ(nullptr, get_last_diag());
  EXPECT_EQ(++c, get_count());

  // CFI check for a data address inside the DSO.
  __cfi_slowpath(43, get_global_address());
  EXPECT_EQ(43U, get_last_type_id());
  EXPECT_EQ(get_global_address(), get_last_address());
  EXPECT_EQ(++c, get_count());

  // CFI check for a function inside _this_ DSO. It either goes to this DSO's __cfi_check,
  // or (if missing) is simply ignored. Any way, it does not affect the test lib's counters.
  __cfi_slowpath(44, reinterpret_cast<void*>(&f));
  EXPECT_EQ(43U, get_last_type_id());
  EXPECT_EQ(get_global_address(), get_last_address());
  EXPECT_EQ(c, get_count());

  // Check all the addresses.
  const size_t bss_size = 1024 * 1024;
  static_assert(bss_size >= kLibraryAlignment * 2, "test range not big enough");
  for (size_t i = 0; i < bss_size; ++i) {
    __cfi_slowpath(47, bss + i);
    EXPECT_EQ(++c, get_count());
  }

  // Load the same library again.
  void* handle2 = dlopen("libcfi-test.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();
  EXPECT_EQ(handle2, handle);

  // Check that it is still there.
  __cfi_slowpath(43, get_global_address());
  EXPECT_EQ(43U, get_last_type_id());
  EXPECT_EQ(get_global_address(), get_last_address());
  EXPECT_EQ(++c, get_count());

  dlclose(handle);
  dlclose(handle2);
#endif
}

TEST(cfi_test, invalid) {
#if defined(__BIONIC__)
  void* handle;
  handle = dlopen("libcfi-test-bad.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_FALSE(handle != nullptr) << dlerror();

  handle = dlopen("libcfi-test-bad.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_FALSE(handle != nullptr) << dlerror();
#endif
}

// cfi_test_helper exports __cfi_check, which triggers CFI initialization at startup.
TEST(cfi_test, early_init) {
#if defined(__BIONIC__)
  std::string helper = GetTestLibRoot() + "/cfi_test_helper";
  ExecTestHelper eth;
  eth.SetArgs({ helper.c_str(), nullptr });
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, nullptr);
#endif
}

// cfi_test_helper2 depends on a library that exports __cfi_check, which triggers CFI initialization
// at startup.
TEST(cfi_test, early_init2) {
#if defined(__BIONIC__)
  std::string helper = GetTestLibRoot() + "/cfi_test_helper2";
  ExecTestHelper eth;
  eth.SetArgs({ helper.c_str(), nullptr });
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, nullptr);
#endif
}
```