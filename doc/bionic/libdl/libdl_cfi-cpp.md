Response:
Let's break down the thought process for analyzing the C++ code and generating the detailed Chinese response.

**1. Understanding the Core Task:**

The request asks for a comprehensive analysis of the provided `libdl_cfi.cpp` source code. The key is to identify its purpose, its relation to Android, its internal workings, potential errors, and how it's used within the Android ecosystem. The request also specifically asks for Frida hooking examples.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly read through the code, looking for key terms and patterns:

* **`CFI`:** This immediately stands out as the central theme. Control Flow Integrity.
* **`shadow`:**  Repeated use of "shadow," "shadow_base," "shadow_load," indicating a mapping or representation of something else.
* **`__cfi_init`, `__cfi_shadow_size`, `__cfi_slowpath`, `__cfi_slowpath_diag`:**  These are likely the entry points and core functions of the CFI mechanism.
* **`__loader_cfi_fail`:**  Indicates an error handling path.
* **`dlopen`, `dlclose` (in the comments):** Hints at the dynamic linker's involvement.
* **`mmap`, `max_android_page_size()`:** Suggest memory management.
* **`__attribute__((__weak__, visibility("default")))`:**  Compiler attributes, suggesting this function might be overridden.
* **`untag_address`:**  Pointer manipulation.
* **`CFIShadow::*`:**  Interaction with another (likely header-defined) component.

**3. Inferring the Purpose:**

Based on the keywords, the core function seems to be about enforcing Control Flow Integrity. The "shadow" likely holds information about valid function call targets. The `__cfi_slowpath` functions are probably invoked when an indirect call needs to be validated. The `__loader_cfi_fail` is the failure handler.

**4. Mapping to Android's Functionality:**

The file's location (`bionic/libdl`) and the mention of the dynamic linker immediately connect it to Android's core libraries. CFI is a security feature, and its presence in `libdl` indicates it's crucial for protecting against attacks that manipulate function pointers.

**5. Deep Dive into Each Function:**

Now, analyze each function individually:

* **`__loader_cfi_fail`:**  Clearly a failure handler, likely called when a CFI violation is detected. Since it's weak, it can be overridden by higher-level components for more specific error reporting.
* **`shadow_base_storage`:** A static variable to store the base address of the CFI shadow mapping. The `alignas` ensures proper alignment for memory mapping.
* **`__cfi_init`:** Called early by the dynamic linker to initialize the `shadow_base_storage`. The constraints mentioned in the comments (before global constructors, etc.) are important.
* **`__cfi_shadow_size`:** Returns the size of the shadow mapping, or 0 if CFI is not enabled.
* **`shadow_load`:**  The crucial function to retrieve CFI information for a given address. It untags the pointer, calculates an offset into the shadow, and reads the value.
* **`cfi_check_addr`:**  This is more complex. It takes the shadow value and the target address and performs a reverse calculation to determine the *expected* target address based on the CFI information. This indicates that the shadow doesn't store direct addresses but some form of encoding. The ARM-specific adjustment is a detail to note.
* **`cfi_slowpath_common`:** The core logic for checking CFI. It loads the shadow value and takes different actions based on its value (failure, no check, or actual address comparison).
* **`__cfi_slowpath` and `__cfi_slowpath_diag`:**  Public entry points for the CFI check, with the latter allowing for additional diagnostic data.

**6. Dynamic Linker Interaction:**

The comments mentioning `dlopen` and `dlclose` are key. The CFI shadow needs to be managed as libraries are loaded and unloaded. The linker is responsible for:

* Mapping the CFI shadow region.
* Informing `libdl_cfi.cpp` of the shadow's base address via `__cfi_init`.
* Potentially updating the shadow contents during `dlopen` and `dlclose` (though this isn't directly in this file).

**7. Hypothetical Input and Output (Logical Reasoning):**

Consider a scenario where a virtual function call is made.

* **Input:**  A function pointer to a virtual method in a loaded shared library.
* **Process:** The `__cfi_slowpath` function would be called. `shadow_load` would fetch the CFI information for the target address. `cfi_check_addr` would calculate the expected address. If the calculated address doesn't match the actual target address (or if the shadow value indicates an error), `__loader_cfi_fail` is called.
* **Output (Success):** The call proceeds.
* **Output (Failure):**  The application crashes or terminates (depending on the implementation of `__loader_cfi_fail`).

**8. Common User Errors:**

Consider how developers might interact with this indirectly.

* **Incorrectly casting function pointers:**  This could lead to CFI violations.
* **Memory corruption:** If the CFI shadow itself is corrupted, this could lead to unpredictable behavior.
* **Using libraries built without CFI:** Calls into such libraries might bypass CFI checks or cause false positives.

**9. Android Framework and NDK Interaction:**

Think about how a typical Android app reaches this code:

* **App starts:** The zygote process forks the app process.
* **Dynamic linker loads libraries:**  `linker64` (or `linker`) loads `libdl.so` early in the startup process.
* **CFI initialization:** The linker maps the CFI shadow and calls `__cfi_init`.
* **App makes indirect calls:** When the app calls a virtual function or uses a function pointer to call a function in a shared library, the compiler (LLVM) inserts calls to `__cfi_slowpath`.
* **NDK:** NDK developers writing native code are directly subject to these checks. If their code manipulates function pointers incorrectly, CFI will detect it.

**10. Frida Hooking:**

Think about what parts of the process would be useful to observe with Frida:

* **`__cfi_init`:** To see when the shadow is initialized and its base address.
* **`shadow_load`:** To inspect the CFI values associated with different memory locations.
* **`cfi_check_addr`:** To understand the calculation being performed.
* **`__cfi_slowpath` and `__cfi_slowpath_diag`:** To see when CFI checks are being triggered and the values being passed.
* **`__loader_cfi_fail`:** To catch CFI violations.

**11. Structuring the Response:**

Organize the information logically with clear headings and explanations. Use examples and code snippets to illustrate the concepts. Start with a high-level overview and then delve into the details. Pay attention to the specific points raised in the original request. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the shadow stores direct function addresses.
* **Correction:** The `cfi_check_addr` function reveals that it's more of an encoding scheme, where the shadow value is used to reconstruct an expected address.
* **Initial thought:** Focus only on `libdl_cfi.cpp`.
* **Refinement:** Recognize the crucial interaction with the dynamic linker and the `CFIShadow` component (even though its code isn't provided).

By following this systematic approach, combining code analysis with a good understanding of Android's architecture and security mechanisms, we can construct a comprehensive and accurate explanation like the example provided in the prompt.
这个文件 `bionic/libdl/libdl_cfi.cpp` 是 Android Bionic 库的一部分，专门负责实现**控制流完整性 (Control Flow Integrity, CFI)** 的机制。CFI 是一种安全技术，旨在防止攻击者通过篡改函数指针等手段来改变程序的执行流程。

下面详细列举其功能并进行解释：

**主要功能:**

1. **CFI 影子内存管理 (CFI Shadow Memory Management):**
   - **目的:** 为进程中所有可执行代码的函数入口点维护一个影子内存区域，用于存储 CFI 元数据。这些元数据用于验证间接函数调用（例如，通过函数指针进行的调用）的目标是否合法。
   - **实现:**
     - `shadow_base_storage`:  一个静态变量，用于存储 CFI 影子内存区域的基地址。这个地址由动态链接器在初始化时传递进来。
     - `__cfi_init(uintptr_t shadow_base)`:  这个函数由动态链接器在映射 CFI 影子内存后立即调用。它将影子内存的基地址存储到 `shadow_base_storage` 中。这个函数需要在非常早期的启动阶段执行，甚至在 `libdl.so` 的全局构造函数之前。
     - `__cfi_shadow_size()`:  返回 CFI 影子内存映射的大小。如果 CFI 未启用，则返回 0。

2. **CFI 检查 (CFI Checking):**
   - **目的:**  在间接函数调用发生时，检查目标地址是否是合法的函数入口点，从而防止恶意代码注入或函数指针劫持。
   - **实现:**
     - `shadow_load(void* p)`:  根据给定的地址 `p`，计算其在 CFI 影子内存中的偏移量，并加载对应的 CFI 元数据（一个 `uint16_t` 值）。
     - `cfi_check_addr(uint16_t v, void* Ptr)`:  根据加载的 CFI 元数据 `v` 和目标地址 `Ptr`，计算出预期的合法目标地址。这个计算涉及到将 CFI 元数据解码回地址信息。
     - `cfi_slowpath_common(uint64_t CallSiteTypeId, void* Ptr, void* DiagData)`:  CFI 检查的核心逻辑。它调用 `shadow_load` 获取 CFI 元数据，并根据其值执行不同的操作：
       - `CFIShadow::kInvalidShadow`:  表示目标地址没有对应的 CFI 信息，调用 `__loader_cfi_fail`，表明 CFI 检查失败。
       - `CFIShadow::kUncheckedShadow`:  表示该地址不需要进行 CFI 检查。
       - 其他值:  将 CFI 元数据解码后，通过函数指针调用一个检查函数，该函数会进一步验证调用是否合法。
     - `__cfi_slowpath(uint64_t CallSiteTypeId, void* Ptr)`:  CFI 检查的入口点，不带诊断信息。
     - `__cfi_slowpath_diag(uint64_t CallSiteTypeId, void* Ptr, void* DiagData)`: CFI 检查的入口点，带有诊断信息。

3. **CFI 失败处理 (CFI Failure Handling):**
   - **目的:**  当 CFI 检查失败时，提供一个默认的处理机制。
   - **实现:**
     - `__loader_cfi_fail(uint64_t CallSiteTypeId, void* Ptr, void* DiagData, void* CallerPc)`:  一个弱链接的外部函数，当 CFI 检查失败时被调用。默认情况下，它的实现可能只是终止程序。其他组件可以提供更具体的实现来处理 CFI 失败事件。

**与 Android 功能的关系及举例说明:**

CFI 是 Android 安全框架的重要组成部分，用于提高系统的安全性，防止恶意代码通过篡改函数指针等方式获得控制权。

**举例说明:**

假设一个应用程序通过函数指针调用一个共享库中的函数：

1. **编译器 (LLVM):**  当编译器遇到间接函数调用时，会生成代码，在调用目标函数之前调用 `__cfi_slowpath` 或 `__cfi_slowpath_diag`。
2. **`__cfi_slowpath` 调用:**  `__cfi_slowpath` 函数被调用，传入调用点类型 ID (`CallSiteTypeId`) 和目标地址 (`Ptr`)。
3. **`shadow_load`:** `shadow_load` 函数根据目标地址 `Ptr`，从 CFI 影子内存中加载对应的 CFI 元数据。
4. **`cfi_check_addr`:** 如果加载的元数据不是 `kInvalidShadow` 或 `kUncheckedShadow`，`cfi_check_addr` 会根据元数据和目标地址计算出一个预期的合法目标地址。
5. **CFI 检查函数调用:** 计算出的地址被用来调用一个实际的 CFI 检查函数。这个检查函数会验证目标地址是否与预期的地址匹配，以及是否是该调用点类型允许的目标。
6. **成功:** 如果检查通过，原始的间接函数调用继续进行。
7. **失败:** 如果检查失败，`__loader_cfi_fail` 函数会被调用，通常会导致程序终止，从而阻止潜在的安全漏洞被利用。

**libc 函数的功能实现:**

这个文件中定义的是 `libdl` 相关的 CFI 功能，它本身并不直接实现传统的 libc 函数（如 `malloc`, `printf` 等）。但是，它依赖于一些底层的 libc 功能，例如内存管理相关的系统调用（尽管在这个文件中没有直接调用，但 CFI 影子内存的映射肯定涉及到 `mmap` 或类似的调用）。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本:**

假设我们有一个共享库 `libexample.so`，它包含一些可执行代码，并且 CFI 已启用。

```
加载地址: 0xXXXXXXXXXXXX000
----------------------------
.text (代码段):  0xXXXXXXXXXXXX000 - 0xXXXXXXXXXXXXXXX
  - 函数 A 的代码
  - 函数 B 的代码
  - ...
.rodata (只读数据段): 0xYYYYYYYYYYYY000 - 0xYYYYYYYYYYYYYYY
  - 常量数据
.data (可读写数据段): 0xZZZZZZZZZZZZ000 - 0xZZZZZZZZZZZZZZZ
  - 全局变量
.bss (未初始化数据段): ...
.dynamic (动态链接信息): ...
.plt/.got (过程链接表/全局偏移表): ...
.cfi_shadow (CFI 影子内存): 0xAAAAAAAAAAAAAAAA000 - 0xAAAAAAAAAAAAAAAAFFF  // 假设的 CFI 影子内存区域
----------------------------
```

**链接的处理过程:**

1. **动态链接器 (`linker64` 或 `linker`):**  在加载共享库 `libexample.so` 时，动态链接器会负责创建并映射 CFI 影子内存区域。这个区域的大小和布局是预定义的，通常与代码段的大小相关。
2. **CFI 元数据写入:**  在链接时或加载时，动态链接器或相关的工具（例如 `llvm-cfi-verify`) 会分析 `libexample.so` 的代码，识别所有的函数入口点，并为这些入口点在 `.cfi_shadow` 段中写入相应的 CFI 元数据。
3. **`__cfi_init` 调用:**  在 CFI 影子内存映射完成后，动态链接器会调用 `libdl_cfi.so` 中的 `__cfi_init` 函数，将 CFI 影子内存的基地址（例如 `0xAAAAAAAAAAAAAAAA000`）传递给它。
4. **运行时 CFI 检查:**  当应用程序执行到需要进行 CFI 检查的间接函数调用时，`libdl_cfi.so` 中的函数（如 `shadow_load`, `cfi_check_addr`）会被调用，使用存储在 `.cfi_shadow` 中的元数据来验证调用的合法性。

**假设输入与输出 (逻辑推理):**

**假设输入:**

- `Ptr`:  一个函数指针，指向 `libexample.so` 中的某个地址 `0xXXXXXXXXXXXX123`。
- `shadow_base_storage.v`:  CFI 影子内存的基地址 `0xAAAAAAAAAAAAAAAA000`。
- 假设地址 `0xXXXXXXXXXXXX123` 对应的 CFI 元数据在影子内存中的偏移量计算后为 `0xBBBBBBBBBBBB456`，并且该位置存储的值为 `CFIShadow::kRegularShadowMin + 0x10`（假设 `kRegularShadowMin` 为 1）。

**输出:**

1. **`shadow_load(Ptr)`:**
   - `untag_address(Ptr)` 返回 `0xXXXXXXXXXXXX123` (假设没有地址标签)。
   - `CFIShadow::MemToShadowOffset(0xXXXXXXXXXXXX123)` 计算出偏移量，假设为 `0xBBBBBBBBBBBB456`。
   - 从 `shadow_base_storage.v + 0xBBBBBBBBBBBB456` (即 `0xAAAAAAAAAAAAAAAA000 + 0xBBBBBBBBBBBB456`) 读取 CFI 元数据，得到值 `1 + 0x10 = 0x11`。
   - 返回 `0x11`。

2. **`cfi_check_addr(0x11, Ptr)`:**
   - `aligned_addr` 计算为 `__builtin_align_down(0xXXXXXXXXXXXX123, CFIShadow::kShadowAlign) + CFIShadow::kShadowAlign`。假设 `CFIShadow::kShadowAlign` 为 8，则 `aligned_addr` 可能为 `0xXXXXXXXXXXXX128`。
   - `p` 计算为 `0xXXXXXXXXXXXX128 - (0x11 - 1) << CFIShadow::kCfiCheckGranularity`。假设 `CFIShadow::kCfiCheckGranularity` 为 2，则 `p = 0xXXXXXXXXXXXX128 - 0x10 * 4 = 0xXXXXXXXXXXXX088`。
   - 返回 `0xXXXXXXXXXXXX089` (因为 `__arm__` 宏可能被定义，导致 +1 操作)。

**注意:**  实际的地址计算和 CFI 元数据的含义会更加复杂，这里只是一个简化的示例。

**用户或编程常见的使用错误:**

用户或开发者通常不会直接与 `libdl_cfi.cpp` 交互。CFI 的工作是透明的。但是，一些编程错误可能会导致 CFI 检查失败：

1. **函数指针类型不匹配:**  如果将一个函数指针强制转换为不兼容的类型，然后进行调用，CFI 可能会检测到目标地址与预期类型不符。
   ```c++
   void func1(int arg);
   void func2(float arg);

   void (*fp)(int) = func1;
   fp(10); // OK

   void (*fp2)(float) = (void (*)(float))func1; // 错误的类型转换
   // fp2(3.14f); // 可能导致 CFI 失败，因为 func1 的入口点可能不符合 float 参数的调用约定。
   ```

2. **跳转到函数中间:**  如果程序逻辑错误导致跳转到函数的非入口地址，CFI 会检测到该地址不是合法的函数入口点。
   ```c++
   void my_function() {
       int x = 10;
   middle:
       x++;
       // ...
   }

   void some_other_function() {
       goto middle; // 错误地跳转到函数中间
   }
   ```

3. **内存损坏导致函数指针被篡改:**  如果程序存在缓冲区溢出或其他内存错误，导致函数指针的值被意外修改，CFI 会检测到目标地址不是预期的合法地址。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到 `libdl_cfi.cpp` 的路径:**

1. **NDK 开发/Framework 代码:**  开发者使用 NDK 编写 C/C++ 代码，或编写 Android Framework 的 native 组件。这些代码中可能包含间接函数调用（例如，虚函数调用、函数指针调用）。
2. **编译器 (LLVM):**  当编译这些代码时，LLVM 编译器会识别出需要进行 CFI 保护的间接调用点，并在这些调用点之前插入调用 `__cfi_slowpath` 或 `__cfi_slowpath_diag` 的指令。这些调用会将调用点类型信息和目标地址传递给 CFI 检查函数。
3. **动态链接器 (`linker64` 或 `linker`):** 当应用程序或共享库被加载时，动态链接器负责加载必要的库，包括 `libdl.so` (其中包含了 `libdl_cfi.cpp` 编译后的代码)。动态链接器还会映射 CFI 影子内存，并调用 `__cfi_init` 进行初始化。
4. **运行时调用:**  当应用程序执行到被编译器插入的 `__cfi_slowpath` 调用时，程序流程会进入 `libdl_cfi.cpp` 中的 CFI 检查逻辑。

**Frida Hook 示例:**

可以使用 Frida 来 hook `libdl_cfi.cpp` 中的关键函数，以观察 CFI 的工作过程。

```javascript
// Hook __cfi_init，查看影子内存基地址
Interceptor.attach(Module.findExportByName("libdl.so", "__cfi_init"), {
  onEnter: function (args) {
    console.log("[__cfi_init] shadow_base:", args[0]);
  },
});

// Hook __cfi_slowpath，查看调用点类型和目标地址
Interceptor.attach(Module.findExportByName("libdl.so", "__cfi_slowpath"), {
  onEnter: function (args) {
    console.log("[__cfi_slowpath] CallSiteTypeId:", args[0]);
    console.log("[__cfi_slowpath] Ptr:", args[1]);
    // 可以进一步解析 CallSiteTypeId 来了解具体的调用点信息
  },
});

// Hook shadow_load，查看加载的 CFI 元数据
Interceptor.attach(Module.findExportByName("libdl.so", "_Z11shadow_loadPv"), { // 函数名可能需要 demangle
  onEnter: function (args) {
    console.log("[shadow_load] Ptr:", args[0]);
  },
  onLeave: function (retval) {
    console.log("[shadow_load] 返回值 (CFI 元数据):", retval);
  },
});

// Hook __loader_cfi_fail，查看 CFI 失败的情况
Interceptor.attach(Module.findExportByName("libdl.so", "__loader_cfi_fail"), {
  onEnter: function (args) {
    console.error("[__loader_cfi_fail] CFI 检查失败！");
    console.error("[__loader_cfi_fail] CallSiteTypeId:", args[0]);
    console.error("[__loader_cfi_fail] Ptr:", args[1]);
    console.error("[__loader_cfi_fail] DiagData:", args[2]);
    console.error("[__loader_cfi_fail] CallerPc:", args[3]);
  },
});
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的设备已 root，并且安装了 Frida 和 Frida server。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中 (例如 `cfi_hook.js`)。
3. **运行 Frida 脚本:** 使用 `frida -U -f <your_app_package_name> -l cfi_hook.js --no-pause` 命令来启动你的应用程序并注入 Frida 脚本。
4. **触发 CFI 检查:**  在你的应用程序中执行一些会触发间接函数调用的操作。
5. **查看 Frida 输出:**  观察 Frida 的控制台输出，你会看到 hook 到的函数的调用信息，包括 CFI 影子内存的基地址、CFI 检查的参数、加载的元数据以及 CFI 失败的信息。

通过这些 Frida hook，你可以深入了解 Android 系统中 CFI 的工作原理，以及应用程序是如何与这些安全机制进行交互的。

Prompt: 
```
这是目录为bionic/libdl/libdl_cfi.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <sys/mman.h>

#include "private/CFIShadow.h"

__attribute__((__weak__, visibility("default"))) extern "C" void __loader_cfi_fail(
    uint64_t CallSiteTypeId, void* Ptr, void* DiagData, void* CallerPc);

// Base address of the CFI shadow. Passed down from the linker in __cfi_init()
// and does not change after that. The contents of the shadow change in
// dlopen/dlclose.
static struct {
  uintptr_t v;
  char padding[max_android_page_size() - sizeof(v)];
} shadow_base_storage alignas(max_android_page_size());

// __cfi_init is called by the loader as soon as the shadow is mapped. This may happen very early
// during startup, before libdl.so global constructors, and, on i386, even before __libc_sysinfo is
// initialized. This function should not do any system calls.
extern "C" uintptr_t* __cfi_init(uintptr_t shadow_base) {
  shadow_base_storage.v = shadow_base;
  static_assert(sizeof(shadow_base_storage) == max_android_page_size(), "");
  return &shadow_base_storage.v;
}

// Returns the size of the CFI shadow mapping, or 0 if CFI is not (yet) used in this process.
extern "C" size_t __cfi_shadow_size() {
  return shadow_base_storage.v != 0 ? CFIShadow::kShadowSize : 0;
}

static uint16_t shadow_load(void* p) {
  // Untag the pointer to move it into the address space covered by the shadow.
  uintptr_t addr = reinterpret_cast<uintptr_t>(untag_address(p));
  uintptr_t ofs = CFIShadow::MemToShadowOffset(addr);
  if (ofs > CFIShadow::kShadowSize) return CFIShadow::kInvalidShadow;
  return *reinterpret_cast<uint16_t*>(shadow_base_storage.v + ofs);
}

static uintptr_t cfi_check_addr(uint16_t v, void* Ptr) {
  uintptr_t addr = reinterpret_cast<uintptr_t>(Ptr);
  // The aligned range of [0, kShadowAlign) uses a single shadow element, therefore all pointers in
  // this range must get the same aligned_addr below. This matches CFIShadowWriter::Add; not the
  // same as just __builtin_align_up().
  uintptr_t aligned_addr = __builtin_align_down(addr, CFIShadow::kShadowAlign) + CFIShadow::kShadowAlign;
  uintptr_t p = aligned_addr - (static_cast<uintptr_t>(v - CFIShadow::kRegularShadowMin)
                                << CFIShadow::kCfiCheckGranularity);
#ifdef __arm__
  // Assume Thumb encoding. FIXME: force thumb at compile time?
  p++;
#endif
  return p;
}

static inline void cfi_slowpath_common(uint64_t CallSiteTypeId, void* Ptr, void* DiagData) {
  uint16_t v = shadow_load(Ptr);
  switch (v) {
    case CFIShadow::kInvalidShadow:
      __loader_cfi_fail(CallSiteTypeId, Ptr, DiagData, __builtin_return_address(0));
      break;
    case CFIShadow::kUncheckedShadow:
      break;
    default:
      reinterpret_cast<CFIShadow::CFICheckFn>(cfi_check_addr(v, Ptr))(CallSiteTypeId, Ptr, DiagData);
  }
}

extern "C" void __cfi_slowpath(uint64_t CallSiteTypeId, void* Ptr) {
  cfi_slowpath_common(CallSiteTypeId, Ptr, nullptr);
}

extern "C" void __cfi_slowpath_diag(uint64_t CallSiteTypeId, void* Ptr, void* DiagData) {
  cfi_slowpath_common(CallSiteTypeId, Ptr, DiagData);
}

"""

```