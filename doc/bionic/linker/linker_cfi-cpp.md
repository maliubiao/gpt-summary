Response:
Let's break down the thought process for analyzing this `linker_cfi.cpp` file and generating the detailed response.

1. **Understand the Core Functionality:** The file name `linker_cfi.cpp` and the comment at the top immediately signal its purpose: Control Flow Integrity (CFI) within the Android dynamic linker. The comments about shadow memory further reinforce this. The core idea is to protect against indirect call/jump target hijacking.

2. **Identify Key Components:** Scan the code for important classes, functions, and data structures. The `CFIShadowWriter` class stands out as the central component. Within it, functions like `AddConstant`, `AddUnchecked`, `AddInvalid`, `Add`, `MapShadow`, `AddLibrary`, `NotifyLibDl`, `MaybeInit`, `AfterLoad`, `BeforeUnload`, `InitialLinkDone`, and `CfiFail` suggest the lifecycle and operations related to managing the CFI shadow.

3. **Analyze `CFIShadowWriter` Methods:**  Go through each method of `CFIShadowWriter` and understand its individual role:
    * **Constructor/Destructor (`ShadowWrite`):**  Focus on the memory manipulation aspects (`mmap`, `mremap`, `mprotect`). The goal is to update the shadow memory atomically and without making it writable in normal circumstances. This is a crucial security optimization.
    * **`FixupVmaName`:**  A simple function using `prctl` for debugging/introspection.
    * **`AddConstant`, `AddUnchecked`, `AddInvalid`:**  These are variations of the same theme – setting shadow memory to specific values. `AddConstant` is the general case, while the others are specializations.
    * **`Add`:** The most complex method. It calculates shadow values based on the library's address range and the location of `__cfi_check`. The logic involving `kShadowAlign`, `kCfiCheckGranularity`, and `sv_step` is critical to understand how CFI checks are encoded in the shadow memory. The error handling within this function (wrapping, existing data) is important.
    * **`MapShadow`:**  Allocates the shadow memory region.
    * **`AddLibrary`:**  Integrates a newly loaded library into the CFI scheme. It checks for the `__cfi_check` symbol.
    * **`NotifyLibDl`:**  Crucial for communication between the linker and `libdl.so`. It shares the shadow memory address.
    * **`MaybeInit`:**  Handles the initialization of the CFI shadow, particularly during the initial linking phase.
    * **`AfterLoad`, `BeforeUnload`:**  Manage the CFI shadow as libraries are loaded and unloaded.
    * **`InitialLinkDone`:**  Marks the end of the initial linking process and triggers potential CFI initialization.
    * **`CfiFail`:** The handler when a CFI violation occurs. It attempts to find `__cfi_check` in the calling library and delegate the error handling.

4. **Examine Helper Functions:** Understand the role of `find_libdl` and `soinfo_find_symbol`/`soinfo_find_cfi_check`. These facilitate locating `libdl.so` and the `__cfi_check` symbol within shared libraries.

5. **Connect to Android Functionality:**  Explicitly link the code to broader Android security concepts. Explain *why* CFI is important (preventing exploits). Mention the role of the dynamic linker in the application startup process.

6. **Detail Libc and Dynamic Linker Interaction:** Since the code is part of the dynamic linker, explicitly discuss the functions used from libc (`mmap`, `mremap`, `mprotect`, `memcpy`, `memset`, `prctl`, `strcmp`). Explain *why* these are used in the context of CFI. For the dynamic linker, describe the process of loading shared objects, resolving symbols, and how CFI fits into this. A simplified SO layout diagram is very helpful here.

7. **Consider Edge Cases and Errors:**  Think about situations where things might go wrong. Examples include:
    * Missing `__cfi_check` symbol.
    * Unaligned `__cfi_check`.
    * Shadow memory conflicts (though the `ShadowWrite` class aims to prevent this).
    * Binary too large causing shadow value wraparound.

8. **Illustrate with Examples:** Provide concrete examples to clarify abstract concepts. This includes:
    * Frida hook examples to show how to observe the CFI initialization process.
    * Hypothetical scenarios to explain the logic within functions like `Add`.

9. **Structure the Response:** Organize the information logically. Start with a high-level overview, then delve into details, and finally provide concrete examples and debugging techniques. Use headings and bullet points to improve readability.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any technical inaccuracies or areas where the explanation could be improved. For instance, initially, I might have just mentioned `mmap` without explaining the specific `MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE` flags – adding these details makes the explanation more thorough. Similarly, explaining the rationale behind the `ShadowWrite` class's approach to memory management strengthens the explanation.

By following this systematic approach, the detailed and comprehensive response covering the functionalities, relationships to Android, libc and dynamic linker interactions, potential errors, and debugging techniques can be constructed.
好的，让我们深入分析一下 `bionic/linker/linker_cfi.cpp` 这个文件。

**功能概述**

`linker_cfi.cpp` 文件的核心功能是实现 Android 系统中动态链接器的控制流完整性（Control Flow Integrity，CFI）机制。CFI 是一种安全机制，旨在防止攻击者通过修改函数指针等方式改变程序的执行流程，从而执行恶意代码。

具体来说，这个文件负责以下几个关键任务：

1. **维护 CFI 影子内存 (Shadow Memory):**  它创建并管理一块特殊的内存区域，称为 CFI 影子内存。这块内存与程序代码内存相对应，但存储的是 CFI 的元数据，而不是实际的代码。
2. **记录代码地址的 CFI 属性:**  对于加载到内存中的共享库（.so 文件），它会根据库中是否包含特定的 CFI 符号 (`__cfi_check`)，将代码地址范围标记为不同的 CFI 状态（例如：受保护、未检查、无效）。
3. **通知 `libdl.so`:**  将 CFI 影子内存的地址传递给 `libdl.so` 库，以便 `libdl.so` 也能参与到 CFI 检查过程中。
4. **在库加载和卸载时更新 CFI 影子内存:** 当新的共享库被加载或卸载时，它会动态地更新 CFI 影子内存，以反映代码内存的变化。
5. **处理 CFI 检查失败:** 当 CFI 检查失败时（即，程序尝试跳转到一个不被允许的目标地址），它会调用相应的错误处理函数。

**与 Android 功能的关系及举例说明**

CFI 是 Android 安全体系中的一个重要组成部分，主要用于防御以下类型的攻击：

* **ROP (Return-Oriented Programming):** 攻击者通过精心构造的返回地址链，利用已有的代码片段（gadgets）来执行恶意操作。CFI 可以确保返回地址的有效性，阻止 ROP 攻击。
* **JOP (Jump-Oriented Programming):** 类似于 ROP，但利用的是间接跳转指令。CFI 可以限制间接跳转的目标地址，防止 JOP 攻击。
* **函数指针劫持:** 攻击者修改函数指针的值，使其指向恶意代码。CFI 可以验证函数指针的目标地址是否合法。

**举例说明:**

假设一个应用程序加载了一个包含漏洞的共享库。攻击者尝试利用该漏洞，通过修改一个函数指针，使其指向攻击者注入的恶意代码。如果启用了 CFI，动态链接器会在执行间接调用/跳转之前，检查目标地址在 CFI 影子内存中的状态。如果目标地址没有被标记为合法的 CFI 目标，程序执行将会被阻止，从而防止攻击。

**详细解释每一个 libc 函数的功能是如何实现的**

`linker_cfi.cpp` 中使用了一些 libc 函数，它们的实现细节非常复杂，位于 bionic 仓库的其他源文件中。这里我们简要说明它们在本文件中的作用：

* **`<sys/mman.h>`:**
    * **`mmap(nullptr, size, PROT_NONE/PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)`:**  用于分配一块新的内存区域。
        * `nullptr`:  让系统自动选择分配的地址。
        * `size`:  分配内存的大小。
        * `PROT_NONE`:  初始时不允许任何访问（读、写、执行）。
        * `PROT_READ | PROT_WRITE`:  允许读写访问。
        * `MAP_PRIVATE`:  创建私有匿名映射，对该内存的修改不会影响其他进程。
        * `MAP_ANONYMOUS`:  表示映射的是匿名内存，而不是文件。
        * `MAP_NORESERVE`:  不预留交换空间，只有在实际访问时才分配物理页面。
        * `-1, 0`:  用于文件映射，这里是匿名映射，所以使用默认值。
    * **`mprotect(addr, len, prot)`:** 修改指定内存区域的保护属性。例如，可以将一块内存从可读写修改为只读 (`PROT_READ`)。这在 CFI 中用于保护影子内存，使其在正常情况下不可写。
    * **`mremap(old_address, old_size, new_size, flags, new_address)`:**  重新映射内存区域。这里用于在更新影子内存时，将准备好的新数据原子地替换旧数据。
        * `MREMAP_MAYMOVE`:  允许系统移动内存区域。
        * `MREMAP_FIXED`:  如果指定了 `new_address`，则必须映射到该地址，否则 `mremap` 会失败。
* **`<sys/prctl.h>`:**
    * **`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, start_address, size, "cfi shadow")`:**  用于设置匿名内存区域的名称。这主要用于调试和性能分析，可以更容易地在 `/proc/<pid>/maps` 中识别 CFI 影子内存。
* **`<sys/types.h>` 和 `<cstdint>`:**  提供基本的类型定义，如 `uintptr_t` 和 `uint16_t`。
* **`<cstring>` (通过 `#include "linker_debug.h"` 间接包含):**
    * **`strcmp(str1, str2)`:**  用于比较两个字符串是否相等，用于查找 `libdl.so`。
    * **`memcpy(dest, src, count)`:** 用于将内存从 `src` 复制到 `dest`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**SO 布局样本：**

假设我们有一个简单的共享库 `libtest.so`，它支持 CFI。它的布局可能如下：

```
.text        (代码段 - 可执行)
    ... 一些函数 ...
    <__cfi_check 函数的入口点>   <- 关键：CFI 检查函数
    ... 更多函数 ...
.rodata      (只读数据段)
    ... 常量数据 ...
.data        (可读写数据段)
    ... 全局变量 ...
.bss         (未初始化数据段)
    ... 未初始化的全局变量 ...
.symtab      (符号表)
    ... 其他符号 ...
    __cfi_check  (指向 __cfi_check 函数入口点的符号)
    ... 其他符号 ...
.strtab      (字符串表)
    ... 符号名称等字符串 ...
```

**链接的处理过程：**

1. **加载共享库:** 当应用程序请求加载 `libtest.so` 时，动态链接器会将其加载到内存中的某个地址空间。
2. **解析 ELF 文件头:** 动态链接器会解析 `libtest.so` 的 ELF 文件头，以获取各个段的地址和大小信息。
3. **查找 `__cfi_check` 符号:**  动态链接器会扫描 `.symtab` 段，查找名为 `__cfi_check` 的符号。如果找到了，它会记录 `__cfi_check` 函数的入口地址。
4. **更新 CFI 影子内存:**  `CFIShadowWriter::AddLibrary` 函数会被调用。
   - 如果找到了 `__cfi_check`，`Add` 函数会被调用。它会计算出 `libtest.so` 代码段对应的 CFI 影子内存范围，并根据 `__cfi_check` 的地址，在该范围内填充相应的 CFI 状态值。这些值表示哪些地址是合法的间接调用/跳转目标。
   - 如果没有找到 `__cfi_check`，`AddUnchecked` 函数会被调用，将该库的代码段标记为未检查。
5. **运行时 CFI 检查:**  当程序执行到需要进行 CFI 检查的间接调用/跳转指令时（通常由编译器插入 `__cfi_check` 函数调用），会发生以下过程：
   - 获取目标地址。
   - 使用目标地址计算出其在 CFI 影子内存中的偏移。
   - 读取 CFI 影子内存中对应的值。
   - 如果该值表示目标地址是合法的，则继续执行跳转/调用。
   - 如果该值表示目标地址不合法，则调用 `CFIShadowWriter::CfiFail` 处理错误。

**假设输入与输出（针对 `CFIShadowWriter::Add` 函数）**

**假设输入：**

* `begin`:  `libtest.so` 代码段的起始地址，例如 `0x7000000000`。
* `end`:  `libtest.so` 代码段的结束地址，例如 `0x7000001000`。
* `cfi_check`: `__cfi_check` 函数的入口地址，例如 `0x7000000100`。
* 假设 `kShadowAlign` 为 16，`kCfiCheckAlign` 为 4，`kShadowGranularity` 为 4，`kCfiCheckGranularity` 为 2，`kRegularShadowMin` 为 1。

**逻辑推理：**

1. `begin` 会根据 `kShadowAlign` 对齐，`begin = std::max(begin, cfi_check) & ~(kShadowAlign - 1)`。假设 `cfi_check` 比 `begin` 大，且对齐后 `begin` 保持不变。
2. 计算影子内存的起始和结束地址：`shadow_begin = MemToShadow(begin)`, `shadow_end = MemToShadow(end - 1) + 1`。`MemToShadow` 函数将代码内存地址转换为影子内存地址，这通常涉及位运算。
3. 计算初始影子值：`sv_begin = ((begin + kShadowAlign - cfi_check) >> kCfiCheckGranularity) + kRegularShadowMin`。
4. 计算影子值步进：`sv_step = 1 << (kShadowGranularity - kCfiCheckGranularity)`，这里是 `1 << (4 - 2) = 4`。
5. 遍历影子内存范围，为每个影子内存单元赋值。初始值为 `sv_begin`，每次递增 `sv_step`。如果遇到 wraparound 或已存在值，则设置为 `kUncheckedShadow`。

**可能的输出（影子内存中的值）：**

影子内存的布局和具体值取决于 `MemToShadow` 的实现和具体的地址计算。但大致来说，与 `libtest.so` 代码段对应的影子内存区域，从 `__cfi_check` 函数的地址开始，会被填充递增的值。例如，如果 `sv_begin` 是 1，那么接下来的值可能是 5, 9, 13，以此类推。在 `__cfi_check` 地址之前的区域可能保持为 `kInvalidShadow` 或其他初始值。

**用户或编程常见的使用错误**

1. **未在编译时启用 CFI 标志:** 如果在编译共享库时没有使用 `-fcf-protection=full` 或类似的编译器标志，`__cfi_check` 函数将不会被生成，CFI 也不会生效。
2. **`__cfi_check` 函数未正确定义或导出:** 如果 `__cfi_check` 函数的定义不正确，或者在链接时没有被正确导出，动态链接器可能无法找到它。
3. **在不应使用 CFI 的地方使用了 CFI 保护:** 某些代码可能由于其特殊性质（例如，JIT 代码）而不适合进行 CFI 保护。过度使用 CFI 可能会导致性能问题或兼容性问题。
4. **假设所有库都启用了 CFI:**  并非所有 Android 系统库或第三方库都启用了 CFI。开发者不能假设所有间接调用都会受到 CFI 的保护。
5. **手动修改 CFI 影子内存:** 用户或恶意程序不应该尝试直接修改 CFI 影子内存。`ShadowWrite` 类使用了 `mremap` 等机制来保证原子性和安全性。

**Android Framework 或 NDK 是如何一步步的到达这里**

1. **应用程序启动:** 当 Android 系统启动一个应用程序时，zygote 进程会 fork 出一个新的进程。
2. **加载 `linker64` 或 `linker`:** 新进程首先会加载动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`)。
3. **链接器初始化:** 动态链接器会进行初始化，包括设置内存管理、加载必要的系统库等。
4. **加载 `app_process` 或 `dalvikvm`:**  根据应用程序的类型，会加载 `app_process` (用于 Java 应用) 或 `dalvikvm` (较旧版本的 Android)。
5. **加载应用程序依赖的库:**  `app_process` 或 `dalvikvm` 会加载应用程序所依赖的共享库。
6. **调用 `CFIShadowWriter::AfterLoad`:** 每当加载一个新的共享库时，动态链接器会调用 `CFIShadowWriter::AfterLoad`，以便更新 CFI 影子内存。
7. **调用 `CFIShadowWriter::InitialLinkDone`:**  当初始链接过程完成时，动态链接器会调用 `CFIShadowWriter::InitialLinkDone`，触发 CFI 影子内存的最终初始化。
8. **运行时 CFI 检查:**  当应用程序执行代码时，如果遇到需要进行 CFI 检查的间接调用/跳转，会调用编译器插入的 `__cfi_check` 函数。这个函数最终会访问 CFI 影子内存来验证目标地址的合法性.

**Frida Hook 示例调试这些步骤**

以下是一个使用 Frida Hook 调试 CFI 相关步骤的示例：

```javascript
// Hook CFIShadowWriter::AddLibrary 函数，查看库加载时 CFI 的处理
Interceptor.attach(Module.findExportByName(null, "_ZN16CFIShadowWriter10AddLibraryEP6soinfo"), {
  onEnter: function(args) {
    const soinfoPtr = ptr(args[1]);
    const soname = soinfoPtr.readCString();
    console.log(`[CFI] Loading library: ${soname}`);
  },
  onLeave: function(retval) {
    console.log(`[CFI] AddLibrary returned: ${retval}`);
  }
});

// Hook CFIShadowWriter::CfiFail 函数，捕获 CFI 检查失败的情况
Interceptor.attach(Module.findExportByName(null, "_ZN16CFIShadowWriter7CfiFailEyPvS0_Pv"), {
  onEnter: function(args) {
    console.error("[CFI] CFI check failed!");
    console.error(`[CFI] CallSiteTypeId: ${args[0].toInt()}`);
    console.error(`[CFI] Ptr: ${args[1]}`);
    console.error(`[CFI] DiagData: ${args[2]}`);
    console.error(`[CFI] CallerPc: ${args[3]}`);

    // 可以选择在这里阻止程序继续执行
    // return -1;
  }
});

// Hook mmap 函数，查看 CFI 影子内存的分配
Interceptor.attach(Module.findExportByName(null, "mmap"), {
  onEnter: function(args) {
    const size = args[1].toInt();
    const flags = args[3].toInt();
    if ((flags & 0x2) && (flags & 0x20)) { // MAP_PRIVATE 和 MAP_ANONYMOUS
      console.log(`[CFI] mmap called with size: ${size}, flags: ${flags.toString(16)}`);
    }
  },
  onLeave: function(retval) {
    if (this.context.lr.equals(Module.findExportByName(null, "_ZN16CFIShadowWriter9MapShadowEv"))) {
      console.log(`[CFI] CFI Shadow memory allocated at: ${retval}`);
    }
  }
});
```

**使用步骤：**

1. 将上述 JavaScript 代码保存到一个文件中，例如 `cfi_hook.js`。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l cfi_hook.js --no-pause` (替换 `<package_name>` 为目标应用的包名)。
3. 当目标应用加载共享库或发生 CFI 失败时，Frida 控制台会输出相应的日志信息。

通过这些 Hook，你可以观察到 CFI 影子内存的分配、库加载时 CFI 信息的添加，以及 CFI 检查失败时的详细信息，从而帮助你理解 Android CFI 的工作原理。

希望以上详细的解释能够帮助你理解 `bionic/linker/linker_cfi.cpp` 的功能和实现细节。

### 提示词
```
这是目录为bionic/linker/linker_cfi.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include "linker_cfi.h"

#include "linker_debug.h"
#include "linker_globals.h"
#include "platform/bionic/page.h"

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <cstdint>

// Update shadow without making it writable by preparing the data on the side and mremap-ing it in
// place.
class ShadowWrite {
  char* shadow_start;
  char* shadow_end;
  char* aligned_start;
  char* aligned_end;
  char* tmp_start;

 public:
  ShadowWrite(uint16_t* s, uint16_t* e) {
    shadow_start = reinterpret_cast<char*>(s);
    shadow_end = reinterpret_cast<char*>(e);
    aligned_start = reinterpret_cast<char*>(page_start(reinterpret_cast<uintptr_t>(shadow_start)));
    aligned_end = reinterpret_cast<char*>(page_end(reinterpret_cast<uintptr_t>(shadow_end)));
    tmp_start =
        reinterpret_cast<char*>(mmap(nullptr, aligned_end - aligned_start, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    CHECK(tmp_start != MAP_FAILED);
    mprotect(aligned_start, aligned_end - aligned_start, PROT_READ);
    memcpy(tmp_start, aligned_start, shadow_start - aligned_start);
    memcpy(tmp_start + (shadow_end - aligned_start), shadow_end, aligned_end - shadow_end);
  }

  uint16_t* begin() {
    return reinterpret_cast<uint16_t*>(tmp_start + (shadow_start - aligned_start));
  }

  uint16_t* end() {
    return reinterpret_cast<uint16_t*>(tmp_start + (shadow_end - aligned_start));
  }

  ~ShadowWrite() {
    size_t size = aligned_end - aligned_start;
    mprotect(tmp_start, size, PROT_READ);
    void* res = mremap(tmp_start, size, size, MREMAP_MAYMOVE | MREMAP_FIXED,
                       reinterpret_cast<void*>(aligned_start));
    CHECK(res != MAP_FAILED);
  }
};

void CFIShadowWriter::FixupVmaName() {
  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, *shadow_start, kShadowSize, "cfi shadow");
}

void CFIShadowWriter::AddConstant(uintptr_t begin, uintptr_t end, uint16_t v) {
  uint16_t* shadow_begin = MemToShadow(begin);
  uint16_t* shadow_end = MemToShadow(end - 1) + 1;

  ShadowWrite sw(shadow_begin, shadow_end);
  std::fill(sw.begin(), sw.end(), v);
}

void CFIShadowWriter::AddUnchecked(uintptr_t begin, uintptr_t end) {
  AddConstant(begin, end, kUncheckedShadow);
}

void CFIShadowWriter::AddInvalid(uintptr_t begin, uintptr_t end) {
  AddConstant(begin, end, kInvalidShadow);
}

void CFIShadowWriter::Add(uintptr_t begin, uintptr_t end, uintptr_t cfi_check) {
  CHECK((cfi_check & (kCfiCheckAlign - 1)) == 0);

  // Don't fill anything below cfi_check. We can not represent those addresses
  // in the shadow, and must make sure at codegen to place all valid call
  // targets above cfi_check.
  begin = std::max(begin, cfi_check) & ~(kShadowAlign - 1);
  uint16_t* shadow_begin = MemToShadow(begin);
  uint16_t* shadow_end = MemToShadow(end - 1) + 1;

  ShadowWrite sw(shadow_begin, shadow_end);
  uint16_t sv_begin = ((begin + kShadowAlign - cfi_check) >> kCfiCheckGranularity) + kRegularShadowMin;

  // With each step of the loop below, __cfi_check address computation base is increased by
  // 2**ShadowGranularity.
  // To compensate for that, each next shadow value must be increased by 2**ShadowGranularity /
  // 2**CfiCheckGranularity.
  uint16_t sv_step = 1 << (kShadowGranularity - kCfiCheckGranularity);
  uint16_t sv = sv_begin;
  for (uint16_t& s : sw) {
    if (sv < sv_begin) {
      // If shadow value wraps around, also fall back to unchecked. This means the binary is too
      // large. FIXME: consider using a (slow) resolution function instead.
      s = kUncheckedShadow;
      continue;
    }
    // If there is something there already, fall back to unchecked. This may happen in rare cases
    // with MAP_FIXED libraries. FIXME: consider using a (slow) resolution function instead.
    s = (s == kInvalidShadow) ? sv : kUncheckedShadow;
    sv += sv_step;
  }
}

static soinfo* find_libdl(soinfo* solist) {
  for (soinfo* si = solist; si != nullptr; si = si->next) {
    if (strcmp(si->get_soname(), "libdl.so") == 0) {
      return si;
    }
  }
  return nullptr;
}

static uintptr_t soinfo_find_symbol(soinfo* si, const char* s) {
  SymbolName name(s);
  if (const ElfW(Sym)* sym = si->find_symbol_by_name(name, nullptr)) {
    return si->resolve_symbol_address(sym);
  }
  return 0;
}

uintptr_t soinfo_find_cfi_check(soinfo* si) {
  return soinfo_find_symbol(si, "__cfi_check");
}

uintptr_t CFIShadowWriter::MapShadow() {
  void* p =
      mmap(nullptr, kShadowSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  CHECK(p != MAP_FAILED);
  return reinterpret_cast<uintptr_t>(p);
}

bool CFIShadowWriter::AddLibrary(soinfo* si) {
  CHECK(shadow_start != nullptr);
  if (si->base == 0 || si->size == 0) {
    return true;
  }
  uintptr_t cfi_check = soinfo_find_cfi_check(si);
  if (cfi_check == 0) {
    LD_DEBUG(cfi, "[ CFI add 0x%zx + 0x%zx %s ]", static_cast<uintptr_t>(si->base),
         static_cast<uintptr_t>(si->size), si->get_soname());
    AddUnchecked(si->base, si->base + si->size);
    return true;
  }

  LD_DEBUG(cfi, "[ CFI add 0x%zx + 0x%zx %s: 0x%zx ]", static_cast<uintptr_t>(si->base),
       static_cast<uintptr_t>(si->size), si->get_soname(), cfi_check);
#ifdef __arm__
  // Require Thumb encoding.
  if ((cfi_check & 1UL) != 1UL) {
    DL_ERR("__cfi_check in not a Thumb function in the library \"%s\"", si->get_soname());
    return false;
  }
  cfi_check &= ~1UL;
#endif
  if ((cfi_check & (kCfiCheckAlign - 1)) != 0) {
    DL_ERR("unaligned __cfi_check in the library \"%s\"", si->get_soname());
    return false;
  }
  Add(si->base, si->base + si->size, cfi_check);
  return true;
}

// Pass the shadow mapping address to libdl.so. In return, we get an pointer to the location
// libdl.so uses to store the address.
bool CFIShadowWriter::NotifyLibDl(soinfo* solist, uintptr_t p) {
  soinfo* libdl = find_libdl(solist);
  if (libdl == nullptr) {
    DL_ERR("CFI could not find libdl");
    return false;
  }

  uintptr_t cfi_init = soinfo_find_symbol(libdl, "__cfi_init");
  CHECK(cfi_init != 0);
  shadow_start = reinterpret_cast<uintptr_t* (*)(uintptr_t)>(cfi_init)(p);
  CHECK(shadow_start != nullptr);
  CHECK(*shadow_start == p);
  mprotect(shadow_start, page_size(), PROT_READ);
  return true;
}

bool CFIShadowWriter::MaybeInit(soinfo* new_si, soinfo* solist) {
  CHECK(initial_link_done);
  CHECK(shadow_start == nullptr);
  // Check if CFI shadow must be initialized at this time.
  bool found = false;
  if (new_si == nullptr) {
    // This is the case when we've just completed the initial link. There may have been earlier
    // calls to MaybeInit that were skipped. Look though the entire solist.
    for (soinfo* si = solist; si != nullptr; si = si->next) {
      if (soinfo_find_cfi_check(si)) {
        found = true;
        break;
      }
    }
  } else {
    // See if the new library uses CFI.
    found = soinfo_find_cfi_check(new_si);
  }

  // Nothing found.
  if (!found) {
    return true;
  }

  // Init shadow and add all currently loaded libraries (not just the new ones).
  if (!NotifyLibDl(solist, MapShadow()))
    return false;
  for (soinfo* si = solist; si != nullptr; si = si->next) {
    if (!AddLibrary(si))
      return false;
  }
  FixupVmaName();
  return true;
}

bool CFIShadowWriter::AfterLoad(soinfo* si, soinfo* solist) {
  if (!initial_link_done) {
    // Too early.
    return true;
  }

  if (shadow_start == nullptr) {
    return MaybeInit(si, solist);
  }

  // Add the new library to the CFI shadow.
  if (!AddLibrary(si))
    return false;
  FixupVmaName();
  return true;
}

void CFIShadowWriter::BeforeUnload(soinfo* si) {
  if (shadow_start == nullptr) return;
  if (si->base == 0 || si->size == 0) return;
  LD_DEBUG(cfi, "[ CFI remove 0x%zx + 0x%zx: %s ]", static_cast<uintptr_t>(si->base),
           static_cast<uintptr_t>(si->size), si->get_soname());
  AddInvalid(si->base, si->base + si->size);
  FixupVmaName();
}

bool CFIShadowWriter::InitialLinkDone(soinfo* solist) {
  CHECK(!initial_link_done);
  initial_link_done = true;
  return MaybeInit(nullptr, solist);
}

// Find __cfi_check in the caller and let it handle the problem. Since caller_pc is likely not a
// valid CFI target, we can not use CFI shadow for lookup. This does not need to be fast, do the
// regular symbol lookup.
void CFIShadowWriter::CfiFail(uint64_t CallSiteTypeId, void* Ptr, void* DiagData, void* CallerPc) {
  soinfo* si = find_containing_library(CallerPc);
  if (!si) {
    __builtin_trap();
  }

  uintptr_t cfi_check = soinfo_find_cfi_check(si);
  if (!cfi_check) {
    __builtin_trap();
  }

  reinterpret_cast<CFICheckFn>(cfi_check)(CallSiteTypeId, Ptr, DiagData);
}
```