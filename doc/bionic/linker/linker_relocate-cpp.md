Response:
Let's break down the thought process for analyzing this `linker_relocate.cpp` file and generating the detailed response.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of `linker_relocate.cpp` within the Android Bionic context. Key aspects include: functionality, relationship to Android, implementation details of libc functions, dynamic linker aspects (with SO layout and linking process), logical reasoning, common errors, and how Android Framework/NDK reach this code, including Frida hooking.

**2. Initial Skim and Identification of Core Responsibilities:**

A quick read of the code reveals its primary purpose: **relocation of shared libraries (DSOs/SOs) during the dynamic linking process.**  Keywords like "relocate," "linker," "soinfo," "ElfW," and various relocation types (e.g., `R_GENERIC_ABSOLUTE`, `R_GENERIC_RELATIVE`) immediately confirm this. The inclusion of TLS relocation types (`R_GENERIC_TLS_DTPMOD`, etc.) indicates it handles thread-local storage as well.

**3. Deconstructing Functionality (High-Level):**

I mentally (or could actually) create a list of the main tasks this code performs:

* **Iterating through relocations:**  The code iterates over relocation entries within the ELF file.
* **Symbol lookup:** It resolves symbolic references in the relocation entries by searching through the loaded shared libraries.
* **Applying relocations:**  Based on the relocation type and the resolved symbol address, it modifies memory locations within the shared library.
* **Handling different relocation types:** The code explicitly addresses various ELF relocation types.
* **Special handling for IFUNCs:**  It deals with indirect function calls (IFUNCs).
* **TLS relocation:** Specific logic exists for handling thread-local storage relocations.
* **Performance optimizations:**  The `RelocMode` enum and template functions suggest an attempt to optimize common relocation scenarios.
* **Debugging and Statistics:**  The `LD_DEBUG` and `linker_stats` indicate debugging and performance tracking features.

**4. Connecting to Android Functionality:**

The crucial link is the **dynamic linker (`/system/bin/linker` or `/system/bin/linker64`)**. This file is a core component of the dynamic linker in Bionic. The dynamic linker is responsible for loading shared libraries into memory when an application starts or when `dlopen()` is called. Relocation is a *fundamental step* in this process, making the code directly related to the correct execution of Android applications and libraries.

**5. Identifying Key Data Structures:**

Understanding the data structures involved is essential:

* **`soinfo`:** Represents a loaded shared library in memory. It contains information like the base address, symbol table, string table, and relocation tables.
* **`ElfW(Rel)`/`ElfW(Rela)`:**  Structures defining a single relocation entry.
* **`ElfW(Sym)`:** Structure representing a symbol in the symbol table.
* **`VersionTracker`:**  Handles symbol versioning.
* **`SymbolLookupList`:**  Manages the search order for symbols.
* **`Relocator`:** A class to encapsulate the state needed during the relocation process.

**6. Delving into Implementation Details (libc functions):**

The request specifically asks about libc functions. A careful scan reveals these:

* **`async_safe_fatal`:** Used for fatal errors that can occur in asynchronous contexts (important for signal safety).
* **`__libc_shared_globals()`:** Accesses global data managed by libc, specifically for TLS information.

I would then explain how these are likely implemented (e.g., `async_safe_fatal` using `write` to stderr and then `abort` or `_exit`).

**7. Explaining Dynamic Linker Aspects:**

This requires understanding the linking process:

* **SO Layout:**  Describing the typical ELF structure of a shared library (.text, .data, .bss, .dynamic, .dynsym, .dynstr, .rel.dyn, .rela.dyn, .plt, .got).
* **Linking Process:**  Outlining the steps: Loading, Symbol Resolution, Relocation. Emphasize the role of the dynamic linker and how `linker_relocate.cpp` fits into the relocation phase.

**8. Logical Reasoning and Examples:**

Consider specific relocation types and what needs to happen. For `R_GENERIC_ABSOLUTE`, the linker needs to add the symbol's address to a location in the SO. For `R_GENERIC_RELATIVE`, it adds the load bias. Create simple "before and after" scenarios.

**9. Common Usage Errors:**

Think about what can go wrong in practice:

* **Missing symbols:**  A common error leading to "cannot locate symbol" messages.
* **ABI incompatibility:**  Linking against libraries built with different assumptions.
* **Incorrect linker flags:** Leading to unexpected relocation behavior.
* **Incorrect library paths:** Preventing the linker from finding necessary libraries.

**10. Tracing the Execution Path (Framework/NDK):**

Start from the application launch:

* **Android OS starts the app process.**
* **`zygote` forks the process.**
* **The dynamic linker is invoked to load the application's dependencies.**
* **When a shared library needs to be loaded, the dynamic linker calls functions within `linker_relocate.cpp` to perform the necessary relocations.**

For NDK, the process is similar, but the developer explicitly includes shared libraries.

**11. Frida Hooking:**

Identify relevant functions for hooking (e.g., `soinfo::relocate`, `process_relocation_impl`). Provide a basic Frida script demonstrating how to intercept these calls and log information.

**12. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use formatting (bolding, code blocks) to improve readability.

**Self-Correction/Refinement during the thought process:**

* **Initially, I might focus too narrowly on specific relocation types.** I need to ensure I cover the broader purpose and context.
* **I might forget to explicitly mention the dynamic linker's role.**  This is crucial.
* **The explanation of libc function implementation might be too superficial.** I need to provide more detail.
* **The Frida example should be practical and demonstrate a useful debugging technique.**

By following this structured approach, combining code analysis with knowledge of Android's internals and dynamic linking concepts, I can generate a comprehensive and accurate response to the request.
好的，让我们来详细分析一下 `bionic/linker/linker_relocate.cpp` 这个文件的功能。

**文件功能概述：**

`linker_relocate.cpp` 文件的核心功能是 **执行共享库 (Shared Object, SO) 的重定位 (Relocation) 操作**。重定位是动态链接器在加载共享库到内存时，修正代码和数据中对外部符号引用的过程，确保程序能够正确地访问和调用其他模块的函数和数据。

**与 Android 功能的关系及举例：**

这个文件是 Android 动态链接器 (linker) 的关键组成部分，因此与 Android 系统的核心功能息息相关。几乎每一个使用动态链接的 Android 应用和系统服务都会涉及到这个文件的代码执行。

**举例说明：**

1. **应用启动:** 当你启动一个 Android 应用时，操作系统会创建一个新的进程，并将应用的主执行文件加载到内存中。应用的执行文件通常会依赖一些共享库 (例如 libc.so, libm.so, libandroid.so 等)。动态链接器负责加载这些共享库，而 `linker_relocate.cpp` 中的代码则负责修正这些共享库中对其他库或自身内部符号的引用。例如，`libc.so` 中的 `printf` 函数可能需要访问 `libm.so` 中的数学函数，重定位过程会确保 `printf` 能够找到正确的 `libm.so` 函数地址。

2. **`dlopen()` 函数:** Android 应用可以使用 `dlopen()` 函数在运行时动态加载共享库。当 `dlopen()` 被调用时，动态链接器会加载指定的 SO 文件，并使用 `linker_relocate.cpp` 中的代码来完成该 SO 的重定位。

3. **系统服务启动:** Android 系统服务 (例如 `system_server`) 也依赖于大量的共享库。在系统启动过程中，动态链接器会加载这些服务所需的 SO 文件，并进行重定位。

**详细解释每一个 libc 函数的功能是如何实现的：**

在这个文件中，直接调用的 libc 函数不多，主要是以下几个：

* **`async_safe_fatal(const char* fmt, ...)`:**  这是一个 Bionic 提供的用于在异步信号处理程序中安全地终止程序的函数。它的实现通常会避免调用可能导致死锁或数据竞争的函数。在 `linker_relocate.cpp` 中，当检测到严重的内部错误 (例如字符串表越界) 时，会调用此函数来立即终止进程，防止进一步的错误发生。其内部实现可能使用 `write()` 系统调用直接向 `stderr` 写入错误信息，然后调用 `_exit()` 系统调用来终止进程。

* **`__libc_shared_globals()`:**  这个函数返回一个指向 libc 全局数据结构的指针。这个结构体包含了 libc 内部使用的各种全局变量，例如线程局部存储 (TLS) 的相关信息。在 `linker_relocate.cpp` 中，它被用来获取静态 TLS 的布局信息，以便正确地处理 TLS 相关的重定位。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**SO 布局样本：**

一个典型的 Android 共享库 (SO) 的 ELF 文件布局如下 (简化版本)：

```
ELF Header
Program Headers (描述内存段的加载信息)
Section Headers (描述各个 section 的信息)

.text         (代码段，包含可执行指令)
.rodata       (只读数据段，例如字符串常量)
.data         (已初始化的可写数据段)
.bss          (未初始化的可写数据段)

.dynamic      (动态链接信息，包含 DT_NEEDED, DT_SYMTAB, DT_STRTAB, DT_REL/RELA 等)
.dynsym       (动态符号表)
.dynstr       (动态字符串表)
.hash         (符号哈希表，用于加速符号查找)
.gnu.hash     (GNU 风格的符号哈希表)

.rel.dyn      (重定位表，用于 .data 和 .bss 段)
.rela.dyn     (带显式 addend 的重定位表，用于 .data 和 .bss 段)
.rel.plt      (PLT (Procedure Linkage Table) 的重定位表)
.rela.plt     (带显式 addend 的 PLT 重定位表)

.plt          (PLT 代码段，用于延迟绑定)
.got          (GOT (Global Offset Table)，用于存放全局变量和函数地址)
.got.plt      (GOT 的一部分，专门用于 PLT 条目)

... (其他 section)
```

**链接的处理过程：**

1. **加载 SO 文件:** 动态链接器首先将 SO 文件的各个段 (segment) 加载到内存中。Program Headers 提供了加载所需的内存地址和大小信息。

2. **解析 .dynamic 段:** 动态链接器解析 SO 文件的 `.dynamic` 段，获取动态链接所需的各种信息，例如依赖的共享库列表 (`DT_NEEDED`)、符号表地址 (`DT_SYMTAB`)、字符串表地址 (`DT_STRTAB`)、重定位表地址和大小 (`DT_REL`, `DT_RELSZ`, `DT_RELA`, `DT_RELASZ`) 等。

3. **符号查找:** 当遇到需要重定位的条目时，动态链接器会根据重定位类型和符号索引，在当前 SO 的动态符号表 (`.dynsym`) 以及已加载的其他共享库的符号表中查找对应的符号。`linker_relocate.cpp` 中的 `lookup_symbol` 函数就负责这个过程。

4. **应用重定位:**  `linker_relocate.cpp` 中的 `process_relocation_impl` 函数根据重定位类型 (例如 `R_GENERIC_ABSOLUTE`, `R_GENERIC_RELATIVE`, `R_GENERIC_GLOB_DAT`, `R_GENERIC_JUMP_SLOT` 等) 和查找到的符号地址，计算出需要写入到内存中的最终地址，并将其写入到相应的内存位置。

   * **`R_GENERIC_ABSOLUTE`:** 将符号的绝对地址写入到指定位置。
   * **`R_GENERIC_RELATIVE`:** 将 SO 的加载基址加上一个偏移量写入到指定位置，用于实现与位置无关的代码 (PIC)。
   * **`R_GENERIC_GLOB_DAT`:** 将全局数据符号的地址写入到 GOT 表项中。
   * **`R_GENERIC_JUMP_SLOT`:** 将函数的地址写入到 PLT 表项中，用于延迟绑定。

5. **处理 TLS 重定位:**  `linker_relocate.cpp` 中专门的代码处理线程局部存储 (TLS) 相关的重定位，例如 `R_GENERIC_TLS_DTPMOD`, `R_GENERIC_TLS_DTPREL`, `R_GENERIC_TLS_TPREL`。这些重定位类型用于确定线程特定数据的地址。

**假设输入与输出 (逻辑推理)：**

假设我们有一个简单的共享库 `libtest.so`，其中包含一个全局变量 `global_var` 和一个函数 `test_func`。另一个共享库 `libapp.so` 引用了 `libtest.so` 中的 `global_var`。

**libtest.so 的相关部分：**

* **`.dynsym`:** 包含 `global_var` 的符号信息 (地址为占位符，例如 0x1000)。
* **`.rela.dyn` (或其他重定位 section):**  包含针对 `global_var` 的重定位条目，类型可能是 `R_GENERIC_GLOBAL_DAT`，目标地址指向 `libapp.so` 中用于存放 `global_var` 地址的 GOT 表项。

**libapp.so 的相关部分：**

* **`.got`:**  包含 `global_var` 的 GOT 表项 (初始值为 0)。
* **`.text`:**  包含访问 `global_var` 的代码，例如 `load [GOT + offset]`。

**链接处理过程：**

1. 动态链接器加载 `libtest.so` 和 `libapp.so`。
2. 当处理 `libapp.so` 中对 `global_var` 的重定位时：
   * `lookup_symbol` 会在 `libtest.so` 的符号表中找到 `global_var` 的符号信息。
   * `process_relocation_impl` 根据 `R_GENERIC_GLOBAL_DAT` 类型，将 `libtest.so` 中 `global_var` 的实际加载地址 (例如 `libtest.so` 的加载基址 + 0x1000) 写入到 `libapp.so` 的 GOT 表中对应的表项。

**假设输入与输出：**

* **输入 (重定位条目):**  `r_offset` 指向 `libapp.so` 的 GOT 表项地址， `r_info` 表示 `R_GENERIC_GLOBAL_DAT` 类型和 `global_var` 的符号索引。
* **输入 (符号表):** `libtest.so` 的符号表中 `global_var` 的 `st_value` 是 0x1000。
* **输入 (加载基址):** `libtest.so` 的加载基址是 0x70000000。
* **输出 (内存修改):**  `libapp.so` 的 GOT 表项中的值被修改为 0x70001000。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **找不到符号 (Symbol Not Found):**  这是最常见的错误。如果一个共享库依赖于另一个共享库中的符号，但链接器在加载时找不到该符号，就会报错。
   * **原因:**  依赖的库没有被加载，或者符号在依赖库中不是全局可见的。
   * **示例:**  你的应用依赖于 `libcrypto.so` 中的某个函数，但你没有正确地将 `libcrypto.so` 打包到你的 APK 中，或者该函数在 `libcrypto.so` 中被声明为 `static`。

2. **ABI 不兼容:** 如果链接时使用的共享库版本与运行时加载的版本不兼容，可能会导致重定位错误或运行时崩溃。
   * **原因:**  不同版本的库，其符号的布局、调用约定或语义可能发生变化。
   * **示例:**  你的应用在编译时链接了 Android SDK 的某个版本的 `libc.so`，但在运行时，设备上安装的是另一个版本的 Android，导致 `libc.so` 的内部结构发生了变化。

3. **循环依赖:**  如果两个或多个共享库相互依赖，可能会导致加载和重定位的顺序问题。
   * **原因:**  链接器需要按照一定的顺序加载和重定位库，循环依赖会使得这个顺序无法确定。
   * **示例:** `libA.so` 依赖 `libB.so`，而 `libB.so` 又依赖 `libA.so`。

4. **文本重定位 (Text Relocations):**  在现代 Android 系统中，文本重定位是被禁止的，因为它可能导致安全问题。如果一个共享库需要在代码段进行重定位，链接器会报错。
   * **原因:**  文本重定位意味着代码段不是只读的，攻击者可能利用这个漏洞修改代码。
   * **示例:**  编译共享库时未使用 `-fPIC` 选项，导致生成了需要文本重定位的代码。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

**Android Framework 到 `linker_relocate.cpp` 的路径：**

1. **应用启动:** 当 Android Framework 启动一个新的应用进程时，`zygote` 进程会 fork 出一个新的进程。
2. **`app_process` / `app_process64`:**  新进程执行的是 `app_process` 或 `app_process64` 可执行文件，这是 Android 应用程序框架的入口点。
3. **动态链接器调用:**  `app_process` 在启动时，其自身依赖的共享库 (例如 `libandroid_runtime.so`, `libbinder.so` 等) 需要被加载。操作系统会调用动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 来完成这个过程。
4. **共享库加载和重定位:** 动态链接器会读取这些 SO 文件的 ELF 头和段信息，并调用 `linker_relocate.cpp` 中的函数来执行重定位操作，修正符号引用。

**NDK 应用到 `linker_relocate.cpp` 的路径：**

1. **NDK 应用启动:** 当一个使用 NDK 开发的 Android 应用启动时，其主执行文件 (通常包含 native 代码) 会被加载。
2. **依赖的 Native 库加载:**  NDK 应用通常会依赖一些 native 共享库 (例如你自定义的 `.so` 文件，或者 Android 系统提供的 native 库)。
3. **动态链接器调用:**  与 Framework 应用类似，操作系统会调用动态链接器来加载这些 native 共享库。
4. **重定位:** 动态链接器会使用 `linker_relocate.cpp` 中的代码来重定位这些 native 库。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `soinfo::relocate` 函数的示例，可以帮助你调试重定位过程：

```javascript
function hook_relocate() {
  const linker_module = Process.getModuleByName("linker64"); // 或者 "linker" 对于 32 位
  if (linker_module) {
    const relocate_addr = linker_module.findSymbolByName("_ZN6soinfo8relocateERK16SymbolLookupList").address; // 获取 soinfo::relocate 的地址，可能需要根据 Android 版本调整符号名

    if (relocate_addr) {
      Interceptor.attach(relocate_addr, {
        onEnter: function (args) {
          const soinfo_ptr = this.context.r0; // 或者其他寄存器，取决于架构和调用约定
          const soinfo = new NativePointer(soinfo_ptr);
          const realpath_ptr = soinfo.readPointer(); // 假设 soinfo 的第一个字段是指向 realpath 的指针
          const realpath = realpath_ptr.readCString();
          console.log("[+] Hooking soinfo::relocate for: " + realpath);
        },
        onLeave: function (retval) {
          console.log("[+] soinfo::relocate returned: " + retval);
        }
      });
    } else {
      console.log("[-] Failed to find soinfo::relocate symbol.");
    }
  } else {
    console.log("[-] Failed to find linker module.");
  }
}

setImmediate(hook_relocate);
```

**解释 Frida 代码：**

1. **`Process.getModuleByName("linker64")`:** 获取动态链接器模块的句柄。
2. **`linker_module.findSymbolByName("_ZN6soinfo8relocateERK16SymbolLookupList")`:**  查找 `soinfo::relocate` 函数的符号地址。你需要根据 Android 版本和架构调整符号名。可以使用 `adb shell cat /proc/pid/maps` 或 `readelf -sW /system/bin/linker64` 来查找确切的符号名。
3. **`Interceptor.attach(relocate_addr, ...)`:**  拦截 `soinfo::relocate` 函数的调用。
4. **`onEnter`:** 在函数执行前被调用。我们在这里获取 `soinfo` 对象的指针，并尝试读取 SO 文件的路径，然后打印日志。
5. **`onLeave`:** 在函数执行后被调用。我们在这里打印函数的返回值。

**调试步骤：**

1. 将上述 Frida 脚本保存为 `.js` 文件 (例如 `hook_relocate.js`)。
2. 使用 Frida 连接到目标 Android 设备或模拟器上的应用进程：
   ```bash
   frida -U -f <your_package_name> -l hook_relocate.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_package_name> -l hook_relocate.js
   ```
3. 当动态链接器加载共享库并调用 `soinfo::relocate` 时，你将在 Frida 的控制台中看到相应的日志输出，包括正在重定位的 SO 文件的路径。

**更细粒度的 Hooking：**

你还可以 Hook `process_relocation_impl` 函数来观察每个重定位条目的处理过程。这需要更复杂的 Frida 脚本来解析重定位条目的结构和相关信息。

希望这些详细的解释能够帮助你理解 `linker_relocate.cpp` 的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linker_relocate.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include "linker_relocate.h"

#include <elf.h>
#include <link.h>

#include <type_traits>

#include "linker.h"
#include "linker_debug.h"
#include "linker_globals.h"
#include "linker_gnu_hash.h"
#include "linker_phdr.h"
#include "linker_relocs.h"
#include "linker_reloc_iterators.h"
#include "linker_sleb128.h"
#include "linker_soinfo.h"
#include "private/bionic_globals.h"

#include <platform/bionic/mte.h>

static bool is_tls_reloc(ElfW(Word) type) {
  switch (type) {
    case R_GENERIC_TLS_DTPMOD:
    case R_GENERIC_TLS_DTPREL:
    case R_GENERIC_TLS_TPREL:
#if defined(R_GENERIC_TLSDESC)
    case R_GENERIC_TLSDESC:
#endif
      return true;
    default:
      return false;
  }
}

class Relocator {
 public:
  Relocator(const VersionTracker& version_tracker, const SymbolLookupList& lookup_list)
      : version_tracker(version_tracker), lookup_list(lookup_list)
  {}

  soinfo* si = nullptr;
  const char* si_strtab = nullptr;
  size_t si_strtab_size = 0;
  ElfW(Sym)* si_symtab = nullptr;

  const VersionTracker& version_tracker;
  const SymbolLookupList& lookup_list;

  // Cache key
  ElfW(Word) cache_sym_val = 0;
  // Cache value
  const ElfW(Sym)* cache_sym = nullptr;
  soinfo* cache_si = nullptr;

  std::vector<TlsDynamicResolverArg>* tlsdesc_args;
  std::vector<std::pair<TlsDescriptor*, size_t>> deferred_tlsdesc_relocs;
  size_t tls_tp_base = 0;

  __attribute__((always_inline))
  const char* get_string(ElfW(Word) index) {
    if (__predict_false(index >= si_strtab_size)) {
      async_safe_fatal("%s: strtab out of bounds error; STRSZ=%zd, name=%d",
                       si->get_realpath(), si_strtab_size, index);
    }
    return si_strtab + index;
  }
};

template <bool DoLogging>
__attribute__((always_inline))
static inline bool lookup_symbol(Relocator& relocator, uint32_t r_sym, const char* sym_name,
                                 soinfo** found_in, const ElfW(Sym)** sym) {
  if (r_sym == relocator.cache_sym_val) {
    *found_in = relocator.cache_si;
    *sym = relocator.cache_sym;
    count_relocation_if<DoLogging>(kRelocSymbolCached);
  } else {
    const version_info* vi = nullptr;
    if (!relocator.si->lookup_version_info(relocator.version_tracker, r_sym, sym_name, &vi)) {
      return false;
    }

    soinfo* local_found_in = nullptr;
    const ElfW(Sym)* local_sym = soinfo_do_lookup(sym_name, vi, &local_found_in, relocator.lookup_list);

    relocator.cache_sym_val = r_sym;
    relocator.cache_si = local_found_in;
    relocator.cache_sym = local_sym;
    *found_in = local_found_in;
    *sym = local_sym;
  }

  if (*sym == nullptr) {
    if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) != STB_WEAK) {
      DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, relocator.si->get_realpath());
      return false;
    }
  }

  count_relocation_if<DoLogging>(kRelocSymbol);
  return true;
}

enum class RelocMode {
  // Fast path for JUMP_SLOT relocations.
  JumpTable,
  // Fast path for typical relocations: ABSOLUTE, GLOB_DAT, or RELATIVE.
  Typical,
  // Handle all relocation types, relocations in text sections, and statistics/tracing.
  General,
};

struct linker_stats_t {
  int count[kRelocMax];
};

static linker_stats_t linker_stats;

void count_relocation(RelocationKind kind) {
  ++linker_stats.count[kind];
}

void print_linker_stats() {
  LD_DEBUG(statistics,
           "RELO STATS: %s: %d abs, %d rel, %d symbol (%d cached)",
           g_argv[0],
           linker_stats.count[kRelocAbsolute],
           linker_stats.count[kRelocRelative],
           linker_stats.count[kRelocSymbol],
           linker_stats.count[kRelocSymbolCached]);
}

static bool process_relocation_general(Relocator& relocator, const rel_t& reloc);

template <RelocMode Mode>
__attribute__((always_inline))
static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
  constexpr bool IsGeneral = Mode == RelocMode::General;

  void* const rel_target = reinterpret_cast<void*>(
      relocator.si->apply_memtag_if_mte_globals(reloc.r_offset + relocator.si->load_bias));
  const uint32_t r_type = ELFW(R_TYPE)(reloc.r_info);
  const uint32_t r_sym = ELFW(R_SYM)(reloc.r_info);

  soinfo* found_in = nullptr;
  const ElfW(Sym)* sym = nullptr;
  const char* sym_name = nullptr;
  ElfW(Addr) sym_addr = 0;

  if (r_sym != 0) {
    sym_name = relocator.get_string(relocator.si_symtab[r_sym].st_name);
  }

  // While relocating a DSO with text relocations (obsolete and 32-bit only), the .text segment is
  // writable (but not executable). To call an ifunc, temporarily remap the segment as executable
  // (but not writable). Then switch it back to continue applying relocations in the segment.
#if defined(__LP64__)
  const bool handle_text_relocs = false;
  auto protect_segments = []() { return true; };
  auto unprotect_segments = []() { return true; };
#else
  const bool handle_text_relocs = IsGeneral && relocator.si->has_text_relocations;
  auto protect_segments = [&]() {
    // Make .text executable.
    if (phdr_table_protect_segments(relocator.si->phdr, relocator.si->phnum,
                                    relocator.si->load_bias, relocator.si->should_pad_segments(),
                                    relocator.si->should_use_16kib_app_compat()) < 0) {
      DL_ERR("can't protect segments for \"%s\": %m", relocator.si->get_realpath());
      return false;
    }
    return true;
  };
  auto unprotect_segments = [&]() {
    // Make .text writable.
    if (phdr_table_unprotect_segments(relocator.si->phdr, relocator.si->phnum,
                                      relocator.si->load_bias, relocator.si->should_pad_segments(),
                                      relocator.si->should_use_16kib_app_compat()) < 0) {
      DL_ERR("can't unprotect loadable segments for \"%s\": %m",
             relocator.si->get_realpath());
      return false;
    }
    return true;
  };
#endif

  // Skip symbol lookup for R_GENERIC_NONE relocations.
  if (__predict_false(r_type == R_GENERIC_NONE)) {
    LD_DEBUG(reloc && IsGeneral, "RELO NONE");
    return true;
  }

#if defined(USE_RELA)
  auto get_addend_rel   = [&]() -> ElfW(Addr) { return reloc.r_addend; };
  auto get_addend_norel = [&]() -> ElfW(Addr) { return reloc.r_addend; };
#else
  auto get_addend_rel   = [&]() -> ElfW(Addr) { return *static_cast<ElfW(Addr)*>(rel_target); };
  auto get_addend_norel = [&]() -> ElfW(Addr) { return 0; };
#endif

  if (!IsGeneral && __predict_false(is_tls_reloc(r_type))) {
    // Always process TLS relocations using the slow code path, so that STB_LOCAL symbols are
    // diagnosed, and ifunc processing is skipped.
    return process_relocation_general(relocator, reloc);
  }

  if (IsGeneral && is_tls_reloc(r_type)) {
    if (r_sym == 0) {
      // By convention in ld.bfd and lld, an omitted symbol on a TLS relocation
      // is a reference to the current module.
      found_in = relocator.si;
    } else if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) == STB_LOCAL) {
      // In certain situations, the Gold linker accesses a TLS symbol using a
      // relocation to an STB_LOCAL symbol in .dynsym of either STT_SECTION or
      // STT_TLS type. Bionic doesn't support these relocations, so issue an
      // error. References:
      //  - https://groups.google.com/d/topic/generic-abi/dJ4_Y78aQ2M/discussion
      //  - https://sourceware.org/bugzilla/show_bug.cgi?id=17699
      sym = &relocator.si_symtab[r_sym];
      auto sym_type = ELF_ST_TYPE(sym->st_info);
      if (sym_type == STT_SECTION) {
        DL_ERR("unexpected TLS reference to local section in \"%s\": sym type %d, rel type %u",
               relocator.si->get_realpath(), sym_type, r_type);
      } else {
        DL_ERR(
            "unexpected TLS reference to local symbol \"%s\" in \"%s\": sym type %d, rel type %u",
            sym_name, relocator.si->get_realpath(), sym_type, r_type);
      }
      return false;
    } else if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) {
      return false;
    }
    if (found_in != nullptr && found_in->get_tls() == nullptr) {
      // sym_name can be nullptr if r_sym is 0. A linker should never output an ELF file like this.
      DL_ERR("TLS relocation refers to symbol \"%s\" in solib \"%s\" with no TLS segment",
             sym_name, found_in->get_realpath());
      return false;
    }
    if (sym != nullptr) {
      if (ELF_ST_TYPE(sym->st_info) != STT_TLS) {
        // A toolchain should never output a relocation like this.
        DL_ERR("reference to non-TLS symbol \"%s\" from TLS relocation in \"%s\"",
               sym_name, relocator.si->get_realpath());
        return false;
      }
      sym_addr = sym->st_value;
    }
  } else {
    if (r_sym == 0) {
      // Do nothing.
    } else {
      if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) return false;
      if (sym != nullptr) {
        const bool should_protect_segments = handle_text_relocs &&
                                             found_in == relocator.si &&
                                             ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC;
        if (should_protect_segments && !protect_segments()) return false;
        sym_addr = found_in->resolve_symbol_address(sym);
        if (should_protect_segments && !unprotect_segments()) return false;
      } else if constexpr (IsGeneral) {
        // A weak reference to an undefined symbol. We typically use a zero symbol address, but
        // use the relocation base for PC-relative relocations, so that the value written is zero.
        switch (r_type) {
#if defined(__x86_64__)
          case R_X86_64_PC32:
            sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
            break;
#elif defined(__i386__)
          case R_386_PC32:
            sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
            break;
#endif
        }
      }
    }
  }

  if constexpr (IsGeneral || Mode == RelocMode::JumpTable) {
    if (r_type == R_GENERIC_JUMP_SLOT) {
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_norel();
      LD_DEBUG(reloc && IsGeneral, "RELO JMP_SLOT %16p <- %16p %s",
               rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    }
  }

  if constexpr (IsGeneral || Mode == RelocMode::Typical) {
    // Almost all dynamic relocations are of one of these types, and most will be
    // R_GENERIC_ABSOLUTE. The platform typically uses RELR instead, but R_GENERIC_RELATIVE is
    // common in non-platform binaries.
    if (r_type == R_GENERIC_ABSOLUTE) {
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      if (found_in) sym_addr = found_in->apply_memtag_if_mte_globals(sym_addr);
      const ElfW(Addr) result = sym_addr + get_addend_rel();
      LD_DEBUG(reloc && IsGeneral, "RELO ABSOLUTE %16p <- %16p %s",
               rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    } else if (r_type == R_GENERIC_GLOB_DAT) {
      // The i386 psABI specifies that R_386_GLOB_DAT doesn't have an addend. The ARM ELF ABI
      // document (IHI0044F) specifies that R_ARM_GLOB_DAT has an addend, but Bionic isn't adding
      // it.
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      if (found_in) sym_addr = found_in->apply_memtag_if_mte_globals(sym_addr);
      const ElfW(Addr) result = sym_addr + get_addend_norel();
      LD_DEBUG(reloc && IsGeneral, "RELO GLOB_DAT %16p <- %16p %s",
               rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    } else if (r_type == R_GENERIC_RELATIVE) {
      // In practice, r_sym is always zero, but if it weren't, the linker would still look up the
      // referenced symbol (and abort if the symbol isn't found), even though it isn't used.
      count_relocation_if<IsGeneral>(kRelocRelative);
      ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();
      // MTE globals reuses the place bits for additional tag-derivation metadata for
      // R_AARCH64_RELATIVE relocations, which makes it incompatible with
      // `-Wl,--apply-dynamic-relocs`. This is enforced by lld, however there's nothing stopping
      // Android binaries (particularly prebuilts) from building with this linker flag if they're
      // not built with MTE globals. Thus, don't use the new relocation semantics if this DSO
      // doesn't have MTE globals.
      if (relocator.si->should_tag_memtag_globals()) {
        int64_t* place = static_cast<int64_t*>(rel_target);
        int64_t offset = *place;
        result = relocator.si->apply_memtag_if_mte_globals(result + offset) - offset;
      }
      LD_DEBUG(reloc && IsGeneral, "RELO RELATIVE %16p <- %16p",
               rel_target, reinterpret_cast<void*>(result));
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    }
  }

  if constexpr (!IsGeneral) {
    // Almost all relocations are handled above. Handle the remaining relocations below, in a
    // separate function call. The symbol lookup will be repeated, but the result should be served
    // from the 1-symbol lookup cache.
    return process_relocation_general(relocator, reloc);
  }

  switch (r_type) {
    case R_GENERIC_IRELATIVE:
      // In the linker, ifuncs are called as soon as possible so that string functions work. We must
      // not call them again. (e.g. On arm32, resolving an ifunc changes the meaning of the addend
      // from a resolver function to the implementation.)
      if (!relocator.si->is_linker()) {
        count_relocation_if<IsGeneral>(kRelocRelative);
        const ElfW(Addr) ifunc_addr = relocator.si->load_bias + get_addend_rel();
        LD_DEBUG(reloc && IsGeneral, "RELO IRELATIVE %16p <- %16p",
                 rel_target, reinterpret_cast<void*>(ifunc_addr));
        if (handle_text_relocs && !protect_segments()) return false;
        const ElfW(Addr) result = call_ifunc_resolver(ifunc_addr);
        if (handle_text_relocs && !unprotect_segments()) return false;
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;
    case R_GENERIC_COPY:
      // Copy relocations allow read-only data or code in a non-PIE executable to access a
      // variable from a DSO. The executable reserves extra space in its .bss section, and the
      // linker copies the variable into the extra space. The executable then exports its copy
      // to interpose the copy in the DSO.
      //
      // Bionic only supports PIE executables, so copy relocations aren't supported. The ARM and
      // AArch64 ABI documents only allow them for ET_EXEC (non-PIE) objects. See IHI0056B and
      // IHI0044F.
      DL_ERR("%s COPY relocations are not supported", relocator.si->get_realpath());
      return false;
    case R_GENERIC_TLS_TPREL:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        ElfW(Addr) tpoff = 0;
        if (found_in == nullptr) {
          // Unresolved weak relocation. Leave tpoff at 0 to resolve
          // &weak_tls_symbol to __get_tls().
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          const TlsModule& mod = get_tls_module(found_in->get_tls()->module_id);
          if (mod.static_offset != SIZE_MAX) {
            tpoff += mod.static_offset - relocator.tls_tp_base;
          } else {
            DL_ERR("TLS symbol \"%s\" in dlopened \"%s\" referenced from \"%s\" using IE access model",
                   sym_name, found_in->get_realpath(), relocator.si->get_realpath());
            return false;
          }
        }
        tpoff += sym_addr + get_addend_rel();
        LD_DEBUG(reloc && IsGeneral, "RELO TLS_TPREL %16p <- %16p %s",
                 rel_target, reinterpret_cast<void*>(tpoff), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = tpoff;
      }
      break;
    case R_GENERIC_TLS_DTPMOD:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        size_t module_id = 0;
        if (found_in == nullptr) {
          // Unresolved weak relocation. Evaluate the module ID to 0.
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          module_id = found_in->get_tls()->module_id;
          CHECK(module_id != kTlsUninitializedModuleId);
        }
        LD_DEBUG(reloc && IsGeneral, "RELO TLS_DTPMOD %16p <- %zu %s",
                 rel_target, module_id, sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = module_id;
      }
      break;
    case R_GENERIC_TLS_DTPREL:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) result = sym_addr + get_addend_rel() - TLS_DTV_OFFSET;
        LD_DEBUG(reloc && IsGeneral, "RELO TLS_DTPREL %16p <- %16p %s",
                 rel_target, reinterpret_cast<void*>(result), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;

#if defined(__aarch64__) || defined(__riscv)
    // Bionic currently implements TLSDESC for arm64 and riscv64. This implementation should work
    // with other architectures, as long as the resolver functions are implemented.
    case R_GENERIC_TLSDESC:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        ElfW(Addr) addend = reloc.r_addend;
        TlsDescriptor* desc = static_cast<TlsDescriptor*>(rel_target);
        if (found_in == nullptr) {
          // Unresolved weak relocation.
          desc->func = tlsdesc_resolver_unresolved_weak;
          desc->arg = addend;
          LD_DEBUG(reloc && IsGeneral, "RELO TLSDESC %16p <- unresolved weak, addend 0x%zx %s",
                   rel_target, static_cast<size_t>(addend), sym_name);
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          size_t module_id = found_in->get_tls()->module_id;
          const TlsModule& mod = get_tls_module(module_id);
          if (mod.static_offset != SIZE_MAX) {
            desc->func = tlsdesc_resolver_static;
            desc->arg = mod.static_offset - relocator.tls_tp_base + sym_addr + addend;
            LD_DEBUG(reloc && IsGeneral, "RELO TLSDESC %16p <- static (0x%zx - 0x%zx + 0x%zx + 0x%zx) %s",
                     rel_target, mod.static_offset, relocator.tls_tp_base,
                     static_cast<size_t>(sym_addr), static_cast<size_t>(addend),
                     sym_name);
          } else {
            relocator.tlsdesc_args->push_back({
              .generation = mod.first_generation,
              .index.module_id = module_id,
              .index.offset = sym_addr + addend,
            });
            // Defer the TLSDESC relocation until the address of the TlsDynamicResolverArg object
            // is finalized.
            relocator.deferred_tlsdesc_relocs.push_back({
              desc, relocator.tlsdesc_args->size() - 1
            });
            const TlsDynamicResolverArg& desc_arg = relocator.tlsdesc_args->back();
            LD_DEBUG(reloc && IsGeneral, "RELO TLSDESC %16p <- dynamic (gen %zu, mod %zu, off %zu) %s",
                     rel_target, desc_arg.generation, desc_arg.index.module_id,
                     desc_arg.index.offset, sym_name);
          }
        }
      }
      break;
#endif  // defined(__aarch64__) || defined(__riscv)

#if defined(__x86_64__)
    case R_X86_64_32:
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      {
        const Elf32_Addr result = sym_addr + reloc.r_addend;
        LD_DEBUG(reloc && IsGeneral, "RELO R_X86_64_32 %16p <- 0x%08x %s",
                 rel_target, result, sym_name);
        *static_cast<Elf32_Addr*>(rel_target) = result;
      }
      break;
    case R_X86_64_PC32:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) target = sym_addr + reloc.r_addend;
        const ElfW(Addr) base = reinterpret_cast<ElfW(Addr)>(rel_target);
        const Elf32_Addr result = target - base;
        LD_DEBUG(reloc && IsGeneral, "RELO R_X86_64_PC32 %16p <- 0x%08x (%16p - %16p) %s",
                 rel_target, result, reinterpret_cast<void*>(target),
                 reinterpret_cast<void*>(base), sym_name);
        *static_cast<Elf32_Addr*>(rel_target) = result;
      }
      break;
#elif defined(__i386__)
    case R_386_PC32:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) target = sym_addr + get_addend_rel();
        const ElfW(Addr) base = reinterpret_cast<ElfW(Addr)>(rel_target);
        const ElfW(Addr) result = target - base;
        LD_DEBUG(reloc && IsGeneral, "RELO R_386_PC32 %16p <- 0x%08x (%16p - %16p) %s",
                 rel_target, result, reinterpret_cast<void*>(target),
                 reinterpret_cast<void*>(base), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;
#endif
    default:
      DL_ERR("unknown reloc type %d in \"%s\"", r_type, relocator.si->get_realpath());
      return false;
  }
  return true;
}

__attribute__((noinline))
static bool process_relocation_general(Relocator& relocator, const rel_t& reloc) {
  return process_relocation_impl<RelocMode::General>(relocator, reloc);
}

template <RelocMode Mode>
__attribute__((always_inline))
static inline bool process_relocation(Relocator& relocator, const rel_t& reloc) {
  return Mode == RelocMode::General ?
      process_relocation_general(relocator, reloc) :
      process_relocation_impl<Mode>(relocator, reloc);
}

template <RelocMode Mode>
__attribute__((noinline))
static bool plain_relocate_impl(Relocator& relocator, rel_t* rels, size_t rel_count) {
  for (size_t i = 0; i < rel_count; ++i) {
    if (!process_relocation<Mode>(relocator, rels[i])) {
      return false;
    }
  }
  return true;
}

template <RelocMode Mode>
__attribute__((noinline))
static bool packed_relocate_impl(Relocator& relocator, sleb128_decoder decoder) {
  return for_all_packed_relocs(decoder, [&](const rel_t& reloc) {
    return process_relocation<Mode>(relocator, reloc);
  });
}

static bool needs_slow_relocate_loop(const Relocator& relocator __unused) {
#if !defined(__LP64__)
  if (relocator.si->has_text_relocations) return true;
#endif
  // Both LD_DEBUG relocation logging and statistics need the slow path.
  if (g_linker_debug_config.any || g_linker_debug_config.statistics) {
    return true;
  }
  return false;
}

template <RelocMode OptMode, typename ...Args>
static bool plain_relocate(Relocator& relocator, Args ...args) {
  return needs_slow_relocate_loop(relocator) ?
      plain_relocate_impl<RelocMode::General>(relocator, args...) :
      plain_relocate_impl<OptMode>(relocator, args...);
}

template <RelocMode OptMode, typename ...Args>
static bool packed_relocate(Relocator& relocator, Args ...args) {
  return needs_slow_relocate_loop(relocator) ?
      packed_relocate_impl<RelocMode::General>(relocator, args...) :
      packed_relocate_impl<OptMode>(relocator, args...);
}

bool soinfo::relocate(const SymbolLookupList& lookup_list) {
  // For ldd, don't apply relocations because TLS segments are not registered.
  // We don't care whether ldd diagnoses unresolved symbols.
  if (g_is_ldd) {
    return true;
  }

  VersionTracker version_tracker;

  if (!version_tracker.init(this)) {
    return false;
  }

  Relocator relocator(version_tracker, lookup_list);
  relocator.si = this;
  relocator.si_strtab = strtab_;
  relocator.si_strtab_size = has_min_version(1) ? strtab_size_ : SIZE_MAX;
  relocator.si_symtab = symtab_;
  relocator.tlsdesc_args = &tlsdesc_args_;
  relocator.tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();

  // The linker already applied its RELR relocations in an earlier pass, so
  // skip the RELR relocations for the linker.
  if (relr_ != nullptr && !is_linker()) {
    LD_DEBUG(reloc, "[ relocating %s relr ]", get_realpath());
    const ElfW(Relr)* begin = relr_;
    const ElfW(Relr)* end = relr_ + relr_count_;
    if (!relocate_relr(begin, end, load_bias, should_tag_memtag_globals())) {
      return false;
    }
  }

  if (android_relocs_ != nullptr) {
    // check signature
    if (android_relocs_size_ > 3 &&
        android_relocs_[0] == 'A' &&
        android_relocs_[1] == 'P' &&
        android_relocs_[2] == 'S' &&
        android_relocs_[3] == '2') {
      LD_DEBUG(reloc, "[ relocating %s android rel/rela ]", get_realpath());

      const uint8_t* packed_relocs = android_relocs_ + 4;
      const size_t packed_relocs_size = android_relocs_size_ - 4;

      if (!packed_relocate<RelocMode::Typical>(relocator, sleb128_decoder(packed_relocs, packed_relocs_size))) {
        return false;
      }
    } else {
      DL_ERR("bad android relocation header.");
      return false;
    }
  }

#if defined(USE_RELA)
  if (rela_ != nullptr) {
    LD_DEBUG(reloc, "[ relocating %s rela ]", get_realpath());

    if (!plain_relocate<RelocMode::Typical>(relocator, rela_, rela_count_)) {
      return false;
    }
  }
  if (plt_rela_ != nullptr) {
    LD_DEBUG(reloc, "[ relocating %s plt rela ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rela_, plt_rela_count_)) {
      return false;
    }
  }
#else
  if (rel_ != nullptr) {
    LD_DEBUG(reloc, "[ relocating %s rel ]", get_realpath());
    if (!plain_relocate<RelocMode::Typical>(relocator, rel_, rel_count_)) {
      return false;
    }
  }
  if (plt_rel_ != nullptr) {
   LD_DEBUG(reloc, "[ relocating %s plt rel ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rel_, plt_rel_count_)) {
      return false;
    }
  }
#endif

  // Once the tlsdesc_args_ vector's size is finalized, we can write the addresses of its elements
  // into the TLSDESC relocations.
#if defined(__aarch64__) || defined(__riscv)
  // Bionic currently only implements TLSDESC for arm64 and riscv64.
  for (const std::pair<TlsDescriptor*, size_t>& pair : relocator.deferred_tlsdesc_relocs) {
    TlsDescriptor* desc = pair.first;
    desc->func = tlsdesc_resolver_dynamic;
    desc->arg = reinterpret_cast<size_t>(&tlsdesc_args_[pair.second]);
  }
#endif // defined(__aarch64__) || defined(__riscv)

  return true;
}
```