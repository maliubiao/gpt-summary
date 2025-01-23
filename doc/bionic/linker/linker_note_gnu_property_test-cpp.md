Response:
Let's break down the thought process for analyzing the C++ source code.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `linker_note_gnu_property_test.cpp` file, its relation to Android, and how it interacts with the dynamic linker. We also need to identify potential user errors and how to debug this code.

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for important keywords and structures. These immediately jump out:

* **`#include` statements:**  These tell us the dependencies. `stdlib.h`, `iostream`, `sstream`, `string` are standard C++ libraries. More importantly, `#include "linker.h"`, `#include "linker_globals.h"`, and `#include "linker_note_gnu_property.h"` indicate the core purpose of this test file is related to the Android dynamic linker. `gtest/gtest.h` signals this is a unit test file.
* **`#define` macros:** `SONAME` suggests a shared object name. `PHDR_WITH_NOTE_GNU_PROPERTY`, `ASSERT_NO_ERROR_MSG`, and `ASSERT_ERROR_MSG_EQ` are helper macros for simplifying the test structure.
* **Function definitions:** `linker_get_error_buffer`, `linker_get_error_buffer_size`, `reset_error_buffer`, `test_bti_not_supported`, `test_bti_supported`. These reveal key functionalities and testing scenarios.
* **Class definition:** `GnuPropertySectionBuilder` hints at how the `.note.gnu.property` section is constructed for testing.
* **`TEST()` macros:**  These clearly define individual test cases. The test names (`default`, `phdr_null`, etc.) give clues about what's being tested.
* **`g_platform_properties`:** This global variable indicates a system-wide configuration related to features like BTI.
* **`GNU_PROPERTY_AARCH64_FEATURE_1_BTI`:** This constant strongly suggests a test related to Branch Target Identification (BTI), a security feature in ARMv8.5-A architecture.
* **Error handling:** The presence of `error_buffer`, `linker_get_error_buffer`, and the `ASSERT_ERROR_MSG_EQ` macro shows that the tests verify expected error messages.
* **Conditional compilation:** `#if defined(__aarch64__)` indicates architecture-specific tests.

**3. Inferring Functionality:**

Based on the keywords, includes, and definitions, I deduced the following:

* **Core Functionality:** The file tests the parsing and validation of the `.note.gnu.property` section within ELF files, specifically focusing on the `GNU_PROPERTY_TYPE_0`. This section is used by the dynamic linker to determine properties of a shared object.
* **Specific Feature:** The tests heavily emphasize Branch Target Identification (BTI), a security feature that helps prevent code-reuse attacks. The `GnuPropertySection` class likely extracts and interprets BTI-related information from the `.note.gnu.property` section.
* **Testing Strategy:** The tests cover various scenarios:
    * Default behavior.
    * Invalid or missing program headers (`PT_GNU_PROPERTY`).
    * Incorrectly formatted `.note.gnu.property` sections (bad sizes, types, names).
    * Correctly formatted sections with and without the BTI property.
    * Interaction with platform-level BTI support.
* **Error Reporting:** The tests verify that the linker produces specific error messages when encountering invalid `.note.gnu.property` data.

**4. Connecting to Android:**

Knowing that this is in `bionic/linker`, the connection to Android is direct:

* **Dynamic Linker:** The Android dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) is responsible for loading shared libraries (`.so` files) and resolving symbols at runtime. The `.note.gnu.property` section is part of the ELF format of these shared libraries.
* **Security:** BTI is a security feature implemented within Android to enhance the robustness of the system against certain types of attacks. The linker needs to understand and enforce these properties.
* **NDK and Framework:**  Developers using the NDK can potentially influence the contents of the `.note.gnu.property` section (indirectly through compiler and linker flags). The Android Framework relies on the dynamic linker to load its components.

**5. Explaining `libc` Functions:**

The code uses standard C++ features. The key is to explain their *role* in the context of the test, not just their general definition:

* `stdlib.h`: Provides `NULL` for null pointers.
* `iostream`, `sstream`: Used for outputting debug information (like the `dump()` method in `GnuPropertySectionBuilder`) and potentially for error reporting (though the test uses a custom error buffer).
* `string`:  Used for string comparisons in the assertion macros.
* `memcpy`, `memset`: Used in `GnuPropertySectionBuilder` to construct the raw byte representation of the `.note.gnu.property` section.

**6. Dynamic Linker Aspects:**

This requires understanding how the linker processes ELF files:

* **ELF Structure:** Explain the role of Program Headers (PHDRs), especially `PT_GNU_PROPERTY`.
* **`.note.gnu.property`:** Detail its structure (`NhdrGNUProperty`, `Prop`).
* **Linking Process:** Briefly describe how the linker iterates through the PHDRs, finds `PT_GNU_PROPERTY`, and then parses its contents.
* **SO Layout Sample:** Create a simplified example showing where the `.note.gnu.property` section would reside within the ELF file.

**7. Logical Reasoning and Assumptions:**

For the input/output examples, I focused on the key tests related to BTI. The assumption is that if the `.note.gnu.property` correctly specifies BTI support, and the platform supports it, then `IsBTICompatible()` should return `true`. Otherwise, it should be `false`.

**8. Common User Errors:**

Think about what mistakes a developer might make when creating shared libraries:

* Incorrect linker flags.
* Manually crafting ELF files (unlikely but possible for advanced users).
* Using older toolchains that don't support BTI.

**9. Reaching the Code from Android:**

This requires tracing the path from higher levels to the linker:

* **App/Framework:** An application or framework component needs to load a shared library.
* **`dlopen()`:** This is the primary function used to load shared libraries.
* **Linker Invocation:** `dlopen()` ultimately calls into the dynamic linker.
* **ELF Parsing:** The linker parses the ELF header and program headers of the shared library.
* **`.note.gnu.property` Processing:**  The linker specifically looks for and processes the `PT_GNU_PROPERTY` segment.

**10. Frida Hook Example:**

The key is to hook a function that is directly involved in processing the `.note.gnu.property` section. Since the code defines a `GnuPropertySection` class, hooking its constructor or a method like `IsBTICompatible()` would be effective. The Frida example should show how to intercept the call and potentially inspect the arguments.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the specific bit manipulation within the BTI flags.
* **Correction:** Realized the higher-level goal is to understand the *testing* of the `.note.gnu.property` section's structure and basic validation, not necessarily the intricate details of BTI flag encoding (unless the prompt specifically asked for that).
* **Initial thought:** Explain every single line of code.
* **Correction:** Focus on the *functional purpose* of different code blocks and libraries within the context of the test.
* **Initial thought:**  Just describe the general linking process.
* **Correction:**  Provide more specific details about how the linker finds and interprets the `.note.gnu.property` section.

By following these steps, iteratively analyzing the code, and connecting the pieces to the broader Android ecosystem, I could construct a comprehensive and informative response to the prompt.
这个文件 `bionic/linker/linker_note_gnu_property_test.cpp` 是 Android Bionic 库中的一个单元测试文件，专门用于测试动态链接器 (linker) 如何处理 ELF 文件中的 `.note.gnu.property` section。这个 section 包含有关共享库的各种属性信息，例如是否支持某些 CPU 特性 (例如 ARMv8.5-A 的 BTI)。

以下是该文件的功能及其与 Android 功能的关系的详细说明：

**1. 功能概述:**

* **测试 `.note.gnu.property` Section 的解析和验证:** 该文件主要测试 `GnuPropertySection` 类的功能，该类负责解析 ELF 文件 Program Header 中的 `PT_GNU_PROPERTY` 类型的 segment，并从中提取和验证 `.note.gnu.property` section 的内容。
* **测试 BTI (Branch Target Identification) 支持:**  重点测试了动态链接器如何识别和处理 `.note.gnu.property` 中关于 BTI 支持的信息。BTI 是一种安全特性，用于防止代码重用攻击。
* **模拟各种 `.note.gnu.property` 场景:**  测试用例涵盖了各种有效的和无效的 `.note.gnu.property` section 格式，例如：
    *  缺少 `PT_GNU_PROPERTY` segment。
    *  `PT_GNU_PROPERTY` segment 大小不正确。
    *  `.note.gnu.property` header ( `NhdrGNUProperty`) 中的字段值不正确（例如，`n_namesz`, `n_type`）。
    *  `.note.gnu.property` section 中包含的 property entry (`Prop`) 的格式不正确。
    *  包含 BTI 支持标志和不包含 BTI 支持标志的情况。
* **验证错误处理:**  测试用例会检查当遇到无效的 `.note.gnu.property` section 时，动态链接器是否会产生预期的错误消息。

**2. 与 Android 功能的关系及举例说明:**

该文件直接关系到 Android 的动态链接过程和安全性。

* **动态链接器 (linker):**  Android 系统使用动态链接器来加载和链接共享库 (`.so` 文件)。当加载一个共享库时，链接器需要解析其 ELF 文件格式，包括 Program Headers。`PT_GNU_PROPERTY` segment 指向 `.note.gnu.property` section，链接器会读取该 section 来了解库的属性。
    * **举例:**  当 Android 系统启动一个应用程序时，应用程序可能依赖于一些共享库。链接器会加载这些共享库，并检查它们是否声明了某些需要的属性，例如对特定 CPU 特性的支持。如果一个库声明支持 BTI，并且设备 CPU 也支持 BTI，那么链接器可以进行相应的优化或安全检查。
* **安全性 (BTI):**  BTI 是 ARMv8.5-A 架构引入的一项安全特性，旨在防止攻击者跳转到代码中的任意位置。通过在 `.note.gnu.property` section 中声明对 BTI 的支持，共享库可以告知链接器需要强制执行 BTI 保护。
    * **举例:**  如果一个关键的系统库 (例如 `libc.so`) 声明了支持 BTI，那么链接器在加载该库时，会确保所有间接分支指令都跳转到有效的入口点，从而阻止某些类型的代码注入攻击。
* **ABI 兼容性:** `.note.gnu.property` 可以用于指示共享库所依赖的 ABI 版本或其他兼容性信息。虽然这个测试文件主要关注 BTI，但 `.note.gnu.property` 的其他用途也与 Android 的兼容性管理相关。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

该测试文件本身主要使用了 C++ 标准库的功能，而不是直接调用 `libc` 函数。以下是使用到的 C++ 标准库功能以及它们在测试中的作用：

* **`<stdlib.h>`:**  提供了 `NULL` 宏，用于表示空指针。
* **`<iostream>`:** 提供了 `std::cout`，用于输出调试信息。
* **`<sstream>`:** 提供了 `std::stringstream`，虽然在这个文件中没有直接使用，但通常用于在内存中构建字符串。
* **`<string>`:** 提供了 `std::string`，用于字符串操作和比较。
* **`<cstring>`:**  间接通过 `<string>` 使用，可能用到了 `memcpy` 等函数（虽然代码中直接使用了 `memcpy`）。
* **`<gtest/gtest.h>`:**  这是一个 Google Test 框架的头文件，提供了编写和运行单元测试所需的宏和类，例如 `TEST`, `ASSERT_TRUE`, `ASSERT_FALSE`, `ASSERT_STREQ` 等。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本 (简化):**

```
ELF Header:
  ...
Program Headers:
  Type           Offset   VirtAddr PhysAddr FileSiz  MemSiz   Flags Align
  LOAD           0x000000 0xXXXXXXXX 0xXXXXXXXX 0xYYYYYY 0xYYYYYY R E   0x1000
  LOAD           0xZZZZZZ 0xAAAAAAAA 0xAAAAAAAA 0xBBBBBB 0xBBBBBB RW    0x1000
  GNU_PROPERTY   0xCCCCCC 0xDDDDDDDD 0xDDDDDDDD 0xEEEE    0xEEEE   R     0x8
  ...
Section Headers:
  ...
.note.gnu.property section (位于 GNU_PROPERTY 指向的位置):
  n_namesz = 4
  n_descsz = ...
  n_type   = 5 (NT_GNU_PROPERTY_TYPE_0)
  name     = "GNU"
  描述数据 (包含一个或多个 property entry):
    pr_type   = 1 (例如，GNU_PROPERTY_AARCH64_FEATURE_1_AND)
    pr_datasz = 4
    pr_data   = { 0x00000001 }  // 例如，表示支持 BTI
    ...
```

**链接的处理过程 (简化):**

1. **加载 SO 文件:** 当系统需要加载一个共享库时，例如通过 `dlopen` 调用，动态链接器会打开该 SO 文件。
2. **解析 ELF Header:** 链接器首先解析 ELF header，获取关键信息，例如 Program Header Table 的位置和大小。
3. **遍历 Program Headers:** 链接器遍历 Program Header Table 中的每一个 entry。
4. **查找 `PT_GNU_PROPERTY`:** 链接器寻找 `p_type` 字段为 `PT_GNU_PROPERTY` 的 Program Header。
5. **定位 `.note.gnu.property`:**  找到 `PT_GNU_PROPERTY` 后，链接器会根据其 `p_vaddr` (或 `p_offset`，取决于具体实现和加载方式) 定位到 `.note.gnu.property` section 在内存或文件中的位置。
6. **解析 `.note.gnu.property` Header:** 链接器读取并解析 `.note.gnu.property` section 的 header (`NhdrGNUProperty`)，验证 `n_namesz`, `n_type`, `name` 等字段。
7. **解析 Property Entries:** 根据 `n_descsz`，链接器遍历并解析 section 中的每一个 property entry (`Prop`)。每个 entry 包含 `pr_type`, `pr_datasz` 和 `pr_data`。
8. **处理属性:** 链接器根据解析出的属性进行相应的处理。例如，如果 `pr_type` 是 `GNU_PROPERTY_AARCH64_FEATURE_1_AND` 且 `pr_data` 中包含 `GNU_PROPERTY_AARCH64_FEATURE_1_BTI`，则链接器知道该库支持 BTI。
9. **应用属性:** 链接器可能会基于这些属性进行一些决策，例如启用或禁用某些优化，或者进行安全相关的设置。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

**假设输入 (针对 BTI 测试):**

* **场景 1: SO 文件的 `.note.gnu.property` section 声明支持 BTI。**
    * `pr_type` = `GNU_PROPERTY_AARCH64_FEATURE_1_AND`
    * `pr_datasz` = 4
    * `pr_data` = `{ 0x00000001 }` (假设 `GNU_PROPERTY_AARCH64_FEATURE_1_BTI` 的值为 1)
    * 并且 `g_platform_properties.bti_supported` 为 `true`。
* **场景 2: SO 文件的 `.note.gnu.property` section 没有声明支持 BTI。**
    * 或者 `pr_type` 不是 `GNU_PROPERTY_AARCH64_FEATURE_1_AND`。
    * 或者 `pr_data` 中不包含 `GNU_PROPERTY_AARCH64_FEATURE_1_BTI`。
    * 或者 `g_platform_properties.bti_supported` 为 `false`。

**预期输出:**

* **场景 1:** `GnuPropertySection::IsBTICompatible()` 返回 `true`，且没有错误消息。
* **场景 2:** `GnuPropertySection::IsBTICompatible()` 返回 `false`，且没有与 BTI 相关的错误消息（除非有其他格式错误）。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误地构造 `.note.gnu.property` section:**  开发者在手动创建或修改 ELF 文件时，可能会错误地设置 `n_namesz`, `n_descsz`, `n_type` 等字段，或者 property entry 的 `pr_type`, `pr_datasz`。这会导致链接器解析错误。
    * **例子:**  将 `n_namesz` 设置为 3 而不是 4，导致链接器报错 "unexpected name size"。
* **工具链问题:**  使用的编译工具链可能不支持生成包含特定 `.note.gnu.property` 属性的 ELF 文件。
    * **例子:**  使用旧版本的 clang/LLVM 可能无法生成包含 BTI 属性的 `.note.gnu.property` section。
* **链接器脚本配置错误:**  在复杂的构建过程中，链接器脚本的配置可能导致 `.note.gnu.property` section 没有被正确地包含或生成。
* **忽略链接器警告或错误:**  当链接器遇到无效的 `.note.gnu.property` section 时，通常会产生警告或错误。开发者可能会忽略这些信息，导致运行时出现问题或安全漏洞。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 `linker_note_gnu_property_test.cpp` 的路径:**

这个 `.cpp` 文件是一个单元测试文件，它**不会**在正常的 Android Framework 或 NDK 应用程序执行流程中被直接执行。它的目的是在 Bionic 库的开发和测试阶段，验证动态链接器处理 `.note.gnu.property` section 的正确性。

然而，Android Framework 或 NDK 应用程序会间接地触发与 `.note.gnu.property` section 处理相关的代码。

1. **NDK 编译:**  NDK 开发者使用 C/C++ 编写代码，并通过 NDK 提供的工具链（例如 `clang++`, `lld`）将其编译成共享库 (`.so` 文件)。
2. **链接器 (lld) 处理:**  链接器 `lld` 在生成 `.so` 文件时，可能会根据编译选项和目标架构，在 ELF 文件中创建 `PT_GNU_PROPERTY` segment 和 `.note.gnu.property` section，包含诸如 BTI 支持等属性。
3. **Android 应用加载共享库:**  当 Android 应用程序启动或在运行时需要使用 NDK 编译的共享库时，它会调用 `dlopen` 或其他相关函数来加载这些库。
4. **动态链接器 (linker) 执行:**  Android 系统中的动态链接器 (位于 `/system/bin/linker` 或 `/system/bin/linker64`) 负责处理 `dlopen` 请求。
5. **链接器解析 `.note.gnu.property`:**  动态链接器会解析加载的共享库的 ELF 文件，包括查找和解析 `PT_GNU_PROPERTY` segment 和 `.note.gnu.property` section。
6. **根据属性进行操作:** 链接器会根据 `.note.gnu.property` 中声明的属性（例如 BTI 支持），进行相应的操作。

**Frida Hook 示例:**

可以使用 Frida Hook 动态链接器中与解析 `.note.gnu.property` 相关的函数，来观察其执行过程。由于测试文件关注 `GnuPropertySection` 类，我们可以尝试 hook 它的构造函数或者相关方法。

假设我们想观察 `GnuPropertySection` 的构造函数被调用的情况，可以尝试以下 Frida 脚本：

```javascript
if (Process.arch === 'arm64') {
  const GnuPropertySection = Module.findExportByName(null, "_ZN18GnuPropertySectionC1EPKNS_6ElfWPhijPKcE"); // 查找构造函数符号

  if (GnuPropertySection) {
    Interceptor.attach(GnuPropertySection, {
      onEnter: function (args) {
        console.log("[+] GnuPropertySection constructor called");
        console.log("    phdr:", args[0]);
        console.log("    phnum:", args[1]);
        console.log("    load_bias:", args[2]);
        console.log("    soname:", args[3].readUtf8String());
      }
    });
  } else {
    console.log("[-] GnuPropertySection constructor not found");
  }
} else {
  console.log("[*] This script is designed for arm64 architecture.");
}
```

**解释:**

1. **`Process.arch === 'arm64'`:**  检查进程架构，因为 BTI 是 ARMv8.5-A 特性。
2. **`Module.findExportByName(null, "_ZN18GnuPropertySectionC1EPKNS_6ElfWPhijPKcE")`:**  尝试查找 `GnuPropertySection` 类的构造函数的符号。符号名称可能会因编译器和架构而异，需要根据实际情况调整。可以使用 `frida-ps -U` 和 `frida -U -n <process_name> -l <script.js>` 来查看进程的导出符号。
3. **`Interceptor.attach(...)`:**  使用 Frida 的 `Interceptor` API 来 hook 构造函数。
4. **`onEnter`:**  当构造函数被调用时，`onEnter` 函数会被执行。
5. **`args`:**  `args` 数组包含了传递给构造函数的参数。我们可以打印出 Program Header 的指针、数量、加载基址以及 SO 的名字。

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_gnu_property.js`)。
2. 找到一个运行中的 Android 进程，该进程会加载包含 `.note.gnu.property` section 的共享库（例如，一个使用了 NDK 库的应用程序）。
3. 使用 Frida 连接到该进程：`frida -U -n <process_name> -l hook_gnu_property.js`
4. 当目标进程加载共享库并创建 `GnuPropertySection` 对象时，Frida 会拦截调用并打印出相关信息。

**注意:**  hook 动态链接器的内部函数需要一定的 Frida 和动态链接器知识。符号名称可能会因 Android 版本和架构而异，需要根据实际情况进行调整。

通过这些步骤，我们可以理解 `linker_note_gnu_property_test.cpp` 文件的功能，它与 Android 动态链接器和安全性的关系，以及如何在 Android 系统中间接地触发相关的代码执行。 Frida 提供了一种强大的方式来动态地观察和调试这些底层过程。

### 提示词
```
这是目录为bionic/linker/linker_note_gnu_property_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "linker.h"
#include "linker_globals.h"
#include "linker_note_gnu_property.h"
#include "platform/bionic/macros.h"

#define SONAME "test_so"

static char error_buffer[1024];

char* linker_get_error_buffer() {
  return error_buffer;
}

size_t linker_get_error_buffer_size() {
  return std::size(error_buffer);
}

static void reset_error_buffer() {
  error_buffer[0] = '\0';
}

platform_properties g_platform_properties {
#if defined(__aarch64__)
  // Assume "hardware" supports Armv8.5-A BTI.
  .bti_supported = true
#endif
};

// Helper macro to make the test cleaner.
#define PHDR_WITH_NOTE_GNU_PROPERTY(__prop)                                   \
  reset_error_buffer();                                                       \
  ElfW(Phdr) phdrs[] = {                                                      \
      {.p_type = PT_LOAD},                                                    \
      {                                                                       \
          .p_type = PT_GNU_PROPERTY,                                          \
          .p_vaddr = reinterpret_cast<ElfW(Addr)>(__prop),                    \
          .p_memsz = sizeof(ElfW(NhdrGNUProperty)) + (__prop)->nhdr.n_descsz, \
      },                                                                      \
      {.p_type = PT_NULL},                                                    \
  };                                                                          \
  auto note = GnuPropertySection(&phdrs[0], std::size(phdrs), 0, SONAME)

// Helper to check for no error message.
#define ASSERT_NO_ERROR_MSG() ASSERT_STREQ(error_buffer, "")

// Helper to check expected error message.
#define ASSERT_ERROR_MSG_EQ(__expected) ASSERT_STREQ(error_buffer, "\"" SONAME "\" " __expected)

static void test_bti_not_supported(GnuPropertySection& note __unused) {
#if defined(__aarch64__)
  ASSERT_FALSE(note.IsBTICompatible());
#endif
}

#if defined(__aarch64__)
static void test_bti_supported(GnuPropertySection& note __unused) {
  ASSERT_TRUE(note.IsBTICompatible());
}
#endif

// Helper class to build a well-formed .note.gnu.property section.
class GnuPropertySectionBuilder {
 public:
  GnuPropertySectionBuilder() {
    note = reinterpret_cast<ElfW(NhdrGNUProperty)*>(&section[0]);
    note->nhdr.n_namesz = 4;
    note->nhdr.n_descsz = 0;
    note->nhdr.n_type = NT_GNU_PROPERTY_TYPE_0;
    memcpy(note->n_name, "GNU", 4);
  }

  template <typename T>
  bool push(ElfW(Word) pr_type, ElfW(Word) pr_datasz, const T* pr_data) {
    // Must be aligned.
    const uintptr_t addition = __builtin_align_up(pr_datasz, sizeof(ElfW(Addr)));
    if ((offset() + addition) > kMaxSectionSize) {
      return false;
    }
    ++entries;
    ElfW(Prop)* prop = reinterpret_cast<ElfW(Prop)*>(&section[offset()]);
    // Header
    prop->pr_type = pr_type;
    prop->pr_datasz = pr_datasz;
    step(2 * sizeof(ElfW(Word)));
    // Data
    memcpy(&section[offset()], reinterpret_cast<const void*>(pr_data), pr_datasz);
    step(pr_datasz);
    // Padding
    memset(&section[offset()], 0xAA, addition - pr_datasz);
    step(addition - pr_datasz);
    return true;
  }

  ElfW(NhdrGNUProperty)* data() const { return note; }

  void dump() const {
    std::cout << ".note.gnu.property\n";
    dump_member("n_namesz", note->nhdr.n_namesz);
    dump_member("n_descsz", note->nhdr.n_descsz);
    dump_member("n_type  ", note->nhdr.n_type);
    dump_member("n_name  ", note->n_name);
    dump_member("entries ", entries);
    if (entries > 0) {
      std::cout << "    raw data:";
      const uintptr_t end = note->nhdr.n_descsz + 16;
      for (uintptr_t offset = 16; offset < end; ++offset) {
        std::cout << std::hex;
        if ((offset % 8) == 0) {
          std::cout << "\n   ";
        }
        auto value = static_cast<unsigned>(section[offset]);
        std::cout << " ";
        if (value < 0x10) {
          std::cout << "0";
        }
        std::cout << static_cast<unsigned>(section[offset]);
      }
      std::cout << std::dec << "\n";
    }
  }

  void corrupt_n_descsz(ElfW(Word) n_descsz) { note->nhdr.n_descsz = n_descsz; }

 private:
  template <typename T>
  void dump_member(const char* name, T value) const {
    std::cout << "  " << name << " " << value << "\n";
  }

  ElfW(Word) offset() const { return note->nhdr.n_descsz + 16; }

  template <typename T>
  void step(T value) {
    note->nhdr.n_descsz += static_cast<ElfW(Word)>(value);
  }

  static const size_t kMaxSectionSize = 1024;

  alignas(8) uint8_t section[kMaxSectionSize];
  ElfW(NhdrGNUProperty)* note;
  size_t entries = 0;
};

// Tests that the default constructed instance does not report support
// for Armv8.5-A BTI.
TEST(note_gnu_property, default) {
  GnuPropertySection note;
  test_bti_not_supported(note);
  ASSERT_NO_ERROR_MSG();
}

// Tests that an instance without valid phdr pointer does not report
// support for Armv8.5-A BTI.
TEST(note_gnu_property, phdr_null) {
  auto note = GnuPropertySection(nullptr, 0, 0, SONAME);
  test_bti_not_supported(note);
  ASSERT_NO_ERROR_MSG();
}

// Tests that an instance without finding PT_GNU_PROPERTY does not
// report support for Armv8.5-A BTI.
TEST(note_gnu_property, no_pt_gnu_property) {
  ElfW(Phdr) phdrs[] = {
      {.p_type = PT_LOAD},
      {.p_type = PT_NULL},
  };

  reset_error_buffer();
  auto note = GnuPropertySection(&phdrs[0], std::size(phdrs), 0, SONAME);
  test_bti_not_supported(note);
  ASSERT_NO_ERROR_MSG();
}

// Tests the validity check for invalid PT_GNU_PROPERTY size.
TEST(note_gnu_property, pt_gnu_property_bad_size) {
  ElfW(Phdr) phdrs[] = {
      {.p_type = PT_LOAD},
      {
          .p_type = PT_GNU_PROPERTY,
          .p_vaddr = 0,
          .p_memsz = sizeof(ElfW(NhdrGNUProperty)) - 1,  // Invalid
      },
      {.p_type = PT_NULL},
  };

  reset_error_buffer();
  auto note = GnuPropertySection(&phdrs[0], std::size(phdrs), 0, SONAME);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ("PT_GNU_PROPERTY segment is too small. Segment size is 15, minimum is 16.");
}

// Tests that advertised n_descsz should still fit into p_memsz.
TEST(note_gnu_property, pt_gnu_property_too_small) {
  ElfW(NhdrGNUProperty) prop = {
      .nhdr = {.n_namesz = PT_GNU_PROPERTY, .n_descsz = 1, .n_type = NT_GNU_PROPERTY_TYPE_0},
      .n_name = "GNU",
  };
  ElfW(Phdr) phdrs[] = {
      {
          .p_type = PT_GNU_PROPERTY,
          .p_vaddr = reinterpret_cast<ElfW(Addr)>(&prop),
          .p_memsz = sizeof(ElfW(NhdrGNUProperty)),  // Off by one
      },
  };

  reset_error_buffer();
  auto note = GnuPropertySection(&phdrs[0], std::size(phdrs), 0, SONAME);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ("PT_GNU_PROPERTY segment p_memsz (16) is too small for note n_descsz (1).");
}

// Tests the validity check for invalid .note.gnu.property type.
TEST(note_gnu_property, pt_gnu_property_bad_type) {
  ElfW(NhdrGNUProperty) prop = {
      .nhdr =
          {
              .n_namesz = 4,
              .n_descsz = 0,
              .n_type = NT_GNU_PROPERTY_TYPE_0 - 1  // Invalid
          },
      .n_name = "GNU",
  };
  PHDR_WITH_NOTE_GNU_PROPERTY(&prop);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ(".note.gnu.property: unexpected note type. Expected 5, got 4.");
}

// Tests the validity check for invalid .note.gnu.property name size.
TEST(note_gnu_property, pt_gnu_property_bad_namesz) {
  ElfW(NhdrGNUProperty) prop = {
      .nhdr = {.n_namesz = 3,  // Invalid
               .n_descsz = 0,
               .n_type = NT_GNU_PROPERTY_TYPE_0},
      .n_name = "GNU",
  };
  PHDR_WITH_NOTE_GNU_PROPERTY(&prop);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ(".note.gnu.property: unexpected name size. Expected 4, got 3.");
}

// Tests the validity check for invalid .note.gnu.property name.
TEST(note_gnu_property, pt_gnu_property_bad_name) {
  ElfW(NhdrGNUProperty) prop = {
      .nhdr = {.n_namesz = 4, .n_descsz = 0, .n_type = NT_GNU_PROPERTY_TYPE_0},
      .n_name = "ABC",  // Invalid
  };
  PHDR_WITH_NOTE_GNU_PROPERTY(&prop);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ(".note.gnu.property: unexpected name. Expected 'GNU', got 'ABC'.");
}

// Tests the validity check for not enough space for a Program Property header.
TEST(note_gnu_property, pt_gnu_property_pphdr_no_space) {
  ElfW(NhdrGNUProperty) prop = {
      .nhdr = {.n_namesz = 4,
               .n_descsz = 7,  // Invalid
               .n_type = NT_GNU_PROPERTY_TYPE_0},
      .n_name = "GNU",
  };
  PHDR_WITH_NOTE_GNU_PROPERTY(&prop);
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ(".note.gnu.property: no more space left for a Program Property Note header.");
}

// Tests an empty .note.gnu.property.
TEST(note_gnu_property, pt_gnu_property_no_data) {
  GnuPropertySectionBuilder prop;
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  test_bti_not_supported(note);
  ASSERT_NO_ERROR_MSG();
}

// Tests a .note.gnu.property section with elements with pr_datasz = 0.
TEST(note_gnu_property, pt_gnu_property_no_prop) {
  GnuPropertySectionBuilder prop;
  ASSERT_TRUE(prop.push(1, 0, (void*)nullptr));
  ASSERT_TRUE(prop.push(2, 0, (void*)nullptr));
  ASSERT_TRUE(prop.push(3, 0, (void*)nullptr));
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  test_bti_not_supported(note);
  ASSERT_NO_ERROR_MSG();
}

// Tests that GNU_PROPERTY_AARCH64_FEATURE_1_AND must have pr_datasz = 4.
TEST(note_gnu_property, pt_gnu_property_bad_pr_datasz) {
#if defined(__aarch64__)
  GnuPropertySectionBuilder prop;
  ElfW(Word) pr_data[] = {GNU_PROPERTY_AARCH64_FEATURE_1_BTI, 0, 0};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 12, &pr_data));
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  test_bti_not_supported(note);
  ASSERT_ERROR_MSG_EQ(
      ".note.gnu.property: property descriptor size is invalid. Expected 4 bytes for "
      "GNU_PROPERTY_AARCH64_FEATURE_1_AND, got 12.");
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}

// Tests a .note.gnu.property section with only GNU_PROPERTY_AARCH64_FEATURE_1_BTI property array.
TEST(note_gnu_property, pt_gnu_property_ok_1) {
#if defined(__aarch64__)
  GnuPropertySectionBuilder prop;
  ElfW(Word) pr_data[] = {GNU_PROPERTY_AARCH64_FEATURE_1_BTI};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, sizeof(pr_data), &pr_data));
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  ASSERT_NO_ERROR_MSG();
  test_bti_supported(note);
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}

// Tests a .note.gnu.property section with only GNU_PROPERTY_AARCH64_FEATURE_1_BTI property array.
TEST(note_gnu_property, pt_gnu_property_ok_2) {
#if defined(__aarch64__)
  GnuPropertySectionBuilder prop;
  ElfW(Word) pr_data[] = {static_cast<ElfW(Word)>(~GNU_PROPERTY_AARCH64_FEATURE_1_BTI)};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, sizeof(pr_data), &pr_data));
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  ASSERT_NO_ERROR_MSG();
  test_bti_not_supported(note);
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}

// Tests a .note.gnu.property section with more property arrays.
TEST(note_gnu_property, pt_gnu_property_ok_3) {
#if defined(__aarch64__)
  GnuPropertySectionBuilder prop;

  ElfW(Word) pr_data_0[8] = {0xCD};
  ASSERT_TRUE(prop.push(1, 4, &pr_data_0));
  ASSERT_TRUE(prop.push(2, 3, &pr_data_0));
  ASSERT_TRUE(prop.push(3, 8, &pr_data_0));

  ElfW(Word) pr_data[] = {GNU_PROPERTY_AARCH64_FEATURE_1_BTI};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, sizeof(pr_data), &pr_data));

  ASSERT_TRUE(prop.push(4, 1, &pr_data_0));

  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  ASSERT_NO_ERROR_MSG();
  test_bti_supported(note);
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}

// Tests a .note.gnu.property but with bad property descriptor size.
TEST(note_gnu_property, pt_gnu_property_bad_n_descsz) {
#if defined(__aarch64__)
  GnuPropertySectionBuilder prop;
  ElfW(Word) pr_data[] = {GNU_PROPERTY_AARCH64_FEATURE_1_BTI};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, sizeof(pr_data), &pr_data));

  ElfW(Word) n_descsz;
  if (sizeof(ElfW(Addr)) == 4) {
    n_descsz = 11;
  } else {
    n_descsz = 15;
  }

  prop.corrupt_n_descsz(n_descsz);

  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  if (sizeof(ElfW(Addr)) == 4) {
    ASSERT_ERROR_MSG_EQ(
        ".note.gnu.property: property descriptor size is invalid. Expected at least 12 bytes, got "
        "11.");
  } else {
    ASSERT_ERROR_MSG_EQ(
        ".note.gnu.property: property descriptor size is invalid. Expected at least 16 bytes, got "
        "15.");
  }
  test_bti_not_supported(note);
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}

// Tests if platform support is missing.
TEST(note_gnu_property, no_platform_support) {
#if defined(__aarch64__)
  auto bti_supported_orig = g_platform_properties.bti_supported;
  g_platform_properties.bti_supported = false;

  GnuPropertySectionBuilder prop;
  ElfW(Word) pr_data[] = {GNU_PROPERTY_AARCH64_FEATURE_1_BTI};
  ASSERT_TRUE(prop.push(GNU_PROPERTY_AARCH64_FEATURE_1_AND, sizeof(pr_data), &pr_data));
  PHDR_WITH_NOTE_GNU_PROPERTY(prop.data());
  ASSERT_NO_ERROR_MSG();
  test_bti_not_supported(note);

  g_platform_properties.bti_supported = bti_supported_orig;
#else
  GTEST_SKIP() << "BTI is not supported on this architecture.";
#endif
}
```