Response:
Let's break down the thought process for analyzing the provided C++ test file. The goal is to provide a comprehensive explanation covering its functionality, relationship to Android, libc/dynamic linker details, potential errors, and how Android frameworks might reach this code.

**1. Initial Understanding and Context:**

* **File Path:**  `bionic/tests/memtag_globals_test.cpp` immediately tells us this is a *test file* within the *bionic* project. Bionic is Android's C library, math library, and dynamic linker. This is crucial context.
* **Keywords:** "memtag_globals" strongly suggests this test is related to Memory Tagging Extension (MTE), a hardware feature for memory safety.
* **Headers:**  The included headers provide clues:
    * `gtest/gtest.h`:  Indicates this is a Google Test based unit test.
    * `android-base/test_utils.h`:  Suggests Android-specific testing utilities are used.
    * `sys/stat.h`, `unistd.h`, `string`, `tuple`: Standard C/C++ library headers, likely used for file manipulation, process execution, and data structures.
    * `platform/bionic/mte.h`: Confirms the focus on MTE.
* **Class `MemtagGlobalsTest`:** This is the main test fixture, inheriting from `testing::TestWithParam`. The parameterization hints at testing different scenarios.

**2. Dissecting the Test Cases:**

* **`TEST_P(MemtagGlobalsTest, test)`:**
    * **`SKIP_WITH_HWASAN`:**  Indicates incompatibility with Hardware Address Sanitizer (HWASan), another memory safety tool. This is a good initial observation.
    * **`#if defined(__BIONIC__) && defined(__aarch64__)`:**  Confirms the test is specific to 64-bit ARM architecture within Bionic.
    * **`GetTestLibRoot() + "/memtag_globals_binary"`:**  This constructs a path to an executable. The naming convention suggests this executable is specifically designed for this test. The `_static` suffix suggests testing both dynamically and statically linked versions.
    * **`chmod(binary.c_str(), 0755)`:** Makes the test executable runnable.
    * **`ExecTestHelper`:** An Android-specific helper class for running external processes. This suggests the test involves launching another program.
    * **`execve`:** The core system call for executing a new program. The test simulates this.
    * **Conditional Expected Exit Code:** The crucial part. It expects `-SIGSEGV` (segmentation fault) if MTE is supported and the binary is *not* static. Otherwise, it expects a clean exit (0). This implies the test checks if MTE correctly detects memory errors in global variables for dynamically linked executables. The "Assertions were passed" message for the static case suggests that even without MTE, the program itself should have internal checks that pass.
    * **`INSTANTIATE_TEST_SUITE_P`:** Sets up the parameterized testing, running the `test` case twice: once with `false` (dynamic linking) and once with `true` (static linking).

* **`TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442)`:**
    *  Similar structure to the first test.
    *  The binary name `"mte_globals_relr_regression_test_b_314038442"` suggests this is a regression test specifically for a bug with ID `b_314038442`, likely related to RELR relocations and MTE globals.
    *  The expected exit code is 0, and the output message "Program loaded successfully.*Tags are zero!" suggests this test checks that without MTE, the global variables have zero tags (as expected).

* **`TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442WithMteGlobals)`:**
    *  Explicitly checks for `mte_supported()`.
    *  Uses a binary named `"mte_globals_relr_regression_test_b_314038442_mte"`.
    *  Expects an exit code of 0 and the message "Program loaded successfully.*Tags are non-zero", verifying that *with* MTE enabled, global variables get tagged.

**3. Connecting to Android and Bionic:**

* **Bionic Context:** The file location is the primary indicator. The use of `ExecTestHelper` reinforces this.
* **MTE Feature:**  The entire test suite revolves around the MTE feature, which is a security enhancement in modern ARM architectures and a focus within Android's system-level development.
* **Dynamic Linker Implication:** The tests with `execve` and different binary types (static/dynamic) directly involve the dynamic linker's behavior. The RELR regression tests point to specific linker optimizations or bug fixes related to MTE.

**4. Considering Libc and Dynamic Linker Details (and recognizing limitations):**

* **Libc Functions:** The test itself doesn't directly call many standard libc functions *within the test code*. The key libc function interaction happens *within the executables being tested* (`memtag_globals_binary` and its variations). We can infer that these executables likely use libc functions to access and potentially overflow global variables. `execve` is a libc function. `chmod` is also a libc function.
* **Dynamic Linker:** The `execve` call initiates the dynamic linking process for the non-static binaries. The RELR tests strongly indicate interaction with the dynamic linker's relocation process. We need to *infer* how the dynamic linker is involved in setting up MTE tags for globals.

**5. Anticipating Errors and Usage:**

* **Incorrect MTE Configuration:** A user might try to enable MTE in a way that's not supported by the hardware or Android configuration, leading to unexpected behavior.
* **Static Linking and MTE:** The test explicitly highlights that MTE globals don't apply to fully static executables. This is a potential point of confusion for developers.
* **Incorrectly Handling Signals:**  While not directly shown in this test, incorrect signal handling related to MTE violations is a potential error.

**6. Thinking about Android Framework and Frida Hooks:**

* **Framework Path:**  Tracing how the Android framework leads to this specific test file is less direct. Framework developers might run these tests as part of the build or verification process. The framework itself relies on Bionic, so any memory safety features are ultimately important.
* **NDK:** NDK developers using global variables in shared libraries would be indirectly affected by how MTE tagging works.
* **Frida Hooks:**  The key is to identify the relevant functions or system calls to hook. `execve` is a prime candidate to observe the process launch. If we wanted to see the MTE tagging in action, we'd need to look at memory allocation within the dynamic linker or the code that handles MTE instructions (if accessible).

**7. Structuring the Output:**

Organize the information logically:

* Start with the high-level purpose.
* Detail the functionality of each test case.
* Explain the connection to Android and Bionic.
* Discuss the relevant libc and dynamic linker aspects (acknowledging where we're inferring behavior of the *tested* executables).
* Provide concrete examples of errors and usage.
* Outline how the Android framework might relate and offer Frida hook suggestions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the libc functions *called in the test code itself*.
* **Correction:** Realize the core interaction with libc and the dynamic linker happens within the *external binaries* being executed by the test. Shift focus to what those binaries likely do and how the dynamic linker sets up the environment.
* **Initial thought:**  Try to detail the exact low-level MTE instructions.
* **Correction:**  Recognize that the test is high-level. Focus on the *effects* of MTE (signal generation, tagging) rather than the precise instruction sequences (which would require deeper knowledge of the ARM architecture and kernel internals). Keep the explanation accessible.
* **Initial thought:**  Overcomplicate the Frida hook examples.
* **Correction:** Provide simple, illustrative examples that target key points like `execve` rather than attempting to hook internal dynamic linker functions (which can be complex and platform-dependent).

By following these steps, iterating, and refining the understanding, we can arrive at a comprehensive and accurate explanation of the given test file.
这个文件 `bionic/tests/memtag_globals_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试**内存标签 (Memory Tagging Extension, MTE)** 功能在处理全局变量时的正确性。MTE 是一种硬件功能，可以为内存分配的每个“tag”分配一个小的元数据标签，并在访问内存时检查标签是否匹配，从而帮助检测内存安全错误，例如堆溢出和使用后释放。

以下是该文件的功能及其与 Android 功能的关联的详细解释：

**1. 功能概述:**

* **测试 MTE 对全局变量的影响:** 该测试旨在验证当 MTE 功能启用时，全局变量是否会被正确地“标记”。这意味着分配给全局变量的内存应该有一个相关的 MTE 标签。
* **测试静态链接和动态链接的情况:** 测试用例会分别针对静态链接和动态链接的二进制文件进行测试，以确保 MTE 在不同链接方式下都能正常工作。
* **测试 RELR 重定位:**  其中一些测试用例（例如 `RelrRegressionTestForb314038442`）专门用于测试与 RELR (Relative Relocations) 重定位相关的特定回归问题。RELR 是一种优化技术，用于减小动态链接的可执行文件的大小。
* **验证错误检测:** 对于动态链接的二进制文件，测试期望在发生全局缓冲区溢出时能够捕获到 `SIGSEGV` 信号，这表明 MTE 成功检测到了内存错误。
* **验证无错误情况:** 对于静态链接的二进制文件，或者当 MTE 不可用时，测试期望程序能够正常运行并通过内部断言。

**2. 与 Android 功能的关联和举例说明:**

* **内存安全:** MTE 是 Android 为了提高系统安全性和应用稳定性而引入的一项重要技术。通过在硬件层面提供内存标签，可以更有效地检测和防止各种内存安全漏洞。这个测试文件直接验证了 MTE 功能的核心部分——全局变量的保护。
* **Bionic 库的核心功能测试:** 作为 Bionic 的一部分，该测试确保了 Bionic 库在处理内存分配和链接时能够正确地利用硬件提供的 MTE 功能。
* **动态链接器 (linker):** 该测试涉及到动态链接，因为它会执行外部的二进制文件，而动态链接器负责加载和链接这些二进制文件。测试中针对 RELR 重定位的测试用例，更是直接关联到动态链接器的优化和正确性。
* **NDK 开发:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的本地代码。如果 NDK 开发者在本地代码中使用全局变量，那么 MTE 功能就能帮助检测这些全局变量相关的内存错误。

**举例说明:**

假设有一个 NDK 应用，其中定义了一个全局字符数组：

```c++
// my_native_lib.cpp
char global_buffer[10];

void write_to_buffer(const char* data) {
  strcpy(global_buffer, data); // 可能导致缓冲区溢出
}
```

如果该应用运行在支持 MTE 的 Android 设备上，当 `write_to_buffer` 函数尝试写入超过 `global_buffer` 容量的数据时，MTE 应该能够检测到这个缓冲区溢出，并产生一个 `SIGSEGV` 信号，从而阻止潜在的安全漏洞。`memtag_globals_test.cpp` 中的测试正是为了验证这种情况下 MTE 的行为是否符合预期。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件本身并没有直接实现很多 libc 函数，它主要使用了以下 libc 函数：

* **`chmod(const char *pathname, mode_t mode)`:**  用于更改指定文件的权限。在测试中，它被用来将测试二进制文件设置为可执行权限 (`0755`)。
    * **实现:** `chmod` 是一个系统调用，它会传递给操作系统内核。内核会根据进程的权限检查是否允许修改文件权限，如果允许，则更新文件的 inode 中的权限信息。
* **`execve(const char *pathname, char *const argv[], char *const envp[])`:**  用新的进程替换当前进程。这是测试中执行外部测试二进制文件的关键函数。
    * **实现:** `execve` 也是一个系统调用。内核会创建一个新的进程，并将指定的程序加载到该进程的地址空间中。新的进程会继承一些当前进程的属性（例如打开的文件描述符），但其代码、数据和堆栈会被新的程序替换。动态链接器（如 `ld-linux.so` 或 `linker64`）会在新进程启动时被加载，并负责加载和链接程序依赖的共享库。
* **`strerror(int errnum)`:**  将错误码转换为错误消息字符串。在测试中，它用于在 `execve` 调用失败时打印错误信息。
    * **实现:** `strerror` 通常使用一个静态的字符串数组来存储各种错误码对应的错误消息。它根据传入的错误码 `errnum` 查找对应的字符串并返回。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

* **SO 布局样本 (以 `memtag_globals_binary` 为例，假设它是动态链接的):**

```
LOAD 0x000000xxxxxxxxxxxx  # .text (代码段), 包含可执行指令
LOAD 0x000000yyyyyyyyyyyy  # .rodata (只读数据段), 包含常量
LOAD 0x000000zzzzzzzzzzzz  # .data (已初始化数据段), 包含已初始化的全局变量
LOAD 0x000000aaaaaaaaaaaa  # .bss (未初始化数据段), 包含未初始化的全局变量

DYNAMIC:
  TAG_NEEDED: libc.so  # 依赖的共享库
  TAG_SYMTAB: ...       # 符号表
  TAG_STRTAB: ...       # 字符串表
  TAG_PLTGOT: ...       # PLT/GOT 表
  TAG_RELR: ...         # RELR 重定位表 (如果使用)
  ...
```

* **链接的处理过程:**

1. **`execve` 调用:** 当 `execve` 被调用时，内核会加载可执行文件的头部信息，并识别出它是一个动态链接的程序。
2. **加载动态链接器:** 内核会加载与该体系结构匹配的动态链接器 (`/system/bin/linker64` 或类似路径）。
3. **动态链接器初始化:** 动态链接器开始初始化自身，例如设置堆栈、解析环境变量等。
4. **加载依赖库:** 动态链接器会解析可执行文件的 `DYNAMIC` 段，找到它依赖的共享库 (例如 `libc.so`)。然后，它会尝试在系统路径中找到这些库并加载到内存中。
5. **符号解析和重定位:**
   * **符号查找:** 动态链接器会遍历已加载的共享库的符号表，查找程序中引用的外部符号（例如，来自 `libc.so` 的函数）。
   * **重定位:**  由于共享库被加载到内存中的地址可能不是编译时确定的地址，动态链接器需要修改程序和共享库中的某些指令和数据，使其指向正确的内存地址。
     * **RELR (Relative Relocations):**  RELR 是一种优化的重定位方式，它使用相对偏移量来减少重定位表的大小。测试用例中提到的 `RelrRegressionTestForb314038442` 就是针对 RELR 重定位过程中可能出现的问题进行测试的，特别是在涉及到 MTE 时。
6. **MTE 标签的分配 (如果启用):**  当 MTE 功能启用时，动态链接器在为全局变量分配内存时（通常在 `.data` 和 `.bss` 段），会为这些内存区域分配和关联 MTE 标签。这确保了对这些全局变量的访问可以被 MTE 监控。
7. **程序启动:**  动态链接完成后，动态链接器会将控制权转移到程序的入口点，程序开始执行。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

在 `MemtagGlobalsTest::test` 这个测试用例中：

* **假设输入 (对于动态链接的情况):**
    * 存在一个名为 `memtag_globals_binary` 的动态链接可执行文件。
    * 该可执行文件在运行时会尝试写入超出其全局缓冲区范围的数据，从而触发全局缓冲区溢出。
    * MTE 功能在测试环境中是启用的。

* **预期输出 (对于动态链接的情况):**
    * `execve` 调用会导致程序启动并执行。
    * 当发生全局缓冲区溢出时，MTE 会检测到错误。
    * 进程会因为收到 `SIGSEGV` 信号而终止。
    * 测试框架会捕获到 `-SIGSEGV` 的返回值，并判断测试通过。

* **假设输入 (对于静态链接的情况):**
    * 存在一个名为 `memtag_globals_binary_static` 的静态链接可执行文件。
    * 该可执行文件可能包含类似的缓冲区溢出逻辑，但由于是静态链接，MTE 对其全局变量不起作用。
    * 该可执行文件内部包含断言，用于检查内存操作的正确性。

* **预期输出 (对于静态链接的情况):**
    * `execve` 调用会导致程序启动并执行。
    * 即使存在潜在的缓冲区溢出，MTE 也不会触发 `SIGSEGV`。
    * 可执行文件内部的断言会执行，如果断言通过，程序会正常退出，返回值为 0。
    * 测试框架会捕获到 0 的返回值，并判断测试通过，并记录 "Assertions were passed"。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **未对齐的内存访问:** 虽然 MTE 主要针对越界访问，但某些 MTE 实现可能对未对齐的访问也有限制的检测能力。用户代码如果尝试以不符合硬件要求的对齐方式访问全局变量，可能会导致意外行为或崩溃。
* **在不支持 MTE 的设备上运行依赖 MTE 的代码:** 如果开发者在开发过程中依赖 MTE 来检测错误，但将应用部署到不支持 MTE 的旧设备上，那么这些内存错误可能无法被及时发现。
* **错误地假设 MTE 可以捕获所有类型的内存错误:** MTE 主要针对基于 tag 的内存访问错误。其他类型的内存错误，例如使用未初始化的变量，可能无法被 MTE 直接捕获。
* **过度依赖 MTE 而忽略了代码审查和静态分析:** MTE 是一种运行时检测工具，不应取代良好的编程习惯和静态代码分析。开发者不应该因为有 MTE 就放松对代码质量的要求。
* **与 ASan/HWAsan 的冲突:** 正如测试代码中指出的，MTE globals 测试与 HWAsan 不兼容。在某些调试场景下，开发者可能需要在 MTE 和 ASan/HWAsan 之间做出选择，避免冲突。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 或 NDK 应用本身不会直接调用到 `memtag_globals_test.cpp` 中的代码。这个文件是一个**测试文件**，它属于 Android 平台的开发和测试流程。

**Android Framework 如何间接关联:**

1. **Android 平台的构建和测试:**  `memtag_globals_test.cpp` 是 Android 平台源代码树的一部分。在构建 Android 系统时，这些测试文件会被编译并执行，以验证 Bionic 库的正确性。
2. **Bionic 库作为基础:** Android Framework 的许多组件以及系统服务都依赖于 Bionic 库提供的基本功能，包括内存管理、线程、文件操作等。MTE 作为 Bionic 的一部分，其正确性直接影响到整个系统的稳定性。
3. **Framework 的内存管理:** 虽然 Framework 通常使用 Java 或 Kotlin 编写，但其底层仍然会涉及到 Native 代码和 Bionic 库。Framework 的某些部分，或者其依赖的 Native 库，可能会受益于 MTE 提供的内存安全保护。

**NDK 如何间接关联:**

1. **NDK 应用链接到 Bionic:** NDK 应用在编译时会链接到 Android 设备的 Bionic 库。如果 NDK 应用使用了全局变量，并且运行在支持 MTE 的设备上，那么 MTE 就能为这些全局变量提供保护。
2. **开发者使用 NDK 进行性能优化或访问底层功能:** NDK 开发者可能会出于性能考虑或需要访问某些 Android Framework 不提供的底层功能而使用 Native 代码。在这种情况下，Bionic 库的稳定性和安全性就显得尤为重要。

**Frida Hook 示例调试步骤:**

要调试与 MTE 全局变量相关的行为，可以使用 Frida Hook 技术来拦截和观察关键函数的调用。以下是一些可能的 Hook 点和示例：

1. **Hook `execve` 系统调用:**  可以观察测试可执行文件的启动。

```javascript
// Frida script
Interceptor.attach(Module.findExportByName(null, "execve"), {
  onEnter: function (args) {
    console.log("execve called");
    console.log("  pathname: " + Memory.readUtf8String(args[0]));
    // ... 打印其他参数
  },
  onLeave: function (retval) {
    console.log("execve returned: " + retval);
  }
});
```

2. **Hook 与 MTE 相关的 Bionic 内部函数 (如果已知):**  如果知道 Bionic 中负责分配和标记全局变量内存的具体函数，可以尝试 Hook 这些函数。这需要对 Bionic 的内部实现有一定的了解。例如，可能会有与内存分配器或动态链接器相关的内部函数。

```javascript
// Frida script (假设存在一个名为 "__bionic_allocate_global_with_tag" 的函数)
const allocateGlobalFn = Module.findExportByName("libc.so", "__bionic_allocate_global_with_tag");
if (allocateGlobalFn) {
  Interceptor.attach(allocateGlobalFn, {
    onEnter: function (args) {
      console.log("__bionic_allocate_global_with_tag called");
      console.log("  size: " + args[0]);
      // ... 打印其他参数
    },
    onLeave: function (retval) {
      console.log("__bionic_allocate_global_with_tag returned: " + retval);
    }
  });
}
```

3. **Hook 动态链接器中的关键函数:** 可以尝试 Hook 动态链接器 (`linker64` 或 `ld-android.so`) 中负责处理全局变量重定位和 MTE 标签的函数。这需要对动态链接器的实现有深入的了解。

```javascript
// Frida script (Hook linker 中的一个函数，名称需要根据实际情况确定)
const linkerFunc = Module.findExportByName("/system/bin/linker64", "__linker_handle_global_relocation_mte");
if (linkerFunc) {
  Interceptor.attach(linkerFunc, {
    onEnter: function (args) {
      console.log("__linker_handle_global_relocation_mte called");
      // ... 检查参数，例如全局变量的地址
    },
    onLeave: function (retval) {
      // ...
    }
  });
}
```

**调试步骤示例:**

1. **准备环境:** 确保拥有一个可以运行 Frida 的 Android 设备或模拟器，并且目标设备上启用了 MTE 功能。
2. **编写 Frida 脚本:** 根据需要 Hook 的函数编写 Frida JavaScript 脚本。
3. **运行 Frida:** 使用 Frida 连接到目标设备上的测试进程或运行测试的进程。
   ```bash
   frida -U -f <测试可执行文件的包名或进程名> -l your_frida_script.js --no-pause
   ```
4. **分析输出:** 查看 Frida 的输出，分析 Hook 点的调用情况和参数，从而了解 MTE 在全局变量处理过程中的行为。

请注意，Hook 系统库或动态链接器的内部函数可能比较复杂，需要深入了解 Android 平台的实现细节，并且不同 Android 版本之间可能存在差异。 上述 Frida 脚本示例仅供参考，具体的 Hook 点和实现方式需要根据实际的调试目标和环境进行调整。

### 提示词
```
这是目录为bionic/tests/memtag_globals_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <gtest/gtest.h>

#if defined(__BIONIC__)
#include "gtest_globals.h"
#include "utils.h"
#endif  // defined(__BIONIC__)

#include <android-base/test_utils.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <tuple>

#include "platform/bionic/mte.h"

class MemtagGlobalsTest : public testing::TestWithParam<bool> {};

TEST_P(MemtagGlobalsTest, test) {
  SKIP_WITH_HWASAN << "MTE globals tests are incompatible with HWASan";
#if defined(__BIONIC__) && defined(__aarch64__)
  std::string binary = GetTestLibRoot() + "/memtag_globals_binary";
  bool is_static = MemtagGlobalsTest::GetParam();
  if (is_static) {
    binary += "_static";
  }

  chmod(binary.c_str(), 0755);
  ExecTestHelper eth;
  eth.SetArgs({binary.c_str(), nullptr});
  eth.Run(
      [&]() {
        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
      },
      // We catch the global-buffer-overflow and crash only when MTE globals is
      // supported. Note that MTE globals is unsupported for fully static
      // executables, but we should still make sure the binary passes its
      // assertions, just that global variables won't be tagged.
      (mte_supported() && !is_static) ? -SIGSEGV : 0, "Assertions were passed");
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

INSTANTIATE_TEST_SUITE_P(MemtagGlobalsTest, MemtagGlobalsTest, testing::Bool(),
                         [](const ::testing::TestParamInfo<MemtagGlobalsTest::ParamType>& info) {
                           if (info.param) return "MemtagGlobalsTest_static";
                           return "MemtagGlobalsTest";
                         });

TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442) {
  SKIP_WITH_HWASAN << "MTE globals tests are incompatible with HWASan";
#if defined(__BIONIC__) && defined(__aarch64__)
  std::string binary = GetTestLibRoot() + "/mte_globals_relr_regression_test_b_314038442";
  chmod(binary.c_str(), 0755);
  ExecTestHelper eth;
  eth.SetArgs({binary.c_str(), nullptr});
  eth.Run(
      [&]() {
        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
      },
      /* exit code */ 0, "Program loaded successfully.*Tags are zero!");
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}

TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442WithMteGlobals) {
  if (!mte_supported()) GTEST_SKIP() << "Must have MTE support.";
#if defined(__BIONIC__) && defined(__aarch64__)
  std::string binary = GetTestLibRoot() + "/mte_globals_relr_regression_test_b_314038442_mte";
  chmod(binary.c_str(), 0755);
  ExecTestHelper eth;
  eth.SetArgs({binary.c_str(), nullptr});
  eth.Run(
      [&]() {
        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
      },
      /* exit code */ 0, "Program loaded successfully.*Tags are non-zero");
#else
  GTEST_SKIP() << "bionic/arm64 only";
#endif
}
```