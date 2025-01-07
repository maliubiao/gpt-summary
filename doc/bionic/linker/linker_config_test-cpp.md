Response:
Let's break down the thought process for analyzing the `linker_config_test.cpp` file.

**1. Understanding the Context:**

The first step is to grasp the purpose of the file. The prompt clearly states it's a test file (`*_test.cpp`) within the `bionic/linker` directory. Bionic is Android's core C library and dynamic linker. Therefore, this file likely tests the functionality of the dynamic linker's configuration parsing.

**2. Initial Scan for Key Elements:**

A quick skim of the code reveals several important components:

* **Includes:**  `<stdlib.h>`, `<string.h>`, `<sys/mman.h>`, `<gtest/gtest.h>`,  `linker_config.h`, `linker_utils.h`, `<unistd.h>`, `<android-base/...>`. These headers suggest the code interacts with standard C libraries, memory management, Google Test framework, and Android-specific utilities. The presence of `linker_config.h` is crucial – it's the primary component being tested.
* **`config_str`:** This large string literal looks like a configuration file. The structure with sections and key-value pairs strongly suggests it's an `ld.config.txt` file (or a similar format).
* **`write_version` function:**  This function writes a version number to a file. This hints at testing how the linker configuration interacts with target SDK versions.
* **`resolve_paths` function:** This function likely takes a list of paths and resolves symbolic links or relative paths to absolute paths.
* **`run_linker_config_smoke_test` function:** This function appears to be a parameterized test runner, taking a `SmokeTestType` enum. The different cases (`None`, `Asan`, `Hwasan`) suggest it tests different configurations related to AddressSanitizer and Hardware AddressSanitizer.
* **`TEST` macros:**  These are part of the Google Test framework and clearly define individual test cases.

**3. Deciphering the `config_str`:**

This is the core of the test. I need to analyze the structure and meaning of the configuration:

* **Sections:**  `[test]` defines a section.
* **Key-Value Pairs:**  `key = value` format.
* **`dir.test`:**  Defines a directory variable.
* **`enable.target.sdk.version`:** A boolean flag.
* **`additional.namespaces`:**  Specifies additional linker namespaces. The `+=` suggests appending to a list.
* **`namespace.default.*`, `namespace.system.*`, `namespace.vndk.*`, `namespace.vndk_in_system.*`:** These sections define configurations for different linker namespaces. Key attributes include:
    * `isolated`: Whether the namespace is isolated.
    * `visible`: Whether the namespace is visible to others.
    * `search.paths`: Directories to search for shared libraries. `${LIB}` is a placeholder.
    * `permitted.paths`: Directories that are allowed for loading libraries.
    * `links`: Defines links to other namespaces.
    * `link.<target_namespace>.shared_libs`:  Specifies shared libraries to link to a target namespace.
    * `link.<target_namespace>.allow_all_shared_libs`: A boolean to allow linking all libraries from the target namespace.
    * `whitelisted`, `allowed_libs`: Lists of allowed libraries (for specific namespace types).
* **Comments:** `#` denotes comments.
* **Whitespace Handling:** The comment about "irregular whitespaces" indicates the test is checking the parser's robustness against varied formatting.

**4. Analyzing the Test Cases:**

* **`smoke` tests:**  These are basic tests to verify core functionality. The `run_linker_config_smoke_test` function sets up expected values based on the `SmokeTestType` and then reads the configuration. It asserts that the parsed configuration matches the expectations. The different `SmokeTestType` values show how ASan and HWASan influence the search and permitted paths.
* **`ns_link_shared_libs_invalid_settings`:** This test specifically checks for an error condition: when both `shared_libs` and `allow_all_shared_libs` are defined for the same namespace link. This is a crucial test for validating error handling.
* **`dir_path_resolve`:** This test checks if the linker configuration correctly resolves symbolic links in the `dir.*` properties. It creates a temporary directory, a subdirectory, and a symlink to the subdirectory, and then verifies that the parsed configuration uses the real path of the subdirectory.

**5. Connecting to Android Functionality:**

The linker configuration is fundamental to how Android loads and manages shared libraries. The namespaces provide isolation and control over library dependencies. This is crucial for:

* **Security:** Preventing applications from accessing unintended system libraries.
* **Stability:**  Managing dependencies between different parts of the system and applications.
* **Modularity:** Allowing different components to have their own sets of libraries.

The different namespaces (default, system, VNDK) are key parts of Android's library organization. VNDK (Vendor Native Development Kit) is particularly important for separating vendor-specific libraries from the core system.

**6. Explaining Libc Functions (as requested):**

The prompt asked for explanations of libc functions. I identified the libc functions used in the test:

* `close()`: Closes a file descriptor.
* `unlink()`: Deletes a file.
* `mkdir()`: Creates a directory.
* `rmdir()`: Removes a directory.
* `symlink()`: Creates a symbolic link.

For each, I provided a brief explanation of its purpose.

**7. Dynamic Linker Aspects:**

The entire test revolves around the dynamic linker's configuration. The `so` layout and linking process involve:

* **Namespaces:**  The `ld.config.txt` defines the namespaces, which act as isolated environments for libraries.
* **Search Paths:** The `search.paths` within each namespace tell the linker where to look for `.so` files.
* **Permitted Paths:**  `permitted.paths` restrict where libraries can be loaded from.
* **Links:**  Namespace links define dependencies between namespaces, allowing libraries from one namespace to be used in another.
* **Shared Libraries:** The `shared_libs` lists specify which libraries to explicitly link when a namespace is linked.
* **`allow_all_shared_libs`:** This allows linking any library from the target namespace.

I described a hypothetical scenario with an `app.so` depending on libraries in different namespaces to illustrate the linking process.

**8. Common User Errors:**

I brainstormed common mistakes developers might make when dealing with linker configurations, such as incorrect paths, typos, conflicts in link settings, and understanding namespace isolation.

**9. Android Framework/NDK Integration:**

I explained that the linker configuration is read early in the Android boot process and when apps are launched. The framework and NDK don't directly interact with this *test file*, but the concepts it tests are core to their operation.

**10. Frida Hook Example:**

I crafted a Frida script to hook the `Config::read_binary_config` function, demonstrating how to intercept and inspect the configuration loading process.

**11. Language and Formatting:**

Finally, I ensured the response was in Chinese as requested and used clear, concise language. I also paid attention to formatting to improve readability (e.g., using code blocks for examples).

This iterative process of understanding the context, identifying key components, analyzing the code, connecting it to the larger system, and addressing the specific points in the prompt allows for a comprehensive and accurate explanation.
这个文件 `bionic/linker/linker_config_test.cpp` 是 Android Bionic 库中动态链接器配置功能的单元测试文件。它的主要功能是测试 `linker_config.h` 中定义的 `Config` 类及其相关功能，该类负责解析和管理动态链接器的配置文件（通常是 `ld.config.txt` 或其二进制形式）。

下面详细列举其功能和与 Android 功能的关系，并解释涉及的代码细节：

**1. 功能列举:**

* **解析动态链接器配置文件:**  测试 `Config::read_binary_config` 函数，该函数负责读取并解析动态链接器的配置文件内容。配置文件定义了库的搜索路径、命名空间隔离、链接关系等重要信息。
* **验证配置项的正确解析:**  测试各种配置项是否被正确解析和存储到 `Config` 对象中，例如：
    * `dir.<section>`: 目录变量的解析和路径解析。
    * `enable.target.sdk.version`: 目标 SDK 版本的启用状态。
    * `additional.namespaces`: 额外的命名空间。
    * `namespace.<name>.isolated`: 命名空间是否隔离。
    * `namespace.<name>.visible`: 命名空间是否可见。
    * `namespace.<name>.search.paths`: 命名空间的搜索路径。
    * `namespace.<name>.permitted.paths`: 命名空间的允许路径。
    * `namespace.<name>.links`: 命名空间之间的链接关系。
    * `namespace.<name>.link.<target_namespace>.shared_libs`:  指定链接到目标命名空间的共享库。
    * `namespace.<name>.link.<target_namespace>.allow_all_shared_libs`:  允许链接目标命名空间的所有共享库。
    * `namespace.<name>.whitelisted`: 允许的库列表。
    * `namespace.<name>.allowed_libs`: 允许的库列表（另一种形式）。
* **测试不同配置场景:**  通过 `run_linker_config_smoke_test` 函数和 `SmokeTestType` 枚举，测试在不同场景下（例如是否启用 ASan 或 HWASan）配置解析的行为。
* **测试错误处理:**  测试当配置文件中存在错误配置时，`Config::read_binary_config` 是否能正确检测并返回错误信息。例如，测试 `ns_link_shared_libs_invalid_settings` 检查同时设置 `shared_libs` 和 `allow_all_shared_libs` 的情况。
* **路径解析:** 测试 `dir.` 配置项中的路径是否被正确解析，包括处理符号链接。

**2. 与 Android 功能的关系及举例说明:**

动态链接器配置是 Android 系统启动和应用运行的关键组成部分。它控制着库的加载和链接行为，直接影响到系统的稳定性和安全性。

* **命名空间隔离:**  `namespace.<name>.isolated` 配置项用于实现命名空间隔离。例如，`namespace.default.isolated = true` 意味着默认命名空间是隔离的，应用程序默认情况下只能访问其允许的库，这提高了安全性，防止应用访问不应访问的系统库。
* **库搜索路径:**  `namespace.<name>.search.paths` 定义了动态链接器在哪些目录下查找共享库。例如，`namespace.system.search.paths = /system/${LIB}` 指示系统命名空间会在 `/system/lib` (或 `/system/lib64` 在 64 位系统上) 下查找库。这确保了系统库能够被正确加载。
* **VNDK (Vendor Native Development Kit):**  配置文件中包含了 `namespace.vndk` 和 `namespace.vndk_in_system` 的配置。VNDK 是 Android 中用于分隔平台代码和供应商代码的重要机制。通过配置，可以控制哪些库属于 VNDK，哪些库可以被供应商代码使用，以及 VNDK 库如何与系统库链接。
    * 例如，`namespace.vndk.search.paths = /system/${LIB}/vndk` 指定了 VNDK 库的搜索路径。
    * `namespace.vndk_in_system.whitelisted = libz.so:libyuv.so:libtinyxml2.so`  定义了 `vndk_in_system` 命名空间中允许的白名单库。
* **ASan/HWASan 支持:**  配置文件中包含 `*.asan.search.paths` 和 `*.hwasan.search.paths` 等配置，用于指定在启用 AddressSanitizer 或 Hardware AddressSanitizer 时的库搜索路径。这允许在调试和测试阶段使用 ASan/HWASan 来检测内存错误。

**3. 详细解释 libc 函数的功能实现:**

该测试文件中使用了一些 libc 函数：

* **`stdlib.h` 中的函数:**
    * `atoi()`:  尽管代码中没有直接使用 `atoi`，但 `android::base::StringPrintf` 和 `android::base::WriteStringToFile` 内部可能会使用到字符串到整数的转换函数。`atoi` 的基本实现是将字符串形式的数字转换为整数。它会跳过前导空格，然后读取数字字符，直到遇到非数字字符或字符串结束符。错误处理通常比较简单，如果字符串无法转换为整数，则返回 0。
    * `malloc()`, `free()`:  动态内存分配和释放。这些函数是 C 语言内存管理的基础。`malloc` 从堆中分配指定大小的内存块，并返回指向该内存块的指针。`free` 将之前由 `malloc` 或相关函数分配的内存块释放回堆中。
* **`string.h` 中的函数:**
    * `strcmp()`:  字符串比较函数。用于比较两个字符串是否相等。它逐个比较字符串中的字符，直到遇到不同的字符或字符串结束符。如果两个字符串完全相同，则返回 0。
    * `strlen()`:  计算字符串的长度，不包括字符串结束符 `\0`。它从字符串的起始位置开始计数，直到遇到 `\0`。
    * `strcpy()`/`strncpy()`:  字符串复制函数。`strcpy` 将源字符串复制到目标字符串，包括 `\0`。`strncpy` 复制指定数量的字符，如果源字符串长度大于指定数量，则不会复制 `\0`。
* **`sys/mman.h` 中的函数:**
    * `mmap()`:  创建内存映射。可以将文件或设备映射到进程的地址空间，或者创建匿名映射。这允许高效地访问文件内容或共享内存。
    * `munmap()`:  解除内存映射。将之前由 `mmap` 创建的映射从进程的地址空间中移除。
* **`unistd.h` 中的函数:**
    * `close()`:  关闭一个文件描述符。文件描述符是内核用来标识打开文件或 socket 的整数。关闭文件描述符会释放相关的系统资源。
    * `unlink()`:  删除一个文件。它从文件系统中移除指定的文件名。
    * `mkdir()`: 创建一个目录。
    * `rmdir()`: 删除一个空目录。
    * `symlink()`: 创建一个符号链接。符号链接是一个特殊类型的文件，它指向另一个文件或目录。

**4. 涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程:**

此测试文件主要关注的是动态链接器的配置，而不是链接的实际执行过程。但可以根据配置内容推断链接行为。

**SO 布局样本 (假设 `namespace.default.link.system.shared_libs = libc.so:libm.so:libdl.so`)：**

假设有一个应用程序 `app` 链接到默认命名空间，并且默认命名空间链接到系统命名空间。

```
/system/lib[64]/libc.so
/system/lib[64]/libm.so
/system/lib[64]/libdl.so
/vendor/lib[64]/some_vendor_lib.so
/data/local/tmp/app  // 应用程序本身
```

**链接的处理过程:**

1. **应用程序启动:** 当应用程序 `app` 启动时，Android 的 `zygote` 进程会 fork 出一个新的进程来运行该应用。
2. **动态链接器启动:** 新进程的启动过程会调用动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。
3. **读取配置:** 动态链接器会读取其配置文件（由 `linker_config_test.cpp` 测试的解析过程）。根据配置，动态链接器会了解到：
    * 默认命名空间是隔离的。
    * 默认命名空间链接到 `system` 命名空间。
    * 链接到 `system` 命名空间时，需要加载 `libc.so`, `libm.so`, `libdl.so`。
4. **加载共享库:**
    * 动态链接器首先在默认命名空间的搜索路径（例如 `/vendor/lib[64]`) 中查找应用程序依赖的库。
    * 由于默认命名空间链接到 `system` 命名空间，并且指定了 `shared_libs`，动态链接器会在 `system` 命名空间的搜索路径（例如 `/system/lib[64]`) 中查找 `libc.so`, `libm.so`, `libdl.so` 并加载它们。
5. **符号解析:** 动态链接器会解析应用程序及其加载的共享库中的符号引用，将函数调用和全局变量访问指向正确的内存地址。例如，如果 `app` 中调用了 `printf` 函数（在 `libc.so` 中定义），动态链接器会将该调用指向 `libc.so` 中 `printf` 的实现地址。

**5. 逻辑推理，假设输入与输出:**

**假设输入 (基于 `config_str`)：**

一个待加载的应用程序 `/data/local/tmp/my_app`。

**逻辑推理:**

根据 `config_str` 中的配置：

* 应用程序运行在 `default` 命名空间。
* `default` 命名空间是隔离的。
* `default` 命名空间链接到 `system` 和 `vndk` 命名空间。
* 链接到 `system` 命名空间时，会加载 `libc.so`, `libm.so`, `libdl.so`, `libstdc++.so`。
* 链接到 `vndk` 命名空间时，会加载 `libcutils.so`, `libbase.so`。
* `default` 命名空间的搜索路径是 `/vendor/lib[64]`。

**预期输出 (动态链接器的行为):**

* 动态链接器首先会在 `/vendor/lib[64]` 中查找 `my_app` 依赖的共享库。
* 如果 `my_app` 依赖于 `libc.so`, `libm.so`, `libdl.so`, `libstdc++.so`，动态链接器会在 `/system/lib[64]` 中找到并加载它们。
* 如果 `my_app` 依赖于 `libcutils.so`, `libbase.so`，动态链接器会在 `/system/lib[64]/vndk` 中找到并加载它们。
* 由于 `default` 命名空间是隔离的，`my_app` 无法直接加载不在其搜索路径或链接的命名空间中的库。

**6. 用户或编程常见的使用错误:**

* **配置路径错误:**  在 `ld.config.txt` 中配置了错误的搜索路径，导致动态链接器无法找到需要的共享库。例如，将 `/system/lib` 误写成 `/systm/lib`。
* **命名空间隔离理解不足:**  不理解命名空间隔离的概念，导致应用程序尝试加载不应该访问的系统库，或者在不同的命名空间之间出现库冲突。
* **链接库配置错误:** 在 `namespace.<name>.link.<target_namespace>.shared_libs` 中指定了不存在的库名，或者同时设置了 `shared_libs` 和 `allow_all_shared_libs` 导致配置冲突。
* **`${LIB}` 宏的误用:**  不清楚 `${LIB}` 宏的含义，在 32 位系统上错误地使用了 64 位路径，或者反之。
* **权限问题:** 尽管配置文件正确，但由于文件系统权限问题，动态链接器可能无法读取配置文件或加载共享库。

**7. Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

动态链接器配置的加载发生在 Android 系统启动的早期阶段和应用程序启动时。

**系统启动过程:**

1. **`init` 进程启动:** Android 系统的第一个进程是 `init`。
2. **`zygote` 进程启动:** `init` 进程会启动 `zygote` 进程，它是所有 Android 应用进程的父进程。
3. **动态链接器加载到 `zygote`:**  `zygote` 进程本身也是一个 native 进程，它的启动也依赖于动态链接器。在 `zygote` 启动过程中，动态链接器会读取全局的配置文件（通常位于 `/system/etc/ld.config.txt` 或其二进制形式）。
4. **配置被解析和应用:** 动态链接器解析配置文件，构建内部的数据结构，用于后续应用进程的库加载和链接。

**应用程序启动过程:**

1. **`zygote` fork 新进程:** 当启动一个新的 Android 应用程序时，`zygote` 进程会使用 `fork()` 系统调用创建一个新的子进程。
2. **`linker` 接管:** 新的应用程序进程启动后，执行的第一个代码是动态链接器。
3. **读取应用特定的配置 (可能):**  根据应用程序的属性或安全上下文，动态链接器可能会读取额外的、特定于应用程序的配置文件。这部分配置会与全局配置合并或覆盖。
4. **根据配置加载库:**  动态链接器根据解析后的配置信息，确定应用程序需要的库的搜索路径、依赖关系和命名空间，并加载必要的共享库。

**NDK 的关系:**

当使用 NDK 开发 native 代码时，编译生成的共享库会被打包到 APK 文件中。当应用加载这些 native 库时，动态链接器会按照上述过程进行加载和链接。NDK 开发者通常不需要直接操作 `ld.config.txt`，但他们编写的 native 代码的行为会受到动态链接器配置的影响。

**Frida Hook 示例:**

可以使用 Frida hook `Config::read_binary_config` 函数来观察配置文件的加载和解析过程。

```javascript
// hook linker_config.cc 中的 Config::read_binary_config 函数

Interceptor.attach(Module.findExportByName("linker", "_ZN6Config19read_binary_configEPKcS1_bbPKS_PS1_"), {
  onEnter: function (args) {
    console.log("Config::read_binary_config called");
    console.log("  config_path:", Memory.readUtf8String(args[0]));
    console.log("  executable_path:", Memory.readUtf8String(args[1]));
    console.log("  is_asan:", args[2]);
    console.log("  is_hwasan:", args[3]);
  },
  onLeave: function (retval) {
    console.log("Config::read_binary_config returned:", retval);
    if (retval) {
      // 如果成功读取配置，可以尝试访问解析后的 Config 对象
      // 注意：直接访问 C++ 对象可能需要更深入的 Frida 技巧和符号信息
      console.log("  Config object address:", this.context.r0); // 假设返回值在 r0 寄存器中
    } else {
      // 如果读取失败，可以通过 args[5] 获取错误信息
      console.log("  Error message:", Memory.readUtf8String(this.context.r5)); // 假设错误信息指针在 r5 寄存器中
    }
  }
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_linker_config.js`）。
2. 使用 Frida 连接到目标 Android 设备或模拟器上的进程 (例如 `zygote` 或目标应用进程)。
3. 运行 Frida 命令：`frida -U -f <target_process_name_or_pid> -l hook_linker_config.js --no-pause`

**预期输出:**

当动态链接器加载配置文件时，Frida 会拦截 `Config::read_binary_config` 的调用，并打印出配置文件的路径、可执行文件路径以及是否启用了 ASan/HWASan 等信息。如果配置读取成功，还会尝试打印出 `Config` 对象的地址；如果失败，会打印出错误信息。

请注意，直接访问 C++ 对象的内存布局和寄存器依赖于具体的架构和编译选项，上面的 Frida 示例可能需要根据实际情况进行调整。需要有目标进程的符号信息才能更可靠地访问 `Config` 对象的内容。

Prompt: 
```
这是目录为bionic/linker/linker_config_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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
#include <string.h>
#include <sys/mman.h>

#include <gtest/gtest.h>

#include "linker_config.h"
#include "linker_utils.h"

#include <unistd.h>

#include <android-base/file.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <vector>

#if defined(__LP64__)
#define ARCH_SUFFIX "64"
#else
#define ARCH_SUFFIX ""
#endif

// clang-format off
static const char* config_str =
  "# comment \n"
  "dir.test = /data/local/tmp\n"
  "\n"
  "[test]\n"
  "\n"
  "enable.target.sdk.version = true\n"
  "additional.namespaces=system\n"
  "additional.namespaces+=vndk\n"
  "additional.namespaces+=vndk_in_system\n"
  "namespace.default.isolated = true\n"
  "namespace.default.search.paths = /vendor/${LIB}\n"
  "namespace.default.permitted.paths = /vendor/${LIB}\n"
  "namespace.default.asan.search.paths = /data\n"
  "namespace.default.asan.search.paths += /vendor/${LIB}\n"
  "namespace.default.asan.permitted.paths = /data:/vendor\n"
  "namespace.default.hwasan.search.paths = /vendor/${LIB}/hwasan\n"
  "namespace.default.hwasan.search.paths += /vendor/${LIB}\n"
  "namespace.default.hwasan.permitted.paths = /vendor/${LIB}/hwasan\n"
  "namespace.default.hwasan.permitted.paths += /vendor/${LIB}\n"
  "namespace.default.links = system\n"
  "namespace.default.links += vndk\n"
  // irregular whitespaces are added intentionally for testing purpose
  "namespace.default.link.system.shared_libs=  libc.so\n"
  "namespace.default.link.system.shared_libs +=   libm.so:libdl.so\n"
  "namespace.default.link.system.shared_libs   +=libstdc++.so\n"
  "namespace.default.link.vndk.shared_libs = libcutils.so:libbase.so\n"
  "namespace.system.isolated = true\n"
  "namespace.system.visible = true\n"
  "namespace.system.search.paths = /system/${LIB}\n"
  "namespace.system.permitted.paths = /system/${LIB}\n"
  "namespace.system.asan.search.paths = /data:/system/${LIB}\n"
  "namespace.system.asan.permitted.paths = /data:/system\n"
  "namespace.system.hwasan.search.paths = /system/${LIB}/hwasan\n"
  "namespace.system.hwasan.search.paths += /system/${LIB}\n"
  "namespace.system.hwasan.permitted.paths = /system/${LIB}/hwasan\n"
  "namespace.system.hwasan.permitted.paths += /system/${LIB}\n"
  "namespace.vndk.isolated = tr\n"
  "namespace.vndk.isolated += ue\n" // should be ignored and return as 'false'.
  "namespace.vndk.search.paths = /system/${LIB}/vndk\n"
  "namespace.vndk.asan.search.paths = /data\n"
  "namespace.vndk.asan.search.paths += /system/${LIB}/vndk\n"
  "namespace.vndk.hwasan.search.paths = /system/${LIB}/vndk/hwasan\n"
  "namespace.vndk.hwasan.search.paths += /system/${LIB}/vndk\n"
  "namespace.vndk.links = default\n"
  "namespace.vndk.link.default.allow_all_shared_libs = true\n"
  "namespace.vndk.link.vndk_in_system.allow_all_shared_libs = true\n"
  "namespace.vndk_in_system.isolated = true\n"
  "namespace.vndk_in_system.visible = true\n"
  "namespace.vndk_in_system.search.paths = /system/${LIB}\n"
  "namespace.vndk_in_system.permitted.paths = /system/${LIB}\n"
  "namespace.vndk_in_system.whitelisted = libz.so:libyuv.so\n"
  "namespace.vndk_in_system.whitelisted += libtinyxml2.so\n"
  "namespace.vndk_in_system.allowed_libs = libfoo.so:libbar.so\n"
  "namespace.vndk_in_system.allowed_libs += libtinyxml3.so\n"
  "\n";
// clang-format on

static bool write_version(const std::string& path, uint32_t version) {
  std::string content = android::base::StringPrintf("%d", version);
  return android::base::WriteStringToFile(content, path);
}

static std::vector<std::string> resolve_paths(std::vector<std::string> paths) {
  std::vector<std::string> resolved_paths;
  resolve_paths(paths, &resolved_paths);
  return resolved_paths;
}

enum class SmokeTestType {
  None,
  Asan,
  Hwasan,
};

static void run_linker_config_smoke_test(SmokeTestType type) {
  std::vector<std::string> expected_default_search_path;
  std::vector<std::string> expected_default_permitted_path;
  std::vector<std::string> expected_system_search_path;
  std::vector<std::string> expected_system_permitted_path;
  std::vector<std::string> expected_vndk_search_path;

  switch (type) {
    case SmokeTestType::None:
      expected_default_search_path = { "/vendor/lib" ARCH_SUFFIX };
      expected_default_permitted_path = { "/vendor/lib" ARCH_SUFFIX };
      expected_system_search_path = { "/system/lib" ARCH_SUFFIX };
      expected_system_permitted_path = { "/system/lib" ARCH_SUFFIX };
      expected_vndk_search_path = { "/system/lib" ARCH_SUFFIX "/vndk" };
      break;
    case SmokeTestType::Asan:
      expected_default_search_path = { "/data", "/vendor/lib" ARCH_SUFFIX };
      expected_default_permitted_path = { "/data", "/vendor" };
      expected_system_search_path = { "/data", "/system/lib" ARCH_SUFFIX };
      expected_system_permitted_path = { "/data", "/system" };
      expected_vndk_search_path = { "/data", "/system/lib" ARCH_SUFFIX "/vndk" };
      break;
    case SmokeTestType::Hwasan:
      expected_default_search_path = { "/vendor/lib" ARCH_SUFFIX "/hwasan", "/vendor/lib" ARCH_SUFFIX };
      expected_default_permitted_path = { "/vendor/lib" ARCH_SUFFIX "/hwasan", "/vendor/lib" ARCH_SUFFIX };
      expected_system_search_path = { "/system/lib" ARCH_SUFFIX "/hwasan" , "/system/lib" ARCH_SUFFIX };
      expected_system_permitted_path = { "/system/lib" ARCH_SUFFIX "/hwasan", "/system/lib" ARCH_SUFFIX };
      expected_vndk_search_path = { "/system/lib" ARCH_SUFFIX "/vndk/hwasan", "/system/lib" ARCH_SUFFIX "/vndk" };
      break;
  }

  expected_default_search_path = resolve_paths(expected_default_search_path);
  // expected_default_permitted_path is skipped on purpose, permitted paths
  // do not get resolved in linker_config.cpp
  expected_system_search_path = resolve_paths(expected_system_search_path);
  // expected_system_permitted_path is skipped on purpose, permitted paths
  // do not get resolved in linker_config.cpp
  expected_vndk_search_path = resolve_paths(expected_vndk_search_path);

  TemporaryFile tmp_file;
  close(tmp_file.fd);
  tmp_file.fd = -1;

  android::base::WriteStringToFile(config_str, tmp_file.path);

  TemporaryDir tmp_dir;

  std::string executable_path = std::string(tmp_dir.path) + "/some-binary";
  std::string version_file = std::string(tmp_dir.path) + "/.version";

  auto file_guard =
      android::base::make_scope_guard([&version_file] { unlink(version_file.c_str()); });

  ASSERT_TRUE(write_version(version_file, 113U)) << strerror(errno);

  // read config
  const Config* config = nullptr;
  std::string error_msg;
  ASSERT_TRUE(Config::read_binary_config(tmp_file.path,
                                         executable_path.c_str(),
                                         type == SmokeTestType::Asan,
                                         type == SmokeTestType::Hwasan,
                                         &config,
                                         &error_msg)) << error_msg;
  ASSERT_TRUE(config != nullptr);
  ASSERT_TRUE(error_msg.empty());

  ASSERT_EQ(113, config->target_sdk_version());

  const NamespaceConfig* default_ns_config = config->default_namespace_config();
  ASSERT_TRUE(default_ns_config != nullptr);

  ASSERT_TRUE(default_ns_config->isolated());
  ASSERT_FALSE(default_ns_config->visible());
  ASSERT_EQ(expected_default_search_path, default_ns_config->search_paths());
  ASSERT_EQ(expected_default_permitted_path, default_ns_config->permitted_paths());

  const auto& default_ns_links = default_ns_config->links();
  ASSERT_EQ(2U, default_ns_links.size());

  ASSERT_EQ("system", default_ns_links[0].ns_name());
  ASSERT_EQ("libc.so:libm.so:libdl.so:libstdc++.so", default_ns_links[0].shared_libs());
  ASSERT_FALSE(default_ns_links[0].allow_all_shared_libs());

  ASSERT_EQ("vndk", default_ns_links[1].ns_name());
  ASSERT_EQ("libcutils.so:libbase.so", default_ns_links[1].shared_libs());
  ASSERT_FALSE(default_ns_links[1].allow_all_shared_libs());

  auto& ns_configs = config->namespace_configs();
  ASSERT_EQ(4U, ns_configs.size());

  // find second namespace
  const NamespaceConfig* ns_system = nullptr;
  const NamespaceConfig* ns_vndk = nullptr;
  const NamespaceConfig* ns_vndk_in_system = nullptr;
  for (auto& ns : ns_configs) {
    std::string ns_name = ns->name();
    ASSERT_TRUE(ns_name == "system" || ns_name == "default" ||
                ns_name == "vndk" || ns_name == "vndk_in_system")
        << "unexpected ns name: " << ns->name();

    if (ns_name == "system") {
      ns_system = ns.get();
    } else if (ns_name == "vndk") {
      ns_vndk = ns.get();
    } else if (ns_name == "vndk_in_system") {
      ns_vndk_in_system = ns.get();
    }
  }

  ASSERT_TRUE(ns_system != nullptr) << "system namespace was not found";

  ASSERT_TRUE(ns_system->isolated());
  ASSERT_TRUE(ns_system->visible());
  ASSERT_EQ(expected_system_search_path, ns_system->search_paths());
  ASSERT_EQ(expected_system_permitted_path, ns_system->permitted_paths());

  ASSERT_TRUE(ns_vndk != nullptr) << "vndk namespace was not found";

  ASSERT_FALSE(ns_vndk->isolated()); // malformed bool property
  ASSERT_FALSE(ns_vndk->visible()); // undefined bool property
  ASSERT_EQ(expected_vndk_search_path, ns_vndk->search_paths());

  const auto& ns_vndk_links = ns_vndk->links();
  ASSERT_EQ(1U, ns_vndk_links.size());
  ASSERT_EQ("default", ns_vndk_links[0].ns_name());
  ASSERT_TRUE(ns_vndk_links[0].allow_all_shared_libs());

  ASSERT_TRUE(ns_vndk_in_system != nullptr) << "vndk_in_system namespace was not found";
  ASSERT_EQ(std::vector<std::string>({"libz.so", "libyuv.so", "libtinyxml2.so", "libfoo.so",
                                      "libbar.so", "libtinyxml3.so"}),
            ns_vndk_in_system->allowed_libs());
}

TEST(linker_config, smoke) {
  run_linker_config_smoke_test(SmokeTestType::None);
}

TEST(linker_config, asan_smoke) {
  run_linker_config_smoke_test(SmokeTestType::Asan);
}

TEST(linker_config, hwasan_smoke) {
  run_linker_config_smoke_test(SmokeTestType::Hwasan);
}

TEST(linker_config, ns_link_shared_libs_invalid_settings) {
  // This unit test ensures an error is emitted when a namespace link in ld.config.txt specifies
  // both shared_libs and allow_all_shared_libs.

  static const char config_str[] =
    "dir.test = /data/local/tmp\n"
    "\n"
    "[test]\n"
    "additional.namespaces = system\n"
    "namespace.default.links = system\n"
    "namespace.default.link.system.shared_libs = libc.so:libm.so\n"
    "namespace.default.link.system.allow_all_shared_libs = true\n"
    "\n";

  TemporaryFile tmp_file;
  close(tmp_file.fd);
  tmp_file.fd = -1;

  android::base::WriteStringToFile(config_str, tmp_file.path);

  TemporaryDir tmp_dir;

  std::string executable_path = std::string(tmp_dir.path) + "/some-binary";

  const Config* config = nullptr;
  std::string error_msg;
  ASSERT_FALSE(Config::read_binary_config(tmp_file.path,
                                          executable_path.c_str(),
                                          false,
                                          false,
                                          &config,
                                          &error_msg));
  ASSERT_TRUE(config == nullptr);
  ASSERT_EQ(std::string(tmp_file.path) + ":6: "
            "error: both shared_libs and allow_all_shared_libs are set for default->system link.",
            error_msg);
}

TEST(linker_config, dir_path_resolve) {
  // This unit test ensures the linker resolves paths of dir.${section}
  // properties to real path.

  TemporaryDir tmp_dir;

  std::string sub_dir = std::string(tmp_dir.path) + "/subdir";
  mkdir(sub_dir.c_str(), 0755);

  auto subdir_guard =
      android::base::make_scope_guard([&sub_dir] { rmdir(sub_dir.c_str()); });

  std::string symlink_path = std::string(tmp_dir.path) + "/symlink";
  symlink(sub_dir.c_str(), symlink_path.c_str());

  auto symlink_guard =
      android::base::make_scope_guard([&symlink_path] { unlink(symlink_path.c_str()); });

  std::string config_str =
      "dir.test = " + symlink_path + "\n"
      "\n"
      "[test]\n";

  TemporaryFile tmp_file;
  close(tmp_file.fd);
  tmp_file.fd = -1;

  android::base::WriteStringToFile(config_str, tmp_file.path);

  std::string executable_path = sub_dir + "/some-binary";

  const Config* config = nullptr;
  std::string error_msg;

  ASSERT_TRUE(Config::read_binary_config(tmp_file.path,
                                         executable_path.c_str(),
                                         false,
                                         false,
                                         &config,
                                         &error_msg)) << error_msg;

  ASSERT_TRUE(config != nullptr) << error_msg;
  ASSERT_TRUE(error_msg.empty()) << error_msg;
}

"""

```