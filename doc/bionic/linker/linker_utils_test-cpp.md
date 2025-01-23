Response:
Let's break down the thought process for generating the comprehensive response about `linker_utils_test.cpp`.

**1. Understanding the Goal:**

The request asks for a detailed analysis of the provided C++ test file (`linker_utils_test.cpp`) within the context of Android's Bionic library, particularly its dynamic linker. The key is to extract the functionality being tested and relate it to Android's core operations. The request also includes specific requirements like explaining libc functions, detailing dynamic linker interactions, providing SO layouts and linking processes, discussing common errors, and illustrating how the code is reached from Android frameworks/NDK, along with Frida hooking examples.

**2. Initial Examination of the Code:**

The first step is to read through the code and identify the different test cases. Each `TEST(linker_utils, ...)` block focuses on a specific function within `linker_utils.h` (though the header file itself isn't provided, the tests reveal the functions' names and basic behavior). I can immediately see tests for:

* `format_string`:  String manipulation with placeholders.
* `normalize_path`:  Path canonicalization.
* `file_is_in_dir`:  Checking if a file is directly within a directory.
* `file_is_under_dir`: Checking if a file is within or under a directory.
* `parse_zip_path`:  Extracting zip archive and entry paths.
* `page_start`:  Calculating the start address of a memory page.
* `page_offset`: Calculating the offset within a memory page.
* `safe_add`:  Performing addition with overflow protection.

**3. Connecting to Android's Functionality:**

Now, I need to think about how these utility functions are used within the Android dynamic linker and the broader Android system.

* **`format_string`:** This is likely used for constructing paths or other strings dynamically, possibly for loading libraries or resources. Think of `$LIB` as a variable that needs to be replaced.
* **`normalize_path`:**  Essential for security and correctness. Android needs to resolve paths reliably to prevent path traversal vulnerabilities and ensure the correct files are accessed. Consider how applications specify paths to shared libraries.
* **`file_is_in_dir` and `file_is_under_dir`:**  These are access control mechanisms. The linker and other system components need to verify if a file is located in an allowed directory before loading or accessing it. Security contexts and sandbox restrictions are relevant here.
* **`parse_zip_path`:** Android apps are often packaged as APKs, which are ZIP files. The linker needs to parse paths that refer to files *within* an APK.
* **`page_start` and `page_offset`:** These are fundamental to memory management at a low level. The dynamic linker works with memory pages for loading and relocating libraries. Understanding page boundaries is crucial for memory mapping operations.
* **`safe_add`:** Prevents integer overflows, which can lead to security vulnerabilities. This is important when calculating memory addresses or sizes.

**4. Detailing libc Functions:**

The included headers `<stdlib.h>`, `<string.h>`, and `<sys/mman.h>` indicate the use of standard C library functions. I need to explain the purpose of functions like `ASSERT_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE` (from gtest), and the low-level memory management functions.

**5. Explaining Dynamic Linker Interactions:**

This is a crucial part. I need to explain *why* these utilities are important for the dynamic linker. This involves describing the linking process:

* **Loading SOs:**  The linker needs to locate and load shared libraries. The tested path manipulation functions are directly involved in this.
* **Relocation:** After loading, the linker needs to adjust addresses within the loaded libraries. The `page_start` and `page_offset` functions relate to understanding memory layout during relocation.
* **Dependencies:** The linker needs to resolve dependencies between shared libraries. Path manipulation is used to find these dependencies.

I need to provide a simple SO layout example to illustrate how libraries are organized in memory and how the linker interacts with them.

**6. Providing SO Layout and Linking Process:**

A simplified example of an SO layout in memory is helpful. I should include the different sections (e.g., `.text`, `.data`, `.bss`) and briefly explain their purpose. The linking process can be described as a sequence of steps: loading, symbol resolution, relocation, and execution.

**7. Hypothetical Inputs and Outputs:**

For each test case, I should consider the inputs and the expected outputs to illustrate the function's behavior. The tests themselves provide excellent examples.

**8. Common User/Programming Errors:**

Thinking about how developers might misuse these functions is important. Examples include incorrect path construction, assuming a file exists without proper checks, or ignoring potential overflow issues.

**9. Android Framework/NDK Path:**

This requires understanding the higher-level Android components. The process starts with an app request (e.g., starting an Activity). The Android framework then needs to load the app's native libraries. This involves the `dlopen` family of functions, which eventually calls into the dynamic linker. The tested utility functions are used internally by the linker during this process.

**10. Frida Hooking Examples:**

Providing concrete Frida code snippets will help developers understand how to inspect the behavior of these functions at runtime. I need to show how to hook the relevant functions and log their inputs and outputs.

**11. Structuring the Response:**

Finally, I need to organize the information clearly using headings and subheadings to address all the points in the request. Using bolding and formatting can improve readability. It's important to maintain a logical flow, starting with the general functionality and then delving into more specific details.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe I should explain the details of ELF file format.
* **Correction:** While relevant, focusing too much on ELF details might be overkill for this request. I should keep the SO layout explanation relatively simple and focus on how the linker uses the utility functions.
* **Initial Thought:** I could list all the functions in `linker_utils.h`.
* **Correction:**  Since the header file isn't provided, I should stick to the functions explicitly tested in the given code. Listing hypothetical functions could be confusing.
* **Initial Thought:** Should I provide very complex Frida scripts?
* **Correction:**  Simple, illustrative examples are better for understanding the basic hooking principles. More complex scenarios can be added if specifically requested.

By following this structured approach and iterating on the details, I can generate a comprehensive and accurate response that addresses all aspects of the user's request.好的，我们来详细分析一下 `bionic/linker/linker_utils_test.cpp` 这个文件。

**文件功能总览**

`linker_utils_test.cpp` 是 Android Bionic 库中动态链接器 (`linker`) 的一个测试文件。它的主要功能是 **测试 `linker_utils.h` 中定义的一些工具函数的功能是否正确**。这些工具函数通常用于处理字符串、路径、内存地址等与动态链接过程相关的任务。

**与 Android 功能的关系及举例说明**

这个测试文件直接关系到 Android 的核心功能——动态链接。动态链接器负责在程序启动时加载和链接所需的共享库（.so 文件）。 `linker_utils.h` 中定义的工具函数在动态链接的各个阶段都会被使用，例如：

* **路径处理:**  在加载共享库时，链接器需要解析和规范化库的路径。`normalize_path` 函数就用于实现这个功能。例如，当应用程序请求加载 `libfoo.so` 时，链接器可能需要处理类似 `/system/lib64//./libfoo.so` 这样的路径，并将其规范化为 `/system/lib64/libfoo.so`。
* **字符串格式化:** 有时需要根据一些参数动态生成字符串，例如构造错误消息或者构建库的搜索路径。 `format_string` 函数就提供了这种能力。 例如，根据 ABI (Application Binary Interface) 和 SDK 版本动态生成库路径的一部分。
* **内存地址计算:** 链接器需要进行内存地址的计算，例如计算页面的起始地址和偏移量。`page_start` 和 `page_offset` 函数用于执行这些计算。 这在加载和重定位共享库时非常关键。
* **安全性检查:**  链接器需要进行一些安全检查，例如判断一个文件是否在某个目录下。 `file_is_in_dir` 和 `file_is_under_dir` 函数用于执行这类检查，防止加载不信任的库。
* **处理 APK 中的库:** Android 应用通常打包成 APK 文件，其中可能包含共享库。链接器需要能够解析 APK 中库的路径。 `parse_zip_path` 函数用于解析这种路径。

**libc 函数的功能及实现**

这个测试文件本身并没有直接实现 `libc` 函数，而是使用了 `libc` 中的一些标准库函数来进行测试。下面解释一下文件中用到的 `libc` 函数：

* **`stdlib.h`**
    * **`size_t page_size()` (虽然不是标准 libc，但在 Bionic 中提供):**  这个函数返回系统页面的大小（通常是 4096 字节或 16384 字节）。它的实现通常通过系统调用（例如 `sysconf(_SC_PAGESIZE)`）来获取。
* **`string.h`**
    * **`memset(void* s, int c, size_t n)`:**  将内存块 `s` 的前 `n` 个字节设置为值 `c`。实现通常通过汇编优化，快速填充内存。
    * **`strcmp(const char* s1, const char* s2)`:**  比较字符串 `s1` 和 `s2`。实现逐个字符比较，直到遇到不同的字符或字符串结束符。
* **`sys/mman.h`**
    * **`mmap()` (虽然这里没有直接调用，但 `page_start` 等函数隐含了对内存页的理解):**  用于创建新的内存映射。链接器在加载共享库时会使用 `mmap` 将库的代码和数据段映射到进程的地址空间。

**动态链接器功能：SO 布局样本及链接处理过程**

`linker_utils_test.cpp`  主要测试的是链接器的一些辅助功能，而不是链接器本身的核心逻辑。但是，理解测试的上下文需要对动态链接过程有一定的了解。

**SO 布局样本 (简化)**

```
地址空间起始
+-----------------+  <-- 加载基址 (由链接器决定)
|     ELF Header    |
+-----------------+
| Program Headers |  <-- 描述不同的段
+-----------------+
|     .text       |  <-- 代码段 (可执行，只读)
+-----------------+
|     .rodata     |  <-- 只读数据段
+-----------------+
|     .data       |  <-- 已初始化数据段 (可读写)
+-----------------+
|     .bss        |  <-- 未初始化数据段 (可读写，初始化为零)
+-----------------+
|   .dynamic      |  <-- 动态链接信息，例如依赖库、符号表位置
+-----------------+
|  Symbol Table   |  <-- 包含导出和导入的符号信息
+-----------------+
|  String Table   |  <-- 存储符号名称等字符串
+-----------------+
地址空间结束
```

**链接处理过程 (简化)**

1. **加载器 (例如 `app_process`) 启动:** 当 Android 启动一个应用程序时，操作系统会创建一个进程，并加载应用程序的可执行文件 (APK 中的 DEX 文件会被解释或编译成本地代码)。
2. **遇到依赖:**  在执行应用程序代码的过程中，可能会遇到对共享库的依赖。
3. **`dlopen` 请求 (或者由链接器自动处理依赖):**  应用程序可以通过 `dlopen` 系列函数显式加载共享库，或者链接器在处理程序依赖时会自动加载。
4. **查找共享库:** 链接器根据库的名称在预定义的路径中搜索 (例如 `/system/lib64`, `/vendor/lib64` 等)。 `normalize_path` 等工具函数在这里发挥作用。
5. **加载共享库:**  找到库文件后，链接器使用 `mmap` 将其加载到进程的地址空间。
6. **符号解析:** 链接器解析共享库的符号表，找到程序需要使用的函数和变量的地址。
7. **重定位:** 由于共享库被加载到进程地址空间的哪个位置是不确定的（地址空间布局随机化 ASLR），链接器需要修改代码和数据段中的地址引用，使其指向正确的内存位置。 `page_start` 和 `page_offset` 等函数辅助进行内存地址的计算。
8. **依赖库处理:**  如果加载的共享库还有其他的依赖库，链接器会递归地处理这些依赖。
9. **返回句柄:**  `dlopen` 调用成功后，返回一个指向加载的共享库的句柄。

**假设输入与输出 (基于测试用例)**

* **`format_string`:**
    * **假设输入 `str_smoke`:** `"LIB$LIB${LIB${SDKVER}SDKVER$TEST$"`
    * **假设输入 `params`:** `{{ "LIB", "lib32"}, { "SDKVER", "42"}}`
    * **预期输出:** `"LIBlib32${LIB42SDKVER$TEST$"`  (将 `$LIB` 替换为 "lib32"，`${SDKVER}` 替换为 "42")

* **`normalize_path`:**
    * **假设输入:** `"/../root///dir/.///dir2/somedir/../zipfile!/dir/dir9//..///afile"`
    * **预期输出:** `"/root/dir/dir2/zipfile!/dir/afile"` (规范化路径，去除多余的斜杠和 `..`)

* **`file_is_in_dir`:**
    * **假设输入 `file_path`:** `"/foo/bar/file"`
    * **假设输入 `dir_path`:** `"/foo/bar"`
    * **预期输出:** `true` (文件直接位于目录下)

* **`file_is_under_dir`:**
    * **假设输入 `file_path`:** `"/foo/bar/file"`
    * **假设输入 `dir_path`:** `"/foo"`
    * **预期输出:** `true` (文件位于目录下或子目录下)

* **`parse_zip_path`:**
    * **假设输入:** `"/zip/path/file.zip!/path/in/zip"`
    * **预期输出 `zip_path`:** `"/zip/path/file.zip"`
    * **预期输出 `entry_path`:** `"path/in/zip"` (解析出 zip 文件路径和内部条目路径)

* **`page_start` (假设 `kPageSize` 为 4096):**
    * **假设输入:** `0x300222f`
    * **预期输出:** `0x3002000` (返回地址所在页面的起始地址)

* **`page_offset` (假设 `kPageSize` 为 4096):**
    * **假设输入:** `0x30222f`
    * **预期输出:** `0x22f` (返回地址在页面内的偏移量)

* **`safe_add`:**
    * **假设输入 `val`:** `42`, `add`:** `INT64_MAX-42`, `count`:** `42U`
    * **预期输出:** `true` (没有溢出)，`val` 被更新为 `INT64_MAX`

**用户或编程常见的使用错误**

虽然这些工具函数通常由链接器内部使用，但了解它们可以帮助理解一些与动态链接相关的常见错误：

* **路径错误:**  手动构建共享库路径时，可能会出现路径错误，例如多余的斜杠、错误的相对路径等。这可能导致链接器找不到库。 `normalize_path` 函数可以帮助规范化路径，减少这类错误。
* **假设文件位于特定目录:**  在某些情况下，开发者可能会错误地假设某个库文件位于特定的目录下，而没有进行适当的检查。 `file_is_in_dir` 和 `file_is_under_dir` 的逻辑可以帮助理解链接器如何进行安全检查。
* **处理 APK 路径错误:**  当尝试加载 APK 中的共享库时，可能会出现 APK 路径或内部条目路径错误。 `parse_zip_path` 的测试用例展示了如何正确解析这类路径。
* **整数溢出 (针对 `safe_add`):** 虽然 `safe_add` 函数旨在防止溢出，但在其他涉及地址计算的场景中，如果没有进行适当的检查，可能会发生整数溢出，导致内存访问错误或其他安全问题。

**Android Framework 或 NDK 如何到达这里**

1. **应用程序启动:**  当用户启动一个 Android 应用程序时，Zygote 进程 fork 出新的应用程序进程。
2. **`app_process`:**  新进程会执行 `app_process` (或 `app_process64`) 可执行文件，这是 Android 的应用程序进程启动器。
3. **`dalvikvm` 或 `art`:** `app_process` 进程会启动 Dalvik 虚拟机（在旧版本 Android 中）或 ART (Android Runtime，在较新版本中)。
4. **加载 Native 库:** 当应用程序代码需要使用 Native 代码时（例如通过 JNI 调用），ART 会调用 `System.loadLibrary()` 或 `System.load()`。
5. **`dlopen` 系统调用:** 这些 Java 方法最终会调用底层的 `dlopen` 系统调用。
6. **`linker` (动态链接器):**  `dlopen` 系统调用会进入到 Bionic 库中的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。
7. **链接器内部操作:** 链接器执行上述的查找、加载、符号解析和重定位等操作。在这个过程中，`linker_utils.h` 中定义的工具函数会被广泛使用，例如：
    * **路径规范化:**  使用 `normalize_path` 处理库的搜索路径。
    * **字符串格式化:**  可能用于构建错误消息或日志信息。
    * **页面对齐计算:**  使用 `page_start` 和 `page_offset` 进行内存映射和重定位。
    * **安全检查:** 使用 `file_is_in_dir` 或 `file_is_under_dir` 检查库文件是否位于允许的目录下。
    * **APK 路径解析:**  如果加载的库位于 APK 中，使用 `parse_zip_path` 解析路径。

**Frida Hook 示例调试步骤**

可以使用 Frida Hook 来观察这些工具函数的行为。以下是一些示例：

```javascript
// Hook format_string 函数
Interceptor.attach(Module.findExportByName("linker64", "_ZN6format_stringERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEERKSt6vectorISt4pairIS6_S6_ESaIS9_EEE"), {
  onEnter: function(args) {
    console.log("format_string called!");
    console.log("  String to format:", Memory.readUtf8String(args[1]));
    let params = new NativePointer(args[2]);
    let size = params.readUSize();
    console.log("  Number of parameters:", size);
    for (let i = 0; i < size; i++) {
      let pairPtr = params.add(Process.pointerSize * 2 * i);
      let key = Memory.readUtf8String(pairPtr.readPointer());
      let value = Memory.readUtf8String(pairPtr.add(Process.pointerSize).readPointer());
      console.log(`    Parameter ${i}: ${key} = ${value}`);
    }
  },
  onLeave: function(retval) {
    console.log("  Resulting string:", Memory.readUtf8String(this.context.rsi)); // 假设返回值在 rsi 寄存器中
  }
});

// Hook normalize_path 函数
Interceptor.attach(Module.findExportByName("linker64", "_ZN14normalize_pathERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPS6_"), {
  onEnter: function(args) {
    console.log("normalize_path called!");
    console.log("  Input path:", Memory.readUtf8String(args[1]));
  },
  onLeave: function(retval) {
    console.log("  Return value:", retval);
    if (retval.toInt() !== 0) {
      console.log("  Normalized path:", Memory.readUtf8String(arguments[2]));
    }
  }
});

// Hook parse_zip_path 函数
Interceptor.attach(Module.findExportByName("linker64", "_ZN14parse_zip_pathERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPS6_PS6_"), {
  onEnter: function(args) {
    console.log("parse_zip_path called!");
    console.log("  Input path:", Memory.readUtf8String(args[1]));
  },
  onLeave: function(retval) {
    console.log("  Return value:", retval);
    if (retval.toInt() !== 0) {
      console.log("  Zip path:", Memory.readUtf8String(arguments[2]));
      console.log("  Entry path:", Memory.readUtf8String(arguments[3]));
    }
  }
});

// Hook page_start 函数
Interceptor.attach(Module.findExportByName("linker64", "_Z10page_startm"), {
  onEnter: function(args) {
    console.log("page_start called!");
    console.log("  Address:", args[0]);
  },
  onLeave: function(retval) {
    console.log("  Page start:", retval);
  }
});

// Hook file_is_in_dir 函数
Interceptor.attach(Module.findExportByName("linker64", "_Z13file_is_in_dirRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEES7_"), {
  onEnter: function(args) {
    console.log("file_is_in_dir called!");
    console.log("  File path:", Memory.readUtf8String(args[1]));
    console.log("  Directory path:", Memory.readUtf8String(args[2]));
  },
  onLeave: function(retval) {
    console.log("  Return value:", retval);
  }
});
```

**使用方法：**

1. 将 Frida JavaScript 代码保存为 `.js` 文件 (例如 `hook_linker_utils.js`).
2. 找到目标 Android 进程的进程 ID (PID)。
3. 使用 Frida 命令注入 Hook 代码：
   ```bash
   frida -U -f <your_package_name> -l hook_linker_utils.js --no-pause
   # 或者 attach 到已运行的进程
   frida -U <PID> -l hook_linker_utils.js
   ```
4. 当 Android 系统进行动态链接操作时，Frida 会打印出相应的日志信息，显示这些工具函数的输入和输出，帮助你理解它们的行为。

请注意，你需要根据目标 Android 设备的架构 (32位或64位) 和 Bionic 库的版本，调整模块名称 (例如 "linker" 或 "linker64") 和符号名称（可以使用 `frida-ps -U` 找到进程，然后使用 `frida -U -n <process_name> -l list_exports.js` 类似的脚本来列出导出的符号）。

希望这个详细的解释能够帮助你理解 `linker_utils_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linker_utils_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

#include "linker_utils.h"
#include "platform/bionic/page.h"

TEST(linker_utils, format_string) {
  std::vector<std::pair<std::string, std::string>> params = {{ "LIB", "lib32"}, { "SDKVER", "42"}};
  std::string str_smoke = "LIB$LIB${LIB${SDKVER}SDKVER$TEST$";
  format_string(&str_smoke, params);
  ASSERT_EQ("LIBlib32${LIB42SDKVER$TEST$", str_smoke);
}

TEST(linker_utils, normalize_path_smoke) {
  std::string output;
  ASSERT_TRUE(normalize_path("/../root///dir/.///dir2/somedir/../zipfile!/dir/dir9//..///afile", &output));
  ASSERT_EQ("/root/dir/dir2/zipfile!/dir/afile", output);

  ASSERT_TRUE(normalize_path("/../root///dir/.///dir2/somedir/.../zipfile!/.dir/dir9//..///afile", &output));
  ASSERT_EQ("/root/dir/dir2/somedir/.../zipfile!/.dir/afile", output);

  ASSERT_TRUE(normalize_path("/root/..", &output));
  ASSERT_EQ("/", output);

  ASSERT_TRUE(normalize_path("/root/notroot/..", &output));
  ASSERT_EQ("/root/", output);

  ASSERT_TRUE(normalize_path("/a/../../b", &output));
  ASSERT_EQ("/b", output);

  ASSERT_TRUE(normalize_path("/..", &output));
  ASSERT_EQ("/", output);

  output = "unchanged";
  ASSERT_FALSE(normalize_path("root///dir/.///dir2/somedir/../zipfile!/dir/dir9//..///afile", &output));
  ASSERT_EQ("unchanged", output);
}

TEST(linker_utils, file_is_in_dir_smoke) {
  ASSERT_TRUE(file_is_in_dir("/foo/bar/file", "/foo/bar"));
  ASSERT_FALSE(file_is_in_dir("/foo/bar/file", "/foo"));

  ASSERT_FALSE(file_is_in_dir("/foo/bar/file", "/bar/foo"));

  ASSERT_TRUE(file_is_in_dir("/file", ""));
  ASSERT_FALSE(file_is_in_dir("/file", "/"));
}

TEST(linker_utils, file_is_under_dir_smoke) {
  ASSERT_TRUE(file_is_under_dir("/foo/bar/file", "/foo/bar"));
  ASSERT_TRUE(file_is_under_dir("/foo/bar/file", "/foo"));

  ASSERT_FALSE(file_is_under_dir("/foo/bar/file", "/bar/foo"));

  ASSERT_TRUE(file_is_under_dir("/file", ""));
  ASSERT_TRUE(file_is_under_dir("/foo/bar/file", ""));
  ASSERT_FALSE(file_is_under_dir("/file", "/"));
  ASSERT_FALSE(file_is_under_dir("/foo/bar/file", "/"));
}

TEST(linker_utils, parse_zip_path_smoke) {
  std::string zip_path;
  std::string entry_path;

  ASSERT_FALSE(parse_zip_path("/not/a/zip/path/file.zip", &zip_path, &entry_path));
  ASSERT_FALSE(parse_zip_path("/not/a/zip/path/file.zip!path/in/zip", &zip_path, &entry_path));
  ASSERT_TRUE(parse_zip_path("/zip/path/file.zip!/path/in/zip", &zip_path, &entry_path));
  ASSERT_EQ("/zip/path/file.zip", zip_path);
  ASSERT_EQ("path/in/zip", entry_path);

  ASSERT_TRUE(parse_zip_path("/zip/path/file2.zip!/", &zip_path, &entry_path));
  ASSERT_EQ("/zip/path/file2.zip", zip_path);
  ASSERT_EQ("", entry_path);
}

TEST(linker_utils, page_start) {
  const size_t kPageSize = page_size();

  if (kPageSize == 4096) {
    ASSERT_EQ(0x0001000U, page_start(0x0001000));
    ASSERT_EQ(0x3002000U, page_start(0x300222f));
    ASSERT_EQ(0x6001000U, page_start(0x6001fff));
  } else if (kPageSize == 16384) {
    ASSERT_EQ(0x0004000U, page_start(0x0004000));
    ASSERT_EQ(0x3008000U, page_start(0x300822f));
    ASSERT_EQ(0x6004000U, page_start(0x6004fff));
  } else {
    FAIL() << "Page size not supported " << kPageSize;
  }
}

TEST(linker_utils, page_offset) {
  const size_t kPageSize = page_size();

  if (kPageSize == 4096) {
    ASSERT_EQ(0x0U, page_offset(0x0001000));
    ASSERT_EQ(0x22fU, page_offset(0x30222f));
    ASSERT_EQ(0xfffU, page_offset(0x6001fff));
  } else if (kPageSize == 16384) {
    ASSERT_EQ(0x0U, page_offset(0x0004000));
    ASSERT_EQ(0x322fU, page_offset(0x30322f));
    ASSERT_EQ(0x3fffU, page_offset(0x6003fff));
  } else {
    FAIL() << "Page size not supported " << kPageSize;
  }
}

TEST(linker_utils, safe_add) {
  int64_t val = 42;
  ASSERT_FALSE(safe_add(&val, INT64_MAX-20, 21U));
  ASSERT_EQ(42, val);
  ASSERT_TRUE(safe_add(&val, INT64_MAX-42, 42U));
  ASSERT_EQ(INT64_MAX, val);
  ASSERT_TRUE(safe_add(&val, 2000, 42U));
  ASSERT_EQ(2042, val);
}
```