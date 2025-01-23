Response:
Let's break down the thought process for answering the request about `bionic/tests/glob_test.cpp`.

**1. Understanding the Core Request:**

The central task is to analyze the provided C++ code, which is a test file for the `glob` function in Android's Bionic library. The request has several sub-components, each requiring a specific type of analysis:

* **Functionality:** What does this *test file* do?  (Not what `glob` itself does, initially).
* **Relationship to Android:** How does testing `glob` relate to the broader Android system?
* **`libc` Function Details:**  Specifically about the functions tested.
* **Dynamic Linker:** How does `glob` interact with the dynamic linker?
* **Logic/Assumptions:**  Identify any implied logic or assumptions in the tests.
* **Common Errors:**  What mistakes do developers make when using `glob`?
* **Android Framework/NDK Path:** How does a request from the Android framework or NDK eventually use `glob`?
* **Frida Hooking:** How can we observe `glob`'s behavior using Frida?

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the code to get a general idea:

* **Includes:**  `<glob.h>`, `<dirent.h>`, `<sys/cdefs.h>`, `gtest/gtest.h`, `<string>`, `<vector>`, `android-base/file.h`. This tells me it's testing the `glob` function, using standard C library components (directory access, definitions), a testing framework (gtest), and some Android-specific utilities (`android-base/file.h`).
* **Test Structure:** The code uses the Google Test framework (`TEST(glob, ...)`). Each `TEST` function focuses on a specific aspect of `glob`.
* **Helper Functions (Conditional):** The `#if !defined(ANDROID_HOST_MUSL)` block defines several "fake" directory functions (`fake_opendir`, `fake_readdir`, etc.). This strongly suggests that some tests simulate file system interactions without actually touching the real file system. This is a common practice in unit testing for isolation and controlled environments.
* **Assertions:**  The tests heavily rely on `ASSERT_EQ`, `ASSERT_STREQ`, etc., to verify the behavior of `glob`.
* **Focus on Flags:**  Many tests examine the behavior of `glob` with different flags like `GLOB_APPEND`, `GLOB_DOOFFS`, `GLOB_MARK`, `GLOB_NOCHECK`, `GLOB_NOSORT`, `GLOB_ERR`, `GLOB_ALTDIRFUNC`.

**3. Addressing Each Request Sub-Component:**

Now, I'd systematically address each part of the initial request:

* **Functionality (of the test file):** The main purpose is to *test* the `glob` function. It verifies different scenarios, flags, and error conditions. It uses a mock file system for some tests.
* **Relationship to Android:** `glob` is a standard Unix function for pathname expansion. Android uses it for tasks like finding files based on patterns, which is useful in various parts of the system (package management, file explorers, command-line tools, etc.).
* **`libc` Function Details:**
    * **`glob()`:** The core function being tested. I'd explain its purpose: finding pathnames matching a pattern.
    * **`globfree()`:**  The cleanup function. Important to release memory.
    * **`opendir()`, `readdir()`, `closedir()`:**  These are used by `glob` for directory traversal. The test file *mocks* them in some cases, but in real usage, `glob` relies on the actual system calls.
    * **`lstat()`, `stat()`:** Used to get file information (type, etc.) needed for matching. Also mocked in the tests.
    * **`strcpy()`:** Used in the mock `fake_readdir`. This is a standard C string copy function.
* **Dynamic Linker:**  Here, the connection is indirect. `glob` itself doesn't directly involve the dynamic linker *during its execution*. However:
    * `glob` is part of `libc.so`, which *is* loaded by the dynamic linker.
    * Applications using `glob` will have a dependency on `libc.so`, handled by the dynamic linker.
    * The test file itself needs `libc.so` to run.
    I'd provide a basic `libc.so` layout example and explain the linker's role in resolving symbols like `glob`.
* **Logic/Assumptions:**  The "fake" directory functions make specific assumptions:
    * The directory contents are predefined.
    * `lstat` and `stat` always succeed (return 0).
    * The `/opendir-fail/` path triggers an error.
    I'd provide examples of how the input `fake_dir` vector leads to specific `glob` outputs in tests like `glob_GLOB_NOSORT`.
* **Common Errors:**  I'd brainstorm typical mistakes:
    * Forgetting to call `globfree()`.
    * Incorrectly escaping special characters in patterns.
    * Misunderstanding the behavior of different flags.
    * Assuming `glob` sorts results when it might not.
* **Android Framework/NDK Path:**  This requires tracing back the usage of `glob`. I'd give a plausible scenario, starting from a high-level Android API (like `java.io.File.listFiles`) and showing how it might eventually call native code using the NDK, which then uses `glob` (or a related function) from `libc`.
* **Frida Hooking:** I'd provide concrete Frida code snippets to hook the `glob` function, allowing observation of its arguments (pattern, flags) and return value. I'd also show how to hook the mocked functions to see how the test environment is set up.

**4. Refining and Structuring the Answer:**

Once I have the raw information, I need to structure it clearly and concisely. This involves:

* **Using Headings:** To organize the different parts of the answer (Functionality, Android Relation, etc.).
* **Providing Code Examples:**  Illustrating concepts with relevant snippets from the test file and the hypothetical Frida hooks.
* **Explaining `libc` Functions:**  Providing concise definitions and explaining how they relate to `glob`.
* **Addressing the Dynamic Linker Carefully:**  Making sure to distinguish between the direct and indirect involvement of the dynamic linker.
* **Clarity and Conciseness:**  Avoiding jargon where possible and explaining technical terms.
* **Reviewing and Editing:**  Checking for accuracy and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the *implementation* of `glob`.
* **Correction:** Realize the request is about the *test file*. Shift focus to what the tests are verifying. Details of `glob`'s internal implementation are less relevant here than understanding how it's *used* and *tested*.
* **Initial thought:**  Overcomplicate the dynamic linker explanation.
* **Correction:**  Simplify to the basic concept of `libc.so` loading and symbol resolution. Avoid going into deep details of relocation and linking algorithms unless explicitly asked.
* **Initial thought:**  Just list the `libc` functions.
* **Correction:**  Explain *how* each function is used by `glob` (or the test).

By following this structured thought process, I can systematically address all aspects of the request and generate a comprehensive and accurate answer.
这是对 Android Bionic 库中 `glob_test.cpp` 文件的分析。这个测试文件旨在验证 `glob` 函数及其相关功能在 Android 环境下的正确性。

**`bionic/tests/glob_test.cpp` 的功能:**

这个测试文件的主要功能是使用 Google Test 框架 (gtest) 来测试 `glob` 函数的不同使用场景和标志位。它通过一系列的测试用例，覆盖了 `glob` 函数的各种功能和边缘情况。具体来说，测试文件验证了以下方面：

1. **基本的模式匹配:** 验证 `glob` 函数能否正确地匹配符合指定模式的文件和目录。例如，使用 `*`, `?` 等通配符进行匹配。
2. **`GLOB_APPEND` 标志:** 测试 `GLOB_APPEND` 标志能否将新的匹配结果追加到已有的 `glob_t` 结构体中。
3. **`GLOB_DOOFFS` 标志:** 测试 `GLOB_DOOFFS` 标志能否在 `gl_pathv` 数组的前面预留指定数量的空指针。
4. **`GLOB_ERR` 标志和错误处理:** 验证当遇到错误（例如无法打开目录）时，`GLOB_ERR` 标志能否导致 `glob` 函数返回错误，以及使用自定义错误回调函数 `gl_errfunc` 的机制。
5. **`GLOB_MARK` 标志:** 测试 `GLOB_MARK` 标志能否在匹配到的目录路径末尾添加斜杠 `/`。
6. **`GLOB_NOCHECK` 标志:** 验证当没有匹配到任何文件时，`GLOB_NOCHECK` 标志能否使 `glob` 函数返回模式本身。
7. **`GLOB_NOSORT` 标志:** 测试 `GLOB_NOSORT` 标志能否阻止 `glob` 函数对匹配结果进行排序，按照目录读取顺序返回。
8. **`GLOB_MAGCHAR` 标志:** 验证 `glob` 函数是否正确设置了 `GLOB_MAGCHAR` 标志，以指示模式中是否包含特殊字符。
9. **使用自定义目录迭代函数 (`GLOB_ALTDIRFUNC`):** 通过提供自定义的 `opendir`, `readdir`, `closedir`, `lstat`, `stat` 函数，模拟不同的文件系统行为，用于测试 `glob` 函数在非标准文件系统下的表现。

**与 Android 功能的关系及举例说明:**

`glob` 函数是 POSIX 标准的一部分，用于执行路径名模式扩展，也就是根据通配符查找匹配的文件或目录。在 Android 系统中，许多组件和工具都依赖于 `glob` 或类似的功能：

* **`adb shell` 命令:** 当你在 `adb shell` 中使用带有通配符的命令，例如 `ls /sdcard/*.txt`，shell 内部就会使用类似 `glob` 的机制来查找匹配的文件。
* **软件包管理器 (`pm`) 命令:** 一些 `pm` 命令可能使用 `glob` 来查找符合特定模式的 APK 文件。
* **系统服务:** 某些系统服务可能使用 `glob` 来监控特定目录下的文件变化或查找配置文件。
* **NDK 开发:** 使用 NDK 进行 native 开发时，开发者可以使用 `glob` 函数来方便地查找文件。例如，一个图片处理应用可能需要查找某个目录下所有的 `.jpg` 文件。

**举例说明:**

假设一个 Android 应用需要在 `/sdcard/images/` 目录下查找所有以 "photo_" 开头的 JPEG 文件。开发者可以使用 NDK 中的 `glob` 函数来实现：

```c++
#include <glob.h>
#include <stdio.h>

int find_photos() {
  glob_t globbuf;
  const char *pattern = "/sdcard/images/photo_*.jpg";
  int rv = glob(pattern, 0, NULL, &globbuf);

  if (rv == 0) {
    for (size_t i = 0; i < globbuf.gl_pathc; i++) {
      printf("Found photo: %s\n", globbuf.gl_pathv[i]);
    }
  } else if (rv == GLOB_NOMATCH) {
    printf("No photos found matching the pattern.\n");
  } else {
    printf("Error occurred while globbing.\n");
  }

  globfree(&globbuf);
  return rv;
}
```

**详细解释每一个 libc 函数的功能是如何实现的:**

以下是测试文件中涉及的 libc 函数的简要解释：

* **`glob()`:**  `glob` 函数接收一个模式字符串作为输入，并根据该模式查找匹配的文件路径。其实现通常涉及以下步骤：
    1. **解析模式:**  分解模式字符串，识别通配符（如 `*`, `?`, `[]`）和普通字符。
    2. **目录遍历:**  根据模式中的路径部分，递归地遍历文件系统目录。
    3. **匹配:**  对于遍历到的每个文件或目录，将其名称与模式的相应部分进行匹配。
    4. **存储结果:**  将匹配到的路径存储在 `glob_t` 结构体的 `gl_pathv` 数组中。
    5. **排序 (可选):** 如果没有指定 `GLOB_NOSORT` 标志，会对匹配结果进行排序。
    6. **错误处理:**  处理遍历过程中的错误，例如权限不足、目录不存在等。
* **`globfree()`:**  `globfree` 函数用于释放 `glob()` 函数分配的内存。它接收一个指向 `glob_t` 结构体的指针，并释放 `gl_pathv` 数组以及 `glob_t` 结构体本身所占用的内存。这对于避免内存泄漏至关重要。
* **`opendir()`:**  `opendir` 函数用于打开一个目录，以便后续读取目录中的条目。它接收一个目录路径作为参数，如果成功打开目录，则返回一个指向 `DIR` 结构体的指针，该结构体表示打开的目录流。如果打开失败，则返回 `NULL` 并设置 `errno`。
* **`readdir()`:**  `readdir` 函数用于从通过 `opendir` 打开的目录流中读取下一个目录条目。每次调用 `readdir` 都会返回一个指向 `dirent` 结构体的指针，该结构体包含了目录条目的信息，最重要的是文件名 (`d_name`). 当读取到目录末尾时，`readdir` 返回 `NULL`.
* **`closedir()`:**  `closedir` 函数用于关闭通过 `opendir` 打开的目录流，释放相关的系统资源。它接收一个指向 `DIR` 结构体的指针作为参数。
* **`lstat()`:**  `lstat` 函数用于获取文件或目录的状态信息，但不跟随符号链接。它接收一个路径作为参数，并将状态信息存储在 `stat` 结构体中。`stat` 结构体包含了诸如文件类型、权限、大小、修改时间等信息。
* **`stat()`:**  `stat` 函数与 `lstat` 类似，用于获取文件或目录的状态信息。不同之处在于，如果路径指向一个符号链接，`stat` 会返回符号链接所指向的实际文件的状态信息，而 `lstat` 返回符号链接自身的状态信息。
* **`strcpy()`:**  `strcpy` 函数是 C 标准库中的字符串复制函数。它将源字符串（包括 null 终止符）复制到目标缓冲区。在测试代码中，它被用于模拟 `readdir` 返回的 `dirent` 结构体中的文件名。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`glob` 函数本身是 `libc.so` 库的一部分。当一个 Android 应用或进程调用 `glob` 函数时，动态链接器负责在运行时加载 `libc.so` 并解析 `glob` 函数的地址，以便程序能够正确调用该函数。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:  // 包含可执行代码
        ...
        glob:   // glob 函数的入口地址
            <glob 函数的机器码>
        ...
    .data:  // 包含已初始化的全局变量
        ...
    .bss:   // 包含未初始化的全局变量
        ...
    .dynsym: // 动态符号表，包含导出的符号 (例如 glob)
        glob  ADDRESS_OF_GLOB
        ...
    .dynstr: // 动态字符串表，包含符号名称
        "glob"
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译器编译包含 `glob` 函数调用的代码时，它会生成对 `glob` 函数的未解析引用。链接器在链接时会记录这个依赖关系，并将其添加到可执行文件或共享库的动态链接信息中。
2. **加载时链接:** 当 Android 系统加载可执行文件或共享库时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会被调用。
3. **查找依赖:** 动态链接器会读取可执行文件或共享库的动态链接段，找到其依赖的共享库，包括 `libc.so`。
4. **加载共享库:** 动态链接器会加载 `libc.so` 到进程的地址空间。如果 `libc.so` 已经被加载，则会重用已加载的实例。
5. **符号解析:** 动态链接器会遍历可执行文件或共享库中未解析的符号引用 (例如 `glob`)，并在已加载的共享库 (`libc.so`) 的动态符号表中查找匹配的符号。
6. **重定位:** 动态链接器会将未解析的符号引用替换为 `glob` 函数在 `libc.so` 中的实际地址。这通常涉及到修改可执行文件或共享库的代码段或数据段中的地址。
7. **执行:** 一旦所有必要的符号都被解析和重定位，程序就可以正确地调用 `glob` 函数。

**假设输入与输出 (针对测试用例):**

* **测试用例: `glob_result_GLOB_NOMATCH`**
    * **假设输入:** 模式字符串 "/will/match/nothing"，当前文件系统中不存在该路径。
    * **预期输出:** `glob` 函数返回 `GLOB_NOMATCH`，`g.gl_pathc` 为 0。
* **测试用例: `glob_GLOB_APPEND`**
    * **假设输入:**  模式字符串 "/proc/version"，当前 Android 系统中该文件存在。第一次调用 `glob` 时不带 `GLOB_APPEND`，第二次调用带 `GLOB_APPEND`。
    * **预期输出:** 第一次调用后，`g.gl_pathc` 为 1，`g.gl_pathv[0]` 指向 "/proc/version"。第二次调用后，`g.gl_pathc` 为 2，`g.gl_pathv[0]` 和 `g.gl_pathv[1]` 都指向 "/proc/version"。
* **测试用例 (使用 `GLOB_ALTDIRFUNC`): `glob_globbing`**
    * **假设输入:**  使用 `InstallFake` 设置模拟目录 `fake_dir = { "f1", "f2", "f30", "f40" }`，模式字符串 "f?"。
    * **预期输出:** `glob` 函数返回 0，`g.gl_pathc` 为 2，`g.gl_pathv[0]` 指向 "f1"，`g.gl_pathv[1]` 指向 "f2"。

**用户或编程常见的使用错误:**

1. **忘记调用 `globfree()`:** `glob` 函数会动态分配内存来存储匹配到的路径。如果在不再需要这些路径时忘记调用 `globfree()`，会导致内存泄漏。
   ```c++
   glob_t globbuf;
   glob("/tmp/*.txt", 0, NULL, &globbuf);
   // ... 使用 globbuf.gl_pathv ...
   // 错误：忘记调用 globfree(&globbuf);
   ```
2. **不正确地转义特殊字符:** 如果模式字符串中包含 `*`, `?`, `[` 等特殊字符，但用户希望将其作为普通字符匹配，则需要使用反斜杠 `\` 进行转义。
   ```c++
   // 错误：希望匹配名为 "file*.txt" 的文件，但 * 被解释为通配符
   glob("file*.txt", 0, NULL, &globbuf);

   // 正确：转义 * 字符
   glob("file\\*.txt", 0, NULL, &globbuf);
   ```
3. **假设 `glob` 总是会排序结果:** 默认情况下，`glob` 会对匹配结果进行排序。但是，如果指定了 `GLOB_NOSORT` 标志，则不会进行排序。用户需要注意这一点，不要依赖于特定的排序顺序，除非确实需要并了解是否使用了 `GLOB_NOSORT`。
4. **缓冲区溢出 (理论上，实际 `glob` 实现会处理):** 在早期或不安全的 `glob` 实现中，如果匹配到的路径数量过多，可能会导致缓冲区溢出。现代的 `glob` 实现通常会动态分配内存来避免这个问题，但用户仍然需要注意，避免传递过于宽泛的模式，导致匹配到大量的文件。
5. **不检查 `glob` 的返回值:** `glob` 函数可能会返回不同的错误代码，例如 `GLOB_NOMATCH`, `GLOB_ABORTED`, `GLOB_ERR` 等。用户应该检查返回值，以了解 `glob` 函数是否成功执行，以及是否发生了错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**Android Framework 到 `glob` 的路径示例 (可能的情况):**

1. **Java 代码调用:** Android Framework 中的 Java 代码，例如 `java.io.File` 或 `android.content.Context` 的某些方法，可能需要列出或查找符合特定模式的文件。
2. **JNI 调用:** 这些 Java 方法最终可能会通过 Java Native Interface (JNI) 调用到 Native 代码。
3. **NDK 代码使用 `glob`:** NDK 开发的 Native 代码可以直接调用 `glob` 函数。例如，一个媒体扫描器服务可能使用 `glob` 来查找新的媒体文件。

**Frida Hook 示例:**

假设我们要 hook `libc.so` 中的 `glob` 函数，查看其被调用的情况。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "glob"), {
    onEnter: function(args) {
        var pattern = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        console.log("[+] glob called with pattern: " + pattern + ", flags: " + flags);
        this.pattern = pattern;
    },
    onLeave: function(retval) {
        console.log("[+] glob returned: " + retval);
        if (retval == 0) {
            var glob_t_ptr = this.context.r2; // 假设在 ARM64 上，glob_t 结构体指针在 r2 寄存器中
            var pathc = Memory.readU32(glob_t_ptr);
            console.log("[+] Number of matches: " + pathc);
            if (pathc > 0) {
                var pathv_ptr = Memory.readPointer(glob_t_ptr.add(Process.pointerSize * 2)); // 假设 gl_pathv 在偏移 2 * pointerSize
                for (var i = 0; i < pathc; i++) {
                    var path = Memory.readPointer(pathv_ptr.add(i * Process.pointerSize));
                    console.log("[+] Match " + i + ": " + Memory.readUtf8String(path));
                }
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 安装 Frida 和 Python 的 Frida 模块，确保你的 Android 设备已 root 并启用了 USB 调试。
2. **编写 Frida 脚本:**  如上面的示例代码，使用 `Interceptor.attach` 钩住 `libc.so` 中的 `glob` 函数。
3. **运行 Frida 脚本:**  使用 `frida -U -f com.example.myapp your_frida_script.py` 启动你的应用并注入 Frida 脚本。
4. **触发 `glob` 调用:** 在你的应用中执行会导致调用 `glob` 函数的操作。例如，如果你的应用有文件选择功能，尝试选择符合特定模式的文件。
5. **查看 Frida 输出:** Frida 脚本会在 `glob` 函数被调用时打印出其参数（模式字符串和标志位）以及返回值和匹配到的路径。

通过 Frida hook，你可以实时观察 `glob` 函数的调用情况，验证你的假设，并调试与文件路径匹配相关的问题。你需要根据目标架构 (ARM, ARM64, etc.) 调整 Frida 脚本中访问 `glob_t` 结构体成员的方式 (例如寄存器和偏移量)。

### 提示词
```
这是目录为bionic/tests/glob_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <glob.h>

#include <dirent.h>
#include <sys/cdefs.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <android-base/file.h>

#if defined(__BIONIC__)
#define ASSERT_MATCH_COUNT(n_,g_) ASSERT_EQ(n_, g_.gl_matchc)
#else
#define ASSERT_MATCH_COUNT(n_,g_)
#endif

//
// Helper for use with GLOB_ALTDIRFUNC to iterate over the elements of `fake_dir`.
//

#if !defined(ANDROID_HOST_MUSL)
static std::vector<std::string> fake_dir;
static size_t fake_dir_offset;
static void fake_closedir(void*) {
}
static dirent* fake_readdir(void*) {
  static dirent d;
  if (fake_dir_offset >= fake_dir.size()) return nullptr;
  strcpy(d.d_name, fake_dir[fake_dir_offset++].c_str());
  return &d;
}
static void* fake_opendir(const char* path) {
  fake_dir_offset = 0;
  if (strcmp(path, "/opendir-fail/") == 0) {
    errno = EINVAL;
    return nullptr;
  }
  return &fake_dir;
}
static int fake_lstat(const char*, struct stat*) {
  return 0;
}
static int fake_stat(const char*, struct stat*) {
  return 0;
}
static void InstallFake(glob_t* g) {
  g->gl_closedir = fake_closedir;
  g->gl_readdir = fake_readdir;
  g->gl_opendir = fake_opendir;
  g->gl_lstat = fake_lstat;
  g->gl_stat = fake_stat;
}
#endif

TEST(glob, glob_result_GLOB_NOMATCH) {
  glob_t g = {};
  ASSERT_EQ(GLOB_NOMATCH, glob("/will/match/nothing", 0, nullptr, &g));
  ASSERT_EQ(0U, g.gl_pathc);
  ASSERT_MATCH_COUNT(0U, g);
}

TEST(glob, glob_GLOB_APPEND) {
  glob_t g = {};
  ASSERT_EQ(0, glob("/proc/version", 0, nullptr, &g));
  ASSERT_EQ(1U, g.gl_pathc);
  ASSERT_MATCH_COUNT(1U, g);
  ASSERT_STREQ("/proc/version", g.gl_pathv[0]);
  ASSERT_EQ(nullptr, g.gl_pathv[1]);
  ASSERT_EQ(0, glob("/proc/version", GLOB_APPEND, nullptr, &g));
  ASSERT_EQ(2U, g.gl_pathc);
  ASSERT_MATCH_COUNT(1U, g);
  ASSERT_STREQ("/proc/version", g.gl_pathv[0]);
  ASSERT_STREQ("/proc/version", g.gl_pathv[1]);
  ASSERT_EQ(nullptr, g.gl_pathv[2]);
  globfree(&g);
}

TEST(glob, glob_GLOB_DOOFFS) {
  glob_t g = {};
  g.gl_offs = 2;
  ASSERT_EQ(0, glob("/proc/version", GLOB_DOOFFS, nullptr, &g));
  ASSERT_EQ(1U, g.gl_pathc);
  ASSERT_MATCH_COUNT(1U, g);
  ASSERT_EQ(nullptr, g.gl_pathv[0]);
  ASSERT_EQ(nullptr, g.gl_pathv[1]);
  ASSERT_STREQ("/proc/version", g.gl_pathv[2]);
  ASSERT_EQ(nullptr, g.gl_pathv[3]);
  globfree(&g);
}

#if !defined(ANDROID_HOST_MUSL)
static std::string g_failure_path;
static int g_failure_errno;
static int test_error_callback_result;
static int test_error_callback(const char* failure_path, int failure_errno) {
  g_failure_path = failure_path;
  g_failure_errno = failure_errno;
  return test_error_callback_result;
}
#endif

TEST(glob, glob_gl_errfunc) {
#if !defined(ANDROID_HOST_MUSL)
  glob_t g = {};
  InstallFake(&g);

  test_error_callback_result = 0;
  g_failure_errno = 0;
  ASSERT_EQ(GLOB_NOMATCH, glob("/opendir-fail/x*", GLOB_ALTDIRFUNC, test_error_callback, &g));
  ASSERT_EQ("/opendir-fail/", g_failure_path);
  ASSERT_EQ(EINVAL, g_failure_errno);

  test_error_callback_result = 1;
  g_failure_errno = 0;
  ASSERT_EQ(GLOB_ABORTED, glob("/opendir-fail/x*", GLOB_ALTDIRFUNC, test_error_callback, &g));
  ASSERT_EQ("/opendir-fail/", g_failure_path);
  ASSERT_EQ(EINVAL, g_failure_errno);
#else
  GTEST_SKIP() << "musl doesn't support GLOB_ALTDIRFUNC";
#endif
}

TEST(glob, glob_GLOB_ERR) {
#if !defined(ANDROID_HOST_MUSL)
  glob_t g = {};
  InstallFake(&g);

  ASSERT_EQ(GLOB_NOMATCH, glob("/opendir-fail/x*", GLOB_ALTDIRFUNC, nullptr, &g));

  ASSERT_EQ(GLOB_ABORTED, glob("/opendir-fail/x*", GLOB_ALTDIRFUNC | GLOB_ERR, nullptr, &g));
#else
  GTEST_SKIP() << "musl doesn't support GLOB_ALTDIRFUNC";
#endif
}

TEST(glob, glob_GLOB_MARK) {
  TemporaryDir td;
  // The pattern we're about to pass doesn't have a trailing '/'...
  ASSERT_NE('/', std::string(td.path).back());

  glob_t g = {};
  // Using GLOB_MARK gets you a trailing '/' on a directory...
  ASSERT_EQ(0, glob(td.path, GLOB_MARK, nullptr, &g));
  ASSERT_EQ(1U, g.gl_pathc);
  ASSERT_MATCH_COUNT(1U, g);
  ASSERT_EQ(std::string(td.path) + "/", g.gl_pathv[0]);
  ASSERT_EQ(nullptr, g.gl_pathv[1]);

  TemporaryFile tf;
  // But not on a file...
  ASSERT_EQ(0, glob(tf.path, GLOB_MARK, nullptr, &g));
  ASSERT_EQ(1U, g.gl_pathc);
  ASSERT_MATCH_COUNT(1U, g);
  ASSERT_STREQ(tf.path, g.gl_pathv[0]);
  ASSERT_EQ(nullptr, g.gl_pathv[1]);

  globfree(&g);
}

TEST(glob, glob_GLOB_NOCHECK) {
  glob_t g = {};
  ASSERT_EQ(0, glob("/will/match/nothing", GLOB_NOCHECK, nullptr, &g));
  ASSERT_EQ(1U, g.gl_pathc);
  ASSERT_MATCH_COUNT(0U, g);
  ASSERT_STREQ("/will/match/nothing", g.gl_pathv[0]);
  ASSERT_EQ(nullptr, g.gl_pathv[1]);
  globfree(&g);
}

TEST(glob, glob_GLOB_NOSORT) {
#if !defined(ANDROID_HOST_MUSL)
  fake_dir = { "c", "a", "d", "b" };

  glob_t g = {};
  InstallFake(&g);

  ASSERT_EQ(0, glob("*", GLOB_ALTDIRFUNC, nullptr, &g));
  ASSERT_EQ(4U, g.gl_pathc);
  ASSERT_MATCH_COUNT(4U, g);
  ASSERT_STREQ("a", g.gl_pathv[0]);
  ASSERT_STREQ("b", g.gl_pathv[1]);
  ASSERT_STREQ("c", g.gl_pathv[2]);
  ASSERT_STREQ("d", g.gl_pathv[3]);
  ASSERT_EQ(nullptr, g.gl_pathv[4]);

  ASSERT_EQ(0, glob("*", GLOB_ALTDIRFUNC | GLOB_NOSORT, nullptr, &g));
  ASSERT_EQ(4U, g.gl_pathc);
  ASSERT_MATCH_COUNT(4U, g);
  ASSERT_STREQ("c", g.gl_pathv[0]);
  ASSERT_STREQ("a", g.gl_pathv[1]);
  ASSERT_STREQ("d", g.gl_pathv[2]);
  ASSERT_STREQ("b", g.gl_pathv[3]);
  ASSERT_EQ(nullptr, g.gl_pathv[4]);
#else
  GTEST_SKIP() << "musl doesn't support GLOB_ALTDIRFUNC";
#endif
}

TEST(glob, glob_GLOB_MAGCHAR) {
#if !defined(ANDROID_HOST_MUSL)
  glob_t g = {};
  ASSERT_EQ(GLOB_NOMATCH, glob("/does-not-exist", 0, nullptr, &g));
  ASSERT_TRUE((g.gl_flags & GLOB_MAGCHAR) == 0);
  ASSERT_EQ(GLOB_NOMATCH, glob("/does-not-exist*", 0, nullptr, &g));
  ASSERT_TRUE((g.gl_flags & GLOB_MAGCHAR) != 0);

  // We can lie, but glob(3) will turn that into truth...
  ASSERT_EQ(GLOB_NOMATCH, glob("/does-not-exist", GLOB_MAGCHAR, nullptr, &g));
  ASSERT_TRUE((g.gl_flags & GLOB_MAGCHAR) == 0);
#else
  GTEST_SKIP() << "musl doesn't support GLOB_MAGCHAR";
#endif
}

#if !defined(ANDROID_HOST_MUSL)
static void CheckGlob(const char* pattern, const std::vector<std::string>& expected_matches) {
  glob_t g = {};
  InstallFake(&g);

  int expected_result = expected_matches.empty() ? GLOB_NOMATCH : 0;
  ASSERT_EQ(expected_result, glob(pattern, GLOB_ALTDIRFUNC, nullptr, &g)) << pattern;
  ASSERT_EQ(expected_matches.size(), g.gl_pathc);
  ASSERT_MATCH_COUNT(expected_matches.size(), g);
  for (size_t i = 0; i < expected_matches.size(); ++i) {
    ASSERT_EQ(expected_matches[i], g.gl_pathv[i]);
  }
  if (!expected_matches.empty()) {
    ASSERT_EQ(nullptr, g.gl_pathv[expected_matches.size()]);
  }
  globfree(&g);
}
#endif

TEST(glob, glob_globbing) {
#if !defined(ANDROID_HOST_MUSL)
  fake_dir = { "f1", "f2", "f30", "f40" };

  CheckGlob("f?", { "f1", "f2" });
  CheckGlob("f??", { "f30", "f40" });
  CheckGlob("f*", { "f1", "f2", "f30", "f40" });
#else
  GTEST_SKIP() << "musl doesn't support GLOB_ALTDIRFUNC";
#endif
}

TEST(glob, glob_globbing_rsc) {
#if !defined(ANDROID_HOST_MUSL)
  // https://research.swtch.com/glob
  fake_dir = { "axbxcxdxe" };
  CheckGlob("a*b*c*d*e*", { "axbxcxdxe" });
  fake_dir = { "axbxcxdxexxx" };
  CheckGlob("a*b*c*d*e*", { "axbxcxdxexxx" });
  fake_dir = { "abxbbxdbxebxczzx" };
  CheckGlob("a*b?c*x", { "abxbbxdbxebxczzx" });
  fake_dir = { "abxbbxdbxebxczzy" };
  CheckGlob("a*b?c*x", {});

  fake_dir = { std::string(100, 'a') };
  CheckGlob("a*a*a*a*b", {});
#else
  GTEST_SKIP() << "musl doesn't support GLOB_ALTDIRFUNC";
#endif
}
```