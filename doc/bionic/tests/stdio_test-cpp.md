Response:
My thinking process to summarize the functionality of the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The file is named `stdio_test.cpp` and resides within the `bionic/tests` directory. The comment at the beginning confirms that `bionic` is Android's C library. This immediately tells me the primary function of this file: **testing the standard C input/output library (stdio) implementation in Android's bionic library.**

2. **Scan Included Headers:**  The `#include` directives reveal the scope of the tests:
    * `<gtest/gtest.h>`:  Indicates the use of Google Test framework for writing tests.
    * Standard C library headers (`<errno.h>`, `<fcntl.h>`, `<limits.h>`, etc.):  Confirms the focus on testing standard C functions related to file I/O, locales, math (though less prominent here), and system calls.
    * Android-specific headers (`<android-base/...>`): Shows the tests also interact with Android's base utility libraries, likely for helper functions related to file manipulation and temporary directories.
    * `<linux/fs.h>`: Suggests testing specific Linux kernel features related to the file system, like `RENAME_` constants.
    * `<string>`, `<thread>`, `<vector>`: Indicates the use of standard C++ features within the tests, though the focus remains on C stdio.

3. **Analyze Test Structure:** The code defines several `TEST` macros, suggesting individual test cases. The `STDIO_TEST` and `STDIO_DEATHTEST` macros are used to categorize tests. The presence of `SilentDeathTest` indicates tests that are expected to cause the program to terminate (e.g., due to an assertion failure or signal).

4. **Examine Helper Functions:**  Functions like `SetFileTo`, `AssertFileIs`, `EXPECT_SNPRINTF`, `EXPECT_SWPRINTF` are clearly helper functions designed to simplify test writing. They perform common actions like:
    * Creating files with specific content.
    * Asserting file content.
    * Comparing the output of `snprintf` and `swprintf` with expected strings.

5. **Categorize Test Cases by Functionality:**  As I read through the individual `TEST` cases, I try to group them based on the stdio function being tested. For example:
    * File operations: `tmpfile`, `tmpfile64`, `dprintf`, `fdopen`, `fclose`, `fopen`, `fileno`.
    * Input/Output: `fprintf`, `fgets`, `getline`, `getdelim`, `fread`, `fwrite`.
    * Formatted output: `snprintf`, `swprintf` (with various format specifiers like `%d`, `%s`, `%f`, `%x`, `%a`, `%lc`, `%ls`, `%n`, etc.).
    * Locking: `flockfile`, `funlockfile`.
    * Process execution: `popen`, `pclose`.
    * Error handling and edge cases: Tests with `_invalid` suffixes, tests involving `NULL` pointers, tests for buffer overflows, tests for specific values like `INT_MAX`, `HUGE_VALF`, `NaN`, and infinity.
    * Locale-specific behavior: Testing UTF-8 handling.
    * Threading:  A test to check `snprintf` in a small-stack thread.

6. **Identify Android-Specific Aspects:** While the tests primarily focus on standard C functions, some tests reveal Android-specific behavior or configurations:
    * `tmpfile_TMPDIR`: Tests how the `TMPDIR` environment variable affects temporary file creation, an aspect relevant to Android's file system sandboxing.
    * `%n` format specifier in `snprintf` and `swprintf`: The death tests explicitly check that `%n` is *not* allowed on Android (`__BIONIC__`). This is a security measure.
    * Differences in `nullptr` representation in `printf` with `%p`:  The tests show that bionic might print `0x0` while other libraries print `(nil)`.

7. **Synthesize the Summary:** Based on the above analysis, I formulate a concise summary that captures the main purpose and key functionalities being tested. I prioritize the core function (testing stdio) and then list the major categories of functions covered by the tests. I also include the Android-specific observations.

8. **Refine and Organize:**  I structure the summary with clear headings and bullet points for readability. I use precise language to describe the functionalities.

By following these steps, I can systematically analyze the code and generate a comprehensive yet concise summary of its purpose and functionality.
这是目录为 `bionic/tests/stdio_test.cpp` 的 Android bionic 源代码文件，主要用于测试 Android C 库（bionic）中标准输入输出库（stdio）的实现。

**该文件的主要功能可以归纳为：**

* **全面测试 bionic 库中的 stdio 函数：**  该文件包含了大量的单元测试，覆盖了 stdio 库中各种函数的行为，包括但不限于文件操作、格式化输入输出、错误处理、以及与多字节字符相关的函数。

**具体功能点的展开（从代码内容推断）：**

1. **文件操作测试：**
   - `tmpfile`, `tmpfile64`: 测试创建临时文件的功能，包括其在 `$TMPDIR` 环境变量影响下的行为。
   - `fopen`, `fclose`: 测试打开和关闭文件的基本操作。
   - `fdopen`: 测试将文件描述符转换为 `FILE` 指针。
   - `fileno`: 测试获取 `FILE` 指针对应的文件描述符。
   - `dprintf`: 测试向文件描述符写入格式化输出。
   - `getdelim`, `getline`: 测试按分隔符或行读取文件的功能。
   - `rewind`: 测试重置文件流的位置。

2. **格式化输出测试 (`printf`, `fprintf`, `sprintf`, `snprintf`, `vsnprintf`, `swprintf`, `swprintf`)：**
   - **基本格式化:** 测试各种格式化控制符（如 `%d`, `%s`, `%x`, `%f`, `%p` 等）的输出是否正确。
   - **宽度和精度控制:** 测试使用数字、星号 (`*`) 控制输出宽度和精度的功能。
   - **长度修饰符:** 测试 `h`, `hh`, `l`, `ll`, `L`, `j`, `z`, `t` 等长度修饰符对输出的影响。
   - **标志:** 测试 `+`, `-`, ` `, `#`, `0` 等标志的作用。
   - **处理 `NULL` 指针:** 测试格式化输出如何处理 `NULL` 指针。
   - **处理宽字符:** 测试 `%lc`, `%ls`, `%C`, `%S` 等宽字符相关的格式化输出。
   - **处理浮点数特殊值:** 测试 `NaN` 和 `Infinity` 的格式化输出和解析。
   - **位置参数:** 测试使用 `%n$` 进行位置参数指定的功能。
   - **安全性和边界情况:** 测试 `snprintf` 的缓冲区溢出保护，以及 `%n` 格式符在 bionic 中的禁用。
   - **负零:** 测试负零的格式化输出。
   - **UTF-8 支持:** 测试在 UTF-8 locale 下的格式化输出。

3. **格式化输入测试 (`scanf`, `sscanf`, `swscanf`)：**
   - 主要体现在 `snprintf_sscanf_inf_nan` 和 `swprintf_swscanf_inf_nan` 这两个测试用例中，测试了 `sscanf` 和 `swscanf` 对 NaN 和 Infinity 字符串的解析是否正确。

4. **错误处理测试：**
   - 测试 `getdelim` 和 `getline` 在接收到无效参数时的错误处理（返回 -1 并设置 `errno` 为 `EINVAL`）。
   - 测试 `fprintf` 在写入只读文件或关闭文件时的错误处理。

5. **文件锁定测试：**
   - `flockfile`, `funlockfile`: 测试文件锁定的功能，并验证 bionic 使用递归互斥锁实现。

6. **进程管道测试：**
   - `popen`, `pclose`: 测试创建管道并执行子进程的功能，包括数据传递和返回值检查。

7. **其他 stdio 函数测试：**
   - `feof`:  间接在 `flockfile` 测试中使用。
   - `clearerr`: 在 `getdelim` 和 `getline` 测试中使用。
   - `setbuf`: 在 `fprintf_failures_7229520` 测试中使用。
   - `fflush`: 在 `popen_socketpair` 测试中使用。
   - `shutdown`: 在 `popen_socketpair_shutdown` 测试中使用。

8. **与 Android 功能相关的举例说明：**
   - **临时文件路径：** `tmpfile_TMPDIR` 测试用例验证了 Android 系统中 `TMPDIR` 环境变量对临时文件创建路径的影响。这与 Android 的文件系统权限和应用沙箱机制有关。例如，当应用调用 `tmpfile` 时，Android 系统需要确保临时文件被创建在应用有权限访问的目录下。
   - **禁用 `%n` 格式符：** `snprintf_n` 和 `swprintf_n` 这两个 death test 验证了 bionic 中禁用了 `%n` 格式符。这是一个安全措施，因为 `%n` 可以用来向内存中写入数据，可能导致安全漏洞。Android 作为移动操作系统，对安全性有更高的要求。
   - **`popen` 的使用场景：** Android Framework 或 NDK 中的某些功能可能需要执行系统命令来完成特定的任务，例如获取系统信息、处理音频/视频等。`popen` 可以用来执行这些命令并获取其输出。例如，可以使用 `popen` 调用 `dumpsys` 命令来获取系统服务的信息。

9. **libc 函数的实现细节（根据代码推断，无法直接看到实现）：**
   - **`tmpfile` / `tmpfile64`：**  大概率会调用底层的系统调用 `open`，并使用 `O_TMPFILE` 标志来创建匿名临时文件。在 Android 中，临时文件通常会创建在 `/data/local/tmp` 或 `$TMPDIR` 指定的目录下。`tmpfile64` 可能是为了处理大于 2GB 的文件。
   - **`fopen` / `fclose`：** `fopen` 会调用底层的 `open` 系统调用来打开文件，并分配一个 `FILE` 结构体来管理文件流的缓冲区、文件描述符等信息。`fclose` 会刷新缓冲区并将数据写入文件（如果以写入模式打开），然后调用 `close` 系统调用关闭文件，并释放 `FILE` 结构体的内存。
   - **`fprintf` / `printf` / `sprintf` / `snprintf`：** 这些函数负责将格式化的数据写入到文件流或字符串缓冲区。它们的实现通常包含一个状态机来解析格式化字符串，并根据不同的格式符调用相应的函数来处理不同类型的数据（整数、浮点数、字符串等）。`snprintf` 会额外检查缓冲区大小，防止溢出。`printf` 最终会调用 `fwrite` 或类似的系统调用将数据写入到标准输出。
   - **`getline` / `getdelim`：** 这些函数会动态分配内存来存储读取到的行或分隔符之间的内容。它们会循环读取文件，直到遇到换行符或指定的分隔符。`getline` 会自动处理缓冲区大小的增长。
   - **`popen` / `pclose`：** `popen` 的实现会调用 `pipe` 创建管道，然后使用 `fork` 创建子进程。子进程会执行指定的命令，并将标准输出或标准输入重定向到管道。父进程通过管道与子进程通信。`pclose` 会关闭管道，并等待子进程结束，返回子进程的退出状态。
   - **`flockfile` / `funlockfile`：** 这些函数使用互斥锁（`pthread_mutex_t`）来控制对 `FILE` 结构体的并发访问，实现线程安全的文件操作。bionic 中使用递归互斥锁允许同一个线程多次获取同一个文件锁。

10. **涉及 dynamic linker 的功能：**
    - **该测试文件本身不直接涉及 dynamic linker 的复杂功能。** 它主要测试的是 stdio 库的内部逻辑。
    - **so 布局样本：**  虽然 `stdio_test.cpp` 不直接测试 dynamic linker，但 stdio 库本身是 `libc.so` 的一部分。一个简化的 `libc.so` 布局可能如下：
      ```
      libc.so:
          .text          # 包含 printf, fopen, fclose 等函数的代码
          .data          # 包含全局变量，例如标准流的 FILE 结构体
          .bss           # 未初始化的全局变量
          .dynsym        # 动态符号表
          .dynstr        # 动态字符串表
          .rel.dyn       # 重定位信息
          .plt           # 程序链接表（PLT）
          .got.plt       # 全局偏移表（GOT）入口
      ```
    - **链接的处理过程：** 当程序调用 `printf` 等 stdio 函数时，如果这些函数在当前可执行文件中未定义，dynamic linker 会在加载时或运行时查找 `libc.so` 中对应的符号。这个过程涉及：
      1. **查找共享对象：** dynamic linker 根据程序的依赖关系找到 `libc.so`。
      2. **符号查找：** dynamic linker 在 `libc.so` 的 `.dynsym` 中查找 `printf` 的符号。
      3. **重定位：** dynamic linker 使用 `.rel.dyn` 中的信息，修改程序的 GOT 条目，使其指向 `libc.so` 中 `printf` 函数的实际地址。
      4. **PLT 跳转：** 当程序第一次调用 `printf` 时，会跳转到 PLT 中的一个桩代码，该桩代码会通过 GOT 跳转到 dynamic linker 的解析函数。解析函数会完成上述符号查找和重定位过程，并将 `printf` 的实际地址写入 GOT。后续的 `printf` 调用将直接通过 GOT 跳转到其实现。

11. **假设输入与输出（以 `snprintf` 为例）：**
    - **假设输入：** `snprintf(buf, sizeof(buf), "The answer is %d", 42);`
    - **预期输出：** 如果 `buf` 大小足够，则 `buf` 中包含字符串 "The answer is 42"，返回值是写入的字符数（不包括 null 终止符），即 15。
    - **假设输入：** `snprintf(buf, 5, "The answer is %d", 42);`
    - **预期输出：** `buf` 中包含字符串 "The " (最多写入 `sizeof(buf) - 1` 个字符)，返回值是 *原本应该写入的字符数*，即 15。

12. **用户或编程常见的使用错误：**
    - **`snprintf` 缓冲区溢出：**  错误地认为 `snprintf` 总是能避免缓冲区溢出，而没有检查其返回值或提供足够的缓冲区大小。
      ```c
      char buf[10];
      snprintf(buf, sizeof(buf), "This is a long string"); // 缓冲区太小
      printf("%s\n", buf); // 可能输出不完整或引发问题
      ```
    - **忘记检查 `fopen` 的返回值：** `fopen` 在打开文件失败时会返回 `NULL`。不检查返回值会导致空指针解引用。
      ```c
      FILE *fp = fopen("nonexistent_file.txt", "r");
      fprintf(fp, "Hello"); // 如果 fp 是 NULL，这里会崩溃
      ```
    - **`fclose` 失败时未处理错误：** `fclose` 在刷新缓冲区时可能会遇到错误（例如磁盘空间不足）。应该检查 `fclose` 的返回值。
    - **`getline` / `getdelim` 内存泄漏：** 使用 `getline` 或 `getdelim` 读取数据后，需要手动 `free` 分配的内存。
      ```c
      char *line = NULL;
      size_t len = 0;
      getline(&line, &len, stdin);
      // ... 使用 line ...
      free(line); // 忘记释放内存会导致泄漏
      ```
    - **`popen` 后忘记 `pclose`：**  `popen` 创建的管道和子进程需要使用 `pclose` 关闭和清理资源。

13. **Android Framework 或 NDK 如何到达这里：**
    - **Android Framework (Java 层)：**  当 Java 代码需要进行文件操作或格式化输出时，可能会通过 JNI 调用 NDK 中的 C/C++ 代码。
    - **NDK (C/C++ 层)：** NDK 代码可以直接使用 bionic 提供的 stdio 函数。
    - **步骤示例 (Java -> NDK -> bionic)：**
      1. **Java 代码：**  `java.io.FileWriter` 或 `String.format` 等类的方法最终会调用底层的 Native 方法。
      2. **JNI 调用：** 这些 Native 方法是在 NDK 中实现的，例如一个 NDK 函数可能负责将 Java 的字符串格式化后写入文件。
      3. **bionic stdio 函数：** NDK 函数会调用 `fopen` 打开文件，使用 `fprintf` 进行格式化写入，最后用 `fclose` 关闭文件。

14. **Frida Hook 示例调试步骤：**
    ```python
    import frida
    import sys

    package_name = "your.target.package" # 替换为你的目标应用包名

    def on_message(message, data):
        if message['type'] == 'send':
            print(f"[*] {message['payload']}")
        else:
            print(message)

    session = frida.get_usb_device().attach(package_name)
    script = session.create_script("""
    // Hook fopen
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            var mode = Memory.readUtf8String(args[1]);
            send(`fopen called with path: ${path}, mode: ${mode}`);
        },
        onLeave: function(retval) {
            send(`fopen returned: ${retval}`);
        }
    });

    // Hook fprintf
    Interceptor.attach(Module.findExportByName("libc.so", "fprintf"), {
        onEnter: function(args) {
            var fd = args[0];
            var format = Memory.readUtf8String(args[1]);
            var arg2 = (args.length > 2) ? args[2] : null;
            send(`fprintf called with fd: ${fd}, format: ${format}, arg2: ${arg2}`);
        }
    });

    // Hook snprintf
    Interceptor.attach(Module.findExportByName("libc.so", "snprintf"), {
        onEnter: function(args) {
            var buf = args[0];
            var size = args[1].toInt();
            var format = Memory.readUtf8String(args[2]);
            send(`snprintf called with buf: ${buf}, size: ${size}, format: ${format}`);
        },
        onLeave: function(retval) {
            send(`snprintf returned: ${retval}`);
        }
    });
    """)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    ```
    **使用方法：**
    1. 将 `your.target.package` 替换为你要调试的 Android 应用的包名。
    2. 确保你的 Android 设备已连接并通过 USB 授权。
    3. 运行 Frida Python 脚本。
    4. 在目标应用中执行涉及到文件操作或格式化输出的操作。
    5. Frida 会拦截对 `fopen`, `fprintf`, `snprintf` 的调用，并打印出相关的参数信息，帮助你调试代码执行流程。

**总结（针对第 1 部分的归纳）：**

该 `stdio_test.cpp` 文件的第 1 部分主要集中在以下 stdio 函数的测试：

* **文件操作：** `flockfile` (带递归锁特性), `tmpfile`, `tmpfile64` (以及 `$TMPDIR` 影响), `dprintf`.
* **输入：** `getdelim`, `getline` (包括错误处理).
* **格式化输出 (基于 `snprintf` 和 `swprintf`):**
    * 针对 `ssize_t` 类型的输出.
    * 浮点数格式 (`%a`, `%La`).
    * 宽字符格式 (`%lc`, `%C`, `%ls`, `%S`).
    * 安全性测试 (禁用 `%n`).
    * 测量输出长度的行为.
    * 各种基本格式化输出的组合测试.
    * 处理 `NaN` 和 `Infinity`.
    * 极大/极小整数值的输出 (`INTMAX_MAX`, `INT_MAX`, `LONG_MAX`, `LLONG_MAX`, `UINT_MAX`).
    * 负零的输出.
    * UTF-8 编码下的输出.
    * 在小栈线程中调用 `snprintf` 的安全性.
    * 使用星号控制宽度和精度时的溢出处理.
    * 处理 `NULL` 指针的情况.

总而言之，这部分代码通过各种细致的测试用例，确保了 bionic 库中与基本文件操作、格式化输出以及相关的边界情况处理的 stdio 函数的正确性和健壮性。

Prompt: 
```
这是目录为bionic/tests/stdio_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <wchar.h>

#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/silent_death_test.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>
#include <android-base/unique_fd.h>

#include "utils.h"

// This #include is actually a test too. We have to duplicate the
// definitions of the RENAME_ constants because <linux/fs.h> also contains
// pollution such as BLOCK_SIZE which conflicts with lots of user code.
// Important to check that we have matching definitions.
// There's no _MAX to test that we have all the constants, sadly.
#include <linux/fs.h>

#if defined(NOFORTIFY)
#define STDIO_TEST stdio_nofortify
#define STDIO_DEATHTEST stdio_nofortify_DeathTest
#else
#define STDIO_TEST stdio
#define STDIO_DEATHTEST stdio_DeathTest
#endif

using namespace std::string_literals;

using stdio_DeathTest = SilentDeathTest;
using stdio_nofortify_DeathTest = SilentDeathTest;

static void SetFileTo(const char* path, const char* content) {
  FILE* fp;
  ASSERT_NE(nullptr, fp = fopen(path, "w"));
  ASSERT_NE(EOF, fputs(content, fp));
  ASSERT_EQ(0, fclose(fp));
}

static void AssertFileIs(const char* path, const char* expected) {
  FILE* fp;
  ASSERT_NE(nullptr, fp = fopen(path, "r"));
  char* line = nullptr;
  size_t length;
  ASSERT_NE(EOF, getline(&line, &length, fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_STREQ(expected, line);
  free(line);
}

static void AssertFileIs(FILE* fp, const char* expected, bool is_fmemopen = false) {
  rewind(fp);

  char line[1024];
  memset(line, 0xff, sizeof(line));
  ASSERT_EQ(line, fgets(line, sizeof(line), fp));
  ASSERT_STREQ(expected, line);

  if (is_fmemopen) {
    // fmemopen appends a trailing NUL byte, which probably shouldn't show up as an
    // extra empty line, but does on every C library I tested...
    ASSERT_EQ(line, fgets(line, sizeof(line), fp));
    ASSERT_STREQ("", line);
  }

  // Make sure there isn't anything else in the file.
  ASSERT_EQ(nullptr, fgets(line, sizeof(line), fp)) << "junk at end of file: " << line;
}

#define EXPECT_SNPRINTF_N(expected, n, fmt, ...)                        \
  {                                                                     \
    char buf[BUFSIZ];                                                   \
    int w = snprintf(buf, sizeof(buf), fmt __VA_OPT__(, ) __VA_ARGS__); \
    EXPECT_EQ(n, w);                                                    \
    EXPECT_STREQ(expected, buf);                                        \
  }

#define EXPECT_SNPRINTF(expected, fmt, ...) \
  EXPECT_SNPRINTF_N(expected, static_cast<int>(strlen(expected)), fmt __VA_OPT__(, ) __VA_ARGS__)

#define EXPECT_SWPRINTF_N(expected, n, fmt, ...)                        \
  {                                                                     \
    wchar_t buf[BUFSIZ];                                                \
    int w = swprintf(buf, sizeof(buf), fmt __VA_OPT__(, ) __VA_ARGS__); \
    EXPECT_EQ(n, w);                                                    \
    EXPECT_EQ(std::wstring(expected), std::wstring(buf, w));            \
  }
#define EXPECT_SWPRINTF(expected, fmt, ...) \
  EXPECT_SWPRINTF_N(expected, static_cast<int>(wcslen(expected)), fmt __VA_OPT__(, ) __VA_ARGS__)

TEST(STDIO_TEST, flockfile_18208568_stderr) {
  flockfile(stderr);
  // Check that we're using a _recursive_ mutex for flockfile() by calling
  // something that will take the lock.
  ASSERT_EQ(0, feof(stderr));
  funlockfile(stderr);
}

TEST(STDIO_TEST, flockfile_18208568_regular) {
  // We never had a bug for streams other than stdin/stdout/stderr, but test anyway.
  FILE* fp = fopen("/dev/null", "w");
  ASSERT_TRUE(fp != nullptr);
  flockfile(fp);
  // Check that we're using a _recursive_ mutex for flockfile() by calling
  // something that will take the lock.
  ASSERT_EQ(0, feof(fp));
  funlockfile(fp);
  fclose(fp);
}

TEST(STDIO_TEST, tmpfile_fileno_fprintf_rewind_fgets) {
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  int fd = fileno(fp);
  ASSERT_NE(fd, -1);

  struct stat sb;
  int rc = fstat(fd, &sb);
  ASSERT_NE(rc, -1);
  ASSERT_EQ(sb.st_mode & 0777, 0600U);

  rc = fprintf(fp, "hello\n");
  ASSERT_EQ(rc, 6);

  AssertFileIs(fp, "hello\n");
  fclose(fp);
}

TEST(STDIO_TEST, tmpfile64) {
  FILE* fp = tmpfile64();
  ASSERT_TRUE(fp != nullptr);
  fclose(fp);
}

TEST(STDIO_TEST, tmpfile_TMPDIR) {
  TemporaryDir td;
  setenv("TMPDIR", td.path, 1);

  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fileno(fp));
  char path[PATH_MAX];
  ASSERT_GT(readlink(fd_path.c_str(), path, sizeof(path)), 0);
  // $TMPDIR influenced where our temporary file ended up?
  ASSERT_TRUE(android::base::StartsWith(path, td.path)) << path;
  // And we used O_TMPFILE, right?
  ASSERT_TRUE(android::base::EndsWith(path, " (deleted)")) << path;
}

TEST(STDIO_TEST, dprintf) {
  TemporaryFile tf;

  int rc = dprintf(tf.fd, "hello\n");
  ASSERT_EQ(rc, 6);

  lseek(tf.fd, 0, SEEK_SET);
  FILE* tfile = fdopen(tf.fd, "r");
  ASSERT_TRUE(tfile != nullptr);

  AssertFileIs(tfile, "hello\n");
  fclose(tfile);
}

TEST(STDIO_TEST, getdelim) {
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  const char* line_written = "This  is a test";
  int rc = fprintf(fp, "%s", line_written);
  ASSERT_EQ(rc, static_cast<int>(strlen(line_written)));

  rewind(fp);

  char* word_read = nullptr;
  size_t allocated_length = 0;

  const char* expected[] = { "This ", " ", "is ", "a ", "test" };
  for (size_t i = 0; i < 5; ++i) {
    ASSERT_FALSE(feof(fp));
    ASSERT_EQ(getdelim(&word_read, &allocated_length, ' ', fp), static_cast<int>(strlen(expected[i])));
    ASSERT_GE(allocated_length, strlen(expected[i]));
    ASSERT_STREQ(expected[i], word_read);
  }
  // The last read should have set the end-of-file indicator for the stream.
  ASSERT_TRUE(feof(fp));
  clearerr(fp);

  // getdelim returns -1 but doesn't set errno if we're already at EOF.
  // It should set the end-of-file indicator for the stream, though.
  errno = 0;
  ASSERT_EQ(getdelim(&word_read, &allocated_length, ' ', fp), -1);
  ASSERT_ERRNO(0);
  ASSERT_TRUE(feof(fp));

  free(word_read);
  fclose(fp);
}

TEST(STDIO_TEST, getdelim_invalid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  char* buffer = nullptr;
  size_t buffer_length = 0;

  // The first argument can't be NULL.
  errno = 0;
  ASSERT_EQ(getdelim(nullptr, &buffer_length, ' ', fp), -1);
  ASSERT_ERRNO(EINVAL);

  // The second argument can't be NULL.
  errno = 0;
  ASSERT_EQ(getdelim(&buffer, nullptr, ' ', fp), -1);
  ASSERT_ERRNO(EINVAL);
  fclose(fp);
#pragma clang diagnostic pop
}

TEST(STDIO_TEST, getdelim_directory) {
  FILE* fp = fopen("/proc", "r");
  ASSERT_TRUE(fp != nullptr);
  char* word_read;
  size_t allocated_length;
  ASSERT_EQ(-1, getdelim(&word_read, &allocated_length, ' ', fp));
  fclose(fp);
}

TEST(STDIO_TEST, getline) {
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  const char* line_written = "This is a test for getline\n";
  const size_t line_count = 5;

  for (size_t i = 0; i < line_count; ++i) {
    int rc = fprintf(fp, "%s", line_written);
    ASSERT_EQ(rc, static_cast<int>(strlen(line_written)));
  }

  rewind(fp);

  char* line_read = nullptr;
  size_t allocated_length = 0;

  size_t read_line_count = 0;
  ssize_t read_char_count;
  while ((read_char_count = getline(&line_read, &allocated_length, fp)) != -1) {
    ASSERT_EQ(read_char_count, static_cast<int>(strlen(line_written)));
    ASSERT_GE(allocated_length, strlen(line_written));
    ASSERT_STREQ(line_written, line_read);
    ++read_line_count;
  }
  ASSERT_EQ(read_line_count, line_count);

  // The last read should have set the end-of-file indicator for the stream.
  ASSERT_TRUE(feof(fp));
  clearerr(fp);

  // getline returns -1 but doesn't set errno if we're already at EOF.
  // It should set the end-of-file indicator for the stream, though.
  errno = 0;
  ASSERT_EQ(getline(&line_read, &allocated_length, fp), -1);
  ASSERT_ERRNO(0);
  ASSERT_TRUE(feof(fp));

  free(line_read);
  fclose(fp);
}

TEST(STDIO_TEST, getline_invalid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  char* buffer = nullptr;
  size_t buffer_length = 0;

  // The first argument can't be NULL.
  errno = 0;
  ASSERT_EQ(getline(nullptr, &buffer_length, fp), -1);
  ASSERT_ERRNO(EINVAL);

  // The second argument can't be NULL.
  errno = 0;
  ASSERT_EQ(getline(&buffer, nullptr, fp), -1);
  ASSERT_ERRNO(EINVAL);
  fclose(fp);
#pragma clang diagnostic pop
}

TEST(STDIO_TEST, printf_ssize_t) {
  // http://b/8253769
  ASSERT_EQ(sizeof(ssize_t), sizeof(long int));
  ASSERT_EQ(sizeof(ssize_t), sizeof(size_t));
  // For our 32-bit ABI, we had a ssize_t definition that confuses GCC into saying:
  // error: format '%zd' expects argument of type 'signed size_t',
  //     but argument 4 has type 'ssize_t {aka long int}' [-Werror=format]
  ssize_t v = 1;
  EXPECT_SNPRINTF("1", "%zd", v);
  EXPECT_SWPRINTF(L"1", L"%zd", v);
}

// https://code.google.com/p/android/issues/detail?id=64886
TEST(STDIO_TEST, snprintf_a) {
  EXPECT_SNPRINTF("<0x1.3831e147ae148p+13>", "<%a>", 9990.235);
}

// https://code.google.com/p/android/issues/detail?id=64886
TEST(STDIO_TEST, swprintf_a) {
  EXPECT_SWPRINTF(L"<0x1.3831e147ae148p+13>", L"<%a>", 9990.235);
}

// http://b/152588929
TEST(STDIO_TEST, snprintf_La) {
#if defined(__LP64__)
  union {
    uint64_t a[2];
    long double v;
  } u;

  u.a[0] = UINT64_C(0x9b9b9b9b9b9b9b9b);
  u.a[1] = UINT64_C(0xdfdfdfdfdfdfdfdf);
  EXPECT_SNPRINTF("<-0x1.dfdfdfdfdfdf9b9b9b9b9b9b9b9bp+8160>", "<%La>", u.v);

  u.a[0] = UINT64_C(0xffffffffffffffff);
  u.a[1] = UINT64_C(0x7ffeffffffffffff);
  EXPECT_SNPRINTF("<0x1.ffffffffffffffffffffffffffffp+16383>", "<%La>", u.v);

  u.a[0] = UINT64_C(0x0000000000000000);
  u.a[1] = UINT64_C(0x0000000000000000);
  EXPECT_SNPRINTF("<0x0p+0>", "<%La>", u.v);
#else
  GTEST_SKIP() << "no ld128";
#endif
}

// http://b/152588929
TEST(STDIO_TEST, swprintf_La) {
#if defined(__LP64__)
  union {
    uint64_t a[2];
    long double v;
  } u;

  u.a[0] = UINT64_C(0x9b9b9b9b9b9b9b9b);
  u.a[1] = UINT64_C(0xdfdfdfdfdfdfdfdf);
  EXPECT_SWPRINTF(L"<-0x1.dfdfdfdfdfdf9b9b9b9b9b9b9b9bp+8160>", L"<%La>", u.v);

  u.a[0] = UINT64_C(0xffffffffffffffff);
  u.a[1] = UINT64_C(0x7ffeffffffffffff);
  EXPECT_SWPRINTF(L"<0x1.ffffffffffffffffffffffffffffp+16383>", L"<%La>", u.v);

  u.a[0] = UINT64_C(0x0000000000000000);
  u.a[1] = UINT64_C(0x0000000000000000);
  EXPECT_SWPRINTF(L"<0x0p+0>", L"<%La>", u.v);
#else
  GTEST_SKIP() << "no ld128";
#endif
}

TEST(STDIO_TEST, snprintf_lc) {
  wint_t wc = L'a';
  EXPECT_SNPRINTF("<a>", "<%lc>", wc);
}

TEST(STDIO_TEST, swprintf_lc) {
  wint_t wc = L'a';
  EXPECT_SWPRINTF(L"<a>", L"<%lc>", wc);
}

TEST(STDIO_TEST, snprintf_C) {  // Synonym for %lc.
  wchar_t wc = L'a';
  EXPECT_SNPRINTF("<a>", "<%C>", wc);
}

TEST(STDIO_TEST, swprintf_C) {  // Synonym for %lc.
  wchar_t wc = L'a';
  EXPECT_SWPRINTF(L"<a>", L"<%C>", wc);
}

TEST(STDIO_TEST, snprintf_ls_null) {
  EXPECT_SNPRINTF("<(null)>", "<%ls>", static_cast<wchar_t*>(nullptr));
}

TEST(STDIO_TEST, swprintf_ls_null) {
  EXPECT_SWPRINTF(L"<(null)>", L"<%ls>", static_cast<wchar_t*>(nullptr));
}

TEST(STDIO_TEST, snprintf_ls) {
  static const wchar_t chars[] = L"Hello\u0666 World";
  EXPECT_SNPRINTF("<Hello\xd9\xa6 World>", "<%ls>", chars);
}

TEST(STDIO_TEST, swprintf_ls) {
  static const wchar_t chars[] = L"Hello\u0666 World";
  EXPECT_SWPRINTF(L"<Hello\u0666 World>", L"<%ls>", chars);
}

TEST(STDIO_TEST, snprintf_S_nullptr) {  // Synonym for %ls.
  EXPECT_SNPRINTF("<(null)>", "<%S>", static_cast<wchar_t*>(nullptr));
}

TEST(STDIO_TEST, swprintf_S_nullptr) {  // Synonym for %ls.
  EXPECT_SWPRINTF(L"<(null)>", L"<%S>", static_cast<wchar_t*>(nullptr));
}

TEST(STDIO_TEST, snprintf_S) { // Synonym for %ls.
  static const wchar_t chars[] = L"Hello\u0666 World";
  EXPECT_SNPRINTF("<Hello\xd9\xa6 World>", "<%S>", chars);
}

TEST(STDIO_TEST, swprintf_S) {  // Synonym for %ls.
  static const wchar_t chars[] = L"Hello\u0666 World";
  EXPECT_SWPRINTF(L"<Hello\u0666 World>", L"<%S>", chars);
}

TEST_F(STDIO_DEATHTEST, snprintf_n) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
  // http://b/14492135 and http://b/31832608.
  char buf[32];
  int i = 1234;
  EXPECT_DEATH(snprintf(buf, sizeof(buf), "a %n b", &i), "%n not allowed on Android");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "glibc does allow %n";
#endif
}

TEST_F(STDIO_DEATHTEST, swprintf_n) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
  // http://b/14492135 and http://b/31832608.
  wchar_t buf[32];
  int i = 1234;
  EXPECT_DEATH(swprintf(buf, sizeof(buf), L"a %n b", &i), "%n not allowed on Android");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "glibc does allow %n";
#endif
}

TEST(STDIO_TEST, snprintf_measure) {
  char buf[1] = {'x'};
  ASSERT_EQ(11, snprintf(buf, 0, "Hello %s", "world"));
  ASSERT_EQ('x', buf[0]);
}

// Unlike snprintf(), you *can't* use swprintf() to measure.
TEST(STDIO_TEST, swprintf_measure) {
  wchar_t buf[1] = {L'x'};
  ASSERT_EQ(-1, swprintf(buf, 0, L"Hello %S", L"world"));
  ASSERT_EQ(L'x', buf[0]);
}

TEST(STDIO_TEST, snprintf_smoke) {
  EXPECT_SNPRINTF("a", "a");
  EXPECT_SNPRINTF("%", "%%");
  EXPECT_SNPRINTF("01234", "01234");
  EXPECT_SNPRINTF("a01234b", "a%sb", "01234");

  EXPECT_SNPRINTF("a(null)b", "a%sb", static_cast<char*>(nullptr));
  EXPECT_SNPRINTF("aabbcc", "aa%scc", "bb");
  EXPECT_SNPRINTF("abc", "a%cc", 'b');
  EXPECT_SNPRINTF("a1234b", "a%db", 1234);
  EXPECT_SNPRINTF("a-8123b", "a%db", -8123);
  EXPECT_SNPRINTF("a16b", "a%hdb", static_cast<short>(0x7fff0010));
  EXPECT_SNPRINTF("a16b", "a%hhdb", static_cast<char>(0x7fffff10));
  EXPECT_SNPRINTF("a68719476736b", "a%lldb", 0x1000000000LL);
  EXPECT_SNPRINTF("a70000b", "a%ldb", 70000L);
  EXPECT_SNPRINTF("a0xb0001234b", "a%pb", reinterpret_cast<void*>(0xb0001234));
  EXPECT_SNPRINTF("a12abz", "a%xz", 0x12ab);
  EXPECT_SNPRINTF("a12ABz", "a%Xz", 0x12ab);
  EXPECT_SNPRINTF("a00123456z", "a%08xz", 0x123456);
  EXPECT_SNPRINTF("a 1234z", "a%5dz", 1234);
  EXPECT_SNPRINTF("a01234z", "a%05dz", 1234);
  EXPECT_SNPRINTF("a    1234z", "a%8dz", 1234);
  EXPECT_SNPRINTF("a1234    z", "a%-8dz", 1234);
  EXPECT_SNPRINTF("Aabcdef     Z", "A%-11sZ", "abcdef");
  EXPECT_SNPRINTF("Ahello:1234Z", "A%s:%dZ", "hello", 1234);
  EXPECT_SNPRINTF("a005:5:05z", "a%03d:%d:%02dz", 5, 5, 5);

#if defined(__BIONIC__)
  EXPECT_SNPRINTF("a5,0x0z", "a%d,%pz", 5, static_cast<void*>(nullptr));
#else // __BIONIC__
  EXPECT_SNPRINTF("a5,(nil)z", "a%d,%pz", 5, static_cast<void*>(nullptr));
#endif // __BIONIC__

  EXPECT_SNPRINTF("a68719476736,6,7,8z", "a%lld,%d,%d,%dz", 0x1000000000LL, 6, 7, 8);

  EXPECT_SNPRINTF("a_1.230000_b", "a_%f_b", 1.23f);
  EXPECT_SNPRINTF("a_3.14_b", "a_%g_b", 3.14);
  EXPECT_SNPRINTF("print_me_twice print_me_twice", "%1$s %1$s", "print_me_twice");
}

TEST(STDIO_TEST, swprintf_smoke) {
  EXPECT_SWPRINTF(L"a", L"a");
  EXPECT_SWPRINTF(L"%", L"%%");
  EXPECT_SWPRINTF(L"01234", L"01234");
  EXPECT_SWPRINTF(L"a01234b", L"a%sb", "01234");

  EXPECT_SWPRINTF(L"a(null)b", L"a%sb", static_cast<char*>(nullptr));
  EXPECT_SWPRINTF(L"aabbcc", L"aa%scc", "bb");
  EXPECT_SWPRINTF(L"abc", L"a%cc", 'b');
  EXPECT_SWPRINTF(L"a1234b", L"a%db", 1234);
  EXPECT_SWPRINTF(L"a-8123b", L"a%db", -8123);
  EXPECT_SWPRINTF(L"a16b", L"a%hdb", static_cast<short>(0x7fff0010));
  EXPECT_SWPRINTF(L"a16b", L"a%hhdb", static_cast<char>(0x7fffff10));
  EXPECT_SWPRINTF(L"a68719476736b", L"a%lldb", 0x1000000000LL);
  EXPECT_SWPRINTF(L"a70000b", L"a%ldb", 70000L);
  EXPECT_SWPRINTF(L"a0xb0001234b", L"a%pb", reinterpret_cast<void*>(0xb0001234));
  EXPECT_SWPRINTF(L"a12abz", L"a%xz", 0x12ab);
  EXPECT_SWPRINTF(L"a12ABz", L"a%Xz", 0x12ab);
  EXPECT_SWPRINTF(L"a00123456z", L"a%08xz", 0x123456);
  EXPECT_SWPRINTF(L"a 1234z", L"a%5dz", 1234);
  EXPECT_SWPRINTF(L"a01234z", L"a%05dz", 1234);
  EXPECT_SWPRINTF(L"a    1234z", L"a%8dz", 1234);
  EXPECT_SWPRINTF(L"a1234    z", L"a%-8dz", 1234);
  EXPECT_SWPRINTF(L"Aabcdef     Z", L"A%-11sZ", "abcdef");
  EXPECT_SWPRINTF(L"Ahello:1234Z", L"A%s:%dZ", "hello", 1234);
  EXPECT_SWPRINTF(L"a005:5:05z", L"a%03d:%d:%02dz", 5, 5, 5);

#if defined(__BIONIC__)
  EXPECT_SWPRINTF(L"a5,0x0z", L"a%d,%pz", 5, static_cast<void*>(nullptr));
#else   // __BIONIC__
  EXPECT_SWPRINTF(L"a5,(nil)z", L"a%d,%pz", 5, static_cast<void*>(nullptr));
#endif  // __BIONIC__

  EXPECT_SWPRINTF(L"a68719476736,6,7,8z", L"a%lld,%d,%d,%dz", 0x1000000000LL, 6, 7, 8);

  EXPECT_SWPRINTF(L"a_1.230000_b", L"a_%f_b", 1.23f);
  EXPECT_SWPRINTF(L"a_3.14_b", L"a_%g_b", 3.14);
  EXPECT_SWPRINTF(L"print_me_twice print_me_twice", L"%1$s %1$s", "print_me_twice");
}

template <typename T>
static void CheckInfNan(int snprintf_fn(T*, size_t, const T*, ...),
                        int sscanf_fn(const T*, const T*, ...),
                        const T* fmt_string, const T* fmt, const T* fmt_plus,
                        const T* minus_inf, const T* inf_, const T* plus_inf,
                        const T* minus_nan, const T* nan_, const T* plus_nan) {
  T buf[BUFSIZ];
  float f;

  // NaN.

  snprintf_fn(buf, sizeof(buf), fmt, nan(""));
  EXPECT_STREQ(nan_, buf) << fmt;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_TRUE(isnan(f));

  snprintf_fn(buf, sizeof(buf), fmt, -nan(""));
  EXPECT_STREQ(minus_nan, buf) << fmt;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_TRUE(isnan(f));

  snprintf_fn(buf, sizeof(buf), fmt_plus, nan(""));
  EXPECT_STREQ(plus_nan, buf) << fmt_plus;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_TRUE(isnan(f));

  snprintf_fn(buf, sizeof(buf), fmt_plus, -nan(""));
  EXPECT_STREQ(minus_nan, buf) << fmt_plus;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_TRUE(isnan(f));

  // Inf.

  snprintf_fn(buf, sizeof(buf), fmt, HUGE_VALF);
  EXPECT_STREQ(inf_, buf) << fmt;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_EQ(HUGE_VALF, f);

  snprintf_fn(buf, sizeof(buf), fmt, -HUGE_VALF);
  EXPECT_STREQ(minus_inf, buf) << fmt;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_EQ(-HUGE_VALF, f);

  snprintf_fn(buf, sizeof(buf), fmt_plus, HUGE_VALF);
  EXPECT_STREQ(plus_inf, buf) << fmt_plus;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_EQ(HUGE_VALF, f);

  snprintf_fn(buf, sizeof(buf), fmt_plus, -HUGE_VALF);
  EXPECT_STREQ(minus_inf, buf) << fmt_plus;
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f));
  EXPECT_EQ(-HUGE_VALF, f);

  // Check case-insensitivity.
  snprintf_fn(buf, sizeof(buf), fmt_string, "[InFiNiTy]");
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f)) << buf;
  EXPECT_EQ(HUGE_VALF, f);
  snprintf_fn(buf, sizeof(buf), fmt_string, "[NaN]");
  EXPECT_EQ(1, sscanf_fn(buf, fmt, &f)) << buf;
  EXPECT_TRUE(isnan(f));
}

TEST(STDIO_TEST, snprintf_sscanf_inf_nan) {
  CheckInfNan(snprintf, sscanf, "%s",
              "[%a]", "[%+a]",
              "[-inf]", "[inf]", "[+inf]",
              "[-nan]", "[nan]", "[+nan]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%A]", "[%+A]",
              "[-INF]", "[INF]", "[+INF]",
              "[-NAN]", "[NAN]", "[+NAN]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%e]", "[%+e]",
              "[-inf]", "[inf]", "[+inf]",
              "[-nan]", "[nan]", "[+nan]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%E]", "[%+E]",
              "[-INF]", "[INF]", "[+INF]",
              "[-NAN]", "[NAN]", "[+NAN]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%f]", "[%+f]",
              "[-inf]", "[inf]", "[+inf]",
              "[-nan]", "[nan]", "[+nan]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%F]", "[%+F]",
              "[-INF]", "[INF]", "[+INF]",
              "[-NAN]", "[NAN]", "[+NAN]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%g]", "[%+g]",
              "[-inf]", "[inf]", "[+inf]",
              "[-nan]", "[nan]", "[+nan]");
  CheckInfNan(snprintf, sscanf, "%s",
              "[%G]", "[%+G]",
              "[-INF]", "[INF]", "[+INF]",
              "[-NAN]", "[NAN]", "[+NAN]");
}

TEST(STDIO_TEST, swprintf_swscanf_inf_nan) {
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%a]", L"[%+a]",
              L"[-inf]", L"[inf]", L"[+inf]",
              L"[-nan]", L"[nan]", L"[+nan]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%A]", L"[%+A]",
              L"[-INF]", L"[INF]", L"[+INF]",
              L"[-NAN]", L"[NAN]", L"[+NAN]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%e]", L"[%+e]",
              L"[-inf]", L"[inf]", L"[+inf]",
              L"[-nan]", L"[nan]", L"[+nan]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%E]", L"[%+E]",
              L"[-INF]", L"[INF]", L"[+INF]",
              L"[-NAN]", L"[NAN]", L"[+NAN]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%f]", L"[%+f]",
              L"[-inf]", L"[inf]", L"[+inf]",
              L"[-nan]", L"[nan]", L"[+nan]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%F]", L"[%+F]",
              L"[-INF]", L"[INF]", L"[+INF]",
              L"[-NAN]", L"[NAN]", L"[+NAN]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%g]", L"[%+g]",
              L"[-inf]", L"[inf]", L"[+inf]",
              L"[-nan]", L"[nan]", L"[+nan]");
  CheckInfNan(swprintf, swscanf, L"%s",
              L"[%G]", L"[%+G]",
              L"[-INF]", L"[INF]", L"[+INF]",
              L"[-NAN]", L"[NAN]", L"[+NAN]");
}

TEST(STDIO_TEST, snprintf_jd_INTMAX_MAX) {
  EXPECT_SNPRINTF("9223372036854775807", "%jd", INTMAX_MAX);
}

TEST(STDIO_TEST, swprintf_jd_INTMAX_MAX) {
  EXPECT_SWPRINTF(L"9223372036854775807", L"%jd", INTMAX_MAX);
}

TEST(STDIO_TEST, snprintf_jd_INTMAX_MIN) {
  EXPECT_SNPRINTF("-9223372036854775808", "%jd", INTMAX_MIN);
}

TEST(STDIO_TEST, swprintf_jd_INTMAX_MIN) {
  EXPECT_SWPRINTF(L"-9223372036854775808", L"%jd", INTMAX_MIN);
}

TEST(STDIO_TEST, snprintf_ju_UINTMAX_MAX) {
  EXPECT_SNPRINTF("18446744073709551615", "%ju", UINTMAX_MAX);
}

TEST(STDIO_TEST, swprintf_ju_UINTMAX_MAX) {
  EXPECT_SWPRINTF(L"18446744073709551615", L"%ju", UINTMAX_MAX);
}

TEST(STDIO_TEST, snprintf_1$ju_UINTMAX_MAX) {
  EXPECT_SNPRINTF("18446744073709551615", "%1$ju", UINTMAX_MAX);
}

TEST(STDIO_TEST, swprintf_1$ju_UINTMAX_MAX) {
  EXPECT_SWPRINTF(L"18446744073709551615", L"%1$ju", UINTMAX_MAX);
}

TEST(STDIO_TEST, snprintf_d_INT_MAX) {
  EXPECT_SNPRINTF("2147483647", "%d", INT_MAX);
}

TEST(STDIO_TEST, swprintf_d_INT_MAX) {
  EXPECT_SWPRINTF(L"2147483647", L"%d", INT_MAX);
}

TEST(STDIO_TEST, snprintf_d_INT_MIN) {
  EXPECT_SNPRINTF("-2147483648", "%d", INT_MIN);
}

TEST(STDIO_TEST, swprintf_d_INT_MIN) {
  EXPECT_SWPRINTF(L"-2147483648", L"%d", INT_MIN);
}

TEST(STDIO_TEST, snprintf_ld_LONG_MAX) {
#if defined(__LP64__)
  EXPECT_SNPRINTF("9223372036854775807", "%ld", LONG_MAX);
#else
  EXPECT_SNPRINTF("2147483647", "%ld", LONG_MAX);
#endif
}

TEST(STDIO_TEST, swprintf_ld_LONG_MAX) {
#if defined(__LP64__)
  EXPECT_SWPRINTF(L"9223372036854775807", L"%ld", LONG_MAX);
#else
  EXPECT_SWPRINTF(L"2147483647", L"%ld", LONG_MAX);
#endif
}

TEST(STDIO_TEST, snprintf_ld_LONG_MIN) {
#if defined(__LP64__)
  EXPECT_SNPRINTF("-9223372036854775808", "%ld", LONG_MIN);
#else
  EXPECT_SNPRINTF("-2147483648", "%ld", LONG_MIN);
#endif
}

TEST(STDIO_TEST, swprintf_ld_LONG_MIN) {
#if defined(__LP64__)
  EXPECT_SWPRINTF(L"-9223372036854775808", L"%ld", LONG_MIN);
#else
  EXPECT_SWPRINTF(L"-2147483648", L"%ld", LONG_MIN);
#endif
}

TEST(STDIO_TEST, snprintf_lld_LLONG_MAX) {
  EXPECT_SNPRINTF("9223372036854775807", "%lld", LLONG_MAX);
}

TEST(STDIO_TEST, swprintf_lld_LLONG_MAX) {
  EXPECT_SWPRINTF(L"9223372036854775807", L"%lld", LLONG_MAX);
}

TEST(STDIO_TEST, snprintf_lld_LLONG_MIN) {
  EXPECT_SNPRINTF("-9223372036854775808", "%lld", LLONG_MIN);
}

TEST(STDIO_TEST, swprintf_lld_LLONG_MIN) {
  EXPECT_SWPRINTF(L"-9223372036854775808", L"%lld", LLONG_MIN);
}

TEST(STDIO_TEST, snprintf_o_UINT_MAX) {
  EXPECT_SNPRINTF("37777777777", "%o", UINT_MAX);
}

TEST(STDIO_TEST, swprintf_o_UINT_MAX) {
  EXPECT_SWPRINTF(L"37777777777", L"%o", UINT_MAX);
}

TEST(STDIO_TEST, snprintf_u_UINT_MAX) {
  EXPECT_SNPRINTF("4294967295", "%u", UINT_MAX);
}

TEST(STDIO_TEST, swprintf_u_UINT_MAX) {
  EXPECT_SWPRINTF(L"4294967295", L"%u", UINT_MAX);
}

TEST(STDIO_TEST, snprintf_x_UINT_MAX) {
  EXPECT_SNPRINTF("ffffffff", "%x", UINT_MAX);
}

TEST(STDIO_TEST, swprintf_x_UINT_MAX) {
  EXPECT_SWPRINTF(L"ffffffff", L"%x", UINT_MAX);
}

TEST(STDIO_TEST, snprintf_X_UINT_MAX) {
  EXPECT_SNPRINTF("FFFFFFFF", "%X", UINT_MAX);
}

TEST(STDIO_TEST, swprintf_X_UINT_MAX) {
  EXPECT_SWPRINTF(L"FFFFFFFF", L"%X", UINT_MAX);
}

TEST(STDIO_TEST, snprintf_e) {
  EXPECT_SNPRINTF("1.500000e+00", "%e", 1.5);
  EXPECT_SNPRINTF("1.500000e+00", "%Le", 1.5L);
}

TEST(STDIO_TEST, swprintf_e) {
  EXPECT_SWPRINTF(L"1.500000e+00", L"%e", 1.5);
  EXPECT_SWPRINTF(L"1.500000e+00", L"%Le", 1.5L);
}

TEST(STDIO_TEST, snprintf_negative_zero_5084292) {
  EXPECT_SNPRINTF("-0.000000e+00", "%e", -0.0);
  EXPECT_SNPRINTF("-0.000000E+00", "%E", -0.0);
  EXPECT_SNPRINTF("-0.000000", "%f", -0.0);
  EXPECT_SNPRINTF("-0.000000", "%F", -0.0);
  EXPECT_SNPRINTF("-0", "%g", -0.0);
  EXPECT_SNPRINTF("-0", "%G", -0.0);
  EXPECT_SNPRINTF("-0x0p+0", "%a", -0.0);
  EXPECT_SNPRINTF("-0X0P+0", "%A", -0.0);
}

TEST(STDIO_TEST, swprintf_negative_zero_5084292) {
  EXPECT_SWPRINTF(L"-0.000000e+00", L"%e", -0.0);
  EXPECT_SWPRINTF(L"-0.000000E+00", L"%E", -0.0);
  EXPECT_SWPRINTF(L"-0.000000", L"%f", -0.0);
  EXPECT_SWPRINTF(L"-0.000000", L"%F", -0.0);
  EXPECT_SWPRINTF(L"-0", L"%g", -0.0);
  EXPECT_SWPRINTF(L"-0", L"%G", -0.0);
  EXPECT_SWPRINTF(L"-0x0p+0", L"%a", -0.0);
  EXPECT_SWPRINTF(L"-0X0P+0", L"%A", -0.0);
}

TEST(STDIO_TEST, snprintf_utf8_15439554) {
  locale_t cloc = newlocale(LC_ALL, "C.UTF-8", nullptr);
  locale_t old_locale = uselocale(cloc);

  // http://b/15439554
  char buf[BUFSIZ];

  // 1-byte character.
  snprintf(buf, sizeof(buf), "%dx%d", 1, 2);
  EXPECT_STREQ("1x2", buf);
  // 2-byte character.
  snprintf(buf, sizeof(buf), "%d\xc2\xa2%d", 1, 2);
  EXPECT_STREQ("1¢2", buf);
  // 3-byte character.
  snprintf(buf, sizeof(buf), "%d\xe2\x82\xac%d", 1, 2);
  EXPECT_STREQ("1€2", buf);
  // 4-byte character.
  snprintf(buf, sizeof(buf), "%d\xf0\xa4\xad\xa2%d", 1, 2);
  EXPECT_STREQ("1𤭢2", buf);

  uselocale(old_locale);
  freelocale(cloc);
}

static void* snprintf_small_stack_fn(void*) {
  // Make life (realistically) hard for ourselves by allocating our own buffer for the result.
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "/proc/%d", getpid());
  return nullptr;
}

TEST(STDIO_TEST, snprintf_small_stack) {
  // Is it safe to call snprintf on a thread with a small stack?
  // (The snprintf implementation puts some pretty large buffers on the stack.)
  pthread_attr_t a;
  ASSERT_EQ(0, pthread_attr_init(&a));
  ASSERT_EQ(0, pthread_attr_setstacksize(&a, PTHREAD_STACK_MIN));

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &a, snprintf_small_stack_fn, nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST(STDIO_TEST, snprintf_asterisk_overflow) {
  char buf[128];
  ASSERT_EQ(5, snprintf(buf, sizeof(buf), "%.*s%c", 4, "hello world", '!'));
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.*s%c", INT_MAX/2, "hello world", '!'));
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.*s%c", INT_MAX-1, "hello world", '!'));
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.*s%c", INT_MAX, "hello world", '!'));
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.*s%c", -1, "hello world", '!'));

  // INT_MAX-1, INT_MAX, INT_MAX+1.
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.2147483646s%c", "hello world", '!'));
  ASSERT_EQ(12, snprintf(buf, sizeof(buf), "%.2147483647s%c", "hello world", '!'));
  ASSERT_EQ(-1, snprintf(buf, sizeof(buf), "%.2147483648s%c", "hello world", '!'));
  ASSERT_ERRNO(ENOMEM);
}

TEST(STDIO_TEST, swprintf_asterisk_overflow) {
  wchar_t buf[128];
  ASSERT_EQ(5, swprintf(buf, sizeof(buf), L"%.*s%c", 4, "hello world", '!'));
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.*s%c", INT_MAX / 2, "hello world", '!'));
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.*s%c", INT_MAX - 1, "hello world", '!'));
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.*s%c", INT_MAX, "hello world", '!'));
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.*s%c", -1, "hello world", '!'));

  // INT_MAX-1, INT_MAX, INT_MAX+1.
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.2147483646s%c", "hello world", '!'));
  ASSERT_EQ(12, swprintf(buf, sizeof(buf), L"%.2147483647s%c", "hello world", '!'));
  ASSERT_EQ(-1, swprintf(buf, sizeof(buf), L"%.2147483648s%c", "hello world", '!'));
  ASSERT_ERRNO(ENOMEM);
}

// Inspired by https://github.com/landley/toybox/issues/163.
TEST(STDIO_TEST, printf_NULL) {
  char* null = nullptr;
  EXPECT_SNPRINTF("<(n>", "<%*.*s>", 2, 2, null);
  EXPECT_SNPRINTF("<(null)>", "<%*.*s>", 2, 8, null);
  EXPECT_SNPRINTF("<      (n>", "<%*.*s>", 8, 2, null);
  EXPECT_SNPRINTF("<  (null)>", "<%*.*s>", 8, 8, null);
}

TEST(STDIO_TEST, wprintf_NULL) {
  char* null = nullptr;
  EXPECT_SWPRINTF(L"<(n>", L"<%*.*s>", 2, 2, null);
  EXPECT_SWPRINTF(L"<(null)>", L"<%*.*s>", 2, 8, null);
  EXPECT_SWPRINTF(L"<      (n>", L"<%*.*s>", 8, 2, null);
  EXPECT_SWPRINTF(L"<  (null)>", L"<%*.*s>", 8, 8, null);
}

TEST(STDIO_TEST, fprintf) {
  TemporaryFile tf;

  FILE* tfile = fdopen(tf.fd, "r+");
  ASSERT_TRUE(tfile != nullptr);

  ASSERT_EQ(7, fprintf(tfile, "%d %s", 123, "abc"));
  AssertFileIs(tfile, "123 abc");
  fclose(tfile);
}

TEST(STDIO_TEST, fprintf_failures_7229520) {
  // http://b/7229520
  FILE* fp;
  int fd_rdonly = open("/dev/null", O_RDONLY);
  ASSERT_NE(-1, fd_rdonly);

  // Unbuffered case where the fprintf(3) itself fails.
  ASSERT_NE(nullptr, fp = tmpfile());
  setbuf(fp, nullptr);
  ASSERT_EQ(4, fprintf(fp, "epic"));
  ASSERT_NE(-1, dup2(fd_rdonly, fileno(fp)));
  ASSERT_EQ(-1, fprintf(fp, "fail"));
  ASSERT_EQ(0, fclose(fp));

  // Buffered case where we won't notice until the fclose(3).
  // It's likely this is what was actually seen in http://b/7229520,
  // and that expecting fprintf to fail is setting yourself up for
  // disappointment. Remember to check fclose(3)'s return value, kids!
  ASSERT_NE(nullptr, fp = tmpfile());
  ASSERT_EQ(4, fprintf(fp, "epic"));
  ASSERT_NE(-1, dup2(fd_rdonly, fileno(fp)));
  ASSERT_EQ(4, fprintf(fp, "fail"));
  ASSERT_EQ(-1, fclose(fp));
}

TEST(STDIO_TEST, popen_r) {
  FILE* fp = popen("cat /proc/version", "r");
  ASSERT_TRUE(fp != nullptr);

  char buf[16];
  char* s = fgets(buf, sizeof(buf), fp);
  buf[13] = '\0';
  ASSERT_STREQ("Linux version", s);

  ASSERT_EQ(0, pclose(fp));
}

TEST(STDIO_TEST, popen_socketpair) {
  FILE* fp = popen("cat", "r+");
  ASSERT_TRUE(fp != nullptr);

  fputs("hello\nworld\n", fp);
  fflush(fp);

  char buf[16];
  ASSERT_NE(nullptr, fgets(buf, sizeof(buf), fp));
  EXPECT_STREQ("hello\n", buf);
  ASSERT_NE(nullptr, fgets(buf, sizeof(buf), fp));
  EXPECT_STREQ("world\n", buf);

  ASSERT_EQ(0, pclose(fp));
}

TEST(STDIO_TEST, popen_socketpair_shutdown) {
  FILE* fp = popen("uniq -c", "r+");
  ASSERT_TRUE(fp != nullptr);

  fputs("a\na\na\na\nb\n", fp);
  fflush(fp);
  ASSERT_EQ(0, shutdown(fileno(fp), SHUT_WR));

  char buf[16];
  ASSERT_NE(nullptr, fgets(buf, sizeof(buf), fp));
  EXPECT_STREQ("      4 a\n", buf);
  ASSERT_NE(nullptr, fgets(buf, sizeof(buf), fp));
  EXPECT_STREQ("      1 b\n", buf);

  ASSERT_EQ(0, pclose(fp));
}

TEST(STDIO_TEST, popen_return_value_0) {
  FILE* fp = popen("true", "r");
  ASSERT_TRUE(fp != nullptr);
  int status = pclose(fp);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(STDIO_TEST, popen_return_valu
"""


```