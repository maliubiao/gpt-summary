Response:
Let's break down the thought process for analyzing the `stdlib_test.cpp` file. The goal is to understand its purpose, the functions it tests, and how those functions relate to Android.

**1. Understanding the Core Purpose:**

The filename `stdlib_test.cpp` and the inclusion of `<stdlib.h>` immediately suggest that this file contains tests for standard C library functions related to general utilities, memory management, random number generation, string conversions, and system interactions. The location in `bionic/tests` confirms this is specifically testing Android's implementation of the standard library.

**2. Initial Scan for Included Headers:**

The `#include` directives provide a roadmap of the functionality being tested. I'd scan these first:

* **Standard C Library Headers:**  `<errno.h>`, `<fcntl.h>`, `<libgen.h>`, `<limits.h>`, `<math.h>`, `<pthread.h>`, `<stdint.h>`, `<stdlib.h>`, `<sys/cdefs.h>`, `<sys/types.h>`, `<sys/wait.h>`, `<unistd.h>` - These point to fundamental C library functions.
* **C++ Standard Library Headers:** `<limits>`, `<string>`, `<thread>` -  Indicates some C++ functionality might also be indirectly involved or the tests might use C++ features.
* **Android-Specific Headers:** `<android-base/file.h>`, `<android-base/macros.h>`, `<android-base/silent_death_test.h>`, `<android-base/test_utils.h>` - These are key indicators that the tests are running within the Android build system and potentially exercising Android-specific aspects or using Android testing utilities.
* **Google Test Header:** `<gtest/gtest.h>` - Confirms the use of the Google Test framework.
* **Local Headers:** `"math_data_test.h"`, `"utils.h"` - Suggests helper functions or data specific to these tests.

**3. Identifying Tested Functions (High-Level):**

Based on the included headers and a quick skim through the test names (`TEST(stdlib, function_name)`), I'd create an initial list of functions being tested:

* **Random Number Generation:** `drand48`, `erand48`, `lcong48`, `lrand48`, `random`, `rand`, `mrand48`, `jrand48`
* **Memory Allocation:** `posix_memalign`, `aligned_alloc`
* **Path Manipulation:** `realpath`
* **Sorting:** `qsort`, `qsort_r`
* **Environment Variables:** (Indirectly via `getenv` in a death test)
* **Temporary Files:** `mkostemp`, `mkostemp64`, `mkstemp`, `mkstemp64`
* **System Execution:** `system`
* **String to Number Conversion:** `atof`, `strtod`, `strtof`, `strtold`, `strtol`, `strtoll`, `strtoul`, `strtoull`, `strtoimax`, `strtoumax`, `atoi`, `atol`
* **Process Control:** `quick_exit`, `at_quick_exit`, `exit`, `_Exit`
* **Pseudo-Terminal (PTY) Handling:** `getpt`, `grantpt`, `ptsname_r`, `posix_openpt`, `ttyname`, `ttyname_r`, `unlockpt`
* **Option Parsing:** `getsubopt`
* **Multi-byte Character Handling:** `mblen`
* **Absolute Value:** `abs`, `labs`, `llabs`
* **System Load:** `getloadavg`
* **Program Name:** `getprogname`, `setprogname`

**4. Analyzing Individual Tests (Focusing on Functionality and Android Relevance):**

For each test, I'd consider:

* **What specific function is being tested?**
* **What aspects of the function's behavior are being verified?** (e.g., return values for specific inputs, error conditions, edge cases, correct output after seeding, alignment of allocated memory).
* **Is there anything specific to Android or bionic being tested?** (e.g., the use of `/data/local/tmp` or `/tmp` for temporary files, interactions with `/proc`, specific error codes).
* **Are there any potential user errors being highlighted implicitly by the tests?** (e.g., providing invalid alignment values to memory allocation functions, passing `NULL` pointers).

**5. Dynamic Linker Considerations:**

The prompt specifically mentions the dynamic linker. Scanning the included headers and test names doesn't directly reveal tests for dynamic linker *functions*. However, the very act of running these tests involves the dynamic linker loading the test executable and any necessary shared libraries.

* **Implicit Dynamic Linking:** The tests implicitly rely on the dynamic linker to locate and load the C library itself (bionic).
* **SO Layout:**  To illustrate SO layout, I'd need to create a simple scenario where a test depends on a custom shared library. This wasn't directly present in the provided code, so I would have to *infer* a common scenario.
* **Linking Process:** I'd outline the general steps of dynamic linking, explaining how symbols are resolved and how relocation happens.

**6. Android Framework/NDK Connection:**

To demonstrate how the Android framework or NDK reaches these libc functions:

* **Framework:** Start with a high-level Android API call (e.g., working with files, getting system properties). Trace this down through the framework's native layer (often written in C++) and show how it ultimately calls into standard C library functions.
* **NDK:**  Show a simple NDK example (e.g., allocating memory, opening a file) and point out the direct mapping to `malloc`, `open`, etc.

**7. Frida Hooking:**

For Frida examples, I'd choose a few representative libc functions and show how to intercept them using Frida's JavaScript API. This would involve finding the function's address and replacing its implementation or observing its arguments and return values.

**8. Structure and Language:**

Finally, organize the information clearly, using headings and bullet points. Use precise language to describe the functions and their behavior. Provide concrete examples wherever possible. Address all parts of the prompt.

**Self-Correction/Refinement during the process:**

* **Initial Oversimplification:**  Initially, I might just say "tests for standard library functions."  But the prompt asks for specifics. I'd then go back and list out the individual functions.
* **Missing Android Context:**  If I initially focus too much on generic libc behavior, I'd need to revisit the tests and highlight the Android-specific aspects (e.g., the temporary directory paths, `/proc` usage).
* **Dynamic Linker Depth:**  If my initial explanation of the dynamic linker is too basic, I'd add details about symbol resolution and relocation.
* **Frida Example Selection:** I'd choose diverse functions for Frida examples to illustrate different types of interactions (e.g., a memory allocation function, a file operation function).

By following this structured approach, I can systematically analyze the `stdlib_test.cpp` file and generate a comprehensive answer that addresses all aspects of the prompt.
好的，让我们来详细分析一下 `bionic/tests/stdlib_test.cpp` 这个文件。

**功能列举:**

这个 `stdlib_test.cpp` 文件的主要功能是作为 Android Bionic C 库中 `stdlib.h` 头文件中声明的各种函数的单元测试。它使用 Google Test 框架来验证这些函数的行为是否符合预期。 具体来说，它测试了以下几个方面的功能：

1. **随机数生成:**  测试 `rand`, `srand`, `random`, `srandom`, `drand48`, `srand48`, `erand48`, `lrand48`, `mrand48`, `jrand48`, `lcong48` 等一系列随机数生成函数及其种子设置。
2. **内存管理:** 测试 `posix_memalign` 和 `aligned_alloc` 两个用于分配对齐内存的函数。
3. **路径操作:** 测试 `realpath` 函数，用于将相对路径或包含符号链接的路径转换为绝对规范路径。
4. **排序:** 测试 `qsort` 和 `qsort_r` 函数，用于对数组进行排序。
5. **环境变量:**  通过一个死亡测试间接测试 `getenv` 函数在多线程环境下的行为。
6. **临时文件:** 测试 `mkstemp`, `mkstemp64`, `mkostemp`, `mkostemp64` 等创建唯一临时文件的函数。
7. **系统命令执行:** 测试 `system` 函数，用于执行 shell 命令。
8. **字符串到浮点数转换:** 测试 `atof`, `strtod`, `strtof`, `strtold` 等函数，用于将字符串转换为浮点数。
9. **进程控制:** 测试 `quick_exit` 和 `at_quick_exit` 函数，用于快速退出程序，以及 `exit` 函数及其 `atexit` 机制，还有底层的 `_Exit` 函数。
10. **伪终端 (PTY):** 测试 `getpt`, `grantpt`, `ptsname_r`, `posix_openpt`, `ttyname`, `ttyname_r`, `unlockpt` 等与 PTY 相关的函数。
11. **子选项解析:** 测试 `getsubopt` 函数，用于解析字符串中的子选项。
12. **多字节字符:** 测试 `mblen` 函数，用于获取多字节字符的长度。
13. **字符串到整数转换:** 测试 `atoi`, `atol`, `strtol`, `strtoll`, `strtoul`, `strtoull`, `strtoimax`, `strtoumax` 等函数，用于将字符串转换为整数。
14. **绝对值:** 测试 `abs`, `labs`, `llabs` 函数，用于计算整数的绝对值。
15. **系统负载:** 测试 `getloadavg` 函数，用于获取系统的平均负载。
16. **程序名:** 测试 `getprogname` 和 `setprogname` 函数，用于获取和设置程序名。

**与 Android 功能的关系及举例说明:**

由于 `bionic` 是 Android 的 C 库，因此这个测试文件中的所有函数都直接或间接地与 Android 的功能相关。以下是一些具体示例：

* **随机数生成:**  Android 系统中的很多组件和应用都需要生成随机数，例如生成加密密钥、分配随机端口号、实现游戏逻辑等。`rand`, `srand` 等函数被广泛使用。
* **内存管理:**  Android 应用和系统服务都需要动态分配内存。`malloc`, `free`, `posix_memalign`, `aligned_alloc` 等函数是内存管理的基础。例如，当应用创建一个新的 Bitmap 对象时，底层的图形库可能会使用这些函数来分配内存。
* **路径操作:**  Android 系统中频繁进行文件和目录的路径操作。例如，当应用需要访问存储在外部存储器上的文件时，就需要使用路径操作函数。`realpath` 可以用于解析符号链接，确保访问到的是目标文件。
* **排序:**  在 Android 的各种组件中，排序是很常见的操作。例如，联系人应用需要按字母顺序排列联系人，文件管理器需要按文件名或日期排序文件。`qsort` 等函数提供了通用的排序功能。
* **环境变量:**  Android 系统使用环境变量来传递配置信息。例如，`PATH` 环境变量指定了可执行文件的搜索路径。应用可以使用 `getenv` 函数来获取环境变量的值。
* **临时文件:**  Android 应用在运行时可能需要创建临时文件来存储中间数据。`mkstemp` 等函数可以安全地创建唯一的临时文件。
* **系统命令执行:**  某些 Android 系统级别的操作可能需要执行 shell 命令。例如，某些管理工具可能会使用 `system` 函数来执行 `adb` 命令。
* **字符串到数字转换:**  在解析配置文件、网络数据或者用户输入时，经常需要将字符串转换为数字。例如，解析 XML 或 JSON 数据时，可能会使用 `atoi`, `strtod` 等函数。
* **进程控制:**  Android 系统是基于进程的。应用的启动、退出以及进程间的通信都涉及到进程控制。`fork`, `exec`, `exit` 等函数是基础的进程控制函数。`quick_exit` 和 `at_quick_exit` 提供了在某些特定场景下更快速退出的方式。
* **伪终端 (PTY):**  PTY 在 Android 中主要用于终端模拟器和远程登录等场景。例如，当你在 Android 设备上使用终端模拟器应用时，该应用会使用 PTY 相关函数来创建和管理伪终端。
* **子选项解析:**  某些 Android 命令行工具或配置文件可能使用逗号分隔的选项和键值对。`getsubopt` 可以用来方便地解析这些选项。
* **多字节字符:**  Android 系统需要支持多语言，因此需要处理多字节字符编码（如 UTF-8）。`mblen` 等函数用于处理这些字符。
* **绝对值:**  在各种数值计算中都需要用到绝对值函数，例如计算距离、误差等。
* **系统负载:**  Android 系统可能会监控系统负载，以便进行资源管理或告警。`getloadavg` 可以获取系统的平均负载信息。
* **程序名:**  `getprogname` 和 `setprogname` 用于获取和设置程序的名字，这在调试和日志记录中很有用。

**libc 函数的实现解释:**

由于 `bionic` 是 Android 的 C 库，这些函数的具体实现细节可以在 `bionic` 的源代码中找到。以下是一些常见函数的简要解释（注意：具体实现可能比较复杂，这里只提供基本思路）：

* **`rand()` 和 `srand()`:**
    * `srand(seed)`：使用 `seed` 初始化一个全局的随机数生成器的种子。
    * `rand()`：使用线性同余发生器 (LCG) 或其他伪随机数生成算法，根据当前的种子生成一个伪随机数。
* **`malloc()` 和 `free()`:**
    * `malloc(size)`：从堆内存中分配一块大小为 `size` 字节的内存块。`bionic` 的实现通常会维护一个或多个空闲内存块的链表，找到合适大小的块并返回其地址。
    * `free(ptr)`：将 `ptr` 指向的内存块释放回堆内存。`bionic` 的实现会将该内存块添加到空闲内存块链表中，以便后续分配。
* **`open()`:**  调用底层的 Linux 系统调用 `open`，与内核交互，打开指定路径的文件。
* **`read()` 和 `write()`:**  调用底层的 Linux 系统调用 `read` 和 `write`，与内核交互，从文件描述符读取数据或向文件描述符写入数据。
* **`printf()`:**  格式化字符串，并将结果输出到标准输出。`bionic` 的实现会解析格式化字符串，并将参数按照指定的格式转换为字符串，然后调用底层的 `write` 系统调用输出。
* **`strcpy()`:**  将源字符串复制到目标字符串。`bionic` 的实现会逐个字符地从源字符串复制到目标字符串，直到遇到空字符 `\0`。
* **`strcmp()`:**  比较两个字符串。`bionic` 的实现会逐个字符地比较两个字符串，直到找到不同的字符或遇到空字符。
* **`system()`:**
    1. 调用 `fork()` 创建一个子进程。
    2. 在子进程中，调用 `execve()` 执行指定的命令（通常通过 `/system/bin/sh`）。
    3. 父进程调用 `waitpid()` 等待子进程结束。
    4. 返回子进程的退出状态。
* **`exit()`:**
    1. 执行所有通过 `atexit()` 注册的清理函数（按照注册顺序的逆序执行）。
    2. 调用底层的 Linux 系统调用 `_exit` 终止进程。
* **`realpath()`:**
    1. 解析输入路径中的各个组成部分。
    2. 对于每个符号链接，解析其指向的目标。
    3. 处理 `.` 和 `..` 等特殊路径组成部分。
    4. 构建规范化的绝对路径。

**Dynamic Linker 功能及 SO 布局样本和链接处理过程:**

涉及 dynamic linker 的功能主要体现在程序启动和共享库加载的过程中。`stdlib_test.cpp` 并没有直接测试
Prompt: 
```
这是目录为bionic/tests/stdlib_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>
#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/silent_death_test.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "math_data_test.h"
#include "utils.h"

using namespace std::string_literals;

template <typename T = int (*)(char*)>
class GenericTemporaryFile {
 public:
  explicit GenericTemporaryFile(T mk_fn = mkstemp) : mk_fn_(mk_fn) {
    // Since we might be running on the host or the target, and if we're
    // running on the host we might be running under bionic or glibc,
    // let's just try both possible temporary directories and take the
    // first one that works.
    init("/data/local/tmp");
    if (fd == -1) {
      init("/tmp");
    }
  }

  ~GenericTemporaryFile() {
    close(fd);
    unlink(path);
  }

  int fd;
  char path[1024];

 private:
  T mk_fn_;

  void init(const char* tmp_dir) {
    snprintf(path, sizeof(path), "%s/TemporaryFile-XXXXXX", tmp_dir);
    fd = mk_fn_(path);
  }

  DISALLOW_COPY_AND_ASSIGN(GenericTemporaryFile);
};

typedef GenericTemporaryFile<> MyTemporaryFile;

// The random number generator tests all set the seed, get four values, reset the seed and check
// that they get the first two values repeated, and then reset the seed and check two more values
// to rule out the possibility that we're just going round a cycle of four values.
// TODO: factor this out.

TEST(stdlib, drand48) {
  srand48(0x01020304);
  EXPECT_DOUBLE_EQ(0.65619299195623526, drand48());
  EXPECT_DOUBLE_EQ(0.18522597229772941, drand48());
  EXPECT_DOUBLE_EQ(0.42015087072844537, drand48());
  EXPECT_DOUBLE_EQ(0.061637783047395089, drand48());
  srand48(0x01020304);
  EXPECT_DOUBLE_EQ(0.65619299195623526, drand48());
  EXPECT_DOUBLE_EQ(0.18522597229772941, drand48());
  srand48(0x01020304);
  EXPECT_DOUBLE_EQ(0.65619299195623526, drand48());
  EXPECT_DOUBLE_EQ(0.18522597229772941, drand48());
}

TEST(stdlib, erand48) {
  const unsigned short seed[3] = { 0x330e, 0xabcd, 0x1234 };
  unsigned short xsubi[3];
  memcpy(xsubi, seed, sizeof(seed));
  EXPECT_DOUBLE_EQ(0.39646477376027534, erand48(xsubi));
  EXPECT_DOUBLE_EQ(0.84048536941142515, erand48(xsubi));
  EXPECT_DOUBLE_EQ(0.35333609724524351, erand48(xsubi));
  EXPECT_DOUBLE_EQ(0.44658343479654405, erand48(xsubi));
  memcpy(xsubi, seed, sizeof(seed));
  EXPECT_DOUBLE_EQ(0.39646477376027534, erand48(xsubi));
  EXPECT_DOUBLE_EQ(0.84048536941142515, erand48(xsubi));
  memcpy(xsubi, seed, sizeof(seed));
  EXPECT_DOUBLE_EQ(0.39646477376027534, erand48(xsubi));
  EXPECT_DOUBLE_EQ(0.84048536941142515, erand48(xsubi));
}

TEST(stdlib, lcong48) {
  unsigned short p[7] = { 0x0102, 0x0304, 0x0506, 0x0708, 0x090a, 0x0b0c, 0x0d0e };
  lcong48(p);
  EXPECT_EQ(1531389981, lrand48());
  EXPECT_EQ(1598801533, lrand48());
  EXPECT_EQ(2080534853, lrand48());
  EXPECT_EQ(1102488897, lrand48());
  lcong48(p);
  EXPECT_EQ(1531389981, lrand48());
  EXPECT_EQ(1598801533, lrand48());
  lcong48(p);
  EXPECT_EQ(1531389981, lrand48());
  EXPECT_EQ(1598801533, lrand48());
}

TEST(stdlib, lrand48) {
  srand48(0x01020304);
  EXPECT_EQ(1409163720, lrand48());
  EXPECT_EQ(397769746, lrand48());
  EXPECT_EQ(902267124, lrand48());
  EXPECT_EQ(132366131, lrand48());
  srand48(0x01020304);
  EXPECT_EQ(1409163720, lrand48());
  EXPECT_EQ(397769746, lrand48());
  srand48(0x01020304);
  EXPECT_EQ(1409163720, lrand48());
  EXPECT_EQ(397769746, lrand48());
}

TEST(stdlib, random) {
  srandom(0x01020304);
  EXPECT_EQ(55436735, random());
  EXPECT_EQ(1399865117, random());
  EXPECT_EQ(2032643283, random());
  EXPECT_EQ(571329216, random());
  srandom(0x01020304);
  EXPECT_EQ(55436735, random());
  EXPECT_EQ(1399865117, random());
  srandom(0x01020304);
  EXPECT_EQ(55436735, random());
  EXPECT_EQ(1399865117, random());
}

TEST(stdlib, rand) {
  srand(0x01020304);
  EXPECT_EQ(55436735, rand());
  EXPECT_EQ(1399865117, rand());
  EXPECT_EQ(2032643283, rand());
  EXPECT_EQ(571329216, rand());
  srand(0x01020304);
  EXPECT_EQ(55436735, rand());
  EXPECT_EQ(1399865117, rand());
  srand(0x01020304);
  EXPECT_EQ(55436735, rand());
  EXPECT_EQ(1399865117, rand());
}

TEST(stdlib, mrand48) {
  srand48(0x01020304);
  EXPECT_EQ(-1476639856, mrand48());
  EXPECT_EQ(795539493, mrand48());
  EXPECT_EQ(1804534249, mrand48());
  EXPECT_EQ(264732262, mrand48());
  srand48(0x01020304);
  EXPECT_EQ(-1476639856, mrand48());
  EXPECT_EQ(795539493, mrand48());
  srand48(0x01020304);
  EXPECT_EQ(-1476639856, mrand48());
  EXPECT_EQ(795539493, mrand48());
}

TEST(stdlib, jrand48_distribution) {
  const int iterations = 4096;
  const int pivot_low  = 1536;
  const int pivot_high = 2560;

  unsigned short xsubi[3];
  int bits[32] = {};

  for (int iter = 0; iter < iterations; ++iter) {
    long rand_val = jrand48(xsubi);
    for (int bit = 0; bit < 32; ++bit) {
      bits[bit] += (static_cast<unsigned long>(rand_val) >> bit) & 0x01;
    }
  }

  // Check that bit probability is uniform
  for (int bit = 0; bit < 32; ++bit) {
    EXPECT_TRUE((pivot_low <= bits[bit]) && (bits[bit] <= pivot_high));
  }
}

TEST(stdlib, mrand48_distribution) {
  const int iterations = 4096;
  const int pivot_low  = 1536;
  const int pivot_high = 2560;

  int bits[32] = {};

  for (int iter = 0; iter < iterations; ++iter) {
    long rand_val = mrand48();
    for (int bit = 0; bit < 32; ++bit) {
      bits[bit] += (static_cast<unsigned long>(rand_val) >> bit) & 0x01;
    }
  }

  // Check that bit probability is uniform
  for (int bit = 0; bit < 32; ++bit) {
    EXPECT_TRUE((pivot_low <= bits[bit]) && (bits[bit] <= pivot_high));
  }
}

TEST(stdlib, posix_memalign_sweep) {
  SKIP_WITH_HWASAN;
  void* ptr;

  // These should all fail.
  for (size_t align = 0; align < sizeof(long); align++) {
    ASSERT_EQ(EINVAL, posix_memalign(&ptr, align, 256))
        << "Unexpected value at align " << align;
  }

  // Verify powers of 2 up to 2048 allocate, and verify that all other
  // alignment values between the powers of 2 fail.
  size_t last_align = sizeof(long);
  for (size_t align = sizeof(long); align <= 2048; align <<= 1) {
    // Try all of the non power of 2 values from the last until this value.
    for (size_t fail_align = last_align + 1; fail_align < align; fail_align++) {
      ASSERT_EQ(EINVAL, posix_memalign(&ptr, fail_align, 256))
          << "Unexpected success at align " << fail_align;
    }
    ASSERT_EQ(0, posix_memalign(&ptr, align, 256))
        << "Unexpected failure at align " << align;
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) & (align - 1))
        << "Did not return a valid aligned ptr " << ptr << " expected alignment " << align;
    free(ptr);
    last_align = align;
  }
}

TEST(stdlib, posix_memalign_various_sizes) {
  std::vector<size_t> sizes{1, 4, 8, 256, 1024, 65000, 128000, 256000, 1000000};
  for (auto size : sizes) {
    void* ptr;
    ASSERT_EQ(0, posix_memalign(&ptr, 16, 1))
        << "posix_memalign failed at size " << size;
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) & 0xf)
        << "Pointer not aligned at size " << size << " ptr " << ptr;
    free(ptr);
  }
}

TEST(stdlib, posix_memalign_overflow) {
  SKIP_WITH_HWASAN;
  void* ptr;
  ASSERT_NE(0, posix_memalign(&ptr, 16, SIZE_MAX));
}

TEST(stdlib, aligned_alloc_sweep) {
  SKIP_WITH_HWASAN;
  // Verify powers of 2 up to 2048 allocate, and verify that all other
  // alignment values between the powers of 2 fail.
  size_t last_align = 1;
  for (size_t align = 1; align <= 2048; align <<= 1) {
    // Try all of the non power of 2 values from the last until this value.
    for (size_t fail_align = last_align + 1; fail_align < align; fail_align++) {
      ASSERT_TRUE(aligned_alloc(fail_align, fail_align) == nullptr)
          << "Unexpected success at align " << fail_align;
      ASSERT_ERRNO(EINVAL) << "Unexpected errno at align " << fail_align;
    }
    void* ptr = aligned_alloc(align, 2 * align);
    ASSERT_TRUE(ptr != nullptr) << "Unexpected failure at align " << align;
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) & (align - 1))
        << "Did not return a valid aligned ptr " << ptr << " expected alignment " << align;
    free(ptr);
    last_align = align;
  }
}

TEST(stdlib, aligned_alloc_overflow) {
  SKIP_WITH_HWASAN;
  ASSERT_TRUE(aligned_alloc(16, SIZE_MAX) == nullptr);
}

TEST(stdlib, aligned_alloc_size_not_multiple_of_alignment) {
  SKIP_WITH_HWASAN;

  ASSERT_TRUE(aligned_alloc(2048, 1) == nullptr);
  ASSERT_TRUE(aligned_alloc(4, 3) == nullptr);
  ASSERT_TRUE(aligned_alloc(4, 7) == nullptr);
  ASSERT_TRUE(aligned_alloc(16, 8) == nullptr);
}

TEST(stdlib, realpath__NULL_filename) {
  errno = 0;
  // Work around the compile-time error generated by FORTIFY here.
  const char* path = nullptr;
  char* p = realpath(path, nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(EINVAL);
}

TEST(stdlib, realpath__empty_filename) {
  errno = 0;
  char* p = realpath("", nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(ENOENT);
}

TEST(stdlib, realpath__ENOENT) {
  errno = 0;
  char* p = realpath("/this/directory/path/almost/certainly/does/not/exist", nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(ENOENT);
}

TEST(stdlib, realpath__ELOOP) {
  TemporaryDir td;
  std::string link = std::string(td.path) + "/loop";
  ASSERT_EQ(0, symlink(link.c_str(), link.c_str()));

  errno = 0;
  char* p = realpath(link.c_str(), nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(ELOOP);
}

TEST(stdlib, realpath__component_after_non_directory) {
  errno = 0;
  char* p = realpath("/dev/null/.", nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(ENOTDIR);

  errno = 0;
  p = realpath("/dev/null/..", nullptr);
  ASSERT_TRUE(p == nullptr);
  ASSERT_ERRNO(ENOTDIR);
}

TEST(stdlib, realpath) {
  // Get the name of this executable.
  char executable_path[PATH_MAX];
  int rc = readlink("/proc/self/exe", executable_path, sizeof(executable_path));
  ASSERT_NE(rc, -1);
  executable_path[rc] = '\0';

  char buf[PATH_MAX + 1];
  char* p = realpath("/proc/self/exe", buf);
  ASSERT_STREQ(executable_path, p);

  p = realpath("/proc/self/exe", nullptr);
  ASSERT_STREQ(executable_path, p);
  free(p);
}

TEST(stdlib, realpath__dot) {
  char* p = realpath("/proc/./version", nullptr);
  ASSERT_STREQ("/proc/version", p);
  free(p);
}

TEST(stdlib, realpath__dot_dot) {
  char* p = realpath("/dev/../proc/version", nullptr);
  ASSERT_STREQ("/proc/version", p);
  free(p);
}

TEST(stdlib, realpath__deleted) {
  TemporaryDir td;

  // Create a file "A".
  std::string A_path = td.path + "/A"s;
  ASSERT_TRUE(android::base::WriteStringToFile("test\n", A_path));

  // Get an O_PATH fd for it.
  android::base::unique_fd fd(open(A_path.c_str(), O_PATH));
  ASSERT_NE(fd, -1);

  // Create a file "A (deleted)".
  android::base::unique_fd fd2(open((td.path + "/A (deleted)"s).c_str(),
                                    O_CREAT | O_TRUNC | O_WRONLY, 0644));
  ASSERT_NE(fd2, -1);

  // Delete "A".
  ASSERT_EQ(0, unlink(A_path.c_str()));

  // Now realpath() on the O_PATH fd, and check we *don't* get "A (deleted)".
  std::string path = android::base::StringPrintf("/proc/%d/fd/%d", static_cast<int>(getpid()),
                                                 fd.get());
  errno = 0;
  char* result = realpath(path.c_str(), nullptr);
  ASSERT_EQ(nullptr, result) << result;
  ASSERT_ERRNO(ENOENT);
  free(result);
}

TEST(stdlib, qsort) {
  struct s {
    char name[16];
    static int comparator(const void* lhs, const void* rhs) {
      return strcmp(reinterpret_cast<const s*>(lhs)->name, reinterpret_cast<const s*>(rhs)->name);
    }
  };
  s entries[3];
  strcpy(entries[0].name, "charlie");
  strcpy(entries[1].name, "bravo");
  strcpy(entries[2].name, "alpha");

  qsort(entries, 3, sizeof(s), s::comparator);
  ASSERT_STREQ("alpha", entries[0].name);
  ASSERT_STREQ("bravo", entries[1].name);
  ASSERT_STREQ("charlie", entries[2].name);

  qsort(entries, 3, sizeof(s), s::comparator);
  ASSERT_STREQ("alpha", entries[0].name);
  ASSERT_STREQ("bravo", entries[1].name);
  ASSERT_STREQ("charlie", entries[2].name);
}

TEST(stdlib, qsort_r) {
  struct s {
    char name[16];
    static int comparator(const void* lhs, const void* rhs, void* context) {
      int* count_p = reinterpret_cast<int*>(context);
      *count_p += 1;
      return strcmp(reinterpret_cast<const s*>(lhs)->name, reinterpret_cast<const s*>(rhs)->name);
    }
  };
  s entries[3];
  strcpy(entries[0].name, "charlie");
  strcpy(entries[1].name, "bravo");
  strcpy(entries[2].name, "alpha");

  int count;
  void* context = &count;

  count = 0;
  qsort_r(entries, 3, sizeof(s), s::comparator, context);
  ASSERT_STREQ("alpha", entries[0].name);
  ASSERT_STREQ("bravo", entries[1].name);
  ASSERT_STREQ("charlie", entries[2].name);
  ASSERT_EQ(count, 3);
}

static void* TestBug57421_child(void* arg) {
  pthread_t main_thread = reinterpret_cast<pthread_t>(arg);
  pthread_join(main_thread, nullptr);
  char* value = getenv("ENVIRONMENT_VARIABLE");
  if (value == nullptr) {
    setenv("ENVIRONMENT_VARIABLE", "value", 1);
  }
  return nullptr;
}

static void TestBug57421_main() {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, TestBug57421_child, reinterpret_cast<void*>(pthread_self())));
  pthread_exit(nullptr);
}

// Even though this isn't really a death test, we have to say "DeathTest" here so gtest knows to
// run this test (which exits normally) in its own process.

using stdlib_DeathTest = SilentDeathTest;

TEST_F(stdlib_DeathTest, getenv_after_main_thread_exits) {
  // https://code.google.com/p/android/issues/detail?id=57421
  ASSERT_EXIT(TestBug57421_main(), ::testing::ExitedWithCode(0), "");
}

TEST(stdlib, mkostemp64_smoke) {
  MyTemporaryFile tf([](char* path) { return mkostemp64(path, O_CLOEXEC); });
  ASSERT_TRUE(CloseOnExec(tf.fd));
}

TEST(stdlib, mkostemp) {
  MyTemporaryFile tf([](char* path) { return mkostemp(path, O_CLOEXEC); });
  ASSERT_TRUE(CloseOnExec(tf.fd));
}

TEST(stdlib, mkstemp64_smoke) {
  MyTemporaryFile tf(mkstemp64);
  struct stat64 sb;
  ASSERT_EQ(0, fstat64(tf.fd, &sb));
  ASSERT_EQ(O_LARGEFILE, fcntl(tf.fd, F_GETFL) & O_LARGEFILE);
}

TEST(stdlib, mkstemp) {
  MyTemporaryFile tf(mkstemp);
  struct stat sb;
  ASSERT_EQ(0, fstat(tf.fd, &sb));
}

TEST(stdlib, system) {
  int status;

  status = system("exit 0");
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(0, WEXITSTATUS(status));

  status = system("exit 1");
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(1, WEXITSTATUS(status));
}

TEST(stdlib, system_NULL) {
  // "The system() function shall always return non-zero when command is NULL."
  // https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/system.html
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  ASSERT_NE(0, system(nullptr));
#pragma clang diagnostic pop
}

// https://austingroupbugs.net/view.php?id=1440
TEST(stdlib, system_minus) {
  // Create a script with a name that starts with a '-'.
  TemporaryDir td;
  std::string script = std::string(td.path) + "/-minus";
  ASSERT_TRUE(android::base::WriteStringToFile("#!" BIN_DIR "sh\nexit 66\n", script));

  // Set $PATH so we can find it.
  setenv("PATH", td.path, 1);
  // Make it executable so we can run it.
  ASSERT_EQ(0, chmod(script.c_str(), 0555));

  int status = system("-minus");
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(66, WEXITSTATUS(status));

  // While we're here and have all the setup, let's test popen(3) too...
  FILE* fp = popen("-minus", "r");
  ASSERT_TRUE(fp != nullptr);
  status = pclose(fp);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(66, WEXITSTATUS(status));
}

TEST(stdlib, atof) {
  ASSERT_DOUBLE_EQ(1.23, atof("1.23"));
}

template <typename T>
static void CheckStrToFloat(T fn(const char* s, char** end)) {
  FpUlpEq<0, T> pred;

  EXPECT_PRED_FORMAT2(pred, 9.0, fn("9.0", nullptr));
  EXPECT_PRED_FORMAT2(pred, 9.0, fn("0.9e1", nullptr));
  EXPECT_PRED_FORMAT2(pred, 9.0, fn("0x1.2p3", nullptr));

  const char* s = " \t\v\f\r\n9.0";
  char* p;
  EXPECT_PRED_FORMAT2(pred, 9.0, fn(s, &p));
  EXPECT_EQ(s + strlen(s), p);

  EXPECT_TRUE(isnan(fn("+nan", nullptr)));
  EXPECT_TRUE(isnan(fn("nan", nullptr)));
  EXPECT_TRUE(isnan(fn("-nan", nullptr)));

  EXPECT_TRUE(isnan(fn("+nan(0xff)", nullptr)));
  EXPECT_TRUE(isnan(fn("nan(0xff)", nullptr)));
  EXPECT_TRUE(isnan(fn("-nan(0xff)", nullptr)));

  EXPECT_TRUE(isnan(fn("+nanny", &p)));
  EXPECT_STREQ("ny", p);
  EXPECT_TRUE(isnan(fn("nanny", &p)));
  EXPECT_STREQ("ny", p);
  EXPECT_TRUE(isnan(fn("-nanny", &p)));
  EXPECT_STREQ("ny", p);

  EXPECT_EQ(0, fn("muppet", &p));
  EXPECT_STREQ("muppet", p);
  EXPECT_EQ(0, fn("  muppet", &p));
  EXPECT_STREQ("  muppet", p);

  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("+inf", nullptr));
  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("inf", nullptr));
  EXPECT_EQ(-std::numeric_limits<T>::infinity(), fn("-inf", nullptr));

  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("+infinity", nullptr));
  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("infinity", nullptr));
  EXPECT_EQ(-std::numeric_limits<T>::infinity(), fn("-infinity", nullptr));

  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("+infinitude", &p));
  EXPECT_STREQ("initude", p);
  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("infinitude", &p));
  EXPECT_STREQ("initude", p);
  EXPECT_EQ(-std::numeric_limits<T>::infinity(), fn("-infinitude", &p));
  EXPECT_STREQ("initude", p);

  // Check case-insensitivity.
  EXPECT_EQ(std::numeric_limits<T>::infinity(), fn("InFiNiTy", nullptr));
  EXPECT_TRUE(isnan(fn("NaN", nullptr)));
}

TEST(stdlib, strtod) {
  CheckStrToFloat(strtod);
}

TEST(stdlib, strtof) {
  CheckStrToFloat(strtof);
}

TEST(stdlib, strtold) {
  CheckStrToFloat(strtold);
}

TEST(stdlib, strtof_2206701) {
  ASSERT_EQ(0.0f, strtof("7.0064923216240853546186479164495e-46", nullptr));
  ASSERT_EQ(1.4e-45f, strtof("7.0064923216240853546186479164496e-46", nullptr));
}

TEST(stdlib, strtod_largest_subnormal) {
  // This value has been known to cause javac and java to infinite loop.
  // http://www.exploringbinary.com/java-hangs-when-converting-2-2250738585072012e-308/
  ASSERT_EQ(2.2250738585072014e-308, strtod("2.2250738585072012e-308", nullptr));
  ASSERT_EQ(2.2250738585072014e-308, strtod("0.00022250738585072012e-304", nullptr));
  ASSERT_EQ(2.2250738585072014e-308, strtod("00000002.2250738585072012e-308", nullptr));
  ASSERT_EQ(2.2250738585072014e-308, strtod("2.225073858507201200000e-308", nullptr));
  ASSERT_EQ(2.2250738585072014e-308, strtod("2.2250738585072012e-00308", nullptr));
  ASSERT_EQ(2.2250738585072014e-308, strtod("2.22507385850720129978001e-308", nullptr));
  ASSERT_EQ(-2.2250738585072014e-308, strtod("-2.2250738585072012e-308", nullptr));
}

TEST(stdlib, quick_exit) {
  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    quick_exit(99);
  }

  AssertChildExited(pid, 99);
}

static int quick_exit_status = 0;

static void quick_exit_1(void) {
  ASSERT_EQ(quick_exit_status, 0);
  quick_exit_status = 1;
}

static void quick_exit_2(void) {
  ASSERT_EQ(quick_exit_status, 1);
}

static void not_run(void) {
  FAIL();
}

TEST(stdlib, at_quick_exit) {
  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    ASSERT_EQ(at_quick_exit(quick_exit_2), 0);
    ASSERT_EQ(at_quick_exit(quick_exit_1), 0);
    atexit(not_run);
    quick_exit(99);
  }

  AssertChildExited(pid, 99);
}

static void exit_from_atexit_func4() {
  std::thread([] { exit(4); }).detach();
  usleep(1000);
  fprintf(stderr, "4");
}

static void exit_from_atexit_func3() {
  std::thread([] { exit(3); }).detach();
  fprintf(stderr, "3");
  usleep(1000);
  // This should cause us to exit with status 99,
  // but not before printing "4",
  // and without re-running the previous atexit handlers.
  exit(99);
}

static void exit_from_atexit_func2() {
  std::thread([] { exit(2); }).detach();
  fprintf(stderr, "2");
  usleep(1000);
  // Register another atexit handler from within an atexit handler.
  atexit(exit_from_atexit_func3);
}

static void exit_from_atexit_func1() {
  // These atexit handlers all spawn another thread that tries to exit,
  // and sleep to try to lose the race.
  // The lock in exit() should ensure that only the first thread to call
  // exit() can ever win (but see exit_from_atexit_func3() for a subtelty).
  std::thread([] { exit(1); }).detach();
  usleep(1000);
  fprintf(stderr, "1");
}

static void exit_torturer() {
  atexit(exit_from_atexit_func4);
  // We deliberately don't register exit_from_atexit_func3() here;
  // see exit_from_atexit_func2().
  atexit(exit_from_atexit_func2);
  atexit(exit_from_atexit_func1);
  exit(0);
}

TEST(stdlib, exit_torture) {
  // Test that the atexit() handlers are run in the defined order (reverse
  // order of registration), even though one of them is registered by another
  // when it runs, and that we get the exit code from the last call to exit()
  // on the first thread to call exit() (rather than one of the other threads
  // or a deadlock from the second call on the same thread).
  ASSERT_EXIT(exit_torturer(), testing::ExitedWithCode(99), "1234");
}

TEST(unistd, _Exit) {
  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    _Exit(99);
  }

  AssertChildExited(pid, 99);
}

#if defined(ANDROID_HOST_MUSL)
// musl doesn't have getpt
int getpt() {
  return posix_openpt(O_RDWR|O_NOCTTY);
}
#endif

TEST(stdlib, pty_smoke) {
  // getpt returns a pty with O_RDWR|O_NOCTTY.
  int fd = getpt();
  ASSERT_NE(-1, fd);

  // grantpt is a no-op.
  ASSERT_EQ(0, grantpt(fd));

  // ptsname_r should start "/dev/pts/".
  char name_r[128];
  ASSERT_EQ(0, ptsname_r(fd, name_r, sizeof(name_r)));
  name_r[9] = 0;
  ASSERT_STREQ("/dev/pts/", name_r);

  close(fd);
}

TEST(stdlib, posix_openpt) {
  int fd = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC);
  ASSERT_NE(-1, fd);
  close(fd);
}

TEST(stdlib, ptsname_r_ENOTTY) {
  errno = 0;
  char buf[128];
  ASSERT_EQ(ENOTTY, ptsname_r(STDOUT_FILENO, buf, sizeof(buf)));
  ASSERT_ERRNO(ENOTTY);
}

TEST(stdlib, ptsname_r_EINVAL) {
  int fd = getpt();
  ASSERT_NE(-1, fd);
  errno = 0;
  char* buf = nullptr;
  ASSERT_EQ(EINVAL, ptsname_r(fd, buf, 128));
  ASSERT_ERRNO(EINVAL);
  close(fd);
}

TEST(stdlib, ptsname_r_ERANGE) {
  int fd = getpt();
  ASSERT_NE(-1, fd);
  errno = 0;
  char buf[1];
  ASSERT_EQ(ERANGE, ptsname_r(fd, buf, sizeof(buf)));
  ASSERT_ERRNO(ERANGE);
  close(fd);
}

TEST(stdlib, ttyname) {
  int fd = getpt();
  ASSERT_NE(-1, fd);

  // ttyname returns "/dev/ptmx" for a pty.
  ASSERT_STREQ("/dev/ptmx", ttyname(fd));

  close(fd);
}

TEST(stdlib, ttyname_r) {
  int fd = getpt();
  ASSERT_NE(-1, fd);

  // ttyname_r returns "/dev/ptmx" for a pty.
  char name_r[128];
  ASSERT_EQ(0, ttyname_r(fd, name_r, sizeof(name_r)));
  ASSERT_STREQ("/dev/ptmx", name_r);

  close(fd);
}

TEST(stdlib, ttyname_r_ENOTTY) {
  int fd = open("/dev/null", O_WRONLY);
  errno = 0;
  char buf[128];
  ASSERT_EQ(ENOTTY, ttyname_r(fd, buf, sizeof(buf)));
  ASSERT_ERRNO(ENOTTY);
  close(fd);
}

TEST(stdlib, ttyname_r_EINVAL) {
  int fd = getpt();
  ASSERT_NE(-1, fd);
  errno = 0;
  char* buf = nullptr;
  ASSERT_EQ(EINVAL, ttyname_r(fd, buf, 128));
  ASSERT_ERRNO(EINVAL);
  close(fd);
}

TEST(stdlib, ttyname_r_ERANGE) {
  int fd = getpt();
  ASSERT_NE(-1, fd);
  errno = 0;
  char buf[1];
  ASSERT_EQ(ERANGE, ttyname_r(fd, buf, sizeof(buf)));
  ASSERT_ERRNO(ERANGE);
  close(fd);
}

TEST(stdlib, unlockpt_ENOTTY) {
  int fd = open("/dev/null", O_WRONLY);
  errno = 0;
  ASSERT_EQ(-1, unlockpt(fd));
  ASSERT_ERRNO(ENOTTY);
  close(fd);
}

TEST(stdlib, getsubopt) {
  char* const tokens[] = {
    const_cast<char*>("a"),
    const_cast<char*>("b"),
    const_cast<char*>("foo"),
    nullptr
  };
  std::string input = "a,b,foo=bar,a,unknown";
  char* subopts = &input[0];
  char* value = nullptr;

  ASSERT_EQ(0, getsubopt(&subopts, tokens, &value));
  ASSERT_EQ(nullptr, value);
  ASSERT_EQ(1, getsubopt(&subopts, tokens, &value));
  ASSERT_EQ(nullptr, value);
  ASSERT_EQ(2, getsubopt(&subopts, tokens, &value));
  ASSERT_STREQ("bar", value);
  ASSERT_EQ(0, getsubopt(&subopts, tokens, &value));
  ASSERT_EQ(nullptr, value);

  ASSERT_EQ(-1, getsubopt(&subopts, tokens, &value));
}

TEST(stdlib, mblen) {
  // "If s is a null pointer, mblen() shall return a non-zero or 0 value, if character encodings,
  // respectively, do or do not have state-dependent encodings." We're always UTF-8.
  EXPECT_EQ(0, mblen(nullptr, 1));

  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  // 1-byte UTF-8.
  EXPECT_EQ(1, mblen("abcdef", 6));
  // 2-byte UTF-8.
  EXPECT_EQ(2, mblen("\xc2\xa2" "cdef", 6));
  // 3-byte UTF-8.
  EXPECT_EQ(3, mblen("\xe2\x82\xac" "def", 6));
  // 4-byte UTF-8.
  EXPECT_EQ(4, mblen("\xf0\xa4\xad\xa2" "ef", 6));

  // Illegal over-long sequence.
  ASSERT_EQ(-1, mblen("\xf0\x82\x82\xac" "ef", 6));

  // "mblen() shall ... return 0 (if s points to the null byte)".
  EXPECT_EQ(0, mblen("", 1));
}

template <typename T>
static void CheckStrToInt(T fn(const char* s, char** end, int base)) {
  char* end_p;

  // Negative base => invalid.
  errno = 0;
  ASSERT_EQ(T(0), fn("123", &end_p, -1));
  ASSERT_ERRNO(EINVAL);

  // Base 1 => invalid (base 0 means "please guess").
  errno = 0;
  ASSERT_EQ(T(0), fn("123", &end_p, 1));
  ASSERT_ERRNO(EINVAL);

  // Base > 36 => invalid.
  errno = 0;
  ASSERT_EQ(T(0), fn("123", &end_p, 37));
  ASSERT_ERRNO(EINVAL);

  // Both leading + or - are always allowed (even for the strtou* family).
  ASSERT_EQ(T(-123), fn("-123", &end_p, 10));
  ASSERT_EQ(T(123), fn("+123", &end_p, 10));

  // If we see "0b" *not* followed by a binary digit, we shouldn't swallow the 'b'.
  ASSERT_EQ(T(0), fn("0b", &end_p, 2));
  ASSERT_EQ('b', *end_p);

  // Binary (the "0b" prefix) is case-insensitive.
  ASSERT_EQ(T(0b101), fn("0b101", &end_p, 0));
  ASSERT_EQ(T(0b101), fn("0B101", &end_p, 0));

  // If we see "0x" *not* followed by a hex digit, we shouldn't swallow the 'x'.
  ASSERT_EQ(T(0), fn("0xy", &end_p, 16));
  ASSERT_EQ('x', *end_p);

  // Hexadecimal (both the "0x" prefix and the digits) is case-insensitive.
  ASSERT_EQ(T(0xab), fn("0xab", &end_p, 0));
  ASSERT_EQ(T(0xab), fn("0Xab", &end_p, 0));
  ASSERT_EQ(T(0xab), fn("0xAB", &end_p, 0));
  ASSERT_EQ(T(0xab), fn("0XAB", &end_p, 0));
  ASSERT_EQ(T(0xab), fn("0xAb", &end_p, 0));
  ASSERT_EQ(T(0xab), fn("0XAb", &end_p, 0));

  // Octal lives! (Sadly.)
  ASSERT_EQ(T(0666), fn("0666", &end_p, 0));

  if (std::numeric_limits<T>::is_signed) {
    // Minimum (such as -128).
    std::string min{std::to_string(std::numeric_limits<T>::min())};
    end_p = nullptr;
    errno = 0;
    ASSERT_EQ(std::numeric_limits<T>::min(), fn(min.c_str(), &end_p, 0));
    ASSERT_ERRNO(0);
    ASSERT_EQ('\0', *end_p);
    // Too negative (such as -129).
    min.back() = (min.back() + 1);
    end_p = nullptr;
    errno = 0;
    ASSERT_EQ(std::numeric_limits<T>::min(), fn(min.c_str(), &end_p, 0));
    ASSERT_ERRNO(ERANGE);
    ASSERT_EQ('\0', *end_p);
  }

  // Maximum (such as 127).
  std::string max{std::to_string(std::numeric_limits<T>::max())};
  end_p = nullptr;
  errno = 0;
  ASSERT_EQ(std::numeric_limits<T>::max(), fn(max.c_str(), &end_p, 0));
  ASSERT_ERRNO(0);
  ASSERT_EQ('\0', *end_p);
  // Too positive (such as 128).
  max.back() = (max.back() + 1);
  end_p = nullptr;
  errno = 0;
  ASSERT_EQ(std::numeric_limits<T>::max(), fn(max.c_str(), &end_p, 0));
  ASSERT_ERRNO(ERANGE);
  ASSERT_EQ('\0', *end_p);

  // Junk at the end of a valid conversion.
  errno = 0;
  ASSERT_EQ(static_cast<T>(123), fn("123abc", &end_p, 0));
  ASSERT_ERRNO(0);
  ASSERT_STREQ("abc", end_p);

  // In case of overflow, strto* leaves us pointing past the end of the number,
  // not at the digit that overflowed.
  end_p = nullptr;
  errno = 0;
  ASSERT_EQ(std::numeric_limits<T>::max(),
            fn("99999999999999999999999999999999999999999999999999999abc", &end_p, 0));
  ASSERT_ERRNO(ERANGE);
  ASSERT_STREQ("abc", end_p);
  if (std::numeric_limits<T>::is_signed) {
      end_p = nullptr;
      errno = 0;
      ASSERT_EQ(std::numeric_limits<T>::min(),
                fn("-99999999999999999999999999999999999999999999999999999abc", &end_p, 0));
      ASSERT_ERRNO(ERANGE);
      ASSERT_STREQ("abc", end_p);
  }
}

TEST(stdlib, strtol_smoke) {
  CheckStrToInt(strtol);
}

TEST(stdlib, strtoll_smoke) {
  CheckStrToInt(strtoll);
}

TEST(stdlib, strtoul_smoke) {
  CheckStrToInt(strtoul);
}

TEST(stdlib, strtoull_smoke) {
  CheckStrToInt(strtoull);
}

TEST(stdlib, strtoimax_smoke) {
  CheckStrToInt(strtoimax);
}

TEST(stdlib, strtoumax_smoke) {
  CheckStrToInt(strtoumax);
}

TEST(stdlib, atoi) {
  // Implemented using strtol in bionic, so extensive testing unnecessary.
  ASSERT_EQ(123, atoi("123four"));
  ASSERT_EQ(0, atoi("hello"));
}

TEST(stdlib, atol) {
  // Implemented using strtol in bionic, so extensive testing unnecessary.
  ASSERT_EQ(123L, atol("123four"));
  ASSERT_EQ(0L, atol("hello"));
}

TEST(stdlib, abs) {
  ASSERT_EQ(INT_MAX, abs(-INT_MAX));
  ASSERT_EQ(INT_MAX, abs(INT_MAX));
}

TEST(stdlib, labs) {
  ASSERT_EQ(LONG_MAX, labs(-LONG_MAX));
  ASSERT_EQ(LONG_MAX, labs(LONG_MAX));
}

TEST(stdlib, llabs) {
  ASSERT_EQ(LLONG_MAX, llabs(-LLONG_MAX));
  ASSERT_EQ(LLONG_MAX, llabs(LLONG_MAX));
}

TEST(stdlib, getloadavg) {
  double load[3];

  // The second argument should have been size_t.
  ASSERT_EQ(-1, getloadavg(load, -1));
  ASSERT_EQ(-1, getloadavg(load, INT_MIN));

  // Zero is a no-op.
  ASSERT_EQ(0, getloadavg(load, 0));

  // The Linux kernel doesn't support more than 3 (but you can ask for fewer).
  ASSERT_EQ(1, getloadavg(load, 1));
  ASSERT_EQ(2, getloadavg(load, 2));
  ASSERT_EQ(3, getloadavg(load, 3));
  ASSERT_EQ(3, getloadavg(load, 4));
  ASSERT_EQ(3, getloadavg(load, INT_MAX));

  // Read /proc/loadavg and check that it's "close enough".
  double expected[3];
  std::unique_ptr<FILE, decltype(&fclose)> fp{fopen("/proc/loadavg", "re"), fclose};
  ASSERT_EQ(3, fscanf(fp.get(), "%lf %lf %lf", &expected[0], &expected[1], &expected[2]));
  load[0] = load[1] = load[2] = nan("");
  ASSERT_EQ(3, getloadavg(load, 3));

  // Check that getloadavg(3) at least overwrote the NaNs.
  ASSERT_FALSE(isnan(load[0]));
  ASSERT_FALSE(isnan(load[1]));
  ASSERT_FALSE(isnan(load[2]));
  // And that the difference between /proc/loadavg and getloadavg(3) is "small".
  ASSERT_TRUE(fabs(expected[0] - load[0]) < 0.5) << expected[0] << ' ' << load[0];
  ASSERT_TRUE(fabs(expected[1] - load[1]) < 0.5) << expected[1] << ' ' << load[1];
  ASSERT_TRUE(fabs(expected[2] - load[2]) < 0.5) << expected[2] << ' ' << load[2];
}

TEST(stdlib, getprogname) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "glibc and musl don't have getprogname()";
#else
  // You should always have a name.
  ASSERT_TRUE(getprogname() != nullptr);
  // The name should never have a slash in it.
  ASSERT_TRUE(strchr(getprogname(), '/') == nullptr);
#endif
}

TEST(stdlib, setprogname) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "glibc and musl don't have setprogname()";
#else
  // setprogname() only takes the basename of what you give it.
  setprogname("/usr/bin/muppet");
  ASSERT_STREQ("muppet", getprogname());
#endif
}

"""

```