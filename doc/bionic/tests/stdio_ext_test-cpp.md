Response:
Let's break down the thought process to answer the user's request about `bionic/tests/stdio_ext_test.cpp`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the provided C++ test file. Key elements to address are:

* **Functionality:** What does this test file *do*? What aspects of `stdio_ext.h` does it verify?
* **Relationship to Android:** How do these functions relate to the broader Android system? Provide examples.
* **libc Implementation:** Explain how each tested function in `stdio_ext.h` likely works *under the hood*. This requires knowledge of standard C library implementations.
* **Dynamic Linker (if applicable):**  Does this file directly test dynamic linking? If so, provide relevant details. *Initial thought: This file seems to test `stdio` extensions, which are part of libc. Dynamic linking is involved in *how* libc is loaded, but the tests themselves don't seem to directly manipulate the linker.*
* **Logic and Assumptions:**  If there's any logical deduction, state the inputs and expected outputs. For a test file, the "inputs" are often the setup conditions, and the "outputs" are the assertions.
* **Common Errors:** What mistakes do programmers often make when using these `stdio` extensions?
* **Android Framework/NDK Path:** How does a call from the Android framework or NDK eventually lead to these `stdio` functions?
* **Frida Hooking:** How can Frida be used to observe these functions in action?

**2. Initial Scan and Categorization of Tests:**

The first step is to read through the test file and identify the functions being tested. The `TEST(stdio_ext, ...)` macros clearly indicate which function from `stdio_ext.h` each test targets. This leads to a list:

* `__fbufsize`
* `__flbf`
* `__fpending`
* `__freadahead`
* `__fpurge`
* `_flushlbf`
* `__freadable` and `__fwritable` (grouped together)
* `__freading` and `__fwriting` (grouped together)
* `__fseterr`
* `__fsetlocking`

**3. Function-by-Function Analysis (Core Logic):**

For each tested function, consider the following:

* **Purpose:** What does the function *do* from a user's perspective? (This can be inferred from the test names and the operations performed in the tests).
* **Mechanism (libc Implementation):**  How is this likely implemented in the C library? This requires some background knowledge of `FILE` structures and buffering in C. *For example, `__fbufsize` likely accesses a member of the `FILE` structure that stores the buffer size.*
* **Android Relevance:** Is there anything specific about how Android might use this?  *For example, buffering behavior affects performance, which is crucial on mobile.*
* **Test Logic:** What is the test doing to verify the function?  What are the expected outcomes (assertions)?  This helps understand the function's behavior more concretely.
* **Potential Errors:** What common mistakes might a programmer make when using this function? *For example, using `__fpurge` without realizing it discards buffered output.*

**4. Addressing Specific Requirements:**

* **Dynamic Linker:**  Realize that while `stdio` is part of libc, and libc is dynamically linked, this test file doesn't directly manipulate or test the dynamic linker itself. Therefore, a detailed dynamic linker explanation isn't strictly required *for this specific file*. However, acknowledge the dynamic linking aspect of libc's loading in the "Android Framework/NDK Path" section.
* **SO Layout:**  Since dynamic linking isn't a primary focus of the *test*, a detailed SO layout isn't crucial here. A simplified explanation of libc's existence as a shared object is sufficient.
* **Logic and Assumptions (Input/Output):**  For each test, the "input" is the setup (e.g., opening a file, setting buffering mode), and the "output" is the asserted value. Present these clearly.
* **Android Framework/NDK Path:**  Start from high-level Android components (like Java framework or NDK) and trace down to the C library. Mention the JNI bridge.
* **Frida Hooking:**  Provide concrete Frida code snippets to illustrate how to intercept calls to the tested functions.

**5. Structuring the Response:**

Organize the information logically:

* **Introduction:** Briefly state the purpose of the file.
* **Functionality Summary:**  Provide a high-level overview of what the tests cover.
* **Detailed Function Analysis:**  Go through each tested function individually, addressing all the required points (purpose, implementation, Android relevance, test logic, errors).
* **Dynamic Linker Aspects:**  Address this, even if it's to explain that the test doesn't directly focus on it. Explain libc's role as a shared object.
* **Android Framework/NDK Path:** Explain the call chain.
* **Frida Hooking:** Provide examples.
* **Conclusion:** Briefly summarize.

**6. Refinement and Language:**

* **Clarity:** Use clear and concise language. Avoid jargon where possible or explain it.
* **Accuracy:** Ensure technical details are correct.
* **Completeness:** Address all aspects of the user's request.
* **Chinese:**  Provide the entire response in Chinese, as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `__fsetlocking` has something to do with file locking across processes, potentially involving kernel system calls. *Correction:* The test focuses on the *stdio* locking mechanism, not necessarily system-level locks.
* **Realization:**  The user asked for dynamic linker details. While this test file doesn't directly test the dynamic linker, libc *is* dynamically linked. So, acknowledge that and briefly explain it in the context of how these functions become available. Don't overemphasize it.
* **Frida Snippets:** Ensure the Frida code is functional and clearly demonstrates how to hook the functions.

By following these steps, breaking down the request into manageable parts, and systematically analyzing the code, a comprehensive and accurate answer can be constructed. The key is to combine knowledge of C standard libraries, Android internals, and debugging techniques like Frida.
好的，让我们来详细分析一下 `bionic/tests/stdio_ext_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/stdio_ext_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 `stdio_ext.h` 头文件中声明的扩展标准输入/输出库函数的功能。 这些函数不是标准 C 库的一部分，而是 Android Bionic 提供的额外功能，旨在提供更细粒度的文件 I/O 控制和信息。

**与 Android 功能的关系及举例说明**

`stdio_ext.h` 中定义的函数提供了对标准 I/O 流更底层的访问和控制，这在 Android 系统中对于优化性能、处理特定场景非常有用。

* **`__fbufsize(FILE *fp)`:**  获取与文件流 `fp` 关联的缓冲区大小。在 Android 中，不同的应用场景可能需要不同大小的缓冲区来提高效率。例如，读取大文件时可能需要更大的缓冲区。
* **`__flbf(FILE *fp)`:** 检查文件流 `fp` 是否是行缓冲。  在日志记录等场景中，行缓冲可以确保每行数据都立即写入，这对于调试至关重要。Android 的 logcat 系统可能在某些底层操作中会用到这种缓冲模式。
* **`__fpending(FILE *fp)`:** 获取文件流 `fp` 中未写入的数据量（对于写操作）或已读取但尚未被 `getc` 等函数取走的数据量（对于读操作）。  这在需要精确控制数据刷新和读取的场景中很有用，例如在网络编程或需要保证数据完整性的文件操作中。
* **`__freadahead(FILE *fp)`:**  （非 POSIX 标准，glibc 中不存在）返回文件流 `fp` 中已经预读到缓冲区的数据量。这可以帮助了解 I/O 系统的预读行为，并可能用于性能分析。
* **`__fpurge(FILE *fp)`:** 清空文件流 `fp` 的缓冲区，丢弃所有未写入或未读取的数据。在需要立即刷新缓冲区或丢弃不需要的数据时使用，例如在某些错误处理场景中。
* **`_flushlbf()`:** 刷新所有行缓冲的文件流。这在确保所有行缓冲的数据都被写入时很有用，例如在程序退出前需要确保所有日志都已记录。
* **`__freadable(FILE *fp)` 和 `__fwritable(FILE *fp)`:**  检查文件流 `fp` 是否可读或可写。这可以用于在进行 I/O 操作前进行安全性检查。
* **`__freading(FILE *fp)` 和 `__fwriting(FILE *fp)`:** 检查文件流 `fp` 当前是否正在进行读操作或写操作。这在某些复杂的 I/O 状态管理中可能用到。
* **`__fseterr(FILE *fp)`:** 设置文件流 `fp` 的错误标志。这允许程序手动设置错误状态，可能用于模拟或测试错误处理逻辑。
* **`__fsetlocking(FILE *fp, int type)`:**  控制文件流 `fp` 的锁定模式，可以是内部锁定或由调用者负责锁定。这对于多线程环境下的文件操作至关重要，可以避免数据竞争。

**libc 函数的功能实现**

这些 `stdio_ext.h` 中定义的函数通常是对标准 C 库 `stdio.h` 中函数的扩展或补充。它们在 Bionic 中的实现细节可能涉及以下方面：

* **`FILE` 结构体访问:**  `FILE` 结构体是标准 C 库中用于表示文件流的数据结构。这些扩展函数通常会直接访问 `FILE` 结构体中的成员变量来获取或修改其状态，例如缓冲区指针、缓冲区大小、缓冲模式等。
* **系统调用:**  底层的 I/O 操作最终会通过系统调用与操作系统内核交互。例如，`fflush` 函数会调用 `write` 系统调用将缓冲区中的数据写入文件。`__fpurge` 可能会涉及类似的机制来清空缓冲区，但不执行实际的写入。
* **缓冲管理:**  标准 C 库实现了缓冲机制来提高 I/O 效率。这些扩展函数允许开发者更精细地控制缓冲行为。例如，`setvbuf` 函数允许用户自定义缓冲模式和缓冲区。
* **线程安全:**  在多线程环境下，对 `FILE` 结构体的访问需要进行同步。`__fsetlocking` 函数就是用来控制这种同步机制的。

**以 `__fbufsize(FILE *fp)` 为例：**

它的实现很可能直接访问 `FILE` 结构体内部表示缓冲区大小的成员。在 glibc 中，这个成员通常是 `_IO_buf_end - _IO_buf_base`。在 Bionic 中，虽然具体的结构体定义可能有所不同，但原理类似。

```c
// 假设的 Bionic __fbufsize 实现
size_t __fbufsize(FILE *fp) {
  if (fp && fp->_IO_buf_base && fp->_IO_buf_end) {
    return (size_t)(fp->_IO_buf_end - fp->_IO_buf_base);
  }
  return 0;
}
```

**涉及 Dynamic Linker 的功能**

`stdio_ext_test.cpp` 本身并没有直接测试 Dynamic Linker 的功能。它测试的是 Bionic C 库中 `stdio` 扩展的功能。但是，Bionic C 库 (libc.so) 本身就是一个动态链接库，它的加载和链接是由 Dynamic Linker 负责的。

**SO 布局样本：**

假设一个简单的 Android 应用使用了 `stdio_ext.h` 中的函数，那么其进程的内存布局中会包含 `libc.so`：

```
...
7b00000000-7b001ffffff r--p 00000000 b3:0e 131078       /apex/com.android.runtime/lib64/bionic/libc.so
7b001ffffff-7b0031fffff r-xp 00200000 b3:0e 131078       /apex/com.android.runtime/lib64/bionic/libc.so
7b0031fffff-7b0035ffffff r--p 00400000 b3:0e 131078       /apex/com.android.runtime/lib64/bionic/libc.so
7b0035ffffff-7b0036000ff r--p 004ff000 b3:0e 131078       /apex/com.android.runtime/lib64/bionic/libc.so
7b0036000ff-7b00363ffff rw-p 00500000 b3:0e 131078       /apex/com.android.runtime/lib64/bionic/libc.so
...
```

* **`r--p`**: 可读，不可写，私有映射，包含 ELF header 和只读数据段。
* **`r-xp`**: 可读，可执行，私有映射，包含代码段。
* **`rw-p`**: 可读，可写，私有映射，包含未初始化数据段 (BSS) 和堆。

**链接的处理过程：**

1. **加载时重定位：** 当应用启动时，Android 的 `zygote` 进程会 fork 出新的进程来运行应用。Dynamic Linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用的依赖库，包括 `libc.so`。
2. **符号查找：** 当应用代码调用 `stdio_ext.h` 中声明的函数时，例如 `__fbufsize`，Dynamic Linker 会在 `libc.so` 的符号表中查找该函数的地址。
3. **地址绑定：** 找到符号地址后，Dynamic Linker 会将调用指令中的占位符替换为实际的函数地址，这个过程称为重定位。

**假设输入与输出 (针对测试用例)**

我们以 `TEST(stdio_ext, __fbufsize)` 为例：

* **假设输入：**
    * 打开文件 `/proc/version` 用于读取 (`fopen("/proc/version", "r")`)。
    * 初始状态下，文件流 `fp` 可能还没有分配缓冲区。
    * 调用 `fgets` 读取数据后，会分配默认大小的缓冲区。
    * 使用 `setvbuf` 修改缓冲区大小。
* **预期输出：**
    * 初始调用 `__fbufsize(fp)` 应该返回 `0`。
    * 调用 `fgets` 后，`__fbufsize(fp)` 应该返回默认缓冲区大小，通常是 `1024`。
    * 使用 `setvbuf(fp, buf, _IOFBF, 1)` 后，`__fbufsize(fp)` 应该返回 `1`。
    * 使用 `setvbuf(fp, buf, _IOFBF, 8)` 后，`__fbufsize(fp)` 应该返回 `8`。

**用户或编程常见的使用错误**

* **不理解缓冲行为:**  开发者可能不清楚不同缓冲模式 (`_IOFBF`, `_IOLBF`, `_IONBF`) 的区别，导致数据写入不及时或丢失。例如，在行缓冲模式下，如果没有遇到换行符，数据可能不会立即写入。
* **错误地使用 `__fpurge`:**  过度或不必要地使用 `__fpurge` 可能会导致数据丢失，特别是对于输出流。应该谨慎使用，只在真正需要丢弃缓冲区内容时使用。
* **多线程环境下的竞争条件:**  在多线程环境下，如果不使用合适的锁定机制（例如通过 `__fsetlocking` 或 `flockfile`/`funlockfile`），多个线程同时操作同一个文件流可能导致数据损坏或程序崩溃。
* **假设默认缓冲区大小:**  开发者不应该假设默认缓冲区的大小，因为它可能因平台和实现而异。应该使用 `setvbuf` 来明确设置需要的缓冲区大小。
* **混淆 `__fpending` 的含义:**  对于输入流和输出流，`__fpending` 的含义不同。对于输出流，它表示待写入的数据；对于输入流，它表示已读取但未被消耗的数据。混淆这两者可能导致逻辑错误。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java层):**  Android Framework 中很多涉及文件 I/O 的操作最终会通过 JNI (Java Native Interface) 调用到 Native 代码。
2. **NDK (Native 开发):**  使用 Android NDK 开发的应用可以直接调用 Bionic 提供的 C/C++ 接口，包括 `stdio.h` 和 `stdio_ext.h` 中声明的函数。
3. **JNI 调用:**  当 Java 代码需要进行文件操作时，可能会调用到 Framework 中相关的 Native 方法。这些 Native 方法会使用标准的 C 库函数（如 `fopen`, `fread`, `fwrite` 等）。
4. **Bionic libc:**  这些标准 C 库函数以及 `stdio_ext.h` 中定义的扩展函数都由 Bionic C 库 (`libc.so`) 提供。
5. **系统调用:**  Bionic C 库中的 I/O 函数最终会通过系统调用与 Linux 内核交互，完成实际的文件读写操作。

**Frida Hook 示例调试步骤**

假设我们要 Hook `__fbufsize` 函数，查看其在实际应用中的行为。

**Frida Hook 代码 (JavaScript):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const moduleName = "libc.so";
    const functionName = "__fbufsize";

    const moduleBase = Module.getBaseAddress(moduleName);
    const fbufsizeAddress = Module.findExportByName(moduleName, functionName);

    if (fbufsizeAddress) {
        console.log(`Found ${functionName} at address: ${fbufsizeAddress}`);

        Interceptor.attach(fbufsizeAddress, {
            onEnter: function (args) {
                const fp = ptr(args[0]);
                console.log(`[${functionName}] Called with fp: ${fp}`);
            },
            onLeave: function (retval) {
                console.log(`[${functionName}] Returned: ${retval}`);
            }
        });
    } else {
        console.error(`Could not find export for ${functionName} in ${moduleName}`);
    }
} else {
    console.warn("This script is designed for ARM/ARM64 architectures.");
}
```

**调试步骤：**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **运行目标应用:** 启动你想要分析的 Android 应用。
3. **运行 Frida Hook 脚本:**  使用 Frida 命令将上面的 JavaScript 脚本注入到目标应用进程中。你需要知道目标应用的进程名或 PID。例如：
   ```bash
   frida -U -f <package_name> -l your_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <process_name_or_pid> -l your_script.js
   ```
4. **观察输出:**  当目标应用执行到 `__fbufsize` 函数时，Frida 会拦截该调用，并打印出 `onEnter` 和 `onLeave` 中定义的日志信息，包括 `FILE` 指针和返回值（缓冲区大小）。
5. **分析结果:**  通过观察 Frida 的输出，你可以了解 `__fbufsize` 函数在应用中的调用情况，例如在哪些文件流上调用，以及返回的缓冲区大小是多少。

**更复杂的 Hook 示例 (例如 Hook `fgets` 并查看 `__fbufsize` 的影响):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const libcModule = Process.getModuleByName("libc.so");
    const fgetsAddress = libcModule.findExportByName("fgets");
    const fbufsizeAddress = libcModule.findExportByName("__fbufsize");

    if (fgetsAddress && fbufsizeAddress) {
        console.log("Found fgets and __fbufsize. Attaching...");

        Interceptor.attach(fgetsAddress, {
            onEnter: function (args) {
                this.fp = ptr(args[2]);
                console.log("[fgets] Called with fp:", this.fp);
            },
            onLeave: function (retval) {
                if (retval.isNull()) {
                    console.log("[fgets] Returned NULL (EOF or error)");
                } else {
                    const bufferSize = Memory.readUSize(fbufsizeAddress, [this.fp]);
                    console.log("[fgets] Read line:", Memory.readUtf8String(retval));
                    console.log("[fgets] __fbufsize for this fp:", bufferSize);
                }
            }
        });
    } else {
        console.error("Could not find fgets or __fbufsize exports.");
    }
} else {
    console.warn("This script is designed for ARM/ARM64 architectures.");
}
```

这个例子会 Hook `fgets` 函数，并在 `fgets` 执行后，调用 `__fbufsize` 来查看当前文件流的缓冲区大小。这可以帮助你理解缓冲区大小与实际读取操作之间的关系。

希望以上详细的分析能够帮助你理解 `bionic/tests/stdio_ext_test.cpp` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/stdio_ext_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <stdio_ext.h>

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
#include <locale.h>

#include <android-base/file.h>

#include "utils.h"

TEST(stdio_ext, __fbufsize) {
  FILE* fp = fopen("/proc/version", "r");

  // Initially, there's no buffer in case the first thing you do is disable buffering.
  ASSERT_EQ(0U, __fbufsize(fp));

  // A read forces a buffer to be created.
  char buf[128];
  fgets(buf, sizeof(buf), fp);
  ASSERT_EQ(1024U, __fbufsize(fp));

  ASSERT_EQ(0, setvbuf(fp, buf, _IOFBF, 1));
  ASSERT_EQ(1U, __fbufsize(fp));

  ASSERT_EQ(0, setvbuf(fp, buf, _IOFBF, 8));
  ASSERT_EQ(8U, __fbufsize(fp));

  fclose(fp);
}

TEST(stdio_ext, __flbf) {
  FILE* fp = fopen("/proc/version", "r");

  ASSERT_FALSE(__flbf(fp));

  char buf[128];
  ASSERT_EQ(0, setvbuf(fp, buf, _IOLBF, sizeof(buf)));

  ASSERT_TRUE(__flbf(fp));

  fclose(fp);
}

TEST(stdio_ext, __fpending) {
  FILE* fp = fopen("/dev/null", "w");
  ASSERT_EQ(0U, __fpending(fp));
  ASSERT_EQ('x', fputc('x', fp));
  ASSERT_EQ(1U, __fpending(fp));
  ASSERT_EQ('y', fputc('y', fp));
  ASSERT_EQ(2U, __fpending(fp));
  fflush(fp);
  ASSERT_EQ(0U, __fpending(fp));
  fclose(fp);
}

TEST(stdio_ext, __freadahead) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc doesn't have __freadahead";
#else
  FILE* fp = tmpfile();
  ASSERT_NE(EOF, fputs("hello", fp));
  rewind(fp);

  ASSERT_EQ('h', fgetc(fp));
  ASSERT_EQ(4u, __freadahead(fp));

  ASSERT_EQ('H', ungetc('H', fp));
  ASSERT_EQ(5u, __freadahead(fp));

  fclose(fp);
#endif
}

TEST(stdio_ext, __fpurge) {
  FILE* fp = tmpfile();

  ASSERT_EQ('a', fputc('a', fp));
  ASSERT_EQ(1U, __fpending(fp));
  __fpurge(fp);
  ASSERT_EQ(0U, __fpending(fp));

  ASSERT_EQ('b', fputc('b', fp));
  ASSERT_EQ('\n', fputc('\n', fp));
  ASSERT_EQ(2U, __fpending(fp));

  rewind(fp);

  char buf[16];
  char* s = fgets(buf, sizeof(buf), fp);
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("b\n", s);

  fclose(fp);
}

TEST(stdio_ext, _flushlbf) {
  FILE* fp = fopen("/dev/null", "w");

  char buf[128];
  ASSERT_EQ(0, setvbuf(fp, buf, _IOLBF, sizeof(buf)));

  ASSERT_EQ('a', fputc('a', fp));
  ASSERT_EQ(1U, __fpending(fp));

  _flushlbf();

  ASSERT_EQ(0U, __fpending(fp));

  fclose(fp);
}

TEST(stdio_ext, __freadable__fwritable) {
  FILE* fp;

  // Read-only.
  fp = fopen("/dev/null", "r");
  ASSERT_TRUE(__freadable(fp));
  ASSERT_FALSE(__fwritable(fp));
  fclose(fp);

  // Write-only.
  fp = fopen("/dev/null", "w");
  ASSERT_FALSE(__freadable(fp));
  ASSERT_TRUE(__fwritable(fp));
  fclose(fp);

  // Append (aka write-only).
  fp = fopen("/dev/null", "a");
  ASSERT_FALSE(__freadable(fp));
  ASSERT_TRUE(__fwritable(fp));
  fclose(fp);

  // The three read-write modes.
  for (auto read_write_mode : {"r+", "w+", "a+"}) {
    fp = fopen("/dev/null", read_write_mode);
    ASSERT_TRUE(__freadable(fp));
    ASSERT_TRUE(__fwritable(fp));
    fclose(fp);
  }
}

TEST(stdio_ext, __freading__fwriting) {
  FILE* fp;

  // Append (aka write-only). Never reading. Always writing.
  fp = fopen("/dev/zero", "a");
  ASSERT_FALSE(__freading(fp)); // Not reading initially.
  ASSERT_TRUE(__fwriting(fp)); // Writing initially.
  ASSERT_TRUE(fputc('x', fp) != EOF);
  ASSERT_FALSE(__freading(fp)); // Not reading after write.
  ASSERT_TRUE(__fwriting(fp)); // Still writing after write.
  fclose(fp);

  // Write-only. Never reading. Always writing.
  fp = fopen("/dev/zero", "w");
  ASSERT_FALSE(__freading(fp)); // Not reading initially.
  ASSERT_TRUE(__fwriting(fp)); // Writing initially.
  ASSERT_TRUE(fputc('x', fp) != EOF);
  ASSERT_FALSE(__freading(fp)); // Not reading after write.
  ASSERT_TRUE(__fwriting(fp)); // Still writing after write.
  fclose(fp);

  // Read-only. Always reading. Never writing.
  fp = fopen("/dev/zero", "r");
  ASSERT_TRUE(__freading(fp)); // Reading initially.
  ASSERT_FALSE(__fwriting(fp)); // Not writing initially.
  ASSERT_TRUE(fgetc(fp) == 0);
  ASSERT_TRUE(__freading(fp)); // Still reading after read.
  ASSERT_FALSE(__fwriting(fp)); // Still not writing after read.
  fclose(fp);

  // The three read-write modes.
  for (auto read_write_mode : {"r+", "w+", "a+"}) {
    fp = fopen("/dev/zero", read_write_mode);
    ASSERT_FALSE(__freading(fp)); // Not reading initially.
    ASSERT_FALSE(__fwriting(fp)); // Not writing initially.
    ASSERT_TRUE(fgetc(fp) == 0);
    ASSERT_TRUE(__freading(fp)); // Reading after read.
    ASSERT_FALSE(__fwriting(fp)); // Not writing after read.
    ASSERT_TRUE(fputc('x', fp) != EOF);
    ASSERT_FALSE(__freading(fp)); // Not reading after write.
    ASSERT_TRUE(__fwriting(fp)); // Writing after write.
    fclose(fp);
  }
}

TEST(stdio_ext, __fseterr) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc doesn't have __fseterr, but gnulib will use it";
#else
  FILE* fp = fopen("/dev/null", "w");

  ASSERT_FALSE(ferror(fp));
  __fseterr(fp);
  ASSERT_TRUE(ferror(fp));
  clearerr(fp);
  ASSERT_FALSE(ferror(fp));

  fclose(fp);
#endif
}

TEST(stdio_ext, __fsetlocking) {
  FILE* fp = fopen("/proc/version", "r");
  ASSERT_EQ(FSETLOCKING_INTERNAL, __fsetlocking(fp, FSETLOCKING_QUERY));
  ASSERT_EQ(FSETLOCKING_INTERNAL, __fsetlocking(fp, FSETLOCKING_BYCALLER));
  ASSERT_EQ(FSETLOCKING_BYCALLER, __fsetlocking(fp, FSETLOCKING_QUERY));
  ASSERT_EQ(FSETLOCKING_BYCALLER, __fsetlocking(fp, FSETLOCKING_INTERNAL));
  ASSERT_EQ(FSETLOCKING_INTERNAL, __fsetlocking(fp, FSETLOCKING_QUERY));
  fclose(fp);
}

static void LockingByCallerHelper(std::atomic<pid_t>* pid) {
  *pid = gettid();
  flockfile(stdout);
  funlockfile(stdout);
}

TEST(stdio_ext, __fsetlocking_BYCALLER) {
  // Check if users can use flockfile/funlockfile to protect stdio operations.
  int old_state = __fsetlocking(stdout, FSETLOCKING_BYCALLER);
  flockfile(stdout);
  pthread_t thread;
  std::atomic<pid_t> pid(0);
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
                              reinterpret_cast<void* (*)(void*)>(LockingByCallerHelper), &pid));
  WaitUntilThreadSleep(pid);
  funlockfile(stdout);

  ASSERT_EQ(0, pthread_join(thread, nullptr));
  __fsetlocking(stdout, old_state);
}

"""

```