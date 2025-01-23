Response:
Let's break down the thought process for analyzing this `fnmatch_test.cpp` file.

**1. Understanding the Core Request:**

The fundamental goal is to understand the functionality of the `fnmatch_test.cpp` file within the context of Android's Bionic library. This involves identifying its purpose, how it relates to Android, and details about the underlying libc function it tests (`fnmatch`). The request also touches on dynamic linking, usage errors, and how this code is reached from higher levels of Android.

**2. Initial Analysis of the Code:**

* **Headers:** The file includes `<gtest/gtest.h>` and `<fnmatch.h>`. This immediately tells us it's a test file using Google Test and specifically testing the `fnmatch` function.
* **Test Structure:** The code is organized into `TEST` macros, each with a name (e.g., `basic`, `casefold`). This structure is standard for Google Test.
* **`EXPECT_EQ`:**  The core of each test case uses `EXPECT_EQ` to compare the result of `fnmatch` with an expected value (0 for match, `FNM_NOMATCH` for no match).
* **Test Cases:**  A quick scan reveals different categories of tests: basic matching, case-insensitive matching, character classes, wildcards (`*` and `?`), and the `FNM_LEADING_DIR` flag.

**3. Identifying the Functionality:**

Based on the test cases, the primary functionality of this file is to test the `fnmatch` function. The tests cover various aspects of pattern matching:

* **Exact matching:**  Testing if simple strings match.
* **Case-insensitive matching:** Using the `FNM_CASEFOLD` flag.
* **Character classes:** Testing square brackets `[]` for literal sets, negated sets (`[^...]`), ranges (`[a-z]`), and named character classes (`[:digit:]`).
* **Wildcards:** Testing `*` (matches zero or more characters) and `?` (matches any single character).
* **`FNM_PATHNAME`:** Testing the behavior of wildcards when path separators (`/`) are present.
* **`FNM_LEADING_DIR`:** Testing if a pattern matches the initial portion of a path.

**4. Connecting to Android:**

Since this file is located in `bionic/tests`, it's clearly part of Android's foundational C library. The `fnmatch` function itself is a standard POSIX function that's provided by the C library. Its relevance to Android lies in its use for:

* **File system operations:** Many Android components need to match file names or paths based on patterns (e.g., finding files of a specific type).
* **Shell scripting:**  The shell uses pattern matching extensively.
* **Security policies:**  Access control rules might involve pattern matching on file paths or other resources.
* **Package management:**  Matching package names or components.

**5. Explaining `fnmatch` Implementation (Conceptual):**

While the actual implementation of `fnmatch` in Bionic is complex C code, we can explain the core logic conceptually:

* **Input:** Takes a `pattern` string and a `string` to match against, plus flags.
* **Traversal:**  Iterates through both the `pattern` and the `string` simultaneously.
* **Character Matching:**  Compares characters directly.
* **Wildcard Handling:**
    * `*`:  Can match zero or more characters. This often involves backtracking or recursion to explore different matching possibilities.
    * `?`: Matches any single character.
* **Character Class Handling:**
    * `[...]`:  Checks if the current character in the `string` is within the specified set (literal, range, or named class). Handles negation (`^`).
* **Flag Handling:**  Implements the specific behavior dictated by flags like `FNM_CASEFOLD`, `FNM_PATHNAME`, and `FNM_LEADING_DIR`.

**6. Dynamic Linker Aspects (Limited in this file):**

This specific test file doesn't directly *use* the dynamic linker. However, the `fnmatch` function itself resides within libc.so, which is loaded by the dynamic linker.

* **SO Layout (Hypothetical):**
    ```
    libc.so:
        .text:  // Code section
            fnmatch:  // Implementation of fnmatch
            ... other libc functions ...
        .data:  // Initialized data
            ...
        .bss:   // Uninitialized data
            ...
        .dynsym: // Dynamic symbol table (contains fnmatch)
            fnmatch
            ...
        .dynstr: // Dynamic string table
            "fnmatch"
            ...
    ```
* **Linking Process:** When a program (or another shared library) calls `fnmatch`, the dynamic linker ensures that `libc.so` is loaded into memory and the call to `fnmatch` is resolved to the correct address within `libc.so`.

**7. Common Usage Errors:**

* **Incorrect quoting:** Forgetting to escape special characters in shell commands when using pattern matching.
* **Misunderstanding wildcards:** Confusing the behavior of `*` and `?`.
* **Case sensitivity issues:**  Not being aware of case sensitivity (or using `FNM_CASEFOLD` when needed).
* **Pathname issues:**  Not considering the impact of `FNM_PATHNAME` when matching paths.

**8. Android Framework/NDK Interaction:**

The journey to `fnmatch` can start from various points:

* **Android Framework (Java/Kotlin):**  A high-level framework component might need to interact with the file system. It could use Java APIs like `File.listFiles(FilenameFilter)` which, internally, might delegate to native code using `fnmatch`-like functionality (though not necessarily directly calling the libc `fnmatch`).
* **NDK (C/C++):**  An NDK application could directly call `fnmatch` after including `<fnmatch.h>`.

**9. Frida Hook Example:**

The Frida script demonstrates how to intercept calls to `fnmatch`:

```javascript
if (Process.platform === 'android') {
  const fnmatchPtr = Module.findExportByName('libc.so', 'fnmatch');
  if (fnmatchPtr) {
    Interceptor.attach(fnmatchPtr, {
      onEnter: function (args) {
        const pattern = Memory.readUtf8String(args[0]);
        const string = Memory.readUtf8String(args[1]);
        const flags = args[2].toInt();
        console.log(`fnmatch called with pattern: "${pattern}", string: "${string}", flags: ${flags}`);
      },
      onLeave: function (retval) {
        console.log(`fnmatch returned: ${retval}`);
      }
    });
  } else {
    console.log('Could not find fnmatch in libc.so');
  }
} else {
  console.log('This script is for Android only.');
}
```

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Maybe the test file directly uses dynamic linking APIs. **Correction:**  While the *tested function* is part of a dynamically linked library, the test itself primarily focuses on the *functionality* of `fnmatch`, not the dynamic linking process. The dynamic linking aspect is more about the context in which `fnmatch` operates.
* **Initial thought:**  Deeply dive into the assembly of `fnmatch`. **Correction:**  The request asks for an *explanation* of the functionality. A high-level conceptual understanding of how `fnmatch` works is sufficient, unless the request specifically asks for implementation details.
* **Considering the scope:** The request mentions "Android framework or NDK". It's important to provide examples from both levels, showing how `fnmatch` or related concepts might be used. The Frida example helps bridge this gap by allowing observation at the native level.

By following these steps and iteratively refining the analysis, we arrive at a comprehensive understanding of the `fnmatch_test.cpp` file and its place within the Android ecosystem.好的，让我们来详细分析一下 `bionic/tests/fnmatch_test.cpp` 这个文件。

**文件功能:**

`bionic/tests/fnmatch_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试 `fnmatch` 函数的实现是否正确。`fnmatch` 函数是一个标准的 POSIX C 库函数，用于匹配文件名模式。该测试文件使用 Google Test 框架编写了一系列测试用例，涵盖了 `fnmatch` 函数的各种匹配规则和标志位。

**与 Android 功能的关系及举例说明:**

`fnmatch` 函数在 Android 中被广泛使用，特别是在涉及到文件路径匹配的场景中。一些常见的应用场景包括：

* **Shell 命令:** Android 的 shell (如 `bash`) 在进行文件名匹配时会使用 `fnmatch` 或类似的机制。例如，`ls *.txt` 命令会列出当前目录下所有以 `.txt` 结尾的文件，这个 `*.txt` 的匹配就是通过类似 `fnmatch` 的功能实现的。
* **软件包管理器 (Package Manager):** Android 的软件包管理器在查找、安装和卸载应用时，可能需要根据特定的模式匹配 APK 文件或其他相关文件。
* **文件查找工具:**  用户或系统工具可能需要根据模式查找特定的文件，例如查找所有包含特定关键字的日志文件。
* **权限管理:**  在某些情况下，权限配置可能涉及到基于文件名模式的匹配。

**举例说明:**

假设你有一个 Android 设备，并且你使用 ADB shell 连接到该设备。

1. **Shell 命令:** 你可以使用 `ls *.png` 命令来列出当前目录下所有以 `.png` 结尾的图片文件。 这个操作背后就可能涉及到对 `fnmatch` 函数的调用，以判断文件名是否匹配 `*.png` 模式。

2. **软件包管理器:** 当你安装一个 APK 文件时，系统可能需要验证 APK 文件的签名。这个过程中，可能会使用模式匹配来查找签名文件或验证相关的文件路径。

**libc 函数 `fnmatch` 的功能及实现原理:**

`fnmatch` 函数用于判断一个字符串是否匹配给定的模式。其函数原型如下：

```c
#include <fnmatch.h>

int fnmatch(const char *pattern, const char *string, int flags);
```

* **`pattern`:**  指向用于匹配的模式字符串。模式字符串可以包含特殊字符，如 `*`, `?`, `[]` 等。
* **`string`:** 指向需要匹配的字符串。
* **`flags`:**  用于指定匹配行为的标志位，可以是以下值的按位或：
    * `FNM_CASEFOLD`: 忽略大小写进行匹配。
    * `FNM_NOESCAPE`:  反斜杠 `\` 被视为普通字符，而不是转义字符。
    * `FNM_PATHNAME`: 斜杠 `/` 必须显式匹配，通配符 `*` 和 `?` 不会匹配斜杠。
    * `FNM_PERIOD`:  字符串的第一个字符如果是句点 `.`，则模式的第一个字符也必须是句点才能匹配。
    * `FNM_LEADING_DIR`: 如果字符串是目录名的前缀，则匹配成功。

**实现原理 (简化描述):**

`fnmatch` 函数的实现通常基于状态机或者递归算法。它会逐个比较模式字符串和目标字符串的字符，并根据模式中的特殊字符进行相应的处理。

* **普通字符:** 如果模式中的字符不是特殊字符，则必须与目标字符串中的对应字符完全匹配。
* **`?` (问号):** 匹配目标字符串中的任意单个字符。
* **`*` (星号):** 匹配目标字符串中的零个或多个字符。
* **`[...]` (字符类):** 匹配目标字符串中包含在方括号内的任意单个字符。可以包含：
    * **字面字符:** 例如 `[abc]` 匹配 `a`、`b` 或 `c`。
    * **范围:** 例如 `[a-z]` 匹配 `a` 到 `z` 之间的任意小写字母。
    * **取反:** 例如 `[^abc]` 匹配除了 `a`、`b` 和 `c` 之外的任意字符。
    * **具名字符类:** 例如 `[[:digit:]]` 匹配任意数字。
* **`\` (反斜杠):**  通常用于转义下一个字符，使其失去特殊含义 (除非设置了 `FNM_NOESCAPE` 标志)。

**逻辑推理的假设输入与输出:**

基于 `fnmatch_test.cpp` 中的测试用例，我们可以进行一些逻辑推理：

* **假设输入:** `pattern = "abc"`, `string = "abc"`, `flags = 0`
* **预期输出:** `0` (匹配成功)

* **假设输入:** `pattern = "ab*d"`, `string = "abxyzcd"`, `flags = 0`
* **预期输出:** `0` (匹配成功，`*` 匹配 "xyzc")

* **假设输入:** `pattern = "a[0-9]b"`, `string = "a5b"`, `flags = 0`
* **预期输出:** `0` (匹配成功，`[0-9]` 匹配数字 5)

* **假设输入:** `pattern = "a[0-9]b"`, `string = "acb"`, `flags = 0`
* **预期输出:** `FNM_NOMATCH` (匹配失败，`c` 不在 `0-9` 的范围内)

* **假设输入:** `pattern = "ab*", `string = "ab/cd"`, `flags = FNM_PATHNAME`
* **预期输出:** `FNM_NOMATCH` (匹配失败，`*` 不匹配斜杠 `/`，因为设置了 `FNM_PATHNAME`)

**涉及 dynamic linker 的功能 (无直接涉及，但 `fnmatch` 位于 `libc.so`):**

这个测试文件本身并没有直接测试 dynamic linker 的功能。然而，`fnmatch` 函数是 `libc` 库的一部分，而 `libc.so` 是一个共享库，它的加载和链接是由 dynamic linker 负责的。

**SO 布局样本 (libc.so 的简化示意):**

```
libc.so:
    .text:  // 包含可执行代码
        fnmatch:  // fnmatch 函数的代码
        ... 其他 libc 函数的代码 ...
    .data:  // 包含已初始化的全局变量
        ...
    .bss:   // 包含未初始化的全局变量
        ...
    .dynsym: // 动态符号表，包含导出的符号 (如 fnmatch)
        fnmatch
        ...
    .dynstr: // 动态字符串表，包含符号名称等字符串
        "fnmatch"
        ...
    .plt:   // Procedure Linkage Table，用于延迟绑定
        ...
    .got:   // Global Offset Table，用于存放全局变量的地址
        ...
```

**链接的处理过程:**

1. **编译链接:** 当程序或共享库需要使用 `fnmatch` 函数时，编译器会将对 `fnmatch` 的调用标记为需要动态链接。
2. **加载时链接:** 当程序启动或共享库被加载时，dynamic linker (通常是 `linker` 或 `ld-linux.so`) 会执行以下操作：
    * **加载依赖:** 加载所有需要的共享库，包括 `libc.so`。
    * **符号解析:**  查找被调用的外部符号 (如 `fnmatch`) 在其依赖库中的地址。Dynamic linker 会在 `libc.so` 的 `.dynsym` 表中查找 `fnmatch` 符号。
    * **重定位:** 更新程序或共享库中的代码和数据，将对外部符号的引用指向其在共享库中的实际地址。对于 `fnmatch` 的调用，会更新到 `libc.so` 中 `fnmatch` 函数的入口地址。
    * **延迟绑定 (如果使用 PLT/GOT):** 为了优化启动时间，链接器通常使用延迟绑定。最初，对 `fnmatch` 的调用会跳转到 PLT 中的一个条目。第一次调用 `fnmatch` 时，PLT 条目会触发 dynamic linker 解析符号并更新 GOT 表，使其指向 `fnmatch` 的实际地址。后续的调用将直接通过 GOT 表跳转到 `fnmatch` 的代码。

**用户或编程常见的使用错误:**

1. **通配符理解错误:**  不清楚 `*` 和 `?` 的区别，或者不理解字符类的用法。
    ```c++
    // 错误地认为 '?' 可以匹配多个字符
    fnmatch("a?", "abc", 0); // 返回 FNM_NOMATCH
    ```

2. **忽略大小写问题:** 在需要忽略大小写的情况下忘记使用 `FNM_CASEFOLD` 标志。
    ```c++
    fnmatch("ABC", "abc", 0); // 返回 FNM_NOMATCH
    fnmatch("ABC", "abc", FNM_CASEFOLD); // 返回 0
    ```

3. **路径名匹配问题:**  在匹配路径时没有考虑 `FNM_PATHNAME` 标志，导致通配符错误地匹配了斜杠。
    ```c++
    fnmatch("dir*", "dir/file", 0); // 返回 0 (可能不是期望的行为)
    fnmatch("dir*", "dir/file", FNM_PATHNAME); // 返回 FNM_NOMATCH (更符合路径匹配的预期)
    ```

4. **转义字符问题:**  没有正确处理需要字面匹配的特殊字符。
    ```c++
    // 想要匹配 "a*b"，但 * 被解释为通配符
    fnmatch("a*b", "axb", 0); // 返回 0
    // 正确的做法是转义 *
    fnmatch("a\\*b", "a*b", 0); // 返回 0 (假设 FNM_NOESCAPE 未设置)
    ```

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 到 `fnmatch` 的路径 (示例):**

1. **Java Framework:**  Android Framework 中的一个 Java 类，例如 `java.io.File` 或 `android.content.IntentFilter`，可能需要进行文件路径或字符串模式匹配。
2. **JNI 调用:**  Java 代码会通过 JNI (Java Native Interface) 调用 Native 代码。
3. **Native 代码:**  底层的 Native 代码 (C/C++) 中可能会使用 POSIX API，包括 `fnmatch` 函数。例如，一个处理文件系统操作的 Native 组件。

**NDK 到 `fnmatch` 的路径:**

1. **NDK 应用:**  一个使用 NDK 开发的 Android 应用，其 C/C++ 代码可以直接调用 `fnmatch` 函数，只需要包含 `<fnmatch.h>` 头文件。

**Frida Hook 示例:**

以下是一个使用 Frida hook `fnmatch` 函数的示例，用于观察其调用情况：

```javascript
if (Process.platform === 'android') {
  const fnmatchPtr = Module.findExportByName('libc.so', 'fnmatch');
  if (fnmatchPtr) {
    Interceptor.attach(fnmatchPtr, {
      onEnter: function (args) {
        const pattern = Memory.readUtf8String(args[0]);
        const string = Memory.readUtf8String(args[1]);
        const flags = args[2].toInt();
        console.log(`fnmatch called with pattern: "${pattern}", string: "${string}", flags: ${flags}`);
      },
      onLeave: function (retval) {
        console.log(`fnmatch returned: ${retval}`);
      }
    });
    console.log('fnmatch hooked!');
  } else {
    console.log('Could not find fnmatch in libc.so');
  }
} else {
  console.log('This script is for Android only.');
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存到一个文件中，例如 `hook_fnmatch.js`。
2. 确保你的 Android 设备已 root，并且安装了 Frida。
3. 确定你想要 hook 的进程的包名或进程 ID。
4. 使用 Frida 命令运行 hook 脚本：
   ```bash
   frida -U -f <包名> -l hook_fnmatch.js --no-pause
   # 或者
   frida -U <进程ID> -l hook_fnmatch.js --no-pause
   ```
   将 `<包名>` 替换为你想要监控的应用程序的包名，或者将 `<进程ID>` 替换为进程 ID。

**调试步骤:**

1. 运行 Frida hook 脚本后，当目标应用程序调用 `fnmatch` 函数时，Frida 会拦截调用。
2. `onEnter` 函数会被执行，打印出 `fnmatch` 函数的参数：`pattern`，`string` 和 `flags`。
3. `onLeave` 函数会在 `fnmatch` 函数执行完毕后被执行，打印出返回值。
4. 通过观察 Frida 的输出，你可以了解哪些组件在调用 `fnmatch`，使用了什么样的模式和标志位，以及匹配的结果。

通过这种方式，你可以追踪 Android Framework 或 NDK 应用中对 `fnmatch` 函数的调用，从而理解其在系统中的具体应用场景和调用路径。

希望这个详细的分析能够帮助你理解 `bionic/tests/fnmatch_test.cpp` 文件以及 `fnmatch` 函数在 Android 中的作用。

### 提示词
```
这是目录为bionic/tests/fnmatch_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <gtest/gtest.h>

#include <fnmatch.h>

TEST(fnmatch, basic) {
  EXPECT_EQ(0, fnmatch("abc", "abc", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("abc", "abd", 0));
}

TEST(fnmatch, casefold) {
  EXPECT_EQ(FNM_NOMATCH, fnmatch("abc", "aBc", 0));
  EXPECT_EQ(0, fnmatch("abc", "aBc", FNM_CASEFOLD));
}

TEST(fnmatch, character_class) {
  // Literal.
  EXPECT_EQ(0, fnmatch("ab[cd]", "abc", 0));
  EXPECT_EQ(0, fnmatch("ab[cd]", "abd", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab[cd]", "abe", 0));

  // Inverted literal.
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab[^cd]", "abc", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab[^cd]", "abd", 0));
  EXPECT_EQ(0, fnmatch("ab[^cd]", "abe", 0));

  // Range.
  EXPECT_EQ(0, fnmatch("a[0-9]b", "a0b", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("a[0-9]b", "aOb", 0));

  // Inverted range.
  EXPECT_EQ(0, fnmatch("a[^0-9]b", "aOb", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("a[^0-9]b", "a0b", 0));

  // Named.
  EXPECT_EQ(0, fnmatch("a[[:digit:]]b", "a0b", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("a[[:digit:]]b", "aOb", 0));

  // Inverted named.
  EXPECT_EQ(FNM_NOMATCH, fnmatch("a[^[:digit:]]b", "a0b", 0));
  EXPECT_EQ(0, fnmatch("a[^[:digit:]]b", "aOb", 0));
}

TEST(fnmatch, wild_any) {
  EXPECT_EQ(0, fnmatch("ab*", "ab", 0));
  EXPECT_EQ(0, fnmatch("ab*", "abc", 0));
  EXPECT_EQ(0, fnmatch("ab*", "abcd", 0));
  EXPECT_EQ(0, fnmatch("ab*", "ab/cd", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab*", "ab/cd", FNM_PATHNAME));
}

TEST(fnmatch, wild_one) {
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?", "ab", 0));
  EXPECT_EQ(0, fnmatch("ab?", "abc", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?", "abcd", 0));
  EXPECT_EQ(0, fnmatch("ab?d", "abcd", 0));
  EXPECT_EQ(0, fnmatch("ab?cd", "ab/cd", 0));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?cd", "ab/cd", FNM_PATHNAME));
}

TEST(fnmatch, leading_dir) {
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab", "abcd", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab*", "abcd", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("*ab*", "1/2/3/4/abcd", FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("*ab*", "1/2/3/4/abcd", FNM_PATHNAME | FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?", "abcd", FNM_LEADING_DIR));

  EXPECT_EQ(0, fnmatch("ab", "ab/cd", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab", "ab/cd", FNM_PATHNAME | FNM_LEADING_DIR));
  // TODO(b/175302045) fix this case and enable this test.
  // EXPECT_EQ(0, fnmatch("*ab", "1/2/3/4/ab/cd", FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("*ab", "1/2/3/4/ab/cd", FNM_PATHNAME | FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab*", "ab/cd/ef", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab*", "ab/cd/ef", FNM_PATHNAME | FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("*ab*", "1/2/3/4/ab/cd/ef", FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("*ab*", "1/2/3/4/ab/cd/ef", FNM_PATHNAME | FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?", "ab/cd/ef", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab?", "abx/cd/ef", FNM_LEADING_DIR));

  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab/", "ab/cd/ef", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab/*", "ab/cd/ef", FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab/?", "ab/cd/ef", FNM_LEADING_DIR));

  // TODO(b/175302045) fix this case and enable this test.
  // EXPECT_EQ(0, fnmatch("ab*c", "ab/1/2/3/c/d/e", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab?c", "ab/c/ef", FNM_LEADING_DIR));

  EXPECT_EQ(0, fnmatch("ab*c*", "ab/1/2/3/c/d/e", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab?c*", "ab/c/ef", FNM_LEADING_DIR));

  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab*c/", "ab/1/2/3/c/d/e", FNM_LEADING_DIR));
  EXPECT_EQ(FNM_NOMATCH, fnmatch("ab?c/", "ab/c/ef", FNM_LEADING_DIR));

  EXPECT_EQ(0, fnmatch("ab*c/*", "ab/1/2/3/c/d/e", FNM_LEADING_DIR));
  EXPECT_EQ(0, fnmatch("ab?c/*", "ab/c/ef", FNM_LEADING_DIR));
}
```