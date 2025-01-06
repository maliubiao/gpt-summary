Response:
Let's break down the thought process for answering the user's request. The request is quite comprehensive and requires understanding of C, Android Bionic, and some system-level concepts.

**1. Understanding the Core Request:**

The user wants to understand the `libgen_test.cpp` file within Android's Bionic library. They specifically want to know:

* **Functionality:** What does this test file do? What functions does it test?
* **Android Relevance:** How does this relate to overall Android functionality?  Provide examples.
* **Detailed Implementation:** Explain how the tested functions work.
* **Dynamic Linker Integration:**  If the code touches dynamic linking, explain it with examples and layouts.
* **Logic and I/O:**  Explain the test logic with assumed inputs and outputs.
* **Common Errors:** What mistakes do users/programmers make when using these functions?
* **Android Path:** How does code execution reach these functions from the framework or NDK?
* **Frida Hooking:**  Provide examples for debugging with Frida.

**2. Initial Analysis of the Source Code:**

* **Includes:** The file includes `libgen.h`, `errno.h`, and `gtest/gtest.h`. This immediately tells us it's a unit test for functions defined in `libgen.h`, and it uses the Google Test framework. `errno.h` suggests error handling is being tested.
* **Test Functions:**  The code defines several `TEST` blocks within the `libgen` test suite. The names of the tests are `dirname`, `basename_r`, and `dirname_r`. This directly reveals the functions being tested.
* **Helper Functions:** There are helper functions like `TestDirname` (overloaded) and `TestBasename`. These functions simplify the test setup and assertions. They take input strings and expected output strings (and potentially buffer information for `_r` variants).
* **Assertions:** The `ASSERT_STREQ` and `ASSERT_EQ` macros are used for verifying the correctness of the function outputs and error codes.
* **Conditional Compilation:** The `#if defined(__BIONIC__) && !defined(__LP64__)` block is significant. It indicates that `basename_r` and `dirname_r` (the reentrant versions) are only tested on 32-bit Bionic.

**3. Addressing Each Part of the User's Request:**

* **Functionality:**  The file tests the `dirname` function (standard libc) and the reentrant versions `basename_r` and `dirname_r` (specific to Bionic for 32-bit). The purpose of these functions is to manipulate pathnames.

* **Android Relevance:**  Think about where path manipulation is crucial in Android. Examples:
    * **File System Access:**  Any time an app or system service interacts with files, it uses paths.
    * **APK Handling:** The package manager needs to extract directory and file names from APK paths.
    * **Native Libraries:** Loading native libraries (`.so` files) involves path manipulation.
    * **Command Line Tools (ADB Shell):** Many shell commands work with paths.

* **Detailed Implementation (libc functions):**
    * **`dirname`:**  The core logic is to find the last '/' in the path. If found, truncate the string there. Handle edge cases (no '/', '/', empty string, NULL). *Self-correction:  Realized the original `dirname` can modify the input string, which is why the test uses `strdup`.*
    * **`basename`:** Similar to `dirname`, but returns the part *after* the last '/'. Handle similar edge cases.
    * **`basename_r` and `dirname_r`:** These are thread-safe versions. They require a buffer to store the result, preventing modification of the input string and race conditions. The return code indicates success or failure (and potentially the required buffer size if it failed due to insufficient space).

* **Dynamic Linker (dlopen, etc.):**  While `libgen` functions *can* be used in the context of dynamic linking (e.g., to extract the directory of a loaded `.so`), the *test file itself* doesn't directly test dynamic linker functionality. Therefore, focus on how `dirname` and `basename` *could be used* in the dynamic linker's implementation. Provide a conceptual `.so` layout. Explain the linker's search process and how it might use path manipulation.

* **Logic and I/O:** Go through each `TestDirname` and `TestBasename` call. For each, state the input and the expected output. This demonstrates the test cases and the expected behavior.

* **Common Errors:** Brainstorm typical mistakes developers make when using these functions:
    * **Forgetting to `free` the result of `strdup` (when used with `dirname`).**
    * **Buffer overflows with `basename_r` and `dirname_r` (not providing a large enough buffer).**
    * **Misunderstanding the behavior with empty strings or NULL input.**
    * **Assuming `dirname` doesn't modify its input in all implementations (it *does* in the provided Bionic test, hence the `strdup`).**

* **Android Path:**  Start high-level and work down:
    * **Framework/NDK:**  An app using Java code for file operations or an NDK app using C/C++ file APIs.
    * **System Calls:** These file operations eventually translate to system calls (like `open`, `stat`, etc.).
    * **Bionic:**  The C library functions (like `fopen`, which might internally use `dirname` or `basename` for path decomposition) are part of Bionic.
    * **`libgen.so` (or potentially linked directly into `libc.so`):** The implementation of `dirname` and `basename` resides here.

* **Frida Hooking:**  Provide concrete Frida examples. Hook the `dirname` function. Demonstrate how to intercept the input argument and the return value. Show how to modify the behavior (though caution against doing this in production).

**4. Structuring the Response:**

Organize the answer clearly, following the user's request structure. Use headings and bullet points to improve readability. Explain each concept thoroughly and provide code examples where relevant.

**5. Refinement and Review:**

After drafting the initial answer, review it for accuracy, completeness, and clarity. Ensure that the explanations are easy to understand, especially for someone who might not be deeply familiar with Bionic internals. Double-check the Frida code for correctness. Make sure all parts of the original request are addressed.

This step-by-step process, combined with a good understanding of the underlying technologies, allows for a comprehensive and accurate answer to the user's detailed question. The key is to break down the problem into smaller, manageable parts and address each one systematically.
好的，我们来详细分析一下 `bionic/tests/libgen_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/libgen_test.cpp` 是 Android Bionic 库中用于测试 `libgen.h` 头文件中声明的函数的单元测试文件。`libgen.h` 主要包含用于处理路径名的函数，例如提取目录名和基本文件名。

**与 Android 功能的关系及举例**

这些路径名处理函数在 Android 系统和应用程序的各个方面都有应用：

* **文件系统操作:**  Android 应用和系统服务经常需要操作文件和目录。`dirname` 和 `basename` 可以用于从完整路径中提取目录名或文件名。例如，当应用需要创建一个临时文件时，它可能需要先获取临时目录的路径，这时 `dirname` 就可能被用到。
* **动态库加载:** Android 系统在加载动态链接库 (`.so` 文件) 时，需要解析库文件的路径。虽然测试代码本身没有直接涉及动态链接器，但 `libgen` 中的函数可以被动态链接器内部使用，例如获取库文件所在的目录。
* **包管理:**  Android 的包管理器 (PackageManager) 在安装、卸载和管理应用时，需要处理 APK 文件的路径，也可能用到这些函数。
* **命令行工具:**  在 Android 的 adb shell 中使用的各种命令，例如 `ls`, `cd` 等，内部实现也会用到路径名处理函数。

**libc 函数的实现解释**

这个测试文件主要测试了 `dirname`、`basename_r` 和 `dirname_r` 这几个函数。

1. **`dirname(char *path)`:**

   * **功能:**  `dirname` 函数接收一个指向以 null 结尾的字符串的指针，该字符串表示一个路径名。它返回一个指向以 null 结尾的字符串的指针，该字符串是路径名的目录部分。如果路径名不包含斜杠 `/`，或者 `path` 指向空字符串或为 `NULL`，则返回 `.`。如果路径名以 `/` 结尾，则返回 `/`。
   * **实现原理 (基于测试代码推断):**
     * 测试代码首先使用 `strdup` 创建输入路径的副本，因为 `dirname` 函数在某些实现中可能会修改其输入字符串。
     * `dirname` 函数通常会从路径字符串的末尾开始查找最后一个斜杠 `/`。
     * 如果找到了斜杠，它会将该斜杠之后的所有字符替换为 null 终止符 `\0`，从而截断字符串，留下目录部分。
     * 如果没有找到斜杠，则返回 `"."`。
     * 特殊情况处理：
       * `NULL` 输入：返回 `"."`。
       * 空字符串 `""`：返回 `"."`。
       * 根目录 `/`：返回 `/`。
   * **潜在问题:**  由于某些 `dirname` 实现会修改输入字符串，因此在使用前需要确保输入字符串是可写的，或者复制一份。

2. **`basename_r(const char *path, char *buf, size_t size)`:**

   * **功能:**  `basename_r` 是 `basename` 函数的可重入版本。它接收一个指向路径名的指针 `path`，一个用于存储结果的缓冲区 `buf`，以及缓冲区的大小 `size`。它将路径名的基本文件名（最后一个斜杠之后的部分）复制到 `buf` 中。
   * **实现原理 (基于测试代码推断):**
     * 函数首先查找路径字符串中最后一个斜杠 `/` 的位置。
     * 如果找到斜杠，则将斜杠后的子字符串复制到 `buf` 中。
     * 如果没有找到斜杠，则将整个路径字符串复制到 `buf` 中。
     * 特殊情况处理：
       * 空字符串 `""`：复制 `"."` 到 `buf`。
       * `NULL` 输入：行为未定义或可能导致崩溃（测试代码没有覆盖 `path` 为 `NULL` 的情况，这可能是一个疏忽）。
       * 根目录 `/`：复制 `/` 到 `buf`。
       * 缓冲区大小不足：如果 `buf` 的大小 `size` 不足以容纳基本文件名（包括 null 终止符），函数会返回 `-1` 并设置 `errno` 为 `ERANGE`。测试代码对此进行了验证。
   * **返回值:**  成功时返回复制到 `buf` 的字符串的长度（不包括 null 终止符），失败时返回 `-1` 并设置 `errno`。

3. **`dirname_r(const char *path, char *buf, size_t size)`:**

   * **功能:**  `dirname_r` 是 `dirname` 函数的可重入版本。它接收参数与 `basename_r` 相同，并将路径名的目录部分复制到 `buf` 中。
   * **实现原理 (基于测试代码推断):**
     * 函数首先查找路径字符串中最后一个斜杠 `/` 的位置。
     * 如果找到斜杠：
       * 如果斜杠是字符串的第一个字符（即路径为 `/...`），则复制 `/` 到 `buf`。
       * 否则，将斜杠之前的所有字符复制到 `buf` 中，并在末尾添加 null 终止符。
     * 如果没有找到斜杠，则复制 `"."` 到 `buf`。
     * 特殊情况处理：
       * 空字符串 `""`：复制 `"."` 到 `buf`。
       * `NULL` 输入：行为未定义或可能导致崩溃（测试代码没有覆盖 `path` 为 `NULL` 的情况）。
       * 缓冲区大小不足：与 `basename_r` 类似，如果 `buf` 太小，返回 `-1` 并设置 `errno` 为 `ERANGE`。
   * **返回值:**  成功时返回复制到 `buf` 的字符串的长度，失败时返回 `-1` 并设置 `errno`。

**涉及 dynamic linker 的功能**

虽然 `libgen_test.cpp` 本身没有直接测试动态链接器的功能，但 `dirname` 和 `basename` 这类函数在动态链接器的实现中可能会被用到。

**so 布局样本**

假设我们有一个动态链接库 `libexample.so`，它位于 `/system/lib/`.

```
/
├── system
│   └── lib
│       └── libexample.so
└── data
    └── ...
```

**链接的处理过程**

当 Android 系统加载 `libexample.so` 时，动态链接器可能需要解析库文件的路径。例如，当应用程序调用 `System.loadLibrary("example")` 或使用 NDK 的 `dlopen("libexample.so", ...)` 时，会触发动态链接过程。

1. **查找库文件:** 动态链接器会在一系列预定义的路径中搜索 `libexample.so`。这些路径通常包括 `/system/lib`, `/vendor/lib`, 以及应用私有目录等。
2. **解析路径:**  如果 `dlopen` 传入的是相对路径 `"libexample.so"`，动态链接器需要将其转换为绝对路径。在这个过程中，可能需要获取当前进程的工作目录，或者基于某些规则构建完整的路径。
3. **加载和链接:** 一旦找到库文件，动态链接器会将其加载到内存中，并解析其依赖关系，进行符号重定位等操作。

在这个过程中，`dirname` 可能被用来提取 `libexample.so` 所在的目录 `/system/lib`，例如在查找依赖的库时，或者记录日志信息时。`basename` 可能被用来提取库文件的名称 `libexample.so` 本身。

**假设输入与输出 (逻辑推理)**

以下基于测试代码中的示例进行说明：

* **`dirname` 函数:**
    * **输入:** `/usr/lib`
    * **输出:** `/usr`
    * **输入:** `/usr/`
    * **输出:** `/`
    * **输入:** `usr`
    * **输出:** `.`
    * **输入:** `""`
    * **输出:** `.`
* **`basename_r` 函数:**
    * **输入:** `/usr/lib`, `buf` (大小足够)
    * **输出:** `lib` (复制到 `buf`)，返回值 `3`
    * **输入:** `/usr/`, `buf` (大小足够)
    * **输出:** `usr` (复制到 `buf`)，返回值 `3`
    * **输入:** `""`, `buf` (大小足够)
    * **输出:** `.` (复制到 `buf`)，返回值 `1`
    * **输入:** `"", buf` (大小为 1)
    * **输出:** (无确定内容，因为会出错)，返回值 `-1`，`errno` 设置为 `ERANGE`
* **`dirname_r` 函数:**
    * **输入:** `/usr/lib`, `buf` (大小足够)
    * **输出:** `/usr` (复制到 `buf`)，返回值 `4`
    * **输入:** `/usr/`, `buf` (大小足够)
    * **输出:** `/` (复制到 `buf`)，返回值 `1`
    * **输入:** `usr`, `buf` (大小足够)
    * **输出:** `.` (复制到 `buf`)，返回值 `1`
    * **输入:** `"", buf` (大小为 1)
    * **输出:** (无确定内容，因为会出错)，返回值 `-1`，`errno` 设置为 `ERANGE`

**用户或编程常见的使用错误**

1. **`dirname` 修改输入缓冲区:**  忘记 `dirname` 函数可能会修改其输入字符串。如果输入字符串是只读的（例如字符串字面量），则会导致程序崩溃。**示例:**

   ```c
   const char* path = "/path/to/file";
   char* dir = dirname(path); // 错误！path 指向只读内存
   printf("Directory: %s\n", dir);
   ```

   **正确做法:**

   ```c
   const char* path = "/path/to/file";
   char* path_copy = strdup(path);
   if (path_copy) {
       char* dir = dirname(path_copy);
       printf("Directory: %s\n", dir);
       free(path_copy);
   }
   ```

2. **`basename_r` 和 `dirname_r` 缓冲区溢出:**  提供的缓冲区 `buf` 太小，无法容纳结果字符串。**示例:**

   ```c
   char buf[5];
   const char* path = "/long/path/to/file";
   int rc = basename_r(path, buf, sizeof(buf));
   if (rc == -1 && errno == ERANGE) {
       printf("Buffer too small!\n");
   }
   ```

   **正确做法:**  确保缓冲区足够大，或者在调用前计算所需的大小。

3. **对 `dirname` 的返回值不进行 `NULL` 检查 (虽然测试代码中没有体现，但理论上可能发生):**  虽然通常 `dirname` 不会返回 `NULL`，但在某些极端情况下或特定实现中可能发生，因此进行检查是一个好的实践。

4. **混淆 `dirname` 和 `basename` 的功能:**  错误地使用了其中一个函数，导致提取了错误的路径部分。

**Android framework 或 ndk 如何到达这里**

1. **Android Framework (Java 代码):**
   * 假设你在 Java 代码中需要获取一个文件的父目录：
     ```java
     File file = new File("/sdcard/Pictures/image.png");
     File parentDir = file.getParentFile();
     String parentPath = parentDir.getAbsolutePath();
     ```
   * `File.getParentFile()` 和 `File.getAbsolutePath()` 等方法最终会通过 JNI (Java Native Interface) 调用到底层的 Native 代码。
   * 在 Native 代码中，可能会使用 Bionic 提供的文件系统相关的函数，这些函数内部可能会调用 `dirname` 或类似的路径处理逻辑。

2. **Android NDK (C/C++ 代码):**
   * 如果你直接在 NDK 代码中使用 POSIX 标准的 C 库函数，例如：
     ```c++
     #include <libgen.h>
     #include <string.h>
     #include <stdlib.h>
     #include <stdio.h>

     void process_path(const char* path) {
         char* path_copy = strdup(path);
         if (path_copy) {
             char* dir = dirname(path_copy);
             printf("Directory: %s\n", dir);
             free(path_copy);
         }
     }
     ```
   * 当这段 NDK 代码被编译并运行在 Android 设备上时，它将链接到 Bionic 库，因此会调用 Bionic 提供的 `dirname` 实现。

**Frida hook 示例调试步骤**

假设我们要 hook `dirname` 函数，查看其输入和输出。

**Frida Hook 代码:**

```javascript
if (Process.platform === 'android') {
  const dirnamePtr = Module.findExportByName("libc.so", "dirname");

  if (dirnamePtr) {
    Interceptor.attach(dirnamePtr, {
      onEnter: function (args) {
        const path = args[0];
        if (path) {
          console.log("[dirname] Input path:", path.readCString());
        } else {
          console.log("[dirname] Input path: NULL");
        }
      },
      onLeave: function (retval) {
        if (retval) {
          console.log("[dirname] Returned directory:", retval.readCString());
        } else {
          console.log("[dirname] Returned directory: NULL");
        }
      }
    });
    console.log("[Frida] Attached to dirname");
  } else {
    console.error("[Frida] Error: dirname not found in libc.so");
  }
} else {
  console.log("[Frida] This script is for Android");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **运行目标应用:** 启动你想要调试的 Android 应用，该应用需要调用到 `dirname` 函数。
3. **运行 Frida 脚本:** 使用 Frida 命令将上面的 JavaScript 代码注入到目标应用进程中。例如，如果应用的进程 ID 是 `12345`：
   ```bash
   frida -U -p 12345 -l your_script.js
   ```
   或者，如果知道应用包名：
   ```bash
   frida -U -f com.example.your_app -l your_script.js --no-pause
   ```
4. **触发 `dirname` 调用:** 在应用中执行一些操作，这些操作会导致调用 `dirname` 函数。例如，浏览文件、打开某些界面等。
5. **查看 Frida 输出:** 在 Frida 的控制台中，你将看到类似以下的输出，显示了 `dirname` 函数的输入和输出：

   ```
   [Frida] Attached to dirname
   [dirname] Input path: /sdcard/DCIM/Camera/image.jpg
   [dirname] Returned directory: /sdcard/DCIM/Camera
   [dirname] Input path: /data/user/0/com.example.your_app/cache/temp_file
   [dirname] Returned directory: /data/user/0/com.example.your_app/cache
   ```

**对于 `basename_r` 和 `dirname_r` 的 hook 示例:**

由于这两个函数都需要缓冲区，hook 时需要读取缓冲区的内容。

```javascript
if (Process.platform === 'android') {
  const basename_rPtr = Module.findExportByName("libc.so", "basename_r");
  const dirname_rPtr = Module.findExportByName("libc.so", "dirname_r");

  if (basename_rPtr) {
    Interceptor.attach(basename_rPtr, {
      onEnter: function (args) {
        const path = args[0] ? args[0].readCString() : "NULL";
        const buf = args[1];
        const size = args[2].toInt();
        this.bufPtr = buf;
        this.bufSize = size;
        console.log("[basename_r] Input path:", path, "Buffer size:", size);
      },
      onLeave: function (retval) {
        if (retval.toInt() >= 0 && this.bufPtr) {
          const result = this.bufPtr.readCString();
          console.log("[basename_r] Returned:", result, "Return code:", retval.toInt());
        } else {
          console.log("[basename_r] Failed, return code:", retval.toInt());
        }
      }
    });
    console.log("[Frida] Attached to basename_r");
  }

  if (dirname_rPtr) {
    Interceptor.attach(dirname_rPtr, {
      onEnter: function (args) {
        const path = args[0] ? args[0].readCString() : "NULL";
        const buf = args[1];
        const size = args[2].toInt();
        this.bufPtr = buf;
        this.bufSize = size;
        console.log("[dirname_r] Input path:", path, "Buffer size:", size);
      },
      onLeave: function (retval) {
        if (retval.toInt() >= 0 && this.bufPtr) {
          const result = this.bufPtr.readCString();
          console.log("[dirname_r] Returned:", result, "Return code:", retval.toInt());
        } else {
          console.log("[dirname_r] Failed, return code:", retval.toInt());
        }
      }
    });
    console.log("[Frida] Attached to dirname_r");
  }
} else {
  console.log("[Frida] This script is for Android");
}
```

通过这些 Frida hook 示例，你可以动态地观察这些路径处理函数在 Android 系统中的行为，帮助理解它们的用法和调试相关问题。

希望以上详细的分析能够帮助你理解 `bionic/tests/libgen_test.cpp` 文件的功能以及相关概念。

Prompt: 
```
这是目录为bionic/tests/libgen_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <libgen.h>

#include <errno.h>
#include <gtest/gtest.h>

static void TestDirname(const char* in, const char* expected_out) {
  char* writable_in = (in != nullptr) ? strdup(in) : nullptr;
  errno = 0;
  const char* out = dirname(&writable_in[0]);
  ASSERT_STREQ(expected_out, out) << in;
  ASSERT_EQ(0, errno) << in;
  free(writable_in);
}

TEST(libgen, dirname) {
  TestDirname(nullptr, ".");
  TestDirname("", ".");
  TestDirname("/usr/lib", "/usr");
  TestDirname("/usr/", "/");
  TestDirname("usr", ".");
  TestDirname(".", ".");
  TestDirname("..", ".");
  TestDirname("/", "/");
}

#if defined(__BIONIC__) && !defined(__LP64__)
static void TestBasename(const char* in, const char* expected_out, int expected_rc,
                         char* buf, size_t buf_size, int expected_errno) {
  errno = 0;
  int rc = basename_r(in, buf, buf_size);
  ASSERT_EQ(expected_rc, rc) << in;
  if (rc != -1 && buf != nullptr) {
    ASSERT_STREQ(expected_out, buf) << in;
  }
  ASSERT_EQ(expected_errno, errno) << in;
}

static void TestDirname(const char* in, const char* expected_out, int expected_rc,
                        char* buf, size_t buf_size, int expected_errno) {
  errno = 0;
  int rc = dirname_r(in, buf, buf_size);
  ASSERT_EQ(expected_rc, rc) << in;
  if (rc != -1 && buf != nullptr) {
    ASSERT_STREQ(expected_out, buf) << in;
  }
  ASSERT_EQ(expected_errno, errno) << in;
}
#endif // __BIONIC__

TEST(libgen, basename_r) {
#if defined(__BIONIC__) && !defined(__LP64__)
  char buf[256];
  TestBasename("", ".",  1, nullptr, 0, 0);
  TestBasename("", ".", -1, buf, 0, ERANGE);
  TestBasename("", ".", -1, buf, 1, ERANGE);
  TestBasename("", ".", 1, buf, 2, 0);
  TestBasename("", ".", 1, buf, sizeof(buf), 0);
  TestBasename("/usr/lib", "lib", 3, buf, sizeof(buf), 0);
  TestBasename("/usr/", "usr", 3, buf, sizeof(buf), 0);
  TestBasename("usr", "usr", 3, buf, sizeof(buf), 0);
  TestBasename("/", "/", 1, buf, sizeof(buf), 0);
  TestBasename(".", ".", 1, buf, sizeof(buf), 0);
  TestBasename("..", "..", 2, buf, sizeof(buf), 0);
#else // __BIONIC__
  GTEST_SKIP() << "basename_r is only available on 32-bit bionic";
#endif // __BIONIC__
}

TEST(libgen, dirname_r) {
#if defined(__BIONIC__) && !defined(__LP64__)
  char buf[256];
  TestDirname("", ".",  1, nullptr, 0, 0);
  TestDirname("", ".", -1, buf, 0, ERANGE);
  TestDirname("", ".", -1, buf, 1, ERANGE);
  TestDirname("", ".", 1, buf, 2, 0);
  TestDirname("/usr/lib", "/usr", 4, buf, sizeof(buf), 0);
  TestDirname("/usr/", "/", 1, buf, sizeof(buf), 0);
  TestDirname("usr", ".", 1, buf, sizeof(buf), 0);
  TestDirname(".", ".", 1, buf, sizeof(buf), 0);
  TestDirname("..", ".", 1, buf, sizeof(buf), 0);
#else // __BIONIC__
  GTEST_SKIP() << "dirname_r is only available on 32-bit bionic";
#endif // __BIONIC__
}

"""

```