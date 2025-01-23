Response:
Let's break down the thought process for analyzing the provided `linker_utils.cpp` file and generating the detailed explanation.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of `linker_utils.cpp` within the Android Bionic context, specifically focusing on its relationship with Android features, libc functions, the dynamic linker, common errors, and how it's reached. The request also asks for examples, code snippets, and a Frida hook demonstration.

**2. High-Level Overview of the File:**

The first step is to quickly scan the code to identify the key functions and their apparent purpose. Keywords like `format_string`, `dirname`, `normalize_path`, `file_is_in_dir`, `parse_zip_path`, `safe_add`, `split_path`, `resolve_path`, and `is_first_stage_init` stand out. The include headers (`linker_debug.h`, `linker_globals.h`, `android-base/strings.h`, `sys/stat.h`, `unistd.h`) provide clues about the dependencies and the file's domain.

**3. Function-by-Function Analysis:**

The next step is to analyze each function individually:

* **`format_string`:** The name suggests string manipulation involving placeholders. The code confirms this, showing how `$token` and `${token}` are replaced. The logic is relatively straightforward.
* **`dirname`:** This is clearly a utility to extract the directory part of a path, similar to the standard `dirname` utility.
* **`normalize_path`:** This looks like it's aimed at cleaning up paths, handling `.` and `..` components, and ensuring absolute paths. The error handling with `DL_WARN` is important to note.
* **`file_is_in_dir`:** This seems to check if a file is directly within a given directory (no subdirectories).
* **`file_is_under_dir`:** Similar to the above, but checks if a file is anywhere *under* a given directory.
* **`parse_zip_path`:** This is a crucial function for handling paths that refer to files inside ZIP archives, a common mechanism in Android. The `!/` separator is key.
* **`safe_add`:**  This is a safety measure to prevent integer overflows during addition, particularly when dealing with file offsets.
* **`split_path`:** This utilizes `android::base::Split` to break a path string into components based on delimiters, a standard string processing task.
* **`resolve_paths`:** This iterates through a list of paths and calls `resolve_path` on each.
* **`resolve_path`:** This is a complex function that attempts to find the absolute path of a given path. It handles both regular file system paths and paths within ZIP archives. It also checks if the resolved path is a directory. The use of `realpath` is central here. The fallback mechanism for ZIP paths and existing directories is also important.
* **`is_first_stage_init`:** This function checks if the linker is running as PID 1 (init process) during the very early stages of boot.

**4. Identifying Relationships with Android Features:**

As each function is analyzed, consider how it relates to Android's dynamic linking process:

* **Path Handling (all path-related functions):**  Crucial for locating shared libraries. Android uses complex path resolution rules, especially with APKs and split APKs.
* **ZIP Archive Support (`parse_zip_path`, `resolve_path`):**  Essential because APKs are ZIP files containing native libraries.
* **Safety (`safe_add`):** Important for preventing vulnerabilities in a system component like the linker.
* **First Stage Initialization (`is_first_stage_init`):** Related to the initial setup of the Android system.

**5. Identifying libc Function Usage and Explanation:**

Note the use of standard C library functions:

* `strrchr`:  For finding the last occurrence of a character.
* `strlen`:  For getting string length.
* `strncmp`: For comparing the beginning of strings.
* `strchr`: For finding the first occurrence of a character.
* `strstr`: For finding a substring.
* `strlcpy`: For safely copying strings.
* `realpath`: For resolving absolute paths.
* `stat`: For getting file status information.
* `getpid`: For getting the process ID.
* `access`: For checking file accessibility.

For each, provide a brief explanation of its standard C library purpose.

**6. Linking to Dynamic Linker Functionality:**

Focus on how these utilities support the linker's core tasks:

* **Library Loading:**  Path manipulation is fundamental to finding libraries.
* **Dependency Resolution:** The linker needs to parse and resolve paths specified in library dependencies.
* **Security:**  Path normalization and checks help prevent path traversal vulnerabilities.
* **APK Handling:**  ZIP path parsing is critical for loading libraries from APKs.

**7. SO Layout and Linking Process Example:**

Create a simple example demonstrating how the linker uses these utilities. A basic scenario with an app loading a shared library from within an APK is effective. Outline the steps involved in the linking process, highlighting where path resolution and ZIP path parsing come into play.

**8. Common User/Programming Errors:**

Think about typical mistakes developers make that relate to these utilities:

* Incorrect path formats.
* Assuming libraries are in the system path.
* Forgetting about the `!/` separator for ZIP paths.
* Incorrectly handling relative paths.

**9. Android Framework/NDK to `linker_utils.cpp`:**

Trace the path from user code to this file:

1. NDK code uses `dlopen`.
2. `dlopen` calls into the linker.
3. The linker uses functions in `linker_utils.cpp` to find and load the library.

**10. Frida Hook Example:**

Choose a relevant function (e.g., `resolve_path`) and show how to use Frida to intercept calls, inspect arguments, and potentially modify behavior.

**11. Structure and Language:**

Organize the information logically with clear headings and subheadings. Use precise language and provide code examples where necessary. Ensure the response is in Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the intricacies of `realpath`.
* **Correction:**  Realize the importance of the ZIP path handling and give it significant attention.
* **Initial thought:** Briefly mention libc functions.
* **Correction:** Explain their purpose in more detail within the context of the linker.
* **Initial thought:**  Provide a very complex SO layout.
* **Correction:** Simplify the SO layout example for clarity.
* **Initial thought:**  Just list possible errors.
* **Correction:**  Provide concrete examples of how these errors manifest.

By following this structured approach, breaking down the problem into smaller pieces, and continually refining the explanation, a comprehensive and accurate response can be generated. The key is to connect the individual functions back to the larger purpose of the dynamic linker within the Android ecosystem.
好的，让我们来详细分析一下 `bionic/linker/linker_utils.cpp` 这个文件。

**功能概述:**

`linker_utils.cpp` 文件在 Android Bionic 动态链接器中扮演着工具箱的角色，它包含了一系列用于处理字符串、路径、文件系统以及与动态链接相关的辅助函数。这些函数被链接器的其他模块广泛使用，以简化常见的操作并提高代码的可读性和可维护性。

**具体功能列举:**

1. **`format_string`**:  格式化字符串，允许替换字符串中的占位符。
2. **`dirname`**:  获取给定路径的目录部分。
3. **`normalize_path`**:  规范化路径，处理 `.` 和 `..` 等特殊目录，并确保路径是绝对路径。
4. **`file_is_in_dir`**:  检查一个文件是否直接位于给定的目录下（不包含子目录）。
5. **`file_is_under_dir`**:  检查一个文件是否位于给定的目录下或其子目录下。
6. **`parse_zip_path`**:  解析 ZIP 文件路径，提取 ZIP 文件名和 ZIP 文件内部的条目路径。
7. **`safe_add`**:  安全地进行加法运算，防止整数溢出。
8. **`split_path`**:  根据指定的分隔符分割路径字符串。
9. **`resolve_paths`**:  解析一组路径，将相对路径转换为绝对路径。
10. **`resolve_path`**:  解析单个路径，尝试将其转换为绝对路径，并处理 ZIP 文件中的路径。
11. **`is_first_stage_init`**:  判断当前进程是否为 init 进程的第一阶段初始化。

**与 Android 功能的关系及举例说明:**

这些工具函数与 Android 的核心功能密切相关，特别是与动态库的加载、链接和管理息息相关。

* **动态库查找和加载:**  `normalize_path`, `resolve_path`, `parse_zip_path` 等函数用于处理动态库的路径，包括从 APK 文件中查找和加载 `.so` 文件。例如，当应用启动时，系统需要加载其依赖的动态库。链接器会使用这些函数来找到这些库的实际位置。如果一个库位于 APK 文件的 `lib` 目录下，`parse_zip_path` 就能解析出 APK 路径和库在 APK 内的路径。

* **安全性和路径规范化:** `normalize_path` 可以防止路径遍历攻击，确保访问的文件都在预期的位置。例如，如果一个恶意应用尝试使用 `../../sensitive_file` 这样的路径来加载库，`normalize_path` 会将其规范化，阻止访问到不应该访问的文件。

* **应用安装和更新:** Android 应用通常打包成 APK 文件，其中包含 `.so` 动态库。`parse_zip_path` 使得链接器能够理解 APK 文件的结构，并从中提取需要的动态库。

* **系统启动:** `is_first_stage_init` 用于判断是否处于系统启动的早期阶段，这有助于链接器根据不同的启动阶段执行不同的初始化操作。

**libc 函数的功能实现:**

让我们详细解释一下 `linker_utils.cpp` 中使用的一些 libc 函数：

* **`strrchr(const char* s, int c)`:**  在字符串 `s` 中查找字符 `c` 最后一次出现的位置。如果找到，返回指向该位置的指针；否则返回 `nullptr`。
    * **实现原理:**  `strrchr` 从字符串 `s` 的末尾开始向前遍历，逐个字符与 `c` 进行比较，直到找到匹配的字符或到达字符串的开头。
    * **在 `dirname` 中的应用:**  用于找到路径中最后一个 `/` 字符的位置，从而确定目录名。

* **`strlen(const char* s)`:** 计算字符串 `s` 的长度，不包括 null 终止符。
    * **实现原理:** `strlen` 从字符串 `s` 的开头开始遍历，直到遇到 null 终止符 `\0`，并返回遍历的字符数。
    * **在多个函数中的应用:** 例如 `normalize_path`, `file_is_in_dir`, `parse_zip_path` 中都需要知道字符串的长度。

* **`strncmp(const char* s1, const char* s2, size_t n)`:** 比较字符串 `s1` 和 `s2` 的前 `n` 个字符。如果前 `n` 个字符相同，则返回 0；如果 `s1` 的前 `n` 个字符小于 `s2` 的前 `n` 个字符，则返回负值；否则返回正值。
    * **实现原理:** `strncmp` 从两个字符串的开头开始逐个字符进行比较，直到比较了 `n` 个字符或者遇到了不同的字符或 null 终止符。
    * **在 `file_is_in_dir` 和 `file_is_under_dir` 中的应用:** 用于比较路径的前缀，判断一个文件是否位于指定的目录下。

* **`strchr(const char* s, int c)`:** 在字符串 `s` 中查找字符 `c` 第一次出现的位置。如果找到，返回指向该位置的指针；否则返回 `nullptr`。
    * **实现原理:** `strchr` 从字符串 `s` 的开头开始向前遍历，逐个字符与 `c` 进行比较，直到找到匹配的字符或到达字符串的末尾。
    * **在 `file_is_in_dir` 中的应用:**  用于检查在目录名之后是否还有 `/` 字符，以判断是否是直接位于该目录下。

* **`strstr(const char* haystack, const char* needle)`:** 在字符串 `haystack` 中查找子字符串 `needle` 第一次出现的位置。如果找到，返回指向该位置的指针；否则返回 `nullptr`。
    * **实现原理:** `strstr` 从 `haystack` 的开头开始，尝试将 `needle` 与 `haystack` 中从当前位置开始的子字符串进行匹配。如果匹配成功，则返回当前位置的指针；否则，将起始位置向后移动一位，继续匹配。
    * **在 `parse_zip_path` 中的应用:** 用于查找 ZIP 文件分隔符 `!/`。

* **`strlcpy(char* dest, const char* src, size_t size)`:** 将字符串 `src` 复制到 `dest`，最多复制 `size - 1` 个字符，并确保 `dest` 以 null 结尾。返回复制的字符数（不包括 null 终止符），如果源字符串的长度大于等于 `size`，则返回 `size`。
    * **实现原理:** `strlcpy` 首先检查 `size` 是否为 0，如果是则直接返回 0。然后，它从 `src` 复制字符到 `dest`，直到复制了 `size - 1` 个字符、遇到了 `src` 的 null 终止符，或发生错误。最后，它在 `dest` 的末尾添加 null 终止符。
    * **在 `parse_zip_path` 中的应用:** 用于安全地复制路径字符串。

* **`realpath(const char* pathname, char* resolved_path)`:** 将相对路径名 `pathname` 转换为绝对路径名。解析路径中的符号链接、`.` 和 `..` 组件。结果存储在 `resolved_path` 中。如果成功，返回 `resolved_path`；如果失败，返回 `nullptr` 并设置 `errno`。
    * **实现原理:** `realpath` 首先检查 `pathname` 是否为绝对路径。如果不是，则将其与当前工作目录组合。然后，它逐个解析路径中的组件。对于每个符号链接，它会解析链接指向的目标。对于 `.` 和 `..`，它会进行相应的目录跳转。
    * **在 `resolve_path` 中的应用:** 用于获取文件的真实绝对路径。

* **`stat(const char* pathname, struct stat* buf)`:** 获取由 `pathname` 指向的文件或目录的状态信息，并将结果存储在 `buf` 指向的 `stat` 结构体中。如果成功，返回 0；如果失败，返回 -1 并设置 `errno`。
    * **实现原理:** `stat` 系统调用会访问文件系统的元数据，获取文件的各种属性，例如文件类型、权限、大小、修改时间等。
    * **在 `resolve_path` 中的应用:** 用于检查解析后的路径是否是一个目录。

* **`getpid(void)`:** 获取当前进程的进程 ID。
    * **实现原理:** 这是一个简单的系统调用，内核会返回当前进程的唯一标识符。
    * **在 `is_first_stage_init` 中的应用:** 用于判断当前进程是否是 init 进程 (PID 为 1)。

* **`access(const char* pathname, int mode)`:** 检查调用进程是否可以访问由 `pathname` 指向的文件。`mode` 指定要检查的访问类型（例如，文件是否存在 `F_OK`，可读 `R_OK`，可写 `W_OK`，可执行 `X_OK`）。如果调用成功，所有请求的访问都被允许，则返回 0。如果任何请求的访问被拒绝，则返回 -1 并设置 `errno`。
    * **实现原理:** `access` 系统调用会检查进程的有效用户 ID 和组 ID 是否有权限执行指定的操作。
    * **在 `is_first_stage_init` 中的应用:** 用于检查 `/proc/self/exe` 文件是否存在，以判断是否处于 init 进程的早期阶段。

**涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程:**

`linker_utils.cpp` 中的许多函数都直接支持动态链接器的核心功能。以下是一个简单的 `.so` 布局样本和链接处理过程：

**so 布局样本:**

假设我们有一个简单的应用程序 `app`，它依赖于一个共享库 `libmylib.so`。

```
/system/lib64/libc.so
/system/lib64/libdl.so
/data/app/com.example.myapp/lib/arm64-v8a/libmylib.so
/data/app/com.example.myapp/base.apk
```

其中：

* `libc.so` 和 `libdl.so` 是系统提供的标准 C 库和动态链接器库。
* `libmylib.so` 是应用程序自定义的共享库，位于应用的私有目录下。
* `base.apk` 是应用程序的安装包。

**链接的处理过程:**

1. **应用启动:** 当 Android 系统启动 `app` 时，首先会加载 `app` 的主执行文件。
2. **依赖查找:**  `app` 的 ELF 文件头中包含了它所依赖的共享库的信息，包括 `libmylib.so`。
3. **路径解析:** 动态链接器需要找到 `libmylib.so` 的实际路径。这通常涉及到搜索预定义的目录列表（例如，通过 `LD_LIBRARY_PATH` 环境变量或默认的系统库路径）。在这个过程中，`normalize_path` 和 `resolve_path` 等函数会被用来规范化和解析可能的路径。
4. **APK 内查找:** 如果 `libmylib.so` 没有在标准路径下找到，链接器可能会检查应用程序的 APK 文件。`parse_zip_path` 函数会被用来解析 APK 路径和库在 APK 内部的路径。例如，如果 `libmylib.so` 位于 `base.apk!/lib/arm64-v8a/libmylib.so`，`parse_zip_path` 会提取出 APK 路径和内部路径。
5. **库加载:** 一旦找到 `libmylib.so`，链接器会将其加载到内存中。
6. **符号解析和重定位:** 链接器会解析 `libmylib.so` 中的符号，并将其与 `app` 中使用的符号进行关联。这涉及到修改代码和数据段中的地址，使其指向正确的内存位置。
7. **执行:**  链接完成后，`app` 就可以调用 `libmylib.so` 中提供的函数了。

**逻辑推理，假设输入与输出:**

**示例 1: `normalize_path`**

* **假设输入:** `"/foo/bar/../baz"`
* **逻辑推理:** 函数会处理 `..`，向上级目录跳转。
* **输出:** `"/foo/baz"`

* **假设输入:** `"foo/bar"` (非绝对路径)
* **逻辑推理:** 函数会检测到不是绝对路径，并输出警告。
* **输出:** 返回 `false`。

**示例 2: `parse_zip_path`**

* **假设输入:** `"/data/app/com.example.myapp/base.apk!/lib/arm64-v8a/libmylib.so"`
* **逻辑推理:** 函数会识别 `!/` 分隔符。
* **输出:** `zip_path` 为 `"/data/app/com.example.myapp/base.apk"`，`entry_path` 为 `"lib/arm64-v8a/libmylib.so"`，返回 `true`。

* **假设输入:** `"/system/lib64/libc.so"` (没有 `!/`)
* **逻辑推理:** 函数找不到 `!/` 分隔符。
* **输出:** 返回 `false`。

**用户或编程常见的使用错误:**

1. **路径格式错误:**  例如，在应该使用绝对路径的地方使用了相对路径，或者在 ZIP 文件路径中 `!` 和 `/` 的使用不正确。
   * **示例:** 在 `dlopen` 中传递一个相对路径 `"./libmylib.so"`，而不是其绝对路径。链接器可能无法正确找到该库。

2. **忘记处理 APK 中的库:**  当库位于 APK 文件中时，需要使用正确的 ZIP 文件路径格式（包含 `!/` 分隔符）。
   * **示例:**  尝试直接加载 APK 文件内部的库，例如 `dlopen("/data/app/com.example.myapp/base.apk/lib/arm64-v8a/libmylib.so")`，这会失败，因为链接器需要知道这是一个 ZIP 文件。

3. **权限问题:**  即使路径正确，如果应用程序没有访问该路径下文件的权限，加载也会失败。

**Android framework or ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**路径:**

1. **NDK 代码:** 开发者在 NDK 代码中使用 `dlopen` 函数来加载动态库。例如：
   ```c++
   #include <dlfcn.h>

   void load_library() {
       void* handle = dlopen("/data/app/com.example.myapp/lib/arm64-v8a/libmylib.so", RTLD_LAZY);
       if (handle == nullptr) {
           // 处理错误
       }
   }
   ```

2. **Framework 调用:**  NDK 的 `dlopen` 函数实际上是对 Bionic 库中 `libdl.so` 的 `dlopen` 实现的封装。

3. **Bionic Linker (`libdl.so`):** `libdl.so` 中的 `dlopen` 函数会调用到动态链接器 `/system/bin/linker64` (或 `/system/bin/linker` for 32-bit)。

4. **Linker 内部:**  链接器内部会使用 `linker_utils.cpp` 中提供的函数来处理库的路径，例如 `normalize_path` 和 `resolve_path` 来确定库的实际位置。

**Frida Hook 示例:**

我们可以使用 Frida Hook `resolve_path` 函数来观察链接器是如何解析库路径的。

```javascript
if (Process.arch === 'arm64') {
    var resolve_path_addr = Module.findExportByName("linker64", "_Z12resolve_pathRKSs"); // C++ 符号修饰名
} else {
    var resolve_path_addr = Module.findExportByName("linker", "_Z12resolve_pathRKSs");  // C++ 符号修饰名
}

if (resolve_path_addr) {
    Interceptor.attach(resolve_path_addr, {
        onEnter: function (args) {
            var path = args[0].readUtf8String();
            console.log("[resolve_path] Enter, path:", path);
        },
        onLeave: function (retval) {
            var resolved_path = retval.readUtf8String();
            console.log("[resolve_path] Leave, resolved path:", resolved_path);
        }
    });
} else {
    console.error("Could not find resolve_path function.");
}
```

**使用方法:**

1. 将以上 JavaScript 代码保存为 `.js` 文件（例如 `hook_resolve_path.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <your_app_package_name> -l hook_resolve_path.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_resolve_path.js
   ```

**预期输出:**

当应用尝试加载动态库时，Frida 会拦截对 `resolve_path` 函数的调用，并在控制台中打印输入路径和解析后的路径，从而帮助你理解链接器是如何工作的。例如：

```
[resolve_path] Enter, path: /data/app/com.example.myapp/lib/arm64-v8a/libmylib.so
[resolve_path] Leave, resolved path: /data/app/com.example.myapp/lib/arm64-v8a/libmylib.so
```

或者，如果涉及到 APK 内部的库：

```
[resolve_path] Enter, path: /data/app/com.example.myapp/base.apk!/lib/arm64-v8a/libmylib.so
[resolve_path] Leave, resolved path: /data/app/com.example.myapp/base.apk!/lib/arm64-v8a/libmylib.so
```

这个 Frida 示例可以帮助你深入了解 Android 系统如何加载和管理动态库，以及 `linker_utils.cpp` 中提供的工具函数在其中的作用。

### 提示词
```
这是目录为bionic/linker/linker_utils.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include "linker_utils.h"

#include "linker_debug.h"
#include "linker_globals.h"

#include "android-base/strings.h"

#include <sys/stat.h>
#include <unistd.h>

void format_string(std::string* str, const std::vector<std::pair<std::string, std::string>>& params) {
  size_t pos = 0;
  while (pos < str->size()) {
    pos = str->find("$", pos);
    if (pos == std::string::npos) break;
    for (const auto& param : params) {
      const std::string& token = param.first;
      const std::string& replacement = param.second;
      if (str->substr(pos + 1, token.size()) == token) {
        str->replace(pos, token.size() + 1, replacement);
        // -1 to compensate for the ++pos below.
        pos += replacement.size() - 1;
        break;
      } else if (str->substr(pos + 1, token.size() + 2) == "{" + token + "}") {
        str->replace(pos, token.size() + 3, replacement);
        pos += replacement.size() - 1;
        break;
      }
    }
    // Skip $ in case it did not match any of the known substitutions.
    ++pos;
  }
}

std::string dirname(const char* path) {
  const char* last_slash = strrchr(path, '/');

  if (last_slash == path) {
    return "/";
  } else if (last_slash == nullptr) {
    return ".";
  } else {
    return std::string(path, last_slash - path);
  }
}

bool normalize_path(const char* path, std::string* normalized_path) {
  // Input should be an absolute path
  if (path[0] != '/') {
    DL_WARN("normalize_path - invalid input: \"%s\", the input path should be absolute", path);
    return false;
  }

  const size_t len = strlen(path) + 1;
  char buf[len];

  const char* in_ptr = path;
  char* out_ptr = buf;

  while (*in_ptr != 0) {
    if (*in_ptr == '/') {
      char c1 = in_ptr[1];
      if (c1 == '.') {
        char c2 = in_ptr[2];
        if (c2 == '/') {
          in_ptr += 2;
          continue;
        } else if (c2 == '.' && (in_ptr[3] == '/' || in_ptr[3] == 0)) {
          in_ptr += 3;
          while (out_ptr > buf && *--out_ptr != '/') {
          }
          if (in_ptr[0] == 0) {
            // retain '/' (or write the initial '/' for "/..")
            *out_ptr++ = '/';
          }
          continue;
        }
      } else if (c1 == '/') {
        ++in_ptr;
        continue;
      }
    }
    *out_ptr++ = *in_ptr++;
  }

  *out_ptr = 0;
  *normalized_path = buf;
  return true;
}

bool file_is_in_dir(const std::string& file, const std::string& dir) {
  const char* needle = dir.c_str();
  const char* haystack = file.c_str();
  size_t needle_len = strlen(needle);

  return strncmp(haystack, needle, needle_len) == 0 &&
         haystack[needle_len] == '/' &&
         strchr(haystack + needle_len + 1, '/') == nullptr;
}

bool file_is_under_dir(const std::string& file, const std::string& dir) {
  const char* needle = dir.c_str();
  const char* haystack = file.c_str();
  size_t needle_len = strlen(needle);

  return strncmp(haystack, needle, needle_len) == 0 &&
         haystack[needle_len] == '/';
}

const char* const kZipFileSeparator = "!/";

bool parse_zip_path(const char* input_path, std::string* zip_path, std::string* entry_path) {
  std::string normalized_path;
  if (!normalize_path(input_path, &normalized_path)) {
    return false;
  }

  const char* const path = normalized_path.c_str();
  LD_DEBUG(any, "Trying zip file open from path \"%s\" -> normalized \"%s\"", input_path, path);

  // Treat an '!/' separator inside a path as the separator between the name
  // of the zip file on disk and the subdirectory to search within it.
  // For example, if path is "foo.zip!/bar/bas/x.so", then we search for
  // "bar/bas/x.so" within "foo.zip".
  const char* const separator = strstr(path, kZipFileSeparator);
  if (separator == nullptr) {
    return false;
  }

  char buf[512];
  if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf)) {
    DL_WARN("ignoring very long library path: %s", path);
    return false;
  }

  buf[separator - path] = '\0';

  *zip_path = buf;
  *entry_path = &buf[separator - path + 2];

  return true;
}

bool safe_add(off64_t* out, off64_t a, size_t b) {
  CHECK(a >= 0);
  if (static_cast<uint64_t>(INT64_MAX - a) < b) {
    return false;
  }

  *out = a + b;
  return true;
}

void split_path(const char* path, const char* delimiters,
                std::vector<std::string>* paths) {
  if (path != nullptr && path[0] != 0) {
    *paths = android::base::Split(path, delimiters);
  }
}

void resolve_paths(std::vector<std::string>& paths,
                   std::vector<std::string>* resolved_paths) {
  resolved_paths->clear();
  for (const auto& path : paths) {
    // skip empty paths
    if (path.empty()) {
      continue;
    }
    std::string resolved = resolve_path(path);
    if (!resolved.empty()) {
      resolved_paths->push_back(std::move(resolved));
    }
  }
}

std::string resolve_path(const std::string& path) {
  char resolved_path[PATH_MAX];
  const char* original_path = path.c_str();
  if (realpath(original_path, resolved_path) != nullptr) {
    struct stat s;
    if (stat(resolved_path, &s) == -1) {
      DL_WARN("Warning: cannot stat file \"%s\": %m (ignoring)", resolved_path);
      return "";
    }
    if (!S_ISDIR(s.st_mode)) {
      DL_WARN("Warning: \"%s\" is not a directory (ignoring)", resolved_path);
      return "";
    }
    return resolved_path;
  } else {
    std::string normalized_path;
    if (!normalize_path(original_path, &normalized_path)) {
      DL_WARN("Warning: unable to normalize \"%s\" (ignoring)", original_path);
      return "";
    }

    std::string zip_path;
    std::string entry_path;
    if (parse_zip_path(normalized_path.c_str(), &zip_path, &entry_path)) {
      if (realpath(zip_path.c_str(), resolved_path) == nullptr) {
        DL_WARN("Warning: unable to resolve \"%s\": %m (ignoring)", zip_path.c_str());
        return "";
      }

      return std::string(resolved_path) + kZipFileSeparator + entry_path;
    } else {
      struct stat s;
      if (stat(normalized_path.c_str(), &s) == 0 && S_ISDIR(s.st_mode)) {
        // Path is not a zip path, but an existing directory. Then add it
        // although we failed to resolve it. b/119656753
        return normalized_path;
      }
    }
  }
  return "";
}

bool is_first_stage_init() {
  static bool ret = (getpid() == 1 && access("/proc/self/exe", F_OK) == -1);
  return ret;
}
```