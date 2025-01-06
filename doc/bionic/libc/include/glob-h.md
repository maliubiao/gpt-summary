Response:
Let's break down the thought process for answering the request about `glob.h`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided `glob.h` header file and explain its functionality within the Android/Bionic context. The request has several specific sub-questions:

* Functionality of `glob.h`.
* Relationship to Android.
* Detailed explanation of libc functions.
* Dynamic linker aspects.
* Logic, assumptions, inputs/outputs.
* Common user errors.
* How Android Framework/NDK reaches this code.
* Frida hook examples.

**2. Initial Analysis of `glob.h`:**

The first step is to carefully read the header file. Key observations:

* **Copyright and History:**  It's derived from BSD, indicating a standard Unix functionality.
* **Includes:**  Includes `sys/cdefs.h` and `sys/types.h`, standard system headers. `struct dirent` and `struct stat` point towards file system operations.
* **`glob_t` Structure:** This is the core data structure. Its members suggest it's used to store results from a globbing operation:
    * `gl_pathc`: Path count.
    * `gl_matchc`: Matching path count.
    * `gl_offs`: Offset for prepending null pointers.
    * `gl_flags`:  Flags passed to the `glob` function.
    * `gl_pathv`:  Pointer to an array of matching path strings.
    * `gl_errfunc`:  Error callback function.
    * `gl_closedir`, `gl_readdir`, `gl_opendir`, `gl_lstat`, `gl_stat`: Function pointers for overriding standard directory/file functions. This immediately suggests the `GLOB_ALTDIRFUNC` flag.
* **`GLOB_` Defines:** These are the flags that control the behavior of the `glob` function. They provide clues about what `glob` does (appending, adding offsets, error handling, marking directories, etc.).
* **Function Declarations:**  `glob` and `globfree` are the core functions. The `__INTRODUCED_IN(28)` annotation strongly suggests this functionality was introduced in Android API level 28.

**3. Addressing the Specific Questions (Iterative Process):**

* **Functionality:** Based on the structure members and `GLOB_` defines, the core functionality is *pathname expansion* or *globbing*. It takes a pattern (potentially with wildcards) and finds matching file paths.

* **Relationship to Android:**  Since Bionic is Android's C library, `glob.h` and its associated functions are fundamental for Android applications (native code) that need to work with file paths. Examples would be file managers, installers, shell commands, etc.

* **libc Function Implementation:**  The header file *doesn't* contain the implementation. It only declares the structure and functions. The actual implementation would be in a `.c` file within the Bionic source tree. The thought here is to explain the *concept* of how `glob` *might* work: iterate through directories, compare filenames against the pattern, handle wildcards, etc. Emphasize it's a *simplified* explanation.

* **Dynamic Linker:**  `glob.h` itself doesn't directly interact with the dynamic linker. *However*, the `glob` function is part of `libc.so`, which *is* loaded by the dynamic linker. Therefore, the explanation should focus on how `libc.so` is linked and how `glob` becomes accessible. This involves explaining shared libraries, symbol tables, relocation, etc. The SO layout example should be simple and illustrate the relevant sections (`.text`, `.data`, `.dynsym`, `.plt`, `.got`).

* **Logic and Assumptions:**  For a simple pattern like `"*.txt"`, the logic is clear. For more complex cases, outlining the matching process for different wildcards (`*`, `?`, `[]`) is crucial. Assumptions need to be stated explicitly (e.g., case sensitivity, handling of hidden files).

* **User Errors:**  Think about common mistakes when using `glob`: incorrect pattern syntax, forgetting to call `globfree`, handling errors, dealing with large numbers of files.

* **Android Framework/NDK Path:** This requires tracing back how a typical Android application might use `glob`. A common scenario is using NDK to write native code that interacts with the file system. The chain would be: Java code (potentially using `File` or `Runtime.exec`), JNI call to native code, native code calling `glob`. Command-line tools within Android (like `ls`) also likely use `glob` internally.

* **Frida Hooking:**  Focus on hooking the `glob` function itself. Provide a simple example demonstrating how to intercept calls, examine arguments (the pattern and flags), and potentially modify the behavior.

**4. Structuring the Answer:**

Organize the information logically to match the questions in the request. Use headings and bullet points to improve readability. Provide code examples where appropriate (like the Frida hook).

**5. Refinement and Detail:**

After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand, even for someone who might not be deeply familiar with C or Android internals. Add details like mentioning the specific Android API level where `glob` was introduced.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the internal implementation details of `glob`.
* **Correction:** Realized the header file doesn't provide the implementation. Shifted focus to the *concept* and the user-facing aspects.
* **Initial thought:** Just list the `GLOB_` flags without explanation.
* **Correction:** Provided a brief description of each flag to make the functionality clearer.
* **Initial thought:** Overcomplicate the dynamic linker explanation.
* **Correction:** Simplified the explanation to focus on the core concepts relevant to how `glob` (as part of `libc.so`) is loaded and accessed.

By following these steps, the comprehensive and detailed answer addressing all aspects of the request can be constructed. The iterative process of analyzing, structuring, and refining is crucial for generating a high-quality response.
好的，让我们详细分析一下 `bionic/libc/include/glob.handroid` 这个头文件。

**功能列举:**

`glob.h` 定义了用于执行**路径名模式匹配** (pathname pattern matching)，也称为 "globbing" 的数据结构和函数原型。它的主要功能是：

1. **模式匹配:**  根据用户提供的包含通配符（例如 `*`, `?`, `[]`）的模式字符串，在文件系统中查找所有匹配的文件和目录。
2. **结果存储:** 提供一个名为 `glob_t` 的结构体，用于存储匹配结果，包括匹配到的路径数量、实际路径字符串数组等。
3. **灵活的配置:**  通过 `glob` 函数的 `flags` 参数，允许用户自定义匹配行为，例如是否排序、是否返回未匹配的模式、是否添加目录标记等。
4. **自定义行为:**  允许用户通过提供自定义的函数指针，替换默认的目录操作函数 (opendir, readdir, closedir) 和文件状态查询函数 (lstat, stat)。这在需要访问虚拟文件系统或其他非标准文件系统时非常有用。
5. **资源管理:** 提供 `globfree` 函数用于释放 `glob` 函数分配的内存。

**与 Android 功能的关系及举例:**

`glob` 函数及其相关的结构体和宏定义是 POSIX 标准的一部分，因此在 Android 的 C 库 Bionic 中实现是很自然的。它在 Android 中被广泛使用，主要体现在以下几个方面：

1. **Shell 命令:**  Android 的 shell (如 `adb shell`) 内部的许多命令，例如 `ls`, `find`, `rm` 等，都依赖 `glob` 函数来实现通配符的路径扩展。

   * **例子:** 在 `adb shell` 中执行 `ls *.txt` 命令时，shell 会调用 `glob` 函数来查找当前目录下所有以 `.txt` 结尾的文件。

2. **NDK 开发:**  使用 Android NDK 进行原生开发的应用程序，如果需要进行文件查找或处理，可以直接使用 `glob` 函数。

   * **例子:** 一个文件管理器应用可以使用 `glob` 来查找特定类型的文件，例如用户输入搜索 "*.jpg" 来查找所有 JPEG 图片。

3. **Android Framework (间接使用):** 虽然 Android Framework 主要使用 Java 编写，但其底层实现中，有些涉及到文件系统操作的部分可能会间接地使用到 `glob` 函数，或者使用到基于类似模式匹配的机制。例如，在解析 AndroidManifest.xml 文件时，可能会涉及到对特定文件模式的查找。

   * **例子:**  Android 的包管理器 (PackageManager) 在安装应用程序时，可能需要查找 APK 文件中的特定资源文件，这个过程在底层可能涉及到类似 `glob` 的操作。

**libc 函数的功能实现详细解释:**

`glob.h` 文件本身只是一个头文件，它只声明了数据结构和函数原型。 `glob` 函数和 `globfree` 函数的实际实现代码位于 Bionic 库的源文件中（通常是 `.c` 文件）。

**`glob` 函数的实现 (概念性解释):**

`glob` 函数的实现通常会遵循以下步骤：

1. **参数解析:** 解析传入的模式字符串和标志 (`flags`)。
2. **目录遍历:** 从给定的路径开始，递归地遍历目录结构。
3. **模式匹配:**  对于遍历到的每个文件或目录名，与模式字符串进行匹配。
    * **`*` (星号):** 匹配零个或多个任意字符。
    * **`?` (问号):** 匹配任意一个字符。
    * **`[...]` (方括号):** 匹配方括号中包含的任意一个字符。可以使用连字符 `-` 指定字符范围，例如 `[a-z]` 匹配所有小写字母。 `[^...]` 表示匹配不在方括号内的任意字符。
    * **转义字符 `\`:**  用于转义特殊字符，使其被视为普通字符。
4. **结果存储:**  将所有匹配到的路径名存储到 `glob_t` 结构体的 `gl_pathv` 数组中。根据 `flags` 参数的设置，可能会对结果进行排序、添加目录标记等。
5. **错误处理:**  如果遇到错误（例如无法访问目录），会根据 `GLOB_ERR` 标志的设置来决定是否立即返回。如果提供了错误回调函数 `gl_errfunc`，则会调用该函数。
6. **资源分配:**  动态分配内存来存储匹配到的路径名。

**`globfree` 函数的实现:**

`globfree` 函数的主要功能是释放 `glob` 函数分配的内存。它会执行以下操作：

1. **释放路径数组:** 释放 `glob_t` 结构体中 `gl_pathv` 指向的字符串数组中的每个字符串的内存。
2. **释放 `gl_pathv` 数组本身:** 释放存储路径字符串指针的数组的内存。
3. **重置 `glob_t` 结构体:** 将 `glob_t` 结构体的相关成员（例如 `gl_pathc`, `gl_matchc`, `gl_pathv`) 重置为初始状态或空值。

**动态链接器功能 (与 `glob` 函数相关):**

`glob` 函数是 `libc.so` 共享库的一部分。当一个应用程序需要使用 `glob` 函数时，Android 的动态链接器 (`linker`) 会负责将 `libc.so` 加载到进程的内存空间，并将应用程序中对 `glob` 函数的调用链接到 `libc.so` 中 `glob` 函数的实际实现。

**SO 布局样本 (简化版):**

```
libc.so:
    .text:  # 代码段，包含 glob 函数的机器码
        ...
        [glob 函数的机器码]
        ...
    .data:  # 已初始化数据段
        ...
    .bss:   # 未初始化数据段
        ...
    .dynsym: # 动态符号表，包含导出的符号信息 (例如 glob)
        ...
        [glob 函数的符号信息]
        ...
    .dynstr: # 动态字符串表，存储符号名称等字符串
        ...
        "glob"
        ...
    .plt:   # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
        ...
    .got:   # 全局偏移表 (Global Offset Table)，存储全局符号的地址
        ...
```

**链接的处理过程 (针对 `glob` 函数):**

1. **编译时:** 当编译器遇到对 `glob` 函数的调用时，它会生成一个对 `glob` 函数的未解析引用。
2. **链接时 (静态链接器):**  在静态链接的情况下，静态链接器会将应用程序的目标文件与 `libc.a` (静态库) 链接在一起，并将 `glob` 函数的代码直接复制到应用程序的可执行文件中。
3. **运行时 (动态链接器):** 在动态链接的情况下 (Android 通常使用动态链接):
    * **加载 `libc.so`:**  当应用程序启动时，动态链接器会加载 `libc.so` 共享库到进程的内存空间。
    * **符号查找:**  动态链接器会查找 `libc.so` 的 `.dynsym` 表，找到 `glob` 函数的符号信息。
    * **重定位:** 动态链接器会更新应用程序的 `.got` 表，将 `glob` 函数的实际地址填入对应的表项中。
    * **调用 `glob`:** 当应用程序执行到调用 `glob` 函数的代码时，它会通过 `.plt` 表跳转到 `.got` 表中存储的 `glob` 函数的地址，从而执行 `libc.so` 中 `glob` 函数的实际代码。

**逻辑推理、假设输入与输出:**

假设我们调用 `glob` 函数，输入以下参数：

* `__pattern`: `"*.txt"`
* `__flags`: `0` (默认标志)
* `__error_callback`: `NULL`
* `__result_ptr`: 指向一个已分配的 `glob_t` 结构体的指针

**假设当前目录下有以下文件:**

* `file1.txt`
* `file2.txt`
* `image.png`
* `subdir/` (一个子目录)

**输出 (存储在 `__result_ptr` 指向的 `glob_t` 结构体中):**

* `gl_pathc`: 2 (匹配到的路径数量)
* `gl_matchc`: 2
* `gl_pathv`: 指向一个包含两个字符串指针的数组：
    * `gl_pathv[0]` 指向字符串 `"file1.txt"`
    * `gl_pathv[1]` 指向字符串 `"file2.txt"`
* `gl_flags`:  传入的 `flags` 值 (0)

**如果输入模式为 `"nonexistent*.doc"` 且 `GLOB_NOCHECK` 标志未设置，则：**

* `gl_pathc`: 0
* `gl_matchc`: 0
* `gl_pathv`: `NULL` 或指向一个空指针数组 (取决于具体实现)
* `glob` 函数会返回 `GLOB_NOMATCH`。

**用户或编程常见的使用错误:**

1. **忘记调用 `globfree`:** `glob` 函数会动态分配内存来存储匹配结果，如果在使用完 `glob_t` 结构体后忘记调用 `globfree`，会导致内存泄漏。

   ```c
   #include <glob.h>
   #include <stdio.h>

   int main() {
       glob_t globbuf;
       int ret = glob("*.txt", 0, NULL, &globbuf);
       if (ret == 0) {
           for (size_t i = 0; i < globbuf.gl_pathc; i++) {
               printf("%s\n", globbuf.gl_pathv[i]);
           }
           // 忘记调用 globfree(&globbuf);  <-- 内存泄漏
       }
       return 0;
   }
   ```

2. **不正确的模式字符串:**  通配符的使用规则不熟悉，导致模式字符串无法匹配到预期的文件。

   * **错误例子:**  想要匹配所有以 `.` 开头的文件（隐藏文件），错误地使用 `"*.`"，应该使用 `".*"`。

3. **没有处理 `glob` 函数的返回值:** `glob` 函数可能会返回错误代码，例如 `GLOB_NOSPACE` (内存不足)，`GLOB_ABORTED` (发生未忽略的错误)，`GLOB_NOMATCH` (没有匹配项)。忽略返回值可能导致程序行为不正确。

   ```c
   #include <glob.h>
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       glob_t globbuf;
       int ret = glob("*.txt", 0, NULL, &globbuf);
       // 没有检查返回值
       for (size_t i = 0; i < globbuf.gl_pathc; i++) { // 如果 ret != 0，globbuf 的内容可能是未定义的
           printf("%s\n", globbuf.gl_pathv[i]);
       }
       globfree(&globbuf);
       return 0;
   }
   ```

4. **错误地使用 `GLOB_APPEND` 标志:**  当多次调用 `glob` 并使用 `GLOB_APPEND` 时，需要确保正确管理 `glob_t` 结构体，避免重复添加或内存管理错误。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 层):**
   * 开发者可能在 Java 代码中使用 `java.io.File` 类进行文件操作，例如列出目录内容。
   * 一些高级 API，例如 `android.content.pm.PackageManager` 在查找应用信息时，可能会在底层涉及到文件和目录的查找。
   * 当涉及到执行 shell 命令时 (例如使用 `Runtime.getRuntime().exec()`)，传递给 shell 的包含通配符的路径名会被 shell 解释，并最终调用到 `glob` 函数。

2. **JNI 调用:**
   * 如果 Android 应用使用 NDK 编写了原生代码，并且需要在原生代码中进行文件查找，开发者可以直接调用 `glob` 函数。

   ```c++
   // C++ NDK 代码
   #include <glob.h>
   #include <string>
   #include <vector>

   std::vector<std::string> findFiles(const std::string& pattern) {
       glob_t globbuf;
       std::vector<std::string> results;
       int ret = glob(pattern.c_str(), 0, nullptr, &globbuf);
       if (ret == 0) {
           for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
               results.push_back(globbuf.gl_pathv[i]);
           }
       }
       globfree(&globbuf);
       return results;
   }

   // ... (JNI 函数调用 findFiles)
   ```

3. **Bionic `libc.so`:**
   * 无论是在 shell 命令中还是通过 NDK 调用，最终都会链接到 Android 的 C 库 `libc.so` 中 `glob` 函数的实现。

**Frida Hook 示例调试步骤:**

假设我们要 hook `glob` 函数，查看传入的模式字符串和标志：

```javascript
if (Process.platform === 'android') {
  const globPtr = Module.findExportByName("libc.so", "glob");
  if (globPtr) {
    Interceptor.attach(globPtr, {
      onEnter: function (args) {
        const pattern = args[0].readCString();
        const flags = args[1].toInt();
        console.log(`[glob Hook] Pattern: ${pattern}, Flags: ${flags}`);
        this.pattern = pattern; // 保存 pattern，在 onLeave 中使用
      },
      onLeave: function (retval) {
        console.log(`[glob Hook] Returned: ${retval}`);
        // 可以根据需要访问和修改返回值或参数
      }
    });
    console.log("[Frida] glob hook installed on Android.");
  } else {
    console.log("[Frida] glob not found in libc.so.");
  }
} else {
  console.log("[Frida] This script is for Android.");
}
```

**调试步骤:**

1. **安装 Frida:** 确保你的电脑和 Android 设备上都安装了 Frida 和 Frida server。
2. **运行目标应用:** 启动你想要调试的 Android 应用程序。
3. **运行 Frida 脚本:** 使用 Frida 命令将上面的 JavaScript 代码注入到目标进程中。例如：
   ```bash
   frida -U -f <包名> -l your_script.js --no-pause
   ```
   将 `<包名>` 替换为目标应用程序的包名，`your_script.js` 替换为保存 Frida 脚本的文件名。
4. **触发 `glob` 调用:**  在应用程序中执行一些操作，这些操作预计会调用到 `glob` 函数，例如浏览文件、搜索文件等。
5. **查看 Frida 输出:**  Frida 会在控制台上打印出 hook 到的 `glob` 函数的调用信息，包括传入的模式字符串和标志，以及返回值。

通过 Frida hook，你可以动态地观察 `glob` 函数的调用情况，理解应用程序在文件查找方面做了什么操作，并可以进行更深入的分析和调试。

希望以上详细的解释能够帮助你理解 `bionic/libc/include/glob.handroid` 这个头文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/glob.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)glob.h	8.1 (Berkeley) 6/2/93
 * $FreeBSD$
 */

#ifndef _GLOB_H_
#define _GLOB_H_

#include <sys/cdefs.h>
#include <sys/types.h>

struct dirent;
struct stat;

typedef struct {
  size_t gl_pathc;	/* Count of total paths so far. */
  size_t gl_matchc;	/* Count of paths matching pattern. */
  size_t gl_offs;		/* Reserved at beginning of gl_pathv. */
  int gl_flags;		/* Copy of flags parameter to glob. */

  /** List of paths matching pattern. */
  char* _Nullable * _Nullable gl_pathv;

  /** Copy of `__error_callback` parameter to glob. */
  int (* _Nullable gl_errfunc)(const char* _Nonnull __failure_path, int __failure_errno);

  /** Called instead of closedir() when GLOB_ALTDIRFUNC flag is specified. */
  void (* _Nullable gl_closedir)(void* _Nonnull);
  /** Called instead of readdir() when GLOB_ALTDIRFUNC flag is specified. */
  struct dirent* _Nullable (* _Nonnull gl_readdir)(void* _Nonnull);
  /** Called instead of opendir() when GLOB_ALTDIRFUNC flag is specified. */
  void* _Nullable (* _Nonnull gl_opendir)(const char* _Nonnull);
  /** Called instead of lstat() when GLOB_ALTDIRFUNC flag is specified. */
  int (* _Nullable gl_lstat)(const char* _Nonnull, struct stat* _Nonnull);
  /** Called instead of stat() when GLOB_ALTDIRFUNC flag is specified. */
  int (* _Nullable gl_stat)(const char* _Nonnull, struct stat* _Nonnull);
} glob_t;

/* Believed to have been introduced in 1003.2-1992 */
#define GLOB_APPEND	0x0001	/* Append to output from previous call. */
#define GLOB_DOOFFS	0x0002	/* Prepend `gl_offs` null pointers (leaving space for exec, say). */
#define GLOB_ERR	0x0004	/* Return on error. */
#define GLOB_MARK	0x0008	/* Append "/" to the names of returned directories. */
#define GLOB_NOCHECK	0x0010	/* Return pattern itself if nothing matches. */
#define GLOB_NOSORT	0x0020	/* Don't sort. */
#define GLOB_NOESCAPE	0x2000	/* Disable backslash escaping. */

/* Error values returned by glob(3) */
#define GLOB_NOSPACE	(-1)	/* Malloc call failed. */
#define GLOB_ABORTED	(-2)	/* Unignored error. */
#define GLOB_NOMATCH	(-3)	/* No match and GLOB_NOCHECK was not set. */

#if __USE_BSD
#define GLOB_ALTDIRFUNC	0x0040	/* Use alternately specified directory funcs. */
#define GLOB_BRACE	0x0080	/* Expand braces like csh. */
#define GLOB_MAGCHAR	0x0100	/* Set in `gl_flags` if the pattern had globbing characters. */
#define GLOB_NOMAGIC	0x0200	/* GLOB_NOCHECK without magic chars (csh). */
#define GLOB_QUOTE	0x0400	/* Quote special chars with \. */
#define GLOB_TILDE	0x0800	/* Expand tilde names from the passwd file. */
#define GLOB_LIMIT	0x1000	/* limit number of returned paths */
#endif

__BEGIN_DECLS


#if __BIONIC_AVAILABILITY_GUARD(28)
int glob(const char* _Nonnull __pattern, int __flags, int (* _Nullable __error_callback)(const char* _Nonnull __failure_path, int __failure_errno), glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
void globfree(glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


__END_DECLS

#endif

"""

```