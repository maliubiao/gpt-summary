Response:
Let's break down the thought process for answering the request about `bionic/libc/upstream-freebsd/lib/libc/gen/glob.c`.

**1. Understanding the Core Functionality:**

The first step is to recognize that this code implements the `glob()` function. This function is about filename expansion based on patterns (wildcards). The comments at the beginning of the file confirm this.

**2. Identifying Key Features and Flags:**

Next, I scanned the initial comments and the `glob()` function signature to identify the various flags that modify the behavior of `glob()`. These flags are crucial for understanding the function's capabilities. I noted things like `GLOB_QUOTE`, `GLOB_MAGCHAR`, `GLOB_NOCHECK`, `GLOB_ALTDIRFUNC`, `GLOB_TILDE`, `GLOB_BRACE`, and `GLOB_NOSORT`.

**3. Dissecting the Code - Function by Function (High Level):**

I then went through the code, function by function, to understand the role of each. I didn't need to understand every line in detail initially, but I focused on the purpose and interactions between functions.

* **`glob()`:** The main entry point, responsible for initialization, handling quoting, and calling the core expansion logic.
* **`globexp0`, `globexp1`, `globexp2`:** These functions handle brace expansion (`{}`). Recognizing the recursive nature of brace expansion is important.
* **`globtilde()`:**  Handles tilde expansion (`~user`).
* **`glob0()`:** The core logic for handling wildcards (`*`, `?`, `[]`). It converts the pattern into an internal representation.
* **`glob1`, `glob2`, `glob3`:**  The recursive functions that traverse the directory structure and match filenames against the pattern. `glob2` handles non-meta characters, while `glob3` handles directory traversal and matching against meta-characters.
* **`globextend()`:**  Allocates and adds matching filenames to the result list.
* **`match()`:** The core pattern matching algorithm.
* **`globfree()`:**  Releases the memory allocated by `glob()`.
* **`g_opendir`, `g_lstat`, `g_stat`:** Wrappers around standard directory access functions, allowing for alternative implementations via `GLOB_ALTDIRFUNC`.
* **`g_strchr`, `g_Ctoc`:** Utility functions for string manipulation (finding characters and converting between wide and multi-byte strings).
* **`err_nomatch`, `err_aborted`:** Handle error conditions.

**4. Connecting to Android:**

With an understanding of the core functionality, I considered how this relates to Android. Since this is part of `bionic` (Android's libc), any program on Android using standard C library functions for file system operations will likely use this `glob()` implementation. Examples include shell commands, file managers, and applications that need to find files based on patterns.

**5. Explaining Function Implementations (Key Insights):**

For the explanation of function implementations, I focused on the *how* and the key data structures involved:

* **`glob()`:**  Pay attention to the handling of `GLOB_QUOTE` and the conversion to wide characters.
* **Brace Expansion (`globexp*`)**: Emphasize the recursive nature and how it generates combinations.
* **Tilde Expansion (`globtilde()`):**  Highlight the use of `getpwnam()` and `getenv("HOME")`.
* **Wildcard Handling (`glob0()`):** Explain the conversion of patterns into an internal format (e.g., `*` to `M_ALL`).
* **Directory Traversal (`glob2`, `glob3`):**  Describe the recursive search, the use of `opendir()` and `readdir()`, and the role of `match()`.
* **Pattern Matching (`match()`):**  Explain how it handles `*`, `?`, and character sets (`[]`).

**6. Dynamic Linker Aspects:**

I looked for any direct interaction with the dynamic linker. This file primarily deals with file system operations. While libc functions are used by dynamically linked programs, this specific code doesn't directly *manipulate* the dynamic linker. Therefore, the explanation focused on the standard process of linking against libc and the resulting shared object dependencies. Providing a basic `.so` layout and linking steps is sufficient.

**7. Assumptions, Inputs, and Outputs:**

For logical reasoning, I thought about typical use cases and potential edge cases. Examples like a simple wildcard, a character set, and brace expansion helped illustrate the input-output relationship.

**8. Common Usage Errors:**

I considered common mistakes programmers might make when using `glob()`, such as forgetting to call `globfree()`, misunderstanding wildcard syntax, or encountering buffer overflows with very long paths.

**9. Android Framework/NDK Integration and Frida Hooking:**

I traced the path from higher levels (Android framework, NDK) down to this `glob()` implementation. The key is recognizing that the NDK provides the standard C library, and the framework, or applications built with the NDK, can ultimately call functions that rely on `glob()`. The Frida hook example focuses on intercepting the `glob()` call itself and examining its arguments and results.

**10. Language and Formatting:**

Finally, I ensured the response was in Chinese and used clear, concise language, breaking down complex concepts into smaller parts. Formatting with headings and bullet points improves readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the file directly interacted with the dynamic linker. **Correction:** Upon closer inspection, the interaction is indirect; it's a standard libc function used by dynamically linked programs. The focus should be on how it's *used* in that context, not direct manipulation of the linker.
* **Emphasis on core concepts:**  Realized the importance of clearly explaining the purpose of the different flags and the overall workflow of the `glob()` function.
* **Frida example clarity:** Made sure the Frida hook example was concrete and showed how to intercept the function and log useful information.

By following these steps, I aimed to provide a comprehensive and accurate explanation of the `glob.c` source code within the context of Android.
好的，让我们详细分析一下 `bionic/libc/upstream-freebsd/lib/libc/gen/glob.c` 这个文件。

**功能概述**

`glob.c` 文件实现了 `glob()` 函数及其相关的辅助函数。`glob()` 函数的主要功能是执行路径名模式匹配，也被称为 "globbing"。简单来说，它接受一个包含通配符（如 `*`, `?`, `[]`）的字符串作为模式，然后在文件系统中查找所有匹配该模式的文件和目录。

**主要功能点:**

1. **基本通配符匹配:**
   - `*`: 匹配零个或多个任意字符。
   - `?`: 匹配任意单个字符。
   - `[]`: 匹配括号内指定的字符集合中的任意一个字符。
   - `[!...]`: 匹配不在括号内指定的字符集合中的任意一个字符。

2. **转义字符:**
   - `\`：用于转义后面的特殊字符，使其失去通配符的含义。例如，`\*` 匹配字面上的星号。可以通过 `GLOB_NOESCAPE` 标志禁用转义。

3. **特殊标志提供的额外功能:**
   - `GLOB_QUOTE`:  启用反斜杠转义。
   - `GLOB_MAGCHAR`:  如果模式中包含任何通配符，则在 `gl_flags` 中设置此标志。
   - `GLOB_NOMAGIC`:  类似于 `GLOB_NOCHECK`，但只有在模式中没有通配符时才将模式添加到结果中。
   - `GLOB_ALTDIRFUNC`:  允许使用用户自定义的目录访问函数（通过 `glob_t` 结构体传递）。
   - `GLOB_TILDE`:  展开以 `~` 开头的路径。例如，`~/foo` 会展开为当前用户的主目录下的 `foo`。`~username/foo` 会展开为指定用户主目录下的 `foo`。
   - `GLOB_BRACE`:  展开花括号表达式。例如，`{a,b}c` 会展开为 `ac bc`。
   - `GLOB_DOOFFS`:  指定在 `gl_pathv` 数组前面预留多少个空指针位置。
   - `GLOB_APPEND`:  将本次 `glob()` 的结果追加到之前的结果中。
   - `GLOB_NOCHECK`:  如果模式没有匹配到任何文件，则将原始模式添加到结果中。
   - `GLOB_NOSORT`:  不排序匹配到的路径名。
   - `GLOB_MARK`:  如果匹配到的是目录，则在路径名末尾添加一个 `/`。
   - `GLOB_ERR`:  如果在读取目录时发生错误，立即返回错误。
   - `GLOB_LIMIT`:  限制匹配到的路径名数量，用于防止拒绝服务攻击。

**与 Android 功能的关系及举例说明**

`glob()` 函数是 POSIX 标准的一部分，因此在 Android 的 C 库 `bionic` 中实现是至关重要的。许多 Android 系统工具和应用程序都会直接或间接地使用到它。

**举例说明:**

1. **Shell 命令:** Android 的 shell (如 `bash`, `zsh`) 内部就使用了 `glob()` 来展开命令行中的通配符。例如，当你输入 `ls *.txt` 时，shell 会调用 `glob("*.txt", ...)` 来获取当前目录下所有以 `.txt` 结尾的文件列表。

2. **`find` 命令:**  `find` 命令也广泛使用了模式匹配，其底层可能调用了 `glob()` 或类似的机制来实现文件查找。

3. **APK 打包工具:**  在构建 Android 应用程序时，打包工具（如 `aapt2`）可能使用 `glob()` 来查找需要包含在 APK 文件中的资源文件，例如 `res/*.png`。

4. **NDK 开发:**  使用 NDK 进行原生开发时，开发者可以直接调用 `glob()` 函数来执行文件查找操作。例如，一个音频处理应用可能需要查找指定目录下的所有 `.wav` 文件。

**libc 函数的实现细节**

以下是对一些关键 libc 函数的实现细节解释：

1. **`glob(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *pglob)`:**
   - **初始化:**  初始化 `glob_t` 结构体，设置标志位，并处理 `GLOB_APPEND` 的情况。
   - **模式转换:** 将输入的 `char*` 类型的模式转换为内部使用的 `Char*` 类型（宽字符），并处理转义字符。如果设置了 `GLOB_BRACE`，则会先调用 `globexp0` 处理花括号展开。否则，调用 `glob0` 进行基本的通配符匹配。
   - **错误处理:**  如果模式过长，返回 `GLOB_NOSPACE`。

2. **`globexp0(const Char *pattern, glob_t *pglob, struct glob_limit *limit, const char *origpat)`， `globexp1`， `globexp2`:**
   - **花括号展开:**  这些函数递归地处理花括号表达式。`globexp1` 查找模式中的第一个 `{`，然后 `globexp2` 负责解析和展开该花括号内的内容。例如，对于模式 `{a,b}{1,2}`，它会先展开 `{a,b}`，生成 `a` 和 `b` 两个分支，然后分别将 `1,2` 应用到这两个分支，最终得到 `a1`, `a2`, `b1`, `b2`。
   - **递归调用:**  每次展开一个花括号项，都会构造新的模式，并递归调用 `globexp1` 或 `glob0` 来处理剩余的模式。
   - **限制:** 通过 `GLOB_LIMIT_BRACE` 限制花括号展开的层数，防止无限递归导致的拒绝服务攻击。

3. **`globtilde(const Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)`:**
   - **틸트展开:**  如果模式以 `~` 开头且设置了 `GLOB_TILDE` 标志，则尝试进行틸트展开。
   - **查找用户信息:** 如果是 `~` 或 `~/`，则尝试获取环境变量 `HOME`，或者通过 `getlogin()` 或 `getpwuid()` 获取当前用户的主目录。如果是 `~username/`，则通过 `getpwnam()` 获取指定用户的主目录。
   - **路径替换:** 将틸트部分替换为用户的主目录。
   - **错误处理:** 如果找不到用户信息或缓冲区溢出，则返回错误。

4. **`glob0(const Char *pattern, glob_t *pglob, struct glob_limit *limit, const char *origpat)`:**
   - **核心匹配逻辑:** 这是处理基本通配符的核心函数。
   - **模式预处理:** 将通配符转换为内部表示，例如 `*` 转换为 `M_ALL`，`?` 转换为 `M_ONE`，`[...]` 转换为 `M_SET` 等。
   - **调用 `glob1`:**  将预处理后的模式传递给 `glob1` 进行实际的文件系统搜索。

5. **`glob1(Char *pattern, glob_t *pglob, struct glob_limit *limit)`， `glob2`， `glob3`:**
   - **目录遍历:** 这些函数共同实现了递归的目录遍历和模式匹配。
   - **`glob1`:** 作为入口，获取初始路径。
   - **`glob2`:** 遍历模式中的每个路径段。如果当前段没有通配符，则直接添加到路径缓冲区，并继续处理下一个段。如果遇到包含通配符的段，则调用 `glob3` 进行匹配。
   - **`glob3`:**  打开当前路径对应的目录，并使用 `readdir` 读取目录项。然后，调用 `match` 函数将每个目录项与模式的当前部分进行匹配。如果匹配成功，则递归调用 `glob2` 处理剩余的模式。
   - **`g_opendir`， `g_lstat`， `g_stat`:** 这些是封装了标准 `opendir`， `lstat` 和 `stat` 的函数，允许通过 `GLOB_ALTDIRFUNC` 使用自定义的实现。

6. **`globextend(const Char *path, glob_t *pglob, struct glob_limit *limit, const char *origpat)`:**
   - **结果存储:**  当找到一个匹配项时，此函数负责将其添加到 `glob_t` 结构体的 `gl_pathv` 数组中。
   - **内存管理:** 使用 `reallocarray` 动态地扩展 `gl_pathv` 数组。
   - **字符串复制:** 将匹配到的路径名复制到新分配的内存中。
   - **限制:**  检查是否超过了 `GLOB_LIMIT` 限制。

7. **`match(Char *name, Char *pat, Char *patend)`:**
   - **模式匹配算法:**  实现具体的通配符匹配逻辑。
   - **逐字符比较:**  比较文件名中的字符和模式中的字符，处理 `*`， `?`， `[]` 等通配符。

8. **`globfree(glob_t *pglob)`:**
   - **资源释放:** 释放 `glob()` 函数分配的内存，包括 `gl_pathv` 数组及其指向的字符串。

**涉及 dynamic linker 的功能**

`glob.c` 本身并没有直接涉及 dynamic linker 的功能。它的主要职责是文件路径名匹配，不涉及到动态链接库的加载和链接过程。

但是，`glob()` 函数作为 libc 的一部分，会被许多动态链接的程序所使用。当一个程序调用 `glob()` 时，它会链接到 `libc.so` 这个共享对象。

**so 布局样本:**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text          # 包含 glob() 等函数的代码
    .data          # 包含全局变量
    .bss           # 包含未初始化的全局变量
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表
    .got           # 全局偏移表
    ...
```

**链接的处理过程:**

1. **编译时:**  当程序编译链接时，链接器 (如 `lld`) 会在程序的可执行文件中记录下对 `libc.so` 中 `glob()` 函数的依赖。这通常通过 `.dynsym` 和 `.dynstr` 表来实现，记录了所需的符号（如 `glob`）。

2. **加载时:**  当程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责加载程序依赖的共享对象，包括 `libc.so`。

3. **符号解析:** 动态链接器会解析程序中对 `glob()` 函数的引用，将其与 `libc.so` 中 `glob()` 函数的实际地址关联起来。这通常涉及到查找 `.dynsym` 表。

4. **重定位:**  动态链接器会修改程序中的指令，将对 `glob()` 函数的引用指向其在 `libc.so` 中的加载地址。这通常涉及到 `.plt` 和 `.got` 表。`.plt` 中的条目会跳转到 `.got` 中存储的 `glob()` 的地址，而 `.got` 的初始值会在动态链接时被填充。

**假设输入与输出 (逻辑推理)**

假设我们有以下文件和目录结构：

```
.
├── a.txt
├── b.txt
├── c.log
└── dir
    ├── d.txt
    └── e.txt
```

**假设输入与输出:**

1. **输入模式:** `"*.txt"`
   - **输出:** `"a.txt"`, `"b.txt"` (顺序可能不同，取决于是否设置了 `GLOB_NOSORT`)

2. **输入模式:** `"?.txt"`
   - **输出:** `"a.txt"`, `"b.txt"`

3. **输入模式:** `"*.?"`
   - **输出:** `"a.txt"`, `"b.txt"`, `"c.log"`

4. **输入模式:** `"dir/*"`
   - **输出:** `"dir/d.txt"`, `"dir/e.txt"`

5. **输入模式:** `"[!ab]*.txt"`
   - **输出:** (无匹配)

6. **输入模式:** `"*.{txt,log}"` (如果设置了 `GLOB_BRACE`)
   - **输出:** `"a.txt"`, `"b.txt"`, `"c.log"`

**用户或编程常见的使用错误**

1. **忘记调用 `globfree()`:** `glob()` 函数会动态分配内存来存储匹配到的路径名。如果在使用完 `glob_t` 结构体后忘记调用 `globfree()`，会导致内存泄漏。

   ```c
   glob_t globbuf;
   glob("*.txt", 0, NULL, &globbuf);
   // ... 使用 globbuf.gl_pathv ...
   // 忘记调用 globfree(&globbuf); // 错误！
   ```

2. **不正确的通配符使用:** 对通配符的含义理解不准确，导致无法匹配到预期的文件。例如，认为 `*.txt*` 只匹配以 `.txt` 结尾的文件，但实际上它会匹配包含 `.txt` 的任何文件。

3. **缓冲区溢出风险 (旧版本或不当使用):**  虽然现代的 `glob()` 实现通常会动态分配内存，但在某些情况下，如果模式或匹配到的路径名过长，可能会导致缓冲区溢出。正确使用 `glob_t` 结构体和检查错误返回值可以避免这个问题。

4. **假设结果顺序:**  除非设置了 `GLOB_NOSORT`，否则 `glob()` 的结果通常是排序的。但是，依赖特定的排序顺序可能不是一个好主意，因为不同的实现或文件系统可能会有不同的排序规则。

5. **错误处理不当:**  `glob()` 函数会返回不同的错误代码。没有正确检查返回值并处理错误情况可能导致程序行为异常。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   - Android Framework 中的一些 API，例如 `java.io.File.listFiles(FilenameFilter)`，虽然没有直接使用 `glob()`，但其底层的实现可能会涉及到文件系统的遍历和模式匹配。
   - 某些系统服务或应用可能会通过 JNI (Java Native Interface) 调用 NDK 提供的 C/C++ 代码，然后在 C/C++ 代码中调用 `glob()`。

2. **Android NDK (C/C++ 层):**
   - NDK 提供了标准的 C 库，其中包括 `glob()` 函数。
   - 开发者在编写原生 Android 应用或库时，可以直接包含 `<glob.h>` 头文件并调用 `glob()` 函数。

**Frida Hook 示例**

可以使用 Frida Hook 来观察 `glob()` 函数的调用过程和参数：

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "glob"), {
    onEnter: function(args) {
        var pattern = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        console.log("[*] glob() called");
        console.log("    pattern: " + pattern);
        console.log("    flags: " + flags);
        this.globbuf = ptr(args[3]);
    },
    onLeave: function(retval) {
        console.log("    retval: " + retval);
        if (retval == 0) {
            var globbuf = this.globbuf;
            var pathc = globbuf.readUSize(); // gl_pathc 的偏移可能需要调整
            var pathv = globbuf.add(Process.pointerSize).readPointer(); // gl_pathv 的偏移可能需要调整
            console.log("    Matches:");
            for (var i = 0; i < pathc; i++) {
                var path = pathv.add(i * Process.pointerSize).readPointer();
                console.log("        " + Memory.readUtf8String(path));
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**Frida Hook 示例说明:**

1. **附加进程:**  首先，使用 Frida 连接到目标 Android 应用程序的进程。
2. **查找 `glob` 函数:** 使用 `Module.findExportByName` 找到 `libc.so` 中 `glob` 函数的地址。
3. **`onEnter` Hook:** 在 `glob()` 函数被调用时执行：
   - 读取并打印 `pattern` 参数（模式字符串）。
   - 读取并打印 `flags` 参数（标志位）。
   - 保存 `glob_t` 结构体的指针，以便在 `onLeave` 中访问。
4. **`onLeave` Hook:** 在 `glob()` 函数执行完毕后执行：
   - 打印返回值。
   - 如果返回值表示成功（0），则读取 `glob_t` 结构体中的 `gl_pathc` (匹配到的路径数量) 和 `gl_pathv` (指向路径名数组的指针)。
   - 遍历 `gl_pathv` 数组，打印每个匹配到的路径名。

通过这个 Frida Hook，你可以实时观察 Android 应用程序中 `glob()` 函数的调用情况，包括传递的模式、标志位以及最终匹配到的文件列表，从而帮助调试和理解文件系统相关的操作。

希望以上详细的解释能够帮助你理解 `bionic/libc/upstream-freebsd/lib/libc/gen/glob.c` 文件的功能和实现细节。

Prompt: 
```
这是目录为bionic/libc/upstream-freebsd/lib/libc/gen/glob.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
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
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)glob.c	8.3 (Berkeley) 10/13/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/lib/libc/gen/glob.c 317913 2017-05-07 19:52:56Z jilles $");

/*
 * glob(3) -- a superset of the one defined in POSIX 1003.2.
 *
 * The [!...] convention to negate a range is supported (SysV, Posix, ksh).
 *
 * Optional extra services, controlled by flags not defined by POSIX:
 *
 * GLOB_QUOTE:
 *	Escaping convention: \ inhibits any special meaning the following
 *	character might have (except \ at end of string is retained).
 * GLOB_MAGCHAR:
 *	Set in gl_flags if pattern contained a globbing character.
 * GLOB_NOMAGIC:
 *	Same as GLOB_NOCHECK, but it will only append pattern if it did
 *	not contain any magic characters.  [Used in csh style globbing]
 * GLOB_ALTDIRFUNC:
 *	Use alternately specified directory access functions.
 * GLOB_TILDE:
 *	expand ~user/foo to the /home/dir/of/user/foo
 * GLOB_BRACE:
 *	expand {1,2}{a,b} to 1a 1b 2a 2b
 * gl_matchc:
 *	Number of matches in the current invocation of glob.
 */

/*
 * Some notes on multibyte character support:
 * 1. Patterns with illegal byte sequences match nothing - even if
 *    GLOB_NOCHECK is specified.
 * 2. Illegal byte sequences in filenames are handled by treating them as
 *    single-byte characters with a values of such bytes of the sequence
 *    cast to wchar_t.
 * 3. State-dependent encodings are not currently supported.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include "collate.h"

/*
 * glob(3) expansion limits. Stop the expansion if any of these limits
 * is reached. This caps the runtime in the face of DoS attacks. See
 * also CVE-2010-2632
 */
#define	GLOB_LIMIT_BRACE	128	/* number of brace calls */
#define	GLOB_LIMIT_PATH		65536	/* number of path elements */
#define	GLOB_LIMIT_READDIR	16384	/* number of readdirs */
#define	GLOB_LIMIT_STAT		1024	/* number of stat system calls */
#define	GLOB_LIMIT_STRING	ARG_MAX	/* maximum total size for paths */

struct glob_limit {
	size_t	l_brace_cnt;
	size_t	l_path_lim;
	size_t	l_readdir_cnt;	
	size_t	l_stat_cnt;	
	size_t	l_string_cnt;
};

#define	DOT		L'.'
#define	EOS		L'\0'
#define	LBRACKET	L'['
#define	NOT		L'!'
#define	QUESTION	L'?'
#define	QUOTE		L'\\'
#define	RANGE		L'-'
#define	RBRACKET	L']'
#define	SEP		L'/'
#define	STAR		L'*'
#define	TILDE		L'~'
#define	LBRACE		L'{'
#define	RBRACE		L'}'
#define	COMMA		L','

#define	M_QUOTE		0x8000000000ULL
#define	M_PROTECT	0x4000000000ULL
#define	M_MASK		0xffffffffffULL
#define	M_CHAR		0x00ffffffffULL

typedef uint_fast64_t Char;

#define	CHAR(c)		((Char)((c)&M_CHAR))
#define	META(c)		((Char)((c)|M_QUOTE))
#define	UNPROT(c)	((c) & ~M_PROTECT)
#define	M_ALL		META(L'*')
#define	M_END		META(L']')
#define	M_NOT		META(L'!')
#define	M_ONE		META(L'?')
#define	M_RNG		META(L'-')
#define	M_SET		META(L'[')
#define	ismeta(c)	(((c)&M_QUOTE) != 0)
#ifdef DEBUG
#define	isprot(c)	(((c)&M_PROTECT) != 0)
#endif

static int	 compare(const void *, const void *);
static int	 g_Ctoc(const Char *, char *, size_t);
static int	 g_lstat(Char *, struct stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static const Char *g_strchr(const Char *, wchar_t);
#ifdef notdef
static Char	*g_strcat(Char *, const Char *);
#endif
static int	 g_stat(Char *, struct stat *, glob_t *);
static int	 glob0(const Char *, glob_t *, struct glob_limit *,
    const char *);
static int	 glob1(Char *, glob_t *, struct glob_limit *);
static int	 glob2(Char *, Char *, Char *, Char *, glob_t *,
    struct glob_limit *);
static int	 glob3(Char *, Char *, Char *, Char *, Char *, glob_t *,
    struct glob_limit *);
static int	 globextend(const Char *, glob_t *, struct glob_limit *,
    const char *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static int	 globexp0(const Char *, glob_t *, struct glob_limit *,
    const char *);
static int	 globexp1(const Char *, glob_t *, struct glob_limit *);
static int	 globexp2(const Char *, const Char *, glob_t *,
    struct glob_limit *);
static int	 globfinal(glob_t *, struct glob_limit *, size_t,
    const char *);
static int	 match(Char *, Char *, Char *);
static int	 err_nomatch(glob_t *, struct glob_limit *, const char *);
static int	 err_aborted(glob_t *, int, char *);
#ifdef DEBUG
static void	 qprintf(const char *, Char *);
#endif

int
glob(const char * __restrict pattern, int flags,
	 int (*errfunc)(const char *, int), glob_t * __restrict pglob)
{
	struct glob_limit limit = { 0, 0, 0, 0, 0 };
	const char *patnext;
	Char *bufnext, *bufend, patbuf[MAXPATHLEN], prot;
	mbstate_t mbs;
	wchar_t wc;
	size_t clen;
	int too_long;

	patnext = pattern;
	if (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		if (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	if (flags & GLOB_LIMIT) {
		limit.l_path_lim = pglob->gl_matchc;
		if (limit.l_path_lim == 0)
			limit.l_path_lim = GLOB_LIMIT_PATH;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	bufnext = patbuf;
	bufend = bufnext + MAXPATHLEN - 1;
	too_long = 1;
	if (flags & GLOB_NOESCAPE) {
		memset(&mbs, 0, sizeof(mbs));
		while (bufnext <= bufend) {
			clen = mbrtowc(&wc, patnext, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2)
				return (err_nomatch(pglob, &limit, pattern));
			else if (clen == 0) {
				too_long = 0;
				break;
			}
			*bufnext++ = wc;
			patnext += clen;
		}
	} else {
		/* Protect the quoted characters. */
		memset(&mbs, 0, sizeof(mbs));
		while (bufnext <= bufend) {
			if (*patnext == '\\') {
				if (*++patnext == '\0') {
					*bufnext++ = QUOTE;
					continue;
				}
				prot = M_PROTECT;
			} else
				prot = 0;
			clen = mbrtowc(&wc, patnext, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2)
				return (err_nomatch(pglob, &limit, pattern));
			else if (clen == 0) {
				too_long = 0;
				break;
			}
			*bufnext++ = wc | prot;
			patnext += clen;
		}
	}
	if (too_long)
		return (err_nomatch(pglob, &limit, pattern));
	*bufnext = EOS;

	if (flags & GLOB_BRACE)
	    return (globexp0(patbuf, pglob, &limit, pattern));
	else
	    return (glob0(patbuf, pglob, &limit, pattern));
}

static int
globexp0(const Char *pattern, glob_t *pglob, struct glob_limit *limit,
    const char *origpat) {
	int rv;
	size_t oldpathc;

	/* Protect a single {}, for find(1), like csh */
	if (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS) {
		if ((pglob->gl_flags & GLOB_LIMIT) &&
		    limit->l_brace_cnt++ >= GLOB_LIMIT_BRACE) {
			errno = E2BIG;
			return (GLOB_NOSPACE);
		}
		return (glob0(pattern, pglob, limit, origpat));
	}

	oldpathc = pglob->gl_pathc;

	if ((rv = globexp1(pattern, pglob, limit)) != 0)
		return rv;

	return (globfinal(pglob, limit, oldpathc, origpat));
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static int
globexp1(const Char *pattern, glob_t *pglob, struct glob_limit *limit)
{
	const Char* ptr;

	if ((ptr = g_strchr(pattern, LBRACE)) != NULL) {
		if ((pglob->gl_flags & GLOB_LIMIT) &&
		    limit->l_brace_cnt++ >= GLOB_LIMIT_BRACE) {
			errno = E2BIG;
			return (GLOB_NOSPACE);
		}
		return (globexp2(ptr, pattern, pglob, limit));
	}

	return (glob0(pattern, pglob, limit, NULL));
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static int
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    struct glob_limit *limit)
{
	int     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pm1, *pl;
	Char    patbuf[MAXPATHLEN];

	/* copy part up to the brace */
	for (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		continue;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	for (i = 0, pe = ++ptr; *pe != EOS; pe++)
		if (*pe == LBRACKET) {
			/* Ignore everything between [] */
			for (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				continue;
			if (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		}
		else if (*pe == LBRACE)
			i++;
		else if (*pe == RBRACE) {
			if (i == 0)
				break;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	if (i != 0 || *pe == EOS)
		return (glob0(pattern, pglob, limit, NULL));

	for (i = 0, pl = pm = ptr; pm <= pe; pm++)
		switch (*pm) {
		case LBRACKET:
			/* Ignore everything between [] */
			for (pm1 = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				continue;
			if (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pm1;
			}
			break;

		case LBRACE:
			i++;
			break;

		case RBRACE:
			if (i) {
			    i--;
			    break;
			}
			/* FALLTHROUGH */
		case COMMA:
			if (i && *pm == COMMA)
				break;
			else {
				/* Append the current string */
				for (lm = ls; (pl < pm); *lm++ = *pl++)
					continue;
				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				for (pl = pe + 1; (*lm++ = *pl++) != EOS;)
					continue;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limit);
				if (rv)
					return (rv);

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			break;

		default:
			break;
		}
	return (0);
}



/*
 * expand tilde from the passwd file.
 */
static const Char *
globtilde(const Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	struct passwd *pwd;
	char *h, *sc;
	const Char *p;
	Char *b, *eb;
	wchar_t wc;
	wchar_t wbuf[MAXPATHLEN];
	wchar_t *wbufend, *dc;
	size_t clen;
	mbstate_t mbs;
	int too_long;

	if (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		return (pattern);

	/* 
	 * Copy up to the end of the string or / 
	 */
	eb = &patbuf[patbuf_len - 1];
	for (p = pattern + 1, b = patbuf;
	    b < eb && *p != EOS && UNPROT(*p) != SEP; *b++ = *p++)
		continue;

	if (*p != EOS && UNPROT(*p) != SEP)
		return (NULL);

	*b = EOS;
	h = NULL;

	if (patbuf[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME first (iff
		 * we're not running setuid or setgid) and then trying
		 * the password file
		 */
		if (issetugid() != 0 ||
		    (h = getenv("HOME")) == NULL) {
			if (((h = getlogin()) != NULL &&
			     (pwd = getpwnam(h)) != NULL) ||
			    (pwd = getpwuid(getuid())) != NULL)
				h = pwd->pw_dir;
			else
				return (pattern);
		}
	}
	else {
		/*
		 * Expand a ~user
		 */
		if (g_Ctoc(patbuf, (char *)wbuf, sizeof(wbuf)))
			return (NULL);
		if ((pwd = getpwnam((char *)wbuf)) == NULL)
			return (pattern);
		else
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	dc = wbuf;
	sc = h;
	wbufend = wbuf + MAXPATHLEN - 1;
	too_long = 1;
	memset(&mbs, 0, sizeof(mbs));
	while (dc <= wbufend) {
		clen = mbrtowc(&wc, sc, MB_LEN_MAX, &mbs);
		if (clen == (size_t)-1 || clen == (size_t)-2) {
			/* XXX See initial comment #2. */
			wc = (unsigned char)*sc;
			clen = 1;
			memset(&mbs, 0, sizeof(mbs));
		}
		if ((*dc++ = wc) == EOS) {
			too_long = 0;
			break;
		}
		sc += clen;
	}
	if (too_long)
		return (NULL);

	dc = wbuf;
	for (b = patbuf; b < eb && *dc != EOS; *b++ = *dc++ | M_PROTECT)
		continue;
	if (*dc != EOS)
		return (NULL);

	/* Append the rest of the pattern */
	if (*p != EOS) {
		too_long = 1;
		while (b <= eb) {
			if ((*b++ = *p++) == EOS) {
				too_long = 0;
				break;
			}
		}
		if (too_long)
			return (NULL);
	} else
		*b = EOS;

	return (patbuf);
}


/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.
 */
static int
glob0(const Char *pattern, glob_t *pglob, struct glob_limit *limit,
    const char *origpat) {
	const Char *qpatnext;
	int err;
	size_t oldpathc;
	Char *bufnext, c, patbuf[MAXPATHLEN];

	qpatnext = globtilde(pattern, patbuf, MAXPATHLEN, pglob);
	if (qpatnext == NULL) {
		errno = E2BIG;
		return (GLOB_NOSPACE);
	}
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	while ((c = *qpatnext++) != EOS) {
		switch (c) {
		case LBRACKET:
			c = *qpatnext;
			if (c == NOT)
				++qpatnext;
			if (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				if (c == NOT)
					--qpatnext;
				break;
			}
			*bufnext++ = M_SET;
			if (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				*bufnext++ = CHAR(c);
				if (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} while ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			break;
		case QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			break;
		case STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to ensure "**" at the end continues to match the
			 * empty string
			 */
			if (bufnext == patbuf || bufnext[-1] != M_ALL)
			    *bufnext++ = M_ALL;
			break;
		default:
			*bufnext++ = CHAR(c);
			break;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	if ((err = glob1(patbuf, pglob, limit)) != 0)
		return(err);

	if (origpat != NULL)
		return (globfinal(pglob, limit, oldpathc, origpat));

	return (0);
}

static int
globfinal(glob_t *pglob, struct glob_limit *limit, size_t oldpathc,
    const char *origpat) {
	if (pglob->gl_pathc == oldpathc)
		return (err_nomatch(pglob, limit, origpat));

	if (!(pglob->gl_flags & GLOB_NOSORT))
		qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
		    pglob->gl_pathc - oldpathc, sizeof(char *), compare);

	return (0);
}

static int
compare(const void *p, const void *q)
{
	return (strcoll(*(char **)p, *(char **)q));
}

static int
glob1(Char *pattern, glob_t *pglob, struct glob_limit *limit)
{
	Char pathbuf[MAXPATHLEN];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	if (*pattern == EOS)
		return (0);
	return (glob2(pathbuf, pathbuf, pathbuf + MAXPATHLEN - 1,
	    pattern, pglob, limit));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static int
glob2(Char *pathbuf, Char *pathend, Char *pathend_last, Char *pattern,
      glob_t *pglob, struct glob_limit *limit)
{
	struct stat sb;
	Char *p, *q;
	int anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	for (anymeta = 0;;) {
		if (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;
			if (g_lstat(pathbuf, &sb, pglob))
				return (0);

			if ((pglob->gl_flags & GLOB_LIMIT) &&
			    limit->l_stat_cnt++ >= GLOB_LIMIT_STAT) {
				errno = E2BIG;
				return (GLOB_NOSPACE);
			}
			if ((pglob->gl_flags & GLOB_MARK) &&
			    UNPROT(pathend[-1]) != SEP &&
			    (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    g_stat(pathbuf, &sb, pglob) == 0 &&
			    S_ISDIR(sb.st_mode)))) {
				if (pathend + 1 > pathend_last) {
					errno = E2BIG;
					return (GLOB_NOSPACE);
				}
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			return (globextend(pathbuf, pglob, limit, NULL));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		while (*p != EOS && UNPROT(*p) != SEP) {
			if (ismeta(*p))
				anymeta = 1;
			if (q + 1 > pathend_last) {
				errno = E2BIG;
				return (GLOB_NOSPACE);
			}
			*q++ = *p++;
		}

		if (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			while (UNPROT(*pattern) == SEP) {
				if (pathend + 1 > pathend_last) {
					errno = E2BIG;
					return (GLOB_NOSPACE);
				}
				*pathend++ = *pattern++;
			}
		} else			/* Need expansion, recurse. */
			return (glob3(pathbuf, pathend, pathend_last, pattern,
			    p, pglob, limit));
	}
	/* NOTREACHED */
}

static int
glob3(Char *pathbuf, Char *pathend, Char *pathend_last,
      Char *pattern, Char *restpattern,
      glob_t *pglob, struct glob_limit *limit)
{
	struct dirent *dp;
	DIR *dirp;
	int err, too_long, saverrno, saverrno2;
	char buf[MAXPATHLEN + MB_LEN_MAX - 1];

	struct dirent *(*readdirfunc)(DIR *);

	if (pathend > pathend_last) {
		errno = E2BIG;
		return (GLOB_NOSPACE);
	}
	*pathend = EOS;
	if (pglob->gl_errfunc != NULL &&
	    g_Ctoc(pathbuf, buf, sizeof(buf))) {
		errno = E2BIG;
		return (GLOB_NOSPACE);
	}

	saverrno = errno;
	errno = 0;
	if ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		if (errno == ENOENT || errno == ENOTDIR)
			return (0);
		err = err_aborted(pglob, errno, buf);
		if (errno == 0)
			errno = saverrno;
		return (err);
	}

	err = 0;

	/* pglob->gl_readdir takes a void *, fix this manually */
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = (struct dirent *(*)(DIR *))pglob->gl_readdir;
	else
		readdirfunc = readdir;

	errno = 0;
	/* Search directory for matching names. */
	while ((dp = (*readdirfunc)(dirp)) != NULL) {
		char *sc;
		Char *dc;
		wchar_t wc;
		size_t clen;
		mbstate_t mbs;

		if ((pglob->gl_flags & GLOB_LIMIT) &&
		    limit->l_readdir_cnt++ >= GLOB_LIMIT_READDIR) {
			errno = E2BIG;
			err = GLOB_NOSPACE;
			break;
		}

		/* Initial DOT must be matched literally. */
		if (dp->d_name[0] == '.' && UNPROT(*pattern) != DOT) {
			errno = 0;
			continue;
		}
		memset(&mbs, 0, sizeof(mbs));
		dc = pathend;
		sc = dp->d_name;
		too_long = 1;
		while (dc <= pathend_last) {
			clen = mbrtowc(&wc, sc, MB_LEN_MAX, &mbs);
			if (clen == (size_t)-1 || clen == (size_t)-2) {
				/* XXX See initial comment #2. */
				wc = (unsigned char)*sc;
				clen = 1;
				memset(&mbs, 0, sizeof(mbs));
			}
			if ((*dc++ = wc) == EOS) {
				too_long = 0;
				break;
			}
			sc += clen;
		}
		if (too_long && (err = err_aborted(pglob, ENAMETOOLONG,
		    buf))) {
			errno = ENAMETOOLONG;
			break;
		}
		if (too_long || !match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			errno = 0;
			continue;
		}
		if (errno == 0)
			errno = saverrno;
		err = glob2(pathbuf, --dc, pathend_last, restpattern,
		    pglob, limit);
		if (err)
			break;
		errno = 0;
	}

	saverrno2 = errno;
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	else
		closedir(dirp);
	errno = saverrno2;

	if (err)
		return (err);

	if (dp == NULL && errno != 0 &&
	    (err = err_aborted(pglob, errno, buf)))
		return (err);

	if (errno == 0)
		errno = saverrno;
	return (0);
}


/*
 * Extend the gl_pathv member of a glob_t structure to accommodate a new item,
 * add the new item, and update gl_pathc.
 *
 * This assumes the BSD realloc, which only copies the block when its size
 * crosses a power-of-two boundary; for v7 realloc, this would cause quadratic
 * behavior.
 *
 * Return 0 if new item added, error code if memory couldn't be allocated.
 *
 * Invariant of the glob_t structure:
 *	Either gl_pathc is zero and gl_pathv is NULL; or gl_pathc > 0 and
 *	gl_pathv points to (gl_offs + gl_pathc + 1) items.
 */
static int
globextend(const Char *path, glob_t *pglob, struct glob_limit *limit,
    const char *origpat)
{
	char **pathv;
	size_t i, newn, len;
	char *copy;
	const Char *p;

	if ((pglob->gl_flags & GLOB_LIMIT) &&
	    pglob->gl_matchc > limit->l_path_lim) {
		errno = E2BIG;
		return (GLOB_NOSPACE);
	}

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	/* reallocarray(NULL, newn, size) is equivalent to malloc(newn*size). */
	pathv = reallocarray(pglob->gl_pathv, newn, sizeof(*pathv));
	if (pathv == NULL)
		return (GLOB_NOSPACE);

	if (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		for (i = pglob->gl_offs + 1; --i > 0; )
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	if (origpat != NULL)
		copy = strdup(origpat);
	else {
		for (p = path; *p++ != EOS;)
			continue;
		len = MB_CUR_MAX * (size_t)(p - path); /* XXX overallocation */
		if ((copy = malloc(len)) != NULL) {
			if (g_Ctoc(path, copy, len)) {
				free(copy);
				errno = E2BIG;
				return (GLOB_NOSPACE);
			}
		}
	}
	if (copy != NULL) {
		limit->l_string_cnt += strlen(copy) + 1;
		if ((pglob->gl_flags & GLOB_LIMIT) &&
		    limit->l_string_cnt >= GLOB_LIMIT_STRING) {
			free(copy);
			errno = E2BIG;
			return (GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;
	return (copy == NULL ? GLOB_NOSPACE : 0);
}

/*
 * pattern matching function for filenames.
 */
static int
match(Char *name, Char *pat, Char *patend)
{
	int ok, negate_range;
	Char c, k, *nextp, *nextn;
#if !defined(__BIONIC__)
	struct xlocale_collate *table =
		(struct xlocale_collate*)__get_locale()->components[XLC_COLLATE];
#endif

	nextn = NULL;
	nextp = NULL;

	while (1) {
		while (pat < patend) {
			c = *pat++;
			switch (c & M_MASK) {
			case M_ALL:
				if (pat == patend)
					return (1);
				if (*name == EOS)
					return (0);
				nextn = name + 1;
				nextp = pat - 1;
				break;
			case M_ONE:
				if (*name++ == EOS)
					goto fail;
				break;
			case M_SET:
				ok = 0;
				if ((k = *name++) == EOS)
					goto fail;
				negate_range = ((*pat & M_MASK) == M_NOT);
				if (negate_range != 0)
					++pat;
				while (((c = *pat++) & M_MASK) != M_END)
					if ((*pat & M_MASK) == M_RNG) {
#if defined(__BIONIC__)
						if (c <= k && k <= pat[1])
#else
						if (table->__collate_load_error ?
						    CHAR(c) <= CHAR(k) &&
						    CHAR(k) <= CHAR(pat[1]) :
						    __wcollate_range_cmp(CHAR(c),
						    CHAR(k)) <= 0 &&
						    __wcollate_range_cmp(CHAR(k),
						    CHAR(pat[1])) <= 0)
#endif
							ok = 1;
						pat += 2;
					} else if (c == k)
						ok = 1;
				if (ok == negate_range)
					goto fail;
				break;
			default:
				if (*name++ != c)
					goto fail;
				break;
			}
		}
		if (*name == EOS)
			return (1);

	fail:
		if (nextn == NULL)
			break;
		pat = nextp;
		name = nextn;
	}
	return (0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	char **pp;

	if (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		for (i = pglob->gl_pathc; i--; ++pp)
			if (*pp)
				free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
}

static DIR *
g_opendir(Char *str, glob_t *pglob)
{
	char buf[MAXPATHLEN + MB_LEN_MAX - 1];

	if (*str == EOS)
		strcpy(buf, ".");
	else {
		if (g_Ctoc(str, buf, sizeof(buf))) {
			errno = ENAMETOOLONG;
			return (NULL);
		}
	}

	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_opendir)(buf));

	return (opendir(buf));
}

static int
g_lstat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[MAXPATHLEN + MB_LEN_MAX - 1];

	if (g_Ctoc(fn, buf, sizeof(buf))) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return((*pglob->gl_lstat)(buf, sb));
	return (lstat(buf, sb));
}

static int
g_stat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[MAXPATHLEN + MB_LEN_MAX - 1];

	if (g_Ctoc(fn, buf, sizeof(buf))) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (pglob->gl_flags & GLOB_ALTDIRFUNC)
		return ((*pglob->gl_stat)(buf, sb));
	return (stat(buf, sb));
}

static const Char *
g_strchr(const Char *str, wchar_t ch)
{

	do {
		if (*str == ch)
			return (str);
	} while (*str++);
	return (NULL);
}

static int
g_Ctoc(const Char *str, char *buf, size_t len)
{
	mbstate_t mbs;
	size_t clen;

	memset(&mbs, 0, sizeof(mbs));
	while (len >= MB_CUR_MAX) {
		clen = wcrtomb(buf, CHAR(*str), &mbs);
		if (clen == (size_t)-1) {
			/* XXX See initial comment #2. */
			*buf = (char)CHAR(*str);
			clen = 1;
			memset(&mbs, 0, sizeof(mbs));
		}
		if (CHAR(*str) == EOS)
			return (0);
		str++;
		buf += clen;
		len -= clen;
	}
	return (1);
}

static int
err_nomatch(glob_t *pglob, struct glob_limit *limit, const char *origpat) {
	/*
	 * If there was no match we are going to append the origpat
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the origpat did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	if ((pglob->gl_flags & GLOB_NOCHECK) ||
	    ((pglob->gl_flags & GLOB_NOMAGIC) &&
	    !(pglob->gl_flags & GLOB_MAGCHAR)))
		return (globextend(NULL, pglob, limit, origpat));
	return (GLOB_NOMATCH);
}

static int
err_aborted(glob_t *pglob, int err, char *buf) {
	if ((pglob->gl_errfunc != NULL && pglob->gl_errfunc(buf, err)) ||
	    (pglob->gl_flags & GLOB_ERR))
		return (GLOB_ABORTED);
	return (0);
}

#ifdef DEBUG
static void
qprintf(const char *str, Char *s)
{
	Char *p;

	(void)printf("%s\n", str);
	if (s != NULL) {
		for (p = s; *p != EOS; p++)
			(void)printf("%c", (char)CHAR(*p));
		(void)printf("\n");
		for (p = s; *p != EOS; p++)
			(void)printf("%c", (isprot(*p) ? '\\' : ' '));
		(void)printf("\n");
		for (p = s; *p != EOS; p++)
			(void)printf("%c", (ismeta(*p) ? '_' : ' '));
		(void)printf("\n");
	}
}
#endif

"""

```