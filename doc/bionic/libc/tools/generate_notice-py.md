Response:
Let's break down the thought process for analyzing the `generate_notice.py` script.

**1. Understanding the Goal:**

The first step is to read the problem description and the script itself to grasp the core purpose. The description clearly states that the script processes source files in the Android Bionic library to extract copyright notices. The filename "generate_notice.py" is a strong indicator of its function.

**2. Initial Code Scan (High-Level):**

Quickly scan the main parts of the code:

* **Imports:**  `os`, `pathlib`, `re`, `sys`, `typing`. These suggest file system operations, regular expressions, and type hinting.
* **Global Variables:** `VERBOSE`, `copyrights`. `copyrights` stands out as a container to store the extracted information. `VERBOSE` likely controls output verbosity.
* **Functions:**  `warn`, `warn_verbose`, `is_interesting`, `is_copyright_end`, `extract_copyright_at`, `do_file`, `do_dir`, `main`. These represent the script's modular structure.
* **`main()` function:**  This is the entry point and controls the overall flow, processing arguments (directories or files).

**3. Analyzing Key Functions - Deductive Reasoning:**

Now, analyze the core functions to understand their individual roles and how they contribute to the main goal.

* **`is_interesting(path_str)`:** The name suggests filtering files. The code checks file extensions and names against a list of uninteresting items. This is a common practice to avoid processing irrelevant files (build scripts, documentation, etc.).

* **`is_copyright_end(line, first_line_was_hash)`:** This function tries to determine if a line marks the end of a copyright notice. It looks for specific keywords and patterns commonly found at the end of copyright headers in C/C++ files. The `first_line_was_hash` parameter hints at handling different copyright comment styles.

* **`extract_copyright_at(lines, i)`:** This is the heart of the copyright extraction logic. It assumes it's at a line containing "Copyright". It backtracks to find the start of the comment block (if necessary), then iterates forward until it finds an "end" marker using `is_copyright_end`. It then cleans up the extracted lines by removing comment markers. The use of `copyrights.add()` confirms the accumulation of extracted notices.

* **`do_file(path)`:** This function handles a single file. It reads the file, attempts to decode it as UTF-8 (with a fallback to ISO-8859-1), and then scans for "Copyright". If found, it uses `extract_copyright_at` to extract the notice. It includes warnings for missing copyright notices or short files.

* **`do_dir(arg)`:** This function recursively walks through a directory structure. It uses `os.walk` and filters out the `.git` directory. It calls `do_file` for each interesting file it finds.

* **`main()`:**  Handles command-line arguments. If no arguments are given, it defaults to the current directory. It iterates through the arguments, calling `do_dir` for directories and `do_file` for files. Finally, it prints the collected copyright notices.

**4. Connecting to Android Bionic:**

The problem statement explicitly mentions Android Bionic. The script resides within the Bionic source tree (`bionic/libc/tools/generate_notice.py`). This strongly implies that the script is used as part of the Bionic build process to collect copyright information for licensing or attribution purposes.

**5. Addressing Specific Questions:**

Now, specifically address the points raised in the prompt:

* **Functionality:**  Summarize the purpose of each key function.
* **Relationship to Android:** Explain how this script likely contributes to the overall Android build (creating NOTICE files, managing licensing information).
* **`libc` Function Details:** The script *doesn't* implement `libc` functions. It *processes* `libc` source code. This distinction is crucial. Clarify this point.
* **Dynamic Linker:**  Similar to `libc`, the script processes source code, which *may* include dynamic linker code. The script itself doesn't *perform* dynamic linking. Focus on how the extracted copyright notices might be used for licensing of the dynamic linker components. Provide a hypothetical SO layout and link processing example to demonstrate understanding of the *context* in which the script operates.
* **Logic Inference/Hypothetical Input/Output:**  Create simple examples of source files with copyright notices and demonstrate how the script would process them, showing the extracted output.
* **Common Usage Errors:** Think about how a user might misuse this script (e.g., running it on non-source code directories).
* **Android Framework/NDK Path:** Explain the likely chain of events during the Android build process where this script would be invoked. Mention build systems like Soong/Make.
* **Frida Hook Example:**  Provide a practical example of using Frida to intercept the `copyrights.add()` call to see what copyright notices are being extracted. This directly demonstrates debugging and understanding the script's behavior.

**6. Structuring the Answer:**

Organize the information logically with clear headings for each point in the prompt. Use code blocks and formatting to improve readability. Provide clear and concise explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the script *executes* some `libc` functions.
* **Correction:**  No, the script *analyzes* `libc` source code. The focus is on extracting copyright information, not executing code.

* **Initial thought:** The script directly interacts with the dynamic linker during runtime.
* **Correction:** The script likely runs during the build process, *before* runtime. It helps gather information *about* the dynamic linker's source code, not interacting with it at runtime.

By following this structured thought process, combining code analysis with domain knowledge (Android Bionic, build systems), and addressing each point in the prompt methodically, a comprehensive and accurate answer can be constructed.
好的，让我们来详细分析一下 `bionic/libc/tools/generate_notice.py` 这个 Python 脚本的功能和它在 Android Bionic 中的作用。

**脚本功能概览:**

`generate_notice.py` 的主要功能是**从指定的源代码目录中扫描并提取版权声明信息**。它会遍历目录下的所有文件，识别出符合版权声明格式的注释块，并将这些声明汇总起来。

**功能分解:**

1. **目录/文件遍历 (`do_dir`, `do_file`, `main`)**:
   - `main()` 函数是脚本的入口点，它接收命令行参数，这些参数通常是源代码目录的路径。如果未提供参数，则默认扫描当前目录。
   - `do_dir(arg)` 函数用于处理目录，它使用 `os.walk()` 递归地遍历目录及其子目录下的所有文件。它会跳过 `.git` 目录。
   - `do_file(path)` 函数用于处理单个文件。

2. **文件类型过滤 (`is_interesting`)**:
   - `is_interesting(path_str)` 函数用于判断一个文件是否需要被处理。它会检查文件的扩展名和文件名，排除一些已知的不包含版权声明或不相关的类型，例如 `.bp`, `.map`, `.md`, `.mk`, `.py`, `.txt`, `.xml` 等。 也会排除 `notice`, `readme`, `pylintrc` 这些文件名。

3. **读取文件内容 (`do_file`)**:
   - `do_file` 函数会读取文件的内容，首先尝试使用 UTF-8 编码解码，如果失败则尝试使用 ISO-8859-1 编码。

4. **查找版权声明 (`do_file`)**:
   - `do_file` 函数会在文件内容中搜索 "Copyright" 字符串来初步判断文件中是否包含版权声明。

5. **提取版权声明内容 (`extract_copyright_at`)**:
   - `extract_copyright_at(lines, i)` 函数是提取版权声明的核心逻辑。它接收文件的行列表 `lines` 和当前行号 `i` 作为输入。
   - 它会查找包含 "Copyright" 的行，并尝试识别版权声明块的起始和结束位置。
   - 它会处理 C 风格的 `/* ... */` 和单行注释 `#` 的版权声明格式。
   - `is_copyright_end(line, first_line_was_hash)` 函数用于判断当前行是否是版权声明的结束标记。它会检查一些常见的版权声明结束语，例如 `*/`, `$FreeBSD:`, `$OpenBSD:` 等。
   - 它会对提取到的版权声明文本进行清理，去除注释符号 (`/*`, `*`, `#`) 和一些不必要的空白。
   - 提取到的版权声明会被添加到全局集合 `copyrights` 中，以避免重复。

6. **输出版权声明 (`main`)**:
   - `main()` 函数在处理完所有文件后，会遍历 `copyrights` 集合，并将所有提取到的版权声明按照字母顺序打印到标准输出。每个版权声明之间会用分隔线隔开。

**与 Android 功能的关系及举例说明:**

这个脚本在 Android Bionic 中扮演着重要的角色，它主要用于**生成 NOTICE 文件**。NOTICE 文件通常包含项目中使用的第三方代码的版权声明和许可信息。Android 需要维护这些信息，以符合开源许可协议的要求。

**举例说明:**

假设 `bionic/libc/src/stdio/printf.c` 文件中包含以下版权声明：

```c
/*
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California. All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
```

当运行 `generate_notice.py bionic/libc/src/stdio/printf.c` 或 `generate_notice.py bionic/libc/src/stdio` 时，该脚本会扫描 `printf.c` 文件，识别出上述的版权声明，并将其添加到 `copyrights` 集合中。最终，运行脚本会输出类似以下的版权声明信息：

```
Copyright (c) 1990, 1993
	The Regents of the University of California. All rights reserved.

This code is derived from software contributed to Berkeley by
Chris Torek.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the University nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

-------------------------------------------------------------------
```

**详细解释每一个 libc 函数的功能是如何实现的:**

这个脚本本身**并没有实现任何 `libc` 函数的功能**。它的作用是分析 `libc` 的源代码，提取版权信息。`libc` 函数的实现逻辑是在 C 源代码中完成的，例如 `printf` 函数的实现涉及到格式化字符串、参数处理、输出到标准输出等步骤。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个脚本也**没有直接涉及 dynamic linker 的运行时功能**。它只是扫描源代码。然而，dynamic linker 的源代码中也会包含版权声明，该脚本可以提取这些声明。

**假设 dynamic linker 的一个源文件 `bionic/linker/linker.cpp` 中包含以下版权声明：**

```cpp
/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 */
```

当 `generate_notice.py` 扫描 `bionic/linker` 目录时，它会提取出上述版权声明。

**SO 布局样本 (针对 dynamic linker `linker64`):**

```
LOAD           0x000000733c770000  0x000000733c770000  0x0000000000000000  0x000000000001a000 R E 0x1000
LOAD           0x000000733c78a000  0x000000733c78a000  0x000000000001a000  0x0000000000002000 RW  0x1000
DYNAMIC        0x000000733c78a000  0x000000733c78a000  0x000000000001a000  0x00000000000001f0 d   0x8
INTERP         0x000000733c78a1a0  0x000000733c78a1a0  0x000000000001a1a0  0x000000000000001c s   0x1
GNU_HASH       0x000000733c770210  0x000000733c770210  0x0000000000000210  0x0000000000000024 w   0x4
STRTAB         0x000000733c770238  0x000000733c770238  0x0000000000000238  0x0000000000000675 a   0x8
SYMTAB         0x000000733c7708ac  0x000000733c7708ac  0x00000000000008ac  0x00000000000004c0 A   0x8
STRTAB         0x000000733c770d6c  0x000000733c770d6c  0x0000000000000d6c  0x0000000000000017 a   0x1
SYMTAB         0x000000733c770d84  0x000000733c770d84  0x0000000000000d84  0x0000000000000030 A   0x4
RELR           0x000000733c770db4  0x000000733c770db4  0x0000000000000db4  0x0000000000000060 r   0x8
RELRCOUNT      0x000000733c770018  0x000000733c770018  0x0000000000000018  0x0000000000000004 R   0x4
```

这是一个简化的 `linker64` 的段布局示例，显示了加载地址、内存权限等信息。

**链接的处理过程 (与本脚本无关，但简单说明):**

动态链接器在程序启动时负责加载程序依赖的共享库 (`.so` 文件)。这个过程包括：

1. **查找共享库:** 根据程序的依赖信息 (通常存储在 ELF 文件的 `DT_NEEDED` 条目中)，在预定义的路径 (如 `/system/lib64`, `/vendor/lib64` 等) 中查找所需的共享库。
2. **加载共享库:** 将共享库的代码和数据段加载到内存中。
3. **符号解析 (Symbol Resolution):**  解析程序和共享库之间的符号引用关系，找到函数和变量的实际地址。
4. **重定位 (Relocation):**  由于共享库可能被加载到不同的内存地址，需要修改代码和数据中的绝对地址引用，使其指向正确的地址。
5. **执行初始化代码:** 运行共享库的初始化函数 (`.init` 和 `.init_array` 段中的代码)。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入 (一个简单的 C 文件 `test.c`):**

```c
/*
 * Copyright (C) 2023 My Company
 * All rights reserved.
 */

#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

**运行命令:** `python3 generate_notice.py test.c`

**假设输出:**

```
Copyright (C) 2023 My Company
All rights reserved.

-------------------------------------------------------------------
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限问题:** 用户可能没有读取目标源代码目录或文件的权限，导致脚本无法访问并报错。
2. **编码问题:**  如果源代码文件使用了非 UTF-8 或 ISO-8859-1 的编码，脚本可能会解码失败，导致提取的版权信息乱码或无法提取。虽然脚本尝试了两种编码，但并不保证覆盖所有情况。
3. **不规范的版权声明格式:** 如果源代码中的版权声明格式不符合脚本预期的模式 (例如，使用了不常见的注释风格或结束标记)，脚本可能无法正确识别和提取。
4. **误用命令行参数:** 用户可能传递了错误的目录或文件路径作为参数，导致脚本找不到目标文件。
5. **依赖缺失:**  虽然这个脚本依赖的库很少 (主要是 Python 内置库)，但在某些极端情况下，如果 Python 环境不完整，可能会出现 `import` 错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`generate_notice.py` 通常不是 Android Framework 或 NDK 在运行时直接调用的。它更像是一个**构建时工具**。

**步骤说明:**

1. **Android 构建系统 (Soong/Make):**  在 Android 系统的构建过程中，构建系统 (例如 Soong 或 Make) 会解析 `Android.bp` 或 `Android.mk` 文件，这些文件定义了如何编译和链接 Bionic 库。
2. **定义构建规则:** 在 Bionic 的构建规则中，可能会定义一个步骤来生成 NOTICE 文件。这个步骤会调用 `generate_notice.py` 脚本。
3. **执行脚本:** 构建系统会执行 `generate_notice.py`，并将 Bionic 的源代码目录作为参数传递给它。
4. **生成 NOTICE 文件:** `generate_notice.py` 扫描源代码，提取版权声明，并将结果输出到标准输出。构建系统会将这个输出重定向到一个文件中，通常命名为 `NOTICE` 或 `NOTICE.txt`。
5. **集成到最终镜像:** 生成的 NOTICE 文件会被包含到最终的 Android 系统镜像中。

**NDK 的关系:**

NDK (Native Development Kit) 用于开发 Android 平台的原生应用程序。NDK 也会依赖 Bionic 库。当使用 NDK 构建原生应用程序时，链接器会将应用程序与 Bionic 库链接起来。Bionic 库的 NOTICE 文件信息对于使用 NDK 开发的应用程序也适用，因为它涉及到 Bionic 库的许可信息。

**Frida Hook 示例:**

要使用 Frida Hook 调试 `generate_notice.py` 的执行过程，我们可以 Hook 脚本中关键的函数调用，例如 `copyrights.add()`，来观察提取到的版权信息。

**Frida Hook 代码 (假设脚本在名为 `generate_notice.py` 的文件中运行):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Extracted Copyright: {message['payload']}")
    else:
        print(message)

session = frida.spawn(["python3", "generate_notice.py", "bionic/libc"], on_message=on_message, stdio='pipe')
script = session.create_script("""
console.log("Script loaded");

const set_add = Module.findExportByName(null, '_ZNSt3setISsSt4lessISsESaISsEE3addERKSsE'); // This is highly platform-dependent and may not work directly

if (set_add) {
    Interceptor.attach(set_add, {
        onEnter: function(args) {
            console.log("Adding copyright:", Memory.readUtf8String(args[1]));
            send(Memory.readUtf8String(args[1]));
        }
    });
} else {
    console.log("Warning: Could not find the set::add method. Hooking the copyrights global variable might be more reliable but complex.");
    // A more robust but complex approach would involve finding and hooking the assignment to the 'copyrights' global variable.
}
""")
script.load()
sys.stdin.read()
```

**说明:**

1. **`frida.spawn()`:**  使用 Frida 启动一个新的进程来运行 `generate_notice.py`，并将 `bionic/libc` 作为参数传递给它。
2. **`on_message()`:**  定义一个消息处理函数，用于接收脚本中通过 `send()` 发送的消息。
3. **`session.create_script()`:** 创建一个 Frida 脚本。
4. **查找 `set::add` 方法:**  尝试查找 `std::set::add` 方法的符号。**请注意，这个符号名称在不同的编译器和标准库实现中可能会有所不同，因此这个方法可能需要根据实际情况进行调整。**
5. **Hook `set::add`:** 如果找到了 `set::add` 方法，则使用 `Interceptor.attach()` Hook 该方法。
6. **`onEnter()`:**  在 `set::add` 方法被调用时执行。`args[1]` 通常指向要添加到 set 中的元素 (即版权声明字符串)。我们读取这个字符串并使用 `send()` 函数发送到 Frida 主进程。
7. **`send()`:**  将版权声明字符串发送回 Frida 主进程，`on_message()` 函数会打印出来。

**更可靠的 Hook 方式 (更复杂):**

由于直接 Hook 标准库的实现细节可能不可靠，更可靠的方法是直接 Hook Python 脚本本身对 `copyrights` 集合的 `add()` 方法调用。但这需要理解 Python 的对象模型和 Frida 的 Python API，可能更复杂。

**总结:**

`generate_notice.py` 是一个用于提取源代码版权声明的构建时工具，对于维护 Android Bionic 的许可信息至关重要。它不直接参与 `libc` 函数的实现或 dynamic linker 的运行时行为，但会处理它们的源代码，提取相关的版权信息。使用 Frida 可以 Hook 脚本的执行过程，观察其如何提取版权声明。

### 提示词
```
这是目录为bionic/libc/tools/generate_notice.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```python
#!/usr/bin/env python3
# Run with directory arguments from any directory, with no special setup
# required.

import os
from pathlib import Path
import re
import sys
from typing import Sequence

VERBOSE = False

copyrights = set()


def warn(s):
    sys.stderr.write("warning: %s\n" % s)


def warn_verbose(s):
    if VERBOSE:
        warn(s)


def is_interesting(path_str: str) -> bool:
    path = Path(path_str.lower())
    uninteresting_extensions = [
        ".bp",
        ".map",
        ".md",
        ".mk",
        ".py",
        ".pyc",
        ".swp",
        ".txt",
        ".xml",
    ]
    if path.suffix in uninteresting_extensions:
        return False
    if path.name in {"notice", "readme", "pylintrc"}:
        return False
    # Backup files for some editors.
    if path.match("*~"):
        return False
    return True


def is_copyright_end(line: str, first_line_was_hash: bool) -> bool:
    endings = [
        " $FreeBSD: ",
        "$Citrus$",
        "$FreeBSD$",
        "*/",
        "From: @(#)",
        # OpenBSD likes to say where stuff originally came from:
        "Original version ID:",
        "\t$Citrus: ",
        "\t$NetBSD: ",
        "\t$OpenBSD: ",
        "\t@(#)",
        "\tcitrus Id: ",
        "\tfrom: @(#)",
        "from OpenBSD:",
    ]
    if first_line_was_hash and not line:
        return True

    for ending in endings:
        if ending in line:
            return True

    return False


def extract_copyright_at(lines: Sequence[str], i: int) -> int:
    first_line_was_hash = lines[i].startswith("#")

    # Do we need to back up to find the start of the copyright header?
    start = i
    if not first_line_was_hash:
        while start > 0:
            if "/*" in lines[start - 1]:
                break
            start -= 1

    # Read comment lines until we hit something that terminates a
    # copyright header.
    while i < len(lines):
        if is_copyright_end(lines[i], first_line_was_hash):
            break
        i += 1

    end = i

    # Trim trailing cruft.
    while end > 0:
        line = lines[end - 1]
        if line not in {
                " *", " * ===================================================="
        }:
            break
        end -= 1

    # Remove C/assembler comment formatting, pulling out just the text.
    clean_lines = []
    for line in lines[start:end]:
        line = line.replace("\t", "    ")
        line = line.replace("/* ", "")
        line = re.sub(r"^ \* ", "", line)
        line = line.replace("** ", "")
        line = line.replace("# ", "")
        if line.startswith("++Copyright++"):
            continue
        line = line.replace("--Copyright--", "")
        line = line.rstrip()
        # These come last and take care of "blank" comment lines.
        if line in {"#", " *", "**", "-"}:
            line = ""
        clean_lines.append(line)

    # Trim blank lines from head and tail.
    while clean_lines[0] == "":
        clean_lines = clean_lines[1:]
    while clean_lines[len(clean_lines) - 1] == "":
        clean_lines = clean_lines[0:(len(clean_lines) - 1)]

    copyrights.add("\n".join(clean_lines))

    return i


def do_file(path: str) -> None:
    raw = Path(path).read_bytes()
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        warn("bad UTF-8 in %s" % path)
        content = raw.decode("iso-8859-1")

    lines = content.split("\n")

    if len(lines) <= 4:
        warn_verbose("ignoring short file %s" % path)
        return

    if not "Copyright" in content:
        if "public domain" in content.lower():
            warn_verbose("ignoring public domain file %s" % path)
            return
        warn('no copyright notice found in "%s" (%d lines)' %
             (path, len(lines)))
        return

    # Manually iterate because extract_copyright_at tells us how many lines to
    # skip.
    i = 0
    while i < len(lines):
        if "Copyright" in lines[i] and not "@(#) Copyright" in lines[i]:
            i = extract_copyright_at(lines, i)
        else:
            i += 1


def do_dir(arg):
    for directory, sub_directories, filenames in os.walk(arg):
        if ".git" in sub_directories:
            sub_directories.remove(".git")
        sub_directories = sorted(sub_directories)

        for filename in sorted(filenames):
            path = os.path.join(directory, filename)
            if is_interesting(path):
                do_file(path)


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 0:
        args = ["."]

    for arg in args:
        if os.path.isdir(arg):
            do_dir(arg)
        else:
            do_file(arg)

    for notice in sorted(copyrights):
        print(notice)
        print()
        print("-" * 67)
        print()


if __name__ == "__main__":
    main()
```