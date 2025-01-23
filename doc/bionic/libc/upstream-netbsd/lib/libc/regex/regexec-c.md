Response:
我的目标是对提供的C源代码文件 `regexec.c` 进行分析，并用中文详细解释其功能、与 Android 的关系、涉及的 libc 函数实现、动态链接处理、逻辑推理、常见错误、以及在 Android 框架/NDK 中的调用路径和 Frida Hook 示例。

**1. 功能概述:**

首先，我需要理解 `regexec.c` 的核心功能。从注释和代码结构来看，它实现了正则表达式的匹配功能。它接收一个预编译的正则表达式 (`regex_t`) 和一个待匹配的字符串，并尝试在字符串中找到匹配项。

**2. 与 Android 的关系:**

由于这是 Android Bionic libc 的一部分，因此 `regexec.c` 是 Android 系统中处理正则表达式匹配的核心组件。任何需要进行正则匹配的 Android 功能都可能间接或直接地使用它。

**3. libc 函数实现:**

`regexec.c` 依赖于一些标准的 C 库函数。我需要详细解释这些函数的功能及其实现方式。例如，`malloc` 用于动态内存分配，`memset` 用于内存填充，`memcpy` 用于内存拷贝，`memcmp` 用于内存比较，等等。对于每个函数，我需要描述其目的、参数、返回值，并简要说明其内部实现原理。

**4. 动态链接处理:**

`regexec.c` 作为 libc 的一部分，会被动态链接到其他可执行文件或共享库中。我需要描述动态链接的过程，包括符号查找、重定位等。为了说明，需要提供一个简单的 so 布局示例，并解释链接器如何将 `regexec` 函数链接到调用它的代码。

**5. 逻辑推理:**

`regexec.c` 内部会进行复杂的逻辑推理以匹配正则表达式。我可以尝试分析代码中的一些关键逻辑，并给出假设的输入和输出，以展示匹配过程。例如，给定一个简单的正则表达式和字符串，我可以预测 `regexec` 如何进行匹配并返回结果。

**6. 常见错误:**

用户在使用正则表达式匹配时可能会犯一些常见的错误。我需要列举这些错误，例如传递无效的正则表达式、内存泄漏等，并提供示例说明。

**7. Android 框架/NDK 调用路径和 Frida Hook:**

要说明 `regexec` 在 Android 中的使用，需要找到一个从 Android Framework 或 NDK 调用到 `regexec` 的路径。这可能涉及到 Java 代码通过 JNI 调用到 Native 代码，然后调用到 libc 的过程。找到这样的路径后，我可以提供一个 Frida Hook 示例，演示如何拦截和观察 `regexec` 的调用。

**8. 代码结构分析:**

`regexec.c` 的代码结构比较特殊，它包含了三次 `engine.c`。我需要理解这种设计模式的目的，即通过宏定义来选择不同的状态表示方式和匹配引擎。

**9. 多字节字符处理:**

代码中包含了对多字节字符的支持 (`MB_CUR_MAX > 1`)。我需要解释这部分代码的作用，以及它如何处理不同字符编码的匹配。

**10. 核心匹配逻辑 (engine.c):**

虽然 `engine.c` 的具体代码没有提供，但从宏定义和注释可以看出，它包含了实际的正则表达式匹配算法。我需要根据 `regexec.c` 中对 `engine.c` 的调用方式来推断其大致的工作原理。

**反思和精炼:**

在完成初步分析后，我会重新审视我的答案，确保逻辑清晰、表达准确，并尽可能详细地覆盖所有要求。例如，对于动态链接部分，我会确保 so 布局示例清晰易懂。对于 Frida Hook 示例，我会提供具体的代码，并解释其工作原理。

通过以上思考过程，我能够更系统地分析 `regexec.c`，并生成一个全面的、有条理的中文回复。
这个C源文件 `regexec.c` 是 Android Bionic C 库中用于执行正则表达式匹配的核心组件。它基于 NetBSD 的实现，并在 Android 环境中被广泛使用。

**它的功能：**

`regexec` 函数的主要功能是：

1. **执行正则表达式匹配：** 给定一个预编译的正则表达式 (`regex_t *preg`) 和一个待匹配的字符串 (`const char *string`)，它会尝试在字符串中找到与正则表达式匹配的部分。
2. **返回匹配结果：** 如果匹配成功，它会将匹配到的子串信息存储在 `regmatch_t pmatch[]` 数组中。`pmatch[i]` 存储了第 `i` 个捕获组的起始和结束位置。`pmatch[0]` 存储整个匹配的起始和结束位置。
3. **处理匹配选项：** 通过 `eflags` 参数，`regexec` 可以控制匹配的行为，例如：
    * `REG_NOTBOL`:  不将字符串的开头视为行的开头。
    * `REG_NOTEOL`:  不将字符串的结尾视为行的结尾。
    * `REG_STARTEND`: 使用 `pmatch[0]` 指定匹配的起始和结束位置。
    * `REG_TRACE`: 启用执行跟踪（通常用于调试）。
    * `REG_LARGE`: 强制使用大状态表示（用于处理复杂的正则表达式）。
    * `REG_BACKR`: 强制使用反向引用代码。
4. **选择不同的匹配引擎：**  `regexec` 内部会根据正则表达式的复杂程度和系统架构（是否支持多字节字符）选择不同的匹配引擎：
    * `smatcher`: 用于状态数量较小且不支持多字节字符的情况。
    * `lmatcher`: 用于状态数量较大且不支持多字节字符的情况。
    * `mmatcher`: 用于支持多字节字符的情况。

**与 Android 功能的关系及举例说明：**

`regexec` 在 Android 中扮演着至关重要的角色，许多系统功能和应用程序都依赖于它进行文本处理和模式匹配。

* **文本搜索和替换：**  Android 系统中的文件管理器、文本编辑器等应用，在进行查找和替换操作时，可能会使用正则表达式，从而调用到 `regexec`。
* **数据校验：**  应用程序在接收用户输入时，可以使用正则表达式校验输入格式，例如邮箱地址、手机号码等。
* **网络请求处理：**  网络库在解析 URL 或 HTTP 响应头时，可能会使用正则表达式进行模式匹配。
* **日志分析：**  Android 系统和应用程序会产生大量的日志信息，使用正则表达式可以方便地提取和分析特定模式的日志。
* **`grep` 命令：** Android 的 shell 环境中包含了 `grep` 命令，它可以使用正则表达式进行文件内容搜索，最终会调用到 Bionic libc 中的 `regexec`。

**举例说明：**

假设一个 Android 应用需要校验用户输入的邮箱地址格式。它可以使用 NDK 提供的正则表达式接口，最终会调用到 `regexec`。

```c
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *email = "test@example.com";
    const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    regex_t regex;
    int reti;

    // 编译正则表达式
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }

    // 执行匹配
    reti = regexec(&regex, email, 0, NULL, 0);
    if (!reti) {
        printf("Email address is valid.\n");
    } else if (reti == REG_NOMATCH) {
        printf("Email address is invalid.\n");
    } else {
        char msgbuf[100];
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        exit(1);
    }

    // 释放正则表达式资源
    regfree(&regex);
    return 0;
}
```

在这个例子中，`regexec(&regex, email, 0, NULL, 0)` 会被调用，以检查 `email` 字符串是否符合 `pattern` 定义的邮箱地址格式。

**libc 函数的功能及实现：**

`regexec.c` 依赖于以下 libc 函数：

* **`malloc` 和 `free` (stdlib.h):**
    * **功能：** `malloc` 用于动态分配内存，`free` 用于释放已分配的内存。
    * **实现：**  Bionic 的内存分配器通常使用 `dlmalloc` 或其变体。它维护着一块大的内存区域，并根据请求分配和释放小的内存块。内部实现涉及维护空闲块列表、合并相邻的空闲块等。在 `regexec.c` 中，`malloc` 用于分配状态表示所需的内存空间（在 `lmatcher` 和 `mmatcher` 中），`free` 用于释放这些空间。
* **`memset` 和 `memcpy` 和 `memcmp` (string.h):**
    * **功能：**
        * `memset`: 将一块内存区域设置为指定的值。
        * `memcpy`: 将一块内存区域的内容复制到另一块内存区域。
        * `memcmp`: 比较两块内存区域的内容。
    * **实现：** 这些函数通常通过优化的汇编代码实现，以提高性能。它们会逐字节或逐字地操作内存。在 `regexec.c` 中，`memset` 用于初始化状态集合，`memcpy` 用于复制状态集合，`memcmp` 用于比较状态集合是否相等。
* **`strlen` (string.h):**
    * **功能：** 计算以 null 结尾的字符串的长度。
    * **实现：**  `strlen` 会从字符串的起始位置开始遍历，直到遇到 null 终止符 (`\0`)。
* **`mbrtowc` (wchar.h):**
    * **功能：** 将一个多字节字符转换为宽字符。
    * **实现：** 这涉及到根据当前的 locale 和字符编码（如 UTF-8）解析多字节序列，并将其转换为对应的宽字符表示。`regexec.c` 中自定义的 `xmbrtowc` 函数是对 `mbrtowc` 的封装，并在没有 NLS 支持时提供一个简单的单字节实现。
* **`ctype.h` 中的字符分类函数 (例如 `isspace`, `isdigit` 等):**
    * **功能：**  判断字符的类型（例如是否为空白字符、数字等）。
    * **实现：**  这些函数通常通过查表的方式实现，预先计算好每个字符的属性。正则表达式引擎可能会使用这些函数来处理字符类。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`regexec.c` 编译后的代码会位于 `libc.so` 这个共享库中。当一个应用程序需要使用正则表达式匹配功能时，动态链接器会将 `libc.so` 加载到进程的地址空间，并将对 `regexec` 函数的调用重定向到 `libc.so` 中对应的代码地址。

**so 布局样本 (简化):**

```
libc.so:
    .text:
        ...
        [regexec函数的代码]   <-- regexec 的入口地址
        ...
    .data:
        ...
    .dynsym:  // 动态符号表
        ...
        regexec (address of regexec)
        ...
```

**链接的处理过程：**

1. **编译时：**  应用程序在编译时，编译器看到对 `regexec` 的调用，会生成一个 PLT (Procedure Linkage Table) 条目，用于后续的动态链接。
2. **加载时：** 当应用程序启动时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会被加载到进程空间。
3. **加载共享库：** 动态链接器会解析应用程序的依赖关系，并加载 `libc.so` 到进程的内存空间。
4. **符号解析：** 动态链接器会遍历 `libc.so` 的动态符号表 (`.dynsym`)，找到 `regexec` 的地址。
5. **重定位：** 动态链接器会更新应用程序的 PLT 条目，将 `regexec` 的调用地址指向 `libc.so` 中 `regexec` 函数的实际地址。
6. **运行时：** 当应用程序执行到调用 `regexec` 的代码时，程序会跳转到 `libc.so` 中 `regexec` 的代码执行。

**逻辑推理，假设输入与输出：**

假设我们使用以下代码：

```c
#include <regex.h>
#include <stdio.h>

int main() {
    const char *string = "The quick brown fox jumps over the lazy dog.";
    const char *pattern = "fox";
    regex_t regex;
    regmatch_t pmatch[1];

    regcomp(&regex, pattern, 0);
    if (regexec(&regex, string, 1, pmatch, 0) == 0) {
        printf("Match found at position %ld, length %ld\n",
               pmatch[0].rm_so, pmatch[0].rm_eo - pmatch[0].rm_so);
    } else {
        printf("No match found\n");
    }
    regfree(&regex);
    return 0;
}
```

**假设输入：**

* `string`: "The quick brown fox jumps over the lazy dog."
* `pattern`: "fox"

**逻辑推理：**

1. `regcomp` 会将正则表达式 "fox" 编译成内部表示。
2. `regexec` 会在 `string` 中搜索 "fox"。
3. 匹配过程会在 "brown " 后面找到 "fox"。
4. `pmatch[0].rm_so` 将会被设置为 "fox" 在 `string` 中的起始位置索引（16）。
5. `pmatch[0].rm_eo` 将会被设置为 "fox" 在 `string` 中的结束位置索引加一（19）。

**预期输出：**

```
Match found at position 16, length 3
```

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **未编译正则表达式就调用 `regexec`：**
   ```c
   regex_t regex;
   const char *string = "test";
   // regcomp(&regex, "...", 0); // 忘记编译
   regexec(&regex, string, 0, NULL, 0); // 导致未定义行为
   ```
   **错误：**  必须先调用 `regcomp` 编译正则表达式，才能在 `regexec` 中使用。

2. **正则表达式语法错误：**
   ```c
   regex_t regex;
   regcomp(&regex, "**invalid**", REG_EXTENDED); // 无效的正则表达式语法
   // regexec 会返回一个非零错误码
   ```
   **错误：**  确保正则表达式语法正确。可以使用 `regerror` 获取详细的错误信息。

3. **`pmatch` 数组大小不足：**
   ```c
   regex_t regex;
   regmatch_t pmatch[1]; // 只有一个元素
   regcomp(&regex, "(a)(b)", REG_EXTENDED); // 包含两个捕获组
   regexec(&regex, "ab", 2, pmatch, 0); // 尝试获取两个匹配结果，但 pmatch 太小
   ```
   **错误：**  `pmatch` 数组的大小应该足够容纳所有需要捕获的子表达式的数量（包括整个匹配）。

4. **内存泄漏：**
   ```c
   regex_t *regex = malloc(sizeof(regex_t));
   regcomp(regex, "pattern", 0);
   // ... 使用 regex ...
   // 忘记调用 regfree(regex);
   // 忘记调用 free(regex); // 如果使用 malloc 分配了 regex_t 结构体
   ```
   **错误：**  使用 `regcomp` 编译的正则表达式需要使用 `regfree` 释放资源。如果使用 `malloc` 分配了 `regex_t` 结构体，还需要使用 `free` 释放。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `regexec` 的路径示例 (简化的假设路径):**

1. **Java 代码：**  Android Framework 中的某个 Java 类，例如 `java.util.regex.Pattern` 或 `java.lang.String` 的某些方法（如 `matches()`, `replaceAll()`, `split()` 等），需要进行正则表达式匹配。
2. **JNI 调用：** 这些 Java 类会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的 Native 代码。
3. **ART Native 代码：** ART 的 Native 代码会处理正则表达式的编译和执行。对于执行匹配，最终会调用到 Bionic libc 中的 `regexec` 函数。这可能通过一个中间的 Native 方法来实现，该方法负责将 Java 的正则表达式对象和字符串转换为 `regexec` 可以接受的参数。
4. **Bionic libc：**  ART 的 Native 代码会调用 `regexec` 函数执行实际的正则表达式匹配。

**NDK 到 `regexec` 的路径示例：**

1. **NDK C/C++ 代码：**  开发者使用 NDK 编写的 Native 代码，包含了对 Bionic libc 正则表达式接口的调用，例如 `regcomp`, `regexec`, `regfree` 等。
2. **直接调用：**  NDK 代码会直接链接到 Bionic libc，并调用 `regexec` 函数。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `regexec` 函数调用的示例：

```javascript
Java.perform(function() {
    var libc = Process.getModuleByName("libc.so");
    var regexecPtr = libc.getExportByName("regexec");

    if (regexecPtr) {
        Interceptor.attach(regexecPtr, {
            onEnter: function(args) {
                console.log("Called regexec");
                var preg = ptr(args[0]);
                var string = ptr(args[1]).readCString();
                var nmatch = args[2].toInt();
                var eflags = args[4].toInt();

                console.log("  preg:", preg);
                console.log("  string:", string);
                console.log("  nmatch:", nmatch);
                console.log("  eflags:", eflags);

                // 你可以进一步解析 preg 来查看正则表达式的内容
            },
            onLeave: function(retval) {
                console.log("regexec returned:", retval);
            }
        });
        console.log("Hooked regexec");
    } else {
        console.log("Could not find regexec in libc.so");
    }
});
```

**Frida Hook 解释：**

1. **`Java.perform(function() { ... });`**:  确保 Frida 代码在 Java 虚拟机加载后执行。
2. **`Process.getModuleByName("libc.so");`**: 获取 `libc.so` 模块的句柄。
3. **`libc.getExportByName("regexec");`**: 获取 `regexec` 函数的地址。
4. **`Interceptor.attach(regexecPtr, { ... });`**:  拦截 `regexec` 函数的调用。
5. **`onEnter: function(args)`**:  在 `regexec` 函数被调用时执行。`args` 数组包含了传递给 `regexec` 的参数。
    * `args[0]`: 指向 `regex_t` 结构的指针。
    * `args[1]`: 指向待匹配字符串的指针。
    * `args[2]`: `nmatch` 参数。
    * `args[4]`: `eflags` 参数。
6. **`ptr(args[1]).readCString()`**:  读取 C 风格的字符串。
7. **`onLeave: function(retval)`**: 在 `regexec` 函数返回后执行。`retval` 是函数的返回值。

通过运行这个 Frida 脚本，你可以观察到 `regexec` 函数何时被调用，以及它的参数和返回值，从而调试 Android Framework 或 NDK 中正则表达式的使用情况。你需要将此脚本注入到目标 Android 进程中才能生效。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/regex/regexec.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*	$NetBSD: regexec.c,v 1.26 2021/02/26 19:24:47 christos Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993, 1994 Henry Spencer.
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer.
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
 *	@(#)regexec.c	8.3 (Berkeley) 3/20/94
 */

#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
#endif

#include <sys/cdefs.h>
#if 0
static char sccsid[] = "@(#)regexec.c	8.3 (Berkeley) 3/20/94";
__FBSDID("$FreeBSD: head/lib/libc/regex/regexec.c 326025 2017-11-20 19:49:47Z pfg $");
#endif
__RCSID("$NetBSD: regexec.c,v 1.26 2021/02/26 19:24:47 christos Exp $");

/*
 * the outer shell of regexec()
 *
 * This file includes engine.c three times, after muchos fiddling with the
 * macros that code uses.  This lets the same code operate on two different
 * representations for state sets and characters.
 */

#ifndef LIBHACK
#include "namespace.h"
#endif
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <regex.h>

#if defined(__weak_alias) && !defined(LIBHACK)
__weak_alias(regexec,_regexec)
#endif

#include "utils.h"
#include "regex2.h"

static __inline size_t
xmbrtowc(wint_t *wi, const char *s, size_t n, mbstate_t *mbs, wint_t dummy)
{
#ifdef NLS
	size_t nr;
	wchar_t wc;

	nr = mbrtowc(&wc, s, n, mbs);
	if (wi != NULL)
		*wi = wc;
	if (nr == 0)
		return (1);
	else if (nr == (size_t)-1 || nr == (size_t)-2) {
		memset(mbs, 0, sizeof(*mbs));
		if (wi != NULL)
			*wi = dummy;
		return (1);
	} else
                return (nr);
#else
	if (wi)
		*wi = *s;
	return 1;
#endif
}

static __inline size_t
xmbrtowc_dummy(wint_t *wi,
		const char *s,
		size_t n __unused,
		mbstate_t *mbs __unused,
		wint_t dummy __unused)
{

	if (wi != NULL)
		*wi = (unsigned char)*s;
	return (1);
}

/* macros for manipulating states, small version */
#define	states	long
#define	states1	states		/* for later use in regexec() decision */
#define	CLEAR(v)	((v) = 0)
#define	SET0(v, n)	((v) &= ~((unsigned long)1 << (n)))
#define	SET1(v, n)	((v) |= (unsigned long)1 << (n))
#define	ISSET(v, n)	(((v) & ((unsigned long)1 << (n))) != 0)
#define	ASSIGN(d, s)	((d) = (s))
#define	EQ(a, b)	((a) == (b))
#define	STATEVARS	long dummy	/* dummy version */
#define	STATESETUP(m, n)	/* nothing */
#define	STATETEARDOWN(m)	/* nothing */
#define	SETUP(v)	((v) = 0)
#define	onestate	long
#define	INIT(o, n)	((o) = (unsigned long)1 << (n))
#define	INC(o)	((o) <<= 1)
#define	ISSTATEIN(v, o)	(((v) & (o)) != 0)
/* some abbreviations; note that some of these know variable names! */
/* do "if I'm here, I can also be there" etc without branches */
#define	FWD(dst, src, n)	((dst) |= ((unsigned long)(src)&(here)) << (n))
#define	BACK(dst, src, n)	((dst) |= ((unsigned long)(src)&(here)) >> (n))
#define	ISSETBACK(v, n)	(((v) & ((unsigned long)here >> (n))) != 0)
/* no multibyte support */
#define	XMBRTOWC	xmbrtowc_dummy
#define	ZAPSTATE(mbs)	((void)(mbs))
/* function names */
#define SNAMES			/* engine.c looks after details */

#include "engine.c"

/* now undo things */
#undef	states
#undef	CLEAR
#undef	SET0
#undef	SET1
#undef	ISSET
#undef	ASSIGN
#undef	EQ
#undef	STATEVARS
#undef	STATESETUP
#undef	STATETEARDOWN
#undef	SETUP
#undef	onestate
#undef	INIT
#undef	INC
#undef	ISSTATEIN
#undef	FWD
#undef	BACK
#undef	ISSETBACK
#undef	SNAMES
#undef	XMBRTOWC
#undef	ZAPSTATE

/* macros for manipulating states, large version */
#define	states	char *
#define	CLEAR(v)	memset(v, 0, m->g->nstates)
#define	SET0(v, n)	((v)[n] = 0)
#define	SET1(v, n)	((v)[n] = 1)
#define	ISSET(v, n)	((v)[n])
#define	ASSIGN(d, s)	memcpy(d, s, m->g->nstates)
#define	EQ(a, b)	(memcmp(a, b, m->g->nstates) == 0)
#define	STATEVARS	long vn; char *space
#define	STATESETUP(m, nv)	{ (m)->space = malloc((nv)*(m)->g->nstates); \
				if ((m)->space == NULL) return(REG_ESPACE); \
				(m)->vn = 0; }
#define	STATETEARDOWN(m)	{ free((m)->space); }
#define	SETUP(v)	((v) = &m->space[m->vn++ * m->g->nstates])
#define	onestate	long
#define	INIT(o, n)	((o) = (n))
#define	INC(o)	((o)++)
#define	ISSTATEIN(v, o)	((v)[o])
/* some abbreviations; note that some of these know variable names! */
/* do "if I'm here, I can also be there" etc without branches */
#define	FWD(dst, src, n)	((dst)[here+(n)] |= (src)[here])
#define	BACK(dst, src, n)	((dst)[here-(n)] |= (src)[here])
#define	ISSETBACK(v, n)	((v)[here - (n)])
/* no multibyte support */
#define	XMBRTOWC	xmbrtowc_dummy
#define	ZAPSTATE(mbs)	((void)(mbs))
/* function names */
#define	LNAMES			/* flag */

#include "engine.c"

/* multibyte character & large states version */
#undef	LNAMES
#undef	XMBRTOWC
#undef	ZAPSTATE
#define	XMBRTOWC	xmbrtowc
#define	ZAPSTATE(mbs)	memset((mbs), 0, sizeof(*(mbs)))
#define	MNAMES

#include "engine.c"

/*
 - regexec - interface for matching
 = extern int regexec(const regex_t *, const char *, size_t, \
 =					regmatch_t [], int);
 = #define	REG_NOTBOL	00001
 = #define	REG_NOTEOL	00002
 = #define	REG_STARTEND	00004
 = #define	REG_TRACE	00400	// tracing of execution
 = #define	REG_LARGE	01000	// force large representation
 = #define	REG_BACKR	02000	// force use of backref code
 *
 * We put this here so we can exploit knowledge of the state representation
 * when choosing which matcher to call.  Also, by this point the matchers
 * have been prototyped.
 */
int				/* 0 success, REG_NOMATCH failure */
regexec(const regex_t * __restrict preg,
	const char * __restrict string,
	size_t nmatch,
	regmatch_t pmatch[__restrict],
	int eflags)
{
	struct re_guts *g = preg->re_g;
#ifdef REDEBUG
#	define	GOODFLAGS(f)	(f)
#else
#	define	GOODFLAGS(f)	((f)&(REG_NOTBOL|REG_NOTEOL|REG_STARTEND))
#endif
	_DIAGASSERT(preg != NULL);
	_DIAGASSERT(string != NULL);

	if (preg->re_magic != MAGIC1 || g->magic != MAGIC2)
		return(REG_BADPAT);
	assert(!(g->iflags&BAD));
	if (g->iflags&BAD)		/* backstop for no-debug case */
		return(REG_BADPAT);
	eflags = GOODFLAGS(eflags);

	if (MB_CUR_MAX > 1)
		return(mmatcher(g, string, nmatch, pmatch, eflags));
	else if (g->nstates <= CHAR_BIT*sizeof(states1) && !(eflags&REG_LARGE))
		return(smatcher(g, string, nmatch, pmatch, eflags));
	else
		return(lmatcher(g, string, nmatch, pmatch, eflags));
}
```