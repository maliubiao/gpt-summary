Response:
Let's break down the thought process for analyzing the `getsubopt.c` code.

1. **Understand the Core Request:** The primary goal is to analyze the provided C code snippet for `getsubopt`, explain its functionality, relate it to Android, and explore its usage and potential issues.

2. **Initial Reading and High-Level Understanding:**  First, I read through the code to get a general idea of what it's doing. I see loops, string manipulation, and comparisons. The copyright notice indicates it's derived from OpenBSD. The comments mention "suboptions," hinting at parsing comma-separated options with optional values. The global variable `suboptarg` stands out.

3. **Identify Key Functions:** The main function is `getsubopt`. It takes three arguments: `optionp`, `tokens`, and `valuep`. This suggests it's taking an option string, a list of valid tokens, and is intended to extract a value. The `stdlib.h` and `string.h` includes confirm that string manipulation is involved.

4. **Analyze `getsubopt` Step-by-Step:**  I go through the code line by line, focusing on what each part does:

    * **Initialization:** `suboptarg` and `*valuep` are set to `NULL`. This is important for error handling and default behavior.
    * **Input Validation:**  It checks if `optionp` or `*optionp` is null, returning -1 if so. This is good defensive programming.
    * **Skipping Delimiters:** The first loop skips leading whitespace, commas, and tabs. This makes the function more robust.
    * **End of Input Check:**  If the input string is exhausted, it returns -1.
    * **Token Extraction:** The loop extracts a "token" until it encounters a delimiter (comma, equals, space, tab). The extracted token's start is stored in `suboptarg`.
    * **Value Extraction (Optional):** If an equals sign is found, the code extracts the "value" following it, storing the pointer in `*valuep`. Crucially, it null-terminates both the token and the value.
    * **Updating `optionp`:**  The `*optionp` is updated to point to the character after the processed token (and optional value). This is how the function iterates through the suboptions.
    * **Token Matching:** The final loop compares the extracted `suboptarg` with the provided `tokens`. If a match is found, the index of the matching token is returned.
    * **No Match:** If no match is found, -1 is returned.

5. **Determine Functionality:** Based on the step-by-step analysis, I can summarize the function's core purpose:  `getsubopt` parses a string of comma-separated options, each potentially having a value associated with it via an equals sign. It tries to match each option against a provided list of valid tokens.

6. **Relate to Android Bionic:** The prompt explicitly mentions this is from Android Bionic. This means it's part of Android's core C library. I consider where such a function might be used in Android. Command-line tools, configuration files, and system properties come to mind. I create example scenarios, like parsing mount options or settings in `init.rc`.

7. **Explain Libc Function Implementation:** I rephrase the step-by-step analysis into a more descriptive explanation of how the function works internally. I focus on the pointer manipulation and string termination aspects.

8. **Address Dynamic Linker (SO) Aspects:** The `getsubopt` function itself *doesn't directly involve the dynamic linker*. It's a string parsing utility. It's important to be accurate here and state that directly. However, I recognize that *other parts of Bionic* that *use* `getsubopt` might interact with the dynamic linker. So, I briefly explain the role of the dynamic linker in loading shared libraries and provide a simple example of an SO structure, focusing on ELF headers and symbol tables. I also outline the linking process. This addresses the prompt's request while maintaining accuracy.

9. **Consider Logical Reasoning and Examples:** I create hypothetical input and output examples to illustrate how `getsubopt` behaves in different scenarios (matching, no matching, with and without values). This helps solidify understanding.

10. **Identify Common Usage Errors:** I think about how a programmer might misuse `getsubopt`. Common errors include providing a null `optionp`, incorrect token lists, forgetting to advance the `optionp`, and not checking the return value. I provide code examples to illustrate these errors.

11. **Trace the Execution Path (Android Framework/NDK):**  This requires some logical deduction. I know that Android applications use the NDK to access native code, which in turn uses Bionic's libc. I create a plausible call chain: Android framework -> JNI call -> NDK code -> `getsubopt`. I illustrate this with a simplified Frida hook example targeting `getsubopt`. This demonstrates how to intercept calls to this function.

12. **Structure and Language:**  Finally, I organize the information logically, using clear headings and bullet points. I ensure the language is Chinese as requested. I review for clarity, accuracy, and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `getsubopt` is used to parse arguments for `dlopen`. **Correction:** While possible, `getsubopt` itself doesn't directly handle dynamic linking. It's a general-purpose string parsing tool that *could* be used in such a context.
* **Realization:**  The prompt asks for "detailed explanation of how each libc function is implemented." I initially focused only on `getsubopt`. **Correction:** I realized I needed to explain the other included libc functions (`unistd.h`, `stdlib.h`, `string.h`) at a high level.
* **Focus on the "why":**  Instead of just describing what the code does, I tried to explain *why* it's done that way (e.g., skipping whitespace for robustness).
* **Clarity on SO Structure:** I initially provided a very technical explanation of ELF. **Correction:** I simplified it to focus on the key concepts relevant to linking (headers, symbol tables).

By following these steps and including self-correction, I arrived at the comprehensive and accurate answer provided.
这是一个关于 Android Bionic 中 `getsubopt.c` 文件的分析。`getsubopt` 是一个 C 标准库函数，用于解析以逗号分隔的子选项字符串。

**`getsubopt.c` 的功能:**

`getsubopt` 函数的主要功能是从一个字符串中提取子选项，并将它们与一个预定义的令牌（token）列表进行匹配。它的具体功能如下：

1. **解析子选项字符串:** 将一个包含多个子选项的字符串（由逗号分隔）分解成独立的子选项。
2. **匹配令牌:** 将提取出的子选项与一个预定义的字符串数组（`tokens`）中的令牌进行比较。
3. **提取值:** 如果子选项包含一个用等号 (`=`) 分隔的值，则提取该值。
4. **迭代处理:** 设计为可以被多次调用，以便逐步处理整个子选项字符串。
5. **错误指示:** 如果找不到匹配的令牌，则返回一个特定的值（-1），并通过全局变量 `suboptarg` 指示未匹配的子选项。

**与 Android 功能的关系及举例说明:**

`getsubopt` 是一个通用的字符串解析工具，在 Android 系统中可以用于多种场景，特别是在需要解析配置字符串或者命令行参数的场景中。

**举例说明:**

* **挂载选项:** 在 Android 中，`mount` 命令用于挂载文件系统。挂载命令通常接受一系列以逗号分隔的选项。`getsubopt` 可以用来解析这些挂载选项。例如，一个挂载选项字符串可能是 "ro,sync,nosuid"。`getsubopt` 可以逐个提取 "ro"、"sync" 和 "nosuid"，并将它们与预定义的有效挂载选项令牌列表进行比较，以确定用户指定的选项是否合法。
* **`adb push` 或 `adb pull` 选项:** 虽然 `adb` 命令本身可能不直接使用 `getsubopt`，但其内部的守护进程或相关工具可能会使用类似的方式解析选项。例如，未来可能添加更复杂的选项来控制传输行为，这些选项可以使用类似 `getsubopt` 的机制来解析。
* **`init.rc` 文件解析:** Android 的 `init` 进程在启动时会解析 `init.rc` 文件。该文件可能包含一些配置项，其值可能包含以逗号分隔的子选项。`getsubopt` 可以用来解析这些子选项。例如，某个服务的 `onrestart` 指令可能包含多个动作，这些动作可以用逗号分隔。

**详细解释每一个 libc 函数的功能是如何实现的:**

1. **`unistd.h`:** 这是一个 POSIX 标准头文件，包含了很多与操作系统服务相关的函数声明。在这个文件中被包含可能只是为了兼容性，因为 `getsubopt` 的实现本身并没有直接调用 `unistd.h` 中定义的函数。

2. **`stdlib.h`:**  这个头文件包含了通用工具函数，例如内存分配（`malloc`, `free`）、随机数生成（`rand`, `srand`）、字符串转换函数（`atoi`, `atol`）等。 `getsubopt` 使用了 `stdlib.h` 中的函数：
   * **`NULL`:**  这是一个空指针常量，用于表示指针不指向任何有效的内存地址。在 `getsubopt` 中，`NULL` 被用来初始化 `*valuep` 和在错误情况下返回。

3. **`string.h`:** 这个头文件包含了字符串处理函数，例如字符串复制（`strcpy`, `strncpy`）、字符串比较（`strcmp`）、字符串查找（`strstr`）等。 `getsubopt` 使用了 `string.h` 中的函数：
   * **`strcmp(const char *s1, const char *s2)`:**  用于比较两个字符串 `s1` 和 `s2` 是否相等。在 `getsubopt` 中，它被用来比较提取出的子选项 `suboptarg` 和 `tokens` 数组中的令牌。

**`getsubopt` 的实现逻辑:**

```c
int
getsubopt(char **optionp, char * const *tokens, char **valuep)
{
	int cnt;
	char *p;

	suboptarg = *valuep = NULL; // 初始化全局变量 suboptarg 和 valuep 指针

	if (!optionp || !*optionp) // 检查 optionp 指针是否有效以及指向的字符串是否为空
		return(-1);

	// 跳过前导的空白字符和逗号
	for (p = *optionp; *p && (*p == ',' || *p == ' ' || *p == '\t'); ++p);

	if (!*p) { // 如果跳过空白后字符串为空，则表示没有更多子选项
		*optionp = p;
		return(-1);
	}

	// 找到当前子选项的结尾（逗号、等号、空格、制表符）
	for (suboptarg = p;
	    *++p && *p != ',' && *p != '=' && *p != ' ' && *p != '\t';);

	if (*p) {
		// 如果遇到等号，则提取值部分
		if (*p == '=') {
			*p = '\0'; // 将等号替换为 null 终止符，标记子选项的结束
			for (*valuep = ++p; // valuep 指向等号后的第一个字符
			    *p && *p != ',' && *p != ' ' && *p != '\t'; ++p); // 找到值部分的结尾
			if (*p)
				*p++ = '\0'; // 将值部分后的分隔符替换为 null 终止符
		} else
			*p++ = '\0'; // 将子选项后的分隔符替换为 null 终止符
		// 跳过子选项或值后面的空白字符和逗号
		for (; *p && (*p == ',' || *p == ' ' || *p == '\t'); ++p);
	}

	// 更新 optionp 指针，指向下一个子选项的开始
	*optionp = p;

	// 遍历令牌列表，查找匹配的令牌
	for (cnt = 0; *tokens; ++tokens, ++cnt)
		if (!strcmp(suboptarg, *tokens))
			return(cnt); // 找到匹配，返回令牌的索引

	return(-1); // 没有找到匹配的令牌
}
```

**对于涉及 dynamic linker 的功能:**

`getsubopt` 函数本身 **并不直接涉及 dynamic linker (动态链接器)** 的功能。它是一个纯粹的字符串处理函数，不负责加载或链接共享库。动态链接器负责在程序运行时加载所需的共享库（.so 文件）并将它们链接到程序中。

虽然 `getsubopt` 本身不涉及动态链接器，但在某些情况下，被解析的选项可能与动态链接器的行为有关。例如，一个程序可能使用 `getsubopt` 解析环境变量 `LD_PRELOAD` 的值，该环境变量用于指定在程序启动时预加载的共享库。

**so 布局样本以及链接的处理过程:**

由于 `getsubopt` 不直接涉及动态链接器，这里给出一个 **通用的共享库（.so）布局样本和链接处理过程**，而不是专门针对 `getsubopt` 的场景：

**so 布局样本:**

一个典型的 Android 共享库（.so 文件）是 ELF (Executable and Linkable Format) 文件。其基本布局如下：

```
ELF Header
  - Magic Number (标识 ELF 文件)
  - Class (32 位或 64 位)
  - Endianness (字节序)
  - Entry Point Address (程序入口地址，对于库通常为 0)
  - Program Header Table Offset
  - Section Header Table Offset
  - ...

Program Header Table
  - 描述内存段的属性 (加载地址、大小、权限等)
  - 例如：LOAD 段 (用于加载代码和数据)

Section Header Table
  - 描述各个段的信息 (.text, .data, .bss, .symtab, .strtab, .rel.dyn, .rel.plt 等)
  - **.text:**  代码段
  - **.data:**  已初始化的全局变量和静态变量
  - **.bss:**   未初始化的全局变量和静态变量
  - **.symtab:** 符号表 (包含导出的函数和变量)
  - **.strtab:** 字符串表 (存储符号名称等字符串)
  - **.rel.dyn:** 动态重定位表
  - **.rel.plt:**  PLT (Procedure Linkage Table) 重定位表

.text Section (代码段)
  - 包含可执行的机器指令

.data Section (数据段)
  - 包含已初始化的全局变量和静态变量

.bss Section (未初始化数据段)
  - 包含未初始化的全局变量和静态变量

... (其他段)
```

**链接的处理过程:**

1. **编译时链接 (Static Linking):**  将所有需要的库的代码合并到最终的可执行文件中。Android 中主要使用动态链接，静态链接较少见。
2. **运行时链接 (Dynamic Linking):**
   - 当程序启动时，内核加载器会加载程序的主要可执行文件。
   - 动态链接器 (例如 Android 的 `linker64` 或 `linker`) 被加载并运行。
   - 动态链接器解析可执行文件的 ELF Header 和 Program Header Table，找到需要加载的共享库。
   - 动态链接器加载这些共享库到内存中。
   - **符号解析 (Symbol Resolution):** 动态链接器查找程序和已加载的共享库中未定义的符号 (例如，程序中调用的共享库函数)。
   - **重定位 (Relocation):**  由于共享库被加载到内存的哪个地址是不确定的，动态链接器需要修改代码和数据中的地址引用，使其指向正确的内存位置。这通过重定位表 (.rel.dyn, .rel.plt) 来完成。
   - **PLT 和 GOT:**  对于函数调用，通常使用 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table)。PLT 中的条目最初指向动态链接器的代码，第一次调用时，动态链接器会解析函数地址并更新 GOT 条目，后续调用将直接跳转到 GOT 中存储的函数地址，从而提高效率。

**假设输入与输出:**

假设我们有以下输入：

* `optionp` 指向字符串 `"debug,level=3,verbose"`
* `tokens` 指向字符串数组 `{"debug", "level", "verbose"}`
* 第一次调用：

   * 输入：`*optionp` 为 `"debug,level=3,verbose"`
   * 输出：返回 `0` (匹配 "debug" 的索引)，`suboptarg` 指向 `"debug"`, `*valuep` 为 `NULL`, `*optionp` 更新为指向 `",level=3,verbose"` 的 `'l'`

* 第二次调用：

   * 输入：`*optionp` 为 `"level=3,verbose"`
   * 输出：返回 `1` (匹配 "level" 的索引)，`suboptarg` 指向 `"level"`, `*valuep` 指向 `"3"`, `*optionp` 更新为指向 `",verbose"` 的 `'v'`

* 第三次调用：

   * 输入：`*optionp` 为 `"verbose"`
   * 输出：返回 `2` (匹配 "verbose" 的索引)，`suboptarg` 指向 `"verbose"`, `*valuep` 为 `NULL`, `*optionp` 更新为指向字符串末尾的 `'\0'`

* 第四次调用：

   * 输入：`*optionp` 为 `""` (空字符串)
   * 输出：返回 `-1`

**用户或者编程常见的使用错误:**

1. **未检查返回值:**  忘记检查 `getsubopt` 的返回值，导致在未找到匹配项时继续错误处理。

   ```c
   char *options = "unknown_option,level=5";
   char *opts = options;
   char *tokens[] = {"level", NULL};
   char *value;
   int ret = getsubopt(&opts, tokens, &value);
   // 错误：没有检查 ret 的值，如果 unknown_option 不匹配，ret 为 -1，但 value 可能仍然被修改
   if (value) {
       printf("Level: %s\n", value);
   }
   ```

2. **错误的令牌列表:** 提供的 `tokens` 列表中缺少某些有效的子选项，导致无法正确解析。

   ```c
   char *options = "debug,verbose";
   char *opts = options;
   char *tokens[] = {"debug", NULL}; // 缺少 "verbose"
   char *value;
   int ret;
   while ((ret = getsubopt(&opts, tokens, &value)) != -1) {
       if (ret == 0) {
           printf("Debug mode enabled\n");
       }
   }
   // 错误：verbose 选项会被忽略
   ```

3. **未正确更新 `optionp`:**  在循环中使用 `getsubopt` 时，必须传递 `optionp` 的地址，以便函数可以更新其指向下一个子选项的位置。如果传递的是 `optionp` 的副本，则会导致无限循环或只解析第一个子选项。

   ```c
   char *options = "opt1,opt2";
   char *opts = options;
   char *tokens[] = {"opt1", "opt2", NULL};
   char *value;
   int ret = getsubopt(&options, tokens, &value); // 错误：应该传递 &opts
   // ... 循环可能会出错
   ```

4. **假设值的存在:**  在子选项可能没有值的情况下，直接访问 `valuep` 指向的内存可能导致空指针解引用。

   ```c
   char *options = "debug,level";
   char *opts = options;
   char *tokens[] = {"debug", "level", NULL};
   char *value;
   int ret;
   while ((ret = getsubopt(&opts, tokens, &value)) != -1) {
       if (ret == 1) { // 假设 "level" 总是带有值
           printf("Level: %s\n", value); // 错误：如果 level 没有值，value 为 NULL
       }
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `getsubopt` 是一个标准的 C 库函数，它可以被 Android Framework 的 Java 代码通过 JNI (Java Native Interface) 间接调用，或者直接被 NDK (Native Development Kit) 开发的 C/C++ 代码调用。

**可能的调用链:**

1. **Android Framework (Java):**
   - Framework 的某个组件（例如，处理系统属性、解析配置文件等）需要处理包含子选项的字符串。
   - 该组件通过 JNI 调用一个 Native 方法。

2. **JNI (C/C++):**
   - Native 方法接收 Java 传递的字符串。
   - Native 方法可能会调用 Bionic libc 中的 `getsubopt` 函数来解析该字符串。

3. **Bionic libc (`getsubopt.c`):**
   - `getsubopt` 函数执行其字符串解析逻辑。

**NDK 调用:**

1. **NDK App (C/C++):**
   - 使用 NDK 开发的应用程序代码需要解析用户输入或配置文件中的子选项字符串.
   - NDK 代码直接调用 `getsubopt` 函数。

**Frida Hook 示例:**

我们可以使用 Frida 来 hook `getsubopt` 函数，观察其调用情况和参数。

```javascript
// Frida 脚本
if (Process.platform === 'android') {
  const getsubopt = Module.findExportByName("libc.so", "getsubopt");
  if (getsubopt) {
    Interceptor.attach(getsubopt, {
      onEnter: function (args) {
        console.log("getsubopt called!");
        console.log("  optionp:", Memory.readUtf8String(args[0].readPointer()));
        const tokensPtr = args[1];
        let tokens = [];
        let i = 0;
        while (true) {
          const tokenPtr = tokensPtr.readPointer();
          if (tokenPtr.isNull()) break;
          tokens.push(Memory.readUtf8String(tokenPtr));
          tokensPtr.add(Process.pointerSize);
          i++;
        }
        console.log("  tokens:", tokens);
      },
      onLeave: function (retval) {
        console.log("getsubopt returned:", retval);
        if (retval.toInt32() !== -1) {
          console.log("  suboptarg:", DebugSymbol.fromAddress(Module.findExportByName("libc.so", "suboptarg")).readPointer().readCString());
        }
      }
    });
  } else {
    console.log("Could not find getsubopt in libc.so");
  }
} else {
  console.log("This script is for Android only.");
}
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 frida-tools。
2. **运行 Android 应用:** 运行你想要调试的 Android 应用程序或系统进程。
3. **运行 Frida 脚本:** 使用 Frida 连接到目标进程并运行上述脚本。例如：
   ```bash
   frida -U -f <package_name_or_process_name> -l getsubopt_hook.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name_or_process_name> -l getsubopt_hook.js
   ```

**Frida Hook 输出示例:**

当你运行的 Android 应用或进程调用 `getsubopt` 时，Frida 会拦截该调用并输出类似以下的信息：

```
getsubopt called!
  optionp: debug,level=3,verbose
  tokens: debug,level,verbose
getsubopt returned: 0
  suboptarg: debug
getsubopt called!
  optionp: level=3,verbose
  tokens: debug,level,verbose
getsubopt returned: 1
  suboptarg: level
getsubopt called!
  optionp: verbose
  tokens: debug,level,verbose
getsubopt returned: 2
  suboptarg: verbose
```

通过 Frida Hook，你可以动态地观察 `getsubopt` 函数的调用时机、传入的参数（子选项字符串和令牌列表）以及返回值，从而更好地理解其在 Android 系统中的使用方式。

总而言之，`getsubopt` 是一个简单但实用的字符串解析函数，在 Android 系统中用于处理各种配置和选项字符串。虽然它本身不涉及动态链接，但可以被用于解析与动态链接相关的环境变量或配置项。理解其功能和使用方式对于分析 Android 系统行为和开发 Native 代码非常有帮助。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdlib/getsubopt.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: getsubopt.c,v 1.4 2005/08/08 08:05:36 espie Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/*
 * The SVID interface to getsubopt provides no way of figuring out which
 * part of the suboptions list wasn't matched.  This makes error messages
 * tricky...  The extern variable suboptarg is a pointer to the token
 * which didn't match.
 */
char *suboptarg;

int
getsubopt(char **optionp, char * const *tokens, char **valuep)
{
	int cnt;
	char *p;

	suboptarg = *valuep = NULL;

	if (!optionp || !*optionp)
		return(-1);

	/* skip leading white-space, commas */
	for (p = *optionp; *p && (*p == ',' || *p == ' ' || *p == '\t'); ++p);

	if (!*p) {
		*optionp = p;
		return(-1);
	}

	/* save the start of the token, and skip the rest of the token. */
	for (suboptarg = p;
	    *++p && *p != ',' && *p != '=' && *p != ' ' && *p != '\t';);

	if (*p) {
		/*
		 * If there's an equals sign, set the value pointer, and
		 * skip over the value part of the token.  Terminate the
		 * token.
		 */
		if (*p == '=') {
			*p = '\0';
			for (*valuep = ++p;
			    *p && *p != ',' && *p != ' ' && *p != '\t'; ++p);
			if (*p) 
				*p++ = '\0';
		} else
			*p++ = '\0';
		/* Skip any whitespace or commas after this token. */
		for (; *p && (*p == ',' || *p == ' ' || *p == '\t'); ++p);
	}

	/* set optionp for next round. */
	*optionp = p;

	for (cnt = 0; *tokens; ++tokens, ++cnt)
		if (!strcmp(suboptarg, *tokens))
			return(cnt);
	return(-1);
}
```