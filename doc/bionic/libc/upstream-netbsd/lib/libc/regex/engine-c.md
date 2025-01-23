Response:
Let's break down the thought process for analyzing the provided C code and fulfilling the user's request.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of `engine.c`, a source file from Android's Bionic libc, specifically the regex engine. The request includes listing functionalities, explaining relationships to Android, detailing libc function implementations, addressing dynamic linking, providing examples, discussing common errors, and outlining how the code is reached from Android.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to grasp its overall purpose. Keywords like `regex`, `match`, `state`, `backref`, and the copyright notice mentioning Henry Spencer immediately suggest this is a regular expression matching engine. The `#ifdef` blocks with `SNAMES`, `LNAMES`, `MNAMES` hint at different internal representations or optimizations. The structure `struct match` and the various functions within it point to the core logic.

**3. Deconstructing the Request - Functionality:**

The request asks for a list of functionalities. This requires identifying the main tasks performed by the code. The function names themselves are strong indicators: `matcher`, `walk`, `dissect`, `backref`, `step`. These clearly relate to the process of matching a regular expression against a string. The pre-processing related to Boyer-Moore and the handling of different regex flags also become apparent.

**4. Android Relevance and Examples:**

Connecting the code to Android requires understanding *where* regular expressions are used in Android. Common uses include:

* **Input validation:**  Checking user input formats.
* **Data parsing:**  Extracting information from text files or network responses.
* **Text searching/filtering:**  Implementing features like "find in page."
* **Routing/Intent filtering:** Matching patterns in Android's intent system.

Once these use cases are identified, concrete examples can be formulated. Validating email addresses, parsing log files, and intent filtering are good illustrations.

**5. Deep Dive into Libc Function Implementations:**

This is the most technical part. For each function (`matcher`, `walk`, `dissect`, `backref`, `step`, and helper functions like `stepback`), a detailed explanation of its purpose, algorithm, and key data structures is needed.

* **`matcher`:** The entry point, handling pre-processing, the main matching loop, and result extraction.
* **`walk`:** The core matching loop, iterating through the input string and managing the state machine.
* **`step`:**  The state transition function, determining the next possible states based on the current state and input character.
* **`dissect`:**  For non-backtracking matches, figuring out which parts of the regex matched which parts of the string.
* **`backref`:**  Handling backreferences, which requires a more complex, potentially recursive approach.
* **`stepback`:**  A utility function for moving backwards in a multibyte string.

For each function, explaining the key variables within the `struct match` is essential. The role of `states`, `fresh`, `tmp`, etc., in managing the state machine needs clarification.

**6. Dynamic Linker Aspects:**

This requires knowledge of how shared libraries (`.so` files) are loaded and linked in Android. Key concepts include:

* **`.so` file structure:**  ELF format, sections like `.text`, `.data`, `.rodata`, `.dynsym`, `.dynstr`, `.rel.dyn`, `.rel.plt`.
* **Linker:** `linker64` or `linker` in Android.
* **Symbol resolution:** How the linker finds the addresses of functions and variables.
* **Relocation:**  Adjusting addresses in the loaded library.
* **GOT (Global Offset Table) and PLT (Procedure Linkage Table):** Mechanisms for lazy symbol resolution.

A sample `.so` layout and a step-by-step description of the linking process are needed. Mentioning tools like `readelf` for inspecting `.so` files is beneficial.

**7. Logical Reasoning, Assumptions, Input/Output:**

This involves illustrating how the regex engine works with specific examples. Choosing a simple regex and input string, then tracing the execution flow (at a high level), showing the expected match, and the values of relevant variables, helps in understanding. Assumptions about the regex flags and input encoding should be stated.

**8. Common User/Programming Errors:**

Think about typical mistakes developers make when using regular expressions:

* **Incorrect regex syntax:**  Forgetting to escape special characters, using wrong quantifiers.
* **Misunderstanding regex behavior:** Greedy vs. non-greedy matching, the effect of anchors.
* **Performance issues:**  Writing inefficient regexes that lead to backtracking.
* **Security vulnerabilities:**  Regex injection attacks.

Concrete examples of such errors make the explanation clearer.

**9. Android Framework/NDK Path and Frida Hooking:**

Tracing the execution flow from the Android framework or NDK down to `engine.c` involves:

* **Identifying relevant Android APIs:**  `java.util.regex` in the framework, `<regex.h>` in the NDK.
* **Mapping the API calls to native code:**  JNI calls for the framework, direct linking for NDK.
* **Illustrating the call stack:**  Showing the sequence of function calls leading to `matcher`.

A Frida hook example targeting the `matcher` function allows for runtime inspection and demonstrates how to interact with this code. The hook should show how to intercept the function call, access arguments, and potentially modify the behavior.

**10. Structuring the Response:**

Finally, organize the information logically and clearly using headings, bullet points, and code formatting. Use precise language and avoid jargon where possible. Provide sufficient detail without being overwhelming. The request specified Chinese, so the entire response should be in Chinese.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus only on the core matching logic.
* **Correction:** The request is broader, requiring understanding of the Android context, dynamic linking, and practical usage.
* **Initial thought:** Provide very low-level code details for every function.
* **Correction:**  Focus on the main algorithms and data structures. For extremely complex functions, provide a high-level overview.
* **Initial thought:** Assume the user is a regex expert.
* **Correction:** Explain concepts clearly, even for someone with a basic understanding of regular expressions.
* **Initial thought:** Provide a single Frida hook example.
* **Correction:**  Explain the purpose of Frida and how the hook interacts with the target code.

By following these steps and iteratively refining the analysis, a comprehensive and accurate response can be generated.
这是一个关于正则表达式匹配引擎的源代码文件，属于 Android Bionic C 库中 NetBSD 上游代码的一部分。它实现了正则表达式的匹配功能。

**它的功能:**

该文件（`engine.c`）包含了实现正则表达式匹配的核心逻辑。具体来说，它负责：

1. **`matcher` 函数:**  这是正则表达式匹配的入口点。它接收编译好的正则表达式结构 (`re_guts`) 和要匹配的字符串，并返回匹配结果（成功或失败）。它还处理一些预处理步骤，例如 Boyer-Moore 优化，以加速匹配过程。

2. **`walk` 函数:** 这是一个状态机驱动的匹配过程的核心。它在输入字符串上移动，根据正则表达式的状态转换来更新当前可能匹配的状态集合。它可以以快速模式 (`fast`) 运行，找到第一个可能的匹配结束位置，或者以慢速模式运行，找到所有可能的匹配结束位置。

3. **`step` 函数:**  这个函数执行状态转换。给定当前状态集合和输入字符，它计算出下一个可能的状态集合。它处理各种正则表达式操作符，例如字符匹配、字符集匹配、锚点（`^`, `$`, `\b`, `\B`）、分组和分支。

4. **`dissect` 函数:**  用于在非回溯匹配的情况下，确定正则表达式的各个子表达式匹配了输入字符串的哪一部分。

5. **`backref` 函数:**  处理带有后向引用的正则表达式匹配。后向引用允许在正则表达式中引用之前匹配的子表达式。这个函数需要更复杂的逻辑，因为它可能需要回溯来找到正确的匹配。

6. **`stepback` 函数:**  一个辅助函数，用于在多字节字符串中向后移动指定的字符数。这在处理国际化字符时非常重要。

**与 Android 功能的关系及举例说明:**

正则表达式在 Android 系统中被广泛使用，用于各种任务，例如：

* **文本搜索和替换:**  许多应用程序，包括文件管理器、文本编辑器和邮件客户端，都使用正则表达式来实现查找和替换功能。
    * **举例:** 用户在一个文本编辑器中搜索所有以 "a" 开头并以 "z" 结尾的单词。底层的实现会调用 Bionic libc 的正则表达式匹配功能。

* **输入验证:**  应用程序可以使用正则表达式来验证用户输入的数据格式，例如电子邮件地址、电话号码或日期。
    * **举例:**  一个注册表单使用正则表达式来验证用户输入的电子邮件地址是否符合标准格式。

* **数据解析:**  正则表达式可以用于从非结构化或半结构化文本数据中提取特定信息，例如日志文件分析。
    * **举例:**  Android 系统可以使用正则表达式从系统日志中提取错误信息或性能指标。

* **路由和意图过滤:**  Android 的意图（Intent）机制使用正则表达式来匹配应用程序可以处理的意图类型。
    * **举例:**  当用户点击一个链接时，Android 系统会使用正则表达式来找到能够处理该链接的应用程序。

* **网络请求处理:**  某些网络库或框架可能会使用正则表达式来解析 URL 或 HTTP 头部。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于篇幅限制，我们无法逐行解释所有代码，但可以概述关键函数的实现思路：

* **`matcher`:**
    * 初始化 `match` 结构体，存储匹配过程所需的信息，例如正则表达式结构、输入字符串、匹配结果等。
    * 如果正则表达式包含必须出现的子字符串 (`g->must`)，则进行预搜索以快速排除不可能匹配的情况（Boyer-Moore 优化）。
    * 调用 `walk` 函数开始主匹配循环。
    * 如果需要子表达式匹配信息 (`nmatch > 0`)，则根据是否包含后向引用分别调用 `dissect` 或 `backref` 函数来填充 `pmatch` 数组。
    * 清理分配的内存。

* **`walk`:**
    * 初始化状态集合 `st`，只包含起始状态。
    * 遍历输入字符串的每个字符。
    * 对于每个字符，调用 `step` 函数更新状态集合。
    * 处理行首 (`BOL`)、行尾 (`EOL`)、单词边界 (`BOW`, `EOW`) 等特殊情况。
    * 如果到达终止状态 (`stopst`)，则表示匹配成功。

* **`step`:**
    * 遍历当前状态集合 `bef` 中的每个状态。
    * 根据当前状态对应的正则表达式操作码 (`OP(s)`) 和输入字符 `ch`，计算出下一个可能的状态，并添加到 `aft` 集合中。
    * 处理各种操作码：
        * `OCHAR`: 字符匹配。
        * `OBOL`, `OEOL`, `OBOW`, `OEOW`, `OBOS`, `OEOS`, `OWBND`, `ONWBND`: 锚点匹配。
        * `OANY`: 匹配任意字符。
        * `OANYOF`: 匹配字符集中的任意字符。
        * `OPLUS_`, `O_PLUS`, `OQUEST_`, `O_QUEST`, `OCH_`, `OOR1`, `OOR2`, `O_CH`: 处理量词和分支。
        * `OLPAREN`, `ORPAREN`: 标记子表达式的开始和结束。
        * `OBACK_`, `O_BACK`: 处理后向引用。

* **`dissect`:**
    * 遍历正则表达式的指令序列。
    * 根据不同的操作码，递归调用 `walk` 函数来确定子表达式匹配的字符串部分。

* **`backref`:**
    * 与 `dissect` 类似，但需要处理后向引用的情况。
    * 当遇到 `OBACK_` 操作码时，它会检查之前匹配的子表达式是否与当前位置的字符串匹配。
    * 如果匹配失败，可能需要回溯到之前的状态。

* **`stepback`:**
    * 使用 `mbrtowc` 函数来正确处理多字节字符，确保向后移动的距离是以字符为单位而不是字节为单位。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`engine.c` 本身并不直接涉及 dynamic linker 的功能。它的代码会被编译成 Bionic libc 的一部分，通常是 `libc.so`。dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 在应用程序启动时负责加载 `libc.so` 以及其他依赖的共享库。

**`libc.so` 布局样本 (简化版):**

```
libc.so:
    .text:  // 包含可执行代码，包括 matcher, walk, step 等函数
        matcher: ...
        walk: ...
        step: ...
        dissect: ...
        backref: ...
        stepback: ...
        ... 其他 libc 函数 ...
    .data:  // 包含已初始化的全局变量
        ...
    .rodata: // 包含只读数据，例如字符串常量
        ...
    .bss:   // 包含未初始化的全局变量
        ...
    .dynsym: // 动态符号表，包含导出的符号信息 (例如函数名和地址)
        matcher
        ...
    .dynstr: // 动态字符串表，包含符号表中使用的字符串
        "matcher"
        ...
    .rel.dyn: // 数据重定位表
        ...
    .rel.plt: // PLT (Procedure Linkage Table) 重定位表，用于延迟绑定
        ...
```

**链接的处理过程 (简化版):**

1. **加载 `libc.so`:** 当应用程序启动时，dynamic linker 会读取应用程序的可执行文件头，找到其依赖的共享库列表，其中包括 `libc.so`。然后，它会将 `libc.so` 加载到内存中的某个地址。

2. **符号解析:**  应用程序可能调用 `libc.so` 中提供的正则表达式相关函数，例如 `regcomp` (编译正则表达式) 和 `regexec` (执行匹配)。当调用 `regexec` 时，dynamic linker 需要找到 `regexec` 函数在 `libc.so` 中的地址。这通过查找 `libc.so` 的 `.dynsym` 和 `.dynstr` 表来完成。

3. **重定位:**  由于 `libc.so` 被加载到内存的地址可能不是编译时的地址，dynamic linker 需要修改 `libc.so` 中使用到的全局变量和函数地址。`.rel.dyn` 表描述了数据重定位信息，`.rel.plt` 表描述了 PLT 条目的重定位信息。

4. **PLT 和 GOT (延迟绑定):**  对于在 `libc.so` 中定义的函数 (例如 `matcher`)，应用程序可能会通过 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 进行调用。最初，GOT 表中的条目指向 PLT 中的一段代码。当第一次调用 `matcher` 时，PLT 代码会调用 dynamic linker 来解析 `matcher` 的实际地址，并将该地址写入 GOT 表。后续的调用会直接通过 GOT 表跳转到 `matcher` 的地址，避免了重复的解析过程。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们使用一个简单的正则表达式 `"a[bc]d"` 和输入字符串 `"xbcd" `，来观察 `matcher` 和 `walk` 函数的执行过程：

**假设输入:**

* 正则表达式: `"a[bc]d"` (编译后会生成相应的 `re_guts` 结构)
* 输入字符串: `"abcd"`

**逻辑推理 (简化):**

1. **`matcher` 调用:**  `matcher` 函数被调用，接收编译后的正则表达式和输入字符串。
2. **`walk` 调用:** `matcher` 调用 `walk` 函数开始匹配。
3. **`walk` 状态初始化:** `walk` 函数初始化状态集合，包含正则表达式的起始状态。
4. **`walk` 逐字符匹配:**
   * **字符 'a':** `walk` 调用 `step`，`step` 函数检查当前状态是否能通过字符 'a' 转换到下一个状态。如果可以，更新状态集合。
   * **字符 'b':** `walk` 调用 `step`，`step` 函数检查当前状态是否能通过字符 'b' (或 'c') 转换到下一个状态（因为正则表达式是 `[bc]`）。
   * **字符 'c':**  如果前一步匹配了 'b'，则继续匹配 'c'。
   * **字符 'd':** `walk` 调用 `step`，`step` 函数检查当前状态是否能通过字符 'd' 转换到终止状态。
5. **匹配成功:** 当 `walk` 函数到达字符串末尾并且当前状态集合包含终止状态时，匹配成功。

**假设输出:**

* `matcher` 函数返回 0 (表示匹配成功)。
* 如果请求了子表达式匹配信息，`pmatch` 数组会包含匹配的起始和结束位置：
    * `pmatch[0].rm_so = 0` (整个匹配从字符串的索引 0 开始)
    * `pmatch[0].rm_eo = 4` (整个匹配到字符串的索引 4 结束)

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记转义特殊字符:**
   * **错误示例:** 使用 `.` 来匹配字面意义的点号。
   * **正确示例:** 使用 `\.` 来匹配字面意义的点号。
   * **说明:** `.` 在正则表达式中是特殊字符，匹配任意单个字符。要匹配字面意义的点号，需要使用反斜杠进行转义。

2. **对量词的理解错误:**
   * **错误示例:** 期望 `a*` 只匹配一个或多个 'a'。
   * **正确理解:** `a*` 匹配零个或多个 'a'。要匹配一个或多个 'a'，应使用 `a+`。

3. **回溯过多导致性能问题:**
   * **错误示例:** 使用复杂的、嵌套的量词，例如 `(a+)*b`，在某些输入下可能导致大量的回溯，使匹配过程非常缓慢。
   * **改进:** 尽量使用更明确的模式，减少不必要的回溯。

4. **未锚定正则表达式导致意外匹配:**
   * **错误示例:** 使用 `abc` 来匹配以 "abc" 开头的字符串，但实际上 `abc` 会匹配任何包含 "abc" 的字符串。
   * **正确示例:** 使用 `^abc` 来匹配以 "abc" 开头的字符串。

5. **字符集使用错误:**
   * **错误示例:**  期望 `[^abc]` 只匹配非 'a'、非 'b' 且非 'c' 的字符。
   * **正确理解:** `[^abc]` 匹配除了 'a'、'b' 或 'c' 以外的任何单个字符。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `engine.c` 的路径:**

1. **Java Framework (e.g., `java.util.regex.Pattern`, `java.util.regex.Matcher`):**  Android 应用通常通过 Java 框架提供的 `java.util.regex` 包来使用正则表达式。

2. **Native Method Calls:** `java.util.regex.Pattern` 和 `java.util.regex.Matcher` 的许多方法最终会调用到本地 (native) 方法。这些本地方法通常在 `libjavacrypto.so` 或其他相关库中实现。

3. **JNI 调用:** 这些本地方法通过 JNI (Java Native Interface) 与 C/C++ 代码进行交互。

4. **Bionic Libc (`libc.so`):**  `libjavacrypto.so` (或相关的 JNI 库) 会链接到 Bionic libc，其中包含了 `regcomp`, `regexec` 等 POSIX 正则表达式 API 的实现。

5. **`regexec` 调用:**  在 `libc.so` 中，`regexec` 函数会被调用，它会接收编译后的正则表达式结构和要匹配的字符串。

6. **`matcher` 调用:** `regexec` 函数内部会调用 `engine.c` 中定义的 `matcher` 函数来执行实际的匹配操作。

**Android NDK 到 `engine.c` 的路径:**

1. **NDK Includes (`<regex.h>`):**  使用 NDK 开发的 C/C++ 代码可以直接包含 `<regex.h>` 头文件。

2. **Bionic Libc Linking:**  NDK 编译的应用程序会链接到 Bionic libc。

3. **`regcomp` 和 `regexec` 调用:**  NDK 代码可以直接调用 `regcomp` 来编译正则表达式，然后调用 `regexec` 来执行匹配。

4. **`matcher` 调用:** 同样地，`regexec` 函数内部会调用 `engine.c` 中的 `matcher` 函数。

**Frida Hook 示例:**

以下是一个使用 Frida hook `matcher` 函数的示例，用于观察其参数：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const matcherPtr = Module.findExportByName("libc.so", "matcher");

  if (matcherPtr) {
    Interceptor.attach(matcherPtr, {
      onEnter: function (args) {
        console.log("[+] matcher called");
        console.log("[-] Regex guts:", args[0]); // 指向 re_guts 结构的指针
        console.log("[-] String:", args[1].readUtf8String()); // 要匹配的字符串
        console.log("[-] nmatch:", args[2]); // pmatch 数组的大小
        console.log("[-] pmatch:", args[3]); // 指向 regmatch_t 数组的指针
        console.log("[-] eflags:", args[4]); // 标志位
      },
      onLeave: function (retval) {
        console.log("[-] matcher returned:", retval);
      }
    });
  } else {
    console.log("[-] matcher function not found in libc.so");
  }
} else {
  console.log("[-] Frida hook example is for arm64 or x64 architecture.");
}
```

**Frida Hook 代码解释:**

1. **检查架构:**  `Process.arch` 用于检查当前进程的架构，因为函数参数传递方式可能因架构而异。
2. **查找 `matcher` 函数:** `Module.findExportByName("libc.so", "matcher")` 尝试在 `libc.so` 中查找名为 "matcher" 的导出函数。
3. **附加拦截器:** `Interceptor.attach(matcherPtr, ...)` 用于在 `matcher` 函数的入口和出口处插入自定义的代码。
4. **`onEnter` 回调:**  当 `matcher` 函数被调用时，`onEnter` 回调函数会被执行。`args` 数组包含了传递给 `matcher` 函数的参数。我们打印了这些参数的值，包括正则表达式结构指针、输入字符串、匹配数量和标志位。
5. **`onLeave` 回调:** 当 `matcher` 函数执行完毕并返回时，`onLeave` 回调函数会被执行。`retval` 包含了函数的返回值。

**使用 Frida Hook 调试步骤:**

1. **准备 Frida 环境:**  确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_matcher.js`。
3. **运行目标应用:** 启动你想要调试的 Android 应用程序。
4. **执行 Frida 命令:** 使用 Frida 命令行工具将脚本注入到目标应用程序的进程中：
   ```bash
   frida -U -f <目标应用包名> -l hook_matcher.js --no-pause
   ```
   将 `<目标应用包名>` 替换为你想要调试的应用程序的包名。
5. **观察输出:** 当应用程序执行涉及到正则表达式匹配的代码时，Frida 会拦截 `matcher` 函数的调用，并在终端中打印出相应的参数和返回值信息。

通过 Frida hook，你可以动态地观察 `matcher` 函数的执行过程，了解它接收到的参数，并验证你的理解。这对于调试正则表达式相关的错误或分析性能问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/regex/engine.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* $NetBSD: engine.c,v 1.29 2021/02/25 21:47:46 christos Exp $ */

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
 *	@(#)engine.c	8.5 (Berkeley) 3/20/94
 */

#include <sys/cdefs.h>
#ifdef __FBSDID
__FBSDID("$FreeBSD: head/lib/libc/regex/engine.c 368358 2020-12-05 03:16:05Z kevans $");
#endif
__RCSID("$NetBSD: engine.c,v 1.29 2021/02/25 21:47:46 christos Exp $");

#include <stdbool.h>

/*
 * The matching engine and friends.  This file is #included by regexec.c
 * after suitable #defines of a variety of macros used herein, so that
 * different state representations can be used without duplicating masses
 * of code.
 */

#ifdef SNAMES
#define	stepback sstepback
#define	matcher	smatcher
#define	walk	swalk
#define	dissect	sdissect
#define	backref	sbackref
#define	step	sstep
#define	print	sprint
#define	at	sat
#define	match	smat
#endif
#ifdef LNAMES
#define	stepback lstepback
#define	matcher	lmatcher
#define	walk	lwalk
#define	dissect	ldissect
#define	backref	lbackref
#define	step	lstep
#define	print	lprint
#define	at	lat
#define	match	lmat
#endif
#ifdef MNAMES
#define	stepback mstepback
#define	matcher	mmatcher
#define	walk	mwalk
#define	dissect	mdissect
#define	backref	mbackref
#define	step	mstep
#define	print	mprint
#define	at	mat
#define	match	mmat
#endif

/* another structure passed up and down to avoid zillions of parameters */
struct match {
	struct re_guts *g;
	int eflags;
	regmatch_t *pmatch;	/* [nsub+1] (0 element unused) */
	const char *offp;	/* offsets work from here */
	const char *beginp;	/* start of string -- virtual NUL precedes */
	const char *endp;	/* end of string -- virtual NUL here */
	const char *coldp;	/* can be no match starting before here */
	const char **lastpos;	/* [nplus+1] */
	STATEVARS;
	states st;		/* current states */
	states fresh;		/* states for a fresh start */
	states tmp;		/* temporary */
	states empty;		/* empty set of states */
	mbstate_t mbs;		/* multibyte conversion state */
};

/* ========= begin header generated by ./mkh ========= */
#ifdef __cplusplus
extern "C" {
#endif

/* === engine.c === */
static int matcher(struct re_guts *g, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);
static const char *dissect(struct match *m, const char *start, const char *stop, sopno startst, sopno stopst);
static const char *backref(struct match *m, const char *start, const char *stop, sopno startst, sopno stopst, sopno lev, int);
static const char *walk(struct match *m, const char *start, const char *stop, sopno startst, sopno stopst, bool fast);
static states step(struct re_guts *g, sopno start, sopno stop, states bef, wint_t ch, states aft, int sflags);
#define MAX_RECURSION	100
#define	BOL	(OUT-1)
#define	EOL	(BOL-1)
#define	BOLEOL	(BOL-2)
#define	NOTHING	(BOL-3)
#define	BOW	(BOL-4)
#define	EOW	(BOL-5)
#define	BADCHAR	(BOL-6)
#define	NWBND	(BOL-7)
#define	NONCHAR(c)	((c) <= OUT)
/* sflags */
#define	SBOS	0x0001
#define	SEOS	0x0002

#ifdef REDEBUG
static void print(struct match *m, const char *caption, states st, int ch, FILE *d);
#endif
#ifdef REDEBUG
static void at(struct match *m, const char *title, const char *start, const char *stop, sopno startst, sopno stopst);
#endif
#ifdef REDEBUG
static const char *pchar(int ch);
#endif

#ifdef __cplusplus
}
#endif
/* ========= end header generated by ./mkh ========= */

#ifdef REDEBUG
#define	SP(t, s, c)	print(m, t, s, c, stdout)
#define	AT(t, p1, p2, s1, s2)	at(m, t, p1, p2, s1, s2)
#define	NOTE(str)	{ if (m->eflags&REG_TRACE) printf("=%s\n", (str)); }
#else
#define	SP(t, s, c)	/* nothing */
#define	AT(t, p1, p2, s1, s2)	/* nothing */
#define	NOTE(s)	/* nothing */
#endif

/*
 * Given a multibyte string pointed to by start, step back nchar characters
 * from current position pointed to by cur.
 */
static const char *
stepback(const char *start, const char *cur, int nchar)
{
#ifdef NLS
	const char *ret;
	size_t wc, mbc;
	mbstate_t mbs;
	size_t clen;

	if (MB_CUR_MAX == 1)
		goto out;

	ret = cur;
	for (wc = nchar; wc > 0; wc--) {
		for (mbc = 1; mbc <= MB_CUR_MAX; mbc++) {
			if ((ret - mbc) < start)
				return (NULL);
			memset(&mbs, 0, sizeof(mbs));
			clen = mbrtowc(NULL, ret - mbc, mbc, &mbs);
			if (clen != (size_t)-1 && clen != (size_t)-2)
				break;
		}
		if (mbc > MB_CUR_MAX)
			return (NULL);
		ret -= mbc;
	}

	return (ret);
out:
#endif
	return (cur - nchar) > start ? cur - nchar : NULL;
}

/*
 - matcher - the actual matching engine
 == static int matcher(struct re_guts *g, const char *string, \
 ==	size_t nmatch, regmatch_t pmatch[], int eflags);
 */
static int			/* 0 success, REG_NOMATCH failure */
matcher(struct re_guts *g,
	const char *string,
	size_t nmatch,
	regmatch_t pmatch[],
	int eflags)
{
	const char *endp;
	size_t i;
	struct match mv;
	struct match *m = &mv;
	const char *dp = NULL;
	const sopno gf = g->firststate+1;	/* +1 for OEND */
	const sopno gl = g->laststate;
	const char *start;
	const char *stop;
	/* Boyer-Moore algorithms variables */
	const char *pp;
	size_t cj, mj;
	const char *mustfirst;
	const char *mustlast;
	size_t *matchjump;
	size_t *charjump;
	int error = 0;

	_DIAGASSERT(g != NULL);
	_DIAGASSERT(string != NULL);
	/* pmatch checked below */

	/* simplify the situation where possible */
	if (g->cflags&REG_NOSUB)
		nmatch = 0;
	if (eflags&REG_STARTEND) {
		_DIAGASSERT(pmatch != NULL);
		start = string + (size_t)pmatch[0].rm_so;
		stop = string + (size_t)pmatch[0].rm_eo;
	} else {
		start = string;
		stop = start + strlen(start);
	}
	if (stop < start)
		return(REG_INVARG);

	/* prescreening; this does wonders for this rather slow code */
	if (g->must != NULL) {
		if (g->charjump != NULL && g->matchjump != NULL) {
			mustfirst = g->must;
			mustlast = g->must + g->mlen - 1;
			charjump = g->charjump;
			matchjump = g->matchjump;
			pp = mustlast;
			for (dp = start+g->mlen-1; dp < stop;) {
				/* Fast skip non-matches */
				while (dp < stop && charjump[(int)*dp])
					dp += charjump[(int)*dp];

				if (dp >= stop)
					break;

				/* Greedy matcher */
				/* We depend on not being used for
				 * for strings of length 1
				 */
				while (*--dp == *--pp && pp != mustfirst);

				if (*dp == *pp)
					break;

				/* Jump to next possible match */
				mj = matchjump[pp - mustfirst];
				cj = charjump[(int)*dp];
				dp += (cj < mj ? mj : cj);
				pp = mustlast;
			}
			if (pp != mustfirst)
				return(REG_NOMATCH);
		} else {
			for (dp = start; dp < stop; dp++)
				if (*dp == g->must[0] &&
				    (size_t)(stop - dp) >= g->mlen &&
				    memcmp(dp, g->must, (size_t)g->mlen) == 0)
					break;
			if (dp == stop)		/* we didn't find g->must */
				return(REG_NOMATCH);
		}
	}

	/* match struct setup */
	m->g = g;
	m->eflags = eflags;
	m->pmatch = NULL;
	m->lastpos = NULL;
	m->offp = string;
	m->beginp = start;
	m->endp = stop;
	STATESETUP(m, 4);
	SETUP(m->st);
	SETUP(m->fresh);
	SETUP(m->tmp);
	SETUP(m->empty);
	CLEAR(m->empty);
	ZAPSTATE(&m->mbs);

	/* Adjust start according to moffset, to speed things up */
	if (dp != NULL && g->moffset > -1) {
		const char *nstart;

		nstart = stepback(start, dp, g->moffset);
		if (nstart != NULL)
			start = nstart;
	}

	SP("mloop", m->st, *start);

	/* this loop does only one repetition except for backrefs */
	for (;;) {
		endp = walk(m, start, stop, gf, gl, true);
		if (endp == NULL) {		/* a miss */
			error = REG_NOMATCH;
			goto done;
		}
		if (nmatch == 0 && !g->backrefs)
			break;		/* no further info needed */

		/* where? */
		assert(m->coldp != NULL);
		for (;;) {
			NOTE("finding start");
			endp = walk(m, m->coldp, stop, gf, gl, false);
			if (endp != NULL)
				break;
			assert(m->coldp < m->endp);
			m->coldp += XMBRTOWC(NULL, m->coldp,
			    (size_t)(m->endp - m->coldp), &m->mbs, 0);
		}
		if (nmatch == 1 && !g->backrefs)
			break;		/* no further info needed */

		/* oh my, he wants the subexpressions... */
		if (m->pmatch == NULL)
			m->pmatch = (regmatch_t *)malloc((m->g->nsub + 1) *
							sizeof(regmatch_t));
		if (m->pmatch == NULL) {
			error = REG_ESPACE;
			goto done;
		}
		for (i = 1; i <= m->g->nsub; i++)
			m->pmatch[i].rm_so = m->pmatch[i].rm_eo = -1;
		if (!g->backrefs && !(m->eflags&REG_BACKR)) {
			NOTE("dissecting");
			dp = dissect(m, m->coldp, endp, gf, gl);
		} else {
			if (g->nplus > 0 && m->lastpos == NULL)
				m->lastpos = malloc((g->nplus+1) *
						sizeof(const char *));
			if (g->nplus > 0 && m->lastpos == NULL) {
				error = REG_ESPACE;
				goto done;
			}
			NOTE("backref dissect");
			dp = backref(m, m->coldp, endp, gf, gl, (sopno)0, 0);
		}
		if (dp != NULL)
			break;

		/* uh-oh... we couldn't find a subexpression-level match */
		assert(g->backrefs);	/* must be back references doing it */
		assert(g->nplus == 0 || m->lastpos != NULL);
		for (;;) {
			if (dp != NULL || endp <= m->coldp)
				break;		/* defeat */
			NOTE("backoff");
			endp = walk(m, m->coldp, endp-1, gf, gl, false);
			if (endp == NULL)
				break;		/* defeat */
			/* try it on a shorter possibility */
#ifndef NDEBUG
			for (i = 1; i <= m->g->nsub; i++) {
				assert(m->pmatch[i].rm_so == (regoff_t)-1);
				assert(m->pmatch[i].rm_eo == (regoff_t)-1);
			}
#endif
			NOTE("backoff dissect");
			dp = backref(m, m->coldp, endp, gf, gl, (sopno)0, 0);
		}
		assert(dp == NULL || dp == endp);
		if (dp != NULL)		/* found a shorter one */
			break;

		/* despite initial appearances, there is no match here */
		NOTE("false alarm");
		/* recycle starting later */
		start = m->coldp + XMBRTOWC(NULL, m->coldp,
		    (size_t)(stop - m->coldp), &m->mbs, 0);
		assert(start <= stop);
	}

	/* fill in the details if requested */
	if (nmatch > 0) {
		_DIAGASSERT(pmatch != NULL);
		pmatch[0].rm_so = m->coldp - m->offp;
		pmatch[0].rm_eo = endp - m->offp;
	}
	if (nmatch > 1) {
		assert(m->pmatch != NULL);
		for (i = 1; i < nmatch; i++)
			if (i <= m->g->nsub)
				pmatch[i] = m->pmatch[i];
			else {
				pmatch[i].rm_so = (regoff_t)-1;
				pmatch[i].rm_eo = (regoff_t)-1;
			}
	}

done:
	if (m->pmatch != NULL) {
		free(m->pmatch);
		m->pmatch = NULL;
	}
	if (m->lastpos != NULL) {
		free(__UNCONST(m->lastpos));
		m->lastpos = NULL;
	}
	STATETEARDOWN(m);
	return error;
}

/*
 - dissect - figure out what matched what, no back references
 == static const char *dissect(struct match *m, const char *start, \
 ==	const char *stop, sopno startst, sopno stopst);
 */
static const char *		/* == stop (success) always */
dissect(
	struct match *m,
	const char *start,
	const char *stop,
	sopno startst,
	sopno stopst)
{
	int i;
	sopno ss;		/* start sop of current subRE */
	sopno es;		/* end sop of current subRE */
	const char *sp;		/* start of string matched by it */
	const char *stp;	/* string matched by it cannot pass here */
	const char *rest;	/* start of rest of string */
	const char *tail;	/* string unmatched by rest of RE */
	sopno ssub;		/* start sop of subsubRE */
	sopno esub;		/* end sop of subsubRE */
	const char *ssp;	/* start of string matched by subsubRE */
	const char *sep;	/* end of string matched by subsubRE */
	const char *oldssp;	/* previous ssp */
	const char *dp __unused;

	_DIAGASSERT(m != NULL);
	_DIAGASSERT(start != NULL);
	_DIAGASSERT(stop != NULL);

	AT("diss", start, stop, startst, stopst);
	sp = start;
	for (ss = startst; ss < stopst; ss = es) {
		/* identify end of subRE */
		es = ss;
		switch (OP(m->g->strip[es])) {
		case OPLUS_:
		case OQUEST_:
			es += OPND(m->g->strip[es]);
			break;
		case OCH_:
			while (OP(m->g->strip[es]) != O_CH)
				es += OPND(m->g->strip[es]);
			break;
		}
		es++;

		/* figure out what it matched */
		switch (OP(m->g->strip[ss])) {
		case OEND:
			assert(nope);
			break;
		case OCHAR:
			sp += XMBRTOWC(NULL, sp, (size_t)(stop - start),
			    &m->mbs, 0);
			break;
		case OBOL:
		case OEOL:
		case OBOW:
		case OEOW:
		case OBOS:
		case OEOS:
		case OWBND:
		case ONWBND:
			break;
		case OANY:
		case OANYOF:
			sp += XMBRTOWC(NULL, sp, (size_t)(stop - start),
			    &m->mbs, 0);
			break;
		case OBACK_:
		case O_BACK:
			assert(nope);
			break;
		/* cases where length of match is hard to find */
		case OQUEST_:
			stp = stop;
			for (;;) {
				/* how long could this one be? */
				rest = walk(m, sp, stp, ss, es, false);
				assert(rest != NULL);	/* it did match */
				/* could the rest match the rest? */
				tail = walk(m, rest, stop, es, stopst, false);
				if (tail == stop)
					break;		/* yes! */
				/* no -- try a shorter match for this one */
				stp = rest - 1;
				assert(stp >= sp);	/* it did work */
			}
			ssub = ss + 1;
			esub = es - 1;
			/* did innards match? */
			if (walk(m, sp, rest, ssub, esub, false) != NULL) {
				dp = dissect(m, sp, rest, ssub, esub);
				assert(dp == rest);
			} else		/* no */
				assert(sp == rest);
			sp = rest;
			break;
		case OPLUS_:
			stp = stop;
			for (;;) {
				/* how long could this one be? */
				rest = walk(m, sp, stp, ss, es, false);
				assert(rest != NULL);	/* it did match */
				/* could the rest match the rest? */
				tail = walk(m, rest, stop, es, stopst, false);
				if (tail == stop)
					break;		/* yes! */
				/* no -- try a shorter match for this one */
				stp = rest - 1;
				assert(stp >= sp);	/* it did work */
			}
			ssub = ss + 1;
			esub = es - 1;
			ssp = sp;
			oldssp = ssp;
			for (;;) {	/* find last match of innards */
				sep = walk(m, ssp, rest, ssub, esub, false);
				if (sep == NULL || sep == ssp)
					break;	/* failed or matched null */
				oldssp = ssp;	/* on to next try */
				ssp = sep;
			}
			if (sep == NULL) {
				/* last successful match */
				sep = ssp;
				ssp = oldssp;
			}
			assert(sep == rest);	/* must exhaust substring */
			assert(walk(m, ssp, sep, ssub, esub, false) == rest);
			dp = dissect(m, ssp, sep, ssub, esub);
			assert(dp == sep);
			sp = rest;
			break;
		case OCH_:
			stp = stop;
			for (;;) {
				/* how long could this one be? */
				rest = walk(m, sp, stp, ss, es, false);
				assert(rest != NULL);	/* it did match */
				/* could the rest match the rest? */
				tail = walk(m, rest, stop, es, stopst, false);
				if (tail == stop)
					break;		/* yes! */
				/* no -- try a shorter match for this one */
				stp = rest - 1;
				assert(stp >= sp);	/* it did work */
			}
			ssub = ss + 1;
			esub = ss + OPND(m->g->strip[ss]) - 1;
			assert(OP(m->g->strip[esub]) == OOR1);
			for (;;) {	/* find first matching branch */
				if (walk(m, sp, rest, ssub, esub, false) == rest)
					break;	/* it matched all of it */
				/* that one missed, try next one */
				assert(OP(m->g->strip[esub]) == OOR1);
				esub++;
				assert(OP(m->g->strip[esub]) == OOR2);
				ssub = esub + 1;
				esub += OPND(m->g->strip[esub]);
				if (OP(m->g->strip[esub]) == OOR2)
					esub--;
				else
					assert(OP(m->g->strip[esub]) == O_CH);
			}
			dp = dissect(m, sp, rest, ssub, esub);
			assert(dp == rest);
			sp = rest;
			break;
		case O_PLUS:
		case O_QUEST:
		case OOR1:
		case OOR2:
		case O_CH:
			assert(nope);
			break;
		case OLPAREN:
			i = OPND(m->g->strip[ss]);
			assert(0 < i && i <= m->g->nsub);
			m->pmatch[i].rm_so = sp - m->offp;
			break;
		case ORPAREN:
			i = OPND(m->g->strip[ss]);
			assert(0 < i && i <= m->g->nsub);
			m->pmatch[i].rm_eo = sp - m->offp;
			break;
		default:		/* uh oh */
			assert(nope);
			break;
		}
	}

	assert(sp == stop);
	return(sp);
}

#define	ISBOW(m, sp)					\
    (sp < m->endp && ISWORD(*sp) &&			\
    ((sp == m->beginp && !(m->eflags&REG_NOTBOL)) ||	\
    (sp > m->offp && !ISWORD(*(sp-1)))))
#define	ISEOW(m, sp)					\
    (((sp == m->endp && !(m->eflags&REG_NOTEOL)) ||	\
    (sp < m->endp && *sp == '\n' &&			\
    (m->g->cflags&REG_NEWLINE)) ||			\
    (sp < m->endp && !ISWORD(*sp)) ) &&			\
    (sp > m->beginp && ISWORD(*(sp-1))))		\

/*
 - backref - figure out what matched what, figuring in back references
 == static const char *backref(struct match *m, const char *start, \
 ==	const char *stop, sopno startst, sopno stopst, sopno lev);
 */
static const char *		/* == stop (success) or NULL (failure) */
backref(
	struct match *m,
	const char *start,
	const char *stop,
	sopno startst,
	sopno stopst,
	sopno lev,		/* PLUS nesting level */
	int rec)
{
	int i;
	sopno ss;		/* start sop of current subRE */
	const char *sp;		/* start of string matched by it */
	sopno ssub;		/* start sop of subsubRE */
	sopno esub;		/* end sop of subsubRE */
	const char *ssp;	/* start of string matched by subsubRE */
	const char *dp;
	size_t len;
	int hard;
	sop s;
	regoff_t offsave;
	cset *cs;
	wint_t wc;

	_DIAGASSERT(m != NULL);
	_DIAGASSERT(start != NULL);
	_DIAGASSERT(stop != NULL);

	AT("back", start, stop, startst, stopst);
	sp = start;

	/* get as far as we can with easy stuff */
	hard = 0;
	for (ss = startst; !hard && ss < stopst; ss++)
		switch (OP(s = m->g->strip[ss])) {
		case OCHAR:
			if (sp == stop)
				return(NULL);
			sp += XMBRTOWC(&wc, sp, (size_t)(stop - sp),
			    &m->mbs, BADCHAR);
			if (wc != (wint_t)OPND(s))
				return(NULL);
			break;
		case OANY:
			if (sp == stop)
				return(NULL);
			sp += XMBRTOWC(&wc, sp, (size_t)(stop - sp),
			    &m->mbs, BADCHAR);
			if (wc == BADCHAR)
				return (NULL);
			break;
		case OANYOF:
			if (sp == stop)
				return (NULL);
			cs = &m->g->sets[OPND(s)];
			sp += XMBRTOWC(&wc, sp, (size_t)(stop - sp),
			    &m->mbs, BADCHAR);
			if (wc == BADCHAR || !CHIN(cs, wc))
				return(NULL);
			break;
		case OBOS:
			if (sp == m->beginp && (m->eflags & REG_NOTBOL) == 0)
				{ /* yes */ }
			else
				return(NULL);
			break;
		case OEOS:
			if (sp == m->endp && (m->eflags & REG_NOTEOL) == 0)
				{ /* yes */ }
			else
				return(NULL);
			break;
		case OBOL:
			if ((sp == m->beginp && !(m->eflags&REG_NOTBOL)) ||
			    (sp > m->offp && sp < m->endp &&
			    *(sp-1) == '\n' && (m->g->cflags&REG_NEWLINE)))
				{ /* yes */ }
			else
				return(NULL);
			break;
		case OEOL:
			if ( (sp == m->endp && !(m->eflags&REG_NOTEOL)) ||
					(sp < m->endp && *sp == '\n' &&
						(m->g->cflags&REG_NEWLINE)) )
				{ /* yes */ }
			else
				return(NULL);
			break;
		case OWBND:
			if (ISBOW(m, sp) || ISEOW(m, sp))
				{ /* yes */ }
			else
				return(NULL);
			break;
		case ONWBND:
			if (((sp == m->beginp) && !ISWORD(*sp)) ||
			    (sp == m->endp && !ISWORD(*(sp - 1))))
				{ /* yes, beginning/end of subject */ }
			else if (ISWORD(*(sp - 1)) == ISWORD(*sp))
				{ /* yes, beginning/end of subject */ }
			else
				return(NULL);
			break;
		case OBOW:
			if (ISBOW(m, sp))
				{ /* yes */ }
			else
				return(NULL);
			break;
		case OEOW:
			if (ISEOW(m, sp))
				{ /* yes */ }
			else
				return(NULL);
			break;
		case O_QUEST:
			break;
		case OOR1:	/* matches null but needs to skip */
			ss++;
			s = m->g->strip[ss];
			do {
				assert(OP(s) == OOR2);
				ss += OPND(s);
			} while (OP(s = m->g->strip[ss]) != O_CH);
			/* note that the ss++ gets us past the O_CH */
			break;
		default:	/* have to make a choice */
			hard = 1;
			break;
		}
	if (!hard) {		/* that was it! */
		if (sp != stop)
			return(NULL);
		return(sp);
	}
	ss--;			/* adjust for the for's final increment */

	/* the hard stuff */
	AT("hard", sp, stop, ss, stopst);
	s = m->g->strip[ss];
	switch (OP(s)) {
	case OBACK_:		/* the vilest depths */
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		if (m->pmatch[i].rm_eo == -1)
			return(NULL);
		assert(m->pmatch[i].rm_so != -1);
		len = m->pmatch[i].rm_eo - m->pmatch[i].rm_so;
		if (len == 0 && rec++ > MAX_RECURSION)
			return(NULL);
		assert(stop - m->beginp >= len);
		if (sp > stop - len)
			return(NULL);	/* not enough left to match */
		ssp = m->offp + m->pmatch[i].rm_so;
		if (memcmp(sp, ssp, len) != 0)
			return(NULL);
		while (m->g->strip[ss] != SOP(O_BACK, i))
			ss++;
		return(backref(m, sp+len, stop, ss+1, stopst, lev, rec));
	case OQUEST_:		/* to null or not */
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);	/* not */
		return(backref(m, sp, stop, ss+OPND(s)+1, stopst, lev, rec));
	case OPLUS_:
		assert(m->lastpos != NULL);
		assert(lev+1 <= m->g->nplus);
		m->lastpos[lev+1] = sp;
		return(backref(m, sp, stop, ss+1, stopst, lev+1, rec));
	case O_PLUS:
		if (sp == m->lastpos[lev])	/* last pass matched null */
			return(backref(m, sp, stop, ss+1, stopst, lev-1, rec));
		/* try another pass */
		m->lastpos[lev] = sp;
		dp = backref(m, sp, stop, ss-OPND(s)+1, stopst, lev, rec);
		if (dp == NULL)
			return(backref(m, sp, stop, ss+1, stopst, lev-1, rec));
		else
			return(dp);
	case OCH_:		/* find the right one, if any */
		ssub = ss + 1;
		esub = ss + OPND(s) - 1;
		assert(OP(m->g->strip[esub]) == OOR1);
		for (;;) {	/* find first matching branch */
			dp = backref(m, sp, stop, ssub, esub, lev, rec);
			if (dp != NULL)
				return(dp);
			/* that one missed, try next one */
			if (OP(m->g->strip[esub]) == O_CH)
				return(NULL);	/* there is none */
			esub++;
			assert(OP(m->g->strip[esub]) == OOR2);
			ssub = esub + 1;
			esub += OPND(m->g->strip[esub]);
			if (OP(m->g->strip[esub]) == OOR2)
				esub--;
			else
				assert(OP(m->g->strip[esub]) == O_CH);
		}
		/* NOTREACHED */
		break;
	case OLPAREN:		/* must undo assignment if rest fails */
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		offsave = m->pmatch[i].rm_so;
		m->pmatch[i].rm_so = sp - m->offp;
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);
		m->pmatch[i].rm_so = offsave;
		return(NULL);
	case ORPAREN:		/* must undo assignment if rest fails */
		i = OPND(s);
		assert(0 < i && i <= m->g->nsub);
		offsave = m->pmatch[i].rm_eo;
		m->pmatch[i].rm_eo = sp - m->offp;
		dp = backref(m, sp, stop, ss+1, stopst, lev, rec);
		if (dp != NULL)
			return(dp);
		m->pmatch[i].rm_eo = offsave;
		return(NULL);
	default:		/* uh oh */
		assert(nope);
		break;
	}

	/* "can't happen" */
	assert(nope);
	/* NOTREACHED */
	return "shut up gcc";
}

/*
 - walk - step through the string either quickly or slowly
 == static const char *walk(struct match *m, const char *start, \
 ==	const char *stop, sopno startst, sopno stopst, bool fast);
 */
static const char * /* where it ended, or NULL */
walk(struct match *m, const char *start, const char *stop, sopno startst,
	sopno stopst, bool fast)
{
	states st = m->st;
	states fresh = m->fresh;
	states empty = m->empty;
	states tmp = m->tmp;
	const char *p = start;
	wint_t c;
	wint_t lastc;		/* previous c */
	wint_t flagch;
	int sflags;
	const char *matchp;	/* last p at which a match ended */
	size_t i, clen;

	_DIAGASSERT(m != NULL);
	_DIAGASSERT(start != NULL);
	_DIAGASSERT(stop != NULL);

	sflags = 0;
	AT("walk", start, stop, startst, stopst);
	CLEAR(st);
	SET1(st, startst);
	SP("sstart", st, *p);
	st = step(m->g, startst, stopst, st, NOTHING, st, sflags);
	if (fast)
		ASSIGN(fresh, st);
	matchp = NULL;
	if (start == m->offp || (start == m->beginp && !(m->eflags&REG_NOTBOL)))
		c = OUT;
	else {
		/*
		 * XXX Wrong if the previous character was multi-byte.
		 * Newline never is (in encodings supported by FreeBSD),
		 * so this only breaks the ISWORD tests below.
		 */
		c = (uch)*(start - 1);
	}
	for (;;) {
		/* next character */
		lastc = c;
		sflags = 0;
		if (p == m->endp) {
			c = OUT;
			clen = 0;
		} else
			clen = XMBRTOWC(&c, p, (size_t)(m->endp - p),
			    &m->mbs, BADCHAR);

		if (fast && EQ(st, fresh))
			matchp = p;

		/* is there an EOL and/or BOL between lastc and c? */
		flagch = '\0';
		i = 0;
		if ( (lastc == '\n' && m->g->cflags&REG_NEWLINE) ||
				(lastc == OUT && !(m->eflags&REG_NOTBOL)) ) {
			flagch = BOL;
			i = m->g->nbol;
		}
		if ( (c == '\n' && m->g->cflags&REG_NEWLINE) ||
				(c == OUT && !(m->eflags&REG_NOTEOL)) ) {
			flagch = (flagch == BOL) ? BOLEOL : EOL;
			i += m->g->neol;
		}
		if (lastc == OUT && (m->eflags & REG_NOTBOL) == 0) {
			sflags |= SBOS;
			/* Step one more for BOS. */
			i++;
		}
		if (c == OUT && (m->eflags & REG_NOTEOL) == 0) {
			sflags |= SEOS;
			/* Step one more for EOS. */
			i++;
		}
		if (i != 0) {
			for (; i > 0; i--)
				st = step(m->g, startst, stopst, st, flagch, st,
				    sflags);
			SP("sboleol", st, c);
		}

		/* how about a word boundary? */
		if ( (flagch == BOL || (lastc != OUT && !ISWORD(lastc))) &&
					(c != OUT && ISWORD(c)) ) {
			flagch = BOW;
		}
		if ( (lastc != OUT && ISWORD(lastc)) &&
				(flagch == EOL || (c != OUT && !ISWORD(c))) ) {
			flagch = EOW;
		}
		if (flagch == BOW || flagch == EOW) {
			st = step(m->g, startst, stopst, st, flagch, st, sflags);
			SP("sboweow", st, c);
		}
		if (lastc != OUT && c != OUT &&
		    ISWORD(lastc) == ISWORD(c)) {
			flagch = NWBND;
		} else if ((lastc == OUT && !ISWORD(c)) ||
		    (c == OUT && !ISWORD(lastc))) {
			flagch = NWBND;
		}
		if (flagch == NWBND) {
			st = step(m->g, startst, stopst, st, flagch, st, sflags);
			SP("snwbnd", st, c);
		}

		/* are we done? */
		if (ISSET(st, stopst)) {
			if (fast)
				break;
			else
				matchp = p;
		}
		if (EQ(st, empty) || p == stop || clen > (size_t)(stop - p))
			break;		/* NOTE BREAK OUT */

		/* no, we must deal with this character */
		ASSIGN(tmp, st);
		if (fast)
			ASSIGN(st, fresh);
		else
			ASSIGN(st, empty);
		assert(c != OUT);
		st = step(m->g, startst, stopst, tmp, c, st, sflags);
		SP("saft", st, c);
		assert(EQ(step(m->g, startst, stopst, st, NOTHING, st, sflags),
		    st));
		p += clen;
	}

	if (fast) {
		assert(matchp != NULL);
		m->coldp = matchp;
		if (ISSET(st, stopst))
			return (p + XMBRTOWC(NULL, p, (size_t)(stop - p),
			    &m->mbs, 0));
		else
			return (NULL);
	} else
		return (matchp);
}

/*
 - step - map set of states reachable before char to set reachable after
 == static states step(struct re_guts *g, sopno start, sopno stop, \
 ==	states bef, int ch, states aft);
 == #define	BOL	(OUT-1)
 == #define	EOL	(BOL-1)
 == #define	BOLEOL	(BOL-2)
 == #define	NOTHING	(BOL-3)
 == #define	BOW	(BOL-4)
 == #define	EOW	(BOL-5)
 == #define	BADCHAR	(BOL-6)
 == #define	NONCHAR(c)	((c) <= OUT)
 */
static states
step(struct re_guts *g,
	sopno start,		/* start state within strip */
	sopno stop,		/* state after stop state within strip */
	states bef,		/* states reachable before */
	wint_t ch,		/* character or NONCHAR code */
	states aft,		/* states already known reachable after */
	int sflags)		/* state flags */
{
	cset *cs;
	sop s;
	sopno pc;
	onestate here;		/* note, macros know this name */
	sopno look;
	int i;

	_DIAGASSERT(g != NULL);

	for (pc = start, INIT(here, pc); pc != stop; pc++, INC(here)) {
		s = g->strip[pc];
		switch (OP(s)) {
		case OEND:
			assert(pc == stop-1);
			break;
		case OCHAR:
			/* only characters can match */
			assert(!NONCHAR(ch) || ch != OPND(s));
			if (ch == (wint_t)OPND(s))
				FWD(aft, bef, 1);
			break;
		case OBOS:
			if ((ch == BOL || ch == BOLEOL) && (sflags & SBOS) != 0)
				FWD(aft, bef, 1);
			break;
		case OEOS:
			if ((ch == EOL || ch == BOLEOL) && (sflags & SEOS) != 0)
				FWD(aft, bef, 1);
			break;
		case OBOL:
			if (ch == BOL || ch == BOLEOL)
				FWD(aft, bef, 1);
			break;
		case OEOL:
			if (ch == EOL || ch == BOLEOL)
				FWD(aft, bef, 1);
			break;
		case OBOW:
			if (ch == BOW)
				FWD(aft, bef, 1);
			break;
		case OEOW:
			if (ch == EOW)
				FWD(aft, bef, 1);
			break;
		case OWBND:
			if (ch == BOW || ch == EOW)
				FWD(aft, bef, 1);
			break;
		case ONWBND:
			if (ch == NWBND)
				FWD(aft, aft, 1);
			break;
		case OANY:
			if (!NONCHAR(ch))
				FWD(aft, bef, 1);
			break;
		case OANYOF:
			cs = &g->sets[OPND(s)];
			if (!NONCHAR(ch) && CHIN(cs, ch))
				FWD(aft, bef, 1);
			break;
		case OBACK_:		/* ignored here */
		case O_BACK:
			FWD(aft, aft, 1);
			break;
		case OPLUS_:		/* forward, this is just an empty */
			FWD(aft, aft, 1);
			break;
		case O_PLUS:		/* both forward and back */
			FWD(aft, aft, 1);
			i = ISSETBACK(aft, OPND(s));
			BACK(aft, aft, OPND(s));
			if (!i && ISSETBACK(aft, OPND(s))) {
				/* oho, must reconsider loop body */
				pc -= OPND(s) + 1;
				INIT(here, pc);
			}
			break;
		case OQUEST_:		/* two branches, both forward */
			FWD(aft, aft, 1);
			FWD(aft, aft, OPND(s));
			break;
		case O_QUEST:		/* just an empty */
			FWD(aft, aft, 1);
			break;
		case OLPAREN:		/* not significant here */
		case ORPAREN:
			FWD(aft, aft, 1);
			break;
		case OCH_:		/* mark the first two branches */
			FWD(aft, aft, 1);
			assert(OP(g->strip[pc+OPND(s)]) == OOR2);
			FWD(aft, aft, OPND(s));
			break;
		case OOR1:		/* done a branch, find the O_CH */
			if (ISSTATEIN(aft, here)) {
				for (look = 1;
				    OP(s = g->strip[pc+look]) != O_CH;
				    look += OPND(s))
					assert(OP(s) == OOR2);
				FWD(aft, aft, look + 1);
			}
			break;
		case OOR2:		/* propagate OCH_'s marking */
			FWD(aft, aft, 1);
			if (OP(g->strip[pc+OPND(s)]) != O_CH) {
				assert(OP(g->strip[pc+OPND(s)]) == OOR2);
				FWD(aft, aft, OPND(s));
			}
			break;
		case O_CH:		/* just empty */
			FWD(aft, aft, 1);
			break;
		default:		/* ooooops... */
			assert(nope);
			break;
		}
	}

	return(aft);
}

#ifdef REDEBUG
/*
 - print - print a set of states
 == #ifdef REDEBUG
 == static void print(struct match *m, const char *caption, states st, \
 ==	int ch, FILE *d);
 == #endif
 */
static void
print(struct match *m,
	const char *caption,
	states st,
	int ch,
	FILE *d)
{
	struct re_guts *g = m->g;
	sopno i;
	int first = 1;

	_DIAGASSERT(m != NULL);
	_DIAGASSERT(caption != NULL);

	if (!(m->eflags&REG_TRACE))
		return;

	_DIAGASSERT(d != NULL);

	fprintf(d, "%s", caption);
	if (ch != '\0')
		fprintf(d, " %s", pchar(ch));
	for (i = 0; i < g->nstates; i++)
		if (ISSET(st, i)) {
			fprintf(d, "%s%lu", (first) ? "\t" : ", ", i);
			first = 0;
		}
	fprintf(d, "\n");
}

/*
 - at - print current situation
 == #ifdef REDEBUG
 == static void at(struct match *m, const char *title, const char *start, \
 ==			 const char *stop, sopno startst, sopno stopst);
 == #endif
 */
static void
at(	struct match *m,
	const char *title,
	const char *start,
	const char *stop,
	sopno startst,
	sopno stopst)
{

	_DIAGASSERT(m != NULL);
	_DIAGASSERT(title != NULL);
	_DIAGASSERT(start != NULL);
	_DIAGASSERT(stop != NULL);

	if (!(m->eflags&REG_TRACE))
		return;

	printf("%s %s-", title, pchar(*start));
	printf("%s ", pchar(*stop));
	printf("%ld-%ld\n", (long)startst, (long)stopst);
}

#ifndef PCHARDONE
#define	PCHARDONE	/* never again */
/*
 - pchar - make a character printable
 == #ifdef REDEBUG
 == static const char *pchar(int ch);
 == #endif
 *
 * Is this identical to regchar() over in debug.c?  Well, yes.  But a
 * duplicate here avoids having a debugging-capable regexec.o tied to
 * a matching debug.o, and this is convenient.  It all disappears in
 * the non-debug compilation anyway, so it doesn't matter much.
 */
static const char *		/* -> representation */
pchar(int ch)
{
	static char pbuf[10];

	if (isprint((uch)ch) || ch == ' ')
		snprintf(pbuf, sizeof(pbuf), "%c", ch);
	else
		snprintf(pbuf, sizeof(pbuf), "\\%o", ch);
	return(pbuf);
}
#endif
#endif

#undef	stepback
#undef	matcher
#undef	walk
#undef	dissect
#undef	backref
#undef	step
#undef	print
#undef	at
#undef	match
```