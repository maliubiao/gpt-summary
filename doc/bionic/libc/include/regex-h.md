Response:
Let's break down the thought process for answering the request about `bionic/libc/include/regex.handroid`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the `regex.h` header file within the Android Bionic library. The key aspects to cover are functionality, Android relevance, implementation details of libc functions, dynamic linker aspects, logical reasoning (if applicable), common errors, and how Android Framework/NDK utilize it, along with Frida hooking.

**2. Initial Analysis of `regex.h`:**

The first step is to read and understand the header file itself. Key observations:

* **License:** It's based on OpenBSD/NetBSD, indicating a standard POSIX regex implementation.
* **Includes:** `sys/cdefs.h` and `sys/types.h` suggest standard system-level definitions.
* **Typedefs:** `regoff_t`, `regex_t`, and `regmatch_t` define the core data structures for regex operations. Pay attention to the members of these structs.
* **Macros (Definitions):**  `REG_BASIC`, `REG_EXTENDED`, etc., define the flags used with `regcomp` and `regexec`. These are crucial for understanding how regex behavior is controlled. Similarly, the `REG_NOMATCH`, `REG_BADPAT`, etc., error codes are important.
* **Function Declarations:** `regcomp`, `regerror`, `regexec`, and `regfree` are the fundamental regex functions. Recognize these as the entry points for regex operations.

**3. Addressing Specific Request Points (Iterative Process):**

Now, systematically address each part of the request:

* **功能列举:**  Based on the function declarations and the structure definitions, identify the core functionalities: compiling regular expressions, executing them against strings, reporting errors, and freeing resources.

* **与 Android 功能的关系:**  Think about where regex is commonly used in Android. Text processing, input validation, pattern matching in system services, and within applications for searching and data manipulation are key areas. Provide concrete examples (e.g., validating email addresses, searching files).

* **libc 函数实现:** This requires deeper knowledge of the underlying implementation. Since the header doesn't provide the implementation, you have to infer based on common regex engine design. The key steps for each function are:
    * **`regcomp`:**  Lexing the regex, parsing it into an internal representation (NFA/DFA), and potentially optimizing it. Mention the flags that influence this process.
    * **`regexec`:**  Taking the compiled regex and the input string, performing the matching algorithm (e.g., backtracking for NFA). Explain the role of `regmatch_t` in returning match locations. Describe the impact of `REG_NOTBOL`, `REG_NOTEOL`, and `REG_STARTEND`.
    * **`regerror`:**  Mapping error codes to human-readable strings. Highlight the importance of the `errcode` and how the function populates the buffer.
    * **`regfree`:**  Releasing the memory allocated by `regcomp`. Emphasize the importance of calling this to avoid memory leaks.

* **Dynamic Linker 功能:** The header itself doesn't directly interact with the dynamic linker. However, the *implementation* of the regex functions is part of `libc.so`, which *is* managed by the dynamic linker. Explain the basic concept of shared libraries and how the linker resolves symbols. Provide a simplified `libc.so` layout and the linking process (symbol lookup, relocation).

* **逻辑推理 (假设输入与输出):** Create simple examples for each function to illustrate their behavior. This helps solidify understanding. For `regcomp`, show a simple pattern and how flags affect compilation. For `regexec`, show a string and the expected `regmatch_t` results.

* **用户或编程常见错误:**  Think about the common pitfalls when using regex: forgetting to free memory, incorrect flags, escaping issues, performance problems with complex regexes, and not handling errors properly.

* **Android Framework/NDK 到达路径:**  Trace how a regex call might originate from higher levels in the Android stack. Start with a simple example in Java (using `java.util.regex`) and explain how it eventually calls native code through JNI. Similarly, for NDK, show a direct C++ usage of the `<regex.h>` functions.

* **Frida Hook 示例:** Provide practical Frida snippets to intercept and inspect the calls to `regcomp`, `regexec`, etc. This demonstrates how to debug and analyze regex usage in a running Android process.

**4. Structuring the Answer:**

Organize the information logically, using clear headings and bullet points. Start with a general overview and then delve into the specifics of each function and aspect. Use examples to illustrate concepts.

**5. Language and Tone:**

Maintain a clear and informative tone. Explain technical terms where necessary. Since the request is in Chinese, the entire response should be in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the flags. **Correction:** While important, balance the explanation with the core functionality and implementation details.
* **Initial thought:**  Overcomplicate the dynamic linker explanation. **Correction:** Simplify it to the essentials: shared libraries, symbol resolution, and basic layout.
* **Initial thought:**  Provide very complex regex examples. **Correction:** Use simple, illustrative examples to avoid confusion.
* **Initial thought:**  Assume a deep understanding of regex concepts. **Correction:** Provide brief explanations of key regex terms like "parenthesized subexpressions" where relevant.

By following this structured and iterative approach, the goal is to provide a comprehensive and accurate answer that addresses all aspects of the request. The process involves understanding the header file, inferring implementation details, connecting it to the Android ecosystem, and providing practical examples for learning and debugging.
这是一个关于 Android Bionic 库中 `regex.h` 文件的分析。`regex.h` 定义了 POSIX 扩展正则表达式（ERE）接口，用于在程序中进行模式匹配。

**功能列举:**

`regex.h` 文件定义了以下主要功能，用于处理正则表达式：

1. **正则表达式编译 (`regcomp`):** 将一个字符串形式的正则表达式编译成一种内部表示，这种表示可以被后续的匹配操作使用。
2. **正则表达式匹配 (`regexec`):**  在一个给定的字符串中执行已编译的正则表达式的匹配操作。它可以找到字符串中与正则表达式匹配的部分。
3. **错误处理 (`regerror`):**  将 `regcomp` 或 `regexec` 产生的错误代码转换为人类可读的错误消息。
4. **释放资源 (`regfree`):**  释放由 `regcomp` 分配的用于存储已编译正则表达式的内存。

**与 Android 功能的关系及其举例说明:**

正则表达式在 Android 系统中被广泛使用，以下是一些例子：

* **文本搜索和替换:**  在文本编辑器、IDE、以及系统级别的搜索功能中，正则表达式用于定义搜索模式。例如，在 Android Studio 中使用查找/替换功能，你可以使用正则表达式来查找特定的代码结构或文本模式。
* **输入验证:**  应用程序可以使用正则表达式来验证用户输入的数据格式，例如邮箱地址、电话号码、密码强度等。例如，一个注册页面可以使用正则表达式来确保用户输入的邮箱地址符合标准格式。
* **URL 解析和路由:**  Android 系统内部，包括网络栈和应用框架，可能使用正则表达式来解析 URL 和路由请求。例如，当你的应用处理一个 Intent 时，系统可能会使用正则表达式来匹配 Intent 的数据 URI。
* **日志分析:**  Android 系统生成大量的日志信息，开发者可以使用正则表达式来过滤和分析这些日志，找出感兴趣的信息或者错误。例如，在 `adb logcat` 中，可以使用正则表达式来过滤特定进程或特定标签的日志。
* **权限控制和安全策略:**  在某些情况下，正则表达式可以用于定义安全策略或权限控制规则。例如，可以定义哪些类型的请求可以访问特定的资源。

**libc 函数的功能实现详解:**

`regex.h` 仅仅是头文件，它声明了这些函数的接口。实际的函数实现位于 Bionic 库的源代码中（通常在 `bionic/libc/src/regex` 目录下）。以下是这些函数的基本实现原理：

1. **`regcomp(regex_t* __re, const char* __regex, int __flags)`:**
   * **功能:** 将 `__regex` 指向的字符串编译成一个可以被 `regexec` 使用的内部表示，并将结果存储在 `__re` 指向的 `regex_t` 结构中。`__flags` 参数控制编译过程的行为，例如是否区分大小写 (`REG_ICASE`)，使用基本正则表达式还是扩展正则表达式 (`REG_EXTENDED`) 等。
   * **实现原理:**
     * **词法分析 (Lexing):** 扫描正则表达式字符串，将其分解成一个个的词法单元（例如，普通字符、元字符、量词等）。
     * **语法分析 (Parsing):**  根据正则表达式的语法规则，将词法单元组织成一个抽象语法树（AST）或者其他中间表示。Bionic 的实现可能使用了一种基于有限状态自动机（FSA）的方法，将正则表达式转换成非确定性有限状态自动机 (NFA) 或确定性有限状态自动机 (DFA)。
     * **优化 (Optional):**  对生成的自动机进行优化，例如合并状态、消除冗余等，以提高匹配效率。
     * **存储:** 将生成的内部表示（例如，NFA/DFA 的状态转移表、元数据等）存储在 `regex_t` 结构中。`re_g` 成员通常指向这个内部结构。
   * **假设输入与输出:**
     * **输入:** `__regex = "^a[bc]*d$"`, `__flags = REG_EXTENDED`
     * **输出:** 如果编译成功，`__re` 指向的结构将包含表示该正则表达式的内部数据。如果编译失败，`regcomp` 会返回一个非零的错误代码。

2. **`regexec(const regex_t* __re, const char* __s, size_t __match_count, regmatch_t __matches[_Nullable], int __flags)`:**
   * **功能:**  尝试将 `__s` 指向的字符串与 `__re` 指向的已编译正则表达式进行匹配。如果找到匹配项，将匹配的起始和结束位置存储在 `__matches` 数组中。`__match_count` 指定了 `__matches` 数组的大小。`__flags` 参数控制匹配过程的行为，例如是否将字符串的开头作为行的开头 (`REG_NOTBOL`)，是否将字符串的结尾作为行的结尾 (`REG_NOTEOL`)。
   * **实现原理:**
     * **状态机模拟:**  根据 `__re` 中存储的已编译正则表达式的内部表示（通常是 NFA 或 DFA），模拟状态机的运行。
     * **匹配过程:** 从输入字符串的开始位置（或由 `REG_STARTEND` 指定的位置）开始，逐个字符地遍历输入字符串，并根据状态转移规则更新状态机的状态。
     * **子表达式匹配:** 如果正则表达式包含括号括起来的子表达式，`regexec` 还会记录每个子表达式的匹配位置，并将结果存储在 `__matches` 数组中。`rm_so` 和 `rm_eo` 分别表示匹配的起始和结束偏移量。
     * **回溯 (Backtracking):** 对于 NFA，如果存在多个可能的匹配路径，匹配引擎可能会进行回溯，尝试不同的路径直到找到匹配或所有路径都尝试完毕。
   * **假设输入与输出:**
     * **输入:** `__re` 是由 `^a(b*)c$` 编译得到的， `__s = "abbbcde"`, `__match_count = 2`
     * **输出:** 如果匹配成功，返回 0，并且 `__matches[0]` 将包含整个匹配的起始和结束位置（`rm_so = 0`, `rm_eo = 5`），`__matches[1]` 将包含第一个子表达式 `(b*)` 的匹配位置（`rm_so = 1`, `rm_eo = 4`）。

3. **`regerror(int __error_code, const regex_t* _Nullable __re, char* _Nullable __buf, size_t __n)`:**
   * **功能:** 将 `__error_code` 表示的错误代码转换为人类可读的错误消息，并将结果存储在 `__buf` 指向的缓冲区中，最多存储 `__n` 个字符。`__re` 可以为 NULL，但在某些实现中，它可能用于提供更详细的错误信息。
   * **实现原理:**
     * **错误码映射:**  维护一个错误码到错误消息字符串的映射表。
     * **格式化:**  根据 `__error_code` 查找对应的错误消息字符串，并将其复制到 `__buf` 中。如果 `__re` 不为 NULL，可能会根据 `regex_t` 中的信息提供更具体的错误描述。
   * **假设输入与输出:**
     * **输入:** `__error_code = REG_BADPAT`, `__buf` 指向一个大小为 100 的缓冲区。
     * **输出:** `__buf` 中将包含类似于 "invalid regular expression" 的错误消息，`regerror` 返回消息的长度。

4. **`regfree(regex_t* __re)`:**
   * **功能:** 释放由 `regcomp` 为 `__re` 指向的 `regex_t` 结构分配的内存。
   * **实现原理:**
     * **释放内部数据:**  释放 `__re->re_g` 指向的内部结构所占用的内存。
     * **重置结构:**  通常会将 `__re` 中的指针成员设置为 NULL，以防止悬挂指针。

**涉及 dynamic linker 的功能，对应的 so 布局样本以及链接的处理过程:**

`regex.h` 定义的函数声明位于头文件中，而其实现位于 Bionic 库的动态链接共享对象 (`libc.so`) 中。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:  // 存放代码段
        regcomp:  // regcomp 函数的机器码
            ...
        regexec:  // regexec 函数的机器码
            ...
        regerror: // regerror 函数的机器码
            ...
        regfree:  // regfree 函数的机器码
            ...
    .data:  // 存放已初始化的全局变量
        ...
    .bss:   // 存放未初始化的全局变量
        ...
    .dynsym: // 动态符号表，包含导出的符号信息
        regcomp
        regexec
        regerror
        regfree
        ...
    .dynstr: // 动态字符串表，存储符号名称
        "regcomp"
        "regexec"
        "regerror"
        "regfree"
        ...
    .plt:   // 程序链接表 (Procedure Linkage Table)
        // 用于延迟绑定
        ...
```

**链接的处理过程:**

1. **编译时:** 当你编译一个使用了正则表达式的 Android Native 代码时，编译器会识别到你使用了 `regcomp`、`regexec` 等函数。
2. **链接时:**  链接器在链接你的代码时，会查找这些符号的定义。由于这些函数在 `libc.so` 中，链接器会在你的可执行文件或共享库的动态链接信息中记录对 `libc.so` 的依赖，以及需要从 `libc.so` 中解析的符号（例如 `regcomp`）。
3. **运行时:**
   * 当你的程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会被加载并执行。
   * 动态链接器会读取你的可执行文件或共享库的动态链接信息，找到所有依赖的共享库 (`libc.so` 等)。
   * 动态链接器会将这些共享库加载到内存中。
   * **符号解析 (Symbol Resolution):**  动态链接器会遍历你的程序中对外部符号的引用（例如对 `regcomp` 的调用），并在已加载的共享库的动态符号表中查找这些符号的定义。当找到 `regcomp` 在 `libc.so` 中的定义时，动态链接器会将你的程序中的调用地址更新为 `libc.so` 中 `regcomp` 函数的实际内存地址。这通常通过修改程序链接表 (PLT) 中的条目来实现 (延迟绑定)。
   * 之后，当你的程序执行到调用 `regcomp` 的代码时，它会跳转到 `libc.so` 中 `regcomp` 的实际地址执行。

**逻辑推理 (假设输入与输出):**

以下是一个使用 `regcomp` 和 `regexec` 的简单逻辑推理示例：

**假设输入:**

* 正则表达式: `"hello"`
* 待匹配字符串: `"world hello world"`

**步骤:**

1. **`regcomp`:** 使用正则表达式 `"hello"` 调用 `regcomp`。假设编译成功。
2. **`regexec`:** 使用编译后的 `regex_t` 结构和待匹配字符串 `"world hello world"` 调用 `regexec`。
3. **匹配过程:** `regexec` 会在待匹配字符串中查找与 `"hello"` 完全匹配的子串。
4. **结果:** `regexec` 会找到一个匹配项，起始位置为 6，结束位置为 11。`regmatch_t` 结构中的 `rm_so` 将为 6，`rm_eo` 将为 11。

**用户或编程常见的使用错误举例说明:**

1. **忘记调用 `regfree`:** `regcomp` 会分配内存来存储编译后的正则表达式。如果在使用完 `regex_t` 结构后不调用 `regfree`，会导致内存泄漏。

   ```c
   regex_t regex;
   int ret = regcomp(&regex, "pattern", 0);
   if (ret == 0) {
       // 使用 regex 进行匹配
       ...
       // 忘记调用 regfree(&regex);
   } else {
       // 处理编译错误
   }
   ```

2. **正则表达式语法错误:** 编写的正则表达式不符合语法规则，导致 `regcomp` 失败。需要仔细检查正则表达式的语法。

   ```c
   regex_t regex;
   int ret = regcomp(&regex, "a[bc", REG_EXTENDED); // 缺少闭合方括号
   if (ret != 0) {
       char errbuf[100];
       regerror(ret, &regex, errbuf, sizeof(errbuf));
       fprintf(stderr, "Regex compilation error: %s\n", errbuf);
   }
   ```

3. **`regmatch_t` 数组大小不足:** 当正则表达式包含多个捕获组时，需要确保传递给 `regexec` 的 `regmatch_t` 数组足够大以存储所有捕获组的匹配信息。

   ```c
   regex_t regex;
   regcomp(&regex, "a(b)(c)", REG_EXTENDED);
   regmatch_t matches[2]; // 只能存储整个匹配和第一个捕获组
   regexec(&regex, "abc", 2, matches, 0); // 可能导致越界访问
   ```

4. **不检查 `regcomp` 和 `regexec` 的返回值:** 这两个函数都可能返回错误代码。不检查返回值可能导致程序在遇到错误时继续执行，产生不可预测的结果。

   ```c
   regex_t regex;
   regcomp(&regex, "invalid pattern", 0); // 假设编译失败
   regexec(&regex, "string", 0, NULL, 0); // 使用未成功编译的 regex
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `regex.h` 的路径 (以 Java 代码使用正则表达式为例):**

1. **Java 代码使用 `java.util.regex` 包:** Android 应用的 Java 代码通常使用 `java.util.regex.Pattern` 和 `java.util.regex.Matcher` 类来进行正则表达式操作。

   ```java
   String text = "hello world";
   String pattern = "hello";
   Pattern p = Pattern.compile(pattern);
   Matcher m = p.matcher(text);
   if (m.find()) {
       System.out.println("Match found: " + m.group());
   }
   ```

2. **JNI 调用:** `java.util.regex` 包的实现最终会调用 Native 代码。`Pattern.compile()` 方法内部会调用 Native 方法，该 Native 方法在 Android 平台的实现位于 `libjavacrypto.so` 或 `libicu_jni.so` 中 (取决于 Android 版本和具体实现)。这些 Native 代码会使用底层的正则表达式库。

3. **Bionic `regex` 库调用:**  在 `libjavacrypto.so` 或 `libicu_jni.so` 的 Native 代码中，可能会直接或间接地调用 Bionic 库提供的正则表达式函数 (`regcomp`, `regexec` 等)。例如，ICU (International Components for Unicode) 库被广泛用于 Android 的文本处理，而 ICU 内部可能使用了自己的正则表达式引擎，或者在某些情况下，它可能会调用系统的 POSIX 正则表达式实现。

**NDK 到达 `regex.h` 的路径:**

1. **C/C++ 代码包含 `<regex.h>`:** 在使用 NDK 开发的 Native 代码中，可以直接包含 `<regex.h>` 头文件。

   ```c++
   #include <regex.h>
   #include <stdio.h>

   int main() {
       regex_t regex;
       int ret = regcomp(&regex, "pattern", 0);
       if (ret == 0) {
           // ... 使用 regex 进行匹配 ...
           regfree(&regex);
       }
       return 0;
   }
   ```

2. **编译链接:**  在编译 NDK 代码时，需要链接到 `libc` 库，其中包含了 `regex` 函数的实现。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `regcomp` 和 `regexec` 函数来观察正则表达式的编译和匹配过程。

```javascript
// Hook regcomp
Interceptor.attach(Module.findExportByName("libc.so", "regcomp"), {
  onEnter: function(args) {
    const regexPtr = args[0];
    const patternPtr = args[1];
    const flags = args[2].toInt();
    const pattern = patternPtr.readCString();
    console.log(`regcomp: regex=${pattern}, flags=${flags}`);
    this.regexPtr = regexPtr;
  },
  onLeave: function(retval) {
    console.log(`regcomp returned: ${retval}`);
    if (retval.toInt() === 0) {
      // 编译成功，可以尝试读取 regex_t 结构
      // const magic = this.regexPtr.readU32();
      // const nsub = this.regexPtr.add(4).readSize();
      // console.log(`  Compiled regex info: magic=${magic}, nsub=${nsub}`);
    }
  }
});

// Hook regexec
Interceptor.attach(Module.findExportByName("libc.so", "regexec"), {
  onEnter: function(args) {
    const regexPtr = args[0];
    const strPtr = args[1];
    const nmatch = args[2].toInt();
    const pmatchPtr = args[3];
    const eflags = args[4].toInt();
    const str = strPtr.readCString();

    // 尝试读取 regex_t 结构来获取编译的正则表达式 (可能需要逆向)
    // const patternPtr = regexPtr.add(...).readPointer();
    // const pattern = patternPtr ? patternPtr.readCString() : "unknown";

    console.log(`regexec: regex=?, string="${str}", nmatch=${nmatch}, eflags=${eflags}`);
    this.pmatchPtr = pmatchPtr;
  },
  onLeave: function(retval) {
    console.log(`regexec returned: ${retval}`);
    if (retval.toInt() === 0) {
      // 匹配成功，读取 regmatch_t 数组
      if (this.pmatchPtr.isNull() === false) {
        for (let i = 0; i < 10 && i < arguments[2].toInt(); i++) {
          const rm_so = this.pmatchPtr.add(i * Process.pointerSize * 2).readS64();
          const rm_eo = this.pmatchPtr.add(i * Process.pointerSize * 2 + Process.pointerSize).readS64();
          if (rm_so === -1 && rm_eo === -1) break;
          console.log(`  Match ${i}: start=${rm_so}, end=${rm_eo}`);
        }
      }
    }
  }
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `regex_hook.js`).
2. 使用 Frida 连接到目标 Android 进程: `frida -U -f <package_name> -l regex_hook.js --no-pause` (替换 `<package_name>` 为目标应用的包名，如果应用已运行，可以使用 `-n <process_name>`).

**调试步骤:**

* 运行 Hook 脚本后，Frida 会拦截目标进程中对 `regcomp` 和 `regexec` 的调用。
* `onEnter` 函数会在函数调用前执行，你可以查看传入的参数，例如正则表达式字符串、匹配的字符串等。
* `onLeave` 函数会在函数返回后执行，你可以查看返回值以及匹配结果 (例如 `regmatch_t` 结构中的匹配位置)。
* 通过观察 Frida 的输出，你可以了解应用在何时使用了正则表达式，使用了哪些正则表达式，以及匹配的结果。

这个分析提供了关于 Android Bionic 库中 `regex.h` 文件的详细信息，包括其功能、与 Android 的关系、实现原理、动态链接、常见错误以及如何使用 Frida 进行调试。希望这些信息对你有所帮助。

Prompt: 
```
这是目录为bionic/libc/include/regex.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: regex.h,v 1.6 2003/06/02 19:34:12 millert Exp $	*/
/*	$NetBSD: regex.h,v 1.4.6.1 1996/06/10 18:57:07 explorer Exp $	*/

/*-
 * Copyright (c) 1992 Henry Spencer.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer of the University of Toronto.
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
 *	@(#)regex.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _REGEX_H_
#define	_REGEX_H_

#include <sys/cdefs.h>
#include <sys/types.h>

/* POSIX says regoff_t is at least as large as the larger of ptrdiff_t and
 * ssize_t. BSD uses off_t, but that interacts badly with _FILE_OFFSET_BITS. */
typedef ssize_t regoff_t;

typedef struct {
	int re_magic;
	size_t re_nsub;		/* number of parenthesized subexpressions */
	const char * __BIONIC_COMPLICATED_NULLNESS re_endp;	/* end pointer for REG_PEND */
	struct re_guts * __BIONIC_COMPLICATED_NULLNESS re_g;	/* none of your business :-) */
} regex_t;

typedef struct {
	regoff_t rm_so;		/* start of match */
	regoff_t rm_eo;		/* end of match */
} regmatch_t;

/* regcomp() flags */
#define	REG_BASIC	0000
#define	REG_EXTENDED	0001
#define	REG_ICASE	0002
#define	REG_NOSUB	0004
#define	REG_NEWLINE	0010
#define	REG_NOSPEC	0020
#define	REG_PEND	0040
#define	REG_DUMP	0200
#define	REG_GNU		0400

/* regerror() flags */
#define	REG_NOMATCH	 1
#define	REG_BADPAT	 2
#define	REG_ECOLLATE	 3
#define	REG_ECTYPE	 4
#define	REG_EESCAPE	 5
#define	REG_ESUBREG	 6
#define	REG_EBRACK	 7
#define	REG_EPAREN	 8
#define	REG_EBRACE	 9
#define	REG_BADBR	10
#define	REG_ERANGE	11
#define	REG_ESPACE	12
#define	REG_BADRPT	13
#define	REG_EMPTY	14
#define	REG_ASSERT	15
#define	REG_INVARG	16
#define	REG_ILLSEQ	17
#define	REG_ATOI	255	/* convert name to number (!) */
#define	REG_ITOA	0400	/* convert number to name (!) */

/* regexec() flags */
#define	REG_NOTBOL	00001
#define	REG_NOTEOL	00002
#define	REG_STARTEND	00004
#define	REG_TRACE	00400	/* tracing of execution */
#define	REG_LARGE	01000	/* force large representation */
#define	REG_BACKR	02000	/* force use of backref code */

__BEGIN_DECLS
int regcomp(regex_t* _Nonnull __re, const char* _Nonnull __regex, int __flags);
size_t regerror(int __error_code, const regex_t* _Nullable __re, char* _Nullable __buf, size_t __n);
int regexec(const regex_t* _Nonnull __re, const char* _Nonnull __s, size_t __match_count, regmatch_t __matches[_Nullable], int __flags);
void regfree(regex_t* _Nonnull __re);
__END_DECLS

#endif

"""

```