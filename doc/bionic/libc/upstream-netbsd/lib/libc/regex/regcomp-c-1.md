Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Understanding the Goal:**

The overarching goal is to analyze a specific C source file (`regcomp.c`) from Android's Bionic libc, focusing on its functionality within the larger context of regular expression compilation. The prompt asks for a breakdown of its functions, its relation to Android, examples, explanations of libc functions, handling of dynamic linking (though this snippet isn't heavily involved), logical reasoning, common errors, and how Android reaches this code. Finally, a summary is requested.

**2. Initial Scan and Keyword Recognition:**

My first step is to quickly read through the code, identifying key functions and data structures. I'd look for:

* **Function definitions:** `static wint_t p_b_symbol(...)`, `static bool may_escape(...)`, etc. The `static` keyword is important, as it indicates these functions are internal to the compilation unit.
* **Data structures:** `struct parse *p`, `struct re_guts *g`, `cset *cs`. These suggest the code is part of a larger regular expression processing system.
* **Macros:** `_DIAGASSERT`, `REQUIRE`, `MORE`, `EATTWO`, `WGETNEXT`, `SETERROR`, `EMIT`, `INSERT`, `ASTERN`, `AHEAD`, `DROP`, `HERE`, `THERE`, `THERETHERE`, `OP`, `OPND`, `SOP`, `NC`, `CHIN`, `OUT`, `NC_MAX`. These often encapsulate important logic and need closer examination (even though the prompt focuses on the functions).
* **Error codes:** `REG_EBRACK`, `REG_ECOLLATE`, `REG_ILLSEQ`, `REG_ASSERT`, `REG_ESPACE`. These tell us about the types of errors this code can handle.
* **Conditional compilation:** `#ifdef NLS`, `#else`, `#endif`. This hints at internationalization (National Language Support) features.
* **Standard C library functions:** `strncmp`, `strlen`, `memset`, `mbrtowc`, `isalpha`, `towlower`, `towupper`, `iswalpha`, `iswupper`, `iswlower`, `wcrtomb`, `reallocarray`, `free`, `memcpy`, `calloc`, `malloc`, `iswctype`, `strcmp`. The prompt specifically asks to explain these.

**3. Functional Decomposition (Top-Down):**

I'd then try to group the functions based on their likely purpose. Looking at the names and their internal logic:

* **Parsing Bracket Expressions:** Functions starting with `p_b_` (like `p_b_symbol`, `p_b_coll_elem`) clearly deal with parsing character classes within square brackets `[]`.
* **Character Handling:** Functions like `may_escape`, `othercase`, `bothcases`, and `ordinary` focus on how individual characters are processed, including handling escape sequences and case insensitivity.
* **Repetition:** The `repeat` function handles quantifiers like `*`, `+`, `?`, and `{m,n}`.
* **Low-Level Operations:** Functions like `wgetnext`, `seterr`, `allocset`, `freeset`, `CHadd`, `CHaddrange`, `CHaddtype` seem to be utilities for managing the parsing state and character sets.
* **Code Emission:** Functions like `dupl`, `doemit`, `doinsert`, `dofwd` are responsible for generating the internal representation of the regular expression.
* **Memory Management:** `enlarge`, `stripsnug` deal with allocating and resizing memory for the compiled regular expression.
* **Optimization:** `findmust`, `computejumps`, `computematchjumps` are involved in optimizing the regex for faster matching (Boyer-Moore algorithm).
* **Analysis:** `pluscount` seems to analyze the structure of the compiled regex.

**4. Connecting to Android (Hypothesizing):**

At this stage, I'd consider how regular expressions are used in Android. Obvious places include:

* **Text processing:**  String manipulation, data validation, log analysis.
* **Networking:** Parsing URLs, filtering network traffic.
* **System services:**  Matching package names, process names.
* **Framework components:**  Input validation in UI elements.

I would then try to imagine scenarios where these specific functions might be called within an Android context. For instance, `p_b_symbol` is likely involved when parsing a regex used to validate user input in an Android app.

**5. Detailed Explanation of `libc` Functions:**

The prompt specifically requests explanations of `libc` functions. I would go through each one identified in step 2 and provide a concise explanation of its standard C library purpose.

**6. Dynamic Linking (Considering but Noting Limited Scope):**

While the prompt mentions dynamic linking, this specific code snippet doesn't show direct interaction with the dynamic linker. I would acknowledge this, explaining that `regcomp.c` will be compiled into `libc.so` and linked against other Android components. I'd provide a basic example of `libc.so`'s place in memory.

**7. Logical Reasoning and Examples:**

For functions with more complex logic (like `repeat` or the bracket parsing functions), I'd try to create simple hypothetical inputs and trace the expected output. This helps solidify understanding and provides concrete examples.

**8. Common Errors:**

Based on my understanding of regular expressions, I would list common mistakes developers make when writing regexes, which could lead to errors handled by this code (e.g., unbalanced brackets).

**9. Android Framework/NDK Integration and Frida Hooking:**

This requires understanding the layers of Android. I'd explain the path from the Android framework (Java code using `java.util.regex`) or the NDK (C/C++ code using `<regex.h>`) down to the native `regcomp` function within `libc.so`. I'd then provide a basic Frida hook example to intercept calls to one of the functions in the snippet.

**10. Summarization (The Final Step):**

Finally, I would synthesize the information gathered into a concise summary of the functionality of the code snippet. This involves reiterating the main purpose (parsing bracket expressions, handling characters, etc.) and its role within the larger regex compilation process.

**Self-Correction/Refinement:**

Throughout this process, I'd constantly review my understanding and look for inconsistencies or areas where I need more information. For example, if I'm unsure about the exact purpose of a macro, I'd make a note to research it further. If my initial assumptions about Android integration are too vague, I'd try to find more concrete examples. Recognizing that this snippet is *part* of a larger regex engine is crucial – I wouldn't try to explain the *entire* regex compilation process based solely on this fragment.
这是对 `bionic/libc/upstream-netbsd/lib/libc/regex/regcomp.c` 文件中部分代码的分析，主要集中在处理正则表达式编译过程中的特定元素。根据代码片段，我们可以归纳出以下功能：

**主要功能归纳:**

这段代码片段主要负责解析正则表达式中与 **字符类（character class）** 和 **转义字符** 相关的部分，以及一些辅助功能，为构建正则表达式的内部表示（通常是状态机）做准备。具体来说，它处理了以下内容：

1. **解析具名字符（Collating Symbol）:** 允许在字符类中使用形如 `[.symbol.]` 的结构来表示特定的排序符号。
2. **解析排序元素（Collating Element）:**  允许在字符类中使用形如 `[element]` 的结构，可以代表单个字符或多字符的排序单元。
3. **判断字符是否需要转义:**  根据上下文判断给定的字符是否需要被转义。
4. **处理字符的大小写:**  提供将字符转换为其对应大小写形式的功能，用于实现不区分大小写的匹配。
5. **生成同时匹配大小写的代码:**  对于需要进行不区分大小写匹配的字符，生成能够同时匹配其大写和小写形式的代码。
6. **生成普通字符的匹配代码:**  将普通字符添加到正则表达式的内部表示中。
7. **生成匹配除换行符外任意字符的代码:**  在需要匹配除换行符以外的任意字符时生成相应的代码。
8. **处理重复操作（Repeat）:**  为正则表达式中的重复操作符（如 `*`, `+`, `?`, `{m,n}`）生成相应的代码，可能需要递归处理。
9. **获取下一个宽字符:**  从输入的正则表达式字符串中安全地获取下一个宽字符，并处理可能的编码错误。
10. **设置错误状态:**  在解析过程中遇到错误时，记录错误状态。
11. **分配和释放字符集:**  为表示字符类分配和释放内存。
12. **判断字符集是否只包含一个字符:**  用于优化某些情况下的匹配。
13. **向字符集中添加字符、字符范围和字符类型:**  构建字符类的核心功能。
14. **复制一段正则表达式代码:**  在处理重复操作时，可能需要复制已生成的代码。
15. **发射（Emit）操作码:**  将正则表达式的操作码添加到内部表示中。
16. **插入操作码:**  在已生成的代码中插入新的操作码。
17. **完成前向引用:**  在解析过程中，某些操作需要稍后才能确定目标位置，这个函数用于完成这些引用。
18. **扩展正则表达式代码缓冲区:**  当现有缓冲区不足以容纳更多代码时，动态扩展缓冲区。
19. **压缩正则表达式代码:**  在编译完成后，将缓冲区大小调整为实际使用的大小。
20. **查找必须匹配的字符串:**  用于优化正则表达式匹配，提前查找必须出现的字符串。
21. **计算多个路径中的最大偏移量:**  在处理 `|` 分支时，计算偏移量。
22. **计算 Boyer-Moore 算法的字符跳转表:**  用于优化正则表达式匹配的算法。
23. **计算 Boyer-Moore 算法的匹配跳转表:**  同样用于优化正则表达式匹配的算法。
24. **计算 `+` 操作符的嵌套深度:**  用于分析正则表达式的结构。

**与 Android 功能的关系举例说明:**

这些功能是正则表达式编译器的核心组成部分，而正则表达式在 Android 中被广泛使用。以下是一些例子：

* **`p_b_symbol` 和 `p_b_coll_elem`:**  在 Android 的国际化支持中，某些语言可能需要特定的排序规则。当一个应用使用正则表达式来验证用户输入的排序或查找特定的字符组合时，这两个函数可能会被调用。例如，验证一个包含特殊排序字符的姓名。
* **`may_escape`:**  在 Android 应用中，用户可能会输入包含转义字符的模式进行搜索或过滤。例如，在文件浏览器中搜索包含 `.` 字符的文件，正则表达式需要正确处理 `\.`。
* **`bothcases` 和 `ordinary`:**  在 Android 的搜索功能中，很多时候需要不区分大小写。例如，在联系人列表中搜索 "john"，无论用户输入 "John"、"john" 还是 "JOHN" 都应该匹配。
* **`repeat`:**  在 Android 的文本编辑器或代码编辑器中，正则表达式可以用于查找重复的模式，例如查找连续出现三次的空格。
* **`wgetnext` 和 `seterr`:** 当 Android 应用处理来自网络或文件的文本数据时，可能会使用正则表达式进行解析。如果遇到非法的字符编码，这些函数会负责处理错误。

**详细解释 libc 函数的功能实现:**

由于这是一个代码片段，我们只能看到部分 `libc` 函数的使用。以下是一些在这个片段中出现的 `libc` 函数的解释：

* **`strncmp(const char *s1, const char *s2, size_t n)`:**  比较字符串 `s1` 的前 `n` 个字符和字符串 `s2` 的前 `n` 个字符。返回值小于 0 表示 `s1` 小于 `s2`，等于 0 表示相等，大于 0 表示 `s1` 大于 `s2`。这里用于比较输入的排序元素名称和已知的排序元素名称。
* **`strlen(const char *s)`:**  计算字符串 `s` 的长度，不包括结尾的空字符 `\0`。这里用于确保找到完整的排序元素名称。
* **`memset(void *s, int c, size_t n)`:**  将内存块 `s` 的前 `n` 个字节设置为值 `c`。这里用于初始化 `mbstate_t` 结构，用于多字节字符的转换。
* **`mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps)`:**  将以 `s` 开始的多字节字符序列转换为一个宽字符，存储在 `*pwc` 中。`n` 是 `s` 的最大字节数，`ps` 是多字节转换状态对象。返回值是成功转换的字节数，如果遇到不完整的或无效的多字节字符，则返回错误。这里用于将多字节字符转换为宽字符进行处理。
* **`isalpha(int c)`:**  检查字符 `c` 是否为字母（a-z 或 A-Z）。
* **`towlower(wint_t wc)`:**  将宽字符 `wc` 转换为其小写形式。
* **`towupper(wint_t wc)`:**  将宽字符 `wc` 转换为其大写形式。
* **`iswalpha(wint_t wc)`:**  检查宽字符 `wc` 是否为字母。
* **`iswupper(wint_t wc)`:**  检查宽字符 `wc` 是否为大写字母。
* **`iswlower(wint_t wc)`:**  检查宽字符 `wc` 是否为小写字母。
* **`wcrtomb(char *s, wchar_t wc, mbstate_t *ps)`:**  将宽字符 `wc` 转换为其对应的多字节字符序列，存储在 `s` 中。`ps` 是多字节转换状态对象。返回值是写入 `s` 的字节数，如果发生错误则返回 -1。这里用于将宽字符转换回多字节字符。
* **`reallocarray(void *ptr, size_t nmemb, size_t size)`:**  更改 `ptr` 指向的内存块的大小为 `nmemb * size` 字节。它类似于 `realloc`，但可以防止整数溢出。
* **`free(void *ptr)`:**  释放之前由 `malloc`、`calloc` 或 `realloc` 分配的内存块。
* **`memcpy(void *dest, const void *src, size_t n)`:**  将 `src` 指向的内存块的前 `n` 个字节复制到 `dest` 指向的内存块。
* **`calloc(size_t nmemb, size_t size)`:**  分配 `nmemb * size` 字节的内存，并将分配的内存初始化为零。
* **`malloc(size_t size)`:**  分配 `size` 字节的内存，但不进行初始化。
* **`iswctype(wint_t wc, wctype_t desc)`:**  检查宽字符 `wc` 是否属于 `desc` 描述的字符类型。
* **`strcmp(const char *s1, const char *s2)`:** 比较字符串 `s1` 和字符串 `s2`。返回值与 `strncmp` 类似。

**涉及 dynamic linker 的功能:**

这段代码本身主要关注正则表达式的编译逻辑，与 dynamic linker 的直接交互较少。但是，作为 `libc` 的一部分，它会被编译成动态链接库 `libc.so`。

**so 布局样本:**

`libc.so` 是 Android 系统中非常重要的共享库，其布局大致如下（简化）：

```
地址范围      | 内容
-------------|------------------------------------
...           |
text segment  | 包含可执行代码，例如这里的 regcomp.c 编译后的机器码
...           |
rodata segment| 包含只读数据，例如字符串常量
...           |
data segment  | 包含已初始化的全局变量和静态变量
...           |
bss segment   | 包含未初始化的全局变量和静态变量
...           |
dynamic section| 包含动态链接器需要的信息，例如依赖的库、符号表等
...           |
symbol table  | 包含导出的符号（函数名、变量名等）及其地址
...           |
relocation table| 包含重定位信息，指示在加载时如何修改代码和数据中的地址
...           |
```

**链接的处理过程:**

当一个 Android 应用或系统服务需要使用正则表达式功能时，它会调用 `libc.so` 中提供的 `regcomp` 等函数。这个过程涉及 dynamic linker：

1. **加载时链接:** 当应用启动时，Android 的 zygote 进程会 fork 出新的进程来运行应用。在加载应用的过程中，dynamic linker (`/system/bin/linker` 或 `linker64`) 会加载应用依赖的共享库，包括 `libc.so`。
2. **符号解析:**  当应用代码调用 `regcomp` 时，dynamic linker 会在 `libc.so` 的符号表中查找 `regcomp` 的地址。
3. **重定位:**  由于共享库在内存中的加载地址可能不是编译时的地址，dynamic linker 会根据重定位表中的信息修改 `libc.so` 中与地址相关的指令和数据，确保代码能够正确执行。
4. **运行时链接:**  在应用运行过程中，如果需要动态加载其他共享库，dynamic linker 也会参与链接过程。

**假设输入与输出 (逻辑推理):**

由于这是代码片段，没有完整的上下文，很难给出精确的输入输出。但是，对于某些函数可以进行假设：

* **`p_b_symbol(struct parse *p)`:**
    * **假设输入:** `p->next` 指向字符串 `"[.ch.]"`
    * **预期输出:** 返回字符 `ch` 对应的宽字符值，`p->next` 指向 `"]"` 之后的位置。如果 `ch` 不是有效的排序符号，则会设置错误状态。
* **`may_escape(struct parse *p, const wint_t ch)`:**
    * **假设输入:** `p->pflags` 没有设置 `PFLAG_LEGACY_ESC`，`ch` 是字符 `'*'`.
    * **预期输出:** 返回 `true`，因为 `*` 在当前上下文中可以被转义。
    * **假设输入:** `p->pflags` 没有设置 `PFLAG_LEGACY_ESC`，`ch` 是字符 `'a'`.
    * **预期输出:** 返回 `false`，因为字母通常不需要转义。

**用户或编程常见的使用错误举例说明:**

这段代码处理的是正则表达式编译的底层细节，用户或编程错误通常发生在更高层次的正则表达式字符串的编写上，但最终会被这里的代码捕获：

* **`p_b_symbol` 和 `p_b_coll_elem`:**
    * **错误:**  使用了无效的排序符号，例如 `"[.invalid.]"`。
    * **结果:** `p_b_coll_elem` 中 `strncmp` 找不到匹配的名称，会根据是否启用 NLS 进行不同的处理，最终可能设置 `REG_ECOLLATE` 错误。
* **`repeat`:**
    * **错误:**  使用了无效的重复次数，例如 `"{a,b}"` 或 `"{1,}"` 但语法不支持。
    * **结果:**  `repeat` 函数中的条件判断会处理这些情况，并可能设置 `REG_BADBR` 或 `REG_BADRPT` 错误（虽然这里没有直接展示错误设置，但逻辑上是会发生的）。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java):**
   * 在 Java 代码中，通常使用 `java.util.regex.Pattern` 类来编译正则表达式，并使用 `java.util.regex.Matcher` 类进行匹配。
   * 当调用 `Pattern.compile(regex)` 时，Java 层会将正则表达式传递给 Native 层。
   * Native 层的实现位于 `libjavacrypto.so` 或 `libicuuc.so` 中，具体取决于 Android 版本和配置。
   * 这些 Native 代码最终会调用到 Bionic libc 中的正则表达式编译函数，例如 `regcomp`。

2. **Android NDK (C/C++):**
   * 在 NDK 中，可以使用 `<regex.h>` 头文件中声明的函数，例如 `regcomp`, `regexec`, `regfree` 等。
   * 当 C/C++ 代码调用 `regcomp` 时，会直接链接到 Bionic libc 中的 `regcomp` 函数。

**Frida Hook 示例:**

假设我们想 hook `p_b_symbol` 函数，可以使用以下 Frida 脚本：

```javascript
if (Process.arch === 'arm64') {
    var module = Process.getModuleByName("libc.so");
    var p_b_symbol_addr = module.findSymbolByName("_Z10p_b_symbolP5parse"); // 函数名可能需要根据 Bionic 版本调整

    if (p_b_symbol_addr) {
        Interceptor.attach(p_b_symbol_addr, {
            onEnter: function (args) {
                console.log("p_b_symbol called!");
                var parse_ptr = args[0];
                // 可以进一步解析 parse 结构体的内容
                // 例如：console.log("p->next:", Memory.readUtf8String(ptr(parse_ptr).add(offset_of_next)));
            },
            onLeave: function (retval) {
                console.log("p_b_symbol returned:", retval);
            }
        });
    } else {
        console.log("Could not find p_b_symbol symbol.");
    }
} else {
    console.log("Frida hook example is for arm64 architecture.");
}
```

**解释 Frida Hook 示例:**

* **`if (Process.arch === 'arm64')`:**  检查当前进程的架构，这里假设是 arm64。
* **`Process.getModuleByName("libc.so")`:** 获取 `libc.so` 模块的句柄。
* **`module.findSymbolByName("_Z10p_b_symbolP5parse")`:**  在 `libc.so` 中查找 `p_b_symbol` 函数的符号地址。C++ 函数名会被编译器 mangled，所以需要使用 mangled 的名称。可以使用 `arm-linux-androideabi-nm -D libc.so | grep p_b_symbol` 命令在 Android 设备上查找实际的符号名。
* **`Interceptor.attach(p_b_symbol_addr, { ... })`:**  在找到的地址处附加拦截器。
* **`onEnter: function (args)`:**  在 `p_b_symbol` 函数被调用时执行。`args` 数组包含了函数的参数。
* **`onLeave: function (retval)`:** 在 `p_b_symbol` 函数返回时执行。`retval` 是函数的返回值。
* **`Memory.readUtf8String(ptr(parse_ptr).add(offset_of_next))`:**  这部分代码演示了如何读取 `parse` 结构体中的成员变量。你需要知道 `next` 成员在结构体中的偏移量。

**归纳一下它的功能 (作为第 2 部分的总结):**

这段 `regcomp.c` 的代码片段专注于正则表达式编译过程中的 **字符类和转义字符的处理**。它包含了一系列静态函数，用于解析和理解 `[]` 字符类中的各种元素（如具名字符、排序元素），判断字符是否需要转义，并生成相应的内部表示代码。这些功能是构建完整正则表达式编译器的关键组成部分，为后续的匹配过程奠定了基础。它处理了与国际化、大小写敏感性以及字符的各种属性相关的复杂性，确保正则表达式能够正确地匹配各种文本模式。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/regex/regcomp.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
- p_b_symbol - parse a character or [..]ed multicharacter collating symbol
 == static wint_t p_b_symbol(struct parse *p);
 */
static wint_t			/* value of symbol */
p_b_symbol(struct parse *p)
{
	wint_t value;

	_DIAGASSERT(p != NULL);

	(void)REQUIRE(MORE(), REG_EBRACK);
	if (!EATTWO('[', '.'))
		return(WGETNEXT());

	/* collating symbol */
	value = p_b_coll_elem(p, '.');
	(void)REQUIRE(EATTWO('.', ']'), REG_ECOLLATE);
	return(value);
}

/*
 - p_b_coll_elem - parse a collating-element name and look it up
 == static wint_t p_b_coll_elem(struct parse *p, wint_t endc);
 */
static wint_t			/* value of collating element */
p_b_coll_elem(struct parse *p,
	wint_t endc)		/* name ended by endc,']' */
{
	const char *sp = p->next;
	struct cname *cp;
	size_t len;

	_DIAGASSERT(p != NULL);

	while (MORE() && !SEETWO(endc, ']'))
		NEXT();
	if (!MORE()) {
		SETERROR(REG_EBRACK);
		return(0);
	}
	len = p->next - sp;
	for (cp = cnames; cp->name != NULL; cp++)
		if (strncmp(cp->name, sp, len) == 0 && strlen(cp->name) == len)
			return(cp->code);	/* known name */
#ifdef NLS
	mbstate_t mbs;
	wchar_t wc;
	size_t clen;

	memset(&mbs, 0, sizeof(mbs));
	if ((clen = mbrtowc(&wc, sp, len, &mbs)) == len)
		return (wc);			/* single character */
	else if (clen == (size_t)-1 || clen == (size_t)-2)
		SETERROR(REG_ILLSEQ);
	else
		SETERROR(REG_ECOLLATE);		/* neither */
	return(0);
#else
	if (len == 1)
		return *sp;    /* single character */
	SETERROR(REG_ECOLLATE);                 /* neither */
	return 0;
#endif
}

/*
 - may_escape - determine whether 'ch' is escape-able in the current context
 == static int may_escape(struct parse *p, const wint_t ch)
 */
static bool
may_escape(struct parse *p, const wint_t ch)
{

	if ((p->pflags & PFLAG_LEGACY_ESC) != 0)
		return (true);
	if (isalpha(ch) || ch == '\'' || ch == '`')
		return (false);
	return (true);
#ifdef NOTYET
	/*
	 * Build a whitelist of characters that may be escaped to produce an
	 * ordinary in the current context. This assumes that these have not
	 * been otherwise interpreted as a special character. Escaping an
	 * ordinary character yields undefined results according to
	 * IEEE 1003.1-2008. Some extensions (notably, some GNU extensions) take
	 * advantage of this and use escaped ordinary characters to provide
	 * special meaning, e.g. \b, \B, \w, \W, \s, \S.
	 */
	switch(ch) {
	case '|':
	case '+':
	case '?':
		/* The above characters may not be escaped in BREs */
		if (!(p->g->cflags&REG_EXTENDED))
			return (false);
		/* Fallthrough */
	case '(':
	case ')':
	case '{':
	case '}':
	case '.':
	case '[':
	case ']':
	case '\\':
	case '*':
	case '^':
	case '$':
		return (true);
	default:
		return (false);
	}
#endif
}

/*
 - othercase - return the case counterpart of an alphabetic
 == static wint_t othercase(wint_t ch);
 */
static wint_t			/* if no counterpart, return ch */
othercase(wint_t ch)
{
	assert(iswalpha(ch));
	if (iswupper(ch))
		return(towlower(ch));
	else if (iswlower(ch))
		return(towupper(ch));
	else			/* peculiar, but could happen */
		return(ch);
}

/*
 - bothcases - emit a dualcase version of a two-case character
 == static void bothcases(struct parse *p, wint_t ch);
 *
 * Boy, is this implementation ever a kludge...
 */
static void
bothcases(struct parse *p, wint_t ch)
{
	const char *oldnext = p->next;
	const char *oldend = p->end;
	char bracket[3 + MB_LEN_MAX];
	size_t n;

	_DIAGASSERT(p != NULL);

	assert(othercase(ch) != ch);	/* p_bracket() would recurse */
	p->next = bracket;
#ifdef NLS
	mbstate_t mbs;
	memset(&mbs, 0, sizeof(mbs));
	n = wcrtomb(bracket, ch, &mbs);
	assert(n != (size_t)-1);
#else
	n = 0;
	bracket[n++] = ch;
#endif
	bracket[n] = ']';
	bracket[n + 1] = '\0';
	p->end = bracket+n+1;
	p_bracket(p);
	assert(p->next == p->end);
	p->next = oldnext;
	p->end = oldend;
}

/*
 - ordinary - emit an ordinary character
 == static void ordinary(struct parse *p, wint_t ch);
 */
static void
ordinary(struct parse *p, wint_t ch)
{
	cset *cs;

	_DIAGASSERT(p != NULL);

	if ((p->g->cflags&REG_ICASE) && iswalpha(ch) && othercase(ch) != ch)
		bothcases(p, ch);
	else if ((wint_t)(ch & OPDMASK) == ch)
		EMIT(OCHAR, (size_t)ch);
	else {
		/*
		 * Kludge: character is too big to fit into an OCHAR operand.
		 * Emit a singleton set.
		 */
		if ((cs = allocset(p)) == NULL)
			return;
		CHadd(p, cs, ch);
		EMIT(OANYOF, (size_t)(cs - p->g->sets));
	}
}

/*
 - nonnewline - emit REG_NEWLINE version of OANY
 == static void nonnewline(struct parse *p);
 *
 * Boy, is this implementation ever a kludge...
 */
static void
nonnewline(struct parse *p)
{
	const char *oldnext = p->next;
	const char *oldend = p->end;
	char bracket[4];

	_DIAGASSERT(p != NULL);

	p->next = bracket;
	p->end = bracket+3;
	bracket[0] = '^';
	bracket[1] = '\n';
	bracket[2] = ']';
	bracket[3] = '\0';
	p_bracket(p);
	assert(p->next == bracket+3);
	p->next = oldnext;
	p->end = oldend;
}

/*
 - repeat - generate code for a bounded repetition, recursively if needed
 == static void repeat(struct parse *p, sopno start, int from, int to);
 */
static void
repeat(struct parse *p,
	sopno start,		/* operand from here to end of strip */
	int from,		/* repeated from this number */
	int to)			/* to this number of times (maybe INFINITY) */
{
	sopno finish = HERE();
#	define	N	2
#	define	INF	3
#	define	REP(f, t)	((f)*8 + (t))
#	define	MAP(n)	(((n) <= 1) ? (n) : ((n) == INFINITY) ? INF : N)
	sopno copy;

	_DIAGASSERT(p != NULL);

	if (p->error != 0)	/* head off possible runaway recursion */
		return;

	assert(from <= to);

	switch (REP(MAP(from), MAP(to))) {
	case REP(0, 0):			/* must be user doing this */
		DROP(finish-start);	/* drop the operand */
		break;
	case REP(0, 1):			/* as x{1,1}? */
	case REP(0, N):			/* as x{1,n}? */
	case REP(0, INF):		/* as x{1,}? */
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, start);		/* offset is wrong... */
		repeat(p, start+1, 1, to);
		ASTERN(OOR1, start);
		AHEAD(start);			/* ... fix it */
		EMIT(OOR2, 0);
		AHEAD(THERE());
		ASTERN(O_CH, THERETHERE());
		break;
	case REP(1, 1):			/* trivial case */
		/* done */
		break;
	case REP(1, N):			/* as x?x{1,n-1} */
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, start);
		ASTERN(OOR1, start);
		AHEAD(start);
		EMIT(OOR2, 0);			/* offset very wrong... */
		AHEAD(THERE());			/* ...so fix it */
		ASTERN(O_CH, THERETHERE());
		copy = dupl(p, start+1, finish+1);
		assert(copy == finish+4);
		repeat(p, copy, 1, to-1);
		break;
	case REP(1, INF):		/* as x+ */
		INSERT(OPLUS_, start);
		ASTERN(O_PLUS, start);
		break;
	case REP(N, N):			/* as xx{m-1,n-1} */
		copy = dupl(p, start, finish);
		repeat(p, copy, from-1, to-1);
		break;
	case REP(N, INF):		/* as xx{n-1,INF} */
		copy = dupl(p, start, finish);
		repeat(p, copy, from-1, to);
		break;
	default:			/* "can't happen" */
		SETERROR(REG_ASSERT);	/* just in case */
		break;
	}
}

/*
 - wgetnext - helper function for WGETNEXT() macro. Gets the next wide
 - character from the parse struct, signals a REG_ILLSEQ error if the
 - character can't be converted. Returns the number of bytes consumed.
 */
static wint_t
wgetnext(struct parse *p)
{
#ifdef NLS
	mbstate_t mbs;
	wchar_t wc;
	size_t n;

	memset(&mbs, 0, sizeof(mbs));
	n = mbrtowc(&wc, p->next, (size_t)(p->end - p->next), &mbs);
	if (n == (size_t)-1 || n == (size_t)-2) {
		SETERROR(REG_ILLSEQ);
		return (0);
	}
	if (n == 0)
		n = 1;
	p->next += n;
	return wc;
#else
	return *p->next++;
#endif
}

/*
 - seterr - set an error condition
 == static int seterr(struct parse *p, int e);
 */
static int			/* useless but makes type checking happy */
seterr(struct parse *p, int e)
{

	_DIAGASSERT(p != NULL);

	if (p->error == 0)	/* keep earliest error condition */
		p->error = e;
	p->next = nuls;		/* try to bring things to a halt */
	p->end = nuls;
	return(0);		/* make the return value well-defined */
}

/*
 - allocset - allocate a set of characters for []
 == static cset *allocset(struct parse *p);
 */
static cset *
allocset(struct parse *p)
{
	cset *cs, *ncs;

	_DIAGASSERT(p != NULL);

	ncs = reallocarray(p->g->sets, p->g->ncsets + 1, sizeof(*ncs));
	if (ncs == NULL) {
		SETERROR(REG_ESPACE);
		return (NULL);
	}
	p->g->sets = ncs;
	cs = &p->g->sets[p->g->ncsets++];
	memset(cs, 0, sizeof(*cs));

	return(cs);
}

/*
 - freeset - free a now-unused set
 == static void freeset(struct parse *p, cset *cs);
 */
static void
freeset(struct parse *p, cset *cs)
{
	cset *top;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	top = &p->g->sets[p->g->ncsets];

	free(cs->wides);
	free(cs->ranges);
	free(cs->types);
	memset(cs, 0, sizeof(*cs));
	if (cs == top-1)	/* recover only the easy case */
		p->g->ncsets--;
}

/*
 - singleton - Determine whether a set contains only one character,
 - returning it if so, otherwise returning OUT.
 */
static wint_t
singleton(cset *cs)
{
	wint_t i, s, n;

	for (i = n = 0; i < NC; i++)
		if (CHIN(cs, i)) {
			n++;
			s = i;
		}
	if (n == 1)
		return (s);
	if (cs->nwides == 1 && cs->nranges == 0 && cs->ntypes == 0 &&
	    cs->icase == 0)
		return (cs->wides[0]);
	/* Don't bother handling the other cases. */
	return (OUT);
}

/*
 - CHadd - add character to character set.
 */
static void
CHadd(struct parse *p, cset *cs, wint_t ch)
{
	wint_t nch, *newwides;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	assert(ch >= 0);
	if (ch < NC)
		cs->bmp[(unsigned)ch >> 3] |= 1 << (ch & 7);
	else {
		newwides = reallocarray(cs->wides, cs->nwides + 1,
		    sizeof(*cs->wides));
		if (newwides == NULL) {
			SETERROR(REG_ESPACE);
			return;
		}
		cs->wides = newwides;
		cs->wides[cs->nwides++] = ch;
	}
	if (cs->icase) {
		if ((nch = towlower(ch)) < NC)
			cs->bmp[(unsigned)nch >> 3] |= 1 << (nch & 7);
		if ((nch = towupper(ch)) < NC)
			cs->bmp[(unsigned)nch >> 3] |= 1 << (nch & 7);
	}
}

/*
 - CHaddrange - add all characters in the range [min,max] to a character set.
 */
static void
CHaddrange(struct parse *p, cset *cs, wint_t min, wint_t max)
{
	crange *newranges;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	for (; min < NC && min <= max; min++)
		CHadd(p, cs, min);
	if (min >= max)
		return;
	newranges = reallocarray(cs->ranges, cs->nranges + 1,
	    sizeof(*cs->ranges));
	if (newranges == NULL) {
		SETERROR(REG_ESPACE);
		return;
	}
	cs->ranges = newranges;
	cs->ranges[cs->nranges].min = min;
	cs->ranges[cs->nranges].max = max;
	cs->nranges++;
}

/*
 - CHaddtype - add all characters of a certain type to a character set.
 */
static void
CHaddtype(struct parse *p, cset *cs, wctype_t wct)
{
	wint_t i;
	wctype_t *newtypes;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	for (i = 0; i < NC; i++)
		if (iswctype(i, wct))
			CHadd(p, cs, i);
	newtypes = reallocarray(cs->types, cs->ntypes + 1,
	    sizeof(*cs->types));
	if (newtypes == NULL) {
		SETERROR(REG_ESPACE);
		return;
	}
	cs->types = newtypes;
	cs->types[cs->ntypes++] = wct;
}

/*
 - dupl - emit a duplicate of a bunch of sops
 == static sopno dupl(struct parse *p, sopno start, sopno finish);
 */
static sopno			/* start of duplicate */
dupl(struct parse *p,
	sopno start,		/* from here */
	sopno finish)		/* to this less one */
{
	sopno ret = HERE();
	sopno len = finish - start;

	_DIAGASSERT(p != NULL);

	assert(finish >= start);
	if (len == 0)
		return(ret);
	if (!enlarge(p, p->ssize + len)) /* this many unexpected additions */
		return(ret);
	(void) memcpy(p->strip + p->slen,
	    p->strip + start, len * sizeof(*p->strip));
	p->slen += len;
	return(ret);
}

/*
 - doemit - emit a strip operator
 == static void doemit(struct parse *p, sop op, size_t opnd);
 *
 * It might seem better to implement this as a macro with a function as
 * hard-case backup, but it's just too big and messy unless there are
 * some changes to the data structures.  Maybe later.
 */
static void
doemit(struct parse *p, sop op, size_t opnd)
{
	/* avoid making error situations worse */
	if (p->error != 0)
		return;

	_DIAGASSERT(p != NULL);

	/* deal with oversize operands ("can't happen", more or less) */
	assert(opnd < 1<<OPSHIFT);

	/* deal with undersized strip */
	if (p->slen >= p->ssize)
		if (!enlarge(p, (p->ssize+1) / 2 * 3))	/* +50% */
			return;

	/* finally, it's all reduced to the easy case */
	p->strip[p->slen++] = (sopno)SOP(op, opnd);
}

/*
 - doinsert - insert a sop into the strip
 == static void doinsert(struct parse *p, sop op, size_t opnd, sopno pos);
 */
static void
doinsert(struct parse *p, sop op, size_t opnd, sopno pos)
{
	sopno sn;
	sop s;
	int i;

	_DIAGASSERT(p != NULL);

	/* avoid making error situations worse */
	if (p->error != 0)
		return;

	sn = HERE();
	EMIT(op, opnd);		/* do checks, ensure space */
	assert(HERE() == sn+1);
	s = p->strip[sn];

	/* adjust paren pointers */
	assert(pos > 0);
	for (i = 1; i < NPAREN; i++) {
		if (p->pbegin[i] >= pos) {
			p->pbegin[i]++;
		}
		if (p->pend[i] >= pos) {
			p->pend[i]++;
		}
	}

	memmove(&p->strip[pos+1], &p->strip[pos],
	    (HERE()-pos-1)*sizeof(*p->strip));
	p->strip[pos] = s;
}

/*
 - dofwd - complete a forward reference
 == static void dofwd(struct parse *p, sopno pos, sop value);
 */
static void
dofwd(struct parse *p, sopno pos, sop value)
{

	_DIAGASSERT(p != NULL);

	/* avoid making error situations worse */
	if (p->error != 0)
		return;

	assert(value < 1<<OPSHIFT);
	p->strip[pos] = OP(p->strip[pos]) | value;
}

/*
 - enlarge - enlarge the strip
 == static int enlarge(struct parse *p, sopno size);
 */
static int
enlarge(struct parse *p, sopno size)
{
	sop *sp;

	_DIAGASSERT(p != NULL);

	if (p->ssize >= size)
		return 1;

	sp = reallocarray(p->strip, size, sizeof(*p->strip));
	if (sp == NULL) {
		SETERROR(REG_ESPACE);
		return 0;
	}
	p->strip = sp;
	p->ssize = size;
	return 1;
}

/*
 - stripsnug - compact the strip
 == static void stripsnug(struct parse *p, struct re_guts *g);
 */
static void
stripsnug(struct parse *p, struct re_guts *g)
{

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(g != NULL);

	g->nstates = p->slen;
	g->strip = reallocarray(p->strip, p->slen, sizeof(*p->strip));
	if (g->strip == NULL) {
		SETERROR(REG_ESPACE);
		g->strip = p->strip;
	}
}

/*
 - findmust - fill in must and mlen with longest mandatory literal string
 == static void findmust(struct parse *p, struct re_guts *g);
 *
 * This algorithm could do fancy things like analyzing the operands of |
 * for common subsequences.  Someday.  This code is simple and finds most
 * of the interesting cases.
 *
 * Note that must and mlen got initialized during setup.
 */
static void
findmust(struct parse *p, struct re_guts *g)
{
	sop *scan;
	sop *start = NULL;
	sop *newstart = NULL;
	sopno newlen;
	sop s;
	char *cp;
	int offset;
	mbstate_t mbs;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(g != NULL);

	/* avoid making error situations worse */
	if (p->error != 0)
		return;

#ifdef notyet
	/*
	 * It's not generally safe to do a ``char'' substring search on
	 * multibyte character strings, but it's safe for at least
	 * UTF-8 (see RFC 3629).
	 */
	if (MB_CUR_MAX > 1 &&
	    strcmp(_CurrentRuneLocale->__encoding, "UTF-8") != 0)
		return;
#endif

	/* find the longest OCHAR sequence in strip */
	newlen = 0;
	offset = 0;
	g->moffset = 0;
	scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OCHAR:		/* sequence member */
			if (newlen == 0) {		/* new sequence */
				memset(&mbs, 0, sizeof(mbs));
				newstart = scan - 1;
			}
#ifdef NLS
			char buf[MB_LEN_MAX];
			size_t clen = wcrtomb(buf, (int)OPND(s), &mbs);
			if (clen == (size_t)-1)
				goto toohard;
			newlen += (sopno)clen;
#else
			newlen++;
#endif
			break;
		case OPLUS_:		/* things that don't break one */
		case OLPAREN:
		case ORPAREN:
			break;
		case OQUEST_:		/* things that must be skipped */
		case OCH_:
			offset = altoffset(scan, offset);
			scan--;
			do {
				scan += OPND(s);
				s = *scan;
				/* assert() interferes w debug printouts */
				if (OP(s) != O_QUEST &&
				    OP(s) != O_CH && OP(s) != OOR2) {
					g->iflags |= BAD;
					return;
				}
			} while (OP(s) != O_QUEST && OP(s) != O_CH);
			/* FALLTHROUGH */
		case OBOW:		/* things that break a sequence */
		case OEOW:
		case OBOL:
		case OEOL:
		case OBOS:
		case OEOS:
		case OWBND:
		case ONWBND:
		case O_QUEST:
		case O_CH:
		case OEND:
			if (newlen > (sopno)g->mlen) {		/* ends one */
				start = newstart;
				g->mlen = newlen;
				if (offset > -1) {
					g->moffset += offset;
					offset = newlen;
				} else
					g->moffset = offset;
			} else {
				if (offset > -1)
					offset += newlen;
			}
			newlen = 0;
			break;
		case OANY:
			if (newlen > (sopno)g->mlen) {		/* ends one */
				start = newstart;
				g->mlen = newlen;
				if (offset > -1) {
					g->moffset += offset;
					offset = newlen;
				} else
					g->moffset = offset;
			} else {
				if (offset > -1)
					offset += newlen;
			}
			if (offset > -1)
				offset++;
			newlen = 0;
			break;
		case OANYOF:		/* may or may not invalidate offset */
			/* First, everything as OANY */
			if (newlen > (sopno)g->mlen) {		/* ends one */
				start = newstart;
				g->mlen = newlen;
				if (offset > -1) {
					g->moffset += offset;
					offset = newlen;
				} else
					g->moffset = offset;
			} else {
				if (offset > -1)
					offset += newlen;
			}
			if (offset > -1)
				offset++;
			newlen = 0;
			break;
#ifdef NLS
		toohard:/*FALLTHROUGH*/
#endif
		default:
			/* Anything here makes it impossible or too hard
			 * to calculate the offset -- so we give up;
			 * save the last known good offset, in case the
			 * must sequence doesn't occur later.
			 */
			if (newlen > (sopno)g->mlen) {		/* ends one */
				start = newstart;
				g->mlen = newlen;
				if (offset > -1)
					g->moffset += offset;
				else
					g->moffset = offset;
			}
			offset = -1;
			newlen = 0;
			break;
		}
	} while (OP(s) != OEND);

	if (g->mlen == 0) {		/* there isn't one */
		g->moffset = -1;
		return;
	}

	/* turn it into a character string */
	g->must = malloc((size_t)g->mlen + 1);
	if (g->must == NULL) {		/* argh; just forget it */
		g->mlen = 0;
		g->moffset = -1;
		return;
	}
	cp = g->must;
	scan = start;
	memset(&mbs, 0, sizeof(mbs));
	while (cp < g->must + g->mlen) {
		while (OP(s = *scan++) != OCHAR)
			continue;
#ifdef NLS
		size_t clen = wcrtomb(cp, (int)OPND(s), &mbs);
		assert(clen != (size_t)-1);
		cp += clen;
#else
		*cp++ = OPND(s);
#endif
	}
	assert(cp == g->must + g->mlen);
	*cp++ = '\0';		/* just on general principles */
}

/*
 - altoffset - choose biggest offset among multiple choices
 == static int altoffset(sop *scan, int offset);
 *
 * Compute, recursively if necessary, the largest offset among multiple
 * re paths.
 */
static int
altoffset(sop *scan, int offset)
{
	int largest;
	int try;
	sop s;

	_DIAGASSERT(scan != NULL);

	/* If we gave up already on offsets, return */
	if (offset == -1)
		return -1;

	largest = 0;
	try = 0;
	s = *scan++;
	while (OP(s) != O_QUEST && OP(s) != O_CH) {
		switch (OP(s)) {
		case OOR1:
			if (try > largest)
				largest = try;
			try = 0;
			break;
		case OQUEST_:
		case OCH_:
			try = altoffset(scan, try);
			if (try == -1)
				return -1;
			scan--;
			do {
				scan += OPND(s);
				s = *scan;
				if (OP(s) != O_QUEST &&
				    OP(s) != O_CH && OP(s) != OOR2)
					return -1;
			} while (OP(s) != O_QUEST && OP(s) != O_CH);
			/* We must skip to the next position, or we'll
			 * leave altoffset() too early.
			 */
			scan++;
			break;
		case OANYOF:
		case OCHAR:
		case OANY:
			try++;
			/*FALLTHROUGH*/
		case OBOW:
		case OEOW:
		case OWBND:
		case ONWBND:
		case OLPAREN:
		case ORPAREN:
		case OOR2:
			break;
		default:
			try = -1;
			break;
		}
		if (try == -1)
			return -1;
		s = *scan++;
	}

	if (try > largest)
		largest = try;

	return largest+offset;
}

/*
 - computejumps - compute char jumps for BM scan
 == static void computejumps(struct parse *p, struct re_guts *g);
 *
 * This algorithm assumes g->must exists and is has size greater than
 * zero. It's based on the algorithm found on Computer Algorithms by
 * Sara Baase.
 *
 * A char jump is the number of characters one needs to jump based on
 * the value of the character from the text that was mismatched.
 */
static void
computejumps(struct parse *p, struct re_guts *g)
{
	int ch;
	size_t mindex;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(g != NULL);

	/* Avoid making errors worse */
	if (p->error != 0)
		return;

	g->charjump = calloc((NC_MAX + 1), sizeof(*g->charjump));
	if (g->charjump == NULL)	/* Not a fatal error */
		return;
	/* Adjust for signed chars, if necessary */
	g->charjump = &g->charjump[-(CHAR_MIN)];

	/* If the character does not exist in the pattern, the jump
	 * is equal to the number of characters in the pattern.
	 */
	for (ch = CHAR_MIN; ch < (CHAR_MAX + 1); ch++)
		g->charjump[ch] = g->mlen;

	/* If the character does exist, compute the jump that would
	 * take us to the last character in the pattern equal to it
	 * (notice that we match right to left, so that last character
	 * is the first one that would be matched).
	 */
	for (mindex = 0; mindex < g->mlen; mindex++)
		g->charjump[(int)g->must[mindex]] = g->mlen - mindex - 1;
}

/*
 - computematchjumps - compute match jumps for BM scan
 == static void computematchjumps(struct parse *p, struct re_guts *g);
 *
 * This algorithm assumes g->must exists and is has size greater than
 * zero. It's based on the algorithm found on Computer Algorithms by
 * Sara Baase.
 *
 * A match jump is the number of characters one needs to advance based
 * on the already-matched suffix.
 * Notice that all values here are minus (g->mlen-1), because of the way
 * the search algorithm works.
 */
static void
computematchjumps(struct parse *p, struct re_guts *g)
{
	size_t mindex;		/* General "must" iterator */
	size_t suffix;		/* Keeps track of matching suffix */
	size_t ssuffix;		/* Keeps track of suffixes' suffix */
	size_t* pmatches;	/* pmatches[k] points to the next i
				 * such that i+1...mlen is a substring
				 * of k+1...k+mlen-i-1
				 */

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(g != NULL);

	/* Avoid making errors worse */
	if (p->error != 0)
		return;

	pmatches = calloc(g->mlen, sizeof(*pmatches));
	if (pmatches == NULL) {
		g->matchjump = NULL;
		return;
	}

	g->matchjump = calloc(g->mlen, sizeof(*g->matchjump));
	if (g->matchjump == NULL) {	/* Not a fatal error */
		free(pmatches);
		return;
	}

	/* Set maximum possible jump for each character in the pattern */
	for (mindex = 0; mindex < g->mlen; mindex++)
		g->matchjump[mindex] = 2 * g->mlen - mindex - 1;

	/* Compute pmatches[] */
	for (suffix = mindex = g->mlen; mindex-- > 0; suffix--) {
		pmatches[mindex] = suffix;

		/* If a mismatch is found, interrupting the substring,
		 * compute the matchjump for that position. If no
		 * mismatch is found, then a text substring mismatched
		 * against the suffix will also mismatch against the
		 * substring.
		 */
		while (suffix < g->mlen
		    && g->must[mindex] != g->must[suffix]) {
			g->matchjump[suffix] = MIN(g->matchjump[suffix],
			    g->mlen - mindex - 1);
			suffix = pmatches[suffix];
		}
	}

	/* Compute the matchjump up to the last substring found to jump
	 * to the beginning of the largest must pattern prefix matching
	 * it's own suffix.
	 */
	for (mindex = 0; mindex <= suffix; mindex++)
		g->matchjump[mindex] = MIN(g->matchjump[mindex],
		    g->mlen + suffix - mindex);

        ssuffix = pmatches[suffix];
        while (suffix < g->mlen) {
                while (suffix <= ssuffix && suffix < g->mlen) {
                        g->matchjump[suffix] = MIN(g->matchjump[suffix],
			    g->mlen + ssuffix - suffix);
                        suffix++;
                }
		if (suffix < g->mlen)
                	ssuffix = pmatches[ssuffix];
        }

	free(pmatches);
}

/*
 - pluscount - count + nesting
 == static sopno pluscount(struct parse *p, struct re_guts *g);
 */
static sopno			/* nesting depth */
pluscount(struct parse *p, struct re_guts *g)
{
	sop *scan;
	sop s;
	sopno plusnest = 0;
	sopno maxnest = 0;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(g != NULL);

	if (p->error != 0)
		return(0);	/* there may not be an OEND */

	scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OPLUS_:
			plusnest++;
			break;
		case O_PLUS:
			if (plusnest > maxnest)
				maxnest = plusnest;
			plusnest--;
			break;
		}
	} while (OP(s) != OEND);
	if (plusnest != 0)
		g->iflags |= BAD;
	return(maxnest);
}
```