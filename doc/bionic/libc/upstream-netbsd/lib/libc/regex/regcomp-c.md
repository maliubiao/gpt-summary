Response:
The user wants a comprehensive analysis of the C source code file `regcomp.c`. Specifically, they want:

1. **Functionality Summary:** A high-level overview of what the code does.
2. **Android Relevance:** How this code relates to the Android operating system and its functionalities, with examples.
3. **`libc` Function Details:**  Detailed explanations of the implementation of each `libc` function used.
4. **Dynamic Linker Interaction:** If the code interacts with the dynamic linker, an explanation of how, including SO layout and linking process.
5. **Logical Reasoning:** If any logical deductions are made within the code, describe them with input and output examples.
6. **Common User Errors:** Examples of typical mistakes programmers might make when using this code.
7. **Android Framework/NDK Integration:**  How a request from the Android framework or NDK reaches this code, with Frida hook examples for debugging.
8. **Part 1 Summary:** A concise summary of the code's functionality, considering this is part 1 of 2.

Let's break down the file's content to address these points:

- **License and Copyright:** Standard BSD license information, indicating its origin is NetBSD and contributions from various parties.
- **Includes:** Includes standard library headers like `stdio.h`, `string.h`, `ctype.h`, `stdlib.h`, `regex.h`, and Android-specific/internal headers like `bionic/libc/upstream-netbsd/lib/libc/regex/utils.h` and `bionic/libc/upstream-netbsd/lib/libc/regex/regex2.h`. This signals that the file is part of the regular expression compilation functionality within Android's `libc`.
- **Structure Definitions:** Defines structures like `branchc` (for tracking branching context during parsing) and `parse` (holding the parsing state).
- **Function Declarations:** Declares a large number of static functions, most starting with `p_`, suggesting they are internal parsing functions.
- **`regcomp_internal` and `regcomp`:** These are the core functions. `regcomp` is the public entry point for compiling regular expressions, and it calls `regcomp_internal` to do the actual work.
- **Parsing Logic:** The code seems to implement a recursive descent parser for regular expressions, handling both basic and extended regular expression syntax. It uses a state machine approach with different parsing functions for different parts of the grammar (e.g., `p_ere_exp` for extended RE expressions, `p_simp_re` for simple RE expressions).
- **Opcode Emission:** The code emits opcodes (`EMIT` macro) into a `strip` (likely representing a compiled regular expression).
- **Character Set Handling:**  Functions like `p_bracket`, `p_b_term`, `allocset`, `CHadd`, etc., deal with parsing and handling character sets within square brackets `[]`.
- **Repetition Handling:** The code handles repetition operators like `*`, `+`, `?`, and `{}`.
- **Backreferences:**  The code appears to support backreferences (e.g., `\1`, `\2`).
- **Anchors:** It handles anchors like `^` (beginning of line) and `$` (end of line).
- **GNU Extensions:** The code has conditional compilation for GNU regular expression extensions.
- **Error Handling:** The `SETERROR` macro is used to record errors during parsing.
- **Optimization:**  The code mentions Boyer-Moore algorithm for optimization.

**Plan for the response:**

1. **Summarize Functionality:** Start with a high-level overview of the file's main purpose: compiling regular expressions.
2. **Android Relevance:** Explain how regular expression compilation is crucial in Android for various tasks like input validation, text searching, and pattern matching in system services and applications. Provide examples of Android components using regex.
3. **`libc` Functions:**  Select a few representative `libc` functions used (e.g., `malloc`, `calloc`, `free`, `strlen`, `memcpy`, `strcmp`, `isdigit`) and explain their standard C library function and purpose. Mention that this file *implements* regex functionality rather than heavily relying on other complex `libc` functions.
4. **Dynamic Linker:**  Address the dynamic linker aspect by stating that this specific *compilation* unit doesn't directly interact with the dynamic linker during its operation. The compiled regex is used later by the matching engine (likely in another file). If the user provides the *other* file, that interaction could be analyzed. For now, explain what the dynamic linker does in general.
5. **Logical Reasoning:**  Give an example of the parsing logic, like how the code handles the `|` (OR) operator or repetition operators, showing the input pattern and the resulting opcodes.
6. **Common User Errors:**  Illustrate common regex syntax errors that this compiler would catch (e.g., unmatched parentheses, invalid repetition counts).
7. **Android Framework/NDK Integration:** Explain a simplified path: NDK -> C API (like `regcomp`) -> `libc` -> `regcomp.c`. Provide a basic Frida hook example for `regcomp`.
8. **Part 1 Summary:**  Reiterate that this part focuses on the compilation of regular expressions into an internal representation.
这是 `bionic/libc/upstream-netbsd/lib/libc/regex/regcomp.c` 文件的第一部分源代码分析。这个文件的主要功能是**将正则表达式编译成一种内部表示形式，以便后续的匹配操作**。

以下是对其功能的归纳：

1. **正则表达式编译:**  `regcomp.c` 实现了将用户提供的正则表达式字符串（`pattern`）转换成一种内部的、更容易执行的形式（存储在 `regex_t` 结构体中的 `re_guts` 成员中）。这个过程涉及到词法分析和语法分析，将正则表达式的结构和模式转换成一系列的操作码 (opcodes)。

2. **支持不同的正则表达式语法:**  代码可以处理两种主要的正则表达式语法：
    * **基本正则表达式 (BRE):**  这是较早的、功能较弱的语法，通常在某些旧的 Unix 工具中使用。
    * **扩展正则表达式 (ERE):**  这是功能更强大的语法，支持更多的元字符和特性。用户可以通过 `regcomp` 函数的 `cflags` 参数（`REG_EXTENDED`）来选择使用哪种语法。

3. **处理正则表达式的各种元素:** 代码能够识别和处理正则表达式中的各种元素，包括：
    * **普通字符:**  直接匹配输入的字符。
    * **元字符:**  具有特殊含义的字符，如 `.` (匹配任意字符), `^` (匹配行首), `$` (匹配行尾), `*` (匹配零个或多个), `+` (匹配一个或多个), `?` (匹配零个或一个), `[]` (字符集), `()` (分组) 和 `|` (或)。
    * **转义字符:**  使用反斜杠 `\` 来取消元字符的特殊含义或引入特殊的字符序列（例如 `\t` 表示制表符）。
    * **重复操作符:**  如 `*`, `+`, `?`, `{m,n}` 等，用于指定匹配次数。
    * **锚定:**  `^` 和 `$` 用于将匹配限制在行的开头或结尾。
    * **字符类:**  `[...]` 用于匹配指定字符集中的任意字符。
    * **反向引用:**  使用 `\1` 到 `\9` 来匹配之前捕获的分组。
    * **GNU 扩展 (可选):**  如果定义了 `REGEX_GNU_EXTENSIONS`，则支持一些 GNU 特有的正则表达式扩展，例如 `\` ``, `\'`, `\b`, `\B`, `\w`, `\W`, `\s`, `\S`。

4. **错误处理:**  如果在编译过程中发现正则表达式存在语法错误，`regcomp.c` 会设置 `parse` 结构体中的 `error` 字段，并返回相应的错误码（例如 `REG_BADRPT`, `REG_EPAREN`, `REG_EBRACK` 等）。

5. **内部优化:**  代码中包含一些优化步骤，例如 `stripsnug` 用于移除未使用的空间， `findmust` 用于寻找必须出现的字符串，以及 `computejumps` 和 `computematchjumps` 用于生成跳转表，以提高后续匹配的效率（类似于 Boyer-Moore 算法）。

6. **处理大小写不敏感匹配:**  通过 `regcomp` 函数的 `cflags` 参数 `REG_ICASE`，可以指定进行大小写不敏感的匹配。编译过程会将此信息考虑在内。

7. **处理换行符:**  通过 `regcomp` 函数的 `cflags` 参数 `REG_NEWLINE`，可以指定如何处理换行符，例如 `.` 不匹配换行符，`^` 和 `$` 匹配每行的开头和结尾。

**与 Android 功能的关系:**

正则表达式编译是 Android 系统中许多核心功能的基础。以下是一些例子：

* **文本搜索:** Android 系统中的搜索功能（例如在设置、文件管理器中搜索）可能使用正则表达式来进行更复杂的模式匹配。
* **输入验证:**  应用程序可以使用正则表达式来验证用户输入的数据格式，例如电子邮件地址、电话号码等。
* **网络请求处理:**  Android 系统内部的网络库或应用程序可能会使用正则表达式来解析 URL、HTTP 头等信息。
* **日志分析:**  系统服务和应用程序可以使用正则表达式来解析和过滤日志信息。
* **安全策略:**  某些安全策略或防火墙规则可能使用正则表达式来匹配特定的网络流量模式。
* **`grep` 等命令行工具:**  通过 Android 的 shell 环境，用户可以使用 `grep` 等工具，这些工具的底层正则表达式处理很可能就依赖于 `libc` 提供的正则表达式功能。

**Android 框架或 NDK 如何一步步到达这里:**

1. **NDK (Native Development Kit):**  如果开发者使用 NDK 编写 C/C++ 代码，他们可以直接调用 `regcomp` 函数。例如：

   ```c++
   #include <regex.h>
   #include <stdio.h>

   int main() {
       regex_t regex;
       int ret;
       const char *pattern = "a[bc]*d";
       const char *text = "abbcd";

       ret = regcomp(&regex, pattern, 0); // 调用 regcomp

       if (ret == 0) {
           printf("正则表达式编译成功\n");
           // ... 使用 regexec 进行匹配 ...
           regfree(&regex);
       } else {
           char error_buffer[100];
           regerror(ret, &regex, error_buffer, sizeof(error_buffer));
           printf("正则表达式编译失败: %s\n", error_buffer);
       }
       return 0;
   }
   ```

2. **Android Framework:**  Android Framework 中的 Java 代码可以通过 JNI (Java Native Interface) 调用到 `libc` 中的 `regcomp`。例如，某些系统服务可能需要进行文本模式匹配，而底层的实现会调用到本地代码。

3. **命令行工具:** 当用户在 Android 的 shell 环境中使用 `grep` 或 `sed` 等工具时，这些工具会调用 `libc` 提供的正则表达式函数。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `regcomp` 函数来观察其行为，例如传入的正则表达式和编译标志。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.spawn(["com.example.yourapp"]) # 替换为你的应用包名
    if not pid:
        device.resume(session.pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "regcomp"), {
            onEnter: function(args) {
                var regexPtr = args[0];
                var patternPtr = args[1];
                var cflags = args[2].toInt();
                var pattern = ptr(patternPtr).readCString();
                var flagsStr = "";
                if (cflags & 0x0001) flagsStr += "REG_EXTENDED ";
                if (cflags & 0x0002) flagsStr += "REG_ICASE ";
                if (cflags & 0x0004) flagsStr += "REG_NOSUB ";
                if (cflags & 0x0010) flagsStr += "REG_NEWLINE ";
                if (cflags & 0x0020) flagsStr += "REG_NOSPEC ";
                if (cflags & 0x0040) flagsStr += "REG_PEND ";
                if (cflags & 0x0200) flagsStr += "REG_DUMP ";

                send({
                    type: "regcomp",
                    pattern: pattern,
                    cflags: cflags,
                    flagsStr: flagsStr
                });
            },
            onLeave: function(retval) {
                send({
                    type: "regcomp_return",
                    retval: retval.toInt()
                });
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    print("[*] Waiting for messages...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

要运行此 Frida 脚本，你需要找到目标进程的 PID：

```bash
frida -U -f com.example.yourapp # 如果要 spawn 应用
# 或
frida -U <PID> # 如果应用已经在运行
```

**总结：**

`bionic/libc/upstream-netbsd/lib/libc/regex/regcomp.c` 文件的主要功能是将正则表达式字符串编译成一种内部表示形式，以便后续的匹配操作。它支持基本的和扩展的正则表达式语法，并处理各种正则表达式元素。这个功能是 Android 系统中许多文本处理功能的基础。

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
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*	$NetBSD: regcomp.c,v 1.47 2022/12/21 17:44:15 wiz Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993, 1994 Henry Spencer.
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
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
 *	@(#)regcomp.c	8.5 (Berkeley) 3/20/94
 */

#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
#endif

#include <sys/cdefs.h>
#if 0
static char sccsid[] = "@(#)regcomp.c	8.5 (Berkeley) 3/20/94";
__FBSDID("$FreeBSD: head/lib/libc/regex/regcomp.c 368359 2020-12-05 03:18:48Z kevans $");
#endif
__RCSID("$NetBSD: regcomp.c,v 1.47 2022/12/21 17:44:15 wiz Exp $");

#ifndef LIBHACK
#define REGEX_GNU_EXTENSIONS

#include "namespace.h"
#endif
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <regex.h>
#include <stdbool.h>

#if defined(__weak_alias) && !defined(LIBHACK)
__weak_alias(regcomp,_regcomp)
#endif

#ifdef REGEX_LIBC_COLLATE
#include "collate.h"
#endif

#include "utils.h"
#include "regex2.h"

#include "cname.h"

/*
 * Branching context, used to keep track of branch state for all of the branch-
 * aware functions. In addition to keeping track of branch positions for the
 * p_branch_* functions, we use this to simplify some clumsiness in BREs for
 * detection of whether ^ is acting as an anchor or being used erroneously and
 * also for whether we're in a sub-expression or not.
 */
struct branchc {
	sopno start;
	sopno back;
	sopno fwd;

	int nbranch;
	int nchain;
	bool outer;
	bool terminate;
};

/*
 * parse structure, passed up and down to avoid global variables and
 * other clumsinesses
 */
struct parse {
	const char *next;	/* next character in RE */
	const char *end;	/* end of string (-> NUL normally) */
	int error;		/* has an error been seen? */
	int gnuext;
	sop *strip;		/* malloced strip */
	sopno ssize;		/* malloced strip size (allocated) */
	sopno slen;		/* malloced strip length (used) */
	size_t ncsalloc;	/* number of csets allocated */
	struct re_guts *g;
#	define	NPAREN	10	/* we need to remember () 1-9 for back refs */
	sopno pbegin[NPAREN];	/* -> ( ([0] unused) */
	sopno pend[NPAREN];	/* -> ) ([0] unused) */
	bool allowbranch;	/* can this expression branch? */
	bool bre;		/* convenience; is this a BRE? */
	int pflags;		/* other parsing flags -- legacy escapes? */
	bool (*parse_expr)(struct parse *, struct branchc *);
	void (*pre_parse)(struct parse *, struct branchc *);
	void (*post_parse)(struct parse *, struct branchc *);
};

#define PFLAG_LEGACY_ESC	0x00000001

/* ========= begin header generated by ./mkh ========= */
#ifdef __cplusplus
extern "C" {
#endif

/* === regcomp.c === */
static bool p_ere_exp(struct parse *p, struct branchc *bc);
static void p_str(struct parse *p);
static int p_branch_eat_delim(struct parse *p, struct branchc *bc);
static void p_branch_ins_offset(struct parse *p, struct branchc *bc);
static void p_branch_fix_tail(struct parse *p, struct branchc *bc);
static bool p_branch_empty(struct parse *p, struct branchc *bc);
static bool p_branch_do(struct parse *p, struct branchc *bc);
static void p_bre_pre_parse(struct parse *p, struct branchc *bc);
static void p_bre_post_parse(struct parse *p, struct branchc *bc);
static void p_re(struct parse *p, int end1, int end2);
static bool p_simp_re(struct parse *p, struct branchc *bc);
static int p_count(struct parse *p);
static void p_bracket(struct parse *p);
static int p_range_cmp(wchar_t c1, wchar_t c2);
static void p_b_term(struct parse *p, cset *cs);
#ifdef REGEX_GNU_EXTENSIONS
static int p_b_pseudoclass(struct parse *p, char c);
#endif
static void p_b_cclass(struct parse *p, cset *cs);
static void p_b_cclass_named(struct parse *p, cset *cs, const char[]);
static void p_b_eclass(struct parse *p, cset *cs);
static wint_t p_b_symbol(struct parse *p);
static wint_t p_b_coll_elem(struct parse *p, wint_t endc);
static bool may_escape(struct parse *p, const wint_t ch);
static wint_t othercase(wint_t ch);
static void bothcases(struct parse *p, wint_t ch);
static void ordinary(struct parse *p, wint_t ch);
static void nonnewline(struct parse *p);
static void repeat(struct parse *p, sopno start, int from, int to);
static int seterr(struct parse *p, int e);
static cset *allocset(struct parse *p);
static void freeset(struct parse *p, cset *cs);
static void CHadd(struct parse *p, cset *cs, wint_t ch);
static void CHaddrange(struct parse *p, cset *cs, wint_t min, wint_t max);
static void CHaddtype(struct parse *p, cset *cs, wctype_t wct);
static wint_t singleton(cset *cs);
static sopno dupl(struct parse *p, sopno start, sopno finish);
static void doemit(struct parse *p, sop op, size_t opnd);
static void doinsert(struct parse *p, sop op, size_t opnd, sopno pos);
static void dofwd(struct parse *p, sopno pos, sop value);
static int enlarge(struct parse *p, sopno size);
static void stripsnug(struct parse *p, struct re_guts *g);
static void findmust(struct parse *p, struct re_guts *g);
static int altoffset(sop *scan, int offset);
static void computejumps(struct parse *p, struct re_guts *g);
static void computematchjumps(struct parse *p, struct re_guts *g);
static sopno pluscount(struct parse *p, struct re_guts *g);
static wint_t wgetnext(struct parse *p);

#ifdef __cplusplus
}
#endif
/* ========= end header generated by ./mkh ========= */

static char nuls[10];		/* place to point scanner in event of error */

/*
 * macros for use with parse structure
 * BEWARE:  these know that the parse structure is named `p' !!!
 */
#define	PEEK()	(*p->next)
#define	PEEK2()	(*(p->next+1))
#define	MORE()	(p->next < p->end)
#define	MORE2()	(p->next+1 < p->end)
#define	SEE(c)	(MORE() && PEEK() == (c))
#define	SEETWO(a, b)	(MORE() && MORE2() && PEEK() == (a) && PEEK2() == (b))
#define	SEESPEC(a)	(p->bre ? SEETWO('\\', a) : SEE(a))
#define	EAT(c)	((SEE(c)) ? (NEXT(), 1) : 0)
#define	EATTWO(a, b)	((SEETWO(a, b)) ? (NEXT2(), 1) : 0)
#define	EATSPEC(a)	(p->bre ? EATTWO('\\', a) : EAT(a))
#define	NEXT()	(p->next++)
#define	NEXT2()	(p->next += 2)
#define	NEXTn(n)	(p->next += (n))
#define	GETNEXT()	(*p->next++)
#define	WGETNEXT()	wgetnext(p)
#define	SETERROR(e)	seterr(p, (e))
#define	REQUIRE(co, e)	((co) || SETERROR(e))
#define	MUSTSEE(c, e)	(REQUIRE(MORE() && PEEK() == (c), e))
#define	MUSTEAT(c, e)	(REQUIRE(MORE() && GETNEXT() == (c), e))
#define	MUSTNOTSEE(c, e)	(REQUIRE(!MORE() || PEEK() != (c), e))
#define	EMIT(op, sopnd)	doemit(p, (op), (sopnd))
#define	INSERT(op, pos)	doinsert(p, (op), HERE()-(pos)+1, pos)
#define	AHEAD(pos)		dofwd(p, pos, HERE()-(pos))
#define	ASTERN(sop, pos)	EMIT(sop, HERE()-pos)
#define	HERE()		(p->slen)
#define	THERE()		(p->slen - 1)
#define	THERETHERE()	(p->slen - 2)
#define	DROP(n)	(p->slen -= (n))

/* Macro used by computejump()/computematchjump() */
#ifndef MIN
#define MIN(a,b)	((a)<(b)?(a):(b))
#endif

#ifndef NLS
static const struct {
	const char *name;
	int (*func)(int);
} wctypes[] = {
#define ADD(x) { .name = # x, .func = is ## x }
	ADD(alnum),
	ADD(alpha),
	ADD(blank),
	ADD(cntrl),
	ADD(digit),
	ADD(graph),
	ADD(lower),
	ADD(print),
	ADD(punct),
	ADD(space),
	ADD(upper),
	ADD(xdigit),
#undef ADD
};

wctype_t
__regex_wctype(const char *str)
{
	for (size_t i = 0; i < __arraycount(wctypes); i++) {
		if (strcmp(wctypes[i].name, str) == 0)
			return (wctype_t)(i + 1);
	}
	return (wctype_t)0;
}

int
__regex_iswctype(wint_t c, wctype_t ct)
{
	if (ct == 0)
		return 0;
	return (*wctypes[ct - 1].func)(c);
}
#endif

static int				/* 0 success, otherwise REG_something */
regcomp_internal(regex_t * __restrict preg,
	const char * __restrict pattern,
	int cflags, int pflags)
{
	struct parse pa;
	struct re_guts *g;
	struct parse *p = &pa;
	int i;
	size_t len;
	size_t maxlen;
#ifdef REDEBUG
#	define	GOODFLAGS(f)	(f)
#else
#	define	GOODFLAGS(f)	((f)&~REG_DUMP)
#endif

	_DIAGASSERT(preg != NULL);
	_DIAGASSERT(pattern != NULL);

	cflags = GOODFLAGS(cflags);
	if ((cflags&REG_EXTENDED) && (cflags&REG_NOSPEC))
		return(REG_INVARG);

	if (cflags&REG_PEND) {
		if (preg->re_endp < pattern)
			return(REG_INVARG);
		len = preg->re_endp - pattern;
	} else
		len = strlen(pattern);

	/* do the mallocs early so failure handling is easy */
	g = malloc(sizeof(*g));
	if (g == NULL)
		return(REG_ESPACE);
	/*
	 * Limit the pattern space to avoid a 32-bit overflow on buffer
	 * extension.  Also avoid any signed overflow in case of conversion
	 * so make the real limit based on a 31-bit overflow.
	 *
	 * Likely not applicable on 64-bit systems but handle the case
	 * generically (who are we to stop people from using ~715MB+
	 * patterns?).
	 */
	maxlen = ((size_t)-1 >> 1) / sizeof(*p->strip) * 2 / 3;
	if (len >= maxlen) {
		free(g);
		return(REG_ESPACE);
	}
	p->ssize = (sopno)(len / 2 * 3 + 1);	/* ugh */
	assert(p->ssize >= len);

	p->strip = calloc(p->ssize, sizeof(*p->strip));
	p->slen = 0;
	if (p->strip == NULL) {
		free(g);
		return(REG_ESPACE);
	}

	/* set things up */
	p->g = g;
	p->next = pattern;	/* convenience; we do not modify it */
	p->end = p->next + len;
	p->error = 0;
	p->ncsalloc = 0;
	p->pflags = pflags;
	for (i = 0; i < NPAREN; i++) {
		p->pbegin[i] = 0;
		p->pend[i] = 0;
	}
#ifdef REGEX_GNU_EXTENSIONS
	if ((cflags & REG_GNU) == 0) {
		p->gnuext = false;
		p->allowbranch = (cflags & REG_EXTENDED) != 0;
	} else
		p->gnuext = p->allowbranch = true;
#else
	p->gnuext = false;
	p->allowbranch = (cflags & REG_EXTENDED) != 0;
#endif
	if (cflags & REG_EXTENDED) {
		p->bre = false;
		p->parse_expr = p_ere_exp;
		p->pre_parse = NULL;
		p->post_parse = NULL;
	} else {
		p->bre = true;
		p->parse_expr = p_simp_re;
		p->pre_parse = p_bre_pre_parse;
		p->post_parse = p_bre_post_parse;
	}
	g->sets = NULL;
	g->ncsets = 0;
	g->cflags = cflags;
	g->iflags = 0;
	g->nbol = 0;
	g->neol = 0;
	g->must = NULL;
	g->moffset = -1;
	g->charjump = NULL;
	g->matchjump = NULL;
	g->mlen = 0;
	g->nsub = 0;
	g->backrefs = 0;

	/* do it */
	EMIT(OEND, 0);
	g->firststate = THERE();
	if (cflags & REG_NOSPEC)
		p_str(p);
	else
		p_re(p, OUT, OUT);
	EMIT(OEND, 0);
	g->laststate = THERE();

	/* tidy up loose ends and fill things in */
	stripsnug(p, g);
	findmust(p, g);
	/* only use Boyer-Moore algorithm if the pattern is bigger
	 * than three characters
	 */
	if(g->mlen > 3) {
		computejumps(p, g);
		computematchjumps(p, g);
		if(g->matchjump == NULL && g->charjump != NULL) {
			free(g->charjump);
			g->charjump = NULL;
		}
	}
	g->nplus = pluscount(p, g);
	g->magic = MAGIC2;
	preg->re_nsub = g->nsub;
	preg->re_g = g;
	preg->re_magic = MAGIC1;
#ifndef REDEBUG
	/* not debugging, so can't rely on the assert() in regexec() */
	if (g->iflags&BAD)
		SETERROR(REG_ASSERT);
#endif

	/* win or lose, we're done */
	if (p->error != 0)	/* lose */
		regfree(preg);
	return(p->error);
}

/*
 - regcomp - interface for parser and compilation
 = extern int regcomp(regex_t *, const char *, int);
 = #define	REG_BASIC	0000
 = #define	REG_EXTENDED	0001
 = #define	REG_ICASE	0002
 = #define	REG_NOSUB	0004
 = #define	REG_NEWLINE	0010
 = #define	REG_NOSPEC	0020
 = #define	REG_PEND	0040
 = #define	REG_DUMP	0200
 */
int				/* 0 success, otherwise REG_something */
regcomp(regex_t * __restrict preg,
	const char * __restrict pattern,
	int cflags)
{

	return (regcomp_internal(preg, pattern, cflags, 0));
}

/*
 - p_ere_exp - parse one subERE, an atom possibly followed by a repetition op,
 - return whether we should terminate or not
 == static bool p_ere_exp(struct parse *p);
 */
static bool
p_ere_exp(struct parse *p, struct branchc *bc)
{
	char c;
	wint_t wc;
	sopno pos;
	int count;
	int count2;
#ifdef REGEX_GNU_EXTENSIONS
	size_t i;
	int handled;
#endif
	sopno subno;
	int wascaret = 0;

	_DIAGASSERT(p != NULL);

	(void)bc;
	assert(MORE());		/* caller should have ensured this */
	c = GETNEXT();

#ifdef REGEX_GNU_EXTENSIONS
	handled = 0;
#endif
	pos = HERE();
	switch (c) {
	case '(':
		(void)REQUIRE(MORE(), REG_EPAREN);
		p->g->nsub++;
		subno = (sopno)p->g->nsub;
		if (subno < NPAREN)
			p->pbegin[subno] = HERE();
		EMIT(OLPAREN, subno);
		if (!SEE(')'))
			p_re(p, ')', IGN);
		if (subno < NPAREN) {
			p->pend[subno] = HERE();
			assert(p->pend[subno] != 0);
		}
		EMIT(ORPAREN, subno);
		(void)MUSTEAT(')', REG_EPAREN);
		break;
#ifndef POSIX_MISTAKE
	case ')':		/* happens only if no current unmatched ( */
		/*
		 * You may ask, why the ifndef?  Because I didn't notice
		 * this until slightly too late for 1003.2, and none of the
		 * other 1003.2 regular-expression reviewers noticed it at
		 * all.  So an unmatched ) is legal POSIX, at least until
		 * we can get it fixed.
		 */
		SETERROR(REG_EPAREN);
		break;
#endif
	case '^':
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
		wascaret = 1;
		break;
	case '$':
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
		break;
	case '|':
		SETERROR(REG_EMPTY);
		break;
	case '*':
	case '+':
	case '?':
	case '{':
		SETERROR(REG_BADRPT);
		break;
	case '.':
		if (p->g->cflags&REG_NEWLINE)
			nonnewline(p);
		else
			EMIT(OANY, 0);
		break;
	case '[':
		p_bracket(p);
		break;
	case '\\':
		(void)REQUIRE(MORE(), REG_EESCAPE);
		wc = WGETNEXT();
#ifdef REGEX_GNU_EXTENSIONS
		if (p->gnuext) {
			handled = 1;
			switch (wc) {
			case '`':
				EMIT(OBOS, 0);
				break;
			case '\'':
				EMIT(OEOS, 0);
				break;
			case 'B':
				EMIT(ONWBND, 0);
				break;
			case 'b':
				EMIT(OWBND, 0);
				break;
			case 'W':
			case 'w':
			case 'S':
			case 's':
				p_b_pseudoclass(p, wc);
				break;
			case 'a':
				ordinary(p, '\a');
				break;
			case 'e':
				ordinary(p, '\e');
				break;
			case 'f':
				ordinary(p, '\f');
				break;
			case 'n':
				ordinary(p, '\n');
				break;
			case 'r':
				ordinary(p, '\r');
				break;
			case 't':
				ordinary(p, '\t');
				break;
			case 'v':
				ordinary(p, '\v');
				break;
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				i = wc - '0';
				assert(i < NPAREN);
				if (p->pend[i] != 0) {
					assert(i <= p->g->nsub);
					EMIT(OBACK_, i);
					assert(p->pbegin[i] != 0);
					assert(OP(p->strip[p->pbegin[i]]) == OLPAREN);
					assert(OP(p->strip[p->pend[i]]) == ORPAREN);
					(void) dupl(p, p->pbegin[i]+1, p->pend[i]);
					EMIT(O_BACK, i);
				} else
					SETERROR(REG_ESUBREG);
				p->g->backrefs = 1;
				break;
			default:
				handled = 0;
			}
			/* Don't proceed to the POSIX bits if we've already handled it */
			if (handled)
				break;
		}
#endif
		switch (wc) {
		case '<':
			EMIT(OBOW, 0);
			break;
		case '>':
			EMIT(OEOW, 0);
			break;
		default:
			if (may_escape(p, wc))
				ordinary(p, wc);
			else
				SETERROR(REG_EESCAPE);
			break;
		}
		break;
	default:
		if (p->error != 0)
			return (false);
		p->next--;
		wc = WGETNEXT();
		ordinary(p, wc);
		break;
	}

	if (!MORE())
		return (false);
	c = PEEK();
	/* we call { a repetition if followed by a digit */
	if (!( c == '*' || c == '+' || c == '?' || c == '{'))
		return (false);		/* no repetition, we're done */
	else if (c == '{')
		(void)REQUIRE(MORE2() && \
		    (isdigit((uch)PEEK2()) || PEEK2() == ','), REG_BADRPT);
	NEXT();

	(void)REQUIRE(!wascaret, REG_BADRPT);
	switch (c) {
	case '*':	/* implemented as +? */
		/* this case does not require the (y|) trick, noKLUDGE */
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
		break;
	case '+':
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		break;
	case '?':
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, pos);		/* offset slightly wrong */
		ASTERN(OOR1, pos);		/* this one's right */
		AHEAD(pos);			/* fix the OCH_ */
		EMIT(OOR2, 0);			/* offset very wrong... */
		AHEAD(THERE());			/* ...so fix it */
		ASTERN(O_CH, THERETHERE());
		break;
	case '{':
		count = p_count(p);
		if (EAT(',')) {
			if (isdigit((uch)PEEK())) {
				count2 = p_count(p);
				(void)REQUIRE(count <= count2, REG_BADBR);
			} else		/* single number with comma */
				count2 = INFINITY;
		} else		/* just a single number */
			count2 = count;
		repeat(p, pos, count, count2);
		if (!EAT('}')) {	/* error heuristics */
			while (MORE() && PEEK() != '}')
				NEXT();
			(void)REQUIRE(MORE(), REG_EBRACE);
			SETERROR(REG_BADBR);
		}
		break;
	}

	if (!MORE())
		return (false);
	c = PEEK();
	if (!( c == '*' || c == '+' || c == '?' ||
				(c == '{' && MORE2() && isdigit((uch)PEEK2())) ) )
		return (false);
	SETERROR(REG_BADRPT);
	return (false);
}

/*
 - p_str - string (no metacharacters) "parser"
 == static void p_str(struct parse *p);
 */
static void
p_str(struct parse *p)
{
	(void)REQUIRE(MORE(), REG_EMPTY);
	while (MORE())
		ordinary(p, WGETNEXT());
}

/*
 * Eat consecutive branch delimiters for the kind of expression that we are
 * parsing, return the number of delimiters that we ate.
 */
static int
p_branch_eat_delim(struct parse *p, struct branchc *bc)
{
	int nskip;

	(void)bc;
	nskip = 0;
	while (EATSPEC('|'))
		++nskip;
	return (nskip);
}

/*
 * Insert necessary branch book-keeping operations. This emits a
 * bogus 'next' offset, since we still have more to parse
 */
static void
p_branch_ins_offset(struct parse *p, struct branchc *bc)
{

	if (bc->nbranch == 0) {
		INSERT(OCH_, bc->start);	/* offset is wrong */
		bc->fwd = bc->start;
		bc->back = bc->start;
	}

	ASTERN(OOR1, bc->back);
	bc->back = THERE();
	AHEAD(bc->fwd);			/* fix previous offset */
	bc->fwd = HERE();
	EMIT(OOR2, 0);			/* offset is very wrong */
	++bc->nbranch;
}

/*
 * Fix the offset of the tail branch, if we actually had any branches.
 * This is to correct the bogus placeholder offset that we use.
 */
static void
p_branch_fix_tail(struct parse *p, struct branchc *bc)
{

	/* Fix bogus offset at the tail if we actually have branches */
	if (bc->nbranch > 0) {
		AHEAD(bc->fwd);
		ASTERN(O_CH, bc->back);
	}
}

/*
 * Signal to the parser that an empty branch has been encountered; this will,
 * in the future, be used to allow for more permissive behavior with empty
 * branches. The return value should indicate whether parsing may continue
 * or not.
 */
static bool
p_branch_empty(struct parse *p, struct branchc *bc)
{

	(void)bc;
	SETERROR(REG_EMPTY);
	return (false);
}

/*
 * Take care of any branching requirements. This includes inserting the
 * appropriate branching instructions as well as eating all of the branch
 * delimiters until we either run out of pattern or need to parse more pattern.
 */
static bool
p_branch_do(struct parse *p, struct branchc *bc)
{
	int ate = 0;

	ate = p_branch_eat_delim(p, bc);
	if (ate == 0)
		return (false);
	else if ((ate > 1 || (bc->outer && !MORE())) && !p_branch_empty(p, bc))
		/*
		 * Halt parsing only if we have an empty branch and p_branch_empty
		 * indicates that we must not continue. In the future, this will not
		 * necessarily be an error.
		 */
		return (false);
	p_branch_ins_offset(p, bc);

	return (true);
}

static void
p_bre_pre_parse(struct parse *p, struct branchc *bc)
{

	(void)bc;
	/*
	 * Does not move cleanly into expression parser because of
	 * ordinary interpration of * at the beginning position of
	 * an expression.
	 */
	if (EAT('^')) {
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
	}
}

static void
p_bre_post_parse(struct parse *p, struct branchc *bc)
{

	/* Expression is terminating due to EOL token */
	if (bc->terminate) {
		DROP(1);
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
	}
}

/*
 - p_re - Top level parser, concatenation and BRE anchoring
 == static void p_re(struct parse *p, int end1, int end2);
 * Giving end1 as OUT essentially eliminates the end1/end2 check.
 *
 * This implementation is a bit of a kludge, in that a trailing $ is first
 * taken as an ordinary character and then revised to be an anchor.
 * The amount of lookahead needed to avoid this kludge is excessive.
 */
static void
p_re(struct parse *p,
	int end1,	/* first terminating character */
	int end2)	/* second terminating character; ignored for EREs */
{
	struct branchc bc;

	bc.nbranch = 0;
	if (end1 == OUT && end2 == OUT)
		bc.outer = true;
	else
		bc.outer = false;
#define	SEEEND()	(!p->bre ? SEE(end1) : SEETWO(end1, end2))
	for (;;) {
		bc.start = HERE();
		bc.nchain = 0;
		bc.terminate = false;
		if (p->pre_parse != NULL)
			p->pre_parse(p, &bc);
		while (MORE() && (!p->allowbranch || !SEESPEC('|')) && !SEEEND()) {
			bc.terminate = p->parse_expr(p, &bc);
			++bc.nchain;
		}
		if (p->post_parse != NULL)
			p->post_parse(p, &bc);
		(void) REQUIRE(p->gnuext || HERE() != bc.start, REG_EMPTY);
#ifdef REGEX_GNU_EXTENSIONS
		if (p->gnuext && HERE() == bc.start && !p_branch_empty(p, &bc))
			break;
#endif
		if (!p->allowbranch)
			break;
		/*
		 * p_branch_do's return value indicates whether we should
		 * continue parsing or not. This is both for correctness and
		 * a slight optimization, because it will check if we've
		 * encountered an empty branch or the end of the string
		 * immediately following a branch delimiter.
		 */
		if (!p_branch_do(p, &bc))
			break;
	}
#undef SEE_END
	if (p->allowbranch)
		p_branch_fix_tail(p, &bc);
	assert(!MORE() || SEE(end1));
}

/*
 - p_simp_re - parse a simple RE, an atom possibly followed by a repetition
 == static bool p_simp_re(struct parse *p, struct branchc *bc);
 */
static bool			/* was the simple RE an unbackslashed $? */
p_simp_re(struct parse *p, struct branchc *bc)
{
	int c;
	int cc;			/* convenient/control character */
	int count;
	int count2;
	sopno pos;
	bool handled;
	size_t i;
	wint_t wc;
	sopno subno;
#	define	BACKSL	(1<<CHAR_BIT)

	pos = HERE();		/* repetition op, if any, covers from here */
	handled = false;

	assert(MORE());		/* caller should have ensured this */
	c = GETNEXT();
	if (c == '\\') {
		(void)REQUIRE(MORE(), REG_EESCAPE);
		cc = GETNEXT();
		c = BACKSL | cc;
#ifdef REGEX_GNU_EXTENSIONS
		if (p->gnuext) {
			handled = true;
			switch (c) {
			case BACKSL|'`':
				EMIT(OBOS, 0);
				break;
			case BACKSL|'\'':
				EMIT(OEOS, 0);
				break;
			case BACKSL|'B':
				EMIT(ONWBND, 0);
				break;
			case BACKSL|'b':
				EMIT(OWBND, 0);
				break;
			case BACKSL|'W':
			case BACKSL|'w':
			case BACKSL|'S':
			case BACKSL|'s':
				p_b_pseudoclass(p, cc);
				break;
			case BACKSL|'a':
				ordinary(p, '\a');
				break;
			case BACKSL|'e':
				ordinary(p, '\e');
				break;
			case BACKSL|'f':
				ordinary(p, '\f');
				break;
			case BACKSL|'n':
				ordinary(p, '\n');
				break;
			case BACKSL|'r':
				ordinary(p, '\r');
				break;
			case BACKSL|'t':
				ordinary(p, '\t');
				break;
			case BACKSL|'v':
				ordinary(p, '\v');
				break;
			default:
				handled = false;
			}
		}
#endif
	}
	if (!handled) {
		switch (c) {
		case '.':
			if (p->g->cflags&REG_NEWLINE)
				nonnewline(p);
			else
				EMIT(OANY, 0);
			break;
		case '[':
			p_bracket(p);
			break;
		case BACKSL|'<':
			EMIT(OBOW, 0);
			break;
		case BACKSL|'>':
			EMIT(OEOW, 0);
			break;
		case BACKSL|'{':
			SETERROR(REG_BADRPT);
			break;
		case BACKSL|'(':
			p->g->nsub++;
			subno = (sopno)p->g->nsub;
			if (subno < NPAREN)
				p->pbegin[subno] = HERE();
			EMIT(OLPAREN, subno);
			/* the MORE here is an error heuristic */
			if (MORE() && !SEETWO('\\', ')'))
				p_re(p, '\\', ')');
			if (subno < NPAREN) {
				p->pend[subno] = HERE();
				assert(p->pend[subno] != 0);
			}
			EMIT(ORPAREN, subno);
			(void)REQUIRE(EATTWO('\\', ')'), REG_EPAREN);
			break;
		case BACKSL|')':	/* should not get here -- must be user */
			SETERROR(REG_EPAREN);
			break;
		case BACKSL|'1':
		case BACKSL|'2':
		case BACKSL|'3':
		case BACKSL|'4':
		case BACKSL|'5':
		case BACKSL|'6':
		case BACKSL|'7':
		case BACKSL|'8':
		case BACKSL|'9':
			i = (c&~BACKSL) - '0';
			assert(i < NPAREN);
			if (p->pend[i] != 0) {
				assert(i <= p->g->nsub);
				EMIT(OBACK_, i);
				assert(p->pbegin[i] != 0);
				assert(OP(p->strip[p->pbegin[i]]) == OLPAREN);
				assert(OP(p->strip[p->pend[i]]) == ORPAREN);
				(void) dupl(p, p->pbegin[i]+1, p->pend[i]);
				EMIT(O_BACK, i);
			} else
				SETERROR(REG_ESUBREG);
			p->g->backrefs = 1;
			break;
		case '*':
			/*
			 * Ordinary if used as the first character beyond BOL anchor of
			 * a (sub-)expression, counts as a bad repetition operator if it
			 * appears otherwise.
			 */
			(void)REQUIRE(bc->nchain == 0, REG_BADRPT);
			/* FALLTHROUGH */
		default:
			if (p->error != 0)
				return (false);	/* Definitely not $... */
			p->next--;
			wc = WGETNEXT();
			if ((c & BACKSL) == 0 || may_escape(p, wc))
				ordinary(p, wc);
			else
				SETERROR(REG_EESCAPE);
			break;
		}
	}

	if (EAT('*')) {		/* implemented as +? */
		/* this case does not require the (y|) trick, noKLUDGE */
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
#ifdef REGEX_GNU_EXTENSIONS
	} else if (p->gnuext && EATTWO('\\', '?')) {
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
	} else if (p->gnuext && EATTWO('\\', '+')) {
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
#endif
	} else if (EATTWO('\\', '{')) {
		count = p_count(p);
		if (EAT(',')) {
			if (MORE() && isdigit((uch)PEEK())) {
				count2 = p_count(p);
				(void)REQUIRE(count <= count2, REG_BADBR);
			} else		/* single number with comma */
				count2 = INFINITY;
		} else		/* just a single number */
			count2 = count;
		repeat(p, pos, count, count2);
		if (!EATTWO('\\', '}')) {	/* error heuristics */
			while (MORE() && !SEETWO('\\', '}'))
				NEXT();
			(void)REQUIRE(MORE(), REG_EBRACE);
			SETERROR(REG_BADBR);
		}
	} else if (c == '$')     /* $ (but not \$) ends it */
		return (true);

	return (false);
}

/*
 - p_count - parse a repetition count
 == static int p_count(struct parse *p);
 */
static int			/* the value */
p_count(struct parse *p)
{
	int count = 0;
	int ndigits = 0;

	while (MORE() && isdigit((uch)PEEK()) && count <= DUPMAX) {
		count = count*10 + (GETNEXT() - '0');
		ndigits++;
	}

	(void)REQUIRE(ndigits > 0 && count <= DUPMAX, REG_BADBR);
	return(count);
}

/*
 - p_bracket - parse a bracketed character list
 == static void p_bracket(struct parse *p);
 */
static void
p_bracket(struct parse *p)
{
	cset *cs;
	wint_t ch;

	/* Dept of Truly Sickening Special-Case Kludges */
	if (p->next + 5 < p->end && strncmp(p->next, "[:<:]]", 6) == 0) {
		EMIT(OBOW, 0);
		NEXTn(6);
		return;
	}
	if (p->next + 5 < p->end && strncmp(p->next, "[:>:]]", 6) == 0) {
		EMIT(OEOW, 0);
		NEXTn(6);
		return;
	}

	if ((cs = allocset(p)) == NULL)
		return;

	if (p->g->cflags&REG_ICASE)
		cs->icase = 1;
	if (EAT('^'))
		cs->invert = 1;
	if (EAT(']'))
		CHadd(p, cs, ']');
	else if (EAT('-'))
		CHadd(p, cs, '-');
	while (MORE() && PEEK() != ']' && !SEETWO('-', ']'))
		p_b_term(p, cs);
	if (EAT('-'))
		CHadd(p, cs, '-');
	(void)MUSTEAT(']', REG_EBRACK);

	if (p->error != 0)	/* don't mess things up further */
		return;

	if (cs->invert && p->g->cflags&REG_NEWLINE)
		cs->bmp['\n' >> 3] |= 1 << ('\n' & 7);

	if ((ch = singleton(cs)) != OUT) {	/* optimize singleton sets */
		ordinary(p, ch);
		freeset(p, cs);
	} else
		EMIT(OANYOF, (size_t)(cs - p->g->sets));
}

static int
p_range_cmp(wchar_t c1, wchar_t c2)
{
#ifdef REGEX_LIBC_COLLATE
	return __wcollate_range_cmp(c1, c2);
#elif defined(NLS)
	/* Copied from libc/collate __wcollate_range_cmp */
	wchar_t s1[2], s2[2];

	s1[0] = c1;
	s1[1] = L'\0';
	s2[0] = c2;
	s2[1] = L'\0';
	return wcscoll(s1, s2);
#else
	char s1[2], s2[2];

	s1[0] = (char)c1;
	s1[1] = '\0';
	s2[0] = (char)c2;
	s2[1] = '\0';
	return strcoll(s1, s2);
#endif
}

/*
 - p_b_term - parse one term of a bracketed character list
 == static void p_b_term(struct parse *p, cset *cs);
 */
static void
p_b_term(struct parse *p, cset *cs)
{
	char c;
	wint_t start, finish;
	wint_t i;
#ifdef REGEX_LIBC_COLLATE
	struct xlocale_collate *table =
		(struct xlocale_collate*)__get_locale()->components[XLC_COLLATE];
#endif

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	/* classify what we've got */
	switch ((MORE()) ? PEEK() : '\0') {
	case '[':
		c = (MORE2()) ? PEEK2() : '\0';
		break;
	case '-':
		SETERROR(REG_ERANGE);
		return;			/* NOTE RETURN */
	default:
		c = '\0';
		break;
	}

	switch (c) {
	case ':':		/* character class */
		NEXT2();
		(void)REQUIRE(MORE(), REG_EBRACK);
		c = PEEK();
		(void)REQUIRE(c != '-' && c != ']', REG_ECTYPE);
		p_b_cclass(p, cs);
		(void)REQUIRE(MORE(), REG_EBRACK);
		(void)REQUIRE(EATTWO(':', ']'), REG_ECTYPE);
		break;
	case '=':		/* equivalence class */
		NEXT2();
		(void)REQUIRE(MORE(), REG_EBRACK);
		c = PEEK();
		(void)REQUIRE(c != '-' && c != ']', REG_ECOLLATE);
		p_b_eclass(p, cs);
		(void)REQUIRE(MORE(), REG_EBRACK);
		(void)REQUIRE(EATTWO('=', ']'), REG_ECOLLATE);
		break;
	default:		/* symbol, ordinary character, or range */
		start = p_b_symbol(p);
		if (SEE('-') && MORE2() && PEEK2() != ']') {
			/* range */
			NEXT();
			if (EAT('-'))
				finish = '-';
			else
				finish = p_b_symbol(p);
		} else
			finish = start;
		if (start == finish)
			CHadd(p, cs, start);
		else {
#ifdef REGEX_LIBC_COLLATE
			if (table->__collate_load_error || MB_CUR_MAX > 1) {
#else
			if (MB_CUR_MAX > 1) {
#endif
				(void)REQUIRE(start <= finish, REG_ERANGE);
				CHaddrange(p, cs, start, finish);
			} else {
				(void)REQUIRE(p_range_cmp(start, finish) <= 0, REG_ERANGE);
				for (i = 0; i <= UCHAR_MAX; i++) {
					if (p_range_cmp(start, i) <= 0 &&
					    p_range_cmp(i, finish) <= 0 )
						CHadd(p, cs, i);
				}
			}
		}
		break;
	}
}

#ifdef REGEX_GNU_EXTENSIONS
/*
 - p_b_pseudoclass - parse a pseudo-class (\w, \W, \s, \S)
 == static int p_b_pseudoclass(struct parse *p, char c)
 */
static int
p_b_pseudoclass(struct parse *p, char c) {
	cset *cs;

	if ((cs = allocset(p)) == NULL)
		return(0);

	if (p->g->cflags&REG_ICASE)
		cs->icase = 1;

	switch (c) {
	case 'W':
		cs->invert = 1;
		/* FALLTHROUGH */
	case 'w':
		p_b_cclass_named(p, cs, "alnum");
		break;
	case 'S':
		cs->invert = 1;
		/* FALLTHROUGH */
	case 's':
		p_b_cclass_named(p, cs, "space");
		break;
	default:
		return(0);
	}

	EMIT(OANYOF, (size_t)(cs - p->g->sets));
	return(1);
}
#endif

/*
 - p_b_cclass - parse a character-class name and deal with it
 == static void p_b_cclass(struct parse *p, cset *cs);
 */
static void
p_b_cclass(struct parse *p, cset *cs)
{
	const char *sp = p->next;
	size_t len;
	char clname[16];

	while (MORE() && isalpha((uch)PEEK()))
		NEXT();
	len = p->next - sp;
	if (len >= sizeof(clname) - 1) {
		SETERROR(REG_ECTYPE);
		return;
	}
	memcpy(clname, sp, len);
	clname[len] = '\0';

	p_b_cclass_named(p, cs, clname);
}

/*
 - p_b_cclass_named - deal with a named character class
 == static void p_b_cclass_named(struct parse *p, cset *cs, const char []);
 */
static void
p_b_cclass_named(struct parse *p, cset *cs, const char clname[]) {
	wctype_t wct;

	if ((wct = wctype(clname)) == 0) {
		SETERROR(REG_ECTYPE);
		return;
	}
	CHaddtype(p, cs, wct);
}

/*
 - p_b_eclass - parse an equivalence-class name and deal with it
 == static void p_b_eclass(struct parse *p, cset *cs);
 *
 * This implementation is incomplete. xxx
 */
static void
p_b_eclass(struct parse *p, cset *cs)
{
	wint_t c;

	_DIAGASSERT(p != NULL);
	_DIAGASSERT(cs != NULL);

	c = p_b_coll_elem(p, '=');
	CHadd(p, cs, c);
}

/*
```