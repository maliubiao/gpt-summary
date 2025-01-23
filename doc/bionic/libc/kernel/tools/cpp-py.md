Response:
My thinking process to answer the request about `bionic/libc/kernel/tools/cpp.py` goes like this:

1. **Understand the Core Request:** The request asks for a functional summary of the provided Python code (`cpp.py`), its relationship to Android, detailed explanations of libc functions (though none are directly present in *this* code), dynamic linker aspects (again, not directly present, but related concepts can be discussed), examples of logic and usage errors, how Android frameworks interact with this code (indirectly), and Frida hooking examples. The key constraint for *this* part is to provide a *summary* of the file's functionality.

2. **Initial Code Scan - Identify Key Areas:** I first quickly scan the code to identify the major components and their purposes. Keywords like `Tokenizer`, `Expr`, `clang`, `macros`, and the various token definitions stand out. The imports also give strong hints (e.g., `clang.cindex`).

3. **Focus on the Stated Goal:** The docstring at the top clearly states: "A glorified C pre-processor parser." This immediately tells me the primary function of the script.

4. **Break Down the Functionality:** I start dissecting the code's structure and purpose, focusing on the main classes and their roles:

    * **`Token`:**  Represents individual tokens, enhancing the base `clang.cindex.Token` with an `id` for storing the processed token string. This is crucial for macro expansion and other pre-processing tasks.

    * **`CppTokenizer`:**  The core component for breaking down C/C++ code into a sequence of tokens. It leverages `libclang` for the heavy lifting but adds custom logic, particularly for associating cursors with tokens more effectively. The `parseString` and `parseFile` methods are fundamental.

    * **`CppExpr`:**  Handles the parsing and representation of preprocessor expressions (like those in `#if` and `#elif` directives). It builds an expression tree and provides methods for evaluation and optimization. The precedence rules for operators are explicitly defined.

5. **Identify Relationships and Dependencies:** I note the dependency on `libclang` and how it's configured. The use of `ANDROID_BUILD_TOP` signifies its context within the Android build system.

6. **Relate to Android (High-Level):**  I recognize that a C preprocessor is essential for compiling any C/C++ code, including the Android system libraries (Bionic). This script is a *tool* used *during the build process* of Android. It doesn't run on the Android device itself.

7. **Address the "List its functions" part:**  Based on the breakdown, I can list the primary functions:
    * Tokenizing C/C++ code.
    * Parsing preprocessor expressions.
    * Representing expressions as trees.
    * Optimizing these expressions.

8. **Address the "Relationship with Android" part:** I explain its role in the Android build process, specifically in handling preprocessor directives within the Bionic C library source code. I emphasize it's a *build-time tool*.

9. **Address the "Detailed explanation of libc functions":**  Crucially, I realize *this script itself doesn't implement libc functions*. It *processes* code that might *contain* libc functions. This distinction is important. Therefore, I state that the script focuses on *preprocessing* and doesn't directly implement libc functions.

10. **Address the "Dynamic linker functionality":** Similar to libc functions, this script doesn't directly implement dynamic linking. However, preprocessor directives can influence how code is compiled and linked. I explain this indirect relationship – the script processes code that *eventually* gets linked. I note the absence of direct dynamic linker manipulation in the provided code.

11. **Address "Logic and usage errors":**  I look for error handling in the code. `BadExpectedToken` and `UnparseableStruct` are explicitly defined exceptions, which are good examples of how the parser handles invalid input. I can formulate examples of situations that would trigger these (e.g., malformed `#if` conditions).

12. **Address "Android framework or NDK":** I explain that this script is a *low-level build tool*. The Android Framework and NDK interact with the *output* of the compilation process, not directly with this preprocessor script. The interaction is indirect. The NDK uses compilers that have their own preprocessing steps, but this script could be used as a custom or supplementary tool within the build system.

13. **Address "Frida hook example":**  Since this is a build-time tool, directly hooking it with Frida (which runs on a live Android system) is not the typical use case. However, I can still provide a *conceptual* example of how one *might* try to intercept its execution during a build process, emphasizing the complexity and the fact that it's not a standard debugging target with Frida.

14. **Address "归纳一下它的功能 (Summarize its function)":** This ties back to the initial understanding. I reiterate the core functionality:  It's a C preprocessor parser used in the Android build process, responsible for tokenizing and parsing preprocessor directives and expressions.

15. **Structure the Answer:** Finally, I organize the information logically, using clear headings and bullet points to address each part of the request. I ensure the language is precise and avoids overstating the script's capabilities. I focus on what the code *actually does*.

By following this systematic approach, I can provide a comprehensive and accurate answer that addresses all aspects of the request while remaining true to the provided code. The key is to distinguish between what the script *is*, what it *does*, and its relationships (direct or indirect) with the broader Android ecosystem.
好的，我们来归纳一下 `bionic/libc/kernel/tools/cpp.py` 文件的功能。

**`bionic/libc/kernel/tools/cpp.py` 的主要功能：**

这个 Python 脚本是一个 C 预处理器解析器（C Pre-Processor Parser）。它的核心任务是读取 C 或 C++ 代码，并理解和处理其中的预处理器指令，例如 `#define`、`#ifdef`、`#ifndef`、`#if` 等。

**更具体的功能点包括：**

1. **词法分析 (Tokenization):**  它使用 `libclang` 库将输入的 C/C++ 代码分解成一个个独立的“词法单元”（tokens）。例如，将 `int a = 10;` 分解成 `int`, `a`, `=`, `10`, `;` 等 token。  它自定义了一个 `Token` 类来增强 `libclang` 提供的 token 对象，例如添加了 `id` 属性用于存储 token 的新拼写。

2. **预处理指令解析:**  能够识别和解析各种 C 预处理器指令，例如：
    * **宏定义 (`#define`):**  理解宏的名称和值。
    * **条件编译 (`#ifdef`, `#ifndef`, `#if`, `#elif`, `#else`, `#endif`):**  解析条件表达式，并根据表达式的结果决定哪些代码块应该被保留，哪些应该被忽略。
    * **文件包含 (`#include`):** 虽然代码中没有直接处理 `#include` 的逻辑，但作为预处理器的一部分，它在概念上是相关的。
    * **其他指令:** 例如 `#undef`。

3. **表达式解析 (`CppExpr` 类):**  对于 `#if` 和 `#elif` 等指令中的条件表达式，它使用 `CppExpr` 类进行解析，构建表达式树，并进行优化。这包括处理各种运算符（逻辑运算符、算术运算符、比较运算符等）和 `defined` 运算符。

4. **宏替换 (Macro Substitution):**  虽然代码中没有显式地执行宏替换的动作，但其解析过程为后续的宏替换提供了基础。通过理解宏定义，它可以为后续的工具提供宏的信息。

5. **表达式求值 (Expression Evaluation):** `CppExpr` 类可以对解析得到的表达式进行求值，特别是用于确定条件编译指令的真假。

**与 Android 功能的关系举例：**

在 Android Bionic 库的构建过程中，大量的 C 和 C++ 代码使用了预处理器指令来进行条件编译，以适应不同的架构、平台特性和编译选项。

* **架构特定代码:** 例如，某些代码可能只在 ARM 架构下编译，而在 x86 架构下不编译。这可以通过 `#ifdef __arm__` 或 `#ifndef __i386__` 等指令实现。`cpp.py` 能够解析这些指令，并辅助构建系统决定包含哪些代码。
* **系统调用:** Bionic 库中与内核交互的部分，例如系统调用，可能会根据 Android 内核版本的不同而有所差异。预处理器指令可以用来选择合适的系统调用号或结构体定义。`cpp.py` 帮助理解这些选择逻辑。
* **功能开关:** 某些功能可能通过宏定义来启用或禁用。`cpp.py` 可以解析这些宏定义和相关的条件编译指令。

**例子：**

假设在 Bionic 的某个头文件中，有以下代码片段：

```c
#ifdef __LP64__
typedef unsigned long size_t;
#else
typedef unsigned int size_t;
#endif
```

当构建 64 位 Android 系统时，会定义 `__LP64__` 宏。`cpp.py` 解析这段代码时，会识别出 `__LP64__` 已定义，从而选择 `typedef unsigned long size_t;` 这行代码。在构建 32 位系统时，`__LP64__` 未定义，会选择 `typedef unsigned int size_t;`。

**总结:**

`bionic/libc/kernel/tools/cpp.py` 是一个用于理解 C/C++ 预处理逻辑的工具。它在 Android Bionic 库的构建过程中扮演着重要的角色，帮助构建系统正确地处理条件编译指令，从而生成适应特定平台和配置的代码。它本身不执行编译或链接，而是为这些步骤提供必要的预处理信息。

请注意，这个脚本的主要作用是 *解析* 和 *理解* 预处理指令，而不是像 `gcc` 或 `clang` 的预处理器那样直接执行宏替换和条件编译。它更像是一个分析工具，用于理解代码中的预处理逻辑。

### 提示词
```
这是目录为bionic/libc/kernel/tools/cpp.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
#!/usr/bin/env python3
"""A glorified C pre-processor parser."""

import ctypes
import logging
import os
import re
import site
import unittest
import utils

top = os.getenv('ANDROID_BUILD_TOP')
if top is None:
    utils.panic('ANDROID_BUILD_TOP not set.\n')

# Set up the env vars for libclang.
site.addsitedir(os.path.join(top, 'prebuilts/clang/host/linux-x86/clang-stable/lib/python3/site-packages/'))

import clang.cindex
from clang.cindex import conf
from clang.cindex import Cursor
from clang.cindex import CursorKind
from clang.cindex import SourceLocation
from clang.cindex import SourceRange
from clang.cindex import TokenGroup
from clang.cindex import TokenKind
from clang.cindex import TranslationUnit

# Set up LD_LIBRARY_PATH to include libclang.so, libLLVM.so, and etc.
# Note that setting LD_LIBRARY_PATH with os.putenv() sometimes doesn't help.
clang.cindex.Config.set_library_file(os.path.join(top, 'prebuilts/clang/host/linux-x86/clang-stable/lib/libclang.so'))

from defaults import *


debugBlockParser = False
debugCppExpr = False
debugOptimIf01 = False

###############################################################################
###############################################################################
#####                                                                     #####
#####           C P P   T O K E N S                                       #####
#####                                                                     #####
###############################################################################
###############################################################################

# the list of supported C-preprocessor tokens
# plus a couple of C tokens as well
tokEOF = "\0"
tokLN = "\n"
tokSTRINGIFY = "#"
tokCONCAT = "##"
tokLOGICAND = "&&"
tokLOGICOR = "||"
tokSHL = "<<"
tokSHR = ">>"
tokEQUAL = "=="
tokNEQUAL = "!="
tokLT = "<"
tokLTE = "<="
tokGT = ">"
tokGTE = ">="
tokELLIPSIS = "..."
tokSPACE = " "
tokDEFINED = "defined"
tokLPAREN = "("
tokRPAREN = ")"
tokNOT = "!"
tokPLUS = "+"
tokMINUS = "-"
tokMULTIPLY = "*"
tokDIVIDE = "/"
tokMODULUS = "%"
tokBINAND = "&"
tokBINOR = "|"
tokBINXOR = "^"
tokCOMMA = ","
tokLBRACE = "{"
tokRBRACE = "}"
tokARROW = "->"
tokINCREMENT = "++"
tokDECREMENT = "--"
tokNUMBER = "<number>"
tokIDENT = "<ident>"
tokSTRING = "<string>"


class Token(clang.cindex.Token):
    """A class that represents one token after parsing.

    It inherits the class in libclang, with an extra id property to hold the
    new spelling of the token. The spelling property in the base class is
    defined as read-only. New names after macro instantiation are saved in
    their ids now. It also facilitates the renaming of directive optimizations
    like replacing 'ifndef X' with 'if !defined(X)'.

    It also overrides the cursor property of the base class. Because the one
    in libclang always queries based on a single token, which usually doesn't
    hold useful information. The cursor in this class can be set by calling
    CppTokenizer.getTokensWithCursors(). Otherwise it returns the one in the
    base class.
    """

    def __init__(self, tu=None, group=None, int_data=None, ptr_data=None,
                 cursor=None):
        clang.cindex.Token.__init__(self)
        self._id = None
        self._tu = tu
        self._group = group
        self._cursor = cursor
        # self.int_data and self.ptr_data are from the base class. But
        # self.int_data doesn't accept a None value.
        if int_data is not None:
            self.int_data = int_data
        self.ptr_data = ptr_data

    @property
    def id(self):
        """Name of the token."""
        if self._id is None:
            return self.spelling
        else:
            return self._id

    @id.setter
    def id(self, new_id):
        """Setting name of the token."""
        self._id = new_id

    @property
    def cursor(self):
        if self._cursor is None:
            self._cursor = clang.cindex.Token.cursor
        return self._cursor

    @cursor.setter
    def cursor(self, new_cursor):
        self._cursor = new_cursor

    def __repr__(self):
        if self.id == 'defined':
            return self.id
        elif self.kind == TokenKind.IDENTIFIER:
            return "(ident %s)" % self.id

        return self.id

    def __str__(self):
        return self.id


class BadExpectedToken(Exception):
    """An exception that will be raised for unexpected tokens."""
    pass


class UnparseableStruct(Exception):
    """An exception that will be raised for structs that cannot be parsed."""
    pass


# The __contains__ function in libclang SourceRange class contains a bug. It
# gives wrong result when dealing with single line range.
# Bug filed with upstream:
# http://llvm.org/bugs/show_bug.cgi?id=22243, http://reviews.llvm.org/D7277
def SourceRange__contains__(self, other):
    """Determine if a given location is inside the range."""
    if not isinstance(other, SourceLocation):
        return False
    if other.file is None and self.start.file is None:
        pass
    elif (self.start.file.name != other.file.name or
          other.file.name != self.end.file.name):
        # same file name
        return False
    # same file, in between lines
    if self.start.line < other.line < self.end.line:
        return True
    # same file, same line
    elif self.start.line == other.line == self.end.line:
        if self.start.column <= other.column <= self.end.column:
            return True
    elif self.start.line == other.line:
        # same file first line
        if self.start.column <= other.column:
            return True
    elif other.line == self.end.line:
        # same file last line
        if other.column <= self.end.column:
            return True
    return False


SourceRange.__contains__ = SourceRange__contains__


################################################################################
################################################################################
#####                                                                      #####
#####           C P P   T O K E N I Z E R                                  #####
#####                                                                      #####
################################################################################
################################################################################


class CppTokenizer(object):
    """A tokenizer that converts some input text into a list of tokens.

    It calls libclang's tokenizer to get the parsed tokens. In addition, it
    updates the cursor property in each token after parsing, by calling
    getTokensWithCursors().
    """

    clang_flags = ['-E', '-x', 'c']
    options = TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

    def __init__(self):
        """Initialize a new CppTokenizer object."""
        self._indexer = clang.cindex.Index.create()
        self._tu = None
        self._index = 0
        self.tokens = None

    def _getTokensWithCursors(self):
        """Helper method to return all tokens with their cursors.

        The cursor property in a clang Token doesn't provide enough
        information. Because it is queried based on single token each time
        without any context, i.e. via calling conf.lib.clang_annotateTokens()
        with only one token given. So we often see 'INVALID_FILE' in one
        token's cursor. In this function it passes all the available tokens
        to get more informative cursors.
        """

        tokens_memory = ctypes.POINTER(clang.cindex.Token)()
        tokens_count = ctypes.c_uint()

        conf.lib.clang_tokenize(self._tu, self._tu.cursor.extent,
                                ctypes.byref(tokens_memory),
                                ctypes.byref(tokens_count))

        count = int(tokens_count.value)

        # If we get no tokens, no memory was allocated. Be sure not to return
        # anything and potentially call a destructor on nothing.
        if count < 1:
            return

        cursors = (Cursor * count)()
        cursors_memory = ctypes.cast(cursors, ctypes.POINTER(Cursor))

        conf.lib.clang_annotateTokens(self._tu, tokens_memory, count,
                                      cursors_memory)

        tokens_array = ctypes.cast(
            tokens_memory,
            ctypes.POINTER(clang.cindex.Token * count)).contents
        token_group = TokenGroup(self._tu, tokens_memory, tokens_count)

        tokens = []
        for i in range(0, count):
            token = Token(self._tu, token_group,
                          int_data=tokens_array[i].int_data,
                          ptr_data=tokens_array[i].ptr_data,
                          cursor=cursors[i])
            # We only want non-comment tokens.
            if token.kind != TokenKind.COMMENT:
                tokens.append(token)

        return tokens

    def parseString(self, lines):
        """Parse a list of text lines into a BlockList object."""
        file_ = 'no-filename-available.c'
        self._tu = self._indexer.parse(file_, self.clang_flags,
                                       unsaved_files=[(file_, lines)],
                                       options=self.options)
        self.tokens = self._getTokensWithCursors()

    def parseFile(self, file_):
        """Parse a file into a BlockList object."""
        self._tu = self._indexer.parse(file_, self.clang_flags,
                                       options=self.options)
        self.tokens = self._getTokensWithCursors()

    def nextToken(self):
        """Return next token from the list."""
        if self._index < len(self.tokens):
            t = self.tokens[self._index]
            self._index += 1
            return t
        else:
            return None


class CppStringTokenizer(CppTokenizer):
    """A CppTokenizer derived class that accepts a string of text as input."""

    def __init__(self, line):
        CppTokenizer.__init__(self)
        self.parseString(line)


class CppFileTokenizer(CppTokenizer):
    """A CppTokenizer derived class that accepts a file as input."""

    def __init__(self, file_):
        CppTokenizer.__init__(self)
        self.parseFile(file_)


# Unit testing
#
class CppTokenizerTests(unittest.TestCase):
    """CppTokenizer tests."""

    def get_tokens(self, token_string, line_col=False):
        tokens = CppStringTokenizer(token_string)
        token_list = []
        while True:
            token = tokens.nextToken()
            if not token:
                break
            if line_col:
                token_list.append((token.id, token.location.line,
                                   token.location.column))
            else:
                token_list.append(token.id)
        return token_list

    def test_hash(self):
        self.assertEqual(self.get_tokens("#an/example  && (01923_xy)"),
                         ["#", "an", "/", "example", tokLOGICAND, tokLPAREN,
                          "01923_xy", tokRPAREN])

    def test_parens(self):
        self.assertEqual(self.get_tokens("FOO(BAR) && defined(BAZ)"),
                         ["FOO", tokLPAREN, "BAR", tokRPAREN, tokLOGICAND,
                          "defined", tokLPAREN, "BAZ", tokRPAREN])

    def test_comment(self):
        self.assertEqual(self.get_tokens("/*\n#\n*/"), [])

    def test_line_cross(self):
        self.assertEqual(self.get_tokens("first\nsecond"), ["first", "second"])

    def test_line_cross_line_col(self):
        self.assertEqual(self.get_tokens("first second\n  third", True),
                         [("first", 1, 1), ("second", 1, 7), ("third", 2, 3)])

    def test_comment_line_col(self):
        self.assertEqual(self.get_tokens("boo /* what the\nhell */", True),
                         [("boo", 1, 1)])

    def test_escapes(self):
        self.assertEqual(self.get_tokens("an \\\n example", True),
                         [("an", 1, 1), ("example", 2, 2)])


################################################################################
################################################################################
#####                                                                      #####
#####           C P P   E X P R E S S I O N S                              #####
#####                                                                      #####
################################################################################
################################################################################


class CppExpr(object):
    """A class that models the condition of #if directives into an expr tree.

    Each node in the tree is of the form (op, arg) or (op, arg1, arg2) where
    "op" is a string describing the operation
    """

    unaries = ["!", "~"]
    binaries = ["+", "-", "<", "<=", ">=", ">", "&&", "||", "*", "/", "%",
                "&", "|", "^", "<<", ">>", "==", "!=", "?", ":"]
    precedences = {
        "?": 1, ":": 1,
        "||": 2,
        "&&": 3,
        "|": 4,
        "^": 5,
        "&": 6,
        "==": 7, "!=": 7,
        "<": 8, "<=": 8, ">": 8, ">=": 8,
        "<<": 9, ">>": 9,
        "+": 10, "-": 10,
        "*": 11, "/": 11, "%": 11,
        "!": 12, "~": 12
    }

    def __init__(self, tokens):
        """Initialize a CppExpr. 'tokens' must be a CppToken list."""
        self.tokens = tokens
        self._num_tokens = len(tokens)
        self._index = 0

        if debugCppExpr:
            print("CppExpr: trying to parse %s" % repr(tokens))
        self.expr = self.parseExpression(0)
        if debugCppExpr:
            print("CppExpr: got " + repr(self.expr))
        if self._index != self._num_tokens:
            self.throw(BadExpectedToken, "crap at end of input (%d != %d): %s"
                       % (self._index, self._num_tokens, repr(tokens)))

    def throw(self, exception, msg):
        if self._index < self._num_tokens:
            tok = self.tokens[self._index]
            print("%d:%d: %s" % (tok.location.line, tok.location.column, msg))
        else:
            print("EOF: %s" % msg)
        raise exception(msg)

    def expectId(self, id):
        """Check that a given token id is at the current position."""
        token = self.tokens[self._index]
        if self._index >= self._num_tokens or token.id != id:
            self.throw(BadExpectedToken,
                       "### expecting '%s' in expression, got '%s'" % (
                           id, token.id))
        self._index += 1

    def is_decimal(self):
        token = self.tokens[self._index].id
        if token[-1] in "ULul":
            token = token[:-1]
        try:
            val = int(token, 10)
            self._index += 1
            return ('int', val)
        except ValueError:
            return None

    def is_octal(self):
        token = self.tokens[self._index].id
        if token[-1] in "ULul":
            token = token[:-1]
        if len(token) < 2 or token[0] != '0':
            return None
        try:
            val = int(token, 8)
            self._index += 1
            return ('oct', val)
        except ValueError:
            return None

    def is_hexadecimal(self):
        token = self.tokens[self._index].id
        if token[-1] in "ULul":
            token = token[:-1]
        if len(token) < 3 or (token[:2] != '0x' and token[:2] != '0X'):
            return None
        try:
            val = int(token, 16)
            self._index += 1
            return ('hex', val)
        except ValueError:
            return None

    def is_integer(self):
        if self.tokens[self._index].kind != TokenKind.LITERAL:
            return None

        c = self.is_hexadecimal()
        if c:
            return c

        c = self.is_octal()
        if c:
            return c

        c = self.is_decimal()
        if c:
            return c

        return None

    def is_number(self):
        t = self.tokens[self._index]
        if t.id == tokMINUS and self._index + 1 < self._num_tokens:
            self._index += 1
            c = self.is_integer()
            if c:
                op, val = c
                return (op, -val)
        if t.id == tokPLUS and self._index + 1 < self._num_tokens:
            self._index += 1
            c = self.is_integer()
            if c:
                return c

        return self.is_integer()

    def is_defined(self):
        t = self.tokens[self._index]
        if t.id != tokDEFINED:
            return None

        # We have the defined keyword, check the rest.
        self._index += 1
        used_parens = False
        if (self._index < self._num_tokens and
            self.tokens[self._index].id == tokLPAREN):
            used_parens = True
            self._index += 1

        if self._index >= self._num_tokens:
            self.throw(BadExpectedToken,
                       "### 'defined' must be followed by macro name or left "
                       "paren")

        t = self.tokens[self._index]
        if t.kind != TokenKind.IDENTIFIER:
            self.throw(BadExpectedToken,
                       "### 'defined' must be followed by macro name")

        self._index += 1
        if used_parens:
            self.expectId(tokRPAREN)

        return ("defined", t.id)

    def is_call_or_ident(self):
        if self._index >= self._num_tokens:
            return None

        t = self.tokens[self._index]
        if t.kind != TokenKind.IDENTIFIER:
            return None

        name = t.id

        self._index += 1
        if (self._index >= self._num_tokens or
            self.tokens[self._index].id != tokLPAREN):
            return ("ident", name)

        params = []
        depth = 1
        self._index += 1
        j = self._index
        while self._index < self._num_tokens:
            id = self.tokens[self._index].id
            if id == tokLPAREN:
                depth += 1
            elif depth == 1 and (id == tokCOMMA or id == tokRPAREN):
                k = self._index
                param = self.tokens[j:k]
                params.append(param)
                if id == tokRPAREN:
                    break
                j = self._index + 1
            elif id == tokRPAREN:
                depth -= 1
            self._index += 1

        if self._index >= self._num_tokens:
            return None

        self._index += 1
        return ("call", (name, params))

    # Implements the "precedence climbing" algorithm from
    # http://www.engr.mun.ca/~theo/Misc/exp_parsing.htm.
    # The "classic" algorithm would be fine if we were using a tool to
    # generate the parser, but we're not. Dijkstra's "shunting yard"
    # algorithm hasn't been necessary yet.

    def parseExpression(self, minPrecedence):
        if self._index >= self._num_tokens:
            return None

        node = self.parsePrimary()
        while (self.token() and self.isBinary(self.token()) and
               self.precedence(self.token()) >= minPrecedence):
            op = self.token()
            self.nextToken()
            rhs = self.parseExpression(self.precedence(op) + 1)
            node = (op.id, node, rhs)

        return node

    def parsePrimary(self):
        op = self.token()
        if self.isUnary(op):
            self.nextToken()
            return (op.id, self.parseExpression(self.precedence(op)))

        primary = None
        if op.id == tokLPAREN:
            self.nextToken()
            primary = self.parseExpression(0)
            self.expectId(tokRPAREN)
        elif op.id == "?":
            self.nextToken()
            primary = self.parseExpression(0)
            self.expectId(":")
        elif op.id == '+' or op.id == '-' or op.kind == TokenKind.LITERAL:
            primary = self.is_number()
        # Checking for 'defined' needs to come first now because 'defined' is
        # recognized as IDENTIFIER.
        elif op.id == tokDEFINED:
            primary = self.is_defined()
        elif op.kind == TokenKind.IDENTIFIER:
            primary = self.is_call_or_ident()
        else:
            self.throw(BadExpectedToken,
                       "didn't expect to see a %s in factor" % (
                           self.tokens[self._index].id))
        return primary

    def isBinary(self, token):
        return token.id in self.binaries

    def isUnary(self, token):
        return token.id in self.unaries

    def precedence(self, token):
        return self.precedences.get(token.id)

    def token(self):
        if self._index >= self._num_tokens:
            return None
        return self.tokens[self._index]

    def nextToken(self):
        self._index += 1
        if self._index >= self._num_tokens:
            return None
        return self.tokens[self._index]

    def dump_node(self, e):
        op = e[0]
        line = "(" + op
        if op == "int":
            line += " %d)" % e[1]
        elif op == "oct":
            line += " 0%o)" % e[1]
        elif op == "hex":
            line += " 0x%x)" % e[1]
        elif op == "ident":
            line += " %s)" % e[1]
        elif op == "defined":
            line += " %s)" % e[1]
        elif op == "call":
            arg = e[1]
            line += " %s [" % arg[0]
            prefix = ""
            for param in arg[1]:
                par = ""
                for tok in param:
                    par += str(tok)
                line += "%s%s" % (prefix, par)
                prefix = ","
            line += "])"
        elif op in CppExpr.unaries:
            line += " %s)" % self.dump_node(e[1])
        elif op in CppExpr.binaries:
            line += " %s %s)" % (self.dump_node(e[1]), self.dump_node(e[2]))
        else:
            line += " ?%s)" % repr(e[1])

        return line

    def __repr__(self):
        return self.dump_node(self.expr)

    def source_node(self, e):
        op = e[0]
        if op == "int":
            return "%d" % e[1]
        if op == "hex":
            return "0x%x" % e[1]
        if op == "oct":
            return "0%o" % e[1]
        if op == "ident":
            # XXX: should try to expand
            return e[1]
        if op == "defined":
            return "defined(%s)" % e[1]

        prec = CppExpr.precedences.get(op, 1000)
        arg = e[1]
        if op in CppExpr.unaries:
            arg_src = self.source_node(arg)
            arg_op = arg[0]
            arg_prec = CppExpr.precedences.get(arg_op, 1000)
            if arg_prec < prec:
                return "!(" + arg_src + ")"
            else:
                return "!" + arg_src
        if op in CppExpr.binaries:
            arg2 = e[2]
            arg1_op = arg[0]
            arg2_op = arg2[0]
            arg1_src = self.source_node(arg)
            arg2_src = self.source_node(arg2)
            if CppExpr.precedences.get(arg1_op, 1000) < prec:
                arg1_src = "(%s)" % arg1_src
            if CppExpr.precedences.get(arg2_op, 1000) < prec:
                arg2_src = "(%s)" % arg2_src

            return "%s %s %s" % (arg1_src, op, arg2_src)
        return "???"

    def __str__(self):
        return self.source_node(self.expr)

    @staticmethod
    def int_node(e):
        if e[0] in ["int", "oct", "hex"]:
            return e[1]
        else:
            return None

    def toInt(self):
        return self.int_node(self.expr)

    def optimize_node(self, e, macros=None):
        if macros is None:
            macros = {}
        op = e[0]

        if op == "defined":
            op, name = e
            if name in macros:
                if macros[name] == kCppUndefinedMacro:
                    return ("int", 0)
                else:
                    try:
                        value = int(macros[name])
                        return ("int", value)
                    except ValueError:
                        return ("defined", macros[name])

            if kernel_remove_config_macros and name.startswith("CONFIG_"):
                return ("int", 0)

            return e

        elif op == "ident":
            op, name = e
            if name in macros:
                try:
                    value = int(macros[name])
                    expanded = ("int", value)
                except ValueError:
                    expanded = ("ident", macros[name])
                return self.optimize_node(expanded, macros)
            return e

        elif op == "!":
            op, v = e
            v = self.optimize_node(v, macros)
            if v[0] == "int":
                if v[1] == 0:
                    return ("int", 1)
                else:
                    return ("int", 0)
            return ('!', v)

        elif op == "&&":
            op, l, r = e
            l = self.optimize_node(l, macros)
            r = self.optimize_node(r, macros)
            li = self.int_node(l)
            ri = self.int_node(r)
            if li is not None:
                if li == 0:
                    return ("int", 0)
                else:
                    return r
            elif ri is not None:
                if ri == 0:
                    return ("int", 0)
                else:
                    return l
            return (op, l, r)

        elif op == "||":
            op, l, r = e
            l = self.optimize_node(l, macros)
            r = self.optimize_node(r, macros)
            li = self.int_node(l)
            ri = self.int_node(r)
            if li is not None:
                if li == 0:
                    return r
                else:
                    return ("int", 1)
            elif ri is not None:
                if ri == 0:
                    return l
                else:
                    return ("int", 1)
            return (op, l, r)

        else:
            return e

    def optimize(self, macros=None):
        if macros is None:
            macros = {}
        self.expr = self.optimize_node(self.expr, macros)

class CppExprTest(unittest.TestCase):
    """CppExpr unit tests."""

    def get_expr(self, expr):
        return repr(CppExpr(CppStringTokenizer(expr).tokens))

    def test_cpp_expr(self):
        self.assertEqual(self.get_expr("0"), "(int 0)")
        self.assertEqual(self.get_expr("1"), "(int 1)")
        self.assertEqual(self.get_expr("-5"), "(int -5)")
        self.assertEqual(self.get_expr("+1"), "(int 1)")
        self.assertEqual(self.get_expr("0U"), "(int 0)")
        self.assertEqual(self.get_expr("015"), "(oct 015)")
        self.assertEqual(self.get_expr("015l"), "(oct 015)")
        self.assertEqual(self.get_expr("0x3e"), "(hex 0x3e)")
        self.assertEqual(self.get_expr("(0)"), "(int 0)")
        self.assertEqual(self.get_expr("1 && 1"), "(&& (int 1) (int 1))")
        self.assertEqual(self.get_expr("1 && 0"), "(&& (int 1) (int 0))")
        self.assertEqual(self.get_expr("EXAMPLE"), "(ident EXAMPLE)")
        self.assertEqual(self.get_expr("EXAMPLE - 3"),
                         "(- (ident EXAMPLE) (int 3))")
        self.assertEqual(self.get_expr("defined(EXAMPLE)"),
                         "(defined EXAMPLE)")
        self.assertEqual(self.get_expr("defined ( EXAMPLE ) "),
                         "(defined EXAMPLE)")
        self.assertEqual(self.get_expr("!defined(EXAMPLE)"),
                         "(! (defined EXAMPLE))")
        self.assertEqual(self.get_expr("defined(ABC) || defined(BINGO)"),
                         "(|| (defined ABC) (defined BINGO))")
        self.assertEqual(self.get_expr("FOO(BAR,5)"), "(call FOO [BAR,5])")
        self.assertEqual(self.get_expr("A == 1 || defined(B)"),
                         "(|| (== (ident A) (int 1)) (defined B))")

    def get_expr_optimize(self, expr, macros=None):
        if macros is None:
            macros = {}
        e = CppExpr(CppStringTokenizer(expr).tokens)
        e.optimize(macros)
        return repr(e)

    def test_cpp_expr_optimize(self):
        self.assertEqual(self.get_expr_optimize("0"), "(int 0)")
        self.assertEqual(self.get_expr_optimize("1"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("1 && 1"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("1 && +1"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("0x1 && 01"), "(oct 01)")
        self.assertEqual(self.get_expr_optimize("1 && 0"), "(int 0)")
        self.assertEqual(self.get_expr_optimize("0 && 1"), "(int 0)")
        self.assertEqual(self.get_expr_optimize("0 && 0"), "(int 0)")
        self.assertEqual(self.get_expr_optimize("1 || 1"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("1 || 0"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("0 || 1"), "(int 1)")
        self.assertEqual(self.get_expr_optimize("0 || 0"), "(int 0)")
        self.assertEqual(self.get_expr_optimize("A"), "(ident A)")
        self.assertEqual(self.get_expr_optimize("A", {"A": 1}), "(int 1)")
        self.assertEqual(self.get_expr_optimize("A || B", {"A": 1}), "(int 1)")
        self.assertEqual(self.get_expr_optimize("A || B", {"B": 1}), "(int 1)")
        self.assertEqual(self.get_expr_optimize("A && B", {"A": 1}), "(ident B)")
        self.assertEqual(self.get_expr_optimize("A && B", {"B": 1}), "(ident A)")
        self.assertEqual(self.get_expr_optimize("A && B"), "(&& (ident A) (ident B))")
        self.assertEqual(self.get_expr_optimize("EXAMPLE"), "(ident EXAMPLE)")
        self.assertEqual(self.get_expr_optimize("EXAMPLE - 3"), "(- (ident EXAMPLE) (int 3))")
        self.assertEqual(self.get_expr_optimize("defined(EXAMPLE)"), "(defined EXAMPLE)")
        self.assertEqual(self.get_expr_optimize("defined(EXAMPLE)",
                                                {"EXAMPLE": "XOWOE"}),
                         "(defined XOWOE)")
        self.assertEqual(self.get_expr_optimize("defined(EXAMPLE)",
                                                {"EXAMPLE": kCppUndefinedMacro}),
                         "(int 0)")
        self.assertEqual(self.get_expr_optimize("!defined(EXAMPLE)"), "(! (defined EXAMPLE))")
        self.assertEqual(self.get_expr_optimize("!defined(EXAMPLE)",
                                                {"EXAMPLE": "XOWOE"}),
                         "(! (defined XOWOE))")
        self.assertEqual(self.get_expr_optimize("!defined(EXAMPLE)",
                                                {"EXAMPLE": kCppUndefinedMacro}),
                         "(int 1)")
        self.assertEqual(self.get_expr_optimize("defined(A) || defined(B)"),
                        "(|| (defined A) (defined B))")
        self.assertEqual(self.get_expr_optimize("defined(A) || defined(B)",
                                                {"A": "1"}),
                         "(int 1)")
        self.assertEqual(self.get_expr_optimize("defined(A) || defined(B)",
                                                {"B": "1"}),
                         "(int 1)")
        self.assertEqual(self.get_expr_optimize("defined(A) || defined(B)",
                                                {"B": kCppUndefinedMacro}),
                         "(defined A)")
        self.assertEqual(self.get_expr_optimize("defined(A) || defined(B)",
                                                {"A": kCppUndefinedMacro,
                                                 "B": kCppUndefinedMacro}),
                         "(int 0)")
        self.assertEqual(self.get_expr_optimize("defined(A) && defined(B)"),
                         "(&& (defined A) (defined B))")
        self.assertEqual(self.get_expr_optimize("defined(A) && defined(B)",
                                                {"A": "1"}),
                         "(defined B)")
        self.assertEqual(self.get_expr_optimize("defined(A) && defined(B)",
                                                {"B": "1"}),
                         "(defined A)")
        self.assertEqual(self.get_expr_optimize("defined(A) && defined(B)",
                                                {"B": kCppUndefinedMacro}),
                        "(int 0)")
        self.assertEqual(self.get_expr_optimize("defined(A) && defined(B)",
                                                {"A": kCppUndefinedMacro}),
                        "(int 0)")
        self.assertEqual(self.get_expr_optimize("A == 1 || defined(B)"),
                         "(|| (== (ident A) (int 1)) (defined B))")
        self.assertEqual(self.get_expr_optimize(
              "defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)",
              {"__KERNEL__": kCppUndefinedMacro}),
              "(|| (! (defined __GLIBC__)) (< (ident __GLIBC__) (int 2)))")

    def get_expr_string(self, expr):
        return str(CppExpr(CppStringTokenizer(expr).tokens))

    def test_cpp_expr_string(self):
        self.assertEqual(self.get_expr_string("0"), "0")
        self.assertE
```