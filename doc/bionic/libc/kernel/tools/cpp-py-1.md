Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The user wants a summary of the functionality of the provided Python code (`cpp.py`), which is part of Android's Bionic library build system. They also want to know its relationship to Android, explanations of key functions, details on dynamic linking aspects, common errors, and how Android Framework/NDK uses it. The request specifically asks for a *summary* of its functionality in *this part* (part 2 of 3).

2. **Identify the Key Components in the Provided Code:**  The code defines several classes:
    * `Block`: Represents a block of code (either preprocessor directive or regular code).
    * `BlockList`:  A container for a list of `Block` objects, providing methods for manipulating them.
    * `BlockParser`:  Parses raw C/C++ code (represented by tokens) into a `BlockList`.
    * Helper functions: `strip_space`, `find_matching_endif`, `optimize_if01`.

3. **Focus on "归纳一下它的功能" (Summarize its functionality):** This is the core of the current request (part 2). I need to extract the overarching purpose and key actions performed by this code.

4. **Analyze `Block`:**
    *  It stores tokens and indicates if it's a directive (like `#if`, `#define`).
    *  It handles `#ifdef`/`#ifndef` conversion.
    *  It has methods to check if it's a specific directive type (`isIf`, `isDefine`, `isInclude`, etc.).
    *  The `write` method is important for outputting the block's content.
    *  `format_blocks` is for formatting regular code blocks.

5. **Analyze `BlockList`:**
    * It holds a list of `Block` objects.
    * Crucially, it has methods for *optimizing* the code represented by the blocks:
        * `optimizeIf01`: Removes code within `#if 0` blocks.
        * `optimizeMacros`:  Simplifies conditional expressions based on defined macros.
        * `removeStructs`:  Removes struct definitions (and adds includes).
        * `removeVarsAndFuncs`: Removes variable and function declarations.
        * `replaceTokens`:  Performs token replacements.
    * It also has methods for finding includes (`findIncludes`) and writing the blocks to output (`write`).

6. **Analyze `BlockParser`:**
    * It takes a `Tokenizer` (not shown in this snippet but implied) as input.
    * Its main purpose is to parse the token stream and group them into `Block` objects, creating a `BlockList`.
    * It distinguishes between preprocessor directives, variable declarations, function declarations, and regular code.

7. **Identify the Core Functionality:** Based on the analysis, the core functionality is:
    * **Parsing:** Taking C/C++ code as input and breaking it down into meaningful blocks (`BlockParser`).
    * **Representation:**  Representing these code blocks with the `Block` class.
    * **Organization:**  Organizing the blocks into a list (`BlockList`).
    * **Optimization/Manipulation:**  Performing transformations on the code blocks, primarily related to preprocessor directives and removing unwanted declarations (`BlockList` methods).
    * **Output:**  Writing the processed code blocks (`Block` and `BlockList` `write` methods).

8. **Formulate the Summary (in Chinese):** Now, I need to express these functionalities concisely in Chinese, directly addressing the request for a summary of *this part* of the code. I'll focus on the classes and their primary roles.

9. **Review and Refine:**  Read through the summary to ensure it accurately reflects the code's purpose and the functionality of the key classes. Make sure it's in clear, understandable Chinese. In this case, I'd emphasize the *processing* of code blocks and the optimization aspects.

By following this structured approach, I can break down the code, identify the key functionalities, and generate a relevant and accurate summary in Chinese as requested. The focus on the classes and their methods helps to provide a clear and organized overview.
## `bionic/libc/kernel/tools/cpp.py` 源代码功能归纳 (第 2 部分)

这是对 `bionic/libc/kernel/tools/cpp.py` 源代码文件第二部分的分析和功能归纳。基于提供的代码片段，主要功能集中在 **对 C/C++ 代码进行块状解析和处理**，特别是针对预处理器指令和代码结构的管理和优化。

**核心功能归纳:**

1. **代码块的抽象表示 (`Block` 类):**
   -  `Block` 类是代码的基本单元，可以表示预处理器指令（如 `#if`, `#define`, `#include`）或者普通的 C/C++ 代码段。
   -  它可以存储一系列的 `Token` 对象，以及指示该块是否为指令的 `directive` 属性。
   -  它能识别并处理 `#ifdef` 和 `#ifndef` 指令，将其转换为 `#if defined(...)` 的形式。
   -  它提供了判断块类型的便捷方法，例如 `isDirective()`, `isConditional()`, `isDefine()`, `isIf()`, `isEndif()`, `isInclude()`。
   -  针对普通代码块，提供了 `format_blocks()` 方法进行代码格式化（添加缩进、处理换行等）。
   -  `write()` 方法用于将代码块输出到指定的文件流。

2. **代码块列表的管理 (`BlockList` 类):**
   -  `BlockList` 类用于存储和管理一系列的 `Block` 对象，代表整个源代码文件或其一部分。
   -  它提供了对 `Block` 对象的访问和遍历功能。
   -  **关键功能在于对代码块列表进行优化和修改：**
     -  `optimizeIf01()`:  移除 `#if 0` 到 `#endif` 之间的代码块。
     -  `optimizeMacros()`:  根据已知的宏定义，优化条件表达式。
     -  `removeStructs()`:  移除指定的结构体定义，并可以添加相应的头文件包含。
     -  `removeVarsAndFuncs()`:  移除变量和函数声明，保留类型定义（typedef, enum, struct, union）。
     -  `replaceTokens()`:  根据提供的字典替换代码块中的 token。
   -  `findIncludes()` 方法用于提取代码块列表中包含的头文件。

3. **代码块的解析 (`BlockParser` 类):**
   -  `BlockParser` 类负责将输入的 token 流（由 `Tokenizer` 提供，未在本次代码片段中展示）解析成 `Block` 对象的列表 (`BlockList`)。
   -  它能识别预处理器指令，并将其中的 token 提取出来，创建 `Block` 对象。
   -  它能识别变量声明、函数声明等代码结构，并将相应的 token 组织成 `Block` 对象。
   -  通过 `getBlocks()` 或 `parse()` 方法实现解析过程。

4. **辅助功能:**
   -  `strip_space()` 函数用于去除字符串中多余的空格，并对函数调用时的空格进行处理。
   -  `find_matching_endif()` 函数用于查找与 `#if` 等条件编译指令匹配的 `#endif` 指令。
   -  `optimize_if01()` 函数的具体实现，用于移除 `#if 0` 块。

**与 Android 功能的关系举例说明:**

`cpp.py` 是 Android Bionic 库构建系统的一部分，用于处理 C/C++ 源代码。其功能与 Android 的编译过程紧密相关，特别是在处理 libc, libm 等底层库的头文件时：

- **预处理器指令处理:** Android 的构建系统需要根据不同的目标平台、编译选项等，通过预处理器指令（如 `#if __ANDROID__`, `#ifdef __arm__`）来选择性地编译代码。`Block` 类和 `BlockList` 类能够有效地表示和操作这些指令块。例如，`optimizeIf01()` 可以去除在特定配置下不生效的代码，减少编译产物的大小。
- **结构体移除:**  Android 为了减小库的大小，可能会移除某些不必要的结构体定义。`removeStructs()` 方法可以实现这一功能，例如，在为特定设备构建时，移除一些硬件相关的结构体。这与 Android 的模块化和定制化特性相关。
- **变量和函数声明移除:** `removeVarsAndFuncs()` 用于去除不必要的变量和函数声明，可以减少头文件的体积，加快编译速度，并减少符号冲突的风险。这在构建共享库（.so 文件）时非常重要。
- **头文件包含提取:** `findIncludes()` 可以用于分析代码依赖，生成编译所需的头文件列表。

**详细解释 libc 函数的功能实现 (本代码未涉及):**

提供的代码主要关注预处理和代码结构的管理，并没有直接涉及 libc 函数的具体实现。libc 函数的实现通常在 C 语言源文件中，并由编译器编译成机器码。

**涉及 dynamic linker 的功能 (本代码未涉及):**

此代码片段的功能集中在预处理阶段的代码处理，与动态链接器的直接交互较少。动态链接器的功能通常在加载和链接共享库时发挥作用。

**逻辑推理、假设输入与输出 (部分涉及):**

- **`optimizeIf01()` 的逻辑:**
    - **假设输入:** 一个包含 `#if 0 ... #endif` 块的 `BlockList`。
    - **输出:**  移除了 `#if 0 ... #endif` 及其内部代码块的 `BlockList`。
    - **示例:**
      ```
      #if 1
      int a = 1;
      #else
      int b = 2;
      #endif
      ```
      优化后会保留 `int a = 1;`。

      ```
      #if 0
      int c = 3;
      #endif
      int d = 4;
      ```
      优化后会移除 `#if 0` 到 `#endif` 之间的 `int c = 3;`，保留 `int d = 4;`。

**用户或编程常见的使用错误 (本代码未直接体现):**

此代码是构建系统的一部分，开发者通常不会直接使用。但理解其功能可以帮助开发者理解 Android 构建过程中的一些行为，例如：

- **宏定义的影响:**  条件编译指令的行为依赖于宏定义，如果宏定义不正确，可能会导致意外的代码被包含或排除。
- **头文件依赖:**  不正确的头文件包含可能导致编译错误或链接错误。

**Android Framework or NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤 (超出本代码片段范围):**

要跟踪 Android Framework 或 NDK 如何使用 `cpp.py`，需要深入了解 Android 的构建系统 (如 Soong 或 Make)。大致流程如下：

1. **编译系统启动:**  当构建 Android 系统或 NDK 中的库时，构建系统会解析 `Android.bp` 或 `Android.mk` 文件。
2. **编译任务生成:**  构建系统根据配置文件生成具体的编译任务，包括预处理、编译、链接等步骤。
3. **预处理阶段调用:** 在预处理阶段，构建系统可能会调用 `cpp.py` (或类似的工具) 来处理 C/C++ 源代码。
4. **`BlockParser` 解析:**  `cpp.py` 中的 `BlockParser` 会将源代码解析成 `Block` 对象。
5. **`BlockList` 处理:** `BlockList` 对象会根据配置进行优化，例如移除 `#if 0` 块、移除特定结构体等。
6. **输出预处理结果:**  处理后的代码会作为编译器的输入。

**Frida Hook 示例 (需要结合构建系统上下文):**

由于 `cpp.py` 是 Python 脚本，Frida 可以 hook 其函数。以下是一个假设的示例，用于 hook `BlockParser` 的 `getBlocks` 方法：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

session = frida.attach("python3") # 假设构建过程使用 python3

script = session.create_script("""
console.log("Script loaded");

const BlockParser = Java.use('cpp'); // 假设 cpp.py 被某种方式包装成 Java 对象

BlockParser.getBlocks.implementation = function(tokzer) {
  console.log("BlockParser.getBlocks called with:", tokzer);
  const result = this.getBlocks(tokzer);
  console.log("BlockParser.getBlocks returned:", result);
  return result;
}
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
""")

```

**请注意:** 上述 Frida 示例是高度简化的，实际 hook 过程会更复杂，需要理解构建系统的具体实现和 `cpp.py` 的调用方式。`cpp.py` 通常作为构建系统内部的工具被调用，而不是直接作为一个独立的进程运行，因此 hook 的方式可能需要根据具体情况调整。

**总结：**

提供的代码片段主要实现了 C/C++ 代码的块状解析和处理，为后续的编译过程提供基础。`Block` 和 `BlockList` 类提供了对代码结构的抽象表示和操作能力，能够进行代码优化和修改，例如移除条件编译块、移除结构体和声明等。`BlockParser` 类则负责将原始的 token 流转化为结构化的代码块列表。这些功能是 Android Bionic 库构建过程中的关键环节，用于处理头文件和源代码，以适应不同的构建配置和优化目标。

Prompt: 
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
这是第2部分，共3部分，请归纳一下它的功能

"""
qual(self.get_expr_string("1"), "1")
        self.assertEqual(self.get_expr_string("1 && 1"), "1 && 1")
        self.assertEqual(self.get_expr_string("1 && 0"), "1 && 0")
        self.assertEqual(self.get_expr_string("0 && 1"), "0 && 1")
        self.assertEqual(self.get_expr_string("0 && 0"), "0 && 0")
        self.assertEqual(self.get_expr_string("1 || 1"), "1 || 1")
        self.assertEqual(self.get_expr_string("1 || 0"), "1 || 0")
        self.assertEqual(self.get_expr_string("0 || 1"), "0 || 1")
        self.assertEqual(self.get_expr_string("0 || 0"), "0 || 0")
        self.assertEqual(self.get_expr_string("EXAMPLE"), "EXAMPLE")
        self.assertEqual(self.get_expr_string("EXAMPLE - 3"), "EXAMPLE - 3")
        self.assertEqual(self.get_expr_string("defined(EXAMPLE)"), "defined(EXAMPLE)")
        self.assertEqual(self.get_expr_string("defined EXAMPLE"), "defined(EXAMPLE)")
        self.assertEqual(self.get_expr_string("A == 1 || defined(B)"), "A == 1 || defined(B)")


################################################################################
################################################################################
#####                                                                      #####
#####          C P P   B L O C K                                           #####
#####                                                                      #####
################################################################################
################################################################################


class Block(object):
    """A class used to model a block of input source text.

    There are two block types:
      - directive blocks: contain the tokens of a single pre-processor
        directive (e.g. #if)
      - text blocks, contain the tokens of non-directive blocks

    The cpp parser class below will transform an input source file into a list
    of Block objects (grouped in a BlockList object for convenience)
    """

    def __init__(self, tokens, directive=None, lineno=0, identifier=None):
        """Initialize a new block, if 'directive' is None, it is a text block.

        NOTE: This automatically converts '#ifdef MACRO' into
        '#if defined(MACRO)' and '#ifndef MACRO' into '#if !defined(MACRO)'.
        """

        if directive == "ifdef":
            tok = Token()
            tok.id = tokDEFINED
            tokens = [tok] + tokens
            directive = "if"

        elif directive == "ifndef":
            tok1 = Token()
            tok2 = Token()
            tok1.id = tokNOT
            tok2.id = tokDEFINED
            tokens = [tok1, tok2] + tokens
            directive = "if"

        self.tokens = tokens
        self.directive = directive
        self.define_id = identifier
        if lineno > 0:
            self.lineno = lineno
        else:
            self.lineno = self.tokens[0].location.line

        if self.isIf():
            self.expr = CppExpr(self.tokens)

    def isDirective(self):
        """Return True iff this is a directive block."""
        return self.directive is not None

    def isConditional(self):
        """Return True iff this is a conditional directive block."""
        return self.directive in ["if", "ifdef", "ifndef", "else", "elif",
                                  "endif"]

    def isDefine(self):
        """Return the macro name in a #define directive, or None otherwise."""
        if self.directive != "define":
            return None
        return self.define_id

    def isIf(self):
        """Return True iff this is an #if-like directive block."""
        return self.directive in ["if", "ifdef", "ifndef", "elif"]

    def isEndif(self):
        """Return True iff this is an #endif directive block."""
        return self.directive == "endif"

    def isInclude(self):
        """Check whether this is a #include directive.

        If true, returns the corresponding file name (with brackets or
        double-qoutes). None otherwise.
        """

        if self.directive != "include":
            return None
        return ''.join([str(x) for x in self.tokens])

    @staticmethod
    def format_blocks(tokens, indent=0):
        """Return the formatted lines of strings with proper indentation."""
        newline = True
        result = []
        buf = ''
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t.id == '{':
                buf += ' {'
                result.append(strip_space(buf))
                # Do not indent if this is extern "C" {
                if i < 2 or tokens[i-2].id != 'extern' or tokens[i-1].id != '"C"':
                    indent += 2
                buf = ''
                newline = True
            elif t.id == '}':
                if indent >= 2:
                    indent -= 2
                if not newline:
                    result.append(strip_space(buf))
                # Look ahead to determine if it's the end of line.
                if (i + 1 < len(tokens) and
                    (tokens[i+1].id == ';' or
                     tokens[i+1].id in ['else', '__attribute__',
                                        '__attribute', '__packed'] or
                     tokens[i+1].kind == TokenKind.IDENTIFIER)):
                    buf = ' ' * indent + '}'
                    newline = False
                else:
                    result.append(' ' * indent + '}')
                    buf = ''
                    newline = True
            elif t.id == ';':
                result.append(strip_space(buf) + ';')
                buf = ''
                newline = True
            # We prefer a new line for each constant in enum.
            elif t.id == ',' and t.cursor.kind == CursorKind.ENUM_DECL:
                result.append(strip_space(buf) + ',')
                buf = ''
                newline = True
            else:
                if newline:
                    buf += ' ' * indent + str(t)
                else:
                    buf += ' ' + str(t)
                newline = False
            i += 1

        if buf:
            result.append(strip_space(buf))

        return result, indent

    def write(self, out, indent):
        """Dump the current block."""
        # removeWhiteSpace() will sometimes creates non-directive blocks
        # without any tokens. These come from blocks that only contained
        # empty lines and spaces. They should not be printed in the final
        # output, and then should not be counted for this operation.
        #
        if self.directive is None and not self.tokens:
            return indent

        if self.directive:
            out.write(str(self) + '\n')
        else:
            lines, indent = self.format_blocks(self.tokens, indent)
            for line in lines:
                out.write(line + '\n')

        return indent

    def __repr__(self):
        """Generate the representation of a given block."""
        if self.directive:
            result = "#%s " % self.directive
            if self.isIf():
                result += repr(self.expr)
            else:
                for tok in self.tokens:
                    result += repr(tok)
        else:
            result = ""
            for tok in self.tokens:
                result += repr(tok)

        return result

    def __str__(self):
        """Generate the string representation of a given block."""
        if self.directive:
            # "#if"
            if self.directive == "if":
                # small optimization to re-generate #ifdef and #ifndef
                e = self.expr.expr
                op = e[0]
                if op == "defined":
                    result = "#ifdef %s" % e[1]
                elif op == "!" and e[1][0] == "defined":
                    result = "#ifndef %s" % e[1][1]
                else:
                    result = "#if " + str(self.expr)

            # "#define"
            elif self.isDefine():
                result = "#%s %s" % (self.directive, self.define_id)
                if self.tokens:
                    result += " "
                expr = strip_space(' '.join([tok.id for tok in self.tokens]))
                # remove the space between name and '(' in function call
                result += re.sub(r'(\w+) \(', r'\1(', expr)

            # "#error"
            # Concatenating tokens with a space separator, because they may
            # not be quoted and broken into several tokens
            elif self.directive == "error":
                result = "#error %s" % ' '.join([tok.id for tok in self.tokens])

            else:
                result = "#%s" % self.directive
                if self.tokens:
                    result += " "
                result += ''.join([tok.id for tok in self.tokens])
        else:
            lines, _ = self.format_blocks(self.tokens)
            result = '\n'.join(lines)

        return result


class BlockList(object):
    """A convenience class used to hold and process a list of blocks.

    It calls the cpp parser to get the blocks.
    """

    def __init__(self, blocks):
        self.blocks = blocks

    def __len__(self):
        return len(self.blocks)

    def __getitem__(self, n):
        return self.blocks[n]

    def __repr__(self):
        return repr(self.blocks)

    def __str__(self):
        result = '\n'.join([str(b) for b in self.blocks])
        return result

    def dump(self):
        """Dump all the blocks in current BlockList."""
        print('##### BEGIN #####')
        for i, b in enumerate(self.blocks):
            print('### BLOCK %d ###' % i)
            print(b)
        print('##### END #####')

    def optimizeIf01(self):
        """Remove the code between #if 0 .. #endif in a BlockList."""
        self.blocks = optimize_if01(self.blocks)

    def optimizeMacros(self, macros):
        """Remove known defined and undefined macros from a BlockList."""
        for b in self.blocks:
            if b.isIf():
                b.expr.optimize(macros)

    def removeStructs(self, structs):
        """Remove structs."""
        extra_includes = set()
        block_num = 0
        num_blocks = len(self.blocks)
        while block_num < num_blocks:
            b = self.blocks[block_num]
            block_num += 1
            # Have to look in each block for a top-level struct definition.
            if b.directive:
                continue
            num_tokens = len(b.tokens)
            # A struct definition usually looks like:
            #   struct
            #   ident
            #   {
            #   }
            #   ;
            # However, the structure might be spread across multiple blocks
            # if the structure looks like this:
            #   struct ident
            #   {
            #   #ifdef VARIABLE
            #     pid_t pid;
            #   #endif
            #   }:
            # So the total number of tokens in the block might be less than
            # five but assume at least three.
            if num_tokens < 3:
                continue

            # This is a simple struct finder, it might fail if a top-level
            # structure has an #if type directives that confuses the algorithm
            # for finding the end of the structure. Or if there is another
            # structure definition embedded in the structure.
            i = 0
            while i < num_tokens - 2:
                if (b.tokens[i].kind != TokenKind.KEYWORD or
                    b.tokens[i].id != "struct"):
                    i += 1
                    continue
                if (b.tokens[i + 1].kind == TokenKind.IDENTIFIER and
                    b.tokens[i + 2].kind == TokenKind.PUNCTUATION and
                    b.tokens[i + 2].id == "{" and b.tokens[i + 1].id in structs):
                    # Add an include for the structure to be removed of the form:
                    #  #include <bits/STRUCT_NAME.h>
                    struct_token = b.tokens[i + 1]
                    if struct_token.id in structs and structs[struct_token.id]:
                        extra_includes.add("<%s>" % structs[struct_token.id])

                    # Search forward for the end of the structure.
                    # Very simple search, look for } and ; tokens.
                    # If we hit the end of the block, we'll need to start
                    # looking at the next block.
                    j = i + 3
                    depth = 1
                    struct_removed = False
                    while not struct_removed:
                        while j < num_tokens:
                            if b.tokens[j].kind == TokenKind.PUNCTUATION:
                                if b.tokens[j].id == '{':
                                    depth += 1
                                elif b.tokens[j].id == '}':
                                    depth -= 1
                                elif b.tokens[j].id == ';' and depth == 0:
                                    b.tokens = b.tokens[0:i] + b.tokens[j + 1:num_tokens]
                                    num_tokens = len(b.tokens)
                                    struct_removed = True
                                    break
                            j += 1
                        if not struct_removed:
                            b.tokens = b.tokens[0:i]

                            # Skip directive blocks.
                            start_block = block_num
                            while block_num < num_blocks:
                                if not self.blocks[block_num].directive:
                                    break
                                block_num += 1
                            if block_num >= num_blocks:
                                # Unparsable struct, error out.
                                raise UnparseableStruct("Cannot remove struct %s: %s" % (struct_token.id, struct_token.location))
                            self.blocks = self.blocks[0:start_block] + self.blocks[block_num:num_blocks]
                            num_blocks = len(self.blocks)
                            b = self.blocks[start_block]
                            block_num = start_block + 1
                            num_tokens = len(b.tokens)
                            i = 0
                            j = 0
                    continue
                i += 1

        for extra_include in sorted(extra_includes):
            replacement = CppStringTokenizer(extra_include)
            self.blocks.insert(2, Block(replacement.tokens, directive='include'))

    def optimizeAll(self, macros):
        self.optimizeMacros(macros)
        self.optimizeIf01()
        return

    def findIncludes(self):
        """Return the list of included files in a BlockList."""
        result = []
        for b in self.blocks:
            i = b.isInclude()
            if i:
                result.append(i)
        return result

    def write(self, out):
        indent = 0
        for b in self.blocks:
            indent = b.write(out, indent)

    def removeVarsAndFuncs(self, keep):
        """Remove variable and function declarations.

        All extern and static declarations corresponding to variable and
        function declarations are removed. We only accept typedefs and
        enum/structs/union declarations.

        In addition, remove any macros expanding in the headers. Usually,
        these macros are static inline functions, which is why they are
        removed.

        However, we keep the definitions corresponding to the set of known
        static inline functions in the set 'keep', which is useful
        for optimized byteorder swap functions and stuff like that.
        """

        # state = NORMAL => normal (i.e. LN + spaces)
        # state = OTHER_DECL => typedef/struct encountered, ends with ";"
        # state = VAR_DECL => var declaration encountered, ends with ";"
        # state = FUNC_DECL => func declaration encountered, ends with "}"
        NORMAL = 0
        OTHER_DECL = 1
        VAR_DECL = 2
        FUNC_DECL = 3

        state = NORMAL
        depth = 0
        blocksToKeep = []
        blocksInProgress = []
        blocksOfDirectives = []
        ident = ""
        state_token = ""
        macros = set()
        for block in self.blocks:
            if block.isDirective():
                # Record all macros.
                if block.directive == 'define':
                    macro_name = block.define_id
                    paren_index = macro_name.find('(')
                    if paren_index == -1:
                        macros.add(macro_name)
                    else:
                        macros.add(macro_name[0:paren_index])
                blocksInProgress.append(block)
                # If this is in a function/variable declaration, we might need
                # to emit the directives alone, so save them separately.
                blocksOfDirectives.append(block)
                continue

            numTokens = len(block.tokens)
            lastTerminatorIndex = 0
            i = 0
            while i < numTokens:
                token_id = block.tokens[i].id
                terminator = False
                if token_id == '{':
                    depth += 1
                    if (i >= 2 and block.tokens[i-2].id == 'extern' and
                        block.tokens[i-1].id == '"C"'):
                        # For an extern "C" { pretend as though this is depth 0.
                        depth -= 1
                elif token_id == '}':
                    if depth > 0:
                        depth -= 1
                    if depth == 0:
                        if state == OTHER_DECL:
                            # Loop through until we hit the ';'
                            i += 1
                            while i < numTokens:
                                if block.tokens[i].id == ';':
                                    token_id = ';'
                                    break
                                i += 1
                            # If we didn't hit the ';', just consider this the
                            # terminator any way.
                        terminator = True
                elif depth == 0:
                    if token_id == ';':
                        if state == NORMAL:
                            blocksToKeep.extend(blocksInProgress)
                            blocksInProgress = []
                            blocksOfDirectives = []
                            state = FUNC_DECL
                        terminator = True
                    elif (state == NORMAL and token_id == '(' and i >= 1 and
                          block.tokens[i-1].kind == TokenKind.IDENTIFIER and
                          block.tokens[i-1].id in macros):
                        # This is a plain macro being expanded in the header
                        # which needs to be removed.
                        blocksToKeep.extend(blocksInProgress)
                        if lastTerminatorIndex < i - 1:
                            blocksToKeep.append(Block(block.tokens[lastTerminatorIndex:i-1]))
                        blocksInProgress = []
                        blocksOfDirectives = []

                        # Skip until we see the terminating ')'
                        i += 1
                        paren_depth = 1
                        while i < numTokens:
                            if block.tokens[i].id == ')':
                                paren_depth -= 1
                                if paren_depth == 0:
                                    break
                            elif block.tokens[i].id == '(':
                                paren_depth += 1
                            i += 1
                        lastTerminatorIndex = i + 1
                    elif (state != FUNC_DECL and token_id == '(' and
                          state_token != 'typedef'):
                        blocksToKeep.extend(blocksInProgress)
                        blocksInProgress = []
                        blocksOfDirectives = []
                        state = VAR_DECL
                    elif state == NORMAL and token_id in ['struct', 'typedef',
                                                          'enum', 'union',
                                                          '__extension__', '=']:
                        state = OTHER_DECL
                        state_token = token_id
                    elif block.tokens[i].kind == TokenKind.IDENTIFIER:
                        if state != VAR_DECL or ident == "":
                            ident = token_id

                if terminator:
                    if state != VAR_DECL and state != FUNC_DECL or ident in keep:
                        blocksInProgress.append(Block(block.tokens[lastTerminatorIndex:i+1]))
                        blocksToKeep.extend(blocksInProgress)
                    else:
                        # Only keep the directives found.
                        blocksToKeep.extend(blocksOfDirectives)
                    lastTerminatorIndex = i + 1
                    blocksInProgress = []
                    blocksOfDirectives = []
                    state = NORMAL
                    ident = ""
                    state_token = ""
                i += 1
            if lastTerminatorIndex < numTokens:
                blocksInProgress.append(Block(block.tokens[lastTerminatorIndex:numTokens]))
        if len(blocksInProgress) > 0:
            blocksToKeep.extend(blocksInProgress)
        self.blocks = blocksToKeep

    def replaceTokens(self, replacements):
        """Replace tokens according to the given dict."""
        for b in self.blocks:
            made_change = False
            if b.isInclude() is None:
                i = 0
                while i < len(b.tokens):
                    tok = b.tokens[i]
                    if tok.kind == TokenKind.IDENTIFIER:
                        if tok.id in replacements:
                            tok.id = replacements[tok.id]
                            made_change = True
                    i += 1

                if b.isDefine():
                    tokens = CppStringTokenizer(b.define_id).tokens
                    id_change = False
                    for tok in tokens:
                        if tok.kind == TokenKind.IDENTIFIER:
                            if tok.id in replacements:
                                tok.id = replacements[tok.id]
                                id_change = True
                    if id_change:
                        b.define_id = ''.join([tok.id for tok in tokens])
                        made_change = True


            if made_change and b.isIf():
                # Keep 'expr' in sync with 'tokens'.
                b.expr = CppExpr(b.tokens)



def strip_space(s):
    """Strip out redundant space in a given string."""

    # NOTE: It ought to be more clever to not destroy spaces in string tokens.
    replacements = {' . ': '.',
                    ' [': '[',
                    '[ ': '[',
                    ' ]': ']',
                    '( ': '(',
                    ' )': ')',
                    ' ,': ',',
                    '# ': '#',
                    ' ;': ';',
                    '~ ': '~',
                    ' -> ': '->'}
    result = s
    for r in replacements:
        result = result.replace(r, replacements[r])

    # Remove the space between function name and the parenthesis.
    result = re.sub(r'(\w+) \(', r'\1(', result)
    return result


class BlockParser(object):
    """A class that converts an input source file into a BlockList object."""

    def __init__(self, tokzer=None):
        """Initialize a block parser.

        The input source is provided through a Tokenizer object.
        """
        self._tokzer = tokzer
        self._parsed = False

    @property
    def parsed(self):
        return self._parsed

    @staticmethod
    def _short_extent(extent):
        return '%d:%d - %d:%d' % (extent.start.line, extent.start.column,
                                  extent.end.line, extent.end.column)

    def getBlocks(self, tokzer=None):
        """Return all the blocks parsed."""

        def consume_extent(i, tokens, extent=None, detect_change=False):
            """Return tokens that belong to the given extent.

            It parses all the tokens that follow tokens[i], until getting out
            of the extent. When detect_change is True, it may terminate early
            when detecting preprocessing directives inside the extent.
            """

            result = []
            if extent is None:
                extent = tokens[i].cursor.extent

            while i < len(tokens) and tokens[i].location in extent:
                t = tokens[i]
                if debugBlockParser:
                    print(' ' * 2, t.id, t.kind, t.cursor.kind)
                if (detect_change and t.cursor.extent != extent and
                    t.cursor.kind == CursorKind.PREPROCESSING_DIRECTIVE):
                    break
                result.append(t)
                i += 1
            return (i, result)

        def consume_line(i, tokens):
            """Return tokens that follow tokens[i] in the same line."""
            result = []
            line = tokens[i].location.line
            while i < len(tokens) and tokens[i].location.line == line:
                if tokens[i].cursor.kind == CursorKind.PREPROCESSING_DIRECTIVE:
                    break
                result.append(tokens[i])
                i += 1
            return (i, result)

        if tokzer is None:
            tokzer = self._tokzer
        tokens = tokzer.tokens

        blocks = []
        buf = []
        i = 0

        while i < len(tokens):
            t = tokens[i]
            cursor = t.cursor

            if debugBlockParser:
                print ("%d: Processing [%s], kind=[%s], cursor=[%s], "
                       "extent=[%s]" % (t.location.line, t.spelling, t.kind,
                                        cursor.kind,
                                        self._short_extent(cursor.extent)))

            if cursor.kind == CursorKind.PREPROCESSING_DIRECTIVE:
                if buf:
                    blocks.append(Block(buf))
                    buf = []

                j = i
                if j + 1 >= len(tokens):
                    raise BadExpectedToken("### BAD TOKEN at %s" % (t.location))
                directive = tokens[j+1].id

                if directive == 'define':
                    if i+2 >= len(tokens):
                        raise BadExpectedToken("### BAD TOKEN at %s" %
                                               (tokens[i].location))

                    # Skip '#' and 'define'.
                    extent = tokens[i].cursor.extent
                    i += 2
                    id = ''
                    # We need to separate the id from the remaining of
                    # the line, especially for the function-like macro.
                    if (i + 1 < len(tokens) and tokens[i+1].id == '(' and
                        (tokens[i].location.column + len(tokens[i].spelling) ==
                         tokens[i+1].location.column)):
                        while i < len(tokens):
                            id += tokens[i].id
                            if tokens[i].spelling == ')':
                                i += 1
                                break
                            i += 1
                    else:
                        id += tokens[i].id
                        # Advance to the next token that follows the macro id
                        i += 1

                    (i, ret) = consume_extent(i, tokens, extent=extent)
                    blocks.append(Block(ret, directive=directive,
                                        lineno=t.location.line, identifier=id))

                else:
                    (i, ret) = consume_extent(i, tokens)
                    blocks.append(Block(ret[2:], directive=directive,
                                        lineno=t.location.line))

            elif cursor.kind == CursorKind.INCLUSION_DIRECTIVE:
                if buf:
                    blocks.append(Block(buf))
                    buf = []
                directive = tokens[i+1].id
                (i, ret) = consume_extent(i, tokens)

                blocks.append(Block(ret[2:], directive=directive,
                                    lineno=t.location.line))

            elif cursor.kind == CursorKind.VAR_DECL:
                if buf:
                    blocks.append(Block(buf))
                    buf = []

                (i, ret) = consume_extent(i, tokens, detect_change=True)
                buf += ret

            elif cursor.kind == CursorKind.FUNCTION_DECL:
                if buf:
                    blocks.append(Block(buf))
                    buf = []

                (i, ret) = consume_extent(i, tokens, detect_change=True)
                buf += ret

            else:
                (i, ret) = consume_line(i, tokens)
                buf += ret

        if buf:
            blocks.append(Block(buf))

        # _parsed=True indicates a successful parsing, although may result an
        # empty BlockList.
        self._parsed = True

        return BlockList(blocks)

    def parse(self, tokzer):
        return self.getBlocks(tokzer)

    def parseFile(self, path):
        return self.getBlocks(CppFileTokenizer(path))


class BlockParserTests(unittest.TestCase):
    """BlockParser unit tests."""

    def get_blocks(self, lines):
        blocks = BlockParser().parse(CppStringTokenizer('\n'.join(lines)))
        return list(map(lambda a: str(a), blocks))

    def test_hash(self):
        self.assertEqual(self.get_blocks(["#error hello"]), ["#error hello"])

    def test_empty_line(self):
        self.assertEqual(self.get_blocks(["foo", "", "bar"]), ["foo bar"])

    def test_hash_with_space(self):
        # We currently cannot handle the following case with libclang properly.
        # Fortunately it doesn't appear in current headers.
        #self.assertEqual(self.get_blocks(["foo", "  #  ", "bar"]), ["foo", "bar"])
        pass

    def test_with_comment(self):
        self.assertEqual(self.get_blocks(["foo",
                                          "  #  /* ahah */ if defined(__KERNEL__) /* more */",
                                          "bar", "#endif"]),
                         ["foo", "#ifdef __KERNEL__", "bar", "#endif"])


################################################################################
################################################################################
#####                                                                      #####
#####        B L O C K   L I S T   O P T I M I Z A T I O N                 #####
#####                                                                      #####
################################################################################
################################################################################


def find_matching_endif(blocks, i):
    """Traverse the blocks to find out the matching #endif."""
    n = len(blocks)
    depth = 1
    while i < n:
        if blocks[i].isDirective():
            dir_ = blocks[i].directive
            if dir_ in ["if", "ifndef", "ifdef"]:
                depth += 1
            elif depth == 1 and dir_ in ["else", "elif"]:
                return i
            elif dir_ == "endif":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return i


def optimize_if01(blocks):
    """Remove the code between #if 0 .. #endif in a list of CppBlocks."""
    i = 0
    n = len(blocks)
    result = []
    while i < n:
        j = i
        while j < n and not blocks[j].isIf():
            j += 1
        if j > i:
            logging.debug("appending lines %d to %d", blocks[i].lineno,
                          blocks[j-1].lineno)
            result += blocks[i:j]
        if j >= n:
            break
        expr = blocks[j].expr
        r = expr.toInt()
        if r is None:
            result.append(blocks[j])
            i = j + 1
            continue

        if r == 0:
            # if 0 => skip everything until the corresponding #endif
            start_dir = blocks[j].directive
            j = find_matching_endif(blocks, j + 1)
            if j >= n:
                # unterminated #if 0, finish here
                break
            dir_ = blocks[j].directive
            if dir_ == "endif":
                logging.debug("remove 'if 0' .. 'endif' (lines %d to %d)",
                              blocks[i].lineno, blocks[j].lineno)
                if start_dir == "elif":
                    # Pu
"""


```