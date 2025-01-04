Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Core Purpose:** The filename and the initial comments clearly state the script's function: `cmake2meson.py` aims to convert CMake build files (`CMakeLists.txt`) into Meson build files (`meson.build`). This immediately tells us it's a build system conversion tool.

2. **High-Level Structure Analysis:**  A quick scan reveals the typical structure of a Python script:
    * Imports: `typing`, `pathlib`, `sys`, `re`, `argparse`. These suggest handling file paths, regular expressions for parsing, command-line arguments, and type hinting.
    * Classes: `Token`, `Statement`, `Lexer`, `Parser`, `Converter`. This object-oriented design hints at a multi-stage process: breaking down the input, interpreting it, and then transforming it.
    * `if __name__ == '__main__':` block: This is the entry point of the script, indicating how it's executed.

3. **Decomposition of Key Classes:**

    * **`Token`:**  Represents a basic unit of the CMake language (like keywords, identifiers, strings). It stores the token's type (`tid`) and value. The `lineno` and `colno` are crucial for error reporting during parsing.

    * **`Statement`:**  Represents a CMake command or directive. It stores the command name (`name`) and its arguments (`args`). Lowercasing the name suggests case-insensitive handling of CMake commands.

    * **`Lexer`:**  Responsible for the *lexical analysis* or *tokenization* phase. It takes the raw CMake code as input and breaks it down into a stream of `Token` objects. The `token_specification` uses regular expressions to define the patterns for different token types. The order matters (longest to shortest) to correctly identify tokens.

    * **`Parser`:**  Responsible for the *syntax analysis* or *parsing* phase. It takes the token stream from the `Lexer` and builds a structured representation (a sequence of `Statement` objects). The `getsym`, `accept`, and `expect` methods are typical for a simple recursive descent parser. The `statement` and `arguments` methods define the grammar rules for CMake.

    * **`Converter`:** The core of the translation process. It takes the parsed `Statement` objects and generates the corresponding Meson code.
        * `ignored_funcs`: Indicates certain CMake commands are skipped during conversion.
        * `convert_args`:  Handles the translation of CMake arguments to Meson syntax.
        * `write_entry`:  Contains the logic for converting individual CMake statements to Meson equivalents. This is where much of the domain-specific knowledge of CMake-to-Meson mapping resides (e.g., `add_subdirectory`, `add_executable`, `find_package`).
        * `convert`:  Manages the overall conversion process, including handling subdirectories.
        * `write_options`: Generates the `meson_options.txt` file.

4. **Identifying Connections to Reverse Engineering, Binaries, Kernels, and Frameworks:**

    * **Reverse Engineering:**  The tool itself isn't directly a reverse engineering tool. However, build systems are *essential* for building software, including software that might be subject to reverse engineering. Understanding how a target is built (libraries linked, compiler flags used, etc.) is valuable in reverse engineering. The script's ability to convert build systems could indirectly aid in this by making the build process clearer.

    * **Binary Underlying:** Build systems manage the compilation and linking process that generates executables and libraries (binary files). This script, by converting build systems, indirectly deals with the steps that lead to creating these binaries. The `add_executable` and `add_library` conversions are direct examples.

    * **Linux/Android Kernel & Frameworks:** Frida often interacts with these lower levels. While this script doesn't *directly* touch the kernel, it helps manage the build process of tools (like Frida itself or extensions) that *do* interact with these components. The presence of "frida" in the path strongly suggests this connection. The `shared_library` conversion is relevant for building `.so` files often used in Linux and Android.

5. **Logical Reasoning (Input/Output):**  Focus on the core function: `CMakeLists.txt` in, `meson.build` and `meson_options.txt` out. Think of simple CMake commands and their Meson equivalents.

6. **Common Usage Errors:** Think about what could go wrong when using such a conversion tool:
    * Incorrect CMake syntax.
    * Unsupported CMake features.
    * Issues with file paths.

7. **Tracing User Actions (Debugging Clue):** Consider how a developer working with Frida might end up needing this script:
    * They might be porting an existing CMake-based project to use Meson.
    * They might be examining Frida's own build process.
    * They might be contributing to Frida and need to understand its build system.

8. **Refining and Organizing:** After the initial exploration, organize the findings into a structured answer, grouping related points together and providing specific examples. Use clear and concise language. Pay attention to the prompt's specific requests (examples, reasoning, etc.).

**(Self-Correction during the process):**

* Initially, I might focus too much on the low-level parsing details. I need to remember the high-level goal of the script.
* I might miss the indirect connections to reverse engineering and lower-level systems. Thinking about the context of "Frida" helps here.
* I need to ensure my examples are concrete and illustrate the points I'm making.
* I should double-check that I've addressed all parts of the prompt.

By following these steps, moving from the general to the specific, and constantly relating the code back to its purpose, a comprehensive and accurate analysis can be achieved.
这个Python脚本 `cmake2meson.py` 的主要功能是将 CMake 构建系统描述文件 (`CMakeLists.txt`) 转换为 Meson 构建系统描述文件 (`meson.build` 和 `meson_options.txt`)。Meson 是一个专注于速度和用户友好性的构建系统。

以下是该脚本功能的详细列表，并结合了您提出的几个方面：

**主要功能:**

1. **解析 CMakeLists.txt:**
   - 使用 `Lexer` 类对 `CMakeLists.txt` 文件内容进行词法分析，将其分解成一系列的 `Token` 对象，例如标识符、字符串、括号等。
   - 使用 `Parser` 类对 `Token` 流进行语法分析，将其组织成 `Statement` 对象，每个 `Statement` 代表一个 CMake 命令及其参数。

2. **转换 CMake 命令到 Meson:**
   - `Converter` 类负责将解析后的 CMake `Statement` 对象转换为相应的 Meson 构建语句。
   - 它维护了一个 `ignored_funcs` 字典，用于跳过一些不需要转换的 CMake 命令，如 `cmake_minimum_required`、`enable_testing` 和 `include`。
   - 针对不同的 CMake 命令，`write_entry` 方法实现了到 Meson 语句的特定转换逻辑，例如：
     - `add_subdirectory` 转换为 `subdir()`
     - `add_executable` 转换为 `executable()`
     - `add_library` 转换为 `shared_library()` 或 `static_library()` 或 `library()`
     - `find_package` 转换为 `dependency()`
     - `set` 转换为 Meson 的变量赋值
     - `if`, `elseif`, `else`, `endif` 转换为 Meson 的条件语句

3. **生成 meson.build 文件:**
   - `Converter.convert()` 方法读取 `CMakeLists.txt`，解析并转换其中的语句，并将生成的 Meson 语句写入到同级目录下的 `meson.build` 文件中。
   - 它会递归处理 `add_subdirectory` 命令，进入子目录进行转换。

4. **生成 meson_options.txt 文件:**
   - `Converter.write_options()` 方法将解析到的 CMake `option()` 命令转换为 Meson 的 `option()` 语句，并写入到 `meson_options.txt` 文件中。这个文件定义了构建时的可配置选项。

**与逆向方法的关系及举例:**

虽然这个脚本本身不是一个直接的逆向工具，但它在逆向工程的上下文中可能有用：

- **理解目标软件的构建过程:** 逆向工程师经常需要理解目标软件是如何构建的，以找到潜在的漏洞或理解其内部结构。如果目标软件使用 CMake 构建，而逆向工程师更熟悉 Meson，那么这个脚本可以帮助他们将 CMake 构建描述转换为更容易理解的 Meson 格式，从而加速对构建过程的理解。
    - **举例:** 假设一个逆向工程师需要分析一个使用 CMake 构建的共享库。通过 `cmake2meson.py` 将其 `CMakeLists.txt` 转换为 `meson.build` 后，工程师可以更容易地看到库的依赖项 (通过 `find_package` 转换成 `dependency`)，编译选项 (虽然脚本中没有直接处理复杂的编译选项，但可以初步了解)，以及如何构建可执行文件 (通过 `add_executable`)。这有助于他们构建一个测试环境或理解目标库的加载和链接方式。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

该脚本虽然处理的是构建系统描述，但构建过程本身与二进制底层和操作系统概念紧密相关：

- **库的类型 (共享库 vs. 静态库):** 脚本能够区分 CMake 中 `add_library` 命令定义的共享库 (`SHARED`) 和静态库 (`STATIC`)，并将其转换为 Meson 中对应的 `shared_library` 和 `static_library`。这直接关系到二进制文件的链接方式和运行时行为。共享库在运行时动态链接，而静态库在编译时被链接到可执行文件中。
    - **举例:** 在 Android 逆向中，理解一个模块是作为共享库 (`.so`) 还是静态库链接到进程中至关重要。通过查看转换后的 `meson.build` 文件，逆向工程师可以快速了解目标模块的链接方式，这有助于确定在哪个地址空间中查找代码和数据。

- **可执行文件的生成:** `add_executable` 命令的转换涉及到生成最终的二进制可执行文件。这需要编译器、链接器等工具的参与，并将源代码编译成机器码。
    - **举例:** 在 Linux 内核模块逆向中，尽管内核模块的构建过程与用户空间程序略有不同，但理解构建系统如何将 `.c` 文件编译成 `.ko` 文件仍然重要。`cmake2meson.py` 虽然不直接处理内核模块的 CMakeLists.txt (通常更复杂)，但其转换思路可以帮助理解用户空间工具如何与内核交互。

- **依赖管理 (`find_package`):**  CMake 的 `find_package` 命令用于查找和链接外部库。脚本将其转换为 Meson 的 `dependency()`。这反映了软件构建中依赖关系的重要性。
    - **举例:**  在 Android 框架逆向中，理解一个系统服务依赖了哪些其他库 (例如，Binder 相关的库) 对于分析其功能至关重要。转换后的 `meson.build` 文件可以清晰地展示这些依赖关系。

**逻辑推理及假设输入与输出:**

脚本的核心逻辑是根据 CMake 命令的语义将其转换为等效的 Meson 命令。

**假设输入 (CMakeLists.txt 内容):**

```cmake
cmake_minimum_required(VERSION 3.0)
project(MyProject C C++)

add_executable(my_app src/main.c src/utils.c)

add_library(mylib SHARED lib/mylib.c)

find_package(ZLIB REQUIRED)
target_link_libraries(my_app mylib ZLIB::ZLIB)

if(ENABLE_DEBUG)
  add_definitions(-DDEBUG_ENABLED)
endif()
```

**假设输出 (meson.build 内容):**

```meson
project('myproject', 'c', 'cpp', default_options : ['default_library=static'])
my_app_exe = executable('my_app', ['src/main.c', 'src/utils.c'])
mylib_lib = shared_library('mylib', ['lib/mylib.c'])
zlib_dep = dependency('ZLIB')
link_with = [mylib_lib, zlib_dep]
if get_option('enable_debug')
  add_project_arguments('-DDEBUG_ENABLED', language: 'c')
  add_project_arguments('-DDEBUG_ENABLED', language: 'cpp')
endif
```

**假设输出 (meson_options.txt 内容 - 如果 CMakeLists.txt 中有 `option()`):**

```
# 如果 CMakeLists.txt 中定义了 option(ENABLE_DEBUG ...)，则会生成类似这样的内容
# option('enable_debug', type : 'boolean', value : false, description : 'Enable debug mode')
```

**涉及用户或编程常见的使用错误及举例:**

- **CMake 语法错误:** 如果 `CMakeLists.txt` 中存在语法错误，CMake 本身会报错。但如果错误比较隐蔽，`cmake2meson.py` 的解析器可能无法正确处理，导致转换后的 `meson.build` 文件不正确或出现异常。
    - **举例:**  CMake 中字符串没有正确闭合 (`add_executable(my_app "src/main.c`)，`cmake2meson.py` 的词法分析器可能会在解析字符串时出错。

- **不支持的 CMake 特性:** `cmake2meson.py` 可能无法处理所有 CMake 的高级或复杂的特性。尝试转换使用了这些特性的 `CMakeLists.txt` 可能会导致转换失败或生成不完整的 `meson.build` 文件。
    - **举例:**  如果 `CMakeLists.txt` 中使用了自定义的 CMake 函数或宏，而 `cmake2meson.py` 没有针对这些进行适配，转换结果可能会不正确。

- **文件路径问题:** 如果 `CMakeLists.txt` 中引用的源文件或子目录路径不正确，虽然 `cmake2meson.py` 可以完成转换，但后续使用 Meson 构建时会因为找不到文件而失败。
    - **举例:** `add_executable(my_app src/main.c)`，如果实际上 `src/main.c` 不存在，Meson 构建会报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要将一个基于 CMake 的项目转换为使用 Meson 构建。** 这可能是因为他们希望利用 Meson 的速度和简洁性，或者他们的项目需要与其他使用 Meson 的项目集成。

2. **用户找到了 `cmake2meson.py` 这个工具。** 这可能是通过搜索、查看 Frida 项目的构建脚本，或者从其他开发者那里得知。

3. **用户下载或获取了 `cmake2meson.py` 脚本。**

4. **用户需要知道如何使用这个脚本。** 他们可能会查看脚本的帮助信息或文档 (如果存在)。从脚本末尾的 `if __name__ == '__main__':` 部分可以看到，用户需要在命令行提供 CMake 项目的根目录作为参数。

5. **用户在命令行执行该脚本，并提供 CMake 项目的根目录。**
   ```bash
   python path/to/cmake2meson.py /path/to/cmake/project
   ```

6. **脚本开始执行，读取并解析 `/path/to/cmake/project` 目录下的 `CMakeLists.txt` 文件。**

7. **脚本遍历 `CMakeLists.txt` 中的 CMake 命令，并根据其内部的转换逻辑生成 `meson.build` 和 `meson_options.txt` 文件到相应的目录中。** 如果有子目录，也会递归处理子目录下的 `CMakeLists.txt`。

**调试线索:**

如果转换过程中出现问题，可以按照以下线索进行调试：

- **检查 `cmake2meson.py` 的输出或错误信息。**  脚本可能会打印一些警告或错误信息，指示解析或转换过程中遇到的问题。
- **比对原始的 `CMakeLists.txt` 和生成的 `meson.build` 文件。**  检查是否有重要的 CMake 命令没有被正确转换，或者转换后的 Meson 语句是否语义一致。
- **逐步调试 `cmake2meson.py` 脚本。** 可以使用 Python 的调试工具 (如 `pdb`) 来跟踪脚本的执行流程，查看在哪个 CMake 命令的转换过程中出现了问题。
- **查看 Meson 的构建日志。** 如果 `cmake2meson.py` 生成的 `meson.build` 文件在后续的 Meson 构建过程中出错，Meson 的构建日志会提供更详细的错误信息，帮助定位问题是由转换引起的，还是其他原因。
- **检查 `meson_options.txt` 文件。** 确保 CMake 的 `option()` 命令被正确地转换为 Meson 的选项定义。

总而言之，`cmake2meson.py` 是一个用于简化从 CMake 到 Meson 迁移过程的实用工具，它通过解析 CMakeLists.txt 并将其转换为相应的 Meson 构建描述来实现其功能。理解其内部机制可以帮助开发者更好地进行构建系统的迁移和调试。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/tools/cmake2meson.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2014 Jussi Pakkanen

import typing as T
from pathlib import Path
import sys
import re
import argparse


class Token:
    def __init__(self, tid: str, value: str):
        self.tid = tid
        self.value = value
        self.lineno = 0
        self.colno = 0

class Statement:
    def __init__(self, name: str, args: list):
        self.name = name.lower()
        self.args = args

class Lexer:
    def __init__(self) -> None:
        self.token_specification = [
            # Need to be sorted longest to shortest.
            ('ignore', re.compile(r'[ \t]')),
            ('string', re.compile(r'"([^\\]|(\\.))*?"', re.M)),
            ('varexp', re.compile(r'\${[-_0-9a-z/A-Z.]+}')),
            ('id', re.compile('''[,-><${}=+_0-9a-z/A-Z|@.*]+''')),
            ('eol', re.compile(r'\n')),
            ('comment', re.compile(r'#.*')),
            ('lparen', re.compile(r'\(')),
            ('rparen', re.compile(r'\)')),
        ]

    def lex(self, code: str) -> T.Iterator[Token]:
        lineno = 1
        line_start = 0
        loc = 0
        col = 0
        while loc < len(code):
            matched = False
            for (tid, reg) in self.token_specification:
                mo = reg.match(code, loc)
                if mo:
                    col = mo.start() - line_start
                    matched = True
                    loc = mo.end()
                    match_text = mo.group()
                    if tid == 'ignore':
                        continue
                    if tid == 'comment':
                        yield(Token('comment', match_text))
                    elif tid == 'lparen':
                        yield(Token('lparen', '('))
                    elif tid == 'rparen':
                        yield(Token('rparen', ')'))
                    elif tid == 'string':
                        yield(Token('string', match_text[1:-1]))
                    elif tid == 'id':
                        yield(Token('id', match_text))
                    elif tid == 'eol':
                        # yield('eol')
                        lineno += 1
                        col = 1
                        line_start = mo.end()
                    elif tid == 'varexp':
                        yield(Token('varexp', match_text[2:-1]))
                    else:
                        raise ValueError(f'lex: unknown element {tid}')
                    break
            if not matched:
                raise ValueError('Lexer got confused line %d column %d' % (lineno, col))

class Parser:
    def __init__(self, code: str) -> None:
        self.stream = Lexer().lex(code)
        self.getsym()

    def getsym(self) -> None:
        try:
            self.current = next(self.stream)
        except StopIteration:
            self.current = Token('eof', '')

    def accept(self, s: str) -> bool:
        if self.current.tid == s:
            self.getsym()
            return True
        return False

    def expect(self, s: str) -> bool:
        if self.accept(s):
            return True
        raise ValueError(f'Expecting {s} got {self.current.tid}.', self.current.lineno, self.current.colno)

    def statement(self) -> Statement:
        cur = self.current
        if self.accept('comment'):
            return Statement('_', [cur.value])
        self.accept('id')
        self.expect('lparen')
        args = self.arguments()
        self.expect('rparen')
        return Statement(cur.value, args)

    def arguments(self) -> T.List[T.Union[Token, T.Any]]:
        args: T.List[T.Union[Token, T.Any]] = []
        if self.accept('lparen'):
            args.append(self.arguments())
            self.expect('rparen')
        arg = self.current
        if self.accept('comment'):
            rest = self.arguments()
            args += rest
        elif self.accept('string') \
                or self.accept('varexp') \
                or self.accept('id'):
            args.append(arg)
            rest = self.arguments()
            args += rest
        return args

    def parse(self) -> T.Iterator[Statement]:
        while not self.accept('eof'):
            yield(self.statement())

def token_or_group(arg: T.Union[Token, T.List[Token]]) -> str:
    if isinstance(arg, Token):
        return ' ' + arg.value
    elif isinstance(arg, list):
        line = ' ('
        for a in arg:
            line += ' ' + token_or_group(a)
        line += ' )'
        return line
    raise RuntimeError('Conversion error in token_or_group')

class Converter:
    ignored_funcs = {'cmake_minimum_required': True,
                     'enable_testing': True,
                     'include': True}

    def __init__(self, cmake_root: str):
        self.cmake_root = Path(cmake_root).expanduser()
        self.indent_unit = '  '
        self.indent_level = 0
        self.options: T.List[T.Tuple[str, str, T.Optional[str]]] = []

    def convert_args(self, args: T.List[Token], as_array: bool = True) -> str:
        res = []
        if as_array:
            start = '['
            end = ']'
        else:
            start = ''
            end = ''
        for i in args:
            if i.tid == 'id':
                res.append("'%s'" % i.value)
            elif i.tid == 'varexp':
                res.append('%s' % i.value.lower())
            elif i.tid == 'string':
                res.append("'%s'" % i.value)
            else:
                raise ValueError(f'Unknown arg type {i.tid}')
        if len(res) > 1:
            return start + ', '.join(res) + end
        if len(res) == 1:
            return res[0]
        return ''

    def write_entry(self, outfile: T.TextIO, t: Statement) -> None:
        if t.name in Converter.ignored_funcs:
            return
        preincrement = 0
        postincrement = 0
        if t.name == '_':
            line = t.args[0]
        elif t.name == 'add_subdirectory':
            line = "subdir('" + t.args[0].value + "')"
        elif t.name == 'pkg_search_module' or t.name == 'pkg_search_modules':
            varname = t.args[0].value.lower()
            mods = ["dependency('%s')" % i.value for i in t.args[1:]]
            if len(mods) == 1:
                line = '{} = {}'.format(varname, mods[0])
            else:
                line = '{} = [{}]'.format(varname, ', '.join(["'%s'" % i for i in mods]))
        elif t.name == 'find_package':
            line = "{}_dep = dependency('{}')".format(t.args[0].value, t.args[0].value)
        elif t.name == 'find_library':
            line = "{} = find_library('{}')".format(t.args[0].value.lower(), t.args[0].value)
        elif t.name == 'add_executable':
            line = '{}_exe = executable({})'.format(t.args[0].value, self.convert_args(t.args, False))
        elif t.name == 'add_library':
            if t.args[1].value == 'SHARED':
                libcmd = 'shared_library'
                args = [t.args[0]] + t.args[2:]
            elif t.args[1].value == 'STATIC':
                libcmd = 'static_library'
                args = [t.args[0]] + t.args[2:]
            else:
                libcmd = 'library'
                args = t.args
            line = '{}_lib = {}({})'.format(t.args[0].value, libcmd, self.convert_args(args, False))
        elif t.name == 'add_test':
            line = 'test(%s)' % self.convert_args(t.args, False)
        elif t.name == 'option':
            optname = t.args[0].value
            description = t.args[1].value
            if len(t.args) > 2:
                default = t.args[2].value
            else:
                default = None
            self.options.append((optname, description, default))
            return
        elif t.name == 'project':
            pname = t.args[0].value
            args = [pname]
            for l in t.args[1:]:
                l = l.value.lower()
                if l == 'cxx':
                    l = 'cpp'
                args.append(l)
            args = ["'%s'" % i for i in args]
            line = 'project(' + ', '.join(args) + ", default_options : ['default_library=static'])"
        elif t.name == 'set':
            varname = t.args[0].value.lower()
            line = '{} = {}\n'.format(varname, self.convert_args(t.args[1:]))
        elif t.name == 'if':
            postincrement = 1
            try:
                line = 'if %s' % self.convert_args(t.args, False)
            except AttributeError:  # complex if statements
                line = t.name
                for arg in t.args:
                    line += token_or_group(arg)
        elif t.name == 'elseif':
            preincrement = -1
            postincrement = 1
            try:
                line = 'elif %s' % self.convert_args(t.args, False)
            except AttributeError:  # complex if statements
                line = t.name
                for arg in t.args:
                    line += token_or_group(arg)
        elif t.name == 'else':
            preincrement = -1
            postincrement = 1
            line = 'else'
        elif t.name == 'endif':
            preincrement = -1
            line = 'endif'
        else:
            line = '''# {}({})'''.format(t.name, self.convert_args(t.args))
        self.indent_level += preincrement
        indent = self.indent_level * self.indent_unit
        outfile.write(indent)
        outfile.write(line)
        if not(line.endswith('\n')):
            outfile.write('\n')
        self.indent_level += postincrement

    def convert(self, subdir: Path = None) -> None:
        if not subdir:
            subdir = self.cmake_root
        cfile = Path(subdir).expanduser() / 'CMakeLists.txt'
        try:
            with cfile.open(encoding='utf-8') as f:
                cmakecode = f.read()
        except FileNotFoundError:
            print('\nWarning: No CMakeLists.txt in', subdir, '\n', file=sys.stderr)
            return
        p = Parser(cmakecode)
        with (subdir / 'meson.build').open('w', encoding='utf-8') as outfile:
            for t in p.parse():
                if t.name == 'add_subdirectory':
                    # print('\nRecursing to subdir',
                    #       self.cmake_root / t.args[0].value,
                    #       '\n')
                    self.convert(subdir / t.args[0].value)
                    # print('\nReturning to', self.cmake_root, '\n')
                self.write_entry(outfile, t)
        if subdir == self.cmake_root and len(self.options) > 0:
            self.write_options()

    def write_options(self) -> None:
        filename = self.cmake_root / 'meson_options.txt'
        with filename.open('w', encoding='utf-8') as optfile:
            for o in self.options:
                (optname, description, default) = o
                if default is None:
                    typestr = ''
                    defaultstr = ''
                else:
                    if default == 'OFF':
                        typestr = ' type : \'boolean\','
                        default = 'false'
                    elif default == 'ON':
                        default = 'true'
                        typestr = ' type : \'boolean\','
                    else:
                        typestr = ' type : \'string\','
                    defaultstr = ' value : %s,' % default
                line = "option({!r},{}{} description : '{}')\n".format(optname,
                                                                 typestr,
                                                                 defaultstr,
                                                                 description)
                optfile.write(line)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Convert CMakeLists.txt to meson.build and meson_options.txt')
    p.add_argument('cmake_root', help='CMake project root (where top-level CMakeLists.txt is)')
    P = p.parse_args()

    Converter(P.cmake_root).convert()

"""

```