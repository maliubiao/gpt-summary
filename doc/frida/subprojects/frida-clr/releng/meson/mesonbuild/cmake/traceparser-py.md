Response:
My thinking process to analyze the Python code and fulfill the request involved these steps:

1. **Understand the Goal:** The primary goal is to analyze the provided Python code snippet for Frida's CMake trace parser and describe its functionality, especially regarding reverse engineering, low-level details, logic, potential errors, and how a user might reach this code during debugging.

2. **Initial Code Scan and Class Identification:** I started by quickly scanning the code to identify the main classes: `CMakeTraceLine`, `CMakeCacheEntry`, `CMakeTarget`, `CMakeGeneratorTarget`, and `CMakeTraceParser`. The core logic seems to reside within `CMakeTraceParser`.

3. **Focus on `CMakeTraceParser`:**  Given its name and the context (parsing CMake trace output), I deduced that `CMakeTraceParser` is the central component. I examined its methods and attributes to understand its responsibilities.

4. **Attribute Analysis:** I went through the attributes of `CMakeTraceParser`:
    * `vars`, `vars_by_file`, `targets`, `cache`, `explicit_headers`, `custom_targets`: These clearly indicate the parser's role in extracting and storing information about CMake variables, targets, cache entries, headers, and custom commands.
    * `env`, `permissive`, `cmake_version`, `trace_file`, `trace_file_path`, `trace_format`, `errors`: These attributes manage the parser's environment, error handling behavior, and how it interacts with the CMake trace file.
    * `delayed_commands`, `stored_commands`: These suggest a mechanism for handling commands that need to be executed later.
    * `functions`:  This dictionary is crucial. It maps CMake function names to the parser's internal methods, highlighting the specific CMake commands the parser understands.

5. **Method Analysis (Key Methods):** I then focused on the key methods of `CMakeTraceParser`:
    * `__init__`: Initialization, setting up internal data structures and configurations. The handling of different CMake versions (`trace_format`) is important.
    * `trace_args`: Determines the correct arguments to pass to CMake to generate the desired trace output. The conditional inclusion of `--trace-redirect` based on CMake version caught my attention.
    * `parse`: The core parsing logic. It reads the trace, uses different lexers (`_lex_trace_human`, `_lex_trace_json`) based on the `trace_format`, and then iterates through the parsed lines, calling the appropriate handler function from the `functions` dictionary. The post-processing step involving generator expressions is also critical.
    * The `_cmake_*` methods: These are the handlers for individual CMake commands (e.g., `_cmake_set`, `_cmake_add_executable`). I noticed how they extract information from the parsed `CMakeTraceLine` and update the parser's internal state (e.g., adding variables to `self.vars`, targets to `self.targets`).
    * The `_lex_trace_human` and `_lex_trace_json` methods: These are responsible for converting the raw trace string (in different formats) into a stream of `CMakeTraceLine` objects. The regular expressions in `_lex_trace_human` are key here.
    * Helper methods like `get_cmake_var`, `var_to_bool`, `_flatten_args`, `_guess_files`: These provide utility functions for accessing and manipulating the parsed data.

6. **Connect to Requirements (Reverse Engineering, Low-Level, Logic, Errors, Usage):**  As I analyzed the methods, I started making connections to the specific requirements of the prompt:
    * **Reverse Engineering:**  The whole purpose of the parser is to understand the build process described by the CMake files. This information is crucial for reverse engineering because it reveals dependencies, build commands, and target configurations.
    * **Low-Level Details:** The interaction with the CMake trace, which reflects the execution of CMake commands, hints at the underlying build system. The handling of different CMake versions and trace formats also touches on implementation details.
    * **Logic and Assumptions:** The handling of delayed commands (`delayed_commands`, `stored_commands`, `_meson_ps_execute_delayed_calls`), the logic in the `_cmake_*` methods for extracting information, and the handling of generator expressions are examples of logical deductions made by the parser. The assumptions about CMake syntax and command behavior are implicit.
    * **User Errors:**  The `permissive` flag and the `_gen_exception` method highlight how the parser handles unexpected or invalid trace data. The code itself doesn't directly involve *user* actions causing errors in this script, but it's designed to handle potential inconsistencies in the *CMake* configuration driven by the user.
    * **User Path to the Code:**  I considered how Frida interacts with CMake. Frida likely executes CMake with tracing enabled and then uses this parser to interpret the output. Debugging within Frida's build process when CMake is involved would be a scenario where this code is relevant.

7. **Synthesize and Organize:** Finally, I organized my findings into the requested format:  listing the functionalities, providing examples related to reverse engineering, low-level details, logic, user errors, and describing the user's path to encountering this code. I made sure to provide concrete examples where possible.

8. **Refine and Review:** I reviewed my analysis to ensure accuracy, clarity, and completeness, addressing all parts of the prompt. I double-checked the code snippets and explanations. For example, I made sure the explanation of generator expressions was clear and the examples related to reverse engineering were relevant.

This iterative process of scanning, analyzing, connecting, and organizing allowed me to thoroughly understand the code's function and address the various aspects of the request.
好的，这是对 `frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/traceparser.py` 文件第一部分的分析和功能归纳：

**文件功能归纳（第一部分）:**

`traceparser.py` 文件是 Frida 项目中用于解析 CMake 跟踪（trace）输出的 Python 模块。它的主要功能是读取和理解 CMake 构建过程的详细执行日志，从中提取关键信息，用于辅助构建系统集成和分析。

**详细功能列举:**

1. **解析 CMake 跟踪日志:**  该模块的核心功能是解析 CMake 生成的跟踪日志文件（默认为 `cmake_trace.txt`）。它可以处理两种不同的跟踪格式：`human` (人类可读格式) 和 `json-v1` (JSON 格式)，并根据 CMake 版本自动选择或指定。

2. **提取 CMake 变量:**  解析跟踪日志以识别和存储 CMake `set` 命令设置的变量及其值。它维护了全局变量字典 `self.vars` 和按文件划分的变量字典 `self.vars_by_file`。

3. **提取 CMake 目标信息:**  解析 `add_executable`, `add_library`, `add_custom_target` 等命令，提取有关构建目标的信息，包括目标名称、类型（可执行文件、库、自定义目标等）、是否为导入目标、以及定义目标的跟踪行信息。这些信息存储在 `self.targets` 字典中。

4. **提取 CMake 缓存信息:**  解析 `set` 命令中带有 `CACHE` 关键字的情况，提取 CMake 缓存变量及其类型和值，存储在 `self.cache` 字典中。

5. **提取自定义命令信息:**  解析 `add_custom_command` 命令，提取自定义命令的输出文件、执行命令、依赖项和工作目录等信息，存储在 `self.custom_targets` 列表中。

6. **提取显式头文件信息:** 解析 `set_property` 命令中设置 `HEADER_FILE_ONLY` 属性的情况，记录显式声明的头文件路径。

7. **处理 CMake 函数属性:**  解析 `set_property` 和 `set_target_properties` 命令，提取目标（或源文件）的属性信息，例如编译定义、编译选项、包含目录、链接库和链接选项等。这些属性存储在 `CMakeTarget` 对象的 `properties` 字典中。

8. **处理 CMake 依赖关系:**  解析 `add_dependencies` 命令，记录目标之间的依赖关系。

9. **处理生成器表达式:**  在解析完成后，会对提取出的变量、目标属性等信息中包含的 CMake 生成器表达式进行评估和替换。

10. **错误处理:**  在非 `permissive` 模式下，如果解析过程中遇到不支持的命令或格式错误，会抛出 `CMakeException` 异常。在 `permissive` 模式下，会记录警告信息。

11. **支持延迟命令执行:**  通过 `meson_ps_execute_delayed_calls` 和 `meson_ps_reload_vars` 等特殊函数，实现延迟执行某些 CMake 命令的功能。

**与逆向方法的关联及举例说明:**

该模块与逆向工程有密切关系，因为它提供了理解目标软件构建过程的关键信息。

* **理解构建依赖:** 通过解析 `add_dependencies` 和目标属性中的链接库信息，逆向工程师可以了解目标程序依赖了哪些库，这对于理解程序的功能模块和潜在的攻击面非常有帮助。例如，如果一个目标依赖于加密库，那么逆向工程师可能会重点关注该目标中与加密相关的逻辑。
* **分析编译选项:**  解析 `target_compile_options` 可以了解目标程序在编译时使用了哪些编译器选项，这有助于理解程序的安全特性（例如是否启用了某些安全编译选项）和性能优化策略。
* **追踪代码来源:** 通过 `CMakeTraceLine` 中记录的文件和行号，逆向工程师可以追溯特定 CMake 命令的来源，从而理解构建逻辑的上下文。例如，当分析一个未知的编译选项时，可以找到设置该选项的 CMake 文件和具体行号。
* **理解自定义构建步骤:** 解析 `add_custom_command` 可以了解在标准编译流程之外执行了哪些自定义构建步骤，例如代码生成、资源处理等。这对于理解整个构建过程至关重要，特别是在分析复杂的软件时。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然该模块本身是用 Python 编写的，但它处理的是与底层构建过程相关的信息，因此间接涉及这些知识。

* **二进制底层:**  解析出的链接库信息直接对应于最终二进制文件中需要链接的库文件。编译选项也会影响最终生成的二进制代码。
* **Linux:**  许多 CMake 构建系统都用于构建 Linux 平台上的软件。该模块解析的信息可能包含与 Linux 系统调用、库文件路径等相关的内容。例如，链接库的路径可能指向 `/usr/lib` 或 `/lib` 等 Linux 系统标准库路径。
* **Android 内核及框架:**  Frida 本身常用于 Android 平台的动态 instrumentation。该模块在 Frida 的上下文中，可能用于解析构建 Android 平台特定组件（例如 CLR 运行时）的 CMake 日志。这可能涉及到 Android SDK/NDK 的路径、Android 特有的编译选项或链接库。例如，可能涉及到 Android 的 `liblog.so` 或其他系统库。

**逻辑推理及假设输入与输出:**

该模块进行了逻辑推理来理解 CMake 的构建过程。

**假设输入:**  一个包含以下内容的 `cmake_trace.txt` 文件：

```
/path/to/CMakeLists.txt(10):  set(MY_VAR my_value)
/path/to/CMakeLists.txt(15):  add_executable(my_exe IMPORTED some_lib)
/path/to/CMakeLists.txt(20):  target_link_libraries(my_exe another_lib)
```

**输出:**

* `self.vars`: `{'MY_VAR': ['my_value']}`
* `self.targets`:
    ```
    {
        'my_exe': CMakeTarget(
            name='my_exe',
            type='EXECUTABLE',
            imported=True,
            properties={'LINK_LIBRARIES': ['another_lib']},
            tline=CMakeTraceLine(file=Path('/path/to/CMakeLists.txt'), line=15, func='add_executable', args=['IMPORTED', 'some_lib'])
        )
    }
    ```

**涉及用户或编程常见的使用错误及举例说明:**

虽然用户不直接操作这个 Python 脚本，但在使用 Frida 或编写 CMakeLists.txt 时的错误会影响到这个脚本的运行和解析结果。

* **CMakeLists.txt 语法错误:** 如果 `CMakeLists.txt` 中存在语法错误，CMake 无法正确生成跟踪日志，或者生成的日志格式不符合预期，导致 `traceparser.py` 解析失败或得到不正确的结果。例如，如果 `add_executable` 命令缺少必要的参数。
* **CMake 版本不兼容:**  如果使用的 CMake 版本过低，不支持 JSON 格式的跟踪日志，而 `traceparser.py` 尝试以 JSON 格式解析，则会出错。
* **跟踪日志未生成或路径错误:** 如果在运行 Frida 时没有正确配置 CMake 生成跟踪日志，或者 `traceparser.py` 指向的跟踪日志文件路径不存在，会导致解析失败。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户使用 Frida 对目标进程进行 instrumentation，并且该目标进程或其依赖项是通过 CMake 构建的。**
2. **Frida 内部的构建系统或工具链需要了解目标进程的构建信息，例如依赖的库。**
3. **Frida 可能会执行目标工程的 CMake 构建过程，并启用跟踪功能，生成 `cmake_trace.txt` 文件。**
4. **`traceparser.py` 模块被 Frida 调用，读取和解析这个 `cmake_trace.txt` 文件。**
5. **如果解析过程中出现错误，或者提取的信息不符合预期，Frida 的开发者或高级用户可能会深入到 `traceparser.py` 的代码中进行调试，例如查看解析逻辑、正则表达式匹配、以及对不同 CMake 命令的处理方式。**

**功能归纳:**

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/traceparser.py` 的第一部分主要负责从 CMake 的跟踪日志中提取关键的构建信息，包括变量、目标、缓存和自定义命令等，为 Frida 进一步分析和利用目标进程的构建上下文提供了基础。它支持不同的 CMake 跟踪格式，并具备一定的错误处理能力。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/traceparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

# This class contains the basic functionality needed to run any interpreter
# or an interpreter-based tool.
from __future__ import annotations

from .common import CMakeException
from .generator import parse_generator_expressions
from .. import mlog
from ..mesonlib import version_compare

import typing as T
from pathlib import Path
from functools import lru_cache
import re
import json
import textwrap

if T.TYPE_CHECKING:
    from ..environment import Environment

class CMakeTraceLine:
    def __init__(self, file_str: str, line: int, func: str, args: T.List[str]) -> None:
        self.file = CMakeTraceLine._to_path(file_str)
        self.line = line
        self.func = func.lower()
        self.args = args

    @staticmethod
    @lru_cache(maxsize=None)
    def _to_path(file_str: str) -> Path:
        return Path(file_str)

    def __repr__(self) -> str:
        s = 'CMake TRACE: {0}:{1} {2}({3})'
        return s.format(self.file, self.line, self.func, self.args)

class CMakeCacheEntry(T.NamedTuple):
    value: T.List[str]
    type: str

class CMakeTarget:
    def __init__(
                self,
                name:        str,
                target_type: str,
                properties:  T.Optional[T.Dict[str, T.List[str]]] = None,
                imported:    bool = False,
                tline:       T.Optional[CMakeTraceLine] = None
            ):
        if properties is None:
            properties = {}
        self.name = name
        self.type = target_type
        self.properties = properties
        self.imported = imported
        self.tline = tline
        self.depends: T.List[str] = []
        self.current_bin_dir: T.Optional[Path] = None
        self.current_src_dir: T.Optional[Path] = None

    def __repr__(self) -> str:
        s = 'CMake TARGET:\n  -- name:      {}\n  -- type:      {}\n  -- imported:  {}\n  -- properties: {{\n{}     }}\n  -- tline: {}'
        propSTR = ''
        for i in self.properties:
            propSTR += "      '{}': {}\n".format(i, self.properties[i])
        return s.format(self.name, self.type, self.imported, propSTR, self.tline)

    def strip_properties(self) -> None:
        # Strip the strings in the properties
        if not self.properties:
            return
        for key, val in self.properties.items():
            self.properties[key] = [x.strip() for x in val]
            assert all(';' not in x for x in self.properties[key])

class CMakeGeneratorTarget(CMakeTarget):
    def __init__(self, name: str) -> None:
        super().__init__(name, 'CUSTOM', {})
        self.outputs: T.List[Path] = []
        self._outputs_str: T.List[str] = []
        self.command: T.List[T.List[str]] = []
        self.working_dir: T.Optional[Path] = None

class CMakeTraceParser:
    def __init__(self, cmake_version: str, build_dir: Path, env: 'Environment', permissive: bool = True) -> None:
        self.vars:                      T.Dict[str, T.List[str]] = {}
        self.vars_by_file: T.Dict[Path, T.Dict[str, T.List[str]]] = {}
        self.targets:                   T.Dict[str, CMakeTarget] = {}
        self.cache:                     T.Dict[str, CMakeCacheEntry] = {}

        self.explicit_headers: T.Set[Path] = set()

        # T.List of targes that were added with add_custom_command to generate files
        self.custom_targets: T.List[CMakeGeneratorTarget] = []

        self.env = env
        self.permissive = permissive
        self.cmake_version = cmake_version
        self.trace_file = 'cmake_trace.txt'
        self.trace_file_path = build_dir / self.trace_file
        self.trace_format = 'json-v1' if version_compare(cmake_version, '>=3.17') else 'human'

        self.errors: T.List[str] = []

        # State for delayed command execution. Delayed command execution is realised
        # with a custom CMake file that overrides some functions and adds some
        # introspection information to the trace.
        self.delayed_commands: T.List[str] = []
        self.stored_commands: T.List[CMakeTraceLine] = []

        # All supported functions
        self.functions: T.Dict[str, T.Callable[[CMakeTraceLine], None]] = {
            'set': self._cmake_set,
            'unset': self._cmake_unset,
            'add_executable': self._cmake_add_executable,
            'add_library': self._cmake_add_library,
            'add_custom_command': self._cmake_add_custom_command,
            'add_custom_target': self._cmake_add_custom_target,
            'set_property': self._cmake_set_property,
            'set_target_properties': self._cmake_set_target_properties,
            'target_compile_definitions': self._cmake_target_compile_definitions,
            'target_compile_options': self._cmake_target_compile_options,
            'target_include_directories': self._cmake_target_include_directories,
            'target_link_libraries': self._cmake_target_link_libraries,
            'target_link_options': self._cmake_target_link_options,
            'add_dependencies': self._cmake_add_dependencies,
            'message': self._cmake_message,

            # Special functions defined in the preload script.
            # These functions do nothing in the CMake code, but have special
            # meaning here in the trace parser.
            'meson_ps_execute_delayed_calls': self._meson_ps_execute_delayed_calls,
            'meson_ps_reload_vars': self._meson_ps_reload_vars,
            'meson_ps_disabled_function': self._meson_ps_disabled_function,
        }

        if version_compare(self.cmake_version, '<3.17.0'):
            mlog.deprecation(textwrap.dedent(f'''\
                CMake support for versions <3.17 is deprecated since Meson 0.62.0.
                |
                |   However, Meson was only able to find CMake {self.cmake_version}.
                |
                |   Support for all CMake versions below 3.17.0 will be removed once
                |   newer CMake versions are more widely adopted. If you encounter
                |   any errors please try upgrading CMake to a newer version first.
            '''), once=True)

    def trace_args(self) -> T.List[str]:
        arg_map = {
            'human': ['--trace', '--trace-expand'],
            'json-v1': ['--trace-expand', '--trace-format=json-v1'],
        }

        base_args = ['--no-warn-unused-cli']
        if not self.requires_stderr():
            base_args += [f'--trace-redirect={self.trace_file}']

        return arg_map[self.trace_format] + base_args

    def requires_stderr(self) -> bool:
        return version_compare(self.cmake_version, '<3.16')

    def parse(self, trace: T.Optional[str] = None) -> None:
        # First load the trace (if required)
        if not self.requires_stderr():
            if not self.trace_file_path.exists and not self.trace_file_path.is_file():
                raise CMakeException(f'CMake: Trace file "{self.trace_file_path!s}" not found')
            trace = self.trace_file_path.read_text(errors='ignore', encoding='utf-8')
        if not trace:
            raise CMakeException('CMake: The CMake trace was not provided or is empty')

        # Second parse the trace
        lexer1 = None
        if self.trace_format == 'human':
            lexer1 = self._lex_trace_human(trace)
        elif self.trace_format == 'json-v1':
            lexer1 = self._lex_trace_json(trace)
        else:
            raise CMakeException(f'CMake: Internal error: Invalid trace format {self.trace_format}. Expected [human, json-v1]')

        # Primary pass -- parse everything
        for l in lexer1:
            # store the function if its execution should be delayed
            if l.func in self.delayed_commands:
                self.stored_commands += [l]
                continue

            # "Execute" the CMake function if supported
            fn = self.functions.get(l.func, None)
            if fn:
                fn(l)

        # Evaluate generator expressions
        strlist_gen:  T.Callable[[T.List[str]], T.List[str]] = lambda strlist: parse_generator_expressions(';'.join(strlist), self).split(';') if strlist else []
        pathlist_gen: T.Callable[[T.List[str]], T.List[Path]] = lambda strlist: [Path(x) for x in parse_generator_expressions(';'.join(strlist), self).split(';')] if strlist else []

        self.vars = {k: strlist_gen(v) for k, v in self.vars.items()}
        self.vars_by_file = {
            p: {k: strlist_gen(v) for k, v in d.items()}
            for p, d in self.vars_by_file.items()
        }
        self.explicit_headers = {Path(parse_generator_expressions(str(x), self)) for x in self.explicit_headers}
        self.cache = {
            k: CMakeCacheEntry(
                strlist_gen(v.value),
                v.type
            )
            for k, v in self.cache.items()
        }

        for tgt in self.targets.values():
            tgtlist_gen: T.Callable[[T.List[str], CMakeTarget], T.List[str]] = lambda strlist, t: parse_generator_expressions(';'.join(strlist), self, context_tgt=t).split(';') if strlist else []
            tgt.name = parse_generator_expressions(tgt.name, self, context_tgt=tgt)
            tgt.type = parse_generator_expressions(tgt.type, self, context_tgt=tgt)
            tgt.properties = {
                k: tgtlist_gen(v, tgt) for k, v in tgt.properties.items()
            } if tgt.properties is not None else None
            tgt.depends = tgtlist_gen(tgt.depends, tgt)

        for ctgt in self.custom_targets:
            ctgt.outputs = pathlist_gen(ctgt._outputs_str)
            temp = ctgt.command
            ctgt.command = [strlist_gen(x) for x in ctgt.command]
            for command, src in zip(ctgt.command, temp):
                if command[0] == "":
                    raise CMakeException(
                        "We evaluated the cmake variable '{}' to an empty string, which is not a valid path to an executable.".format(src[0])
                    )
            ctgt.working_dir = Path(parse_generator_expressions(str(ctgt.working_dir), self)) if ctgt.working_dir is not None else None

        # Postprocess
        for tgt in self.targets.values():
            tgt.strip_properties()

    def get_first_cmake_var_of(self, var_list: T.List[str]) -> T.List[str]:
        # Return the first found CMake variable in list var_list
        for i in var_list:
            if i in self.vars:
                return self.vars[i]

        return []

    def get_cmake_var(self, var: str) -> T.List[str]:
        # Return the value of the CMake variable var or an empty list if var does not exist
        if var in self.vars:
            return self.vars[var]

        return []

    def var_to_str(self, var: str) -> T.Optional[str]:
        if var in self.vars and self.vars[var]:
            return self.vars[var][0]

        return None

    def _str_to_bool(self, expr: T.Union[str, T.List[str]]) -> bool:
        if not expr:
            return False
        if isinstance(expr, list):
            expr_str = expr[0]
        else:
            expr_str = expr
        expr_str = expr_str.upper()
        return expr_str not in ['0', 'OFF', 'NO', 'FALSE', 'N', 'IGNORE'] and not expr_str.endswith('NOTFOUND')

    def var_to_bool(self, var: str) -> bool:
        return self._str_to_bool(self.vars.get(var, []))

    def _gen_exception(self, function: str, error: str, tline: CMakeTraceLine) -> None:
        # Generate an exception if the parser is not in permissive mode

        if self.permissive:
            mlog.debug(f'CMake trace warning: {function}() {error}\n{tline}')
            return None
        raise CMakeException(f'CMake: {function}() {error}\n{tline}')

    def _cmake_set(self, tline: CMakeTraceLine) -> None:
        """Handler for the CMake set() function in all varieties.

        comes in three flavors:
        set(<var> <value> [PARENT_SCOPE])
        set(<var> <value> CACHE <type> <docstring> [FORCE])
        set(ENV{<var>} <value>)

        We don't support the ENV variant, and any uses of it will be ignored
        silently. the other two variates are supported, with some caveats:
        - we don't properly handle scoping, so calls to set() inside a
          function without PARENT_SCOPE set could incorrectly shadow the
          outer scope.
        - We don't honor the type of CACHE arguments
        """
        # DOC: https://cmake.org/cmake/help/latest/command/set.html

        cache_type = None
        cache_force = 'FORCE' in tline.args
        try:
            cache_idx = tline.args.index('CACHE')
            cache_type = tline.args[cache_idx + 1]
        except (ValueError, IndexError):
            pass

        # 1st remove PARENT_SCOPE and CACHE from args
        args = []
        for i in tline.args:
            if not i or i == 'PARENT_SCOPE':
                continue

            # Discard everything after the CACHE keyword
            if i == 'CACHE':
                break

            args.append(i)

        if len(args) < 1:
            return self._gen_exception('set', 'requires at least one argument', tline)

        # Now that we've removed extra arguments all that should be left is the
        # variable identifier and the value, join the value back together to
        # ensure spaces in the value are correctly handled. This assumes that
        # variable names don't have spaces. Please don't do that...
        identifier = args.pop(0)
        value = ' '.join(args)

        # Write to the CMake cache instead
        if cache_type:
            # Honor how the CMake FORCE parameter works
            if identifier not in self.cache or cache_force:
                self.cache[identifier] = CMakeCacheEntry(value.split(';'), cache_type)

        if not value:
            # Same as unset
            if identifier in self.vars:
                del self.vars[identifier]
        else:
            self.vars[identifier] = value.split(';')
            self.vars_by_file.setdefault(tline.file, {})[identifier] = value.split(';')

    def _cmake_unset(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/unset.html
        if len(tline.args) < 1:
            return self._gen_exception('unset', 'requires at least one argument', tline)

        if tline.args[0] in self.vars:
            del self.vars[tline.args[0]]

    def _cmake_add_executable(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/add_executable.html
        args = list(tline.args) # Make a working copy

        # Make sure the exe is imported
        is_imported = True
        if 'IMPORTED' not in args:
            return self._gen_exception('add_executable', 'non imported executables are not supported', tline)

        args.remove('IMPORTED')

        if len(args) < 1:
            return self._gen_exception('add_executable', 'requires at least 1 argument', tline)

        self.targets[args[0]] = CMakeTarget(args[0], 'EXECUTABLE', {}, tline=tline, imported=is_imported)

    def _cmake_add_library(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/add_library.html
        args = list(tline.args) # Make a working copy

        # Make sure the lib is imported
        if 'INTERFACE' in args:
            args.remove('INTERFACE')

            if len(args) < 1:
                return self._gen_exception('add_library', 'interface library name not specified', tline)

            self.targets[args[0]] = CMakeTarget(args[0], 'INTERFACE', {}, tline=tline, imported='IMPORTED' in args)
        elif 'IMPORTED' in args:
            args.remove('IMPORTED')

            # Now, only look at the first two arguments (target_name and target_type) and ignore the rest
            if len(args) < 2:
                return self._gen_exception('add_library', 'requires at least 2 arguments', tline)

            self.targets[args[0]] = CMakeTarget(args[0], args[1], {}, tline=tline, imported=True)
        elif 'ALIAS' in args:
            args.remove('ALIAS')

            # Now, only look at the first two arguments (target_name and target_ref) and ignore the rest
            if len(args) < 2:
                return self._gen_exception('add_library', 'requires at least 2 arguments', tline)

            # Simulate the ALIAS with INTERFACE_LINK_LIBRARIES
            self.targets[args[0]] = CMakeTarget(args[0], 'ALIAS', {'INTERFACE_LINK_LIBRARIES': [args[1]]}, tline=tline)
        elif 'OBJECT' in args:
            return self._gen_exception('add_library', 'OBJECT libraries are not supported', tline)
        else:
            self.targets[args[0]] = CMakeTarget(args[0], 'NORMAL', {}, tline=tline)

    def _cmake_add_custom_command(self, tline: CMakeTraceLine, name: T.Optional[str] = None) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/add_custom_command.html
        args = self._flatten_args(list(tline.args))  # Commands can be passed as ';' separated lists

        if not args:
            return self._gen_exception('add_custom_command', 'requires at least 1 argument', tline)

        # Skip the second function signature
        if args[0] == 'TARGET':
            return self._gen_exception('add_custom_command', 'TARGET syntax is currently not supported', tline)

        magic_keys = ['OUTPUT', 'COMMAND', 'MAIN_DEPENDENCY', 'DEPENDS', 'BYPRODUCTS',
                      'IMPLICIT_DEPENDS', 'WORKING_DIRECTORY', 'COMMENT', 'DEPFILE',
                      'JOB_POOL', 'VERBATIM', 'APPEND', 'USES_TERMINAL', 'COMMAND_EXPAND_LISTS']

        target = CMakeGeneratorTarget(name)

        def handle_output(key: str, target: CMakeGeneratorTarget) -> None:
            target._outputs_str += [key]

        def handle_command(key: str, target: CMakeGeneratorTarget) -> None:
            if key == 'ARGS':
                return
            target.command[-1] += [key]

        def handle_depends(key: str, target: CMakeGeneratorTarget) -> None:
            target.depends += [key]

        working_dir = None

        def handle_working_dir(key: str, target: CMakeGeneratorTarget) -> None:
            nonlocal working_dir
            if working_dir is None:
                working_dir = key
            else:
                working_dir += ' '
                working_dir += key

        fn = None

        for i in args:
            if i in magic_keys:
                if i == 'OUTPUT':
                    fn = handle_output
                elif i == 'DEPENDS':
                    fn = handle_depends
                elif i == 'WORKING_DIRECTORY':
                    fn = handle_working_dir
                elif i == 'COMMAND':
                    fn = handle_command
                    target.command += [[]]
                else:
                    fn = None
                continue

            if fn is not None:
                fn(i, target)

        cbinary_dir = self.var_to_str('MESON_PS_CMAKE_CURRENT_BINARY_DIR')
        csource_dir = self.var_to_str('MESON_PS_CMAKE_CURRENT_SOURCE_DIR')

        target.working_dir = Path(working_dir) if working_dir else None
        target.current_bin_dir = Path(cbinary_dir) if cbinary_dir else None
        target.current_src_dir = Path(csource_dir) if csource_dir else None
        target._outputs_str = self._guess_files(target._outputs_str)
        target.depends = self._guess_files(target.depends)
        target.command = [self._guess_files(x) for x in target.command]

        self.custom_targets += [target]
        if name:
            self.targets[name] = target

    def _cmake_add_custom_target(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/add_custom_target.html
        # We only the first parameter (the target name) is interesting
        if len(tline.args) < 1:
            return self._gen_exception('add_custom_target', 'requires at least one argument', tline)

        # It's pretty much the same as a custom command
        self._cmake_add_custom_command(tline, tline.args[0])

    def _cmake_set_property(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/set_property.html
        args = list(tline.args)

        scope = args.pop(0)

        append = False
        targets = []
        while args:
            curr = args.pop(0)
            # XXX: APPEND_STRING is specifically *not* supposed to create a
            # list, is treating them as aliases really okay?
            if curr in {'APPEND', 'APPEND_STRING'}:
                append = True
                continue

            if curr == 'PROPERTY':
                break

            targets += curr.split(';')

        if not args:
            return self._gen_exception('set_property', 'failed to parse argument list', tline)

        if len(args) == 1:
            # Tries to set property to nothing so nothing has to be done
            return

        identifier = args.pop(0)
        if self.trace_format == 'human':
            value = ' '.join(args).split(';')
        else:
            value = [y for x in args for y in x.split(';')]
        if not value:
            return

        def do_target(t: str) -> None:
            if t not in self.targets:
                return self._gen_exception('set_property', f'TARGET {t} not found', tline)

            tgt = self.targets[t]
            if identifier not in tgt.properties:
                tgt.properties[identifier] = []

            if append:
                tgt.properties[identifier] += value
            else:
                tgt.properties[identifier] = value

        def do_source(src: str) -> None:
            if identifier != 'HEADER_FILE_ONLY' or not self._str_to_bool(value):
                return

            current_src_dir = self.var_to_str('MESON_PS_CMAKE_CURRENT_SOURCE_DIR')
            if not current_src_dir:
                mlog.warning(textwrap.dedent('''\
                    CMake trace: set_property(SOURCE) called before the preload script was loaded.
                    Unable to determine CMAKE_CURRENT_SOURCE_DIR. This can lead to build errors.
                '''))
                current_src_dir = '.'

            cur_p = Path(current_src_dir)
            src_p = Path(src)

            if not src_p.is_absolute():
                src_p = cur_p / src_p
            self.explicit_headers.add(src_p)

        if scope == 'TARGET':
            for i in targets:
                do_target(i)
        elif scope == 'SOURCE':
            files = self._guess_files(targets)
            for i in files:
                do_source(i)

    def _cmake_set_target_properties(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/set_target_properties.html
        args = list(tline.args)

        targets = []
        while args:
            curr = args.pop(0)
            if curr == 'PROPERTIES':
                break

            targets.append(curr)

        # Now we need to try to reconstitute the original quoted format of the
        # arguments, as a property value could have spaces in it. Unlike
        # set_property() this is not context free. There are two approaches I
        # can think of, both have drawbacks:
        #
        #   1. Assume that the property will be capitalized ([A-Z_]), this is
        #      convention but cmake doesn't require it.
        #   2. Maintain a copy of the list here: https://cmake.org/cmake/help/latest/manual/cmake-properties.7.html#target-properties
        #
        # Neither of these is awesome for obvious reasons. I'm going to try
        # option 1 first and fall back to 2, as 1 requires less code and less
        # synchronization for cmake changes.
        #
        # With the JSON output format, introduced in CMake 3.17, spaces are
        # handled properly and we don't have to do either options

        arglist: T.List[T.Tuple[str, T.List[str]]] = []
        if self.trace_format == 'human':
            name = args.pop(0)
            values: T.List[str] = []
            prop_regex = re.compile(r'^[A-Z_]+$')
            for a in args:
                if prop_regex.match(a):
                    if values:
                        arglist.append((name, ' '.join(values).split(';')))
                    name = a
                    values = []
                else:
                    values.append(a)
            if values:
                arglist.append((name, ' '.join(values).split(';')))
        else:
            arglist = [(x[0], x[1].split(';')) for x in zip(args[::2], args[1::2])]

        for name, value in arglist:
            for i in targets:
                if i not in self.targets:
                    return self._gen_exception('set_target_properties', f'TARGET {i} not found', tline)

                self.targets[i].properties[name] = value

    def _cmake_add_dependencies(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/add_dependencies.html
        args = list(tline.args)

        if len(args) < 2:
            return self._gen_exception('add_dependencies', 'takes at least 2 arguments', tline)

        target = self.targets.get(args[0])
        if not target:
            return self._gen_exception('add_dependencies', 'target not found', tline)

        for i in args[1:]:
            target.depends += i.split(';')

    def _cmake_target_compile_definitions(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/target_compile_definitions.html
        self._parse_common_target_options('target_compile_definitions', 'COMPILE_DEFINITIONS', 'INTERFACE_COMPILE_DEFINITIONS', tline)

    def _cmake_target_compile_options(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/target_compile_options.html
        self._parse_common_target_options('target_compile_options', 'COMPILE_OPTIONS', 'INTERFACE_COMPILE_OPTIONS', tline)

    def _cmake_target_include_directories(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/target_include_directories.html
        self._parse_common_target_options('target_include_directories', 'INCLUDE_DIRECTORIES', 'INTERFACE_INCLUDE_DIRECTORIES', tline, ignore=['SYSTEM', 'BEFORE'], paths=True)

    def _cmake_target_link_options(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/target_link_options.html
        self._parse_common_target_options('target_link_options', 'LINK_OPTIONS', 'INTERFACE_LINK_OPTIONS', tline)

    def _cmake_target_link_libraries(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/target_link_libraries.html
        self._parse_common_target_options('target_link_options', 'LINK_LIBRARIES', 'INTERFACE_LINK_LIBRARIES', tline)

    def _cmake_message(self, tline: CMakeTraceLine) -> None:
        # DOC: https://cmake.org/cmake/help/latest/command/message.html
        args = list(tline.args)

        if len(args) < 1:
            return self._gen_exception('message', 'takes at least 1 argument', tline)

        if args[0].upper().strip() not in ['FATAL_ERROR', 'SEND_ERROR']:
            return

        self.errors += [' '.join(args[1:])]

    def _parse_common_target_options(self, func: str, private_prop: str, interface_prop: str, tline: CMakeTraceLine, ignore: T.Optional[T.List[str]] = None, paths: bool = False) -> None:
        if ignore is None:
            ignore = ['BEFORE']

        args = list(tline.args)

        if len(args) < 1:
            return self._gen_exception(func, 'requires at least one argument', tline)

        target = args[0]
        if target not in self.targets:
            return self._gen_exception(func, f'TARGET {target} not found', tline)

        interface = []
        private = []

        mode = 'PUBLIC'
        for i in args[1:]:
            if i in ignore:
                continue

            if i in {'INTERFACE', 'LINK_INTERFACE_LIBRARIES', 'PUBLIC', 'PRIVATE', 'LINK_PUBLIC', 'LINK_PRIVATE'}:
                mode = i
                continue

            if mode in {'INTERFACE', 'LINK_INTERFACE_LIBRARIES', 'PUBLIC', 'LINK_PUBLIC'}:
                interface += i.split(';')

            if mode in {'PUBLIC', 'PRIVATE', 'LINK_PRIVATE'}:
                private += i.split(';')

        if paths:
            interface = self._guess_files(interface)
            private = self._guess_files(private)

        interface = [x for x in interface if x]
        private = [x for x in private if x]

        for j in [(private_prop, private), (interface_prop, interface)]:
            if not j[0] in self.targets[target].properties:
                self.targets[target].properties[j[0]] = []

            self.targets[target].properties[j[0]] += j[1]

    def _meson_ps_execute_delayed_calls(self, tline: CMakeTraceLine) -> None:
        for l in self.stored_commands:
            fn = self.functions.get(l.func, None)
            if fn:
                fn(l)

        # clear the stored commands
        self.stored_commands = []

    def _meson_ps_reload_vars(self, tline: CMakeTraceLine) -> None:
        self.delayed_commands = self.get_cmake_var('MESON_PS_DELAYED_CALLS')

    def _meson_ps_disabled_function(self, tline: CMakeTraceLine) -> None:
        args = list(tline.args)
        if not args:
            mlog.error('Invalid preload.cmake script! At least one argument to `meson_ps_disabled_function` is expected')
            return
        mlog.warning(f'The CMake function "{args[0]}" was disabled to avoid compatibility issues with Meson.')

    def _lex_trace_human(self, trace: str) -> T.Generator[CMakeTraceLine, None, None]:
        # The trace format is: '<file>(<line>):  <func>(<args -- can contain \n> )\n'
        reg_tline = re.compile(r'\s*(.*\.(cmake|txt))\(([0-9]+)\):\s*(\w+)\(([\s\S]*?) ?\)\s*\n', re.MULTILINE)
        reg_other = re.compile(r'[^\n]*\n')
        loc = 0
        while loc < len(trace):
            mo_file_line = reg_tline.match(trace, loc)
            if not mo_file_line:
                skip_match = reg_other.match(trace, loc)
                if not skip_match:
                    print(trace[loc:])
                    raise CMakeException('Failed to parse CMake trace')

                loc = skip_match.end()
                continue

            loc = mo_file_line.end()

            file = mo_file_line.group(1)
            line = mo_file_line.group(3)
            func = mo_file_line.group(4)
            args = mo_file_line.group(5)
            argl = args.split(' ')
            argl = [a.strip() for a in argl]

            yield CMakeTraceLine(file, int(line), func, argl)

    def _lex_trace_json(self, trace: str) -> T.Generator[CMakeTraceLine, None, None]:
        lines = trace.splitlines(keepends=False)
        lines.pop(0)  # The first line is the version
        for i in lines:
            data = json.loads(i)
            assert isinstance(data['file'], str)
            assert isinstance(data['line'], int)
            assert isinstance(data['cmd'],  str)
            assert isinstance(data['args'], list)
            args = data['args']
            for j in args:
                assert isinstance(j, str)
            yield CMakeTraceLine(data['file'], data['line'], data['cmd'], args)

    def _flatten_args(self, args: T.List[str]) -> T.List[str]:
        # Split lists in arguments
        res: T.List[str] = []
        for i in args:
            res += i.split(';')
        return res

    def _guess_files(self, broken_list: T.List[str]) -> T.List[str]:
        # Nothing has to be done for newer formats
        if self.trace_format != 'human':
            return broken_list

        # Try joining file paths that contain spaces

        reg_start = re.compile(r'^([A-Za-z]:)?/(.*/)*[^./]+$')
        reg_end = re.compile(r'^.*\.[a-zA-Z]+$')

        fixed_list: T.List[str] = []
        curr_str: T.Optional[str] = None
        path_found = False

        for i in broken_list:
            if curr_str is None:
                curr_str = i
                path_found = False
            elif Path(curr_str).is_file():
                # Abort concatenation if curr_str is an existing file
                fixed_list += [curr_str]
                curr_str = i
                path_found = False
            elif not reg_start.match(curr_str):
                # Abort concatenation if curr_str no longer matches the regex
                fixed_list += [curr_str]
                curr_str = i
                path_found = False
            elif reg_end.match(i):
                # File detected
                curr_str = f'{curr_str} {i}'
                fixed_list +=
"""


```