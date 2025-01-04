Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding & Purpose:**

The first step is to read the docstring at the beginning. It clearly states the file's purpose: parsing CMake trace output for the Frida dynamic instrumentation tool. This immediately tells us it's about understanding how a CMake build process unfolds.

**2. Core Classes and Their Roles:**

Next, I'd identify the main classes and what they represent:

*   `CMakeTraceLine`: Represents a single line in the CMake trace, capturing the file, line number, function name, and arguments. This is the fundamental unit of the trace.
*   `CMakeCacheEntry`: Represents an entry in the CMake cache, storing the value and type of a cached variable.
*   `CMakeTarget`: Represents a CMake target (executable, library, etc.), storing its name, type, properties, dependencies, and related trace information.
*   `CMakeGeneratorTarget`: A specialized `CMakeTarget` for custom commands/targets, including outputs, commands, and working directory.
*   `CMakeTraceParser`: The central class, responsible for parsing the entire trace, managing variables, targets, and cache information.

**3. Key Data Structures within `CMakeTraceParser`:**

Within the `CMakeTraceParser`, I'd note the important data structures:

*   `vars`: A dictionary storing CMake variables and their values.
*   `vars_by_file`:  Variables, but organized by the file where they were set.
*   `targets`:  A dictionary of `CMakeTarget` objects, keyed by name.
*   `cache`:  A dictionary of `CMakeCacheEntry` objects.
*   `custom_targets`: A list of `CMakeGeneratorTarget` objects.
*   `functions`: A dictionary mapping CMake function names to their corresponding handler methods in the parser.

**4. Functionality by Examining Methods:**

Now, I'd go through the methods in `CMakeTraceParser` to understand the actions it performs:

*   `__init__`:  Initialization, setting up data structures, and determining the trace format based on the CMake version.
*   `trace_args`:  Constructs the necessary command-line arguments for CMake to generate the trace.
*   `requires_stderr`: Determines if the trace is output to stderr (older CMake versions).
*   `parse`: The core parsing logic. It reads the trace, iterates through lines, and calls the appropriate handler functions based on the CMake command. It also handles generator expressions.
*   `get_first_cmake_var_of`, `get_cmake_var`, `var_to_str`, `var_to_bool`: Methods for accessing CMake variable values.
*   `_cmake_*`: A large set of methods (e.g., `_cmake_set`, `_cmake_add_executable`, `_cmake_target_link_libraries`) that handle specific CMake commands. These are crucial for understanding how the parser interprets the trace.
*   `_lex_trace_human`, `_lex_trace_json`:  Methods for reading and tokenizing the trace data in different formats.
*   `_flatten_args`, `_guess_files`: Utility methods for processing command arguments and attempting to fix file paths with spaces.
*   `_meson_ps_*`:  Special functions likely introduced by Frida's build system to control the trace parsing.

**5. Identifying Connections to Reverse Engineering, Binary/Kernel Knowledge:**

At this point, the connection to reverse engineering becomes apparent. Frida is a dynamic instrumentation tool used for reverse engineering and security analysis. This parser's purpose is to understand how the target application (built with CMake) is structured. This information can then be used by Frida to inject code, hook functions, and observe behavior.

The code itself doesn't directly manipulate binaries or interact with the kernel *within this file*. However, the *information* it extracts (target names, dependencies, compile options, link libraries) is essential for tools like Frida that *do* operate at that level. The mention of Linux and Android kernel/framework arises because Frida is commonly used on these platforms, and the CMake build process will reflect that (e.g., linking against system libraries).

**6. Logical Inference and Error Handling:**

I'd look for methods that perform logic, such as `_str_to_bool` which converts CMake boolean strings. The error handling (`_gen_exception`) and the permissive mode are also important to note.

**7. User Interaction (Debugging Clues):**

The `trace_args` method gives a clue about how a user would initiate the trace generation. They would need to run CMake with specific arguments (`--trace`, `--trace-expand`, `--trace-format`). The code also reveals the expected location and name of the trace file (`cmake_trace.txt`). If the trace file is missing or empty, the `parse` method will raise an exception, indicating a potential user error.

**8. Synthesizing the Functionality:**

Finally, I'd synthesize all the observations into a concise summary of the file's functionality. This would involve combining the purpose, the roles of the main classes, and the key actions performed by the methods.

**Self-Correction/Refinement During Analysis:**

*   **Initial Misunderstanding:** I might initially think the parser directly interacts with the build process. However, closer inspection reveals it *consumes* the output of a *completed* CMake run.
*   **Granularity:**  I would start with a high-level overview and then delve into the specifics of each method.
*   **Assumptions:** I'd note any assumptions made by the code, like the capitalization of CMake properties in older versions.
*   **Context:** I'd constantly keep in mind the context of Frida and its use cases to understand the *why* behind the parser's design.

This iterative process of reading, identifying key components, understanding their roles, and connecting them back to the overall purpose, along with attention to error handling and user interaction, allows for a comprehensive analysis of the code.
好的，让我们来分析一下 `frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/traceparser.py` 文件的功能。

**文件主要功能归纳：**

这个 Python 文件的主要功能是**解析 CMake 的跟踪 (trace) 输出**，提取构建过程中的关键信息，并将其结构化表示出来。 这些信息包括：

1. **CMake 变量及其值**:  跟踪 `set` 和 `unset` 命令，记录 CMake 变量的设置和取消设置。
2. **构建目标 (Targets)**:  识别并记录 `add_executable`、`add_library`、`add_custom_command` 和 `add_custom_target` 定义的构建目标，包括它们的名称、类型、以及是否是导入的 (imported)。
3. **目标属性 (Target Properties)**:  解析 `set_property` 和 `set_target_properties` 命令，获取目标的各种属性，例如编译定义、编译选项、包含目录、链接库等。
4. **目标依赖 (Target Dependencies)**:  通过 `add_dependencies` 命令记录目标之间的依赖关系。
5. **CMake 缓存 (Cache)**:  解析 `set` 命令中 `CACHE` 关键字的使用，记录 CMake 缓存中的变量及其类型。
6. **自定义命令 (Custom Commands)**: 详细解析 `add_custom_command`，提取其输出文件、执行的命令、依赖项和工作目录等信息。
7. **错误信息**: 捕获 CMake `message` 命令中 `FATAL_ERROR` 或 `SEND_ERROR` 级别的错误信息。
8. **处理生成器表达式**: 解析 CMake 生成器表达式，以便更好地理解变量和属性的值。

**与逆向方法的关联及举例说明：**

这个文件与逆向方法密切相关，因为它帮助理解目标程序是如何被构建的。在逆向工程中，理解构建过程可以提供以下信息：

*   **目标文件的类型和名称**: 知道哪些可执行文件和库被构建出来，以及它们的命名方式。这对于后续查找和分析目标文件至关重要。
*   **编译选项和定义**:  了解编译时使用的选项（例如优化级别、架构特定选项）和预定义的宏。这些信息有助于理解代码的编译方式，可能会揭示某些功能的开启或关闭。例如，如果逆向一个被 strip 过的二进制文件，了解其是否在编译时启用了调试信息 (`-g`)  虽然已经移除，但可以推断其开发过程。
*   **依赖库**:  确定目标程序依赖哪些库。这可以帮助逆向工程师识别可能被利用的第三方库，或者理解程序的模块化结构。例如，如果一个 Android 应用依赖了某个加密库，逆向工程师可能会重点关注与该库的交互部分。
*   **自定义构建步骤**:  `add_custom_command` 可以定义一些非标准的构建步骤，理解这些步骤有助于了解最终生成文件的来源和处理过程。例如，一个自定义命令可能用于代码混淆或加密，理解这个步骤对于逆向至关重要。

**举例说明：**

假设 CMake 跟踪文件中包含以下几行：

```
/path/to/CMakeLists.txt(10):  add_executable(my_app IMPORTED my_imported_app)
/path/to/CMakeLists.txt(15):  set_target_properties(my_app PROPERTIES COMPILE_DEFINITIONS DEBUG_MODE)
/path/to/CMakeLists.txt(20):  target_link_libraries(my_app my_library)
```

`traceparser.py` 解析后，会生成类似以下的内部数据结构：

*   `targets['my_app']`:  一个 `CMakeTarget` 对象，其 `type` 为 `'EXECUTABLE'`，`imported` 为 `True`，并且具有属性 `properties['COMPILE_DEFINITIONS'] = ['DEBUG_MODE']`，以及依赖 `depends = ['my_library']`。

逆向工程师通过分析这些信息可以得知：

*   存在一个名为 `my_app` 的可执行文件，它是通过 `IMPORTED` 关键字引入的，可能代表一个预编译的二进制文件。
*   在编译 `my_app` 时定义了 `DEBUG_MODE` 宏，暗示了可能存在调试相关的代码分支。
*   `my_app` 链接了 `my_library` 库。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

虽然 `traceparser.py` 本身不直接操作二进制或内核，但它解析的信息反映了构建过程中的底层细节和平台相关的知识：

*   **二进制底层**:  `add_executable` 和 `add_library` 最终会生成二进制文件（可执行文件或库）。解析这些命令以及相关的链接选项 (`target_link_libraries`) 可以了解二进制文件的类型、依赖关系以及可能的架构 (`CMAKE_SYSTEM_PROCESSOR` 变量)。
*   **Linux**: 在 Linux 环境下构建的程序，其链接库 (`target_link_libraries`) 可能会包含如 `pthread` (线程库)、`dl` (动态链接库管理) 等 Linux 特有的库。解析这些信息可以了解程序与 Linux 系统功能的交互。
*   **Android 内核及框架**:  如果 Frida 用于 Android 平台的逆向，CMake 构建过程可能会涉及到 Android NDK 和 Android 框架库。`traceparser.py` 可以解析出链接的 Android 系统库（例如 `log` 用于日志输出）。例如，如果 `target_link_libraries` 中出现了 `android` 或特定的 Android framework 库，则表明这是一个 Android 应用或组件。

**举例说明：**

如果 CMake 跟踪中包含：

```
/path/to/CMakeLists.txt(30):  target_link_libraries(my_android_app log android)
```

解析后，`targets['my_android_app'].depends` 将包含 `log` 和 `android`。逆向工程师由此可以判断 `my_android_app` 是一个 Android 应用，并使用了 Android 的日志功能。

**逻辑推理、假设输入与输出：**

`traceparser.py` 做了很多逻辑推理，例如：

*   **解析参数**:  它需要根据 CMake 命令的语法规则解析参数列表，例如 `set` 命令的不同形式。
*   **关联信息**:  将 `set_target_properties` 命令关联到之前定义的 `add_executable` 或 `add_library` 目标。
*   **处理 `IMPORTED` 目标**:  识别并标记导入的目标。

**假设输入：**

假设 CMake 跟踪文件 `cmake_trace.txt` 包含以下内容（`trace_format` 为 `human`）：

```
/path/to/CMakeLists.txt(5):  set(MY_VAR my_value)
/path/to/CMakeLists.txt(10): add_executable(my_program my_program.c)
/path/to/CMakeLists.txt(15): set_target_properties(my_program PROPERTIES OUTPUT_NAME "renamed_program")
```

**输出：**

`CMakeTraceParser` 解析后，内部状态会包含：

*   `self.vars['MY_VAR'] = ['my_value']`
*   `self.targets['my_program']`:  一个 `CMakeTarget` 对象，其 `type` 为 `'EXECUTABLE'`，`properties['OUTPUT_NAME'] = ['renamed_program']`。

**涉及用户或者编程常见的使用错误及举例说明：**

*   **CMake 跟踪未启用或格式不正确**: 用户需要确保在运行 CMake 时使用了正确的跟踪参数（如 `--trace`, `--trace-expand`, `--trace-format=json-v1` 或 `--trace-format=human`）。如果跟踪文件不存在或格式不符合预期，`parse` 方法会抛出 `CMakeException`。

    **用户操作步骤导致错误：** 用户在构建 Frida 或其依赖项时，没有配置 CMake 以生成跟踪文件，或者使用了错误的 CMake 版本（不支持所需的跟踪格式）。

*   **CMake 脚本错误导致跟踪不完整**: 如果 CMake 脚本本身存在语法错误或逻辑错误，导致构建过程提前终止，那么生成的跟踪文件可能不完整，`traceparser.py` 可能无法解析到所有预期的信息。

    **用户操作步骤导致错误：** 用户修改了 Frida 的 CMake 构建脚本，引入了语法错误，导致 CMake 执行失败，跟踪文件不完整。

*   **依赖于特定 CMake 版本的特性**:  `traceparser.py` 需要根据 CMake 的版本来处理不同的跟踪格式。如果用户使用的 CMake 版本与 `traceparser.py` 的预期不符，可能会导致解析错误。

    **用户操作步骤导致错误：** 用户使用的 CMake 版本过旧，不支持 JSON 格式的跟踪，而 `traceparser.py` 尝试以 JSON 格式解析，导致错误。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 的构建过程**: 用户尝试构建 Frida 或其 Python 绑定。Frida 的构建系统使用 Meson 作为元构建系统。
2. **Meson 调用 CMake**: Meson 会根据 `meson.build` 文件中的配置，调用 CMake 来处理特定的子项目或外部依赖。
3. **启用 CMake 跟踪**: 为了让 `traceparser.py` 工作，Meson 在调用 CMake 时会传递特定的参数来启用跟踪功能。这通常在 Frida 的构建脚本中配置。例如，可能在 Meson 的配置中设置了 `cmake_trace = true` 这样的选项。
4. **CMake 生成跟踪文件**: CMake 执行构建过程，并将跟踪信息输出到指定的文件（默认为 `cmake_trace.txt`）。
5. **`traceparser.py` 被调用**:  Frida 的构建系统中的某个步骤会调用 `traceparser.py`，并将生成的 CMake 跟踪文件的内容传递给它。
6. **解析和使用跟踪信息**: `traceparser.py` 解析跟踪文件，提取构建信息，并将其用于 Frida 构建过程的后续步骤，例如理解依赖关系、生成特定的构建文件等。

**调试线索：**

如果 `traceparser.py` 出现问题，以下是一些可能的调试线索：

*   **检查 CMake 版本**: 确认使用的 CMake 版本是否与 `traceparser.py` 兼容。
*   **检查 CMake 跟踪文件**:  查看 `cmake_trace.txt` 文件是否存在，是否为空，以及其内容是否符合预期的 CMake 跟踪格式。
*   **检查 Meson 构建配置**: 确认 Meson 是否正确配置了 CMake 跟踪选项。
*   **查看 Frida 构建日志**:  Frida 的构建日志可能会包含与 CMake 跟踪相关的错误信息。
*   **手动运行 CMake 并检查跟踪输出**:  可以尝试手动运行 CMake 命令并添加跟踪参数，以验证 CMake 本身是否能正确生成跟踪信息。

**总结 `traceparser.py` 的功能：**

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/traceparser.py` 是 Frida 构建系统中的一个关键组件，它的核心功能是**解析 CMake 的构建跟踪输出，从中提取关键的构建信息，为 Frida 的构建过程提供必要的上下文和依赖关系数据**。 这对于理解 Frida 的构建过程，处理依赖，以及进行一些高级的构建操作至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/traceparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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