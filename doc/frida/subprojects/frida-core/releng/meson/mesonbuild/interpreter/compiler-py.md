Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understanding the Goal:** The request asks for an analysis of a specific Python file (`compiler.py`) within the Frida project. The key aspects are its functionality, relation to reverse engineering, interaction with low-level concepts, logical reasoning, potential user errors, debugging hints, and a summary of its purpose. The "Part 1 of 2" suggests this is a large file, so focusing on the provided snippet is crucial.

2. **Initial Code Scan and High-Level Overview:**  The first step is to quickly read through the code, identifying key elements:
    * **Imports:**  See a lot of imports from the same project (`..build`, `..coredata`, etc.) and standard Python libraries (`collections`, `enum`, `os`, `typing`). This suggests the file is part of a larger system and deals with compiler-related tasks.
    * **Class `CompilerHolder`:** This is the central class and seems to be wrapping or representing a compiler object. It has methods like `compiles_method`, `links_method`, `has_function_method`, etc. These names strongly indicate interactions with a compiler.
    * **Decorators:**  See `@typed_pos_args`, `@typed_kwargs`, `@noPosargs`, `@noKwargs`, `@FeatureNew`, `@disablerIfNotFound`. These decorators modify the behavior of the methods and likely handle argument parsing, versioning, and conditional disabling.
    * **Type Hints:**  Extensive use of type hints (`T.List`, `T.Optional`, `TypedDict`). This is a good sign for code clarity and maintainability, and it also gives clues about the data types involved.
    * **Logging:**  The `mlog` module is used for logging messages, indicating that the code performs checks and provides feedback to the user.

3. **Inferring Functionality Based on Method Names:** This is a crucial step. The method names are very descriptive:
    * `compiles_method`, `links_method`:  Likely check if code compiles or links successfully.
    * `has_function_method`, `has_member_method`, `has_type_method`: Check for the existence of functions, members of structures, or types.
    * `compute_int_method`, `sizeof_method`, `get_define_method`:  Retrieve information about the target environment (integer values, sizes of types, preprocessor definitions).
    * `check_header_method`, `has_header_method`, `has_header_symbol_method`: Check for the availability of header files and symbols within them.
    * `run_method`: Executes code.
    * `find_library_method`: Searches for external libraries.
    * `has_argument_method`, `get_supported_arguments_method`:  Deals with compiler arguments.

4. **Connecting to Reverse Engineering:**  Based on the functionality, connections to reverse engineering become apparent:
    * **Target Environment Discovery:**  Checking for headers, symbols, function existence, type sizes – this is crucial when you're working with a compiled target (which is common in reverse engineering). You need to understand its capabilities and structure.
    * **Compiler Argument Manipulation:**  Understanding how the target was compiled (or how to recompile it with modifications) is essential. The methods related to compiler arguments are relevant here.
    * **Dynamic Instrumentation (Frida Context):** Given the file path and the Frida context, these compiler checks are likely used to prepare for or validate code that will be injected into a running process.

5. **Identifying Low-Level Concepts:** The method names and the context point to low-level concepts:
    * **Binary Structure:** `sizeof`, `has_member` directly relate to the layout of data in memory.
    * **Operating System and Kernel:** Header files often provide interfaces to OS and kernel functionalities. Checking for their existence is vital.
    * **Compiler Behavior:**  The functions check compiler-specific features and flags.
    * **Linking:** `links_method`, `find_library_method` deal with the linking process, a fundamental step in creating executables.

6. **Logical Reasoning (Hypothetical Input/Output):**  Consider a few examples:
    * **`has_function_method("pthread_create")`:**  *Input:*  Function name "pthread_create". *Possible Output:* `True` (if the target environment has POSIX threads) or `False` (if not).
    * **`sizeof_method("int")`:** *Input:* Type name "int". *Possible Output:* `4` (on a 32-bit or some 64-bit systems), `8` (on other 64-bit systems). The output depends on the target architecture.
    * **`compiles_method("int main() { return 0; }")`:** *Input:*  Simple C code. *Possible Output:* `True` (if the compiler can compile it) or `False` (if there are syntax errors or the compiler is not configured).

7. **Potential User Errors:** Think about how a user interacting with Frida's scripting API (which likely uses these functions internally) might make mistakes:
    * **Incorrect Header Name:**  `has_header_method("UnlikelyHeader.h")` would likely return `False`.
    * **Typo in Function Name:** `has_function_method("ptread_create")` would likely return `False`.
    * **Missing Dependencies:** If a library requires another, and it's not specified in the `dependencies` kwarg, `links_method` or `find_library_method` might fail.
    * **Incorrect Compiler Arguments:** Providing incorrect arguments in the `args` kwarg might lead to compilation or linking errors.

8. **Debugging Clues (User Operation to Reach the Code):**  Imagine a Frida script:
    * The user might start by attaching to a process.
    * The script might then use Frida's API to query information about the target process's environment. This is where the functions in `compiler.py` would be invoked. For example, `Process.findModuleByName("libc.so").enumerateExports()` might internally trigger checks related to header files and symbol existence if Frida needs to compile a snippet of code to interact with those exports. Or a user might explicitly use a Frida API that uses these compiler checks to determine compatibility before attempting an injection.

9. **Summarizing Functionality (Part 1):** Based on the above analysis, the key functions of this code snippet are:
    * **Abstracting Compiler Interactions:** It provides a Python interface to various compiler functionalities.
    * **Environment Probing:** It allows checking for the presence of headers, functions, types, and preprocessor definitions.
    * **Code Compilation and Linking Checks:** It enables testing whether code snippets can be compiled and linked against the target environment.
    * **Dependency Management:** It handles dependencies required for compilation and linking checks.
    * **Facilitating Conditional Logic:** The results of these checks can be used to make decisions within the Frida scripting environment.

10. **Iterative Refinement:**  Review the code and the analysis. Are there any details missed?  For example, the decorators provide valuable information about when certain features were introduced. The `mlog` output shows how the checks are reported to the user. Ensure the explanation is clear and concise.

This systematic approach, starting with a high-level understanding and progressively drilling down into the details, helps in effectively analyzing and explaining the functionality of a code snippet like this.
这是 frida 动态 instrumentation 工具的源代码文件 `compiler.py` 的一部分，它属于 Meson 构建系统的解释器部分，专门处理与编译器相关的操作。让我们分解一下它的功能：

**主要功能归纳:**

1. **编译器能力探测:**  该文件定义了一个 `CompilerHolder` 类，它封装了对底层编译器对象的操作。其核心功能是允许 Frida 的构建系统 (使用 Meson) **探测目标环境的编译器能力**。这包括检查编译器是否支持特定的语言特性、头文件、库、函数、类型、成员变量等等。

2. **编译和链接测试:**  它提供了方法来 **编译和链接代码片段**，以验证编译环境的有效性以及特定代码是否能在目标环境下成功编译和链接。

3. **获取编译器信息:**  可以获取编译器的版本、ID、命令行参数等基本信息。

4. **条件编译和构建逻辑:**  这些探测结果被 Frida 的构建系统用来 **决定如何构建 Frida 的各个组件**，例如根据目标环境的特性选择不同的编译选项或包含不同的代码。

**与逆向方法的关系及举例说明:**

该文件直接服务于 Frida 这样的动态 instrumentation 工具，而动态 instrumentation 本身就是一种重要的逆向分析技术。

* **探测目标环境的 API 可用性:**  在逆向分析中，我们常常需要在目标进程中调用某些 API。该文件可以帮助 Frida 确定目标环境下是否存在特定的函数 (例如 `pthread_create`) 或头文件 (例如 `unistd.h`)，从而决定是否可以使用依赖于这些 API 的功能。

   * **例子:**  假设 Frida 需要在目标 Android 进程中调用 `getpid()` 函数。`has_function_method("getpid")` 方法会被调用，如果返回 `True`，则说明目标环境支持该函数，Frida 可以安全地尝试调用它。

* **确定数据结构的大小和布局:**  逆向分析经常需要理解目标进程中使用的数据结构。`sizeof_method` 和 `has_member_method` 可以帮助 Frida 确定目标环境下特定数据类型的大小 (例如 `sizeof(int)`) 以及结构体成员的偏移量。

   * **例子:**  假设你需要分析一个目标 Linux 进程中 `struct sockaddr_in` 的布局。你可以使用 `sizeof_method("struct sockaddr_in")` 来获取该结构体的大小，并使用 `has_member_method("struct sockaddr_in", "sin_port")` 来检查是否存在 `sin_port` 成员。

* **检查编译器的特定行为:** 不同的编译器可能对代码有不同的解释或使用不同的命名约定。`symbols_have_underscore_prefix_method` 可以检查 C 符号是否以下划线开头，这在处理跨平台兼容性时很重要。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

该文件虽然是 Python 代码，但其背后的操作和探测涉及底层的编译和链接过程，以及目标操作系统的知识。

* **二进制底层:**  `sizeof_method` 实际上是在目标环境下编译并运行一小段代码来获取类型的大小，这直接关系到二进制数据在内存中的表示。

   * **例子:**  在 32 位系统上，`sizeof("int")` 可能返回 4，而在 64 位系统上可能返回 8。这个信息对于理解内存布局至关重要。

* **Linux/Android 内核:**  `check_header_method` 和 `has_header_method` 经常用于检查是否存在 Linux 或 Android 内核提供的头文件 (例如 `sys/types.h`, `linux/ioctl.h`)。这些头文件定义了与内核交互的接口。

   * **例子:**  Frida 可能需要检查是否存在 `asm/unistd.h` 头文件来确定目标 Linux 内核的系统调用号。

* **Android 框架:**  在 Android 逆向中，检查特定的 Android 框架头文件或函数也是常见的需求。例如，检查是否存在 `android/log.h` 头文件或 `__android_log_print` 函数。

   * **例子:**  Frida 可以使用 `has_header_method("android/log.h")` 来判断目标进程是否使用了 Android 的日志系统。

**逻辑推理、假设输入与输出:**

这些方法通常会编译并运行一些小的测试代码来验证特性。

* **假设输入:** 调用 `has_function_method("malloc")`
* **输出:** `True` (如果目标环境存在 `malloc` 函数) 或 `False` (如果不存在，虽然这种情况很罕见)。

* **假设输入:** 调用 `sizeof_method("size_t")`
* **输出:**  `4` 或 `8`，取决于目标系统的架构是 32 位还是 64 位。

* **假设输入:** 调用 `check_header_method("nonexistent_header.h")`
* **输出:** `False`

**涉及用户或编程常见的使用错误及举例说明:**

用户通常不会直接操作这个 Python 文件，但他们在使用 Frida 的 API 时，可能会间接地触发这里的代码。

* **错误的头文件名:** 如果用户在 Frida 脚本中尝试检查一个不存在的头文件，例如 `compiler.has_header("wrong_header.h")`，那么 `has_header_method` 将返回 `False`。

* **拼写错误的函数名:** 类似地，如果用户检查一个拼写错误的函数，例如 `compiler.has_function("getpidd")`，将会返回 `False`。

* **缺少必要的依赖:** 在进行编译或链接测试时，如果目标代码依赖于某个库，但用户没有在 `dependencies` 参数中指定，那么 `compiles_method` 或 `links_method` 可能会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户编写 Frida 脚本并运行时，Frida 内部会使用 Meson 构建系统来管理一些编译相关的任务。以下是一个可能的流程：

1. **用户编写 Frida 脚本:**  脚本中可能包含一些需要了解目标环境信息的操作，例如查找模块、枚举导出函数等。

2. **Frida 脚本执行:** Frida 的 runtime 会解析脚本。

3. **内部调用 Meson 的构建逻辑:** 当 Frida 需要进行与编译相关的检查时 (例如，为了注入代码，可能需要先编译一小段桥接代码)，它会调用 Meson 提供的接口。

4. **Meson 解释器执行:** Meson 的解释器会读取构建定义文件 (通常是 `meson.build`)，其中可能包含对编译器进行探测的调用。

5. **调用 `compiler.py` 中的方法:**  Meson 解释器会执行 `meson.build` 文件中与编译器相关的指令，这会导致调用 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/compiler.py` 文件中定义的方法，例如 `has_function_method` 或 `sizeof_method`。

6. **实际的编译器调用:** 这些方法会调用底层的编译器 (例如 GCC 或 Clang) 来执行实际的检查。

7. **结果返回:** 编译器的输出和返回码会被解析，并将结果返回给 Meson 解释器，最终传递回 Frida runtime。

**总结一下它的功能 (针对第 1 部分):**

`compiler.py` 文件的主要功能是为 Frida 的构建系统提供了一个 **抽象层来与目标环境的编译器进行交互**。它允许 Frida 在构建过程中 **探测目标环境的编译能力**，包括检查头文件、函数、类型、成员变量的存在性以及进行代码的编译和链接测试。这些信息对于 Frida **动态地适应不同的目标环境** 并确保其功能的正常运行至关重要。它充当了 Frida 构建系统和底层编译器之间的桥梁，使得 Frida 能够根据目标环境的特性做出智能的构建决策。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/compiler.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2021 The Meson development team
# Copyright © 2021 Intel Corporation
from __future__ import annotations

import collections
import enum
import functools
import os
import itertools
import typing as T

from .. import build
from .. import coredata
from .. import dependencies
from .. import mesonlib
from .. import mlog
from ..compilers import SUFFIX_TO_LANG
from ..compilers.compilers import CompileCheckMode
from ..interpreterbase import (ObjectHolder, noPosargs, noKwargs,
                               FeatureNew, FeatureNewKwargs, disablerIfNotFound,
                               InterpreterException)
from ..interpreterbase.decorators import ContainerTypeInfo, typed_kwargs, KwargInfo, typed_pos_args
from ..mesonlib import OptionKey
from .interpreterobjects import (extract_required_kwarg, extract_search_dirs)
from .type_checking import REQUIRED_KW, in_set_validator, NoneType

if T.TYPE_CHECKING:
    from ..interpreter import Interpreter
    from ..compilers import Compiler, RunResult
    from ..interpreterbase import TYPE_var, TYPE_kwargs
    from .kwargs import ExtractRequired, ExtractSearchDirs
    from .interpreter import SourceOutputs
    from ..mlog import TV_LoggableList

    from typing_extensions import TypedDict, Literal

    class GetSupportedArgumentKw(TypedDict):

        checked: Literal['warn', 'require', 'off']

    class AlignmentKw(TypedDict):

        prefix: str
        args: T.List[str]
        dependencies: T.List[dependencies.Dependency]

    class BaseCompileKW(TypedDict):
        no_builtin_args: bool
        include_directories: T.List[build.IncludeDirs]
        args: T.List[str]

    class CompileKW(BaseCompileKW):

        name: str
        dependencies: T.List[dependencies.Dependency]
        werror: bool

    class CommonKW(BaseCompileKW):

        prefix: str
        dependencies: T.List[dependencies.Dependency]

    class ComputeIntKW(CommonKW):

        guess: T.Optional[int]
        high: T.Optional[int]
        low: T.Optional[int]

    class HeaderKW(CommonKW, ExtractRequired):
        pass

    class HasKW(CommonKW, ExtractRequired):
        pass

    class HasArgumentKW(ExtractRequired):
        pass

    class FindLibraryKW(ExtractRequired, ExtractSearchDirs):

        disabler: bool
        has_headers: T.List[str]
        static: bool

        # This list must be all of the `HeaderKW` values with `header_`
        # prepended to the key
        header_args: T.List[str]
        header_dependencies: T.List[dependencies.Dependency]
        header_include_directories: T.List[build.IncludeDirs]
        header_no_builtin_args: bool
        header_prefix: str
        header_required: T.Union[bool, coredata.UserFeatureOption]

    class PreprocessKW(TypedDict):
        output: str
        compile_args: T.List[str]
        include_directories: T.List[build.IncludeDirs]
        dependencies: T.List[dependencies.Dependency]
        depends: T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]


class _TestMode(enum.Enum):

    """Whether we're doing a compiler or linker check."""

    COMPILER = 0
    LINKER = 1


class TryRunResultHolder(ObjectHolder['RunResult']):
    def __init__(self, res: 'RunResult', interpreter: 'Interpreter'):
        super().__init__(res, interpreter)
        self.methods.update({'returncode': self.returncode_method,
                             'compiled': self.compiled_method,
                             'stdout': self.stdout_method,
                             'stderr': self.stderr_method,
                             })

    @noPosargs
    @noKwargs
    def returncode_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> int:
        return self.held_object.returncode

    @noPosargs
    @noKwargs
    def compiled_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.held_object.compiled

    @noPosargs
    @noKwargs
    def stdout_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.held_object.stdout

    @noPosargs
    @noKwargs
    def stderr_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.held_object.stderr


_ARGS_KW: KwargInfo[T.List[str]] = KwargInfo(
    'args',
    ContainerTypeInfo(list, str),
    listify=True,
    default=[],
)
_DEPENDENCIES_KW: KwargInfo[T.List['dependencies.Dependency']] = KwargInfo(
    'dependencies',
    ContainerTypeInfo(list, dependencies.Dependency),
    listify=True,
    default=[],
)
_DEPENDS_KW: KwargInfo[T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]] = KwargInfo(
    'depends',
    ContainerTypeInfo(list, (build.BuildTarget, build.CustomTarget, build.CustomTargetIndex)),
    listify=True,
    default=[],
)
_INCLUDE_DIRS_KW: KwargInfo[T.List[build.IncludeDirs]] = KwargInfo(
    'include_directories',
    ContainerTypeInfo(list, build.IncludeDirs),
    default=[],
    listify=True,
)
_PREFIX_KW: KwargInfo[str] = KwargInfo(
    'prefix',
    (str, ContainerTypeInfo(list, str)),
    default='',
    since_values={list: '1.0.0'},
    convertor=lambda x: '\n'.join(x) if isinstance(x, list) else x)

_NO_BUILTIN_ARGS_KW = KwargInfo('no_builtin_args', bool, default=False)
_NAME_KW = KwargInfo('name', str, default='')
_WERROR_KW = KwargInfo('werror', bool, default=False, since='1.3.0')

# Many of the compiler methods take this kwarg signature exactly, this allows
# simplifying the `typed_kwargs` calls
_COMMON_KWS: T.List[KwargInfo] = [_ARGS_KW, _DEPENDENCIES_KW, _INCLUDE_DIRS_KW, _PREFIX_KW, _NO_BUILTIN_ARGS_KW]

# Common methods of compiles, links, runs, and similar
_COMPILES_KWS: T.List[KwargInfo] = [_NAME_KW, _ARGS_KW, _DEPENDENCIES_KW, _INCLUDE_DIRS_KW, _NO_BUILTIN_ARGS_KW,
                                    _WERROR_KW]

_HEADER_KWS: T.List[KwargInfo] = [REQUIRED_KW.evolve(since='0.50.0', default=False), *_COMMON_KWS]
_HAS_REQUIRED_KW = REQUIRED_KW.evolve(since='1.3.0', default=False)

class CompilerHolder(ObjectHolder['Compiler']):
    preprocess_uid: T.Dict[str, itertools.count] = collections.defaultdict(itertools.count)

    def __init__(self, compiler: 'Compiler', interpreter: 'Interpreter'):
        super().__init__(compiler, interpreter)
        self.environment = self.env
        self.methods.update({'compiles': self.compiles_method,
                             'links': self.links_method,
                             'get_id': self.get_id_method,
                             'get_linker_id': self.get_linker_id_method,
                             'compute_int': self.compute_int_method,
                             'sizeof': self.sizeof_method,
                             'get_define': self.get_define_method,
                             'has_define': self.has_define_method,
                             'check_header': self.check_header_method,
                             'has_header': self.has_header_method,
                             'has_header_symbol': self.has_header_symbol_method,
                             'run': self.run_method,
                             'has_function': self.has_function_method,
                             'has_member': self.has_member_method,
                             'has_members': self.has_members_method,
                             'has_type': self.has_type_method,
                             'alignment': self.alignment_method,
                             'version': self.version_method,
                             'cmd_array': self.cmd_array_method,
                             'find_library': self.find_library_method,
                             'has_argument': self.has_argument_method,
                             'has_function_attribute': self.has_func_attribute_method,
                             'get_supported_function_attributes': self.get_supported_function_attributes_method,
                             'has_multi_arguments': self.has_multi_arguments_method,
                             'get_supported_arguments': self.get_supported_arguments_method,
                             'first_supported_argument': self.first_supported_argument_method,
                             'has_link_argument': self.has_link_argument_method,
                             'has_multi_link_arguments': self.has_multi_link_arguments_method,
                             'get_supported_link_arguments': self.get_supported_link_arguments_method,
                             'first_supported_link_argument': self.first_supported_link_argument_method,
                             'symbols_have_underscore_prefix': self.symbols_have_underscore_prefix_method,
                             'get_argument_syntax': self.get_argument_syntax_method,
                             'preprocess': self.preprocess_method,
                             })

    @property
    def compiler(self) -> 'Compiler':
        return self.held_object

    def _dep_msg(self, deps: T.List['dependencies.Dependency'], compile_only: bool, endl: str) -> str:
        msg_single = 'with dependency {}'
        msg_many = 'with dependencies {}'
        names = []
        for d in deps:
            if isinstance(d, dependencies.InternalDependency):
                FeatureNew.single_use('compiler method "dependencies" kwarg with internal dep', '0.57.0', self.subproject,
                                      location=self.current_node)
                continue
            if isinstance(d, dependencies.ExternalLibrary):
                if compile_only:
                    continue
                name = '-l' + d.name
            else:
                name = d.name
            names.append(name)
        if not names:
            return endl
        tpl = msg_many if len(names) > 1 else msg_single
        if endl is None:
            endl = ''
        return tpl.format(', '.join(names)) + endl

    @noPosargs
    @noKwargs
    def version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.compiler.version

    @noPosargs
    @noKwargs
    def cmd_array_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> T.List[str]:
        return self.compiler.exelist

    def _determine_args(self, kwargs: BaseCompileKW,
                        mode: CompileCheckMode = CompileCheckMode.LINK) -> T.List[str]:
        args: T.List[str] = []
        for i in kwargs['include_directories']:
            for idir in i.to_string_list(self.environment.get_source_dir(), self.environment.get_build_dir()):
                args.extend(self.compiler.get_include_args(idir, False))
        if not kwargs['no_builtin_args']:
            opts = coredata.OptionsView(self.environment.coredata.options, self.subproject)
            args += self.compiler.get_option_compile_args(opts)
            if mode is CompileCheckMode.LINK:
                args.extend(self.compiler.get_option_link_args(opts))
        if kwargs.get('werror', False):
            args.extend(self.compiler.get_werror_args())
        args.extend(kwargs['args'])
        return args

    def _determine_dependencies(self, deps: T.List['dependencies.Dependency'], compile_only: bool = False, endl: str = ':') -> T.Tuple[T.List['dependencies.Dependency'], str]:
        deps = dependencies.get_leaf_external_dependencies(deps)
        return deps, self._dep_msg(deps, compile_only, endl)

    @typed_pos_args('compiler.alignment', str)
    @typed_kwargs(
        'compiler.alignment',
        _PREFIX_KW,
        _ARGS_KW,
        _DEPENDENCIES_KW,
    )
    def alignment_method(self, args: T.Tuple[str], kwargs: 'AlignmentKw') -> int:
        typename = args[0]
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=self.compiler.is_cross)
        result, cached = self.compiler.alignment(typename, kwargs['prefix'], self.environment,
                                                 extra_args=kwargs['args'],
                                                 dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        mlog.log('Checking for alignment of',
                 mlog.bold(typename, True), msg, mlog.bold(str(result)), cached_msg)
        return result

    @typed_pos_args('compiler.run', (str, mesonlib.File))
    @typed_kwargs('compiler.run', *_COMPILES_KWS)
    def run_method(self, args: T.Tuple['mesonlib.FileOrString'], kwargs: 'CompileKW') -> 'RunResult':
        if self.compiler.language not in {'d', 'c', 'cpp', 'objc', 'objcpp'}:
            FeatureNew.single_use(f'compiler.run for {self.compiler.get_display_language()} language',
                                  '1.5.0', self.subproject, location=self.current_node)
        code = args[0]
        if isinstance(code, mesonlib.File):
            self.interpreter.add_build_def_file(code)
            code = mesonlib.File.from_absolute_file(
                code.rel_to_builddir(self.environment.source_dir))
        testname = kwargs['name']
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=False, endl=None)
        result = self.compiler.run(code, self.environment, extra_args=extra_args,
                                   dependencies=deps)
        if testname:
            if not result.compiled:
                h = mlog.red('DID NOT COMPILE')
            elif result.returncode == 0:
                h = mlog.green('YES')
            else:
                h = mlog.red(f'NO ({result.returncode})')
            mlog.log('Checking if', mlog.bold(testname, True), msg, 'runs:', h)
        return result

    @noPosargs
    @noKwargs
    def get_id_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.compiler.get_id()

    @noPosargs
    @noKwargs
    @FeatureNew('compiler.get_linker_id', '0.53.0')
    def get_linker_id_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.compiler.get_linker_id()

    @noPosargs
    @noKwargs
    def symbols_have_underscore_prefix_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        '''
        Check if the compiler prefixes _ (underscore) to global C symbols
        See: https://en.wikipedia.org/wiki/Name_mangling#C
        '''
        return self.compiler.symbols_have_underscore_prefix(self.environment)

    @typed_pos_args('compiler.has_member', str, str)
    @typed_kwargs('compiler.has_member', _HAS_REQUIRED_KW, *_COMMON_KWS)
    def has_member_method(self, args: T.Tuple[str, str], kwargs: 'HasKW') -> bool:
        typename, membername = args
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Type', mlog.bold(typename, True), 'has member', mlog.bold(membername, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        had, cached = self.compiler.has_members(typename, [membername], kwargs['prefix'],
                                                self.environment,
                                                extra_args=extra_args,
                                                dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not had:
            raise InterpreterException(f'{self.compiler.get_display_language()} member {membername!r} of type {typename!r} not usable')
        elif had:
            hadtxt = mlog.green('YES')
        else:
            hadtxt = mlog.red('NO')
        mlog.log('Checking whether type', mlog.bold(typename, True),
                 'has member', mlog.bold(membername, True), msg, hadtxt, cached_msg)
        return had

    @typed_pos_args('compiler.has_members', str, varargs=str, min_varargs=1)
    @typed_kwargs('compiler.has_members', _HAS_REQUIRED_KW, *_COMMON_KWS)
    def has_members_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'HasKW') -> bool:
        typename, membernames = args
        members = mlog.bold(', '.join([f'"{m}"' for m in membernames]))
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Type', mlog.bold(typename, True), 'has members', members, 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        had, cached = self.compiler.has_members(typename, membernames, kwargs['prefix'],
                                                self.environment,
                                                extra_args=extra_args,
                                                dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not had:
            # print members as array: ['member1', 'member2']
            raise InterpreterException(f'{self.compiler.get_display_language()} members {membernames!r} of type {typename!r} not usable')
        elif had:
            hadtxt = mlog.green('YES')
        else:
            hadtxt = mlog.red('NO')
        mlog.log('Checking whether type', mlog.bold(typename, True),
                 'has members', members, msg, hadtxt, cached_msg)
        return had

    @typed_pos_args('compiler.has_function', str)
    @typed_kwargs('compiler.has_function', _HAS_REQUIRED_KW, *_COMMON_KWS)
    def has_function_method(self, args: T.Tuple[str], kwargs: 'HasKW') -> bool:
        funcname = args[0]
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Has function', mlog.bold(funcname, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = self._determine_args(kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=False)
        had, cached = self.compiler.has_function(funcname, kwargs['prefix'], self.environment,
                                                 extra_args=extra_args,
                                                 dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not had:
            raise InterpreterException(f'{self.compiler.get_display_language()} function {funcname!r} not usable')
        elif had:
            hadtxt = mlog.green('YES')
        else:
            hadtxt = mlog.red('NO')
        mlog.log('Checking for function', mlog.bold(funcname, True), msg, hadtxt, cached_msg)
        return had

    @typed_pos_args('compiler.has_type', str)
    @typed_kwargs('compiler.has_type', _HAS_REQUIRED_KW, *_COMMON_KWS)
    def has_type_method(self, args: T.Tuple[str], kwargs: 'HasKW') -> bool:
        typename = args[0]
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Has type', mlog.bold(typename, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        had, cached = self.compiler.has_type(typename, kwargs['prefix'], self.environment,
                                             extra_args=extra_args, dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not had:
            raise InterpreterException(f'{self.compiler.get_display_language()} type {typename!r} not usable')
        elif had:
            hadtxt = mlog.green('YES')
        else:
            hadtxt = mlog.red('NO')
        mlog.log('Checking for type', mlog.bold(typename, True), msg, hadtxt, cached_msg)
        return had

    @FeatureNew('compiler.compute_int', '0.40.0')
    @typed_pos_args('compiler.compute_int', str)
    @typed_kwargs(
        'compiler.compute_int',
        KwargInfo('low', (int, NoneType)),
        KwargInfo('high', (int, NoneType)),
        KwargInfo('guess', (int, NoneType)),
        *_COMMON_KWS,
    )
    def compute_int_method(self, args: T.Tuple[str], kwargs: 'ComputeIntKW') -> int:
        expression = args[0]
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=self.compiler.is_cross)
        res = self.compiler.compute_int(expression, kwargs['low'], kwargs['high'],
                                        kwargs['guess'], kwargs['prefix'],
                                        self.environment, extra_args=extra_args,
                                        dependencies=deps)
        mlog.log('Computing int of', mlog.bold(expression, True), msg, res)
        return res

    @typed_pos_args('compiler.sizeof', str)
    @typed_kwargs('compiler.sizeof', *_COMMON_KWS)
    def sizeof_method(self, args: T.Tuple[str], kwargs: 'CommonKW') -> int:
        element = args[0]
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=self.compiler.is_cross)
        esize, cached = self.compiler.sizeof(element, kwargs['prefix'], self.environment,
                                             extra_args=extra_args, dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        mlog.log('Checking for size of',
                 mlog.bold(element, True), msg, mlog.bold(str(esize)), cached_msg)
        return esize

    @FeatureNew('compiler.get_define', '0.40.0')
    @typed_pos_args('compiler.get_define', str)
    @typed_kwargs('compiler.get_define', *_COMMON_KWS)
    def get_define_method(self, args: T.Tuple[str], kwargs: 'CommonKW') -> str:
        element = args[0]
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        value, cached = self.compiler.get_define(element, kwargs['prefix'], self.environment,
                                                 extra_args=extra_args,
                                                 dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        value_msg = '(undefined)' if value is None else value
        mlog.log('Fetching value of define', mlog.bold(element, True), msg, value_msg, cached_msg)
        return value if value is not None else ''

    @FeatureNew('compiler.has_define', '1.3.0')
    @typed_pos_args('compiler.has_define', str)
    @typed_kwargs('compiler.has_define', *_COMMON_KWS)
    def has_define_method(self, args: T.Tuple[str], kwargs: 'CommonKW') -> bool:
        define_name = args[0]
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], endl=None)
        value, cached = self.compiler.get_define(define_name, kwargs['prefix'], self.environment,
                                                 extra_args=extra_args,
                                                 dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        h = mlog.green('YES') if value is not None else mlog.red('NO')
        mlog.log('Checking if define', mlog.bold(define_name, True), msg, 'exists:', h, cached_msg)

        return value is not None

    @typed_pos_args('compiler.compiles', (str, mesonlib.File))
    @typed_kwargs('compiler.compiles', *_COMPILES_KWS)
    def compiles_method(self, args: T.Tuple['mesonlib.FileOrString'], kwargs: 'CompileKW') -> bool:
        code = args[0]
        if isinstance(code, mesonlib.File):
            if code.is_built:
                FeatureNew.single_use('compiler.compiles with file created at setup time', '1.2.0', self.subproject,
                                      'It was broken and either errored or returned false.', self.current_node)
            self.interpreter.add_build_def_file(code)
            code = mesonlib.File.from_absolute_file(
                code.absolute_path(self.environment.source_dir, self.environment.build_dir))
        testname = kwargs['name']
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], endl=None)
        result, cached = self.compiler.compiles(code, self.environment,
                                                extra_args=extra_args,
                                                dependencies=deps)
        if testname:
            if result:
                h = mlog.green('YES')
            else:
                h = mlog.red('NO')
            cached_msg = mlog.blue('(cached)') if cached else ''
            mlog.log('Checking if', mlog.bold(testname, True), msg, 'compiles:', h, cached_msg)
        return result

    @typed_pos_args('compiler.links', (str, mesonlib.File))
    @typed_kwargs('compiler.links', *_COMPILES_KWS)
    def links_method(self, args: T.Tuple['mesonlib.FileOrString'], kwargs: 'CompileKW') -> bool:
        code = args[0]
        compiler = None
        if isinstance(code, mesonlib.File):
            if code.is_built:
                FeatureNew.single_use('compiler.links with file created at setup time', '1.2.0', self.subproject,
                                      'It was broken and either errored or returned false.', self.current_node)
            self.interpreter.add_build_def_file(code)
            code = mesonlib.File.from_absolute_file(
                code.absolute_path(self.environment.source_dir, self.environment.build_dir))
            suffix = code.suffix
            if suffix not in self.compiler.file_suffixes:
                for_machine = self.compiler.for_machine
                clist = self.interpreter.coredata.compilers[for_machine]
                if suffix not in SUFFIX_TO_LANG:
                    # just pass it to the compiler driver
                    mlog.warning(f'Unknown suffix for test file {code}')
                elif SUFFIX_TO_LANG[suffix] not in clist:
                    mlog.warning(f'Passed {SUFFIX_TO_LANG[suffix]} source to links method, not specified for {for_machine.get_lower_case_name()} machine.')
                else:
                    compiler = clist[SUFFIX_TO_LANG[suffix]]

        testname = kwargs['name']
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'], compile_only=False)
        result, cached = self.compiler.links(code, self.environment,
                                             compiler=compiler,
                                             extra_args=extra_args,
                                             dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if testname:
            if result:
                h = mlog.green('YES')
            else:
                h = mlog.red('NO')
            mlog.log('Checking if', mlog.bold(testname, True), msg, 'links:', h, cached_msg)
        return result

    @FeatureNew('compiler.check_header', '0.47.0')
    @typed_pos_args('compiler.check_header', str)
    @typed_kwargs('compiler.check_header', *_HEADER_KWS)
    def check_header_method(self, args: T.Tuple[str], kwargs: 'HeaderKW') -> bool:
        hname = args[0]
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Check usable header', mlog.bold(hname, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        haz, cached = self.compiler.check_header(hname, kwargs['prefix'], self.environment,
                                                 extra_args=extra_args,
                                                 dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not haz:
            raise InterpreterException(f'{self.compiler.get_display_language()} header {hname!r} not usable')
        elif haz:
            h = mlog.green('YES')
        else:
            h = mlog.red('NO')
        mlog.log('Check usable header', mlog.bold(hname, True), msg, h, cached_msg)
        return haz

    def _has_header_impl(self, hname: str, kwargs: 'HeaderKW') -> bool:
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Has header', mlog.bold(hname, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        haz, cached = self.compiler.has_header(hname, kwargs['prefix'], self.environment,
                                               extra_args=extra_args, dependencies=deps)
        cached_msg = mlog.blue('(cached)') if cached else ''
        if required and not haz:
            raise InterpreterException(f'{self.compiler.get_display_language()} header {hname!r} not found')
        elif haz:
            h = mlog.green('YES')
        else:
            h = mlog.red('NO')
        mlog.log('Has header', mlog.bold(hname, True), msg, h, cached_msg)
        return haz

    @typed_pos_args('compiler.has_header', str)
    @typed_kwargs('compiler.has_header', *_HEADER_KWS)
    def has_header_method(self, args: T.Tuple[str], kwargs: 'HeaderKW') -> bool:
        return self._has_header_impl(args[0], kwargs)

    @typed_pos_args('compiler.has_header_symbol', str, str)
    @typed_kwargs('compiler.has_header_symbol', *_HEADER_KWS)
    def has_header_symbol_method(self, args: T.Tuple[str, str], kwargs: 'HeaderKW') -> bool:
        hname, symbol = args
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject, default=False)
        if disabled:
            mlog.log('Header', mlog.bold(hname, True), 'has symbol', mlog.bold(symbol, True), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        extra_args = functools.partial(self._determine_args, kwargs)
        deps, msg = self._determine_dependencies(kwargs['dependencies'])
        haz, cached = self.compiler.has_header_symbol(hname, symbol, kwargs['prefix'], self.environment,
                                                      extra_args=extra_args,
                                                      dependencies=deps)
        if required and not haz:
            raise InterpreterException(f'{self.compiler.get_display_language()} symbol {symbol} not found in header {hname}')
        elif haz:
            h = mlog.green('YES')
        else:
            h = mlog.red('NO')
        cached_msg = mlog.blue('(cached)') if cached else ''
        mlog.log('Header', mlog.bold(hname, True), 'has symbol', mlog.bold(symbol, True), msg, h, cached_msg)
        return haz

    def notfound_library(self, libname: str) -> 'dependencies.ExternalLibrary':
        lib = dependencies.ExternalLibrary(libname, None,
                                           self.environment,
                                           self.compiler.language,
                                           silent=True)
        return lib

    @disablerIfNotFound
    @typed_pos_args('compiler.find_library', str)
    @typed_kwargs(
        'compiler.find_library',
        KwargInfo('required', (bool, coredata.UserFeatureOption), default=True),
        KwargInfo('has_headers', ContainerTypeInfo(list, str), listify=True, default=[], since='0.50.0'),
        KwargInfo('static', (bool, NoneType), since='0.51.0'),
        KwargInfo('disabler', bool, default=False, since='0.49.0'),
        KwargInfo('dirs', ContainerTypeInfo(list, str), listify=True, default=[]),
        *(k.evolve(name=f'header_{k.name}') for k in _HEADER_KWS)
    )
    def find_library_method(self, args: T.Tuple[str], kwargs: 'FindLibraryKW') -> 'dependencies.ExternalLibrary':
        # TODO add dependencies support?
        libname = args[0]

        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            mlog.log('Library', mlog.bold(libname), 'skipped: feature', mlog.bold(feature), 'disabled')
            return self.notfound_library(libname)

        # This could be done with a comprehension, but that confuses the type
        # checker, and
"""


```