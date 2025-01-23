Response:
The user wants to understand the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The code defines a `CompilerHolder` class that wraps a `Compiler` object from the Meson build system. This class extends the functionality of the base compiler by providing methods for performing various checks and operations related to compilation, linking, and inspecting code properties.

Here's a plan to address the user's request:

1. **High-level Functionality:** Summarize the main purpose of the `compiler.py` file, focusing on its role in providing compiler-related introspection capabilities within the Meson build system as used by Frida.
2. **Reverse Engineering Relevance:** Explain how the compiler checks and information gathering can be used in reverse engineering scenarios, such as identifying function availability or data structure layouts.
3. **Binary/Kernel/Framework Knowledge:** Point out the methods that directly interact with low-level concepts, like checking for header files, symbols, and data type sizes, which are fundamental in understanding binary structures and operating system interfaces.
4. **Logical Inference:** Identify methods where the code makes deductions based on compiler behavior or code analysis, and illustrate with hypothetical inputs and outputs.
5. **Common Usage Errors:**  Consider potential mistakes developers might make when using these methods, like providing incorrect arguments or misunderstanding the meaning of the checks.
6. **User Operation to Reach Code:**  Describe the typical steps a user (likely a Frida developer or contributor) would take within the Frida build process to trigger the execution of this code.
7. **Concise Summary:**  Finally, provide a succinct summary of the file's overall function.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/compiler.py` 文件的功能归纳：

**核心功能:**

该文件定义了 `CompilerHolder` 类，它是对 Meson 构建系统中 `Compiler` 对象的封装。`CompilerHolder` 类在 Meson 的解释器环境中提供了一系列方法，用于执行与特定编译器相关的检查、查询和操作。这些方法使得构建脚本能够根据目标编译器的特性做出决策，从而实现更灵活和健壮的构建过程。

**主要功能点:**

* **编译器信息获取:** 提供获取编译器基本信息的方法，如版本号 (`version_method`) 和命令行 (`cmd_array_method`)。
* **代码编译和链接测试:**  允许测试一段代码片段是否能够被目标编译器成功编译 (`compiles_method`) 和链接 (`links_method`)。
* **代码运行测试:**  可以编译并运行一段代码，并获取其返回码、标准输出和标准错误 (`run_method`)。
* **符号和类型检查:** 提供检查特定类型是否存在成员 (`has_member_method`, `has_members_method`)，函数是否存在 (`has_function_method`)，类型是否存在 (`has_type_method`) 的能力。
* **数据类型属性查询:** 可以查询数据类型的对齐方式 (`alignment_method`) 和大小 (`sizeof_method`)。
* **宏定义检查和获取:**  能够检查宏定义是否存在 (`has_define_method`) 并获取其值 (`get_define_method`)。
* **头文件检查:**  允许检查头文件是否可用 (`check_header_method`) 以及头文件是否包含特定符号 (`has_header_symbol_method`)。
* **库查找:** 提供查找特定库的功能 (`find_library_method`)。
* **编译器特性检查:**  可以检查编译器是否支持特定的命令行参数 (`has_argument_method`, `has_multi_arguments_method`, `get_supported_arguments_method`, `first_supported_argument_method`) 和链接参数 (`has_link_argument_method`, `has_multi_link_arguments_method`, `get_supported_link_arguments_method`, `first_supported_link_argument_method`)，以及函数属性 (`has_function_attribute_method`, `get_supported_function_attributes_method`)。
* **符号前缀检查:**  检查编译器是否给全局 C 符号添加下划线前缀 (`symbols_have_underscore_prefix_method`)。
* **获取参数语法:** 获取编译器的参数语法 (`get_argument_syntax_method`)。
* **预处理:**  允许对源文件进行预处理并输出结果 (`preprocess_method`)。
* **计算整数表达式:** 允许编译器计算一个整数表达式的值 (`compute_int_method`)。

**与逆向的关系举例:**

假设在 Frida 的构建过程中，需要判断目标系统是否支持某个特定的系统调用，而这个系统调用的声明位于某个特定的头文件中。可以使用 `has_header_symbol_method` 来检查：

```python
# 假设 compiler 是 CompilerHolder 的实例
has_syscall = compiler.has_header_symbol_method(('unistd.h', '__NR_my_syscall'), {})
if has_syscall:
    # 执行依赖于该系统调用的构建步骤
    pass
else:
    # 执行备选的构建步骤
    pass
```

这里，`has_header_symbol_method` 尝试在 `unistd.h` 头文件中查找 `__NR_my_syscall` 这个宏定义（通常用于表示系统调用号）。如果找到，则说明目标系统可能支持该系统调用，可以进行后续的构建操作。这在逆向工程中，尤其是在跨平台适配时，用于探测目标环境的能力非常有用。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例:**

* **`sizeof_method`:**  这个方法用于确定数据类型的大小，这直接涉及到二进制数据的布局。例如，在分析一个二进制文件格式时，需要知道结构体中各个成员的大小，`sizeof_method` 可以帮助在构建时获取这些信息。这对于理解 Linux 或 Android 内核中数据结构的布局至关重要。
* **`has_header_symbol_method`:** 检查头文件中的符号，这可以用于判断目标平台是否定义了特定的内核接口或框架 API。例如，检查 `android/log.h` 中是否存在 `__android_log_print` 符号，可以判断是否为 Android 平台。
* **`alignment_method`:** 数据对齐是二进制底层编程中需要考虑的重要因素，尤其是在涉及到结构体内存布局和跨平台数据交换时。这个方法可以帮助确定特定数据类型在目标平台上的对齐方式。

**逻辑推理举例:**

假设输入以下调用：

```python
compiler.has_function_method(('pthread_create',), {'dependencies': [pthread_dep]})
```

其中 `pthread_dep` 是一个表示 `pthread` 库的依赖项。

**假设输入:** 目标平台安装了 `pthread` 库。

**输出:** `True`

**推理过程:**  `has_function_method` 会尝试编译一个包含 `pthread_create` 函数调用的简单代码片段，并链接 `pthread` 库。由于 `pthread` 库存在，并且 `pthread_create` 是其提供的函数，因此编译和链接都会成功，方法返回 `True`。

**假设输入:** 目标平台没有安装 `pthread` 库。

**输出:** `False`

**推理过程:**  链接阶段会失败，因为找不到 `pthread` 库提供的符号，因此方法返回 `False`。

**常见使用错误举例:**

* **未添加必要的依赖项:**  例如，在使用 `has_function_method` 检查某个需要特定库支持的函数时，忘记在 `dependencies` 参数中指定该库。这会导致即使目标平台安装了该库，检查也可能失败，因为编译器在测试编译时没有链接该库。

  ```python
  # 错误示例：缺少 'dependencies' 参数
  compiler.has_function_method(('some_function_from_lib',), {})
  ```

* **头文件路径不正确:** 在使用 `check_header_method` 或 `has_header_method` 时，如果系统头文件路径配置不当，可能导致无法找到头文件，即使该头文件在系统中存在。Meson 通常会自动处理标准头文件路径，但对于非标准路径的头文件，可能需要进行额外的配置。

**用户操作到达这里的调试线索:**

用户通常是在编写 `meson.build` 构建文件时使用这些编译器检查功能。例如：

1. **配置构建环境:** 用户首先会配置 Frida 的构建环境，这涉及到安装必要的依赖工具和配置 Meson。
2. **编写 `meson.build` 文件:** 用户在 `meson.build` 文件中会使用 `meson` 提供的 `find_library`, `check_header`, `has_function` 等方法，而这些方法最终会调用到 `compiler.py` 中 `CompilerHolder` 实例的相应方法。
3. **运行 Meson:** 用户在命令行执行 `meson setup build` 或类似的命令来配置构建。在这个过程中，Meson 会解析 `meson.build` 文件，并执行其中的编译器检查。
4. **构建过程:**  在实际构建过程中，Meson 可能会根据之前的编译器检查结果来决定如何编译和链接代码。

如果用户在构建过程中遇到与编译器相关的错误，并且怀疑是 Meson 的编译器检查出了问题，他们可能会查看 Meson 的日志输出，或者尝试调试 Meson 的构建脚本。这时，他们可能会追踪到 `compiler.py` 这个文件，了解具体的编译器检查是如何进行的。例如，如果 `find_library` 找不到预期的库，用户可能会检查 `meson.build` 文件中 `find_library` 的调用参数，以及系统中该库的安装情况。

**功能归纳:**

总而言之，`frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/compiler.py` 文件的核心功能是为 Frida 的构建过程提供了一组强大的编译器自省工具。它允许构建脚本在构建时动态地查询目标编译器的各种特性，并根据这些特性做出相应的构建决策，从而确保 Frida 能够正确地在不同的平台上编译和运行。这对于像 Frida 这样需要跨多种操作系统和架构进行构建的复杂项目来说至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/compiler.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```