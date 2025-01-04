Response:
The user wants to understand the functionality of the Python code provided, which is part of the Frida dynamic instrumentation tool. The code is specifically located in the `compiler.py` file within the Meson build system's interpreter.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Purpose:** The filename `compiler.py` strongly suggests that this code is responsible for interacting with compilers during the build process. The imports confirm this, including modules related to compilers, dependencies, and the Meson build system itself.

2. **Analyze Class Structures:**  The code defines two main classes: `TryRunResultHolder` and `CompilerHolder`.
    * `TryRunResultHolder`: This seems to be a wrapper around the result of a compiler execution (`RunResult`). It provides methods to access the return code, compilation status, standard output, and standard error.
    * `CompilerHolder`: This class is central. It holds an instance of a `Compiler` object and exposes various methods for interacting with that compiler.

3. **Examine `CompilerHolder` Methods:**  The `CompilerHolder` class contains a significant number of methods. Carefully examine each method's name and its annotations (`@typed_pos_args`, `@typed_kwargs`). This reveals the specific functionalities related to compiler interaction. Keywords like `compiles`, `links`, `has_header`, `find_library`, etc., are strong indicators of their purpose.

4. **Group Functionalities:**  Organize the discovered functionalities into logical categories. This makes it easier to understand the overall capabilities. Potential categories include:
    * Compilation and Linking checks
    * Header file checks
    * Symbol and type checks
    * Running compiled code
    * Getting compiler information
    * Library searching

5. **Connect to Reverse Engineering:** Think about how the identified compiler functionalities can be used in a reverse engineering context. For example:
    * Checking for the existence of specific headers or functions can help understand the libraries a target binary might be using.
    * Examining the size of data types or the presence of specific members in structures can be crucial for understanding memory layouts and data structures.
    * The ability to run code snippets with the target compiler can be used to probe the target environment.

6. **Relate to Low-Level Details and System Knowledge:** Identify methods that involve lower-level concepts and operating system specifics:
    * Compiler and linker flags and arguments (`_determine_args`)
    * Include directories
    * Dependencies (linking libraries)
    * System headers
    * The concept of static vs. shared libraries

7. **Identify Logical Reasoning:** Look for methods that perform checks or computations based on certain criteria. The `compute_int_method` is a clear example, where the code evaluates an expression using the compiler. The "try compile and run" approach in methods like `has_function` also involves logical reasoning.

8. **Consider User Errors:** Think about common mistakes a user might make when using these compiler interaction functions. This often relates to providing incorrect paths, types, or dependencies.

9. **Trace User Operations:**  Consider the sequence of actions a user would take to reach this code. They would typically be writing a `meson.build` file to define their project's build process. This file would use the Meson DSL, which is then interpreted, leading to the execution of the Python code in `compiler.py`.

10. **Focus on the "Part 1" Request:** The prompt specifically asks for a summary of the *functionalities* in the first part of the code. Avoid going too deep into the implementation details at this stage.

11. **Structure the Output:**  Organize the findings in a clear and structured manner, using headings and bullet points for readability. Provide concrete examples to illustrate the concepts.

**(Self-Correction/Refinement during the process):**

* Initially, I might have just listed all the methods. However, grouping them into functional categories provides a much better high-level understanding.
*  I needed to make sure to connect the technical details back to the prompt's specific requirements regarding reverse engineering, low-level details, and user errors. Simply describing the code isn't enough.
* I realized the importance of explaining how a user would interact with this code, which involves the `meson.build` file and the Meson interpreter.
好的，根据您提供的 frida 源代码文件 `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/compiler.py` 的内容，并结合您的要求，以下是该文件功能的归纳：

**主要功能归纳：**

该 Python 文件定义了 `CompilerHolder` 类，该类作为 Meson 构建系统中编译器对象的包装器，并提供了一系列方法来执行与编译器相关的各种检查和操作。这些方法允许 Meson 构建系统在构建过程中与实际的编译器进行交互，以获取编译器的能力、特性和进行条件判断。

**具体功能点：**

1. **编译器信息获取：**
   - `version_method`: 获取编译器的版本信息。
   - `cmd_array_method`: 获取用于调用编译器的命令行数组。
   - `get_id_method`: 获取编译器的唯一标识符。
   - `get_linker_id_method`: 获取链接器的唯一标识符。
   - `symbols_have_underscore_prefix_method`: 检查编译器是否在全局 C 符号前添加下划线前缀。
   - `get_argument_syntax_method`: 获取编译器参数的语法。

2. **代码编译和链接检查：**
   - `compiles_method`: 检查一段代码片段是否能够被编译器成功编译。
   - `links_method`: 检查一段代码片段是否能够被编译器和链接器成功链接。
   - `run_method`: 编译并运行一段代码片段，并返回运行结果（返回码、标准输出、标准错误）。

3. **头文件检查：**
   - `check_header_method`: 检查头文件是否存在并且可用。
   - `has_header_method`: 检查头文件是否存在。
   - `has_header_symbol_method`: 检查头文件中是否定义了特定的符号。

4. **类型和成员检查：**
   - `has_member_method`: 检查一个类型是否具有特定的成员。
   - `has_members_method`: 检查一个类型是否具有多个特定的成员。
   - `has_type_method`: 检查一个类型是否存在。

5. **宏定义检查：**
   - `get_define_method`: 获取宏定义的值。
   - `has_define_method`: 检查宏定义是否存在。

6. **特性和能力探测：**
   - `has_function_method`: 检查是否存在特定的函数。
   - `has_argument_method`: 检查编译器是否支持特定的命令行参数。
   - `has_function_attribute_method` / `get_supported_function_attributes_method`: 检查编译器是否支持特定的函数属性。
   - `has_multi_arguments_method` / `get_supported_arguments_method` / `first_supported_argument_method`: 检查编译器是否支持多个命令行参数或获取第一个支持的参数。
   - `has_link_argument_method` / `has_multi_link_arguments_method` / `get_supported_link_arguments_method` / `first_supported_link_argument_method`:  检查链接器是否支持特定的命令行参数。

7. **其他检查和计算：**
   - `alignment_method`: 检查特定类型在内存中的对齐方式。
   - `sizeof_method`: 获取特定类型的大小。
   - `compute_int_method`: 使用编译器计算一个整型表达式的值。
   - `preprocess_method`: 使用编译器预处理器处理源文件。

8. **库查找：**
   - `find_library_method`: 在指定的目录中查找特定的库文件。

**与逆向方法的关联及举例：**

这些编译器检查功能在逆向工程中具有重要的辅助作用，可以帮助逆向工程师更好地理解目标软件的构建方式和运行环境。

* **头文件检查 (`has_header_method`, `check_header_method`):**  在尝试理解一个二进制文件时，如果已知其使用了某些库，可以使用这些方法来检查构建该二进制文件时是否使用了对应的头文件。例如，如果逆向一个 Linux 程序怀疑其使用了 `pcap` 库，可以检查是否存在 `<pcap.h>` 头文件。

* **符号检查 (`has_header_symbol_method`):** 可以用来确认目标软件是否使用了某个库的特定功能。例如，如果想知道目标是否使用了 `pthread` 库的 `pthread_create` 函数，可以检查 `<pthread.h>` 中是否定义了 `pthread_create` 符号。

* **类型大小和对齐检查 (`sizeof_method`, `alignment_method`):** 这对于理解目标软件的数据结构至关重要。通过检查关键数据类型的大小和对齐方式，可以推断出目标软件在内存中的布局，这对于漏洞分析和利用开发非常重要。例如，检查 `size_t` 的大小可以帮助理解内存分配和寻址方式。

* **函数存在性检查 (`has_function_method`):**  可以用于快速判断目标软件是否链接了特定的库或者使用了特定的系统调用。例如，检查是否存在 `socket` 函数可以判断目标是否使用了网络编程相关的库。

* **宏定义检查 (`get_define_method`, `has_define_method`):**  宏定义通常用于条件编译和配置。通过检查宏定义，可以了解目标软件在编译时的配置选项，例如是否启用了调试模式、使用了哪些优化级别等。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例：**

这些方法的实现依赖于对底层编译、链接过程的理解，以及对目标平台（如 Linux, Android）的特定知识。

* **编译器和链接器参数 (`_determine_args`):**  该函数根据不同的编译选项和依赖项，生成传递给编译器和链接器的命令行参数。这涉及到对不同编译器（如 GCC, Clang）的命令行选项的了解，例如 `-I` (include 目录), `-L` (库目录), `-l` (链接库) 等。

* **依赖项处理 (`_determine_dependencies`):**  该函数负责处理编译和链接的依赖关系，例如外部库。这需要理解不同类型的依赖项（如系统库、第三方库）以及如何在构建系统中表示和处理它们。

* **头文件和库文件路径：**  在进行头文件和库文件查找时，需要了解目标平台的标准头文件和库文件路径，以及如何配置编译器和链接器以找到这些文件。在 Linux 中，常见的头文件路径包括 `/usr/include`, `/usr/local/include` 等，库文件路径包括 `/usr/lib`, `/usr/local/lib` 等。在 Android 中，情况会更复杂，涉及到 SDK、NDK 的路径。

* **交叉编译 (`self.compiler.is_cross`):** 代码中考虑了交叉编译的情况，这意味着构建过程可能在一个平台上进行，但目标平台是另一个。这需要对交叉编译工具链和相关的配置有深入的理解。

* **Android 特性：** 虽然代码本身没有直接提及 Android 内核或框架，但 Frida 作为一款动态插桩工具，经常用于 Android 平台。因此，理解 Android 的 Bionic Libc、ART 虚拟机、以及系统服务框架对于理解 Frida 的工作原理和使用场景至关重要。

**逻辑推理及假设输入与输出：**

以 `has_function_method` 为例：

* **假设输入：**
    * `funcname`: "malloc"
    * `kwargs`: 一个包含其他编译选项的字典，例如 `include_directories` 指向标准 C 库头文件路径。
* **逻辑推理：**
    1. 构建一个包含对 `malloc` 函数声明的简单 C 代码片段。
    2. 调用编译器编译该代码片段。
    3. 如果编译成功，则认为系统存在 `malloc` 函数。
* **预期输出：** `True` (假设在目标系统上 `malloc` 函数存在)。

以 `compute_int_method` 为例：

* **假设输入：**
    * `expression`: "sizeof(int)"
    * `kwargs`:  可能包含目标平台的编译器信息。
* **逻辑推理：**
    1. 构建一个包含计算 `sizeof(int)` 的 C 代码片段。
    2. 编译并运行该代码片段。
    3. 从运行结果中提取 `sizeof(int)` 的值。
* **预期输出：**  例如，在 32 位系统上可能是 `4`，在 64 位系统上可能是 `4` 或 `8` (取决于编译器和平台)。

**用户或编程常见的使用错误及举例：**

* **错误的头文件路径：** 在使用 `check_header_method` 时，如果 `include_directories` 参数指定的路径不包含目标头文件，则会导致检查失败。
   ```python
   # 错误示例：假设 pcap.h 不在 /opt/include 中
   compiler.check_header('pcap.h', include_directories=['/opt/include'])
   ```

* **缺失的依赖库：** 在使用 `links_method` 或 `run_method` 时，如果代码依赖的库没有被正确链接，会导致链接错误。
   ```python
   # 错误示例：代码使用了 libz，但 dependencies 中没有指定
   compiler.links('int main() { /* ... 使用 zlib 的代码 ... */ return 0; }')
   ```

* **类型名称拼写错误：** 在使用 `sizeof_method` 或 `has_member_method` 时，如果类型名称拼写错误，会导致检查失败。
   ```python
   # 错误示例：将 size_t 拼写为 sizet
   compiler.sizeof('sizet')
   ```

* **传递了不适用的编译器参数：**  某些编译器参数可能只适用于特定的语言或编译器版本，如果传递了不适用的参数，可能会导致编译错误。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：**  用户在项目的根目录下编写 `meson.build` 文件，该文件描述了项目的构建过程，包括依赖项、编译选项、测试等。
2. **用户调用 `meson` 命令配置构建：** 用户在命令行中执行 `meson setup builddir` (或类似的命令) 来配置构建。
3. **Meson 解析 `meson.build` 文件：** Meson 读取并解析 `meson.build` 文件，构建内部的构建图。
4. **解释器执行到相关的编译器检查函数：** 在 `meson.build` 文件中，用户可能会使用 Meson 提供的与编译器交互的函数，例如：
   ```python
   if host_compiler.has_header('stdio.h'):
       # ...
   if host_compiler.links('int main() { return 0; }'):
       # ...
   ```
5. **调用 `CompilerHolder` 的方法：** 当解释器执行到这些函数时，会调用 `CompilerHolder` 实例中对应的方法，例如 `has_header_method` 或 `links_method`。
6. **`CompilerHolder` 与实际编译器交互：** `CompilerHolder` 的方法会调用底层的编译器对象，执行实际的编译器命令，并将结果返回给 Meson 解释器。

作为调试线索，如果用户在构建过程中遇到与编译器相关的错误，例如头文件找不到、链接失败等，可以查看 Meson 的日志输出，其中会包含 `CompilerHolder` 中执行的各种检查的详细信息，例如编译命令、返回码等，从而帮助定位问题。

总而言之，`compiler.py` 文件在 Meson 构建系统中扮演着与底层编译器交互的关键角色，它提供了一组丰富的接口，允许 Meson 构建系统根据目标环境的编译器特性和能力进行灵活的配置和构建。这对于构建跨平台的软件尤其重要。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/compiler.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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