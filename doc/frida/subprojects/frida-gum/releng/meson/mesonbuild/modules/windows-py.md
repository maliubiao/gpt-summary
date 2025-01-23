Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding: The Big Picture**

The first step is to recognize the context. The comments at the beginning tell us this is part of the Frida dynamic instrumentation tool, specifically a Meson module for handling Windows resource compilation. Keywords like "frida," "dynamic instrumentation," "Windows," "resource compilation," and "Meson" are crucial. This immediately tells us the code is about building software, likely targeting Windows, using a specific build system (Meson), and has something to do with embedding resources (like icons, version info, etc.) into the final executable.

**2. Functionality Identification: High-Level Scan**

Next, scan through the class `WindowsModule` and its methods. The key methods are:

* `__init__`:  Initialization, likely setting up internal state.
* `detect_compiler`:  Determines which C/C++ compiler to use. This hints at a connection to the underlying compilation process.
* `_find_resource_compiler`:  Crucial for finding the right tool to compile resource files. It checks for `windres` and `rc`. This is a core function.
* `compile_resources`:  The main workhorse. It takes resource files as input and orchestrates their compilation. The `@typed_pos_args` and `@typed_kwargs` decorators indicate it's part of Meson's interface for user-defined build steps.

**3. Deep Dive into `compile_resources`**

This is the most complex method, so it deserves closer attention. Let's analyze its key steps:

* **Argument Handling:**  It takes a variable number of resource files as positional arguments and various keyword arguments (dependencies, include directories, compiler arguments). This is typical of build system definitions.
* **Include Directory Handling:** It processes `include_directories`, showing how external headers might be needed for resource compilation.
* **Resource Compiler Detection:** It calls `_find_resource_compiler` to get the appropriate tool.
* **Command Generation (Conditional):** This is where the logic branches based on the resource compiler type (`rc`, `windres`, `wrc`). This is significant. Different compilers have different command-line syntax.
* **Output Suffix:**  The output file extension changes based on the compiler (`.res` for `rc`, `.o` for others). This reflects the different output formats.
* **Warning for Spaces in Arguments:** The code specifically warns about potential issues with `windres` and spaces in arguments. This is a practical consideration related to a known bug.
* **Target Creation (Loop):** The code iterates through the input resource files and creates `build.CustomTarget` objects for each. This is how Meson represents individual build steps.
* **Dependency Handling:**  It includes logic for handling dependencies on other build targets and files.
* **Depfile Generation:** It handles the generation of dependency files (`.d`) for `windres`. This is important for incremental builds.

**4. Connecting to Reverse Engineering**

Now, explicitly address the "reverse engineering" aspect:

* **Resource Modification:**  Resource files (like icons, dialogs, version info) are often targets for reverse engineers. Modifying these can change the appearance or behavior of an application. `compile_resources` is the step that embeds these resources. Understanding this process is key to reversing such changes.
* **Binary Analysis:** The output of resource compilation (`.res` or `.o`) becomes part of the final executable. Reverse engineers analyze these binaries. Knowing how these resources are compiled and linked helps in understanding the structure of the final binary.

**5. Binary/Kernel/Framework Connections**

Think about how the code interacts with the lower levels:

* **Binary Format:** The choice between `.res` and `.o` highlights the different binary formats involved (Windows resource format vs. object file). This is a low-level detail.
* **Windows API:** Resource compilation often involves Windows API calls. While the *Python code* doesn't directly make these calls, the resource compiler it invokes does.
* **Linking:** The `.res` files produced by `rc` are directly fed to the linker (`LINK`). This is a crucial step in the overall binary creation process.

**6. Logic and Assumptions**

Look for conditional logic and assumptions:

* **Compiler Detection:** The code assumes a C or C++ compiler is available.
* **Resource Compiler Availability:** It assumes `windres` or `rc` is installed.
* **Command-Line Syntax:** The code hardcodes command-line arguments for different resource compilers. These are assumptions based on the tools' behavior.

**7. Common User Errors**

Consider how a user might misuse this functionality:

* **Incorrect Resource File Paths:** Providing the wrong path to a resource file.
* **Missing Dependencies:** Forgetting to declare dependencies on other targets that generate resources.
* **Incorrect Compiler Arguments:**  Passing invalid arguments through the `args` keyword.
* **Mixing Resource Types:**  Trying to compile resources meant for a different architecture or platform.

**8. Debugging Steps**

Think about how a developer would end up looking at this code during debugging:

* **Build Failures:** A build error related to resource compilation would lead a developer to examine this module.
* **Incorrect Resources:** If the wrong resources are embedded, or if they are not being updated correctly, a developer might trace the build process back to this module.
* **Performance Issues:**  Slow resource compilation might prompt an investigation into how this module works.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  "This is just about compiling resources."  **Correction:**  Realize the nuances of different resource compilers and their specific requirements.
* **Initial thought:** "It doesn't directly interact with the kernel." **Correction:** Recognize that the *output* of this process (the final executable) *does* interact with the Windows kernel and that the resource compilers themselves are system tools.
* **Initial thought:**  Focus only on the happy path. **Correction:**  Consider error handling, warnings, and potential user mistakes.

By following this structured approach, one can systematically analyze the code, understand its purpose, and connect it to broader concepts like reverse engineering, low-level details, and the overall software development process. The key is to break down the code into smaller, manageable parts and then synthesize the information to build a comprehensive understanding.
这个Python源代码文件 `windows.py` 是 Frida 工具中负责处理 **Windows 平台资源编译** 的模块。它属于 Frida-gum 子项目中的构建系统（Meson）的一部分。

以下是它的主要功能以及与逆向、底层、用户错误和调试线索相关的说明：

**主要功能：**

1. **检测 Windows 资源编译器:**  `_find_resource_compiler` 函数负责检测系统上可用的 Windows 资源编译器。它会尝试寻找 `windres`（GNU Resource Compiler）和 `rc`（Microsoft Resource Compiler）。
2. **抽象资源编译过程:**  `compile_resources` 函数是该模块的核心。它接收资源文件作为输入，并根据检测到的资源编译器类型，生成相应的编译命令。它抽象了不同资源编译器的差异，为 Frida 的构建系统提供了一个统一的接口来处理 Windows 资源。
3. **生成自定义构建目标 (Custom Targets):**  `compile_resources` 函数会为每个资源文件创建一个 `build.CustomTarget` 对象。这些目标代表了 Meson 构建系统中的一个编译步骤，负责将资源文件编译成 `.res` (Microsoft `rc`) 或 `.o` (GNU `windres`) 文件。
4. **处理依赖关系:** `compile_resources` 函数可以处理资源编译的依赖关系，包括依赖的其他文件 (`depend_files`) 和其他的构建目标 (`depends`)。这确保了在资源文件或其依赖项发生变化时，会重新编译资源。
5. **处理包含目录:**  它允许指定包含目录 (`include_directories`)，这些目录将被添加到资源编译器的命令行参数中，以便资源文件可以引用其他头文件。
6. **提供统一的接口:**  无论使用哪个资源编译器，用户都通过 `windows.compile_resources` 这个统一的接口来编译 Windows 资源。

**与逆向方法的关系及举例说明：**

* **资源修改/替换:** 逆向工程师经常会修改 Windows 应用程序的资源，例如图标、字符串、对话框等。这个模块的功能正是将这些资源编译到最终的可执行文件中。了解这个编译过程有助于逆向工程师定位和修改目标资源。
    * **例子:** 假设一个逆向工程师想要修改一个程序的图标。他需要找到包含图标的 `.rc` 文件，修改它，然后重新编译。Frida 的构建系统会使用 `windows.compile_resources` 来完成这个重新编译的过程。逆向工程师可能需要理解这个模块如何调用 `rc.exe` 或 `windres.exe` 以及传递哪些参数，才能在自己的环境中手动完成编译。
* **分析资源结构:**  编译后的资源文件（`.res` 或 `.o`）会被链接到最终的可执行文件中。逆向工程师需要分析这些编译后的二进制资源，以理解程序的界面结构或其他资源信息。了解 `windows.compile_resources` 如何生成这些文件，有助于理解它们的格式和内容。
    * **例子:**  逆向工程师可能会用工具查看 `.res` 文件的结构，了解不同类型的资源（如 `RT_ICON`, `RT_STRING`）是如何组织的。`windows.compile_resources` 的代码中对不同资源编译器的处理方式，例如生成 `.res` 或 `.o`，可以帮助理解不同编译器的输出格式差异。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制格式差异 (Windows):**  `windows.compile_resources` 区分了 Microsoft `rc` 和 GNU `windres`，因为它们生成不同的二进制资源格式。`rc` 生成 `.res` 文件，可以直接链接到 PE 文件中，而 `windres` 通常生成 COFF 目标文件 (`.o`)，需要先链接成库再使用。这是 Windows 平台特有的二进制格式差异。
    * **例子:** 代码中可以看到，当使用 `rc` 时，输出后缀是 `.res`，而使用 `windres` 时，输出后缀是 `.o`。这是因为 `.res` 是 Microsoft 链接器可以直接处理的资源格式，而 `.o` 是通用的目标文件格式。
* **命令行工具调用:**  该模块的核心操作是调用底层的命令行工具 `rc.exe` 或 `windres.exe`。理解这些工具的命令行参数和工作原理是理解该模块功能的基础。
    * **例子:** 代码中可以看到构建命令时使用了类似 `['/nologo', '/fo@OUTPUT@', '@INPUT@']` (针对 `rc`) 和 `['@INPUT@', '@OUTPUT@']` (针对 `windres`) 这样的参数。这些参数是特定于这些资源编译器的。
* **Linux (间接相关):** 虽然这个模块是针对 Windows 的，但 Frida 作为一个跨平台的工具，其构建系统 Meson 本身可能在 Linux 环境下运行，来构建针对 Windows 的 Frida 组件。因此，开发人员需要在 Linux 环境下配置交叉编译工具链，才能正确使用这个模块。
    * **例子:** 在 Linux 系统上使用 Meson 构建 Frida 的 Windows 组件时，Meson 会调用这个 `windows.py` 模块，并确保使用了正确的 Windows 资源编译器（例如通过交叉编译工具链提供的）。
* **Android 内核及框架 (基本无关):** 这个模块主要针对 Windows 平台的资源编译，与 Android 内核和框架没有直接关系。Android 有自己的资源编译机制 (aapt/aapt2)。

**逻辑推理及假设输入与输出：**

* **假设输入:**
    * `state`: Meson 的模块状态对象，包含构建环境信息。
    * `args`:  一个包含字符串或 `mesonlib.File` 对象的元组，表示要编译的资源文件路径。例如：`(['my_resource.rc', 'another_resource.rc'])` 或 `([mesonlib.File('/path/to/resource.rc')])`.
    * `kwargs`: 一个字典，包含可选参数，例如 `include_directories=['include']`, `depends=[my_custom_target]`.
* **逻辑推理:**
    1. `compile_resources` 首先调用 `_find_resource_compiler` 来确定使用哪个资源编译器。
    2. 根据资源编译器的类型 (`rc` 或 `windres`)，构建不同的命令行参数。
    3. 遍历输入的资源文件，为每个文件创建一个 `build.CustomTarget`。
    4. 每个 `CustomTarget` 的命令会包含资源编译器的路径、相应的参数、输入文件和输出文件。
    5. 如果指定了依赖项，这些依赖项会被添加到 `CustomTarget` 中，确保在依赖项构建完成后才编译资源。
* **预期输出:**
    * 一个 `ModuleReturnValue` 对象，包含一个 `build.CustomTarget` 对象列表。每个 `CustomTarget` 代表一个资源文件的编译任务，其输出是编译后的 `.res` 或 `.o` 文件。

**涉及用户或者编程常见的使用错误及举例说明：**

* **资源编译器未安装或不在 PATH 中:**  如果系统上没有安装 `rc.exe` 或 `windres.exe`，或者这些工具没有添加到系统的 PATH 环境变量中，`_find_resource_compiler` 将会抛出 `MesonException`。
    * **错误信息:** "Could not find Windows resource compiler"
* **资源文件路径错误:**  如果在 `compile_resources` 中提供的资源文件路径不存在，或者路径不正确，资源编译器将会报错。
    * **例子:** `windows.compile_resources('non_existent.rc')` 将会导致资源编译器报错，Meson 会将错误信息传递给用户。
* **依赖项未正确声明:** 如果资源文件依赖于其他生成的文件，但这些依赖项没有通过 `depends` 参数声明，可能会导致资源编译失败或使用旧版本的依赖文件。
    * **例子:** 假设 `my_resource.rc` 中包含了一个由 `my_custom_target` 生成的头文件。如果调用 `windows.compile_resources('my_resource.rc')` 时没有设置 `depends=[my_custom_target]`, 那么在 `my_custom_target` 的输出发生变化时，`my_resource.rc` 可能不会被重新编译。
* **命令行参数错误:**  通过 `args` 传递给 `compile_resources` 的额外参数如果与资源编译器的语法不符，会导致编译错误。
    * **例子:**  如果错误地传递了 `-D` 参数给 `rc.exe` (它通常使用 `/D`)，会导致编译失败。
* **混淆输入类型:**  错误地将非字符串或 `mesonlib.File` 对象传递给 `compile_resources` 的位置参数。
    * **例子:** `windows.compile_resources(123)` 将会触发类型错误。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置 Meson 构建:** 用户首先需要编写 `meson.build` 文件来描述项目的构建过程。在这个文件中，用户会使用 `windows.compile_resources` 函数来指定需要编译的 Windows 资源文件。
    ```python
    win_res = files('my_app.rc')
    res = windows.compile_resources(win_res, depends: ...)
    executable('my_app', 'main.c', windows_resources: res)
    ```
2. **运行 Meson 配置:** 用户在命令行中执行 `meson setup builddir` 来配置构建目录。Meson 会解析 `meson.build` 文件，并根据用户的配置生成构建系统所需的文件。在这个过程中，当遇到 `windows.compile_resources` 调用时，Meson 会调用 `windows.py` 模块中的 `compile_resources` 函数。
3. **运行 Meson 构建:** 用户执行 `meson compile -C builddir` 来开始构建。Meson 会执行之前配置阶段生成的构建任务。当执行到 `windows.compile_resources` 创建的 `CustomTarget` 时，Meson 会调用相应的资源编译器来编译资源文件。
4. **遇到资源编译错误:** 如果资源编译过程中出现错误（例如资源文件不存在、语法错误、依赖项问题等），Meson 会报告错误信息，并指示哪个构建步骤失败。
5. **开始调试:**  为了调试资源编译问题，开发人员可能会：
    * **查看 Meson 的构建日志:**  日志会显示 Meson 执行的命令，包括调用资源编译器的命令和传递的参数。
    * **检查 `meson.build` 文件:** 确认 `windows.compile_resources` 的调用是否正确，包括输入文件、依赖项和额外的参数。
    * **查看 `windows.py` 的源代码:**  如果错误信息不够明确，或者怀疑 Meson 的资源编译处理逻辑有问题，开发人员可能会查看 `windows.py` 的源代码，特别是 `compile_resources` 函数，来理解其工作原理，例如如何检测资源编译器，如何构建命令行，以及如何处理依赖关系。
    * **手动执行资源编译器命令:** 从 Meson 的构建日志中复制资源编译器的命令，然后在命令行中手动执行，以便更直接地观察错误信息。
    * **使用调试器:** 在某些情况下，如果怀疑 `windows.py` 的代码本身存在问题，可以使用 Python 调试器来逐步执行代码。

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/windows.py` 文件中的 `windows.py` 模块是 Frida 构建系统中处理 Windows 资源编译的关键组件。理解其功能有助于理解 Frida 在 Windows 平台上的构建过程，以及与逆向工程、底层二进制操作相关的方面。 当构建过程中出现资源编译问题时，理解这个模块的源代码可以为调试提供重要的线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/windows.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Meson development team

from __future__ import annotations

import enum
import os
import re
import typing as T


from . import ExtensionModule, ModuleInfo
from . import ModuleReturnValue
from .. import mesonlib, build
from .. import mlog
from ..interpreter.type_checking import DEPEND_FILES_KW, DEPENDS_KW, INCLUDE_DIRECTORIES
from ..interpreterbase.decorators import ContainerTypeInfo, FeatureNew, KwargInfo, typed_kwargs, typed_pos_args
from ..mesonlib import MachineChoice, MesonException
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from . import ModuleState
    from ..compilers import Compiler
    from ..interpreter import Interpreter

    from typing_extensions import TypedDict

    class CompileResources(TypedDict):

        depend_files: T.List[mesonlib.FileOrString]
        depends: T.List[T.Union[build.BuildTarget, build.CustomTarget]]
        include_directories: T.List[T.Union[str, build.IncludeDirs]]
        args: T.List[str]

    class RcKwargs(TypedDict):
        output: str
        input: T.List[T.Union[mesonlib.FileOrString, build.CustomTargetIndex]]
        depfile: T.Optional[str]
        depend_files: T.List[mesonlib.FileOrString]
        depends: T.List[T.Union[build.BuildTarget, build.CustomTarget]]
        command: T.List[T.Union[str, ExternalProgram]]

class ResourceCompilerType(enum.Enum):
    windres = 1
    rc = 2
    wrc = 3

class WindowsModule(ExtensionModule):

    INFO = ModuleInfo('windows')

    def __init__(self, interpreter: 'Interpreter'):
        super().__init__(interpreter)
        self._rescomp: T.Optional[T.Tuple[ExternalProgram, ResourceCompilerType]] = None
        self.methods.update({
            'compile_resources': self.compile_resources,
        })

    def detect_compiler(self, compilers: T.Dict[str, 'Compiler']) -> 'Compiler':
        for l in ('c', 'cpp'):
            if l in compilers:
                return compilers[l]
        raise MesonException('Resource compilation requires a C or C++ compiler.')

    def _find_resource_compiler(self, state: 'ModuleState') -> T.Tuple[ExternalProgram, ResourceCompilerType]:
        # FIXME: Does not handle `native: true` executables, see
        # See https://github.com/mesonbuild/meson/issues/1531
        # Take a parameter instead of the hardcoded definition below
        for_machine = MachineChoice.HOST

        if self._rescomp:
            return self._rescomp

        # Will try cross / native file and then env var
        rescomp = ExternalProgram.from_bin_list(state.environment, for_machine, 'windres')

        if not rescomp or not rescomp.found():
            comp = self.detect_compiler(state.environment.coredata.compilers[for_machine])
            if comp.id in {'msvc', 'clang-cl', 'intel-cl'} or (comp.linker and comp.linker.id in {'link', 'lld-link'}):
                # Microsoft compilers uses rc irrespective of the frontend
                rescomp = ExternalProgram('rc', silent=True)
            else:
                rescomp = ExternalProgram('windres', silent=True)

        if not rescomp.found():
            raise MesonException('Could not find Windows resource compiler')

        for (arg, match, rc_type) in [
                ('/?', '^.*Microsoft.*Resource Compiler.*$', ResourceCompilerType.rc),
                ('/?', 'LLVM Resource Converter.*$', ResourceCompilerType.rc),
                ('--version', '^.*GNU windres.*$', ResourceCompilerType.windres),
                ('--version', '^.*Wine Resource Compiler.*$', ResourceCompilerType.wrc),
        ]:
            p, o, e = mesonlib.Popen_safe(rescomp.get_command() + [arg])
            m = re.search(match, o, re.MULTILINE)
            if m:
                mlog.log('Windows resource compiler: %s' % m.group())
                self._rescomp = (rescomp, rc_type)
                break
        else:
            raise MesonException('Could not determine type of Windows resource compiler')

        return self._rescomp

    @typed_pos_args('windows.compile_resources', varargs=(str, mesonlib.File, build.CustomTarget, build.CustomTargetIndex), min_varargs=1)
    @typed_kwargs(
        'windows.compile_resources',
        DEPEND_FILES_KW.evolve(since='0.47.0'),
        DEPENDS_KW.evolve(since='0.47.0'),
        INCLUDE_DIRECTORIES,
        KwargInfo('args', ContainerTypeInfo(list, str), default=[], listify=True),
    )
    def compile_resources(self, state: 'ModuleState',
                          args: T.Tuple[T.List[T.Union[str, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]]],
                          kwargs: 'CompileResources') -> ModuleReturnValue:
        extra_args = kwargs['args'].copy()
        wrc_depend_files = kwargs['depend_files']
        wrc_depends = kwargs['depends']
        for d in wrc_depends:
            if isinstance(d, build.CustomTarget):
                extra_args += state.get_include_args([
                    build.IncludeDirs('', [], False, [os.path.join('@BUILD_ROOT@', self.interpreter.backend.get_target_dir(d))],
                                      state.is_build_only_subproject)
                ])
        extra_args += state.get_include_args(kwargs['include_directories'])

        rescomp, rescomp_type = self._find_resource_compiler(state)
        if rescomp_type == ResourceCompilerType.rc:
            # RC is used to generate .res files, a special binary resource
            # format, which can be passed directly to LINK (apparently LINK uses
            # CVTRES internally to convert this to a COFF object)
            suffix = 'res'
            res_args = extra_args + ['/nologo', '/fo@OUTPUT@', '@INPUT@']
        elif rescomp_type == ResourceCompilerType.windres:
            # ld only supports object files, so windres is used to generate a
            # COFF object
            suffix = 'o'
            res_args = extra_args + ['@INPUT@', '@OUTPUT@']

            m = 'Argument {!r} has a space which may not work with windres due to ' \
                'a MinGW bug: https://sourceware.org/bugzilla/show_bug.cgi?id=4933'
            for arg in extra_args:
                if ' ' in arg:
                    mlog.warning(m.format(arg), fatal=False)
        else:
            suffix = 'o'
            res_args = extra_args + ['@INPUT@', '-o', '@OUTPUT@']

        res_targets: T.List[build.CustomTarget] = []

        def get_names() -> T.Iterable[T.Tuple[str, str, T.Union[str, mesonlib.File, build.CustomTargetIndex]]]:
            for src in args[0]:
                if isinstance(src, str):
                    yield os.path.join(state.subdir, src), src, src
                elif isinstance(src, mesonlib.File):
                    yield src.relative_name(), src.fname, src
                elif isinstance(src, build.CustomTargetIndex):
                    FeatureNew.single_use('windows.compile_resource CustomTargetIndex in positional arguments', '0.61.0',
                                          state.subproject, location=state.current_node)
                    # This dance avoids a case where two indexes of the same
                    # target are given as separate arguments.
                    yield (f'{src.get_id()}_{src.target.get_outputs().index(src.output)}',
                           f'windows_compile_resources_{src.get_filename()}', src)
                else:
                    if len(src.get_outputs()) > 1:
                        FeatureNew.single_use('windows.compile_resource CustomTarget with multiple outputs in positional arguments',
                                              '0.61.0', state.subproject, location=state.current_node)
                    for i, out in enumerate(src.get_outputs()):
                        # Chances are that src.get_filename() is already the name of that
                        # target, add a prefix to avoid name clash.
                        yield f'{src.get_id()}_{i}', f'windows_compile_resources_{i}_{out}', src[i]

        for name, name_formatted, src in get_names():
            # Path separators are not allowed in target names
            name = name.replace('/', '_').replace('\\', '_').replace(':', '_')
            name_formatted = name_formatted.replace('/', '_').replace('\\', '_').replace(':', '_')
            output = f'{name}_@BASENAME@.{suffix}'
            command: T.List[T.Union[str, ExternalProgram]] = []
            command.append(rescomp)
            command.extend(res_args)
            depfile: T.Optional[str] = None
            # instruct binutils windres to generate a preprocessor depfile
            if rescomp_type == ResourceCompilerType.windres:
                depfile = f'{output}.d'
                command.extend(['--preprocessor-arg=-MD',
                                '--preprocessor-arg=-MQ@OUTPUT@',
                                '--preprocessor-arg=-MF@DEPFILE@'])

            res_targets.append(build.CustomTarget(
                name_formatted,
                state.subdir,
                state.subproject,
                state.environment,
                command,
                [src],
                [output],
                state.is_build_only_subproject,
                depfile=depfile,
                depend_files=wrc_depend_files,
                extra_depends=wrc_depends,
                description='Compiling Windows resource {}'
            ))

        return ModuleReturnValue(res_targets, [res_targets])

def initialize(interp: 'Interpreter') -> WindowsModule:
    return WindowsModule(interp)
```