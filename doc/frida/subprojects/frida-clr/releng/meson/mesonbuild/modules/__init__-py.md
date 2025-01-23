Response:
Let's break down the thought process for analyzing this Python code snippet. The goal is to understand its functionality and relate it to reverse engineering, low-level concepts, and common usage scenarios.

**1. Initial Skim and Identification of Key Elements:**

The first step is a quick read-through to identify the major components and their apparent purposes. Keywords and class names are crucial here:

* `ModuleState`: This immediately suggests a state management mechanism for modules within the Meson build system.
* `ModuleObject`, `NewExtensionModule`, `ExtensionModule`, `NotFoundExtensionModule`:  These strongly indicate a module system with different types of modules. The naming suggests inheritance and specialization.
* `ModuleInfo`:  Seems to hold metadata about modules.
* `ModuleReturnValue`:  Likely represents the value returned by a module function.
* `GResourceTarget`, `GResourceHeaderTarget`, `GirTarget`, `TypelibTarget`, `VapiTarget`:  These look like specific types of build targets, possibly related to specific technologies (GResource, Gir, Vapi).
* `import`:  The imports at the beginning tell us about the dependencies and context (Meson's internal libraries).

**2. Deep Dive into Key Classes:**

Next, focus on the most important classes and their methods.

* **`ModuleState`:**  This class seems to be the central hub for information available to a module. Pay attention to the attributes initialized in `__init__`. They provide context about the build environment: source and build directories, subproject info, compiler information, targets, dependencies, etc. The methods like `get_include_args`, `find_program`, `find_tool`, `dependency`, `test`, `get_option`, and `process_include_dirs` are the primary ways a module interacts with the Meson system.

* **`ModuleObject` and its subclasses:**  These classes define the structure of modules. `methods` attribute in `ModuleObject` is a dictionary mapping names to callable functions, suggesting a mechanism for invoking module functionality. The distinction between `NewExtensionModule`, `ExtensionModule`, and `NotFoundExtensionModule` hints at different module states or implementations.

* **`ModuleReturnValue`:** A simple data class holding the return value and any newly created objects.

* **Target classes:**  These appear to be markers or specializations of `build.CustomTarget`.

**3. Connecting to the Prompt's Questions:**

Now, address each part of the prompt systematically.

* **Functionality:** Summarize the purpose of each identified component. Focus on what the code *does*, not just what it *is*. For example, `ModuleState` *provides access to build information*.

* **Relationship to Reverse Engineering:** This requires thinking about how the code could be used in a reverse engineering context. Frida is mentioned in the prompt, which is a dynamic instrumentation toolkit. Meson is a build system. The connection is that Frida, to work with specific targets (like .NET applications in the `frida-clr` subdirectory), needs to be *built* correctly. This file is part of the build system for Frida's .NET support. Therefore, the functionalities related to finding programs, handling dependencies, and defining build targets are relevant. Specifically, the ability to locate specific binaries or libraries (`find_program`, `find_tool`) is crucial for hooking and instrumentation.

* **Binary/Low-Level/Kernel/Framework Knowledge:**  Look for clues suggesting interaction with the underlying system. `MachineChoice` and `for_machine` parameters in methods point to cross-compilation or handling different architectures. Finding programs and tools inherently involves dealing with executables. The presence of target types like `GirTarget` and `TypelibTarget` might hint at interactions with specific system libraries or frameworks. However, this particular file is more about the *build process* than direct manipulation of the kernel or low-level code.

* **Logical Reasoning (Hypothetical Input/Output):** Focus on the methods that take arguments and produce results. For example, `get_include_args` takes a list of include directories and returns a list of compiler flags. Come up with a simple input and predict the output based on the code.

* **User/Programming Errors:** Think about how a developer using this code (or interacting with Meson in a way that leads to this code being executed) could make mistakes. Incorrect path names, missing dependencies, or wrong option settings are common build system errors.

* **User Operation to Reach This Code:**  Consider the workflow of a developer using Frida. They would likely be building Frida from source, especially if they are working with specific features like the .NET bridge. The path `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/__init__.py` gives a strong clue: this is part of the Meson build system for the `frida-clr` subproject. The user would be running Meson commands to configure and build Frida.

**4. Refinement and Structuring:**

Finally, organize the analysis into clear sections corresponding to the prompt's questions. Use examples to illustrate points, especially for reverse engineering, low-level concepts, and error scenarios. Ensure the language is precise and avoids jargon where possible, or explains it clearly. The goal is to provide a comprehensive and understandable explanation of the code's purpose and context.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the details of individual methods. It's important to step back and see the bigger picture – the role of this file within the Meson build system for Frida.
* I might have over-interpreted some of the target types. While they hint at specific technologies, without more context, it's safer to describe them as "specialized build targets."
* I made sure to connect the functionality back to the context of Frida and dynamic instrumentation, as specified in the prompt. Simply describing Meson's features isn't enough.

By following this structured approach, combining code analysis with an understanding of the surrounding context (Frida, Meson), and addressing each part of the prompt explicitly, we can generate a comprehensive and accurate explanation of the code snippet.
这是 Frida 动态Instrumentation 工具中一个名为 `__init__.py` 的 Python 源代码文件，位于 Meson 构建系统的模块定义目录中。它的主要功能是定义了 Meson 构建系统模块的基础结构和一些通用工具函数，供其他的 Frida 构建模块使用。

让我们逐点分析其功能，并结合您提出的问题进行说明：

**1. 功能列表:**

* **定义 `ModuleState` 类:**  这个类用于封装当前 Meson 构建过程中的各种状态信息，例如源代码根目录、构建目录、当前子项目、编译器环境、项目名称和版本、构建目标、依赖等。模块中的方法可以通过 `ModuleState` 对象访问这些信息，从而了解构建环境。
* **定义 `ModuleObject` 基类及其子类 (`MutableModuleObject`, `NewExtensionModule`, `ExtensionModule`, `NotFoundExtensionModule`):**  这些类定义了 Meson 模块对象的基本结构。
    * `ModuleObject` 是所有模块对象的基类，包含一个 `methods` 字典，用于存储模块提供的方法。
    * `MutableModuleObject` 是可变模块对象的基类 (目前为空)。
    * `NewExtensionModule` 是现代模块的基类，提供了一个 `found` 方法来指示模块是否可用。
    * `ExtensionModule` 继承自 `NewExtensionModule`，并添加了对 `Interpreter` 对象的引用（虽然文档注释建议避免直接使用 `Interpreter`，而应使用 `ModuleState`）。
    * `NotFoundExtensionModule` 用于表示找不到的模块。
* **定义 `ModuleInfo` 数据类:**  用于存储模块的元数据，如名称、添加时间、弃用时间、是否不稳定等。
* **定义 `ModuleReturnValue` 类:** 用于封装模块方法调用的返回值和新创建的对象。
* **定义一些特定类型的构建目标类 (`GResourceTarget`, `GResourceHeaderTarget`, `GirTarget`, `TypelibTarget`, `VapiTarget`):** 这些类似乎是特定于某些技术的自定义构建目标，例如 GNOME 的 GResource、GIR (GNOME 接口存储库)、Typelib 和 VAPI。
* **提供一些辅助函数:**
    * `is_module_library(fname)`:  检查给定的文件名是否是由模块特定的目标（如 `GirTarget` 或 `TypelibTarget`）生成的库文件。

**2. 与逆向方法的关系 (举例说明):**

这个文件本身并不直接参与逆向过程，而是为 Frida 的构建过程提供基础架构。然而，它定义的功能间接地与逆向方法相关，体现在以下几个方面：

* **依赖管理:**  `ModuleState` 提供了访问项目依赖信息 (`interpreter.build.dep_manifest`) 和查找依赖项 (`dependency` 方法) 的能力。在构建 Frida 时，可能需要链接各种库，这些库可能是 Frida 实现某些逆向功能所需的。例如，Frida 需要处理不同平台的 API，可能依赖于特定平台的库。
    * **例子:**  假设 Frida 的一个模块需要使用某个平台特定的库来处理调试符号。这个模块可以使用 `ModuleState` 的 `dependency` 方法来查找并链接这个库。
* **工具查找:** `ModuleState` 提供了 `find_program` 和 `find_tool` 方法，用于查找构建过程中需要的外部程序，例如编译器、链接器、代码生成工具等。这些工具是构建 Frida 可执行文件的必要组成部分，而 Frida 本身就是一个逆向工具。
    * **例子:**  构建 Frida 的 Android 组件时，可能需要使用 Android NDK 中的 `aapt` (Android Asset Packaging Tool) 来打包资源。模块可以使用 `find_tool` 来定位 `aapt` 可执行文件。
* **自定义构建目标:**  `GResourceTarget`, `GirTarget` 等类可能用于定义特定于某些目标平台的构建步骤。例如，构建用于逆向 GNOME 应用程序的 Frida 组件时，可能需要处理 GIR 文件来生成桥接代码。
    * **例子:**  Frida 需要与目标应用程序进行交互，这可能涉及到处理目标应用程序的接口定义。如果目标是 GNOME 应用程序，那么可能需要使用 `GirTarget` 来处理 GIR 文件，生成 Frida 可以用来调用目标应用程序函数的代码。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

虽然这个文件是 Meson 构建系统的代码，它服务的对象是 Frida，而 Frida 经常需要与二进制底层、操作系统内核和框架交互。因此，这个文件间接地反映了这些知识领域：

* **二进制底层:**  构建过程最终生成的是二进制可执行文件和库。`find_program` 和 `find_tool` 方法需要找到编译器和链接器，这些工具负责将源代码转换为二进制代码。
    * **例子:**  在构建 Frida 的某个组件时，Meson 需要找到 C/C++ 编译器 (例如 GCC 或 Clang) 和链接器 (例如 `ld`)。这些工具直接操作二进制代码的生成。
* **Linux:**  Frida 在 Linux 上运行广泛。`ModuleState` 中获取的许多信息，如编译器路径、系统库路径等，都是 Linux 特有的。
    * **例子:**  在 Linux 上构建 Frida 时，`ModuleState` 可以获取到 `/usr/bin/gcc` 作为 C 编译器的路径，或者 `/usr/lib` 作为系统库的搜索路径。
* **Android 内核及框架:**  如果构建目标包含 Android 平台 (`frida-clr` 似乎与 .NET 相关，但 Frida 本身支持 Android)，那么构建过程可能涉及到 Android NDK 和 SDK 的工具。
    * **例子:**  构建 Frida 的 Android 版本时，可能需要使用 Android NDK 中的 `clang` 作为编译器，并链接到 Android 系统库。`ModuleState` 可以帮助找到这些工具和库。

**4. 逻辑推理 (假设输入与输出):**

假设一个模块需要获取当前项目的版本号：

* **假设输入:**  模块代码调用 `state.project_version`。
* **逻辑推理:** `ModuleState` 在初始化时会将 `interpreter.build.dep_manifest[interpreter.active_projectname].version` 的值赋给 `self.project_version`。这意味着它从 Meson 的项目定义文件中读取版本信息。
* **输出:**  `state.project_version` 将返回一个字符串，表示当前 Frida 项目的版本号，例如 `"16.2.8"`.

假设一个模块需要查找名为 `protoc` 的程序：

* **假设输入:** 模块代码调用 `state.find_program('protoc')`。
* **逻辑推理:** `find_program` 方法会在系统环境变量的路径中搜索名为 `protoc` 的可执行文件。如果找到，则返回一个 `ExternalProgram` 对象；如果找不到，且 `required` 参数为 `True` (默认)，则会抛出一个异常。
* **输出 (找到的情况):** 返回一个 `ExternalProgram` 对象，该对象包含 `protoc` 的路径和其他相关信息。
* **输出 (找不到的情况):** 抛出一个 `mesonlib.MesonException` 异常，提示找不到 `protoc` 程序。

**5. 涉及用户或者编程常见的使用错误 (举例说明):**

* **错误的路径:**  如果用户在配置 Meson 构建时，提供的某些工具或库的路径不正确，可能会导致 `find_program` 或 `find_tool` 找不到相应的程序。
    * **例子:**  用户可能设置了错误的 Android SDK 或 NDK 路径，导致构建过程中需要的 `adb` 或 `javac` 等工具找不到。
* **缺少依赖:**  如果构建所需的某些依赖项没有安装或无法找到，`dependency` 方法会失败。
    * **例子:**  如果 Frida 的一个模块依赖于 `libssl-dev`，但用户没有安装这个软件包，构建过程会报错。
* **版本不匹配:**  `dependency` 方法可以指定所需的依赖版本。如果找到的依赖版本不符合要求，构建可能会失败。
    * **例子:**  如果一个模块需要特定版本的 Python，但系统安装的 Python 版本过低或过高，`dependency('python3', wanted='>=3.8')` 可能会失败。
* **错误的模块调用:**  如果在 Meson 构建文件中错误地调用了模块的方法，例如传递了错误的参数类型或数量，会导致运行时错误。
    * **例子:**  某个模块的 `test` 方法需要一个可执行文件作为参数，但用户传递了一个字符串，会导致类型错误。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

当用户尝试构建 Frida 时，Meson 构建系统会解析 `meson.build` 文件，并根据其中的指令执行相应的构建步骤。到达 `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/__init__.py` 的过程可能如下：

1. **用户执行 Meson 配置命令:**  用户在 Frida 的源代码根目录下运行 `meson setup build` (或其他类似的命令)。
2. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录下的 `meson.build` 文件，以及所有子目录下的 `meson.build` 文件。
3. **加载模块:** 当 Meson 解析到需要使用模块的功能时 (通常通过 `import('modname')` 语句)，它会查找并加载相应的模块。
4. **定位 `__init__.py`:** 对于 `import('modname')` 语句，Meson 会在 `mesonbuild/modules` 目录下查找名为 `modname` 的子目录，并执行该子目录下的 `__init__.py` 文件。
5. **初始化模块状态:**  在 `__init__.py` 文件中，`ModuleState` 类会被实例化，并传递当前的 `Interpreter` 对象，从而获取构建状态信息。
6. **模块方法调用:**  在后续的构建过程中，如果 `meson.build` 文件中调用了某个模块提供的函数，例如 `modname.some_function(...)`，Meson 会在已加载的模块对象中查找 `some_function` 方法并执行，并将 `ModuleState` 对象作为参数传递给该方法。

**作为调试线索:**

* **构建错误:** 如果构建过程中出现与模块相关的错误，例如找不到模块、模块方法调用失败等，检查 `mesonbuild/modules/__init__.py` (以及其他模块的 `__init__.py`) 可以帮助理解模块的加载和初始化过程，以及 `ModuleState` 提供的构建信息是否正确。
* **模块功能理解:** 当需要了解某个模块提供的功能和它可以访问的构建信息时，查看模块的 `__init__.py` 文件可以帮助理解其结构和提供的基础工具函数。
* **自定义模块开发:** 如果需要为 Meson 构建系统开发自定义模块，`__init__.py` 文件是定义模块入口点和基础结构的关键。

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/__init__.py` 文件是 Frida 构建系统中 Meson 模块定义的核心文件，它定义了模块的基础结构和一些通用的工具函数，为 Frida 的构建过程提供了必要的支持。虽然它不直接参与逆向操作，但它提供的功能间接地与逆向方法相关，并反映了对二进制底层、操作系统和框架的知识需求。理解这个文件的功能有助于理解 Frida 的构建过程和排查相关的构建错误。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/__init__.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

# This file contains the base representation for import('modname')

from __future__ import annotations
import dataclasses
import typing as T

from .. import build, mesonlib
from ..build import IncludeDirs
from ..interpreterbase.decorators import noKwargs, noPosargs
from ..mesonlib import relpath, HoldableObject, MachineChoice
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from ..interpreter import Interpreter
    from ..interpreter.interpreter import ProgramVersionFunc
    from ..interpreterbase import TYPE_var, TYPE_kwargs
    from ..programs import OverrideProgram
    from ..wrap import WrapMode
    from ..dependencies import Dependency

class ModuleState:
    """Object passed to all module methods.

    This is a WIP API provided to modules, it should be extended to have everything
    needed so modules does not touch any other part of Meson internal APIs.
    """

    def __init__(self, interpreter: 'Interpreter') -> None:
        # Keep it private, it should be accessed only through methods.
        self._interpreter = interpreter

        self.source_root = interpreter.environment.get_source_dir()
        self.build_to_src = relpath(interpreter.environment.get_source_dir(),
                                    interpreter.environment.get_build_dir())
        self.subproject = interpreter.subproject
        self.subdir = interpreter.subdir
        self.root_subdir = interpreter.root_subdir
        self.current_lineno = interpreter.current_lineno
        self.environment = interpreter.environment
        self.project_name = interpreter.build.project_name
        self.project_version = interpreter.build.dep_manifest[interpreter.active_projectname].version
        # The backend object is under-used right now, but we will need it:
        # https://github.com/mesonbuild/meson/issues/1419
        self.backend = interpreter.backend
        self.targets = interpreter.build.targets
        self.data = interpreter.build.data
        self.headers = interpreter.build.get_headers()
        self.man = interpreter.build.get_man()
        self.global_args = interpreter.build.global_args.host
        self.project_args = interpreter.build.projects_args.host.get(interpreter.subproject, {})
        self.current_node = interpreter.current_node
        self.is_build_only_subproject = interpreter.coredata.is_build_only

    def get_include_args(self, include_dirs: T.Iterable[T.Union[str, build.IncludeDirs]], prefix: str = '-I') -> T.List[str]:
        if not include_dirs:
            return []

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()

        dirs_str: T.List[str] = []
        for dirs in include_dirs:
            if isinstance(dirs, str):
                dirs_str += [f'{prefix}{dirs}']
            else:
                dirs_str.extend([f'{prefix}{i}' for i in dirs.to_string_list(srcdir, builddir)])
                dirs_str.extend([f'{prefix}{i}' for i in dirs.get_extra_build_dirs()])

        return dirs_str

    def find_program(self, prog: T.Union[mesonlib.FileOrString, T.List[mesonlib.FileOrString]],
                     required: bool = True,
                     version_func: T.Optional[ProgramVersionFunc] = None,
                     wanted: T.Union[str, T.List[str]] = '', silent: bool = False,
                     for_machine: MachineChoice = MachineChoice.HOST) -> T.Union[ExternalProgram, build.Executable, OverrideProgram]:
        if not isinstance(prog, list):
            prog = [prog]
        return self._interpreter.find_program_impl(prog, required=required, version_func=version_func,
                                                   wanted=wanted, silent=silent, for_machine=for_machine)

    def find_tool(self, name: str, depname: str, varname: str, required: bool = True,
                  wanted: T.Optional[str] = None) -> T.Union['build.Executable', ExternalProgram, 'OverrideProgram']:
        # Look in overrides in case it's built as subproject
        progobj = self._interpreter.program_from_overrides([name], [], MachineChoice.HOST)
        if progobj is not None:
            return progobj

        # Look in machine file
        prog_list = self.environment.lookup_binary_entry(MachineChoice.HOST, name)
        if prog_list is not None:
            return ExternalProgram.from_entry(name, prog_list)

        # Check if pkgconfig has a variable
        dep = self.dependency(depname, native=True, required=False, wanted=wanted)
        if dep.found() and dep.type_name == 'pkgconfig':
            value = dep.get_variable(pkgconfig=varname)
            if value:
                progobj = ExternalProgram(value)
                if not progobj.found():
                    msg = (f'Dependency {depname!r} tool variable {varname!r} contains erroneous value: {value!r}\n\n'
                           f'This is a distributor issue -- please report it to your {depname} provider.')
                    raise mesonlib.MesonException(msg)
                return progobj

        # Normal program lookup
        return self.find_program(name, required=required, wanted=wanted)

    def dependency(self, depname: str, native: bool = False, required: bool = True,
                   wanted: T.Optional[str] = None) -> 'Dependency':
        kwargs: T.Dict[str, object] = {'native': native, 'required': required}
        if wanted:
            kwargs['version'] = wanted
        # FIXME: Even if we fix the function, mypy still can't figure out what's
        # going on here. And we really dont want to call interpreter
        # implementations of meson functions anyway.
        return self._interpreter.func_dependency(self.current_node, [depname], kwargs) # type: ignore

    def test(self, args: T.Tuple[str, T.Union[build.Executable, build.Jar, 'ExternalProgram', mesonlib.File]],
             workdir: T.Optional[str] = None,
             env: T.Union[T.List[str], T.Dict[str, str], str] = None,
             depends: T.List[T.Union[build.CustomTarget, build.BuildTarget]] = None) -> None:
        kwargs = {'workdir': workdir,
                  'env': env,
                  'depends': depends,
                  }
        # typed_* takes a list, and gives a tuple to func_test. Violating that constraint
        # makes the universe (or at least use of this function) implode
        real_args = list(args)
        # TODO: Use interpreter internal API, but we need to go through @typed_kwargs
        self._interpreter.func_test(self.current_node, real_args, kwargs)

    def get_option(self, name: str, subproject: str = '',
                   machine: MachineChoice = MachineChoice.HOST,
                   lang: T.Optional[str] = None,
                   module: T.Optional[str] = None) -> T.Union[T.List[str], str, int, bool, 'WrapMode']:
        return self.environment.coredata.get_option(mesonlib.OptionKey(name, subproject, machine, lang, module))

    def is_user_defined_option(self, name: str, subproject: str = '',
                               machine: MachineChoice = MachineChoice.HOST,
                               lang: T.Optional[str] = None,
                               module: T.Optional[str] = None) -> bool:
        key = mesonlib.OptionKey(name, subproject, machine, lang, module)
        return key in self._interpreter.user_defined_options.cmd_line_options

    def process_include_dirs(self, dirs: T.Iterable[T.Union[str, IncludeDirs]]) -> T.Iterable[IncludeDirs]:
        """Convert raw include directory arguments to only IncludeDirs

        :param dirs: An iterable of strings and IncludeDirs
        :return: None
        :yield: IncludeDirs objects
        """
        for d in dirs:
            if isinstance(d, IncludeDirs):
                yield d
            else:
                yield self._interpreter.build_incdir_object([d])

    def add_language(self, lang: str, for_machine: MachineChoice) -> None:
        self._interpreter.add_languages([lang], True, for_machine)

class ModuleObject(HoldableObject):
    """Base class for all objects returned by modules
    """
    def __init__(self) -> None:
        self.methods: T.Dict[
            str,
            T.Callable[[ModuleState, T.List['TYPE_var'], 'TYPE_kwargs'], T.Union[ModuleReturnValue, 'TYPE_var']]
        ] = {}


class MutableModuleObject(ModuleObject):
    pass


@dataclasses.dataclass
class ModuleInfo:

    """Metadata about a Module."""

    name: str
    added: T.Optional[str] = None
    deprecated: T.Optional[str] = None
    unstable: bool = False
    stabilized: T.Optional[str] = None


class NewExtensionModule(ModuleObject):

    """Class for modern modules

    provides the found method.
    """

    INFO: ModuleInfo

    def __init__(self) -> None:
        super().__init__()
        self.methods.update({
            'found': self.found_method,
        })

    @noPosargs
    @noKwargs
    def found_method(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.found()

    @staticmethod
    def found() -> bool:
        return True

    def postconf_hook(self, b: build.Build) -> None:
        pass

# FIXME: Port all modules to stop using self.interpreter and use API on
# ModuleState instead. Modules should stop using this class and instead use
# ModuleObject base class.
class ExtensionModule(NewExtensionModule):
    def __init__(self, interpreter: 'Interpreter') -> None:
        super().__init__()
        self.interpreter = interpreter

class NotFoundExtensionModule(NewExtensionModule):

    """Class for modern modules

    provides the found method.
    """

    def __init__(self, name: str) -> None:
        super().__init__()
        self.INFO = ModuleInfo(name)

    @staticmethod
    def found() -> bool:
        return False


def is_module_library(fname: mesonlib.FileOrString) -> bool:
    '''
    Check if the file is a library-like file generated by a module-specific
    target, such as GirTarget or TypelibTarget
    '''
    suffix = fname.split('.')[-1]
    return suffix in {'gir', 'typelib'}


class ModuleReturnValue:
    def __init__(self, return_value: T.Optional['TYPE_var'],
                 new_objects: T.Sequence[T.Union['TYPE_var', 'mesonlib.ExecutableSerialisation']]) -> None:
        self.return_value = return_value
        assert isinstance(new_objects, list)
        self.new_objects: T.List[T.Union['TYPE_var', 'mesonlib.ExecutableSerialisation']] = new_objects

class GResourceTarget(build.CustomTarget):
    source_dirs: T.List[str] = []

class GResourceHeaderTarget(build.CustomTarget):
    pass

class GirTarget(build.CustomTarget):
    pass

class TypelibTarget(build.CustomTarget):
    pass

class VapiTarget(build.CustomTarget):
    pass
```