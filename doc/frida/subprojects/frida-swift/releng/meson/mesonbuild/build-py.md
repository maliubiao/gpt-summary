Response:
The user wants a breakdown of the provided Python code, which is part of the Meson build system and specifically relates to how Frida integrates with Swift. I need to analyze the code, identify its core functionalities, and then connect those functionalities to the concepts of reverse engineering, low-level details, and potential user errors. Since this is the first part of a five-part request, I should focus on providing a general overview of the functionalities present in this segment.

Here's a possible thought process to extract the information:

1. **Identify the core purpose of the file:** The file is located within the `frida/subprojects/frida-swift/releng/meson/mesonbuild/build.py` path, indicating it's a part of the build process for Frida's Swift integration using the Meson build system. The filename `build.py` strongly suggests it defines how build targets (like libraries, executables) are constructed.

2. **Analyze the imports:** The imports provide clues about the functionalities. Keywords like `dependencies`, `compilers`, `linkers`, `environment`, `interpreter`, `coredata` point towards build system logic, dependency management, compilation, linking, and configuration. The presence of `abc` suggests the use of abstract base classes for defining target types.

3. **Examine the classes and dataclasses:**  These are the building blocks of the code. Focus on understanding what each class represents:
    * `DependencyOverride`:  Managing how dependencies are resolved.
    * `Headers`, `Man`, `EmptyDir`, `InstallDir`:  Handling the installation of different types of files.
    * `Build`:  The central class holding the state of the entire build.
    * `IncludeDirs`: Representing include directories for compilation.
    * `ExtractedObjects`:  Dealing with extracting object files from targets.
    * `StructuredSources`: Handling source files that require a specific directory structure.
    * `Target`: An abstract base class for different types of build targets.
    * `BuildTarget`: A concrete class representing a generic build target (like a library or executable).

4. **Identify key functionalities within the classes:**
    * **`Build` class:**  Managing targets, dependencies, global and project-specific arguments, testing, installation, and subprojects. It acts as the central repository for build information.
    * **`Target` and `BuildTarget` classes:** Defining the properties of build targets (name, sources, dependencies, installation settings, compiler options, etc.) and methods for processing them.

5. **Connect to reverse engineering concepts:** Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. The code manages how libraries and executables (targets) are built. This is related to reverse engineering because you often need to rebuild parts of a system or create tools that interact with compiled code.

6. **Connect to low-level details:**  The code deals with compilers, linkers, include directories, and library dependencies, which are all fundamental low-level aspects of software compilation and linking. The presence of `linux` and `android` in the user's prompt hints at potential cross-compilation or platform-specific considerations, which might be reflected in how different targets are configured.

7. **Identify potential user errors:** The code includes checks for invalid arguments and warnings about unsupported naming conventions. This provides hints about common mistakes users might make when defining build targets.

8. **Consider user actions leading to this code:**  A user interacts with a build system through configuration files (e.g., `meson.build`). The definitions in these files are parsed and translated into the data structures and logic represented in this `build.py` file. Specifically, commands like `executable()`, `shared_library()`, `static_library()`, `custom_target()`, `install_headers()`, `include_directories()`, etc., would eventually lead to the execution of the code in this file.

9. **Summarize the functionalities for Part 1:** Focus on the high-level purpose and the main entities involved (targets, dependencies, installation). Mention the connection to reverse engineering through Frida and the involvement of low-level compilation and linking concepts.

By following these steps, I can generate a comprehensive answer that addresses the user's request for functional analysis and its relevance to the specified areas.
好的，让我们来分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/build.py` 文件的功能。

**主要功能归纳：**

这个 Python 文件是 Meson 构建系统中用于定义和管理构建过程核心概念的一部分。它定义了各种数据结构（使用 `dataclass`）和类，用于表示构建目标（targets）、依赖（dependencies）、安装规则等。 简单来说，它定义了 **“构建什么”** 和 **“如何构建”** 的抽象概念，供 Meson 构建系统在实际构建过程中使用。

**具体功能点：**

1. **定义构建目标类型 (Target Types):**
   - 声明了各种构建目标类型，如 `BuildTarget`（可执行文件、共享库、静态库等）、`CustomTarget`（自定义构建步骤）、`Headers`（头文件）、`Man`（man 手册）、`Data`（数据文件）等。
   - 使用抽象基类 `Target` 定义了所有构建目标类型的通用属性和方法。

2. **管理依赖关系 (Dependencies):**
   - 提供了 `DependencyOverride` 类来处理依赖项的覆盖和管理。
   - 涉及对外部库和子项目的依赖管理。

3. **处理安装规则 (Installation Rules):**
   - 定义了 `Headers`、`Man`、`EmptyDir`、`InstallDir` 等类来描述不同类型的安装操作，包括安装头文件、man 手册、空目录和指定目录的内容。
   - 提供了与安装路径、权限相关的属性。

4. **管理编译选项和参数 (Compilation Options and Arguments):**
   - `Build` 类中维护了全局和项目级别的编译器参数 (`global_args`, `projects_args`) 和链接器参数 (`global_link_args`, `projects_link_args`)。
   - `Target` 类中处理了构建目标的特定编译选项覆盖 (`override_options`)。

5. **定义包含目录 (Include Directories):**
   - `IncludeDirs` 类用于表示包含目录，包括源目录和构建目录中的包含路径。

6. **处理对象文件提取 (Object File Extraction):**
   - `ExtractedObjects` 类用于描述从现有构建目标中提取特定对象文件的需求，这在某些构建场景中很有用。

7. **管理结构化源代码 (Structured Sources):**
   - `StructuredSources` 类用于处理需要特定文件系统结构的源代码，例如 Rust 或 Cython 项目。

8. **维护构建状态 (Build State):**
   - `Build` 类是核心，它维护了整个构建过程的状态信息，包括所有目标、测试、基准测试、安装规则、子项目信息等。

9. **支持交叉编译 (Cross-compilation):**
   - 通过 `PerMachine` 数据结构来区分构建机器（building machine）和目标机器（host machine）的设置和信息。

**与逆向方法的关系举例：**

在逆向工程中，我们常常需要对目标软件进行编译和构建，以便进行调试、插桩或者创建自定义工具。 `frida` 本身就是一个动态插桩工具，而这个 `build.py` 文件正是用于构建 `frida-swift` 这个子项目。

**举例：** 假设我们想修改 `frida-swift` 的一部分代码，然后重新构建它。Meson 会解析 `meson.build` 文件，其中定义了如何构建 `frida-swift` 的共享库或静态库。这个 `build.py` 文件中的 `BuildTarget` 类就会被用来表示这个库的构建目标，包括：

- **源代码 (`sources`)**:  指定了哪些 Swift 源文件需要被编译。
- **依赖 (`dependencies`)**:  可能依赖于其他的 Frida 组件或其他 Swift 库。
- **编译选项 (`<lang>_args`)**:  传递给 Swift 编译器的特定参数，例如优化级别、调试信息等。
- **链接选项 (`link_args`)**:  传递给链接器的参数，例如要链接的库。

当我们运行 `meson compile` 命令时，Meson 会根据 `build.py` 中定义的结构和规则，调用 Swift 编译器和链接器来生成最终的库文件。这个过程是逆向工程师构建和修改目标软件的基础。

**涉及二进制底层、Linux、Android 内核及框架的知识举例：**

1. **二进制底层:**
   - `BuildTarget` 中关于链接的设置 (`link_with`, `link_whole`, `link_args`) 直接关系到最终生成二进制文件的结构和依赖关系。例如，链接参数可能涉及到指定动态库的搜索路径 (`-L`) 或者要链接的特定库 (`-l`).
   - `Target` 类中关于输出文件名的设置 (`name_prefix`, `name_suffix`) 影响最终二进制文件的命名。

2. **Linux:**
   - 关于共享库的版本控制 (`version`, `soversion` in `known_shlib_kwargs`) 是 Linux 下共享库管理的常见概念。
   - `install_rpath` 是 Linux 下设置运行时库搜索路径的一种方式。

3. **Android 内核及框架:**
   - 虽然这个文件本身没有直接提及 Android 内核，但 `frida` 作为动态插桩工具，经常被用于 Android 平台的逆向和安全分析。`frida-swift` 可能涉及到与 Android 框架层的交互。
   - 构建过程可能需要处理 Android 特有的库依赖和编译选项。

**逻辑推理的假设输入与输出：**

假设输入一个 `meson.build` 文件片段，定义了一个名为 `my_swift_lib` 的共享库：

```meson
shared_library('my_swift_lib',
  sources: ['a.swift', 'b.swift'],
  dependencies: some_dep,
  install: true,
  darwin_versions: ['1.0', '1.0.1']
)
```

**逻辑推理：**

- Meson 解析这个片段，并调用 `shared_library` 函数。
- `build.py` 中的相关代码会创建一个 `SharedLibrary` 类型的 `BuildTarget` 对象。
- **假设输出 (Build 对象的一部分):**
  ```python
  Build {
      # ... 其他属性
      targets: OrderedDict([
          ('my_swift_lib', SharedLibrary(
              name='my_swift_lib',
              subdir='.',  # 假设在当前目录
              subproject=None,
              build_by_default=True,
              for_machine=MachineChoice.HOST, # 假设是本地构建
              environment=<environment.Environment object>,
              compilers={'swift': <compilers.SwiftCompiler object>},
              build_only_subproject=False,
              install=True,
              sources=[File('a.swift'), File('b.swift')],
              dependencies=[<dependencies.ExternalLibrary object>], # 假设 some_dep 被解析为外部库
              darwin_versions=['1.0', '1.0.1'],
              # ... 其他属性
          ))
      ]),
      # ... 其他属性
  }
  ```

**用户或编程常见的使用错误举例：**

1. **拼写错误或未知的关键字参数:**
   - 用户在 `meson.build` 中可能错误地使用了 `shared_library` 的关键字参数，例如将 `sources` 拼写成 `sourcess`。Meson 解析时会报错，因为它无法识别这个参数，这部分逻辑可能在 Meson 的其他文件中处理，但 `build.py` 中定义了哪些是已知的关键字参数 (`known_shlib_kwargs`)，可以帮助 Meson 进行校验。

2. **提供了错误类型的值:**
   - 例如，`sources` 参数应该是一个字符串列表，如果用户提供了一个字符串而不是列表，Meson 会抛出类型错误。`mesonlib.stringlistify` 等函数用于确保参数类型正确。

3. **依赖项未找到:**
   - 如果 `dependencies` 中指定的依赖项 Meson 找不到，构建过程会失败。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户编写 `meson.build` 文件:**  用户在项目根目录下创建或修改 `meson.build` 文件，定义了项目的构建规则，包括目标、依赖等。
2. **用户运行 `meson setup builddir`:** 用户执行 `meson setup` 命令，告诉 Meson 解析 `meson.build` 文件，并生成构建系统所需的中间文件（在 `builddir` 中）。在这个过程中，Meson 的解析器会读取 `meson.build` 文件，并根据其中的指令，创建 `build.py` 中定义的各种对象，填充 `Build` 类的实例。
3. **用户运行 `meson compile -C builddir`:** 用户执行 `meson compile` 命令，指示 Meson 使用之前生成的构建配置来实际编译项目。此时，Meson 会读取之前生成的 `Build` 对象中的信息，并根据 `Target` 对象的属性，调用相应的编译器和链接器来构建目标。

**作为调试线索：** 如果构建过程中出现错误，例如找不到源文件、链接错误等，开发者可以通过查看 `builddir` 中的中间文件（例如，`compile_commands.json` 可以查看编译命令），或者使用 Meson 的调试工具，来了解 Meson 是如何解析 `meson.build` 文件，以及最终生成的 `Build` 对象的状态，从而定位问题。`build.py` 中定义的类和数据结构是理解 Meson 构建过程的关键。

**功能归纳 (Part 1):**

总而言之，这个 `build.py` 文件的主要功能是 **定义了 Meson 构建系统中用于表示和管理各种构建目标、依赖项和安装规则的数据结构和类**。它是 Meson 理解和执行构建指令的核心组成部分，为构建过程提供了抽象和规范。它涉及到了编译、链接、依赖管理、安装等软件构建的关键环节，并为 Frida 的 Swift 子项目的构建提供了基础。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2017 The Meson development team

from __future__ import annotations
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field, InitVar
from functools import lru_cache
import abc
import copy
import hashlib
import itertools, pathlib
import os
import pickle
import re
import textwrap
import typing as T

from . import coredata
from . import dependencies
from . import mlog
from . import programs
from .mesonlib import (
    HoldableObject, SecondLevelHolder,
    File, MesonException, MachineChoice, PerMachine, OrderedSet, listify,
    extract_as_list, typeslistify, stringlistify, classify_unity_sources,
    get_filenames_templates_dict, substitute_values, has_path_sep,
    OptionKey, PerMachineDefaultable,
    MesonBugException, EnvironmentVariables, pickle_load,
)
from .compilers import (
    is_header, is_object, is_source, clink_langs, sort_clink, all_languages,
    is_known_suffix, detect_static_linker
)
from .interpreterbase import FeatureNew, FeatureDeprecated

if T.TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    from . import environment
    from ._typing import ImmutableListProtocol
    from .backend.backends import Backend
    from .compilers import Compiler
    from .interpreter.interpreter import SourceOutputs, Interpreter
    from .interpreter.interpreterobjects import Test
    from .interpreterbase import SubProject
    from .linkers.linkers import StaticLinker
    from .mesonlib import ExecutableSerialisation, FileMode, FileOrString
    from .modules import ModuleState
    from .mparser import BaseNode
    from .wrap import WrapMode

    GeneratedTypes = T.Union['CustomTarget', 'CustomTargetIndex', 'GeneratedList']
    LibTypes = T.Union['SharedLibrary', 'StaticLibrary', 'CustomTarget', 'CustomTargetIndex']
    BuildTargetTypes = T.Union['BuildTarget', 'CustomTarget', 'CustomTargetIndex']
    ObjectTypes = T.Union[str, 'File', 'ExtractedObjects', 'GeneratedTypes']

    class DFeatures(TypedDict):

        unittest: bool
        debug: T.List[T.Union[str, int]]
        import_dirs: T.List[IncludeDirs]
        versions: T.List[T.Union[str, int]]

pch_kwargs = {'c_pch', 'cpp_pch'}

lang_arg_kwargs = {f'{lang}_args' for lang in all_languages}
lang_arg_kwargs |= {
    'd_import_dirs',
    'd_unittest',
    'd_module_versions',
    'd_debug',
}

vala_kwargs = {'vala_header', 'vala_gir', 'vala_vapi'}
rust_kwargs = {'rust_crate_type', 'rust_dependency_map'}
cs_kwargs = {'resources', 'cs_args'}

buildtarget_kwargs = {
    'build_by_default',
    'build_rpath',
    'dependencies',
    'extra_files',
    'gui_app',
    'link_with',
    'link_whole',
    'link_args',
    'link_depends',
    'implicit_include_directories',
    'include_directories',
    'install',
    'install_rpath',
    'install_dir',
    'install_mode',
    'install_tag',
    'name_prefix',
    'name_suffix',
    'native',
    'objects',
    'override_options',
    'sources',
    'gnu_symbol_visibility',
    'link_language',
    'win_subsystem',
}

known_build_target_kwargs = (
    buildtarget_kwargs |
    lang_arg_kwargs |
    pch_kwargs |
    vala_kwargs |
    rust_kwargs |
    cs_kwargs)

known_exe_kwargs = known_build_target_kwargs | {'implib', 'export_dynamic', 'pie', 'vs_module_defs'}
known_shlib_kwargs = known_build_target_kwargs | {'version', 'soversion', 'vs_module_defs', 'darwin_versions', 'rust_abi'}
known_shmod_kwargs = known_build_target_kwargs | {'vs_module_defs', 'rust_abi'}
known_stlib_kwargs = known_build_target_kwargs | {'pic', 'prelink', 'rust_abi'}
known_jar_kwargs = known_exe_kwargs | {'main_class', 'java_resources'}

def _process_install_tag(install_tag: T.Optional[T.List[T.Optional[str]]],
                         num_outputs: int) -> T.List[T.Optional[str]]:
    _install_tag: T.List[T.Optional[str]]
    if not install_tag:
        _install_tag = [None] * num_outputs
    elif len(install_tag) == 1:
        _install_tag = install_tag * num_outputs
    else:
        _install_tag = install_tag
    return _install_tag


@lru_cache(maxsize=None)
def get_target_macos_dylib_install_name(ld) -> str:
    name = ['@rpath/', ld.prefix, ld.name]
    if ld.soversion is not None:
        name.append('.' + ld.soversion)
    name.append('.dylib')
    return ''.join(name)

class InvalidArguments(MesonException):
    pass

@dataclass(eq=False)
class DependencyOverride(HoldableObject):
    dep: dependencies.Dependency
    node: 'BaseNode'
    explicit: bool = True

@dataclass(eq=False)
class Headers(HoldableObject):
    sources: T.List[File]
    install_subdir: T.Optional[str]
    custom_install_dir: T.Optional[str]
    custom_install_mode: 'FileMode'
    subproject: str
    follow_symlinks: T.Optional[bool] = None

    # TODO: we really don't need any of these methods, but they're preserved to
    # keep APIs relying on them working.

    def set_install_subdir(self, subdir: str) -> None:
        self.install_subdir = subdir

    def get_install_subdir(self) -> T.Optional[str]:
        return self.install_subdir

    def get_sources(self) -> T.List[File]:
        return self.sources

    def get_custom_install_dir(self) -> T.Optional[str]:
        return self.custom_install_dir

    def get_custom_install_mode(self) -> 'FileMode':
        return self.custom_install_mode


@dataclass(eq=False)
class Man(HoldableObject):
    sources: T.List[File]
    custom_install_dir: T.Optional[str]
    custom_install_mode: 'FileMode'
    subproject: str
    locale: T.Optional[str]

    def get_custom_install_dir(self) -> T.Optional[str]:
        return self.custom_install_dir

    def get_custom_install_mode(self) -> 'FileMode':
        return self.custom_install_mode

    def get_sources(self) -> T.List['File']:
        return self.sources


@dataclass(eq=False)
class EmptyDir(HoldableObject):
    path: str
    install_mode: 'FileMode'
    subproject: str
    install_tag: T.Optional[str] = None


@dataclass(eq=False)
class InstallDir(HoldableObject):
    source_subdir: str
    installable_subdir: str
    install_dir: str
    install_dir_name: str
    install_mode: 'FileMode'
    exclude: T.Tuple[T.Set[str], T.Set[str]]
    strip_directory: bool
    subproject: str
    from_source_dir: bool = True
    install_tag: T.Optional[str] = None
    follow_symlinks: T.Optional[bool] = None

@dataclass(eq=False)
class DepManifest:
    version: str
    license: T.List[str]
    license_files: T.List[T.Tuple[str, File]]
    subproject: str

    def to_json(self) -> T.Dict[str, T.Union[str, T.List[str]]]:
        return {
            'version': self.version,
            'license': self.license,
            'license_files': [l[1].relative_name() for l in self.license_files],
        }


# literally everything isn't dataclass stuff
class Build:
    """A class that holds the status of one build including
    all dependencies and so on.
    """

    def __init__(self, environment: environment.Environment):
        self.version = coredata.version
        self.project_name = 'name of master project'
        self.project_version = None
        self.environment = environment
        self.projects: PerMachine[T.Dict[SubProject, str]] = PerMachineDefaultable.default(
            environment.is_cross_build(), {}, {})
        self.targets: 'T.OrderedDict[str, T.Union[CustomTarget, BuildTarget]]' = OrderedDict()
        self.targetnames: T.Set[T.Tuple[str, str]] = set() # Set of executable names and their subdir
        self.global_args: PerMachine[T.Dict[str, T.List[str]]] = PerMachine({}, {})
        self.global_link_args: PerMachine[T.Dict[str, T.List[str]]] = PerMachine({}, {})
        self.projects_args: PerMachine[T.Dict[str, T.Dict[str, T.List[str]]]] = PerMachine({}, {})
        self.projects_link_args: PerMachine[T.Dict[str, T.Dict[str, T.List[str]]]] = PerMachine({}, {})
        self.tests: T.List['Test'] = []
        self.benchmarks: T.List['Test'] = []
        self.headers: T.List[Headers] = []
        self.man: T.List[Man] = []
        self.emptydir: T.List[EmptyDir] = []
        self.data: T.List[Data] = []
        self.symlinks: T.List[SymlinkData] = []
        self.static_linker: PerMachine[StaticLinker] = PerMachineDefaultable.default(
            environment.is_cross_build(), None, None)
        self.subprojects: PerMachine[T.Dict[SubProject, str]] = PerMachineDefaultable.default(
            environment.is_cross_build(), {}, {})
        self.subproject_dir = ''
        self.install_scripts: T.List['ExecutableSerialisation'] = []
        self.postconf_scripts: T.List['ExecutableSerialisation'] = []
        self.dist_scripts: T.List['ExecutableSerialisation'] = []
        self.install_dirs: T.List[InstallDir] = []
        self.dep_manifest_name: T.Optional[str] = None
        self.dep_manifest: T.Dict[str, DepManifest] = {}
        self.stdlibs = PerMachine({}, {})
        self.test_setups: T.Dict[str, TestSetup] = {}
        self.test_setup_default_name = None
        self.find_overrides: PerMachine[T.Dict[str, T.Union['Executable', programs.ExternalProgram, programs.OverrideProgram]]] = PerMachineDefaultable.default(
            environment.is_cross_build(), {}, {})
        # The list of all programs that have been searched for.
        self.searched_programs: PerMachine[T.Set[str]] = PerMachineDefaultable.default(
            environment.is_cross_build(), set(), set())

        # If we are doing a cross build we need two caches, if we're doing a
        # build == host compilation the both caches should point to the same place.
        self.dependency_overrides: PerMachine[T.Dict[T.Tuple, DependencyOverride]] = PerMachineDefaultable.default(
            environment.is_cross_build(), {}, {})
        self.devenv: T.List[EnvironmentVariables] = []
        self.modules: T.List[str] = []

    def get_build_targets(self):
        build_targets = OrderedDict()
        for name, t in self.targets.items():
            if isinstance(t, BuildTarget):
                build_targets[name] = t
        return build_targets

    def get_custom_targets(self):
        custom_targets = OrderedDict()
        for name, t in self.targets.items():
            if isinstance(t, CustomTarget):
                custom_targets[name] = t
        return custom_targets

    def copy(self) -> Build:
        other = Build(self.environment)
        for k, v in self.__dict__.items():
            if isinstance(v, (list, dict, set, OrderedDict)):
                other.__dict__[k] = v.copy()
            else:
                other.__dict__[k] = v
        return other

    def copy_for_build_machine(self) -> Build:
        if not self.environment.is_cross_build() or self.environment.coredata.is_build_only:
            return self.copy()
        new = copy.copy(self)
        new.environment = self.environment.copy_for_build()
        new.projects = PerMachineDefaultable(self.projects.build.copy()).default_missing()
        new.projects_args = PerMachineDefaultable(self.projects_args.build.copy()).default_missing()
        new.projects_link_args = PerMachineDefaultable(self.projects_link_args.build.copy()).default_missing()
        new.subprojects = PerMachineDefaultable(self.subprojects.build.copy()).default_missing()
        new.find_overrides = PerMachineDefaultable(self.find_overrides.build.copy()).default_missing()
        new.searched_programs = PerMachineDefaultable(self.searched_programs.build.copy()).default_missing()
        new.static_linker = PerMachineDefaultable(self.static_linker.build).default_missing()
        new.dependency_overrides = PerMachineDefaultable(self.dependency_overrides.build).default_missing()
        # TODO: the following doesn't seem like it should be necessary
        new.emptydir = []
        new.headers = []
        new.man = []
        new.data = []
        new.symlinks = []
        new.install_scripts = []
        new.postconf_scripts = []
        new.install_dirs = []
        new.test_setups = {}
        new.test_setup_default_name = None
        # TODO: what about dist scripts?

        return new

    def merge(self, other: Build) -> None:
        # TODO: this is incorrect for build-only
        self_is_build_only = self.environment.coredata.is_build_only
        other_is_build_only = other.environment.coredata.is_build_only
        for k, v in other.__dict__.items():
            # This is modified for the build-only config, and we don't want to
            # copy it into the build != host config
            if k == 'environment':
                continue

            # These are install data, and we don't want to install from a build only config
            if other_is_build_only and k in {'emptydir', 'headers', 'man', 'data', 'symlinks',
                                             'install_dirs', 'install_scripts', 'postconf_scripts'}:
                continue

            if self_is_build_only != other_is_build_only:
                assert self_is_build_only is False, 'We should never merge a multi machine subproject into a single machine subproject, right?'
                # TODO: we likely need to drop some other values we're not going to
                #      use like install, man, postconf, etc
                if isinstance(v, PerMachine):
                    # In this case v.build is v.host, and they are both for the
                    # build machine. As such, we need to take only the build values
                    # and not the host values
                    pm: PerMachine = getattr(self, k)
                    pm.build = v.build
                    continue
            setattr(self, k, v)

        self.environment.coredata.merge(other.environment.coredata)

    def ensure_static_linker(self, compiler: Compiler) -> None:
        if self.static_linker[compiler.for_machine] is None and compiler.needs_static_linker():
            self.static_linker[compiler.for_machine] = detect_static_linker(self.environment, compiler)

    def get_project(self) -> str:
        return self.projects.host['']

    def get_subproject_dir(self):
        return self.subproject_dir

    def get_targets(self) -> 'T.OrderedDict[str, T.Union[CustomTarget, BuildTarget]]':
        return self.targets

    def get_tests(self) -> T.List['Test']:
        return self.tests

    def get_benchmarks(self) -> T.List['Test']:
        return self.benchmarks

    def get_headers(self) -> T.List['Headers']:
        return self.headers

    def get_man(self) -> T.List['Man']:
        return self.man

    def get_data(self) -> T.List['Data']:
        return self.data

    def get_symlinks(self) -> T.List['SymlinkData']:
        return self.symlinks

    def get_emptydir(self) -> T.List['EmptyDir']:
        return self.emptydir

    def get_install_subdirs(self) -> T.List['InstallDir']:
        return self.install_dirs

    def get_global_args(self, compiler: 'Compiler', for_machine: 'MachineChoice') -> T.List[str]:
        d = self.global_args[for_machine]
        return d.get(compiler.get_language(), [])

    def get_project_args(self, compiler: 'Compiler', project: str, for_machine: 'MachineChoice') -> T.List[str]:
        d = self.projects_args[for_machine]
        args = d.get(project)
        if not args:
            return []
        return args.get(compiler.get_language(), [])

    def get_global_link_args(self, compiler: 'Compiler', for_machine: 'MachineChoice') -> T.List[str]:
        d = self.global_link_args[for_machine]
        return d.get(compiler.get_language(), [])

    def get_project_link_args(self, compiler: 'Compiler', project: str, for_machine: 'MachineChoice') -> T.List[str]:
        d = self.projects_link_args[for_machine]

        link_args = d.get(project)
        if not link_args:
            return []

        return link_args.get(compiler.get_language(), [])

@dataclass(eq=False)
class IncludeDirs(HoldableObject):

    """Internal representation of an include_directories call."""

    curdir: str
    incdirs: T.List[str]
    is_system: bool
    # Interpreter has validated that all given directories
    # actually exist.
    extra_build_dirs: T.List[str] = field(default_factory=list)

    # We need to know this for stringifying correctly
    is_build_only_subproject: bool = False

    def __repr__(self) -> str:
        r = '<{} {}/{}>'
        return r.format(self.__class__.__name__, self.curdir, self.incdirs)

    def get_curdir(self) -> str:
        return self.curdir

    def get_incdirs(self) -> T.List[str]:
        return self.incdirs

    def expand_incdirs(self, builddir: str) -> T.List[IncludeSubdirPair]:
        pairlist = []

        curdir = self.curdir
        bsubdir = compute_build_subdir(curdir, self.is_build_only_subproject)
        for d in self.incdirs:
            # Avoid superfluous '/.' at the end of paths when d is '.'
            if d not in ('', '.'):
                sdir = os.path.normpath(os.path.join(curdir, d))
                bdir = os.path.normpath(os.path.join(bsubdir, d))
            else:
                sdir = curdir
                bdir = bsubdir

            # There may be include dirs where a build directory has not been
            # created for some source dir. For example if someone does this:
            #
            # inc = include_directories('foo/bar/baz')
            #
            # But never subdir()s into the actual dir.
            if not os.path.isdir(os.path.join(builddir, bdir)):
                bdir = None

            pairlist.append(IncludeSubdirPair(sdir, bdir))

        return pairlist

    def get_extra_build_dirs(self) -> T.List[str]:
        return self.extra_build_dirs

    def expand_extra_build_dirs(self) -> T.List[str]:
        dirlist = []
        bsubdir = compute_build_subdir(self.curdir, self.is_build_only_subproject)
        for d in self.extra_build_dirs:
            dirlist.append(os.path.normpath(os.path.join(bsubdir, d)))
        return dirlist

    def to_string_list(self, sourcedir: str, builddir: str) -> T.List[str]:
        """Convert IncludeDirs object to a list of strings.

        :param sourcedir: The absolute source directory
        :param builddir: The absolute build directory, option, build dir will not
            be added if this is unset
        :returns: A list of strings (without compiler argument)
        """
        strlist: T.List[str] = []
        for d in self.expand_incdirs(builddir):
            strlist.append(os.path.join(sourcedir, d.source))
            if d.build is not None:
                strlist.append(os.path.join(builddir, d.build))
        return strlist

@dataclass
class IncludeSubdirPair:
    source: str
    build: T.Optional[str]

@dataclass(eq=False)
class ExtractedObjects(HoldableObject):
    '''
    Holds a list of sources for which the objects must be extracted
    '''
    target: 'BuildTarget'
    srclist: T.List[File] = field(default_factory=list)
    genlist: T.List['GeneratedTypes'] = field(default_factory=list)
    objlist: T.List[T.Union[str, 'File', 'ExtractedObjects']] = field(default_factory=list)
    recursive: bool = True
    pch: bool = False

    def __post_init__(self) -> None:
        if self.target.is_unity:
            self.check_unity_compatible()

    def __repr__(self) -> str:
        r = '<{0} {1!r}: {2}>'
        return r.format(self.__class__.__name__, self.target.name, self.srclist)

    @staticmethod
    def get_sources(sources: T.Sequence['FileOrString'], generated_sources: T.Sequence['GeneratedTypes']) -> T.List['FileOrString']:
        # Merge sources and generated sources
        sources = list(sources)
        for gensrc in generated_sources:
            for s in gensrc.get_outputs():
                # We cannot know the path where this source will be generated,
                # but all we need here is the file extension to determine the
                # compiler.
                sources.append(s)

        # Filter out headers and all non-source files
        return [s for s in sources if is_source(s)]

    def classify_all_sources(self, sources: T.List[FileOrString], generated_sources: T.Sequence['GeneratedTypes']) -> T.Dict['Compiler', T.List['FileOrString']]:
        sources_ = self.get_sources(sources, generated_sources)
        return classify_unity_sources(self.target.compilers.values(), sources_)

    def check_unity_compatible(self) -> None:
        # Figure out if the extracted object list is compatible with a Unity
        # build. When we're doing a Unified build, we go through the sources,
        # and create a single source file from each subset of the sources that
        # can be compiled with a specific compiler. Then we create one object
        # from each unified source file. So for each compiler we can either
        # extra all its sources or none.
        cmpsrcs = self.classify_all_sources(self.target.sources, self.target.generated)
        extracted_cmpsrcs = self.classify_all_sources(self.srclist, self.genlist)

        for comp, srcs in extracted_cmpsrcs.items():
            if set(srcs) != set(cmpsrcs[comp]):
                raise MesonException('Single object files cannot be extracted '
                                     'in Unity builds. You can only extract all '
                                     'the object files for each compiler at once.')


@dataclass(eq=False, order=False)
class StructuredSources(HoldableObject):

    """A container for sources in languages that use filesystem hierarchy.

    Languages like Rust and Cython rely on the layout of files in the filesystem
    as part of the compiler implementation. This structure allows us to
    represent the required filesystem layout.
    """

    sources: T.DefaultDict[str, T.List[T.Union[File, CustomTarget, CustomTargetIndex, GeneratedList]]] = field(
        default_factory=lambda: defaultdict(list))

    def __add__(self, other: StructuredSources) -> StructuredSources:
        sources = self.sources.copy()
        for k, v in other.sources.items():
            sources[k].extend(v)
        return StructuredSources(sources)

    def __bool__(self) -> bool:
        return bool(self.sources)

    def first_file(self) -> T.Union[File, CustomTarget, CustomTargetIndex, GeneratedList]:
        """Get the first source in the root

        :return: The first source in the root
        """
        return self.sources[''][0]

    def as_list(self) -> T.List[T.Union[File, CustomTarget, CustomTargetIndex, GeneratedList]]:
        return list(itertools.chain.from_iterable(self.sources.values()))

    def needs_copy(self) -> bool:
        """Do we need to create a structure in the build directory.

        This allows us to avoid making copies if the structures exists in the
        source dir. Which could happen in situations where a generated source
        only exists in some configurations
        """
        for files in self.sources.values():
            for f in files:
                if isinstance(f, File):
                    if f.is_built:
                        return True
                else:
                    return True
        return False


@dataclass(eq=False)
class Target(HoldableObject, metaclass=abc.ABCMeta):

    name: str
    subdir: str
    subproject: 'SubProject'
    build_by_default: bool
    for_machine: MachineChoice
    environment: environment.Environment
    build_only_subproject: bool
    install: bool = False
    build_always_stale: bool = False
    extra_files: T.List[File] = field(default_factory=list)
    override_options: InitVar[T.Optional[T.Dict[OptionKey, str]]] = None

    @abc.abstractproperty
    def typename(self) -> str:
        pass

    @abc.abstractmethod
    def type_suffix(self) -> str:
        pass

    def __post_init__(self, overrides: T.Optional[T.Dict[OptionKey, str]]) -> None:
        # Patch up a few things if this is a build_only_subproject.
        # We don't want to do any installation from such a project,
        # and we need to set the machine to build to get the right compilers
        if self.build_only_subproject:
            self.install = False
            self.for_machine = MachineChoice.BUILD

        if overrides:
            ovr = {k.evolve(machine=self.for_machine) if k.lang else k: v
                   for k, v in overrides.items()}
        else:
            ovr = {}
        self.options = coredata.OptionsView(self.environment.coredata.options, self.subproject, ovr)
        # XXX: this should happen in the interpreter
        if has_path_sep(self.name):
            # Fix failing test 53 when this becomes an error.
            mlog.warning(textwrap.dedent(f'''\
                Target "{self.name}" has a path separator in its name.
                This is not supported, it can cause unexpected failures and will become
                a hard error in the future.'''))

    # dataclass comparators?
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self.get_id() < other.get_id()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self.get_id() <= other.get_id()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self.get_id() > other.get_id()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self.get_id() >= other.get_id()

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        raise NotImplementedError

    def get_custom_install_dir(self) -> T.List[T.Union[str, Literal[False]]]:
        raise NotImplementedError

    def get_install_dir(self) -> T.Tuple[T.List[T.Union[str, Literal[False]]], T.List[T.Optional[str]], bool]:
        # Find the installation directory.
        default_install_dir, default_install_dir_name = self.get_default_install_dir()
        outdirs: T.List[T.Union[str, Literal[False]]] = self.get_custom_install_dir()
        install_dir_names: T.List[T.Optional[str]]
        if outdirs and outdirs[0] != default_install_dir and outdirs[0] is not True:
            # Either the value is set to a non-default value, or is set to
            # False (which means we want this specific output out of many
            # outputs to not be installed).
            custom_install_dir = True
            install_dir_names = [getattr(i, 'optname', None) for i in outdirs]
        else:
            custom_install_dir = False
            # if outdirs is empty we need to set to something, otherwise we set
            # only the first value to the default.
            if outdirs:
                outdirs[0] = default_install_dir
            else:
                outdirs = [default_install_dir]
            install_dir_names = [default_install_dir_name] * len(outdirs)

        return outdirs, install_dir_names, custom_install_dir

    def get_basename(self) -> str:
        return self.name

    def get_source_subdir(self) -> str:
        return self.subdir

    def get_output_subdir(self) -> str:
        return compute_build_subdir(self.subdir, self.build_only_subproject)

    def get_typename(self) -> str:
        return self.typename

    @staticmethod
    def _get_id_hash(target_id: str) -> str:
        # We don't really need cryptographic security here.
        # Small-digest hash function with unlikely collision is good enough.
        h = hashlib.sha256()
        h.update(target_id.encode(encoding='utf-8', errors='replace'))
        # This ID should be case-insensitive and should work in Visual Studio,
        # e.g. it should not start with leading '-'.
        return h.hexdigest()[:7]

    @staticmethod
    def construct_id_from_path(subdir: str, name: str, type_suffix: str, build_subproject: bool = False) -> str:
        """Construct target ID from subdir, name and type suffix.

        This helper function is made public mostly for tests."""
        # This ID must also be a valid file name on all OSs.
        # It should also avoid shell metacharacters for obvious
        # reasons. '@' is not used as often as '_' in source code names.
        # In case of collisions consider using checksums.
        # FIXME replace with assert when slash in names is prohibited
        name_part = name.replace('/', '@').replace('\\', '@')
        assert not has_path_sep(type_suffix)
        my_id = name_part + type_suffix
        if subdir:
            subdir_part = Target._get_id_hash(subdir)
            # preserve myid for better debuggability
            my_id = f'{subdir_part}@@{my_id}'
        if build_subproject:
            my_id = f'build.{my_id}'
        return my_id

    def get_id(self) -> str:
        """Get the unique ID of the target.

        :return: A unique string id
        """
        name = self.name
        if getattr(self, 'name_suffix_set', False):
            name += '.' + self.suffix
        return self.construct_id_from_path(
            self.subdir, name, self.type_suffix(), self.build_only_subproject)

    def process_kwargs_base(self, kwargs: T.Dict[str, T.Any]) -> None:
        if 'build_by_default' in kwargs:
            self.build_by_default = kwargs['build_by_default']
            if not isinstance(self.build_by_default, bool):
                raise InvalidArguments('build_by_default must be a boolean value.')

        if not self.build_by_default and kwargs.get('install', False):
            # For backward compatibility, if build_by_default is not explicitly
            # set, use the value of 'install' if it's enabled.
            self.build_by_default = True

        self.set_option_overrides(self.parse_overrides(kwargs))

    def set_option_overrides(self, option_overrides: T.Dict[OptionKey, str]) -> None:
        self.options.overrides = {}
        for k, v in option_overrides.items():
            if k.lang:
                self.options.overrides[k.evolve(machine=self.for_machine)] = v
            else:
                self.options.overrides[k] = v

    def get_options(self) -> coredata.OptionsView:
        return self.options

    def get_option(self, key: 'OptionKey') -> T.Union[str, int, bool, 'WrapMode']:
        # We don't actually have wrapmode here to do an assert, so just do a
        # cast, we know what's in coredata anyway.
        # TODO: if it's possible to annotate get_option or validate_option_value
        # in the future we might be able to remove the cast here
        return T.cast('T.Union[str, int, bool, WrapMode]', self.options[key].value)

    @staticmethod
    def parse_overrides(kwargs: T.Dict[str, T.Any]) -> T.Dict[OptionKey, str]:
        opts = kwargs.get('override_options', [])

        # In this case we have an already parsed and ready to go dictionary
        # provided by typed_kwargs
        if isinstance(opts, dict):
            return T.cast('T.Dict[OptionKey, str]', opts)

        result: T.Dict[OptionKey, str] = {}
        overrides = stringlistify(opts)
        for o in overrides:
            if '=' not in o:
                raise InvalidArguments('Overrides must be of form "key=value"')
            k, v = o.split('=', 1)
            key = OptionKey.from_string(k.strip())
            v = v.strip()
            result[key] = v
        return result

    def is_linkable_target(self) -> bool:
        return False

    def get_outputs(self) -> T.List[str]:
        return []

    def should_install(self) -> bool:
        return False

class BuildTarget(Target):
    known_kwargs = known_build_target_kwargs

    install_dir: T.List[T.Union[str, Literal[False]]]

    # This set contains all the languages a linker can link natively
    # without extra flags. For instance, nvcc (cuda) can link C++
    # without injecting -lc++/-lstdc++, see
    #   https://github.com/mesonbuild/meson/issues/10570
    _MASK_LANGS: T.FrozenSet[T.Tuple[str, str]] = frozenset([
        # (language, linker)
        ('cpp', 'cuda'),
    ])

    def __init__(
            self,
            name: str,
            subdir: str,
            subproject: SubProject,
            for_machine: MachineChoice,
            sources: T.List['SourceOutputs'],
            structured_sources: T.Optional[StructuredSources],
            objects: T.List[ObjectTypes],
            environment: environment.Environment,
            compilers: T.Dict[str, 'Compiler'],
            build_only_subproject: bool,
            kwargs: T.Dict[str, T.Any]):
        super().__init__(name, subdir, subproject, True, for_machine, environment, build_only_subproject, install=kwargs.get('install', False))
        self.all_compilers = compilers
        self.compilers: OrderedDict[str, Compiler] = OrderedDict()
        s
"""


```