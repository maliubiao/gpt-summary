Response:
The user wants me to analyze a Python source code file for the Frida dynamic instrumentation tool. I need to extract its functionalities, relate them to reverse engineering if applicable, point out interactions with the binary level, Linux/Android kernel/frameworks, analyze logical inferences based on inputs/outputs, highlight potential user errors, explain how a user might reach this code during debugging, and finally summarize its overall purpose.

**Plan:**

1. **Scan the code for key classes, functions, and data structures.** Identify the main components and their interactions.
2. **Analyze the functionalities of each major component.** Focus on what they do and how they contribute to the overall purpose of the file.
3. **Relate the functionalities to reverse engineering concepts.**  Look for actions like inspecting binaries, manipulating memory, or hooking functions.
4. **Identify interactions with the binary level, OS kernels, and frameworks.** Pay attention to concepts like linking, object files, libraries, and platform-specific features.
5. **Infer logical reasoning and provide input/output examples.**  Where the code manipulates data based on conditions, create hypothetical scenarios.
6. **Spot potential user errors.** Look for configuration options, input validation, and assumptions that could lead to mistakes.
7. **Trace how a user might end up interacting with this file.** Consider the development and debugging workflows for Frida.
8. **Synthesize a summary of the file's role.** Combine all the findings into a concise description of its purpose.
这是 `frida/subprojects/frida-python/releng/meson/mesonbuild/build.py` 文件的第一部分源代码，它定义了 Frida 的 Python 绑定构建过程中使用的各种数据结构和构建逻辑。以下是根据代码内容归纳的功能点：

**主要功能:**

1. **定义构建过程中的数据结构:**
   -  定义了 `Build` 类，它是构建过程的核心状态容器，包含了项目信息、目标（targets）、测试、安装信息等。
   -  定义了各种数据类（使用 `@dataclass`），用于表示构建过程中的实体，例如：
      - `DependencyOverride`: 描述依赖项的覆盖。
      - `Headers`, `Man`, `EmptyDir`, `InstallDir`: 描述需要安装的文件、目录等。
      - `DepManifest`: 描述依赖项的元数据。
      - `IncludeDirs`: 表示包含目录。
      - `ExtractedObjects`: 表示需要提取的对象文件。
      - `StructuredSources`: 表示结构化的源代码（例如 Rust）。
      - `Target`, `BuildTarget`:  抽象和具体的构建目标定义。

2. **管理构建目标 (Targets):**
   -  `Build` 类中的 `targets` 属性存储了所有构建目标（可执行文件、库等）。
   -  定义了 `BuildTarget` 类，它继承自 `Target`，表示一个需要编译和链接的构建目标。
   -  `BuildTarget` 包含了源代码、对象文件、编译器信息、链接选项等。

3. **处理依赖关系:**
   -  `DependencyOverride` 类用于在构建过程中覆盖默认的依赖项。
   -  `Build` 类中包含 `dependency_overrides` 属性来存储这些覆盖。

4. **管理安装信息:**
   -  定义了 `Headers`, `Man`, `EmptyDir`, `InstallDir`, `Data`, `SymlinkData` 等数据类，用于描述需要在构建后安装的文件和目录。
   -  `BuildTarget` 类具有 `install` 属性，指示是否需要安装此目标。

5. **处理编译和链接参数:**
   -  `Build` 类中包含 `global_args`, `global_link_args`, `projects_args`, `projects_link_args` 等属性，用于存储全局和项目级别的编译和链接参数。
   -  `BuildTarget` 类可以访问和管理与特定语言相关的编译和链接参数。

6. **支持交叉编译:**
   -  使用 `PerMachine` 类型来区分主机（host）和目标（target）机器的配置。
   -  `Build` 类可以被复制用于构建机器 (`copy_for_build_machine`)，以便在交叉编译环境中处理构建工具。

7. **处理包含目录:**
   -  `IncludeDirs` 类用于表示包含目录，并可以将其展开为绝对路径。

8. **处理源代码:**
   -  `StructuredSources` 类用于处理需要特定文件系统布局的语言的源代码。
   -  `ExtractedObjects` 用于处理从特定源文件提取对象的情况，这在 Unity 构建中很重要。

**与逆向方法的关联及举例说明:**

虽然此代码本身主要是构建系统的定义，但其最终产物——Frida Python 绑定——是用于动态逆向的工具。这个构建脚本确保了 Frida Python 绑定能够正确地被编译和链接。

**举例说明:**

- **构建共享库 (`SharedLibrary` 未在此部分代码中完整定义，但可以推断):**  逆向工程师使用 Frida Python 绑定来连接到目标进程并执行 JavaScript 代码。这个脚本会确保 Frida 的 C++ 核心库被编译成共享库（如 `.so` 或 `.dylib`），并且 Python 绑定能够正确地链接到这个库。
- **处理依赖项 (`DependencyOverride`):** 在逆向过程中，可能需要特定的库版本。这个脚本允许覆盖默认的依赖项，确保 Frida Python 绑定依赖于正确的库版本，这对于确保逆向工具的稳定性和兼容性至关重要。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

- **二进制底层:**
    - **对象文件 (`objects` 属性, `ExtractedObjects`):**  此代码处理将源代码编译成对象文件的过程。对象文件是二进制代码的中间产物，最终被链接成可执行文件或库。
    - **链接 (`link_with`, `link_args` 等 `BuildTarget` 的属性):** 代码处理链接器（linker）的调用和参数传递，将多个对象文件和库组合成最终的二进制文件。
    - **共享库版本 (`version`, `soversion` 等 `known_shlib_kwargs`):**  对于共享库，代码处理版本信息的设置，这对于动态链接和库的兼容性非常重要。
- **Linux/Android 内核及框架:**
    - **安装路径 (`install_dir` 等属性):** 代码定义了构建产物的安装路径，例如，Frida 的守护进程可能需要安装到特定的系统目录下。
    - **Rpath (`build_rpath`, `install_rpath`):**  代码处理 Rpath 的设置，Rpath 告诉动态链接器在哪里查找共享库。在 Android 和 Linux 中，正确设置 Rpath 对于 Frida 能够找到其依赖的库至关重要。
    - **共享库和动态链接:**  Frida 的核心功能通常以共享库的形式提供，Python 绑定需要加载这些共享库才能工作。这个构建脚本确保了共享库的正确生成和安装。

**逻辑推理及假设输入与输出:**

- **假设输入:**  一个名为 `mylib` 的共享库目标，源代码文件为 `mylib.c`，需要安装到 `/usr/lib` 目录下。
- **代码逻辑:** `BuildTarget` 实例会根据输入参数 (`name='mylib'`, `sources=['mylib.c']`, `install=True`, `install_dir=['/usr/lib']`) 来设置其内部属性。
- **输出 (概念性的):**  Meson 构建系统会根据这些信息生成构建规则，指示编译器如何编译 `mylib.c`，链接器如何生成共享库，以及安装程序如何将生成的共享库复制到 `/usr/lib`。

**涉及用户或者编程常见的使用错误及举例说明:**

- **错误的 `override_options` 格式:** 用户可能在 `override_options` 中提供格式错误的字符串，例如 `"myopt value"` 而不是 `"myopt=value"`，这会导致 `Target.parse_overrides` 中抛出 `InvalidArguments` 异常。
- **在 Unity 构建中提取单个对象文件:**  `ExtractedObjects.check_unity_compatible` 会检查在 Unity 构建中是否尝试提取单个源文件的对象。如果用户尝试这样做，会抛出 `MesonException`，因为 Unity 构建要求要么提取某个编译器支持的所有源文件的对象，要么都不提取。
- **目标名称中包含路径分隔符:**  虽然目前只是一个警告，但未来可能会变成错误。用户在定义目标名称时，如果使用了 `/` 或 `\` 等路径分隔符，可能会导致构建问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户修改了 Frida Python 绑定的源代码或构建配置。**
2. **用户运行 `meson` 命令来配置构建。** Meson 会读取 `meson.build` 文件，其中包括对 `frida-python` 子项目的引用。
3. **Meson 进入 `frida-python` 子项目，并执行其 `meson.build` 文件。**
4. **`frida-python` 的 `meson.build` 文件会调用 Meson 的内置函数来定义构建目标（例如 `shared_library`, `executable`）。**
5. **当 Meson 处理这些构建目标定义时，会创建相应的 `BuildTarget` 或其他 `Target` 类的实例。**
6. **`mesonbuild/build.py` 文件中的代码负责定义这些数据结构，并处理构建目标的各种属性和依赖关系。**
7. **如果构建过程中出现错误，例如依赖项找不到或编译选项错误，用户可能会查看 Meson 的日志输出，其中会包含与这些数据结构相关的信息。**
8. **如果用户需要深入了解构建过程，或者需要调试 Meson 本身的行为，他们可能会直接查看 `mesonbuild/build.py` 的源代码。**

**总结一下它的功能:**

此部分代码定义了 Frida Python 绑定构建过程中使用的核心数据模型和逻辑。它负责表示构建目标、管理依赖关系、处理编译和链接参数、定义安装信息，并支持交叉编译。它是 Meson 构建系统如何理解和执行 Frida Python 绑定构建任务的基础。它为构建过程提供了结构化的表示，使得 Meson 可以有效地生成构建规则并执行实际的编译和链接操作。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```python
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
```