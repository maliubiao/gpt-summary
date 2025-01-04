Response:
My thinking process to answer the request about the `build.py` file goes through these stages:

1. **Understanding the Request:**  The core request is to analyze a Python file (`build.py`) within the Frida project, specifically focusing on its functionality, relationship to reverse engineering, interaction with low-level systems, logical inferences, potential user errors, and how a user might reach this code. It's crucial to remember this is only part 1 of 5, so a general overview is expected.

2. **Initial Scan and Keyword Recognition:**  I quickly scanned the code, looking for recognizable keywords and patterns. I noticed imports like `os`, `pickle`, `hashlib`, and mentions of `linux`, `android`, and various build-related terms (targets, libraries, compilers, linkers). This immediately suggested the file is involved in the build process of a software project.

3. **Identifying Core Functionality - The "Build" Class:** The presence of a class named `Build` is highly significant. It strongly suggests this class is the central data structure holding the state and configuration of a software build. I noted its attributes, which include project name, version, environment, targets, tests, dependencies, compiler settings, and install locations.

4. **Connecting to Reverse Engineering:**  Frida is a dynamic instrumentation toolkit, heavily used in reverse engineering. Therefore, I looked for clues in the code that would tie into this domain. The presence of `link_args`, `include_directories`, and the handling of different target types (executables, shared libraries, static libraries) are all relevant. Reverse engineering often involves manipulating and understanding how binaries are built and linked.

5. **Identifying Low-Level and OS Interactions:**  Keywords like `linux`, `android`, `kernel`, and the handling of file paths and system commands (implied by interactions with compilers and linkers) point towards the file's involvement in managing aspects related to the underlying operating system and potentially kernel interactions.

6. **Analyzing Data Structures and Logic:** I paid attention to data structures like `OrderedDict`, `defaultdict`, `dataclass`, and how they are used. The presence of methods like `merge`, `copy`, and `get_targets` indicates the file manages and manipulates the build state. The `@lru_cache` decorator suggests optimization through memoization, common in build systems.

7. **Inferring Logical Inferences:** The code isn't a standalone script; it's part of a larger build system. The logical inferences are primarily about how the build process is structured:  defining targets, managing dependencies, applying compiler flags, and organizing output files. I considered the inputs (source code, configuration files) and outputs (executables, libraries) of this process.

8. **Considering User Errors:**  I thought about common mistakes users make when configuring build systems. Incorrect file paths, missing dependencies, wrong compiler flags, or trying to install files to restricted locations are typical errors. The `InvalidArguments` exception class hints at input validation.

9. **Tracing User Interaction (as a Debugging Clue):**  I imagined the steps a user would take to trigger this code. They would likely be running a build command (like `meson build`), which would parse a `meson.build` file. This file would define targets, dependencies, and other build settings, eventually leading to the execution of this `build.py` script to manage the build process.

10. **Focusing on Part 1 Summary:** Since the prompt explicitly states "Part 1," I knew I needed to provide a high-level overview of the file's primary function rather than diving into excessive detail of every class and method.

11. **Structuring the Answer:** I organized my findings into the categories requested by the prompt: Functionality, Relationship to Reversing, Binary/OS Knowledge, Logical Inferences, User Errors, and User Operation as Debugging. This provides a clear and structured response.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this file directly interacts with Frida's instrumentation engine.
* **Correction:** On closer inspection, it's more about the *build process* of Frida itself, rather than the instrumentation logic. The connection to reverse engineering is through *how* Frida is built.
* **Initial thought:** Focus on individual functions.
* **Refinement:** Emphasize the `Build` class as the central element and how the different parts of the file contribute to managing the build state.
* **Initial thought:** Provide very specific examples.
* **Refinement:**  Since this is part 1, broader examples illustrating the *types* of interactions are more appropriate than deeply technical, specific scenarios.

By following these steps, I could generate a comprehensive answer that addresses all aspects of the user's request while remaining focused on the specific context of the provided code snippet.
好的，让我们来分析一下 `frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py` 文件（第一部分）。

**文件功能归纳:**

从提供的代码片段来看，`build.py` 文件是 Meson 构建系统中负责**管理和描述软件构建过程**的核心组件。它定义了各种数据结构和类，用于表示构建目标、依赖关系、编译器设置、安装规则等。 它的主要功能可以概括为：

1. **数据结构定义:**  定义了大量的数据类 (`dataclass`) 和普通类，用于组织和存储构建过程中的各种信息，例如：
    * `Build`:  代表整个构建状态，包含项目名称、版本、目标、测试、依赖、编译器设置等。
    * `Target`:  所有构建目标的基类，定义了目标的基本属性和方法。
    * `BuildTarget`:  可执行文件、共享库、静态库等具体构建目标的类。
    * `CustomTarget`:  用于执行自定义构建步骤的目标类。
    * `DependencyOverride`:  用于覆盖默认依赖的类。
    * `Headers`, `Man`, `EmptyDir`, `InstallDir`, `Data`, `SymlinkData`:  表示不同类型的安装目标。
    * `IncludeDirs`:  表示头文件包含路径。
    * `ExtractedObjects`:  表示需要从目标文件中提取的对象。
    * `StructuredSources`:  用于表示需要保持特定目录结构的源文件。
    * 还有一些辅助的数据类，如 `DependencyOverride`, `Headers`, `Man` 等。

2. **构建目标管理:**  `Build` 类维护了一个 `targets` 字典，用于存储所有定义的构建目标。它提供了方法来获取不同类型的目标（可执行文件、自定义目标等）。

3. **依赖关系管理:**  虽然代码片段中没有直接展示依赖解析的逻辑，但 `BuildTarget` 类中存在 `dependencies` 关键字参数，表明这个文件负责处理构建目标之间的依赖关系。`DependencyOverride` 类则允许用户自定义依赖项。

4. **编译器和链接器配置:**  代码中引入了 `compilers` 和 `linkers` 模块，`Build` 类中也存储了全局和项目级别的编译/链接参数 (`global_args`, `global_link_args`, `projects_args`, `projects_link_args`)。 这表明该文件负责管理编译器和链接器的配置。

5. **安装规则管理:**  定义了各种用于描述安装行为的数据类，例如 `Headers`, `Man`, `EmptyDir`, `InstallDir`，以及相关的安装目录和模式。

6. **选项管理:**  `Target` 类和 `Build` 类都与选项 (`options`) 相关，用于管理构建过程中的各种配置选项。

7. **Subproject 管理:**  `Build` 类中存在 `subprojects` 属性，表明它也负责管理子项目。

**与逆向方法的关联 (举例说明):**

`build.py` 虽然本身不是直接的逆向工具，但它描述了 Frida 的构建过程，这对于逆向分析 Frida 本身或者使用 Frida 进行逆向工作非常有帮助。

* **理解 Frida 的模块结构:** 通过分析 `build.py` 中定义的构建目标 (例如，共享库、可执行文件)，逆向工程师可以更好地理解 Frida 的内部模块划分和依赖关系。例如，可能会看到 Frida QML 相关的库是如何构建的，依赖于哪些其他的 Frida 组件。

* **查找关键组件的构建方式:**  如果逆向工程师想深入了解 Frida 的某个特定功能是如何实现的，可以查看 `build.py` 中对应构建目标的定义，找到相关的源文件和编译选项。例如，想要分析 Frida 的核心注入机制，可以查找与注入相关的库或可执行文件的构建配置。

* **定制 Frida 的构建:** 了解 `build.py` 的结构可以帮助逆向工程师修改 Frida 的构建过程，例如添加自定义的编译选项、修改链接行为，以便更好地进行特定的逆向任务。 例如，可能需要添加特定的调试符号，或者禁用某些优化选项。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

`build.py`  在定义构建过程时，不可避免地会涉及到与底层系统相关的概念：

* **二进制文件类型:** 代码中区分了不同类型的构建目标，如共享库 (`SharedLibrary`)、静态库 (`StaticLibrary`) 和可执行文件 (`Executable`)。这些都是操作系统中常见的二进制文件类型。

* **链接 (Linking):** `link_with`, `link_args`, `link_depends` 等关键字参数以及 `static_linker` 属性都与二进制文件的链接过程密切相关。链接是将编译后的目标文件组合成最终可执行文件或库的过程，这涉及到符号解析、地址重定位等底层概念。

* **库的版本管理 (`version`, `soversion`, `darwin_versions`):** 对于共享库，代码中处理了版本信息，这在 Linux 和 macOS 等系统中用于实现库的兼容性和管理。

* **运行时路径 (`build_rpath`, `install_rpath`):** 这些参数用于设置程序运行时查找共享库的路径，这在 Linux 和其他类 Unix 系统中是一个重要的概念。

* **Android 框架 (间接体现):**  虽然代码片段中没有直接提及 Android 内核或框架的细节，但考虑到 `frida-qml` 是 Frida 的一个子项目，并且 Frida 广泛应用于 Android 平台的逆向分析，可以推断出 `build.py` 的配置会间接地考虑到 Android 平台的特殊性，例如编译 Android 平台的库需要使用特定的工具链和参数。

**逻辑推理 (假设输入与输出):**

假设 `build.py` 中的某个函数，例如处理 `include_directories` 的函数，接收到一个包含相对路径的列表作为输入：

* **假设输入:**
  ```python
  include_dirs_data = {
      'curdir': 'src/module_a',
      'incdirs': ['include', '../common_include'],
      'is_system': False
  }
  ```

* **逻辑推理:**  该函数会根据 `curdir` 将相对路径转换为绝对路径，并考虑构建目录的结构。它可能还会检查这些目录是否存在。

* **预期输出:**
  ```python
  # 假设构建目录是 'build'，源代码目录是 'source'
  expanded_include_dirs = [
      'source/src/module_a/include',
      'source/src/common_include'
  ]
  ```
  以及在构建目录中对应的路径 (如果需要):
  ```python
  expanded_build_include_dirs = [
      'build/src/module_a/include',
      'build/src/common_include'
  ]
  ```
  具体实现会根据 `IncludeDirs` 类中的 `expand_incdirs` 方法来确定。

**用户或编程常见的使用错误 (举例说明):**

* **错误的依赖指定:** 用户可能在 `meson.build` 文件中指定了不存在的依赖项，或者循环依赖。`build.py` 的相关逻辑在处理依赖时可能会抛出异常。

* **错误的路径配置:** 用户在 `include_directories` 或其他涉及到路径的配置中使用了错误的路径，导致编译器找不到头文件或库文件。

* **编译选项错误:** 用户可能在 `*_args` 中指定了编译器不支持的选项，导致编译失败。

* **安装目录冲突:** 用户可能为不同的目标指定了相同的安装目录，导致安装过程出现问题。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户编写 `meson.build` 文件:**  用户首先会创建一个 `meson.build` 文件，在其中定义项目的构建目标、依赖关系、源文件、安装规则等。 例如，使用 `executable()` 函数定义一个可执行文件，使用 `shared_library()` 定义一个共享库。

2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建系统。Meson 会解析 `meson.build` 文件，并根据用户的配置和系统环境生成构建所需的中间文件。

3. **Meson 解析 `meson.build` 并创建 `Build` 对象:**  在解析 `meson.build` 文件的过程中，Meson 会创建 `Build` 类的实例，并将 `meson.build` 文件中定义的各种目标、依赖、选项等信息存储到这个对象中。 `build.py` 文件中的代码会被执行，用于创建和管理这些数据结构。

4. **用户运行构建命令 (例如 `ninja`):**  用户运行实际的构建命令，例如 `ninja -C <build_directory>`。

5. **构建工具 (如 Ninja) 使用 `Build` 对象的信息:**  构建工具会读取 Meson 生成的构建文件（这些文件是根据 `Build` 对象中的信息生成的），并执行相应的编译、链接、安装等操作。

**作为调试线索:** 如果构建过程中出现错误，例如找不到源文件、链接错误、安装失败等，开发者可以：

* **检查 `meson.build` 文件:**  确认目标、依赖、路径等配置是否正确。
* **查看 Meson 的配置输出:**  Meson 在配置阶段会输出很多信息，可以从中查看目标是如何定义的，依赖关系是什么，使用了哪些编译选项等。
* **调试 `build.py` 代码 (如果需要深入了解 Meson 的行为):**  虽然通常不需要直接修改或调试 `build.py`，但在某些复杂的情况下，了解 `build.py` 的内部逻辑可以帮助理解 Meson 的行为，从而找到配置错误的原因。例如，可以通过打印 `Build` 对象的内容来查看 Meson 是如何解析 `meson.build` 文件的。

**第一部分功能总结:**

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py` 的第一部分主要负责定义 Meson 构建系统用于描述和管理软件构建过程的核心数据结构和类。它为后续的构建步骤（如代码编译、链接、安装）提供了必要的信息和框架。它涉及到操作系统底层概念、编译器和链接器的知识，并且其结构设计直接影响着用户如何配置和构建软件项目。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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