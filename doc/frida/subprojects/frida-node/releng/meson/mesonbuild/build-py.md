Response:
My thinking process to analyze the provided Python code and generate the summary involved these steps:

1. **Identify the Core Purpose:**  The first line, `# SPDX-License-Identifier: Apache-2.0`, and the surrounding comments hint at this being part of a larger build system (Meson). The filename `build.py` within a `mesonbuild` directory reinforces this. The comment "A class that holds the status of one build including all dependencies and so on" in the `Build` class is a crucial clue.

2. **Break Down the File Structure:** I scanned the imports at the beginning. These imports reveal several key areas:
    * Standard Python libraries (`collections`, `dataclasses`, `functools`, `hashlib`, `itertools`, `os`, `pickle`, `re`, `textwrap`, `typing`). This suggests the file deals with data structures, file system operations, and type hinting.
    * Specific Meson modules (`.`, `coredata`, `dependencies`, `mlog`, `programs`, `mesonlib`, `compilers`, `interpreterbase`). This confirms it's a Meson component and interacts with other parts of the build system.

3. **Focus on Key Classes and Data Structures:** I looked for the major classes defined in the file:
    * `DependencyOverride`, `Headers`, `Man`, `EmptyDir`, `InstallDir`, `DepManifest`: These appear to represent different types of build outputs or configuration elements.
    * `Build`: This seems to be the central class, holding information about the entire build process. The comment confirms this. I noted its attributes (e.g., `targets`, `tests`, `dependencies`, `global_args`).
    * `IncludeDirs`, `IncludeSubdirPair`:  These relate to managing include paths for compilation.
    * `ExtractedObjects`:  This class likely deals with extracting object files from source.
    * `StructuredSources`:  This is for managing source files in a hierarchical manner, relevant for languages like Rust.
    * `Target`, `BuildTarget`:  These represent different types of build targets (e.g., executables, libraries). The inheritance suggests a common base.

4. **Analyze Class Attributes and Methods:**  For each significant class, I examined its attributes and methods, paying attention to their names and type hints. This helped me infer their purpose:
    * `Build` methods like `get_targets`, `get_tests`, `get_global_args`, `copy`, `merge` indicate its role in managing build information.
    * `IncludeDirs` methods like `expand_incdirs`, `to_string_list` suggest operations on include paths.
    * `Target` methods like `get_id`, `get_outputs`, `should_install` relate to identifying and managing build targets.

5. **Look for Connections to Reverse Engineering, Binary/Kernel Concepts:** I specifically looked for keywords or concepts related to the prompt:
    * **Reverse Engineering:**  While the code itself isn't *performing* reverse engineering, the context of Frida (mentioned in the prompt) is directly related. The ability to manage dependencies, compile code, and link libraries is *essential* for building tools used in reverse engineering (like Frida itself).
    * **Binary/Low-Level:** The presence of concepts like "objects," "link_args," "static_linker," and the handling of different languages (C, C++, Rust, etc.) points to interaction with binary compilation and linking processes.
    * **Linux/Android Kernel/Framework:**  Although not explicitly present in *this specific file*, the broader context of Frida implies that this build process might be used to build components that interact with the kernel or Android framework. The handling of shared libraries (`SharedLibrary`) also hints at this.

6. **Identify Logic and Potential User Errors:**
    * **Logic:** The `Build` class's `copy` and `merge` methods involve conditional logic for handling cross-compilation and build-only configurations. The `process_kwargs_base` method in `Target` handles command-line arguments.
    * **User Errors:** The code includes checks for invalid arguments (`InvalidArguments` exception). The warning about path separators in target names suggests a potential user error.

7. **Consider the User's Path:** The prompt mentions the file path. This indicates a user navigating the Frida source code. The likely scenario is someone trying to understand the build system used by Frida, possibly to modify or extend it.

8. **Synthesize and Organize:** Finally, I organized my findings into the requested categories:
    * **Functionality:** I summarized the main purposes of the file and its key components.
    * **Relationship to Reverse Engineering:** I explained how the file contributes to building tools used in reverse engineering.
    * **Binary/Kernel/Framework Knowledge:** I highlighted the parts of the code dealing with low-level compilation and linking.
    * **Logic and Input/Output:** I described the logical operations and potential inputs and outputs of certain functions.
    * **User Errors:** I listed potential mistakes users could make.
    * **User Path:** I explained how a user might arrive at this file.
    * **Overall Functionality (Part 1 Summary):** I provided a concise summary of the file's main role.

By following these steps, I could systematically analyze the code and generate a comprehensive summary that addresses all the points in the prompt. The key was to combine understanding of Python code with knowledge of build systems and the broader context of the Frida project.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/build.py` 文件的功能。

**文件功能归纳（第 1 部分）**

这个 Python 文件 `build.py` 是 Frida 项目中 `frida-node` 子项目的构建系统 Meson 的一部分，主要负责定义和管理项目构建过程中的各种构建目标（targets）、依赖（dependencies）、配置信息以及安装规则。  它定义了用于描述软件构建状态的核心数据结构和类。

**详细功能列表:**

1. **定义核心数据结构：** 文件中定义了多个 dataclass 和类，用于表示构建过程中的各种实体：
    * `DependencyOverride`:  表示对依赖项的覆盖或替换。
    * `Headers`:  表示需要安装的头文件集合及其安装路径和权限。
    * `Man`:  表示需要安装的 man 手册页及其安装路径和权限。
    * `EmptyDir`: 表示需要创建的空目录及其安装路径和权限。
    * `InstallDir`: 表示需要安装的目录及其源路径、目标路径、排除规则等。
    * `DepManifest`: 表示依赖项的清单文件信息。
    * `Build`:  核心类，用于维护整个构建的状态，包括项目名称、版本、环境变量、构建目标、测试、基准测试、安装项、全局参数、依赖覆盖等。
    * `IncludeDirs`:  表示包含目录及其属性（系统包含、构建目录包含等）。
    * `IncludeSubdirPair`:  表示包含目录的源目录和构建目录对。
    * `ExtractedObjects`:  表示需要从目标中提取的特定对象文件。
    * `StructuredSources`: 表示结构化的源代码，例如用于 Rust 等语言。
    * `Target`:  抽象基类，表示一个构建目标，包含名称、子目录、所属子项目、构建选项等通用属性。
    * `BuildTarget`:  `Target` 的子类，表示一个需要编译和链接的构建目标，例如可执行文件、共享库、静态库等。

2. **管理构建目标信息：** `Build` 类维护了各种构建目标的列表（`targets`）、测试（`tests`）、基准测试（`benchmarks`）等。

3. **处理依赖关系：** `Build` 类能够存储和管理依赖覆盖 (`dependency_overrides`)。

4. **管理安装信息：** 文件定义了用于描述各种安装项（头文件、man 手册、目录、数据文件等）的类，以及 `Build` 类中相应的列表 (`headers`, `man`, `emptydir`, `data`, `install_dirs`)。

5. **处理编译和链接参数：** `Build` 类存储了全局的编译和链接参数 (`global_args`, `global_link_args`) 以及项目特定的编译和链接参数 (`projects_args`, `projects_link_args`)。

6. **支持交叉编译：** `Build` 类通过 `PerMachine` 结构来区分主机构建和目标机构建的配置和信息。

7. **提供辅助函数：** 文件中定义了一些辅助函数，例如 `get_target_macos_dylib_install_name` 用于生成 macOS 动态库的安装名称，以及 `_process_install_tag` 用于处理安装标签。

**与逆向方法的关联和举例说明:**

这个文件本身并不直接执行逆向操作，但它是构建 Frida 这样一个动态插桩工具的关键组成部分。Frida 的核心功能是允许开发者在运行时检查、修改进程的行为。

* **构建 Frida 的核心库:** 这个文件参与构建 Frida 的核心共享库或动态链接库，这些库会被注入到目标进程中，从而实现代码的动态修改和监控。例如，在构建 `frida-core` 时，会定义各种编译目标，指定需要编译的源文件、链接的库，以及编译选项。
* **构建 Frida 的命令行工具:**  Frida 包含一些命令行工具，如 `frida`、`frida-ps` 等。这个文件会定义这些可执行文件的构建目标，指定其入口点、依赖的库等。
* **构建 Node.js 绑定 (`frida-node`):**  当前文件所属的路径表明它与 `frida-node` 有关。逆向工程师经常使用 Node.js 来编写 Frida 脚本，与目标进程进行交互。这个文件负责构建 `frida-node` 模块的 C++ 扩展，使其能够在 Node.js 环境中使用 Frida 的功能。

**二进制底层、Linux、Android 内核及框架知识的体现和举例说明:**

* **二进制文件的生成和链接:**  文件中定义的 `BuildTarget` 涉及到编译源代码生成目标文件（`.o` 或类似），并将这些目标文件链接成可执行文件或库。这直接涉及到二进制文件的生成过程。
* **共享库 (`SharedLibrary`) 的构建:**  文件中定义了 `known_shlib_kwargs`，其中包含了与共享库构建相关的参数，如 `version`、`soversion`、`darwin_versions`。这些参数在 Linux 和 macOS 等系统中用于管理共享库的版本和兼容性。
* **静态库 (`StaticLibrary`) 的构建:**  文件中定义了 `known_stlib_kwargs`，包含 `pic`（Position Independent Code，位置无关代码）等与静态库构建相关的参数。
* **可执行文件 (`Executable`) 的构建:**  文件中定义了 `known_exe_kwargs`，包含 `pie`（Position Independent Executable，位置无关可执行文件）等参数，用于提高可执行文件的安全性。
* **链接参数 (`link_args`) 和依赖 (`dependencies`, `link_with`):**  这些参数和属性用于指定链接器需要使用的库和链接选项，例如 `-lpthread` 用于链接 POSIX 线程库，`-L/path/to/libs` 用于指定库的搜索路径。
* **目标文件 (`objects`):**  `BuildTarget` 可以指定预编译的目标文件，这些文件可以直接链接到最终的二进制文件中。
* **安装路径 (`install_dir`):**  文件中定义的安装项会涉及到将生成的文件安装到 Linux 或 Android 系统的特定目录下，例如 `/usr/bin`、`/usr/lib` 等。

**逻辑推理和假设输入与输出:**

假设我们定义了一个简单的构建目标，用于编译一个名为 `hello` 的 C++ 可执行文件：

**假设输入（在 Meson 构建文件中）：**

```python
executable(
  'hello',
  'src/hello.cpp',
  install: true
)
```

**在这个 `build.py` 文件中可能发生的逻辑推理和数据结构变化：**

1. **解析构建目标定义:** Meson 的解释器会读取上述 `executable` 函数调用，并将其转化为内部的数据结构。
2. **创建 `BuildTarget` 对象:**  在 `Build` 类的 `targets` 字典中，会创建一个名为 `'hello'` 的 `BuildTarget` 对象。
3. **设置目标属性:**  `BuildTarget` 对象的属性会被设置，例如：
    * `name`: `'hello'`
    * `subdir`:  当前构建文件所在的子目录。
    * `sources`:  包含 `'src/hello.cpp'` 对应的 `File` 对象。
    * `install`: `True`
4. **确定输出文件名:**  根据平台和目标名称，可能会生成不同的输出文件名，例如 Linux 上可能是 `hello`，Windows 上可能是 `hello.exe`。
5. **添加到安装列表:** 由于 `install` 为 `True`，该 `BuildTarget` 对象会被添加到 `Build` 对象的安装相关列表中。

**假设输入（在 Meson 构建文件中，带依赖）：**

```python
executable(
  'mytool',
  'src/mytool.cpp',
  dependencies: dep('zlib'),
  link_with: mylib
)

mylib = static_library('mylib', 'src/mylib.cpp')
```

**在这个 `build.py` 文件中可能发生的逻辑推理和数据结构变化：**

1. **创建 `BuildTarget` 对象 (`mytool` 和 `mylib`):**  会创建两个 `BuildTarget` 对象，分别对应可执行文件 `mytool` 和静态库 `mylib`。
2. **处理依赖关系:**
    * `mytool` 的 `dependencies` 属性会包含 `zlib` 依赖项的信息。Meson 会尝试找到系统中的 `zlib` 库。
    * `mytool` 的 `link_with` 属性会包含 `mylib` 这个 `BuildTarget` 对象，表示 `mytool` 需要链接 `mylib` 静态库。
3. **确定链接顺序:** Meson 会根据依赖关系确定编译和链接的顺序，确保 `mylib` 在 `mytool` 之前编译。

**用户或编程常见的使用错误和举例说明:**

* **类型错误:**  在 `executable` 等函数调用中，传递了错误类型的参数。例如，将字符串传递给需要文件列表的 `sources` 参数。Meson 的解释器会捕获这些错误并抛出异常。
* **参数名称错误:**  使用了未知的关键字参数。例如，在 `executable` 中使用了拼写错误的参数名 `instlal: true`。Meson 会发出警告或错误。
* **依赖项未找到:**  在 `dependencies` 中指定的依赖项在系统中找不到。Meson 会报错，提示用户需要安装相应的依赖库。
* **循环依赖:**  构建目标之间存在循环依赖关系，导致无法确定构建顺序。Meson 会检测到这种情况并报错。
* **路径错误:**  在指定源文件或包含目录时，使用了不存在的路径。Meson 会报错。
* **`build_by_default` 使用错误:**  错误地设置了 `build_by_default` 参数，导致某些应该默认构建的目标没有被构建。

**用户操作是如何一步步到达这里的，作为调试线索:**

1. **用户编写 Meson 构建文件 (`meson.build`):** 用户首先会创建或修改项目根目录下的 `meson.build` 文件，其中包含了项目的构建目标、依赖关系、配置选项等。
2. **用户运行 `meson setup builddir` 命令:** 用户在项目根目录下执行 `meson setup builddir` 命令，告诉 Meson 根据 `meson.build` 文件生成构建系统所需的文件。
3. **Meson 解析 `meson.build`:**  Meson 的解释器会读取 `meson.build` 文件，并执行其中的函数调用，例如 `executable`, `shared_library`, `dependency` 等。
4. **调用 `build.py` 中的代码:**  在解析 `meson.build` 文件的过程中，Meson 内部会使用 `build.py` 中定义的类和数据结构来存储和管理构建信息。例如，每当遇到 `executable` 函数调用时，就会创建一个 `BuildTarget` 对象。
5. **生成构建系统文件:**  Meson 根据解析的结果，生成特定后端（如 Ninja）所需的构建系统文件，这些文件描述了如何编译和链接项目中的各个目标。
6. **用户运行 `meson compile -C builddir` 命令:** 用户进入构建目录 (`builddir`) 并运行 `meson compile` 命令，指示 Meson 按照生成的构建系统文件进行编译和链接。
7. **编译和链接过程:**  构建系统（如 Ninja）会读取构建系统文件，并调用相应的编译器和链接器来生成最终的可执行文件和库。

**作为调试线索:**

如果用户在构建 Frida 的过程中遇到问题，例如某个目标编译失败、链接错误、依赖项找不到等，他们可能会需要查看 Meson 生成的构建系统文件，或者深入了解 Meson 的工作原理。查看 `frida/subprojects/frida-node/releng/meson/mesonbuild/build.py` 文件的源代码可以帮助他们理解：

* **构建目标的表示方式:**  如何使用 `BuildTarget` 类来描述一个构建目标。
* **依赖关系的管理:**  如何使用 `dependencies` 和 `link_with` 等属性来声明依赖关系。
* **安装规则的定义:**  如何使用 `Headers`, `Man`, `InstallDir` 等类来描述安装项。
* **Meson 的内部数据结构:**  `Build` 类中维护了哪些重要的构建信息。

因此，当用户报告与 Frida 构建相关的问题时，开发者可能会引导他们查看这个文件，以便更好地理解构建过程，并找到问题的根源。 例如，如果一个用户报告 `frida-node` 扩展编译失败，开发者可能会检查这个文件中与 `BuildTarget` 相关的定义，以及如何处理 `frida-core` 的依赖。

希望以上分析能够帮助你理解 `frida/subprojects/frida-node/releng/meson/mesonbuild/build.py` 文件的功能。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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