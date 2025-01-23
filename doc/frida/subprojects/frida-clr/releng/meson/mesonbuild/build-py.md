Response:
The user wants to understand the functionality of the `build.py` file within the Frida dynamic instrumentation tool, specifically in the context of its build system (Meson).

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The file name `build.py` within a `mesonbuild` directory strongly suggests it's involved in defining and managing build targets and configurations.

2. **Analyze Key Classes and Data Structures:**  Look for classes like `Build`, `Target`, `BuildTarget`, `CustomTarget`, and data structures like `OrderedDict`, `list`, `dict`. These will reveal the types of build entities and their organization.

3. **Examine Attributes and Methods:**  For each identified class, analyze its attributes (data it holds) and methods (actions it performs). This will detail the specific properties and functionalities of build elements.

4. **Look for Relationships:** Notice how classes relate to each other (e.g., `Build` contains `targets`, `BuildTarget` inherits from `Target`). This reveals the overall structure of the build system representation.

5. **Connect to Reverse Engineering Concepts:** Think about how the described build elements and processes might relate to reverse engineering tasks. For example, how building shared libraries or executables facilitates dynamic analysis.

6. **Consider System-Level Interactions:**  Note any references to operating systems (Linux, Android), kernels, or lower-level concepts (binary, linking). This highlights the system dependencies the build process handles.

7. **Infer Logic and Control Flow:** Based on the attributes and methods, deduce the logical flow and decision-making within the script. Are there conditional checks? How are dependencies managed?

8. **Identify Potential User Errors:**  Based on the configuration options and build steps, think about common mistakes users might make when setting up or running the build.

9. **Trace User Actions:** Consider how a user's actions in defining build configurations in `meson.build` eventually translate into the data structures and logic within `build.py`.

10. **Focus on the Request's Constraints:** Since this is "Part 1 of 5", the goal is to provide a high-level summary of the file's overall purpose and core functionalities *as presented in the provided code snippet*. Avoid going into extreme detail that might be covered in later parts.

**Mental Walkthrough of the Code:**

* **Imports:**  Start by noting the imported modules. `collections`, `dataclasses`, `functools`, `os`, `pathlib`, etc., indicate general programming utilities. Imports from `.`, like `coredata`, `dependencies`, `mlog`, etc., signify internal Meson modules related to build configuration, dependency management, and logging.
* **Data Classes:**  Pay close attention to the `@dataclass` definitions. These represent core build entities (e.g., `Headers`, `Man`, `BuildTarget`). Their fields reveal the key attributes of these entities.
* **The `Build` Class:** This is likely the central data structure holding the entire build state. Its attributes (e.g., `targets`, `tests`, `headers`) indicate what aspects of the build it manages.
* **The `Target` and `BuildTarget` Classes:** These are crucial for understanding how individual build products (executables, libraries) are represented and configured. The `known_kwargs` and methods like `process_kwargs_base` hint at the various build options.
* **Keywords Related to Linking and Compilation:** Notice keywords like `link_with`, `link_args`, `objects`, `sources`, and references to compilers. These are direct connections to the compilation and linking process.

**Constraint Checklist & Confidence Score:**

1. List its functions? Yes.
2. Relationship with reverse engineering? Yes.
3. Mentions of binary/OS/kernel/framework? Yes.
4. Logical reasoning (input/output)? Yes (though at a high level in this part).
5. Common user errors? Yes.
6. User steps to reach here? Yes.
7. Part 1 summary? Yes.

Confidence Score: 5/5

**Strategizing Complete.** I will now proceed to generate the response based on the analysis.
这是Frida动态Instrumentation工具的源代码文件，位于Meson构建系统的子项目`frida-clr`的构建定义中。该文件 (`build.py`) 的主要功能是**定义和管理构建过程中的各种构建目标 (targets)**。 它使用 Meson 提供的 API 来声明如何构建例如库、可执行文件等产物，以及如何处理源代码、依赖项和安装规则。

以下是其功能的详细列举：

**1. 定义各种构建目标 (Build Targets)：**

*   **声明可执行文件 (Executable):**  通过 `known_exe_kwargs` 定义了构建可执行文件所需的各种参数，例如依赖库 (`link_with`)、链接参数 (`link_args`)、是否导出动态符号 (`export_dynamic`) 等。
*   **声明共享库 (Shared Library):**  通过 `known_shlib_kwargs` 定义了构建共享库的参数，包括版本号 (`version`, `soversion`)、模块定义文件 (`vs_module_defs`) 等。这与逆向工程中分析和注入动态链接库息息相关。
*   **声明共享模块 (Shared Module):** 通过 `known_shmod_kwargs` 定义了构建共享模块的参数。
*   **声明静态库 (Static Library):** 通过 `known_stlib_kwargs` 定义了构建静态库的参数，例如是否需要位置无关代码 (`pic`)。
*   **声明 JAR 文件 (Java Archive):** 通过 `known_jar_kwargs` 定义了构建 JAR 文件的参数，包括主类 (`main_class`) 和 Java 资源 (`java_resources`).
*   **声明自定义目标 (Custom Target):** 虽然代码片段中没有直接展示自定义目标的构建逻辑，但其数据结构（例如 `CustomTarget` 类）被定义和使用，暗示了该文件也支持声明需要用户自定义构建步骤的目标。

**2. 处理源代码和对象文件：**

*   **管理源代码 (Sources):**  `BuildTarget` 类拥有 `sources` 属性，用于指定构建目标所需的源代码文件。
*   **管理对象文件 (Objects):** `BuildTarget` 类拥有 `objects` 属性，用于指定预编译的对象文件。
*   **处理结构化源代码 (Structured Sources):**  定义了 `StructuredSources` 类，用于处理需要按文件系统结构组织的源代码，例如 Rust 和 Cython 项目。这在逆向工程中分析具有特定项目结构的二进制文件时，理解其构建方式很有帮助。
*   **提取对象文件 (Extracted Objects):**  定义了 `ExtractedObjects` 类，允许从其他构建目标中提取特定的对象文件。这在逆向工程中可能用于分析特定模块或功能对应的编译产物。

**3. 管理依赖关系 (Dependencies)：**

*   **声明依赖项 (Dependencies):** `buildtarget_kwargs` 中包含 `dependencies` 参数，用于声明当前构建目标依赖的其他构建目标或外部库。
*   **处理链接依赖 (Link With, Link Whole):** `buildtarget_kwargs` 中包含 `link_with` 和 `link_whole` 参数，用于指定需要链接的库。在逆向工程中，理解目标文件链接了哪些库，有助于分析其功能和可能的漏洞。
*   **处理链接参数 (Link Args):** `buildtarget_kwargs` 中包含 `link_args` 参数，用于指定传递给链接器的额外参数。这些参数可能影响二进制文件的生成方式，对逆向分析至关重要。
*   **依赖项覆盖 (Dependency Override):** 定义了 `DependencyOverride` 类，允许用户覆盖默认的依赖项查找行为。

**4. 管理头文件 (Headers)：**

*   **声明需要安装的头文件 (Headers):**  定义了 `Headers` 类，用于指定需要安装的头文件及其安装路径。这在开发需要提供头文件的库时非常重要，在逆向工程中，查看头文件可以帮助理解库的接口和数据结构。

**5. 管理其他安装文件和目录：**

*   **安装 Man 手册页 (Man):** 定义了 `Man` 类，用于指定需要安装的 man 手册页及其安装路径。
*   **安装数据文件 (Data):** 定义了 `Data` 类，用于指定需要安装的数据文件及其安装路径。
*   **创建空目录 (EmptyDir):** 定义了 `EmptyDir` 类，用于指定需要创建的空目录及其安装路径。
*   **安装目录 (InstallDir):** 定义了 `InstallDir` 类，用于指定需要安装的目录及其安装路径。
*   **安装符号链接 (SymlinkData):** 定义了 `SymlinkData` 类，用于指定需要创建的符号链接及其安装路径。

**6. 配置编译选项和链接选项：**

*   **全局参数 (Global Args):** `Build` 类中包含 `global_args` 属性，用于指定全局的编译器参数。
*   **项目参数 (Projects Args):** `Build` 类中包含 `projects_args` 属性，用于指定特定项目的编译器参数。
*   **全局链接参数 (Global Link Args):** `Build` 类中包含 `global_link_args` 属性，用于指定全局的链接器参数。
*   **项目链接参数 (Projects Link Args):** `Build` 类中包含 `projects_link_args` 属性，用于指定特定项目的链接器参数。
*   **语言特定的参数 (Language Argument Keywords):** 通过 `lang_arg_kwargs` 定义了各种编程语言特定的编译选项，例如 D 语言的导入目录 (`d_import_dirs`)、单元测试 (`d_unittest`) 等。

**7. 管理测试和基准测试 (Tests and Benchmarks):**

*   **声明测试 (Tests):** `Build` 类中包含 `tests` 属性，用于存储定义的测试用例。
*   **声明基准测试 (Benchmarks):** `Build` 类中包含 `benchmarks` 属性，用于存储定义的基准测试。

**8. 处理子项目 (Subprojects):**

*   **管理子项目信息 (Subprojects):** `Build` 类中包含 `subprojects` 属性，用于存储子项目的信息。

**9. 处理安装脚本和配置脚本：**

*   **安装脚本 (Install Scripts):** `Build` 类中包含 `install_scripts` 属性，用于指定需要在安装时执行的脚本。
*   **配置脚本 (Postconf Scripts):** `Build` 类中包含 `postconf_scripts` 属性，用于指定在配置完成后执行的脚本。
*   **分发脚本 (Dist Scripts):** `Build` 类中包含 `dist_scripts` 属性，用于指定在打包分发时执行的脚本。

**10. 管理依赖清单 (Dependency Manifest):**

*   **定义依赖清单 (DepManifest):** 定义了 `DepManifest` 类，用于描述依赖项的版本、许可证等信息。

**与逆向方法的关联及举例说明：**

*   **理解目标文件的构建方式：** 通过分析 `build.py`，逆向工程师可以了解目标可执行文件或库是如何编译和链接的，使用了哪些编译选项和链接参数。这有助于理解二进制文件的结构、功能和潜在的漏洞。
    *   **举例：** 查看 `link_args` 可以了解是否启用了地址空间布局随机化 (ASLR) 或其他安全特性。如果 `pie` 选项被设置为 `True`，则表明生成的可执行文件是位置无关的，这在某些逆向分析场景下需要考虑。
*   **识别依赖库：** `link_with` 参数直接指明了目标文件依赖的库。逆向工程师可以根据这些信息，确定需要分析的外部代码，例如加密库、网络库等。
    *   **举例：** 如果 `link_with` 中包含了 `libssl`，则表明该程序可能使用了 OpenSSL 库进行加密通信，逆向工程师可以重点分析与该库相关的代码。
*   **分析符号信息：** 虽然 `build.py` 不直接控制符号信息的生成，但编译和链接选项会影响符号信息的保留。了解这些选项可以帮助逆向工程师更好地利用符号信息进行分析。
*   **理解模块化构建：** 通过 `StructuredSources` 和 `ExtractedObjects`，可以了解项目是否采用了模块化构建，以及如何将不同的源代码组织和编译成最终的产物。这对于大型项目的逆向分析非常重要。
    *   **举例：** 如果使用了 `ExtractedObjects` 从某个库中提取了特定的对象文件并链接到另一个目标，逆向工程师就需要关注这些被提取出来的特定模块的功能。
*   **动态链接分析：** 对于共享库目标，`version` 和 `soversion` 等参数会影响其动态链接时的行为。逆向工程师需要了解这些版本信息，以便正确地加载和分析共享库。
    *   **举例：**  `darwin_versions` 选项用于指定 macOS 上的兼容性版本号，这对于在 macOS 上进行逆向分析时需要考虑。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明：**

*   **二进制底层：**
    *   **链接参数 (Link Args):**  链接参数直接影响最终二进制文件的布局和特性，例如是否生成 PIC 代码 (`pic`)，是否进行预链接 (`prelink`)。这些都属于二进制底层的知识。
    *   **输出类型：**  区分可执行文件、静态库和共享库涉及到二进制文件的不同格式和加载机制。
*   **Linux：**
    *   **RPATH (`build_rpath`, `install_rpath`):**  这些参数用于设置 Linux 系统上运行时库的搜索路径，是 Linux 系统动态链接器的工作原理相关的知识。
    *   **符号可见性 (`gnu_symbol_visibility`):**  该参数控制符号在共享库中的可见性，是 Linux 系统下共享库开发的重要概念。
*   **Android内核及框架：**
    *   虽然代码中没有直接体现 Android 特有的构建参数，但 `frida-clr` 作为 Frida 的一部分，很可能在其他构建文件中包含针对 Android 平台的配置。例如，构建 Android 上的共享库可能需要指定特定的 NDK 工具链和编译选项。

**逻辑推理的假设输入与输出：**

假设有以下 `meson.build` 文件片段用于定义一个共享库：

```meson
project('mylib', 'cpp')
shlib('mylib', 'mylib.cpp', version: '1.0', soversion: '1')
```

**假设输入:** Meson 解析 `meson.build` 文件后，会将相关信息传递给 `build.py` 中的 `SharedLibrary` 类的初始化方法。`kwargs` 参数会包含：`{'version': '1.0', 'soversion': '1'}`。

**逻辑推理 (在 `SharedLibrary` 类的 `__init__` 或其父类 `BuildTarget` 中):**

*   `self.version` 将被设置为 `'1.0'`。
*   `self.soversion` 将被设置为 `'1'`。
*   根据 `known_shlib_kwargs` 的定义，这些参数会被识别并处理。
*   构建系统会根据这些版本信息生成相应的共享库文件名，例如在 Linux 上可能是 `libmylib.so.1.0`，符号链接 `libmylib.so.1` 指向它，`libmylib.so` 又指向 `libmylib.so.1`。

**假设输出:**  Meson 生成的构建指令会包含将源代码 `mylib.cpp` 编译成位置无关的目标文件，并使用链接器将其链接成共享库，并在生成的文件名中包含版本信息。

**涉及用户或者编程常见的使用错误及举例说明：**

*   **类型错误：**  为需要布尔值的参数传递了非布尔值。
    *   **举例：**  在 `meson.build` 中错误地写成 `install: "true"` 而不是 `install: true`。`build.py` 中会检查 `build_by_default` 的类型，如果用户传递了字符串 `"true"`，则会抛出 `InvalidArguments` 异常。
*   **参数名错误：**  使用了未知的构建目标参数。
    *   **举例：**  在 `meson.build` 中错误地写成 `dependecies` 而不是 `dependencies`。虽然 `build.py` 中定义了 `known_build_target_kwargs` 等来检查参数，但这种拼写错误可能不会立即被捕获，可能导致构建行为不符合预期。
*   **链接库路径错误：**  指定了不存在的依赖库，或者库的路径不正确。
    *   **举例：**  在 `meson.build` 中使用 `link_with: 'nonexistentlib'`。链接器在链接时会报错，提示找不到该库。
*   **循环依赖：**  构建目标之间存在循环依赖关系。
    *   **举例：**  目标 A 依赖目标 B，目标 B 又依赖目标 A。Meson 在解析依赖关系时会检测到循环依赖并报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户使用 Meson 的 DSL (Domain Specific Language) 编写 `meson.build` 文件，描述项目的构建方式，包括定义可执行文件、库、依赖项等。例如，用户可能会在 `meson.build` 中使用 `shared_library()` 函数来定义一个共享库，并指定其源代码文件、版本号等参数。
2. **用户运行 `meson` 命令配置构建：** 用户在项目根目录下运行 `meson build` 命令，指示 Meson 根据 `meson.build` 文件生成构建系统所需的各种文件。
3. **Meson 解析 `meson.build`：** Meson 的解析器会读取并解析 `meson.build` 文件，构建项目的内部表示，包括构建目标、依赖关系、配置选项等。
4. **Meson 调用 `build.py` (或类似的构建定义文件)：**  当 Meson 解析到定义构建目标（例如 `shared_library()`）的语句时，它会调用相应的构建定义文件（例如这里的 `build.py`）中的相关代码，创建表示该构建目标的对象（例如 `SharedLibrary` 的实例）。
5. **`build.py` 中的代码被执行：**  在 `build.py` 中，与构建目标相关的类（例如 `SharedLibrary`，继承自 `BuildTarget` 和 `Target`）的初始化方法会被调用，传入从 `meson.build` 中解析出的参数。
6. **构建目标对象被创建和管理：**  `build.py` 中的代码会根据传入的参数设置构建目标对象的属性，例如源代码文件、依赖库、链接参数等，并将这些对象存储在 `Build` 类的 `targets` 属性中。

**作为调试线索：**  当构建过程中出现问题时，例如链接错误或找不到依赖项，开发者可以检查以下内容：

*   **`meson.build` 文件：**  检查 `meson.build` 中对相关构建目标的定义是否正确，例如源代码文件路径、依赖库名称、链接参数等。
*   **`build.py` (或其他构建定义文件)：**  理解 `build.py` 中如何处理这些参数，例如是否正确地传递给了编译器和链接器。可以通过在 `build.py` 中添加日志输出来跟踪参数的值。
*   **Meson 的构建日志：**  查看 Meson 生成的构建日志，可以了解实际执行的编译和链接命令，以及其中使用的参数。这有助于定位问题所在。
*   **相关的构建目标对象：**  在 Meson 的内部表示中，可以通过调试工具查看 `Build` 对象的 `targets` 属性，了解各个构建目标的详细信息。

**归纳一下它的功能：**

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/build.py` 文件的核心功能是**作为 Frida 项目中 `frida-clr` 子项目的 Meson 构建定义文件，负责声明和配置各种构建目标，包括库、可执行文件等，并管理其源代码、依赖项、编译选项、链接选项和安装规则。** 它为 Meson 提供了构建 `frida-clr` 组件所需的必要信息和逻辑。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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